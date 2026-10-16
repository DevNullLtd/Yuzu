%%%-------------------------------------------------------------------
%%% @doc Tests of the node-wide memory load shedder (yuzu_gw_memory_shedder):
%%%   - config shape validation (the boot guard's decision);
%%%   - the shed/unshed transitions, driven against a REAL agent listener with
%%%     an injected memory reading, asserting a new connection is refused while
%%%     shed and accepted again after, an existing connection keeps working, a
%%%     management listener is never shed, and the gauge/counter move.
%%%
%%% The memory reading is an atomics ref the test sets, so the transition is
%%% driven on a synchronous sample_now/1, never a timed sleep.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_memory_shedder_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).

%%--------------------------------------------------------------------
%% Config validation (the boot guard)
%%--------------------------------------------------------------------

validate_config_test_() ->
    [?_assertEqual(ok, yuzu_gw_memory_shedder:validate_config(#{})),
     ?_assertEqual(ok, yuzu_gw_memory_shedder:validate_config(
                         #{high_water_fraction => 0.75, low_water_fraction => 0.65,
                           interval_ms => 1000})),
     ?_assertEqual(ok, yuzu_gw_memory_shedder:validate_config(
                         #{high_water_bytes => 2000, low_water_bytes => 1000})),
     ?_assertEqual(ok, yuzu_gw_memory_shedder:validate_config(#{enabled => false})),
     ?_assertMatch({error, {unknown_memory_shedding_keys, [bogus]}},
                   yuzu_gw_memory_shedder:validate_config(#{bogus => 1})),
     ?_assertMatch({error, {bad_memory_shedding_values, _}},
                   yuzu_gw_memory_shedder:validate_config(#{high_water_fraction => 1.5})),
     ?_assertMatch({error, {bad_memory_shedding_values, _}},
                   yuzu_gw_memory_shedder:validate_config(#{high_water_bytes => -1})),
     ?_assertMatch({error, {bad_memory_shedding_values, _}},
                   yuzu_gw_memory_shedder:validate_config(#{interval_ms => 0})),
     ?_assertMatch({error, memory_shedding_not_a_map},
                   yuzu_gw_memory_shedder:validate_config([])) ].

%%--------------------------------------------------------------------
%% Inactive / disabled
%%--------------------------------------------------------------------

disabled_is_inactive_test() ->
    setup_apps(),
    {ok, Pid} = yuzu_gw_memory_shedder:start_link(
                  #{register => false, config => #{enabled => false}, listener_refs => []}),
    try
        ?assertMatch(#{active := false}, yuzu_gw_memory_shedder:status(Pid)),
        ?assertEqual({error, inactive}, yuzu_gw_memory_shedder:sample_now(Pid))
    after stop(Pid) end.

system_memory_bytes_is_sane_test() ->
    %% Either undefined (no /proc/meminfo, e.g. macOS) or a positive byte count
    %% (Linux). Never a crash, never zero.
    case yuzu_gw_memory_shedder:system_memory_bytes() of
        undefined -> ok;
        N when is_integer(N), N > 0 -> ok
    end.

fraction_config_does_not_crash_test() ->
    setup_apps(),
    %% A fraction-only config: active where system memory is readable (Linux CI),
    %% inactive where it is not (macOS). Either way it answers status, never fails
    %% to start.
    {ok, Pid} = yuzu_gw_memory_shedder:start_link(
                  #{register => false,
                    config => #{high_water_fraction => 0.75, low_water_fraction => 0.65},
                    listener_refs => []}),
    try ?assertMatch(#{active := _}, yuzu_gw_memory_shedder:status(Pid))
    after stop(Pid) end.

low_not_below_high_is_inactive_test() ->
    setup_apps(),
    {ok, Pid} = yuzu_gw_memory_shedder:start_link(
                  #{register => false,
                    config => #{high_water_bytes => 1000, low_water_bytes => 2000},
                    listener_refs => []}),
    try ?assertMatch(#{active := false}, yuzu_gw_memory_shedder:status(Pid))
    after stop(Pid) end.

%%--------------------------------------------------------------------
%% Shed / unshed against a real listener
%%--------------------------------------------------------------------

shed_and_resume_test_() ->
    {setup, fun setup_metrics/0, fun cleanup_metrics/1,
     {timeout, 30, fun shed_and_resume/0}}.

shed_and_resume() ->
    yuzu_grpc_stub_svc:init_state(),
    %% A real agent listener and a real management listener (never shed).
    {AgentPort, AgentL} = yuzu_gw_test_listener:start(
                            #{name => shed_agent, service_protos => [agent_pb],
                              services => #{?SVC => yuzu_grpc_stub_svc}}),
    {_MgmtPort, MgmtL} = yuzu_gw_test_listener:start(
                           #{name => shed_mgmt, service_protos => [management_pb],
                             services => #{?MGMT_SVC => yuzu_grpc_stub_svc}}),
    Mem = atomics:new(1, []),
    atomics:put(Mem, 1, 0),
    MemFun = fun() -> atomics:get(Mem, 1) end,
    Susp0 = counter(yuzu_gw_memory_shedding_suspensions_total, []),
    {ok, Pid} = yuzu_gw_memory_shedder:start_link(
                  #{register => false,
                    config => #{high_water_bytes => 100, low_water_bytes => 50,
                                interval_ms => 60000},
                    listener_refs => [{yuzu_grpc, shed_agent}],
                    mem_fun => MemFun}),
    %% An existing connection, established before shedding begins.
    Chan = yuzu_gw_test_listener:client_channel(shed_chan, #{port => AgentPort}),
    try
        ?assertMatch(#{active := true, suspended := false}, yuzu_gw_memory_shedder:status(Pid)),
        ?assertEqual(running, ranch:get_status({yuzu_grpc, shed_agent})),

        %% Cross the high-water mark -> the agent listener is suspended.
        atomics:put(Mem, 1, 200),
        ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(suspended, ranch:get_status({yuzu_grpc, shed_agent})),
        %% The management listener is NEVER shed.
        ?assertEqual(running, ranch:get_status({yuzu_grpc, shed_mgmt})),
        ?assertEqual(1, gauge(yuzu_gw_memory_shedding_active, [])),
        ?assert(counter(yuzu_gw_memory_shedding_suspensions_total, []) > Susp0),

        %% A NEW agent connection is refused while shed.
        {ok, C} = gun:open("127.0.0.1", AgentPort, #{protocols => [http2], retry => 0}),
        ?assertMatch({error, _}, gun:await_up(C, 1500)),
        gun:close(C),

        %% The connection established before shedding keeps working.
        ?assertMatch({ok, _, _},
                     yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>},
                                            hb_def(), #{channel => Chan, timeout => 5000})),

        %% Between the marks: no change (hysteresis).
        atomics:put(Mem, 1, 75),
        ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(suspended, ranch:get_status({yuzu_grpc, shed_agent})),

        %% Below the low-water mark -> the agent listener resumes.
        atomics:put(Mem, 1, 10),
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(running, ranch:get_status({yuzu_grpc, shed_agent})),
        ?assertEqual(0, gauge(yuzu_gw_memory_shedding_active, [])),

        %% A new agent connection is accepted again.
        {ok, C2} = gun:open("127.0.0.1", AgentPort, #{protocols => [http2], retry => 0}),
        ?assertEqual({ok, http2}, gun:await_up(C2, 2000)),
        gun:close(C2)
    after
        yuzu_gw_test_listener:stop_channel(Chan),
        stop(Pid),
        yuzu_gw_test_listener:stop(AgentL),
        yuzu_gw_test_listener:stop(MgmtL)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% Start the apps the shedder and listeners need, WITHOUT attaching the global
%% prometheus telemetry handler (the plain tests do not read metrics, and a
%% dangling handler leaks into later test modules — #336).
setup_apps() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(prometheus),
    ok.

%% For the one test that reads metrics: attach the prometheus handler cleanly and
%% detach it on cleanup so it does not leak into later modules.
setup_metrics() ->
    setup_apps(),
    catch telemetry:detach(yuzu_gw_prometheus),
    yuzu_gw_telemetry:setup(),
    ok.

cleanup_metrics(_) ->
    catch telemetry:detach(yuzu_gw_prometheus),
    ok.

stop(Pid) ->
    unlink(Pid),
    Ref = erlang:monitor(process, Pid),
    exit(Pid, shutdown),
    receive {'DOWN', Ref, process, Pid, _} -> ok after 5000 -> ok end.

hb_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

counter(Name, Labels) ->
    case prometheus_counter:value(Name, Labels) of undefined -> 0; V -> V end.

gauge(Name, Labels) ->
    case prometheus_gauge:value(Name, Labels) of undefined -> 0; V -> V end.
