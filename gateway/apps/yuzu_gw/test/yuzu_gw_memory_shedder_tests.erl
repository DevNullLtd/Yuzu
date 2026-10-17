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
    {MgmtPort, MgmtL} = yuzu_gw_test_listener:start(
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

        %% A NEW agent connection is REFUSED while shed: the listen socket is
        %% closed, so the TCP connect fails at once with ECONNREFUSED (an agent
        %% backs off immediately, a balancer retries another node). It does not
        %% sit in a kernel backlog waiting for an accept.
        ?assertEqual({error, econnrefused},
                     gen_tcp:connect("127.0.0.1", AgentPort, [binary, {active, false}], 2000)),
        {ok, C} = gun:open("127.0.0.1", AgentPort, #{protocols => [http2], retry => 0}),
        ?assertMatch({error, _}, gun:await_up(C, 1500)),
        gun:close(C),
        %% ...while a NEW management connection is still accepted.
        {ok, MC} = gun:open("127.0.0.1", MgmtPort, #{protocols => [http2], retry => 0}),
        ?assertEqual({ok, http2}, gun:await_up(MC, 2000)),
        gun:close(MC),

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
%% A transition that fails is retried on the next tick (#5695 review)
%%--------------------------------------------------------------------

%% A resume that fails (here ranch:resume_listener/1 answers {error, emfile},
%% as it would when the node is out of file descriptors) leaves the listener
%% suspended. The shedder must keep trying on every tick, count and show the
%% failure, and resume the listener as soon as the cause clears. It used to
%% mark itself unshed after the first attempt whatever the result, so the
%% gateway stayed shed for good while its gauge said it was not.
resume_failure_is_retried_test_() ->
    {setup, fun setup_metrics/0, fun cleanup_metrics/1,
     {timeout, 30, fun resume_failure_is_retried/0}}.

resume_failure_is_retried() ->
    {AgentPort, AgentL} = yuzu_gw_test_listener:start(
                            #{name => shed_retry_agent, service_protos => [agent_pb],
                              services => #{?SVC => yuzu_grpc_stub_svc}}),
    Ref = {yuzu_grpc, shed_retry_agent},
    {Mem, MemFun} = mem_cell(),
    {ok, Pid} = start_shedder([Ref], MemFun),
    Fail0 = counter(yuzu_gw_memory_shedding_transition_failures_total, [<<"resume">>]),
    ok = meck:new(ranch, [passthrough, no_link, unstick]),
    try
        atomics:put(Mem, 1, 200),
        ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(suspended, ranch:get_status(Ref)),

        meck:expect(ranch, resume_listener, fun(_) -> {error, emfile} end),
        atomics:put(Mem, 1, 10),
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid)),
        %% The resume failed: still suspended, still refusing, and visible.
        ?assertEqual(suspended, ranch:get_status(Ref)),
        ?assertEqual({error, econnrefused},
                     gen_tcp:connect("127.0.0.1", AgentPort, [binary], 2000)),
        ?assertMatch(#{shed := false, failing := #{resume := 1, suspend := 0}},
                     yuzu_gw_memory_shedder:status(Pid)),
        ?assertEqual(1, gauge(yuzu_gw_memory_shedding_transition_failing, [<<"resume">>])),
        ?assertEqual(0, gauge(yuzu_gw_memory_shedding_active, [])),
        ?assertEqual(Fail0 + 1,
                     counter(yuzu_gw_memory_shedding_transition_failures_total, [<<"resume">>])),

        %% The next tick tries again (and counts it again).
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(Fail0 + 2,
                     counter(yuzu_gw_memory_shedding_transition_failures_total, [<<"resume">>])),
        ?assertEqual(suspended, ranch:get_status(Ref)),

        %% The cause clears: the next tick resumes the listener.
        meck:expect(ranch, resume_listener, fun(R) -> meck:passthrough([R]) end),
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(running, ranch:get_status(Ref)),
        ?assertMatch(#{failing := #{resume := 0, suspend := 0}},
                     yuzu_gw_memory_shedder:status(Pid)),
        ?assertEqual(0, gauge(yuzu_gw_memory_shedding_transition_failing, [<<"resume">>])),
        {ok, C} = gun:open("127.0.0.1", AgentPort, #{protocols => [http2], retry => 0}),
        ?assertEqual({ok, http2}, gun:await_up(C, 2000)),
        gun:close(C)
    after
        catch meck:unload(ranch),
        stop(Pid),
        yuzu_gw_test_listener:stop(AgentL)
    end.

%% The other direction: a suspend that fails leaves the listener accepting;
%% the shedder retries it on the next tick rather than believing it is shed.
suspend_failure_is_retried_test_() ->
    {setup, fun setup_metrics/0, fun cleanup_metrics/1,
     {timeout, 30, fun suspend_failure_is_retried/0}}.

suspend_failure_is_retried() ->
    {_AgentPort, AgentL} = yuzu_gw_test_listener:start(
                             #{name => shed_sretry_agent, service_protos => [agent_pb],
                               services => #{?SVC => yuzu_grpc_stub_svc}}),
    Ref = {yuzu_grpc, shed_sretry_agent},
    {Mem, MemFun} = mem_cell(),
    {ok, Pid} = start_shedder([Ref], MemFun),
    Fail0 = counter(yuzu_gw_memory_shedding_transition_failures_total, [<<"suspend">>]),
    ok = meck:new(ranch, [passthrough, no_link, unstick]),
    try
        meck:expect(ranch, suspend_listener, fun(_) -> {error, not_found} end),
        atomics:put(Mem, 1, 200),
        ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(running, ranch:get_status(Ref)),
        ?assertMatch(#{shed := true, failing := #{suspend := 1}},
                     yuzu_gw_memory_shedder:status(Pid)),
        ?assertEqual(1, gauge(yuzu_gw_memory_shedding_transition_failing, [<<"suspend">>])),
        ?assertEqual(Fail0 + 1,
                     counter(yuzu_gw_memory_shedding_transition_failures_total, [<<"suspend">>])),

        meck:expect(ranch, suspend_listener, fun(R) -> meck:passthrough([R]) end),
        ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(suspended, ranch:get_status(Ref)),
        ?assertEqual(0, gauge(yuzu_gw_memory_shedding_transition_failing, [<<"suspend">>])),

        atomics:put(Mem, 1, 10),
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid)),
        ?assertEqual(running, ranch:get_status(Ref))
    after
        catch meck:unload(ranch),
        stop(Pid),
        yuzu_gw_test_listener:stop(AgentL)
    end.

%% A shedder that restarts (a crash; the supervisor starts a fresh one) while
%% the listener is suspended takes the suspended listener as its own, so it
%% resumes it below the low-water mark. The fresh process used to start
%% unshed and never resume a listener its predecessor had suspended.
restart_adopts_suspended_listener_test_() ->
    {setup, fun setup_apps/0, fun(_) -> ok end,
     {timeout, 30, fun restart_adopts_suspended_listener/0}}.

restart_adopts_suspended_listener() ->
    {_AgentPort, AgentL} = yuzu_gw_test_listener:start(
                             #{name => shed_adopt_agent, service_protos => [agent_pb],
                               services => #{?SVC => yuzu_grpc_stub_svc}}),
    Ref = {yuzu_grpc, shed_adopt_agent},
    {Mem, MemFun} = mem_cell(),
    {ok, Pid1} = start_shedder([Ref], MemFun),
    {ok, Pid2} =
        try
            atomics:put(Mem, 1, 200),
            ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Pid1)),
            ?assertEqual(suspended, ranch:get_status(Ref)),
            stop(Pid1),
            atomics:put(Mem, 1, 10),
            start_shedder([Ref], MemFun)
        catch C:R:S ->
            yuzu_gw_test_listener:stop(AgentL),
            erlang:raise(C, R, S)
        end,
    try
        ?assertMatch(#{shed := true}, yuzu_gw_memory_shedder:status(Pid2)),
        ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Pid2)),
        ?assertEqual(running, ranch:get_status(Ref))
    after
        stop(Pid2),
        yuzu_gw_test_listener:stop(AgentL)
    end.

%%--------------------------------------------------------------------
%% The memory limit: the smaller of the cgroup limit and host memory
%%--------------------------------------------------------------------

-define(GIB, 1073741824).
%% A 16 GiB host.
-define(MEMINFO, "MemTotal:       16777216 kB\nMemFree:         1024 kB\n").

memory_limit_test_() ->
    {foreach, fun fixture_dir/0, fun rm_fixture/1,
     [fun(D) -> {"cgroup v2 limit in a container", fun() -> v2_container(D) end} end,
      fun(D) -> {"cgroup v2 max is unlimited: host memory", fun() -> v2_unlimited(D) end} end,
      fun(D) -> {"cgroup v2 limit on an ancestor (systemd slice)", fun() -> v2_ancestor(D) end} end,
      fun(D) -> {"cgroup v1 limit", fun() -> v1_limit(D) end} end,
      fun(D) -> {"cgroup v1 huge value is unlimited", fun() -> v1_unlimited(D) end} end,
      fun(D) -> {"host smaller than the cgroup limit", fun() -> host_smaller(D) end} end,
      fun(D) -> {"unreadable cgroup value falls back to host", fun() -> v2_garbage(D) end} end,
      fun(D) -> {"unreadable cgroup file falls back to host", fun() -> v2_eisdir(D) end} end,
      fun(D) -> {"no cgroup and no host memory: unknown", fun() -> nothing(D) end} end,
      fun(D) -> {"a cgroup path outside the namespace reads the root only",
                 fun() -> outside_namespace(D) end} end,
      fun(D) -> {"the marks are fractions of the cgroup limit", fun() -> marks_from_cgroup(D) end} end]}.

v2_container(D) ->
    put_file(D, "proc_cgroup", "0::/\n"),
    put_file(D, "cg/memory.max", "1073741824\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := ?GIB, source := cgroup_v2, cgroup := ?GIB,
                   host := 17179869184, unreadable := []},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

v2_unlimited(D) ->
    put_file(D, "proc_cgroup", "0::/\n"),
    put_file(D, "cg/memory.max", "max\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := 17179869184, source := host, cgroup := unlimited},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

v2_ancestor(D) ->
    put_file(D, "proc_cgroup", "0::/system.slice/yuzu-gateway.service\n"),
    put_file(D, "cg/system.slice/yuzu-gateway.service/memory.max", "max\n"),
    put_file(D, "cg/system.slice/memory.max", "2147483648\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := 2147483648, source := cgroup_v2},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

v1_limit(D) ->
    %% Docker on cgroup v1 without a cgroup namespace: /proc/self/cgroup names
    %% the host's path, but the container's own memory cgroup is what is
    %% mounted at <root>/memory, so the walk finds it at the top.
    put_file(D, "proc_cgroup", "5:cpuset:/docker/abc\n4:memory:/docker/abc\n"),
    put_file(D, "cg/memory/memory.limit_in_bytes", "536870912\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := 536870912, source := cgroup_v1},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

v1_unlimited(D) ->
    put_file(D, "proc_cgroup", "4:memory:/\n"),
    put_file(D, "cg/memory/memory.limit_in_bytes", "9223372036854771712\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := 17179869184, source := host, cgroup := unlimited},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

host_smaller(D) ->
    put_file(D, "proc_cgroup", "0::/\n"),
    put_file(D, "cg/memory.max", "34359738368\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := 17179869184, source := host, cgroup := 34359738368},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

v2_garbage(D) ->
    put_file(D, "proc_cgroup", "0::/\n"),
    put_file(D, "cg/memory.max", "banana\n"),
    put_file(D, "meminfo", ?MEMINFO),
    #{bytes := B, source := S, unreadable := U} =
        yuzu_gw_memory_shedder:memory_limit(paths(D)),
    ?assertEqual({17179869184, host}, {B, S}),
    ?assertMatch([{_, bad_value}], U).

v2_eisdir(D) ->
    %% A path that exists but cannot be read as a file (EISDIR stands in for
    %% EACCES, which a test running as root could not produce).
    put_file(D, "proc_cgroup", "0::/\n"),
    ok = filelib:ensure_path(filename:join([D, "cg", "memory.max"])),
    put_file(D, "meminfo", ?MEMINFO),
    #{bytes := B, source := S, unreadable := U} =
        yuzu_gw_memory_shedder:memory_limit(paths(D)),
    ?assertEqual({17179869184, host}, {B, S}),
    ?assertMatch([{_, _}], U).

nothing(D) ->
    ?assertMatch(#{bytes := undefined, source := none, cgroup := none, host := undefined},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

outside_namespace(D) ->
    put_file(D, "proc_cgroup", "0::/../other\n"),
    put_file(D, "cg/memory.max", "1073741824\n"),
    put_file(D, "meminfo", ?MEMINFO),
    ?assertMatch(#{bytes := ?GIB, source := cgroup_v2},
                 yuzu_gw_memory_shedder:memory_limit(paths(D))).

marks_from_cgroup(D) ->
    setup_apps(),
    put_file(D, "proc_cgroup", "0::/\n"),
    put_file(D, "cg/memory.max", "1073741824\n"),
    put_file(D, "meminfo", ?MEMINFO),
    {ok, Pid} = yuzu_gw_memory_shedder:start_link(
                  #{register => false, config => #{}, listener_refs => [],
                    memory_paths => paths(D)}),
    try
        ?assertMatch(#{high := 805306368, low := 697932186},
                     yuzu_gw_memory_shedder:status(Pid))
    after stop(Pid) end.

%% Host memory on macOS, which has no /proc/meminfo and no cgroup: hw.memsize.
darwin_host_memory_test() ->
    case os:type() of
        {unix, darwin} ->
            D = fixture_dir(),
            try
                #{bytes := B, source := S} =
                    yuzu_gw_memory_shedder:memory_limit(maps:remove(darwin_sysctl, paths(D))),
                ?assertEqual(host, S),
                ?assert(is_integer(B) andalso B > 0)
            after rm_fixture(D) end;
        _ ->
            ok
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

mem_cell() ->
    Mem = atomics:new(1, []),
    atomics:put(Mem, 1, 0),
    {Mem, fun() -> atomics:get(Mem, 1) end}.

start_shedder(Refs, MemFun) ->
    yuzu_gw_memory_shedder:start_link(
      #{register => false,
        config => #{high_water_bytes => 100, low_water_bytes => 50, interval_ms => 60000},
        listener_refs => Refs, mem_fun => MemFun}).

%% A private directory of fixture files standing in for /sys/fs/cgroup,
%% /proc/self/cgroup and /proc/meminfo.
fixture_dir() ->
    Base = case os:getenv("TMPDIR") of
               false -> "/tmp";
               "" -> "/tmp";
               T -> T
           end,
    D = filename:join(Base, "yuzu_test_shedder_" ++ os:getpid() ++ "_"
                            ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_path(filename:join(D, "cg")),
    D.

rm_fixture(D) ->
    _ = file:del_dir_r(D),
    ok.

put_file(D, Rel, Content) ->
    F = filename:join(D, Rel),
    ok = filelib:ensure_dir(F),
    ok = file:write_file(F, Content).

paths(D) ->
    #{cgroup_root => filename:join(D, "cg"),
      proc_cgroup => filename:join(D, "proc_cgroup"),
      meminfo => filename:join(D, "meminfo"),
      darwin_sysctl => false}.

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
