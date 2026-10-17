%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the HTTP health/readiness endpoint.
%%%
%%% Tests /healthz (liveness), /readyz (readiness, including the check that the
%%% configured gRPC listeners are running), and 404 for unknown paths.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_health_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

health_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"healthz returns 200", fun healthz_ok/0},
      {"readyz returns 200 when core processes alive", fun readyz_ok/0},
      {"unknown path returns 404", fun unknown_path_404/0},
      {"readyz 503 when no listener is configured and none is allowed", fun readyz_503_no_listeners/0},
      {"readyz 200 when the configured listeners are running", fun readyz_listeners_running/0},
      {"readyz 503 once a configured listener is stopped", fun readyz_503_listener_stopped/0},
      {"readyz 503 when one of two configured listeners is stopped",
       fun readyz_503_one_of_two_stopped/0},
      {"readyz 503 when no configured listener serves the agent service",
       fun readyz_503_no_agent_listener/0},
      {"readyz 200 without an agent listener only under allow_no_listeners",
       fun readyz_agentless_only_when_allowed/0},
      {"readyz counts the AgentService as an agent listener whatever the protos",
       fun readyz_agent_service_under_management_protos/0},
      {"readyz 503 while a listener is suspended and 200 again once resumed",
       fun readyz_503_listener_suspended/0},
      {"readyz 503 while the memory shedder cannot resume the agent listener, 200 once it can",
       fun readyz_503_while_shedder_resume_fails/0},
      {"readyz 503 for a configured listener that was never started",
       fun readyz_503_never_started/0},
      {"readyz 503 for an entry that lists agent_pb but routes no AgentService",
       fun readyz_503_agent_pb_without_route/0},
      {"readyz 503 for a combined agent and management entry that routes only the management service",
       fun readyz_503_combined_without_agent_route/0},
      {"readyz 503, not a crash, for a listeners value that is an improper list",
       fun readyz_503_improper_list/0},
      {"readyz 503 while an upstream channel's TLS options are unusable, 200 once they are not",
       fun readyz_503_unusable_upstream_tls/0},
      {"healthz stays 200 while a configured listener is down", fun healthz_ok_listener_down/0}
     ]}.

setup() ->
    %% Bind to port 0 — the OS picks an ephemeral free port and we read
    %% it back from the started gen_server via yuzu_gw_health:port/0.
    %% A previous version of this test hardcoded port 18080, which is
    %% squatted on the Windows CI runner by an unidentified HTTP server
    %% that returns 302 Found for every request — making the eunit
    %% assertion `?assertEqual(200, Status)` fail with `value, 302`.
    %% Ephemeral binding eliminates that whole class of port collision.
    application:set_env(yuzu_gw, health_port, 0),

    %% Readiness requires the configured listeners; these tests run with none
    %% unless a case configures its own.
    PrevListeners = application:get_env(yuzu_gw, grpc_listeners),
    PrevAllow = application:get_env(yuzu_gw, allow_no_listeners),
    application:unset_env(yuzu_gw, grpc_listeners),
    application:set_env(yuzu_gw, allow_no_listeners, true),

    %% Start mock processes for readiness checks.
    %% Only register names that aren't already taken by other test suites.
    MockNames = [yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_router],
    MockPids = lists:filtermap(fun(Name) ->
        case whereis(Name) of
            undefined ->
                Pid = spawn_link(mock_for(Name)),
                register(Name, Pid),
                {true, {Name, Pid, true}};  % true = we own it
            _Existing ->
                {true, {Name, undefined, false}}  % false = already registered
        end
    end, MockNames),

    %% Start upstream with a mocked yuzu_grpc_client for circuit_state/0
    NeedUpstream = (whereis(yuzu_gw_upstream) =:= undefined),
    UpPid = case NeedUpstream of
        true ->
            catch meck:unload(yuzu_grpc_client),
            catch meck:unload(telemetry),
            meck:new(yuzu_grpc_client, [non_strict, no_link]),
            meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
                {ok, #{}, #{}}
            end),
            meck:new(telemetry, [passthrough, no_link]),
            meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
            application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 5),
            application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 10000),
            application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 300000),
            {ok, P} = yuzu_gw_upstream:start_link(),
            P;
        false ->
            whereis(yuzu_gw_upstream)
    end,

    %% Start the health endpoint, then read back the actual ephemeral
    %% port the OS assigned. The 100ms sleep keeps the original timing
    %% margin so the listener's accept loop is up before any test fires.
    {ok, HealthPid} = yuzu_gw_health:start_link(),
    timer:sleep(100),
    {ok, Port} = yuzu_gw_health:port(),
    {Port, HealthPid, UpPid, NeedUpstream, MockPids, {PrevListeners, PrevAllow}}.

cleanup({_Port, HealthPid, UpPid, NeedUpstream, MockPids, {PrevListeners, PrevAllow}}) ->
    restore_env(grpc_listeners, PrevListeners),
    restore_env(allow_no_listeners, PrevAllow),
    catch unlink(HealthPid),
    catch exit(HealthPid, shutdown),
    case NeedUpstream of
        true ->
            catch unlink(UpPid),
            catch exit(UpPid, shutdown),
            meck:unload([yuzu_grpc_client, telemetry]);
        false ->
            ok
    end,
    lists:foreach(fun
        ({Name, Pid, true}) ->
            catch unregister(Name),
            catch unlink(Pid),
            catch exit(Pid, kill);
        ({_Name, _Pid, false}) ->
            ok
    end, MockPids),
    timer:sleep(50),
    ok.

restore_env(Key, {ok, Value}) -> application:set_env(yuzu_gw, Key, Value);
restore_env(Key, undefined) -> application:unset_env(yuzu_gw, Key).

%% The registry stand-in also owns the session index table readiness checks.
mock_for(yuzu_gw_registry) -> fun yuzu_gw_test_registry:mock_registry_loop/0;
mock_for(_Name)            -> fun mock_loop/0.

mock_loop() ->
    receive
        stop -> ok;
        _ -> mock_loop()
    after 60000 -> ok
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

%% setup() bound the listener on port 0 (OS-assigned). Each test reads
%% the actual port from the running gen_server. Eunit's `{setup, …, [Tests]}`
%% form does not pass the setup return value to the tests, so the indirection
%% via yuzu_gw_health:port/0 is the cheapest way to thread the port through.
healthz_ok() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, Body} = http_get(Port, "/healthz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ok">>) =/= nomatch).

readyz_ok() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, Body} = http_get(Port, "/readyz"),
    ?assertEqual(200, Status),
    ?assert(binary:match(Body, <<"ready">>) =/= nomatch),
    %% Core checks should be true
    ?assert(binary:match(Body, <<"\"registry\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"sessions_index\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"upstream\":true">>) =/= nomatch),
    ?assert(binary:match(Body, <<"\"circuit_breaker\":true">>) =/= nomatch).

unknown_path_404() ->
    {ok, Port} = yuzu_gw_health:port(),
    {Status, _Body} = http_get(Port, "/unknown"),
    ?assertEqual(404, Status).

%%% Listener readiness: /readyz asks Ranch whether each configured listener
%%% ({yuzu_grpc, Name}) is running; it does not connect to the port.

-define(AGENT_SVC, 'yuzu.agent.v1.AgentService').
-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').

agent_entry(Name) ->
    #{name => Name, service_protos => [agent_pb], services => #{?AGENT_SVC => yuzu_grpc_stub_svc},
      listen => #{port => 0}}.

mgmt_entry(Name) ->
    #{name => Name, service_protos => [management_pb],
      services => #{?MGMT_SVC => yuzu_grpc_stub_svc}, listen => #{port => 0}}.

%% Run Fun with Entries configured as {yuzu_gw, grpc_listeners}, started (a
%% listener per entry) or not; the environment is put back afterwards.
with_listeners(Entries, Fun) ->
    Prev = application:get_env(yuzu_gw, grpc_listeners),
    PrevAllow = application:get_env(yuzu_gw, allow_no_listeners),
    application:set_env(yuzu_gw, grpc_listeners, Entries),
    try Fun()
    after
        restore_env(grpc_listeners, Prev),
        restore_env(allow_no_listeners, PrevAllow)
    end.

ready(Port) ->
    {Status, Body} = http_get(Port, "/readyz"),
    {Status, binary:match(Body, <<"\"listeners\":true">>) =/= nomatch}.

readyz_503_no_listeners() ->
    {ok, Port} = yuzu_gw_health:port(),
    with_listeners([], fun() ->
        application:unset_env(yuzu_gw, allow_no_listeners),
        ?assertEqual({503, false}, ready(Port)),
        application:set_env(yuzu_gw, allow_no_listeners, false),
        ?assertEqual({503, false}, ready(Port)),
        %% only the literal true is the acknowledgement
        application:set_env(yuzu_gw, allow_no_listeners, yes),
        ?assertEqual({503, false}, ready(Port)),
        application:set_env(yuzu_gw, allow_no_listeners, true),
        ?assertEqual({200, true}, ready(Port))
    end).

readyz_listeners_running() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, A} = yuzu_gw_test_listener:start(agent_entry(ready_agent)),
    {_, M} = yuzu_gw_test_listener:start(mgmt_entry(ready_mgmt)),
    try
        with_listeners([agent_entry(ready_agent), mgmt_entry(ready_mgmt)], fun() ->
            %% setup() allows a gateway with no agent listener; here the agent
            %% listener is what makes the answer ready
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({200, true}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(A),
        yuzu_gw_test_listener:stop(M)
    end.

readyz_503_listener_stopped() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, A} = yuzu_gw_test_listener:start(agent_entry(stop_agent)),
    with_listeners([agent_entry(stop_agent)], fun() ->
        ?assertEqual({200, true}, ready(Port)),
        yuzu_gw_test_listener:stop(A),
        ?assertEqual({503, false}, ready(Port))
    end).

%% A stand-in for a channel's table: config_error/1 reads one row of a named
%% table, so the readiness wiring is tested without opening a connection.
readyz_503_unusable_upstream_tls() ->
    {ok, Port} = yuzu_gw_health:port(),
    Chan = yuzu_health_test_chan,
    Tab = ets:new(Chan, [named_table, public, set]),
    PrevClient = application:get_env(yuzu_gw, upstream_client),
    application:set_env(yuzu_gw, upstream_client,
                        #{channels => [{Chan, [{http, "127.0.0.1", 59999, []}], #{}}]}),
    %% {HTTP status, whether the body says upstream_tls_files is true}
    Tls = fun() ->
              {Status, Body} = http_get(Port, "/readyz"),
              {Status, binary:match(Body, <<"\"upstream_tls_files\":true">>) =/= nomatch}
          end,
    try
        ?assertEqual({200, true}, Tls()),
        true = ets:insert(Tab, {config_error, [{cacertfile, "/nonexistent/ca.pem", enoent}]}),
        ?assertEqual({503, false}, Tls()),
        true = ets:insert(Tab, {config_error, []}),
        ?assertEqual({503, false}, Tls()),
        true = ets:delete(Tab, config_error),
        ?assertEqual({200, true}, Tls())
    after
        ets:delete(Tab),
        restore_env(upstream_client, PrevClient)
    end.

readyz_503_one_of_two_stopped() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, A} = yuzu_gw_test_listener:start(agent_entry(two_agent)),
    {_, M} = yuzu_gw_test_listener:start(mgmt_entry(two_mgmt)),
    try
        with_listeners([agent_entry(two_agent), mgmt_entry(two_mgmt)], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({200, true}, ready(Port)),
            yuzu_gw_test_listener:stop(M),
            %% the agent listener is up, the management one is not
            ?assertEqual({503, false}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(A),
        catch yuzu_gw_test_listener:stop(M)
    end.

readyz_503_no_agent_listener() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, M} = yuzu_gw_test_listener:start(mgmt_entry(only_mgmt)),
    try
        with_listeners([mgmt_entry(only_mgmt)], fun() ->
            %% setup() allows a gateway with no listeners; that is not what is
            %% under test here
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({503, false}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(M)
    end.

%% service_protos naming agent_pb is not routing the AgentService: the route
%% table of such an entry answers every agent RPC UNIMPLEMENTED. The rule is the
%% boot guard's (yuzu_grpc_listener:routes_agent/1).
readyz_503_agent_pb_without_route() ->
    {ok, Port} = yuzu_gw_health:port(),
    Entry = #{name => unrouted_agent, service_protos => [agent_pb], services => #{},
              listen => #{port => 0}},
    {_, L} = yuzu_gw_test_listener:start(Entry),
    try
        with_listeners([Entry], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual(running, ranch:get_status({yuzu_grpc, unrouted_agent})),
            ?assertEqual({503, false}, ready(Port)),
            %% only the literal true excuses it
            application:set_env(yuzu_gw, allow_no_listeners, yes),
            ?assertEqual({503, false}, ready(Port)),
            application:set_env(yuzu_gw, allow_no_listeners, true),
            ?assertEqual({200, true}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(L)
    end.

readyz_503_combined_without_agent_route() ->
    {ok, Port} = yuzu_gw_health:port(),
    Entry = #{name => combined_unrouted, service_protos => [agent_pb, management_pb],
              services => #{?MGMT_SVC => yuzu_grpc_stub_svc}, listen => #{port => 0}},
    {_, L} = yuzu_gw_test_listener:start(Entry),
    try
        with_listeners([Entry], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({503, false}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(L)
    end.

%% A malformed value of the key must answer not-ready; a crash would take the
%% health endpoint down with it.
readyz_503_improper_list() ->
    {ok, Port} = yuzu_gw_health:port(),
    Pid = whereis(yuzu_gw_health),
    %% the first entry is a running agent listener, so a walk of the list that
    %% does not stop at a failure goes on to the improper tail
    {_, A} = yuzu_gw_test_listener:start(agent_entry(improper_agent)),
    try
        with_listeners([agent_entry(improper_agent) | not_a_list], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({503, false}, ready(Port))
        end),
        ?assertEqual(Pid, whereis(yuzu_gw_health)),
        ?assert(is_process_alive(Pid))
    after
        yuzu_gw_test_listener:stop(A)
    end.

%% Boot excuses a gateway with no agent listener under the same acknowledgement
%% as one with no listener at all, so /readyz does too: a running gateway that
%% was told it serves no agent is not "never ready".
readyz_agentless_only_when_allowed() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, M} = yuzu_gw_test_listener:start(mgmt_entry(allowed_mgmt)),
    try
        with_listeners([mgmt_entry(allowed_mgmt)], fun() ->
            application:set_env(yuzu_gw, allow_no_listeners, false),
            ?assertEqual({503, false}, ready(Port)),
            application:set_env(yuzu_gw, allow_no_listeners, true),
            ?assertEqual({200, true}, ready(Port)),
            %% the acknowledgement excuses the absence of an agent listener, not
            %% a listener that is down
            yuzu_gw_test_listener:stop(M),
            ?assertEqual({503, false}, ready(Port))
        end)
    after
        catch yuzu_gw_test_listener:stop(M)
    end.

%% management_pb embeds the AgentService definition: an entry that names it in
%% `services' serves the agents whatever its service_protos say.
readyz_agent_service_under_management_protos() ->
    {ok, Port} = yuzu_gw_health:port(),
    Entry = (mgmt_entry(embedded_agent))#{
              services => #{?AGENT_SVC => yuzu_grpc_stub_svc}},
    {_, L} = yuzu_gw_test_listener:start(Entry),
    try
        with_listeners([Entry], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({200, true}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(L)
    end.

%% A listener Ranch has suspended accepts nothing and is not running: the
%% gateway is not ready until it is resumed.
readyz_503_listener_suspended() ->
    {ok, Port} = yuzu_gw_health:port(),
    {_, A} = yuzu_gw_test_listener:start(agent_entry(suspended_agent)),
    Ref = {yuzu_grpc, suspended_agent},
    try
        with_listeners([agent_entry(suspended_agent)], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({200, true}, ready(Port)),
            ok = ranch:suspend_listener(Ref),
            try
                ?assertEqual(suspended, ranch:get_status(Ref)),
                ?assertEqual({503, false}, ready(Port))
            after
                ok = ranch:resume_listener(Ref)
            end,
            ?assertEqual(running, ranch:get_status(Ref)),
            ?assertEqual({200, true}, ready(Port))
        end)
    after
        yuzu_gw_test_listener:stop(A)
    end.

%% The memory shedder sheds by suspending the agent listener, which closes its
%% listen socket; resuming opens it again and can fail. Here another socket
%% takes the port while it is closed, so the real ranch:resume_listener/1
%% fails with eaddrinuse. /readyz must stay 503 for as long as the listener is
%% not accepting, and the shedder must retry on its next tick and bring
%% readiness back once the port is free.
readyz_503_while_shedder_resume_fails() ->
    {ok, Port} = yuzu_gw_health:port(),
    {AgentPort, A} = yuzu_gw_test_listener:start(agent_entry(shed_resume_agent)),
    Ref = {yuzu_grpc, shed_resume_agent},
    Mem = atomics:new(1, []),
    {ok, Shedder} = yuzu_gw_memory_shedder:start_link(
                      #{register => false,
                        config => #{high_water_bytes => 100, low_water_bytes => 50,
                                    interval_ms => 60000},
                        listener_refs => [Ref],
                        mem_fun => fun() -> atomics:get(Mem, 1) end}),
    try
        with_listeners([agent_entry(shed_resume_agent)], fun() ->
            application:unset_env(yuzu_gw, allow_no_listeners),
            ?assertEqual({200, true}, ready(Port)),
            atomics:put(Mem, 1, 200),
            ?assertEqual({ok, true}, yuzu_gw_memory_shedder:sample_now(Shedder)),
            ?assertEqual({503, false}, ready(Port)),
            {ok, Squat} = gen_tcp:listen(AgentPort, [{ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
            try
                atomics:put(Mem, 1, 10),
                ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Shedder)),
                ?assertEqual(suspended, ranch:get_status(Ref)),
                ?assertEqual({503, false}, ready(Port))
            after
                gen_tcp:close(Squat)
            end,
            ?assertEqual({ok, false}, yuzu_gw_memory_shedder:sample_now(Shedder)),
            ?assertEqual(running, ranch:get_status(Ref)),
            ?assertEqual({200, true}, ready(Port))
        end)
    after
        unlink(Shedder),
        catch gen_server:stop(Shedder, shutdown, 5000),
        yuzu_gw_test_listener:stop(A)
    end.

readyz_503_never_started() ->
    {ok, Port} = yuzu_gw_health:port(),
    with_listeners([agent_entry(never_started_agent)], fun() ->
        ?assertEqual({503, false}, ready(Port))
    end),
    %% an entry that is not a listener at all is not a running one
    with_listeners([not_a_listener], fun() ->
        ?assertEqual({503, false}, ready(Port))
    end).

%% Liveness is about this process only; a listener that is down does not make
%% the node restart-worthy to a liveness probe.
healthz_ok_listener_down() ->
    {ok, Port} = yuzu_gw_health:port(),
    with_listeners([agent_entry(down_agent)], fun() ->
        ?assertMatch({200, _}, http_get(Port, "/healthz"))
    end).

%%%===================================================================
%%% HTTP client helper (minimal, no deps)
%%%===================================================================

http_get(Port, Path) ->
    {ok, Sock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
    Req = iolist_to_binary([
        "GET ", Path, " HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close\r\n",
        "\r\n"
    ]),
    ok = gen_tcp:send(Sock, Req),
    {ok, Data} = recv_all(Sock, <<>>),
    gen_tcp:close(Sock),
    parse_response(Data).

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Chunk}    -> recv_all(Sock, <<Acc/binary, Chunk/binary>>);
        {error, closed} -> {ok, Acc};
        {error, _} = Err -> Err
    end.

parse_response(Data) ->
    case binary:split(Data, <<"\r\n">>) of
        [StatusLine, Rest] ->
            Status = parse_status(StatusLine),
            Body = case binary:split(Rest, <<"\r\n\r\n">>) of
                [_Headers, B] -> B;
                _             -> <<>>
            end,
            {Status, Body};
        _ ->
            {0, <<>>}
    end.

parse_status(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [_, Code | _] -> binary_to_integer(Code);
        _             -> 0
    end.
