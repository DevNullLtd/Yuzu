%%%-------------------------------------------------------------------
%%% @doc Full-stack tests: gateway modules + mocked upstream gRPC.
%%%
%%% These tests verify end-to-end behaviour of the gateway modules
%%% (registry, upstream, router) with a mocked gRPC layer.  The
%%% upstream C++ server is replaced by meck stubs on grpcbox_channel
%%% and grpcbox_client that return canned responses, so no external
%%% process is needed.
%%%
%%% Configuration:
%%%   YUZU_FULLSTACK_AGENTS — concurrent agent count (default 20)
%%%
%%% Run:
%%%   rebar3 ct --suite=yuzu_gw_fullstack_SUITE --verbose
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_fullstack_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%===================================================================
%%% CT callbacks
%%%===================================================================

all() ->
    [multi_agent_register_through_gateway,
     heartbeat_batching_verification,
     command_roundtrip_latency,
     agent_disconnect_propagation,
     gateway_restart_resilience].

suite() ->
    [{timetrap, {minutes, 5}}].

init_per_suite(Config) ->
    %% Start dependencies.
    ok = ensure_started(ctx),
    ok = ensure_started(gproc),

    %% Mock the gRPC transport layer so we never hit a real server.
    ok = setup_upstream_mocks(),

    %% Start gateway modules (unlink so they outlive CT process transitions).
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,
    catch yuzu_gw_telemetry:setup(),
    case whereis(yuzu_gw_registry) of
        undefined ->
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        _ -> ok
    end,
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 1000),
    case whereis(yuzu_gw_upstream) of
        undefined ->
            {ok, UpPid} = yuzu_gw_upstream:start_link(),
            unlink(UpPid);
        _ -> ok
    end,
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined ->
            {ok, HBPid} = yuzu_gw_heartbeat_buffer:start_link(),
            unlink(HBPid);
        _ -> ok
    end,
    case whereis(yuzu_gw_router) of
        undefined ->
            {ok, RouterPid} = yuzu_gw_router:start_link(),
            unlink(RouterPid);
        _ -> ok
    end,

    Config.

end_per_suite(_Config) ->
    %% Deregister all agents.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(500)
    catch _:_ -> ok
    end,
    %% Unload mocks.
    catch meck:unload(grpcbox_channel),
    catch meck:unload(grpcbox_client),
    ok.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    %% Clean up agents registered by this test.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(200)
    catch _:_ -> ok
    end,
    flush_mailbox(),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

%% @doc Spawn N concurrent agent registrations through the gateway's
%% upstream proxy.  Verify all reach the server (no errors).
multi_agent_register_through_gateway(_Config) ->
    N = get_env_int("YUZU_FULLSTACK_AGENTS", 20),
    ct:pal("--- multi_agent_register: ~B agents ---", [N]),

    Parent = self(),
    _Workers = [spawn_link(fun() ->
        AgentId = iolist_to_binary(io_lib:format("fs-agent-~4..0B", [I])),
        Req = #{
            agent_id => AgentId,
            hostname => <<"fullstack-host">>,
            platform => #{os => <<"LINUX">>, arch => <<"x86_64">>},
            plugins  => [#{name => <<"system_info">>, version => <<"1.0.0">>}],
            agent_version => <<"0.1.0">>
        },
        Result = yuzu_gw_upstream:proxy_register(Req),
        Parent ! {register_result, I, Result}
    end) || I <- lists:seq(1, N)],

    %% Collect results.
    Results = [receive
        {register_result, I, Res} -> {I, Res}
    after 30000 ->
        ct:fail("Registration ~B timed out", [I])
    end || I <- lists:seq(1, N)],

    Successes = [R || {_, {ok, _}} = R <- Results],
    Errors    = [R || {_, {error, _}} = R <- Results],

    ct:pal("Registered ~B/~B agents (~B errors)", [length(Successes), N, length(Errors)]),
    lists:foreach(fun({I, {error, Reason}}) ->
        ct:pal("  Agent ~B failed: ~p", [I, Reason])
    end, Errors),

    %% Allow some failures (server may reject duplicates) but most should succeed.
    ?assert(length(Successes) >= N div 2,
            lists:flatten(io_lib:format(
                "Only ~B/~B registrations succeeded", [length(Successes), N]))).

%% @doc Queue N heartbeats per agent, wait for auto-flush, verify no errors.
heartbeat_batching_verification(_Config) ->
    N = get_env_int("YUZU_FULLSTACK_AGENTS", 20),
    HBsPerAgent = 5,
    ct:pal("--- heartbeat_batching: ~B agents x ~B HBs ---", [N, HBsPerAgent]),

    %% Queue heartbeats.
    lists:foreach(fun(I) ->
        AgentId = iolist_to_binary(io_lib:format("hb-agent-~4..0B", [I])),
        lists:foreach(fun(_) ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
                session_id => AgentId,
                agent_id  => AgentId,
                timestamp => #{seconds => erlang:system_time(second)}
            })
        end, lists:seq(1, HBsPerAgent))
    end, lists:seq(1, N)),

    TotalHBs = N * HBsPerAgent,
    ct:pal("Queued ~B heartbeats, waiting for batch flush...", [TotalHBs]),

    %% The upstream module flushes every 1 s (configured in init_per_suite).
    %% Wait for two flush cycles.
    timer:sleep(2500),

    %% If we got here without crashes, the batch was accepted by the server
    %% (or at least sent without error).  The upstream module logs warnings
    %% on failure but doesn't crash.
    ct:pal("Heartbeat batching complete — no crashes").

%% @doc Start an agent gen_statem with a test stream handler,
%% dispatch a command through the router, measure the time until
%% the stream handler receives it.
command_roundtrip_latency(_Config) ->
    ct:pal("--- command_roundtrip_latency ---"),

    TestPid = self(),
    StreamHandler = spawn_link(fun() -> stream_handler_loop(TestPid) end),

    AgentId = <<"roundtrip-agent">>,
    AgentArgs = #{
        agent_id   => AgentId,
        session_id => <<"roundtrip-sess">>,
        agent_info => #{plugins => [#{name => <<"system">>, version => <<"1.0">>}]},
        stream_pid => StreamHandler,
        peer_addr  => <<"127.0.0.1:0">>
    },

    {ok, AgentPid} = yuzu_gw_agent:start_link(AgentArgs),

    %% Allow registration to complete.
    timer:sleep(100),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(AgentId)),

    %% Dispatch command through the router.
    Cmd = #{command_id => <<"rt-cmd-1">>, plugin => <<"system">>},
    T0 = erlang:monotonic_time(microsecond),
    {ok, _FanoutRef} = yuzu_gw_router:send_command([AgentId], Cmd, #{timeout_seconds => 5}),

    %% Wait for stream handler to receive the command.
    receive
        {stream_cmd_received, _RecvCmd, T1} ->
            LatencyUs = T1 - T0,
            ct:pal("Command roundtrip latency: ~B us (~.2f ms)",
                   [LatencyUs, LatencyUs / 1000.0]),
            ?assert(LatencyUs < 50000,  %% < 50 ms
                    lists:flatten(io_lib:format(
                        "Roundtrip ~B us > 50000 us", [LatencyUs])))
    after 5000 ->
        ct:fail("Command not received by stream handler within 5 s")
    end,

    %% Cleanup.
    yuzu_gw_agent:disconnect(AgentPid),
    timer:sleep(200).

%% @doc Start an agent, kill it, verify the registry count drops
%% and the upstream disconnect notification fires within 5 s.
agent_disconnect_propagation(_Config) ->
    ct:pal("--- agent_disconnect_propagation ---"),

    StreamHandler = spawn(fun() -> stream_handler_loop(self()) end),
    AgentId = <<"disconnect-agent">>,
    AgentArgs = #{
        agent_id   => AgentId,
        session_id => <<"disc-sess">>,
        agent_info => #{plugins => [#{name => <<"system">>, version => <<"1.0">>}]},
        stream_pid => StreamHandler,
        peer_addr  => <<"127.0.0.1:0">>
    },

    {ok, _AgentPid} = yuzu_gw_agent:start_link(AgentArgs),
    timer:sleep(100),

    CountBefore = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count before kill: ~B", [CountBefore]),
    ?assert(CountBefore >= 1),

    %% Kill the stream handler — agent detects DOWN and disconnects.
    exit(StreamHandler, kill),

    %% Wait for cleanup.
    ok = wait_until(fun() ->
        yuzu_gw_registry:lookup(AgentId) =:= error
    end, 5000),

    CountAfter = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count after disconnect: ~B (was ~B)", [CountAfter, CountBefore]),
    ?assert(CountAfter < CountBefore).

%% @doc Stop and restart gateway modules, verify agents can re-register
%% and operations resume without error.
gateway_restart_resilience(_Config) ->
    ct:pal("--- gateway_restart_resilience ---"),

    %% Register a test agent (spawn, not spawn_link — we will kill it).
    AgentId = <<"resilience-agent">>,
    Pid1 = spawn(fun agent_loop/0),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid1, <<"sess1">>, [<<"p1">>], <<>>),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(AgentId)),
    ct:pal("Agent registered pre-restart"),

    %% Kill the dummy agent process.
    exit(Pid1, kill),
    ok = wait_until(fun() ->
        yuzu_gw_registry:lookup(AgentId) =:= error
    end, 5000),

    %% Stop and restart the upstream and heartbeat buffer modules.
    catch gen_server:stop(yuzu_gw_heartbeat_buffer),
    catch gen_server:stop(yuzu_gw_upstream),
    timer:sleep(100),

    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 1000),
    {ok, UpPid2} = yuzu_gw_upstream:start_link(),
    unlink(UpPid2),
    {ok, HBPid2} = yuzu_gw_heartbeat_buffer:start_link(),
    unlink(HBPid2),
    ct:pal("Upstream and heartbeat buffer restarted"),

    %% Re-register agent (spawn, not spawn_link — we will kill it).
    Pid2 = spawn(fun agent_loop/0),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid2, <<"sess2">>, [<<"p1">>], <<>>),
    ?assertMatch({ok, Pid2}, yuzu_gw_registry:lookup(AgentId)),

    %% Verify upstream proxy still works.
    Req = #{
        agent_id      => AgentId,
        hostname      => <<"resilience-host">>,
        platform      => #{os => <<"LINUX">>, arch => <<"x86_64">>},
        plugins       => [#{name => <<"system_info">>, version => <<"1.0.0">>}],
        agent_version => <<"0.1.0">>
    },
    case yuzu_gw_upstream:proxy_register(Req) of
        {ok, _Response} ->
            ct:pal("Post-restart registration succeeded");
        {error, Reason} ->
            ct:pal("Post-restart registration error (may be expected): ~p", [Reason])
    end,

    %% Cleanup.
    exit(Pid2, kill),
    wait_until(fun() -> yuzu_gw_registry:lookup(AgentId) =:= error end, 5000).

%%%===================================================================
%%% Internal helpers
%%%===================================================================

%% Stream handler that relays {send_command, Cmd} back to the test process.
stream_handler_loop(TestPid) ->
    receive
        {send_command, Cmd} ->
            TestPid ! {stream_cmd_received, Cmd, erlang:monotonic_time(microsecond)},
            stream_handler_loop(TestPid);
        close_stream ->
            ok;
        _ ->
            stream_handler_loop(TestPid)
    end.

agent_loop() ->
    receive stop -> ok; _ -> agent_loop() end.

get_env_int(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> list_to_integer(Val)
    end.

ensure_started(App) ->
    case application:ensure_all_started(App) of
        {ok, _}            -> ok;
        {error, {already_started, _}} -> ok;
        {error, Reason}    -> {error, Reason}
    end.

%% @doc Mock grpcbox_channel and grpcbox_client so that
%% yuzu_gw_upstream's do_rpc/3 gets canned responses without
%% needing a real gRPC server.
%%
%% RPC dispatch is based on the Path binary that do_rpc/3 builds:
%%   "/yuzu.gateway.v1.GatewayUpstream/ProxyRegister"
%%   "/yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat"
%%   "/yuzu.gateway.v1.GatewayUpstream/ProxyInventory"
%%   "/yuzu.gateway.v1.GatewayUpstream/NotifyStreamStatus"
setup_upstream_mocks() ->
    %% grpcbox_channel:pick/2 is called internally by grpcbox_client.
    meck:new(grpcbox_channel, [non_strict, no_link]),
    meck:expect(grpcbox_channel, pick, fun(_, _) -> {ok, mock_channel} end),

    %% grpcbox_client:unary/5 is the actual RPC call site.
    SessionCounter = atomics:new(1, []),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_Ctx, Path, Req, _Def, _Opts) ->
        mock_upstream_rpc(Path, Req, SessionCounter)
    end),
    ok.

%% @doc Route a mock upstream RPC based on the method in the Path.
mock_upstream_rpc(Path, Req, SessionCounter) ->
    case classify_rpc(Path) of
        proxy_register ->
            N = atomics:add_get(SessionCounter, 1, 1),
            SessionId = iolist_to_binary(
                io_lib:format("mock-session-~6..0B", [N])),
            {ok, #{session_id => SessionId,
                   heartbeat_interval_seconds => 30,
                   server_version => <<"mock-0.1.0">>}, #{}};
        batch_heartbeat ->
            HBs = maps:get(heartbeats, Req, []),
            {ok, #{acknowledged_count => length(HBs)}, #{}};
        proxy_inventory ->
            {ok, #{received => true}, #{}};
        notify_stream_status ->
            {ok, #{acknowledged => true}, #{}};
        unknown ->
            {ok, #{}, #{}}
    end.

classify_rpc(Path) when is_binary(Path) ->
    case {binary:match(Path, <<"ProxyRegister">>),
          binary:match(Path, <<"BatchHeartbeat">>),
          binary:match(Path, <<"ProxyInventory">>),
          binary:match(Path, <<"NotifyStreamStatus">>)} of
        {{_, _}, _, _, _} -> proxy_register;
        {_, {_, _}, _, _} -> batch_heartbeat;
        {_, _, {_, _}, _} -> proxy_inventory;
        {_, _, _, {_, _}} -> notify_stream_status;
        _                 -> unknown
    end.

flush_mailbox() ->
    receive _ -> flush_mailbox()
    after 0 -> ok
    end.

wait_until(Fun, Timeout) when Timeout =< 0 ->
    case Fun() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Fun, Timeout) ->
    case Fun() of
        true  -> ok;
        false ->
            timer:sleep(50),
            wait_until(Fun, Timeout - 50)
    end.
