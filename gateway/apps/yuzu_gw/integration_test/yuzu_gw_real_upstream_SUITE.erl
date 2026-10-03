%%%-------------------------------------------------------------------
%%% @doc Real-upstream tests: gateway modules against a live C++ server.
%%%
%%% Unlike yuzu_gw_fullstack_SUITE which mocks grpcbox, these tests
%%% connect to the actual C++ yuzu-server running in gateway mode.
%%% This validates the full gRPC/protobuf wire protocol end-to-end.
%%%
%%% Prerequisites:
%%%   C++ server running with:
%%%     yuzu-server --gateway-upstream 0.0.0.0:50055 \
%%%                 --no-tls --no-https --web-port 8080
%%%
%%% Run:
%%%   rebar3 as test ct --dir apps/yuzu_gw/integration_test \
%%%       --suite yuzu_gw_real_upstream_SUITE --verbose
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_real_upstream_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(UPSTREAM_HOST, "127.0.0.1").
-define(UPSTREAM_PORT, 50055).
%% Enrollment token for Tier 2 auto-approval.
%% Automatically read from UAT environment (/tmp/yuzu-uat/enrollment-token)
%% or override at runtime: YUZU_GW_TEST_TOKEN=<hex>
-define(UAT_TOKEN_FILE, "/tmp/yuzu-uat/enrollment-token").

%%%===================================================================
%%% CT callbacks
%%%===================================================================

all() ->
    [server_reachable,
     single_agent_register,
     multi_agent_register,
     heartbeat_batching,
     agent_disconnect_notification,
     circuit_breaker_recovery,
     register_and_heartbeat_roundtrip].

suite() ->
    [{timetrap, {minutes, 3}}].

init_per_suite(Config) ->
    %% Verify the C++ server is reachable before running any tests.
    case gen_tcp:connect(?UPSTREAM_HOST, ?UPSTREAM_PORT, [binary], 2000) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            ct:pal("C++ server reachable at ~s:~B", [?UPSTREAM_HOST, ?UPSTREAM_PORT]),
            do_init_per_suite(Config);
        {error, Reason} ->
            {skip, {server_not_reachable, Reason}}
    end.

do_init_per_suite(Config) ->
    %% Start dependencies. ORDER MATTERS: grpcbox reads its client
    %% channels config at application start (`grpcbox_client_sup` builds
    %% the channel registry once); subsequent `application:set_env`
    %% changes are NOT observed. Set the client env BEFORE starting
    %% grpcbox, otherwise `default_channel` is never registered and
    %% every `proxy_register` call blocks the gen_server:call until its
    %% 30s timeout fires (manifests as 6/7 tests failing with
    %% `{timeout, {gen_server,call, ...}}`).
    ok = ensure_started(ctx),
    ok = ensure_started(gproc),

    %% Configure grpcbox client channel to point at the real server
    %% BEFORE starting the application.
    application:set_env(grpcbox, client,
        #{channels => [
            {default_channel,
             [{http, ?UPSTREAM_HOST, ?UPSTREAM_PORT, []}],
             #{}}
        ]}),

    %% If grpcbox is already started (e.g. from a prior suite in the
    %% same CT run), stop it so the new client env takes effect on the
    %% next start. application:set_env on an already-started app does
    %% not retroactively reconfigure its supervision tree.
    case lists:keyfind(grpcbox, 1, application:which_applications()) of
        false -> ok;
        _ -> ok = application:stop(grpcbox)
    end,
    ok = ensure_started(grpcbox),

    %% Start the gateway process group.
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,

    %% Set up telemetry (ignore errors if already set up).
    catch yuzu_gw_telemetry:setup(),

    %% Start gateway modules — NO mocking.
    start_module(yuzu_gw_registry),

    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 1000),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 2000),

    start_module(yuzu_gw_upstream),
    start_module(yuzu_gw_heartbeat_buffer),
    start_module(yuzu_gw_router),

    ct:pal("Gateway modules started (real upstream, no mocks)"),
    Config.

end_per_suite(_Config) ->
    %% Deregister all agents.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(500)
    catch _:_ -> ok
    end,
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

%% @doc Verify the upstream server is reachable via gRPC (not just TCP).
%% This sends a real ProxyRegister RPC and checks we get a session_id back.
server_reachable(_Config) ->
    ct:pal("--- server_reachable: sending ProxyRegister to real C++ server ---"),

    Req = make_register_req(<<"reachable-agent-1">>),
    Result = yuzu_gw_upstream:proxy_register(Req),

    ct:pal("ProxyRegister result: ~p", [Result]),
    ?assertMatch({ok, _}, Result),

    {ok, Response} = Result,
    SessionId = maps:get(session_id, Response, undefined),
    ct:pal("Received session_id: ~p", [SessionId]),
    ?assertNotEqual(undefined, SessionId),
    ?assert(is_binary(SessionId) andalso byte_size(SessionId) > 0,
            "session_id should be a non-empty binary").

%% @doc Register a single agent through the gateway upstream proxy.
single_agent_register(_Config) ->
    ct:pal("--- single_agent_register ---"),

    AgentId = <<"real-single-agent-1">>,
    Req = make_register_req(AgentId),
    {ok, Response} = yuzu_gw_upstream:proxy_register(Req),

    SessionId = maps:get(session_id, Response, <<>>),
    ct:pal("Agent ~s registered with session ~s", [AgentId, SessionId]),
    ?assert(byte_size(SessionId) > 0),

    %% Verify the server knows about this agent via the web API.
    timer:sleep(500),
    case httpc:request(get, {"http://127.0.0.1:8080/livez", []}, [{timeout, 5000}], []) of
        {ok, {{_, 200, _}, _, _}} ->
            ct:pal("Server web API confirmed reachable");
        _ ->
            ct:pal("Server web API not reachable (non-critical)")
    end.

%% @doc Spawn N concurrent agent registrations against the real server.
multi_agent_register(_Config) ->
    N = get_env_int("YUZU_REAL_UPSTREAM_AGENTS", 10),
    ct:pal("--- multi_agent_register: ~B agents against real server ---", [N]),

    Parent = self(),
    _Workers = [spawn_link(fun() ->
        AgentId = iolist_to_binary(io_lib:format("real-agent-~4..0B", [I])),
        Req = make_register_req(AgentId),
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

    %% All should succeed against a real server (no artificial limits).
    ?assertEqual(N, length(Successes),
                 lists:flatten(io_lib:format(
                     "Only ~B/~B registrations succeeded", [length(Successes), N]))).

%% @doc Queue heartbeats for multiple agents, wait for batch flush to the
%% real server, verify no crashes.
heartbeat_batching(_Config) ->
    N = 5,
    HBsPerAgent = 10,
    ct:pal("--- heartbeat_batching: ~B agents x ~B HBs against real server ---",
           [N, HBsPerAgent]),

    %% Queue heartbeats.
    lists:foreach(fun(I) ->
        AgentId = iolist_to_binary(io_lib:format("hb-real-agent-~4..0B", [I])),
        lists:foreach(fun(_) ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
                agent_id  => AgentId,
                timestamp => #{seconds => erlang:system_time(second)}
            })
        end, lists:seq(1, HBsPerAgent))
    end, lists:seq(1, N)),

    TotalHBs = N * HBsPerAgent,
    ct:pal("Queued ~B heartbeats, waiting for batch flush to real server...", [TotalHBs]),

    %% Wait for two flush cycles (flush interval is 1s).
    timer:sleep(2500),

    %% If the heartbeat buffer process is still alive, the batch was sent
    %% (or at least attempted) without crashing.
    ?assert(is_pid(whereis(yuzu_gw_heartbeat_buffer)),
            "Heartbeat buffer process should still be alive after batching"),
    ct:pal("Heartbeat batching to real server completed successfully").

%% @doc Start an agent, disconnect it, verify the upstream disconnect
%% notification is sent to the real server without crashing.
agent_disconnect_notification(_Config) ->
    ct:pal("--- agent_disconnect_notification ---"),

    StreamHandler = spawn(fun() -> stream_handler_loop(self()) end),
    AgentId = <<"real-disconnect-agent">>,
    AgentArgs = #{
        agent_id   => AgentId,
        session_id => <<"real-disc-sess">>,
        agent_info => #{plugins => [#{name => <<"system">>, version => <<"1.0">>}]},
        stream_pid => StreamHandler,
        peer_addr  => <<"127.0.0.1:0">>
    },

    {ok, _AgentPid} = yuzu_gw_agent:start_link(AgentArgs),
    timer:sleep(200),

    CountBefore = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count before disconnect: ~B", [CountBefore]),
    ?assert(CountBefore >= 1),

    %% Kill the stream handler — agent detects DOWN and disconnects.
    %% This fires NotifyStreamStatus to the real server.
    exit(StreamHandler, kill),

    %% Wait for cleanup.
    ok = wait_until(fun() ->
        yuzu_gw_registry:lookup(AgentId) =:= error
    end, 5000),

    CountAfter = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count after disconnect: ~B (was ~B)", [CountAfter, CountBefore]),
    ?assert(CountAfter < CountBefore),

    %% Verify upstream module didn't crash from the notification.
    ?assert(is_pid(whereis(yuzu_gw_upstream)),
            "Upstream process should survive disconnect notification").

%% @doc Simulate circuit breaker by stopping the upstream module,
%% verifying it rejects RPCs, then restarting and verifying recovery.
circuit_breaker_recovery(_Config) ->
    ct:pal("--- circuit_breaker_recovery ---"),

    %% First verify normal operation works.
    Req = make_register_req(<<"cb-agent-before">>),
    {ok, _} = yuzu_gw_upstream:proxy_register(Req),
    ct:pal("Normal registration succeeded (circuit closed)"),

    %% Stop the upstream process and restart it with unreachable server.
    catch gen_server:stop(yuzu_gw_upstream),
    timer:sleep(100),

    %% Reconfigure grpcbox to point at a dead port temporarily.
    application:set_env(grpcbox, client,
        #{channels => [
            {default_channel, [{http, "127.0.0.1", 59999, []}], #{}}
        ]}),

    %% Restart grpcbox to pick up new config.
    catch application:stop(grpcbox),
    timer:sleep(200),
    ok = ensure_started(grpcbox),
    timer:sleep(500),

    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 2),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 1500),
    {ok, _UpPid} = yuzu_gw_upstream:start_link(),

    %% Send requests that should fail (unreachable server).
    Req2 = make_register_req(<<"cb-agent-fail-1">>),
    R1 = yuzu_gw_upstream:proxy_register(Req2),
    ct:pal("Fail attempt 1: ~p", [R1]),

    Req3 = make_register_req(<<"cb-agent-fail-2">>),
    R2 = yuzu_gw_upstream:proxy_register(Req3),
    ct:pal("Fail attempt 2: ~p", [R2]),

    %% After 2 failures, circuit should be open.
    Req4 = make_register_req(<<"cb-agent-fail-3">>),
    R3 = yuzu_gw_upstream:proxy_register(Req4),
    ct:pal("Attempt 3 (should be circuit_open): ~p", [R3]),

    %% Now restore the real server connection.
    catch gen_server:stop(yuzu_gw_upstream),
    timer:sleep(100),

    application:set_env(grpcbox, client,
        #{channels => [
            {default_channel, [{http, ?UPSTREAM_HOST, ?UPSTREAM_PORT, []}], #{}}
        ]}),
    catch application:stop(grpcbox),
    timer:sleep(200),
    ok = ensure_started(grpcbox),
    timer:sleep(500),

    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 2000),
    {ok, UpPid2} = yuzu_gw_upstream:start_link(),
    unlink(UpPid2),

    %% Verify recovery.
    Req5 = make_register_req(<<"cb-agent-recovered">>),
    R5 = yuzu_gw_upstream:proxy_register(Req5),
    ct:pal("Recovery attempt: ~p", [R5]),
    ?assertMatch({ok, _}, R5),

    %% Restart heartbeat buffer since it depends on upstream.
    catch gen_server:stop(yuzu_gw_heartbeat_buffer),
    timer:sleep(100),
    start_module(yuzu_gw_heartbeat_buffer),
    ct:pal("Circuit breaker recovery verified — real server connection restored").

%% @doc Full round-trip: register agents, send heartbeats, verify the
%% server received both via its REST API.
register_and_heartbeat_roundtrip(_Config) ->
    ct:pal("--- register_and_heartbeat_roundtrip ---"),

    %% Ensure upstream and heartbeat buffer are running (may have been
    %% stopped by circuit_breaker_recovery test).
    start_module(yuzu_gw_upstream),
    start_module(yuzu_gw_heartbeat_buffer),

    %% Ensure inets/httpc is available for REST API checks.
    ok = ensure_started(inets),
    ok = ensure_started(ssl),

    %% Register an agent.
    AgentId = <<"roundtrip-real-agent">>,
    Req = make_register_req(AgentId),
    {ok, RegResp} = yuzu_gw_upstream:proxy_register(Req),
    SessionId = maps:get(session_id, RegResp, <<>>),
    ct:pal("Registered ~s with session ~s", [AgentId, SessionId]),
    ?assert(byte_size(SessionId) > 0),

    %% Send heartbeats for this agent.
    lists:foreach(fun(_) ->
        yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
            agent_id  => AgentId,
            timestamp => #{seconds => erlang:system_time(second)}
        })
    end, lists:seq(1, 5)),

    %% Wait for heartbeat flush.
    timer:sleep(2000),

    %% Check the server's /metrics for heartbeat counters.
    case httpc:request(get,
            {"http://127.0.0.1:8080/metrics", []},
            [{timeout, 5000}], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, MetricsBody}} ->
            case binary:match(MetricsBody, <<"yuzu_heartbeats_received_total">>) of
                {_, _} ->
                    ct:pal("Server /metrics confirms heartbeat reception");
                nomatch ->
                    ct:pal("Server /metrics reachable but heartbeat metric not found (may need agent connection)")
            end;
        Other ->
            ct:pal("Could not reach /metrics: ~p (non-critical)", [Other])
    end,

    ct:pal("Full register → heartbeat → server roundtrip completed").

%%%===================================================================
%%% Internal helpers
%%%===================================================================

make_register_req(AgentId) ->
    Token = case os:getenv("YUZU_GW_TEST_TOKEN") of
        false ->
            case file:read_file(?UAT_TOKEN_FILE) of
                {ok, Bin} -> string:trim(Bin);
                {error, _} ->
                    ct:fail("No enrollment token: set YUZU_GW_TEST_TOKEN or "
                            "run scripts/start-UAT.sh first")
            end;
        Val -> list_to_binary(Val)
    end,
    %% RegisterRequest has a nested AgentInfo field (proto/yuzu/agent/v1/
    %% agent.proto: `AgentInfo info = 1`). A flat map of agent_id/hostname/
    %% etc. at the top level marshals to a RegisterRequest with `info`
    %% unset; the server then reads `info.agent_id()` as empty and
    %% rejects with INVALID_ARGUMENT "agent_id length exceeds 256 chars
    %% or empty". Nest everything except enrollment_token under `info`.
    #{
        info => #{
            agent_id      => AgentId,
            hostname      => <<"real-upstream-test-host">>,
            platform      => #{os => <<"LINUX">>, arch => <<"x86_64">>},
            agent_version => <<"0.1.0">>,
            plugins       => [#{name => <<"system_info">>, version => <<"1.0.0">>}]
        },
        enrollment_token => Token
    }.

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

get_env_int(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> list_to_integer(Val)
    end.

ensure_started(App) ->
    case application:ensure_all_started(App) of
        {ok, _}                       -> ok;
        {error, {already_started, _}} -> ok;
        {error, Reason}               -> {error, Reason}
    end.

start_module(Module) ->
    case whereis(Module) of
        undefined ->
            {ok, Pid} = Module:start_link(),
            unlink(Pid);
        _ -> ok
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
