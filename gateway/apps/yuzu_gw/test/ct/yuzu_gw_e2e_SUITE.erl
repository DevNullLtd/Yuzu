%%%-------------------------------------------------------------------
%%% @doc End-to-end Common Test suite for the Yuzu gateway.
%%%
%%% This suite tests the full gRPC flow using actual grpcbox client
%%% calls to simulate agent behavior. It requires:
%%%   - The gateway to be fully started (grpcbox servers running)
%%%   - Mock upstream handlers for the C++ server
%%%
%%% Test scenarios:
%%%   1. Full agent lifecycle: Register → Subscribe → Heartbeat → Disconnect
%%%   2. Command fanout through actual gRPC channels
%%%   3. Error handling and recovery
%%%   4. Concurrent agent connections
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([all/0, suite/0,
         init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    full_agent_lifecycle/1,
    concurrent_agent_connections/1,
    heartbeat_batching_e2e/1,
    agent_reconnection/1,
    command_fanout_e2e/1
]).

-define(AGENT_PORT, 50151).  %% Test port for agent service
-define(MGMT_PORT, 50152).   %% Test port for management service

%% These cases call the agent service handlers in-process (no real
%% connection), so the connection key heartbeat admission compares is
%% supplied by a mock of yuzu_gw_conn. Every call "arrives" on this one
%% connection; the sessions below are bound to it.
-define(CONN_KEY, e2e_test_connection).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [full_agent_lifecycle,
     concurrent_agent_connections,
     heartbeat_batching_e2e,
     agent_reconnection,
     command_fanout_e2e].

init_per_suite(Config) ->
    %% Ensure all required applications are started.
    application:ensure_all_started(telemetry),
    application:ensure_all_started(gproc),
    application:ensure_all_started(gpb),

    %% Configure gateway for testing.
    application:set_env(yuzu_gw, agent_listen_port, ?AGENT_PORT),
    application:set_env(yuzu_gw, mgmt_listen_port, ?MGMT_PORT),
    application:set_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    application:set_env(yuzu_gw, upstream_port, 59999),  %% unused port
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 500),
    application:set_env(yuzu_gw, default_command_timeout_s, 5),
    application:set_env(yuzu_gw, telemetry_gauge_interval_ms, 60000),

    %% Mock upstream so we don't need a real C++ server.
    meck:new(grpcbox_channel, [non_strict, no_link]),
    meck:expect(grpcbox_channel, pick, fun(_, _) -> {ok, mock_channel} end),
    meck:new(grpcbox_client, [non_strict, no_link]),
    setup_upstream_mocks(),

    %% Connection key for the in-process agent service calls (see ?CONN_KEY).
    meck:new(yuzu_gw_conn, [passthrough, no_link]),
    meck:expect(yuzu_gw_conn, key_from_ctx, fun(_Ctx) -> ?CONN_KEY end),

    %% Start pg scope (unlink so it outlives the CT setup process).
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,

    %% Start gateway application (will start supervision tree).
    %% For testing, we start the core processes manually.
    start_gateway_processes(),

    Config.

end_per_suite(_Config) ->
    %% Stop gateway processes.
    stop_gateway_processes(),

    %% Unload mocks.
    meck:unload([grpcbox_channel, grpcbox_client, yuzu_gw_conn]),

    ok.

init_per_testcase(_TestCase, Config) ->
    %% Clean agent registry before each test (guard in case registry isn't running).
    case whereis(yuzu_gw_registry) of
        undefined -> ok;
        _ ->
            lists:foreach(fun(Id) ->
                yuzu_gw_registry:deregister_agent(Id)
            end, yuzu_gw_registry:all_agents()),
            timer:sleep(50)
    end,
    Config.

end_per_testcase(_TestCase, Config) ->
    Config.

%%%===================================================================
%%% Test Cases
%%%===================================================================

%% @doc Test full agent lifecycle: Register → Subscribe → Heartbeat → Disconnect
full_agent_lifecycle(_Config) ->
    AgentId = <<"e2e-lifecycle-1">>,
    ct:pal("Starting full agent lifecycle test for ~s", [AgentId]),

    %% Phase 1: Register
    RegisterReq = #{
        info => #{
            agent_id => AgentId,
            hostname => <<"test-host">>,
            platform => #{os => <<"linux">>, arch => <<"amd64">>},
            plugins => [#{name => <<"svc">>, version => <<"1.0">>}]
        },
        enrollment_token => <<"test-token">>
    },

    Ctx = ctx:background(),
    {ok, RegisterResp, _} = yuzu_gw_agent_service:register(Ctx, RegisterReq),

    SessionId = maps:get(session_id, RegisterResp),
    ct:pal("Registered with session: ~s", [SessionId]),
    ?assertNotEqual(undefined, SessionId),

    %% Phase 2: Subscribe (simulated - we start the agent process directly)
    %% In a real scenario, Subscribe would be called via gRPC bidi stream.
    %% For testing, we simulate by starting the agent process.
    PendingData = yuzu_gw_registry:take_pending(SessionId),
    ?assertNotEqual(undefined, PendingData),

    %% Start agent process (simulates Subscribe handler).
    Args = #{
        agent_id => AgentId,
        session_id => SessionId,
        stream_pid => self(),  %% We act as the stream handler
        agent_info => maps:get(agent_info, PendingData),
        peer_addr => maps:get(peer_addr, PendingData),
        %% Register recorded the connection it arrived on.
        conn_key => maps:get(conn_key, PendingData)
    },
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),
    timer:sleep(50),

    %% Verify agent is registered.
    ?assertMatch({ok, AgentPid}, yuzu_gw_registry:lookup(AgentId)),

    %% Phase 3: Heartbeat
    HeartbeatReq = #{session_id => SessionId},
    {ok, HeartbeatResp, _} = yuzu_gw_agent_service:heartbeat(Ctx, HeartbeatReq),
    ?assertEqual(true, maps:get(acknowledged, HeartbeatResp)),

    %% Phase 4: Get agent info
    {ok, Info} = yuzu_gw_agent:get_info(AgentPid),
    ?assertEqual(AgentId, maps:get(agent_id, Info)),
    ?assertEqual(streaming, maps:get(state, Info)),

    %% Phase 5: Disconnect
    yuzu_gw_agent:disconnect(AgentPid),
    timer:sleep(100),

    %% Verify cleanup.
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)),

    ct:pal("Full lifecycle test passed for ~s", [AgentId]).

%% @doc Test concurrent agent connections.
concurrent_agent_connections(_Config) ->
    N = 20,
    ct:pal("Testing ~b concurrent agent connections", [N]),

    Self = self(),
    Ref = make_ref(),

    %% Spawn N concurrent registration processes.
    %% Each worker acts as stream_pid, so it must stay alive until assertions complete.
    Workers = lists:map(fun(I) ->
        spawn_link(fun() ->
            AgentId = iolist_to_binary(io_lib:format("concurrent-~b", [I])),

            %% Register.
            RegisterReq = #{
                info => #{
                    agent_id => AgentId,
                    hostname => iolist_to_binary(io_lib:format("host-~b", [I])),
                    plugins => [#{name => <<"svc">>}]
                }
            },
            {ok, Resp, _} = yuzu_gw_agent_service:register(ctx:background(), RegisterReq),
            SessionId = maps:get(session_id, Resp),

            %% Start agent process.
            Pending = yuzu_gw_registry:take_pending(SessionId),
            Args = #{
                agent_id => AgentId,
                session_id => SessionId,
                stream_pid => self(),
                agent_info => maps:get(agent_info, Pending),
                peer_addr => <<"127.0.0.1">>,
                conn_key => maps:get(conn_key, Pending)
            },
            {ok, _Pid} = yuzu_gw_agent:start_link(Args),

            Self ! {registered, Ref, AgentId},
            %% Stay alive as stream_pid until told to stop.
            receive stop -> ok end
        end)
    end, lists:seq(1, N)),

    %% Wait for all registrations.
    Registered = collect_registrations(Ref, N, 5000),
    ct:pal("Registered ~b agents", [length(Registered)]),
    ?assertEqual(N, length(Registered)),

    %% Verify all agents are in registry.
    Count = yuzu_gw_registry:agent_count(),
    ?assert(Count >= N),

    %% Verify each agent is lookup-able.
    lists:foreach(fun(AgentId) ->
        ?assertMatch({ok, _}, yuzu_gw_registry:lookup(AgentId))
    end, Registered),

    %% Cleanup: stop workers (triggers agent disconnect via stream_pid monitor).
    lists:foreach(fun(W) -> W ! stop end, Workers),
    timer:sleep(50),

    ct:pal("Concurrent connections test passed").

%% @doc Test heartbeat batching end-to-end.
heartbeat_batching_e2e(_Config) ->
    ct:pal("Testing heartbeat batching"),

    %% Reset meck history so we can check for new BatchHeartbeat calls.
    meck:reset(grpcbox_client),

    %% Heartbeats are admitted only for sessions this node holds, on the
    %% connection that opened them: hold ten live sessions bound to
    %% ?CONN_KEY, then send one heartbeat for each.
    Holders = lists:map(fun(I) ->
        SessionId = iolist_to_binary(io_lib:format("sess-~b", [I])),
        AgentId = iolist_to_binary(io_lib:format("hb-batch-~b", [I])),
        Holder = spawn(fun() -> receive stop -> ok end end),
        ok = yuzu_gw_registry:register_agent(AgentId, Holder, SessionId, [],
                                             <<>>, #{}, ?CONN_KEY),
        Holder
    end, lists:seq(1, 10)),

    Ctx = ctx:background(),
    lists:foreach(fun(I) ->
        HbReq = #{session_id => iolist_to_binary(io_lib:format("sess-~b", [I]))},
        {ok, _, _} = yuzu_gw_agent_service:heartbeat(Ctx, HbReq)
    end, lists:seq(1, 10)),

    %% Wait for batch flush (interval is 500ms in test config).
    timer:sleep(700),

    %% Verify a batch was sent by inspecting meck history.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ct:pal("Batch contained ~b heartbeats", [length(HBs)]),
    ?assert(length(HBs) >= 1),

    lists:foreach(fun(H) -> H ! stop end, Holders),

    ct:pal("Heartbeat batching test passed").

%% @doc Test agent reconnection (same ID, new process).
agent_reconnection(_Config) ->
    AgentId = <<"reconnect-test-1">>,
    ct:pal("Testing agent reconnection for ~s", [AgentId]),

    %% First connection.
    {SessionId1, Pid1} = connect_agent(AgentId),
    ?assertMatch({ok, Pid1}, yuzu_gw_registry:lookup(AgentId)),

    %% Disconnect first agent.
    yuzu_gw_agent:disconnect(Pid1),
    timer:sleep(100),

    %% Reconnect with same agent ID.
    {SessionId2, Pid2} = connect_agent(AgentId),
    ?assertNotEqual(SessionId1, SessionId2),
    ?assertMatch({ok, Pid2}, yuzu_gw_registry:lookup(AgentId)),

    %% Cleanup.
    yuzu_gw_agent:disconnect(Pid2),
    timer:sleep(50),

    ct:pal("Agent reconnection test passed").

%% @doc Test command fanout end-to-end.
command_fanout_e2e(_Config) ->
    ct:pal("Testing command fanout"),

    %% Start multiple agents.
    Agents = lists:map(fun(I) ->
        AgentId = iolist_to_binary(io_lib:format("fanout-e2e-~b", [I])),
        {_SessionId, Pid} = connect_agent(AgentId),
        {AgentId, Pid}
    end, lists:seq(1, 5)),

    AgentIds = [Id || {Id, _} <- Agents],

    %% Send command via router.
    Cmd = #{command_id => <<"cmd-e2e-1">>, plugin => <<"svc">>, action => <<"list">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command(AgentIds, Cmd, #{}),

    %% Collect send_command messages (we're the stream_pid for all agents).
    Commands = collect_send_commands(5, 2000),
    ct:pal("Received ~b command dispatches", [length(Commands)]),
    ?assertEqual(5, length(Commands)),

    %% Simulate all agents responding.
    lists:foreach(fun(AgentId) ->
        yuzu_gw_router ! {fanout_terminal, FanoutRef, AgentId}
    end, AgentIds),

    %% Verify fanout completion.
    receive
        {fanout_complete, FanoutRef, #{targets := 5, received := 5}} ->
            ct:pal("Fanout completed successfully")
    after 3000 ->
        ct:fail("Fanout did not complete")
    end,

    %% Cleanup.
    lists:foreach(fun({_, Pid}) ->
        yuzu_gw_agent:disconnect(Pid)
    end, Agents),
    timer:sleep(50),

    ct:pal("Command fanout test passed").

%%%===================================================================
%%% Helpers
%%%===================================================================

start_gateway_processes() ->
    %% Start core processes in correct order (unlink so they outlive the CT setup process).
    case whereis(yuzu_gw_registry) of
        undefined ->
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        _ -> ok
    end,
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
    ok.

stop_gateway_processes() ->
    %% Stop processes if they were started by us.
    lists:foreach(fun(Name) ->
        case whereis(Name) of
            undefined -> ok;
            Pid ->
                unlink(Pid),
                exit(Pid, shutdown),
                timer:sleep(20)
        end
    end, [yuzu_gw_router, yuzu_gw_upstream, yuzu_gw_registry]).

setup_upstream_mocks() ->
    SessionCounter = atomics:new(1, []),
    meck:expect(grpcbox_client, unary, fun(_, Path, _Req, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch ->
                case binary:match(Path, <<"BatchHeartbeat">>) of
                    nomatch -> {ok, #{}, #{}};
                    _ -> {ok, #{acknowledged_count => 0}, #{}}
                end;
            _ ->
                N = atomics:add_get(SessionCounter, 1, 1),
                SessionId = iolist_to_binary(io_lib:format("test-session-~b", [N])),
                {ok, #{session_id => SessionId}, #{}}
        end
    end).

connect_agent(AgentId) ->
    RegisterReq = #{
        info => #{
            agent_id => AgentId,
            hostname => <<"test-host">>,
            plugins => [#{name => <<"svc">>}]
        }
    },
    {ok, Resp, _} = yuzu_gw_agent_service:register(ctx:background(), RegisterReq),
    SessionId = maps:get(session_id, Resp),

    Pending = yuzu_gw_registry:take_pending(SessionId),
    Args = #{
        agent_id => AgentId,
        session_id => SessionId,
        stream_pid => self(),
        agent_info => maps:get(agent_info, Pending),
        peer_addr => <<"127.0.0.1">>,
        conn_key => maps:get(conn_key, Pending)
    },
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    timer:sleep(20),
    {SessionId, Pid}.

collect_registrations(Ref, N, Timeout) ->
    collect_registrations(Ref, N, Timeout, []).

collect_registrations(_Ref, 0, _Timeout, Acc) ->
    lists:reverse(Acc);
collect_registrations(Ref, N, Timeout, Acc) ->
    receive
        {registered, Ref, AgentId} ->
            collect_registrations(Ref, N - 1, Timeout, [AgentId | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.

collect_send_commands(N, Timeout) ->
    collect_send_commands(N, Timeout, []).

collect_send_commands(0, _Timeout, Acc) ->
    lists:reverse(Acc);
collect_send_commands(N, Timeout, Acc) ->
    receive
        {send_command, Cmd} ->
            collect_send_commands(N - 1, Timeout, [Cmd | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.
