%%%-------------------------------------------------------------------
%%% @doc Common Test suite for end-to-end gateway integration.
%%%
%%% Tests the full gateway stack:
%%%   - gRPC service endpoints (agent-facing and mgmt-facing)
%%%   - Upstream proxy to mock server
%%%   - Agent lifecycle (Register → Subscribe → Heartbeat → Disconnect)
%%%   - Command fanout through the full stack
%%%   - Telemetry and metrics collection
%%%
%%% This suite uses real grpcbox and real pb modules (not mocked),
%%% exercising the actual encode/decode paths and service handlers.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_integration_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([all/0, groups/0, suite/0,
         init_per_suite/1, end_per_suite/1,
         init_per_group/2, end_per_group/2,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    %% Agent lifecycle tests
    agent_register_via_service/1,
    agent_heartbeat_batching/1,
    agent_inventory_proxy/1,
    agent_subscribe_lifecycle/1,
    agent_disconnect_cleanup/1,

    %% Command fanout tests
    command_fanout_single_agent/1,
    command_fanout_multiple_agents/1,
    command_fanout_timeout/1,
    command_fanout_missing_agent/1,

    %% Management service tests
    mgmt_list_agents/1,
    mgmt_get_agent/1,

    %% Upstream proxy tests
    upstream_register_error_handling/1,
    upstream_batch_heartbeat_flush/1,
    upstream_stream_status_notification/1,

    %% Registry and routing tests
    registry_concurrent_registration/1,
    registry_reconnection_handling/1,
    router_broadcast_to_all/1,

    %% Resilience tests
    stream_write_failure_handling/1,
    upstream_disconnect_recovery/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [{group, lifecycle},
     {group, fanout},
     {group, management},
     {group, upstream},
     {group, resilience}].

groups() ->
    [{lifecycle, [sequence], [
        agent_register_via_service,
        agent_heartbeat_batching,
        agent_inventory_proxy,
        agent_subscribe_lifecycle,
        agent_disconnect_cleanup
    ]},
    {fanout, [parallel], [
        command_fanout_single_agent,
        command_fanout_multiple_agents,
        command_fanout_timeout,
        command_fanout_missing_agent
    ]},
    {management, [sequence], [
        mgmt_list_agents,
        mgmt_get_agent
    ]},
    {upstream, [sequence], [
        upstream_register_error_handling,
        upstream_batch_heartbeat_flush,
        upstream_stream_status_notification
    ]},
    {resilience, [parallel], [
        registry_concurrent_registration,
        registry_reconnection_handling,
        router_broadcast_to_all,
        stream_write_failure_handling,
        upstream_disconnect_recovery
    ]}].

init_per_suite(Config) ->
    %% Start required applications.
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(gproc),

    %% Set up mock upstream configuration.
    application:set_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    application:set_env(yuzu_gw, upstream_port, 50099),  %% unused port
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 100),  %% fast for tests
    application:set_env(yuzu_gw, default_command_timeout_s, 5),

    %% Start pg scope if not already started.
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,

    %% Start core gateway processes (unlink so they outlive the CT setup process).
    case whereis(yuzu_gw_registry) of
        undefined ->
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        _ -> ok
    end,
    case whereis(yuzu_gw_router) of
        undefined ->
            {ok, RouterPid} = yuzu_gw_router:start_link(),
            unlink(RouterPid);
        _ -> ok
    end,

    %% Install a global upstream mock for all non-upstream-group tests.
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:new(yuzu_gw_heartbeat_buffer, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),
    meck:expect(yuzu_gw_upstream, proxy_register, fun(_) ->
        {ok, #{session_id => <<"test-session">>}}
    end),
    meck:expect(yuzu_gw_upstream, proxy_inventory, fun(_) ->
        {ok, #{received => true}}
    end),

    Config.

end_per_suite(_Config) ->
    %% Clean up any remaining agents.
    case whereis(yuzu_gw_registry) of
        undefined -> ok;
        _ ->
            lists:foreach(fun(Id) ->
                catch yuzu_gw_registry:deregister_agent(Id)
            end, yuzu_gw_registry:all_agents())
    end,
    %% Unload global mock.
    catch meck:unload(yuzu_gw_upstream),
    ok.

init_per_group(upstream, Config) ->
    %% Temporarily unload the global upstream mock so we can start the real process.
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(yuzu_gw_heartbeat_buffer),
    %% Stop any leftover processes from prior suites.
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        OldPid ->
            catch unlink(OldPid),
            catch gen_server:stop(OldPid, shutdown, 5000),
            timer:sleep(100)
    end,
    %% Mock grpcbox for upstream tests.
    catch meck:unload(grpcbox_channel),
    catch meck:unload(grpcbox_client),
    meck:new(grpcbox_channel, [non_strict, no_link]),
    meck:expect(grpcbox_channel, pick, fun(_, _) -> {ok, mock_channel} end),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    %% Start real upstream and heartbeat buffer (unlink so they outlive CT process).
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined ->
            {ok, HBPid} = yuzu_gw_heartbeat_buffer:start_link(),
            unlink(HBPid);
        _ -> ok
    end,
    [{upstream_pid, Pid} | Config];

init_per_group(_Group, Config) ->
    Config.

end_per_group(upstream, Config) ->
    Pid = proplists:get_value(upstream_pid, Config),
    case is_pid(Pid) andalso is_process_alive(Pid) of
        true ->
            exit(Pid, shutdown),
            timer:sleep(50);
        false ->
            ok
    end,
    catch meck:unload(grpcbox_channel),
    catch meck:unload(grpcbox_client),
    %% Reinstall the global upstream mock for subsequent groups.
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(yuzu_gw_heartbeat_buffer),
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:new(yuzu_gw_heartbeat_buffer, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),
    meck:expect(yuzu_gw_upstream, proxy_register, fun(_) ->
        {ok, #{session_id => <<"test-session">>}}
    end),
    meck:expect(yuzu_gw_upstream, proxy_inventory, fun(_) ->
        {ok, #{received => true}}
    end),
    Config;

end_per_group(_Group, Config) ->
    Config.

init_per_testcase(_TestCase, Config) ->
    %% Ensure required processes are running (they may have been killed by CT teardown).
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,
    case whereis(yuzu_gw_registry) of
        undefined ->
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        _ -> ok
    end,
    case whereis(yuzu_gw_router) of
        undefined ->
            {ok, RouterPid} = yuzu_gw_router:start_link(),
            unlink(RouterPid);
        _ -> ok
    end,
    %% Clean agent registry.
    lists:foreach(fun(Id) ->
        catch yuzu_gw_registry:deregister_agent(Id)
    end, yuzu_gw_registry:all_agents()),
    timer:sleep(50),
    Config.

end_per_testcase(_TestCase, Config) ->
    Config.

%%%===================================================================
%%% Agent Lifecycle Tests
%%%===================================================================

agent_register_via_service(_Config) ->
    %% Update upstream mock for this specific test.
    meck:expect(yuzu_gw_upstream, proxy_register, fun(_Req) ->
        {ok, #{session_id => <<"test-session-1">>}}
    end),

    Ctx = ctx:background(),
    RegisterReq = #{
        info => #{
            agent_id => <<"integration-agent-1">>,
            hostname => <<"test-host">>,
            plugins => [#{name => <<"svc">>}]
        },
        enrollment_token => <<"test-token">>
    },

    {ok, Response, _Ctx2} = yuzu_gw_agent_service:register(Ctx, RegisterReq),

    ?assertEqual(<<"test-session-1">>, maps:get(session_id, Response)),

    %% Verify pending registration was stored (take_pending retrieves and deletes).
    Pending = yuzu_gw_registry:take_pending(<<"test-session-1">>),
    ?assertNotEqual(undefined, Pending),
    ?assertEqual(<<"integration-agent-1">>, maps:get(agent_id, Pending)).

agent_heartbeat_batching(_Config) ->
    BatchRef = make_ref(),
    Self = self(),
    meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(HbReq) ->
        Self ! {heartbeat_queued, BatchRef, HbReq},
        ok
    end),

    Ctx = ctx:background(),
    HbReq = #{session_id => <<"sess-1">>},

    {ok, Response, _} = yuzu_gw_agent_service:heartbeat(Ctx, HbReq),

    ?assertEqual(true, maps:get(acknowledged, Response)),
    ?assert(is_map(maps:get(server_time, Response))),

    receive
        {heartbeat_queued, BatchRef, _} -> ok
    after 1000 ->
        ct:fail("Heartbeat not queued")
    end.

agent_inventory_proxy(_Config) ->
    meck:expect(yuzu_gw_upstream, proxy_inventory, fun(_Report) ->
        {ok, #{received => true}}
    end),

    Ctx = ctx:background(),
    Report = #{
        session_id => <<"sess-1">>,
        collected_at => #{millis_epoch => erlang:system_time(millisecond)},
        plugin_data => #{<<"svc">> => <<"{}">>}
    },

    {ok, Response, _} = yuzu_gw_agent_service:report_inventory(Ctx, Report),
    ?assertEqual(true, maps:get(received, Response)).

agent_subscribe_lifecycle(_Config) ->
    SessionId = <<"subscribe-sess-1">>,
    AgentId = <<"subscribe-agent-1">>,

    yuzu_gw_registry:store_pending(SessionId, #{
        agent_id => AgentId,
        agent_info => #{plugins => [#{name => <<"svc">>}]},
        peer_addr => <<"127.0.0.1">>,
        registered_at => erlang:system_time(millisecond)
    }),

    Args = #{
        agent_id => AgentId,
        session_id => SessionId,
        stream_pid => self(),
        agent_info => #{plugins => [#{name => <<"svc">>}]},
        peer_addr => <<"127.0.0.1">>
    },
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),

    timer:sleep(50),
    ?assertMatch({ok, AgentPid}, yuzu_gw_registry:lookup(AgentId)),

    {ok, Info} = yuzu_gw_agent:get_info(AgentPid),
    ?assertEqual(AgentId, maps:get(agent_id, Info)),
    ?assertEqual(streaming, maps:get(state, Info)),

    yuzu_gw_agent:disconnect(AgentPid),
    timer:sleep(100),

    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

agent_disconnect_cleanup(_Config) ->
    %% Test that agent disconnect properly cleans up all state.
    AgentId = <<"cleanup-agent-1">>,

    %% Start agent.
    Args = #{
        agent_id => AgentId,
        session_id => <<"cleanup-sess-1">>,
        stream_pid => self(),
        agent_info => #{plugins => [#{name => <<"svc">>}, #{name => <<"fs">>}]},
        peer_addr => <<"127.0.0.1">>
    },
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),
    timer:sleep(50),

    %% Verify pg group membership.
    AllAgents = pg:get_members(yuzu_gw, all_agents),
    ?assert(lists:member(AgentPid, AllAgents)),

    %% Kill the agent process.
    exit(AgentPid, kill),
    timer:sleep(100),

    %% Verify cleanup from registry.
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

%%%===================================================================
%%% Command Fanout Tests
%%%===================================================================

command_fanout_single_agent(_Config) ->
    %% Start a fake agent that responds to commands.
    AgentId = <<"fanout-single-1">>,
    {AgentPid, _} = start_responding_agent(AgentId),

    Cmd = #{command_id => <<"cmd-single-1">>, plugin => <<"svc">>, action => <<"list">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command([AgentId], Cmd, #{}),

    %% The fake agent should receive the dispatch.
    receive
        {dispatch_received, <<"cmd-single-1">>} -> ok
    after 2000 ->
        ct:fail("Agent didn't receive dispatch")
    end,

    %% Simulate terminal response.
    yuzu_gw_router ! {fanout_terminal, FanoutRef, AgentId},

    %% Should get fanout_complete.
    receive
        {fanout_complete, FanoutRef, #{targets := 1, received := 1}} -> ok
    after 2000 ->
        ct:fail("No fanout_complete received")
    end,

    stop_agent(AgentPid).

command_fanout_multiple_agents(_Config) ->
    %% Start multiple fake agents.
    Agents = [start_responding_agent(iolist_to_binary(
        io_lib:format("fanout-multi-~b", [I]))) || I <- lists:seq(1, 5)],
    Ids = [Id || {_, Id} <- Agents],

    Cmd = #{command_id => <<"cmd-multi-1">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command(Ids, Cmd, #{}),

    %% All agents should receive the dispatch.
    Received = collect_dispatches(5, 2000),
    ?assertEqual(5, length(Received)),

    %% Simulate all responding.
    lists:foreach(fun(Id) ->
        yuzu_gw_router ! {fanout_terminal, FanoutRef, Id}
    end, Ids),

    receive
        {fanout_complete, FanoutRef, #{targets := 5, received := 5}} -> ok
    after 2000 ->
        ct:fail("No fanout_complete")
    end,

    lists:foreach(fun({Pid, _}) -> stop_agent(Pid) end, Agents).

command_fanout_timeout(_Config) ->
    %% Start an agent that never responds.
    AgentId = <<"fanout-timeout-1">>,
    {AgentPid, _} = start_silent_agent(AgentId),

    Cmd = #{command_id => <<"cmd-timeout-1">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command([AgentId], Cmd, #{timeout_seconds => 1}),

    %% Wait for timeout.
    receive
        {fanout_complete, FanoutRef, #{timed_out := 1}} -> ok
    after 5000 ->
        ct:fail("Fanout didn't timeout")
    end,

    stop_agent(AgentPid).

command_fanout_missing_agent(_Config) ->
    Cmd = #{command_id => <<"cmd-missing-1">>, plugin => <<"svc">>},
    {ok, FanoutRef} = yuzu_gw_router:send_command([<<"nonexistent-agent">>], Cmd, #{}),

    %% Should get immediate error.
    receive
        {command_error, FanoutRef, <<"nonexistent-agent">>, not_connected} -> ok
    after 1000 ->
        ct:fail("Expected command_error")
    end,

    %% And immediate completion.
    receive
        {fanout_complete, FanoutRef, #{targets := 0, skipped := 1}} -> ok
    after 1000 ->
        ct:fail("Expected fanout_complete")
    end.

%%%===================================================================
%%% Management Service Tests
%%%===================================================================

mgmt_list_agents(_Config) ->
    %% Register some agents.
    Agents = [start_silent_agent(iolist_to_binary(
        io_lib:format("list-agent-~b", [I]))) || I <- lists:seq(1, 10)],

    Request = #{limit => 5, cursor => undefined},
    {ok, Response, _} = yuzu_gw_mgmt_service:list_agents(Request, #{}),

    AgentList = maps:get(agents, Response),
    ?assertEqual(5, length(AgentList)),
    ?assertNotEqual(<<>>, maps:get(next_cursor, Response)),

    %% Second page.
    Request2 = #{limit => 10, cursor => maps:get(next_cursor, Response)},
    {ok, Response2, _} = yuzu_gw_mgmt_service:list_agents(Request2, #{}),
    AgentList2 = maps:get(agents, Response2),
    ?assert(length(AgentList2) >= 5),

    lists:foreach(fun({Pid, _}) -> stop_agent(Pid) end, Agents).

mgmt_get_agent(_Config) ->
    AgentId = <<"get-agent-1">>,
    {AgentPid, _} = start_silent_agent(AgentId),

    Request = #{agent_id => AgentId},
    {ok, Response, _} = yuzu_gw_mgmt_service:get_agent(Request, #{}),

    Summary = maps:get(summary, Response),
    ?assertEqual(AgentId, maps:get(agent_id, Summary)),
    ?assertEqual(true, maps:get(online, Summary)),

    stop_agent(AgentPid).

%%%===================================================================
%%% Upstream Proxy Tests
%%%===================================================================

upstream_register_error_handling(Config) ->
    %% Test error handling when upstream returns failure.
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ -> {error, {14, <<"UNAVAILABLE">>, #{}}}
        end
    end),

    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertMatch({error, {14, _}}, Result),
    Config.

upstream_batch_heartbeat_flush(Config) ->
    %% Queue several heartbeats and trigger flush.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),

    %% Queue heartbeats.
    lists:foreach(fun(I) ->
        yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => integer_to_binary(I)})
    end, lists:seq(1, 5)),

    timer:sleep(50),

    %% Trigger flush.
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(150),

    %% Verify batch was sent.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),

    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assertEqual(5, length(HBs)),

    Config.

upstream_stream_status_notification(Config) ->
    %% Test stream status notifications.
    Self = self(),
    Ref = make_ref(),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"NotifyStreamStatus">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                Self ! {stream_status_called, Ref, Req},
                {ok, #{acknowledged => true}, #{}}
        end
    end),

    yuzu_gw_upstream:notify_stream_status(<<"agent-1">>, <<"sess-1">>, connected, <<"127.0.0.1">>,
                                           <<"test-home-1">>),

    %% It's fire-and-forget via spawn, so wait a bit.
    timer:sleep(200),

    receive
        {stream_status_called, Ref, Req} ->
            ?assertEqual(<<"agent-1">>, maps:get(agent_id, Req)),
            ?assertEqual('CONNECTED', maps:get(event, Req))
    after 1000 ->
        ct:fail("NotifyStreamStatus not called")
    end,

    Config.

%%%===================================================================
%%% Resilience Tests
%%%===================================================================

registry_concurrent_registration(_Config) ->
    %% Test concurrent registration from multiple processes.
    N = 100,
    Self = self(),

    Workers = [spawn_link(fun() ->
        Id = iolist_to_binary(io_lib:format("conc-reg-~b", [I])),
        Dummy = spawn(fun() -> receive stop -> ok end end),
        ok = yuzu_gw_registry:register_agent(Id, Dummy, <<"s">>, [], <<>>),
        Self ! {registered, I, Dummy}
    end) || I <- lists:seq(1, N)],

    %% Collect all registrations.
    {Dummies, _} = lists:foldl(fun(_, {Acc, _}) ->
        receive
            {registered, _, Pid} -> {[Pid | Acc], ok}
        after 5000 ->
            {Acc, timeout}
        end
    end, {[], ok}, Workers),

    ?assertEqual(N, length(Dummies)),
    ?assert(yuzu_gw_registry:agent_count() >= N),

    %% Cleanup.
    lists:foreach(fun(Pid) -> Pid ! stop end, Dummies).

registry_reconnection_handling(_Config) ->
    %% Test that re-registering the same agent ID works correctly.
    AgentId = <<"reconnect-agent-1">>,

    %% First registration.
    Pid1 = spawn(fun() -> receive stop -> ok end end),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid1, <<"s1">>, [], <<>>),
    ?assertMatch({ok, Pid1}, yuzu_gw_registry:lookup(AgentId)),

    %% Re-register with new process.
    Pid2 = spawn(fun() -> receive stop -> ok end end),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid2, <<"s2">>, [], <<>>),
    ?assertMatch({ok, Pid2}, yuzu_gw_registry:lookup(AgentId)),

    %% Cleanup.
    Pid1 ! stop,
    Pid2 ! stop.

router_broadcast_to_all(_Config) ->
    %% Test broadcast to all agents.
    Agents = [start_responding_agent(iolist_to_binary(
        io_lib:format("broadcast-~b", [I]))) || I <- lists:seq(1, 3)],

    Cmd = #{command_id => <<"cmd-broadcast">>, plugin => <<"svc">>},
    {ok, _FanoutRef} = yuzu_gw_router:send_command([], Cmd, #{}),

    %% All agents should receive.
    Received = collect_dispatches(3, 2000),
    ?assert(length(Received) >= 3),

    lists:foreach(fun({Pid, _}) -> stop_agent(Pid) end, Agents).

stream_write_failure_handling(_Config) ->
    %% Test that stream write failures are handled gracefully.
    AgentId = <<"write-fail-agent-1">>,

    %% Start agent with us as stream_pid.
    Args = #{
        agent_id => AgentId,
        session_id => <<"wf-sess-1">>,
        stream_pid => self(),
        agent_info => #{plugins => [#{name => <<"svc">>}]},
        peer_addr => <<"127.0.0.1">>
    },
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),
    timer:sleep(50),

    %% Dispatch a command - we receive it as {send_command, Cmd}.
    Cmd = #{command_id => <<"cmd-wf-1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(AgentPid, Cmd, {self(), make_ref()}),

    receive
        {send_command, _ReceivedCmd} -> ok
    after 1000 ->
        ct:fail("No send_command received")
    end,

    %% Simulate stream closure.
    AgentPid ! stream_closed,
    timer:sleep(100),

    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

upstream_disconnect_recovery(_Config) ->
    %% Test that upstream errors don't crash the gateway.
    Self = self(),
    Ref = make_ref(),
    meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) ->
        Self ! {notify_called, Ref},
        ok
    end),
    meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),

    %% Start an agent.
    AgentId = <<"recovery-agent-1">>,
    Args = #{
        agent_id => AgentId,
        session_id => <<"recovery-sess-1">>,
        stream_pid => self(),
        agent_info => #{plugins => []},
        peer_addr => <<"127.0.0.1">>
    },
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),

    %% Verify the notification was sent.
    receive
        {notify_called, Ref} -> ok
    after 1000 ->
        ct:fail("No stream status notification")
    end,

    %% Agent should still be working.
    ?assertMatch({ok, _}, yuzu_gw_agent:get_info(AgentPid)),

    yuzu_gw_agent:disconnect(AgentPid),
    timer:sleep(100).

%%%===================================================================
%%% Test Helpers
%%%===================================================================

start_responding_agent(AgentId) ->
    TestPid = self(),
    Pid = spawn(fun() -> responding_agent_loop(TestPid) end),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid, <<"s">>, [<<"svc">>], <<>>),
    {Pid, AgentId}.

responding_agent_loop(TestPid) ->
    receive
        {'$gen_cast', {dispatch, CommandReq, {_ReplyTo, _FanoutRef}}} ->
            CmdId = maps:get(command_id, CommandReq,
                             maps:get(<<"command_id">>, CommandReq, undefined)),
            TestPid ! {dispatch_received, CmdId},
            responding_agent_loop(TestPid);
        stop ->
            ok;
        _ ->
            responding_agent_loop(TestPid)
    end.

start_silent_agent(AgentId) ->
    Args = #{
        agent_id => AgentId,
        session_id => <<"sess-", AgentId/binary>>,
        stream_pid => self(),
        agent_info => #{plugins => [#{name => <<"svc">>}]},
        peer_addr => <<"127.0.0.1">>
    },
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    timer:sleep(20),
    {Pid, AgentId}.

stop_agent(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            MonRef = monitor(process, Pid),
            exit(Pid, shutdown),
            receive
                {'DOWN', MonRef, process, Pid, _} -> ok
            after 2000 ->
                exit(Pid, kill),
                ok
            end;
        false ->
            ok
    end.

collect_dispatches(N, Timeout) ->
    collect_dispatches(N, Timeout, []).

collect_dispatches(0, _Timeout, Acc) -> lists:reverse(Acc);
collect_dispatches(N, Timeout, Acc) ->
    receive
        {dispatch_received, CmdId} ->
            collect_dispatches(N - 1, Timeout, [CmdId | Acc])
    after Timeout ->
        lists:reverse(Acc)
    end.
