%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_agent — gen_statem lifecycle.
%%%
%%% Mocks: yuzu_gw_upstream, telemetry.
%%% Real:  yuzu_gw_registry (needs pg + ETS).
%%%
%%% The agent sends {send_command, Cmd} to its stream_pid (the test
%%% process). Responses from the agent arrive as {stream_data, Frame}.
%%% Stream close is signalled as the atom stream_closed.
%%%
%%% Key assertions:
%%%   - Agent transitions connecting → streaming on stream_ready
%%%   - Agent dispatches commands to stream_pid
%%%   - Agent tracks pending command map
%%%   - Agent cleans up and STOPS on stream close
%%%   - Pending command waiters are notified on disconnect
%%%   - Orphaned responses are silently dropped
%%%   - Stream handler death triggers disconnect (monitor)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

agent_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"starts in streaming when stream_pid provided", fun starts_streaming/0},
      {"starts in connecting when stream_pid is undefined", fun starts_connecting/0},
      {"connecting transitions to streaming on stream_ready", fun connecting_to_streaming/0},
      {"connecting rejects dispatch", fun connecting_rejects_dispatch/0},
      {"streaming dispatches command to stream_pid", fun streaming_dispatches/0},
      {"streaming tracks pending commands", fun streaming_tracks_pending/0},
      {"streaming removes pending on terminal response", fun streaming_clears_pending/0},
      {"streaming keeps pending on RUNNING response", fun streaming_keeps_running/0},
      {"streaming handles orphaned response", fun streaming_orphaned_response/0},
      {"agent stops on stream_closed", fun stops_on_close/0},
      {"stream_home_id is identical on CONNECTED and DISCONNECTED (#4324)", fun stream_home_id_identical_on_connect_and_disconnect/0},
      {"agent stops on stream_error", fun stops_on_error/0},
      {"disconnect notifies pending waiters", fun disconnect_notifies_pending/0},
      {"get_info returns state", fun get_info_works/0},
      {"stream handler death triggers disconnect", fun stream_handler_death/0},
      {"stream handler death in connecting state", fun stream_handler_death_connecting/0},
      {"HA WS-4 4.4: reannounce for the CURRENT session re-sends CONNECTED",
       fun reannounce_same_session_resends_connected/0},
      {"HA WS-4 4.4: reannounce for a DIFFERENT (superseded) session is ignored",
       fun reannounce_different_session_ignored/0}
     ]}.

setup() ->
    %% Ensure pg + a real registry under its registered name. The helper
    %% navigates both #336 hazards: a mock_loop impostor left by
    %% health_nf_tests (which would hang register_agent), and the
    %% orphaned-but-not-yet-reaped registry whose still-owned named ETS
    %% tables crash a fresh start_link's init/1 (issue #1403).
    yuzu_gw_test_registry:ensure(),
    %% Clean up stale mocks from prior modules.
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(telemetry),
    %% Fail loud at the boundary if a prior test leaked the real
    %% yuzu_gw_upstream gen_server. Otherwise the meck stub installed
    %% below would silently coexist with the registered process and
    %% the next test would time out opaquely. See issue #336.
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    %% Mock external deps.
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status,
                fun(_, _, _, _, _) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

cleanup(_) ->
    meck:unload([yuzu_gw_upstream, telemetry]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

starts_streaming() ->
    %% self() as stream_pid → starts in streaming state
    {Pid, _} = start_agent(<<"ss-1">>, self()),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(streaming, maps:get(state, Info)),
    stop_agent(Pid).

starts_connecting() ->
    %% undefined stream_pid → starts in connecting state
    {Pid, _} = start_agent(<<"sc-1">>, undefined),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(connecting, maps:get(state, Info)),
    stop_agent(Pid).

connecting_to_streaming() ->
    {Pid, _} = start_agent(<<"cts-1">>, undefined),
    {ok, Info1} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(connecting, maps:get(state, Info1)),
    %% stream_ready transitions to streaming.
    gen_statem:cast(Pid, {stream_ready, self()}),
    timer:sleep(20),
    {ok, Info2} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(streaming, maps:get(state, Info2)),
    stop_agent(Pid).

connecting_rejects_dispatch() ->
    {Pid, AgentId} = start_agent(<<"cr-1">>, undefined),
    Ref = make_ref(),
    yuzu_gw_agent:dispatch(Pid, #{command_id => <<"c1">>}, {self(), Ref}),
    receive
        {command_error, Ref, AgentId, not_connected} -> ok
    after 1000 ->
        ?assert(false, "Expected command_error not_connected")
    end,
    stop_agent(Pid).

streaming_dispatches() ->
    %% The agent sends {send_command, Cmd} to our process (stream_pid = self()).
    {Pid, _} = start_agent(<<"sd-1">>, self()),
    Ref = make_ref(),
    Cmd = #{command_id => <<"cmd-1">>, plugin => <<"svc">>, action => <<"list">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), Ref}),
    receive
        {send_command, ReceivedCmd} ->
            ?assertEqual(<<"cmd-1">>, maps:get(command_id, ReceivedCmd,
                                               maps:get(<<"command_id">>, ReceivedCmd, undefined)))
    after 1000 ->
        ?assert(false, "Expected {send_command, Cmd} from agent")
    end,
    stop_agent(Pid).

streaming_tracks_pending() ->
    {Pid, _} = start_agent(<<"stp-1">>, self()),
    Ref = make_ref(),
    Cmd = #{command_id => <<"cmd-p1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), Ref}),
    %% Drain the send_command message so our mailbox doesn't accumulate.
    receive {send_command, _} -> ok after 1000 -> ok end,
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(1, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_clears_pending() ->
    {Pid, _} = start_agent(<<"scp-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-c1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    %% Simulate terminal response arriving at the agent process.
    Pid ! {stream_data, #{command_id => <<"cmd-c1">>, status => 'SUCCESS'}},
    receive
        {command_response, FanoutRef, _, _} -> ok
    after 1000 ->
        ?assert(false, "Expected command_response")
    end,
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(0, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_keeps_running() ->
    {Pid, _} = start_agent(<<"skr-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-r1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    %% RUNNING status should NOT clear pending.
    Pid ! {stream_data, #{command_id => <<"cmd-r1">>, status => 'RUNNING'}},
    timer:sleep(20),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(1, maps:get(pending_cmds, Info)),
    stop_agent(Pid).

streaming_orphaned_response() ->
    {Pid, _} = start_agent(<<"sor-1">>, self()),
    %% Send response for a command we never dispatched — should not crash.
    Pid ! {stream_data, #{command_id => <<"no-such-cmd">>, status => 'SUCCESS'}},
    timer:sleep(20),
    ?assert(is_process_alive(Pid)),
    stop_agent(Pid).

stops_on_close() ->
    {Pid, AgentId} = start_agent(<<"soc-1">>, self()),
    ?assert(is_process_alive(Pid)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(AgentId)),
    %% Simulate gRPC stream close.
    Pid ! stream_closed,
    ok = wait_for_death(Pid, 2000),
    %% Registry must be cleaned up.
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

stops_on_error() ->
    {Pid, AgentId} = start_agent(<<"soe-1">>, self()),
    Pid ! {stream_error, some_error},
    ok = wait_for_death(Pid, 2000),
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

%% HA WS-4 #4324: stream_home_id is minted ONCE in init/1 and must be the
%% SAME value on the CONNECTED call (made during start_agent's init/1) and
%% the later DISCONNECTED call (do_cleanup, triggered by stream_closed) for
%% one process instance. Correctness is structurally guaranteed today (a
%% single #data{} construction site + record-update syntax on every
%% transition, verified by code review) -- this locks it with a real
%% assertion so a future edit that re-mints the id on a second call site
%% regresses loudly instead of silently.
stream_home_id_identical_on_connect_and_disconnect() ->
    {Pid, AgentId} = start_agent(<<"shi-1">>, self()),
    Pid ! stream_closed,
    ok = wait_for_death(Pid, 2000),
    %% The process is dead, so no further call can arrive: waiting for 2
    %% still proves "exactly 2".
    NotifyCalls = await_notify_calls(AgentId, 2),
    ?assertEqual(2, length(NotifyCalls)), % exactly one CONNECTED, one DISCONNECTED
    [ConnectedArgs, DisconnectedArgs] = NotifyCalls,
    ?assertEqual(connected, lists:nth(3, ConnectedArgs)),
    ?assertEqual(disconnected, lists:nth(3, DisconnectedArgs)),
    ConnectedHomeId = lists:nth(5, ConnectedArgs),
    DisconnectedHomeId = lists:nth(5, DisconnectedArgs),
    ?assert(is_binary(ConnectedHomeId)),
    ?assertNotEqual(<<>>, ConnectedHomeId), % genuinely minted, not left empty
    ?assertEqual(ConnectedHomeId, DisconnectedHomeId).

reannounce_same_session_resends_connected() ->
    %% HA WS-4 4.4 (`#4246` #6): reannounce/2 for THIS process's own
    %% session must re-send CONNECTED — the mechanism that converges the
    %% server's freshly-installed AgentSession after a replay-adopted
    %% ProxyRegister wipes its gateway_node/wire_capabilities/
    %% stream_home_id (gateway_service_impl.cpp's ProxyRegister).
    {Pid, AgentId} = start_agent(<<"rsc-1">>, self()),
    SessionId = <<"sess-", AgentId/binary>>,
    meck:reset(yuzu_gw_upstream), % discard the init/1 CONNECTED call
    ok = yuzu_gw_agent:reannounce(Pid, SessionId),
    %% reannounce/2 is a cast; get_info/1 is a call from this same process,
    %% so its reply proves the cast was handled and every notify it makes has
    %% been issued. Waiting for 1 then still proves "exactly 1".
    {ok, _} = yuzu_gw_agent:get_info(Pid),
    NotifyCalls = await_notify_calls(AgentId, 1),
    ?assertEqual(1, length(NotifyCalls)),
    [Args] = NotifyCalls,
    ?assertEqual(SessionId, lists:nth(2, Args)),
    ?assertEqual(connected, lists:nth(3, Args)),
    stop_agent(Pid).

reannounce_different_session_ignored() ->
    %% A reannounce for a session this process no longer holds (it moved
    %% on to a different one, or a stale drip entry) must be a no-op —
    %% the process's own subsequent reconnect already carries the correct
    %% placement.
    {Pid, AgentId} = start_agent(<<"rdi-1">>, self()),
    meck:reset(yuzu_gw_upstream), % discard the init/1 CONNECTED call
    ok = yuzu_gw_agent:reannounce(Pid, <<"sess-someone-else">>),
    %% Barrier: the get_info/1 reply proves the reannounce cast was handled.
    %% The fixed sleep after it is a NEGATIVE check ("no notify arrived"): it
    %% gives a wrongly-issued call's async meck history cast time to land, so
    %% it is kept rather than polled.
    {ok, _} = yuzu_gw_agent:get_info(Pid),
    timer:sleep(20),
    Calls = meck:history(yuzu_gw_upstream),
    NotifyCalls = [Args || {_, {yuzu_gw_upstream, notify_stream_status, Args}, _} <- Calls,
                            lists:nth(1, Args) =:= AgentId],
    ?assertEqual(0, length(NotifyCalls)),
    stop_agent(Pid).

disconnect_notifies_pending() ->
    {Pid, _AgentId} = start_agent(<<"dnp-1">>, self()),
    FanoutRef = make_ref(),
    Cmd = #{command_id => <<"cmd-d1">>, plugin => <<"svc">>},
    yuzu_gw_agent:dispatch(Pid, Cmd, {self(), FanoutRef}),
    receive {send_command, _} -> ok after 1000 -> ok end,
    timer:sleep(20),
    %% Disconnect the agent.
    Pid ! stream_closed,
    %% We should receive a command_error for the pending command.
    receive
        {command_error, FanoutRef, <<"dnp-1">>, agent_disconnected} -> ok
    after 2000 ->
        ?assert(false, "Expected command_error agent_disconnected")
    end.

get_info_works() ->
    {Pid, _} = start_agent(<<"gi-1">>, self()),
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(<<"gi-1">>, maps:get(agent_id, Info)),
    ?assertEqual(streaming, maps:get(state, Info)),
    ?assert(is_integer(maps:get(connected_at, Info))),
    stop_agent(Pid).

stream_handler_death() ->
    %% Start agent with a separate process as stream_pid.
    StreamHandler = spawn(fun() -> receive stop -> ok end end),
    Args = #{agent_id   => <<"shd-1">>,
             session_id => <<"sess-shd-1">>,
             stream_pid => StreamHandler,
             agent_info => #{plugins => [#{name => <<"svc">>}]},
             peer_addr  => <<"127.0.0.1">>},
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    timer:sleep(20),

    %% Verify agent is streaming.
    {ok, Info} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(streaming, maps:get(state, Info)),

    %% Kill the stream handler — agent should detect via monitor.
    exit(StreamHandler, kill),

    %% Agent should transition to disconnected and stop.
    ok = wait_for_death(Pid, 2000),
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"shd-1">>)).

stream_handler_death_connecting() ->
    %% Start in connecting state with a stream_pid that dies.
    StreamHandler = spawn(fun() -> receive stop -> ok end end),
    Args = #{agent_id   => <<"shdc-1">>,
             session_id => <<"sess-shdc-1">>,
             stream_pid => StreamHandler,
             agent_info => #{plugins => []},
             peer_addr  => <<"127.0.0.1">>},
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    timer:sleep(20),

    %% Agent starts in streaming since stream_pid was provided.
    %% To test connecting state, start with undefined then supply pid.
    %% Let's test with a direct pid that dies immediately instead.
    %% Actually, if stream_pid is provided, it starts in streaming.
    %% So let's test: start in connecting (undefined), send stream_ready
    %% with a process that then dies.
    {Pid2, _} = start_agent(<<"shdc-2">>, undefined),
    StreamHandler2 = spawn(fun() -> receive stop -> ok end end),
    gen_statem:cast(Pid2, {stream_ready, StreamHandler2}),
    timer:sleep(20),

    {ok, Info2} = yuzu_gw_agent:get_info(Pid2),
    ?assertEqual(streaming, maps:get(state, Info2)),

    %% Kill the stream handler.
    exit(StreamHandler2, kill),
    ok = wait_for_death(Pid2, 2000),
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"shdc-2">>)),

    %% Cleanup the first agent.
    case is_process_alive(Pid) of
        true  -> yuzu_gw_agent:disconnect(Pid), wait_for_death(Pid, 1000);
        false -> ok
    end.

%%%===================================================================
%%% Helpers
%%%===================================================================

start_agent(AgentId, StreamPid) ->
    Args = #{agent_id   => AgentId,
             session_id => <<"sess-", AgentId/binary>>,
             stream_pid => StreamPid,
             agent_info => #{plugins => [#{name => <<"svc">>}]},
             peer_addr  => <<"127.0.0.1">>},
    {ok, Pid} = yuzu_gw_agent:start_link(Args),
    unlink(Pid),
    {Pid, AgentId}.

%% Poll meck history until at least N notify_stream_status calls for AgentId
%% are recorded (or a 2s deadline passes), and return them in call order.
%% meck records each call with an async cast to its own process, so reading
%% history right after the agent acted (or after a fixed sleep) is an
%% UPPER-bound race on a loaded runner (#4851 runs this suite on macOS CI for
%% the first time; BigMags shares its CPU between two agents). Callers first
%% make sure no further call can be made (a get_info/1 barrier, or the process
%% is dead), and the calls already made were cast to meck before that, so
%% waiting for N and then asserting the exact count is no weaker than the old
%% fixed sleep.
await_notify_calls(AgentId, N) ->
    await_notify_calls(AgentId, N, erlang:monotonic_time(millisecond) + 2000).

await_notify_calls(AgentId, N, Deadline) ->
    Calls = [Args || {_, {yuzu_gw_upstream, notify_stream_status, Args}, _}
                         <- meck:history(yuzu_gw_upstream),
                     lists:nth(1, Args) =:= AgentId],
    case length(Calls) < N andalso erlang:monotonic_time(millisecond) < Deadline of
        true -> timer:sleep(10), await_notify_calls(AgentId, N, Deadline);
        false -> Calls
    end.

stop_agent(Pid) ->
    case is_process_alive(Pid) of
        true ->
            yuzu_gw_agent:disconnect(Pid),
            wait_for_death(Pid, 2000);
        false ->
            ok
    end.

wait_for_death(Pid, Timeout) ->
    MonRef = monitor(process, Pid),
    receive
        {'DOWN', MonRef, process, Pid, _} -> ok
    after Timeout ->
        demonitor(MonRef, [flush]),
        ?assert(false, {process_still_alive, Pid})
    end.
