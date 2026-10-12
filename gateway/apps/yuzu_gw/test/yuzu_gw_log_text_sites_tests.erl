%%%-------------------------------------------------------------------
%%% @doc Agent supplied text in log lines (#4632).
%%%
%%% An agent id, a session id header and a command id are text an agent chooses;
%%% written raw with ~s, a CR, LF or ESC starts a second log line or recolours a
%%% terminal. Every log line naming such a value passes it through
%%% yuzu_gw_env:log_text/1 (cut to 128 bytes, control characters become `?').
%%% The connect and registered lines are pinned by the heartbeat-binding module,
%%% the registration replay lines by the replay module; this module pins exactly
%%% the sites listed here (a log_text/1 call at a site not named here is not
%%% pinned by it):
%%%   - yuzu_gw_agent: stream error, stream handler died, adopted replay
%%%     re-announce (streaming and connecting), stale re-announce ignored,
%%%     orphaned response, disconnect
%%%   - yuzu_gw_agent_service: Subscribe with a session id nobody registered
%%%   - yuzu_gw_upstream: the guardian forward lines (circuit open, at capacity,
%%%     failed); the notification lines (pending store full, peer address
%%%     replaced, failed to notify from a closed-state worker and from the
%%%     half_open probe, probe worker exited, probe killed at its deadline, evicted
%%%     held notification); the
%%%     replay line for a request that could not be encoded; and "Upstream RPC
%%%     failed" with a server message (the request-fault branch and the other)
%%%
%%% Each test provokes its line with an id made of a marker, CR, LF, an injected
%%% word and ESC, waits for it (event driven, bounded) and requires the marker
%%% and none of the raw control characters.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_log_text_sites_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").


-define(AWAIT_MS, 5000).
%% The guardian at-capacity fixture: the table of blocked workers and the key that
%% holds the test's pid.
-define(BLOCKED, yuzu_log_text_blocked_workers).
-define(BLOCKED_TEST, {?MODULE, blocked_test_pid}).
%% The agents the replay test registered ({Id, Pid}), reaped by its teardown.
-define(NOTIFY_AGENTS, yuzu_log_text_notify_agents).
%% The agents a test of the agent group started, reaped by its teardown.
-define(STARTED, yuzu_log_text_started).
-define(ENV_KEYS, [circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms,
                   notify_pending_max,
                   notify_probe_timeout_ms]).
%% The tag of the exception yuzu_gw_upstream:encode_request/2 raises for a request
%% that cannot be encoded here (?LOCAL_ENCODE_FAILED in that module).
-define(LOCAL_ENCODE_FAILED, yuzu_gw_local_encode_failed).

%%%===================================================================
%%% yuzu_gw_agent
%%%===================================================================

agent_test_() ->
    {foreach,
     fun setup_agent/0,
     fun cleanup_agent/1,
     [
      t("stream error", fun agent_stream_error_line/0),
      t("stream handler died", fun agent_stream_handler_died_line/0),
      t("adopted replay re-announce (streaming)", fun agent_reannounce_line/0),
      t("adopted replay re-announce (still connecting)", fun agent_connecting_reannounce_line/0),
      t("stale re-announce ignored", fun agent_stale_reannounce_line/0),
      t("orphaned response names the agent and the command id",
        fun agent_orphaned_response_line/0),
      t("disconnect", fun agent_disconnect_line/0)
     ]}.

setup_agent() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    catch ets:delete(?STARTED),
    ?STARTED = ets:new(?STARTED, [named_table, public, set]),
    ok.

cleanup_agent(_) ->
    Pids = [P || {P} <- ets:tab2list(?STARTED)],
    Mons = [monitor(process, P) || P <- Pids],
    [exit(P, kill) || P <- Pids],
    [receive {'DOWN', M, process, _, _} -> ok after ?AWAIT_MS -> ok end || M <- Mons],
    ets:delete(?STARTED),
    catch meck:unload(yuzu_gw_upstream),
    ok.

%% An agent started the way the Subscribe handler starts it. The ets table of
%% the fixture records it so teardown can reap it. Registered in the (real)
%% registry under the marker id.
start_agent(Started, Id, StreamPid) ->
    Args = #{agent_id => Id, session_id => <<"sess-", Id/binary>>, stream_pid => StreamPid,
             agent_info => #{agent_id => Id}, peer_addr => <<"peer">>, conn_key => conn_log_text},
    {ok, Agent} = yuzu_gw_agent:start_link(Args),
    unlink(Agent),
    true = ets:insert(Started, {Agent}),
    Agent.

agent_stream_error_line() ->
    Started = started(),
    Id = control_id(<<"agent-err">>),
    Line = capture_line(<<"Stream error for agent">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        Agent ! {stream_error, boom}
    end),
    assert_clean(Line, <<"agent-err">>).

agent_stream_handler_died_line() ->
    Started = started(),
    Id = control_id(<<"agent-died">>),
    Stream = spawn(fun() -> receive stop -> ok end end),
    Line = capture_line(<<"Stream handler died for agent">>, fun() ->
        _ = start_agent(Started, Id, Stream),
        exit(Stream, kill)
    end),
    assert_clean(Line, <<"agent-died">>).

agent_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-reann">>),
    Line = capture_line(<<"upstream adopted replay under session">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:reannounce(Agent, <<"sess-", Id/binary>>)
    end, debug),
    assert_clean(Line, <<"agent-reann">>).

%% An agent whose Subscribe handler has not yet reported its stream pid stays in
%% `connecting', which has its own copy of the line.
agent_connecting_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-conn-reann">>),
    Line = capture_line(<<"(still connecting)">>, fun() ->
        Agent = start_agent(Started, Id, undefined),
        yuzu_gw_agent:reannounce(Agent, <<"sess-", Id/binary>>)
    end, debug),
    assert_clean(Line, <<"agent-conn-reann">>).

%% A re-announce for a session this process has moved on from is ignored, and
%% says so under the agent id.
agent_stale_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-stale">>),
    Line = capture_line(<<"ignoring stale upstream_reannounced">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:reannounce(Agent, <<"some-other-session">>)
    end, debug),
    assert_clean(Line, <<"agent-stale">>).

%% The command id is read from the response frame, so it is the agent's text too.
agent_orphaned_response_line() ->
    Started = started(),
    Id = control_id(<<"agent-orph">>),
    CmdId = control_id(<<"cmd-orph">>),
    Line = capture_line(<<"Orphaned response from">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        Agent ! {stream_data, #{<<"command_id">> => CmdId}}
    end, debug),
    assert_clean(Line, <<"agent-orph">>),
    ?assertNotEqual(nomatch, binary:match(Line, <<"cmd-orph">>)).

agent_disconnect_line() ->
    Started = started(),
    Id = control_id(<<"agent-disc">>),
    Line = capture_line(<<"disconnected (was connected">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:disconnect(Agent)
    end, info),
    assert_clean(Line, <<"agent-disc">>).

started() ->
    ?STARTED.

%%%===================================================================
%%% yuzu_gw_agent_service
%%%===================================================================

service_test_() ->
    {foreach,
     fun() ->
         {ok, _} = application:ensure_all_started(telemetry),
         yuzu_gw_test_registry:ensure(),
         ok
     end,
     fun(_) -> ok end,
     [
      t("Subscribe names the session id nobody registered without raw control characters",
        fun subscribe_unknown_session_line/0)
     ]}.

%% The x-yuzu-session-id header is client text. Subscribe logs it when no
%% registration is pending for it.
subscribe_unknown_session_line() ->
    Session = control_id(<<"session-unknown">>),
    catch meck:unload(grpcbox_stream),
    ok = meck:new(grpcbox_stream, [non_strict, no_link]),
    try
        ok = meck:expect(grpcbox_stream, ctx,
                         fun(_State) ->
                             ctx:set(ctx:background(), md_incoming_key,
                                     #{<<"x-yuzu-session-id">> => Session})
                         end),
        Line = capture_line(<<"Subscribe: no pending registration for session">>, fun() ->
            ?assertThrow({grpc_error, {?GRPC_STATUS_NOT_FOUND, _}},
                         yuzu_gw_agent_service:subscribe(make_ref(), not_a_stream_state))
        end),
        assert_clean(Line, <<"session-unknown">>)
    after
        meck:unload(grpcbox_stream)
    end.

%%%===================================================================
%%% yuzu_gw_upstream: the guardian forward lines
%%%===================================================================

guardian_test_() ->
    {foreach,
     fun setup_guardian/0,
     fun cleanup_guardian/1,
     [
      t("a guardian message dropped because the circuit is open",
        fun guardian_dropped_circuit_open_line/0),
      t("a guardian message the upstream failed to take",
        fun guardian_forward_failed_line/0)
     ]}.

%% The in-flight budget of guardian forwards (50) is full: each worker blocks
%% inside the mocked client until the test releases it.
guardian_capacity_test_() ->
    {foreach,
     fun setup_guardian_blocked/0,
     fun cleanup_guardian_blocked/1,
     [
      t("a guardian message dropped because the in-flight budget is full",
        fun guardian_dropped_at_capacity_line/0)
     ]}.

setup_guardian() ->
    {ok, _} = application:ensure_all_started(telemetry),
    catch meck:unload(grpcbox_client),
    yuzu_gw_test_upstream:stop_upstream(),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:set_breaker_env(3),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) -> {error, econnrefused} end),
    yuzu_gw_test_upstream:start_upstream(),
    #{prev_env => Prev}.

cleanup_guardian(#{prev_env := Prev}) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(grpcbox_client),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%% The mocked client reports each call to the test and waits for a release
%% message. The test registers its pid under ?BLOCKED_TEST (setup does not run in
%% the test's process) and the workers sit in a public table the teardown
%% releases by exact pid whatever the test did.
setup_guardian_blocked() ->
    {ok, _} = application:ensure_all_started(telemetry),
    catch meck:unload(grpcbox_client),
    yuzu_gw_test_upstream:stop_upstream(),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:set_breaker_env(3),
    catch ets:delete(?BLOCKED),
    ?BLOCKED = ets:new(?BLOCKED, [named_table, public, set]),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         true = ets:insert(?BLOCKED, {self()}),
                         persistent_term:get(?BLOCKED_TEST) ! {guardian_call_entered, self()},
                         receive release_guardian_call -> {error, {<<"3">>, <<"released">>}, #{}}
                         after 60000 -> {error, {<<"3">>, <<"never released">>}, #{}}
                         end
                     end),
    yuzu_gw_test_upstream:start_upstream(),
    #{prev_env => Prev}.

cleanup_guardian_blocked(Ctx) ->
    [W ! release_guardian_call || {W} <- ets:tab2list(?BLOCKED)],
    ets:delete(?BLOCKED),
    catch persistent_term:erase(?BLOCKED_TEST),
    cleanup_guardian(Ctx).

guardian_dropped_circuit_open_line() ->
    Id = control_id(<<"guardian-open">>),
    trip_breaker(),
    Line = capture_line(<<"Dropping guardian message for">>, fun() ->
        yuzu_gw_upstream:forward_guardian_message(Id, #{})
    end, debug),
    assert_clean(Line, <<"guardian-open">>).

guardian_dropped_at_capacity_line() ->
    ok = persistent_term:put(?BLOCKED_TEST, self()),
    Fill = [yuzu_gw_upstream:forward_guardian_message(<<"filler-", (integer_to_binary(I))/binary>>, #{})
            || I <- lists:seq(1, 50)],
    ?assertEqual(50, length(Fill)),
    %% Every worker is inside the client before the next message is offered.
    Workers = [receive {guardian_call_entered, W} -> W
               after ?AWAIT_MS -> erlang:error(guardian_worker_not_entered)
               end || _ <- Fill],
    Id = control_id(<<"guardian-cap">>),
    try
        Line = capture_line(<<"(at capacity)">>, fun() ->
            yuzu_gw_upstream:forward_guardian_message(Id, #{})
        end, debug),
        assert_clean(Line, <<"guardian-cap">>)
    after
        [W ! release_guardian_call || W <- Workers]
    end.

guardian_forward_failed_line() ->
    Id = control_id(<<"guardian-fail">>),
    Line = capture_line(<<"Failed to forward guardian message for">>, fun() ->
        yuzu_gw_upstream:forward_guardian_message(Id, #{})
    end),
    assert_clean(Line, <<"guardian-fail">>).

%%%===================================================================
%%% yuzu_gw_upstream: the notification, replay and RPC failure lines
%%%===================================================================

%% Breaker thresholds as in the guardian fixture (3 failures to open, timers far
%% beyond a test), so the breaker is tripped by three failed proxy_register calls
%% and moved to half_open by the test, never by a timer. The mock fails every
%% call until a test overrides it.
notify_test_() ->
    {foreach,
     fun() -> setup_notify([]) end,
     fun cleanup_notify/1,
     [
      t("a peer address that was replaced",
        fun notify_peer_addr_replaced_line/0),
      t("a notification a closed-state worker failed to send",
        fun notify_failed_closed_line/0),
      t("a notification the half_open probe failed to send",
        fun notify_failed_probe_line/0),
      t("a half_open probe worker that exited without a result",
        fun notify_probe_worker_exited_line/0),
      t("a held notification evicted because it cannot be encoded",
        fun notify_evicted_line/0),
      t("a registration replay whose stored request could not be encoded",
        fun replay_not_encodable_line/0),
      t("an upstream RPC answered with a request-fault status and a server message",
        fun rpc_failed_request_fault_line/0),
      t("an upstream RPC answered with another status and a server message",
        fun rpc_failed_other_line/0)
     ]}.

%% The probe deadline, 100 ms: the probe worker parks in the mock for ever.
notify_probe_timeout_test_() ->
    {foreach,
     fun() -> setup_notify([{notify_probe_timeout_ms, 100}]) end,
     fun cleanup_notify/1,
     [
      t("a half_open probe worker killed at its deadline",
        fun notify_probe_killed_at_deadline_line/0)
     ]}.

%% Cap 1: one held key fills the store.
notify_cap_test_() ->
    {foreach,
     fun() -> setup_notify([{notify_pending_max, 1}]) end,
     fun cleanup_notify/1,
     [
      t("a held notification dropped because the pending store is full (cap 1)",
        fun notify_pending_full_line/0)
     ]}.

setup_notify(Env) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    yuzu_gw_test_upstream:stop_upstream(),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:set_breaker_env(3),
    [application:set_env(yuzu_gw, K, V) || {K, V} <- Env],
    catch ets:delete(?BLOCKED),
    ?BLOCKED = ets:new(?BLOCKED, [named_table, public, set]),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) -> {error, econnrefused} end),
    yuzu_gw_test_upstream:start_upstream(),
    catch ets:delete(?NOTIFY_AGENTS),
    ?NOTIFY_AGENTS = ets:new(?NOTIFY_AGENTS, [named_table, public, set]),
    #{prev_env => Prev}.

cleanup_notify(Ctx) ->
    [exit(W, kill) || {W} <- ets:tab2list(?BLOCKED)],
    ets:delete(?BLOCKED),
    [begin
         yuzu_gw_registry:deregister_agent(Id),
         exit(Pid, kill)
     end || {Id, Pid} <- ets:tab2list(?NOTIFY_AGENTS)],
    %% deregister_agent/1 is a cast: a call to the registry is handled after it
    %% (same sender), so its reply proves the agents are gone.
    _ = sys:get_state(yuzu_gw_registry, 5000),
    ets:delete(?NOTIFY_AGENTS),
    cleanup_guardian(Ctx).

%% Three failed registrations: the breaker is open.
trip_breaker() ->
    yuzu_gw_test_upstream:trip_breaker(#{info => #{agent_id => <<"a">>}}, 3).

notify(AgentId, PeerAddr) ->
    yuzu_gw_upstream:notify_stream_status(AgentId, <<"sess">>, connected, PeerAddr, <<"home">>).

enter_half_open() ->
    yuzu_gw_upstream ! circuit_half_open,
    ok.

%% The breaker is open, the one slot of the store holds another agent's
%% notification, so the next one is refused.
notify_pending_full_line() ->
    Id = control_id(<<"notify-full">>),
    trip_breaker(),
    notify(<<"holder">>, <<"peer">>),
    Line = capture_line(<<"Dropping stream status notification for">>, fun() ->
        notify(Id, <<"peer">>)
    end, debug),
    assert_clean(Line, <<"notify-full">>).

notify_peer_addr_replaced_line() ->
    Id = control_id(<<"notify-peer">>),
    Line = capture_line(<<"peer address replaced">>, fun() ->
        notify(Id, <<255, 254, 200>>)
    end, debug),
    assert_clean(Line, <<"notify-peer">>).

%% The breaker is closed, so the worker drain/1 spawns reports the failure.
notify_failed_closed_line() ->
    Id = control_id(<<"notify-closed">>),
    Line = capture_line(<<"Failed to notify stream status for">>, fun() ->
        notify(Id, <<"peer">>)
    end),
    assert_clean(Line, <<"notify-closed">>).

%% The breaker is half_open, so the probe worker reports the failure.
notify_failed_probe_line() ->
    Id = control_id(<<"notify-probe">>),
    trip_breaker(),
    notify(Id, <<"peer">>),
    Line = capture_line(<<"Failed to notify stream status for">>, fun() ->
        enter_half_open()
    end),
    assert_clean(Line, <<"notify-probe">>).

%% The probe worker parks inside the mocked client and is killed there.
notify_probe_worker_exited_line() ->
    Id = control_id(<<"notify-exited">>),
    Test = self(),
    trip_breaker(),
    notify(Id, <<"peer">>),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         true = ets:insert(?BLOCKED, {self()}),
                         Test ! {probe_entered, self()},
                         receive release_probe -> {error, econnrefused}
                         after 60000 -> {error, econnrefused}
                         end
                     end),
    Line = capture_line(<<"exited without a result">>, fun() ->
        enter_half_open(),
        Probe = receive {probe_entered, W} -> W
                after ?AWAIT_MS -> erlang:error(probe_worker_not_entered)
                end,
        exit(Probe, kill)
    end),
    assert_clean(Line, <<"notify-exited">>).

%% The probe worker parks inside the mocked client and is never released: only
%% the deadline ends it, and its line names the agent.
notify_probe_killed_at_deadline_line() ->
    Id = control_id(<<"notify-deadline">>),
    Test = self(),
    trip_breaker(),
    notify(Id, <<"peer">>),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         true = ets:insert(?BLOCKED, {self()}),
                         Test ! {probe_entered, self()},
                         receive release_probe -> {error, econnrefused}
                         after 60000 -> {error, econnrefused}
                         end
                     end),
    Line = capture_line(<<"did not answer within">>, fun() ->
        enter_half_open(),
        receive {probe_entered, _} -> ok
        after ?AWAIT_MS -> erlang:error(probe_worker_not_entered)
        end
    end),
    assert_clean(Line, <<"notify-deadline">>).

%% The probe's request cannot be encoded here: the held entry is evicted.
notify_evicted_line() ->
    Id = control_id(<<"notify-evicted">>),
    trip_breaker(),
    notify(Id, <<"peer">>),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         erlang:error({?LOCAL_ENCODE_FAILED, error, boom})
                     end),
    Line = capture_line(<<"Evicted held stream status notification for">>, fun() ->
        enter_half_open()
    end),
    assert_clean(Line, <<"notify-evicted">>).

%% A stored registration request that cannot be encoded is skipped, and the line
%% names the agent.
replay_not_encodable_line() ->
    Id = control_id(<<"replay-enc">>),
    Pid = spawn(fun() -> receive stop -> ok end end),
    true = ets:insert(?NOTIFY_AGENTS, {Id, Pid}),
    ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess-replay-enc">>, [<<"svc">>],
                                         <<"host">>, #{info => #{agent_id => Id}},
                                         conn_log_text),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         erlang:error({?LOCAL_ENCODE_FAILED, error, boom})
                     end),
    Line = capture_line(<<"could not be encoded">>, fun() ->
        gen_server:cast(yuzu_gw_upstream, replay_registrations)
    end),
    assert_clean(Line, <<"replay-enc">>).

%% A server message is the server's text: INVALID_ARGUMENT is a request fault and
%% goes through the rate limited warning, which is told to log now.
rpc_failed_request_fault_line() ->
    Msg = control_id(<<"rpc-fault">>),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         {error, {<<"3">>, Msg}, #{}}
                     end),
    ok = yuzu_gw_safe_call:expire_limit(rpc_answered_error),
    Line = capture_line(<<"Upstream RPC">>, fun() ->
        {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"a">>}})
    end),
    ?assertNotEqual(nomatch, binary:match(Line, <<"failed">>)),
    assert_clean(Line, <<"rpc-fault">>).

%% INTERNAL is not a request fault: the plain warning.
rpc_failed_other_line() ->
    Msg = control_id(<<"rpc-other">>),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         {error, {<<"13">>, Msg}, #{}}
                     end),
    Line = capture_line(<<"Upstream RPC">>, fun() ->
        {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"a">>}})
    end),
    ?assertNotEqual(nomatch, binary:match(Line, <<"failed">>)),
    assert_clean(Line, <<"rpc-other">>).

%%%===================================================================
%%% Helpers
%%%===================================================================

t(Name, Fun) ->
    {timeout, 30, {Name, Fun}}.

%% The marker, a carriage return, a line feed, an injected word and an escape.
control_id(Marker) ->
    <<"ctl-", Marker/binary, 13, 10, "INJECTED", 27, "[31m">>.

assert_clean(Line, Marker) ->
    ?assertNotEqual(nomatch, binary:match(Line, <<"ctl-", Marker/binary>>)),
    %% A line may still wrap where ~p pretty prints a term, so a bare LF is not
    %% the signal: the injected word after it is.
    [?assertEqual({nomatch, Raw}, {binary:match(Line, Raw), Raw})
     || Raw <- [<<13>>, <<27>>, <<10, "INJECTED">>]].

capture_line(Pattern, Fun) ->
    capture_line(Pattern, Fun, warning).

%% Run Fun with a capturing handler at Level and return the first line that
%% contains Pattern and the marker prefix, waiting (bounded) for it to be logged.
capture_line(Pattern, Fun, Level) ->
    yuzu_gw_test_logs:with_handler(Level, fun() ->
        Fun(),
        await_line(Pattern, erlang:monotonic_time(millisecond) + ?AWAIT_MS)
    end).

await_line(Pattern, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {captured_log, Text} ->
            case binary:match(Text, Pattern) =/= nomatch
                 andalso binary:match(Text, <<"ctl-">>) =/= nomatch of
                true  -> Text;
                false -> await_line(Pattern, Deadline)
            end
    after Left ->
        erlang:error({line_not_logged, Pattern})
    end.
