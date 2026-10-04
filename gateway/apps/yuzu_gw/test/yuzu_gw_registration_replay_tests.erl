%%%-------------------------------------------------------------------
%%% @doc EUnit tests for registration replay on upstream reconnect.
%%%
%%% When yuzu_gw_upstream detects the upstream connection coming back
%%% after a failure, it must re-proxy a ProxyRegister for every agent
%%% the registry currently holds — otherwise a freshly-restarted C++
%%% server comes up with an empty registry and the agents the gateway
%%% still holds are silently stranded.
%%%
%%% These tests drive the *closed-state* recovery path (RPC failures
%%% below the trip threshold, then a success) and the *half_open ->
%%% closed* recovery path, and assert:
%%%   - reconnect with N registered agents => N replay ProxyRegister RPCs
%%%   - reconnect with zero agents => no replay RPCs
%%%   - an agent deregistered before reconnect is NOT replayed
%%%   - the replayed payload is byte-identical to the stored RegisterRequest
%%%   - the half_open -> closed transition also triggers replay
%%%
%%% Real:  yuzu_gw_registry (needs pg + ETS — all_register_reqs/0 reads
%%%        straight from the table).
%%% Mocks: grpcbox_client, telemetry.
%%%
%%% #1197 adds the targeted path: the server's unknown-session verdict
%%% (BatchHeartbeatResponse.unknown_session_ids) reaches
%%% yuzu_gw_upstream:replay_sessions/1 and re-proxies exactly those sessions
%%% through the same drip. Those tests are the second half of this file
%%% (verdict_*_test_/0 generators). They read the upstream state record by
%%% field name (see up_get/1), so the field names replay_queue,
%%% recent_replays, session_guard_ms and replay_queue_max are part of the
%%% contract they pin. The mocks log into an ETS table from the calling
%%% process, so a barrier on the upstream process also orders the log.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registration_replay_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler callback, see capture_logs/1

-define(LOGK, {?MODULE, log}).
-define(SUBK, {?MODULE, sub}).
-define(LOG_HANDLER, yuzu_replay_test_log).
-define(DUMMYK, {?MODULE, dummies}).

-define(EV_TRIG,    [yuzu, gw, upstream, registration_replay_triggered]).
-define(EV_REPLAY,  [yuzu, gw, upstream, registration_replay]).
-define(EV_CIRCUIT, [yuzu, gw, upstream, circuit_state]).
-define(EV_DROP,    [yuzu, gw, heartbeat, verdict_dropped]).
-define(EV_TRUNC,   [yuzu, gw, heartbeat, unknown_truncated]).
-define(EV_RPC_ERROR, [yuzu, gw, upstream, rpc_error]).

%%%===================================================================
%%% Test fixture — fresh upstream per test, shared real registry
%%%===================================================================

replay_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"reconnect re-proxies every registered agent",
       fun reconnect_replays_all_agents/0},
      {"reconnect with zero agents sends no replay rpc",
       fun reconnect_zero_agents_no_rpc/0},
      {"agent deregistered before reconnect is not replayed",
       fun deregistered_agent_not_replayed/0},
      {"replayed payload is byte-identical to stored request",
       fun replay_payload_is_verbatim/0},
      {"half_open to closed transition triggers replay",
       fun half_open_recovery_triggers_replay/0},
      {"HA WS-4 4.4: an ADOPTED replay re-announces CONNECTED",
       fun adopted_replay_reannounces_connected/0},
      {"HA WS-4 4.4: a SUPERSEDED replay counts as breaker success and "
       "forces reconnect",
       fun superseded_replay_forces_reconnect/0},
      {"an ADOPTED replay leaves the session binding and routing row unchanged",
       fun adopted_replay_leaves_session_binding/0}
     ]}.

%%%===================================================================
%%% #1197: the targeted path. Four fixtures differ only in the upstream
%%% env they start with (read once, in init/1).
%%%===================================================================

t(Name, Fun) ->
    {timeout, 30, {Name, Fun}}.

%% Default fixture: guard 10000 ms, queue cap 10000, breaker reset 150 ms.
verdict_replay_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      t("E1 a verdict naming one session re-proxies exactly that session",
        fun targeted_replay_reproxies_only_the_named_session/0),
      t("E2 a session this node does not hold sends nothing and is counted not_local",
        fun unheld_session_sends_nothing/0),
      t("E3 a verdict during an in-flight drip is appended, in order, once",
        fun verdict_during_drip_is_appended_without_restart/0),
      t("E4 the same session inside the guard window is replayed once",
        fun same_session_twice_inside_guard_replays_once/0),
      t("E9 a targeted ADOPT re-announces CONNECTED",
        fun targeted_adopt_reannounces_connected/0),
      t("E9 a targeted REFUSE disconnects the agent and counts as breaker success",
        fun targeted_refuse_disconnects_the_agent/0),
      t("E9b REFUSE after the agent re-registered disconnects the captured old pid only",
        fun refuse_after_reregistration_disconnects_the_old_pid_only/0),
      t("E10 the heartbeat trigger is labelled heartbeat",
        fun triggered_event_is_labelled_heartbeat/0),
      t("E10 breaker recovery through proxy_register/1 is labelled breaker",
        fun triggered_event_is_labelled_breaker/0),
      t("E12 4096 junk ids none held: no rpc, no queue, no stamp, 4096 not_local",
        fun junk_verdict_is_all_not_local/0),
      t("E12b a cast of 5000 ids is cut to 4096 at the boundary; a non-list is ignored",
        fun oversized_or_non_list_cast_is_bounded/0),
      t("E15 an empty stored request is skipped: no rpc, no stamp",
        fun empty_stored_request_is_skipped_without_stamp/0),
      t("E15b an agent re-registered under a new session is skipped at pop",
        fun reregistered_agent_is_skipped_at_pop/0),
      t("E16 a missing session index drops the ids and the upstream stays alive",
        fun missing_session_index_keeps_upstream_alive/0),
      t("E16b the registry stopped mid drip aborts the drip without a crash",
        fun registry_stopped_mid_drip_aborts_without_crash/0),
      t("E17 a breaker replay during a targeted drip is dropped, the drip completes",
        fun breaker_replay_during_targeted_drip_is_dropped/0),
      t("E18 registration_replay_triggered fires once per appending cast",
        fun triggered_fires_once_per_appending_cast/0),
      t("E19 notify pressure holds the head queued and unstamped until a slot frees",
        fun notify_pressure_holds_the_head_unstamped/0),
      t("E20 accepted=false: disconnect, no reannounce, breaker success, stamped",
        fun rejected_replay_disconnects_without_reannounce/0),
      t("E20 a missing accepted key still means accepted",
        fun missing_accepted_key_is_accepted/0),
      t("E20 an OK with no response message is a replay failure, not a crash",
        fun non_map_replay_response_is_a_failure/0),
      t("E21 a second session for an already queued agent is not appended",
        fun second_session_for_a_queued_agent_is_not_appended/0),
      t("E22 queue depth is reported on append and after every step",
        fun queue_depth_is_reported_on_append_and_after_each_step/0),
      t("E22 an empty stored request reports depth on append and on skip",
        fun queue_depth_is_reported_on_skip/0),
      t("a flush verdict reaches the targeted replay end to end",
        fun flush_verdict_reaches_the_targeted_replay/0),
      t("E7 flush errors never reach the breaker",
        fun flush_errors_never_reach_the_breaker/0),
      t("E8 a truncated verdict replays only the listed session",
        fun truncated_verdict_replays_only_the_listed_session/0),
      t("E23 format_status shows counts, never the queued requests",
        fun format_status_shows_counts_not_requests/0),
      t("E23 sys:get_status on the real process shows counts, never the requests",
        fun sys_get_status_shows_counts_not_requests/0),
      t("E23 the reports of an abnormal stop carry the queue as counts",
        fun abnormal_stop_reports_show_queue_counts/0),
      t("E20 a server grpc-message is cut and its control characters replaced in the log",
        fun rpc_error_message_is_sanitised_in_the_log/0),
      t("E23 format_status redacts reason, stacktrace args and log, and is total",
        fun format_status_redacts_reason_log_and_odd_fields/0),
      t("E23 an RPC that raises is a counted failure and carries no request",
        fun rpc_exception_is_counted_and_carries_no_request/0),
      t("E23 a crash with a request in the mailbox: the gen_server report is clean",
        fun crash_with_request_in_mailbox_gen_server_report_clean/0)
     ]}.

%% Breaker reset timers far beyond a test: an open breaker stays open until
%% the test sends circuit_half_open itself, so no assertion races a timer.
verdict_breaker_test_() ->
    Env = [{circuit_breaker_reset_timeout_ms, 600000},
           {circuit_breaker_max_reset_timeout_ms, 600000}],
    {foreach,
     fun() -> setup(Env) end,
     fun cleanup/1,
     [
      t("E11 an open breaker drops the verdict; the half_open probe replays once",
        fun open_breaker_drops_verdict_then_half_open_probe_replays_once/0),
      t("E12c an oversized cast with the circuit open counts only 4096 circuit_open",
        fun oversized_cast_with_open_circuit_is_bounded/0),
      t("E14 a failed half_open probe reopens the breaker",
        fun failed_half_open_probe_reopens/0),
      t("E22 queue depth drops to zero when the drip aborts on an open breaker",
        fun queue_depth_is_zero_after_circuit_abort/0)
     ]}.

%% Session guard 100 ms.
verdict_guard_test_() ->
    {foreach,
     fun() -> setup([{registration_replay_session_guard_ms, 100}]) end,
     fun cleanup/1,
     [
      t("E4 the same session is replayed again once the guard has expired",
        fun session_replayed_again_after_guard_expiry/0),
      t("E21 stale stamps are pruned after a breaker-only drain",
        fun stale_stamps_are_pruned_after_a_breaker_only_drain/0)
     ]}.

%% Session guard 100 ms with the breaker held open for the whole test: the
%% abort tests below wait the guard out while a step is held, so neither a
%% reset timer nor a prune on another path may act in between.
verdict_guard_abort_test_() ->
    Env = [{registration_replay_session_guard_ms, 100},
           {circuit_breaker_reset_timeout_ms, 600000},
           {circuit_breaker_max_reset_timeout_ms, 600000}],
    {foreach,
     fun() -> setup(Env) end,
     fun cleanup/1,
     [
      t("E21 expired stamps are pruned when the drip aborts on an open breaker",
        fun expired_stamps_are_pruned_on_circuit_abort/0),
      t("E21 expired stamps are pruned when the drip aborts on an unavailable registry",
        fun expired_stamps_are_pruned_on_registry_abort/0)
     ]}.

%% Queue cap 2.
verdict_cap_test_() ->
    {foreach,
     fun() -> setup([{registration_replay_queue_max, 2}]) end,
     fun cleanup/1,
     [
      t("E21 the queue cap drops the overflow and counts queue_full",
        fun queue_cap_drops_overflow_and_counts_queue_full/0)
     ]}.

%% Env validation: the fixture's upstream is replaced inside each test.
verdict_env_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      t("an out of range or non integer guard falls back to the default with a warning",
        fun env_guard_invalid_falls_back/0),
      t("a guard inside 0..3600000 is kept",
        fun env_guard_valid_is_kept/0),
      t("an out of range or non integer queue cap falls back to the default with a warning",
        fun env_queue_max_invalid_falls_back/0),
      t("a queue cap inside 1..1000000 is kept",
        fun env_queue_max_valid_is_kept/0),
      t("an out of range or non integer replay spacing falls back to the default with a warning",
        fun env_spacing_invalid_falls_back/0),
      t("a replay spacing inside 0..60000 is kept",
        fun env_spacing_valid_is_kept/0)
     ]}.

setup() ->
    setup([]).

%% Env is applied after the defaults below, just before the upstream starts
%% (the guard, queue cap and breaker timers are read once, in init/1).
setup(Env) ->
    %% pg + a real registry, race-safe across modules (#1403 / #336).
    yuzu_gw_test_registry:ensure(),

    %% Clean up stale mocks from prior modules.
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),

    %% Fail loud at the boundary if a prior test leaked the real
    %% yuzu_gw_upstream gen_server — a meck stub coexisting with the
    %% registered process would make this suite time out opaquely (#336).
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,

    %% Call log shared by every mock below. The mocks append from the calling
    %% process, so a reply from the upstream process proves that everything it
    %% did before replying is already in the log (meck's own history is
    %% written by an asynchronous cast and would not give that).
    Tid = ets:new(replay_test_log, [public, ordered_set]),
    persistent_term:put(?LOGK, Tid),
    %% Every dummy agent process spawn_dummy/0 starts, killed in cleanup/1.
    persistent_term:put(?DUMMYK, ets:new(replay_test_dummies, [public, bag])),
    persistent_term:erase(?SUBK),

    meck:new(grpcbox_client, [non_strict, no_link]),
    %% Default: every RPC succeeds. Individual tests override this.
    mock_unary(fun default_rpc/3),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(Event, Meas, Meta) ->
        log({event, Event, Meas, Meta}),
        ok
    end),
    %% HA WS-4 4.4 (`#4246` #6): mocked at the FIXTURE level (unloaded in
    %% cleanup/1 unconditionally, unlike the old per-test meck:new/unload
    %% this replaced) so a failed assertion mid-test can never leave
    %% yuzu_gw_agent mocked for every module that runs after this one —
    %% `passthrough` means only reannounce/2 and disconnect/1 are
    %% intercepted; every other yuzu_gw_agent function used elsewhere in
    %% this suite (none, today) would fall through to the real code.
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    meck:expect(yuzu_gw_agent, reannounce, fun(Pid, SessionId) ->
        log({agent, reannounce, Pid, SessionId}),
        ok
    end),
    meck:expect(yuzu_gw_agent, disconnect, fun(Pid) ->
        log({agent, disconnect, Pid}),
        ok
    end),

    %% Low threshold + fast timers + tight replay spacing so the tests
    %% run quickly. Threshold 5 means 1-2 failures stay closed — that is
    %% the closed-state recovery path the observed bug exercises.
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 5),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 150),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    application:set_env(yuzu_gw, registration_replay_spacing_ms, 3),
    lists:foreach(fun({K, V}) -> application:set_env(yuzu_gw, K, V) end, Env),

    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    UpPid.

cleanup(UpPid) ->
    %% Synchronous stop — exit/shutdown + sleep is racy (#336).
    catch unlink(UpPid),
    catch gen_server:stop(UpPid, shutdown, 5000),
    %% Drop every agent this run registered so the shared registry stays
    %% clean for the next test / module. deregister_agent is a cast, so
    %% poll until the table is empty rather than guessing a sleep.
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 2000),
    kill_dummies(),
    meck:unload([grpcbox_client, telemetry, yuzu_gw_agent]),
    persistent_term:erase(?SUBK),
    persistent_term:erase(?LOGK),
    %% The two verdict replay tunables are read once in init/1; do not leak
    %% them.
    application:unset_env(yuzu_gw, registration_replay_session_guard_ms),
    application:unset_env(yuzu_gw, registration_replay_queue_max),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 150),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

reconnect_replays_all_agents() ->
    N = 4,
    Agents = register_n_agents(N),

    %% Drive a closed-state recovery: one failing RPC (below threshold,
    %% circuit stays closed), then reset history, then a succeeding RPC.
    %% The success-after-failure is the reconnect signal.
    cause_one_failure(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    %% The trigger RPC itself succeeds and is a ProxyRegister.
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% Replay drips one ProxyRegister per registered agent. Plus the
    %% trigger call itself => N + 1 ProxyRegister RPCs total.
    ok = wait_for_proxy_register_count(N + 1, 3000),

    %% Every registered agent's stored request must appear in the
    %% replayed set (the trigger request is distinct and excluded).
    Replayed = proxy_register_requests(),
    lists:foreach(fun({_Id, Req}) ->
        ?assert(lists:member(Req, Replayed))
    end, Agents).

reconnect_zero_agents_no_rpc() ->
    %% No agents registered at all.
    ?assertEqual(0, count_test_agents()),

    cause_one_failure(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% Only the trigger RPC — the replay finds nothing to re-proxy.
    %% Give the (empty) replay cast time to be processed.
    ok = wait_for_proxy_register_count(1, 2000),
    timer:sleep(80),  %% would-be drip window; nothing should arrive
    ?assertEqual(1, proxy_register_count()).

deregistered_agent_not_replayed() ->
    N = 3,
    Agents = register_n_agents(N),
    %% Deregister the middle agent *before* the reconnect — it must not
    %% be replayed. all_register_reqs/0 reads ETS at replay time, so the
    %% deregister just has to land first.
    {DroppedId, DroppedReq} = lists:nth(2, Agents),
    yuzu_gw_registry:deregister_agent(DroppedId),
    wait_until(fun() -> yuzu_gw_registry:lookup(DroppedId) =:= error end, 2000),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% N-1 surviving agents + the trigger call.
    ok = wait_for_proxy_register_count(N, 3000),
    timer:sleep(80),  %% let any stray drip step land before asserting
    ?assertEqual(N, proxy_register_count()),

    Replayed = proxy_register_requests(),
    %% The dropped agent's request is absent...
    ?assertNot(lists:member(DroppedReq, Replayed)),
    %% ...and the two survivors are present.
    Survivors = [R || {Id, R} <- Agents, Id =/= DroppedId],
    lists:foreach(fun(Req) ->
        ?assert(lists:member(Req, Replayed))
    end, Survivors).

replay_payload_is_verbatim() ->
    %% A single agent with a rich RegisterRequest — the replayed bytes
    %% must equal the stored term exactly (this is why option (a) stashes
    %% the verbatim request rather than reconstructing it: the top-level
    %% enrollment_token is not otherwise recoverable).
    Id  = unique_id(<<"verbatim">>),
    Req = #{info => #{agent_id => Id,
                      hostname => <<"verbatim-host">>,
                      plugins  => [#{name => <<"svc">>}]},
            enrollment_token => <<"tok-secret-123">>},
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess-verbatim">>,
                                         [<<"svc">>], <<"verbatim-host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000),  %% trigger + 1 replay
    Replayed = proxy_register_requests(),
    ?assert(lists:member(Req, Replayed)),
    kill_dummy(Pid).

half_open_recovery_triggers_replay() ->
    %% Drive the full circuit trip: 5 consecutive failures -> open, wait
    %% for the half_open timer, then succeed the probe. The half_open ->
    %% closed transition must also trigger the replay.
    N = 2,
    Agents = register_n_agents(N),

    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    lists:foreach(fun(_) ->
        _ = yuzu_gw_upstream:proxy_register(trigger_req())
    end, lists:seq(1, 5)),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% Wait for the open -> half_open timer (150ms reset).
    ok = wait_until(fun() ->
        yuzu_gw_upstream:circuit_state() =:= half_open
    end, 2000),

    meck:reset(grpcbox_client),
    succeed_rpcs(),
    %% This probe succeeds: half_open -> closed, which schedules replay.
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    ok = wait_for_proxy_register_count(N + 1, 3000),
    Replayed = proxy_register_requests(),
    lists:foreach(fun({_Id, Req}) ->
        ?assert(lists:member(Req, Replayed))
    end, Agents).

adopted_replay_reannounces_connected() ->
    %% HA WS-4 4.4 (`#4246` #6): a successful ADOPT-S replay must tell the
    %% still-live agent process to re-send its own CONNECTED, so the
    %% server's freshly-installed (and placement-wiped, per
    %% gateway_service_impl.cpp's ProxyRegister) AgentSession converges.
    %% Verified via the fixture-level meck on yuzu_gw_agent (setup/0)
    %% rather than a real gen_statem — the WIRING is this file's concern;
    %% yuzu_gw_agent_tests.erl covers the state-function's own reaction
    %% to the cast.
    Id  = unique_id(<<"adopt">>),
    Req = agent_req(Id),
    Pid = spawn_dummy(),
    SessionId = <<"sess-", Id/binary>>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, [<<"svc">>], <<"host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    %% Distinguish the trigger RPC (always succeeds, kicking off the
    %% replay) from THIS agent's own replayed request (verbatim-equal to
    %% Req, per replay_payload_is_verbatim's own precedent) by CONTENT —
    %% Path is identical ("ProxyRegister") for both.
    meck:expect(grpcbox_client, unary, fun(_, Path, IncomingReq, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                case IncomingReq of
                    Req -> {ok, #{session_id => SessionId}, #{}};
                    _   -> {ok, #{session_id => <<"ok">>}, #{}}
                end
        end
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000), %% trigger + 1 replay
    ok = wait_until(fun() -> length(meck:history(yuzu_gw_agent)) > 0 end, 2000),
    ReannounceCalls = [{P, S} || {_, {yuzu_gw_agent, reannounce, [P, S]}, _}
                                     <- meck:history(yuzu_gw_agent)],
    ?assert(lists:member({Pid, SessionId}, ReannounceCalls)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    kill_dummy(Pid).

adopted_replay_leaves_session_binding() ->
    %% Gateway replay never creates, moves or deletes a heartbeat binding: the
    %% session row recorded at Subscribe, and the routing row, are the same
    %% after the upstream client has re-proxied the registration and told the
    %% agent process to re-announce it.
    Id  = unique_id(<<"bound">>),
    Req = agent_req(Id),
    Pid = spawn_dummy(),
    SessionId = <<"sess-", Id/binary>>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, [<<"svc">>], <<"host">>,
                                         Req, conn_a),
    SessionBefore = yuzu_gw_registry:lookup_session(SessionId),
    ?assertEqual({ok, #{agent_id => Id, pid => Pid, conn_key => conn_a}}, SessionBefore),
    RowsBefore = ets:lookup(yuzu_gw_sessions, SessionId),
    RouteBefore = ets:lookup(yuzu_gw_agents, Id),
    ?assertMatch([_], RowsBefore),
    ?assertMatch([_], RouteBefore),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    meck:reset(telemetry),
    meck:expect(grpcbox_client, unary, fun(_, Path, IncomingReq, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                case IncomingReq of
                    Req -> {ok, #{session_id => SessionId}, #{}};
                    _   -> {ok, #{session_id => <<"ok">>}, #{}}
                end
        end
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    ok = wait_for_proxy_register_count(2, 3000), %% trigger + 1 replay
    %% The replay step has finished once it has reported its own telemetry,
    %% which it does after the re-announce.
    ok = wait_until(fun() ->
        meck:called(telemetry, execute,
                    [[yuzu, gw, upstream, registration_replay], '_', '_'])
    end, 3000),
    ?assert(lists:member({Pid, SessionId},
                         [{P, S} || {_, {yuzu_gw_agent, reannounce, [P, S]}, _}
                                        <- meck:history(yuzu_gw_agent)])),
    ?assert(is_process_alive(whereis(yuzu_gw_upstream))),
    ?assertEqual(SessionBefore, yuzu_gw_registry:lookup_session(SessionId)),
    ?assertEqual(RowsBefore, ets:lookup(yuzu_gw_sessions, SessionId)),
    ?assertEqual(RouteBefore, ets:lookup(yuzu_gw_agents, Id)),
    kill_dummy(Pid).

superseded_replay_forces_reconnect() ->
    %% HA WS-4 4.4 (`#4246` #6): a genuine stale/zombie replay (the
    %% server's presented-session row belongs to a DIFFERENT, live
    %% session) must (a) NOT trip the circuit breaker — the server
    %% answered authoritatively, this is not an outage — and (b) force
    %% this process to reconnect via yuzu_gw_agent:disconnect/1, per
    %% gateway_route_store.hpp's FORWARD NOTE (agent-driven reconnect is
    %% the only sanctioned recovery for a superseded session). Mocked at
    %% the fixture level (setup/0).
    Id  = unique_id(<<"zombie">>),
    Req = agent_req(Id),
    Pid = spawn_dummy(),
    SessionId = <<"sess-", Id/binary>>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, [<<"svc">>], <<"host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, IncomingReq, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                case IncomingReq of
                    %% ?GRPC_STATUS_FAILED_PRECONDITION (grpcbox.hrl) is the
                    %% BINARY digit string <<"9">> — the raw grpc-status
                    %% trailer value (grpcbox_client_stream.erl reads it
                    %% straight off the HTTP/2 header, never converting to
                    %% an integer). Using the integer 9 here (as the
                    %% pre-existing proxy_register_error test's OWN mock
                    %% does for a different status) would silently miss
                    %% do_replay_one's `Status =:= ?GRPC_STATUS_FAILED_PRECONDITION`
                    %% guard and fall through to the generic error branch.
                    Req -> {error, {<<"9">>, <<"session superseded; reconnect">>}, #{}};
                    _   -> {ok, #{session_id => <<"ok">>}, #{}}
                end
        end
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000), %% trigger + 1 replay attempt
    ok = wait_until(fun() -> length(meck:history(yuzu_gw_agent)) > 0 end, 2000),
    DisconnectCalls = [P || {_, {yuzu_gw_agent, disconnect, [P]}, _}
                                <- meck:history(yuzu_gw_agent)],
    ?assert(lists:member(Pid, DisconnectCalls)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    kill_dummy(Pid).

%%%===================================================================
%%% Helpers — registry population
%%%===================================================================

%% Register N agents in the shared registry, each with a uniquely
%% identifiable verbatim RegisterRequest. Returns [{AgentId, Req}].
register_n_agents(N) ->
    lists:map(fun(I) ->
        Id  = unique_id(integer_to_binary(I)),
        Req = agent_req(Id),
        Pid = spawn_dummy(),
        ok = yuzu_gw_registry:register_agent(
               Id, Pid, <<"sess-", Id/binary>>, [<<"svc">>], <<"host">>, Req),
        {Id, Req}
    end, lists:seq(1, N)).

%% A per-agent RegisterRequest, tagged so it is distinguishable from
%% both other agents and the trigger request.
agent_req(Id) ->
    #{info => #{agent_id => Id,
                hostname => <<"host-", Id/binary>>,
                plugins  => [#{name => <<"svc">>}]},
      enrollment_token => <<"enroll-", Id/binary>>}.

%% The request used for the RPCs that drive circuit transitions. Tagged
%% distinctly so it is never mistaken for a replayed agent request.
trigger_req() ->
    #{info => #{agent_id => <<"__trigger__">>}}.

%% Count agents currently in the registry whose id was minted by this
%% module (unique_id/1 prefixes with the test pid). Used to assert a
%% clean starting state without disturbing other suites' agents.
count_test_agents() ->
    Prefix = id_prefix(),
    length([Id || Id <- yuzu_gw_registry:all_agents(),
                  binary:match(Id, Prefix) =:= {0, byte_size(Prefix)}]).

%%%===================================================================
%%% Helpers — circuit breaker driving
%%%===================================================================

%% One failing RPC. With threshold 5 the circuit stays closed but
%% cb_failures becomes 1 — the precondition for closed-state recovery.
cause_one_failure() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    {error, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    ok.

%% Make every subsequent RPC succeed.
succeed_rpcs() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"ok">>}, #{}}
    end).

%%%===================================================================
%%% Helpers — meck history inspection
%%%===================================================================

%% All ProxyRegister request payloads currently in grpcbox_client history.
proxy_register_requests() ->
    [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _}
                <- meck:history(grpcbox_client),
            is_binary(Path),
            binary:match(Path, <<"ProxyRegister">>) =/= nomatch].

proxy_register_count() ->
    length(proxy_register_requests()).

%% Poll until exactly Expected ProxyRegister RPCs have been recorded.
wait_for_proxy_register_count(Expected, Timeout) ->
    wait_until(fun() -> proxy_register_count() =:= Expected end, Timeout).

%%%===================================================================
%%% Helpers — generic
%%%===================================================================

%% Poll Pred every 10ms until it returns true or Timeout elapses.
wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false ->
            timer:sleep(10),
            wait_until(Pred, Timeout - 10)
    end.

%% A unique, this-module-attributable agent id.
unique_id(Suffix) ->
    <<(id_prefix())/binary, Suffix/binary>>.

id_prefix() ->
    PidBin = list_to_binary(pid_to_list(self())),
    <<"replay-", PidBin/binary, "-">>.

%% A stand-in for an agent process. Recorded so cleanup/1 stops it even when a
%% test never does (the bound agents of the verdict replay tests are never
%% stopped by their tests).
spawn_dummy() ->
    Pid = spawn(fun() -> receive stop -> ok end end),
    case persistent_term:get(?DUMMYK, undefined) of
        undefined -> ok;
        Tid       -> ets:insert(Tid, {dummy, Pid})
    end,
    Pid.

kill_dummies() ->
    case persistent_term:get(?DUMMYK, undefined) of
        undefined ->
            ok;
        Tid ->
            [kill_dummy(Pid) || {dummy, Pid} <- ets:tab2list(Tid)],
            ets:delete(Tid),
            persistent_term:erase(?DUMMYK)
    end.

kill_dummy(Pid) ->
    Pid ! stop.

%%%===================================================================
%%% #1197 verdict replay tests (default fixture)
%%%===================================================================

%% E1: the verdict names S1; the node holds two agents. One ProxyRegister goes
%% out, with A1's stored request and x-yuzu-session-id = S1; A2 produces none.
targeted_replay_reproxies_only_the_named_session() ->
    watch(),
    A1 = bind_agent(<<"e1a">>),
    _ = bind_agent(<<"e1b">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assertEqual([{req(A1), sid(A1)}], replays()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

%% E2: an id the node does not hold. The call after the cast is queued behind
%% it (same sender), so its reply proves the cast was handled; the assertions
%% on the absence of any rpc therefore hold for the whole handling.
unheld_session_sends_nothing() ->
    ok = yuzu_gw_upstream:replay_sessions([<<"never-held-session">>]),
    sync(),
    ?assertEqual(1, dropped(not_local)),
    ?assertEqual(0, proxy_count()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, up_get(cb_failures)),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual(#{}, up_get(recent_replays)).

%% E3: the first drip step is held inside its rpc. A second verdict sent now
%% waits in the mailbox and is appended behind the queue; every session is
%% replayed exactly once, in order. A fourth bound agent that no verdict names
%% is never replayed, so the drip was not reseeded from the registry.
verdict_during_drip_is_appended_without_restart() ->
    watch(),
    [A1, A2, A3 | _] = [bind_agent(S) || S <- [<<"e3a">>, <<"e3b">>, <<"e3c">>, <<"e3d">>]],
    mock_gated([sid(A1)]),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await_msg({rpc_entered, sid(A1)}),
    ok = yuzu_gw_upstream:replay_sessions([sid(A3)]),
    release(sid(A1)),
    await(fun() -> length(replay_hdrs()) >= 3 end),
    await_idle(),
    ?assertEqual([sid(A1), sid(A2), sid(A3)], replay_hdrs()),
    ?assertEqual([#{count => 1}, #{count => 1}], triggers(heartbeat)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

%% E4 (default guard 10000 ms): the second cast is inside the window by a
%% margin no test run can exhaust. The first replay is the positive control.
same_session_twice_inside_guard_replays_once() ->
    watch(),
    A1 = bind_agent(<<"e4a">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assert(is_integer(maps:get(sid(A1), up_get(recent_replays), undefined))),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    sync(),
    ?assertEqual([sid(A1)], replay_hdrs()),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual(1, length(triggers(heartbeat))).

%% E9: ADOPT and REFUSE keep their effects through the targeted path.
targeted_adopt_reannounces_connected() ->
    watch(),
    A1 = bind_agent(<<"e9a">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> lists:member({agent, reannounce, pid(A1), sid(A1)}, agent_calls()) end),
    await_idle(),
    ?assertEqual([], disconnects()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

targeted_refuse_disconnects_the_agent() ->
    watch(),
    A1 = bind_agent(<<"e9r">>),
    cause_one_failure(),
    mock_unary(fun(<<"ProxyRegister">>, _Req, _Hdr) ->
                       {error, {<<"9">>, <<"session superseded; reconnect">>}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> lists:member({agent, disconnect, pid(A1)}, agent_calls()) end),
    await_idle(),
    ?assertEqual([], reannounces()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    %% The refusal is an authoritative answer: it resets the failure count the
    %% earlier failed rpc left at 1 (a failure would have made it 2).
    ?assertEqual(0, up_get(cb_failures)).

%% E9b: the replay rpc for S1 is in flight when the agent re-registers under
%% S2 with a new process. The REFUSE answer disconnects the process captured
%% at pop (the old one); the S2 index row, the routing row and the new process
%% are untouched.
refuse_after_reregistration_disconnects_the_old_pid_only() ->
    watch(),
    A = bind_agent(<<"e9b">>),
    mock_gated([sid(A)], fun(_M, _Req, _Hdr) ->
        {error, {<<"9">>, <<"session superseded; reconnect">>}, #{}}
    end),
    ok = yuzu_gw_upstream:replay_sessions([sid(A)]),
    await_msg({rpc_entered, sid(A)}),
    A2 = rebind(A, <<"sess-e9b-new">>),
    RowBefore = ets:lookup(yuzu_gw_agents, id(A)),
    IndexBefore = ets:lookup(yuzu_gw_sessions, sid(A2)),
    ?assertMatch([_], RowBefore),
    ?assertMatch([_], IndexBefore),
    release(sid(A)),
    await(fun() -> lists:member({agent, disconnect, pid(A)}, agent_calls()) end),
    await_idle(),
    ?assertEqual([pid(A)], disconnects()),
    ?assertEqual(RowBefore, ets:lookup(yuzu_gw_agents, id(A))),
    ?assertEqual(IndexBefore, ets:lookup(yuzu_gw_sessions, sid(A2))),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(sid(A))),
    ?assertMatch({ok, #{pid := _}}, yuzu_gw_registry:lookup_session(sid(A2))).

%% E10.
triggered_event_is_labelled_heartbeat() ->
    watch(),
    A1 = bind_agent(<<"e10h">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assertEqual([#{count => 1}], triggers(heartbeat)),
    ?assertEqual([], triggers(breaker)).

%% The breaker trigger is driven through proxy_register/1, the way a real
%% recovery is, not through a replay. The per-step event keeps its shape.
triggered_event_is_labelled_breaker() ->
    watch(),
    _ = bind_agent(<<"e10b">>),
    cause_one_failure(),
    mock_unary(fun default_rpc/3),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assertEqual([#{count => 1}], triggers(breaker)),
    ?assertEqual([], triggers(heartbeat)),
    ?assertEqual([{#{replayed => 1, queue_depth => 0}, #{}}],
                 [E || {M, _} = E <- events(?EV_REPLAY), maps:get(replayed, M) > 0]).

%% E12: 4096 well formed ids, none held. Nothing is queued, stamped or sent.
junk_verdict_is_all_not_local() ->
    Ids = [iolist_to_binary(io_lib:format("junk-session-~6..0b", [N])) || N <- lists:seq(1, 4096)],
    StampsBefore = up_get(recent_replays),
    ok = yuzu_gw_upstream:replay_sessions(Ids),
    sync(),
    ?assertEqual(4096, dropped(not_local)),
    ?assertEqual(0, proxy_count()),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual(StampsBefore, up_get(recent_replays)).

%% E12b: replay_sessions/1 is exported, so the cast boundary bounds its own
%% input: 5000 ids none of which this node holds count 4096 not_local (not
%% 5000), and anything that is not a list is ignored without crashing the
%% process. The 4096-id case above is the positive control for the counter.
oversized_or_non_list_cast_is_bounded() ->
    UpPid = whereis(yuzu_gw_upstream),
    Ids = [iolist_to_binary(io_lib:format("junk-session-~6..0b", [N])) || N <- lists:seq(1, 5000)],
    ok = yuzu_gw_upstream:replay_sessions(Ids),
    sync(),
    ?assertEqual(4096, dropped(not_local)),
    [begin
         ok = yuzu_gw_upstream:replay_sessions(Bad),
         sync()
     end || Bad <- [not_a_list, <<"abc">>, 42, [<<"improper">> | <<"tail">>]]],
    ?assertEqual(UpPid, whereis(yuzu_gw_upstream)),
    ?assertEqual(4096, dropped(not_local)),
    ?assertEqual(0, proxy_count()),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual([], triggers(heartbeat)).

%% E12c: the same bound on the circuit-open path, which counts before it
%% drops.
oversized_cast_with_open_circuit_is_bounded() ->
    trip_breaker(),
    Ids = [iolist_to_binary(io_lib:format("junk-session-~6..0b", [N])) || N <- lists:seq(1, 5000)],
    ok = yuzu_gw_upstream:replay_sessions(Ids),
    sync(),
    ?assertEqual(4096, dropped(circuit_open)),
    ?assertEqual(0, dropped(not_local)).

%% E15: the agent registered without a stashed request. It is queued (the
%% trigger event says so), then skipped at pop with no rpc and no stamp.
empty_stored_request_is_skipped_without_stamp() ->
    watch(),
    A = bind_agent(<<"e15">>, #{}),
    ok = yuzu_gw_upstream:replay_sessions([sid(A)]),
    await(fun() -> length(triggers(heartbeat)) =:= 1 end),
    await_idle(),
    ?assertEqual(0, proxy_count()),
    ?assertEqual(#{}, up_get(recent_replays)).

%% E15b: B's step is held in its rpc while A re-registers under a new session.
%% A's queued entry (S1) is skipped at pop, and neither S1 nor the new session
%% is stamped; B, which was replayed, is.
reregistered_agent_is_skipped_at_pop() ->
    watch(),
    B = bind_agent(<<"e15bb">>),
    A = bind_agent(<<"e15ba">>),
    mock_gated([sid(B)]),
    ok = yuzu_gw_upstream:replay_sessions([sid(B), sid(A)]),
    await_msg({rpc_entered, sid(B)}),
    A2 = rebind(A, <<"sess-e15b-new">>),
    release(sid(B)),
    await_idle(),
    ?assertEqual([sid(B)], replay_hdrs()),
    ?assertEqual([sid(B)], maps:keys(up_get(recent_replays))),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(sid(A))),
    %% Depth: 2 queued; B's step with A behind it; the skip of A reports 0.
    %% Without the report at the skip the gauge would stay at 1.
    ?assertEqual([{0, 2}, {1, 1}, {0, 0}], depths()),
    _ = A2.

%% E21 abort arms. A0 is replayed first and its stamp is left to expire; A1's
%% step is then held in its rpc while the 100 ms guard is waited out on the
%% monotonic clock (from after A1's stamp, which is before the rpc is entered),
%% so both stamps are expired when the drip aborts at A2. Neither the verdict's
%% enqueue (which prunes first) nor any other path runs in between, so only the
%% prune on the abort path can leave recent_replays empty. The upstream is
%% inside the held rpc, so its state cannot be read until it is released.
expired_stamps_are_pruned_on_circuit_abort() ->
    watch(),
    A0 = bind_agent(<<"e21ca0">>),
    A1 = bind_agent(<<"e21ca1">>),
    A2 = bind_agent(<<"e21ca2">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A0)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assert(maps:is_key(sid(A0), up_get(recent_replays))),
    %% Four failures leave the breaker closed; A1's replay is the fifth.
    mock_unary(fun(_, _, _) -> {error, connection_refused} end),
    [_ = yuzu_gw_upstream:proxy_register(trigger_req()) || _ <- lists:seq(1, 4)],
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    mock_gated([sid(A1)], fun(_, _, _) -> {error, connection_refused} end),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await_msg({rpc_entered, sid(A1)}),
    wait_elapsed(erlang:monotonic_time(millisecond), 100),
    release(sid(A1)),
    await_idle(),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual([sid(A0), sid(A1)], replay_hdrs()),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual(#{}, up_get(recent_replays)),
    ?assertMatch({0, 0}, lists:last(depths())).

expired_stamps_are_pruned_on_registry_abort() ->
    watch(),
    Prev = process_flag(trap_exit, true),
    stop_upstream(),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    A0 = bind_agent(<<"e21ra0">>),
    A1 = bind_agent(<<"e21ra1">>),
    A2 = bind_agent(<<"e21ra2">>),
    try
        ok = yuzu_gw_upstream:replay_sessions([sid(A0)]),
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle(),
        ?assert(maps:is_key(sid(A0), up_get(recent_replays))),
        mock_gated([sid(A1)]),
        ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
        await_msg({rpc_entered, sid(A1)}),
        wait_elapsed(erlang:monotonic_time(millisecond), 100),
        ok = gen_server:stop(whereis(yuzu_gw_registry), normal, 5000),
        await(fun() -> ets:info(yuzu_gw_agents, size) =:= undefined end),
        {_, Lines} = capture_logs(fun() ->
            release(sid(A1)),
            await_idle()
        end),
        ?assertMatch([_], [T || {warning, T} <- Lines,
                                binary:match(T, <<"registry unavailable">>) =/= nomatch]),
        ?assertEqual(UpPid, whereis(yuzu_gw_upstream)),
        ?assertEqual([sid(A0), sid(A1)], replay_hdrs()),
        ?assertEqual([], up_get(replay_queue)),
        ?assertEqual(#{}, up_get(recent_replays))
    after
        ok = yuzu_gw_test_registry:ensure(),
        catch unlink(UpPid),
        catch gen_server:stop(UpPid, normal, 2000),
        process_flag(trap_exit, Prev),
        flush_exits()
    end.

%% E16: the session index table is gone (new code loaded into a running
%% node). The ids are dropped as not_local and the upstream keeps running.
missing_session_index_keeps_upstream_alive() ->
    A = bind_agent(<<"e16">>),
    UpPid = whereis(yuzu_gw_upstream),
    drop_sessions_table(),
    try
        ok = yuzu_gw_upstream:replay_sessions([sid(A)]),
        sync(),
        ?assertEqual(UpPid, whereis(yuzu_gw_upstream)),
        ?assertEqual(1, dropped(not_local)),
        ?assertEqual(0, proxy_count()),
        ?assertEqual([], up_get(replay_queue))
    after
        restore_sessions_table()
    end.

%% E16b: the registry stops while the second entry waits behind a held rpc.
%% The next step cannot read the registry: the drip aborts (queue empty, the
%% unreplayed entry unstamped, depth 0) and the upstream stays up. Without the
%% guarded lookup the upstream crashes. The fixture's upstream is linked to the
%% fixture process, which a crash would take down together with the rest of
%% the group, so this test runs its own upstream, linked to this process, and
%% traps exits: a crash then shows up as a failure of this test alone.
registry_stopped_mid_drip_aborts_without_crash() ->
    watch(),
    Prev = process_flag(trap_exit, true),
    stop_upstream(),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    A1 = bind_agent(<<"e16ba">>),
    A2 = bind_agent(<<"e16bb">>),
    try
        mock_gated([sid(A1)]),
        ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
        await_msg({rpc_entered, sid(A1)}),
        ok = gen_server:stop(whereis(yuzu_gw_registry), normal, 5000),
        await(fun() -> ets:info(yuzu_gw_agents, size) =:= undefined end),
        {_, Lines} = capture_logs(fun() ->
            release(sid(A1)),
            await_idle()
        end),
        ?assertEqual(UpPid, whereis(yuzu_gw_upstream)),
        ?assert(is_process_alive(UpPid)),
        ?assertMatch([_], [T || {warning, T} <- Lines,
                                binary:match(T, <<"registry unavailable">>) =/= nomatch]),
        ?assertEqual([sid(A1)], replay_hdrs()),
        ?assertEqual([], up_get(replay_queue)),
        ?assertEqual([sid(A1)], maps:keys(up_get(recent_replays))),
        ?assertMatch({0, 0}, lists:last(depths()))
    after
        ok = yuzu_gw_test_registry:ensure(),
        catch unlink(UpPid),
        catch gen_server:stop(UpPid, normal, 2000),
        process_flag(trap_exit, Prev),
        flush_exits()
    end.

%% E17: a breaker-triggered full replay cast arrives while a targeted drip has
%% entries queued. The existing in-flight rule drops it; the drip completes
%% and the unnamed third agent is never replayed (a full replay would send it).
breaker_replay_during_targeted_drip_is_dropped() ->
    watch(),
    [A1, A2, _A3] = [bind_agent(S) || S <- [<<"e17a">>, <<"e17b">>, <<"e17c">>]],
    mock_gated([sid(A1)]),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await_msg({rpc_entered, sid(A1)}),
    ok = gen_server:cast(yuzu_gw_upstream, replay_registrations),
    release(sid(A1)),
    await(fun() -> length(replay_hdrs()) >= 2 end),
    await_idle(),
    ?assertEqual([sid(A1), sid(A2)], replay_hdrs()),
    ?assertEqual(2, proxy_count()),
    ?assertEqual([], triggers(breaker)).

%% E18: the event counts appending casts, not sessions. A cast that appends
%% nothing (inside the guard, or not local) emits none.
triggered_fires_once_per_appending_cast() ->
    watch(),
    A1 = bind_agent(<<"e18a">>),
    A2 = bind_agent(<<"e18b">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await(fun() -> length(replay_hdrs()) >= 2 end),
    await_idle(),
    ?assertEqual([#{count => 1}], triggers(heartbeat)),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    ok = yuzu_gw_upstream:replay_sessions([<<"not-held-18">>]),
    sync(),
    ?assertEqual([#{count => 1}], triggers(heartbeat)),
    ?assertEqual(2, length(replay_hdrs())).

%% E19: ten notify workers are held in their rpc, so the notify budget is
%% full. The head of the queue is retried, not popped, and is not stamped;
%% once one worker finishes the head replays. The two barrier calls guarantee
%% that at least one retry has run before the assertions: the first reply
%% follows the cast, the second follows the replay_next the cast scheduled.
notify_pressure_holds_the_head_unstamped() ->
    watch(),
    A = bind_agent(<<"e19">>),
    mock_unary(fun(<<"NotifyStreamStatus">>, _Req, _Hdr) ->
                       notify({notify_entered, self()}),
                       receive release -> ok after 10000 -> ok end,
                       {ok, #{}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    Workers = [begin
                   ok = yuzu_gw_upstream:notify_stream_status(
                          <<"notify-agent-", (integer_to_binary(I))/binary>>,
                          <<"notify-session">>, connected, <<"peer">>, <<"home">>),
                   receive {notify_entered, W} -> W
                   after 3000 -> erlang:error({notify_worker_not_started, I})
                   end
               end || I <- lists:seq(1, 10)],
    try
        ok = yuzu_gw_upstream:replay_sessions([sid(A)]),
        sync(),
        sync(),
        ?assertMatch([{_, _, _}], up_get(replay_queue)),
        ?assertEqual(0, proxy_count()),
        ?assertEqual(#{}, up_get(recent_replays)),
        hd(Workers) ! release,
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle(),
        ?assertEqual([sid(A)], replay_hdrs())
    after
        [W ! release || W <- Workers]
    end.

%% E20: the server answers OK but with accepted=false. The agent is
%% disconnected so it follows its own registration path; no reannounce (the
%% server never installed the session); the answer is authoritative, so the
%% breaker sees a success; the attempt counts as a replay and is stamped. The
%% reason is cut to 128 bytes in the warning.
rejected_replay_disconnects_without_reannounce() ->
    watch(),
    A1 = bind_agent(<<"e20r">>),
    cause_one_failure(),
    Reason = binary:copy(<<"x">>, 300),
    mock_unary(fun(<<"ProxyRegister">>, _Req, Hdr) when Hdr =/= undefined ->
                       {ok, #{accepted => false, reject_reason => Reason,
                              session_id => Hdr}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    {_, Lines} = capture_logs(fun() ->
        ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
        await(fun() -> lists:member({agent, disconnect, pid(A1)}, agent_calls()) end),
        await_idle()
    end),
    ?assertEqual([pid(A1)], disconnects()),
    ?assertEqual([], reannounces()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, up_get(cb_failures)),
    ?assertEqual([#{replayed => 1, queue_depth => 0}],
                 [M || {M, _} <- events(?EV_REPLAY), maps:get(replayed, M) > 0]),
    ?assert(is_integer(maps:get(sid(A1), up_get(recent_replays), undefined))),
    [Warning] = [T || {warning, T} <- Lines, binary:match(T, <<"not accepted">>) =/= nomatch],
    ?assertNotEqual(nomatch, binary:match(Warning, binary:copy(<<"x">>, 128))),
    ?assertEqual(nomatch, binary:match(Warning, binary:copy(<<"x">>, 129))),
    %% Control bytes (CR, LF, ESC, NUL, DEL and the C1 range 16#80..16#9F, here
    %% NEL 16#85 and CSI 16#9B) become `?' after the cut; other bytes pass
    %% through (~s shows the latin-1 byte 16#E9 as its UTF-8 form C3 A9), and
    %% the text is still cut to 128 bytes.
    Crafted = <<"line1\r\nline2\e[31m", 0, 127, 16#85, 16#9B, 16#E9,
                (binary:copy(<<"y">>, 200))/binary>>,
    A2 = bind_agent(<<"e20s">>),
    mock_unary(fun(<<"ProxyRegister">>, _Req, Hdr) when Hdr =/= undefined ->
                       {ok, #{accepted => false, reject_reason => Crafted,
                              session_id => Hdr}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    {_, Lines2} = capture_logs(fun() ->
        ok = yuzu_gw_upstream:replay_sessions([sid(A2)]),
        await(fun() -> lists:member({agent, disconnect, pid(A2)}, agent_calls()) end),
        await_idle()
    end),
    [Warning2] = [T || {warning, T} <- Lines2, binary:match(T, <<"not accepted">>) =/= nomatch],
    [?assertEqual({nomatch, C}, {binary:match(Warning2, <<C>>), C}) || C <- [$\r, $\n, 27, 0, 127]],
    %% U+0085 and U+009B would show as C2 85 and C2 9B if they got through.
    [?assertEqual({nomatch, C}, {binary:match(Warning2, <<16#C2, C>>), C}) || C <- [16#85, 16#9B]],
    Expected = <<"line1??line2?[31m????", 16#C3, 16#A9, (binary:copy(<<"y">>, 128 - 22))/binary>>,
    ?assertNotEqual(nomatch, binary:match(Warning2, Expected)),
    ?assertEqual(nomatch, binary:match(Warning2, binary:copy(<<"y">>, 128 - 21))).

%% E20b: an OK with trailers and no DATA frame reaches the replay as a
%% non-map response. The upstream stays up and the drip goes on; the attempt
%% is a breaker failure, no agent is disconnected or re-announced, and the
%% warning names neither the session id nor the body.
non_map_replay_response_is_a_failure() ->
    watch(),
    Pid = whereis(yuzu_gw_upstream),
    A1 = bind_agent(<<"e20n1">>),
    S1 = sid(A1),
    mock_unary(fun(<<"ProxyRegister">>, _Req, Hdr) when Hdr =:= S1 ->
                       {ok, <<"body-marker">>, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    {_, Lines} = capture_logs(fun() ->
        ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle()
    end),
    ?assertEqual(Pid, whereis(yuzu_gw_upstream)),
    ?assertEqual(1, up_get(cb_failures)),
    ?assertEqual([], disconnects()),
    ?assertEqual([], reannounces()),
    [Warning] = [T || {warning, T} <- Lines,
                      binary:match(T, <<"not a response message">>) =/= nomatch],
    ?assertEqual(nomatch, binary:match(Warning, sid(A1))),
    ?assertEqual(nomatch, binary:match(Warning, <<"body-marker">>)),
    %% The next entry of the same drip still runs after a non-map answer.
    A2 = bind_agent(<<"e20n2">>),
    A3 = bind_agent(<<"e20n3">>),
    S2 = sid(A2),
    mock_unary(fun(<<"ProxyRegister">>, _Req, Hdr) when Hdr =:= S2 ->
                       {ok, <<>>, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    ok = yuzu_gw_upstream:replay_sessions([sid(A2), sid(A3)]),
    await(fun() -> lists:member({agent, reannounce, pid(A3), sid(A3)}, agent_calls()) end),
    await_idle(),
    ?assertEqual(Pid, whereis(yuzu_gw_upstream)),
    ?assertEqual([sid(A1), sid(A2), sid(A3)], replay_hdrs()),
    ?assertEqual([], disconnects()),
    ?assertEqual([{agent, reannounce, pid(A3), sid(A3)}],
                 [C || {agent, reannounce, _, _} = C <- agent_calls()]).

%% The server's grpc-message is untrusted text too: the same cut and the same
%% control-character replacement as reject_reason, in the failed-RPC warning.
rpc_error_message_is_sanitised_in_the_log() ->
    Message = <<"m1\r\nm2\e[31m", 0, 127, 16#85, 16#9B, (binary:copy(<<"z">>, 200))/binary>>,
    mock_unary(fun(<<"ProxyRegister">>, _Req, _Hdr) -> {error, {<<"14">>, Message}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    {Result, Lines} = capture_logs(fun() -> yuzu_gw_upstream:proxy_register(trigger_req()) end),
    ?assertEqual({error, {<<"14">>, Message}}, Result),
    [Warning] = [T || {warning, T} <- Lines, binary:match(T, <<"Upstream RPC">>) =/= nomatch],
    [?assertEqual({nomatch, C}, {binary:match(Warning, <<C>>), C}) || C <- [$\r, $\n, 27, 0, 127]],
    [?assertEqual({nomatch, C}, {binary:match(Warning, <<16#C2, C>>), C}) || C <- [16#85, 16#9B]],
    ?assertNotEqual(nomatch, binary:match(Warning, <<"m1??m2?[31m????">>)),
    ?assertNotEqual(nomatch, binary:match(Warning, binary:copy(<<"z">>, 128 - 15))),
    ?assertEqual(nomatch, binary:match(Warning, binary:copy(<<"z">>, 128 - 14))).

%% Mocks return #{} and older callers omit the key: absent means accepted.
missing_accepted_key_is_accepted() ->
    watch(),
    A1 = bind_agent(<<"e20m">>),
    mock_unary(fun(<<"ProxyRegister">>, _Req, Hdr) when Hdr =/= undefined ->
                       {ok, #{session_id => Hdr}, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> lists:member({agent, reannounce, pid(A1), sid(A1)}, agent_calls()) end),
    await_idle(),
    ?assertEqual([], disconnects()).

%% E21: A has S1 queued behind B's held step and then re-registers as S2. A
%% verdict naming S2 appends nothing (one pending entry per agent), so only B
%% is replayed: S1 is skipped as stale at pop and S2 is not queued.
second_session_for_a_queued_agent_is_not_appended() ->
    watch(),
    B = bind_agent(<<"e21b">>),
    A = bind_agent(<<"e21a">>),
    mock_gated([sid(B)]),
    ok = yuzu_gw_upstream:replay_sessions([sid(B), sid(A)]),
    await_msg({rpc_entered, sid(B)}),
    A2 = rebind(A, <<"sess-e21-new">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A2)]),
    release(sid(B)),
    await_idle(),
    ?assertEqual([sid(B)], replay_hdrs()),
    ?assertEqual(1, length(triggers(heartbeat))),
    ?assertEqual([sid(B)], maps:keys(up_get(recent_replays))).

%% E22: depth on append (replayed 0) and after every popped step.
queue_depth_is_reported_on_append_and_after_each_step() ->
    watch(),
    A1 = bind_agent(<<"e22a">>),
    A2 = bind_agent(<<"e22b">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await(fun() -> length(replay_hdrs()) >= 2 end),
    await_idle(),
    ?assertEqual([{0, 2}, {1, 1}, {1, 0}], depths()).

queue_depth_is_reported_on_skip() ->
    watch(),
    A = bind_agent(<<"e22s">>, #{}),
    ok = yuzu_gw_upstream:replay_sessions([sid(A)]),
    await(fun() -> length(depths()) >= 2 end),
    await_idle(),
    ?assertEqual([{0, 1}, {0, 0}], depths()).

%%% -- Crash reports and sys:get_status must not carry the queued requests ----

%% The credential-bearing keys of agent.proto's RegisterRequest, plus a value
%% per entry; a printed queue or request shows at least one of them.
secret_req(N) ->
    Tag = integer_to_binary(N),
    #{info => #{agent_id => <<"fs-agent-", Tag/binary>>},
      enrollment_token => <<"tok-", Tag/binary>>,
      machine_certificate => <<"cert-", Tag/binary>>,
      csr_pem => <<"csr-", Tag/binary>>}.

secret_queue(Count) ->
    [{<<"fs-agent-", (integer_to_binary(N))/binary>>,
      <<"fs-sess-", (integer_to_binary(N))/binary>>, secret_req(N)}
     || N <- lists:seq(1, Count)].

%% Markers that must never reach a report: the key names and every value.
secret_markers() ->
    ["enrollment_token", "machine_certificate", "csr_pem", "tok-", "cert-", "csr-",
     "fs-agent-", "fs-sess-"].

assert_no_secrets(Text) ->
    [?assertEqual({nomatch, M}, {string:find(Text, M), M}) || M <- secret_markers()],
    ok.

%% The callback on its own: a state holding 50 queued requests and the message
%% that carries one more. The keys of the original status survive.
format_status_shows_counts_not_requests() ->
    Count = 50,
    State0 = sys:get_state(yuzu_gw_upstream),
    State = setelement(up_index(recent_replays),
                       setelement(up_index(replay_queue), State0, secret_queue(Count)),
                       #{<<"fs-sess-1">> => 1, <<"fs-sess-2">> => 2}),
    Status = #{state => State,
               message => {proxy_register, secret_req(0)},
               reason => {test, reason},
               log => []},
    Result = yuzu_gw_upstream:format_status(Status),
    ?assertEqual([log, message, reason, state], lists:sort(maps:keys(Result))),
    assert_no_secrets(lists:flatten(io_lib:format("~p", [Result]))),
    #{state := Shown} = Result,
    ?assertEqual(Count, maps:get(replay_queue_len, Shown)),
    ?assertEqual(2, maps:get(recent_replays_size, Shown)),
    ?assertNot(maps:is_key(replay_queue, Shown)),
    ?assertNot(maps:is_key(recent_replays, Shown)),
    %% The scalar fields are kept.
    ?assertEqual(up_get(cb_state), maps:get(cb_state, Shown)),
    ?assertEqual(up_get(session_guard_ms), maps:get(session_guard_ms, Shown)),
    ?assertEqual(up_get(replay_queue_max), maps:get(replay_queue_max, Shown)),
    ?assertEqual({reason, {test, '$redacted'}}, {reason, maps:get(reason, Result)}),
    %% The wrapped forms of every message that carries a payload.
    [begin
         Shown2 = lists:flatten(io_lib:format("~p", [
                      maps:get(message, yuzu_gw_upstream:format_status(
                                          #{state => State, message => Msg}))])),
         assert_no_secrets(Shown2)
     end || Msg <- [{'$gen_call', {self(), make_ref()}, {proxy_register, secret_req(1)}},
                    {proxy_register, secret_req(2)},
                    {proxy_inventory, secret_req(3)},
                    {replay_sessions, [<<"fs-sess-4">>]},
                    {'$gen_cast', {forward_guardian_message, <<"guardian-agent">>, secret_req(5)}}]],
    %% A message without a payload, and a state that is not the record, pass
    %% through safely.
    ?assertEqual(circuit_state,
                 maps:get(message, yuzu_gw_upstream:format_status(
                                     #{state => State, message => circuit_state}))),
    ?assertEqual('$redacted',
                 maps:get(state, yuzu_gw_upstream:format_status(#{state => secret_queue(1)}))),
    %% A sys:get_status style map has no message key.
    ?assertNot(maps:is_key(message, yuzu_gw_upstream:format_status(#{state => State}))).

%% Through the real process. A drip is not started (no replay_next message is
%% sent), so the queue stays as placed; sys:get_state still returns the record.
sys_get_status_shows_counts_not_requests() ->
    Count = 50,
    _ = sys:replace_state(yuzu_gw_upstream,
                          fun(St) -> setelement(up_index(replay_queue), St,
                                                secret_queue(Count)) end),
    Status = sys:get_status(yuzu_gw_upstream),
    Text = lists:flatten(io_lib:format("~p", [Status])),
    assert_no_secrets(Text),
    ?assertNotEqual(nomatch, string:find(Text, "replay_queue_len")),
    ?assertEqual(Count, length(up_get(replay_queue))),
    _ = sys:replace_state(yuzu_gw_upstream,
                          fun(St) -> setelement(up_index(replay_queue), St, []) end),
    ok.

%% The reason, its stacktrace frames' argument lists, the debug log and fields
%% of the wrong type: none of them may print a request, and the callback must
%% not crash on any of them (OTP would then print the raw message).
format_status_redacts_reason_log_and_odd_fields() ->
    State = sys:get_state(yuzu_gw_upstream),
    Req = secret_req(9),
    Show = fun(Status) -> lists:flatten(io_lib:format("~p", [yuzu_gw_upstream:format_status(Status)])) end,
    %% A stacktrace whose frames carry the request as their argument list.
    Stack = [{m, f, [Req], loc},
             {m, g, [Req, Req], [{file, "m.erl"}, {line, 7}, {error_info, #{cause => Req}}]},
             {m, h, 2, [{line, 1}]},
             {fun(_) -> Req end, [Req], []}],
    Reason = {function_clause, Stack},
    Status = #{state => State, reason => Reason, log => [{in, Req}, {out, Req}]},
    Text = Show(Status),
    assert_no_secrets(Text),
    #{reason := {function_clause, Frames}, log := Log} = yuzu_gw_upstream:format_status(Status),
    ?assertEqual([{log_entries_redacted, 2}], Log),
    ?assertMatch([{m, f, 1, loc},
                  {m, g, 2, [{file, "m.erl"}, {line, 7}]},
                  {m, h, 2, [{line, 1}]},
                  {_, 1, []}], Frames),
    %% A reason that carries a value is cut to its first element; one that is
    %% not an atom or a tuple of one becomes '$redacted'.
    [begin
         assert_no_secrets(Show(#{reason => R})),
         ?assertEqual(Expected, maps:get(reason, yuzu_gw_upstream:format_status(#{reason => R})))
     end || {R, Expected} <- [{normal, normal},
                              {shutdown, shutdown},
                              {{badmatch, Req}, {badmatch, '$redacted'}},
                              {{{badmatch, Req}, [{m, f, [Req], loc}]},
                               {{badmatch, '$redacted'}, [{m, f, 1, loc}]}},
                              {{[Req], [{m, f, [Req], loc}]}, {'$redacted', [{m, f, 1, loc}]}},
                              {{Req, boom}, {'$redacted', '$redacted'}},
                              {Req, '$redacted'},
                              {{function_clause, Req}, {function_clause, '$redacted'}},
                              {{function_clause, [odd, {Req}, {m, f, Req, loc}]},
                               {function_clause, ['$redacted', '$redacted', '$redacted']}}]],
    %% The redacted status still renders through OTP's own report callback
    %% (a log that is not a list crashes it, and the report is then printed raw).
    #{state := ShownState, reason := ShownReason, log := ShownLog} =
        yuzu_gw_upstream:format_status(Status),
    Rendered0 = gen_server:format_log(
                    #{label => {gen_server, terminate}, name => yuzu_gw_upstream,
                      last_message => circuit_state, state => ShownState,
                      log => ShownLog, reason => {ShownReason, []},
                      client_info => undefined, process_label => undefined},
                    #{}),
    Rendered = unicode:characters_to_list(Rendered0),
    assert_no_secrets(Rendered),
    ?assertNotEqual(nomatch, string:find(Rendered, "log_entries_redacted")),
    %% A log that is not a list, and queue fields of the wrong type.
    ?assertEqual([], maps:get(log, yuzu_gw_upstream:format_status(#{log => Req}))),
    Bad = [setelement(up_index(replay_queue), State, Req),
           setelement(up_index(recent_replays), State, [Req]),
           setelement(up_index(replay_queue), setelement(up_index(recent_replays), State, Req),
                      Req)],
    [begin
         assert_no_secrets(Show(#{state => B, message => {proxy_register, Req}})),
         ?assertEqual('$redacted', maps:get(state, yuzu_gw_upstream:format_status(#{state => B})))
     end || B <- Bad],
    ok.

%% An RPC that raises, with the request in the exception's stacktrace args,
%% must not crash the process: it is a failed RPC for the breaker, returns a
%% failure and logs only the class and the redacted reason.
rpc_exception_is_counted_and_carries_no_request() ->
    Pid = whereis(yuzu_gw_upstream),
    ?assertEqual(0, up_get(cb_failures)),
    mock_unary(fun(<<"ProxyRegister">>, Req, _Hdr) ->
                       erlang:error({badmatch, Req}, [Req]);
                  (M, R, H) -> default_rpc(M, R, H)
               end),
    {Result, Lines} = capture_logs(fun() ->
        yuzu_gw_upstream:proxy_register(secret_req(1))
    end),
    ?assertMatch({error, {internal, _}}, Result),
    assert_no_secrets(lists:flatten(io_lib:format("~p", [Result]))),
    ?assertEqual(Pid, whereis(yuzu_gw_upstream)),
    ?assertEqual(1, up_get(cb_failures)),
    Warned = [T || {warning, T} <- Lines, binary:match(T, <<"raised">>) =/= nomatch],
    ?assertMatch([_], Warned),
    [assert_no_secrets(unicode:characters_to_list(T)) || {_, T} <- Lines],
    ?assertEqual([{rpc_error, <<"exception">>}],
                 [{rpc_error, Code} || {#{count := 1}, #{code := Code}} <- events(?EV_RPC_ERROR)]).

%% DOCUMENTS A RESIDUAL, it does not pin it as correct. A crash prints the
%% process mailbox in the proc_lib crash report (`messages:'), from raw data
%% that format_status cannot reach, so a queued proxy_register is visible
%% there; this test says nothing about that section. It asserts only what
%% format_status does cover: the gen_server terminate report.
crash_with_request_in_mailbox_gen_server_report_clean() ->
    Prev = process_flag(trap_exit, true),
    stop_upstream(),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    try
        ok = sys:suspend(UpPid),
        Caller = spawn(fun() -> catch yuzu_gw_upstream:proxy_register(secret_req(1)) end),
        await(fun() -> process_info(UpPid, message_queue_len) =:= {message_queue_len, 1} end),
        {_, Lines} = capture_logs(fun() ->
            catch gen_server:stop(UpPid, {test_crash, boom}, 5000),
            await(fun() -> not is_process_alive(Caller) end)
        end),
        Terminate = [T || {error, T} <- Lines,
                          binary:match(T, <<"gen_server,terminate">>) =/= nomatch,
                          binary:match(T, <<"test_crash">>) =/= nomatch],
        ?assertMatch([_], Terminate),
        [assert_no_secrets(unicode:characters_to_list(R)) || R <- Terminate]
    after
        catch unlink(UpPid),
        catch gen_server:stop(UpPid, normal, 2000),
        process_flag(trap_exit, Prev),
        flush_exits()
    end.

%% An abnormal stop runs the same report path as a crash. The test process
%% owns its own upstream and traps exits, like registry_stopped_mid_drip_*.
%% The state holds 50 queued requests and the mailbox is empty: both reports
%% show the queue as counts. (Nothing here covers the mailbox, see above.)
abnormal_stop_reports_show_queue_counts() ->
    Prev = process_flag(trap_exit, true),
    stop_upstream(),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    Count = 50,
    try
        _ = sys:replace_state(yuzu_gw_upstream,
                              fun(St) -> setelement(up_index(replay_queue), St,
                                                    secret_queue(Count)) end),
        {_, Lines} = capture_logs(fun() ->
            catch gen_server:stop(UpPid, {test_crash, boom}, 5000),
            ok
        end),
        Reports = [T || {error, T} <- Lines,
                        binary:match(T, <<"test_crash">>) =/= nomatch],
        %% The gen_server terminate report and the proc_lib crash report.
        ?assertEqual(2, length(Reports)),
        [assert_no_secrets(unicode:characters_to_list(R)) || R <- Reports],
        ?assertMatch([_], [R || R <- Reports,
                                binary:match(R, <<"replay_queue_len => 50">>) =/= nomatch])
    after
        catch unlink(UpPid),
        catch gen_server:stop(UpPid, normal, 2000),
        process_flag(trap_exit, Prev),
        flush_exits()
    end.

%%% -- The real heartbeat buffer feeding the real upstream ----------------

flush_verdict_reaches_the_targeted_replay() ->
    watch(),
    Buf = start_buffer(),
    try
        A1 = bind_agent(<<"f1a">>),
        _ = bind_agent(<<"f1b">>),
        mock_batch(#{acknowledged_count => 1, unknown_session_ids => [sid(A1)]}),
        ok = flush_one(),
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle(),
        ?assertEqual([sid(A1)], replay_hdrs()),
        ?assertEqual(1, proxy_count()),
        ?assertEqual([#{count => 1}], triggers(heartbeat))
    after
        stop_buffer(Buf)
    end.

%% E7: any number of failed flushes leave the breaker as it was. The verdict
%% flush first is the positive control that the buffer is wired to the upstream.
flush_errors_never_reach_the_breaker() ->
    watch(),
    Buf = start_buffer(),
    try
        A1 = bind_agent(<<"f7a">>),
        mock_batch(#{acknowledged_count => 0, unknown_session_ids => [sid(A1)]}),
        ok = flush_one(),
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle(),
        mock_unary(fun(<<"BatchHeartbeat">>, _, _) -> {error, econnrefused};
                      (M, R, H) -> default_rpc(M, R, H)
                   end),
        [{error, _} = flush_one() || _ <- lists:seq(1, 7)],
        mock_unary(fun(<<"BatchHeartbeat">>, _, _) ->
                           {error, {<<"14">>, <<"unavailable">>}, #{}};
                      (M, R, H) -> default_rpc(M, R, H)
                   end),
        [{error, _} = flush_one() || _ <- lists:seq(1, 7)],
        sync(),
        ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
        ?assertEqual(0, up_get(cb_failures)),
        ?assertEqual([sid(A1)], replay_hdrs()),
        ?assertEqual(1, proxy_count())
    after
        stop_buffer(Buf)
    end.

%% E8: truncated=true with a short list replays that list only; it never
%% starts a full replay (the second agent stays untouched) and is counted.
truncated_verdict_replays_only_the_listed_session() ->
    watch(),
    Buf = start_buffer(),
    try
        A1 = bind_agent(<<"f8a">>),
        _ = bind_agent(<<"f8b">>),
        mock_batch(#{acknowledged_count => 0, unknown_session_ids => [sid(A1)],
                     unknown_session_ids_truncated => true}),
        ok = flush_one(),
        await(fun() -> replay_hdrs() =/= [] end),
        await_idle(),
        ?assertEqual([sid(A1)], replay_hdrs()),
        ?assertEqual(1, proxy_count()),
        ?assertEqual([#{count => 1}], [M || {M, _} <- events(?EV_TRUNC)])
    after
        stop_buffer(Buf)
    end.

%%%===================================================================
%%% Breaker fixture
%%%===================================================================

%% E11: five failures open the breaker. A verdict naming both agents is
%% dropped and counted per id; no rpc, nothing queued, no stamp. After
%% circuit_half_open a verdict naming one agent replays it: that single
%% ProxyRegister is the probe, it closes the breaker, and the second agent is
%% NOT re-proxied (a drip rpc never starts a full replay).
open_breaker_drops_verdict_then_half_open_probe_replays_once() ->
    watch(),
    A1 = bind_agent(<<"e11a">>),
    A2 = bind_agent(<<"e11b">>),
    trip_breaker(),
    Before = proxy_count(),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    sync(),
    ?assertEqual(2, dropped(circuit_open)),
    ?assertEqual(Before, proxy_count()),
    ?assertEqual([], up_get(replay_queue)),
    ?assertEqual(#{}, up_get(recent_replays)),
    to_half_open(),
    mock_unary(fun default_rpc/3),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    ?assertEqual([sid(A1)], replay_hdrs()),
    ?assertEqual(Before + 1, proxy_count()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual([sid(A1)], maps:keys(up_get(recent_replays))).

%% E14: the probe fails, so the breaker opens again (second open event).
failed_half_open_probe_reopens() ->
    watch(),
    A1 = bind_agent(<<"e14">>),
    trip_breaker(),
    to_half_open(),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> proxy_count() =:= 6 end),
    await_idle(),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual([<<"open">>, <<"half_open">>, <<"open">>], circuit_states()).

%% E22: four failures leave the breaker closed; the first replay step is the
%% fifth failure and opens it; the second queued entry is abandoned. Depth is
%% reported on append (2), after the step (1) and zero on the abort.
queue_depth_is_zero_after_circuit_abort() ->
    watch(),
    A1 = bind_agent(<<"e22c">>),
    A2 = bind_agent(<<"e22d">>),
    mock_unary(fun(_, _, _) -> {error, connection_refused} end),
    [_ = yuzu_gw_upstream:proxy_register(trigger_req()) || _ <- lists:seq(1, 4)],
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1), sid(A2)]),
    await(fun() -> length(depths()) >= 3 end),
    await_idle(),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(5, proxy_count()),
    ?assertEqual([{0, 2}, {1, 1}, {0, 0}], depths()),
    ?assertEqual([sid(A1)], maps:keys(up_get(recent_replays))).

%%%===================================================================
%%% Guard fixture (100 ms) and cap fixture (2)
%%%===================================================================

session_replayed_again_after_guard_expiry() ->
    watch(),
    ?assertEqual(100, up_get(session_guard_ms)),
    A1 = bind_agent(<<"e4b">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    wait_elapsed(erlang:monotonic_time(millisecond), 100),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> length(replay_hdrs()) >= 2 end),
    await_idle(),
    ?assertEqual([sid(A1), sid(A1)], replay_hdrs()).

%% A1 is replayed by a verdict and then leaves; A2 arrives; the guard window
%% passes; a breaker recovery replays A2 only. The drain prunes A1's expired
%% stamp and stamps A2.
stale_stamps_are_pruned_after_a_breaker_only_drain() ->
    watch(),
    A1 = bind_agent(<<"e21p">>),
    ok = yuzu_gw_upstream:replay_sessions([sid(A1)]),
    await(fun() -> replay_hdrs() =/= [] end),
    await_idle(),
    Stamped = erlang:monotonic_time(millisecond),
    ?assert(maps:is_key(sid(A1), up_get(recent_replays))),
    yuzu_gw_registry:deregister_agent(id(A1)),
    _ = sys:get_state(yuzu_gw_registry),
    A2 = bind_agent(<<"e21q">>),
    wait_elapsed(Stamped, 100),
    cause_one_failure(),
    mock_unary(fun default_rpc/3),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    await(fun() -> lists:member(sid(A2), replay_hdrs()) end),
    await_idle(),
    ?assertEqual([sid(A2)], maps:keys(up_get(recent_replays))).

%% E21: cap 2. One cast names four held sessions: two are queued, two are
%% dropped as queue_full, and only two are replayed.
queue_cap_drops_overflow_and_counts_queue_full() ->
    watch(),
    ?assertEqual(2, up_get(replay_queue_max)),
    As = [bind_agent(S) || S <- [<<"e21c1">>, <<"e21c2">>, <<"e21c3">>, <<"e21c4">>]],
    ok = yuzu_gw_upstream:replay_sessions([sid(A) || A <- As]),
    await(fun() -> length(replay_hdrs()) >= 2 end),
    await_idle(),
    ?assertEqual(2, dropped(queue_full)),
    ?assertEqual(2, length(lists:usort(replay_hdrs()))),
    ?assertEqual(2, length(replay_hdrs())).

%%%===================================================================
%%% Env validation
%%%===================================================================

env_guard_invalid_falls_back() ->
    [env_case(registration_replay_session_guard_ms, Bad, session_guard_ms, 10000, invalid)
     || Bad <- [-1, 3600001, 1.5, not_a_number, <<"10">>, "10"]],
    ok.

env_guard_valid_is_kept() ->
    [env_case(registration_replay_session_guard_ms, V, session_guard_ms, V, valid)
     || V <- [0, 1, 3600000]],
    ok.

env_queue_max_invalid_falls_back() ->
    [env_case(registration_replay_queue_max, Bad, replay_queue_max, 10000, invalid)
     || Bad <- [0, -5, 1000001, 2.5, not_a_number, <<"10">>]],
    ok.

env_queue_max_valid_is_kept() ->
    [env_case(registration_replay_queue_max, V, replay_queue_max, V, valid)
     || V <- [1, 7, 1000000]],
    ok.

env_spacing_invalid_falls_back() ->
    [env_case(registration_replay_spacing_ms, Bad, replay_spacing, 20, invalid)
     || Bad <- [-5, 60001, 1.5, foo, <<"20">>, "20"]],
    ok.

env_spacing_valid_is_kept() ->
    [env_case(registration_replay_spacing_ms, V, replay_spacing, V, valid)
     || V <- [0, 1, 60000]],
    ok.

%% Restart the upstream with Key=Val and check the state field and the
%% warning. An invalid value warns (naming the key) and takes the default; a
%% valid value is kept and does not warn about that key.
env_case(Key, Val, Field, Expected, Kind) ->
    stop_upstream(),
    application:set_env(yuzu_gw, Key, Val),
    {Pid, Lines} = capture_logs(fun() ->
        {ok, P} = yuzu_gw_upstream:start_link(),
        P
    end),
    try
        ?assertEqual(Expected, up_get(Field)),
        Named = [T || {warning, T} <- Lines,
                      binary:match(T, atom_to_binary(Key, utf8)) =/= nomatch],
        case Kind of
            invalid -> ?assertNotEqual([], Named);
            valid   -> ?assertEqual([], Named)
        end
    after
        catch unlink(Pid),
        catch gen_server:stop(Pid, normal, 5000),
        application:unset_env(yuzu_gw, Key)
    end.

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid -> unlink(Pid), gen_server:stop(Pid, normal, 5000)
    end.

%%%===================================================================
%%% Helpers: agents
%%%===================================================================

bind_agent(Suffix) ->
    bind_agent(Suffix, undefined).

%% A live agent bound with register_agent/7, so the session index row that
%% entries_for_sessions/1 resolves through exists. ReqOverride `undefined'
%% stores the usual per-agent request.
bind_agent(Suffix, ReqOverride) ->
    Id = unique_id(Suffix),
    Sid = <<"sess-", Id/binary>>,
    Req = case ReqOverride of
              undefined -> agent_req(Id);
              R -> R
          end,
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(Id, Pid, Sid, [<<"svc">>], <<"host">>, Req,
                                         conn_test),
    #{id => Id, sid => Sid, pid => Pid, req => Req}.

%% The same agent id reconnects under a new session and a new process.
rebind(#{id := Id, req := Req} = A, NewSid) ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(Id, Pid, NewSid, [<<"svc">>], <<"host">>, Req,
                                         conn_test_2),
    A#{sid := NewSid, pid := Pid}.

id(#{id := V}) -> V.
sid(#{sid := V}) -> V.
pid(#{pid := V}) -> V.
req(#{req := V}) -> V.

%% The registry owns these tables and keeps them protected; run the change
%% inside the owner.
drop_sessions_table() ->
    _ = sys:replace_state(yuzu_gw_registry,
                          fun(St) -> catch ets:delete(yuzu_gw_sessions), St end),
    ok.

restore_sessions_table() ->
    _ = sys:replace_state(yuzu_gw_registry, fun(St) ->
        case ets:whereis(yuzu_gw_sessions) of
            undefined ->
                ets:new(yuzu_gw_sessions,
                        [named_table, set, protected, {read_concurrency, true}]);
            _ ->
                ok
        end,
        St
    end),
    ok.

flush_exits() ->
    receive {'EXIT', _, _} -> flush_exits()
    after 0 -> ok
    end.

%%%===================================================================
%%% Helpers: breaker
%%%===================================================================

trip_breaker() ->
    mock_unary(fun(_, _, _) -> {error, connection_refused} end),
    [_ = yuzu_gw_upstream:proxy_register(trigger_req()) || _ <- lists:seq(1, 5)],
    open = yuzu_gw_upstream:circuit_state(),
    ok.

%% The reset timer is far away in this fixture: deliver its message by hand.
to_half_open() ->
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    sync(),
    half_open = yuzu_gw_upstream:circuit_state(),
    ok.

%%%===================================================================
%%% Helpers: the real heartbeat buffer
%%%===================================================================

start_buffer() ->
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_heartbeat_buffer:start_link(),
    unlink(Pid),
    Pid.

stop_buffer(Pid) ->
    catch gen_server:stop(Pid, shutdown, 2000),
    ok.

%% Queue one heartbeat and flush. The cast and the call come from this
%% process, so the flush sees the heartbeat.
flush_one() ->
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"hb-session">>,
                                               sent_at => #{millis_epoch => 1700000000000}}),
    yuzu_gw_heartbeat_buffer:flush_sync().

mock_batch(Resp) ->
    mock_unary(fun(<<"BatchHeartbeat">>, _Req, _Hdr) -> {ok, Resp, #{}};
                  (M, R, H) -> default_rpc(M, R, H)
               end).

%%%===================================================================
%%% Helpers: mocks and the call log
%%%===================================================================

%% Install a logging grpcbox_client:unary mock. Fun(Method, Req, SessionHdr)
%% returns the unary result; Method is the last path segment and SessionHdr is
%% the x-yuzu-session-id outgoing metadata or `undefined'.
mock_unary(Fun) ->
    meck:expect(grpcbox_client, unary, fun(Ctx, Path, Req, _Def, _Opts) ->
        Method = lists:last(binary:split(Path, <<"/">>, [global])),
        Hdr = maps:get(<<"x-yuzu-session-id">>,
                       grpcbox_metadata:from_outgoing_ctx(Ctx), undefined),
        log({rpc, Method, Req, Hdr}),
        Fun(Method, Req, Hdr)
    end).

default_rpc(<<"ProxyRegister">>, _Req, Hdr) when is_binary(Hdr) ->
    {ok, #{session_id => Hdr, accepted => true}, #{}};
default_rpc(_Method, _Req, _Hdr) ->
    {ok, #{}, #{}}.

%% ProxyRegister for a gated session blocks, inside the upstream process,
%% until the test calls release/1; every other rpc succeeds.
mock_gated(GatedHdrs) ->
    mock_gated(GatedHdrs, fun default_rpc/3).

mock_gated(GatedHdrs, After) ->
    mock_unary(fun(M, Req, Hdr) ->
        case M =:= <<"ProxyRegister">> andalso lists:member(Hdr, GatedHdrs) of
            true  -> gate(Hdr), After(M, Req, Hdr);
            false -> default_rpc(M, Req, Hdr)
        end
    end).

gate(Hdr) ->
    notify({rpc_entered, Hdr}),
    receive {release, Hdr} -> ok
    after 10000 -> ok
    end.

release(Hdr) ->
    whereis(yuzu_gw_upstream) ! {release, Hdr},
    ok.

%% Make the calling process the one the mocks notify.
watch() ->
    persistent_term:put(?SUBK, self()).

notify(Msg) ->
    case persistent_term:get(?SUBK, undefined) of
        undefined -> ok;
        Pid -> Pid ! Msg, ok
    end.

log(Entry) ->
    case persistent_term:get(?LOGK, undefined) of
        undefined ->
            ok;
        Tid ->
            Key = erlang:unique_integer([monotonic]),
            try ets:insert(Tid, {Key, Entry}) catch error:badarg -> ok end,
            notify({logged, Key})
    end.

entries() ->
    Tid = persistent_term:get(?LOGK),
    [E || {_, E} <- ets:tab2list(Tid)].

events(Name) ->
    [{Meas, Meta} || {event, N, Meas, Meta} <- entries(), N =:= Name].

norm(A) when is_atom(A) -> atom_to_binary(A, utf8);
norm(B) -> B.

%% Measurements of the registration_replay_triggered events with this trigger.
triggers(Trigger) ->
    T = atom_to_binary(Trigger, utf8),
    [M || {M, Meta} <- events(?EV_TRIG), norm(maps:get(trigger, Meta, undefined)) =:= T].

%% Sum of the verdict_dropped counts with this reason.
dropped(Reason) ->
    R = atom_to_binary(Reason, utf8),
    lists:sum([maps:get(count, M, 0)
               || {M, Meta} <- events(?EV_DROP), norm(maps:get(reason, Meta, undefined)) =:= R]).

%% {replayed, queue_depth} of every registration_replay event, in order.
depths() ->
    [{maps:get(replayed, M), maps:get(queue_depth, M)} || {M, _} <- events(?EV_REPLAY)].

circuit_states() ->
    [norm(maps:get(state, Meta)) || {_, Meta} <- events(?EV_CIRCUIT)].

%% Every ProxyRegister that carried a session header (drip replays), in order;
%% proxy_register/1 calls carry none.
replays() ->
    [{Req, Hdr} || {rpc, <<"ProxyRegister">>, Req, Hdr} <- entries(), Hdr =/= undefined].

replay_hdrs() ->
    [Hdr || {_, Hdr} <- replays()].

proxy_count() ->
    length([x || {rpc, <<"ProxyRegister">>, _, _} <- entries()]).

agent_calls() ->
    [E || E <- entries(), element(1, E) =:= agent].

disconnects() ->
    [P || {agent, disconnect, P} <- agent_calls()].

reannounces() ->
    [{P, S} || {agent, reannounce, P, S} <- agent_calls()].

%%%===================================================================
%%% Helpers: waiting
%%%===================================================================

%% Re-evaluate Pred after every logged call (event driven), and every 20 ms
%% for conditions no logged call announces. The 3 s bound only ends a failing
%% test; it is not a window a passing test waits out.
await(Pred) ->
    await_until(Pred, erlang:monotonic_time(millisecond) + 3000).

await_until(Pred, Deadline) ->
    case Pred() of
        true ->
            ok;
        false ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            case Left > 0 of
                false ->
                    erlang:error({await_timeout, process_info(self(), current_stacktrace)});
                true ->
                    receive {logged, _} -> ok
                    after min(Left, 20) -> ok
                    end,
                    await_until(Pred, Deadline)
            end
    end.

await_msg(Msg) ->
    receive Msg -> ok
    after 3000 -> erlang:error({no_message, Msg})
    end.

%% A call after a cast from this process is handled after the cast.
sync() ->
    _ = yuzu_gw_upstream:circuit_state(),
    ok.

%% The drip is finished: queue empty twice with a call in between. The call
%% matters: a cast sent from inside the last step (a replay trigger) is in the
%% mailbox before that step's state is readable, so a second read after a
%% round trip would show the queue it seeded.
await_idle() ->
    await(fun() ->
        up_get(replay_queue) =:= []
            andalso begin sync(), up_get(replay_queue) =:= [] end
    end).

%% Sleep until the monotonic clock is past T0 + Ms. Waiting out a time window
%% is the point of the caller; it is not a guess at how long something takes.
wait_elapsed(T0, Ms) ->
    Left = T0 + Ms + 5 - erlang:monotonic_time(millisecond),
    case Left > 0 of
        true  -> timer:sleep(Left), wait_elapsed(T0, Ms);
        false -> ok
    end.

%%%===================================================================
%%% Helpers: the upstream state record
%%%===================================================================

%% The record is private to yuzu_gw_upstream, so read it by field name from
%% the module's own source (like yuzu_gw_telemetry_tests does for the reject
%% atoms; the loaded module has no beam under cover). A field that does not
%% exist fails the test with its name.
up_get(Field) ->
    State = sys:get_state(yuzu_gw_upstream),
    element(up_index(Field), State).

up_index(Field) ->
    Fields = up_fields(),
    case [I || {I, F} <- lists:zip(lists:seq(2, length(Fields) + 1), Fields), F =:= Field] of
        [I] -> I;
        []  -> erlang:error({no_such_state_field, Field, Fields})
    end.

up_fields() ->
    case persistent_term:get({?MODULE, up_fields}, undefined) of
        undefined ->
            Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
            {ok, Forms} = epp:parse_file(Src, []),
            [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
            Names = [field_name(F) || F <- Fs],
            persistent_term:put({?MODULE, up_fields}, Names),
            Names;
        Names ->
            Names
    end.

field_name({typed_record_field, F, _Type}) -> field_name(F);
field_name({record_field, _, {atom, _, Name}}) -> Name;
field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.

%%%===================================================================
%%% Helpers: log capture
%%%===================================================================

%% Run Fun with a capturing logger handler at info level; returns
%% {FunResult, [{Level, Text}]} for every event logged meanwhile. The handler
%% is VM-wide, so callers filter on the text they care about.
capture_logs(Fun) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, info),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => info}),
    try
        Result = Fun(),
        {Result, collect_logs([])}
    after
        logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Prev)
    end.

%% No idle window: the handler runs in the logging process and sends before
%% the logging call returns, and every capture body waits for the process that
%% logs, so every captured line is already in the mailbox.
collect_logs(Acc) ->
    receive {captured_log, Level, Text} -> collect_logs([{Level, Text} | Acc])
    after 0 -> lists:reverse(Acc)
    end.

%% logger handler callback
log(#{level := Level, msg := Msg}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S}     -> unicode:characters_to_binary(S);
        {report, R}     -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args}     -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Level, Text},
    ok.
