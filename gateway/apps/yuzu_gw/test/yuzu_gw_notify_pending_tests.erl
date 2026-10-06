%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the bounded pending store behind stream-status
%%% notifications (#4632): the closed-state drain, the reserved replay slot and
%%% the half_open probe.
%%%
%%% yuzu_gw_upstream used to drop a NotifyStreamStatus when 10 were already in
%%% flight and when the circuit breaker was open. It now holds them in
%%% yuzu_gw_notify_queue (key {agent, session, home}, latest event wins, FIFO by
%%% first insertion, cap notify_pending_max keys) and drains them as capacity
%%% returns. These tests pin that wiring:
%%%   - selection order, coalescing, the cap, the two-sessions case
%%%   - an open breaker holds; half_open sends ONE held entry as the probe, and
%%%     its success closes the breaker and drains first in first out
%%%   - the probe protocol: reopen and requeue at the head on error, a stale
%%%     result or an older generation never touches the breaker, the reserved
%%%     slot for the requeue, a killed or duplicated probe, the 10 worker budget
%%%   - one slot is held back while a registration replay is active
%%%   - the [yuzu,gw,upstream,notify_queue] gauge events
%%%   - format_status shows a count, never the held events
%%%   - an untrappable worker death, an upstream restart, terminate/2
%%%   - notify_pending_max validation and a 1000 agent burst
%%%
%%% The mock of grpcbox_client:unary/5 parks every NotifyStreamStatus worker in
%%% the mock until the test releases it, so "in flight" is something the test
%%% controls. Waits are event driven: the mock and the telemetry handler message
%%% the test process, and every wait has a bounded deadline. There is no
%%% wall-clock margin anywhere.
%%%
%%% Real: yuzu_gw_registry, telemetry (a handler of this module records the
%%% three notify events). Mock: grpcbox_client.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_pending_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([handle_event/4, log/2]).  %% telemetry handler and logger handler callbacks

-define(CTXK, {?MODULE, ctx}).
-define(SUBK, {?MODULE, sub}).
-define(FIELDSK, {?MODULE, up_fields}).
-define(TELEMETRY_HANDLER, yuzu_notify_pending_test_events).
-define(LOG_HANDLER, yuzu_notify_pending_test_log).

-define(EV_QUEUE,     [yuzu, gw, upstream, notify_queue]).
-define(EV_DROPPED,   [yuzu, gw, upstream, notify_dropped]).
-define(EV_COALESCED, [yuzu, gw, upstream, notify_coalesced]).

%% The application env keys a test here may set: saved in setup, restored (or
%% unset, when they were not set) in teardown.
-define(ENV_KEYS, [notify_pending_max,
                   cluster_id,
                   registration_replay_spacing_ms,
                   circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms]).

-define(INFLIGHT_MAX, 10).
%% A peer address that is not UTF-8: the protobuf string encoder raises on it.
-define(POISON_PEER, <<255, 254, 200>>).
%% A worker parked in the mock gives up after this long, so a test that dies
%% cannot leave a parked process behind. Teardown releases them long before.
-define(PARK_MS, 20000).
%% Deadline of every event driven wait.
-define(AWAIT_MS, 5000).

%%%===================================================================
%%% Fixtures: a fresh upstream per test, the breaker timers far beyond a
%%% test so nothing here races a reset timer.
%%%===================================================================

t(Name, Fun) ->
    t(Name, 30, Fun).

t(Name, Seconds, Fun) ->
    {timeout, Seconds, {Name, Fun}}.

closed_test_() ->
    {foreach,
     fun() -> setup([]) end,
     fun cleanup/1,
     [
      t("fifty connected casts: all reach the mock, at most 10 at once, none dropped",
        fun fifty_casts_are_bounded_and_none_dropped/0),
      t("selection order: one slot opens at a time, the k-th entry is the k-th held key",
        fun selection_order_is_first_in_first_out/0),
      t("coalescing: CONNECTED, CONNECTED, DISCONNECTED for one key sends one DISCONNECTED",
        fun coalescing_keeps_the_latest_event/0),
      t("two sessions of one agent are both kept and sent in order",
        fun two_sessions_of_one_agent_are_both_kept/0),
      t("the peer address is made safe at admission: capped, replaced when invalid, else unchanged",
        fun peer_addr_is_sanitised_at_admission/0),
      t("the notification carries exactly the known keys, every binary valid UTF-8",
        fun notification_key_set_and_utf8/0),
      t("the held peer address is a copy: it does not keep the parent binary alive",
        fun peer_addr_does_not_retain_its_parent_binary/0),
      t("an open circuit holds notifications; a half_open probe that succeeds drains them in order",
        fun open_circuit_holds_then_close_drains_in_order/0),
      t("a half_open circuit sends one held notification as the probe and holds the rest",
        fun half_open_circuit_sends_one_probe_and_holds_the_rest/0),
      t("the notify_queue gauges follow a burst and settle at zero, with a zero emit from init",
        fun gauges_follow_a_burst/0),
      t("format_status shows notify_pending_len and never the held events",
        fun format_status_shows_a_count_not_the_events/0),
      t("format_status shows the agent id and event of a notify cast and redacts the rest",
        fun format_status_redacts_the_notify_cast/0),
      t("a worker killed untrappably is removed and the next held entry is spawned",
        fun untrappable_worker_death_is_survived/0),
      t("an upstream restart starts its gauges at zero and loses the old pending entries",
        fun restart_starts_from_zero/0),
      t("terminate/2 with a non-empty store does not crash",
        fun terminate_with_pending_entries/0),
      t("1000 distinct agents, one slot opening at a time: all delivered in order, never above 10",
        60, fun burst_one_slot_at_a_time/0),
      t("1000 distinct agents with free running workers: all delivered, never above 10",
        60, fun burst_free_running/0)
     ]}.

%% Cap 3.
cap_test_() ->
    {foreach,
     fun() -> setup([{notify_pending_max, 3}]) end,
     fun cleanup/1,
     [
      t("the cap counts keys: the overflow is dropped and counted, a replacement is not",
        fun cap_drops_overflow_and_never_a_replacement/0)
     ]}.

%% notify_pending_max validation: the upstream is restarted inside each test,
%% and a logger handler records what init/1 logs.
env_test_() ->
    {foreach,
     fun() -> setup_logs([]) end,
     fun cleanup_logs/1,
     [
      t("a bad notify_pending_max warns naming the key and falls back to 10000",
        fun env_invalid_falls_back/0),
      t("a notify_pending_max inside 1..1000000 is kept, logged, and does not warn",
        fun env_valid_is_kept/0),
      t("a bad circuit_breaker_reset_timeout_ms warns naming the key and falls back to 10000",
        fun reset_timeout_invalid_falls_back/0),
      t("a circuit_breaker_reset_timeout_ms inside 1..3600000 is kept and does not warn",
        fun reset_timeout_valid_is_kept/0),
      t("a bad circuit_breaker_max_reset_timeout_ms warns naming the key and falls back to 300000",
        fun max_reset_timeout_invalid_falls_back/0),
      t("a circuit_breaker_max_reset_timeout_ms inside 1..3600000 is kept and does not warn",
        fun max_reset_timeout_valid_is_kept/0)
     ]}.

%% A registration replay that is active while the pending store is refilled.
%% Replay spacing 1 ms so the drip retries quickly.
replay_test_() ->
    {foreach,
     fun() -> setup([{registration_replay_spacing_ms, 1}]) end,
     fun cleanup/1,
     [
      t("a refilled backlog does not starve an active replay: the replay head advances",
        fun replay_advances_while_the_backlog_is_refilled/0)
     ]}.

%% The reserved replay slot has a size, and a long replay spacing keeps the
%% drip parked (queue non-empty, nothing advancing) so the size can be observed.
replay_reserve_test_() ->
    {foreach,
     fun() -> setup([{registration_replay_spacing_ms, 60000}]) end,
     fun cleanup/1,
     [
      t("while a replay is active the reserve is exactly one slot: refills stop at nine",
        fun replay_reserve_is_exactly_one_slot/0)
     ]}.

%% The half_open probe (#4632). The breaker's reset timer is a long way off (the
%% tests move it to half_open by hand) but short of its cap, so one failed probe
%% shows the backoff doubling. Replay spacing 1 ms.
probe_env(Extra) ->
    [{registration_replay_spacing_ms, 1},
     {circuit_breaker_reset_timeout_ms, 100000},
     {circuit_breaker_max_reset_timeout_ms, 1200000}] ++ Extra.

probe_test_() ->
    {foreach,
     fun() -> setup(probe_env([])) end,
     fun cleanup/1,
     [
      t("probe success closes the breaker, drains the held keys in order and fires the replay",
        fun probe_success_closes_drains_and_replays/0),
      t("probe error reopens the breaker with doubled backoff and requeues the event at the head",
        fun probe_error_reopens_and_requeues_at_the_head/0),
      t("a probe result after a call path RPC closed the circuit leaves the breaker alone (ok)",
        fun stale_probe_ok_after_call_path_close/0),
      t("a probe result after a call path RPC closed the circuit leaves the breaker alone (error)",
        fun stale_probe_error_after_call_path_close/0),
      t("a probe result after a call path failure reopened the breaker leaves it alone (error)",
        fun stale_probe_error_while_open/0),
      t("a probe result after a call path failure reopened the breaker leaves it alone (ok)",
        fun stale_probe_ok_while_open/0),
      t("an old generation probe ok does not close a newer half_open breaker",
        fun older_generation_probe_ok_is_ignored_by_the_breaker/0),
      t("an old generation probe error does not reopen a newer half_open breaker",
        fun older_generation_probe_error_is_ignored_by_the_breaker/0),
      t("a newer event for the probe's key supersedes the failed probe event, counted",
        fun newer_same_key_event_supersedes_a_failed_probe/0),
      t("a probe worker killed with no result is a failure, handled once",
        fun killed_probe_worker_is_one_failure/0),
      t("a duplicate or foreign probe result is ignored",
        fun duplicate_and_foreign_probe_results_are_ignored/0),
      t("a failed old probe is re-sent after the newer same-key event went out",
        fun failed_old_probe_is_resent_after_the_newer_event/0),
      t("while a probe is in flight nothing else drains, ordinary workers included",
        fun nothing_else_drains_while_a_probe_is_in_flight/0),
      t("the probe counts inside the ten worker budget and shows in the inflight gauge",
        fun probe_counts_inside_the_budget/0),
      t("format_status shows notify_probe_held and never the probe event",
        fun format_status_hides_the_probe_event/0),
      t("a held notification whose peer address cannot be encoded does not block the breaker",
        fun poison_head_does_not_block_the_breaker/0),
      t("held notifications that all carry an unencodable peer address still drain",
        fun all_poison_heads_still_drain/0)
     ]}.

%% What a killed probe worker leaves in the log: logger handler at info level.
probe_log_test_() ->
    {foreach,
     fun() -> setup_logs(probe_env([])) end,
     fun cleanup_logs/1,
     [
      t("a probe worker killed with no result logs a warning naming the agent and the reason",
        fun killed_probe_worker_is_logged/0),
      t("the killed probe warning redacts an exit reason that carries payload bytes",
        fun killed_probe_warning_redacts_the_reason/0),
      t("an agent id with control characters never reaches a notify log line raw",
        fun notify_log_lines_carry_no_raw_control_characters/0)
     ]}.

%% A request that cannot be encoded never left the gateway, so it says nothing
%% about the upstream: it must not move the breaker, whichever threshold is set.
%% Run with the test threshold (3) and with the default one (5).
local_exception_test_() ->
    [{foreach,
      fun() -> setup(Env) end,
      fun cleanup/1,
      [
       t("a request that cannot be encoded never feeds the breaker, however many arrive",
         fun register_encode_exception_never_feeds_the_breaker/0)
      ]} || Env <- [[], [{circuit_breaker_failure_threshold, 5}]]].

%% The same on the half_open probe path, with the log recorded.
probe_local_exception_test_() ->
    {foreach,
     fun() -> setup_logs(probe_env([])) end,
     fun cleanup_logs/1,
     [
      t("a probe that cannot be encoded is evicted with a warning, the breaker is untouched",
        fun unencodable_probe_is_evicted_not_requeued/0),
      t("held notifications that all cannot be encoded are evicted one after the other",
        fun all_unencodable_probes_drain_to_empty/0),
      t("a probe that raises for any other reason is a failure: requeued, breaker reopened",
        fun other_probe_exception_is_a_failure/0),
      t("ordinary workers that cannot encode do not touch the breaker or block the rest",
        fun unencodable_ordinary_worker_does_not_touch_the_breaker/0)
     ]}.

%% cluster_id is stamped on every notification: a configured value that is a
%% list of Unicode code points must reach the encoder as UTF-8.
cluster_id_test_() ->
    {foreach,
     fun() -> setup([]) end,
     fun cleanup/1,
     [
      t("a cluster_id configured as code points is converted to UTF-8 and encodes",
        fun cluster_id_list_is_converted_to_utf8/0),
      t("a cluster_id that cannot be represented stops the upstream at init, naming the cause",
        fun cluster_id_unrepresentable_stops_init/0)
     ]}.

%% Cap 3: a failed probe's event always fits back.
probe_cap_test_() ->
    {foreach,
     fun() -> setup(probe_env([{notify_pending_max, 3}])) end,
     fun cleanup/1,
     [
      t("a probe in flight reserves one slot, so a failed probe's event fits back at the cap",
        fun probe_reserves_a_slot_for_its_requeue/0)
     ]}.

setup(Env) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    %% A prior module may have leaked the real upstream. Stop it (stop_upstream/0
    %% does so silently, it does not report the leak) so this fixture owns the
    %% registered name.
    stop_upstream(),
    clear_registry(),
    Prev = [{Key, application:get_env(yuzu_gw, Key)} || Key <- ?ENV_KEYS],
    application:unset_env(yuzu_gw, notify_pending_max),
    application:unset_env(yuzu_gw, registration_replay_spacing_ms),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 600000),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 600000),
    lists:foreach(fun({K, V}) -> application:set_env(yuzu_gw, K, V) end, Env),
    %% Public tables and counters shared with the mock, which runs in the
    %% worker processes the upstream spawns. Atomics: 1 = workers inside the
    %% mock now, 2 = the most that were inside it at once, 3 = gates open.
    Log = ets:new(notify_pending_test_log, [public, ordered_set]),
    Workers = ets:new(notify_pending_test_workers, [public, set]),
    Atoms = atomics:new(3, [{signed, false}]),
    Ctx = #{log => Log, workers => Workers, atoms => Atoms, prev_env => Prev},
    persistent_term:put(?CTXK, Ctx),
    persistent_term:erase(?SUBK),
    meck:new(grpcbox_client, [non_strict, no_link]),
    mock(ok),
    %% Attach before the upstream starts: init/1 emits the first gauge.
    catch telemetry:detach(?TELEMETRY_HANDLER),
    ok = telemetry:attach_many(?TELEMETRY_HANDLER, [?EV_QUEUE, ?EV_DROPPED, ?EV_COALESCED],
                               fun ?MODULE:handle_event/4, #{log => Log}),
    _ = start_upstream(),
    Ctx.

%% All cleanup lives here: open every gate and release the parked workers, let
%% the upstream settle, stop it synchronously, wait for every worker to die,
%% then remove handlers, mecks, tables and persistent terms, and restore the
%% env.
cleanup(#{log := Log, workers := Workers, atoms := Atoms, prev_env := Prev}) ->
    atomics:put(Atoms, 3, 1),
    release_parked(Workers),
    %% With the gates open every held entry drains (unless the breaker is not
    %% closed, then nothing can spawn); stop once nothing is in flight.
    wait_until(fun() -> settled(Log) end, ?AWAIT_MS),
    stop_upstream(),
    release_parked(Workers),
    %% A wait that fails is reported, but only after the rest of the teardown
    %% ran, so one stuck process cannot leave the mock, the tables and the env
    %% behind for the next test.
    Dead = guarded(fun() -> await_dead([W || {W} <- ets:tab2list(Workers)]) end),
    catch telemetry:detach(?TELEMETRY_HANDLER),
    meck:unload(grpcbox_client),
    Cleared = guarded(fun clear_registry/0),
    ets:delete(Log),
    ets:delete(Workers),
    lists:foreach(fun({Key, {ok, V}}) -> application:set_env(yuzu_gw, Key, V);
                     ({Key, undefined}) -> application:unset_env(yuzu_gw, Key)
                  end, Prev),
    persistent_term:erase(?CTXK),
    persistent_term:erase(?SUBK),
    persistent_term:erase(?FIELDSK),
    case [F || F <- [Dead, Cleared], F =/= ok] of
        []       -> ok;
        Failures -> erlang:error({teardown_failed, Failures})
    end.

guarded(Fun) ->
    try Fun(), ok
    catch Class:Reason -> {Class, Reason}
    end.

%% setup/1 plus a logger handler at info level; the primary level is raised for
%% the group and put back by cleanup_logs/1.
setup_logs(Env) ->
    Ctx = setup(Env),
    PrevLevel = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, info),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{log => maps:get(log, Ctx)}, level => info}),
    Ctx#{prev_level => PrevLevel}.

cleanup_logs(#{prev_level := PrevLevel} = Ctx) ->
    catch logger:remove_handler(?LOG_HANDLER),
    logger:set_primary_config(level, PrevLevel),
    cleanup(maps:remove(prev_level, Ctx)).

start_upstream() ->
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    %% The fixture owns the lifetime (stop_upstream/0); a kill in a test must
    %% not take the test process with it.
    unlink(Pid),
    Pid.

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid       -> catch unlink(Pid),
                     catch gen_server:stop(Pid, shutdown, 5000),
                     ok
    end.

%% The shared registry stays empty between tests and modules. deregister_agent
%% is a cast, so poll (bounded) until the table is empty.
clear_registry() ->
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    case wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 2000) of
        ok               -> ok;
        {error, timeout} -> erlang:error({registry_not_empty, yuzu_gw_registry:all_agents()})
    end.

release_parked(Workers) ->
    [W ! release || {W} <- ets:tab2list(Workers)],
    ok.

await_dead(Pid) when is_pid(Pid) ->
    await_dead([Pid]);
await_dead(Pids) ->
    Refs = [{erlang:monitor(process, P), P} || P <- Pids],
    lists:foreach(fun({Ref, P}) ->
                      receive {'DOWN', Ref, process, _, _} -> ok
                      after ?AWAIT_MS -> erlang:error({process_did_not_exit, P})
                      end
                  end, Refs).

%% Nothing in flight (a held entry that could still be spawned would keep the
%% in-flight count above zero while the gates are open), or no upstream to ask.
settled(Log) ->
    case whereis(yuzu_gw_upstream) of
        undefined ->
            true;
        _ ->
            case last_gauge(Log) of
                undefined -> true;
                {_, 0}    -> true;
                _         -> false
            end
    end.

%%%===================================================================
%%% The mock
%%%===================================================================

%% ProxyMode is what every RPC other than NotifyStreamStatus answers: `ok',
%% `fail' (a transport error, which feeds the breaker) or `encode' (the real
%% encoder runs on the request first, as for NotifyStreamStatus, then `ok').
mock(ProxyMode) ->
    meck:expect(grpcbox_client, unary, fun(_Ctx, Path, Req, Def, _Opts) ->
        case lists:last(binary:split(Path, <<"/">>, [global])) of
            <<"NotifyStreamStatus">> ->
                %% The real encoder runs here, in the calling worker, as it does
                %% inside grpcbox_client:unary/5 (send_msg calls the marshal fun
                %% in the caller), so an unencodable field raises out of this
                %% mock exactly as it does out of the real client.
                marshal_like_grpcbox(Def, Req),
                notify_rpc(Req);
            _Other when ProxyMode =:= ok ->
                notify({proxied, Path}),
                {ok, #{}, #{}};
            _Other when ProxyMode =:= encode ->
                marshal_only(Def, Req),
                notify({proxied, Path}),
                {ok, #{}, #{}};
            _Other ->
                {error, connection_refused}
        end
    end).

%% Runs the request through the marshal fun yuzu_gw_upstream handed the client.
%% On a raise the test hears {marshal_failed, AgentId} first, then the original
%% exception continues to the caller (do_rpc turns it into an error result).
marshal_like_grpcbox(#grpcbox_def{marshal_fun = Marshal}, Req) ->
    try Marshal(Req)
    catch Class:Why:Stack ->
        notify({marshal_failed, maps:get(agent_id, Req)}),
        erlang:raise(Class, Why, Stack)
    end.

%% The same for a request that has no agent id of its own (ProxyRegister,
%% ProxyInventory): the marshal fun runs and any raise continues to the caller.
marshal_only(#grpcbox_def{marshal_fun = Marshal}, Req) ->
    _ = Marshal(Req),
    ok.

%% Runs in the worker the upstream spawned. Counts itself in, tells the test it
%% entered, then parks until released (or until the gates are open). `release'
%% answers ok; `{release, Answer}' answers with Answer, a grpcbox_client:unary/5
%% return, so a test can fail one worker.
notify_rpc(Req) ->
    #{log := Log, workers := Workers, atoms := Atoms} = ctx(),
    Now = atomics:add_get(Atoms, 1, 1),
    bump_peak(Atoms, Now),
    true = ets:insert(Log, {erlang:unique_integer([monotonic]), enter, self(), Req}),
    notify({entered, self(), Req}),
    case maps:get(agent_id, Req) of
        <<"kill-me">> -> exit(self(), kill);
        _             -> ok
    end,
    %% Recorded BEFORE the gate flag is read: teardown sets the flag and then
    %% releases every recorded worker, so a worker that read "closed" is always
    %% on that list.
    true = ets:insert(Workers, {self()}),
    Reply = case atomics:get(Atoms, 3) of
        1 -> {ok, #{}, #{}};
        0 -> receive
                 release           -> {ok, #{}, #{}};
                 {release, {raise, Why}} -> atomics:sub(Atoms, 1, 1),
                                            erlang:error(Why);
                 {release, Answer} -> Answer
             after ?PARK_MS -> {ok, #{}, #{}}
             end
    end,
    atomics:sub(Atoms, 1, 1),
    Reply.

bump_peak(Atoms, Now) ->
    case atomics:get(Atoms, 2) of
        Peak when Now > Peak ->
            case atomics:compare_exchange(Atoms, 2, Peak, Now) of
                ok -> ok;
                _  -> bump_peak(Atoms, Now)
            end;
        _ ->
            ok
    end.

ctx() ->
    persistent_term:get(?CTXK).

watch() ->
    persistent_term:put(?SUBK, self()).

notify(Msg) ->
    case persistent_term:get(?SUBK, undefined) of
        undefined -> ok;
        Pid       -> Pid ! Msg, ok
    end.

%% telemetry handler: record the event and wake the waiting test.
handle_event(Event, Measurements, Metadata, #{log := Log}) ->
    Key = erlang:unique_integer([monotonic]),
    true = ets:insert(Log, {Key, event, Event, Measurements, Metadata}),
    notify({logged, Key}),
    ok.

%% logger handler: record every event as text.
log(#{level := Level, msg := Msg}, #{config := #{log := Log}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    catch ets:insert(Log, {erlang:unique_integer([monotonic]), log, Level, Text}),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

fifty_casts_are_bounded_and_none_dropped() ->
    watch(),
    N = 50,
    [cast_connected(agent(I)) || I <- lists:seq(1, N)],
    First = await_entered(?INFLIGHT_MAX),
    sync(),
    ?assertEqual({N - ?INFLIGHT_MAX, ?INFLIGHT_MAX}, last_gauge()),
    open_and_release_all(),
    Rest = await_entered(N - ?INFLIGHT_MAX),
    Ids = [maps:get(agent_id, Req) || {_, Req} <- First ++ Rest],
    ?assertEqual(lists:sort([agent(I) || I <- lists:seq(1, N)]), lists:sort(Ids)),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual(?INFLIGHT_MAX, peak()),
    ?assertEqual(0, count(?EV_DROPPED)),
    ?assertEqual(0, count(?EV_COALESCED)).

selection_order_is_first_in_first_out() ->
    watch(),
    Live0 = fill_slots(),
    Keys = [agent(I) || I <- lists:seq(1, 20)],
    [cast_connected(Id) || Id <- Keys],
    sync(),
    ?assertEqual({20, ?INFLIGHT_MAX}, last_gauge()),
    %% Exactly one slot opens per release, so the next RPC to enter is the head
    %% of the held keys: the k-th entry after the k-th release is the k-th key.
    LiveN = lists:foldl(
              fun(Id, [W | Rest]) ->
                  W ! release,
                  {W2, Req} = await_entered(),
                  ?assertEqual(Id, maps:get(agent_id, Req)),
                  Rest ++ [W2]
              end, Live0, Keys),
    ?assertEqual(?INFLIGHT_MAX, length(LiveN)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual(0, count(?EV_DROPPED)).

coalescing_keeps_the_latest_event() ->
    watch(),
    Live0 = fill_slots(),
    Agent = <<"co-agent">>,
    notify_status(Agent, <<"co-session">>, connected, <<"peer-connect">>, <<"co-home">>),
    notify_status(Agent, <<"co-session">>, connected, <<"peer-connect">>, <<"co-home">>),
    notify_status(Agent, <<"co-session">>, disconnected, <<"peer-disconnect">>, <<"co-home">>),
    sync(),
    ?assertEqual({1, ?INFLIGHT_MAX}, last_gauge()),
    ?assertEqual(2, count(?EV_COALESCED)),
    ?assertEqual(0, count(?EV_DROPPED)),
    hd(Live0) ! release,
    {_, Req} = await_entered(),
    ?assertEqual(Agent, maps:get(agent_id, Req)),
    ?assertEqual('DISCONNECTED', maps:get(event, Req)),
    ?assertEqual(<<"co-session">>, maps:get(session_id, Req)),
    ?assertEqual(<<"peer-disconnect">>, maps:get(peer_addr, Req)),
    ?assertEqual(<<"co-home">>, maps:get(stream_home_id, Req)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    %% One RPC for the key in total.
    ?assertEqual(1, length([x || R <- entered_reqs(), maps:get(agent_id, R) =:= Agent])).

two_sessions_of_one_agent_are_both_kept() ->
    watch(),
    Live0 = fill_slots(),
    Agent = <<"two-agent">>,
    notify_status(Agent, <<"session-one">>, connected, <<"peer">>, <<"home">>),
    notify_status(Agent, <<"session-two">>, connected, <<"peer">>, <<"home">>),
    sync(),
    ?assertEqual({2, ?INFLIGHT_MAX}, last_gauge()),
    ?assertEqual(0, count(?EV_COALESCED)),
    [W1 | Rest] = Live0,
    W1 ! release,
    {_, First} = await_entered(),
    hd(Rest) ! release,
    {_, Second} = await_entered(),
    ?assertEqual([<<"session-one">>, <<"session-two">>],
                 [maps:get(session_id, First), maps:get(session_id, Second)]),
    ?assertEqual([Agent, Agent], [maps:get(agent_id, First), maps:get(agent_id, Second)]).

peer_addr_is_sanitised_at_admission() ->
    watch(),
    Cases = [{<<"p-long">>, binary:copy(<<"a">>, 5000), binary:copy(<<"a">>, 255)},
             {<<"p-bad">>, ?POISON_PEER, <<"invalid">>},
             {<<"p-ok">>, <<"peer-a:1">>, <<"peer-a:1">>}],
    [cast_status(Id, <<"sess">>, Peer) || {Id, Peer, _} <- Cases],
    Entered = await_entered(length(Cases)),
    Got = maps:from_list([{maps:get(agent_id, R), maps:get(peer_addr, R)} || {_, R} <- Entered]),
    ?assertEqual(maps:from_list([{Id, Want} || {Id, _, Want} <- Cases]), Got).

%% The notification map built in the cast handler has exactly these keys. A
%% future field that carries agent supplied or configured text is a new way for
%% every send to fail the same way, so adding a key must be a decision: update
%% this list together with the admission rules in yuzu_gw_upstream's header (the
%% standing invariant) and decide whether the new field needs sanitising.
-define(NOTIFICATION_KEYS, [agent_id, cluster_id, event, gateway_node, peer_addr,
                            session_id, stream_home_id, wire_capabilities]).

notification_key_set_and_utf8() ->
    watch(),
    Odd = [{<<"k-ok">>, <<"sess">>, <<"peer-a:1">>},
           {<<"k-bad">>, <<"sess">>, ?POISON_PEER},
           {<<"k-long">>, <<"sess">>, binary:copy(<<226, 130, 172>>, 200)},
           {<<"k-nonbin">>, <<"sess">>, not_a_binary},
           {<<"k-nosession">>, undefined, <<"peer-a:1">>}],
    [notify_status(Id, Sess, connected, Peer, <<"home">>) || {Id, Sess, Peer} <- Odd],
    Entered = await_entered(length(Odd)),
    lists:foreach(
      fun({_, Req}) ->
          ?assertEqual(?NOTIFICATION_KEYS, lists:sort(maps:keys(Req))),
          Texts = [V || V <- maps:values(Req), is_binary(V)] ++ maps:get(wire_capabilities, Req),
          [?assertEqual(V, unicode:characters_to_binary(V, utf8, utf8)) || V <- Texts],
          %% And the real encoder takes it: the mock already ran it, and so does this.
          ?assert(is_binary(iolist_to_binary(
                    gateway_pb:encode_msg(Req, 'yuzu.gateway.v1.StreamStatusNotification'))))
      end, Entered).

%% A peer address of 100 or 255 valid bytes read out of a large header block
%% passes the sanitiser unchanged; it must still not pin the block while held.
peer_addr_does_not_retain_its_parent_binary() ->
    watch(),
    Big = binary:copy(<<"a">>, 5 * 1024 * 1024),
    [cast_status(<<"sub-", (integer_to_binary(Len))/binary>>, <<"sess">>,
                 binary:part(Big, 0, Len)) || Len <- [100, 255, 1000]],
    Entered = await_entered(3),
    [?assert(binary:referenced_byte_size(maps:get(peer_addr, R)) =< 255) || {_, R} <- Entered].

cap_drops_overflow_and_never_a_replacement() ->
    watch(),
    Live0 = fill_slots(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 5)],
    sync(),
    %% Keys 1..3 held, 4 and 5 over the cap of 3.
    ?assertEqual({3, ?INFLIGHT_MAX}, last_gauge()),
    ?assertEqual(3, pending_len()),
    ?assertEqual([<<"at_capacity">>, <<"at_capacity">>], dropped_reasons()),
    %% A replacement of a held key is never dropped and never grows the store.
    notify_status(agent(1), <<"sess">>, disconnected, <<"peer">>, <<"home">>),
    sync(),
    ?assertEqual(3, pending_len()),
    ?assertEqual(1, count(?EV_COALESCED)),
    ?assertEqual(2, length(dropped_reasons())),
    %% A slot frees: the head (the replaced key 1) is sent, the store has room
    %% for one more key and refuses the next.
    hd(Live0) ! release,
    {_, Head} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, Head)),
    ?assertEqual('DISCONNECTED', maps:get(event, Head)),
    await_until(fun() -> last_gauge() =:= {2, ?INFLIGHT_MAX} end),
    cast_connected(agent(6)),
    cast_connected(agent(7)),
    sync(),
    ?assertEqual(3, pending_len()),
    ?assertEqual(3, length(dropped_reasons())),
    ?assert(lists:all(fun(R) -> R =:= <<"at_capacity">> end, dropped_reasons())).

open_circuit_holds_then_close_drains_in_order() ->
    watch(),
    trip_breaker(),
    Keys = [agent(I) || I <- lists:seq(1, 12)],
    [cast_connected(Id) || Id <- Keys],
    sync(),
    %% Held, not dropped, and nothing was spawned.
    ?assertEqual({12, 0}, last_gauge()),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    ?assertEqual(0, count(?EV_DROPPED)),
    %% The reset timer is far away: half_open by hand. Exactly one held entry
    %% goes out, as the probe; the rest stay held until it closes the breaker.
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    sync(),
    ?assertEqual({11, 1}, last_gauge()),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    mock(ok),
    Probe ! release,
    %% The first ten held keys after the probe went out (their entry order is
    %% not fixed), then the rest one slot at a time, in order.
    First = await_entered(?INFLIGHT_MAX),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(lists:sort(lists:sublist(Keys, 2, ?INFLIGHT_MAX)),
                 lists:sort([maps:get(agent_id, Req) || {_, Req} <- First])),
    await_until(fun() -> last_gauge() =:= {1, ?INFLIGHT_MAX} end),
    Live0 = [W || {W, _} <- First],
    LiveN = lists:foldl(
              fun(Id, [W | Rest]) ->
                  W ! release,
                  {W2, Req} = await_entered(),
                  ?assertEqual(Id, maps:get(agent_id, Req)),
                  Rest ++ [W2]
              end, Live0, lists:nthtail(?INFLIGHT_MAX + 1, Keys)),
    ?assertEqual(?INFLIGHT_MAX, length(LiveN)),
    ?assertEqual(0, count(?EV_DROPPED)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

half_open_circuit_sends_one_probe_and_holds_the_rest() ->
    watch(),
    trip_breaker(),
    enter_half_open(),
    %% Empty store: nothing to probe with. The first arrival while already
    %% half_open becomes the probe, the others are held behind it.
    ?assertEqual([{0, 0}], gauges()),
    Keys = [agent(I) || I <- lists:seq(1, 12)],
    [cast_connected(Id) || Id <- Keys],
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    sync(),
    ?assertEqual({11, 1}, last_gauge()),
    ?assertEqual(1, map_size(up_get(notify_pids))),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, count(?EV_DROPPED)),
    %% The probe fails: the breaker reopens and the entry is back at the head.
    fail_worker(Probe),
    await_until(fun() -> last_gauge() =:= {12, 0} end),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    %% half_open again: the same entry is the probe, and a success closes the
    %% breaker and drains the held keys.
    enter_half_open(),
    {Probe2, ProbeReq2} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq2)),
    mock(ok),
    Probe2 ! release,
    First = await_entered(?INFLIGHT_MAX),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(lists:sort(lists:sublist(Keys, 2, ?INFLIGHT_MAX)),
                 lists:sort([maps:get(agent_id, Req) || {_, Req} <- First])),
    await_until(fun() -> last_gauge() =:= {1, ?INFLIGHT_MAX} end),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

%% Ten workers are parked and 30 distinct keys are held, then a replay of three
%% agents is armed. Releasing one worker at a time frees one slot, and without a
%% reserved slot the freed slot is refilled from the backlog at once, so the
%% replay drip never sees fewer than ten workers until the backlog is empty.
%% The replay head must reach the mock while keys are still held.
replay_advances_while_the_backlog_is_refilled() ->
    watch(),
    Live0 = fill_slots(),
    Backlog = 30,
    [cast_connected(agent(I)) || I <- lists:seq(1, Backlog)],
    Sids = [bind_replay_agent(I) || I <- lists:seq(1, 3)],
    ok = yuzu_gw_upstream:replay_sessions(Sids),
    sync(),
    ?assertEqual({Backlog, ?INFLIGHT_MAX}, last_gauge()),
    ?assertMatch([_, _, _], up_get(replay_queue)),
    Refills = release_until_proxied(Live0, 0),
    ?assertMatch(N when N < Backlog, Refills),
    ?assert(pending_len() > 0),
    %% The other two agents follow, and once the replay is over the reserved
    %% slot is spent on the backlog again.
    [receive {proxied, _} -> ok
     after ?AWAIT_MS -> erlang:error(replay_did_not_continue)
     end || _ <- [2, 3]],
    await_until(fun() -> last_gauge() =:= {Backlog - Refills - 1, ?INFLIGHT_MAX} end),
    ?assertEqual([], up_get(replay_queue)).

%% Ten workers are parked, 30 keys are held and a replay of three agents is armed;
%% the 60 s spacing leaves the drip waiting, so the replay queue stays non-empty.
%% Three workers finish. The first leaves nine in flight, which is the budget while
%% the replay is active, so nothing is refilled; each of the next two leaves eight
%% and is refilled to nine from the backlog. A reserve of more than one slot would
%% stop at fewer than nine, and no reserve would refill to ten.
replay_reserve_is_exactly_one_slot() ->
    watch(),
    Live0 = fill_slots(),
    Backlog = 30,
    [cast_connected(agent(I)) || I <- lists:seq(1, Backlog)],
    Sids = [bind_replay_agent(I) || I <- lists:seq(1, 3)],
    ok = yuzu_gw_upstream:replay_sessions(Sids),
    sync(),
    ?assertEqual({Backlog, ?INFLIGHT_MAX}, last_gauge()),
    ?assertMatch([_, _, _], up_get(replay_queue)),
    [W1, W2, W3 | _] = Live0,
    W1 ! release,
    W2 ! release,
    W3 ! release,
    await_until(fun() -> last_gauge() =:= {Backlog - 2, ?INFLIGHT_MAX - 1} end),
    sync(),
    ?assertEqual(?INFLIGHT_MAX - 1, map_size(up_get(notify_pids))),
    ?assertEqual(Backlog - 2, pending_len()),
    ?assertMatch([_, _, _], up_get(replay_queue)).

gauges_follow_a_burst() ->
    watch(),
    %% init/1 emitted zeros before anything else.
    ?assertEqual([{0, 0}], gauges()),
    [cast_connected(agent(I)) || I <- lists:seq(1, 12)],
    sync(),
    [{W1, _} | _] = await_entered(?INFLIGHT_MAX),
    Cast = [{0, 0}] ++ [{0, I} || I <- lists:seq(1, ?INFLIGHT_MAX)] ++ [{1, ?INFLIGHT_MAX}, {2, ?INFLIGHT_MAX}],
    ?assertEqual(Cast, gauges()),
    %% One slot frees: one worker leaves and one is spawned, reported once.
    W1 ! release,
    await_until(fun() -> length(gauges()) =:= length(Cast) + 1 end),
    ?assertEqual(Cast ++ [{1, ?INFLIGHT_MAX}], gauges()),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    All = gauges(),
    Tail = lists:nthtail(length(Cast), All),
    ?assert(lists:all(fun({_, I}) -> I =< ?INFLIGHT_MAX end, All)),
    %% Back down: the pending count never rises again.
    Pendings = [P || {P, _} <- Tail],
    ?assertEqual(lists:reverse(lists:sort(Pendings)), Pendings),
    ?assertEqual({0, 0}, lists:last(All)).

format_status_redacts_the_notify_cast() ->
    Cast = {notify_stream_status, <<"shown-agent">>, <<"marker-session">>, disconnected,
            <<"marker-peer">>, <<"marker-home">>},
    Redacted = {notify_stream_status, <<"shown-agent">>, '$redacted', disconnected,
                '$redacted', '$redacted'},
    [begin
         #{message := Shown} = yuzu_gw_upstream:format_status(#{message => Msg}),
         ?assertEqual(Want, Shown),
         Text = lists:flatten(io_lib:format("~p", [Shown])),
         [?assertEqual(nomatch, string:find(Text, Marker))
          || Marker <- ["marker-session", "marker-peer", "marker-home"]]
     end || {Msg, Want} <- [{Cast, Redacted},
                            {{'$gen_cast', Cast}, {'$gen_cast', Redacted}},
                            {{'$gen_call', {self(), tag}, {proxy_register, secret}},
                             {'$gen_call', {self(), tag}, {proxy_register, '$redacted'}}}]].

format_status_shows_a_count_not_the_events() ->
    watch(),
    _ = fill_slots(),
    Held = [cast_status(<<"marker-agent-", (integer_to_binary(I))/binary>>,
                        <<"marker-session">>, <<"marker-peer">>)
            || I <- lists:seq(1, 3)],
    ?assertEqual([ok, ok, ok], Held),
    sync(),
    Status = yuzu_gw_upstream:format_status(#{state => sys:get_state(yuzu_gw_upstream)}),
    Shown = maps:get(state, Status),
    ?assertEqual(3, maps:get(notify_pending_len, Shown)),
    ?assertNot(maps:is_key(notify_pending, Shown)),
    Text = lists:flatten(io_lib:format("~p", [Status])),
    ?assertEqual(nomatch, string:find(Text, "marker-agent")),
    ?assertEqual(nomatch, string:find(Text, "marker-peer")),
    ?assertEqual(nomatch, string:find(Text, "marker-session")).

untrappable_worker_death_is_survived() ->
    watch(),
    Up = whereis(yuzu_gw_upstream),
    Live0 = fill_slots(),
    cast_connected(<<"kill-me">>),
    cast_connected(<<"after-kill">>),
    sync(),
    ?assertEqual({2, ?INFLIGHT_MAX}, last_gauge()),
    %% One slot opens: the next held entry is the one that dies, and its death
    %% (no result, no trap) must open the slot for the one behind it.
    hd(Live0) ! release,
    {_, Killed} = await_entered(),
    ?assertEqual(<<"kill-me">>, maps:get(agent_id, Killed)),
    {_, After} = await_entered(),
    ?assertEqual(<<"after-kill">>, maps:get(agent_id, After)),
    await_until(fun() -> last_gauge() =:= {0, ?INFLIGHT_MAX} end),
    ?assertEqual(Up, whereis(yuzu_gw_upstream)),
    ?assertEqual(?INFLIGHT_MAX, map_size(up_get(notify_pids))),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual(0, map_size(up_get(notify_pids))).

restart_starts_from_zero() ->
    watch(),
    OldWorkers = fill_slots(),
    OldHeld = [<<"old-held-", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 3)],
    [cast_connected(Id) || Id <- OldHeld],
    sync(),
    ?assertEqual({3, ?INFLIGHT_MAX}, last_gauge()),
    %% Kill the upstream: the parked workers are unlinked and outlive it.
    Old = whereis(yuzu_gw_upstream),
    MRef = erlang:monitor(process, Old),
    exit(Old, kill),
    receive {'DOWN', MRef, process, Old, _} -> ok
    after ?AWAIT_MS -> erlang:error(upstream_did_not_die)
    end,
    Before = length(gauges()),
    _ = start_upstream(),
    ?assertEqual([{0, 0}], lists:nthtail(Before, gauges())),
    NewKeys = [<<"new-", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 3)],
    [cast_connected(Id) || Id <- NewKeys],
    _ = await_entered(3),
    sync(),
    ?assertEqual({0, 3}, last_gauge()),
    %% The old workers finish late: the new instance neither counts them nor
    %% changes.
    Refs = [erlang:monitor(process, W) || W <- OldWorkers],
    [W ! release || W <- OldWorkers],
    lists:foreach(fun(Ref) ->
                      receive {'DOWN', Ref, process, _, _} -> ok
                      after ?AWAIT_MS -> erlang:error(old_worker_did_not_finish)
                      end
                  end, Refs),
    sync(),
    ?assertEqual({0, 3}, last_gauge()),
    ?assertEqual(3, map_size(up_get(notify_pids))),
    ?assertEqual(0, pending_len()),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    %% The old instance's held keys were never sent by anybody.
    Entered = [maps:get(agent_id, R) || R <- entered_reqs()],
    ?assertEqual([], [Id || Id <- OldHeld, lists:member(Id, Entered)]).

terminate_with_pending_entries() ->
    watch(),
    _ = fill_slots(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 3)],
    sync(),
    ?assertEqual(3, pending_len()),
    Up = whereis(yuzu_gw_upstream),
    ?assertEqual(ok, gen_server:stop(Up, shutdown, ?AWAIT_MS)),
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)).

%% The cast mailbox, not the workers, is what 1000 agents stress. One slot
%% opens at a time, so the order of the entries into the mock IS the selection
%% order, and the in-flight counter in the mock is an event level bound.
burst_one_slot_at_a_time() ->
    watch(),
    N = 1000,
    Keys = [agent(I) || I <- lists:seq(1, N)],
    [cast_connected(Id) || Id <- Keys],
    First = await_entered(?INFLIGHT_MAX),
    ?assertEqual(lists:sort(lists:sublist(Keys, ?INFLIGHT_MAX)),
                 lists:sort([maps:get(agent_id, Req) || {_, Req} <- First])),
    Live0 = [W || {W, _} <- First],
    LiveN = lists:foldl(
              fun(Id, [W | Rest]) ->
                  W ! release,
                  {W2, Req} = await_entered(),
                  ?assertEqual(Id, maps:get(agent_id, Req)),
                  Rest ++ [W2]
              end, Live0, lists:nthtail(?INFLIGHT_MAX, Keys)),
    ?assertEqual(?INFLIGHT_MAX, length(LiveN)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    Entered = [maps:get(agent_id, R) || R <- entered_reqs()],
    ?assertEqual(N, length(Entered)),
    ?assertEqual(lists:sort(Keys), lists:sort(Entered)),
    ?assertEqual(?INFLIGHT_MAX, peak()),
    ?assertEqual(0, count(?EV_DROPPED)).

burst_free_running() ->
    watch(),
    N = 1000,
    Keys = [agent(I) || I <- lists:seq(1, N)],
    atomics:put(maps:get(atoms, ctx()), 3, 1),
    [cast_connected(Id) || Id <- Keys],
    Entered = await_entered(N),
    ?assertEqual(lists:sort(Keys), lists:sort([maps:get(agent_id, Req) || {_, Req} <- Entered])),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assert(peak() =< ?INFLIGHT_MAX),
    ?assertEqual(0, count(?EV_DROPPED)),
    ?assertEqual(N, length(entered_reqs())).

env_invalid_falls_back() ->
    [env_case(Bad, invalid) || Bad <- [0, -5, 1000001, 2.5, not_a_number, <<"abc">>]],
    ok.

env_valid_is_kept() ->
    [env_case(V, valid) || V <- [1, 7, 1000000]],
    ok.

%% Restart the upstream with notify_pending_max = Val. An invalid value warns
%% naming the key and takes the default; a valid one is kept, appears in the
%% init INFO line, and does not warn.
env_case(Val, Kind) ->
    stop_upstream(),
    application:set_env(yuzu_gw, notify_pending_max, Val),
    Mark = last_key(),
    _ = start_upstream(),
    Lines = [{Level, Text} || {Key, log, Level, Text} <- rows(), Key > Mark],
    Named = [T || {warning, T} <- Lines,
                  binary:match(T, <<"notify_pending_max">>) =/= nomatch],
    case Kind of
        invalid ->
            ?assertEqual(10000, up_get(notify_pending_max)),
            ?assertNotEqual([], Named);
        valid ->
            ?assertEqual(Val, up_get(notify_pending_max)),
            ?assertEqual([], Named),
            Expect = iolist_to_binary(["notify_pending_max=", integer_to_binary(Val)]),
            ?assertMatch([_ | _], [T || {info, T} <- Lines, binary:match(T, Expect) =/= nomatch])
    end.

%% A reset timeout of 0 would make the half_open probe a hot loop for ever
%% (trip_circuit doubles 0), so the key is validated like the other breaker and
%% replay keys: 1..3600000, anything else warns naming the key and takes the
%% default. cb_base_timeout is what init/1 settled on.
reset_timeout_invalid_falls_back() ->
    [begin
         Named = env_key_case(circuit_breaker_reset_timeout_ms, Bad),
         ?assertEqual(10000, up_get(cb_base_timeout)),
         ?assertEqual(10000, up_get(cb_cur_timeout)),
         ?assertMatch([_], Named)
     end || Bad <- [0, -1, -10000, 3600001, "10000", 1.5, undefined_atom, <<"5">>]].

reset_timeout_valid_is_kept() ->
    [begin
         Named = env_key_case(circuit_breaker_reset_timeout_ms, Good),
         ?assertEqual(Good, up_get(cb_base_timeout)),
         ?assertEqual([], Named)
     end || Good <- [1, 100, 10000, 3600000]].

max_reset_timeout_invalid_falls_back() ->
    [begin
         Named = env_key_case(circuit_breaker_max_reset_timeout_ms, Bad),
         ?assertEqual(300000, up_get(cb_max_timeout)),
         ?assertMatch([_], Named)
     end || Bad <- [0, -1, 3600001, "300000", 2.5, undefined_atom]].

max_reset_timeout_valid_is_kept() ->
    [begin
         Named = env_key_case(circuit_breaker_max_reset_timeout_ms, Good),
         ?assertEqual(Good, up_get(cb_max_timeout)),
         ?assertEqual([], Named)
     end || Good <- [1, 500, 3600000]].

%% Restart the upstream with Key = Val; returns the warnings that name the key.
env_key_case(Key, Val) ->
    stop_upstream(),
    application:set_env(yuzu_gw, Key, Val),
    Mark = last_key(),
    _ = start_upstream(),
    KeyText = atom_to_binary(Key, utf8),
    [T || {Key1, log, warning, T} <- rows(), Key1 > Mark,
          binary:match(T, KeyText) =/= nomatch].

%%%===================================================================
%%% Tests: the half_open probe
%%%===================================================================

%% Twelve keys are held behind an open breaker. half_open sends the head as the
%% probe; its success closes the breaker, casts the replay, and the held keys
%% drain first in first out. The replay is observed as its ProxyRegister.
probe_success_closes_drains_and_replays() ->
    watch(),
    _ = bind_replay_agent(1),
    trip_breaker(),
    Keys = [agent(I) || I <- lists:seq(1, 12)],
    [cast_connected(Id) || Id <- Keys],
    sync(),
    ?assertEqual({12, 0}, last_gauge()),
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    sync(),
    ?assertEqual({11, 1}, last_gauge()),
    mock(ok),
    Probe ! release,
    First = await_entered(?INFLIGHT_MAX),
    await_until(fun() -> last_gauge() =:= {1, ?INFLIGHT_MAX} end),
    %% The gauge is reported after the replay cast was enqueued, and a call is
    %% answered after it: the replay queue holds the one agent.
    sync(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertMatch([_], up_get(replay_queue)),
    ?assertEqual(lists:sort(lists:sublist(Keys, 2, ?INFLIGHT_MAX)),
                 lists:sort([maps:get(agent_id, Req) || {_, Req} <- First])),
    %% Ten workers are in flight, so the replay waits; one slot opens and the
    %% replay head goes out, then the last held key.
    {W, _} = hd(First),
    W ! release,
    receive {proxied, _} -> ok
    after ?AWAIT_MS -> erlang:error(replay_did_not_run)
    end,
    {_, Last} = await_entered(),
    ?assertEqual(agent(12), maps:get(agent_id, Last)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    Entered = [maps:get(agent_id, R) || R <- entered_reqs()],
    ?assertEqual(lists:sort(Keys), lists:sort(Entered)).

probe_error_reopens_and_requeues_at_the_head() ->
    watch(),
    trip_breaker(),
    Keys = [agent(I) || I <- lists:seq(1, 12)],
    [cast_connected(Id) || Id <- Keys],
    sync(),
    %% The first trip doubled the 100000 ms base once.
    ?assertEqual(200000, up_get(cb_cur_timeout)),
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    fail_worker(Probe),
    await_until(fun() -> last_gauge() =:= {12, 0} end),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(undefined, up_get(notify_probe)),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    %% One failure, one doubling, one requeue, however the worker's exit lands.
    await_dead(Probe),
    sync(),
    ?assertEqual(400000, up_get(cb_cur_timeout)),
    ?assertEqual(0, count(?EV_COALESCED)),
    ?assertEqual(12, pending_len()),
    [{HeadKey, _} | _] = yuzu_gw_notify_queue:to_list(up_get(notify_pending)),
    ?assertEqual({agent(1), <<"sess">>, <<"home">>}, HeadKey),
    %% The next half_open probes with the same entry again.
    enter_half_open(),
    {_, Again} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, Again)).

%% half_open with a probe in flight; a call path RPC succeeds and closes the
%% breaker, and the probe's own result arrives afterwards.
stale_probe_ok_after_call_path_close() ->
    watch(),
    {Probe, Cb} = probe_then_call_path_close(),
    Probe ! release,
    await_until(fun() -> last_gauge() =:= {0, 4} end),
    await_dead(Probe),
    sync(),
    ?assertEqual(Cb, breaker()),
    ?assertEqual(undefined, up_get(notify_probe)),
    %% Delivered: retired, not sent again.
    ?assertEqual(1, length([x || R <- entered_reqs(), maps:get(agent_id, R) =:= agent(1)])).

stale_probe_error_after_call_path_close() ->
    watch(),
    {Probe, Cb} = probe_then_call_path_close(),
    fail_worker(Probe),
    %% Not delivered: requeued, and the breaker being closed, sent again.
    {_, Again} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, Again)),
    await_dead(Probe),
    sync(),
    ?assertEqual(Cb, breaker()),
    ?assertEqual(undefined, up_get(notify_probe)).

%% Five keys held, the head sent as the probe, then a good call path RPC closes
%% the breaker (the other four keys drain). Returns the parked probe and the
%% breaker state to compare against.
probe_then_call_path_close() ->
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 5)],
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    mock(ok),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    _ = await_entered(4),
    sync(),
    ?assertEqual({0, 5}, last_gauge()),
    {Probe, breaker()}.

%% half_open with a probe in flight; a call path RPC fails and reopens the
%% breaker under the SAME generation, and the probe's own result arrives while
%% the breaker is open. The breaker has no transition for a result in that state,
%% so the upstream process must neither restart nor touch the breaker; only the
%% event is settled.
stale_probe_error_while_open() ->
    watch(),
    {Probe, Up, Before} = probe_then_call_path_reopen(),
    fail_worker(Probe),
    %% Not delivered: back at the head of the store, the breaker still open.
    await_until(fun() -> last_gauge() =:= {3, 0} end),
    await_dead(Probe),
    sync(),
    ?assertEqual(Up, whereis(yuzu_gw_upstream)),
    ?assertEqual(Before, breaker()),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(undefined, up_get(notify_probe)),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    ?assertEqual(3, pending_len()),
    [{HeadKey, _} | _] = yuzu_gw_notify_queue:to_list(up_get(notify_pending)),
    ?assertEqual({agent(1), <<"sess">>, <<"home">>}, HeadKey).

stale_probe_ok_while_open() ->
    watch(),
    {Probe, Up, Before} = probe_then_call_path_reopen(),
    Probe ! release,
    %% Delivered: retired, not held again, the breaker still open.
    await_until(fun() -> last_gauge() =:= {2, 0} end),
    await_dead(Probe),
    sync(),
    ?assertEqual(Up, whereis(yuzu_gw_upstream)),
    ?assertEqual(Before, breaker()),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(undefined, up_get(notify_probe)),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    ?assertEqual(2, pending_len()),
    [{HeadKey, _} | _] = yuzu_gw_notify_queue:to_list(up_get(notify_pending)),
    ?assertEqual({agent(2), <<"sess">>, <<"home">>}, HeadKey).

%% Three keys held, the head sent as the probe (parked in the mock), then a
%% failing call path RPC reopens the breaker. Returns the parked probe, the
%% upstream pid and the breaker fields to compare against.
probe_then_call_path_reopen() ->
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 3)],
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    sync(),
    ?assertEqual({2, 1}, last_gauge()),
    {Probe, whereis(yuzu_gw_upstream), breaker()}.

older_generation_probe_ok_is_ignored_by_the_breaker() ->
    watch(),
    {Probe, Cur} = probe_then_newer_half_open(),
    Probe ! release,
    %% The breaker is untouched (still half_open); the probe event was
    %% delivered and retired, so the next probe is the next key.
    {_, Next} = await_entered(),
    ?assertEqual(agent(2), maps:get(agent_id, Next)),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({2, Cur}, {up_get(cb_gen), up_get(cb_cur_timeout)}).

older_generation_probe_error_is_ignored_by_the_breaker() ->
    watch(),
    {Probe, Cur} = probe_then_newer_half_open(),
    fail_worker(Probe),
    %% The breaker is untouched (still half_open); the probe event was
    %% requeued at the head, so the next probe is the same key again.
    {_, Next} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, Next)),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({2, Cur}, {up_get(cb_gen), up_get(cb_cur_timeout)}).

%% Generation 1 half_open with a probe in flight, a failing call path RPC
%% reopens the breaker, and a second half_open (generation 2) follows while the
%% first probe is still out. Returns that probe and the backoff at that point.
probe_then_newer_half_open() ->
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 4)],
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    ?assertEqual(1, up_get(cb_gen)),
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    enter_half_open(),
    ?assertEqual(2, up_get(cb_gen)),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    {Probe, up_get(cb_cur_timeout)}.

probe_reserves_a_slot_for_its_requeue() ->
    watch(),
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 3)],
    sync(),
    ?assertEqual({3, 0}, last_gauge()),
    enter_half_open(),
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    sync(),
    ?assertEqual({2, 1}, last_gauge()),
    %% Two held keys and the probe's reserved slot fill the cap of 3.
    cast_connected(agent(4)),
    cast_connected(agent(5)),
    sync(),
    ?assertEqual(2, pending_len()),
    ?assertEqual([<<"at_capacity">>, <<"at_capacity">>], dropped_reasons()),
    %% A replacement of a held key still goes through.
    notify_status(agent(2), <<"sess">>, disconnected, <<"peer">>, <<"home">>),
    sync(),
    ?assertEqual(2, pending_len()),
    ?assertEqual(1, count(?EV_COALESCED)),
    %% The probe fails: its event is back, at the head, within the cap.
    fail_worker(Probe),
    await_until(fun() -> last_gauge() =:= {3, 0} end),
    ?assertEqual(3, pending_len()),
    [{HeadKey, _} | _] = yuzu_gw_notify_queue:to_list(up_get(notify_pending)),
    ?assertEqual({agent(1), <<"sess">>, <<"home">>}, HeadKey),
    ?assertEqual(2, length(dropped_reasons())).

newer_same_key_event_supersedes_a_failed_probe() ->
    watch(),
    trip_breaker(),
    Agent = <<"co-agent">>,
    notify_status(Agent, <<"co-session">>, connected, <<"peer-connect">>, <<"co-home">>),
    sync(),
    enter_half_open(),
    {Probe, First} = await_entered(),
    ?assertEqual('CONNECTED', maps:get(event, First)),
    %% The probe took the key out of the store, so this is a new entry.
    notify_status(Agent, <<"co-session">>, disconnected, <<"peer-disconnect">>, <<"co-home">>),
    sync(),
    ?assertEqual({1, 1}, last_gauge()),
    ?assertEqual(0, count(?EV_COALESCED)),
    %% The probe fails: its older event is superseded and dropped, counted.
    fail_worker(Probe),
    await_until(fun() -> last_gauge() =:= {1, 0} end),
    ?assertEqual(1, count(?EV_COALESCED)),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    enter_half_open(),
    {_, Second} = await_entered(),
    ?assertEqual('DISCONNECTED', maps:get(event, Second)),
    ?assertEqual(<<"peer-disconnect">>, maps:get(peer_addr, Second)).

killed_probe_worker_is_one_failure() ->
    watch(),
    trip_breaker(),
    cast_connected(<<"kill-me">>),
    cast_connected(agent(1)),
    sync(),
    ?assertEqual(200000, up_get(cb_cur_timeout)),
    enter_half_open(),
    {Probe, Killed} = await_entered(),
    ?assertEqual(<<"kill-me">>, maps:get(agent_id, Killed)),
    %% No result, no trap: the 'DOWN' alone is the failure.
    await_until(fun() -> last_gauge() =:= {2, 0} end),
    await_dead(Probe),
    sync(),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(400000, up_get(cb_cur_timeout)),
    ?assertEqual(undefined, up_get(notify_probe)),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    ?assertEqual(0, count(?EV_COALESCED)),
    [{{HeadId, _, _}, _} | _] = yuzu_gw_notify_queue:to_list(up_get(notify_pending)),
    ?assertEqual(<<"kill-me">>, HeadId).

killed_probe_worker_is_logged() ->
    watch(),
    trip_breaker(),
    cast_connected(<<"kill-me">>),
    sync(),
    enter_half_open(),
    {Probe, _} = await_entered(),
    await_until(fun() -> last_gauge() =:= {1, 0} end),
    await_dead(Probe),
    sync(),
    Lines = [Text || {_, log, warning, Text} <- rows(),
                     string:find(Text, "Notify probe worker") =/= nomatch],
    ?assertMatch([_], Lines),
    [Line] = Lines,
    ?assertNotEqual(nomatch, string:find(Line, "kill-me")),
    ?assertNotEqual(nomatch, string:find(Line, "killed")),
    %% The payload (peer address, session id) is not in the line.
    ?assertEqual(nomatch, string:find(Line, "peer")),
    ?assertEqual(nomatch, string:find(Line, "sess")).

%% The worker is parked inside the mock, so an exit signal with a reason is the
%% only thing that ends it: the reason is what the 'DOWN' carries. It holds
%% payload-looking bytes in the places redact_reason/1 must drop: the offending
%% term of a badmatch and the argument list of a stacktrace frame.
killed_probe_warning_redacts_the_reason() ->
    watch(),
    trip_breaker(),
    cast_connected(agent(1)),
    sync(),
    enter_half_open(),
    {Probe, _} = await_entered(),
    exit(Probe, {{badmatch, <<"peer-secret">>},
                 [{some_module, some_fun, [<<"sess-secret">>, <<"home-secret">>], []}]}),
    await_until(fun() -> last_gauge() =:= {1, 0} end),
    await_dead(Probe),
    sync(),
    Lines = [Text || {_, log, warning, Text} <- rows(),
                     string:find(Text, "Notify probe worker") =/= nomatch],
    ?assertMatch([_], Lines),
    [Line] = Lines,
    ?assertNotEqual(nomatch, string:find(Line, "agent-1")),
    ?assertNotEqual(nomatch, string:find(Line, "badmatch")),
    [?assertEqual(nomatch, string:find(Line, Secret))
     || Secret <- ["peer-secret", "sess-secret", "home-secret"]].

%% A carriage return or line feed in an agent id must not start a second log
%% line: the eviction line and the failed-notify line carry it through log_text.
notify_log_lines_carry_no_raw_control_characters() ->
    watch(),
    Evil = <<"crlf-marker", 13, 10, "INJECTED">>,
    %% Evicted as the probe (the id is not UTF-8, so it cannot be encoded).
    Unencodable = <<255, 13, 10, "crlf-marker">>,
    trip_breaker(),
    notify_status(Unencodable, <<"sess">>, connected, <<"peer">>, <<"home">>),
    sync(),
    enter_half_open(),
    ?assertEqual({marshal_failed, Unencodable}, await_attempt()),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    %% Closed again by a good probe, then a failed ordinary notification.
    cast_connected(agent(1)),
    {entered, Good, _} = await_attempt(),
    Good ! release,
    await_until(fun() -> up_get(cb_state) =:= closed end),
    cast_connected(Evil),
    {entered, Failing, _} = await_attempt(),
    fail_worker(Failing),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    await_dead(Failing),
    sync(),
    Lines = [Text || {_, log, warning, Text} <- rows(),
                     string:find(Text, "crlf-marker") =/= nomatch],
    %% Each control character became one `?': the rest of a ~p rendering may
    %% wrap, so the id is checked as rendered rather than by looking for a
    %% line feed anywhere in the line.
    ?assertEqual(2, length(Lines)),
    ?assertMatch([_], [L || L <- Lines, string:find(L, "??crlf-marker") =/= nomatch]),
    ?assertMatch([_], [L || L <- Lines, string:find(L, "crlf-marker??INJECTED") =/= nomatch]).

duplicate_and_foreign_probe_results_are_ignored() ->
    watch(),
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 3)],
    enter_half_open(),
    {Probe, _} = await_entered(),
    fail_worker(Probe),
    await_until(fun() -> last_gauge() =:= {3, 0} end),
    await_dead(Probe),
    sync(),
    Up = whereis(yuzu_gw_upstream),
    Settled = {breaker(), pending_len(), count(?EV_COALESCED), up_get(notify_probe)},
    %% A second result of the finished probe: no probe is recorded, so nothing.
    Up ! {notify_probe_result, Probe, 1, {error, again}},
    sync(),
    ?assertEqual(Settled, {breaker(), pending_len(), count(?EV_COALESCED), up_get(notify_probe)}),
    %% A result from a pid that is not the recorded probe of a newer one.
    enter_half_open(),
    {Probe2, _} = await_entered(),
    Up ! {notify_probe_result, Probe, 1, {ok, #{}}},
    Up ! {notify_probe_result, Probe, 2, {error, again}},
    sync(),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assertMatch(#{pid := Probe2}, up_get(notify_probe)),
    ?assertEqual(Up, whereis(yuzu_gw_upstream)).

%% The probe's event is sent, the breaker is closed by a call path RPC, the
%% newer event for the same key goes out as an ordinary worker, and then the old
%% probe fails: its event is sent again, after the newer one. The server
%% tolerates the reorder; the breaker and the store stay consistent.
failed_old_probe_is_resent_after_the_newer_event() ->
    watch(),
    trip_breaker(),
    Agent = <<"co-agent">>,
    notify_status(Agent, <<"co-session">>, connected, <<"peer-connect">>, <<"co-home">>),
    sync(),
    enter_half_open(),
    {Probe, First} = await_entered(),
    ?assertEqual('CONNECTED', maps:get(event, First)),
    notify_status(Agent, <<"co-session">>, disconnected, <<"peer-disconnect">>, <<"co-home">>),
    sync(),
    mock(ok),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    {_, Newer} = await_entered(),
    ?assertEqual('DISCONNECTED', maps:get(event, Newer)),
    Up = whereis(yuzu_gw_upstream),
    fail_worker(Probe),
    {_, Older} = await_entered(),
    ?assertEqual('CONNECTED', maps:get(event, Older)),
    await_dead(Probe),
    sync(),
    ?assertEqual(Up, whereis(yuzu_gw_upstream)),
    ?assertEqual({closed, 0}, {up_get(cb_state), up_get(cb_failures)}),
    ?assertEqual(0, count(?EV_COALESCED)),
    ?assertEqual(0, pending_len()).

%% Three ordinary workers are in flight when the breaker goes half_open: the
%% probe starts beside them, and neither a new arrival nor an ordinary worker
%% finishing starts anything else.
nothing_else_drains_while_a_probe_is_in_flight() ->
    watch(),
    [cast_connected(<<"early-", (integer_to_binary(I))/binary>>) || I <- lists:seq(1, 3)],
    Early = await_entered(3),
    trip_breaker(),
    [cast_connected(agent(I)) || I <- lists:seq(1, 5)],
    sync(),
    ?assertEqual({5, 3}, last_gauge()),
    enter_half_open(),
    {_Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    sync(),
    ?assertEqual({4, 4}, last_gauge()),
    cast_connected(agent(6)),
    cast_connected(agent(7)),
    sync(),
    ?assertEqual({6, 4}, last_gauge()),
    %% An ordinary worker finishes: its slot is not refilled.
    {W, _} = hd(Early),
    W ! release,
    await_until(fun() -> last_gauge() =:= {6, 3} end),
    sync(),
    ?assertEqual(6, pending_len()),
    ?assertEqual(3, map_size(up_get(notify_pids))),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()).

probe_counts_inside_the_budget() ->
    watch(),
    Live0 = fill_slots(),
    trip_breaker(),
    cast_connected(agent(1)),
    enter_half_open(),
    sync(),
    %% Ten workers are in flight: no room for a probe yet.
    ?assertEqual({1, ?INFLIGHT_MAX}, last_gauge()),
    ?assertEqual(undefined, up_get(notify_probe)),
    hd(Live0) ! release,
    {Probe, ProbeReq} = await_entered(),
    ?assertEqual(agent(1), maps:get(agent_id, ProbeReq)),
    await_until(fun() -> last_gauge() =:= {0, ?INFLIGHT_MAX} end),
    ?assertEqual(?INFLIGHT_MAX, map_size(up_get(notify_pids))),
    ?assertMatch(#{pid := Probe}, up_get(notify_probe)),
    ?assert(maps:is_key(Probe, up_get(notify_pids))).

format_status_hides_the_probe_event() ->
    watch(),
    trip_breaker(),
    notify_status(<<"marker-agent">>, <<"marker-session">>, connected,
                  <<"marker-peer">>, <<"marker-home">>),
    sync(),
    enter_half_open(),
    {_Probe, _} = await_entered(),
    Status = yuzu_gw_upstream:format_status(#{state => sys:get_state(yuzu_gw_upstream)}),
    Shown = maps:get(state, Status),
    ?assertEqual(true, maps:get(notify_probe_held, Shown)),
    ?assertNot(maps:is_key(notify_probe, Shown)),
    Text = lists:flatten(io_lib:format("~p", [Status])),
    ?assertEqual(nomatch, string:find(Text, "marker-agent")),
    ?assertEqual(nomatch, string:find(Text, "marker-peer")),
    ?assertEqual(nomatch, string:find(Text, "marker-session")),
    ?assertEqual(nomatch, string:find(Text, "marker-home")).

%% A local encode exception (the request never left the gateway) is neither a
%% success nor a failure of the upstream. Found by review: a Register whose
%% request carried text that is not valid UTF-8 raised in the real encoder and
%% was counted, so a handful of them opened the breaker for the whole fleet.
register_encode_exception_never_feeds_the_breaker() ->
    mock(encode),
    Threshold = up_get(cb_threshold),
    Timeout = up_get(cb_cur_timeout),
    Fresh = {closed, 0, 0, Timeout},
    ?assertEqual(Fresh, breaker()),
    BadReg = #{info => #{agent_id => <<"bad-reg">>, hostname => <<255, 254>>}},
    BadInv = #{session_id => <<255>>},
    Rounds = lists:seq(1, Threshold + 2),
    [?assertEqual({error, {internal, <<"rpc exception error:badarg">>}},
                  yuzu_gw_upstream:proxy_register(BadReg)) || _ <- Rounds],
    ?assertEqual(Fresh, breaker()),
    [?assertEqual({error, {internal, <<"rpc exception error:badarg">>}},
                  yuzu_gw_upstream:proxy_inventory(BadInv)) || _ <- Rounds],
    ?assertEqual(Fresh, breaker()),
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_register(
                            #{info => #{agent_id => <<"good-reg">>, hostname => <<"host">>}})),
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_inventory(#{session_id => <<"good-session">>})),
    ?assertEqual(Fresh, breaker()).

%% The head held entry is the half_open probe. One that can never be encoded
%% (here an agent id that is not UTF-8, which the peer address sanitiser does
%% not cover) is evicted: requeueing it would fail every probe for ever. The
%% breaker is not touched, and the next head is probed at once.
unencodable_probe_is_evicted_not_requeued() ->
    watch(),
    trip_breaker(),
    notify_status(<<255>>, <<"sess">>, connected, <<"peer">>, <<"home">>),
    Good = [agent(I) || I <- lists:seq(1, 3)],
    [cast_connected(Id) || Id <- Good],
    sync(),
    ?assertEqual({4, 0}, last_gauge()),
    ?assertEqual({open, 0, 3, 200000}, breaker()),
    enter_half_open(),
    ?assertEqual({marshal_failed, <<255>>}, await_attempt()),
    {entered, W, Next} = await_attempt(),
    ?assertEqual(agent(1), maps:get(agent_id, Next)),
    %% Only the entry into half_open moved the breaker: no failure, no doubling.
    ?assertEqual({half_open, 1, 3, 200000}, breaker()),
    ?assertEqual(2, pending_len()),
    ?assertEqual(0, count(?EV_COALESCED)),
    Evicted = [T || {_, log, warning, T} <- rows(),
                    string:find(T, "Evicted held stream status notification") =/= nomatch],
    ?assertMatch([_], Evicted),
    [Line] = Evicted,
    ?assertNotEqual(nomatch, string:find(Line, "cannot be encoded")),
    ?assertEqual(nomatch, string:find(Line, "peer")),
    ?assertEqual(nomatch, string:find(Line, "sess")),
    W ! release,
    await_until(fun() -> up_get(cb_state) =:= closed end),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual(lists:sort(Good),
                 lists:sort([maps:get(agent_id, R) || R <- entered_reqs()])).

all_unencodable_probes_drain_to_empty() ->
    watch(),
    trip_breaker(),
    Ids = [<<255, I>> || I <- lists:seq(1, 3)],
    [cast_connected(Id) || Id <- Ids],
    sync(),
    ?assertEqual({3, 0}, last_gauge()),
    enter_half_open(),
    [?assertEqual({marshal_failed, Id}, await_attempt()) || Id <- Ids],
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual(undefined, up_get(notify_probe)),
    %% Nothing moved the breaker: it is still waiting for a probe that can answer.
    ?assertEqual({half_open, 1, 3, 200000}, breaker()),
    cast_connected(agent(1)),
    {entered, W, _} = await_attempt(),
    W ! release,
    await_until(fun() -> up_get(cb_state) =:= closed end),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

%% Control: any other exception out of the client is a failure of the upstream
%% path, as before: the probe goes back to the head and the breaker reopens.
other_probe_exception_is_a_failure() ->
    watch(),
    trip_breaker(),
    cast_connected(agent(1)),
    sync(),
    enter_half_open(),
    {Probe, _} = await_entered(),
    Probe ! {release, {raise, boom}},
    await_until(fun() -> last_gauge() =:= {1, 0} end),
    await_dead(Probe),
    sync(),
    ?assertEqual({open, 1, 3, 400000}, breaker()),
    ?assertEqual(1, pending_len()).

%% A worker outside the half_open probe never reports to the breaker, with or
%% without a local exception: the unencodable entry is lost, the rest is sent.
unencodable_ordinary_worker_does_not_touch_the_breaker() ->
    watch(),
    Timeout = up_get(cb_cur_timeout),
    notify_status(<<255>>, <<"sess">>, connected, <<"peer">>, <<"home">>),
    cast_connected(agent(1)),
    %% Two workers run at once, so the two outcomes arrive in either order.
    Attempts = [await_attempt(), await_attempt()],
    ?assertEqual(1, length([x || {marshal_failed, <<255>>} <- Attempts])),
    ?assertMatch([_], [Req || {entered, _W, #{agent_id := <<"agent-1">>} = Req} <- Attempts]),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end),
    ?assertEqual({closed, 0, 0, Timeout}, breaker()),
    ?assertEqual(0, pending_len()).

%% The upstream is restarted per case: cluster_id is read once, at init. A value
%% converted with list_to_binary (a latin-1 truncation) is not valid UTF-8 for a
%% code point above 127 and fails the real encoder on every notification.
cluster_id_list_is_converted_to_utf8() ->
    watch(),
    Cases = [{[90, 252, 114, 105, 99, 104], <<90, 195, 188, 114, 105, 99, 104>>},
             {[16#4E2D, 16#6587], <<228, 184, 173, 230, 150, 135>>},
             {"ascii-id", <<"ascii-id">>},
             {<<"binary-id">>, <<"binary-id">>}],
    lists:foreach(
      fun({{Configured, Expected}, N}) ->
          stop_upstream(),
          application:set_env(yuzu_gw, cluster_id, Configured),
          _ = start_upstream(),
          cast_connected(agent(N)),
          {entered, W, Req} = await_attempt(),
          ?assertEqual(Expected, maps:get(cluster_id, Req)),
          ?assertEqual(Expected, unicode:characters_to_binary(Expected, utf8, utf8)),
          W ! release
      end, lists:zip(Cases, lists:seq(1, length(Cases)))).

%% The boot check in yuzu_gw_app refuses such a value first; this is the second
%% line: init/1 itself stops with a reason that names the cause and never the
%% value. The caller is linked, so it traps exits for the call (whether this OTP
%% still delivers the exit signal of a failed init or not, none is left behind).
cluster_id_unrepresentable_stops_init() ->
    stop_upstream(),
    application:set_env(yuzu_gw, cluster_id, [16#110000]),
    Prev = process_flag(trap_exit, true),
    try
        ?assertEqual({error, {invalid_cluster_id, app_env}}, yuzu_gw_upstream:start_link()),
        ?assertEqual(undefined, whereis(yuzu_gw_upstream))
    after
        receive {'EXIT', _Pid, _Reason} -> ok after 0 -> ok end,
        process_flag(trap_exit, Prev)
    end.

%% A held notification whose payload cannot be encoded (an agent supplied peer
%% address that is not UTF-8) sits at the head of the store. The head is the
%% half_open probe, so if it fails the same way every time the breaker reopens
%% with a doubled backoff and the same head is probed again, for ever, while the
%% server is healthy and the five good notifications behind it are never sent.
%% The server answers fine here (mock(ok)); only the encoding of the head fails.
poison_head_does_not_block_the_breaker() ->
    watch(),
    trip_breaker(),
    notify_status(<<"poison">>, <<"sess">>, disconnected, ?POISON_PEER, <<"home">>),
    Good = [agent(I) || I <- lists:seq(1, 5)],
    [cast_connected(Id) || Id <- Good],
    sync(),
    ?assertEqual({6, 0}, last_gauge()),
    mock(ok),
    {W, Head} = probe_until_encodable(3),
    ?assertEqual(<<"poison">>, maps:get(agent_id, Head)),
    ?assertEqual(<<"invalid">>, maps:get(peer_addr, Head)),
    W ! release,
    await_until(fun() -> up_get(cb_state) =:= closed end),
    await_until(fun() -> length(entered_reqs()) =:= 6 end),
    ?assertEqual(lists:sort(Good),
                 lists:sort([maps:get(agent_id, R) || R <- entered_reqs(),
                                                      maps:get(agent_id, R) =/= <<"poison">>])),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

%% The same with no good notification at all: every held key is poison.
all_poison_heads_still_drain() ->
    watch(),
    trip_breaker(),
    Ids = [<<"poison-", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 3)],
    [notify_status(Id, <<"sess">>, disconnected, ?POISON_PEER, <<"home">>) || Id <- Ids],
    sync(),
    ?assertEqual({3, 0}, last_gauge()),
    mock(ok),
    {W, _Head} = probe_until_encodable(3),
    W ! release,
    await_until(fun() -> up_get(cb_state) =:= closed end),
    await_until(fun() -> length(entered_reqs()) =:= 3 end),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

%% Up to N half_open cycles: each sends the head as the probe and waits for what
%% the mock saw. An encodable head enters the mock and is returned (parked). A
%% head that fails to encode reopens the breaker; wait for that to be settled so
%% the next half_open is a new cycle. Fails loud, with the breaker fields (state,
%% generation, failures, current backoff), when no cycle ever probes an
%% encodable head.
probe_until_encodable(0) ->
    erlang:error({breaker_never_probed_an_encodable_head, breaker()});
probe_until_encodable(N) ->
    enter_half_open(),
    case await_attempt() of
        {entered, W, Req} ->
            {W, Req};
        {marshal_failed, _AgentId} ->
            await_until(fun() -> up_get(notify_probe) =:= undefined end),
            probe_until_encodable(N - 1)
    end.

%% What the next NotifyStreamStatus worker did: entered the mock, or failed to
%% encode its request.
await_attempt() ->
    receive
        {entered, W, Req}      -> {entered, W, Req};
        {marshal_failed, Id}   -> {marshal_failed, Id}
    after ?AWAIT_MS -> erlang:error(no_notify_attempt_reached_the_mock)
    end.

%%%===================================================================
%%% Helpers: driving the upstream
%%%===================================================================

agent(I) ->
    <<"agent-", (integer_to_binary(I))/binary>>.

cast_connected(AgentId) ->
    notify_status(AgentId, <<"sess">>, connected, <<"peer">>, <<"home">>).

cast_status(AgentId, SessionId, PeerAddr) ->
    notify_status(AgentId, SessionId, connected, PeerAddr, <<"home">>).

notify_status(AgentId, SessionId, Event, PeerAddr, HomeId) ->
    ok = yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, Event, PeerAddr, HomeId).

%% Saturate the 10 slots with parked workers; returns their pids.
fill_slots() ->
    [cast_connected(<<"fill-", (integer_to_binary(I))/binary>>) || I <- lists:seq(1, ?INFLIGHT_MAX)],
    Entered = await_entered(?INFLIGHT_MAX),
    sync(),
    ?assertEqual({0, ?INFLIGHT_MAX}, last_gauge()),
    [W || {W, _} <- Entered].

%% A live agent in the shared registry, with a stored request, so a replay
%% verdict naming its session queues it. The stand-in process ends with the test
%% process; clear_registry/0 removes the row in teardown. Returns the session id.
bind_replay_agent(I) ->
    Id = <<"replay-agent-", (integer_to_binary(I))/binary>>,
    Sid = <<"replay-session-", (integer_to_binary(I))/binary>>,
    Owner = self(),
    Pid = spawn(fun() ->
                    MRef = erlang:monitor(process, Owner),
                    receive {'DOWN', MRef, process, _, _} -> ok end
                end),
    ok = yuzu_gw_registry:register_agent(Id, Pid, Sid, [<<"svc">>], <<"host">>,
                                         #{info => #{agent_id => Id}}, conn_test),
    Sid.

%% Release the oldest parked worker and wait for what follows: a new notify
%% worker entering the mock (the freed slot was refilled from the backlog, one
%% refill counted) or a ProxyRegister (the replay head advanced). Returns the
%% number of refills seen before the first ProxyRegister.
release_until_proxied([W | Rest], Refills) ->
    W ! release,
    receive
        {proxied, _}       -> Refills;
        {entered, W2, _Req} -> release_until_proxied(Rest ++ [W2], Refills + 1)
    after ?AWAIT_MS -> erlang:error({replay_never_advanced, Refills})
    end.

%% half_open by hand (the reset timer is far away). The call is answered after
%% the message was handled and the probe, if any, was started.
enter_half_open() ->
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    sync().

%% Answer a parked worker with a transport error.
fail_worker(W) ->
    W ! {release, {error, boom}},
    ok.

%% The breaker fields a stale probe result must not move.
breaker() ->
    {up_get(cb_state), up_get(cb_gen), up_get(cb_failures), up_get(cb_cur_timeout)}.

%% A call is answered after every earlier cast from this process was handled.
sync() ->
    _ = yuzu_gw_upstream:circuit_state(),
    ok.

%% Three failures trip the breaker (threshold 3), leaving it open with the
%% reset timer far away.
trip_breaker() ->
    mock(fail),
    [{error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}) || _ <- [1, 2, 3]],
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

open_and_release_all() ->
    #{atoms := Atoms, workers := Workers} = ctx(),
    atomics:put(Atoms, 3, 1),
    release_parked(Workers).

%%%===================================================================
%%% Helpers: waiting (event driven, bounded)
%%%===================================================================

await_entered() ->
    receive {entered, W, Req} -> {W, Req}
    after ?AWAIT_MS -> erlang:error(no_rpc_entered_the_mock)
    end.

await_entered(N) ->
    [await_entered() || _ <- lists:seq(1, N)].

%% Re-check Pred after every recorded event, up to ?AWAIT_MS without one.
await_until(Pred) ->
    case Pred() of
        true  -> ok;
        false -> receive {logged, _} -> await_until(Pred)
                 after ?AWAIT_MS -> erlang:error({condition_not_reached, gauges()})
                 end
    end.

%% A bounded poll for state nothing reports (teardown only).
wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.

%%%===================================================================
%%% Helpers: reading what was recorded
%%%===================================================================

rows() ->
    ets:tab2list(maps:get(log, ctx())).

last_key() ->
    case rows() of
        [] -> 0;
        Rows -> element(1, lists:last(Rows))
    end.

entered_reqs() ->
    [Req || {_, enter, _, Req} <- rows()].

gauges() ->
    gauges(maps:get(log, ctx())).

gauges(Log) ->
    [{P, I} || {_, event, ?EV_QUEUE, #{pending := P, inflight := I}, _} <- ets:tab2list(Log)].

last_gauge() ->
    last_gauge(maps:get(log, ctx())).

last_gauge(Log) ->
    case gauges(Log) of
        [] -> undefined;
        Gs -> lists:last(Gs)
    end.

count(Event) ->
    length([x || {_, event, E, _, _} <- rows(), E =:= Event]).

dropped_reasons() ->
    [Reason || {_, event, ?EV_DROPPED, _, #{reason := Reason}} <- rows()].

peak() ->
    atomics:get(maps:get(atoms, ctx()), 2).

pending_len() ->
    yuzu_gw_notify_queue:size(up_get(notify_pending)).

%% The record is private to yuzu_gw_upstream, so read it by field name from the
%% module's own source (the same device yuzu_gw_registration_replay_tests uses).
%% A field that does not exist fails the test with its name.
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
    case persistent_term:get(?FIELDSK, undefined) of
        undefined ->
            Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
            {ok, Forms} = epp:parse_file(Src, []),
            [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
            Names = [field_name(F) || F <- Fs],
            persistent_term:put(?FIELDSK, Names),
            Names;
        Names ->
            Names
    end.

field_name({typed_record_field, F, _Type}) -> field_name(F);
field_name({record_field, _, {atom, _, Name}}) -> Name;
field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.
