%%%-------------------------------------------------------------------
%%% @doc A stream-status notice the server answers `acknowledged = false' was
%%% NOT delivered, and the gateway must send it again (#5695, NOTIFY-ACK).
%%%
%%% The server answers NotifyStreamStatus with a transport-level OK and a
%%% StreamStatusAck whose `acknowledged' says whether it recorded the notice.
%%% The gateway used to treat every OK as delivered and never read the field.
%%% An independent test (a stub answering every CONNECTED acknowledged=false
%%% for 60 s, then true) left 500 of 500 agents unknown at the server for the
%%% whole 5 minutes after it switched to true: one CONNECTED per agent, no
%%% retry, and the heartbeat verdict does not repair it (the server knows the
%%% session, so it never lists it as unknown).
%%%
%%% What these tests hold (see "Notices the server did not acknowledge" in
%%% yuzu_gw_upstream's module doc):
%%%   - a refused notice is sent again with backoff until it is acknowledged;
%%%   - a refusal neither fails nor recovers the circuit breaker;
%%%   - a newer event for the key cancels the retry and is delivered in order;
%%%   - a CONNECTED is retried only while the gateway still holds its session,
%%%     a DISCONNECTED only within its window;
%%%   - retries use at most half of the notify lane and fresh notices go first,
%%%     so a large refused population cannot starve them;
%%%   - a pending retry can be the half_open probe;
%%%   - a planned stop sends a refused DISCONNECTED in the last gasp, not a
%%%     refused CONNECTED.
%%%
%%% Real:  yuzu_gw_upstream, yuzu_gw_registry.
%%% Mocks: yuzu_grpc_client (the server), telemetry, yuzu_gw_agent.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_ack_tests).
-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 5000).
-define(THRESHOLD, 5).
-define(CALLS, yuzu_gw_notify_ack_tests_calls).
-define(KEYS, yuzu_gw_notify_ack_tests_keys).
-define(DUMMIES, yuzu_gw_notify_ack_tests_dummies).
-define(WARN_STAMP, {yuzu_gw_safe_call, {kind, notify_unacknowledged}}).
%% Fast retry timing for the tests (the defaults are 1 s and 60 s).
-define(BASE_MS, 20).
-define(MAX_MS, 200).
%% The slow phase, scaled down (the defaults are 15 min and 600 s): once a
%% CONNECTED has been refused continuously for ?SLOW_AFTER_MS it is resent
%% every 0.8 to 1 x ?SLOW_MAX_MS, well above ?MAX_MS.
-define(SLOW_AFTER_MS, 600).
-define(SLOW_MAX_MS, 1500).
-define(SLOW_FLOOR_MS, (?SLOW_MAX_MS - ?SLOW_MAX_MS div 5)).
%% slow_server/0's modes.
-define(REFUSE, 0).
-define(ACCEPT, 1).
-define(REFUSE_ONCE, 2).
-define(HOLD, 3).

notify_ack_test_() ->
    {foreach,
     fun() -> setup(#{}) end,
     fun cleanup/1,
     [t("a refused CONNECTED is sent again until the server acknowledges it",
        fun a_refused_connected_is_resent_until_acknowledged/0),
      t("a refusal neither fails nor recovers the circuit breaker",
        fun a_refusal_is_neither_a_failure_nor_a_success/0),
      t("a DISCONNECTED cancels the pending CONNECTED retry and is delivered after it",
        fun a_disconnected_cancels_a_pending_connected_retry/0),
      t("a DISCONNECTED that arrives while the CONNECTED retry is in flight waits, "
        "and the refused retry is not sent again",
        fun a_disconnected_during_an_inflight_retry_wins/0),
      t("a CONNECTED is no longer retried once the gateway no longer holds its session",
        fun retries_stop_when_the_session_is_gone/0),
      {timeout, 120, {"5,000 refused keys: retries are bounded and fresh notices still flow",
                      fun a_refused_population_does_not_starve_fresh_notices/0}}]}.

disconnected_window_test_() ->
    {foreach,
     fun() -> setup(#{notify_unacked_disconnected_window_ms => 300}) end,
     fun cleanup/1,
     [t("a refused DISCONNECTED is retried within its window, then given up and counted",
        fun a_refused_disconnected_gives_up_after_its_window/0)]}.

probe_test_() ->
    {foreach,
     fun() -> setup(#{circuit_breaker_reset_timeout_ms => 100,
                      circuit_breaker_max_reset_timeout_ms => 100}) end,
     fun cleanup/1,
     [t("a pending retry is the half_open probe when nothing else is held",
        fun a_pending_retry_is_the_half_open_probe/0)]}.

planned_stop_test_() ->
    {foreach,
     %% Long backoff: the refused notices wait in their timers when the stop begins.
     fun() -> setup(#{notify_unacked_retry_base_ms => 60000,
                      notify_unacked_retry_max_ms => 60000}) end,
     fun cleanup/1,
     [t("a planned stop sends a refused DISCONNECTED in the last gasp and drops a "
        "refused CONNECTED",
        fun a_planned_stop_sends_refused_disconnected_not_connected/0)]}.

%% A restarted agent owner (OWNER-RESTART) waits on notify_settled/4 before it
%% presents its predecessor's session to the server again. The retry set must
%% not let a refused notice of that session follow the re-registration.
%% The backoff is 60 s, so a refused notice never becomes due on its own during
%% a case: each case ends the backoff itself, when it chooses, by delivering the
%% message the backoff timer would (due_message/2, deliver/1), including the
%% stale one of a resend already cancelled, during the (slow) re-registration.
%% These cases used a 100 ms backoff and relied on reading the waiting entry
%% before it fell due, which a loaded host did not always do.
owner_restart_settle_test_() ->
    {foreach,
     fun() -> setup(#{notify_unacked_retry_base_ms => 60000,
                      notify_unacked_retry_max_ms => 60000}) end,
     fun cleanup/1,
     [t("a settle cancels a waiting refused DISCONNECTED: none reaches the server after "
        "the re-registration",
        fun a_settle_cancels_a_waiting_disconnected_retry/0),
      t("a settle waits for a resend in flight, then cancels it if it is refused again",
        fun a_settle_waits_for_an_inflight_resend/0),
      t("a predecessor's refused CONNECTED is never resent after the successor's notices",
        fun a_predecessor_connected_retry_never_follows_the_successor/0)]}.

%% Stopgap until the server's answer carries a refusal reason (#6059): a
%% CONNECTED the server keeps refusing (a permanent refusal such as
%% stale_connected_session or cluster_affinity_violation) is slowed once it has
%% been refused continuously for notify_unacked_slow_after_ms, instead of being
%% resent every minute for as long as its session lives. Time, not a refusal
%% count (#6077): many quick refusals (a degraded route store refusing for a
%% minute) must not slow a key.
slow_phase_test_() ->
    {foreach,
     fun() -> setup(#{notify_unacked_slow_after_ms => ?SLOW_AFTER_MS,
                      notify_unacked_slow_max_ms => ?SLOW_MAX_MS}) end,
     fun cleanup/1,
     [t("a CONNECTED refused for notify_unacked_slow_after_ms is resent at the slow interval",
        fun a_connected_refused_past_the_threshold_is_slowed/0),
      t("an acknowledgement ends the slow phase, and a later refusal starts from the base",
        fun an_acknowledgement_ends_the_slow_phase/0),
      t("a newer event for the key ends the slow phase",
        fun a_newer_event_ends_the_slow_phase/0),
      t("a slowed CONNECTED whose session ends leaves the slow phase",
        fun a_slowed_key_whose_session_ends_leaves_the_slow_phase/0),
      t("code_change seeds the slow phase from the configured settings",
        fun code_change_reads_the_configured_slow_phase/0)]}.

%% The threshold far above the case: however many times a CONNECTED is refused
%% within it, it keeps the normal backoff.
slow_phase_threshold_test_() ->
    {foreach,
     fun() -> setup(#{notify_unacked_slow_after_ms => 60000,
                      notify_unacked_slow_max_ms => ?SLOW_MAX_MS}) end,
     fun cleanup/1,
     [t("many refusals within notify_unacked_slow_after_ms keep the normal backoff",
        fun many_quick_refusals_do_not_slow_a_connected/0)]}.

%% A threshold of 0: a CONNECTED is slowed from its first refusal, a
%% DISCONNECTED still never is.
slow_phase_immediate_test_() ->
    {foreach,
     fun() -> setup(#{notify_unacked_slow_after_ms => 0,
                      notify_unacked_slow_max_ms => ?SLOW_MAX_MS,
                      notify_unacked_disconnected_window_ms => 400}) end,
     fun cleanup/1,
     [t("with notify_unacked_slow_after_ms 0 a CONNECTED is slowed from its first refusal",
        fun a_zero_threshold_slows_from_the_first_refusal/0),
      t("a refused DISCONNECTED is never slowed",
        fun a_refused_disconnected_is_never_slowed/0)]}.

t(Name, Fun) -> {timeout, 60, {Name, Fun}}.

%%--------------------------------------------------------------------
%% The tests
%%--------------------------------------------------------------------

a_refused_connected_is_resent_until_acknowledged() ->
    [{Id, Sess}] = register_agents(<<"ack">>, 1),
    Refusals = counter(3),
    answer(fun(_Req) -> case take(Refusals) of true -> unacked; false -> ok end end),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) =:= 4 end)),
    ?assertEqual(ok, wait_until(fun settled/0)),
    %% Acknowledged: nothing more is sent.
    timer:sleep(5 * ?MAX_MS),
    ?assertEqual([unacked, unacked, unacked, ok], [A || {_, connected, A} <- notices(Id)]),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, up_field(cb_failures)),
    ?assertEqual(3, event_count([yuzu, gw, upstream, notify_unacknowledged], #{event => connected})),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended], #{outcome => acknowledged})),
    ?assertEqual(1, max_unacked_gauge()),
    ?assertEqual(0, last_unacked_gauge()),
    ?assertEqual(0, map_size(up_field(notify_unacked))).

%% The breaker counts what the server's health says. A refusal is an answer: it
%% must not count as a failure (ten refusals with a threshold of five leave the
%% breaker closed) nor as a success (it must not wipe out a real failure).
a_refusal_is_neither_a_failure_nor_a_success() ->
    [{A, SA}, {B, SB}] = register_agents(<<"neutral">>, 2),
    Test = self(),
    answer(fun(#{agent_id := Id}) when Id =:= A ->
                   %% Each send of A blocks until the test releases it.
                   Test ! {blocked, self(), Id},
                   receive {release, R} -> R after 20000 -> ok end;
              (#{agent_id := Id}) when Id =:= B ->
                   unacked
           end),
    ok = notify(A, SA, connected),
    W1 = blocked(A),
    W1 ! {release, {error, noproc}},
    %% A real failure: counted once, and A is sent again (and blocks again).
    W2 = blocked(A),
    ?assertEqual(1, up_field(cb_failures)),
    ok = notify(B, SB, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(B)) >= ?THRESHOLD * 2 end)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(1, up_field(cb_failures)),
    W2 ! {release, ok}.

a_disconnected_cancels_a_pending_connected_retry() ->
    [{Id, Sess}] = register_agents(<<"cancel">>, 1),
    answer(fun(#{event := 'CONNECTED'}) -> unacked;
              (#{event := 'DISCONNECTED'}) -> ok
           end),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) >= 2 end)),
    ok = notify(Id, Sess, disconnected),
    ?assertEqual(ok, wait_until(fun() -> lists:keymember(disconnected, 2, notices(Id)) end)),
    timer:sleep(5 * ?MAX_MS),
    %% The DISCONNECTED is the last notice of the key, and no CONNECTED follows it.
    Seen = notices(Id),
    ?assertMatch({_, disconnected, ok}, lists:last(Seen)),
    ?assertEqual(1, length([1 || {_, disconnected, _} <- Seen])),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended], #{outcome => superseded})),
    ?assertEqual(0, last_unacked_gauge()),
    ?assertEqual(0, map_size(up_field(notify_unacked))).

a_disconnected_during_an_inflight_retry_wins() ->
    [{Id, Sess}] = register_agents(<<"inflight">>, 1),
    Test = self(),
    Calls = counter(0),
    answer(fun(#{event := 'CONNECTED'}) ->
                   case bump(Calls) of
                       1 -> unacked;
                       _ -> Test ! {blocked, self(), Id},
                            receive {release, R} -> R after 20000 -> ok end
                   end;
              (#{event := 'DISCONNECTED'}) -> ok
           end),
    ok = notify(Id, Sess, connected),
    %% The retry is in flight (blocked); the DISCONNECTED arrives meanwhile.
    W = blocked(Id),
    ok = notify(Id, Sess, disconnected),
    _ = yuzu_gw_upstream:circuit_state(),
    ?assertNot(lists:keymember(disconnected, 2, notices(Id))),
    W ! {release, unacked},
    ?assertEqual(ok, wait_until(fun() -> lists:keymember(disconnected, 2, notices(Id)) end)),
    timer:sleep(5 * ?MAX_MS),
    ?assertEqual([connected, connected, disconnected], [E || {_, E, _} <- notices(Id)]),
    ?assertEqual(0, map_size(up_field(notify_unacked))),
    ?assertEqual(0, last_unacked_gauge()).

retries_stop_when_the_session_is_gone() ->
    [{Id, Sess}] = register_agents(<<"gone">>, 1),
    answer(fun(_) -> unacked end),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) >= 2 end)),
    yuzu_gw_registry:deregister_agent(Id),
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_registry:lookup_local_session(Id) =:= error end)),
    ?assertEqual(ok, wait_until(fun() -> map_size(up_field(notify_unacked)) =:= 0 end)),
    N = length(notices(Id)),
    timer:sleep(5 * ?MAX_MS),
    ?assertEqual(N, length(notices(Id))),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended], #{outcome => session_gone})),
    ?assertEqual(0, last_unacked_gauge()).

a_refused_disconnected_gives_up_after_its_window() ->
    Id = <<"window-agent">>,
    answer(fun(_) -> unacked end),
    ok = notify(Id, <<"window-session">>, disconnected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) > 1 end)),
    ?assertEqual(ok, wait_until(fun() -> map_size(up_field(notify_unacked)) =:= 0 end)),
    N = length(notices(Id)),
    timer:sleep(5 * ?MAX_MS),
    ?assertEqual(N, length(notices(Id))),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_lost],
                                #{event => disconnected, reason => unacknowledged})),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended], #{outcome => lost})),
    ?assertEqual(0, last_unacked_gauge()).

%% 5,000 keys the server keeps refusing, each refusal answered after 5 ms.
%% Every key is retried (more than 5,000 sends), never more than five retries
%% are in flight at once (half the notify lane), a key never has two sends in
%% flight, and a fresh CONNECTED and a fresh DISCONNECTED of other keys are
%% delivered at once while the population retries.
a_refused_population_does_not_starve_fresh_notices() ->
    N = 5000,
    Refused = register_agents(<<"pop">>, N),
    [{Fresh, FreshSess}] = register_agents(<<"fresh">>, 1),
    RefusedSet = sets:from_list([Id || {Id, _} <- Refused], [{version, 2}]),
    Stats = atomics:new(4, [{signed, true}]),   %% 1 retry inflight, 2 retry peak, 3 key overlap
    answer(fun(#{agent_id := Id, event := Event}) ->
                   case Event =:= 'CONNECTED' andalso sets:is_element(Id, RefusedSet) of
                       false ->
                           ok;
                       true ->
                           Nth = ets:update_counter(?KEYS, {n, Id}, 1,
                                                    {{n, Id}, 0}),
                           Busy = ets:update_counter(?KEYS, {busy, Id},
                                                     1, {{busy, Id}, 0}),
                           Busy > 1 andalso atomics:add(Stats, 3, 1),
                           Retry = Nth > 1,
                           Retry andalso peak(Stats, 1, 2),
                           timer:sleep(5),
                           Retry andalso atomics:sub(Stats, 1, 1),
                           ets:update_counter(?KEYS, {busy, Id}, -1),
                           unacked
                   end
           end),
    [ok = notify(Id, S, connected) || {Id, S} <- Refused],
    ?assertEqual(ok, wait_until(fun() -> refused_sends(Refused) > N + 200 end, 60000)),
    %% Fresh notices while the population retries.
    T0 = erlang:monotonic_time(millisecond),
    ok = notify(Fresh, FreshSess, connected),
    ?assertEqual(ok, wait_until(fun() -> notices(Fresh) =/= [] end, 2000)),
    FreshMs = erlang:monotonic_time(millisecond) - T0,
    {Dis, DisSess} = lists:last(Refused),
    T1 = erlang:monotonic_time(millisecond),
    ok = notify(Dis, DisSess, disconnected),
    ?assertEqual(ok, wait_until(fun() -> lists:keymember(disconnected, 2, notices(Dis)) end, 2000)),
    DisMs = erlang:monotonic_time(millisecond) - T1,
    ?debugFmt("fresh CONNECTED delivered in ~b ms, fresh DISCONNECTED in ~b ms, "
              "~b refused sends, retry peak ~b, unacked keys ~b",
              [FreshMs, DisMs, refused_sends(Refused), atomics:get(Stats, 2),
               map_size(up_field(notify_unacked))]),
    ?assert(FreshMs < 500),
    ?assert(DisMs < 500),
    ?assert(atomics:get(Stats, 2) =< 5),
    ?assert(atomics:get(Stats, 2) >= 1),
    ?assertEqual(0, atomics:get(Stats, 3)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    %% At most one pending retry per key, and the store did not grow with them.
    ?assert(map_size(up_field(notify_unacked)) =< N).

a_pending_retry_is_the_half_open_probe() ->
    [{Id, Sess}] = register_agents(<<"probe">>, 1),
    Accept = counter(0),
    answer(fun(_) -> case atomics:get(Accept, 1) of 0 -> unacked; _ -> ok end end),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) >= 1 end)),
    %% Open the breaker with failed proxied calls of the current generation (the
    %% cast a proxied call sends with its result); nothing is held in the store.
    Gen = up_field(cb_gen),
    [gen_server:cast(yuzu_gw_upstream, {rpc_result, Gen, {error, noproc}})
     || _ <- lists:seq(1, ?THRESHOLD)],
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, yuzu_gw_notify_queue:size(up_field(notify_pending))),
    atomics:put(Accept, 1, 1),
    %% Nothing else is held or sent: the retry is the probe, and its
    %% acknowledgement closes the breaker under the next generation.
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_upstream:circuit_state() =:= closed end)),
    ?assert(up_field(cb_gen) > Gen),
    ?assertEqual(ok, lists:last([A || {_, _, A} <- notices(Id)])),
    ?assertEqual(0, map_size(up_field(notify_unacked))).

a_planned_stop_sends_refused_disconnected_not_connected() ->
    [{C, CSess}] = register_agents(<<"stopc">>, 1),
    D = <<"stop-disconnected-agent">>,
    DRefusals = counter(1),
    answer(fun(#{agent_id := Id}) when Id =:= C -> unacked;
              (#{agent_id := Id}) when Id =:= D ->
                   case take(DRefusals) of true -> unacked; false -> ok end
           end),
    ok = notify(C, CSess, connected),
    ok = notify(D, <<"stop-session">>, disconnected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(C)) =:= 1
                                             andalso length(notices(D)) =:= 1 end)),
    ?assertEqual(ok, wait_until(fun settled/0)),
    ok = yuzu_gw_upstream:begin_stop(),
    Result = yuzu_gw_upstream:last_gasp(erlang:monotonic_time(millisecond) + 2000),
    ?assertEqual(#{sent => 1, left => 0}, Result),
    ?assertEqual([unacked, ok], [A || {_, disconnected, A} <- notices(D)]),
    ?assertEqual([unacked], [A || {_, connected, A} <- notices(C)]),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_lost],
                                #{event => connected, reason => shutdown})).

%% The successor's sequence (yuzu_gw_agent:try_recover/2) driven directly: the
%% predecessor session's DISCONNECTED is refused and waits for its resend; the
%% successor's settle is answered, it re-registers (slow at the server) and
%% casts CONNECTED. No DISCONNECTED may reach the server after the
%% re-registration started: it would remove the session just presented again.
%% The cancelled resend's backoff ends during the re-registration (its timer
%% message was already on its way when the settle cancelled it).
a_settle_cancels_a_waiting_disconnected_retry() ->
    [{Id, Sess}] = register_agents(<<"settle-wait">>, 1),
    Refusals = counter(1),
    Answer = fun(#{event := 'DISCONNECTED'}) ->
                     case take(Refusals) of true -> unacked; false -> ok end;
                (#{event := 'CONNECTED'}) -> ok
             end,
    answer_owner(Answer),
    ok = notify(Id, Sess, disconnected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) =:= 1 andalso settled() end)),
    ?assertMatch(#{status := {waiting, _}}, unacked_entry(Id, Sess)),
    Due = due_message(Id, Sess),
    ok = await_settled(Id, Sess),
    ?assertEqual(none, unacked_entry(Id, Sess)),
    Delivered = counter(0),
    answer_owner(Answer, fun() -> ok = deliver(Due), bump(Delivered) end),
    {ok, _} = yuzu_gw_upstream:reregister_session(register_req(Id), Sess, #{}),
    ?assertEqual(1, atomics:get(Delivered, 1)),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> lists:keymember(connected, 2, notices(Id)) end)),
    ?assertEqual(ok, wait_until(fun settled/0)),
    ?assertEqual([{disconnected, unacked}, {reregister, ok}, {connected, ok}],
                 [{E, A} || {_, E, A} <- notices(Id)]),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended],
                                #{outcome => superseded})),
    ?assertEqual(0, map_size(up_field(notify_unacked))),
    ?assertEqual(0, last_unacked_gauge()).

%% A resend in flight when the settle is asked keeps the key unsettled; refused
%% again, it is not put back to wait: the settle cancels it and answers.
a_settle_waits_for_an_inflight_resend() ->
    [{Id, Sess}] = register_agents(<<"settle-inflight">>, 1),
    Test = self(),
    Calls = counter(0),
    answer_owner(fun(#{event := 'DISCONNECTED'}) ->
                         case bump(Calls) of
                             1 -> unacked;
                             2 -> Test ! {blocked, self(), Id},
                                  receive {release, R} -> R after 20000 -> ok end;
                             _ -> ok
                         end;
                    (#{event := 'CONNECTED'}) -> ok
                 end),
    ok = notify(Id, Sess, disconnected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) =:= 1 andalso settled() end)),
    ok = deliver(due_message(Id, Sess)),
    W = blocked(Id),
    Alias = alias([reply]),
    ok = yuzu_gw_upstream:notify_settled(Id, Sess, <<"home">>, Alias),
    receive {Alias, notify_settled} -> error(settled_with_a_resend_in_flight)
    after 300 -> ok
    end,
    W ! {release, unacked},
    receive {Alias, notify_settled} -> ok
    after ?WAIT_MS -> error(never_settled)
    end,
    ?assertEqual(none, unacked_entry(Id, Sess)),
    {ok, _} = yuzu_gw_upstream:reregister_session(register_req(Id), Sess, #{}),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> lists:keymember(connected, 2, notices(Id)) end)),
    ?assertEqual(ok, wait_until(fun settled/0)),
    ?assertEqual([{disconnected, unacked}, {disconnected, unacked}, {reregister, ok},
                  {connected, ok}],
                 [{E, A} || {_, E, A} <- notices(Id)]),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended],
                                #{outcome => superseded})),
    ?assertEqual(0, map_size(up_field(notify_unacked))).

%% The predecessor's CONNECTED was refused and waits for its resend; the
%% successor sends the session's DISCONNECTED, settles, re-registers and sends
%% CONNECTED. The predecessor's CONNECTED is never sent again after any of it.
a_predecessor_connected_retry_never_follows_the_successor() ->
    [{Id, Sess}] = register_agents(<<"settle-conn">>, 1),
    Refusals = counter(1),
    Answer = fun(#{event := 'CONNECTED'}) ->
                     case take(Refusals) of true -> unacked; false -> ok end;
                (#{event := 'DISCONNECTED'}) -> ok
             end,
    answer_owner(Answer),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) =:= 1 andalso settled() end)),
    ?assertMatch(#{status := {waiting, _}}, unacked_entry(Id, Sess)),
    %% The refused CONNECTED's backoff ends during the re-registration, after
    %% the DISCONNECTED superseded it.
    Due = due_message(Id, Sess),
    ok = notify(Id, Sess, disconnected),
    ok = await_settled(Id, Sess),
    Delivered = counter(0),
    answer_owner(Answer, fun() -> ok = deliver(Due), bump(Delivered) end),
    {ok, _} = yuzu_gw_upstream:reregister_session(register_req(Id), Sess, #{}),
    ?assertEqual(1, atomics:get(Delivered, 1)),
    ok = notify(Id, Sess, connected),
    ?assertEqual(ok, wait_until(fun() -> length(notices(Id)) =:= 4 end)),
    ?assertEqual(ok, wait_until(fun settled/0)),
    ?assertEqual([{connected, unacked}, {disconnected, ok}, {reregister, ok}, {connected, ok}],
                 [{E, A} || {_, E, A} <- notices(Id)]),
    ?assertEqual(0, map_size(up_field(notify_unacked))).

%% The regression of #6077: refused every time, a CONNECTED is refused more
%% than the old count threshold (10) well within notify_unacked_slow_after_ms,
%% and stays at the normal backoff, never counted slow.
many_quick_refusals_do_not_slow_a_connected() ->
    [{Id, Sess}] = register_agents(<<"quick">>, 1),
    _ = slow_server(),
    ok = notify(Id, Sess, connected),
    Many = poll_entry(field_index(notify_unacked), {Id, Sess, <<"home">>},
                      fun(E) -> maps:get(refusals, E) >= 12 end, 30000),
    ?assertEqual(false, maps:get(slow, Many)),
    ?assert(maps:get(delay, Many) =< ?MAX_MS),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    ?assertEqual(0, max_slow_gauge()).

a_connected_refused_past_the_threshold_is_slowed() ->
    [{Id, Sess}] = register_agents(<<"slow">>, 1),
    _ = slow_server(),
    Entry = entry_poller(Id, Sess),
    ok = notify(Id, Sess, connected),
    %% The first refusal past the threshold: the next resend is 0.8 to 1 x the
    %% slow max, and the key is counted slow.
    Slow = Entry(slow()),
    Read = erlang:monotonic_time(millisecond),
    R = maps:get(refusals, Slow),
    ?assert(Read - maps:get(first, Slow) >= ?SLOW_AFTER_MS),
    ?assert(maps:get(delay, Slow) >= ?SLOW_FLOOR_MS),
    ?assert(maps:get(delay, Slow) =< ?SLOW_MAX_MS),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    ?assertEqual(ok, wait_until(fun() -> last_slow_gauge() =:= 1 end)),
    %% The next send comes, is refused again, and stays slow...
    Next = Entry(refusals(R + 1)),
    ?assertEqual(true, maps:get(slow, Next)),
    ?assertEqual(maps:get(first, Slow), maps:get(first, Next)),
    ?assert(maps:get(delay, Next) >= ?SLOW_FLOOR_MS),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    ?assertEqual(1, max_slow_gauge()),
    %% ...and the server received it at least the slow floor after the send
    %% whose refusal slowed the key (the backoff starts at that refusal).
    Sends = sends(),
    ?assertEqual(R + 1, length(Sends)),
    [TR, TNext] = lists:nthtail(R - 1, Sends),
    ?assert(TNext - TR >= ?SLOW_FLOOR_MS).

an_acknowledgement_ends_the_slow_phase() ->
    [{Id, Sess}] = register_agents(<<"slow-ack">>, 1),
    Mode = slow_server(),
    Entry = entry_poller(Id, Sess),
    ok = notify(Id, Sess, connected),
    Slowed = Entry(slow()),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    atomics:put(Mode, 1, ?ACCEPT),
    ?assertEqual(ok, wait_until(fun() -> unacked_entry(Id, Sess) =:= none end,
                                ?SLOW_MAX_MS + ?WAIT_MS)),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    ?assertEqual(ok, wait_until(fun() -> last_slow_gauge() =:= 0 end)),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended],
                                #{outcome => acknowledged})),
    %% A later refusal of the key starts again: a new first refusal, the base
    %% backoff, not slow (its resend is held at the server so the entry of
    %% that one refusal can be read).
    atomics:put(Mode, 1, ?REFUSE_ONCE),
    ok = notify(Id, Sess, connected),
    W = blocked(Id),
    Again = unacked_entry(Id, Sess),
    ?assertMatch(#{status := inflight, refusals := 1, slow := false}, Again),
    ?assert(maps:get(first, Again) > maps:get(first, Slowed)),
    ?assert(maps:get(delay, Again) =< ?MAX_MS),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    W ! {release, ok},
    ?assertEqual(ok, wait_until(fun() -> unacked_entry(Id, Sess) =:= none end)),
    ?assertEqual(0, up_field(notify_unacked_slow)).

a_newer_event_ends_the_slow_phase() ->
    [{Id, Sess}] = register_agents(<<"slow-newer">>, 1),
    Mode = slow_server(),
    Entry = entry_poller(Id, Sess),
    ok = notify(Id, Sess, connected),
    Slowed = Entry(slow()),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    %% A newer CONNECTED for the key (refused once, then held) replaces the
    %% slowed entry, which waits out its slow backoff: its first refusal, and
    %% so the clock of the slow phase, start again, and so does the base backoff.
    atomics:put(Mode, 1, ?REFUSE_ONCE),
    ok = notify(Id, Sess, connected),
    W = blocked(Id),
    Newer = unacked_entry(Id, Sess),
    ?assertMatch(#{status := inflight, refusals := 1, slow := false}, Newer),
    ?assert(maps:get(first, Newer) > maps:get(first, Slowed)),
    ?assert(maps:get(delay, Newer) =< ?MAX_MS),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    ?assertEqual(ok, wait_until(fun() -> last_slow_gauge() =:= 0 end)),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended],
                                #{outcome => superseded})),
    W ! {release, ok},
    ?assertEqual(ok, wait_until(fun() -> unacked_entry(Id, Sess) =:= none end)),
    ?assertEqual(0, up_field(notify_unacked_slow)).

a_slowed_key_whose_session_ends_leaves_the_slow_phase() ->
    [{Id, Sess}] = register_agents(<<"slow-gone">>, 1),
    _ = slow_server(),
    Entry = entry_poller(Id, Sess),
    ok = notify(Id, Sess, connected),
    Slowed = Entry(slow()),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    yuzu_gw_registry:deregister_agent(Id),
    ?assertEqual(ok, wait_until(fun() -> unacked_entry(Id, Sess) =:= none end,
                                ?SLOW_MAX_MS + ?WAIT_MS)),
    %% The slowed resend was not sent: the session was gone when it fell due.
    ?assertEqual(maps:get(refusals, Slowed), length(notices(Id))),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    ?assertEqual(ok, wait_until(fun() -> last_slow_gauge() =:= 0 end)),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_unacked_ended],
                                #{outcome => session_gone})).

a_zero_threshold_slows_from_the_first_refusal() ->
    [{Id, Sess}] = register_agents(<<"slow-zero">>, 1),
    _ = slow_server(),
    Entry = entry_poller(Id, Sess),
    ok = notify(Id, Sess, connected),
    First = Entry(refusals(1)),
    ?assertEqual(true, maps:get(slow, First)),
    ?assert(maps:get(delay, First) >= ?SLOW_FLOOR_MS),
    ?assert(maps:get(delay, First) =< ?SLOW_MAX_MS),
    ?assertEqual(1, up_field(notify_unacked_slow)),
    yuzu_gw_registry:deregister_agent(Id),
    ?assertEqual(ok, wait_until(fun() -> unacked_entry(Id, Sess) =:= none end,
                                ?SLOW_MAX_MS + ?WAIT_MS)),
    ?assertEqual(0, up_field(notify_unacked_slow)).

%% Even with a threshold of 0 a DISCONNECTED keeps the normal backoff until its
%% window passes: a slow delay would push its last resend past the window.
a_refused_disconnected_is_never_slowed() ->
    Id = <<"slow-disconnected-agent">>,
    _ = slow_server(),
    Entry = entry_poller(Id, <<"slow-disconnected-session">>),
    ok = notify(Id, <<"slow-disconnected-session">>, disconnected),
    Again = Entry(fun(E) -> maps:get(refusals, E) >= 2 end),
    ?assertEqual(false, maps:get(slow, Again)),
    ?assert(maps:get(delay, Again) =< ?MAX_MS),
    ?assertEqual(ok, wait_until(fun() -> map_size(up_field(notify_unacked)) =:= 0 end)),
    ?assertEqual(1, event_count([yuzu, gw, upstream, notify_lost],
                                #{event => disconnected, reason => unacknowledged})),
    ?assertEqual(0, up_field(notify_unacked_slow)),
    ?assertEqual(0, max_slow_gauge()).

%% A state from before the slow phase (its four trailing fields missing) is
%% upgraded with the configured settings, not the built-in defaults: the slow
%% max raised to the retry max the state kept, every entry already waiting
%% flagged slow or not by the time rule at the upgrade (a CONNECTED first
%% refused notify_unacked_slow_after_ms or more ago is slow, a DISCONNECTED
%% never), and the slow count recomputed from those flags. Then a state from
%% before the retry set: every retry setting is read from the app env, as
%% init/1 reads it.
code_change_reads_the_configured_slow_phase() ->
    Live = sys:get_state(yuzu_gw_upstream),
    Size = tuple_size(Live),
    Now = erlang:monotonic_time(millisecond),
    %% Pre-slow-phase: older entries without `refusals' or `slow': a CONNECTED
    %% first refused 5 s ago (past the threshold), one refused just now (dated a
    %% minute ahead, so the case cannot cross the threshold: not slow), and a
    %% DISCONNECTED first refused 5 s ago (never slow); a retry max of
    %% 900 kept from the old start; an app env asking for the slow phase after
    %% 1 s of refusal at 700 ms.
    Old = #{{<<"old">>, <<"s">>, <<"home">>} =>
                #{event => connected, class => connected, first => Now - 5000},
            {<<"new">>, <<"s">>, <<"home">>} =>
                #{event => connected, class => connected, first => Now + 60000},
            {<<"gone">>, <<"s">>, <<"home">>} =>
                #{event => disconnected, class => disconnected, first => Now - 5000}},
    Old0 = setelement(field_index(notify_unacked), Live, Old),
    Old1 = setelement(field_index(unacked_max_ms), Old0, 900),
    PreSlow = list_to_tuple(lists:sublist(tuple_to_list(Old1),
                                          field_index(unacked_slow_after_ms) - 1)),
    ?assertEqual(Size - 4, tuple_size(PreSlow)),
    application:set_env(yuzu_gw, notify_unacked_slow_after_ms, 1000),
    application:set_env(yuzu_gw, notify_unacked_slow_max_ms, 700),
    {ok, Up1} = yuzu_gw_upstream:code_change(old, PreSlow, []),
    ?assertEqual(Size, tuple_size(Up1)),
    ?assertEqual(1000, element(field_index(unacked_slow_after_ms), Up1)),
    ?assertEqual(900, element(field_index(unacked_slow_max_ms), Up1)),
    ?assertEqual(1, element(field_index(notify_unacked_slow), Up1)),
    Flags = maps:map(fun(_K, E) -> {maps:get(slow, E), maps:get(refusals, E)} end,
                     element(field_index(notify_unacked), Up1)),
    ?assertEqual(#{{<<"old">>, <<"s">>, <<"home">>} => {true, 1},
                   {<<"new">>, <<"s">>, <<"home">>} => {false, 1},
                   {<<"gone">>, <<"s">>, <<"home">>} => {false, 1}}, Flags),
    %% The configured slow max wins when it is above the kept retry max.
    application:set_env(yuzu_gw, notify_unacked_slow_max_ms, 5000),
    {ok, Up2} = yuzu_gw_upstream:code_change(old, PreSlow, []),
    ?assertEqual(5000, element(field_index(unacked_slow_max_ms), Up2)),
    %% Pre-retry-set (settle_waiters onward missing): the fixture's ?BASE_MS and
    %% ?MAX_MS are read, not the 1 s and 60 s defaults, and nothing is slow.
    PreRetry = list_to_tuple(lists:sublist(tuple_to_list(Live),
                                           field_index(settle_waiters) - 1)),
    {ok, Up3} = yuzu_gw_upstream:code_change(old, PreRetry, []),
    ?assertEqual(Size, tuple_size(Up3)),
    ?assertEqual(?BASE_MS, element(field_index(unacked_base_ms), Up3)),
    ?assertEqual(?MAX_MS, element(field_index(unacked_max_ms), Up3)),
    ?assertEqual(1000, element(field_index(unacked_slow_after_ms), Up3)),
    ?assertEqual(5000, element(field_index(unacked_slow_max_ms), Up3)),
    ?assertEqual(0, element(field_index(notify_unacked_slow), Up3)),
    %% A current state is returned as it is.
    ?assertEqual({ok, Live}, yuzu_gw_upstream:code_change(old, Live, [])).
%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup(Env) ->
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,
    [catch ets:delete(T) || T <- [?CALLS, ?KEYS, ?DUMMIES]],
    %% Owned by this (the fixture's) process, so they outlive the test body.
    ets:new(?CALLS, [named_table, public, ordered_set, {write_concurrency, true}]),
    ets:new(?KEYS, [named_table, public, set, {write_concurrency, true}]),
    ets:new(?DUMMIES, [named_table, public, bag]),
    meck:new(yuzu_grpc_client, [non_strict, no_link]),
    answer(fun(_) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    meck:expect(yuzu_gw_agent, reannounce, fun(_, _) -> ok end),
    meck:expect(yuzu_gw_agent, disconnect, fun(_) -> ok end),
    Defaults = #{circuit_breaker_failure_threshold => ?THRESHOLD,
                 circuit_breaker_reset_timeout_ms => 60000,
                 circuit_breaker_max_reset_timeout_ms => 60000,
                 registration_replay_start_jitter_ms => 0,
                 notify_unacked_retry_base_ms => ?BASE_MS,
                 notify_unacked_retry_max_ms => ?MAX_MS},
    Set = maps:merge(Defaults, Env),
    maps:foreach(fun(K, V) -> application:set_env(yuzu_gw, K, V) end, Set),
    %% The rate-limit stamp of the refusal WARN is created on first use when the
    %% application did not create it; remembered so cleanup leaves the VM as it
    %% found it.
    Stamp = persistent_term:get(?WARN_STAMP, undefined) =/= undefined,
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    {UpPid, maps:keys(Set), Stamp}.

cleanup({UpPid, Keys, Stamp}) ->
    catch unlink(UpPid),
    catch gen_server:stop(UpPid, shutdown, 5000),
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 30000),
    [Pid ! stop || Pid <- take_dummies()],
    meck:unload([yuzu_grpc_client, telemetry, yuzu_gw_agent]),
    [catch ets:delete(T) || T <- [?CALLS, ?KEYS, ?DUMMIES]],
    [application:unset_env(yuzu_gw, K) || K <- Keys],
    Stamp orelse persistent_term:erase(?WARN_STAMP),
    %% The values the other modules' fixtures expect (see
    %% yuzu_gw_upstream_notify_result_tests).
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 150),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    ok.

%% The server: every NotifyStreamStatus is recorded ({Seq, AgentId, Event,
%% Answer}) and answered by Answer(Request): ok (acknowledged=true), unacked
%% (acknowledged=false), {error, Reason} (a transport error). Any other RPC is
%% answered OK.
answer(Answer) ->
    meck:expect(yuzu_grpc_client, unary,
                fun(Meta, Path, Req, Def, Opts) ->
                        notify_answer(Answer, Meta, Path, Req, Def, Opts)
                end).

notify_answer(Answer, _Meta, Path, Req, _Def, _Opts) ->
    case lists:last(binary:split(Path, <<"/">>, [global])) of
        <<"NotifyStreamStatus">> ->
            A = Answer(Req),
            Event = case maps:get(event, Req) of
                        'CONNECTED' -> connected;
                        'DISCONNECTED' -> disconnected
                    end,
            Short = case A of
                        ok -> ok;
                        unacked -> unacked;
                        _ -> error
                    end,
            catch ets:insert(?CALLS, {erlang:unique_integer([monotonic]),
                                      maps:get(agent_id, Req), Event, Short}),
            case A of
                ok -> {ok, #{acknowledged => true}, #{}};
                unacked -> {ok, #{acknowledged => false}, #{}};
                {error, Reason} -> {error, Reason}
            end;
        _ ->
            {ok, #{accepted => true}, #{}}
    end.

%% answer/1, and a ProxyRegister is recorded too ({Seq, AgentId, reregister,
%% ok}) when it arrives, then answered after 300 ms (a slow re-registration:
%% a resend that becomes due meanwhile would be sent during it). OnRegister()
%% runs once the ProxyRegister is recorded, before the answer.
answer_owner(Answer) ->
    answer_owner(Answer, fun() -> ok end).

answer_owner(Answer, OnRegister) ->
    meck:expect(yuzu_grpc_client, unary,
                fun(Meta, Path, Req, Def, Opts) ->
                        case lists:last(binary:split(Path, <<"/">>, [global])) of
                            <<"ProxyRegister">> ->
                                AgentId = maps:get(agent_id, maps:get(info, Req, #{}), undefined),
                                catch ets:insert(?CALLS, {erlang:unique_integer([monotonic]),
                                                          AgentId, reregister, ok}),
                                _ = OnRegister(),
                                timer:sleep(300),
                                {ok, #{accepted => true}, #{}};
                            _ ->
                                notify_answer(Answer, Meta, Path, Req, Def, Opts)
                        end
                end).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% The successor's wait (yuzu_gw_agent:await_settled/1).
await_settled(Id, Sess) ->
    Alias = alias([reply]),
    ok = yuzu_gw_upstream:notify_settled(Id, Sess, <<"home">>, Alias),
    receive {Alias, notify_settled} -> ok
    after ?WAIT_MS -> unalias(Alias), {error, never_settled}
    end.

%% The message that ends the backoff of the key's waiting resend: what its
%% timer (erlang:start_timer/3 in yuzu_gw_upstream) delivers when it fires.
%% Taken while the entry waits, it can be delivered after the entry is gone,
%% as a timer message already on its way when the entry was cancelled.
due_message(Id, Sess) ->
    Key = {Id, Sess, <<"home">>},
    #{status := {waiting, TRef}} = unacked_entry(Id, Sess),
    {timeout, TRef, {notify_unacked_due, Key}}.

%% Deliver a message to the upstream process and return once it has handled it.
deliver(Msg) ->
    yuzu_gw_upstream ! Msg,
    _ = sys:get_state(yuzu_gw_upstream),
    ok.

%% The retry-set entry of the key notify/3 uses, or `none'.
unacked_entry(Id, Sess) ->
    maps:get({Id, Sess, <<"home">>}, up_field(notify_unacked), none).

%% A poller of the key's retry-set entry: Poll(Pred) returns the first entry
%% Pred holds for, polled every 5 ms (the field index is resolved once: a
%% refusal's entry may last only a few tens of milliseconds).
entry_poller(Id, Sess) ->
    Idx = field_index(notify_unacked),
    Key = {Id, Sess, <<"home">>},
    fun(Pred) -> poll_entry(Idx, Key, Pred, ?WAIT_MS) end.

poll_entry(Idx, Key, Pred, Left) ->
    Entry = maps:get(Key, element(Idx, sys:get_state(yuzu_gw_upstream)), none),
    case is_map(Entry) andalso Pred(Entry) of
        true -> Entry;
        false when Left =< 0 -> error({no_matching_entry, Key, Entry});
        false -> timer:sleep(5), poll_entry(Idx, Key, Pred, Left - 5)
    end.

refusals(N) -> fun(E) -> maps:get(refusals, E, undefined) =:= N end.

slow() -> fun(E) -> maps:get(slow, E, false) end.

%% The server of the slow-phase cases; returns its Mode cell. ?REFUSE refuses
%% every notice; ?ACCEPT acknowledges every notice; ?REFUSE_ONCE refuses the
%% next notice and moves to ?HOLD, which blocks every later notice until the
%% test releases it ({release, Answer}), so the entry of that one refusal stays
%% in the retry set (in flight) to be read. Each send's receipt time at the
%% server (monotonic ms) is recorded (sends/0).
slow_server() ->
    Test = self(),
    Mode = counter(?REFUSE),
    answer(fun(#{agent_id := Id}) ->
                   true = ets:insert(?KEYS, {{sent, erlang:unique_integer([monotonic])},
                                             erlang:monotonic_time(millisecond)}),
                   case atomics:get(Mode, 1) of
                       ?REFUSE -> unacked;
                       ?ACCEPT -> ok;
                       _ ->
                           case atomics:compare_exchange(Mode, 1, ?REFUSE_ONCE, ?HOLD) of
                               ok -> unacked;
                               _ -> Test ! {blocked, self(), Id},
                                    receive {release, R} -> R after 20000 -> ok end
                           end
                   end
           end),
    Mode.

%% When the server received each send of slow_server/0, in order.
sends() ->
    [T || {_, T} <- lists:sort([{S, T} || {{sent, S}, T} <- ets:tab2list(?KEYS)])].

register_req(Id) ->
    #{info => #{agent_id => Id, hostname => <<"host">>, plugins => [#{name => <<"svc">>}]},
      enrollment_token => <<"enroll-", Id/binary>>}.


notify(AgentId, SessionId, Event) ->
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, Event, <<"203.0.113.9">>,
                                          <<"home">>).

%% The notices the server received for AgentId, in order: {Seq, Event, Answer}.
notices(AgentId) ->
    [{S, E, A} || {S, Id, E, A} <- ets:tab2list(?CALLS), Id =:= AgentId].

refused_sends(_Refused) ->
    length([1 || {_, _, _, unacked} <- ets:tab2list(?CALLS)]).

blocked(Id) ->
    receive {blocked, W, Id} -> W
    after ?WAIT_MS -> error({never_sent, Id})
    end.

settled() ->
    case yuzu_gw_upstream:lane_snapshot() of
        #{notify_inflight := 0} -> true;
        _ -> false
    end.

counter(N) ->
    C = atomics:new(1, [{signed, true}]),
    atomics:put(C, 1, N),
    C.

%% true while the counter was above zero (and takes one).
take(C) -> atomics:sub_get(C, 1, 1) >= 0.

bump(C) -> atomics:add_get(C, 1, 1).

peak(A, Cur, Max) ->
    V = atomics:add_get(A, Cur, 1),
    peak_max(A, Max, V).

peak_max(A, Max, V) ->
    case atomics:get(A, Max) of
        M when M >= V -> ok;
        M -> case atomics:compare_exchange(A, Max, M, V) of
                 ok -> ok;
                 _ -> peak_max(A, Max, V)
             end
    end.

%% Telemetry events seen with every key of Meta matching.
event_count(Name, Meta) ->
    lists:sum([maps:get(count, M, 1)
               || {_, {telemetry, execute, [N, M, Md]}, _} <- meck:history(telemetry),
                  N =:= Name,
                  maps:with(maps:keys(Meta), Md) =:= Meta]).

unacked_gauge_values() ->
    [K || {_, {telemetry, execute, [[yuzu, gw, upstream, notify_unacked], #{keys := K}, _]}, _}
              <- meck:history(telemetry)].

max_unacked_gauge() -> lists:max([0 | unacked_gauge_values()]).

last_unacked_gauge() ->
    case unacked_gauge_values() of
        [] -> undefined;
        Vs -> lists:last(Vs)
    end.

slow_gauge_values() ->
    [S || {_, {telemetry, execute, [[yuzu, gw, upstream, notify_unacked], #{slow_keys := S}, _]},
           _} <- meck:history(telemetry)].

max_slow_gauge() -> lists:max([0 | slow_gauge_values()]).

last_slow_gauge() ->
    case slow_gauge_values() of
        [] -> undefined;
        Vs -> lists:last(Vs)
    end.

%% A field of the upstream process's #state{}, by name.
up_field(Name) ->
    element(field_index(Name), sys:get_state(yuzu_gw_upstream)).

field_index(Name) ->
    Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
    {ok, Forms} = epp:parse_file(Src, []),
    [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
    Names = [case F of
                 {typed_record_field, {record_field, _, {atom, _, N}}, _} -> N;
                 {typed_record_field, {record_field, _, {atom, _, N}, _}, _} -> N;
                 {record_field, _, {atom, _, N}} -> N;
                 {record_field, _, {atom, _, N}, _} -> N
             end || F <- Fs],
    case [I || {I, N} <- lists:zip(lists:seq(2, length(Names) + 1), Names), N =:= Name] of
        [I] -> I;
        [] -> error({no_state_field, Name})
    end.

register_agents(Prefix0, N) ->
    Prefix = <<Prefix0/binary, "-", (list_to_binary(pid_to_list(self())))/binary>>,
    lists:map(fun(I) ->
        Id  = <<"notify-ack-", Prefix/binary, "-", (integer_to_binary(I))/binary>>,
        Sess = <<"sess-", Id/binary>>,
        Req = #{info => #{agent_id => Id, hostname => <<"host">>,
                          plugins => [#{name => <<"svc">>}]},
                enrollment_token => <<"enroll-", Id/binary>>},
        Pid = spawn(fun() -> receive stop -> ok end end),
        remember_dummy(Pid),
        ok = yuzu_gw_registry:register_agent(Id, Pid, Sess, [<<"svc">>], <<"host">>, Req),
        {Id, Sess}
    end, lists:seq(1, N)).

remember_dummy(Pid) ->
    ets:insert(?DUMMIES, {dummy, Pid}).

take_dummies() ->
    [P || {dummy, P} <- ets:take(?DUMMIES, dummy)].

wait_until(Pred) -> wait_until(Pred, ?WAIT_MS).

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
