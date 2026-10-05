%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the bounded pending store behind stream-status
%%% notifications (#4632), closed-state behaviour.
%%%
%%% yuzu_gw_upstream used to drop a NotifyStreamStatus when 10 were already in
%%% flight and when the circuit breaker was open. It now holds them in
%%% yuzu_gw_notify_queue (key {agent, session, home}, latest event wins, FIFO by
%%% first insertion, cap notify_pending_max keys) and drains them as capacity
%%% returns. These tests pin that wiring:
%%%   - selection order, coalescing, the cap, the two-sessions case
%%%   - an open or half_open breaker holds; a close drains first in first out
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
                   registration_replay_spacing_ms,
                   circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms]).

-define(INFLIGHT_MAX, 10).
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
      t("a circuit that is open holds notifications, closing it drains them first in first out",
        fun open_circuit_holds_then_close_drains_in_order/0),
      t("a half_open circuit holds notifications until a probe RPC closes it",
        fun half_open_circuit_holds_until_closed/0),
      t("the notify_queue gauges follow a burst and settle at zero, with a zero emit from init",
        fun gauges_follow_a_burst/0),
      t("format_status shows notify_pending_len and never the held events",
        fun format_status_shows_a_count_not_the_events/0),
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
        fun env_valid_is_kept/0)
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

setup(Env) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    %% Fail loud at the boundary if a prior module leaked the real upstream.
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
    await_dead([W || {W} <- ets:tab2list(Workers)]),
    catch telemetry:detach(?TELEMETRY_HANDLER),
    meck:unload(grpcbox_client),
    clear_registry(),
    ets:delete(Log),
    ets:delete(Workers),
    lists:foreach(fun({Key, {ok, V}}) -> application:set_env(yuzu_gw, Key, V);
                     ({Key, undefined}) -> application:unset_env(yuzu_gw, Key)
                  end, Prev),
    persistent_term:erase(?CTXK),
    persistent_term:erase(?SUBK),
    persistent_term:erase(?FIELDSK),
    ok.

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
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 2000).

release_parked(Workers) ->
    [W ! release || {W} <- ets:tab2list(Workers)],
    ok.

await_dead(Pids) ->
    Refs = [erlang:monitor(process, P) || P <- Pids],
    lists:foreach(fun(Ref) ->
                      receive {'DOWN', Ref, process, _, _} -> ok
                      after ?AWAIT_MS -> ok
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

%% ProxyMode is what every RPC other than NotifyStreamStatus answers: `ok' or
%% `fail' (a transport error, which feeds the breaker).
mock(ProxyMode) ->
    meck:expect(grpcbox_client, unary, fun(_Ctx, Path, Req, _Def, _Opts) ->
        case lists:last(binary:split(Path, <<"/">>, [global])) of
            <<"NotifyStreamStatus">> ->
                notify_rpc(Req);
            _Other when ProxyMode =:= ok ->
                notify({proxied, Path}),
                {ok, #{}, #{}};
            _Other ->
                {error, connection_refused}
        end
    end).

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
    %% The reset timer is far away: half_open by hand, then a good RPC closes.
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    mock(ok),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({2, ?INFLIGHT_MAX}, last_gauge()),
    %% The first ten held keys went out (their entry order is not fixed), then
    %% the rest one slot at a time, in order.
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
    ?assertEqual(0, count(?EV_DROPPED)),
    open_and_release_all(),
    await_until(fun() -> last_gauge() =:= {0, 0} end).

half_open_circuit_holds_until_closed() ->
    watch(),
    trip_breaker(),
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    Keys = [agent(I) || I <- lists:seq(1, 12)],
    [cast_connected(Id) || Id <- Keys],
    sync(),
    ?assertEqual({12, 0}, last_gauge()),
    ?assertEqual(0, map_size(up_get(notify_pids))),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, count(?EV_DROPPED)),
    %% A failed RPC reopens it: still held.
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({12, 0}, last_gauge()),
    %% half_open again, a good RPC closes it, and the held keys drain.
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    mock(ok),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    First = await_entered(?INFLIGHT_MAX),
    ?assertEqual(lists:sort(lists:sublist(Keys, ?INFLIGHT_MAX)),
                 lists:sort([maps:get(agent_id, Req) || {_, Req} <- First])),
    ?assertEqual({2, ?INFLIGHT_MAX}, last_gauge()),
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
