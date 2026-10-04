%%%-------------------------------------------------------------------
%%% @doc Tests for the per-connection session cap (#1197): one connection may
%%% hold at most `max_sessions_per_connection' (default 8) sessions of other
%%% agents, pending plus live, not counting the agent being (re)registered.
%%%
%%% The registry is real; a connection key is any term (here an atom or a
%%% process id). Covered:
%%%   - the live insert and store_pending/2 both refuse the 9th distinct agent
%%%     with {error, session_limit}, accept the same agent again, and leave a
%%%     different connection alone;
%%%   - every way a session leaves (deregister, supersede, a dead process, a
%%%     pending take or expiry) releases the count: 100 cycles end at exactly the
%%%     right count and the quota then admits exactly what is left;
%%%   - the refusal is counted once per refusal, and logged as one WARN per
%%%     second that names the cap and no id;
%%%   - Register answers UNAVAILABLE before it proxies upstream, and an agent
%%%     process the registry refuses ends with {error, session_limit};
%%%   - a Register repeated with one agent id (no Subscribe) replaces its own
%%%     pending row and is never refused, so the pending table cannot grow;
%%%   - the check and the claim of a slot are one step: 200 concurrent Registers
%%%     admit at most the cap and only the admitted ones reach the server, a
%%%     reservation is released when the proxied Register fails and by the TTL
%%%     sweep, and a reservation held is the admission (no second check).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_session_cap_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([handle_event/4, log/2]).

-define(CAP, 8).
-define(HOLDERS_TAB, yuzu_gw_session_cap_tests_holders).
-define(EVENTS_TAB, yuzu_gw_session_cap_tests_events).
-define(EV_HANDLER, yuzu_gw_session_cap_tests_handler).
-define(LOG_HANDLER, yuzu_gw_session_cap_tests_log).
-define(CTX_KEY, yuzu_test_conn_key).
-define(CONN_INDEX_KEY, {yuzu_gw_registry, conn_index}).

cap_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"live: the 9th distinct agent on a connection is refused, the same agent and another connection are not",
       fun live_cap/0},
      {"pending: the 9th distinct agent's Register row is refused and not stored",
       fun pending_cap/0},
      {"pending plus live count together, an agent with both counts twice for the others",
       fun pending_and_live_count_together/0},
      {"an expired pending row is not counted",
       fun expired_pending_not_counted/0},
      {"a session with no connection key is never counted",
       fun undefined_key_never_counted/0},
      {"every release path frees the count: 100 cycles end at the right count",
       {timeout, 60, fun churn_releases_every_count/0}},
      {"a session id registered again under another connection moves its count",
       fun same_session_id_moves_between_connections/0},
      {"a dead agent process frees its slot",
       fun dead_process_frees_slot/0},
      {"the refusal is counted each time and logged once a second, naming the cap only",
       fun refusal_counter_and_log/0},
      {"max_sessions_per_connection: valid kept, invalid warns naming the key and takes 8",
       fun cap_configuration/0},
      {"Register answers UNAVAILABLE before it proxies upstream",
       fun register_handler_refuses_before_upstream/0},
      {"Subscribe answers UNAVAILABLE before it starts an agent process",
       fun subscribe_handler_refuses_before_start/0},
      {"an agent process the registry refuses ends with session_limit and leaves nothing behind",
       fun agent_process_refused/0},
      {"a Register repeated 40 times with one agent id leaves one pending row and is never refused",
       fun repeated_register_supersedes_pending/0},
      {"the same agent id repeating Register cannot evict another connection's or agent's admissibility",
       fun repeated_register_leaves_only_newest_session_admissible/0},
      {"200 concurrent reservations on one connection admit exactly the cap",
       fun concurrent_reservations_admit_the_cap/0},
      {"200 concurrent Registers proxy at most the cap upstream and store one row per admitted",
       {timeout, 60, fun concurrent_registers_proxy_at_most_cap/0}},
      {"a failed proxied Register releases its reservation",
       fun failed_proxy_releases_reservation/0},
      {"an expired reservation is not counted and the sweep removes it",
       fun expired_reservation_not_counted_and_swept/0},
      {"a reservation held is the admission, one that is gone is checked",
       fun reservation_is_the_admission/0},
      {"the registry dying between the row and its commit answers registry_unavailable, no crash",
       fun registry_dies_before_commit/0},
      {"two rows of one agent, committed in either order, leave one row and a commit of a gone row answers an error",
       fun commit_orders_leave_one_row/0},
      {"a commit of a row a newer commit removed answers superseded, a lost row of an unknown agent registry_unavailable",
       fun commit_of_removed_row_is_superseded/0},
      {"a superseded Register is answered UNAVAILABLE without a WARN, a failing registry INTERNAL with one",
       fun handler_superseded_register_is_retryable/0},
      {"2 and 20 concurrent Registers of one agent id leave exactly one pending row, 200 times",
       {timeout, 120, fun concurrent_same_agent_registers_leave_one_row/0}},
      {"the rows of a connection that dies are gone at once, other connections' rows stay",
       fun closed_connection_rows_dropped/0},
      {"a connection already dead when its row is stored loses the row too",
       fun dead_connection_rows_dropped/0},
      {"one monitor per connection, and none left after 100 connection cycles",
       {timeout, 60, fun connection_monitors_do_not_leak/0}},
      {"the sweep releases the monitor of a live connection with no row left, and keeps the others",
       fun sweep_releases_idle_connection_monitors/0},
      {"the pending index: the cap decision equals a count of the table after random operations on 5 connections",
       {timeout, 120, fun pending_index_matches_table/0}},
      {"a registry round trip stays under 5 ms with 10000 pending rows on other connections",
       {timeout, 120, fun round_trip_with_many_rows_elsewhere/0}}
     ]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = {application:get_env(yuzu_gw, max_sessions_per_connection),
            application:get_env(yuzu_gw, dead_connection_grace_ms)},
    application:unset_env(yuzu_gw, max_sessions_per_connection),
    %% The cases below that pin the removal of a closed connection's rows run with
    %% no grace; the grace cases restart the registry with their own value.
    application:set_env(yuzu_gw, dead_connection_grace_ms, 0),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    catch ets:delete(?EVENTS_TAB),
    ?EVENTS_TAB = ets:new(?EVENTS_TAB, [named_table, public, ordered_set]),
    catch ets:delete(?HOLDERS_TAB),
    ?HOLDERS_TAB = ets:new(?HOLDERS_TAB, [named_table, public, set]),
    catch telemetry:detach(?EV_HANDLER),
    ok = telemetry:attach(?EV_HANDLER, [yuzu, gw, session, limit_rejected],
                          fun ?MODULE:handle_event/4, none),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{table => ?EVENTS_TAB}, level => all}),
    Prev.

cleanup({PrevCap, PrevGrace}) ->
    %% The stand-in agent processes joined pg groups under the registry that is
    %% being replaced: stop them, or a later module that registers the same
    %% agent id would find them through lookup/1's pg fallback.
    kill_holders(),
    catch logger:remove_handler(?LOG_HANDLER),
    catch telemetry:detach(?EV_HANDLER),
    catch ets:delete(?EVENTS_TAB),
    restore_env(max_sessions_per_connection, PrevCap),
    restore_env(dead_connection_grace_ms, PrevGrace),
    catch meck:unload([yuzu_gw_conn, yuzu_gw_upstream]),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    ok.

restore_env(Key, {ok, V})   -> application:set_env(yuzu_gw, Key, V);
restore_env(Key, undefined) -> application:unset_env(yuzu_gw, Key).

handle_event(_Event, #{count := N}, _Meta, _Config) ->
    true = ets:insert(?EVENTS_TAB, {erlang:unique_integer([monotonic]), refused, N}),
    ok.

%% logger handler callback: WARN and above only are recorded, as text.
log(#{level := Level} = Event, #{config := #{table := Tab}}) when Level =:= warning;
                                                                  Level =:= error ->
    Text = unicode:characters_to_binary(logger_formatter:format(Event, #{})),
    catch ets:insert(Tab, {erlang:unique_integer([monotonic]), log, Text}),
    ok;
log(_Event, _Config) ->
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

live_cap() ->
    C1 = conn(), C2 = conn(),
    Held = [bind(agent(I), session(I), C1) || I <- lists:seq(1, ?CAP)],
    ?assertEqual(?CAP, length(Held)),
    %% The 9th distinct agent is refused and not registered.
    P9 = holder(),
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(9), P9, session(9), [], <<>>, #{}, C1)),
    ?assertEqual([], ets:lookup(yuzu_gw_agents, agent(9))),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(session(9))),
    ?assertEqual(1, refused()),
    %% The same agent registering again replaces its own session at the cap.
    P3b = holder(),
    ?assertEqual(ok, yuzu_gw_registry:register_agent(agent(3), P3b, <<"cap-s-3b">>, [], <<>>, #{}, C1)),
    ?assertMatch({ok, #{pid := P3b}}, yuzu_gw_registry:lookup_session(<<"cap-s-3b">>)),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(session(3))),
    ?assertEqual(?CAP, conn_count(C1)),
    %% A different connection has its own quota.
    [?assertEqual(ok, yuzu_gw_registry:register_agent(agent(100 + I), holder(), session(100 + I),
                                                      [], <<>>, #{}, C2))
     || I <- lists:seq(1, ?CAP)],
    ?assertEqual(1, refused()),
    %% A refused registration leaves the agent's older one in place.
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(9), P9, session(9), [], <<>>, #{}, C1)),
    ?assertEqual(?CAP, conn_count(C1)),
    %% Releasing one slot admits exactly one more.
    yuzu_gw_registry:deregister_agent(agent(1), hd(Held), session(1)),
    barrier(),
    ?assertEqual(ok, yuzu_gw_registry:register_agent(agent(9), P9, session(9), [], <<>>, #{}, C1)),
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(10), holder(), session(10), [], <<>>, #{}, C1)).

pending_cap() ->
    C1 = conn(), C2 = conn(),
    [?assertEqual(ok, yuzu_gw_registry:store_pending(session(I), info(agent(I), C1)))
     || I <- lists:seq(1, ?CAP)],
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(session(9), info(agent(9), C1))),
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(session(9))),
    ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(session(9))),
    ?assertEqual(1, refused()),
    %% The same agent registering again (a new session) is never refused.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-1b">>, info(agent(1), C1))),
    %% Another connection is unaffected.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(50), info(agent(50), C2))),
    %% A Subscribe (take_pending) frees a slot.
    ?assertMatch(#{agent_id := _}, yuzu_gw_registry:take_pending(session(2))),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(9), info(agent(9), C1))),
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(session(10), info(agent(10), C1))).

pending_and_live_count_together() ->
    C = conn(),
    [bind(agent(I), session(I), C) || I <- lists:seq(1, 4)],
    [?assertEqual(ok, yuzu_gw_registry:store_pending(session(I), info(agent(I), C)))
     || I <- lists:seq(5, ?CAP)],
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(session(9), info(agent(9), C))),
    %% An agent that has a live session and registers again is excluded from its
    %% own count, so it is admitted at the cap.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-1b">>, info(agent(1), C))),
    %% It now holds a live row and a pending row: two rows for everyone else, so
    %% another agent registering again is refused at the cap (rows are counted,
    %% not agents: each row can carry a snapshot).
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(<<"cap-s-5b">>, info(agent(5), C))),
    %% The live insert counts the pending rows too.
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(9), holder(), session(9), [], <<>>, #{}, C)),
    %% Subscribe takes the pending row: the count is back to the cap and the
    %% agent that was refused is admitted, replacing its own pending row.
    ?assertMatch(#{agent_id := _}, yuzu_gw_registry:take_pending(<<"cap-s-1b">>)),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-5b">>, info(agent(5), C))),
    ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(session(5))),
    ?assertEqual(8, conn_count(C) + length(pending_rows(C))).

expired_pending_not_counted() ->
    C = conn(),
    %% A row stored long ago (the pending TTL is 2 minutes, the sweep a minute).
    Old = erlang:monotonic_time(millisecond) - 10 * 60 * 1000,
    [begin
         ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), C)),
         true = ets:update_element(yuzu_gw_pending, session(I), {3, Old})
     end || I <- lists:seq(1, ?CAP)],
    ?assertEqual(?CAP, length(pending_rows(C))),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(9), info(agent(9), C))),
    ?assertEqual(0, refused()).

undefined_key_never_counted() ->
    [?assertEqual(ok, yuzu_gw_registry:register_agent(agent(I), holder(), session(I), [], <<>>))
     || I <- lists:seq(1, 3 * ?CAP)],
    [?assertEqual(ok, yuzu_gw_registry:store_pending(session(I), info(agent(I), undefined)))
     || I <- lists:seq(100, 100 + 3 * ?CAP)],
    ?assertEqual(0, refused()).

%% 100 cycles of the ways a session ends or is replaced, on one connection, with
%% three agents held throughout: the count ends at exactly three, and the quota
%% admits exactly five more.
churn_releases_every_count() ->
    C = conn(),
    Keep = [bind(agent(I), session(I), C) || I <- lists:seq(1, 3)],
    ?assertEqual(3, conn_count(C)),
    [begin
         A = agent(1000 + I), S = session(1000 + I),
         case I rem 4 of
             0 ->  %% register then fenced deregister
                 P = bind(A, S, C),
                 yuzu_gw_registry:deregister_agent(A, P, S);
             1 ->  %% supersede: same agent id, new process and session, twice
                 P1 = bind(A, S, C),
                 P2 = bind(A, <<S/binary, "-2">>, C),
                 P3 = bind(A, <<S/binary, "-3">>, C),
                 ?assertNotEqual(P1, P2),
                 yuzu_gw_registry:deregister_agent(A, P3, <<S/binary, "-3">>);
             2 ->  %% unfenced deregister
                 _ = bind(A, S, C),
                 yuzu_gw_registry:deregister_agent(A);
             3 ->  %% a pending row taken by Subscribe, then registered and removed
                 ok = yuzu_gw_registry:store_pending(S, info(A, C)),
                 _ = yuzu_gw_registry:take_pending(S),
                 P = bind(A, S, C),
                 yuzu_gw_registry:deregister_agent(A, P, S)
         end,
         barrier()
     end || I <- lists:seq(1, 100)],
    ?assertEqual(3, conn_count(C)),
    ?assertEqual(3, length([x || {_, _, _} <- conn_entries(C)])),
    ?assertEqual(0, refused()),
    %% Exactly the quota that is left.
    [?assertEqual(ok, yuzu_gw_registry:register_agent(agent(2000 + I), holder(), session(2000 + I),
                                                      [], <<>>, #{}, C))
     || I <- lists:seq(1, ?CAP - 3)],
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(3000), holder(), session(3000), [], <<>>, #{}, C)),
    ?assertEqual(?CAP, conn_count(C)),
    %% The index holds no entry of a session that is gone.
    Live = lists:sort([S || {_, _, S} <- conn_entries(C)]),
    Rows = lists:sort([S || {S, _, _, K} <- ets:tab2list(yuzu_gw_sessions), K =:= C]),
    ?assertEqual(Rows, Live),
    _ = Keep.

%% The session index is keyed by session id, so registering an id again replaces
%% its row: the per-connection entry of the old row must go with it.
same_session_id_moves_between_connections() ->
    C1 = conn(), C2 = conn(),
    [bind(agent(I), session(I), C1) || I <- lists:seq(1, ?CAP)],
    ?assertEqual(?CAP, conn_count(C1)),
    %% Agent 1's session id is registered again, by another agent, on C2.
    _ = bind(agent(500), session(1), C2),
    ?assertEqual(1, conn_count(C2)),
    ?assertEqual(?CAP - 1, conn_count(C1)),
    ?assertEqual(ok, yuzu_gw_registry:register_agent(agent(501), holder(), session(501),
                                                     [], <<>>, #{}, C1)).

dead_process_frees_slot() ->
    C = conn(),
    Pids = [bind(agent(I), session(I), C) || I <- lists:seq(1, ?CAP)],
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(9), holder(), session(9), [], <<>>, #{}, C)),
    Victim = hd(Pids),
    Mon = monitor(process, Victim),
    exit(Victim, kill),
    receive {'DOWN', Mon, process, Victim, _} -> ok after 2000 -> error(not_dead) end,
    %% The registry handles its own DOWN asynchronously: wait for the release.
    ok = wait_until(fun() -> conn_count(C) =:= ?CAP - 1 end),
    ?assertEqual(ok, yuzu_gw_registry:register_agent(agent(9), holder(), session(9), [], <<>>, #{}, C)).

refusal_counter_and_log() ->
    C = conn(),
    [bind(agent(I), session(I), C) || I <- lists:seq(1, ?CAP)],
    Secret = <<"agent-id-must-not-be-logged-77">>,
    [?assertEqual({error, session_limit},
                  yuzu_gw_registry:register_agent(Secret, holder(), <<"secret-session-id">>,
                                                  [], <<>>, #{}, C))
     || _ <- lists:seq(1, 5)],
    ?assertEqual(5, refused()),
    Lines = [T || {_, log, T} <- ets:tab2list(?EVENTS_TAB),
                  binary:match(T, <<"max_sessions_per_connection">>) =/= nomatch],
    ?assertEqual(1, length(Lines)),
    [Line] = Lines,
    ?assertNotEqual(nomatch, binary:match(Line, <<"8 agent sessions">>)),
    ?assertEqual(nomatch, binary:match(Line, Secret)),
    ?assertEqual(nomatch, binary:match(Line, <<"secret-session-id">>)).

cap_configuration() ->
    Cap = fun() -> persistent_term:get({yuzu_gw_registry, max_sessions_per_connection}) end,
    Restart = fun(V) ->
        application:set_env(yuzu_gw, max_sessions_per_connection, V),
        yuzu_gw_test_registry:ensure_fresh(),
        unlink(whereis(yuzu_gw_registry))
    end,
    ?assertEqual(8, Cap()),
    [begin
         Restart(V),
         ?assertEqual(V, Cap())
     end || V <- [1, 2, 1000]],
    %% Cap 2 is honoured.
    Restart(2),
    C = conn(),
    bind(agent(1), session(1), C),
    bind(agent(2), session(2), C),
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(3), holder(), session(3), [], <<>>, #{}, C)),
    [begin
         ets:delete_all_objects(?EVENTS_TAB),
         Restart(Bad),
         ?assertEqual(8, Cap()),
         Warned = [T || {_, log, T} <- ets:tab2list(?EVENTS_TAB),
                        binary:match(T, <<"max_sessions_per_connection">>) =/= nomatch],
         ?assertEqual(1, length(Warned))
     end || Bad <- [0, 1001, -3, <<"8">>, 2.5, many]].

register_handler_refuses_before_upstream() ->
    mock_handler_deps(),
    Reg = fun(Conn, I) ->
        yuzu_gw_agent_service:register(ctx_with(Conn),
                                       #{info => #{agent_id => agent(I), hostname => <<"h">>}})
    end,
    [?assertMatch({ok, _, _}, Reg(conn_a, I)) || I <- lists:seq(1, ?CAP)],
    ?assertEqual(?CAP, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')),
    Refused = Reg(conn_a, 9),
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}}, Refused),
    {grpc_error, {_, Message}} = Refused,
    ?assertEqual(nomatch, binary:match(Message, agent(9))),
    %% Nothing reached the server and nothing was stored.
    ?assertEqual(?CAP, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')),
    ?assertEqual(1, refused()),
    %% The same agent again, and another connection, are served.
    ?assertMatch({ok, _, _}, Reg(conn_a, 3)),
    ?assertMatch({ok, _, _}, Reg(conn_b, 9)),
    ?assertEqual(?CAP + 2, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')).

%% No agent supervisor runs: a Subscribe that reached start_agent/1 would answer
%% INTERNAL (agent_sup_unavailable), so UNAVAILABLE proves the quota was asked
%% first, and no process was started to crash.
subscribe_handler_refuses_before_start() ->
    mock_handler_deps(),
    ok = meck:expect(yuzu_gw_conn, key_from_stream, fun(_State) -> conn_a end),
    case whereis(yuzu_gw_agent_sup) of
        undefined -> ok;
        Old -> yuzu_gw_test_registry:stop_agent_sup(Old)
    end,
    [bind(agent(I), session(I), conn_a) || I <- lists:seq(1, ?CAP)],
    %% Register's row for a ninth agent, written directly (store_pending/2 would
    %% refuse it) as if it had been stored before the other eight arrived.
    S = session(9),
    true = ets:insert(yuzu_gw_pending, {S, info(agent(9), conn_a),
                                        erlang:monotonic_time(millisecond)}),
    ok = meck:new(grpcbox_stream, [non_strict, no_link]),
    try
        ok = meck:expect(grpcbox_stream, ctx,
                         fun(_State) ->
                             ctx:set(ctx:background(), md_incoming_key,
                                     #{<<"x-yuzu-session-id">> => S})
                         end),
        Result = try yuzu_gw_agent_service:subscribe(make_ref(), not_a_stream_state)
                 catch throw:T -> {thrown, T}
                 end,
        ?assertMatch({thrown, {grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}}}, Result),
        ?assertEqual(1, refused()),
        %% No error-level report (a crash of a started agent process would be one).
        ?assertEqual([], [T || {_, log, T} <- ets:tab2list(?EVENTS_TAB),
                               binary:match(T, <<"crasher">>) =/= nomatch])
    after
        meck:unload(grpcbox_stream)
    end.

agent_process_refused() ->
    mock_handler_deps(),
    {ok, Sup} = yuzu_gw_agent_sup:start_link(),
    unlink(Sup),
    try
        C = conn(),
        Held = [bind(agent(I), session(I), C) || I <- lists:seq(1, ?CAP)],
        Args = #{agent_id => agent(9), session_id => session(9), stream_pid => self(),
                 agent_info => #{hostname => <<"h">>}, register_req => #{},
                 peer_addr => <<"p">>, conn_key => C},
        ?assertEqual({error, session_limit}, yuzu_gw_agent_sup:start_agent(Args)),
        ?assertEqual(0, yuzu_gw_agent_sup:count()),
        ?assertEqual([], ets:lookup(yuzu_gw_agents, agent(9))),
        ?assertEqual(1, refused()),
        %% The same agent id as one held: accepted.
        {ok, Pid} = yuzu_gw_agent_sup:start_agent(Args#{agent_id => agent(2),
                                                        session_id => <<"cap-s-2b">>}),
        ?assert(is_pid(Pid)),
        ?assertEqual(1, yuzu_gw_agent_sup:count()),
        ?assertEqual(?CAP, length(Held))
    after
        yuzu_gw_test_registry:stop_agent_sup(Sup)
    end.

%% One agent id repeating Register with no Subscribe, the shape of the bypass:
%% every Register stored a pending row that nothing replaced.
repeated_register_supersedes_pending() ->
    C1 = conn(), C2 = conn(),
    %% Seven other agents hold the connection one below the cap.
    [bind(agent(I), session(I), C1) || I <- lists:seq(1, ?CAP - 1)],
    Sessions = [session(1000 + I) || I <- lists:seq(1, 40)],
    [?assertEqual(ok, yuzu_gw_registry:store_pending(S, info(agent(99), C1))) || S <- Sessions],
    %% Never refused, and one pending row (the newest) for the agent.
    ?assertEqual(0, refused()),
    ?assertEqual([lists:last(Sessions)], pending_rows(C1)),
    ?assertEqual([], reserved_rows()),
    ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(hd(Sessions))),
    ?assertMatch(#{agent_id := _}, yuzu_gw_registry:take_pending(lists:last(Sessions))),
    ?assertEqual([], pending_rows(C1)),
    %% Control: the agent holds a slot while its row is pending (cap 8 = 7 + it).
    ok = yuzu_gw_registry:store_pending(<<"cap-s-99">>, info(agent(99), C1)),
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(<<"cap-s-98">>, info(agent(98), C1))),
    ?assertEqual(1, refused()),
    %% Another connection is unaffected, and the same agent id on it has its own rows.
    [?assertEqual(ok, yuzu_gw_registry:store_pending(S, info(agent(99), C2))) || S <- Sessions],
    ?assertEqual([lists:last(Sessions)], pending_rows(C2)),
    ?assertEqual([<<"cap-s-99">>], pending_rows(C1)),
    ?assertEqual(1, refused()),
    %% Pending rows of other agents are not touched by the supersede.
    ok = yuzu_gw_registry:store_pending(<<"cap-s-50">>, info(agent(50), C2)),
    ok = yuzu_gw_registry:store_pending(<<"cap-s-99b">>, info(agent(99), C2)),
    ?assertEqual([<<"cap-s-50">>, <<"cap-s-99b">>], lists:sort(pending_rows(C2))).

%% The heartbeat admission side of the same bypass: only the newest session of
%% the repeating agent is admissible, so what a connection can carry into the
%% heartbeat buffer is bounded by its rows (admission only: the buffer keys its
%% entries by admitted session id, and this suite does not start it).
repeated_register_leaves_only_newest_session_admissible() ->
    mock_handler_deps(),
    Attacker = conn_a, Victim = conn_b,
    ok = yuzu_gw_registry:store_pending(<<"victim-s">>, info(agent(1), Victim)),
    Sessions = [session(2000 + I) || I <- lists:seq(1, 50)],
    [ok = yuzu_gw_registry:store_pending(S, info(agent(2), Attacker)) || S <- Sessions],
    Check = fun(Conn, S) -> yuzu_gw_heartbeat_admission:check(ctx_with(Conn), S) end,
    Admissible = [S || S <- Sessions, Check(Attacker, S) =:= ok],
    ?assertEqual([lists:last(Sessions)], Admissible),
    [?assertEqual({reject, unknown_session}, Check(Attacker, S)) || S <- lists:droplast(Sessions)],
    %% The victim's session is untouched, and still bound to its own connection.
    ?assertEqual(ok, Check(Victim, <<"victim-s">>)),
    ?assertEqual({reject, connection_mismatch}, Check(Attacker, <<"victim-s">>)).

%% 200 processes reserve at once on one connection with distinct agent ids.
concurrent_reservations_admit_the_cap() ->
    C = conn(),
    Parent = self(),
    Pids = [spawn_link(fun() ->
                Parent ! {reserved, self(), yuzu_gw_registry:reserve_session(C, agent(I))}
            end) || I <- lists:seq(1, 200)],
    Results = [receive {reserved, P, R} -> R after 5000 -> error(timeout) end || P <- Pids],
    Admitted = [Ref || {ok, Ref} <- Results],
    ?assertEqual(?CAP, length(Admitted)),
    ?assertEqual(200 - ?CAP, length([x || {error, session_limit} <- Results])),
    ?assertEqual(200 - ?CAP, refused()),
    ?assertEqual(?CAP, length(reserved_rows())),
    %% Each admitted reservation becomes exactly one pending row: no second slot.
    Agents = [agent(I) || I <- lists:seq(1, 200)],
    [begin
         Info = (info(A, C)),
         ok = yuzu_gw_registry:store_pending(<<"cap-conc-", A/binary>>, Info, Ref)
     end || {{ok, Ref}, A} <- lists:zip(Results, Agents), is_reference(Ref)],
    ?assertEqual(?CAP, length(pending_rows(C))),
    ?assertEqual([], reserved_rows()),
    %% The connection is full and stays full.
    ?assertEqual({error, session_limit}, yuzu_gw_registry:reserve_session(C, agent(500))).

%% The same at the handler: only the admitted Registers reach the server, even
%% while they are all in flight, and the rows stored are the ones admitted.
concurrent_registers_proxy_at_most_cap() ->
    mock_handler_deps(),
    Parent = self(),
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         Parent ! {in_proxy, self()},
                         receive {release, Parent} -> ok after 20000 -> error(not_released) end,
                         {ok, #{session_id => <<"reg-session-", Id/binary>>}}
                     end),
    Procs = [spawn_link(fun() ->
                 Reply = yuzu_gw_agent_service:register(
                             ctx_with(conn_a),
                             #{info => #{agent_id => agent(I), hostname => <<"h">>}}),
                 Parent ! {replied, I, Reply}
             end) || I <- lists:seq(1, 200)],
    %% Every process either replies (refused) or is blocked upstream, so a Register
    %% over the cap that was proxied would be one refusal short: the receive times out.
    Refusals = [receive {replied, I, R} -> {I, R} after 5000 -> error(timeout) end
                || _ <- lists:seq(1, 200 - ?CAP)],
    [?assertMatch({_, {grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}}}, R) || R <- Refusals],
    InProxy = [receive {in_proxy, P} -> P after 5000 -> error(timeout) end
               || _ <- lists:seq(1, ?CAP)],
    %% All 192 refusals are in, the 8 admitted are still blocked upstream, and the
    %% slots are held by reservations.
    ?assertEqual(?CAP, length(reserved_rows())),
    [P ! {release, Parent} || P <- InProxy],
    Oks = [receive {replied, I, R} -> {I, R} after 10000 -> error(timeout) end
           || _ <- lists:seq(1, ?CAP)],
    [?assertMatch({_, {ok, _, _}}, R) || R <- Oks],
    ?assertEqual(200, length(Procs)),
    ?assertEqual(?CAP, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')),
    ?assertEqual(?CAP, length(pending_rows(conn_a))),
    ?assertEqual([], reserved_rows()),
    ?assertEqual(200 - ?CAP, refused()).

failed_proxy_releases_reservation() ->
    mock_handler_deps(),
    Reg = fun(Conn, I) ->
        yuzu_gw_agent_service:register(ctx_with(Conn),
                                       #{info => #{agent_id => agent(I), hostname => <<"h">>}})
    end,
    %% More failures than the cap: each releases the slot it claimed.
    Failures = [{error, upstream_down}, {ok, not_a_map}],
    [begin
         ok = meck:expect(yuzu_gw_upstream, proxy_register, fun(_) -> Failure end),
         [?assertMatch({grpc_error, {?GRPC_STATUS_INTERNAL, _}}, Reg(conn_a, I))
          || I <- lists:seq(1, 2 * ?CAP)],
         ?assertEqual([], reserved_rows())
     end || Failure <- Failures],
    ?assertEqual(0, refused()),
    ?assertEqual([], pending_rows(conn_a)),
    %% Control: with a working upstream the connection admits exactly the cap.
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         {ok, #{session_id => <<"reg-session-", Id/binary>>}}
                     end),
    [?assertMatch({ok, _, _}, Reg(conn_a, I)) || I <- lists:seq(1, ?CAP)],
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}}, Reg(conn_a, 9)),
    ?assertEqual([], reserved_rows()).

expired_reservation_not_counted_and_swept() ->
    C = conn(),
    Refs = [begin {ok, Ref} = yuzu_gw_registry:reserve_session(C, agent(I)), Ref end
            || I <- lists:seq(1, ?CAP)],
    ?assertEqual({error, session_limit}, yuzu_gw_registry:reserve_session(C, agent(9))),
    %% Every reservation is made old: the pending TTL is 2 minutes.
    Old = erlang:monotonic_time(millisecond) - 10 * 60 * 1000,
    [true = ets:update_element(yuzu_gw_pending, {reserved, Ref}, {3, Old}) || Ref <- Refs],
    {ok, Fresh} = yuzu_gw_registry:reserve_session(C, agent(9)),
    %% The sweep removes the expired ones and keeps the fresh one.
    yuzu_gw_registry ! sweep_pending,
    barrier(),
    ?assertEqual([{reserved, Fresh}], reserved_rows()),
    %% An expired reservation is no admission either: the cap is checked again.
    [{ok, _} = yuzu_gw_registry:reserve_session(C, agent(10 + I)) || I <- lists:seq(1, ?CAP - 1)],
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(<<"cap-late">>, info(agent(50), C), hd(Refs))),
    ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(<<"cap-late">>)).

reservation_is_the_admission() ->
    C = conn(),
    {ok, Ref} = yuzu_gw_registry:reserve_session(C, agent(1)),
    %% Other agents' rows reach the cap while the reservation is held (stored with
    %% the cap lifted: this is the state the reservation protects against).
    CapKey = {yuzu_gw_registry, max_sessions_per_connection},
    persistent_term:put(CapKey, 100),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), C))
     || I <- lists:seq(2, ?CAP + 1)],
    persistent_term:put(CapKey, ?CAP),
    %% A caller that did not reserve is refused ...
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:store_pending(session(1), info(agent(1), C))),
    ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(session(1))),
    %% ... the one that holds the reservation is stored, once, and it is consumed.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-1r">>, info(agent(1), C), Ref)),
    ?assertMatch({ok, C}, yuzu_gw_registry:lookup_pending_session(<<"cap-s-1r">>)),
    ?assertEqual([], reserved_rows()),
    %% A released reservation is gone: its slot is free again.
    {ok, Ref2} = yuzu_gw_registry:reserve_session(conn(), agent(1)),
    ?assertEqual(ok, yuzu_gw_registry:release_session(Ref2)),
    ?assertEqual(ok, yuzu_gw_registry:release_session(Ref2)),
    ?assertEqual(ok, yuzu_gw_registry:release_session(undefined)),
    ?assertEqual([], reserved_rows()).

%% The registry goes away after the row is stored and before it is committed: the
%% table is gone with it, and dropping the uncommitted row must not raise.
registry_dies_before_commit() ->
    Reg = whereis(yuzu_gw_registry),
    ok = meck:new(yuzu_gw_safe_call, [passthrough, no_link]),
    try
        ok = meck:expect(yuzu_gw_safe_call, call,
                         fun(yuzu_gw_registry, {commit_pending, _, _, _, _}, _Timeout, Error) ->
                                 Mon = monitor(process, Reg),
                                 exit(Reg, kill),
                                 receive {'DOWN', Mon, process, Reg, _} -> ok
                                 after 2000 -> error(registry_not_dead)
                                 end,
                                 ok = wait_until(fun() -> ets:info(yuzu_gw_pending) =:= undefined end),
                                 {error, Error};
                            (Server, Request, Timeout, Error) ->
                                 meck:passthrough([Server, Request, Timeout, Error])
                         end),
        ?assertEqual({error, registry_unavailable},
                     yuzu_gw_registry:store_pending(session(1), info(agent(1), conn()))),
        ?assertEqual(1, meck:num_calls(yuzu_gw_safe_call, call,
                                       ['_', {commit_pending, '_', '_', '_', '_'}, '_', '_']))
    after
        meck:unload(yuzu_gw_safe_call)
    end.

%% Two rows of one agent id on one connection (the two Registers' rows are
%% stored, then the registry commits them one at a time): in every order of
%% commits, and for rows stamped apart or in the same millisecond, exactly one row
%% is left, at least one commit answers ok, a commit answering ok is for a row
%% that is there, and a row newer than the committing one is never removed by it.
commit_orders_leave_one_row() ->
    T = erlang:monotonic_time(millisecond),
    Cases = [{Order, Stamps} || Order <- [[1, 2], [2, 1]],
                                Stamps <- [{T, T + 1}, {T, T}]],
    lists:foreach(fun({Order, {T1, T2}}) ->
        C = conn(),
        A = agent(1),
        Sessions = #{1 => session(1), 2 => session(2)},
        {ok, R1} = yuzu_gw_registry:reserve_session(C, A),
        {ok, R2} = yuzu_gw_registry:reserve_session(C, A),
        Refs = #{1 => R1, 2 => R2},
        true = ets:insert(yuzu_gw_pending, {session(1), info(A, C), T1}),
        true = ets:insert(yuzu_gw_pending, {session(2), info(A, C), T2}),
        Replies = [{I, gen_server:call(yuzu_gw_registry,
                                       {commit_pending, maps:get(I, Sessions), C, A,
                                        maps:get(I, Refs)})}
                   || I <- Order],
        %% The caller of a commit that answered an error releases its reservation.
        [yuzu_gw_registry:release_session(R) || R <- maps:values(Refs)],
        Left = pending_rows(C),
        ?assertEqual(1, length(Left), {Order, T1, T2, Replies}),
        ?assertEqual([], reserved_rows()),
        [Survivor] = Left,
        %% A commit that answered ok is for a row that is there at its end or was
        %% replaced by a later commit, never a row that was not there.
        ?assert(lists:member(ok, [R || {_, R} <- Replies]), {Order, Replies}),
        [?assertEqual({error, superseded}, R)
         || {I, R} <- Replies, R =/= ok, maps:get(I, Sessions) =/= Survivor],
        case T1 =:= T2 of
            %% Stamped apart: the newer row survives whatever the order.
            false -> ?assertEqual(session(2), Survivor);
            %% The same stamp: the commit handled last removes the other.
            true  -> ?assertEqual(maps:get(lists:last(Order), Sessions), Survivor)
        end,
        %% Nothing is left to leak into the next case.
        ets:delete(yuzu_gw_pending, Survivor)
    end, Cases),
    %% A commit whose row was never stored (the registry restarted since) is a
    %% registry failure, not a supersede (the agent has no committed row), and
    %% changes nothing: another agent's row stays.
    C2 = conn(),
    true = ets:insert(yuzu_gw_pending, {session(7), info(agent(7), C2), T}),
    ?assertEqual({error, registry_unavailable},
                 gen_server:call(yuzu_gw_registry,
                                 {commit_pending, session(8), C2, agent(8), undefined})),
    ?assertEqual([session(7)], pending_rows(C2)).

%% A commit whose own row was removed by a newer commit of the same agent answers
%% `superseded' (the registry is healthy); a commit of a row that never was there,
%% for an agent with no committed row, still answers `registry_unavailable'.
commit_of_removed_row_is_superseded() ->
    T = erlang:monotonic_time(millisecond),
    C = conn(),
    A = agent(1),
    {ok, R1} = yuzu_gw_registry:reserve_session(C, A),
    {ok, R2} = yuzu_gw_registry:reserve_session(C, A),
    true = ets:insert(yuzu_gw_pending, {session(1), info(A, C), T}),
    %% Stamped far ahead, so that no later row of this case is newer than it.
    true = ets:insert(yuzu_gw_pending, {session(2), info(A, C), T + 60000}),
    ?assertEqual(ok, gen_server:call(yuzu_gw_registry,
                                     {commit_pending, session(1), C, A, R1})),
    ?assertEqual(ok, gen_server:call(yuzu_gw_registry,
                                     {commit_pending, session(2), C, A, R2})),
    ?assertEqual([session(2)], pending_rows(C)),
    %% The first caller's commit comes late: its row is gone, the newer one is there.
    ?assertEqual({error, superseded},
                 gen_server:call(yuzu_gw_registry,
                                 {commit_pending, session(1), C, A, undefined})),
    ?assertEqual([session(2)], pending_rows(C)),
    %% The same for the entry point the handler calls.
    ?assertEqual({error, superseded},
                 yuzu_gw_registry:store_pending(session(3), info(A, C))),
    %% No committed row of this agent: the lost row is a registry failure.
    ?assertEqual({error, registry_unavailable},
                 gen_server:call(yuzu_gw_registry,
                                 {commit_pending, session(9), C, agent(9), undefined})).

%% A Register superseded by a newer one is answered UNAVAILABLE (retryable, the
%% class the session cap uses) and logs no WARN: the registry is healthy. A
%% registry that fails is still INTERNAL with the WARN.
handler_superseded_register_is_retryable() ->
    mock_handler_deps(),
    A = agent(1),
    %% While this Register is proxied upstream a newer one of the same agent
    %% commits (its row is stamped later than the row this Register stores).
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         Newer = <<"newer-session">>,
                         true = ets:insert(yuzu_gw_pending,
                                           {Newer, info(A, conn_a),
                                            erlang:monotonic_time(millisecond) + 60000}),
                         ok = gen_server:call(yuzu_gw_registry,
                                              {commit_pending, Newer, conn_a, A, undefined}),
                         {ok, #{session_id => <<"reg-session-", Id/binary>>}}
                     end),
    Reply = yuzu_gw_agent_service:register(ctx_with(conn_a),
                                           #{info => #{agent_id => A, hostname => <<"h">>}}),
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}}, Reply),
    {grpc_error, {_, Message}} = Reply,
    ?assertNotEqual(nomatch, binary:match(Message, <<"superseded">>)),
    ?assertEqual([], [T || {_, log, T} <- ets:tab2list(?EVENTS_TAB)]),
    ?assertEqual([<<"newer-session">>], pending_rows(conn_a)),
    ?assertEqual([], reserved_rows()),
    %% A registry failure keeps INTERNAL and the WARN.
    ok = meck:new(yuzu_gw_registry, [passthrough, no_link]),
    try
        ok = meck:expect(yuzu_gw_registry, store_pending,
                         fun(_, _, _) -> {error, registry_unavailable} end),
        Failed = yuzu_gw_agent_service:register(ctx_with(conn_b),
                                                #{info => #{agent_id => A, hostname => <<"h">>}}),
        ?assertMatch({grpc_error, {?GRPC_STATUS_INTERNAL, _}}, Failed),
        ?assertEqual(1, length([T || {_, log, T} <- ets:tab2list(?EVENTS_TAB),
                                     binary:match(T, <<"registry_unavailable">>) =/= nomatch]))
    after
        meck:unload(yuzu_gw_registry)
    end.

%% N Registers of one agent id on one connection stored at once, 200 rounds each
%% for N = 2 and N = 20: after the last reply exactly one pending row is left, it
%% is the row of a caller that was answered ok, and every other caller was
%% answered the fixed error. Before the commit checked its own row, two commits
%% each removed the other's row and both answered ok with no row left.
concurrent_same_agent_registers_leave_one_row() ->
    Parent = self(),
    Agent = agent(1),
    lists:foreach(fun({N, Round}) ->
        C = conn(),
        Id = fun(I) -> iolist_to_binary(["capsession-c", integer_to_list(N), "-",
                                         integer_to_list(Round), "-", integer_to_list(I)]) end,
        Pids = [spawn_link(fun() ->
                    receive go -> ok end,
                    Parent ! {done, I, yuzu_gw_registry:store_pending(Id(I), info(Agent, C))}
                end) || I <- lists:seq(1, N)],
        [P ! go || P <- Pids],
        Results = [receive {done, I, R} -> {I, R} after 5000 -> error(timeout) end
                   || _ <- Pids],
        Left = pending_rows(C),
        ?assertEqual(1, length(Left), {N, Round, Results}),
        [Survivor] = Left,
        [Winner] = [I || {I, _} <- Results, Id(I) =:= Survivor],
        ?assertEqual(ok, proplists:get_value(Winner, Results)),
        ?assert(lists:all(fun({_, R}) -> R =:= ok orelse R =:= {error, superseded} end,
                          Results), Results),
        ?assertEqual([], reserved_rows())
    end, [{N, Round} || N <- [2, 20], Round <- lists:seq(1, 200)]).

%% A connection process that exits takes its reservations and pending rows with
%% it, within a bounded wait (the DOWN, not the 2 minute TTL): rows of a live
%% connection and of another one are untouched.
closed_connection_rows_dropped() ->
    Dying = conn(),
    Live = conn(),
    Other = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
     || I <- lists:seq(1, 3)],
    {ok, _} = yuzu_gw_registry:reserve_session(Dying, agent(4)),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Live))
     || I <- lists:seq(11, 12)],
    {ok, LiveRef} = yuzu_gw_registry:reserve_session(Live, agent(13)),
    ok = yuzu_gw_registry:store_pending(session(21), info(agent(21), Other)),
    ?assertEqual(3, length(pending_rows(Dying))),
    ?assertEqual(1, length(reserved_rows_of(Dying))),
    exit(Dying, kill),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] andalso
                                         reserved_rows_of(Dying) =:= [] end)),
    ?assertEqual([session(11), session(12)], lists:sort(pending_rows(Live))),
    ?assertEqual([{reserved, LiveRef}], reserved_rows_of(Live)),
    ?assertEqual([session(21)], pending_rows(Other)),
    %% The count of the dead connection is free: a reconnect starts at zero.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(31), info(agent(31), conn()))).

dead_connection_rows_dropped() ->
    Dead = spawn(fun() -> ok end),
    Mon = monitor(process, Dead),
    receive {'DOWN', Mon, process, Dead, _} -> ok after 2000 -> error(not_dead) end,
    {ok, Ref} = yuzu_gw_registry:reserve_session(Dead, agent(1)),
    ?assert(is_reference(Ref)),
    %% The caller is answered ok, or the fixed error when the DOWN removed its row
    %% before the commit: either way the row does not stay.
    ?assert(lists:member(yuzu_gw_registry:store_pending(session(2), info(agent(2), Dead)),
                         [ok, {error, registry_unavailable}])),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dead) =:= [] andalso
                                         reserved_rows() =:= [] end)),
    %% The registry still serves, and the monitor is spent.
    ?assertEqual(0, monitor_count()).

%% The monitors the registry holds: one per connection however many rows, and
%% none for a connection that is gone or has no row left.
connection_monitors_do_not_leak() ->
    Base = monitor_count(),
    One = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), One))
     || I <- lists:seq(1, ?CAP)],
    ?assertEqual(Base + 1, monitor_count()),
    [begin
         C = conn(),
         [ok = yuzu_gw_registry:store_pending(session(100 + I), info(agent(100 + I), C))
          || I <- lists:seq(1, 3)],
         exit(C, kill),
         ?assertEqual(ok, wait_until(fun() -> pending_rows(C) =:= [] end))
     end || _ <- lists:seq(1, 100)],
    barrier(),
    ?assertEqual(Base + 1, monitor_count()),
    exit(One, kill),
    ?assertEqual(ok, wait_until(fun() -> monitor_count() =:= Base end)).

sweep_releases_idle_connection_monitors() ->
    Base = monitor_count(),
    Idle = [conn() || _ <- lists:seq(1, 5)],
    Busy = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), C))
     || {I, C} <- lists:zip(lists:seq(1, 5), Idle)],
    ok = yuzu_gw_registry:store_pending(session(9), info(agent(9), Busy)),
    ?assertEqual(Base + 6, monitor_count()),
    %% Subscribe takes the five rows of the idle connections.
    [?assertMatch(#{agent_id := _}, yuzu_gw_registry:take_pending(session(I)))
     || I <- lists:seq(1, 5)],
    yuzu_gw_registry ! sweep_pending,
    barrier(),
    ?assertEqual(Base + 1, monitor_count()),
    %% The idle connection stores a row again: monitored again.
    ok = yuzu_gw_registry:store_pending(session(10), info(agent(10), hd(Idle))),
    ?assertEqual(Base + 2, monitor_count()),
    %% And the busy one still loses its row with its process.
    exit(Busy, kill),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Busy) =:= [] end)).

%% Random reserve / store (with and without a reservation) / release / Subscribe
%% take / same-agent supersede / connection death / expiry plus sweep over 5
%% connections, a cap of 3 so that the boundary is crossed often. After every step
%% the decision of session_admission/2 for every (connection, agent) pair must be
%% what a count of the table says, and every stored row must be in the index of
%% its connection; after a sweep the index holds exactly the rows of the table.
pending_index_matches_table() ->
    CapKey = {yuzu_gw_registry, max_sessions_per_connection},
    Cap = 3,
    persistent_term:put(CapKey, Cap),
    _ = rand:seed(exsss, {7, 11, 13}),
    Agents = [agent(I) || I <- lists:seq(1, 6)],
    Conns0 = maps:from_list([{N, conn()} || N <- lists:seq(1, 5)]),
    Pick = fun(L) -> lists:nth(rand:uniform(length(L)), L) end,
    Check = fun(Conns, Step) ->
        Now = erlang:monotonic_time(millisecond),
        Rows = ets:tab2list(yuzu_gw_pending),
        Index = persistent_term:get({yuzu_gw_registry, pending_index}),
        [begin
             Expected = lists:usort([Ag || {_, #{conn_key := K, agent_id := Ag}, T} <- Rows,
                                           K =:= C, T >= Now - 120000, Ag =/= A]),
             Want = case length(Expected) >= Cap of true -> {error, session_limit}; false -> ok end,
             ?assertEqual(Want, yuzu_gw_registry:session_admission(C, A), {Step, C, A})
         end || C <- maps:values(Conns), A <- Agents],
        [?assert(lists:member({K, Key}, ets:lookup(Index, K)), {Step, K, Key})
         || {Key, #{conn_key := K}, _} <- Rows]
    end,
    Final = lists:foldl(fun(Step, {Conns, Held, Stored}) ->
        C = maps:get(rand:uniform(5), Conns),
        A = Pick(Agents),
        Sess = iolist_to_binary(["capsession-i", integer_to_list(Step)]),
        {Conns2, Held2, Stored2} =
            case rand:uniform(7) of
                1 ->
                    case yuzu_gw_registry:reserve_session(C, A) of
                        {ok, Ref} -> {Conns, [Ref | Held], Stored};
                        _         -> {Conns, Held, Stored}
                    end;
                2 when Held =/= [] ->
                    Ref = Pick(Held),
                    ok = yuzu_gw_registry:release_session(Ref),
                    {Conns, Held -- [Ref], Stored};
                3 when Held =/= [] ->
                    Ref = Pick(Held),
                    _ = yuzu_gw_registry:store_pending(Sess, info(A, C), Ref),
                    {Conns, Held -- [Ref], [Sess | Stored]};
                4 when Stored =/= [] ->
                    S = Pick(Stored),
                    _ = yuzu_gw_registry:take_pending(S),
                    {Conns, Held, Stored -- [S]};
                5 ->
                    _ = yuzu_gw_registry:store_pending(Sess, info(A, C)),
                    {Conns, Held, [Sess | Stored]};
                6 ->
                    N = rand:uniform(5),
                    Dying = maps:get(N, Conns),
                    exit(Dying, kill),
                    ok = wait_until(fun() -> [] =:= [R || {_, #{conn_key := K}, _} = R <-
                                                           ets:tab2list(yuzu_gw_pending),
                                                           K =:= Dying]
                                    end),
                    {Conns#{N => conn()}, Held, Stored};
                _ ->
                    Old = erlang:monotonic_time(millisecond) - 10 * 60 * 1000,
                    [ets:update_element(yuzu_gw_pending, Key, {3, Old})
                     || Key <- [S || S <- Stored, rand:uniform(2) =:= 1]],
                    yuzu_gw_registry ! sweep_pending,
                    barrier(),
                    Index = persistent_term:get({yuzu_gw_registry, pending_index}),
                    Want = lists:sort([{K, Key} || {Key, #{conn_key := K}, _} <-
                                                       ets:tab2list(yuzu_gw_pending)]),
                    ?assertEqual(Want, lists:sort(ets:tab2list(Index)), {sweep, Step}),
                    {Conns, Held, Stored}
            end,
        Check(Conns2, Step),
        {Conns2, Held2, Stored2}
    end, {Conns0, [], []}, lists:seq(1, 400)),
    ?assertEqual(5, maps:size(element(1, Final))).

%% The pending count reads the rows of one connection, not the table: with 10000
%% rows held by 1250 other connections a Register on a new connection (reserve,
%% store, release) keeps its round trip to the registry process under 5 ms. The
%% median of 21 is taken so that one scheduling hiccup does not decide it.
round_trip_with_many_rows_elsewhere() ->
    Others = [conn() || _ <- lists:seq(1, 1250)],
    [[ok = yuzu_gw_registry:store_pending(
               iolist_to_binary(["capsession-m", integer_to_list(N), "-", integer_to_list(I)]),
               info(agent(I), C))
      || I <- lists:seq(1, ?CAP)]
     || {N, C} <- lists:zip(lists:seq(1, 1250), Others)],
    ?assertEqual(10000, ets:info(yuzu_gw_pending, size)),
    Time = fun(Fun) ->
        T0 = erlang:monotonic_time(microsecond),
        Fun(),
        erlang:monotonic_time(microsecond) - T0
    end,
    Median = fun(L) -> lists:nth(11, lists:sort(L)) end,
    Reserve = Median([begin
                          C = conn(),
                          Time(fun() ->
                              {ok, Ref} = yuzu_gw_registry:reserve_session(C, agent(1)),
                              ok = yuzu_gw_registry:release_session(Ref)
                          end)
                      end || _ <- lists:seq(1, 21)]),
    Store = Median([begin
                        C = conn(),
                        Time(fun() ->
                            ok = yuzu_gw_registry:store_pending(
                                     iolist_to_binary(["capsession-t", integer_to_list(I)]),
                                     info(agent(1), C))
                        end)
                    end || I <- lists:seq(1, 21)]),
    ?assert(Reserve < 5000, {reserve_us, Reserve}),
    ?assert(Store < 5000, {store_us, Store}),
    %% The work the registry process does for one reservation, in reductions: not
    %% a function of the load of the machine, and a scan of the table costs it
    %% thousands.
    Reg = whereis(yuzu_gw_registry),
    Reductions = fun() -> {reductions, R} = process_info(Reg, reductions), R end,
    Cs = [conn() || _ <- lists:seq(1, 11)],
    Spent = [begin
                 R0 = Reductions(),
                 {ok, Ref} = yuzu_gw_registry:reserve_session(C, agent(1)),
                 barrier(),
                 R1 = Reductions(),
                 ok = yuzu_gw_registry:release_session(Ref),
                 R1 - R0
             end || C <- Cs],
    ?assert(lists:nth(6, lists:sort(Spent)) < 2000, {reductions, Spent}).

%%%===================================================================
%%% Helpers
%%%===================================================================

conn() -> holder().

%% A stand-in process, remembered so that cleanup/1 can stop it.
holder() ->
    Pid = spawn(fun() -> receive stop -> ok end end),
    true = ets:insert(?HOLDERS_TAB, {Pid}),
    Pid.

kill_holders() ->
    Pids = [P || {P} <- ets:tab2list(?HOLDERS_TAB)],
    Mons = [{P, monitor(process, P)} || P <- Pids],
    [exit(P, kill) || P <- Pids],
    [receive {'DOWN', M, process, P, _} -> ok after 2000 -> ok end || {P, M} <- Mons],
    catch ets:delete(?HOLDERS_TAB),
    ok.

%% Ids no other module uses (the pg groups and tables are shared).
agent(I) -> iolist_to_binary(["capagent-", integer_to_list(I)]).
session(I) -> iolist_to_binary(["capsession-", integer_to_list(I)]).

info(AgentId, ConnKey) ->
    #{agent_id => AgentId, agent_info => #{}, register_req => #{}, peer_addr => <<"p">>,
      conn_key => ConnKey}.

%% Register a live agent process bound to ConnKey; returns its pid.
bind(AgentId, SessionId, ConnKey) ->
    Pid = holder(),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid, SessionId, [], <<>>, #{}, ConnKey),
    Pid.

%% The registry has handled every message sent to it before this call.
barrier() ->
    _ = sys:get_state(yuzu_gw_registry),
    ok.

%% The per-connection index entries of ConnKey.
conn_entries(ConnKey) ->
    ets:lookup(persistent_term:get(?CONN_INDEX_KEY), ConnKey).

conn_count(ConnKey) ->
    length(lists:usort([A || {_, A, _} <- conn_entries(ConnKey)])).

%% The ids of the stored pending rows (not reservations) of ConnKey.
pending_rows(ConnKey) ->
    [S || {S, #{conn_key := K}, _} <- ets:tab2list(yuzu_gw_pending),
          is_binary(S), K =:= ConnKey].

%% The keys of the reservation rows of ConnKey.
reserved_rows_of(ConnKey) ->
    [K || {{reserved, _} = K, #{conn_key := C}, _} <- ets:tab2list(yuzu_gw_pending),
          C =:= ConnKey].

%% How many monitors the registry process holds.
monitor_count() ->
    {monitors, Mons} = process_info(whereis(yuzu_gw_registry), monitors),
    length(Mons).

%% The keys of the reservation rows.
reserved_rows() ->
    [K || {{reserved, _} = K, _, _} <- ets:tab2list(yuzu_gw_pending)].

refused() ->
    lists:sum([N || {_, refused, N} <- ets:tab2list(?EVENTS_TAB)]).

wait_until(Pred) ->
    wait_until(Pred, 400).

wait_until(Pred, 0) ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, N) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(5), wait_until(Pred, N - 1)
    end.

ctx_with(Key) ->
    ctx:set(ctx:background(), ?CTX_KEY, Key).

mock_handler_deps() ->
    catch meck:unload([yuzu_gw_conn, yuzu_gw_upstream]),
    ok = meck:new(yuzu_gw_conn, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_conn, key_from_ctx,
                     fun(Ctx) -> ctx:get(Ctx, ?CTX_KEY, undefined) end),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         {ok, #{session_id => <<"reg-session-", Id/binary>>}}
                     end).
