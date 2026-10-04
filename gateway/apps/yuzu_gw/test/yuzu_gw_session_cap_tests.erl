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
       fun registry_dies_before_commit/0}
     ]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = application:get_env(yuzu_gw, max_sessions_per_connection),
    application:unset_env(yuzu_gw, max_sessions_per_connection),
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

cleanup(Prev) ->
    %% The stand-in agent processes joined pg groups under the registry that is
    %% being replaced: stop them, or a later module that registers the same
    %% agent id would find them through lookup/1's pg fallback.
    kill_holders(),
    catch logger:remove_handler(?LOG_HANDLER),
    catch telemetry:detach(?EV_HANDLER),
    catch ets:delete(?EVENTS_TAB),
    case Prev of
        {ok, V}   -> application:set_env(yuzu_gw, max_sessions_per_connection, V);
        undefined -> application:unset_env(yuzu_gw, max_sessions_per_connection)
    end,
    catch meck:unload([yuzu_gw_conn, yuzu_gw_upstream]),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    ok.

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
    [true = ets:insert(yuzu_gw_pending, {session(I), info(agent(I), C), Old})
     || I <- lists:seq(1, ?CAP)],
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
    %% Other agents' rows reach the cap while the reservation is held (written
    %% directly: this is the state the reservation protects against).
    Now = erlang:monotonic_time(millisecond),
    [true = ets:insert(yuzu_gw_pending, {session(I), info(agent(I), C), Now})
     || I <- lists:seq(2, ?CAP + 1)],
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
