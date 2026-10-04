%%%-------------------------------------------------------------------
%%% @doc Tests for the per-connection session cap (#1197): one connection may
%%% hold at most `max_sessions_per_connection' (default 8) DISTINCT agents'
%%% sessions, pending plus live, not counting the agent being (re)registered.
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
%%%     process the registry refuses ends with {error, session_limit}.
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
      {"pending plus live count together, an agent with both counts once",
       fun pending_and_live_count_together/0},
      {"an expired pending row is not counted",
       fun expired_pending_not_counted/0},
      {"a session with no connection key is never counted",
       fun undefined_key_never_counted/0},
      {"every release path frees the count: 100 cycles end at the right count",
       {timeout, 60, fun churn_releases_every_count/0}},
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
       fun agent_process_refused/0}
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
    %% An agent that has a live session and registers again counts once, and is
    %% excluded from its own count.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-1b">>, info(agent(1), C))),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"cap-s-5b">>, info(agent(5), C))),
    %% The live insert counts the pending rows too.
    ?assertEqual({error, session_limit},
                 yuzu_gw_registry:register_agent(agent(9), holder(), session(9), [], <<>>, #{}, C)).

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
