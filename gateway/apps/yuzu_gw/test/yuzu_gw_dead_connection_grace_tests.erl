%%%-------------------------------------------------------------------
%%% @doc The grace the registry gives the rows of a connection that went down
%%% (`dead_connection_grace_ms', yuzu_gw_registry moduledoc part 4).
%%%
%%% An agent whose connection got GOAWAY after its Register subscribes on the
%%% reconnected channel, so the connection's reservations and pending rows stay
%%% takeable for the grace and go when it is over, never one timer per row.
%%% Covered:
%%%   - within the grace the rows of the dead connection are still there and can
%%%     be taken; another connection's rows are untouched;
%%%   - after the grace every row of the dead connection is gone (and only its),
%%%     including a row stored for it while the grace ran;
%%%   - a grace of 0 removes the rows at once and starts no timer;
%%%   - dropping a dead connection costs its own rows (its index entries), not a
%%%     scan of the pending table: 20000 rows of another connection do not move it;
%%%   - one timer per dead connection, however many rows (counted on the timeout
%%%     messages the registry receives), and none for a connection with no row;
%%%   - a connection that comes back (a new process, the same agent) is unaffected;
%%%   - 100 connection cycles leave no monitor, no timer entry;
%%%   - the sweep cancels the timer of a dead connection whose rows are gone and
%%%     does not trip over rows it has already removed;
%%%   - a registry restart with a grace timer outstanding is harmless;
%%%   - the key is read once, validated: an invalid value warns naming the key and
%%%     takes 15000.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_dead_connection_grace_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).

-define(KEY, dead_connection_grace_ms).
-define(CAP_KEY, {yuzu_gw_registry, max_sessions_per_connection}).
-define(LOG_HANDLER, yuzu_gw_dead_connection_grace_tests_log).
-define(LOG_TAB, yuzu_gw_dead_connection_grace_tests_log_tab).
%% Position of `dead_conns' and `dead_grace_ms' in the registry's state record.
-define(ST_DEAD_CONNS, 5).
-define(ST_GRACE, 6).

grace_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"rows of a dead connection are takeable within the grace, other connections' rows untouched",
       fun takeable_within_grace/0},
      {"after the grace every row of the dead connection is gone and no other",
       fun gone_after_grace/0},
      {"a row stored for the dead connection during the grace goes with the first timer",
       fun row_stored_during_grace/0},
      {"grace 0 removes the rows at once and starts no timer",
       fun grace_zero_is_immediate/0},
      {"dropping a dead connection's rows costs its own rows, not a scan of 20000 rows of others",
       {timeout, 120, fun drop_cost_independent_of_table_size/0}},
      {"a row stored and not yet committed survives the drop of its connection and goes with its commit",
       fun uncommitted_row_survives_drop_until_commit/0},
      {"a dead connection with no row left starts no timer",
       fun no_rows_no_timer/0},
      {"one timer per dead connection with 100 rows",
       fun one_timer_per_connection/0},
      {"a connection that comes back (new process, same agent) is unaffected",
       fun reconnect_unaffected/0},
      {"100 connection cycles leave no monitor and no timer entry",
       {timeout, 60, fun no_leak_after_cycles/0}},
      {"the sweep cancels the timer of a dead connection whose rows are gone",
       fun sweep_cancels_idle_timer/0},
      {"the sweep and the timer over rows past their TTL do not double-delete or crash",
       fun sweep_and_timer_over_expired_rows/0},
      {"a registry restart with a grace timer outstanding is harmless",
       fun registry_restart_with_timer/0},
      {"the key is validated: default 15000, bounds 0..120000, invalid warns naming it",
       fun grace_key_validation/0}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = {application:get_env(yuzu_gw, ?KEY),
            application:get_env(yuzu_gw, max_sessions_per_connection)},
    application:unset_env(yuzu_gw, max_sessions_per_connection),
    ?LOG_TAB = ets:new(?LOG_TAB, [named_table, public, bag]),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE, #{config => #{}, level => all}),
    Prev.

cleanup({PrevGrace, PrevCap}) ->
    catch logger:remove_handler(?LOG_HANDLER),
    catch ets:delete(?LOG_TAB),
    restore(?KEY, PrevGrace),
    restore(max_sessions_per_connection, PrevCap),
    %% Every holder this case spawned is gone with the registry's rows; the next
    %% module starts its own registry.
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    ok.

restore(Key, {ok, V})   -> application:set_env(yuzu_gw, Key, V);
restore(Key, undefined) -> application:unset_env(yuzu_gw, Key).

%% logger handler callback
log(#{level := Level, msg := Msg, meta := _}, _Config) ->
    ets:insert(?LOG_TAB, {Level, lists:flatten(format(Msg))}),
    ok.

format({string, S})      -> io_lib:format("~ts", [S]);
format({report, R})      -> io_lib:format("~p", [R]);
format({Fmt, Args})      -> io_lib:format(Fmt, Args).

%%%===================================================================
%%% Cases
%%%===================================================================

takeable_within_grace() ->
    start_registry(60000),
    Base = monitor_count(),
    Dying = conn(),
    Other = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
     || I <- lists:seq(1, 3)],
    {ok, DyingRef} = yuzu_gw_registry:reserve_session(Dying, agent(4)),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Other))
     || I <- lists:seq(11, 12)],
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    %% Nothing is removed: the rows still name the dead connection, and a
    %% Subscribe on another connection takes them.
    ?assertEqual([session(1), session(2), session(3)], lists:sort(pending_rows(Dying))),
    ?assertEqual([{reserved, DyingRef}], reserved_rows_of(Dying)),
    ?assertEqual([session(11), session(12)], lists:sort(pending_rows(Other))),
    ?assertMatch(#{conn_key := Dying}, yuzu_gw_registry:take_pending(session(1))),
    ?assertEqual({ok, Dying}, yuzu_gw_registry:lookup_pending_session(session(2))),
    %% The rows count for the dead connection key only.
    ?assertEqual(ok, yuzu_gw_registry:session_admission(Other, agent(1))),
    %% The monitor of the dead connection is released (a DOWN is delivered once).
    barrier(),
    ?assertEqual(Base + 1, monitor_count()).

gone_after_grace() ->
    start_registry(50),
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
    %% One taken during the grace: the later removal is a no-op for it.
    kill(Dying),
    ?assertMatch(#{conn_key := Dying}, yuzu_gw_registry:take_pending(session(2))),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] andalso
                                         reserved_rows_of(Dying) =:= [] end, 2000)),
    barrier(),
    ?assertEqual([], dead_conns()),
    ?assertEqual([], index_entries(Dying)),
    ?assertEqual([session(11), session(12)], lists:sort(pending_rows(Live))),
    ?assertEqual([{reserved, LiveRef}], reserved_rows_of(Live)),
    ?assertEqual([session(21)], pending_rows(Other)),
    %% The count of the dead connection is free, the others keep theirs.
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(31), info(agent(31), conn()))).

row_stored_during_grace() ->
    start_registry(300),
    Dying = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(agent(1), Dying)),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    [TRef] = dead_timers(),
    %% A late store for the dead key (an in-flight Register): it is monitored
    %% again, its DOWN fires at once and no second timer starts.
    Late = yuzu_gw_registry:store_pending(session(2), info(agent(2), Dying)),
    ?assert(lists:member(Late, [ok, {error, registry_unavailable}])),
    barrier(),
    ?assertEqual([TRef], dead_timers()),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] end, 3000)),
    barrier(),
    ?assertEqual([], dead_conns()).

grace_zero_is_immediate() ->
    start_registry(0),
    Dying = conn(),
    Other = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
     || I <- lists:seq(1, 3)],
    ok = yuzu_gw_registry:store_pending(session(21), info(agent(21), Other)),
    Trace = trace_registry(),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] end, 2000)),
    barrier(),
    ?assertEqual([], dead_conns()),
    ?assertEqual(0, timeouts_received(Trace)),
    ?assertEqual([session(21)], pending_rows(Other)).

%% 20000 rows of another connection sit in the pending table (stored without an
%% index entry: all a scan would have to read). The work the registry does to
%% drop one dead connection of 3 rows is measured in reductions, which are not a
%% function of the machine's load, and a scan of the table costs thousands of
%% times more: removing the rows by the connection's index entries is what keeps
%% a loss of thousands of connections from being seconds of registry time.
drop_cost_independent_of_table_size() ->
    start_registry(0),
    Others = conn(),
    Now = erlang:monotonic_time(millisecond),
    [true = ets:insert(yuzu_gw_pending, {session(100000 + I), info(agent(100000 + I), Others), Now})
     || I <- lists:seq(1, 20000)],
    ?assertEqual(20000, ets:info(yuzu_gw_pending, size)),
    Reg = whereis(yuzu_gw_registry),
    Reductions = fun() -> {reductions, R} = process_info(Reg, reductions), R end,
    Spent = [begin
                 Dying = conn(),
                 [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
                  || I <- lists:seq(1, 3)],
                 {ok, _} = yuzu_gw_registry:reserve_session(Dying, agent(4)),
                 barrier(),
                 R0 = Reductions(),
                 kill(Dying),
                 ?assertEqual(ok, wait_until(fun() ->
                     lists:all(fun(I) -> not ets:member(yuzu_gw_pending, session(I)) end,
                               [1, 2, 3]) andalso reserved_rows_of(Dying) =:= [] end, 5000)),
                 barrier(),
                 Reductions() - R0
             end || _ <- lists:seq(1, 11)],
    ?assert(lists:nth(6, lists:sort(Spent)) < 2000, {reductions, Spent}),
    %% Nothing of the other connection went with it.
    ?assertEqual(20000, ets:info(yuzu_gw_pending, size)).

%% The drop removes the rows the connection's index names. A row a handler has
%% stored and not committed is in no index: it stays, the commit that follows
%% finds the connection down and monitors it again, and the DOWN removes the row
%% (a caller that never commits is covered by the TTL sweep).
uncommitted_row_survives_drop_until_commit() ->
    start_registry(0),
    Dying = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(agent(1), Dying)),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] end, 5000)),
    barrier(),
    true = ets:insert(yuzu_gw_pending,
                      {session(2), info(agent(2), Dying), erlang:monotonic_time(millisecond)}),
    barrier(),
    ?assertEqual([session(2)], pending_rows(Dying)),
    ?assertEqual(ok, gen_server:call(yuzu_gw_registry,
                                     {commit_pending, session(2), Dying, agent(2), undefined})),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] end, 5000)),
    barrier(),
    ?assertEqual([], index_entries(Dying)),
    ?assertEqual(0, monitor_count()).

no_rows_no_timer() ->
    start_registry(60000),
    Base = monitor_count(),
    C = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(agent(1), C)),
    ?assertMatch(#{}, yuzu_gw_registry:take_pending(session(1))),
    kill(C),
    ?assertEqual(ok, wait_until(fun() -> monitor_count() =:= Base end)),
    barrier(),
    ?assertEqual([], dead_conns()),
    ?assertEqual([], index_entries(C)).

%% The registry's receives are traced: a timer per row would deliver a hundred
%% timeout messages, the timer of the connection delivers one.
one_timer_per_connection() ->
    start_registry(100),
    persistent_term:put(?CAP_KEY, 1000),
    Dying = conn(),
    Other = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
     || I <- lists:seq(1, 100)],
    ok = yuzu_gw_registry:store_pending(session(201), info(agent(201), Other)),
    ?assertEqual(100, length(pending_rows(Dying))),
    Trace = trace_registry(),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    ?assertEqual(1, length(dead_timers())),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Dying) =:= [] end, 3000)),
    barrier(),
    ?assertEqual(1, timeouts_received(Trace)),
    ?assertEqual([], dead_conns()),
    ?assertEqual([session(201)], pending_rows(Other)).

reconnect_unaffected() ->
    start_registry(50),
    Agent = agent(1),
    Old = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(Agent, Old)),
    kill(Old),
    New = conn(),
    %% The same agent registers again on the new connection (its Subscribe on the
    %% old session was not answered in time).
    ok = yuzu_gw_registry:store_pending(session(2), info(Agent, New)),
    {ok, NewRef} = yuzu_gw_registry:reserve_session(New, agent(2)),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(Old) =:= [] end, 2000)),
    barrier(),
    ?assertEqual([session(2)], pending_rows(New)),
    ?assertEqual([{reserved, NewRef}], reserved_rows_of(New)),
    ?assertEqual({ok, New}, yuzu_gw_registry:lookup_pending_session(session(2))),
    %% And the new connection is still monitored: its own death is handled.
    kill(New),
    ?assertEqual(ok, wait_until(fun() -> pending_rows(New) =:= [] andalso
                                         reserved_rows_of(New) =:= [] end, 2000)).

no_leak_after_cycles() ->
    start_registry(20),
    Base = monitor_count(),
    Conns = [begin
                 C = conn(),
                 [ok = yuzu_gw_registry:store_pending(session(100 * N + I),
                                                      info(agent(100 * N + I), C))
                  || I <- lists:seq(1, 3)],
                 C
             end || N <- lists:seq(1, 100)],
    ?assertEqual(Base + 100, monitor_count()),
    [kill(C) || C <- Conns],
    ?assertEqual(ok, wait_until(fun() -> lists:all(fun(C) -> pending_rows(C) =:= [] end, Conns) end,
                                3000)),
    barrier(),
    ?assertEqual(Base, monitor_count()),
    ?assertEqual([], dead_conns()),
    ?assertEqual([], ets:tab2list(yuzu_gw_pending)),
    ?assertEqual(0, ets:info(persistent_term:get({yuzu_gw_registry, pending_index}), size)).

sweep_cancels_idle_timer() ->
    start_registry(60000),
    Dying = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(agent(1), Dying)),
    ok = yuzu_gw_registry:store_pending(session(2), info(agent(2), Dying)),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    %% Subscribe on the new connection takes both rows within the grace.
    [?assertMatch(#{}, yuzu_gw_registry:take_pending(session(I))) || I <- [1, 2]],
    [TRef] = dead_timers(),
    yuzu_gw_registry ! sweep_pending,
    barrier(),
    ?assertEqual([], dead_conns()),
    ?assertEqual(false, erlang:read_timer(TRef)).

sweep_and_timer_over_expired_rows() ->
    start_registry(60000),
    Dying = conn(),
    Other = conn(),
    [ok = yuzu_gw_registry:store_pending(session(I), info(agent(I), Dying))
     || I <- lists:seq(1, 3)],
    ok = yuzu_gw_registry:store_pending(session(21), info(agent(21), Other)),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    %% The rows of the dead connection are past their TTL: the sweep removes
    %% them, and the timer that then fires (a stale message in the mailbox, or
    %% one the sweep did not cancel) finds nothing.
    [TRef] = dead_timers(),
    Old = erlang:monotonic_time(millisecond) - 200000,
    [true = ets:insert(yuzu_gw_pending, {S, Info, Old})
     || S <- pending_rows(Dying), [{_, Info, _}] <- [ets:lookup(yuzu_gw_pending, S)]],
    yuzu_gw_registry ! sweep_pending,
    barrier(),
    ?assertEqual([], pending_rows(Dying)),
    ?assertEqual([], dead_conns()),
    Pid = whereis(yuzu_gw_registry),
    yuzu_gw_registry ! {timeout, TRef, Dying},
    barrier(),
    ?assertEqual(Pid, whereis(yuzu_gw_registry)),
    ?assertEqual([session(21)], pending_rows(Other)).

registry_restart_with_timer() ->
    start_registry(50),
    Dying = conn(),
    ok = yuzu_gw_registry:store_pending(session(1), info(agent(1), Dying)),
    Old = whereis(yuzu_gw_registry),
    kill(Dying),
    ?assertEqual(ok, wait_until(fun() -> dead_conns() =:= [Dying] end)),
    [TRef] = dead_timers(),
    start_registry(50),
    New = whereis(yuzu_gw_registry),
    ?assertNotEqual(Old, New),
    %% The old timer fires at a process that is gone: nothing reaches the new one.
    ?assertEqual(ok, wait_until(fun() -> erlang:read_timer(TRef) =:= false end, 2000)),
    barrier(),
    ?assertEqual({message_queue_len, 0}, process_info(New, message_queue_len)),
    ?assertEqual([], pending_rows(Dying)),
    ?assertEqual([], dead_conns()),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(session(2), info(agent(2), conn()))).

grace_key_validation() ->
    [begin
         application:set_env(yuzu_gw, ?KEY, V),
         ets:delete_all_objects(?LOG_TAB),
         yuzu_gw_test_registry:ensure_fresh(),
         unlink(whereis(yuzu_gw_registry)),
         ?assertEqual(Want, element(?ST_GRACE, sys:get_state(yuzu_gw_registry)), V),
         Warned = [M || {warning, M} <- ets:tab2list(?LOG_TAB),
                        string:find(M, "dead_connection_grace_ms") =/= nomatch],
         ?assertEqual(Warns, length(Warned), {V, Warned})
     end || {V, Want, Warns} <- [{0, 0, 0}, {1, 1, 0}, {120000, 120000, 0},
                                 {-1, 15000, 1}, {120001, 15000, 1},
                                 {<<"50">>, 15000, 1}, {5.0, 15000, 1}]],
    application:unset_env(yuzu_gw, ?KEY),
    ets:delete_all_objects(?LOG_TAB),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    ?assertEqual(15000, element(?ST_GRACE, sys:get_state(yuzu_gw_registry))),
    ?assertEqual([], [M || {warning, M} <- ets:tab2list(?LOG_TAB),
                           string:find(M, "dead_connection_grace_ms") =/= nomatch]).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% A fresh registry that read the grace Ms.
start_registry(Ms) ->
    application:set_env(yuzu_gw, ?KEY, Ms),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    ?assertEqual(Ms, element(?ST_GRACE, sys:get_state(yuzu_gw_registry))).

conn() ->
    spawn(fun() -> receive stop -> ok end end).

kill(Pid) ->
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Mon, process, Pid, _} -> ok after 2000 -> error(not_dead) end.

agent(I) -> iolist_to_binary(["graceagent-", integer_to_list(I)]).
session(I) -> iolist_to_binary(["gracesession-", integer_to_list(I)]).

info(AgentId, ConnKey) ->
    #{agent_id => AgentId, agent_info => #{}, register_req => #{}, peer_addr => <<"p">>,
      conn_key => ConnKey}.

pending_rows(ConnKey) ->
    [S || {S, #{conn_key := K}, _} <- ets:tab2list(yuzu_gw_pending),
          is_binary(S), K =:= ConnKey].

reserved_rows_of(ConnKey) ->
    [K || {{reserved, _} = K, #{conn_key := C}, _} <- ets:tab2list(yuzu_gw_pending),
          C =:= ConnKey].

index_entries(ConnKey) ->
    ets:lookup(persistent_term:get({yuzu_gw_registry, pending_index}), ConnKey).

%% The dead connections the registry holds a grace timer for, and the timers.
dead_conns() ->
    lists:sort(maps:keys(element(?ST_DEAD_CONNS, sys:get_state(yuzu_gw_registry)))).

dead_timers() ->
    maps:values(element(?ST_DEAD_CONNS, sys:get_state(yuzu_gw_registry))).

monitor_count() ->
    {monitors, Mons} = process_info(whereis(yuzu_gw_registry), monitors),
    length(Mons).

barrier() ->
    _ = sys:get_state(yuzu_gw_registry),
    ok.

wait_until(Pred) -> wait_until(Pred, 1000).

wait_until(Pred, Ms) ->
    Deadline = erlang:monotonic_time(millisecond) + Ms,
    wait_loop(Pred, Deadline).

wait_loop(Pred, Deadline) ->
    case Pred() of
        true  -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true  -> {error, timeout};
                false -> timer:sleep(2), wait_loop(Pred, Deadline)
            end
    end.

%% Trace the messages the registry receives; the count of timer messages is read
%% from the mailbox of this process.
trace_registry() ->
    Pid = whereis(yuzu_gw_registry),
    _ = erlang:trace(Pid, true, ['receive']),
    Pid.

timeouts_received(Pid) ->
    _ = erlang:trace(Pid, false, ['receive']),
    drain_timeouts(Pid, 0).

drain_timeouts(Pid, N) ->
    receive
        {trace, Pid, 'receive', {timeout, _, _}} -> drain_timeouts(Pid, N + 1);
        {trace, Pid, 'receive', _}               -> drain_timeouts(Pid, N)
    after 0 -> N
    end.
