%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_registry — ETS routing table + pg groups.
%%%
%%% Tests registration, lookup, deregistration, process monitor cleanup,
%%% pg group membership, cursor-based pagination, pending registration
%%% storage (store_pending/take_pending), TTL sweep, and monitor ref
%%% leak prevention.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — start pg + registry, stop after
%%%===================================================================

registry_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"register and lookup", fun register_and_lookup/0},
      {"lookup missing returns error", fun lookup_missing/0},
      {"deregister removes entry", fun deregister_removes/0},
      {"monitor auto-cleans on process death", fun monitor_cleanup/0},
      {"re-register same agent_id replaces old", fun reregister_replaces/0},
      {"all_agents returns all ids", fun all_agents_list/0},
      {"agent_count is accurate", fun agent_count_accurate/0},
      {"pg group membership for plugins", fun pg_plugin_groups/0},
      {"pagination returns correct pages", fun pagination_basic/0},
      {"pagination cursor advances correctly", fun pagination_cursor/0},
      {"deregister non-existent is safe", fun deregister_nonexistent/0},
      {"lookup dead process returns error", fun lookup_dead_process/0},
      %% Pending registration tests
      {"store_pending and take_pending round-trip", fun pending_store_take/0},
      {"take_pending returns undefined for unknown session", fun pending_take_unknown/0},
      {"take_pending deletes entry atomically", fun pending_take_deletes/0},
      {"take_pending: exactly one winner under concurrent racers (PR #4299 round 6)",
       {timeout, 60, fun pending_take_concurrent_single_winner/0}},
      {"pending sweep removes expired entries", fun pending_sweep_expired/0},
      {"pending sweep preserves fresh entries", fun pending_sweep_preserves_fresh/0},
      %% Monitor ref leak test
      {"re-register does not leak monitor refs", fun reregister_no_monitor_leak/0},
      %% #1197: the replay entries for sessions this node holds
      {"entries_for_sessions returns the replay entry of each held session, read only",
       fun entries_for_held_sessions/0},
      {"entries_for_sessions drops an id whose routing row holds a different pid",
       fun entries_drop_pid_mismatch/0},
      {"entries_for_sessions drops an id whose routing row holds a different session",
       fun entries_drop_session_mismatch/0},
      {"entries_for_sessions drops an id whose process has died",
       fun entries_drop_dead_process/0},
      {"entries_for_sessions returns [] when the session index is missing",
       fun entries_without_session_index/0},
      {"lookup_local_session reports unavailable when the routing table is missing",
       fun lookup_local_session_without_table/0}
     ]}.

setup() ->
    %% pg + a real registry, race-safe across modules. The naive
    %% start_link here previously had no handling for the init/1 crash a
    %% leaked-ETS-table orphan triggers (#1403 / #336).
    yuzu_gw_test_registry:ensure().

cleanup(_) ->
    %% Don't stop the registry — other test suites share it.
    ok.

%%%===================================================================
%%% Correctness tests
%%%===================================================================

register_and_lookup() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-1">>, Pid, <<"sess-1">>, [<<"svc">>], <<>>),
    ?assertMatch({ok, Pid}, yuzu_gw_registry:lookup(<<"agent-1">>)),
    kill_dummy(Pid).

lookup_missing() ->
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"no-such-agent">>)).

deregister_removes() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-2">>, Pid, <<"s">>, [], <<>>),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(<<"agent-2">>)),
    yuzu_gw_registry:deregister_agent(<<"agent-2">>),
    registry_barrier(),  %% the deregister cast is async
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"agent-2">>)),
    kill_dummy(Pid).

monitor_cleanup() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-3">>, Pid, <<"s">>, [], <<>>),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup(<<"agent-3">>)),
    %% Kill the process — registry should auto-clean via DOWN monitor.
    kill_dummy(Pid),
    ?assertEqual(error, await(fun() -> yuzu_gw_registry:lookup(<<"agent-3">>) end, error)).

reregister_replaces() ->
    Pid1 = spawn_dummy(),
    Pid2 = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"agent-4">>, Pid1, <<"s1">>, [], <<>>),
    ok = yuzu_gw_registry:register_agent(<<"agent-4">>, Pid2, <<"s2">>, [], <<>>),
    ?assertMatch({ok, Pid2}, yuzu_gw_registry:lookup(<<"agent-4">>)),
    kill_dummy(Pid1),
    kill_dummy(Pid2).

all_agents_list() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 5)],
    Ids = [iolist_to_binary(io_lib:format("all-~b", [I])) || I <- lists:seq(1, 5)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    All = yuzu_gw_registry:all_agents(),
    lists:foreach(fun(Id) ->
        ?assert(lists:member(Id, All))
    end, Ids),
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

agent_count_accurate() ->
    InitialCount = yuzu_gw_registry:agent_count(),
    Pids = [spawn_dummy() || _ <- lists:seq(1, 10)],
    Ids = [iolist_to_binary(io_lib:format("count-~b", [I])) || I <- lists:seq(1, 10)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    ?assertEqual(InitialCount + 10, yuzu_gw_registry:agent_count()),
    %% Cleanup
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids),
    ?assertEqual(InitialCount,
                 await(fun yuzu_gw_registry:agent_count/0, InitialCount)).

pg_plugin_groups() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"pg-agent">>, Pid, <<"s">>, [<<"svc">>, <<"fs">>], <<>>),
    %% Agent should be in the plugin groups.
    SvcMembers = pg:get_members(yuzu_gw, {plugin, <<"svc">>}),
    FsMembers = pg:get_members(yuzu_gw, {plugin, <<"fs">>}),
    ?assert(lists:member(Pid, SvcMembers)),
    ?assert(lists:member(Pid, FsMembers)),
    kill_dummy(Pid).

pagination_basic() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 5)],
    Ids = [iolist_to_binary(io_lib:format("page-~2..0b", [I])) || I <- lists:seq(1, 5)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    %% Page size 3 should give 3 agents + a cursor.
    {Page1, Cursor1} = yuzu_gw_registry:list_agents(3, undefined),
    ?assertEqual(3, length(Page1)),
    ?assertNotEqual(undefined, Cursor1),
    %% Second page should give remaining.
    {Page2, _Cursor2} = yuzu_gw_registry:list_agents(3, Cursor1),
    %% Page2 should have at least the remaining agents (may include others from other tests).
    ?assert(length(Page2) >= 2),
    %% Cleanup
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

pagination_cursor() ->
    Pids = [spawn_dummy() || _ <- lists:seq(1, 20)],
    Ids = [iolist_to_binary(io_lib:format("cur-~3..0b", [I])) || I <- lists:seq(1, 20)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    %% Walk all pages and collect agent IDs — every ID should appear exactly once.
    AllFound = collect_all_pages(7, undefined, []),
    lists:foreach(fun(Id) ->
        Matches = [A || #{agent_id := A} <- AllFound, A =:= Id],
        ?assertEqual(1, length(Matches), {missing_or_duplicate, Id})
    end, Ids),
    lists:foreach(fun(Pid) -> kill_dummy(Pid) end, Pids).

deregister_nonexistent() ->
    %% Should not crash.
    yuzu_gw_registry:deregister_agent(<<"does-not-exist">>),
    registry_barrier(),  %% also proves the registry survived the cast
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"does-not-exist">>)).

lookup_dead_process() ->
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"dead-lookup">>, Pid, <<"s">>, [], <<>>),
    MonRef = monitor(process, Pid),
    kill_dummy(Pid),
    receive {'DOWN', MonRef, process, Pid, _} -> ok after 1000 -> error(timeout) end,
    %% Process is confirmed dead; lookup checks is_process_alive and should return error.
    ?assertEqual(error, yuzu_gw_registry:lookup(<<"dead-lookup">>)).

%%%===================================================================
%%% Pending registration tests
%%%===================================================================

pending_store_take() ->
    Info = #{agent_id => <<"pending-1">>, peer_addr => <<"1.2.3.4">>},
    ok = yuzu_gw_registry:store_pending(<<"sess-pend-1">>, Info),
    Result = yuzu_gw_registry:take_pending(<<"sess-pend-1">>),
    ?assertEqual(Info, Result).

pending_take_unknown() ->
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"no-such-session">>)).

pending_take_deletes() ->
    Info = #{agent_id => <<"pending-2">>},
    ok = yuzu_gw_registry:store_pending(<<"sess-pend-2">>, Info),
    %% First take returns the data.
    ?assertEqual(Info, yuzu_gw_registry:take_pending(<<"sess-pend-2">>)),
    %% Second take returns undefined (already deleted).
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"sess-pend-2">>)).

%% Regression pin for the take_pending atomicity fix (PR #4299 round 6).
%% take_pending is called directly from yuzu_gw_agent_service:subscribe/2, which
%% grpcbox runs as an independent process per incoming stream, against a `public`
%% ETS table with no serialization. The old lookup-then-delete let two concurrent
%% Subscribe handlers presenting the SAME session id BOTH consume the one pending
%% registration, each spawning an agent process and each emitting its own
%% CONNECTED(S) — a second-CONNECTED-per-session producer that breaks the HA WS-4
%% routing directory's once-per-session invariant (ADR-2002 §7 #4246 #4 / #4324).
%% ets:take/2 is a single atomic retrieve-and-delete: exactly one concurrent
%% caller gets the object for a given key, the rest get []. Assert exactly one
%% winner per round across many barrier-released rounds. (Empirically this fails
%% intermittently on the old lookup+delete code and passes deterministically on
%% ets:take — verified by reverting the fix on a scratch copy.)
pending_take_concurrent_single_winner() ->
    Racers = 50,
    Rounds = 200,
    Parent = self(),
    lists:foreach(
      fun(R) ->
          Session = <<"race-sess-", (integer_to_binary(R))/binary>>,
          Info = #{agent_id => <<"race-agent">>, round => R},
          ok = yuzu_gw_registry:store_pending(Session, Info),
          Go = make_ref(),
          Pids = [spawn(fun() ->
                              Parent ! {ready, self()},
                              receive Go -> ok end,
                              Res = yuzu_gw_registry:take_pending(Session),
                              Parent ! {race_result, self(), Res}
                          end) || _ <- lists:seq(1, Racers)],
          %% TWO-PHASE barrier: wait until EVERY racer is blocked on Go, THEN
          %% release them together — so the take_pending calls collide as tightly
          %% as the scheduler allows, maximizing a reintroduced race's exposure
          %% (a sequential release lets early racers finish before the last is
          %% even woken). Green here is deterministic regardless (ets:take), so
          %% this only strengthens RED power on a regression.
          [receive {ready, P} -> ok end || P <- Pids],
          lists:foreach(fun(P) -> P ! Go end, Pids),
          Results = [receive {race_result, P, Res} -> Res end || P <- Pids],
          Winners = [X || X <- Results, X =/= undefined],
          ?assertEqual(1, length(Winners)),
          ?assertEqual(Info, hd(Winners))
      end, lists:seq(1, Rounds)).

pending_sweep_expired() ->
    %% Directly insert an expired entry into the ETS table.
    ExpiredTime = erlang:monotonic_time(millisecond) - 200000,  %% 200s ago (TTL is 120s)
    ets:insert(yuzu_gw_pending, {<<"sweep-expired-1">>, #{agent_id => <<"x">>}, ExpiredTime}),

    %% Trigger sweep.
    yuzu_gw_registry ! sweep_pending,
    registry_barrier(),

    %% Expired entry should be gone.
    ?assertEqual([], ets:lookup(yuzu_gw_pending, <<"sweep-expired-1">>)).

pending_sweep_preserves_fresh() ->
    %% Insert a fresh entry.
    FreshTime = erlang:monotonic_time(millisecond),
    ets:insert(yuzu_gw_pending, {<<"sweep-fresh-1">>, #{agent_id => <<"y">>}, FreshTime}),

    %% Also insert an expired one.
    ExpiredTime = erlang:monotonic_time(millisecond) - 200000,
    ets:insert(yuzu_gw_pending, {<<"sweep-expired-2">>, #{agent_id => <<"z">>}, ExpiredTime}),

    %% Trigger sweep.
    yuzu_gw_registry ! sweep_pending,
    registry_barrier(),

    %% Fresh entry should still exist.
    ?assertMatch([{_, _, _}], ets:lookup(yuzu_gw_pending, <<"sweep-fresh-1">>)),
    %% Expired entry should be gone.
    ?assertEqual([], ets:lookup(yuzu_gw_pending, <<"sweep-expired-2">>)),

    %% Cleanup.
    ets:delete(yuzu_gw_pending, <<"sweep-fresh-1">>).

%%%===================================================================
%%% Monitor ref leak tests
%%%===================================================================

reregister_no_monitor_leak() ->
    %% Register agent, then re-register with a new process.
    %% The old monitor ref should be removed from the map.
    Pid1 = spawn_dummy(),
    Pid2 = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(<<"leak-test">>, Pid1, <<"s1">>, [], <<>>),
    ok = yuzu_gw_registry:register_agent(<<"leak-test">>, Pid2, <<"s2">>, [], <<>>),

    %% Inspect the gen_server state via sys:get_state.
    {state, MonRefs, _SweepTimer} = sys:get_state(yuzu_gw_registry),

    %% There should be exactly one monitor ref for <<"leak-test">>.
    RefCount = length([V || {_, V} <- maps:to_list(MonRefs), V =:= <<"leak-test">>]),
    ?assertEqual(1, RefCount),

    kill_dummy(Pid1),
    kill_dummy(Pid2).

%%%===================================================================
%%% #1197: entries_for_sessions/1
%%%===================================================================

%% Each held session resolves, through the session index, to the agent id, the
%% session and the stored RegisterRequest, in the shape all_register_reqs/0
%% returns. Ids this node does not hold are dropped. The lookup writes nothing.
entries_for_held_sessions() ->
    {A1, P1, S1, R1} = efs_register(<<"a">>),
    {A2, P2, S2, R2} = efs_register(<<"b">>),
    AgentsBefore = lists:sort(ets:tab2list(yuzu_gw_agents)),
    IndexBefore = lists:sort(ets:tab2list(yuzu_gw_sessions)),
    Got = yuzu_gw_registry:entries_for_sessions([S2, <<"efs-unknown-session">>, S1]),
    ?assertEqual(lists:sort([{A1, S1, R1}, {A2, S2, R2}]), lists:sort(Got)),
    ?assertEqual([], yuzu_gw_registry:entries_for_sessions([<<"efs-unknown-session">>])),
    ?assertEqual([], yuzu_gw_registry:entries_for_sessions([])),
    ?assertEqual(AgentsBefore, lists:sort(ets:tab2list(yuzu_gw_agents))),
    ?assertEqual(IndexBefore, lists:sort(ets:tab2list(yuzu_gw_sessions))),
    efs_cleanup([{A1, P1, S1}, {A2, P2, S2}]).

%% The routing table is public, so a row can be replaced under the index: the
%% index still says S -> P1 while the routing row now holds P2. The id must
%% not resolve; the control line first shows it does while they agree.
entries_drop_pid_mismatch() ->
    {A, P1, S, R} = efs_register(<<"pm">>),
    ?assertEqual([{A, S, R}], yuzu_gw_registry:entries_for_sessions([S])),
    P2 = spawn_dummy(),
    true = ets:insert(yuzu_gw_agents, {A, P2, node(P2), S, [], 0, <<>>, R}),
    ?assertEqual([], yuzu_gw_registry:entries_for_sessions([S])),
    efs_cleanup([{A, P1, S}]),
    kill_dummy(P2).

%% Same, with the routing row holding the right pid but another session.
entries_drop_session_mismatch() ->
    {A, P, S, R} = efs_register(<<"sm">>),
    ?assertEqual([{A, S, R}], yuzu_gw_registry:entries_for_sessions([S])),
    true = ets:insert(yuzu_gw_agents, {A, P, node(P), <<"efs-other-session">>, [], 0, <<>>, R}),
    ?assertEqual([], yuzu_gw_registry:entries_for_sessions([S])),
    efs_cleanup([{A, P, S}]).

%% The process is dead: judged by this test's own monitor, so no registry
%% cleanup has to have run for the answer to be [].
entries_drop_dead_process() ->
    {A, P, S, R} = efs_register(<<"dp">>),
    ?assertEqual([{A, S, R}], yuzu_gw_registry:entries_for_sessions([S])),
    Ref = monitor(process, P),
    exit(P, kill),
    receive {'DOWN', Ref, process, P, _} -> ok
    after 2000 -> erlang:error(dummy_did_not_die)
    end,
    ?assertEqual([], yuzu_gw_registry:entries_for_sessions([S])),
    efs_cleanup([{A, P, S}]).

%% A registry running without its index (new code loaded into a running node)
%% must answer [], not raise. The table is owned by the registry: drop and
%% restore it from inside.
entries_without_session_index() ->
    {A, P, S, R} = efs_register(<<"ni">>),
    ?assertEqual([{A, S, R}], yuzu_gw_registry:entries_for_sessions([S])),
    _ = sys:replace_state(yuzu_gw_registry,
                          fun(St) -> catch ets:delete(yuzu_gw_sessions), St end),
    try
        ?assertEqual([], yuzu_gw_registry:entries_for_sessions([S]))
    after
        _ = sys:replace_state(yuzu_gw_registry, fun(St) ->
            case ets:whereis(yuzu_gw_sessions) of
                undefined ->
                    ets:new(yuzu_gw_sessions,
                            [named_table, set, protected, {read_concurrency, true}]);
                _ ->
                    ok
            end,
            St
        end)
    end,
    efs_cleanup([{A, P, S}]).

%% lookup_local_session/1 is read by the replay drip at pop time. A missing
%% routing table must be an explicit answer the drip can act on, not a crash
%% of the upstream process.
lookup_local_session_without_table() ->
    {A, P, S, _R} = efs_register(<<"lu">>),
    ?assertEqual({ok, {P, S}}, yuzu_gw_registry:lookup_local_session(A)),
    _ = sys:replace_state(yuzu_gw_registry,
                          fun(St) -> catch ets:delete(yuzu_gw_agents), St end),
    try
        ?assertEqual({error, unavailable}, yuzu_gw_registry:lookup_local_session(A))
    after
        _ = sys:replace_state(yuzu_gw_registry, fun(St) ->
            case ets:whereis(yuzu_gw_agents) of
                undefined ->
                    ets:new(yuzu_gw_agents, [named_table, set, public, {read_concurrency, true}]);
                _ ->
                    ok
            end,
            St
        end)
    end,
    efs_cleanup([{A, P, S}]).

%% A live agent bound with register_agent/7 (so the session index row exists)
%% and a request that is unique to it.
efs_register(Suffix) ->
    N = integer_to_binary(erlang:unique_integer([positive])),
    Id = <<"efs-", Suffix/binary, "-", N/binary>>,
    S = <<"efs-session-", Suffix/binary, "-", N/binary>>,
    R = #{info => #{agent_id => Id, hostname => <<"efs-host">>}},
    P = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(Id, P, S, [], <<"efs-host">>, R, efs_conn),
    {Id, P, S, R}.

%% Fenced then unfenced removal, so a replaced routing row and its stale index
%% row both go; the registry barrier drains the casts.
efs_cleanup(Agents) ->
    lists:foreach(fun({A, P, S}) ->
        yuzu_gw_registry:deregister_agent(A, P, S),
        yuzu_gw_registry:deregister_agent(A),
        kill_dummy(P)
    end, Agents),
    registry_barrier().

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Two ways to wait for the registry, replacing fixed `timer:sleep(N)` calls
%% that are UPPER-bound races on a loaded runner (#4851 runs this suite on
%% macOS CI for the first time; BigMags shares its CPU between two agents, and
%% fixed sleeps have already flaked twice there).
%%
%% registry_barrier/0 is for a cast or message THIS process sent the registry
%% (deregister_agent/1, sweep_pending). sys:get_state/1 is a system message
%% queued behind it, so its reply proves the handler has fully run, and the
%% registry's ETS writes are visible as soon as they are made. No deadline is
%% involved, so it also backs the negative checks that follow a sweep.
%%
%% await/2 is for effects driven by ANOTHER process: the registry's monitor
%% 'DOWN' when a dummy agent exits. It polls Fun every 10ms until it returns
%% Want or a 2s deadline passes, and returns the last value. Callers only claim
%% "the cleanup happens", so the deadline changes nothing they assert.
registry_barrier() ->
    _ = sys:get_state(yuzu_gw_registry),
    ok.

await(Fun, Want) ->
    await(Fun, Want, erlang:monotonic_time(millisecond) + 2000).

await(Fun, Want, Deadline) ->
    case Fun() of
        Want -> Want;
        Other ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> Other;
                false -> timer:sleep(10), await(Fun, Want, Deadline)
            end
    end.

spawn_dummy() ->
    spawn(fun() -> receive stop -> ok end end).

kill_dummy(Pid) ->
    Pid ! stop.

collect_all_pages(_Limit, done, Acc) -> Acc;
collect_all_pages(Limit, Cursor, Acc) ->
    {Page, NextCursor} = yuzu_gw_registry:list_agents(Limit, Cursor),
    case Page of
        [] -> Acc;
        _  ->
            Next = case NextCursor of undefined -> done; C -> C end,
            collect_all_pages(Limit, Next, Acc ++ Page)
    end.
