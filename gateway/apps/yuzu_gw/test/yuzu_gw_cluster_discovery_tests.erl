%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_cluster_discovery — HA WS-4 `#4555` gateway
%%% cluster formation (ADR-2002 §7b).
%%%
%%% Real multi-node mesh formation (two live `peer` nodes actually connecting
%%% via this module's redial loop) is exercised by
%%% `yuzu_gw_cluster_formation_multinode_tests.erl`, mirroring the empirical
%%% rigor the HA WS-4 4.3a review required for distributed-Erlang claims. This
%%% module covers the PURE logic in isolation — no real DNS lookup, no real
%%% distribution — so a CI sandbox's network posture can never make these
%%% flaky.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cluster_discovery_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% own_short_name/1 — pure
%%%===================================================================

own_short_name_splits_at_at_sign_test() ->
    ?assertEqual("yuzu_gw", yuzu_gw_cluster_discovery:own_short_name('yuzu_gw@10.0.0.5')).

%% The eunit runner's own non-distributed sentinel node name DOES contain an
%% '@' (it is spelled 'nonode@nohost'), so it splits like any other node atom.
own_short_name_handles_nonode_sentinel_test() ->
    ?assertEqual("nonode",
                 yuzu_gw_cluster_discovery:own_short_name('nonode@nohost')).

%% A genuinely '@'-free atom (not a real node() shape, but a defined input)
%% falls back to the whole atom's string form rather than crashing.
own_short_name_handles_no_at_sign_test() ->
    ?assertEqual("malformed",
                 yuzu_gw_cluster_discovery:own_short_name(malformed)).

own_short_name_zero_arity_matches_node_test() ->
    ?assertEqual(yuzu_gw_cluster_discovery:own_short_name(node()),
                 yuzu_gw_cluster_discovery:own_short_name()).

%%%===================================================================
%%% targets_from_addrs/1 — pure
%%%===================================================================

targets_from_addrs_empty_test() ->
    ?assertEqual([], yuzu_gw_cluster_discovery:targets_from_addrs([])).

targets_from_addrs_uses_own_short_name_test() ->
    Short = yuzu_gw_cluster_discovery:own_short_name(),
    Expected = [list_to_atom(Short ++ "@10.0.0.1"), list_to_atom(Short ++ "@10.0.0.2")],
    ?assertEqual(Expected,
        yuzu_gw_cluster_discovery:targets_from_addrs(["10.0.0.1", "10.0.0.2"])).

%%%===================================================================
%%% sanitize_addrs/1 — pure (BLOCKING PR review fix: atom-table exhaustion)
%%%===================================================================

sanitize_addrs_empty_test() ->
    ?assertEqual([], yuzu_gw_cluster_discovery:sanitize_addrs([])).

sanitize_addrs_rejects_malformed_ipv4_test() ->
    ?assertEqual([],
        yuzu_gw_cluster_discovery:sanitize_addrs(["not-an-address", "gateway", "999.999.999.999"])).

sanitize_addrs_accepts_well_formed_ipv4_test() ->
    ?assertEqual(["10.0.0.1", "10.0.0.2"],
        yuzu_gw_cluster_discovery:sanitize_addrs(["10.0.0.2", "10.0.0.1"])).

sanitize_addrs_dedupes_test() ->
    ?assertEqual(["10.0.0.1"],
        yuzu_gw_cluster_discovery:sanitize_addrs(["10.0.0.1", "10.0.0.1", "10.0.0.1"])).

%% Regression pin for the BLOCKING atom-table-exhaustion fix (FortitudeEtc/
%% Kimi+Codex PR review, empirically reproduced upstream: 10,000 distinct
%% addresses -> +10,000 permanent atoms, no reclaim). A resolved/configured
%% address list larger than the cap must be truncated, never passed through
%% whole — this is the one property that actually prevents the VM-crash,
%% so it gets its own explicit test rather than trusting the cap constant
%% alone.
sanitize_addrs_caps_at_max_target_addrs_test() ->
    ManyAddrs = [lists:flatten(io_lib:format("10.0.~p.~p", [N div 256, N rem 256]))
                 || N <- lists:seq(1, 200)],
    Result = yuzu_gw_cluster_discovery:sanitize_addrs(ManyAddrs),
    ?assertEqual(64, length(Result)),
    %% Every element of the truncated result must still be one of the
    %% original (valid, deduped) candidates -- truncation, not corruption.
    ?assert(lists:all(fun(A) -> lists:member(A, ManyAddrs) end, Result)).

%%%===================================================================
%%% targets_from_addrs/1 — lifetime atom cap (BLOCKING PR review fix,
%%% round 2: a per-call cap alone does not stop UNBOUNDED growth across
%%% many calls each individually under that cap)
%%%===================================================================

%% IMPORTANT: `?SEEN_ADDRS_TABLE` is a process-global, SHARED ETS table —
%% every test below uses `cluster_max_lifetime_addrs` to TEMPORARILY
%% lower the cap to just above the table's CURRENT size (queried fresh
%% each time, never a hardcoded 1024) rather than ever driving the table
%% up to the real production cap. Filling the table to 1024 would
%% permanently poison every OTHER test sharing this eunit VM for the
%% rest of the run (every subsequent call needing a genuinely new
%% address would be refused) — this bit a first draft of this test file
%% and was caught before merge, not after.

%% Feeds a handful of NEW, never-before-seen addresses through
%% targets_from_addrs/1 with the cap temporarily set to just above the
%% current count, until that temporary cap is exactly reached, then
%% asserts one more brand-new address is refused.
targets_from_addrs_enforces_lifetime_cap_test_() ->
    {setup,
     fun() -> application:get_env(yuzu_gw, cluster_max_lifetime_addrs) end,
     fun restore_max_lifetime_addrs/1,
     fun(_Prev) ->
         [{"refuses a genuinely new address once the (temporary) cap is reached",
           fun() ->
               StartCount = yuzu_gw_cluster_discovery:seen_addrs_count(),
               SmallCap = StartCount + 3,
               application:set_env(yuzu_gw, cluster_max_lifetime_addrs, SmallCap),
               _ = yuzu_gw_cluster_discovery:targets_from_addrs(
                       [unique_test_addr() || _ <- lists:seq(1, 3)]),
               ?assertEqual(SmallCap, yuzu_gw_cluster_discovery:seen_addrs_count()),
               Accepted = yuzu_gw_cluster_discovery:targets_from_addrs([unique_test_addr()]),
               ?assertEqual([], Accepted),
               ?assertEqual(SmallCap, yuzu_gw_cluster_discovery:seen_addrs_count())
           end}]
     end}.

%% An address already accepted keeps resolving even with the cap set to
%% (or below) the current count — reuse of an existing atom never
%% consults the cap at all (the ets:lookup hit returns before the cap
%% check is ever reached).
targets_from_addrs_reuses_already_seen_address_past_cap_test_() ->
    {setup,
     fun() -> application:get_env(yuzu_gw, cluster_max_lifetime_addrs) end,
     fun restore_max_lifetime_addrs/1,
     fun(_Prev) ->
         [{"reuse of an already-accepted address is never refused, even at the cap",
           fun() ->
               ExistingAddr = unique_test_addr(),
               [ExistingNode] = yuzu_gw_cluster_discovery:targets_from_addrs([ExistingAddr]),
               StartCount = yuzu_gw_cluster_discovery:seen_addrs_count(),
               application:set_env(yuzu_gw, cluster_max_lifetime_addrs, StartCount),
               ?assertEqual([ExistingNode],
                   yuzu_gw_cluster_discovery:targets_from_addrs([ExistingAddr]))
           end}]
     end}.

restore_max_lifetime_addrs(undefined) ->
    application:unset_env(yuzu_gw, cluster_max_lifetime_addrs);
restore_max_lifetime_addrs({ok, Value}) ->
    application:set_env(yuzu_gw, cluster_max_lifetime_addrs, Value).

unique_test_addr() ->
    "cap-test-" ++ integer_to_list(erlang:unique_integer([positive])).

%%%===================================================================
%%% Table ownership survives a transient user's death (round-3 PR
%%% review: the lifetime cap must be scoped to the OWNING process, not
%%% reset by an unrelated process merely USING the table)
%%%===================================================================

%% This does NOT start the real yuzu_gw_sup tree (whose other children
%% have real port/network side effects unsuited to a plain eunit run) --
%% it instead proves the invariant that actually matters directly:
%% calling targets_from_addrs/1 (exactly what yuzu_gw_cluster_discovery's
%% gen_server does on every tick) from a transient process never makes
%% that process the table's owner, so that process dying (a worker
%% crash-and-restart, in production) cannot delete the table or reset
%% the count. Deliberately spawns and KEEPS ALIVE a dedicated
%% "simulated supervisor" process to establish (or confirm) ownership
%% first, rather than relying on which process happens to own the
%% table already — plain eunit test functions each run in their OWN
%% short-lived process, so which process "incidentally" owns a
%% lazily-created table depends on eunit's own scheduling and is not
%% something this test may assume either way.
worker_process_death_does_not_affect_seen_addrs_table_test() ->
    Self = self(),
    FakeSup = spawn(fun() ->
        ok = yuzu_gw_cluster_discovery:ensure_seen_addrs_table(),
        Self ! sup_ready,
        receive stop -> ok end
    end),
    receive sup_ready -> ok after 2000 -> error(fake_sup_did_not_start) end,
    Owner = ets:info(yuzu_gw_cluster_discovery_seen_addrs, owner),
    ?assert(is_pid(Owner)),
    Addr = unique_test_addr(),
    {WorkerPid, WorkerRef} = spawn_monitor(fun() ->
        [_Node] = yuzu_gw_cluster_discovery:targets_from_addrs([Addr]),
        ok
    end),
    receive
        {'DOWN', WorkerRef, process, WorkerPid, normal} -> ok
    after 2000 ->
        error(worker_did_not_finish)
    end,
    ?assertEqual(Owner, ets:info(yuzu_gw_cluster_discovery_seen_addrs, owner)),
    FakeSup ! stop,
    %% The address the now-dead transient WORKER process atomized is
    %% still resolvable — the table (and the atom it created) survived
    %% the worker's death, independent of the (still-alive) owner.
    ?assertMatch([_], yuzu_gw_cluster_discovery:targets_from_addrs([Addr])).

%%%===================================================================
%%% clamp_interval/1 — pure
%%%===================================================================

clamp_interval_floors_zero_test() ->
    ?assertEqual(1000, yuzu_gw_cluster_discovery:clamp_interval(0)).

clamp_interval_floors_negative_test() ->
    ?assertEqual(1000, yuzu_gw_cluster_discovery:clamp_interval(-500)).

clamp_interval_passes_through_valid_value_test() ->
    ?assertEqual(5000, yuzu_gw_cluster_discovery:clamp_interval(5000)).

%%%===================================================================
%%% resolve_targets/0 — static-override path (deterministic; no network)
%%%===================================================================

resolve_targets_static_override_test_() ->
    {setup,
     fun() ->
         Prev = application:get_env(yuzu_gw, cluster_seed_nodes, []),
         application:set_env(yuzu_gw, cluster_seed_nodes,
                              [<<"10.1.2.3">>, <<"10.1.2.4">>]),
         Prev
     end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"replaces DNS resolution outright with the explicit list",
           fun() ->
               Short = yuzu_gw_cluster_discovery:own_short_name(),
               Expected = [list_to_atom(Short ++ "@10.1.2.3"),
                           list_to_atom(Short ++ "@10.1.2.4")],
               ?assertEqual(Expected, yuzu_gw_cluster_discovery:resolve_targets())
           end}]
     end}.

%% A hand-edited sys.config written in ordinary Erlang string style
%% (`["10.0.0.1"]`) is equally valid config syntax to the env-override
%% path's binaries — LOW PR review finding, previously crashed this
%% gen_server every tick on the string form.
resolve_targets_accepts_mixed_binary_and_string_entries_test_() ->
    {setup,
     fun() ->
         Prev = application:get_env(yuzu_gw, cluster_seed_nodes, []),
         application:set_env(yuzu_gw, cluster_seed_nodes,
                              [<<"10.1.2.3">>, "10.1.2.4"]),
         Prev
     end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"accepts both binary and plain-string entries",
           fun() ->
               Short = yuzu_gw_cluster_discovery:own_short_name(),
               Expected = [list_to_atom(Short ++ "@10.1.2.3"),
                           list_to_atom(Short ++ "@10.1.2.4")],
               ?assertEqual(Expected, yuzu_gw_cluster_discovery:resolve_targets())
           end}]
     end}.

%% A garbage/typo'd static-override entry is filtered by sanitize_addrs/1
%% rather than reaching list_to_atom unfiltered.
resolve_targets_filters_malformed_static_entry_test_() ->
    {setup,
     fun() ->
         Prev = application:get_env(yuzu_gw, cluster_seed_nodes, []),
         application:set_env(yuzu_gw, cluster_seed_nodes,
                              [<<"10.1.2.3">>, <<"not-an-address">>]),
         Prev
     end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"drops the malformed entry, keeps the valid one",
           fun() ->
               Short = yuzu_gw_cluster_discovery:own_short_name(),
               ?assertEqual([list_to_atom(Short ++ "@10.1.2.3")],
                             yuzu_gw_cluster_discovery:resolve_targets())
           end}]
     end}.

%% K-3 (PR review round 2): a cluster_seed_nodes entry that is neither a
%% binary nor a string (e.g. a quoted atom from a hand-edited sys.config)
%% is skipped with a log, not crashed on every tick.
resolve_targets_skips_non_string_static_entry_test_() ->
    {setup,
     fun() ->
         Prev = application:get_env(yuzu_gw, cluster_seed_nodes, []),
         application:set_env(yuzu_gw, cluster_seed_nodes,
                              [<<"10.1.2.3">>, an_atom_not_a_string, 42]),
         Prev
     end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"skips non-binary/non-string entries instead of crashing",
           fun() ->
               Short = yuzu_gw_cluster_discovery:own_short_name(),
               ?assertEqual([list_to_atom(Short ++ "@10.1.2.3")],
                             yuzu_gw_cluster_discovery:resolve_targets())
           end}]
     end}.

%% K-2 (PR review round 2): a static override that is configured but
%% ends up entirely unusable (every entry malformed or unsupported)
%% must not be silently indistinguishable from "no override configured
%% at all" -- it logs a warning. This test only exercises that the
%% function still returns cleanly ([] -- resolve_targets/0 never raises
%% on this path); the warning log itself is asserted by inspection
%% (logger output), not captured here, matching this test file's
%% existing convention of not asserting on log text.
resolve_targets_all_invalid_static_override_returns_empty_test_() ->
    {setup,
     fun() ->
         Prev = application:get_env(yuzu_gw, cluster_seed_nodes, []),
         application:set_env(yuzu_gw, cluster_seed_nodes,
                              [<<"not-an-address">>, <<"also-not-one">>]),
         Prev
     end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"returns an empty list rather than crashing or silently defaulting",
           fun() ->
               ?assertEqual([], yuzu_gw_cluster_discovery:resolve_targets())
           end}]
     end}.

%% An empty static-override list falls through to DNS resolution (exercised
%% here only as far as "does not crash and returns a list" — the seed name
%% defaults to "gateway", which will not resolve in a CI sandbox, and that
%% empty-result case IS the fail-open behavior under test: no peers found is
%% not an error).
resolve_targets_empty_static_falls_through_without_crashing_test_() ->
    {setup,
     fun() -> application:get_env(yuzu_gw, cluster_seed_nodes, []) end,
     fun(Prev) -> application:set_env(yuzu_gw, cluster_seed_nodes, Prev) end,
     fun(_Prev) ->
         [{"empty static list does not crash and returns a list",
           fun() ->
               application:set_env(yuzu_gw, cluster_seed_nodes, []),
               Result = yuzu_gw_cluster_discovery:resolve_targets(),
               ?assert(is_list(Result))
           end}]
     end}.

%% NOTE: a supervised-start test deliberately does NOT live here. This
%% eunit suite runs every test module in ONE shared VM, and
%% yuzu_gw_registry_multinode_tests.erl's ensure_distributed/0 (HA WS-4
%% 4.3a) turns that shared VM distributed and never reverts it (a known,
%% tracked hygiene gap, #4575 item 1) — so whether node() is
%% 'nonode@nohost' by the time THIS module's tests run depends on eunit's
%% module execution order, which this suite must not assume either way.
%% Starting yuzu_gw_cluster_discovery for real, in a genuinely distributed
%% VM with a controlled peer to actually connect to, is covered instead by
%% yuzu_gw_cluster_formation_multinode_tests.erl.
