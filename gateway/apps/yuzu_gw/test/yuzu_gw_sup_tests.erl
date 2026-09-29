%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_sup — HA WS-4 `#4555` round-3 PR review:
%%% `init/1` must call `yuzu_gw_cluster_discovery:ensure_seen_addrs_table/0`
%%% BEFORE the child spec list, so the long-lived supervisor (not the
%%% `yuzu_gw_cluster_discovery` worker, a `permanent`-restart child) owns
%%% the atom-table-exhaustion defense's ETS table.
%%%
%%% `init/1` is a plain function (the supervisor behaviour calls it, but
%%% nothing stops a test calling it directly) — this does NOT start the
%%% real supervisor process or any of its children, so it carries none
%%% of the real application's port/network/registry side effects.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_sup_tests).
-include_lib("eunit/include/eunit.hrl").

init_creates_cluster_discovery_seen_addrs_table_test() ->
    {ok, {_SupFlags, _ChildSpecs}} = yuzu_gw_sup:init([]),
    ?assertNotEqual(undefined, ets:info(yuzu_gw_cluster_discovery_seen_addrs)).

init_includes_cluster_discovery_child_spec_test() ->
    {ok, {_SupFlags, ChildSpecs}} = yuzu_gw_sup:init([]),
    Ids = [maps:get(id, Spec) || Spec <- ChildSpecs],
    ?assert(lists:member(yuzu_gw_cluster_discovery, Ids)).
