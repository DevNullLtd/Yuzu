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

%%%-------------------------------------------------------------------
%%% The listeners are the tree's last children, the pg scope its first
%%%
%%% Nothing is served before the registry, router and agent supervisor a handler
%%% calls exist, and a listener that cannot bind stops the tree only after the
%%% rest is up. The order is the only thing that guarantees either, so it is
%%% asserted on the child specs the supervisor starts.
%%%-------------------------------------------------------------------

-define(CORE, [yuzu_gw_registry, yuzu_gw_upstream, yuzu_gw_heartbeat_buffer, yuzu_gw_router,
               yuzu_gw_gauge, yuzu_gw_cluster_discovery, yuzu_gw_health, yuzu_gw_agent_sup]).

entry(Name) ->
    #{name => Name, service_protos => [agent_pb],
      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service},
      listen => #{port => 0}}.

with_listeners(Listeners, Fun) ->
    Prev = application:get_env(yuzu_gw, grpc_listeners),
    case Listeners of
        unset -> application:unset_env(yuzu_gw, grpc_listeners);
        _ -> application:set_env(yuzu_gw, grpc_listeners, Listeners)
    end,
    try Fun()
    after
        case Prev of
            {ok, V} -> application:set_env(yuzu_gw, grpc_listeners, V);
            undefined -> application:unset_env(yuzu_gw, grpc_listeners)
        end
    end.

child_ids() ->
    {ok, {_Flags, Specs}} = yuzu_gw_sup:init([]),
    [maps:get(id, S) || S <- Specs].

listeners_are_the_last_children_test() ->
    with_listeners([entry(agent), (entry(mgmt))#{service_protos := [management_pb]}], fun() ->
        Ids = child_ids(),
        ?assertEqual([pg_scope | ?CORE] ++ [{yuzu_grpc_listener, agent}, {yuzu_grpc_listener, mgmt}],
                     Ids),
        %% every listener spec starts the listener layer, permanent
        {ok, {_, Specs}} = yuzu_gw_sup:init([]),
        [?assertMatch(#{start := {yuzu_grpc_listener, start_link, [_]}, restart := permanent},
                      S) || S <- Specs, is_tuple(maps:get(id, S))]
    end).

pg_scope_is_the_first_child_test() ->
    with_listeners([entry(agent)], fun() ->
        ?assertEqual(pg_scope, hd(child_ids()))
    end).

no_listener_children_when_none_are_configured_test_() ->
    [{"unset", fun() ->
                   with_listeners(unset, fun() ->
                       ?assertEqual([pg_scope | ?CORE], child_ids())
                   end)
               end},
     {"empty", fun() ->
                   with_listeners([], fun() ->
                       ?assertEqual([pg_scope | ?CORE], child_ids())
                   end)
               end},
     {"not a list", fun() ->
                        with_listeners(not_a_list, fun() ->
                            ?assertEqual([pg_scope | ?CORE], child_ids())
                        end)
                    end}].
