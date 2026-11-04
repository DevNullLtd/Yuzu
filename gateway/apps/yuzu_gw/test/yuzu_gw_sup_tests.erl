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

-define(CORE, [yuzu_gw_registry, yuzu_gw_upstream, yuzu_gw_upstream_pressure,
               yuzu_gw_heartbeat_buffer, yuzu_gw_router,
               yuzu_gw_gauge, yuzu_gw_cluster_discovery, yuzu_gw_health,
               yuzu_gw_memory_shedder, yuzu_gw_mem_reclaim, yuzu_gw_agent_sup, yuzu_gw_mgmt_pins]).

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

%% #5696: the management-pin watcher publishes the pins in its init/1, so it
%% must start before any listener can take a management stream.
mgmt_pin_watcher_precedes_the_listeners_test() ->
    with_listeners([(entry(mgmt))#{service_protos := [management_pb]}], fun() ->
        Ids = child_ids(),
        Watcher = length(lists:takewhile(fun(I) -> I =/= yuzu_gw_mgmt_pins end, Ids)),
        Listener = length(lists:takewhile(fun(I) -> I =/= {yuzu_grpc_listener, mgmt} end, Ids)),
        ?assert(Watcher < length(Ids)),
        ?assert(Watcher < Listener)
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

%%%-------------------------------------------------------------------
%%% The upstream client channels
%%%
%%% One child per channel of {yuzu_gw, upstream_client}, AHEAD of the processes
%%% that call them (yuzu_gw_upstream, yuzu_gw_heartbeat_buffer). A supervisor that
%%% lost them would leave every upstream call {error, no_channel}: no agent
%%% registers while the gateway looks up, so the wiring is asserted on the specs.
%%%-------------------------------------------------------------------

with_upstream_client(Client, Fun) ->
    Prev = application:get_env(yuzu_gw, upstream_client),
    case Client of
        unset -> application:unset_env(yuzu_gw, upstream_client);
        _     -> application:set_env(yuzu_gw, upstream_client, Client)
    end,
    try Fun()
    after
        case Prev of
            {ok, V}   -> application:set_env(yuzu_gw, upstream_client, V);
            undefined -> application:unset_env(yuzu_gw, upstream_client)
        end
    end.

two_channels() ->
    #{channels => [{default_channel, [{http, "127.0.0.1", 59991, []}], #{pool_size => 2}},
                   {second_channel, [{http, "127.0.0.1", 59992, []}], #{}}]}.

channel_children_precede_their_callers_test() ->
    with_listeners(unset, fun() -> with_upstream_client(two_channels(), fun() ->
        ?assertEqual([pg_scope, yuzu_gw_registry,
                      {yuzu_grpc_client_channel, default_channel},
                      {yuzu_grpc_client_channel, second_channel},
                      yuzu_gw_upstream, yuzu_gw_upstream_pressure, yuzu_gw_heartbeat_buffer,
                      yuzu_gw_router, yuzu_gw_gauge, yuzu_gw_cluster_discovery, yuzu_gw_health,
                      yuzu_gw_memory_shedder, yuzu_gw_mem_reclaim, yuzu_gw_agent_sup, yuzu_gw_mgmt_pins],
                     child_ids())
    end) end).

channel_children_are_permanent_workers_started_with_their_parsed_config_test() ->
    with_listeners(unset, fun() -> with_upstream_client(two_channels(), fun() ->
        {ok, {_, Specs}} = yuzu_gw_sup:init([]),
        {ok, [First, Second]} = yuzu_grpc_client_config:from_env(),
        Channels = [S || S <- Specs, is_tuple(maps:get(id, S)),
                         element(1, maps:get(id, S)) =:= yuzu_grpc_client_channel],
        ?assertMatch([#{id := {yuzu_grpc_client_channel, default_channel},
                        start := {yuzu_grpc_client_channel, start_link, [First]},
                        restart := permanent, type := worker},
                      #{id := {yuzu_grpc_client_channel, second_channel},
                        start := {yuzu_grpc_client_channel, start_link, [Second]},
                        restart := permanent, type := worker}],
                     Channels),
        ?assertMatch(#{pool_size := 2}, First)
    end) end).

no_channel_children_without_an_upstream_client_test_() ->
    [{"unset", fun() -> with_listeners(unset, fun() -> with_upstream_client(unset, fun() ->
                        ?assertEqual([pg_scope | ?CORE], child_ids())
                    end) end) end},
     {"an empty channel list", fun() -> with_listeners(unset, fun() ->
                        with_upstream_client(#{channels => []}, fun() ->
                            ?assertEqual([pg_scope | ?CORE], child_ids())
                        end) end) end},
     {"a value that does not parse (yuzu_gw_app refuses it before the tree starts)",
      fun() -> with_listeners(unset, fun() ->
                   with_upstream_client(#{channels => [bogus]}, fun() ->
                       ?assertEqual([pg_scope | ?CORE], child_ids())
                   end) end) end}].
