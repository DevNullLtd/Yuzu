%%%-------------------------------------------------------------------
%%% @doc Top-level supervisor for the yuzu gateway.
%%%
%%% Supervision tree (one_for_one):
%%%   1. yuzu_gw_registry          — ETS owner + pg coordinator
%%%   2. one yuzu_grpc_client_channel per {yuzu_gw, upstream_client} channel — the upstream
%%%      connections (gun), ahead of the processes that call them
%%%      yuzu_gw_upstream          — gRPC client + circuit breaker
%%%      yuzu_gw_upstream_pressure — samples how backed up the path to the server is
%%%   3. yuzu_gw_heartbeat_buffer  — dedicated heartbeat batching worker
%%%   4. yuzu_gw_router            — command fanout coordinator
%%%   5. yuzu_gw_gauge             — periodic VM/agent gauge emitter
%%%   6. yuzu_gw_cluster_discovery — cluster-formation redial loop (#4555)
%%%   7. yuzu_gw_health            — HTTP health/readiness endpoint
%%%   8. yuzu_gw_memory_shedder    — node-wide memory load shedder (suspends the
%%%      agent listener(s) under memory pressure, never the management listener)
%%%   9. yuzu_gw_agent_sup         — simple_one_for_one for agent processes
%%%  10. yuzu_gw_mgmt_pins         — the management-pin watcher (#5696): resolves the
%%%      {cert_file, Path} pins in init, so the first management stream finds them,
%%%      and re-stats them on its own timer; the per-stream check does no file I/O
%%%  11. one yuzu_grpc_listener per {yuzu_gw, grpc_listeners} entry — LAST, so
%%%      nothing is served before the registry, router and agent supervisor a
%%%      handler calls exist, and a listener that cannot bind stops the tree
%%%      rather than leaving a gateway that looks up and serves nothing. The
%%%      entries were validated by yuzu_gw_app before this supervisor started.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_sup).
-behaviour(supervisor).

-export([start_link/0, start_pg/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start the pg scope, tolerating already-started.
start_pg() ->
    case pg:start_link(yuzu_gw) of
        {ok, Pid}                       -> {ok, Pid};
        {error, {already_started, Pid}} -> link(Pid), {ok, Pid};
        Error                           -> Error
    end.

%%--------------------------------------------------------------------
%% supervisor callback
%%--------------------------------------------------------------------

init([]) ->
    %% HA WS-4 #4555, round-3 PR review fix: own the cluster-discovery
    %% lifetime address-cap ETS table HERE, before starting any child, so
    %% the long-lived SUPERVISOR (not the `yuzu_gw_cluster_discovery`
    %% worker below, a `permanent`-restart CHILD) is the table's owner.
    %% A worker restart is an ordinary event over a long operational
    %% lifetime (unrelated bugs, deploys, transient faults) and must NOT
    %% silently reset the atom-table-exhaustion defense — only this
    %% supervisor dying (i.e. the whole `yuzu_gw` application) should.
    %% See yuzu_gw_cluster_discovery.erl's `?DEFAULT_MAX_LIFETIME_ADDRS`
    %% comment for the full rationale.
    ok = yuzu_gw_cluster_discovery:ensure_seen_addrs_table(),

    SupFlags = #{
        strategy  => one_for_one,
        intensity => 10,
        period    => 60
    },

    Children = [
        #{id       => pg_scope,
          start    => {yuzu_gw_sup, start_pg, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_registry,
          start    => {yuzu_gw_registry, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker}

        %% The upstream client channels, ahead of the processes that call them
        %% (yuzu_gw_upstream, yuzu_gw_heartbeat_buffer). The config was validated
        %% by yuzu_gw_app (check_upstream_client_config/0) before this started.
    ] ++ client_channel_children() ++ [
        #{id       => yuzu_gw_upstream,
          start    => {yuzu_gw_upstream, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_upstream_pressure,
          start    => {yuzu_gw_upstream_pressure, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_heartbeat_buffer,
          start    => {yuzu_gw_heartbeat_buffer, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_router,
          start    => {yuzu_gw_router, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_gauge,
          start    => {yuzu_gw_gauge, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        %% HA WS-4 #4555 — always-on cluster-formation redial loop (ADR-2002
        %% §7b). `permanent` restart is the loop's entire "own supervision
        %% strategy": a crash here restarts a fresh gen_server that
        %% immediately re-ticks, same as every other worker in this tree.
        #{id       => yuzu_gw_cluster_discovery,
          start    => {yuzu_gw_cluster_discovery, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_health,
          start    => {yuzu_gw_health, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        %% Node-wide memory load shedder (the third edge bound). Ahead of the
        %% listeners it may suspend; its first tick is one interval away, by
        %% which time the listeners are up. A crash restarts a fresh sampler.
        #{id       => yuzu_gw_memory_shedder,
          start    => {yuzu_gw_memory_shedder, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker},

        #{id       => yuzu_gw_agent_sup,
          start    => {yuzu_gw_agent_sup, start_link, []},
          restart  => permanent,
          shutdown => infinity,
          type     => supervisor},

        %% Directly ahead of the listeners: its init/1 publishes the management
        %% pins before the management listener can take a stream. A restart
        %% leaves the published pins in place (they are a persistent_term).
        #{id       => yuzu_gw_mgmt_pins,
          start    => {yuzu_gw_mgmt_pins, start_link, []},
          restart  => permanent,
          shutdown => 5000,
          type     => worker}
    ] ++ listener_children(),

    {ok, {SupFlags, Children}}.

%% One child per configured upstream channel; none when the key is unset (a
%% gateway under test, which starts its own channels).
client_channel_children() ->
    case yuzu_grpc_client_config:from_env() of
        {ok, Channels} -> [yuzu_grpc_client_channel:child_spec(C) || C <- Channels];
        {error, _}     -> []
    end.

%% One child per configured listener entry; none when the key is unset (a
%% gateway under test, which starts its own listeners).
listener_children() ->
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        Listeners when is_list(Listeners) ->
            [yuzu_grpc_listener:child_spec(Entry) || Entry <- Listeners];
        _ ->
            []
    end.
