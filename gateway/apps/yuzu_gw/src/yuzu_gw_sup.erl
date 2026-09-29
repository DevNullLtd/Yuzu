%%%-------------------------------------------------------------------
%%% @doc Top-level supervisor for the yuzu gateway.
%%%
%%% Supervision tree (one_for_one):
%%%   1. yuzu_gw_registry          — ETS owner + pg coordinator
%%%   2. yuzu_gw_upstream          — gRPC client + circuit breaker
%%%   3. yuzu_gw_heartbeat_buffer  — dedicated heartbeat batching worker
%%%   4. yuzu_gw_router            — command fanout coordinator
%%%   5. yuzu_gw_gauge             — periodic VM/agent gauge emitter
%%%   6. yuzu_gw_cluster_discovery — cluster-formation redial loop (#4555)
%%%   7. yuzu_gw_health            — HTTP health/readiness endpoint
%%%   8. yuzu_gw_agent_sup         — simple_one_for_one for agent processes
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
          type     => worker},

        #{id       => yuzu_gw_upstream,
          start    => {yuzu_gw_upstream, start_link, []},
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

        #{id       => yuzu_gw_agent_sup,
          start    => {yuzu_gw_agent_sup, start_link, []},
          restart  => permanent,
          shutdown => infinity,
          type     => supervisor}
    ],

    {ok, {SupFlags, Children}}.
