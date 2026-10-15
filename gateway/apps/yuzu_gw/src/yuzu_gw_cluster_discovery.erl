%%%-------------------------------------------------------------------
%%% @doc Gateway multi-node cluster FORMATION (HA WS-4 `#4555`, ADR-2002 §7b).
%%%
%%% Owns exactly one thing: whether a mesh of gateway nodes forms and STAYS
%%% formed. It does not know or care about peer health, load, or latency —
%%% that is slice 4.4's `yuzu_gw_cluster` adjacency-table gen_server, layered
%%% on top of the mesh this module maintains.
%%%
%%% ALWAYS-ON, not boot-time-only: `{connect_all, false}` is set in both
%%% `config/sys.config` and `config/sys.config.prod` (deliberately, to avoid
%%% transitive auto-mesh gossip), which means `global`/OTP never self-heals a
%%% partially-connected node set. A node that reaches only some of its
%%% resolvable peers on any given attempt (a peer's epmd up but its own node
%%% not yet registered, a transient DNS timeout, a `net_ticktime` disconnect)
%%% would stay permanently partially-meshed with nothing to ever redial it if
%%% this loop only ran once. So this gen_server ticks on a FIXED interval,
%%% FOREVER, no backoff: each tick resolves the current peer set, subtracts
%%% already-connected nodes (a `net_kernel:connect_node/1` against an
%%% already-connected peer is a harmless no-op, so the steady-state per-tick
%%% cost is one DNS query plus N cheap no-ops), and dials the remainder.
%%%
%%% Fail-open by design: a node that resolves zero peers keeps running
%%% standalone and keeps retrying — this module never refuses to let the
%%% gateway serve the agents already connected to it.
%%%
%%% Redial interval vs. `net_ticktime`: `net_ticktime` (30s, ~120s full
%%% failure-detection window per OTP's own doc — see `config/vm.args.src`'s
%%% comment) governs how long Erlang waits before declaring a node actually
%%% DOWN after a connectivity loss. The default redial interval (5s) is
%%% deliberately much SHORTER than that window: during the window, a redial
%%% attempt against a technically-still-alive-per-Erlang connection is just
%%% another harmless no-op; once `net_ticktime` finally fires `nodedown`, the
%%% NEXT tick (within one interval) reconnects — so this loop heals a real
%%% disconnect promptly without ever fighting the tick-time mechanism.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cluster_discovery).
-behaviour(gen_server).

-export([start_link/0, ensure_seen_addrs_table/0]).
%% exported for testing
-export([resolve_targets/0, targets_from_addrs/1, sanitize_addrs/1,
         own_short_name/0, own_short_name/1, do_tick/1,
         clamp_interval/1, seen_addrs_count/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_INTERVAL_MS, 5000).

%% Cap on resolved/configured peer addresses processed IN ONE CALL
%% (round-1 PR review fix). This alone is NOT sufficient to prevent
%% atom-table exhaustion — round-2 review (FortitudeEtc/Kimi+Codex)
%% correctly re-escalated: a hostile/misconfigured seed-name DNS answer
%% returning a FRESH set of <=64 never-before-seen addresses on EVERY
%% tick still grows the atom table unboundedly, just over hours instead
%% of instantly (no single call ever exceeds this cap, so this warning
%% alone would never fire). This constant rate-limits a single
%% oversized answer; `cluster_max_lifetime_addrs` (`?DEFAULT_MAX_LIFETIME_ADDRS` below) is the actual bound
%% that stops unbounded growth. 64 is generously above any realistic
%% cluster size (`docs/erlang-gateway-blueprint.md` sizes ~1M AGENTS per
%% gateway NODE, so a cluster of dozens of nodes is already large).
-define(MAX_TARGET_ADDRS, 64).

%% Lifetime cap on DISTINCT addresses this VM will EVER turn into an
%% atom, across every tick, for the life of the OWNING PROCESS (the
%% actual atom-table-exhaustion fix — BLOCKING, PR review rounds 2-3).
%% Erlang atoms are NEVER garbage-collected; `?MAX_TARGET_ADDRS` above
%% only rate-limits a single call, so it does nothing against a hostile
%% DNS answer that stays under that cap per tick while rotating through
%% an unbounded total set over time (this module's own threat model
%% already treats hostile/misconfigured DNS as adversarial, see
%% `?MIN_COOKIE_LENGTH` in `yuzu_gw_app.erl`). `?SEEN_ADDRS_TABLE`
%% records every address string ever accepted; once this many DISTINCT
%% addresses have been atomized, any genuinely new address is refused
%% outright (never dialed that tick) rather than atomized — degraded,
%% not catastrophic.
%%
%% ROUND-3 CORRECTION: an earlier version of this comment claimed the
%% cap held "for the life of the process" and that an attacker forcing
%% restarts to reset it "is already bounded by yuzu_gw_sup's own
%% restart-intensity limits" — NEITHER claim was accurate. `ets:new/2`
%% ties a table's automatic-cleanup-on-owner-death to whichever process
%% CALLS `ensure_seen_addrs_table/0` first; if that were still this
%% gen_server (a `permanent`-restart CHILD, not the supervisor), a
%% worker crash-and-restart (an ordinary event over a long operational
%% lifetime — unrelated bugs, deploys, transient faults, NOT
%% specifically rate-limited by `yuzu_gw_sup`'s `intensity => 10, period
%% => 60`, which only throttles BURSTS, not a slower sustained cadence)
%% would silently reset the count to 0 while the atoms already created
%% stayed permanently allocated — narrowing the finding each round
%% without actually closing it. FIXED: `yuzu_gw_sup:init/1` now calls
%% `ensure_seen_addrs_table/0` itself, BEFORE starting any child, so the
%% SUPERVISOR (which outlives every child restart, and only dies if the
%% whole `yuzu_gw` application does) owns the table. This gen_server's
%% own call to the same idempotent function later just finds the table
%% already exists.
%%
%% Runtime-configurable (`cluster_max_lifetime_addrs`, default below)
%% rather than a compile-time constant specifically so a test can
%% exercise the refusal path with a small temporary cap instead of
%% having to permanently exhaust the real one against the process-
%% global, shared `?SEEN_ADDRS_TABLE` (a table sized to the production
%% default would otherwise poison every other test sharing this eunit
%% VM's table for the rest of the run). The production default, 1024,
%% is generously above any realistic deployment's lifetime address
%% churn (container restarts, IP reassignment) and negligible next to
%% the VM's ~1,048,576-entry atom table.
-define(DEFAULT_MAX_LIFETIME_ADDRS, 1024).
-define(SEEN_ADDRS_TABLE, yuzu_gw_cluster_discovery_seen_addrs).

-record(state, {interval :: pos_integer()}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    RawInterval = application:get_env(yuzu_gw, cluster_redial_interval_ms, ?DEFAULT_INTERVAL_MS),
    Interval = clamp_interval(RawInterval),
    %% Non-distributed VM (a plain unit-test run, or a hand-run `rebar3 shell`
    %% without `-name`) has no distribution to form a mesh over — idle rather
    %% than crash `net_kernel:monitor_nodes/1` with `{error, not_alive}`.
    case node() of
        'nonode@nohost' ->
            ok;
        _ ->
            ok = net_kernel:monitor_nodes(true),
            self() ! tick
    end,
    {ok, #state{interval = Interval}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(tick, #state{interval = Interval} = State) ->
    do_tick(),
    erlang:send_after(Interval, self(), tick),
    {noreply, State};

handle_info({nodeup, Node}, State) ->
    telemetry:execute([yuzu, gw, cluster, node_up], #{}, #{node => node_label(Node)}),
    {noreply, State};

handle_info({nodedown, Node}, State) ->
    telemetry:execute([yuzu, gw, cluster, node_down], #{}, #{node => node_label(Node)}),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

%% @doc Pure: clamps to a 1s floor (PR review finding). An unvalidated
%% `YUZU_GW_CLUSTER_REDIAL_INTERVAL_MS=0` would hot-loop DNS lookups
%% every tick, and a negative value would raise `badarg` in
%% `erlang:send_after/3`. Exported for testing.
-spec clamp_interval(integer()) -> pos_integer().
clamp_interval(RawInterval) -> max(RawInterval, 1000).

do_tick() ->
    do_tick(resolve_targets()).

%% @doc The tick body, parameterised on the target list — exported for
%% testing so the connect/telemetry mechanism can be verified against a
%% real peer's REAL node name directly, without going through
%% resolve_targets/0's "peers share my own short name" address
%% construction (which cannot be exercised by two real nodes sharing one
%% EPMD/test host — see yuzu_gw_cluster_formation_multinode_tests.erl's
%% module doc for why).
-spec do_tick([node()]) -> ok.
do_tick(Targets) ->
    Connected = [node() | nodes()],
    ToDial = Targets -- Connected,
    FailedTargets = lists:foldl(fun(Target, Acc) ->
        case net_kernel:connect_node(Target) of
            true -> Acc;
            _    -> [Target | Acc]
        end
    end, [], ToDial),
    %% Self is a RESOLVED-but-never-DIALED address: DNS naturally returns
    %% every replica's address, including this node's own (a scaled Compose
    %% service resolves to all N members). `nodes()` never includes self by
    %% Erlang definition, so counting self into `peers_resolved` makes it
    %% permanently 1 higher than `peers_connected` on a fully healthy
    %% cluster — the `YuzuGatewayClusterPartiallyFormed` alert (`peers_resolved
    %% - peers_connected > 0`) would never clear. Exclude self so both gauges
    %% count EXTERNAL peers on the same basis (found + empirically verified,
    %% HA WS-4 #4555 governance Gate 4 happy-path review).
    ExternalTargets = Targets -- [node()],
    %% SCOPED to ExternalTargets, not a bare length(nodes()) (PR review
    %% finding): an unrelated inbound distributed connection (a stale node
    %% still holding the cluster cookie, a dev-shell someone left connected)
    %% would otherwise inflate `peers_connected` and could mask a genuinely
    %% failed seed peer — the YuzuGatewayClusterPartiallyFormed alert
    %% (`resolved - connected > 0`) staying clear when it shouldn't.
    ConnectedTargets = [T || T <- ExternalTargets, lists:member(T, nodes())],
    telemetry:execute([yuzu, gw, cluster, peers_resolved], #{count => length(ExternalTargets)}, #{}),
    telemetry:execute([yuzu, gw, cluster, peers_connected], #{count => length(ConnectedTargets)}, #{}),
    case FailedTargets of
        [] ->
            ok;
        _ ->
            %% Bounded, state-triggered logging (only on an actual failure,
            %% never per successful/no-op tick) — telemetry alone left an
            %% on-call operator with a bare failure COUNT and no peer names
            %% to act on before Prometheus/Grafana is wired up (consistency-
            %% auditor C-1 / sre Gate 6 finding, #4555 governance run).
            logger:warning(
                "Cluster discovery: failed to connect to ~p peer(s): ~p. "
                "Check the distribution cookie matches on every node, and "
                "that the peer's distribution port (9100-9105) and epmd "
                "(4369) are reachable.",
                [length(FailedTargets), FailedTargets]),
            telemetry:execute([yuzu, gw, cluster, connect_failed],
                               #{count => length(FailedTargets)}, #{})
    end.

%% @doc The current peer node set — an explicit static override
%% (`cluster_seed_nodes`), when non-empty, REPLACES DNS resolution outright
%% (never merged with it, per ADR-2002 §7b: two independently-configured
%% sources must never silently interact). Otherwise resolves the seed DNS
%% name's A records. Self is NOT excluded here (the caller subtracts
%% `[node() | nodes()]`) — this function answers "who is out there", not
%% "who do I still need to dial". Exported for testing.
-spec resolve_targets() -> [node()].
resolve_targets() ->
    case application:get_env(yuzu_gw, cluster_seed_nodes, []) of
        [] ->
            targets_from_addrs(sanitize_addrs(resolve_seed_dns_addrs()));
        ConfiguredAddrs ->
            RawAddrs = lists:filtermap(fun addr_to_string/1, ConfiguredAddrs),
            Sanitized = sanitize_addrs(RawAddrs),
            %% K-2 (PR review, round 2): an operator who configured a
            %% static override that ends up entirely unusable (every
            %% entry malformed or of an unsupported type) gets NO signal
            %% otherwise that this node silently fell back to standalone
            %% — indistinguishable from "genuinely no override configured".
            case {ConfiguredAddrs, Sanitized} of
                {[_ | _], []} ->
                    logger:warning(
                        "Cluster discovery: cluster_seed_nodes/YUZU_GW_SEED_NODES is "
                        "configured with ~p entries but NONE resolved to a usable "
                        "peer address — this node will run standalone until the "
                        "configuration is fixed.",
                        [length(ConfiguredAddrs)]);
                _ ->
                    ok
            end,
            targets_from_addrs(Sanitized)
    end.

%% @private A `cluster_seed_nodes` entry is a binary via the
%% `YUZU_GW_SEED_NODES` env-override path, but a hand-edited `sys.config`
%% written in ordinary Erlang string style (`["10.0.0.1"]`) is equally
%% valid config syntax — accept both. An entry of any OTHER type (e.g. a
%% quoted atom) is logged and skipped rather than crashing this
%% gen_server every tick (K-3, PR review round 2). `lists:filtermap/2`
%% shape: `{true, Value}` keeps it, `false` drops it.
addr_to_string(A) when is_binary(A) -> {true, binary_to_list(A)};
addr_to_string(A) when is_list(A)   -> {true, A};
addr_to_string(A) ->
    logger:warning(
        "Cluster discovery: cluster_seed_nodes entry ~p is neither a binary "
        "nor a string — skipping it.", [A]),
    false.

%% @private A records for the configured seed name, as dotted-decimal
%% strings. `inet_res:lookup/3` returns `[]` on any resolution failure
%% (unset/misconfigured name, no records, timeout) — never raises — which is
%% exactly the fail-open "nothing found, try again next tick" semantics this
%% module needs.
resolve_seed_dns_addrs() ->
    SeedName = application:get_env(yuzu_gw, cluster_seed_dns_name, <<"gateway">>),
    try [inet:ntoa(Addr) || Addr <- inet_res:lookup(binary_to_list(SeedName), in, a)]
    catch Class:Reason ->
        logger:debug("Cluster discovery: DNS lookup for seed name ~p failed: ~p:~p",
                     [SeedName, Class, Reason]),
        []
    end.

%% @doc NOT pure (despite the name pattern of its siblings) — every
%% gateway node shares the SAME short name (nodes are interchangeable,
%% distinguished only by address, ADR-2002 §7b), so a dialed node atom is
%% always `<my own short name>@<peer address>`, but each address is now
%% routed through the lifetime-bounded `?SEEN_ADDRS_TABLE` (round-2 PR
%% review BLOCKING fix — see `?DEFAULT_MAX_LIFETIME_ADDRS`'s comment) rather than
%% atomized unconditionally: an address seen before REUSES its existing
%% atom (no growth), a genuinely new address is atomized and recorded
%% ONLY while under the lifetime cap, and a new address past the cap is
%% dropped from the result outright (not dialed that tick) rather than
%% ever reaching `list_to_atom/1`. Callers MUST route candidate addresses
%% through `sanitize_addrs/1` first (`resolve_targets/0` does) — this
%% function does not re-validate address FORMAT, only bounds atom
%% creation. Exported for testing.
-spec targets_from_addrs([string()]) -> [node()].
targets_from_addrs(AddrStrs) ->
    ensure_seen_addrs_table(),
    Short = own_short_name(),
    Cap = application:get_env(yuzu_gw, cluster_max_lifetime_addrs,
                               ?DEFAULT_MAX_LIFETIME_ADDRS),
    {Accepted, RefusedCount} = lists:foldr(
        fun(AddrStr, {AccAcc, RefAcc}) ->
            case bounded_target_atom(Short, AddrStr, Cap) of
                {true, Node} -> {[Node | AccAcc], RefAcc};
                false        -> {AccAcc, RefAcc + 1}
            end
        end, {[], 0}, AddrStrs),
    %% Logged/telemetered ONCE per call with a COUNT, not once per
    %% refused address (K4, PR review round 3) — under sustained hostile
    %% DNS past the cap this could otherwise be up to ?MAX_TARGET_ADDRS
    %% error-level log lines every tick indefinitely, well after the
    %% dedicated CRITICAL alert has already made the condition known.
    case RefusedCount of
        0 -> ok;
        _ ->
            Size = ets:info(?SEEN_ADDRS_TABLE, size),
            logger:error(
                "Cluster discovery: lifetime address cap (~p) reached — "
                "refused ~p never-before-seen address(es) this tick. This "
                "process has atomized ~p distinct addresses since it started; "
                "if this keeps happening, the seed DNS name may be returning "
                "a rotating/hostile answer set. A yuzu_gw_cluster_discovery "
                "worker restart does NOT reset this counter (the table is "
                "owned by the long-lived yuzu_gw_sup supervisor).",
                [Cap, RefusedCount, Size]),
            telemetry:execute([yuzu, gw, cluster, address_cap_exceeded],
                               #{count => RefusedCount}, #{})
    end,
    Accepted.

%% @private `{true, Node}` for an address already atomized before (the
%% existing atom is reused, no new atom is created) or one accepted
%% because the lifetime cap has not been reached yet (a new atom is
%% created and recorded so it counts against the cap from now on);
%% `false` (dropped — not dialed this tick) once the cap is reached for a
%% genuinely new address. Purely mechanical — no logging/telemetry here,
%% see `targets_from_addrs/1`'s aggregated call site (K4, round 3).
bounded_target_atom(Short, AddrStr, Cap) ->
    Key = Short ++ "@" ++ AddrStr,
    case ets:lookup(?SEEN_ADDRS_TABLE, Key) of
        [{Key, Node}] ->
            {true, Node};
        [] ->
            case ets:info(?SEEN_ADDRS_TABLE, size) of
                Size when Size >= Cap ->
                    false;
                _ ->
                    Node = list_to_atom(Key),
                    ets:insert(?SEEN_ADDRS_TABLE, {Key, Node}),
                    {true, Node}
            end
    end.

%% @doc Idempotent and callable from any process — `yuzu_gw_sup:init/1`
%% calls this BEFORE starting any child specifically so the long-lived
%% SUPERVISOR owns the table rather than the `yuzu_gw_cluster_discovery`
%% worker (a `permanent`-restart CHILD whose restart would otherwise
%% silently reset the lifetime cap — round-3 PR review finding, see
%% `?DEFAULT_MAX_LIFETIME_ADDRS`'s comment). `public` so any caller
%% (a test exercising `targets_from_addrs/1` directly, this gen_server's
%% own later idempotent call) can read/insert regardless of who owns it;
%% the `badarg` catch handles losing a creation race to another process
%% (two processes both observing `undefined` and racing `ets:new/2`).
%% Exported so `yuzu_gw_sup` can call it.
-spec ensure_seen_addrs_table() -> ok.
ensure_seen_addrs_table() ->
    case ets:info(?SEEN_ADDRS_TABLE) of
        undefined ->
            try ets:new(?SEEN_ADDRS_TABLE, [named_table, public, set])
            catch error:badarg -> ?SEEN_ADDRS_TABLE
            end;
        _ ->
            ?SEEN_ADDRS_TABLE
    end,
    ok.

%% @doc Current count of distinct addresses this VM has ever atomized.
%% Exported for testing only.
-spec seen_addrs_count() -> non_neg_integer().
seen_addrs_count() ->
    ensure_seen_addrs_table(),
    ets:info(?SEEN_ADDRS_TABLE, size).

%% @doc Pure: rate-limits a SINGLE call to at most `?MAX_TARGET_ADDRS`
%% entries (see its comment — this does NOT by itself prevent lifetime
%% atom-table growth; `targets_from_addrs/1`'s lifetime cap is what
%% does). Validates each entry is a well-formed IPv4 literal (rejects a
%% garbage/typo'd static-override entry too, not just a hostile DNS
%% answer) and dedupes within the call. Exported for testing.
-spec sanitize_addrs([string()]) -> [string()].
sanitize_addrs(AddrStrs) ->
    Valid = lists:filter(fun is_valid_ipv4_literal/1, AddrStrs),
    Deduped = lists:usort(Valid),
    case length(Deduped) > ?MAX_TARGET_ADDRS of
        true ->
            logger:warning(
                "Cluster discovery: ~p resolved/configured addresses exceeds "
                "the ~p-address cap — truncating. Check the seed DNS name "
                "isn't returning an unexpectedly large or hostile answer.",
                [length(Deduped), ?MAX_TARGET_ADDRS]),
            lists:sublist(Deduped, ?MAX_TARGET_ADDRS);
        false ->
            Deduped
    end.

-spec is_valid_ipv4_literal(string()) -> boolean().
is_valid_ipv4_literal(AddrStr) ->
    case inet:parse_ipv4_address(AddrStr) of
        {ok, _}    -> true;
        {error, _} -> false
    end.

%% @doc This node's own short-name portion (before `@`). Exported for testing.
-spec own_short_name() -> string().
own_short_name() -> own_short_name(node()).

-spec own_short_name(node()) -> string().
own_short_name(Node) ->
    case string:split(atom_to_list(Node), "@") of
        [Short, _Host] -> Short;
        _              -> atom_to_list(Node)
    end.

node_label(Node) ->
    list_to_binary(atom_to_list(Node)).
