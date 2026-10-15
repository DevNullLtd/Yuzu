%%%-------------------------------------------------------------------
%%% @doc Genuine multi-node tests for HA WS-4 `#4555` gateway cluster
%%% formation (ADR-2002 §7b) — a real OTP `peer` connecting via
%%% `yuzu_gw_cluster_discovery`'s actual mechanism, not a mock.
%%%
%%% WHY THIS DOESN'T TEST THE "SAME SHORT NAME" PRODUCTION CONVENTION
%%% DIRECTLY: `yuzu_gw_cluster_discovery:resolve_targets/0` constructs every
%%% dial target as `<this node's own short name>@<resolved address>` — correct
%%% for the real deployment shape (every gateway replica is the identical
%%% image, same short name, different container/address, different EPMD
%%% instance per container). On ONE eunit test host there is exactly ONE
%%% shared EPMD instance, and EPMD registration is keyed by short name ALONE
%%% — two live nodes cannot share a short name on one EPMD regardless of what
%%% host/address string is attached to the name. So the "same short name"
%%% convention is fundamentally untestable with two real peer processes on
%%% one CI host; it is provable only in a genuinely multi-host/multi-container
%%% topology (the HA WS-4 #4555 scale-capable reference Compose rig).
%%%
%%% What IS both real and testable here, and what these tests cover instead:
%%% the mechanism `resolve_targets/0` feeds INTO — `do_tick/1`'s
%%% `net_kernel:connect_node/1` call against a real target actually forms a
%%% distributed connection, and the running gen_server's
%%% `net_kernel:monitor_nodes(true)` wiring actually observes and telemeters
%%% that connection (and its loss) once formed, regardless of which side
%%% initiated it. `do_tick/1` takes an explicit target list precisely so this
%%% suite can pass it a peer's REAL node name directly, sidestepping the
%%% same-short-name construction this file's own module doc explains cannot
%%% be exercised locally.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cluster_formation_multinode_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% do_tick/1 — a real connect_node against a real peer
%%%===================================================================

%% `peer:start_link/1`'s DEFAULT connection mode establishes the origin<->peer
%% distribution connection itself as part of starting up (empirically
%% confirmed — a fresh default-mode peer is already in `nodes()` immediately
%% after `start_peer/0` returns) — the wrong starting state to test do_tick/1
%% FORMING a new connection. `start_disconnected_peer/0` uses
%% `connection => standard_io` instead: the peer's OWN control channel runs
%% over stdio, independent of distribution, so the node starts genuinely
%% NOT distribution-connected AND survives an explicit disconnect (a
%% default-mode peer's control channel IS the distribution link, so
%% disconnecting one self-terminates the peer — empirically confirmed, and
%% the reason this test does not simply disconnect a `start_peer/0` peer
%% instead).
do_tick_connects_a_genuinely_disconnected_peer_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_registry_multinode_tests:ensure_distributed(),
        {ok, Peer, PeerNode} = start_disconnected_peer(),
        try
            ?assertNot(lists:member(PeerNode, nodes())),
            ok = yuzu_gw_cluster_discovery:do_tick([PeerNode]),
            ?assert(lists:member(PeerNode, nodes()))
        after
            stop_peer(Peer)
        end
    end}.

%% A target that cannot possibly resolve to a live node is a clean,
%% non-crashing failure — do_tick/1 must survive it and still report the
%% (zero) connected count via telemetry, not raise. Also asserts the
%% `connect_failed` telemetry counter actually FIRES on this path
%% (quality-engineer finding, #4555 governance run): prior to this test,
%% zero references to `connect_failed`/`peers_resolved`/`peers_connected`
%% existed anywhere in this test suite, so the counter the shipped
%% `YuzuGatewayClusterPartiallyFormed` alert's remediation guidance leans
%% on was unverified by any test.
do_tick_survives_an_unreachable_target_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_registry_multinode_tests:ensure_distributed(),
        Self = self(),
        HandlerId = {?MODULE, erlang:unique_integer([positive])},
        ensure_telemetry_started(),
        telemetry:attach(
            HandlerId,
            [yuzu, gw, cluster, connect_failed],
            fun(_Event, Measurements, _Meta, _Config) ->
                Self ! {connect_failed, Measurements}
            end,
            #{}),
        try
            Bogus = list_to_atom("yuzu_gw_definitely_not_running@127.0.0.1"),
            ?assertEqual(ok, yuzu_gw_cluster_discovery:do_tick([Bogus])),
            ?assertNot(lists:member(Bogus, nodes())),
            Received = receive
                {connect_failed, Meas} -> Meas
            after 2000 ->
                {error, timeout}
            end,
            ?assertEqual(#{count => 1}, Received)
        after
            telemetry:detach(HandlerId)
        end
    end}.

%% Regression pin for the governance-round BLOCKING fix (`ExternalTargets =
%% Targets -- [node()]` in do_tick/1): a resolved target list that includes
%% THIS node's own address must not count itself into `peers_resolved` —
%% `nodes()` never includes self by Erlang definition, so counting self on
%% the resolved side made the gauge permanently 1 higher than
%% `peers_connected` on every healthy cluster, and the shipped
%% `YuzuGatewayClusterPartiallyFormed` alert would never have cleared.
%% `node()` and a bogus unreachable target together: only the bogus one
%% should count.
do_tick_excludes_self_from_peers_resolved_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_registry_multinode_tests:ensure_distributed(),
        Self = self(),
        HandlerId = {?MODULE, erlang:unique_integer([positive])},
        ensure_telemetry_started(),
        telemetry:attach(
            HandlerId,
            [yuzu, gw, cluster, peers_resolved],
            fun(_Event, Measurements, _Meta, _Config) ->
                Self ! {peers_resolved, Measurements}
            end,
            #{}),
        try
            Bogus = list_to_atom("yuzu_gw_definitely_not_running@127.0.0.1"),
            ok = yuzu_gw_cluster_discovery:do_tick([node(), Bogus]),
            Received = receive
                {peers_resolved, Meas} -> Meas
            after 2000 ->
                {error, timeout}
            end,
            ?assertEqual(#{count => 1}, Received)
        after
            telemetry:detach(HandlerId)
        end
    end}.

%% Regression pin for the `peers_connected` SCOPING fix (PR review, MEDIUM):
%% an unrelated distribution connection (a real peer this tick's target
%% list does NOT include) must not inflate `peers_connected` — it is
%% scoped to `ExternalTargets`, not a bare `length(nodes())`.
do_tick_scopes_peers_connected_to_targets_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_registry_multinode_tests:ensure_distributed(),
        {ok, UnrelatedPeer, _UnrelatedNode} = start_peer(),
        {ok, TargetPeer, TargetNode} = start_peer(),
        Self = self(),
        HandlerId = {?MODULE, erlang:unique_integer([positive])},
        ensure_telemetry_started(),
        telemetry:attach(
            HandlerId,
            [yuzu, gw, cluster, peers_connected],
            fun(_Event, Measurements, _Meta, _Config) ->
                Self ! {peers_connected, Measurements}
            end,
            #{}),
        try
            %% Both peers are connected (start_peer auto-connects), but only
            %% TargetNode is in do_tick/1's own target list.
            ok = yuzu_gw_cluster_discovery:do_tick([TargetNode]),
            Received = receive
                {peers_connected, Meas} -> Meas
            after 2000 ->
                {error, timeout}
            end,
            ?assertEqual(#{count => 1}, Received)
        after
            telemetry:detach(HandlerId),
            stop_peer(UnrelatedPeer),
            stop_peer(TargetPeer)
        end
    end}.

%%%===================================================================
%%% Running gen_server — monitor_nodes wiring fires telemetry
%%%===================================================================

%% Once yuzu_gw_cluster_discovery is running (and this VM is distributed), a
%% connection formed by ANY means — here, the test process itself calling
%% connect_node, standing in for what do_tick/1 does internally — must be
%% observed via net_kernel:monitor_nodes(true) and telemetered as
%% [yuzu, gw, cluster, node_up]/[node_down].
%% Pins `cluster_seed_nodes` to a harmless static value before starting the
%% gen_server (Fable pre-push review, #4555): `init/1` self-ticks
%% immediately, and an empty `cluster_seed_nodes` falls through to a REAL
%% `inet_res:lookup("gateway", in, a)` against the seed DNS name default —
%% on a CI host with a blackholed/absent resolver this can take up to
%% 2s x 3 retries, which could stall this test's own 5s `await_telemetry`
%% bound for reasons having nothing to do with what it's testing. The
%% static override skips DNS entirely.
running_server_telemeters_nodeup_and_nodedown_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_registry_multinode_tests:ensure_distributed(),
        PrevSeedNodes = application:get_env(yuzu_gw, cluster_seed_nodes, []),
        application:set_env(yuzu_gw, cluster_seed_nodes, [<<"127.0.0.1">>]),
        {DiscoveryPid, StartedHere} = case yuzu_gw_cluster_discovery:start_link() of
            {ok, Pid}                       -> {Pid, true};
            {error, {already_started, Pid}} -> {Pid, false}
        end,
        Self = self(),
        HandlerId = {?MODULE, erlang:unique_integer([positive])},
        ensure_telemetry_started(),
        telemetry:attach_many(
            HandlerId,
            [[yuzu, gw, cluster, node_up], [yuzu, gw, cluster, node_down]],
            fun(Event, _Measurements, Meta, _Config) ->
                Self ! {telemetry, Event, Meta}
            end,
            #{}),
        %% Bound BEFORE the try (quality-engineer finding, #4555 governance
        %% run): if the node_up assertion below fails/times out, the `after`
        %% clause must still be able to stop the peer -- a zombie distributed
        %% peer process otherwise survives for the rest of this eunit VM's
        %% lifetime, matching the sibling convention every OTHER multinode
        %% test in this file and in yuzu_gw_registry_multinode_tests.erl
        %% already follows.
        {ok, Peer, PeerNode} = start_peer(),
        try
            true = net_kernel:connect_node(PeerNode),
            ?assertEqual(
                ok,
                await_telemetry([yuzu, gw, cluster, node_up], PeerNode, 5000)),
            stop_peer(Peer),
            ?assertEqual(
                ok,
                await_telemetry([yuzu, gw, cluster, node_down], PeerNode, 15000))
        after
            stop_peer(Peer),
            telemetry:detach(HandlerId),
            case StartedHere of
                true  -> unlink(DiscoveryPid), exit(DiscoveryPid, kill);
                false -> ok
            end,
            application:set_env(yuzu_gw, cluster_seed_nodes, PrevSeedNodes)
        end
    end}.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% BLOCKING fix (FortitudeEtc/Kimi+Codex PR review): `telemetry:attach/4`
%% crashes with `{noproc, telemetry_handler_table}` if the `telemetry` OTP
%% application hasn't been started yet — the standard `rebar3 eunit --dir
%% apps/yuzu_gw/test` full-suite invocation does NOT guarantee that by the
%% time this module's tests run (module execution order is not something
%% any test file here should depend on). This module's own earlier
%% "in isolation only" assumption for this exact crash (recorded in the
%% governance ledger, deferred to #4599) was wrong — it reproduced on live
%% CI on both platforms. Matches the in-tree precedent
%% (`yuzu_gw_authz_tests.erl`'s `telemetry_counter_test_/0` setup).
ensure_telemetry_started() ->
    {ok, _} = application:ensure_all_started(telemetry),
    ok.

await_telemetry(_Event, _PeerNode, TimeoutMs) when TimeoutMs =< 0 ->
    {error, timeout};
await_telemetry(Event, PeerNode, TimeoutMs) ->
    ExpectedNodeLabel = list_to_binary(atom_to_list(PeerNode)),
    Start = erlang:monotonic_time(millisecond),
    receive
        {telemetry, Event, #{node := ExpectedNodeLabel}} ->
            ok;
        {telemetry, _OtherEvent, _Meta} ->
            Elapsed = erlang:monotonic_time(millisecond) - Start,
            await_telemetry(Event, PeerNode, TimeoutMs - Elapsed)
    after TimeoutMs ->
        {error, timeout}
    end.

%% Default connection mode — auto-connects via distribution as part of
%% starting. Used where the test wants an already-live peer to observe or
%% dial (redundantly and harmlessly) against.
start_peer() ->
    {ok, Peer, PeerNode} = peer:start_link(#{
        name => peer:random_name(?MODULE),
        args => ["-pa" | code:get_path()]
    }),
    {ok, Peer, PeerNode}.

%% `connection => standard_io` — the peer's control channel is stdio, not
%% distribution, so the node starts genuinely disconnected and survives an
%% explicit `erlang:disconnect_node/1` (a default-mode peer does not — see
%% do_tick_connects_a_genuinely_disconnected_peer_test_'s comment).
start_disconnected_peer() ->
    {ok, Peer, PeerNode} = peer:start_link(#{
        name => peer:random_name(?MODULE),
        connection => standard_io,
        args => ["-pa" | code:get_path()]
    }),
    {ok, Peer, PeerNode}.

stop_peer(Peer) ->
    catch peer:stop(Peer),
    ok.
