%%%-------------------------------------------------------------------
%%% @doc Telemetry event definitions and Prometheus handler.
%%%
%%% All gateway metrics flow through the standard `telemetry` library.
%%% This module:
%%%   1. Defines all event names as a single source of truth.
%%%   2. Attaches a handler that updates Prometheus counters/histograms.
%%%   3. Starts a periodic gauge emitter for BEAM VM stats.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_telemetry).

-export([setup/0, handle_event/4]).

%% All telemetry event names used by the gateway.
-define(EVENTS, [
    %% Agent lifecycle
    [yuzu, gw, agent, connected],
    [yuzu, gw, agent, disconnected],
    [yuzu, gw, agent, count],

    %% Command plane
    [yuzu, gw, command, dispatched],
    [yuzu, gw, command, completed],
    [yuzu, gw, command, timeout],
    [yuzu, gw, command, fanout],

    %% Stream health
    [yuzu, gw, stream, backpressure],
    [yuzu, gw, stream, command_dropped],
    [yuzu, gw, stream, write_error],

    %% Upstream (C++ server)
    [yuzu, gw, upstream, rpc_latency],
    [yuzu, gw, upstream, rpc_error],
    [yuzu, gw, upstream, tls_handshake_failure],
    [yuzu, gw, upstream, circuit_state],
    [yuzu, gw, upstream, registration_replay],
    [yuzu, gw, upstream, notify_dropped],

    %% Guardian side-channel forwarding (agent drift events -> control plane)
    [yuzu, gw, guardian, forward_accepted],
    [yuzu, gw, guardian, forward_dropped],

    %% Mgmt-plane peer authorization (#1422)
    [yuzu, gw, mgmt_auth, rejected],
    [yuzu, gw, mgmt_auth, pin_unresolved],

    %% Cluster
    [yuzu, gw, cluster, node_up],
    [yuzu, gw, cluster, node_down],
    [yuzu, gw, cluster, rebalance],

    %% Cluster formation (HA WS-4 #4555, ADR-2002 §7b) — distinct from the
    %% node_up/node_down pair above (which fire per net_kernel monitor event):
    %% these are per-tick snapshots from yuzu_gw_cluster_discovery's redial
    %% loop, letting an operator distinguish "wrong seed name" (resolved=0)
    %% from "cookie mismatch across some replicas" (resolved > connected > 0,
    %% since connect_node/1 only ever reports a bare `false` with no reason).
    [yuzu, gw, cluster, peers_resolved],
    [yuzu, gw, cluster, peers_connected],
    [yuzu, gw, cluster, connect_failed],
    %% Fires when the lifetime distinct-address cap is reached and a
    %% genuinely new address is refused (never atomized) — the actual
    %% atom-table-exhaustion defense, distinct from the per-call
    %% sanitize_addrs/1 cap warning (#4555 review round 2).
    [yuzu, gw, cluster, address_cap_exceeded],

    %% BEAM VM
    [yuzu, gw, vm, process_count],
    [yuzu, gw, vm, memory],
    [yuzu, gw, vm, scheduler_util]
]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Attach all telemetry handlers and start the gauge emitter.
setup() ->
    %% Declare Prometheus metrics.
    declare_metrics(),

    %% Attach event handler.
    telemetry:attach_many(
        yuzu_gw_prometheus,
        ?EVENTS,
        fun ?MODULE:handle_event/4,
        #{}
    ),

    ok.

%%--------------------------------------------------------------------
%% telemetry handler callback
%%--------------------------------------------------------------------

handle_event([yuzu, gw, agent, connected], #{count := N}, Meta, _Config) ->
    Labels = node_labels(Meta),
    prometheus_counter:inc(yuzu_gw_agents_connected_total, Labels, N);

handle_event([yuzu, gw, agent, disconnected], #{count := N, duration_ms := D}, Meta, _Config) ->
    Labels = node_labels(Meta),
    prometheus_counter:inc(yuzu_gw_agents_disconnected_total, Labels, N),
    prometheus_histogram:observe(yuzu_gw_agent_session_duration_ms, Labels, D);

handle_event([yuzu, gw, agent, count], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_agents_current, [node()], N);

handle_event([yuzu, gw, command, dispatched], #{count := N}, Meta, _Config) ->
    Plugin = maps:get(plugin, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_commands_dispatched_total, [Plugin], N);

handle_event([yuzu, gw, command, completed], #{duration_ms := D}, Meta, _Config) ->
    Plugin = maps:get(plugin, Meta, <<"unknown">>),
    Status = maps:get(status, Meta, <<"unknown">>),
    prometheus_histogram:observe(yuzu_gw_command_duration_ms, [Plugin, Status], D);

handle_event([yuzu, gw, command, timeout], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_commands_timed_out_total, [], N);

handle_event([yuzu, gw, command, fanout],
             #{target_count := T, dispatched := D, skipped := S,
               remote_dispatched := R}, _Meta, _Config) ->
    prometheus_histogram:observe(yuzu_gw_fanout_target_count, [], T),
    prometheus_histogram:observe(yuzu_gw_fanout_dispatched_count, [], D),
    prometheus_histogram:observe(yuzu_gw_fanout_skipped_count, [], S),
    prometheus_histogram:observe(yuzu_gw_fanout_remote_dispatched_count, [], R);

handle_event([yuzu, gw, stream, backpressure], #{queue_len := Q}, _Meta, _Config) ->
    prometheus_histogram:observe(yuzu_gw_stream_queue_len_distribution, [], Q);

handle_event([yuzu, gw, stream, command_dropped], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_commands_dropped_backpressure_total, [], N);

handle_event([yuzu, gw, stream, write_error], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_stream_write_errors_total, [], N);

handle_event([yuzu, gw, upstream, rpc_latency], #{duration_ms := D}, Meta, _Config) ->
    RpcName = maps:get(rpc_name, Meta, <<"unknown">>),
    prometheus_histogram:observe(yuzu_gw_upstream_rpc_duration_ms, [RpcName], D);

handle_event([yuzu, gw, upstream, rpc_error], #{count := N}, Meta, _Config) ->
    RpcName = maps:get(rpc_name, Meta, <<"unknown">>),
    Code = maps:get(code, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_upstream_rpc_errors_total, [RpcName, Code], N);

%% R-3 (#1243): a DISTINCT counter for upstream TLS handshake failures so an
%% operator can tell "the gateway cert/CA broke" (expiry, rotation, wrong-SAN,
%% missing volume) from a generic circuit-open / "server down" — the two were
%% previously indistinguishable in telemetry.
handle_event([yuzu, gw, upstream, tls_handshake_failure], #{count := N}, Meta, _Config) ->
    RpcName = maps:get(rpc_name, Meta, <<"unknown">>),
    Kind = maps:get(kind, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_upstream_tls_handshake_failures_total, [RpcName, Kind], N);

handle_event([yuzu, gw, upstream, circuit_state], #{count := N}, Meta, _Config) ->
    State = maps:get(state, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_upstream_circuit_transitions_total, [State], N);

%% Gate 7 sre OBS-4 — registration-replay observability. `replayed` counts
%% agents re-proxied upstream; `queue_depth` is the gauge an operator alerts
%% on to spot a replay storm (UP-5) that never drains.
handle_event([yuzu, gw, upstream, registration_replay],
             #{replayed := N, queue_depth := Q}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_registration_replay_total, [], N),
    prometheus_gauge:set(yuzu_gw_registration_replay_queue_depth, [node()], Q);

%% HA WS-4 4.4 round-2 review (Gate 3 finding NEW-1 / Gate 6 COMP-2, NEW-2):
%% yuzu_gw_upstream:handle_cast({notify_stream_status, ...}) emits this on
%% BOTH drop paths (circuit_open | at_capacity) — without this clause the
%% event fires into an unregistered telemetry event and never reaches
%% Prometheus, same failure shape `forward_dropped` above exists to avoid,
%% and specifically the failure mode that made the original F2 fix a no-op:
%% a dropped CONNECTED for an ADOPTED replay session (this slice's
%% reannounce/2 mechanism) left gateway_node/wire_capabilities/
%% stream_home_id unconverged with literally zero operator-visible signal.
handle_event([yuzu, gw, upstream, notify_dropped], #{count := N}, Meta, _Config) ->
    Reason = maps:get(reason, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_upstream_notify_dropped_total, [Reason], N);

%% Guardian side-channel forwarding. `forward_accepted` is the denominator for a
%% drop-rate SLO; `forward_dropped` is split by reason (circuit_open | at_capacity).
%% yuzu_gw_upstream:forward_guardian_message/2 emits both — without these clauses
%% the drop counters fire into an unregistered telemetry event and never reach
%% Prometheus, leaving guardian drift loss invisible.
handle_event([yuzu, gw, guardian, forward_accepted], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_guardian_forward_accepted_total, [], N);

handle_event([yuzu, gw, guardian, forward_dropped], #{count := N}, Meta, _Config) ->
    Reason = maps:get(reason, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_guardian_forward_dropped_total, [Reason], N);

%% Mgmt-plane peer authorization (#1422). `rejected` counts every peer the
%% :50063 auth_fun turned away, labeled by the closed reason-atom set from
%% yuzu_gw_authz:reject/1 (never certificate contents — an authenticated-but-
%% unauthorized peer must not control label cardinality). A sustained non-zero
%% rate is either probing (a CA-cert holder that is not the server) or a
%% misrotated pin killing command forwarding. `pin_unresolved` counts auth
%% attempts during which at least one CONFIGURED pin entry failed to resolve —
%% the pre-staged-rotation-typo signal (a dead pin is otherwise silent while
%% another pin still admits the server).
handle_event([yuzu, gw, mgmt_auth, rejected], #{count := N}, Meta, _Config) ->
    Reason = maps:get(reason, Meta, unknown),
    prometheus_counter:inc(yuzu_gw_mgmt_auth_rejected_total,
                           [atom_to_binary(Reason, utf8)], N);

handle_event([yuzu, gw, mgmt_auth, pin_unresolved], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_mgmt_auth_pin_unresolved_total, [], N);

handle_event([yuzu, gw, cluster, node_up], _Measurements, Meta, _Config) ->
    Node = maps:get(node, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_cluster_events_total, [<<"node_up">>, Node], 1);

handle_event([yuzu, gw, cluster, node_down], _Measurements, Meta, _Config) ->
    Node = maps:get(node, Meta, <<"unknown">>),
    prometheus_counter:inc(yuzu_gw_cluster_events_total, [<<"node_down">>, Node], 1);

handle_event([yuzu, gw, cluster, rebalance], #{moved_agents := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_cluster_rebalanced_agents_total, [], N);

handle_event([yuzu, gw, cluster, peers_resolved], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_cluster_peers_resolved, [node()], N);

handle_event([yuzu, gw, cluster, peers_connected], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_cluster_peers_connected, [node()], N);

handle_event([yuzu, gw, cluster, connect_failed], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_cluster_connect_failures_total, [], N);

handle_event([yuzu, gw, cluster, address_cap_exceeded], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_cluster_address_cap_exceeded_total, [], N);

handle_event([yuzu, gw, vm, process_count], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_process_count, [node()], N);

handle_event([yuzu, gw, vm, memory], Measurements, _Meta, _Config) ->
    Node = node(),
    maps:foreach(fun(Type, Bytes) ->
        prometheus_gauge:set(yuzu_gw_beam_memory_bytes, [Node, Type], Bytes)
    end, Measurements);

handle_event([yuzu, gw, vm, scheduler_util], #{weighted_avg := Avg}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_scheduler_util, [node()], Avg);

handle_event(_Event, _Measurements, _Meta, _Config) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

declare_metrics() ->
    %% Counters
    prometheus_counter:declare([
        {name, yuzu_gw_agents_connected_total},
        {labels, [node]},
        {help, "Total agent connections accepted"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_agents_disconnected_total},
        {labels, [node]},
        {help, "Total agent disconnections"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_commands_dispatched_total},
        {labels, [plugin]},
        {help, "Total commands dispatched to agents"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_commands_timed_out_total},
        {labels, []},
        {help, "Total commands that timed out"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_commands_dropped_backpressure_total},
        {labels, []},
        {help, "Total commands dropped due to backpressure"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_stream_write_errors_total},
        {labels, []},
        {help, "Total gRPC stream write errors"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_upstream_rpc_errors_total},
        {labels, [rpc_name, code]},
        {help, "Upstream RPC errors by method and status code"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_upstream_tls_handshake_failures_total},
        {labels, [rpc_name, kind]},
        {help, "Upstream TLS handshake failures (cert expiry / CA rotation / "
               "wrong-SAN / unreadable cert) - distinct from a generic RPC error "
               "so a broken gateway cert is not mistaken for 'server down'"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_upstream_circuit_transitions_total},
        {labels, [state]},
        {help, "Circuit breaker state transitions (closed, open, half_open)"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_events_total},
        {labels, [event, node]},
        {help, "Cluster membership events"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_rebalanced_agents_total},
        {labels, []},
        {help, "Total agents moved during rebalancing"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_connect_failures_total},
        {labels, []},
        {help, "Total net_kernel:connect_node/1 failures from the cluster "
               "discovery redial loop (#4555) — a sustained non-zero rate "
               "alongside a resolved/connected gap most often means a "
               "distribution-cookie mismatch across replicas"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_address_cap_exceeded_total},
        {labels, []},
        {help, "Total times the cluster discovery redial loop's lifetime "
               "distinct-address cap (1024) refused to atomize a "
               "never-before-seen address (#4555 review round 2) — any "
               "non-zero value means the seed DNS name is returning an "
               "unexpectedly large or rotating/hostile answer set and "
               "should be investigated immediately, not just noted"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_registration_replay_total},
        {labels, []},
        {help, "Total agents re-proxied upstream by the registration-replay drip"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_upstream_notify_dropped_total},
        {labels, [reason]},
        {help, "Stream-status (CONNECTED/DISCONNECTED) notifications dropped "
               "before delivery to the C++ server, by reason (circuit_open | "
               "at_capacity). Includes HA WS-4 4.4's reannounce/2-triggered "
               "CONNECTED after a replay-adopted session -- a sustained "
               "non-zero rate here means agents are converging their "
               "gateway_node placement slower than expected, or not at all, "
               "during a recovery replay burst."}]),
    prometheus_counter:declare([
        {name, yuzu_gw_guardian_forward_accepted_total},
        {labels, []},
        {help, "Guardian drift-event forwards accepted for upstream delivery "
               "(denominator for the forward drop-rate)"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_guardian_forward_dropped_total},
        {labels, [reason]},
        {help, "Guardian drift-event forwards dropped before delivery "
               "(reason: circuit_open | at_capacity). Best-effort; durable "
               "buffering is Guardian A3."}]),
    prometheus_counter:declare([
        {name, yuzu_gw_mgmt_auth_rejected_total},
        {labels, [reason]},
        {help, "Mgmt-plane (:50063) peers rejected by the #1422 SPKI peer pin, "
               "by reason atom (closed set; no certificate contents). Sustained "
               "non-zero = probing by a CA-cert holder, or a misrotated pin "
               "killing server command forwarding"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_mgmt_auth_pin_unresolved_total},
        {labels, []},
        {help, "Mgmt-plane auth attempts during which >=1 configured "
               "mgmt_peer_pins entry failed to resolve (typo'd fingerprint, "
               "unreadable cert file) - the pre-staged-rotation-typo signal"}]),

    %% Histograms
    Buckets = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000],
    prometheus_histogram:declare([
        {name, yuzu_gw_agent_session_duration_ms},
        {labels, [node]},
        {buckets, [1000, 10000, 60000, 300000, 3600000]},
        {help, "Agent session duration in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_command_duration_ms},
        {labels, [plugin, status]},
        {buckets, Buckets},
        {help, "Command execution duration in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_upstream_rpc_duration_ms},
        {labels, [rpc_name]},
        {buckets, Buckets},
        {help, "Upstream C++ server RPC latency in milliseconds"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_target_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents targeted per command fanout"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_dispatched_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents actually dispatched per fanout"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_skipped_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents skipped (not connected) per fanout"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_fanout_remote_dispatched_count},
        {labels, []},
        {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
        {help, "Number of agents dispatched to a DIFFERENT node than the "
               "dispatching one per fanout (HA WS-4 4.3a cross-node routing "
               "— counts a cast SEND, not a confirmed delivery; see #4555)"}]),

    %% Gauges
    prometheus_gauge:declare([
        {name, yuzu_gw_agents_current},
        {labels, [node]},
        {help, "Current number of connected agents"}]),
    prometheus_histogram:declare([
        {name, yuzu_gw_stream_queue_len_distribution},
        {labels, []},
        {buckets, [10, 100, 500, 1000, 5000]},
        {help, "Distribution of stream handler mailbox queue lengths at backpressure events"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_process_count},
        {labels, [node]},
        {help, "BEAM VM process count"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_memory_bytes},
        {labels, [node, type]},
        {help, "BEAM VM memory usage by type"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_beam_scheduler_util},
        {labels, [node]},
        {help, "BEAM scheduler utilization (weighted average)"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_registration_replay_queue_depth},
        {labels, [node]},
        {help, "Agents still queued for registration replay (0 = idle; "
               "a persistently non-zero value indicates a replay storm)"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_cluster_peers_resolved},
        {labels, [node]},
        {help, "Peer addresses found by the cluster discovery redial loop's "
               "most recent tick (#4555) — 0 means the seed name/list "
               "resolved nothing, which is expected for a genuinely "
               "single-node deployment"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_cluster_peers_connected},
        {labels, [node]},
        {help, "Distribution-connected peer nodes (length(nodes())) as of "
               "the cluster discovery redial loop's most recent tick "
               "(#4555) — compare against peers_resolved to distinguish a "
               "wrong seed name (resolved=0) from a partial mesh (resolved "
               "> connected > 0, most often a cookie mismatch)"}]),

    ok.

node_labels(Meta) ->
    [maps:get(node, Meta, node())].
