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
-export([mgmt_auth_reject_reasons/0, heartbeat_reject_reasons/0]).

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
    [yuzu, gw, upstream, registration_replay_triggered],

    %% Guardian side-channel forwarding (agent drift events -> control plane)
    [yuzu, gw, guardian, forward_accepted],
    [yuzu, gw, guardian, forward_dropped],

    %% Heartbeat admission (connection-bound sessions)
    [yuzu, gw, heartbeat, rejected],
    [yuzu, gw, heartbeat, session_mismatch],
    [yuzu, gw, heartbeat, unknown_truncated],
    [yuzu, gw, heartbeat, verdict_dropped],
    [yuzu, gw, heartbeat, coalesced],
    [yuzu, gw, heartbeat, buffer_dropped],

    %% Registrations refused by the per-connection session quota
    [yuzu, gw, session, limit_rejected],

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
%% registration replay attempts by the drip, any outcome (success, failure,
%% accepted=false, superseded); `queue_depth` is the gauge an operator alerts
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

%% Heartbeat admission. `rejected' counts heartbeats refused because no usable
%% binding exists, labeled by the closed reason-atom set from
%% yuzu_gw_heartbeat_admission (never anything caller-supplied, so a sender
%% cannot control label cardinality). `session_mismatch' counts a held session
%% whose heartbeat arrived on a different connection; it carries the fixed
%% event="security" label so it routes to the SIEM like the server's
%% session-binding counters.
handle_event([yuzu, gw, heartbeat, rejected], #{count := N}, Meta, _Config) ->
    Reason = maps:get(reason, Meta, unknown_session),
    prometheus_counter:inc(yuzu_gw_heartbeat_rejected_total,
                           [atom_to_binary(Reason, utf8)], N);

handle_event([yuzu, gw, heartbeat, session_mismatch], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_heartbeat_session_mismatch_total,
                           [<<"security">>], N);

%% Heartbeat verdict consumer (#1197). `registration_replay_triggered'
%% counts replays that started, by trigger (breaker | heartbeat); the label is
%% an atom chosen by yuzu_gw_upstream, never caller-supplied, so a sender
%% cannot control label cardinality. `unknown_truncated' counts verdicts the
%% server cut short. `verdict_dropped' counts session ids the verdict named
%% that were not queued for replay, by reason (malformed | not_local |
%% circuit_open | queue_full: the replay queue is at its cap, or the upstream
%% mailbox holds more than 100 messages so the buffer did not cast the ids);
%% the ids already queued or inside the session guard are deduplicated, not
%% dropped, and are not counted. A missing label falls to `unknown' rather than
%% guessing, and the handler must never crash: telemetry detaches a handler
%% that raises, which would silence every metric.
handle_event([yuzu, gw, upstream, registration_replay_triggered], #{count := N}, Meta, _Config) ->
    Trigger = maps:get(trigger, Meta, unknown),
    prometheus_counter:inc(yuzu_gw_registration_replay_triggered_total,
                           [atom_to_binary(Trigger, utf8)], N);

handle_event([yuzu, gw, heartbeat, unknown_truncated], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_heartbeat_unknown_truncated_total, [], N);

handle_event([yuzu, gw, heartbeat, verdict_dropped], #{count := N}, Meta, _Config) ->
    Reason = maps:get(reason, Meta, unknown),
    prometheus_counter:inc(yuzu_gw_heartbeat_verdict_dropped_total,
                           [atom_to_binary(Reason, utf8)], N);

%% Heartbeat buffer bounds. `coalesced' counts a heartbeat merged into the
%% buffered one of the same session. `buffer_dropped' counts what the buffer
%% gave up to stay bounded, by the closed reason set buffer_full (a heartbeat
%% or whole session dropped) | snapshot_oversize (one snapshot larger than a
%% chunk, heartbeat kept) | snapshot_evicted (oldest snapshot dropped to fit the
%% byte cap) | heartbeat_oversize (the status tags of a heartbeat with too many
%% tags, or larger than a chunk, dropped, heartbeat kept) | heartbeat_invalid (a
%% status tag that is not valid UTF-8 repaired with replacement characters,
%% heartbeat kept) |
%% chunk_rejected (one heartbeat the server rejected with a non-transient
%% status, dropped). The label is an atom chosen by yuzu_gw_heartbeat_buffer; any other
%% value falls to `unknown' so a bug cannot widen the label set, and the handler
%% must never crash (telemetry detaches a handler that raises).
handle_event([yuzu, gw, heartbeat, coalesced], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_heartbeat_coalesced_total, [], N);

handle_event([yuzu, gw, heartbeat, buffer_dropped], #{count := N}, Meta, _Config) ->
    Reason = case maps:get(reason, Meta, unknown) of
        R when R =:= buffer_full; R =:= snapshot_oversize; R =:= snapshot_evicted;
               R =:= heartbeat_oversize; R =:= heartbeat_invalid;
               R =:= chunk_rejected -> R;
        _ -> unknown
    end,
    prometheus_counter:inc(yuzu_gw_heartbeat_buffer_dropped_total,
                           [atom_to_binary(Reason, utf8)], N);

%% A Register or Subscribe refused because its connection already holds
%% `max_sessions_per_connection' agent sessions (yuzu_gw_registry).
handle_event([yuzu, gw, session, limit_rejected], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_session_limit_rejected_total, [], N);

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

%% The closed set of reasons yuzu_gw_authz:reject/1 is called with.
%% yuzu_gw_telemetry_tests checks it against yuzu_gw_authz's source.
-spec mgmt_auth_reject_reasons() -> [atom()].
mgmt_auth_reject_reasons() ->
    [internal_error, no_pins_configured, no_pins_resolved, pin_mismatch,
     missing_server_auth_eku, bad_peer_cert, bad_pin_config].

%% The closed set of `reason' values on yuzu_gw_heartbeat_rejected_total: every
%% `{reject, Reason}' yuzu_gw_heartbeat_admission:check/2 returns except
%% connection_mismatch, which is its own family. yuzu_gw_telemetry_tests
%% checks it against that module's source.
-spec heartbeat_reject_reasons() -> [atom()].
heartbeat_reject_reasons() ->
    [unknown_session, no_connection, registry_unavailable].

%% Every `{help, ...}` string below MUST be plain ASCII (#4707, #5177). This
%% source file is UTF-8, so a literal em dash or smart quote becomes a charlist
%% element > 255, and prometheus_text_format:escape_string/2 calls
%% iolist_to_binary/1 on it, which raises badarg on EVERY scrape: :9568/metrics
%% answers a bare inets HTTP 500 for the whole registry, not just the one
%% metric. yuzu_gw_telemetry_tests:metrics_scrape_renders_test_/0 renders the
%% real registry through the real formatter to catch this.
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
               "discovery redial loop (#4555) - a sustained non-zero rate "
               "alongside a resolved/connected gap most often means a "
               "distribution-cookie mismatch across replicas"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_cluster_address_cap_exceeded_total},
        {labels, []},
        {help, "Total times the cluster discovery redial loop's lifetime "
               "distinct-address cap (1024) refused to atomize a "
               "never-before-seen address (#4555 review round 2) - any "
               "non-zero value means the seed DNS name is returning an "
               "unexpectedly large or rotating/hostile answer set and "
               "should be investigated immediately, not just noted"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_registration_replay_total},
        {labels, []},
        {help, "Total registration replay attempts by the drip, any outcome"}]),
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
    %% Create every rejection-reason series at 0 now. A series that first
    %% appears already at 1 is invisible to increase(), so without this the
    %% FIRST rejection per reason (after the first scrape) never raised the
    %% YuzuGatewayMgmtAuthRejected alert (#5177 review). The list is the closed
    %% set of reject/1 reasons in yuzu_gw_authz; a test keeps the two in step.
    [prometheus_counter:inc(yuzu_gw_mgmt_auth_rejected_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- mgmt_auth_reject_reasons()],
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_rejected_total},
        {labels, [reason]},
        {help, "Agent Heartbeat calls rejected before queueing because no "
               "usable session binding exists, by reason (closed set: "
               "unknown_session = not held by this node, no_connection = "
               "no connection key to compare, registry_unavailable = the "
               "session index does not exist). The agent re-registers on the "
               "NOT_FOUND answer when its build includes the reconnect fix "
               "(see the gateway manual); older agents only log it. A held "
               "session whose heartbeat arrived on "
               "a different connection is counted in "
               "yuzu_gw_heartbeat_session_mismatch_total instead"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_session_mismatch_total},
        {labels, [event]},
        {help, "Agent Heartbeat calls rejected because the session is held by "
               "this node but the call arrived on a different connection than "
               "the one that opened it. Also rises when an HTTP/2 proxy "
               "between agents and the gateway spreads one agent's calls over "
               "several connections. A rise of one per affected agent is "
               "expected when an agent's connection is replaced while its "
               "session is still held (observed with an injected GOAWAY, a "
               "test-only trigger; not observed with an abrupt close or a "
               "gateway restart). "
               "Carries event=security for SIEM routing"}]),
    %% Create every series at 0 now (a series that first appears already at 1
    %% is invisible to increase()).
    [prometheus_counter:inc(yuzu_gw_heartbeat_rejected_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- heartbeat_reject_reasons()],
    prometheus_counter:inc(yuzu_gw_heartbeat_session_mismatch_total,
                           [<<"security">>], 0),
    prometheus_counter:declare([
        {name, yuzu_gw_registration_replay_triggered_total},
        {labels, [trigger]},
        {help, "Registration replays started, by trigger (breaker = the upstream "
               "recovered from failures, replaying every agent this node holds; "
               "heartbeat = the server's heartbeat verdict listed sessions it does "
               "not know, replaying only those)"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_unknown_truncated_total},
        {labels, []},
        {help, "BatchHeartbeat responses whose list of unknown sessions the "
               "server truncated. Sessions beyond the cap may be reported again by "
               "later heartbeats"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_verdict_dropped_total},
        {labels, [reason]},
        {help, "Session ids named by a heartbeat verdict that were not queued "
               "for replay, by reason (malformed = not a usable session id, "
               "not_local = this node does not hold the session, circuit_open = "
               "the upstream circuit breaker is open, queue_full = the replay "
               "queue is at its cap, or the upstream process already holds more "
               "than 100 unhandled messages so the ids were not handed to it). "
               "Ids already queued or replayed within the session guard window "
               "are not counted"}]),
    %% Create every series at 0 now (a series that first appears already at 1
    %% is invisible to increase()).
    [prometheus_counter:inc(yuzu_gw_registration_replay_triggered_total, [T], 0)
     || T <- [<<"breaker">>, <<"heartbeat">>]],
    [prometheus_counter:inc(yuzu_gw_heartbeat_verdict_dropped_total, [R], 0)
     || R <- [<<"malformed">>, <<"not_local">>, <<"circuit_open">>, <<"queue_full">>]],
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_buffer_dropped_total},
        {labels, [reason]},
        {help, "Heartbeat data the gateway buffer gave up to stay bounded or to "
               "keep flushing, by reason (buffer_full = a "
               "heartbeat or whole session dropped because the session count or "
               "byte cap was reached, snapshot_oversize = one fleet snapshot "
               "larger than a request chunk was dropped and the heartbeat kept, "
               "snapshot_evicted = the oldest fleet snapshot was dropped to fit "
               "the byte cap and the heartbeat kept, heartbeat_oversize = the "
               "status tags of a heartbeat that had more than 512 tags or was "
               "larger than a request chunk were dropped and the heartbeat kept, "
               "heartbeat_invalid = a status tag with invalid UTF-8 was repaired "
               "with replacement characters, chunk_rejected = a single heartbeat the "
               "server rejected with a non-transient status was dropped)"}]),
    prometheus_counter:declare([
        {name, yuzu_gw_heartbeat_coalesced_total},
        {labels, []},
        {help, "Heartbeats merged into the already buffered heartbeat of the "
               "same session before a flush (the buffer keeps one per session)"}]),
    [prometheus_counter:inc(yuzu_gw_heartbeat_buffer_dropped_total, [R], 0)
     || R <- [<<"buffer_full">>, <<"snapshot_oversize">>, <<"snapshot_evicted">>,
              <<"heartbeat_oversize">>, <<"heartbeat_invalid">>,
              <<"chunk_rejected">>]],
    prometheus_counter:inc(yuzu_gw_heartbeat_coalesced_total, [], 0),
    prometheus_counter:declare([
        {name, yuzu_gw_session_limit_rejected_total},
        {labels, []},
        {help, "Registrations refused because one connection already holds the "
               "configured number of agent sessions"}]),
    prometheus_counter:inc(yuzu_gw_session_limit_rejected_total, [], 0),
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
               "- counts a cast SEND, not a confirmed delivery; see #4555)"}]),

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
               "most recent tick (#4555) - 0 means the seed name/list "
               "resolved nothing, which is expected for a genuinely "
               "single-node deployment"}]),
    prometheus_gauge:declare([
        {name, yuzu_gw_cluster_peers_connected},
        {labels, [node]},
        {help, "Distribution-connected peer nodes (length(nodes())) as of "
               "the cluster discovery redial loop's most recent tick "
               "(#4555) - compare against peers_resolved to distinguish a "
               "wrong seed name (resolved=0) from a partial mesh (resolved "
               "> connected > 0, most often a cookie mismatch)"}]),

    ok.

node_labels(Meta) ->
    [maps:get(node, Meta, node())].
