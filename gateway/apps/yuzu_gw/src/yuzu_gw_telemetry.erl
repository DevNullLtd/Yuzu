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
-export([metric_specs/0, declared_metrics/0, unseeded_metrics/0]).
-export([mgmt_auth_reject_reasons/0, heartbeat_reject_reasons/0,
         origin_ignored_labels/0, dropped_data_reasons/0,
         upstream_dropped_rpcs/0]).

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
    [yuzu, gw, upstream, notify_queue],
    [yuzu, gw, upstream, notify_coalesced],
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

    %% The gRPC layer (yuzu_grpc_stream_h): an origin claim it ignored, and
    %% request bytes it dropped because the call could not use them.
    [yuzu, gw, grpc, origin_ignored],
    [yuzu, gw, grpc, dropped_data],

    %% Edge memory bounds. recv_timeout: a one-request stream aborted because it
    %% buffered its request past limits.request_timeout_ms (yuzu_grpc_stream_h).
    %% The connection-killed counter (max_heap_size) is incremented directly by
    %% yuzu_gw_conn_watch; it is only declared/seeded below, not an event here.
    [yuzu, gw, grpc, recv_timeout],

    %% Node-wide memory load shedding (yuzu_gw_memory_shedder): the current shed
    %% state (gauge 0/1) and each shed transition (counter).
    [yuzu, gw, memory_shedding, state],
    [yuzu, gw, memory_shedding, suspended],

    %% A queued upstream proxy call skipped because its requesting gRPC call
    %% had already ended (yuzu_gw_upstream).
    [yuzu, gw, upstream, call_dropped],

    %% How much of the time the path to the server is backed up
    %% (yuzu_gw_upstream_pressure): the seconds credited since the last event,
    %% and the trailing duty cycle with the slow-server flag derived from it.
    [yuzu, gw, upstream, backpressure],
    [yuzu, gw, upstream, backpressure_state],

    %% Registers refused at the edge, before any upstream call (#4632)
    [yuzu, gw, register, refused],

    %% Mgmt-plane peer authorization (#1422)
    [yuzu, gw, mgmt_auth, rejected],
    [yuzu, gw, mgmt_auth, pin_unresolved],

    %% Certificate files (yuzu_gw_mgmt_pins' tick, yuzu_gw_cert_files): a
    %% pinned management key changed, and a configured certificate file's
    %% readable flag or notAfter changed.
    [yuzu, gw, mgmt_pins, rotated],
    [yuzu, gw, cert_file, state],

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
    [yuzu, gw, vm, scheduler_util],

    %% UPSTREAM workstream (#5695): the permit regulator for proxied calls
    %% (yuzu_gw_upstream_regulator), registration replay outcomes and duration,
    %% and the held stream-status notifications' losses and high-water mark.
    [yuzu, gw, upstream, permits],
    [yuzu, gw, upstream, permit_limit],
    [yuzu, gw, upstream, permit_refused],
    [yuzu, gw, upstream, permit_wait],
    [yuzu, gw, upstream, registration_replay_outcome],
    [yuzu, gw, upstream, registration_replay_done],
    [yuzu, gw, upstream, notify_lost],
    [yuzu, gw, upstream, notify_requeued],
    [yuzu, gw, upstream, notify_held],

    %% METRICS workstream (#5695): the runtime sampler (yuzu_gw_gauge) -- named
    %% processes' mailboxes and queue wait, listener connections against their
    %% ceiling, the management listener's handlers, ports and limits, the run
    %% queue -- the router's fan-outs in flight, and connections Cowboy closed.
    [yuzu, gw, process, mailbox],
    [yuzu, gw, process, queue_wait],
    [yuzu, gw, listener, connections],
    [yuzu, gw, mgmt, streams],
    [yuzu, gw, vm, ports],
    [yuzu, gw, vm, run_queue],
    [yuzu, gw, router, fanouts],
    [yuzu, gw, grpc, connection_closed],

    %% SHEDDER workstream (#5695): the memory shedder's marks in force, and the
    %% suspends and resumes of agent listeners that failed (retried each tick).
    [yuzu, gw, memory_shedding, marks],
    [yuzu, gw, memory_shedding, failing],
    [yuzu, gw, memory_shedding, transition_failed],

    %% G8-CODE workstream (#5695): the concurrent-stream limit the server
    %% declared on the upstream connections (yuzu_gw_upstream_regulator).
    [yuzu, gw, upstream, server_max_streams],

    %% OWNER-RESTART workstream (#5695): a restarted agent owner's outcome
    %% (yuzu_gw_agent's recovering state).
    [yuzu, gw, agent, owner_restart],

    %% NOTIFY-ACK workstream (#5695): stream-status notices the server answered
    %% acknowledged=false (yuzu_gw_upstream): each refusal, the keys awaiting a
    %% resend, and how each awaiting key ended.
    [yuzu, gw, upstream, notify_unacknowledged],
    [yuzu, gw, upstream, notify_unacked],
    [yuzu, gw, upstream, notify_unacked_ended]
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
%% yuzu_gw_upstream emits this when the notify pending store refuses a new
%% key because admitting it would reach `notify_pending_max` keys, counting the
%% key of a half_open probe in flight (#4632: reason is
%% `at_capacity` only; `circuit_open` is no longer emitted because a notify
%% arriving with the breaker not closed is now held, not dropped). Without
%% this clause the event fires into an unregistered telemetry event and never
%% reaches Prometheus, same failure shape `forward_dropped` below exists to
%% avoid. The label is a closed set: `at_capacity' is itself, and a missing
%% reason or any other value (a non-binary included) folds to a pre-seeded
%% `unknown' series, so a bug cannot widen the label set. Only this metric
%% pre-seeds its `unknown' series: verdict_dropped and buffer_dropped fold the
%% same way but their `unknown' series is created on first use.
%% yuzu_gw_upstream emits only the literal at_capacity today. The handler must never crash: telemetry detaches a handler that
%% raises, which would silence every metric.
handle_event([yuzu, gw, upstream, notify_dropped], #{count := N}, Meta, _Config) ->
    Reason = case maps:get(reason, Meta, unknown) of
        <<"at_capacity">> -> <<"at_capacity">>;
        at_capacity -> <<"at_capacity">>;
        _ -> <<"unknown">>
    end,
    prometheus_counter:inc(yuzu_gw_upstream_notify_dropped_total, [Reason], N);

%% #4632: a Register the gateway edge refused itself (an agent id that is empty,
%% missing, not a binary or over 256 bytes), before any reservation and before
%% any upstream call. The label is a closed set: `agent_id_length' is itself, and
%% a missing reason or any other value (a non-binary included) folds to a
%% pre-seeded `unknown' series, so a caller cannot widen the label set and a bug
%% cannot crash this handler (telemetry detaches a handler that raises). The
%% event carries no agent data: the id is the caller's text.
handle_event([yuzu, gw, register, refused], #{count := N}, Meta, _Config) ->
    Reason = case maps:get(reason, Meta, unknown) of
        <<"agent_id_length">> -> <<"agent_id_length">>;
        agent_id_length       -> <<"agent_id_length">>;
        _                     -> <<"unknown">>
    end,
    prometheus_counter:inc(yuzu_gw_register_refused_total, [Reason], N);

%% #4632: size of the notify pending store and the number of NotifyStreamStatus
%% workers the upstream gen_server tracks, reported together because every
%% handler that changes one may change the other. Emitted whenever either
%% changed and once with zeros from yuzu_gw_upstream:init/1.
handle_event([yuzu, gw, upstream, notify_queue],
             #{pending := P, inflight := I}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending, [node()], P),
    prometheus_gauge:set(yuzu_gw_upstream_notify_inflight, [node()], I);

%% #4632: a held notification replaced by a newer event for the same agent
%% session (suppression, not delivery).
handle_event([yuzu, gw, upstream, notify_coalesced], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_notify_coalesced_total, [], N);

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

%% A pinned management key changed (yuzu_gw_mgmt_pins): the wall-clock second
%% it was published. Read by the pin_mismatch alert to tell the rotation window
%% from a real mismatch.
handle_event([yuzu, gw, mgmt_pins, rotated], #{system_time := T}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_mgmt_pin_rotated_timestamp_seconds, [], T);

%% A configured certificate file (yuzu_gw_cert_files): `readable' always, and
%% `not_after' whenever a certificate has ever been read from it -- including
%% after the file became unreadable, when it is the last value read, so an
%% expiring certificate stays loud while readable=0 says the value is no longer
%% confirmed. Never read: no `not_after', no expiry series. `expiry_unknown'
%% (the certificate last read has a notAfter the gateway cannot parse) removes
%% the expiry series: a value kept from an earlier certificate would describe
%% one no longer in the file. role and name are configuration names.
handle_event([yuzu, gw, cert_file, state], M, #{role := Role, name := Name}, _Config) ->
    prometheus_gauge:set(yuzu_gw_cert_file_readable, [Role, Name], maps:get(readable, M)),
    case M of
        #{not_after := T} ->
            prometheus_gauge:set(yuzu_gw_cert_expiry_timestamp_seconds, [Role, Name], T);
        #{expiry_unknown := 1} ->
            _ = prometheus_gauge:remove(yuzu_gw_cert_expiry_timestamp_seconds, [Role, Name]),
            ok;
        _ ->
            ok
    end;

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

%% gRPC layer. `origin_ignored': a listener configured as sitting behind a proxy
%% (yuzu_grpc_origin) did not use the address a claim carried -- the TCP peer is
%% not one of its trusted proxies (untrusted_source), the trusted proxy sent
%% no claim on a call (no_claim: a PROXY LOCAL header, no x-forwarded-for
%% header) or one that is not usable (bad_claim). Origin is resolved per RPC
%% stream, so a health check that opens no stream is never counted. Labelled by
%% mode and reason only, both from closed sets of atoms emitted by that module,
%% never by an address.
%% `dropped_data': request bytes discarded in a state that must not run a
%% handler (a second message of a unary call, DATA after a status).
handle_event([yuzu, gw, grpc, origin_ignored], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_grpc_origin_ignored_total,
                           [atom_to_binary(maps:get(mode, Meta, unknown), utf8),
                            atom_to_binary(maps:get(reason, Meta, unknown), utf8)], N);

handle_event([yuzu, gw, grpc, dropped_data], #{bytes := Bytes}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_grpc_dropped_data_bytes_total,
                           [atom_to_binary(maps:get(reason, Meta, unknown), utf8)], Bytes);

%% A one-request stream aborted because it buffered its request too long. The
%% method is in the event meta for tracing but is not a label (the edge is
%% unauthenticated; the counter must not take attacker-shaped cardinality).
handle_event([yuzu, gw, grpc, recv_timeout], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_grpc_recv_timeout_total, [], N);

handle_event([yuzu, gw, memory_shedding, state], #{active := V}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_memory_shedding_active, [], V);

handle_event([yuzu, gw, memory_shedding, suspended], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_memory_shedding_suspensions_total, [], N);

handle_event([yuzu, gw, upstream, call_dropped], #{count := N}, Meta, _Config) ->
    %% yuzu_gw_upstream names the call as a binary; an atom is tolerated and any
    %% other term is counted as `unknown' (a series that is not pre-seeded), so the
    %% handler cannot fail and be detached by telemetry.
    Rpc = case maps:get(rpc_name, Meta, <<"unknown">>) of
              A when is_atom(A) -> atom_to_binary(A, utf8);
              B when is_binary(B) -> B;
              _ -> <<"unknown">>
          end,
    prometheus_counter:inc(yuzu_gw_upstream_calls_dropped_total, [Rpc], N);

%% Milliseconds credited since the last event, as seconds: a counter whose rate()
%% is the share of time, so its unit is the base unit and the figure needs no
%% scaling. The lanes overlap and are never summed; `any' is the union.
handle_event([yuzu, gw, upstream, backpressure],
             #{any_ms := Any, permits_ms := Permits, notify_ms := Notify,
               guardian_ms := Guardian}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_backpressure_seconds_total, [], Any / 1000),
    [prometheus_counter:inc(yuzu_gw_upstream_lane_saturated_seconds_total,
                            [atom_to_binary(Lane, utf8)], Ms / 1000)
     || {Lane, Ms} <- [{permits, Permits}, {notify, Notify}, {guardian, Guardian}]],
    ok;

handle_event([yuzu, gw, upstream, backpressure_state],
             #{duty_cycle := DutyCycle, slow := Slow}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_backpressure_duty_cycle, [], DutyCycle),
    prometheus_gauge:set(yuzu_gw_upstream_slow, [], Slow);

handle_event([yuzu, gw, heartbeat, session_mismatch], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_heartbeat_session_mismatch_total,
                           [<<"security">>], N);

%% Heartbeat verdict consumer (#1197). `registration_replay_triggered'
%% counts replays that started, by trigger (heartbeat | server_lost_state |
%% notify_loss | manual; breaker is no longer emitted, its series stays); the label is
%% an atom chosen by yuzu_gw_upstream, never caller-supplied, so a sender
%% cannot control label cardinality. `unknown_truncated' counts verdicts the
%% server cut short. `verdict_dropped' counts session ids the verdict named
%% that were not queued for replay, by reason (malformed | not_local |
%% circuit_open | queue_full: the replay queue is at its cap, or the upstream
%% mailbox holds more than 100 messages so the buffer did not cast the ids);
%% the ids already queued or inside the session guard are deduplicated, not
%% dropped, and are not counted. A missing label, or one outside these closed
%% sets (a non-atom included), falls to an `unknown' series that is not
%% pre-seeded, as buffer_dropped does, rather than guessing, and the handler must
%% never crash: telemetry detaches a handler that raises, which would silence
%% every metric.
handle_event([yuzu, gw, upstream, registration_replay_triggered], #{count := N}, Meta, _Config) ->
    Trigger = case maps:get(trigger, Meta, unknown) of
        T when T =:= breaker; T =:= heartbeat; T =:= notify_loss;
               T =:= server_lost_state; T =:= manual -> T;
        _ -> unknown
    end,
    prometheus_counter:inc(yuzu_gw_registration_replay_triggered_total,
                           [atom_to_binary(Trigger, utf8)], N);

handle_event([yuzu, gw, heartbeat, unknown_truncated], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_heartbeat_unknown_truncated_total, [], N);

handle_event([yuzu, gw, heartbeat, verdict_dropped], #{count := N}, Meta, _Config) ->
    Reason = case maps:get(reason, Meta, unknown) of
        R when R =:= malformed; R =:= not_local; R =:= circuit_open;
               R =:= queue_full -> R;
        _ -> unknown
    end,
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

%% UPSTREAM workstream (#5695). Every label is a closed set; a value outside it
%% folds to `unknown' (pre-seeded where the metric is a counter), so a bug can
%% neither widen the label set nor crash this handler.
handle_event([yuzu, gw, upstream, permits], #{held := H, waiting := W}, Meta, _Config) ->
    Class = closed(maps:get(class, Meta, unknown), permit_classes()),
    prometheus_gauge:set(yuzu_gw_upstream_permits_held, [Class], H),
    prometheus_gauge:set(yuzu_gw_upstream_permits_waiting, [Class], W);
handle_event([yuzu, gw, upstream, permit_limit], #{limit := L}, Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_permit_limit,
                         [closed(maps:get(class, Meta, unknown), permit_classes())], L);
handle_event([yuzu, gw, upstream, permit_refused], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_permit_refused_total,
                           [closed(maps:get(class, Meta, unknown), permit_classes()),
                            closed(maps:get(reason, Meta, unknown), permit_refusals())], N);
handle_event([yuzu, gw, upstream, permit_wait], #{seconds := S}, Meta, _Config) ->
    prometheus_histogram:observe(yuzu_gw_upstream_permit_wait_seconds,
                                 [closed(maps:get(class, Meta, unknown), permit_classes())], S);
handle_event([yuzu, gw, upstream, registration_replay_outcome], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_registration_replay_outcomes_total,
                           [closed(maps:get(outcome, Meta, unknown), replay_outcomes())], N);
handle_event([yuzu, gw, upstream, registration_replay_done], #{seconds := S}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_registration_replay_last_duration_seconds, [], S);
handle_event([yuzu, gw, upstream, notify_lost], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_notify_lost_total,
                           [closed(maps:get(event, Meta, unknown), notify_events()),
                            closed(maps:get(reason, Meta, unknown), notify_lost_reasons())], N);
handle_event([yuzu, gw, upstream, notify_requeued], #{count := N}, _Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_notify_requeued_total, [], N);
handle_event([yuzu, gw, upstream, notify_held], #{hwm := Hwm, max := Max}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending_hwm, [], Hwm),
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending_max, [], Max);

%% METRICS workstream (#5695). Labels are closed sets (the sampler's process
%% list, the listener roles, Cowboy's close reasons); anything else folds to
%% `unknown', so a bug can neither widen a label set nor crash this handler.
handle_event([yuzu, gw, process, mailbox], #{len := N}, Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_process_mailbox_len,
                         [closed(maps:get(process, Meta, unknown), process_labels())], N);
handle_event([yuzu, gw, process, queue_wait], #{seconds := S}, Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_process_queue_wait_seconds,
                         [closed(maps:get(process, Meta, unknown), process_labels())], S);
handle_event([yuzu, gw, listener, connections], #{active := A, max := M}, Meta, _Config) ->
    Role = closed(maps:get(listener, Meta, unknown), listener_roles()),
    prometheus_gauge:set(yuzu_gw_listener_connections, [Role], A),
    case M of
        _ when is_integer(M) -> prometheus_gauge:set(yuzu_gw_listener_max_connections, [Role], M);
        _ -> prometheus_gauge:remove(yuzu_gw_listener_max_connections, [Role])
    end;
handle_event([yuzu, gw, mgmt, streams], #{count := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_mgmt_streams_inflight, [], N);
handle_event([yuzu, gw, vm, ports], #{count := N, limit := L} = M, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_ports, [], N),
    prometheus_gauge:set(yuzu_gw_beam_port_limit, [], L),
    case maps:get(fd_limit, M, undefined) of
        F when is_integer(F) -> prometheus_gauge:set(yuzu_gw_beam_fd_limit, [], F);
        _ -> ok
    end;
handle_event([yuzu, gw, vm, run_queue], #{length := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_beam_run_queue, [], N);
handle_event([yuzu, gw, router, fanouts], #{inflight := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_router_fanouts_inflight, [], N);
handle_event([yuzu, gw, grpc, connection_closed], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_grpc_connections_closed_total,
                           [closed(maps:get(listener, Meta, unknown), listener_roles()),
                            closed(maps:get(reason, Meta, unknown), close_reasons())], N);

%% SHEDDER workstream (#5695). `action' is a closed set (suspend, resume);
%% anything else folds to `unknown', so a bug can neither widen the label set
%% nor crash this handler.
handle_event([yuzu, gw, memory_shedding, marks], #{high := H, low := L}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_memory_shedding_high_water_bytes, [], H),
    prometheus_gauge:set(yuzu_gw_memory_shedding_low_water_bytes, [], L);
handle_event([yuzu, gw, memory_shedding, failing], #{count := N}, Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_memory_shedding_transition_failing,
                         [closed(maps:get(action, Meta, unknown), shedding_actions())], N);
handle_event([yuzu, gw, memory_shedding, transition_failed], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_memory_shedding_transition_failures_total,
                           [closed(maps:get(action, Meta, unknown), shedding_actions())], N);

%% G8-CODE workstream (#5695). Unlabelled: the gateway calls upstream on one
%% channel (default_channel).
handle_event([yuzu, gw, upstream, server_max_streams], #{streams := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_server_max_streams, [], N);

%% OWNER-RESTART workstream (#5695). `outcome' is a closed set; anything else
%% folds to `unknown'.
handle_event([yuzu, gw, agent, owner_restart], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_agent_owner_restarts_total,
                           [closed(maps:get(outcome, Meta, unknown), owner_restart_outcomes())], N);

%% NOTIFY-ACK workstream (#5695). `event' and `outcome' are closed sets;
%% anything else folds to `unknown', so a bug can neither widen a label set nor
%% crash this handler.
handle_event([yuzu, gw, upstream, notify_unacknowledged], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_notify_unacknowledged_total,
                           [closed(maps:get(event, Meta, unknown), notify_events())], N);
handle_event([yuzu, gw, upstream, notify_unacked], #{keys := N}, _Meta, _Config) ->
    prometheus_gauge:set(yuzu_gw_upstream_notify_unacked_keys, [], N);
handle_event([yuzu, gw, upstream, notify_unacked_ended], #{count := N}, Meta, _Config) ->
    prometheus_counter:inc(yuzu_gw_upstream_notify_unacked_ended_total,
                           [closed(maps:get(outcome, Meta, unknown), notify_unacked_outcomes())],
                           N);

handle_event(_Event, _Measurements, _Meta, _Config) ->
    ok.

%% UPSTREAM workstream (#5695): the closed label sets, and the fold of anything
%% else (atom or binary) to <<"unknown">>.
permit_classes()      -> [register, replay, inventory].
permit_refusals()     -> [queue_full, deadline, stopping].
replay_outcomes()     -> [adopted, superseded, rejected, failed, skipped, aborted].
notify_events()       -> [connected, disconnected].
notify_lost_reasons() -> [at_capacity, evicted, rejected, crashed, shutdown, unacknowledged].

%% NOTIFY-ACK workstream (#5695): how a notice awaiting a resend ended.
notify_unacked_outcomes() -> [acknowledged, superseded, session_gone, lost].

%% METRICS workstream (#5695): the closed label sets of its families.
process_labels() -> [L || {L, _} <- yuzu_gw_gauge:sampled_processes()].
listener_roles()  -> [agent, management, other].
close_reasons()   -> [idle_timeout, enhance_your_calm, protocol_error].

%% SHEDDER workstream (#5695): the closed label set of its families.
shedding_actions() -> [suspend, resume].

%% OWNER-RESTART workstream (#5695): what a restarted agent owner did.
owner_restart_outcomes() -> [recovered, disconnected_only, gave_up].

closed(Value, Set) when is_atom(Value) ->
    case lists:member(Value, Set) of
        true  -> atom_to_binary(Value, utf8);
        false -> <<"unknown">>
    end;
closed(Value, Set) when is_binary(Value) ->
    case [A || A <- Set, atom_to_binary(A, utf8) =:= Value] of
        [_] -> Value;
        []  -> <<"unknown">>
    end;
closed(_Value, _Set) ->
    <<"unknown">>.

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

%% The closed set of {mode, reason} labels on yuzu_gw_grpc_origin_ignored_total:
%% what yuzu_grpc_origin:resolve/4 can report for each proxy mode (a mode that
%% trusts nothing in particular, `transport', never ignores a claim). For a peer
%% that is a trusted source of a proxy mode, no_claim and bad_claim mean NO
%% OBSERVATION: the origin is undefined and gateway_observed_peer is empty. For
%% a peer that is not a trusted source, untrusted_source, the TCP peer is the
%% origin (as it is in `transport' mode).
-spec origin_ignored_labels() -> [{proxy_protocol | forwarded_for,
                                   untrusted_source | no_claim | bad_claim}].
origin_ignored_labels() ->
    [{Mode, Reason} || Mode <- [proxy_protocol, forwarded_for],
                       Reason <- [untrusted_source, no_claim, bad_claim]].

%% The closed set of `rpc_name' values on yuzu_gw_upstream_calls_dropped_total:
%% the queued upstream calls yuzu_gw_upstream may skip when the caller is gone.
-spec upstream_dropped_rpcs() -> [register | inventory].
upstream_dropped_rpcs() ->
    [register, inventory].

%% The closed set of `reason' values on yuzu_gw_grpc_dropped_data_bytes_total.
-spec dropped_data_reasons() -> [extra_request_data | stream_ended].
dropped_data_reasons() ->
    [extra_request_data, stream_ended].

%% Every `{help, ...}` string below MUST be plain ASCII (#4707, #5177). This
%% source file is UTF-8, so a literal em dash or smart quote becomes a charlist
%% element > 255, and prometheus_text_format:escape_string/2 calls
%% iolist_to_binary/1 on it, which raises badarg on EVERY scrape: :9568/metrics
%% answers a bare inets HTTP 500 for the whole registry, not just the one
%% metric. yuzu_gw_telemetry_tests:metrics_scrape_renders_test_/0 renders the
%% real registry through the real formatter to catch this.
%%
%% @doc Every metric the gateway declares, as {Type, Spec}: the single list
%% declare_metrics/0 declares and declared_metrics/0 names. A metric declared
%% anywhere else is not one of the gateway's.
-spec metric_specs() -> [{counter | gauge | histogram, list()}].
metric_specs() ->
    Buckets = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000],
    [
        %% Counters
        {counter, [
            {name, yuzu_gw_agents_connected_total},
            {labels, [node]},
            {help, "Total agent connections accepted"}]},
        {counter, [
            {name, yuzu_gw_agents_disconnected_total},
            {labels, [node]},
            {help, "Total agent disconnections"}]},
        {counter, [
            {name, yuzu_gw_commands_dispatched_total},
            {labels, [plugin]},
            {help, "Total commands dispatched to agents"}]},
        {counter, [
            {name, yuzu_gw_commands_timed_out_total},
            {labels, []},
            {help, "Total commands that timed out"}]},
        {counter, [
            {name, yuzu_gw_commands_dropped_backpressure_total},
            {labels, []},
            {help, "Total commands dropped due to backpressure"}]},
        {counter, [
            {name, yuzu_gw_stream_write_errors_total},
            {labels, []},
            {help, "Total gRPC stream write errors"}]},
        {counter, [
            {name, yuzu_gw_upstream_rpc_errors_total},
            {labels, [rpc_name, code]},
            {help, "Upstream RPC errors by method and status code. code is a gRPC "
                   "status (a binary digit string), a transport error reason, "
                   "exception (an exception out of the client or transport) or "
                   "encode (the request could not be encoded in this gateway, so it "
                   "never left it; the breaker is not touched). encode and exception "
                   "are pre-seeded at 0 for each RPC name that can emit them; a "
                   "sustained encode increase is a systematic local fault that "
                   "leaves the breaker closed and /readyz ready"}]},
        {counter, [
            {name, yuzu_gw_register_refused_total},
            {labels, [reason]},
            {help, "Registers the gateway edge refused itself before any upstream "
                   "call (the agent id is empty, missing, not a binary or longer "
                   "than 256 bytes), answered INVALID_ARGUMENT. The label reason has "
                   "the closed set agent_id_length, plus unknown for any other value, "
                   "which the gateway does not emit today. These refusals never "
                   "reach the circuit breaker or yuzu_gw_upstream_rpc_errors_total."}]},
        {counter, [
            {name, yuzu_gw_upstream_tls_handshake_failures_total},
            {labels, [rpc_name, kind]},
            {help, "Upstream TLS handshake failures (cert expiry / CA rotation / "
                   "wrong-SAN / unreadable cert) - distinct from a generic RPC error "
                   "so a broken gateway cert is not mistaken for 'server down'"}]},
        {counter, [
            {name, yuzu_gw_upstream_circuit_transitions_total},
            {labels, [state]},
            {help, "Circuit breaker state transitions (closed, open, half_open)"}]},
        {counter, [
            {name, yuzu_gw_cluster_events_total},
            {labels, [event, node]},
            {help, "Cluster membership events"}]},
        {counter, [
            {name, yuzu_gw_cluster_rebalanced_agents_total},
            {labels, []},
            {help, "Total agents moved during rebalancing"}]},
        {counter, [
            {name, yuzu_gw_cluster_connect_failures_total},
            {labels, []},
            {help, "Total net_kernel:connect_node/1 failures from the cluster "
                   "discovery redial loop (#4555) - a sustained non-zero rate "
                   "alongside a resolved/connected gap most often means a "
                   "distribution-cookie mismatch across replicas"}]},
        {counter, [
            {name, yuzu_gw_cluster_address_cap_exceeded_total},
            {labels, []},
            {help, "Total times the cluster discovery redial loop's lifetime "
                   "distinct-address cap (1024) refused to atomize a "
                   "never-before-seen address (#4555 review round 2) - any "
                   "non-zero value means the seed DNS name is returning an "
                   "unexpectedly large or rotating/hostile answer set and "
                   "should be investigated immediately, not just noted"}]},
        {counter, [
            {name, yuzu_gw_registration_replay_total},
            {labels, []},
            {help, "Total registration replay attempts by the drip, any outcome"}]},
        {counter, [
            {name, yuzu_gw_upstream_notify_dropped_total},
            {labels, [reason]},
            {help, "Stream-status (CONNECTED/DISCONNECTED) notifications lost at "
                   "admission because the pending store was at its cap: a new key is "
                   "admitted only while the held keys plus the key of a half_open "
                   "probe in flight stay below notify_pending_max. The label reason "
                   "has the closed set "
                   "at_capacity, plus unknown for any other value, which the "
                   "gateway does not emit today (the circuit_open value is no longer "
                   "emitted: a notification arriving while the breaker is not closed "
                   "is held). It does not count delivery loss after admission (worker failure, "
                   "gateway shutdown). A sustained non-zero rate means agents are "
                   "converging their gateway_node placement slower than expected, or "
                   "not at all, during a connect burst or recovery replay."}]},
        {counter, [
            {name, yuzu_gw_upstream_notify_coalesced_total},
            {labels, []},
            {help, "Held stream-status notifications replaced by a newer event for "
                   "the same agent session and stream home, or a failed probe "
                   "notification superseded by one"}]},
        {counter, [
            {name, yuzu_gw_guardian_forward_accepted_total},
            {labels, []},
            {help, "Guardian drift-event forwards accepted for upstream delivery "
                   "(denominator for the forward drop-rate)"}]},
        {counter, [
            {name, yuzu_gw_guardian_forward_dropped_total},
            {labels, [reason]},
            {help, "Guardian drift-event forwards dropped before delivery "
                   "(reason: circuit_open | at_capacity). Best-effort; durable "
                   "buffering is Guardian A3."}]},
        {counter, [
            {name, yuzu_gw_mgmt_auth_rejected_total},
            {labels, [reason]},
            {help, "Mgmt-plane (:50063) peers rejected by the #1422 SPKI peer pin, "
                   "by reason atom (closed set; no certificate contents). Sustained "
                   "non-zero = probing by a CA-cert holder, or a misrotated pin "
                   "killing server command forwarding"}]},
        {counter, [
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
                   "yuzu_gw_heartbeat_session_mismatch_total instead"}]},
        {counter, [
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
                   "Carries event=security for SIEM routing"}]},
        {counter, [
            {name, yuzu_gw_grpc_origin_ignored_total},
            {labels, [mode, reason]},
            {help, "gRPC calls on a listener configured as behind a proxy whose "
                   "claimed client address was not used, by origin mode "
                   "(proxy_protocol, forwarded_for) and reason (untrusted_source = "
                   "the TCP peer is not one of the listener's trusted proxies, so "
                   "the claim was ignored and the call attributed to the peer; "
                   "no_claim = a trusted proxy sent no claim on the call, such as a "
                   "PROXY LOCAL header or no x-forwarded-for header; bad_claim = the "
                   "claim is not a bare IP address, is over 64 bytes, or has fewer "
                   "than trusted_hops + 1 entries; for these two the call carries no "
                   "observed address). Calls are served either way. "
                   "A steady untrusted_source rate means the listener is reachable "
                   "without going through the proxy"}]},
        {counter, [
            {name, yuzu_gw_grpc_dropped_data_bytes_total},
            {labels, [reason]},
            {help, "Request bytes the gRPC layer discarded because the call could "
                   "not use them, by reason (extra_request_data = a second message "
                   "on a unary or server-streaming call, stream_ended = DATA that "
                   "arrived after a status was sent, including on a refused call). "
                   "The handler is never run for these bytes"}]},
        {counter, [
            {name, yuzu_gw_grpc_recv_timeout_total},
            {labels, []},
            {help, "Unary or server-streaming streams aborted DEADLINE_EXCEEDED "
                   "because the peer buffered the request past "
                   "limits.request_timeout_ms without completing it. A sustained "
                   "non-zero rate on the agent edge is a peer opening streams and "
                   "stalling them half-sent"}]},
        {counter, [
            {name, yuzu_gw_grpc_connection_killed_total},
            {labels, [reason]},
            {help, "Connections the VM killed for passing their per-connection "
                   "memory ceiling (limits.max_connection_memory_bytes, a "
                   "max_heap_size on the Cowboy connection process counting shared "
                   "binaries). reason=max_heap_size. A sustained non-zero rate on "
                   "the agent edge is a peer flooding half-finished requests"}]},
        {gauge, [
            {name, yuzu_gw_memory_shedding_active},
            {labels, []},
            {help, "1 while the gateway is shedding load: erlang:memory(total) "
                   "passed the high-water mark and has not yet fallen to the "
                   "low-water mark, so the agent listener(s) are suspended in Ranch "
                   "and new agent connections are refused; 0 otherwise. A listener "
                   "that could not be suspended or resumed is shown by "
                   "yuzu_gw_memory_shedding_transition_failing. The management "
                   "listener is never suspended"}]},
        {counter, [
            {name, yuzu_gw_memory_shedding_suspensions_total},
            {labels, []},
            {help, "Times the gateway began shedding load (suspended its agent "
                   "listener(s) on crossing the high-water mark). A rising count "
                   "means the node is repeatedly hitting its memory high-water mark"}]},
        {counter, [
            {name, yuzu_gw_upstream_calls_dropped_total},
            {labels, [rpc_name]},
            {help, "Proxied upstream calls not sent because the caller's deadline "
                   "passed while it waited for a permit, or left too little time "
                   "to make the call, by rpc_name (register, inventory)"}]},
        {counter, [
            {name, yuzu_gw_upstream_backpressure_seconds_total},
            {labels, []},
            {help, "Seconds during which the path to the server was backed up: at "
                   "least one lane saturated (a live Register or inventory report "
                   "waiting for a permit, all 10 stream-status notification slots "
                   "held, or all 50 Guardian forward slots held). rate() of "
                   "this is the backpressure duty cycle, 0 to 1. Sampled every "
                   "100 ms"}]},
        {counter, [
            {name, yuzu_gw_upstream_lane_saturated_seconds_total},
            {labels, [lane]},
            {help, "Seconds each lane (permits, notify, guardian) was saturated. The "
                   "lanes overlap: do not add them, use "
                   "yuzu_gw_upstream_backpressure_seconds_total for the whole"}]},
        {counter, [
            {name, yuzu_gw_registration_replay_triggered_total},
            {labels, [trigger]},
            {help, "Registration replays started, by trigger (heartbeat = the server's "
                   "heartbeat verdict listed sessions it does not know, replaying only "
                   "those; server_lost_state = a verdict listed at least half of its "
                   "batch as unknown, so every agent this node holds is replayed; "
                   "notify_loss = a held CONNECTED notification was lost, replaying "
                   "every agent so each re-sends it; manual = a full replay asked for "
                   "by hand; breaker = no longer emitted: a breaker recovery replays "
                   "nothing since PR 5695)"}]},
        {counter, [
            {name, yuzu_gw_heartbeat_unknown_truncated_total},
            {labels, []},
            {help, "BatchHeartbeat responses whose list of unknown sessions the "
                   "server truncated. Sessions beyond the cap may be reported again by "
                   "later heartbeats"}]},
        {counter, [
            {name, yuzu_gw_heartbeat_verdict_dropped_total},
            {labels, [reason]},
            {help, "Session ids named by a heartbeat verdict that were not queued "
                   "for replay, by reason (malformed = not a usable session id, "
                   "not_local = this node does not hold the session, circuit_open = "
                   "the upstream circuit breaker is open, queue_full = the replay "
                   "queue is at its cap, or the upstream process already holds more "
                   "than 100 unhandled messages so the ids were not handed to it). "
                   "Ids already queued or replayed within the session guard window "
                   "are not counted"}]},
        {counter, [
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
                   "server rejected with a non-transient status was dropped)"}]},
        {counter, [
            {name, yuzu_gw_heartbeat_coalesced_total},
            {labels, []},
            {help, "Heartbeats merged into the already buffered heartbeat of the "
                   "same session before a flush (the buffer keeps one per session)"}]},
        {counter, [
            {name, yuzu_gw_session_limit_rejected_total},
            {labels, []},
            {help, "Registrations refused because one connection already holds the "
                   "configured number of agent sessions"}]},
        {counter, [
            {name, yuzu_gw_mgmt_auth_pin_unresolved_total},
            {labels, []},
            {help, "Mgmt-plane auth attempts during which >=1 configured "
                   "mgmt_peer_pins entry failed to resolve (typo'd fingerprint, "
                   "unreadable cert file) - the pre-staged-rotation-typo signal"}]},
        %% Histograms
        {histogram, [
            {name, yuzu_gw_agent_session_duration_ms},
            {labels, [node]},
            {buckets, [1000, 10000, 60000, 300000, 3600000]},
            {help, "Agent session duration in milliseconds"}]},
        {histogram, [
            {name, yuzu_gw_command_duration_ms},
            {labels, [plugin, status]},
            {buckets, Buckets},
            {help, "Command execution duration in milliseconds"}]},
        {histogram, [
            {name, yuzu_gw_upstream_rpc_duration_ms},
            {labels, [rpc_name]},
            {buckets, Buckets},
            {help, "Upstream C++ server RPC latency in milliseconds"}]},
        {histogram, [
            {name, yuzu_gw_fanout_target_count},
            {labels, []},
            {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
            {help, "Number of agents targeted per command fanout"}]},
        {histogram, [
            {name, yuzu_gw_fanout_dispatched_count},
            {labels, []},
            {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
            {help, "Number of agents actually dispatched per fanout"}]},
        {histogram, [
            {name, yuzu_gw_fanout_skipped_count},
            {labels, []},
            {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
            {help, "Number of agents skipped (not connected) per fanout"}]},
        {histogram, [
            {name, yuzu_gw_fanout_remote_dispatched_count},
            {labels, []},
            {buckets, [1, 10, 100, 1000, 10000, 100000, 1000000]},
            {help, "Number of agents dispatched to a DIFFERENT node than the "
                   "dispatching one per fanout (HA WS-4 4.3a cross-node routing "
                   "- counts a cast SEND, not a confirmed delivery; see #4555)"}]},

        %% Gauges
        {gauge, [
            {name, yuzu_gw_agents_current},
            {labels, [node]},
            {help, "Current number of connected agents"}]},
        {histogram, [
            {name, yuzu_gw_stream_queue_len_distribution},
            {labels, []},
            {buckets, [10, 100, 500, 1000, 5000]},
            {help, "Distribution of stream handler mailbox queue lengths at backpressure events"}]},
        {gauge, [
            {name, yuzu_gw_beam_process_count},
            {labels, [node]},
            {help, "BEAM VM process count"}]},
        {gauge, [
            {name, yuzu_gw_beam_memory_bytes},
            {labels, [node, type]},
            {help, "BEAM VM memory usage by type"}]},
        {gauge, [
            {name, yuzu_gw_beam_scheduler_util},
            {labels, [node]},
            {help, "Share of the last sample interval the normal schedulers were busy, "
                   "0 to 1 (dirty schedulers are not counted)"}]},
        {gauge, [
            {name, yuzu_gw_upstream_backpressure_duty_cycle},
            {labels, []},
            {help, "Share of the last 60 s during which the path to the server was "
                   "backed up (0 to 1; see yuzu_gw_upstream_backpressure_seconds_total). "
                   "Reads low for the first minute after a start"}]},
        {gauge, [
            {name, yuzu_gw_upstream_slow},
            {labels, []},
            {help, "1 when yuzu_gw_upstream_backpressure_duty_cycle is 0.5 or more: "
                   "the server answered slower than work arrived for at least half of "
                   "the last minute. 0 otherwise. Not a readiness input"}]},
        {gauge, [
            {name, yuzu_gw_registration_replay_queue_depth},
            {labels, [node]},
            {help, "Agents still queued for registration replay (0 = idle; "
                   "a persistently non-zero value indicates a replay storm)"}]},
        {gauge, [
            {name, yuzu_gw_upstream_notify_pending},
            {labels, [node]},
            {help, "Stream-status notifications held because the in-flight limit is "
                   "reached or the upstream circuit breaker is not closed; drained "
                   "first in first out (0 = nothing held). The key of a half_open "
                   "probe in flight is not counted here, unless a newer "
                   "notification for the same key has since been held, and the "
                   "key still counts toward the notify_pending_max cap"}]},
        {gauge, [
            {name, yuzu_gw_upstream_notify_inflight},
            {labels, [node]},
            {help, "NotifyStreamStatus workers tracked by this gateway process (at "
                   "most 10)"}]},
        %% {duration_unit, false} on both _seconds gauges below: the prometheus
        %% library otherwise reads the suffix as a duration unit and scales every
        %% value set from native time units (a Unix time would render as about 1.76).
        {gauge, [
            {name, yuzu_gw_mgmt_pin_rotated_timestamp_seconds},
            {labels, []},
            {duration_unit, false},
            {help, "Unix time (seconds) at which the management pin watcher last saw a "
                   "pinned {cert_file, Path} certificate change to a different key; 0 "
                   "until the first such change in this process. Not set by the first "
                   "read at start or by a rewrite of the same key"}]},
        {gauge, [
            {name, yuzu_gw_cert_expiry_timestamp_seconds},
            {labels, [role, name]},
            {duration_unit, false},
            {help, "notAfter (Unix seconds) of a certificate file the gateway is "
                   "configured with; for a file holding several certificates, the "
                   "earliest. role: listener | listener_ca | upstream_client | "
                   "upstream_ca | mgmt_peer_pin. If the file stops being readable the "
                   "last value read is kept (see yuzu_gw_cert_file_readable); absent while "
                   "the file holds a certificate whose notAfter cannot be parsed"}]},
        {gauge, [
            {name, yuzu_gw_cert_file_readable},
            {labels, [role, name]},
            {help, "1 when the latest read of every certificate file under this role "
                   "and name parsed as PEM certificates, 0 when a stat, read or parse "
                   "failed (for mgmt_peer_pin the key last read stays pinned). "
                   "Checked every mgmt_pin_refresh_ms"}]},
        {gauge, [
            {name, yuzu_gw_cluster_peers_resolved},
            {labels, [node]},
            {help, "Peer addresses found by the cluster discovery redial loop's "
                   "most recent tick (#4555) - 0 means the seed name/list "
                   "resolved nothing, which is expected for a genuinely "
                   "single-node deployment"}]},
        {gauge, [
            {name, yuzu_gw_cluster_peers_connected},
            {labels, [node]},
            {help, "Distribution-connected peer nodes (length(nodes())) as of "
                   "the cluster discovery redial loop's most recent tick "
                   "(#4555) - compare against peers_resolved to distinguish a "
                   "wrong seed name (resolved=0) from a partial mesh (resolved "
                   "> connected > 0, most often a cookie mismatch)"}]},

        %% ── UPSTREAM workstream (#5695) ────────────────────────────────────────
        %% Proxied-call permits (yuzu_gw_upstream_regulator), registration replay,
        %% held stream-status notifications. Every series is created at 0 here.
        {gauge, [
            {name, yuzu_gw_upstream_permits_held},
            {labels, [class]},
            {help, "Upstream call permits held now, by class: register (a live "
                   "ProxyRegister), replay (a registration replay), inventory (a "
                   "ProxyInventory). register and replay share one pool"}]},
        {gauge, [
            {name, yuzu_gw_upstream_permits_waiting},
            {labels, [class]},
            {help, "Callers waiting for an upstream call permit now, by class. Non-zero "
                   "for register or inventory means every permit of the pool is held"}]},
        {gauge, [
            {name, yuzu_gw_upstream_permit_limit},
            {labels, [class]},
            {help, "Upstream call permits in force, by class (replay is the most of "
                   "the register pool a replay may hold): the configured size, or less "
                   "when the server's declared concurrent-stream limit leaves less room "
                   "(see yuzu_gw_upstream_server_max_streams)"}]},
        {counter, [
            {name, yuzu_gw_upstream_permit_refused_total},
            {labels, [class, reason]},
            {help, "Upstream call permits refused, by class and reason: queue_full (the "
                   "wait queue was full), deadline (the caller's deadline passed first), "
                   "stopping (planned stop). The agent is told UNAVAILABLE and retries"}]},
        {histogram, [
            {name, yuzu_gw_upstream_permit_wait_seconds},
            {labels, [class]},
            {duration_unit, false},
            {buckets, [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]},
            {help, "Seconds a granted upstream call permit was waited for, by class"}]},
        {counter, [
            {name, yuzu_gw_registration_replay_outcomes_total},
            {labels, [outcome]},
            {help, "Registration replay entries by outcome: adopted, superseded, "
                   "rejected (accepted=false), failed, skipped (gone, re-registered, "
                   "no stored request, or replayed within the guard window), aborted "
                   "(dropped when the breaker opened or the registry went away)"}]},
        {gauge, [
            {name, yuzu_gw_registration_replay_last_duration_seconds},
            {labels, []},
            {duration_unit, false},
            {help, "Seconds the last finished registration replay took, from its first "
                   "entry to its last result (0 until one finished)"}]},
        {counter, [
            {name, yuzu_gw_upstream_notify_lost_total},
            {labels, [event, reason]},
            {help, "Stream-status notifications lost, by event (connected, "
                   "disconnected) and reason: at_capacity (not admitted, the held store "
                   "was full), evicted (a held connected notification evicted to admit "
                   "a disconnected one; a full registration replay re-sends it), "
                   "rejected (the server answered that the notification itself was "
                   "wrong, or it could not be encoded), crashed (the send's worker "
                   "died before it reported), shutdown (still held or in flight when "
                   "a planned stop's flush ended, or a refused connected notice still "
                   "waiting for its resend when the flush began), unacknowledged (the "
                   "server answered acknowledged=false and the gateway gave up: a "
                   "disconnected notice past its resend window, any refusal during a "
                   "planned stop's flush, or a full retry set)"}]},
        {counter, [
            {name, yuzu_gw_upstream_notify_requeued_total},
            {labels, []},
            {help, "Stream-status notifications whose send failed and that were held "
                   "again to be retried"}]},
        {gauge, [
            {name, yuzu_gw_upstream_notify_pending_hwm},
            {labels, []},
            {help, "Most stream-status notifications held at once over the last one to "
                   "two minutes (kept by the upstream process, so a spike between "
                   "scrapes is seen)"}]},
        {gauge, [
            {name, yuzu_gw_upstream_notify_pending_max},
            {labels, []},
            {help, "The held stream-status notification cap in force "
                   "(notify_pending_max)"}]},

        %% -- METRICS workstream (#5695) ------------------------------------
        %% Sampled by yuzu_gw_gauge every telemetry_gauge_interval_ms (bounded
        %% cost: a fixed process list, one ranch:info/1 per listener), except
        %% the router's fan-outs (reported by the router on every change) and
        %% the Cowboy closes (counted by yuzu_grpc_stream_h at the event).
        {gauge, [
            {name, yuzu_gw_process_mailbox_len},
            {labels, [process]},
            {help, "Messages waiting in the mailbox of a named gateway process, by "
                   "process (closed set: upstream, upstream_regulator, registry, "
                   "router, heartbeat_buffer, agent_sup, pg, upstream_channel, "
                   "logger). Sampled every telemetry_gauge_interval_ms; 0 when the "
                   "process is not running"}]},
        {gauge, [
            {name, yuzu_gw_process_queue_wait_seconds},
            {labels, [process]},
            {duration_unit, false},
            {help, "Seconds a message sent to a named gateway process waited "
                   "before the process reached it, by process: the round trip of "
                   "a probe sent each sample. While a probe is unanswered, the time "
                   "since it was sent (it grows each sample until the process "
                   "reaches it)"}]},
        {gauge, [
            {name, yuzu_gw_listener_connections},
            {labels, [listener]},
            {help, "Connections a gRPC listener holds now (Ranch active "
                   "connections), by listener role: agent, management, other"}]},
        {gauge, [
            {name, yuzu_gw_listener_max_connections},
            {labels, [listener]},
            {help, "The listener's limits.max_connections, by listener role. "
                   "Absent when the listener has no ceiling (the default)"}]},
        {gauge, [
            {name, yuzu_gw_mgmt_streams_inflight},
            {labels, []},
            {help, "Calls the management listener is running a handler for now "
                   "(SendCommand, WatchEvents and unary calls of the server's "
                   "connections)"}]},
        {gauge, [
            {name, yuzu_gw_router_fanouts_inflight},
            {labels, []},
            {help, "Command fan-outs the router is tracking now (each waits for "
                   "its agents' terminal responses or its timeout)"}]},
        {gauge, [
            {name, yuzu_gw_beam_ports},
            {labels, []},
            {help, "Ports open in the gateway VM (each TCP connection is one, so "
                   "this tracks the file descriptors the connections use)"}]},
        {gauge, [
            {name, yuzu_gw_beam_port_limit},
            {labels, []},
            {help, "The most ports the gateway VM can open (+Q)"}]},
        {gauge, [
            {name, yuzu_gw_beam_fd_limit},
            {labels, []},
            {help, "The file descriptor limit the gateway VM found at start "
                   "(the process's open-files limit)"}]},
        {gauge, [
            {name, yuzu_gw_beam_run_queue},
            {labels, []},
            {help, "Processes ready to run and waiting for a scheduler (normal and "
                   "dirty CPU run queues)"}]},
        {counter, [
            {name, yuzu_gw_grpc_connections_closed_total},
            {labels, [listener, reason]},
            {help, "Connections the gateway's HTTP/2 server (Cowboy) closed itself, "
                   "by listener role and reason: idle_timeout (nothing received for "
                   "the listener's idle_timeout), enhance_your_calm (a flood limit, "
                   "such as more stream cancels than max_cancel_stream_rate), "
                   "protocol_error (any other HTTP/2 connection error). Counted for "
                   "a connection that had a stream open when it closed. A "
                   "connection killed for its memory ceiling is counted in "
                   "yuzu_gw_grpc_connection_killed_total"}]},

        %% -- SHEDDER workstream (#5695) ------------------------------------
        %% The memory shedder (yuzu_gw_memory_shedder): the marks it resolved
        %% at start, and agent listeners it could not suspend or resume (each
        %% retried on its next tick).
        {gauge, [
            {name, yuzu_gw_memory_shedding_high_water_bytes},
            {labels, []},
            {help, "The memory shedder's high-water mark in bytes of "
                   "erlang:memory(total), resolved at start (a fraction of the "
                   "smaller of host memory and the cgroup memory limit, or the "
                   "configured bytes); 0 when the shedder is disabled or inactive"}]},
        {gauge, [
            {name, yuzu_gw_memory_shedding_low_water_bytes},
            {labels, []},
            {help, "The memory shedder's low-water mark in bytes, below which it "
                   "resumes the agent listener(s); 0 when the shedder is disabled "
                   "or inactive"}]},
        {gauge, [
            {name, yuzu_gw_memory_shedding_transition_failing},
            {labels, [action]},
            {help, "Agent listeners the memory shedder's last attempt failed to "
                   "move, by action: suspend (shedding, but the listener still "
                   "accepts) or resume (no longer shedding, but the listener still "
                   "refuses new agents and /readyz stays 503). Retried every "
                   "interval_ms; 0 once it succeeds"}]},
        {counter, [
            {name, yuzu_gw_memory_shedding_transition_failures_total},
            {labels, [action]},
            {help, "Failed attempts by the memory shedder to suspend or resume an "
                   "agent listener, by action (suspend, resume); one per listener "
                   "per attempt, and a failing listener is retried every "
                   "interval_ms"}]},

        %% -- G8-CODE workstream (#5695) ------------------------------------
        %% The server's concurrent-stream limit, learned from its HTTP/2
        %% SETTINGS (yuzu_grpc_client_channel -> yuzu_gw_upstream_regulator).
        {gauge, [
            {name, yuzu_gw_upstream_server_max_streams},
            {labels, []},
            {help, "Concurrent streams the server allows on the gateway's upstream "
                   "connections together, as declared in its HTTP/2 SETTINGS "
                   "(SETTINGS_MAX_CONCURRENT_STREAMS, summed over the connections); 0 "
                   "when nothing is known (no connection up) or the server declared no "
                   "limit. The upstream permits are sized from it"}]},

        %% OWNER-RESTART workstream (#5695).
        {counter, [
            {name, yuzu_gw_agent_owner_restarts_total},
            {labels, [outcome]},
            {help, "Agent owner processes restarted after an abnormal exit, by what the "
                   "restarted owner did: recovered (the session was re-established on the "
                   "agent's open stream), disconnected_only (the session ended without "
                   "recovery; its DISCONNECTED was sent if it had been announced; the "
                   "agent reconnects), gave_up (more than 3 restarts "
                   "in 60 s: the session ended)"}]},

        %% -- NOTIFY-ACK workstream (#5695) ---------------------------------
        %% Stream-status notices the server answered acknowledged=false: not
        %% delivered, held and sent again with backoff (yuzu_gw_upstream,
        %% "Notices the server did not acknowledge").
        {counter, [
            {name, yuzu_gw_upstream_notify_unacknowledged_total},
            {labels, [event]},
            {help, "Stream-status notices the server answered with acknowledged=false "
                   "(it did not record them), by event (connected, disconnected). Each "
                   "answer counts, the refusals of a resend included"}]},
        {gauge, [
            {name, yuzu_gw_upstream_notify_unacked_keys},
            {labels, []},
            {help, "Stream-status notices the server refused (acknowledged=false) that "
                   "the gateway still holds to send again, one per agent session"}]},
        {counter, [
            {name, yuzu_gw_upstream_notify_unacked_ended_total},
            {labels, [outcome]},
            {help, "Refused stream-status notices that stopped waiting for a resend, by "
                   "outcome: acknowledged (a resend was recorded), superseded (a newer "
                   "notice for the session replaced it, or a restarted owner presented "
                   "the session again), session_gone (a connected "
                   "notice whose session ended at the gateway), lost (given up, counted "
                   "in yuzu_gw_upstream_notify_lost_total)"}]}
    ].

%% @doc The names of every metric metric_specs/0 declares.
-spec declared_metrics() -> [atom()].
declared_metrics() ->
    [proplists:get_value(name, Spec) || {_Type, Spec} <- metric_specs()].

declare_metrics() ->
    [declare(Type, Spec) || {Type, Spec} <- metric_specs()],
    seed_metrics().

declare(counter, Spec)   -> prometheus_counter:declare(Spec);
declare(gauge, Spec)     -> prometheus_gauge:declare(Spec);
declare(histogram, Spec) -> prometheus_histogram:declare(Spec).

%% Series created at start, after every metric is declared.
seed_metrics() ->
    %% A series that first appears already at 1 is invisible to increase(), so
    %% the two codes a gateway fault produces (no server answer, so no status
    %% code) start at 0. The RPC names are the do_rpc/3 tags of yuzu_gw_upstream
    %% (register, inventory, notify_stream, guardian) and the heartbeat buffer's
    %% batch_heartbeat, whose marshal failure is counted as code="exception"
    %% (yuzu_gw_heartbeat_buffer do_flush, the {caught, Class} branch), so only
    %% exception is seeded for it; an invalid heartbeat is dropped as
    %% heartbeat_invalid instead. Neither is covered by the encode alert. Status
    %% codes are never pre-seeded.
    [prometheus_counter:inc(yuzu_gw_upstream_rpc_errors_total, [Name, Code], 0)
     || {Name, Code} <- [{N, C} || N <- [<<"register">>, <<"inventory">>,
                                         <<"notify_stream">>, <<"guardian">>],
                                   C <- [<<"encode">>, <<"exception">>]]
                        ++ [{<<"batch_heartbeat">>, <<"exception">>}]],
    [prometheus_counter:inc(yuzu_gw_register_refused_total, [R], 0)
     || R <- [<<"agent_id_length">>, <<"unknown">>]],
    %% A series that first appears already at 1 is invisible to increase(), so
    %% without these the FIRST open of a gateway process never raised
    %% YuzuGatewayUpstreamCircuitOpened -- and a crash-looping gateway opens
    %% its breaker once per life, so it never alerted at all. The states are
    %% the closed set yuzu_gw_upstream emits (trip_circuit/1, the
    %% circuit_half_open timer, on_success/1 from half_open).
    [prometheus_counter:inc(yuzu_gw_upstream_circuit_transitions_total, [S], 0)
     || S <- [<<"closed">>, <<"open">>, <<"half_open">>]],
    %% A series that first appears already at 1 is invisible to increase().
    [prometheus_counter:inc(yuzu_gw_upstream_notify_dropped_total, [R], 0)
     || R <- [<<"at_capacity">>, <<"unknown">>]],
    prometheus_counter:inc(yuzu_gw_upstream_notify_coalesced_total, [], 0),
    %% Create every rejection-reason series at 0 now. A series that first
    %% appears already at 1 is invisible to increase(), so without this the
    %% FIRST rejection per reason (after the first scrape) never raised the
    %% YuzuGatewayMgmtAuthRejected alert (#5177 review). The list is the closed
    %% set of reject/1 reasons in yuzu_gw_authz; a test keeps the two in step.
    [prometheus_counter:inc(yuzu_gw_mgmt_auth_rejected_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- mgmt_auth_reject_reasons()],
    %% Create every series at 0 now (a series that first appears already at 1
    %% is invisible to increase()).
    [prometheus_counter:inc(yuzu_gw_heartbeat_rejected_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- heartbeat_reject_reasons()],
    prometheus_counter:inc(yuzu_gw_heartbeat_session_mismatch_total,
                           [<<"security">>], 0),
    [prometheus_counter:inc(yuzu_gw_grpc_origin_ignored_total,
                            [atom_to_binary(M, utf8), atom_to_binary(R, utf8)], 0)
     || {M, R} <- origin_ignored_labels()],
    [prometheus_counter:inc(yuzu_gw_grpc_dropped_data_bytes_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- dropped_data_reasons()],
    prometheus_counter:inc(yuzu_gw_grpc_recv_timeout_total, [], 0),
    prometheus_counter:inc(yuzu_gw_grpc_connection_killed_total, [<<"max_heap_size">>], 0),
    prometheus_gauge:set(yuzu_gw_memory_shedding_active, [], 0),
    prometheus_counter:inc(yuzu_gw_memory_shedding_suspensions_total, [], 0),
    [prometheus_counter:inc(yuzu_gw_upstream_calls_dropped_total,
                            [atom_to_binary(R, utf8)], 0)
     || R <- upstream_dropped_rpcs()],
    [prometheus_counter:inc(yuzu_gw_upstream_lane_saturated_seconds_total,
                            [atom_to_binary(L, utf8)], 0)
     || L <- yuzu_gw_upstream_pressure:lanes()],
    prometheus_counter:inc(yuzu_gw_upstream_backpressure_seconds_total, [], 0),
    %% Create every series at 0 now (a series that first appears already at 1
    %% is invisible to increase()).
    [prometheus_counter:inc(yuzu_gw_registration_replay_triggered_total, [T], 0)
     || T <- [<<"breaker">>, <<"heartbeat">>, <<"notify_loss">>,
              <<"server_lost_state">>, <<"manual">>]],
    [prometheus_counter:inc(yuzu_gw_heartbeat_verdict_dropped_total, [R], 0)
     || R <- [<<"malformed">>, <<"not_local">>, <<"circuit_open">>, <<"queue_full">>]],
    [prometheus_counter:inc(yuzu_gw_heartbeat_buffer_dropped_total, [R], 0)
     || R <- [<<"buffer_full">>, <<"snapshot_oversize">>, <<"snapshot_evicted">>,
              <<"heartbeat_oversize">>, <<"heartbeat_invalid">>,
              <<"chunk_rejected">>]],
    prometheus_counter:inc(yuzu_gw_heartbeat_coalesced_total, [], 0),
    prometheus_counter:inc(yuzu_gw_session_limit_rejected_total, [], 0),
    %% Present from the first scrape, before the sampler's first event.
    prometheus_gauge:set(yuzu_gw_upstream_backpressure_duty_cycle, [], 0.0),
    prometheus_gauge:set(yuzu_gw_upstream_slow, [], 0),
    %% 0 = no rotation observed: the pin_mismatch alert is then not suppressed.
    prometheus_gauge:set(yuzu_gw_mgmt_pin_rotated_timestamp_seconds, [], 0),
    %% Series at 0 from startup, before yuzu_gw_upstream:init/1 has reported.
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending, [node()], 0),
    prometheus_gauge:set(yuzu_gw_upstream_notify_inflight, [node()], 0),
    [begin
         prometheus_gauge:set(yuzu_gw_upstream_permits_held, [C], 0),
         prometheus_gauge:set(yuzu_gw_upstream_permits_waiting, [C], 0),
         prometheus_gauge:set(yuzu_gw_upstream_permit_limit, [C], 0),
         [prometheus_counter:inc(yuzu_gw_upstream_permit_refused_total, [C, R], 0)
          || R <- [atom_to_binary(R0, utf8) || R0 <- permit_refusals()]]
     end || C <- [atom_to_binary(C0, utf8) || C0 <- permit_classes()]],
    [prometheus_counter:inc(yuzu_gw_registration_replay_outcomes_total, [O], 0)
     || O <- [atom_to_binary(O0, utf8) || O0 <- replay_outcomes()] ++ [<<"unknown">>]],
    prometheus_gauge:set(yuzu_gw_registration_replay_last_duration_seconds, [], 0),
    [prometheus_counter:inc(yuzu_gw_upstream_notify_lost_total, [E, R], 0)
     || E <- [atom_to_binary(E0, utf8) || E0 <- notify_events()],
        R <- [atom_to_binary(R0, utf8) || R0 <- notify_lost_reasons()]],
    prometheus_counter:inc(yuzu_gw_upstream_notify_requeued_total, [], 0),
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending_hwm, [], 0),
    prometheus_gauge:set(yuzu_gw_upstream_notify_pending_max, [], 0),

    %% Node-labelled families whose producer reports on its first tick or event:
    %% present at 0 from the declaration so a dashboard or rate() sees the
    %% series before then.
    Node = node(),
    [prometheus_counter:inc(C, [Node], 0)
     || C <- [yuzu_gw_agents_connected_total, yuzu_gw_agents_disconnected_total]],
    [prometheus_gauge:set(G, [Node], 0)
     || G <- [yuzu_gw_agents_current, yuzu_gw_beam_process_count,
              yuzu_gw_beam_scheduler_util, yuzu_gw_registration_replay_queue_depth,
              yuzu_gw_cluster_peers_resolved, yuzu_gw_cluster_peers_connected]],
    [prometheus_gauge:set(yuzu_gw_beam_memory_bytes, [Node, T], 0)
     || T <- [total, processes, ets, binary]],
    [prometheus_counter:inc(yuzu_gw_guardian_forward_dropped_total, [R], 0)
     || R <- [<<"circuit_open">>, <<"at_capacity">>]],

    %% METRICS workstream (#5695).
    [begin
         prometheus_gauge:set(yuzu_gw_process_mailbox_len, [P], 0),
         prometheus_gauge:set(yuzu_gw_process_queue_wait_seconds, [P], 0)
     end || P <- [atom_to_binary(P0, utf8) || P0 <- process_labels()]],
    [begin
         prometheus_gauge:set(yuzu_gw_listener_connections, [R], 0),
         [prometheus_counter:inc(yuzu_gw_grpc_connections_closed_total, [R, C], 0)
          || C <- [atom_to_binary(C0, utf8) || C0 <- close_reasons()]]
     end || R <- [atom_to_binary(R0, utf8) || R0 <- listener_roles()]],
    [prometheus_gauge:set(G, [], 0)
     || G <- [yuzu_gw_mgmt_streams_inflight, yuzu_gw_router_fanouts_inflight,
              yuzu_gw_beam_ports, yuzu_gw_beam_run_queue]],
    prometheus_gauge:set(yuzu_gw_beam_port_limit, [], erlang:system_info(port_limit)),

    %% SHEDDER workstream (#5695).
    prometheus_gauge:set(yuzu_gw_memory_shedding_high_water_bytes, [], 0),
    prometheus_gauge:set(yuzu_gw_memory_shedding_low_water_bytes, [], 0),
    [begin
         prometheus_gauge:set(yuzu_gw_memory_shedding_transition_failing, [A], 0),
         prometheus_counter:inc(yuzu_gw_memory_shedding_transition_failures_total, [A], 0)
     end || A <- [atom_to_binary(A0, utf8) || A0 <- shedding_actions()]],

    %% G8-CODE workstream (#5695).
    prometheus_gauge:set(yuzu_gw_upstream_server_max_streams, [], 0),

    %% OWNER-RESTART workstream (#5695).
    [prometheus_counter:inc(yuzu_gw_agent_owner_restarts_total, [O], 0)
     || O <- [atom_to_binary(O0, utf8) || O0 <- owner_restart_outcomes()] ++ [<<"unknown">>]],

    %% NOTIFY-ACK workstream (#5695).
    [prometheus_counter:inc(yuzu_gw_upstream_notify_unacknowledged_total, [E], 0)
     || E <- [atom_to_binary(E0, utf8) || E0 <- notify_events()]],
    prometheus_gauge:set(yuzu_gw_upstream_notify_unacked_keys, [], 0),
    [prometheus_counter:inc(yuzu_gw_upstream_notify_unacked_ended_total, [O], 0)
     || O <- [atom_to_binary(O0, utf8) || O0 <- notify_unacked_outcomes()]],

    ok.

%% @doc The declared metrics that have no series until their first event, and
%% why. Every other declared metric has at least one series from the moment it
%% is declared (yuzu_gw_metrics_scrape_tests scrapes a started gateway to hold
%% that). A histogram gets a series only with an observation; the rest have
%% labels whose values are not known at start.
-spec unseeded_metrics() -> [{atom(), string()}].
unseeded_metrics() ->
    [{yuzu_gw_commands_dispatched_total,
      "plugin is the command's plugin name, not a closed set"},
     {yuzu_gw_command_duration_ms,
      "a histogram (series appear with the first observation); plugin is not a closed set"},
     {yuzu_gw_upstream_rpc_duration_ms,
      "a histogram: series appear with the first upstream call of each rpc_name"},
     {yuzu_gw_upstream_permit_wait_seconds,
      "a histogram: series appear with the first permit granted per class"},
     {yuzu_gw_agent_session_duration_ms,
      "a histogram: series appear with the first agent disconnect"},
     {yuzu_gw_upstream_tls_handshake_failures_total,
      "kind is the TLS alert name of the failure, known only when one happens"},
     {yuzu_gw_cluster_events_total,
      "node is the peer node's name, known only when it joins or leaves"},
     {yuzu_gw_cert_expiry_timestamp_seconds,
      "one series per configured certificate file, set when the file is first read"},
     {yuzu_gw_cert_file_readable,
      "one series per configured certificate file, set when the file is first checked"},
     {yuzu_gw_listener_max_connections,
      "a series exists only for a listener role with a max_connections ceiling"},
     {yuzu_gw_beam_fd_limit,
      "set by the first sample, where the VM reports its file descriptor limit"}].

node_labels(Meta) ->
    [maps:get(node, Meta, node())].
