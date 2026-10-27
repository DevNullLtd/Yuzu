# Yuzu Grafana Dashboard Templates

This directory contains Grafana dashboard JSON files and documentation for monitoring a Yuzu deployment with Prometheus.

## Prometheus Metric Families

Yuzu exposes Prometheus metrics from two scrape targets: the **server** (`/metrics` on the web port, default `:8080`) and the **gateway** (`/metrics` on its Prometheus port, default `:9568`). Per-agent metrics are *not* scraped — the agent has no HTTP metrics endpoint; it piggybacks its counters into heartbeats, and fleet-wide health is re-exported by the server as the `yuzu_fleet_*` gauges below. All metric names use the `yuzu_` prefix. The metric names, types, and labels below are taken from the emitting code (`server/core/src`, `gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl`); only metrics that are actually emitted are listed.

### Server Metrics

Scraped from the server `/metrics` endpoint. Note that server metrics use a mix of the bare `yuzu_` prefix (request/fleet/command counters) and the `yuzu_server_` prefix (process-level gauges).

| Metric | Type | Description |
|---|---|---|
| `yuzu_http_requests_total` | counter | Total HTTP requests, labeled by `method`, `status` |
| `yuzu_grpc_requests_total` | counter | Total gRPC requests, labeled by `method`, `status` |
| `yuzu_server_open_connections` | gauge | Current open HTTP connections |
| `yuzu_server_command_queue_depth` | gauge | Commands queued for dispatch |
| `yuzu_server_uptime_seconds` | gauge | Server process uptime |
| `yuzu_server_cpu_usage_percent` | gauge | Server CPU usage |
| `yuzu_server_memory_bytes` | gauge | Server resident memory |
| `yuzu_server_audit_events_total` | counter | Audit events recorded, labeled by `result` |
| `yuzu_server_cert_reloads_total` | gauge | Running count of successful HTTPS certificate hot-reloads |
| `yuzu_server_cert_reload_failures_total` | gauge | Running count of failed certificate hot-reload attempts |

### Command Metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_commands_dispatched_total` | counter | Commands dispatched to agents |
| `yuzu_commands_completed_total` | counter | Commands completed, labeled by `status` (`done`, `error`) |
| `yuzu_command_duration_seconds` | histogram | End-to-end command execution latency (no labels; exposes `_bucket`/`_sum`/`_count`) |
| `yuzu_fleet_commands_executed_total` | gauge | Cumulative commands executed across the fleet |

### Fleet Metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_agents_connected` | gauge | Agents currently connected |
| `yuzu_agents_registered_total` | counter | Total agents registered since server startup |
| `yuzu_heartbeats_received_total` | counter | Heartbeats received, labeled by `via` (direct vs gateway) |
| `yuzu_fleet_agents_healthy` | gauge | Connected agents with a recent heartbeat |
| `yuzu_fleet_agents_by_os` | gauge | Connected agents, labeled by `os` |
| `yuzu_fleet_agents_by_arch` | gauge | Connected agents, labeled by `arch` |
| `yuzu_fleet_agents_by_version` | gauge | Connected agents, labeled by `version` |

### Agent Metrics (not scraped)

The agent does **not** expose a Prometheus `/metrics` endpoint. It maintains in-process counters (`yuzu_agent_uptime_seconds`, `yuzu_agent_commands_executed_total`, `yuzu_agent_plugins_loaded`, `yuzu_agent_plugin_rejected_total`, `yuzu_agent_reconnections_total`) and piggybacks them into heartbeat `status_tags`. They are visible per-agent in the dashboard/device views, but are **not** available as Prometheus series. For fleet-wide agent health in Grafana, use the server-side `yuzu_fleet_*` and `yuzu_agents_*` gauges above.

### Gateway Metrics (`yuzu_gw_*`)

Scraped from the gateway's Prometheus endpoint (default `:9568`). Duration histograms are in **milliseconds** (`_ms`), not seconds.

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_agents_current` | gauge | Agents currently connected to this gateway node, labeled by `node` |
| `yuzu_gw_agents_connected_total` | counter | Total agent connections since startup |
| `yuzu_gw_agents_disconnected_total` | counter | Total agent disconnections |
| `yuzu_gw_commands_dispatched_total` | counter | Commands dispatched to agents, labeled by `plugin` |
| `yuzu_gw_commands_timed_out_total` | counter | Commands that timed out before a response |
| `yuzu_gw_commands_dropped_backpressure_total` | counter | Commands dropped because an agent's send buffer was full |
| `yuzu_gw_stream_write_errors_total` | counter | Agent stream write errors |
| `yuzu_gw_command_duration_ms` | histogram | Command dispatch duration in ms, labeled by `plugin`, `status` |
| `yuzu_gw_agent_session_duration_ms` | histogram | Agent session duration in ms |
| `yuzu_gw_upstream_rpc_duration_ms` | histogram | Upstream (gateway→server) RPC latency in ms, labeled by `rpc_name` |
| `yuzu_gw_upstream_rpc_errors_total` | counter | Upstream RPC errors, labeled by `rpc_name`, `code`. `code` is the gRPC status number or, for a transport failure before any status, a word such as `closed`, `econnrefused`, `timeout`, `stream_error`, `connection_error`, `protocol`, `response_too_large`, `invalid_metadata`, `no_channel`, `other`, or `{tls_alert,<Alert>}`. `code="encode"` (a request that failed in the gateway's own encoder: local, never sent, no breaker effect) and `code="exception"` are pre-seeded to 0 (`encode` for `register`, `inventory`, `notify_stream` and `guardian`; `exception` for those four plus `batch_heartbeat`, whose marshal failures are counted as `code="exception"` and are not covered by the encode alert); other codes appear at their first occurrence. The shipped `YuzuGatewayUpstreamErrors` alert fires above 0.1 errors/s with no `code` filter, and `YuzuGatewayUpstreamEncodeErrors` fires at about ten `code="encode"` increases over 10 minutes (`increase()` extrapolates) |
| `yuzu_gw_register_refused_total` | counter | `Register` calls refused at the gateway edge before any upstream call (agent id outside 1 to 256 bytes), labeled by `reason` (`agent_id_length`, `unknown`; both created at 0 at start) |
| `yuzu_gw_registration_replay_total` | counter | Total registration replay attempts by the drip, any outcome |
| `yuzu_gw_registration_replay_queue_depth` | gauge | Pending registration-replay entries (queued by an upstream recovery or a heartbeat verdict), labeled by `node` |
| `yuzu_gw_registration_replay_triggered_total` | counter | Registration replays started, labeled by `trigger` (`breaker`, `heartbeat`; both created at 0 at start). A `breaker` trigger is dropped while a verdict-seeded drip is queued |
| `yuzu_gw_heartbeat_unknown_truncated_total` | counter | `BatchHeartbeat` responses whose list of unknown sessions the server truncated at 4096 |
| `yuzu_gw_heartbeat_verdict_dropped_total` | counter | Session ids named by a heartbeat verdict that were not queued for replay, labeled by `reason` (`malformed`, `not_local`, `circuit_open`, `queue_full`; all created at 0 at start) |
| `yuzu_gw_heartbeat_buffer_dropped_total` | counter | Heartbeat state the gateway's heartbeat buffer dropped instead of sending, labeled by `reason` (`buffer_full`: a new session's heartbeat or, last resort, the oldest whole session; `snapshot_oversize`: one heartbeat over about 3 MiB sent without its snapshot; `snapshot_evicted`: a retained snapshot dropped oldest first for the byte cap; `heartbeat_oversize`: a heartbeat still over about 3 MiB without its snapshot, or with more than 512 status tags, or with one tag key or value over about 64 KiB or more than about 256 KiB of tag bytes in total (checked before the UTF-8 repair), forwarded without its status tags; `heartbeat_invalid`: a heartbeat with a status tag that is not valid UTF-8 forwarded with the invalid bytes replaced by replacement characters (the reason also counts tags removed because a tag was not a binary, and a heartbeat dropped for a bad or empty session id); `chunk_rejected`: a single heartbeat the server rejected with a non-transient status dropped; all created at 0 at start). What is lost is heartbeat state, which the agent sends again on its own interval, except that a `heartbeat_oversize` heartbeat loses its status tags and a `chunk_rejected` heartbeat is lost whole |
| `yuzu_gw_heartbeat_coalesced_total` | counter | Buffered heartbeats replaced by a newer heartbeat of the same session. Expected to rise while the server is unreachable; the server's `yuzu_heartbeats_received_total{via="gateway"}` under-counts while a backlog is coalesced |
| `yuzu_gw_upstream_notify_pending` | gauge | Stream-status notifications held because the in-flight limit is reached or the upstream circuit breaker is not closed; drained first in first out (0 = nothing held). The key of a half open probe in flight is not counted here, unless a newer notification for the same key has since been held, and the key still counts toward the `notify_pending_max` cap. The gauge can equal `notify_pending_max` without any loss, so do not alert on that; alert on `increase(yuzu_gw_upstream_notify_dropped_total{reason="at_capacity"}[5m]) > 0`. Labeled by `node`, created at 0 at start. Counts the current upstream client process only |
| `yuzu_gw_upstream_notify_inflight` | gauge | NotifyStreamStatus workers tracked by this gateway process (at most 10), labeled by `node`, created at 0 at start. Workers of a previous upstream client process are not counted |
| `yuzu_gw_upstream_notify_coalesced_total` | counter | Held stream-status notifications replaced by a newer event for the same agent session and stream home, or a failed probe notification superseded by one (suppression, not delivery), created at 0 at start |
| `yuzu_gw_upstream_notify_dropped_total` | counter | Stream-status notifications lost at admission because the pending store was at its cap (a new key is admitted only while the held keys plus the key of a half open probe in flight stay below `notify_pending_max`), labeled by `reason` (closed set `at_capacity` and `unknown`, both created at 0 at start; `unknown` is the overflow bucket for an unexpected value and is not emitted today; `circuit_open` is retired and only an older gateway exports it). Does not count delivery loss after admission |
| `yuzu_gw_cluster_peers_resolved` | gauge | Peer addresses found by the cluster-formation redial loop's most recent tick, labeled by `node` (HA WS-4 `#4555`) |
| `yuzu_gw_cluster_peers_connected` | gauge | Distribution-connected peer nodes as of the most recent redial tick, labeled by `node` (`#4555`) |
| `yuzu_gw_cluster_connect_failures_total` | counter | Total `net_kernel:connect_node/1` failures from the redial loop (`#4555`) |
| `yuzu_gw_cluster_address_cap_exceeded_total` | counter | Total times the lifetime distinct-address cap refused a never-before-seen address (`#4555` review round 2) |
| `yuzu_gw_heartbeat_rejected_total` | counter | Agent `Heartbeat` calls rejected before buffering because no usable session binding exists, labeled by `reason` (`unknown_session`, `no_connection`, `registry_unavailable`; all created at 0 at start). The agent re-registers on the `NOT_FOUND` answer when its build includes the reconnect fix (see the gateway manual); older agents only log it |
| `yuzu_gw_inventory_rejected_total` | counter | Agent `ReportInventory` calls refused before forwarding because no session is held on the calling connection, labeled by `reason` (`unknown_session`, `no_connection`, `registry_unavailable`, `connection_mismatch`; all created at 0 at start). The agent retries on its next sync tick |
| `yuzu_gw_heartbeat_session_mismatch_total` | counter | Agent `Heartbeat` calls rejected because the session is held by this node but the call arrived on a different connection than the one that opened it, labeled `event="security"` (created at 0 at start). Also rises behind an unsupported HTTP/2 proxy. A rise of one per affected agent is expected when an agent's connection is replaced while its session is still held (observed with an injected GOAWAY, a test-only trigger; not observed with an abrupt close or a gateway restart). No alert rule ships for these series |
| `yuzu_gw_session_limit_rejected_total` | counter | Registrations refused because one connection already holds the configured number of agent sessions, pending plus live (`max_sessions_per_connection`, default 8). Unlabelled, created at 0 at start. A refused `Register` is answered `UNAVAILABLE` (14); a refused `Subscribe` is also answered `UNAVAILABLE` (14) and is counted the same. A rise means an L4 balancer, forwarder or client carries several agents on one connection (a stock agent holds one); see the gateway manual |
| `yuzu_gw_grpc_origin_ignored_total` | counter | gRPC calls on a listener configured as behind a proxy whose claimed client address was not used, labeled by `mode` (`proxy_protocol`, `forwarded_for`) and `reason` (`untrusted_source`, `no_claim`, `bad_claim`); the call is served either way (`untrusted_source`: attributed to the TCP peer; `no_claim` and `bad_claim`: sent upstream with no observed address, which the server audits as `origin_observed=false`). The origin is resolved per RPC stream, so a health check that opens no stream (L4, TCP, TLS, PROXY `LOCAL`) is never counted. A steady `untrusted_source` rate means the listener is reachable without going through the proxy or `sources` is wrong; a steady `no_claim`/`bad_claim` rate means the proxy is not giving the gateway a usable address (alerts `YuzuGatewayOriginUnusable`, `YuzuGatewayOriginSourcesMismatch`) |
| `yuzu_gw_grpc_dropped_data_bytes_total` | counter | Request bytes the gateway's gRPC layer discarded in a state that must not run a handler, labeled by `reason` (`extra_request_data`, `stream_ended`) |
| `yuzu_gw_upstream_calls_dropped_total` | counter | Queued upstream proxy calls skipped because the requesting gRPC call had already ended (client `RST_STREAM` or deadline while the call waited behind the serial upstream process), labeled by `rpc_name` (`register`, `inventory`; both created at 0). A skipped `Register` creates no server session. Share skipped, relative to successfully forwarded registers (upstream errors are not in the denominator): `rate(yuzu_gw_upstream_calls_dropped_total{rpc_name="register"}[5m]) / (rate(yuzu_gw_upstream_calls_dropped_total{rpc_name="register"}[5m]) + rate(yuzu_gw_upstream_rpc_duration_ms_count{rpc_name="register"}[5m]))` |
| `yuzu_gw_upstream_backpressure_seconds_total` | counter | Seconds during which the path to the server was backed up: at least one lane saturated (the `yuzu_gw_upstream` process inside an RPC of its own with a message waiting, all 10 stream-status notification slots held, or all 50 Guardian forward slots held). `rate()` of it over a window is the backpressure duty cycle, 0 to 1. Sampled every 100 ms. See "Slow server" in the gateway manual |
| `yuzu_gw_upstream_lane_saturated_seconds_total` | counter | The same, per lane (label `lane`: `serial`, `notify`, `guardian`; all three created at 0 at start). The lanes overlap, so never add them: the figure for the gateway as a whole is the counter above |
| `yuzu_gw_upstream_backpressure_duty_cycle` | gauge | The backpressure duty cycle over the last 60 s, 0 to 1. Reads low for the first minute after a start (the missing seconds count as not saturated) |
| `yuzu_gw_upstream_slow` | gauge | 1 when the duty cycle above is 0.5 or more (a slow server, as this gateway sees it), else 0. Not a readiness input |
| `yuzu_gw_mgmt_auth_rejected_total` | counter | Management-listener (`:50063`) streams refused by the SPKI peer pin, labeled by `reason` (closed set of seven, all created at 0 at start) |
| `yuzu_gw_mgmt_auth_pin_unresolved_total` | counter | Management auth attempts during which a configured `mgmt_peer_pins` entry did not resolve |
| `yuzu_gw_mgmt_pin_rotated_timestamp_seconds` | gauge | Unix time the pin watcher last published a different key for a `{cert_file, Path}` pin; 0 until the first change in the process |
| `yuzu_gw_cert_expiry_timestamp_seconds` | gauge | `notAfter` (Unix seconds) of each configured certificate file, labeled by `role` (`listener`, `listener_ca`, `upstream_client`, `upstream_ca`, `mgmt_peer_pin`) and `name`; keeps the last value read if the file becomes unreadable; absent while its `notAfter` cannot be parsed |
| `yuzu_gw_cert_file_readable` | gauge | 1 when the latest read of the certificate file(s) under that `role` and `name` parsed, 0 when it failed |
| `yuzu_gw_process_mailbox_len` | gauge | Messages waiting in the mailbox of a named gateway process, labeled by `process` (closed set: `upstream`, `upstream_regulator`, `registry`, `router`, `heartbeat_buffer`, `agent_sup`, `pg`, `upstream_channel`, `logger`; all created at 0). Sampled every `telemetry_gauge_interval_ms`. Alert: `YuzuGatewayProcessBacklogged` (over 10,000 for 10 minutes) |
| `yuzu_gw_process_queue_wait_seconds` | gauge | How long a message sent to that process waited before it was handled (a probe's round trip each sample; while a probe is unanswered, the time since it was sent), labeled by `process` |
| `yuzu_gw_listener_connections` | gauge | Connections a gRPC listener holds (Ranch active connections), labeled by `listener` role (`agent`, `management`, `other`; all created at 0) |
| `yuzu_gw_listener_max_connections` | gauge | That role's `limits.max_connections`; no series without a ceiling (the default). Alert: `YuzuGatewayListenerNearConnectionCeiling` (over 90% for 10 minutes) |
| `yuzu_gw_mgmt_streams_inflight` | gauge | Calls the management listener is running a handler for |
| `yuzu_gw_router_fanouts_inflight` | gauge | Command fan-outs the router is tracking, set by the router whenever the number changes |
| `yuzu_gw_beam_ports` | gauge | Ports open in the gateway VM (each TCP connection is one). Alert: `YuzuGatewayFileDescriptorsNearLimit` (over 90% of either limit below for 10 minutes) |
| `yuzu_gw_beam_port_limit` | gauge | The most ports the VM can open (`+Q`) |
| `yuzu_gw_beam_fd_limit` | gauge | The open-files limit the VM found at start; no series where the VM does not report one |
| `yuzu_gw_beam_run_queue` | gauge | Processes waiting for a scheduler (`total_run_queue_lengths`) |
| `yuzu_gw_grpc_connections_closed_total` | counter | Connections the gateway's HTTP/2 server closed itself, labeled by `listener` role and `reason` (`idle_timeout`, `enhance_your_calm`, `protocol_error`; every pair created at 0); counted once per connection that had a call open. A memory-ceiling kill is counted in `yuzu_gw_grpc_connection_killed_total` |

The full set of gateway metrics (BEAM scheduler/memory gauges, fan-out and queue-length histograms, circuit-breaker and cluster counters) is registered in `gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl`.

## Available Dashboards

Yuzu ships two dashboard sets.

**Operational — auto-provisioned (`deploy/grafana/`).** These are the dashboards a real deployment uses. The UAT, full-UAT, and viz rigs load them automatically via `deploy/grafana/provisioning/dashboards/yuzu.yml`, which mounts `deploy/grafana/` into Grafana at `/var/lib/grafana/dashboards` — no manual import needed.

| File | Title | Data source | Description |
|---|---|---|---|
| `deploy/grafana/yuzu-dashboard.json` | Yuzu Server Dashboard | Prometheus | Server health, command throughput/latency, fleet counts |
| `deploy/grafana/yuzu-fleet-dashboard.json` | Yuzu Fleet Overview | Prometheus | Connected/healthy agents, heartbeats, agents by OS/arch/version |
| `deploy/grafana/yuzu-gateway-dashboard.json` | Yuzu Gateway | Prometheus | Gateway agent connections, command forwarding, upstream RPC, BEAM stats |
| `deploy/grafana/yuzu-analytics-dashboard.json` | Yuzu Analytics | **ClickHouse** | Analytics-event queries over the `yuzu_events` table — requires the ClickHouse stack (e.g. the full-UAT rig), not Prometheus |

**Standalone template (this directory).** A self-contained Grafana export you can import by hand into any Grafana that has a Prometheus data source:

| File | Title | Data source | Description |
|---|---|---|---|
| [yuzu-overview.json](yuzu-overview.json) | Yuzu Overview | Prometheus | Agent fleet, command throughput, latency, and heartbeat panels |

## Importing Dashboards

The operational `deploy/grafana/` dashboards are **auto-provisioned** — you do not import them by hand. To import the standalone `yuzu-overview.json` template:

1. Open Grafana and navigate to **Dashboards > Import**.
2. Click **Upload JSON file** and select `yuzu-overview.json` from this directory.
3. Select your Prometheus data source when prompted.
4. Click **Import**.

The template assumes a Prometheus data source named `Prometheus`. If your data source has a different name, select the correct source during import (the import dialog maps the `DS_PROMETHEUS` input).

## Scrape Configuration

Add the following targets to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'

  - job_name: 'yuzu-gateway'
    static_configs:
      - targets: ['localhost:9568']
    metrics_path: '/metrics'
```

There is no `yuzu-agent` scrape job: agents do not expose an HTTP `/metrics` endpoint. Per-agent counters are delivered to the server inside heartbeats and surfaced as the server-side `yuzu_fleet_*` / `yuzu_agents_*` series, so the server target above already covers fleet-wide agent health.

Adjust addresses and ports to match your deployment. For Docker Compose deployments, the `deploy/docker/docker-compose.yml` file includes a pre-configured Prometheus instance.
