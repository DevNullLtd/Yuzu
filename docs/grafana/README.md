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
| `yuzu_gw_upstream_rpc_errors_total` | counter | Upstream RPC errors, labeled by `rpc_name`, `code` |
| `yuzu_gw_registration_replay_queue_depth` | gauge | Pending registration-replay entries, labeled by `node` |
| `yuzu_gw_cluster_peers_resolved` | gauge | Peer addresses found by the cluster-formation redial loop's most recent tick, labeled by `node` (HA WS-4 `#4555`) |
| `yuzu_gw_cluster_peers_connected` | gauge | Distribution-connected peer nodes as of the most recent redial tick, labeled by `node` (`#4555`) |
| `yuzu_gw_cluster_connect_failures_total` | counter | Total `net_kernel:connect_node/1` failures from the redial loop (`#4555`) |
| `yuzu_gw_cluster_address_cap_exceeded_total` | counter | Total times the lifetime distinct-address cap refused a never-before-seen address (`#4555` review round 2) |

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
