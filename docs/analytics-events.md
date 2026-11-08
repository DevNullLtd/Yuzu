# Analytics Event Reference

Yuzu emits structured analytics events for time-series analysis. Events follow a common envelope and are buffered locally in SQLite before draining to configured sinks (ClickHouse, JSON Lines).

## Event Envelope

Every event contains:

| Field | Type | Description |
|-------|------|-------------|
| `tenant_id` | string | Tenant identifier (default: "default") |
| `agent_id` | string | Agent that originated or is the subject of the event |
| `session_id` | string | Session identifier |
| `event_type` | string | Dotted event type (e.g. "command.completed") |
| `event_time` | int64 | Milliseconds since epoch when the event occurred |
| `ingest_time` | int64 | Milliseconds since epoch when the event was buffered |
| `plugin` | string | Plugin name (if applicable) |
| `capability` | string | Action within plugin |
| `correlation_id` | string | Links related events (command_id, execution_id) |
| `severity` | enum | debug, info, warn, error, critical |
| `source` | string | "server", "agent", or "gateway" |
| `hostname` | string | Host that generated the event |
| `os` | string | Operating system |
| `arch` | string | CPU architecture |
| `agent_version` | string | Agent version string |
| `principal` | string | User who initiated the action |
| `principal_role` | string | Role of the principal |
| `attributes` | json | Structured metadata (low-cardinality, for filtering) |
| `payload` | json | Type-specific data |
| `schema_version` | int | Schema version (currently 1) |

## Event Types

### Agent Lifecycle

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `agent.registered` | Register RPC succeeds | `enrollment_method`, plugins list |
| `agent.connected` | Subscribe stream opens | `via` (direct/gateway) |
| `agent.disconnected` | Subscribe stream closes | `session_duration_ms` |
| `agent.enrollment_pending` | Agent enters pending queue | hostname, os, arch |
| `agent.enrollment_denied` | Token invalid / admin denied | `reason` |

### Command Execution

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `command.dispatched` | `POST /api/command` or `POST /api/v1/commands` sends to at least one agent (MCP `execute_instruction` does not publish it) | `target_count`, plugin, action, command_id, scope |
| `command.response` | Each RUNNING response from agent | `output_bytes` |
| `command.completed` | Terminal status | `status`, `exit_code`, `error_message` |

### Orchestration

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `execution.created` | Execution created by a rerun: `POST /api/executions/{id}/rerun`, `POST /api/v1/executions/{id}/rerun` or MCP `record_execution_rerun` (once, on success only) | execution_id (the new one), parent_id, trigger |
| `execution.completed` | Execution cancelled: `POST /api/executions/{id}/cancel`, `POST /api/v1/executions/{id}/cancel` or MCP `cancel_execution` (once, on success only) | status |
| `schedule.fired` | ScheduleEngine triggers | definition_id, frequency_type |

### Approval

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `approval.approved` | Approval granted | reviewer |
| `approval.created` | An instruction execute call created a pending approval: `POST /api/instructions/{id}/execute`, `POST /api/v1/instructions/{id}/execute` or MCP `execute_instruction_definition` | none |
| `approval.rejected` | Approval denied | reviewer, comment |

### Instruction Lifecycle

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `instruction.created` | POST /api/instructions | name, plugin, action, type |
| `instruction.updated` | PUT /api/instructions/{id} | instruction_id |
| `instruction.deleted` | DELETE /api/instructions/{id} | instruction_id |
| `instruction.executed` | An instruction execute call reached at least one agent: `POST /api/instructions/{id}/execute`, `POST /api/v1/instructions/{id}/execute` or MCP `execute_instruction_definition` | none |

### Workflow

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `workflow.executed` | The engine admitted and ran a workflow: `POST /api/workflows/{id}/execute`, `POST /api/v1/workflows/{id}/execute` or MCP `execute_workflow`. Published once, whatever the run's outcome; not for a refusal, an idempotent replay or a run that threw | none |

### Auth

| Type | When | Key attributes/payload |
|------|------|----------------------|
| `auth.login` | Successful login | source_ip, user_agent |
| `auth.login_failed` | Failed login | source_ip, username |
| `auth.logout` | Logout | (none) |

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--no-analytics` | (enabled) | Disable analytics collection |
| `--analytics-drain-interval` | 10 | Drain interval in seconds |
| `--analytics-batch-size` | 100 | Batch size per drain cycle |
| `--analytics-jsonl` | (disabled) | Path for JSON Lines output |
| `--clickhouse-url` | (disabled) | ClickHouse HTTP endpoint |
| `--clickhouse-database` | yuzu | ClickHouse database |
| `--clickhouse-table` | yuzu_events | ClickHouse table |
| `--clickhouse-user` | (none) | ClickHouse username |
| `--clickhouse-password` | (none) | ClickHouse password |

### REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/analytics/status` | pending_count, total_emitted, enabled |
| GET | `/api/analytics/recent?limit=50` | Recent events for debugging |

## Sinks

### JSON Lines

Appends one JSON object per line to a file. Compatible with Fluentd, Splunk Universal Forwarder, and other log collectors.

```bash
yuzu-server --analytics-jsonl /var/log/yuzu/analytics.jsonl
```

### ClickHouse

HTTP POST using `JSONEachRow` format. See `docs/clickhouse-setup.md` for DDL and setup.

```bash
yuzu-server --clickhouse-url http://clickhouse:8123 \
            --clickhouse-user default \
            --clickhouse-password secret
```
