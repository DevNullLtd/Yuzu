# Instruction Engine

The instruction engine is the core of Yuzu's content plane. Every ad-hoc query, scheduled task, policy check, and remediation action flows through the same pipeline: a YAML-defined **InstructionDefinition** is dispatched to agents via the existing gRPC wire protocol, tracked by the **ExecutionTracker**, stored by the **ResponseStore**, and audited by the **AuditStore**.

This guide covers everything an operator needs to author, manage, execute, schedule, and govern instructions.

---

## Table of Contents

1. [Core Concepts](#1-core-concepts)
2. [YAML Authoring](#2-yaml-authoring)
3. [InstructionDefinition Reference](#3-instructiondefinition-reference)
4. [InstructionSets](#4-instructionsets)
5. [Parameter Type System](#5-parameter-type-system)
6. [Result Schema and Aggregation](#6-result-schema-and-aggregation)
7. [Approval Workflows](#7-approval-workflows)
8. [Concurrency Model](#8-concurrency-model)
9. [Scheduling](#9-scheduling)
10. [Execution Lifecycle](#10-execution-lifecycle)
11. [Error Codes](#11-error-codes)
12. [REST API Reference](#12-rest-api-reference)
13. [Dashboard UI](#13-dashboard-ui)
14. [Planned Features](#14-planned-features)

---

## 1. Core Concepts

### Content Hierarchy

```
ProductPack          (distribution boundary — Phase 7)
 └── InstructionSet  (permission boundary)
      └── InstructionDefinition  (the atomic unit)
           ├── Parameter Schema   (typed inputs)
           ├── Result Schema      (typed outputs)
           └── Execution Spec     (plugin + action + concurrency)
```

A definition can exist standalone (without a set or pack). Sets group definitions and enforce shared permissions. Packs bundle everything for signed distribution.

### Design Principles

- **Substrate, not scripts.** Definitions target stable plugin primitives. OS-specific syscalls stay inside the plugin layer. Content authors never write shell commands.
- **Everything is an InstructionDefinition.** Ad-hoc commands, scheduled tasks, policy checks, and remediation actions all use the same definition-to-execution-to-response pipeline.
- **Typed end-to-end.** Parameter schemas validate input before dispatch. Result schemas type output for downstream consumption (ClickHouse, Splunk, CSV export).
- **Governed execution.** Every state-changing action can require approval. Every execution is audited. Every response is persisted.

### Two Definition Types

| Type | Purpose | Default Approval | Dashboard Treatment |
|---|---|---|---|
| `question` | Read-only query (inventory, status checks) | `auto` | No confirmation prompt |
| `action` | State-changing operation (restart, install, delete) | `role-gated` | Confirmation required |

---

## 2. YAML Authoring

All instruction content is authored as YAML documents with `apiVersion: yuzu.io/v1alpha1`. The server stores the verbatim YAML as the source of truth (`yaml_source` column) alongside denormalized columns for efficient queries.

### Minimal Definition

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: crossplatform.process.list
  displayName: List Running Processes
  version: 1.0.0
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: processes
    action: list
```

### Saving YAML via API

```bash
# Save a definition from a YAML file (form-encoded; the yaml_source field
# carries the document verbatim)
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/yaml \
  --data-urlencode "yaml_source@definitions/process-list.yaml"

# Validate YAML without saving
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/validate-yaml \
  --data-urlencode "yaml_source@definitions/process-list.yaml"
```

### Dashboard YAML Editor

The Instruction Management page provides two authoring modes:

- **Form mode** -- fill in fields through structured inputs with dropdowns and validation.
- **Code mode** -- a CodeMirror editor with YAML syntax highlighting, live validation, and auto-complete for known plugin/action pairs.

Both modes are served as HTMX fragments.

---

## 3. InstructionDefinition Reference

### Full Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: crossplatform.service.inspect
  displayName: Inspect Service Status
  version: 1.2.0
  description: >-
    Returns the current state, startup type, and PID of a named service
    across Windows (SCM), Linux (systemd), and macOS (launchd).
  tags:
    - services
    - operations
spec:
  type: question
  platforms:
    - windows
    - linux
    - darwin

  execution:
    plugin: services
    action: inspect
    concurrency: per-device
    stagger:
      maxDelaySeconds: 0
      fixedDelaySeconds: 0
    minSuccessPercent: 100

  parameters:
    type: object
    required:
      - serviceName
    properties:
      serviceName:
        type: string
        displayName: Service Name
        description: The name of the service to inspect.
        validation:
          maxLength: 256
      verbose:
        type: boolean
        default: false

  result:
    columns:
      - name: serviceName
        type: string
      - name: state
        type: string
      - name: startupType
        type: string
      - name: pid
        type: int32
    aggregation:
      groupBy: [state]
      operations: [count]

  readablePayload: "Inspect service '${serviceName}'"

  gather:
    ttlSeconds: 300

  response:
    retentionDays: 90

  approval:
    mode: auto

  permissions:
    executeRoles:
      - endpoint-operator
      - endpoint-admin
    authorRoles:
      - content-author

  compatibility:
    minAgentVersion: 0.9.0
    requiredPlugins:
      - services

  legacy_shim:
    enabled: true
```

### Metadata Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Globally unique ID. Convention: `<scope>.<domain>.<action>` (e.g. `crossplatform.service.inspect`). |
| `displayName` | string | Yes | Human-readable name shown in the dashboard. |
| `version` | string | Yes | Semantic version (e.g. `1.2.0`). Used for compatibility checks. |
| `description` | string | No | Detailed description of what this definition does. |
| `tags` | list | No | Freeform tags for categorization and search. |

### Spec Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | `question` (read-only) or `action` (may modify state). |
| `platforms` | list | Yes | -- | Target platforms: `windows`, `linux`, `darwin`. |
| `execution` | object | Yes | -- | Plugin, action, concurrency, stagger. See [Section 8](#8-concurrency-model). |
| `parameters` | object | No | `{}` | Input parameter schema. See [Section 5](#5-parameter-type-system). |
| `result` | object | No | `{}` | Output column schema. See [Section 6](#6-result-schema-and-aggregation). |
| `readablePayload` | string | No | `""` | Template for audit display. Supports `${paramName}` interpolation. |
| `gather` | object | No | -- | `ttlSeconds`: agent response window (default 300). |
| `response` | object | No | -- | `retentionDays`: how long to keep response data (default 90). |
| `approval` | object | No | -- | `mode`: `auto`, `role-gated`, or `always`. See [Section 7](#7-approval-workflows). |
| `permissions` | object | No | -- | `executeRoles` and `authorRoles` arrays. |
| `compatibility` | object | No | -- | `minAgentVersion` and `requiredPlugins`. |
| `legacy_shim` | object | No | -- | `enabled: true` for auto-generated definitions from plugin descriptors. |

### Execution Spec

| Field | Type | Default | Description |
|---|---|---|---|
| `plugin` | string | -- | Plugin identifier (must match a registered plugin's `name`). |
| `action` | string | -- | Action name (must exist in the plugin's `actions[]` array). Case-insensitive; normalized to lowercase at creation time and at dispatch. |
| `concurrency` | string | `per-device` | One of: `per-device`, `per-definition`, `per-set`, `global:<N>`, `unlimited`. Only `per-device` is enforced — see [Section 8](#8-concurrency-model). |
| `stagger.maxDelaySeconds` | int | `0` | Max random delay per agent before execution. `0` = no stagger. |
| `stagger.fixedDelaySeconds` | int | `0` | Fixed delay per agent before execution, added before the random stagger. `0` = no fixed delay. Total wait = `fixedDelaySeconds` + random(`0`, `maxDelaySeconds`). |
| `minSuccessPercent` | int | `100` | Minimum success percentage. `0` = best-effort. |

### Compatibility

| Field | Description |
|---|---|
| `minAgentVersion` | Agents below this version are skipped during dispatch (error `4003`). |
| `requiredPlugins` | Agents missing any listed plugin are skipped (error `4001`). |

---

## 4. InstructionSets

An InstructionSet groups definitions under a shared permission boundary. Sets control who can execute, author, and approve definitions within them.

### Full Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionSet
metadata:
  id: core.crossplatform.services
  displayName: Cross-Platform Service Management
  version: 1.0.0
  description: Inspect, start, stop, and restart services across all platforms.
  platforms:
    - windows
    - linux
    - darwin
  permissions:
    executeRoles:
      - endpoint-operator
      - endpoint-admin
    authorRoles:
      - content-author
      - endpoint-admin
    approveRoles:
      - endpoint-admin
  contents:
    instructionDefinitions:
      - crossplatform.service.inspect
      - crossplatform.service.start
      - crossplatform.service.stop
      - crossplatform.service.restart
    policyFragments: []
    workflowTemplates: []
  defaults:
    approvalMode: role-gated
    responseRetentionDays: 30
    targetEstimationRequiredAbove: 500
  publishing:
    signed: true
    visibility: org
```

### Set-Level Permissions

| Role Type | Purpose |
|---|---|
| `executeRoles` | Roles permitted to run definitions in this set. |
| `authorRoles` | Roles permitted to create or modify definitions in this set. |
| `approveRoles` | Roles permitted to approve executions in this set. |

### Set Defaults

| Field | Default | Description |
|---|---|---|
| `approvalMode` | `auto` | Default approval mode for definitions that do not specify their own. |
| `responseRetentionDays` | `90` | Default retention period for response data. |
| `targetEstimationRequiredAbove` | -- | When estimated target count exceeds this, the UI requires confirmation. |

### Managing Sets via API

```bash
# Create an instruction set
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instruction-sets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Core Service Operations",
    "description": "Service inspect, start, stop, restart"
  }'

# Delete a set (cascades to contained definitions)
curl -s -b cookies.txt \
  -X DELETE http://localhost:8080/api/instruction-sets/abc123
```

---

## 5. Parameter Type System

Parameters use a JSON Schema subset. The root object describes the input shape; each property declares a typed parameter with optional validation.

### Supported Types

| Type | Description | Wire Format | Example |
|---|---|---|---|
| `string` | UTF-8 text | String | `"Spooler"` |
| `boolean` | Boolean flag | `true` / `false` | `true` |
| `int32` | 32-bit signed integer | Numeric string | `"42"` |
| `int64` | 64-bit signed integer | Numeric string | `"9223372036854775807"` |
| `datetime` | ISO 8601 timestamp | String | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | String | `"550e8400-e29b-41d4-a716-446655440000"` |

Parameters are transmitted as `map<string, string>` in the `CommandRequest` protobuf message. The server validates values against declared types and constraints before dispatch.

### Validation Constraints

| Constraint | Applicable Types | Description |
|---|---|---|
| `maxLength` | `string` | Maximum character count. |
| `minLength` | `string` | Minimum character count. |
| `pattern` | `string` | Regex the value must match. |
| `enum` | `string` | List of allowed values. |
| `minimum` | `int32`, `int64` | Minimum value (inclusive). |
| `maximum` | `int32`, `int64` | Maximum value (inclusive). |

### YAML Example

```yaml
parameters:
  type: object
  required:
    - serviceName
    - action
  properties:
    serviceName:
      type: string
      displayName: Service Name
      description: The system service name (not display name).
      validation:
        maxLength: 256
        pattern: "^[a-zA-Z0-9_.-]+$"
    action:
      type: string
      displayName: Action
      description: What to do with the service.
      validation:
        enum: [start, stop, restart]
    timeout:
      type: int32
      default: 30
      description: Seconds to wait for the operation.
      validation:
        minimum: 5
        maximum: 300
    verbose:
      type: boolean
      default: false
```

---

## 6. Result Schema and Aggregation

Result schemas declare typed columns for structured output. These types enable downstream consumption by ClickHouse, Splunk, CSV export, and the dashboard aggregation engine.

### Result Column Types

| Type | Description | Example Value |
|---|---|---|
| `bool` | Boolean | `true`, `false` |
| `int32` | 32-bit signed integer | `4592` |
| `int64` | 64-bit signed integer | `1710700800000` |
| `string` | UTF-8 text | `"running"` |
| `datetime` | ISO 8601 timestamp | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | `"550e8400-e29b-41d4-..."` |
| `clob` | Character large object | Multi-line log output, stack traces |

The `clob` type indicates a potentially large text field. The server may apply configurable truncation to limit storage.

### Server-Side Aggregation

The ResponseStore supports aggregation across agent responses using GROUP BY and aggregate functions.

```yaml
result:
  columns:
    - name: serviceName
      type: string
    - name: state
      type: string
    - name: pid
      type: int32
  aggregation:
    groupBy: [state]
    operations: [count, min, max, sum, avg]
```

| Operation | Description |
|---|---|
| `count` | Number of rows per group. |
| `sum` | Sum of numeric column values. |
| `avg` | Average of numeric column values. |
| `min` | Minimum value per group. |
| `max` | Maximum value per group. |

---

## 7. Approval Workflows

Yuzu supports three approval modes that control whether an execution requires human sign-off before dispatch.

### Approval Modes

| Mode | Behavior |
|---|---|
| `auto` | No approval required. Execution dispatches immediately. |
| `role-gated` | Non-admin users must submit for approval. Admins and users with `approveRoles` can execute directly. |
| `always` | Every execution requires explicit approval, regardless of the user's role. |

### Rules

- **Submitter cannot approve.** The user who submits an execution request cannot be the one to approve it. A different user with the appropriate role must review it.
- **Comments are supported.** Both approve and reject actions accept an optional comment for the audit trail.
- **Pending count.** The API provides a pending approval count for dashboard badges and automation polling.

### YAML Configuration

```yaml
spec:
  approval:
    mode: role-gated    # auto | role-gated | always
```

### Executor-Side Behavior

When a user (or MCP tool) executes an instruction that requires approval:

1. **HTTP 202 response.** The server returns `{"status": "pending_approval", "approval_id": "...", "definition_id": "..."}` instead of dispatching immediately. The execution is queued, not dropped.
2. **Dashboard toast notification.** A toast appears in the web dashboard confirming the request was submitted for approval. The toast includes the approval ID for reference.
3. **Approvals tab.** The pending request is visible in the **Approvals** tab of the dashboard. The executor can check its status there at any time. Once an approver approves or rejects the request, the status updates in the tab and the execution either proceeds or is discarded.

The submitter cannot approve their own request. A different user with the appropriate role must review it.

### Approval API

```bash
# Check pending approval count
curl -s -b cookies.txt \
  http://localhost:8080/api/approvals/pending/count

# Approve an execution request
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/approvals/REQ-001/approve \
  -H "Content-Type: application/json" \
  -d '{"comment": "Reviewed — safe to proceed."}'

# Reject an execution request
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/approvals/REQ-001/reject \
  -H "Content-Type: application/json" \
  -d '{"comment": "Not approved for production during change freeze."}'
```

---

## 8. Concurrency Model

**Corrected 2026-08-31 (ADR-1007) — only `per-device` is actually enforced.** See
`docs/yaml-dsl-spec.md` §12 for the full corrected model (mode-by-mode status, why enforcement is
server-side rather than agent-side, the `plugin: server`-class catalog-definition caveat, what
remains unenforced and why) and `docs/Instruction-Engine.md` §10 for the implementation summary.
This section previously described a fully-implemented 5-mode system, including a wait queue; none
of that was ever built except the one mode below.

### Modes

| Mode | Enforcement | Scope | Status |
|---|---|---|---|
| `per-device` | Server-side | One execution of this definition per device at a time | **Enforced** (default; 191 real shipped definitions use it). |
| `per-definition` | None | — | **Not enforced** — used only on catalog-only definitions with no live dispatch path. Do not rely on this for dangerous global operations (schema migration, bulk delete) — nothing prevents concurrent execution. |
| `per-set` | None | — | **Not enforced, unspecified** — no grouping key defined anywhere. Zero real usage. |
| `global:<N>` | None | — | **Not enforced** — not used in any shipped definition. |
| `unlimited` | None | No limits | No enforcement needed. |

### How Enforcement Works

**`per-device` (the only enforced mode):** enforced server-side. At dispatch, the server holds a
claim on `(definition_id, agent_id)` in a dedicated Postgres table
(`execution_tracker.concurrency_claims`, race-free via a partial unique index), excludes any agent
already holding an open claim for this definition, and releases the claim when that agent reaches
a terminal status. There is no wait queue — an excluded agent is simply not dispatched to on this
attempt; retry once the in-flight execution completes. Error code `3003` is registered for this
condition but not yet surfaced through the dispatch response. Not covered by this gate: raw MCP/REST
dispatch (no `definition_id` in scope) and the fleet-broadcast arm of dispatch.

**One release exception worth knowing:** cancelling an execution does **not** release its claim
(there is no way to tell the agent to stop, so a cancelled-but-still-running execution's claim
behaves like a normal in-flight one until a terminal response or the reconciler's TTL bound releases
it — worst case, one hour). A `per-device` definition dispatched via a **workflow step** (as opposed
to a direct execute call or a schedule) releases and renews the same way as any other dispatch path
— it just won't show progress in the executions drawer, since workflow-step dispatch doesn't yet
correlate a real execution id there.

**All other modes** are accepted and stored but have no enforcement effect — they behave exactly
like `unlimited` in practice.

### YAML Syntax

```yaml
spec:
  execution:
    concurrency: per-device          # default — the only mode actually enforced
    # concurrency: unlimited         # no limits (also the practical effect of any unsupported value)
```

### Stagger

For large-fleet dispatch, stagger introduces a per-agent delay before execution to avoid thundering herd problems. Each agent calculates: **total wait = `fixedDelaySeconds` + random(`0`, `maxDelaySeconds`)**.

```yaml
spec:
  execution:
    stagger:
      maxDelaySeconds: 60       # each agent delays 0-60s randomly
      fixedDelaySeconds: 5      # plus a fixed 5s base delay
```

If the command has an expiration (`expires_at`) and the total delay causes it to expire, the agent sends a `REJECTED` response and skips execution.

The REST API also supports stagger/delay via the `stagger` and `delay` integer fields on `POST /api/command`:

```bash
curl -X POST http://server:8080/api/command \
  -H "Content-Type: application/json" \
  -d '{"plugin":"hardware","action":"cpu-info","stagger":30,"delay":5}'
```

---

## 9. Scheduling

The ScheduleEngine supports recurring instruction executions with four frequency types. The scope expression is evaluated at dispatch time, so newly enrolled devices are automatically included.

### Frequency Types

| Type | Fields Used | Description |
|---|---|---|
| `daily` | `time_of_day` | Runs once per day at the specified time. |
| `weekly` | `time_of_day`, `day_of_week` | Runs once per week. `day_of_week`: 0=Sunday through 6=Saturday. |
| `monthly` | `time_of_day`, `day_of_month` | Runs once per month. `day_of_month`: 1-28 (no 29/30/31 to avoid month-length issues). |
| `interval` | `interval_minutes` | Runs every N minutes. Minimum: 1 minute. |

### Execution semantics

A server-side poller checks for due schedules every 30 seconds, so a fire can
land up to ~30 seconds after its due time — but firing is now two stages, not
one. At fire time the poller creates a tracked execution (attributed to the
schedule's creator, appearing immediately in the Executions history) and
commits a durable occurrence to the command outbox, emitting an
`instruction.schedule_fired` audit event with result `queued`. A leader-gated
delivery loop then drains the outbox and performs the actual dispatch, within
~5 seconds of enqueue — so up to ~35 seconds total from due time to dispatch.
Delivery emits its own `command.outbox_delivered` audit event recording the
real send outcome: `success` (dispatched, with the agents-reached count),
`failure` (no agents currently in scope — recorded and skipped, not retried;
or a malformed occurrence), or `denied` (authority was revoked between
enqueue and delivery). The execution row's targeted-agent count fills in at
delivery, once the real outcome is known. A systemic delivery-gate failure
(for example, containment status unreadable) is treated as transient: the
same occurrence is retried with back-off rather than failed outright.

Approval-gated runs (the schedule's `requires_approval` flag, or a definition
whose `approvalMode` is not `auto` — there is no operator session on the
scheduled path, so `role-gated` also requires a ticket) submit one approval
request per occurrence and hold at the due time. Approving the ticket fires
the run within one poller cycle; rejecting it skips that occurrence, and the
next occurrence submits a fresh request. Approvals follow the standard
four-eyes rule, so the schedule's creator cannot approve their own scheduled
runs. Poller health is observable via the `yuzu_schedule_fires_total`,
`yuzu_schedule_fire_failures_total`, `yuzu_schedule_approvals_submitted_total`
and `yuzu_schedule_tick_errors_total` counters.

### Schedule Properties

| Field | Type | Description |
|---|---|---|
| `name` | string | Human-readable schedule name. |
| `definition_id` | string | The instruction definition to execute. |
| `frequency_type` | string | `daily`, `weekly`, `monthly`, or `interval`. |
| `interval_minutes` | int | Minutes between executions (for `interval` type). |
| `time_of_day` | string | HH:MM format (for `daily`, `weekly`, `monthly`). |
| `day_of_week` | int | 0-6 (for `weekly`). |
| `day_of_month` | int | 1-28 (for `monthly`). |
| `scope_expression` | string | Scope DSL expression evaluated at dispatch time. |
| `requires_approval` | bool | If `true`, each scheduled run goes through the approval workflow. |
| `enabled` | bool | Toggle the schedule on or off without deleting it. |

### Schedule API

```bash
# Create a schedule — daily service check at 06:00
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Service Health Check",
    "definition_id": "crossplatform.service.inspect",
    "frequency_type": "daily",
    "time_of_day": "06:00",
    "scope_expression": "ostype == \"windows\" AND tag:environment == \"Production\"",
    "requires_approval": false,
    "enabled": true
  }'

# Create a schedule — every 30 minutes
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Process inventory sweep",
    "definition_id": "crossplatform.process.list",
    "frequency_type": "interval",
    "interval_minutes": 30,
    "scope_expression": "ostype IN [\"windows\", \"linux\"]",
    "enabled": true
  }'

# Enable or disable a schedule
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/schedules/SCHED-001/enable \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete a schedule
curl -s -b cookies.txt \
  -X DELETE http://localhost:8080/api/schedules/SCHED-001
```

### Execution Tracking for Schedules

Each scheduled dispatch creates a normal `Execution` record. The schedule tracks:
- `next_execution_at` -- when the next run is due.
- `last_executed_at` -- when the last run fired.
- `execution_count` -- total number of completed runs.

---

## 10. Execution Lifecycle

### States

An execution progresses through these states:

```
pending → dispatching → gathering → completed
                                  → failed
                                  → cancelled
```

### Per-Agent Tracking

Each agent targeted by an execution has its own status record:

| Field | Description |
|---|---|
| `agent_id` | The targeted agent. |
| `status` | `pending`, `dispatched`, `running`, `success`, `failure`, `timeout`, `rejected`. |
| `dispatched_at` | When the command was sent to the agent. |
| `first_response_at` | When the agent first responded (streaming). |
| `completed_at` | When the agent finished. |
| `exit_code` | Plugin exit code. |
| `error_detail` | Error message if the agent reported failure. |

### Aggregate Counters

The execution record maintains real-time counters:

| Counter | Description |
|---|---|
| `agents_targeted` | Total agents in scope at dispatch time. |
| `agents_responded` | Agents that have sent at least one response. |
| `agents_success` | Agents that completed successfully. |
| `agents_failure` | Agents that reported failure. |
| `progress_pct` | `(agents_responded / agents_targeted) * 100`. |

### Rerun

Rerun creates a new execution linked to the original via `rerun_of`. Two modes:

```bash
# Rerun all agents
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions/EXEC-001/rerun \
  -H "Content-Type: application/json" \
  -d '{"scope": "all"}'

# Rerun only failed agents
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions/EXEC-001/rerun \
  -H "Content-Type: application/json" \
  -d '{"scope": "failed_only"}'
```

The `scope` field controls which agents are included. Set `"scope": "failed_only"` to target only agents that reported failure; any other value (or omitting the field) reruns all agents.

### Cancel

Cancellation records the requesting user for audit:

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions/EXEC-001/cancel
```

### Parent/Child Executions

Executions can form hierarchies using the `parent_id` field. This supports:
- **Follow-up instructions** -- a remediation execution that references the original diagnostic.
- **Multi-step workflows** -- a chain of executions where each step references the previous.

---

## 11. Error Codes

Errors are categorized into four domains with non-overlapping numeric ranges.

### 1xxx -- Plugin Errors

| Code | Name | Description | Retryable |
|---|---|---|---|
| 1001 | `PLUGIN_ACTION_NOT_FOUND` | Plugin does not support the requested action | No |
| 1002 | `PLUGIN_PARAM_INVALID` | Parameter validation failed | No |
| 1003 | `PLUGIN_PERMISSION_DENIED` | OS-level permission denied (e.g. non-admin) | No |
| 1004 | `PLUGIN_RESOURCE_MISSING` | Target resource does not exist | No |
| 1005 | `PLUGIN_OPERATION_FAILED` | Action executed but failed | Transient |
| 1006 | `PLUGIN_CRASH` | Plugin segfaulted or threw unhandled exception | No |
| 1007 | `PLUGIN_TIMEOUT` | Plugin did not complete within gather TTL | Once |

### 2xxx -- Transport Errors

| Code | Name | Description | Retryable |
|---|---|---|---|
| 2001 | `TRANSPORT_DISCONNECTED` | Agent lost connection during execution | Always |
| 2002 | `TRANSPORT_STREAM_ERROR` | gRPC stream broken mid-response | Always |
| 2003 | `TRANSPORT_RESPONSE_TOO_LARGE` | Response exceeds max message size | No |

### 3xxx -- Orchestration Errors

| Code | Name | Description | Retryable |
|---|---|---|---|
| 3001 | `DefinitionNotFound` | The referenced InstructionDefinition does not exist | No |
| 3002 | `ApprovalRequired` | Execution blocked pending approval | Awaits human |
| 3003 | `ConcurrencyBlocked` | Registered for `per-device` claim exclusion; not yet surfaced through the dispatch response (ADR-1007) | After slot frees |
| 3004 | `ScopeEmpty` | The resolved target scope matched no agents | No |
| 3005 | `ScheduleExpired` | The schedule's execution window has passed | No |

Names above are the taxonomy's actual registered names (`server/core/src/error_codes.cpp`) — this
row set was corrected from a stale naming scheme this table had carried (`ORCH_*` prefixes that
never matched the code). Like 3003, none of 3001/3002/3004/3005 currently has a production call
site that emits it (`error_codes.cpp`'s registration is not the same as being wired to a real
error path yet) — the retry-semantics column above states the DESIGNED behavior per the taxonomy
entry, not an observed one.

### 4xxx -- Agent Errors

| Code | Name | Description | Retryable |
|---|---|---|---|
| 4001 | `AGENT_PLUGIN_NOT_LOADED` | Required plugin not available on agent | No |
| 4002 | `AGENT_SHUTTING_DOWN` | Agent is in shutdown sequence | On reconnect |
| 4003 | `AGENT_VERSION_INCOMPATIBLE` | Agent version below `minAgentVersion` | No |

### Retry Semantics

| Category | Default Retry | Max Attempts | Backoff |
|---|---|---|---|
| Transport (2xxx) | Always | 3 | Exponential (1s, 2s, 4s) |
| Transient plugin (1005, 1007) | If `retryable: true` | 2 | Linear (5s) |
| Deterministic plugin (1001-1004, 1006) | Never | 0 | -- |
| Agent (4001-4003) | Never (except 4002) | 1 | -- |
| Orchestration (3001-3005) | Per-code as noted | -- | -- |

---

## 12. REST API Reference

All API endpoints require session-cookie authentication. Obtain a session by posting to `/login` first.

There are two API surface areas with different response envelopes:

**`/api/*` endpoints** (instruction engine, registered in `instruction_routes.cpp`/`execution_routes.cpp` and `server.cpp`) use domain-keyed responses:

```json
{
  "definitions": [ ... ],
  "count": 42
}
```

The key name varies by resource type (`"definitions"`, `"executions"`, `"schedules"`, `"approvals"`, `"sets"`, `"agents"`, `"children"`). Error responses use `{"error": "message"}`.

**`/api/v1/*` endpoints** (versioned REST API, registered in `rest_api_v1.cpp`) use a standard envelope with metadata:

```json
{
  "data": { ... },
  "meta": { "api_version": "v1" }
}
```

List endpoints on `/api/v1/*` include pagination:

```json
{
  "data": [ ... ],
  "pagination": { "total": 42, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

Error responses on `/api/v1/*`:

```json
{
  "error": "descriptive message",
  "code": 1002,
  "meta": { "api_version": "v1" }
}
```

### Definitions

#### List definitions

```
GET /api/instructions
```

Query parameters: `name`, `plugin`, `type`, `set_id`, `enabled_only`, `limit`.

```bash
# List all definitions
curl -s -b cookies.txt http://localhost:8080/api/instructions

# Filter by plugin
curl -s -b cookies.txt "http://localhost:8080/api/instructions?plugin=services"

# Filter by type
curl -s -b cookies.txt "http://localhost:8080/api/instructions?type=question"
```

#### Get a single definition

```
GET /api/instructions/{id}
```

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/instructions/crossplatform.service.inspect
```

#### Create a definition (JSON)

```
POST /api/instructions
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions \
  -H "Content-Type: application/json" \
  -d '{
    "id": "crossplatform.service.inspect",
    "name": "Inspect Service Status",
    "version": "1.2.0",
    "type": "question",
    "plugin": "services",
    "action": "inspect",
    "description": "Returns current state of a named service.",
    "platforms": "windows,linux,darwin",
    "approval_mode": "auto",
    "concurrency_mode": "per-device",
    "parameter_schema": "{\"type\":\"object\",\"required\":[\"serviceName\"],\"properties\":{\"serviceName\":{\"type\":\"string\"}}}",
    "result_schema": "[{\"name\":\"state\",\"type\":\"string\"},{\"name\":\"pid\",\"type\":\"int32\"}]"
  }'
```

#### Update a definition

```
PUT /api/instructions/{id}
```

```bash
curl -s -b cookies.txt \
  -X PUT http://localhost:8080/api/instructions/crossplatform.service.inspect \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Inspect Service Status",
    "version": "1.3.0",
    "description": "Updated description with new fields."
  }'
```

#### Delete a definition

```
DELETE /api/instructions/{id}
```

```bash
curl -s -b cookies.txt \
  -X DELETE http://localhost:8080/api/instructions/crossplatform.service.inspect
```

#### Save from YAML

```
POST /api/instructions/yaml
```

Accepts `Content-Type: application/x-yaml`. Parses the YAML, extracts metadata and spec fields, and creates or updates the definition. The verbatim YAML is stored as `yaml_source`.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/yaml \
  -H "Content-Type: application/x-yaml" \
  --data-binary @my-definition.yaml
```

#### Validate YAML (dry run)

```
POST /api/instructions/validate-yaml
```

Returns validation errors without saving.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/validate-yaml \
  -H "Content-Type: application/x-yaml" \
  --data-binary @my-definition.yaml
```

#### Import from JSON

```
POST /api/instructions/import
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/import \
  -H "Content-Type: application/json" \
  -d @exported-definition.json
```

#### Export to JSON

```
GET /api/instructions/{id}/export
```

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/instructions/crossplatform.service.inspect/export \
  -o exported-definition.json
```

#### Execute an instruction definition

```
POST /api/instructions/{id}/execute
```

Dispatches the instruction definition to agents. Requires `Execution:Execute` permission.

**Request body:**

```json
{
  "agent_ids": ["agent-uuid-1"],
  "params": {"path": "C:\\Windows\\System32\\notepad.exe"}
}
```

- `agent_ids` — optional array of specific agent IDs to target.
- `scope` — optional scope expression (e.g., `group:servers`, `os:windows AND tag:prod`), or `__all__` for every enrolled agent. **Omit both `scope` and `agent_ids`** to broadcast. A *supplied* empty string, a non-string `scope`, an empty `agent_ids`, a non-array `agent_ids`, or a non-string entry is refused with `400` rather than widened to the whole fleet (#2500) — a target the caller named that resolves to nothing is an error, not a request for everything.
- `params` — key-value parameters to pass to the plugin action. Keys should match the definition's `parameter_schema`.

**Response (200):**

```json
{
  "command_id": "filesystem-a1b2c3",
  "execution_id": "exec-d4e5f6",
  "agents_reached": 3,
  "definition_id": "filesystem.exists"
}
```

- `command_id` — legacy correlation token; retained on the response body for future use. To poll individual agent results, call `query_responses` with the `execution_id` (exact — just this dispatch) or `instruction_id` (all responses to that definition); `command_id` itself is not a `query_responses` filter.
- `execution_id` — per-run identifier required by `GET /api/v1/events` (live JSON SSE stream) and `GET /api/v1/executions/{id}` (final state lookup). Agentic workers should subscribe to the events stream with `?execution_id=<execution_id>` immediately after dispatch to watch progress in real time. Empty string if the server was started without an `ExecutionTracker` (test harnesses and stripped-down deployments only — production always has one).
- `agents_reached` — number of agents the command was actually sent to (may be smaller than the targeted set if some are offline).
- `definition_id` — echoes the path parameter.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instructions/filesystem.exists/execute \
  -H "Content-Type: application/json" \
  -d '{"params":{"path":"C:\\Windows"}}'
```

> **Approval gate:** The response varies based on the definition's `approval_mode`. Definitions with `approval_mode: auto` return HTTP 200 with an immediate execution result. Definitions with `approval_mode: role-gated` or `always` return HTTP 202 with a `pending_approval` status and an `approval_id` when the caller requires approval. See [Section 7](#7-approval-workflows) for details.

#### List definitions (v1 endpoint)

```
GET /api/v1/definitions
```

The versioned v1 endpoint. Returns all definitions with the `{"data": [...], "pagination": {...}, "meta": {...}}` envelope. Note: this endpoint does not currently accept query parameters for filtering -- it returns all definitions. Use `/api/instructions` with query parameters (`name`, `plugin`, `type`, `set_id`, `enabled_only`, `limit`) if filtering is needed.

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/definitions
```

### Instruction Sets

#### List instruction sets

```
GET /api/instruction-sets
```

```bash
curl -s -b cookies.txt http://localhost:8080/api/instruction-sets
```

#### Create a set

```
POST /api/instruction-sets
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/instruction-sets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Service Operations",
    "description": "All service management definitions"
  }'
```

#### Delete a set

```
DELETE /api/instruction-sets/{id}
```

Cascade-deletes all definitions in the set.

```bash
curl -s -b cookies.txt \
  -X DELETE http://localhost:8080/api/instruction-sets/SET-001
```

### Schedules

#### List schedules

```
GET /api/schedules
```

Query parameters: `definition_id`, `enabled_only`.

```bash
# List all schedules
curl -s -b cookies.txt http://localhost:8080/api/schedules

# List only enabled schedules
curl -s -b cookies.txt "http://localhost:8080/api/schedules?enabled_only=true"
```

The dashboard's Schedules tab (see [Dashboard UI](#13-dashboard-ui) below) is backed by the
versioned `GET /api/v1/schedules` twin, not the legacy endpoint above. If the schedule store is
temporarily unreachable, the tab shows "Schedule list temporarily unavailable — retry shortly"
instead of an empty list. Schedule reads (dashboard, REST v1, and MCP `list_schedules` alike) are
capped at 100 rows; if a fleet has more schedules than that, the tab shows a partial-list notice
above the table, and `GET /api/v1/schedules`'s JSON response carries `result_truncated_by_cap: true`
(see [REST API](rest-api.md#get-apiv1schedules)) — the two are the same underlying signal.

#### Create a schedule

```
POST /api/schedules
```

See [Section 9](#9-scheduling) for the full field reference and examples.

#### Delete a schedule

```
DELETE /api/schedules/{id}
```

```bash
curl -s -b cookies.txt -X DELETE http://localhost:8080/api/schedules/SCHED-001
```

#### Enable/disable a schedule

```
POST /api/schedules/{id}/enable
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/schedules/SCHED-001/enable \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

### Approvals

#### List approvals

```
GET /api/approvals
```

Query parameters: `status`, `submitted_by`.

```bash
# List all approvals
curl -s -b cookies.txt http://localhost:8080/api/approvals

# List pending approvals
curl -s -b cookies.txt "http://localhost:8080/api/approvals?status=pending"
```

#### Pending approval count

```
GET /api/approvals/pending/count
```

```bash
curl -s -b cookies.txt http://localhost:8080/api/approvals/pending/count
```

#### Approve

```
POST /api/approvals/{id}/approve
```

The reviewer must be a different operator than the submitter — self-approval
is rejected with HTTP 400 (`"reviewer cannot be the same as the submitter"`),
and the denied attempt is recorded in the audit log.

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/approvals/REQ-001/approve \
  -H "Content-Type: application/json" \
  -d '{"comment": "Approved."}'
```

#### Reject

```
POST /api/approvals/{id}/reject
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/approvals/REQ-001/reject \
  -H "Content-Type: application/json" \
  -d '{"comment": "Denied — change freeze in effect."}'
```

### Executions

All routes below are management-group confined (#3789) — see `rest-api.md`'s "Executions" section
for the per-route permission and confinement/404 behavior.

#### List executions

```
GET /api/executions
```

Query parameters: `definition_id`, `status`, `limit`.

```bash
# List all executions
curl -s -b cookies.txt http://localhost:8080/api/executions

# Filter by definition
curl -s -b cookies.txt "http://localhost:8080/api/executions?definition_id=crossplatform.service.inspect"

# Filter by status
curl -s -b cookies.txt "http://localhost:8080/api/executions?status=completed"
```

#### Get a single execution

```
GET /api/executions/{id}
```

```bash
curl -s -b cookies.txt http://localhost:8080/api/executions/EXEC-001
```

#### Get execution summary

```
GET /api/executions/{id}/summary
```

Returns aggregate counters including `progress_pct`.

```bash
curl -s -b cookies.txt http://localhost:8080/api/executions/EXEC-001/summary
```

#### Get per-agent statuses

```
GET /api/executions/{id}/agents
```

```bash
curl -s -b cookies.txt http://localhost:8080/api/executions/EXEC-001/agents
```

#### Get child executions

```
GET /api/executions/{id}/children
```

```bash
curl -s -b cookies.txt http://localhost:8080/api/executions/EXEC-001/children
```

#### Rerun

```
POST /api/executions/{id}/rerun
```

```bash
# Rerun failed agents only
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions/EXEC-001/rerun \
  -H "Content-Type: application/json" \
  -d '{"scope": "failed_only"}'
```

#### Cancel

```
POST /api/executions/{id}/cancel
```

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8080/api/executions/EXEC-001/cancel
```

---

## 13. Dashboard UI

The Instruction Management page is accessible from the main dashboard. It uses HTMX to load content fragments without full page reloads.

### Tabs

| Tab | Description |
|---|---|
| **Definitions** | Browse, search, create, edit, and delete instruction definitions. Supports both form mode and CodeMirror YAML editor. |
| **Executions** | Execute instructions and view results. The top section provides an execution form: select a definition from the dropdown (grouped by plugin), fill in parameters (auto-populated from the definition's schema), choose a scope (all agents, a group, or an individual agent), and click Execute. Below the form, the execution history table shows each run with a 4-segment status sparkbar (succeeded / failed / running / pending — length encodes count, hue encodes status), the resolved definition name, the wall-clock dispatch time in the operator's local timezone (`HH:MM:SS.mmm <TZ>`, e.g. `12:22:33.251 BST`; full ISO-8601 UTC on hover), and — on failed rows — an 80-character preview of the most recent agent error. The "Fan-out" cell shows succeeded / failed / targeted counts that update in real time as agents respond. Click any row to expand an inline drawer that **live-updates via SSE as responses arrive** — no page reload required. The drawer shows a KPI strip (Total / Succeeded / Failed / p50 / p95 duration), a small-multiples agent grid colored by status (decile-bucketed when the execution targets more than 1024 agents), a per-agent table sorted failed-first with inline duration bars, and a responses table with a **Time** column showing the server-side response arrival time at millisecond precision (same wall-clock format as above). The drawer is keyboard-reachable via Tab and Enter/Space. Pass `?definition_id=<id>` in the page URL to pre-filter the list to one definition. |
| **Schedules** | Create, enable/disable, and delete recurring schedules. Shows next and last execution times. |
| **Approvals** | Review pending approval requests. Approve or reject with comments. Badge shows pending count. A submitter cannot review their own request — a pending row you submitted shows "You submitted this — another reviewer must approve" instead of buttons, and any backend denial (self-review, already-reviewed) surfaces as an error toast. |

### YAML Editor

The definition editor supports two modes:

- **Form mode**: Structured inputs with dropdowns for type, platform, concurrency mode, and approval mode. Validation feedback inline.
- **Code mode**: Full CodeMirror editor with YAML syntax highlighting. Paste or write YAML directly. A "Validate" button checks syntax without saving.

Both modes save through the same `/api/instructions/yaml` endpoint.

### Inline Parameters (CLI-style)

The dashboard instruction bar supports CLI-style inline parameters using `key=value` syntax:

```
filesystem exists path=C:\Windows\System32\notepad.exe
registry get_value hive=HKLM key=SOFTWARE\Microsoft\Windows value=ProductName
```

**Syntax rules:**
- Tokens containing `=` are parsed as `key=value` parameters
- Tokens without `=` form the command text (plugin + action)
- Quoted values are supported: `key="value with spaces"`
- Keys are lowercased; values preserve original case
- Parameters are passed to the plugin as a `map<string, string>`

This differs from YAML-parameterised instructions where parameters are defined in the `parameter_schema` of an `InstructionDefinition`. Inline parameters are ad-hoc and bypass schema validation — they are sent directly to the plugin action. YAML-defined parameters provide type constraints, descriptions, default values, and validation.

### Response Visualization (chart deck)

When the dispatched (plugin, action) reverse-resolves to an enabled `InstructionDefinition` that declares `spec.visualization` or `spec.visualizations`, a chart deck auto-renders above the results table — no operator action required. The dashboard:

1. Resolves `(plugin, action)` to the first enabled definition with a configured visualization. The reverse-lookup is gated on `InstructionDefinition:Read` in addition to `Execution:Execute`; an operator without `InstructionDefinition:Read` sees the dispatch succeed but no chart appears.
2. Emits an OOB `<div id="chart-deck-host">` with a 2-second deferred load trigger so responses have time to arrive.
3. Fetches `/fragments/results?...&definition_id=<id>` which returns one chart-card placeholder per configured chart in a `<div class="yuzu-chart-deck">` container.
4. The Yuzu chart adapter (`/static/yuzu-charts.js`) — built on Apache ECharts 5 (`/static/echarts.min.js`) and themed from Yuzu design tokens — populates each placeholder from `GET /api/v1/executions/{id}/visualization?definition_id=<id>&index=<N>`.

**Limitations operators should expect:**

- **First-match arbitrariness.** When multiple enabled definitions share `(plugin, action)` and more than one declares a visualization, the alphabetically-first definition wins. Authors should ensure at most one chart-bearing definition per `(plugin, action)` — or dispatch via the Instructions tab (which carries `definition_id` explicitly).
- **F5 mid-dispatch.** Reloading the dashboard within the 2-second window cancels the deferred chart load. Re-dispatch to recover.
- **Row cap.** Each chart's underlying response read is capped at 10 000 rows. When the cap is hit, the payload includes `rows_capped: true`; the dashboard renders the chart from the truncated set and the `command.dispatch` audit detail records the truncation.
- **No definition? No chart.** Free-form `(plugin, action)` dispatches that don't correspond to any enabled definition with `spec.visualization` produce only the standard tabular results — the dashboard does not render an empty chart card.
- **Dashboard YAML editor strips `spec.visualization`.** The dashboard's CodeMirror editor (`POST /api/instructions/yaml`) saves the YAML source verbatim into `yaml_source` but its schema-aware field extractor (`instruction_yaml`, which indexes the id/name/plugin/action/type/description/concurrency/approval columns from both the canonical nested and flat schemas) does not extract `spec.visualization` into the indexed `visualization_spec` column. Result: editing a chart-bearing definition in the dashboard editor and saving silently disables its chart until the definition is re-imported via `POST /api/v1/definitions/import` (JSON envelope, full visualization extraction) or via a server restart that triggers the bundled-content auto-import. Author chart-bearing definitions through `POST /api/v1/definitions/import` rather than the editor save. Tracked as a known gap pending yaml-cpp Windows MSVC resolution (#625).

See `docs/yaml-dsl-spec.md` § `spec.visualization` for the chart configuration schema and `docs/user-manual/rest-api.md` § Execution Visualization for the underlying REST API.

**Worked examples (default-shipped).** Six chart-bearing definitions ship in the in-tree content library as the default demo set:

| Definition | Chart |
|---|---|
| `security.vuln_scan.summary` | pie — vulnerabilities by severity |
| `security.antivirus.defender_status` | pie — Defender real-time protection |
| `security.encryption.state` | pie — volume protection (BitLocker / LUKS / FileVault) |
| `security.firewall.state` | column (multi-series) — firewall state per profile |
| `security.certificates.list` | pie — certificates by issuer (top-N + Other) |
| `device.os_info.os_name` | pie — OS distribution across the fleet |

They are bundled as `InstructionSet demo.visualization.fleet-posture` (`content/definitions/visualization_demo_set.yaml`) and as `ProductPack pack.demo.visualization` (`content/packs/visualization-demo-pack.yaml`) and are **auto-imported on server startup** — no manual import step is required on a fresh install. The 217 InstructionDefinitions and 10 InstructionSets under `content/` are converted to JSON envelopes at build time by `server/core/scripts/embed_content.py` (PyYAML), embedded in the server binary as `kBundledDefinitions` / `kBundledSets`, and upserted on every startup via `import_definition_json` / `create_set`. Conflicts on already-existing IDs are silently skipped — operator-customised definitions are never overwritten by the auto-import. Each successful or errored import emits an `audit_events.action="content.bundled_import"` row with `principal=system` for SOC 2 traceability.

On upgrade from a release prior to the build-time content embed, definitions an operator previously DELETED will reappear after restart. To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than deleting the row.

To force-install on an existing deployment via the operator UI (e.g. for a custom InstructionSet not in the in-tree library), still use the dashboard YAML import view or:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
     --data-binary @content/packs/visualization-demo-pack.yaml \
     https://yuzu.example/api/v1/product-packs
```

Then dispatch any of the six from the dashboard "Send" panel — the chart deck auto-renders above the results table.

### Response Templates (saved views)

A response template is a named bundle of *column subset + sort order + filter presets* attached to an `InstructionDefinition`. When the operator opens the execution results view for a definition, the filter bar's **View** dropdown lists every available template; selecting one re-renders the table with the chosen columns visible, the chosen sort applied, and any equals-op filters auto-populated.

**Synthesised default.** Every definition has at least one template — the engine synthesises a `__default__` view from `spec.result.columns` (or, when omitted, from the plugin's hard-coded column schema) so the dropdown is never empty. The synthesised default lists all columns, applies no sort, and applies no filters — i.e. it matches the legacy "show everything" behaviour.

**Authoring.** Operators can author additional templates either by including a `spec.responseTemplates` array in the YAML definition (see `docs/yaml-dsl-spec.md` § `spec.responseTemplates`) or via the REST CRUD surface:

| Verb | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/definitions/{id}/response-templates` | List, with the synthesised default auto-prepended when no operator default is set |
| `GET` | `/api/v1/definitions/{id}/response-templates/{tid}` | Fetch one |
| `POST` | `/api/v1/definitions/{id}/response-templates` | Create (auto-assigns id when absent) |
| `PUT` | `/api/v1/definitions/{id}/response-templates/{tid}` | Replace in place |
| `DELETE` | `/api/v1/definitions/{id}/response-templates/{tid}` | Remove. Rejects `__default__` |

Reads are gated on `InstructionDefinition:Read`, mutations on `InstructionDefinition:Write`.

**Limitations operators should expect:**

- **Equals-op only in dashboard auto-apply.** The dashboard's filter map is exact-match; `contains`/`starts_with`/`ends_with` filters in a template are stored and returned by REST but the dashboard only auto-applies the `equals` clauses. Operators can still use the column-by-column filter controls to narrow the view further once the template is loaded.
- **Detail drawer ignores the column subset.** The expandable per-row detail drawer always shows every parsed field — hiding values there would defeat its "expand for full record" purpose.
- **Dashboard YAML editor strips `spec.responseTemplates`.** Same caveat as `spec.visualization`. Author through `POST /api/v1/definitions/import` (JSON envelope) or the REST template endpoints.

---

## 14. Planned Features

The following instruction engine capabilities are on the roadmap but not yet implemented.

### Workflow Primitives (Phase 7.14)

Conditional logic, iteration, and retry within instruction execution:

- `if` / `else` -- branch execution based on result data from a previous step.
- `foreach` -- iterate over a list of values (e.g. services, files) and execute a definition for each.
- `retry` -- automatically retry a failed step with configurable backoff.

These will be expressed as additional YAML DSL constructs within an InstructionDefinition's `spec.workflow` block.

### Product Packs (Phase 7.9)

Signed distribution bundles containing instruction sets, definitions, policy fragments, and documentation. Product packs will use Ed25519 signatures with a trust chain anchored to an organization root key. Import will support staged review before activation.
