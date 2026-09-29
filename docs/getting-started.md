# Getting Started with Yuzu: Hello, Infrastructure World!

A hands-on tutorial for the Yuzu Instruction Engine.

**Prerequisites:** A running Yuzu server and at least one connected agent. You should be able to log in to the dashboard at `http://localhost:8080` and see your agent(s) on the Devices page. All `curl` commands below assume you have an active admin session cookie -- replace `$COOKIE` with your session token.

---

## Introduction

When you first connect an agent and dispatch a command through the dashboard, Yuzu sends a raw `CommandRequest` over gRPC: a plugin name, an action name, and optional parameters. This works, but it leaves important questions unanswered. Who is allowed to run this command? What parameters does it accept? What does the output look like? Can it be scheduled? Does it need approval before it runs?

The **Instruction Engine** answers all of these. It is a governed lifecycle layer that sits between the operator and the plugin execution layer, turning ad-hoc plugin-plus-action-plus-params commands into managed, auditable operations.

Instead of dispatching raw commands, operators define reusable **InstructionDefinitions** -- versioned templates that declare everything about an endpoint operation: what plugin and action to invoke, what typed parameters it accepts, what typed columns it returns, which platforms it supports, whether it needs approval, and how long its results are retained.

Here are the key concepts you will use in this tutorial:

- **InstructionDefinition** -- A reusable, versioned template for an endpoint operation. It declares the plugin, action, parameters, result schema, approval requirements, and retention policy in one place.

- **Question vs. Action** -- Definitions have a `type` field. A `question` is read-only: it gathers information without modifying endpoint state (list services, read OS info, check disk space). An `action` may modify state (restart a service, install a package, change a registry value). This distinction drives the approval workflow -- questions can auto-execute, while actions can require sign-off.

- **Parameters** -- Typed inputs with validation rules. Parameters are declared with a JSON Schema-style syntax (type, required fields, max length, allowed values) and validated before the command is dispatched to any agent.

- **Result Schema** -- Typed output columns (string, int32, int64, bool, datetime) that describe the structure of response data. Typed results enable server-side aggregation (COUNT, SUM, AVG grouped by column) and clean export to CSV, JSON, ClickHouse, or Splunk.

- **Scope Expressions** -- Target specific devices using a filter expression instead of listing agent IDs. The scope engine supports attribute comparisons (`ostype == "windows"`), tag lookups (`tag:env == "production"`), wildcards (`hostname LIKE "web-*"`), and boolean combinators (`AND`, `OR`, `NOT`).

- **Approval Modes** -- Control who can execute what. `auto` means the instruction runs immediately. `role-gated` means it enters a pending queue and waits for an admin to approve or reject it. `always` means every execution requires approval, regardless of who submits it.

- **InstructionSet** -- A permission boundary that groups related definitions together and declares which roles can author, execute, and approve the definitions it contains.

Let's build all of this up, one step at a time.

---

## Step 1: Hello, Infrastructure!

Start with the simplest possible instruction definition -- a read-only question that calls the `os_info` plugin's `os_name` action to return the operating system name from every targeted endpoint.

### Define it in YAML

Create a file called `hello-system-info.yaml`:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: hello.system.info
  displayName: Get System Info
  version: 1.0.0
  description: Returns basic OS information from all targeted endpoints.
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: os_info
    action: os_name
```

This YAML is the canonical authoring format. Post the file itself: the `yaml_source` form field carries the document verbatim, and the server derives the queryable columns (`metadata.id`, `spec.execution.plugin`, `spec.execution.action`, ...) from it — the YAML remains the definition's source of truth.

### Import it via the API

```bash
curl -s -X POST http://localhost:8080/api/instructions/yaml \
  -b "$COOKIE" \
  --data-urlencode "yaml_source@hello-system-info.yaml"
```

Expected response:

```html
<div class="alert alert-success">Definition created</div>
```

The server uses `metadata.id` (`hello.system.info`) as the definition's ID, takes its display name from `metadata.displayName`, and records an audit event: who created it, when, and from where.

> **Note:** there is also a JSON import endpoint, `POST /api/instructions/import`, meant for distributing definitions as signed envelopes (an Ed25519 `signature` + `publicKey` pair over the `yaml_source` bytes). On a default server, **unsigned** imports through that endpoint are rejected. Bypassing that with `--allow-unsigned-definitions` (or `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1`) is **dangerous** — unsigned instruction content is a fleet arbitrary-code-execution surface, the server emits a `server.unsigned_definitions_allowed` audit event at startup when it is set, and it should not be used outside isolated labs (see [Server Administration](user-manual/server-admin.md)). The endpoint used above is the authoring surface instead: it trusts your authenticated session's `InstructionDefinition:Write` permission, so it works on a default server with no signing bypass.
>
> Re-running the same import is safe: because the definition's ID comes from `metadata.id`, a second attempt returns **HTTP 409** with `Create failed: instruction definition 'hello.system.info' already exists` rather than creating a duplicate.

### Verify the definition exists

```bash
curl -s http://localhost:8080/api/instructions/hello.system.info \
  -b "$COOKIE" | python -m json.tool
```

Expected response (abbreviated):

```json
{
    "id": "hello.system.info",
    "name": "Get System Info",
    "version": "1.0.0",
    "type": "question",
    "plugin": "os_info",
    "action": "os_name",
    "description": "Returns basic OS information from all targeted endpoints.",
    "enabled": true,
    "instruction_set_id": "",
    "created_at": 1742300000,
    "updated_at": 1742300000
}
```

### Execute it

Now dispatch the command to all connected agents:

```bash
curl -s -X POST http://localhost:8080/api/command \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin": "os_info",
    "action": "os_name"
  }'
```

Expected response:

```json
{
    "command_id": "os_info-a1b2c3d4e5f6g7h8",
    "sent_to": 1,
    "status": "dispatched"
}
```

### View the results

```bash
curl -s "http://localhost:8080/api/responses/os_info-a1b2c3d4e5f6g7h8" \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "instruction_id": "os_info-a1b2c3d4e5f6g7h8",
    "count": 1,
    "responses": [
        {
            "id": 1,
            "instruction_id": "os_info-a1b2c3d4e5f6g7h8",
            "agent_id": "agent-001",
            "timestamp": 1742300005,
            "status": 1,
            "output": "os_name|Windows 11 Pro",
            "error_detail": ""
        }
    ]
}
```

### What happened under the hood

1. The server received your `POST /api/command` request and authenticated your session.
2. It constructed a gRPC `CommandRequest` with `plugin=os_info` and `action=os_name`.
3. The request was dispatched to all connected agents over the bidirectional gRPC stream.
4. Each agent's plugin host loaded the `os_info` plugin, invoked the `os_name` action, and streamed the result back as a `CommandResponse`.
5. The server's `ResponseStore` persisted each response in PostgreSQL with the command ID, agent ID, timestamp, status, and output.
6. An audit event was logged with your username, the action taken, and the number of agents targeted.

---

## Step 2: Adding Parameters

The first example had no inputs -- it ran the same action on every agent. Most real-world instructions need parameters. Let's create a definition that inspects a specific service by name.

### Define it in YAML

Create a file called `service-inspect.yaml`:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: tutorial.service.inspect
  displayName: Inspect Service Status
  version: 1.0.0
  description: Returns the current state of a named service.
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: services
    action: list
  parameters:
    type: object
    required: [serviceName]
    properties:
      serviceName:
        type: string
        displayName: Service Name
        description: The name of the service to inspect.
        validation:
          maxLength: 256
  readablePayload: "Inspect service '${serviceName}'"
```

Key additions:

- **`parameters`** declares a typed input schema. The `serviceName` field is required, must be a string, and is limited to 256 characters.
- **`readablePayload`** is a human-readable template that interpolates parameter values. When an operator views the execution log, they see "Inspect service 'sshd'" instead of a raw JSON blob.

### Import it

```bash
curl -s -X POST http://localhost:8080/api/instructions/yaml \
  -b "$COOKIE" \
  --data-urlencode "yaml_source@service-inspect.yaml"
```

Expected response:

```html
<div class="alert alert-success">Definition created</div>
```

### Execute with parameters

```bash
curl -s -X POST http://localhost:8080/api/command \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin": "services",
    "action": "list"
  }'
```

Expected response:

```json
{
    "command_id": "services-f1e2d3c4b5a6a7b8",
    "sent_to": 1,
    "status": "dispatched"
}
```

### View the results

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8" \
  -b "$COOKIE" | python -m json.tool
```

On a Windows agent, you will see pipe-delimited output with the service name, display name, status, and startup type:

```json
{
    "instruction_id": "services-f1e2d3c4b5a6a7b8",
    "count": 1,
    "responses": [
        {
            "id": 2,
            "instruction_id": "services-f1e2d3c4b5a6a7b8",
            "agent_id": "agent-001",
            "timestamp": 1742300100,
            "status": 1,
            "output": "svc|Spooler|Print Spooler|running|automatic\nsvc|sshd|OpenSSH SSH Server|running|automatic\nsvc|W32Time|Windows Time|stopped|manual",
            "error_detail": ""
        }
    ]
}
```

On Linux, the output format is `svc|name|status|description`.

---

## Step 3: Typed Results

Raw pipe-delimited output works for viewing, but it is opaque to the server. To enable aggregation, filtering, and structured export, add a **result schema** that tells the server what columns the output contains and what types they are.

### Extend the definition

Add a `result` section to the service inspect YAML:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: tutorial.service.inspect
  displayName: Inspect Service Status
  version: 1.0.0
  description: Returns the current state of a named service.
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: services
    action: list
  parameters:
    type: object
    required: [serviceName]
    properties:
      serviceName:
        type: string
        displayName: Service Name
        description: The name of the service to inspect.
        validation:
          maxLength: 256
  readablePayload: "Inspect service '${serviceName}'"
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
```

The `result.columns` block declares four typed columns. The `aggregation` block declares default aggregation settings: group by the `state` column and count occurrences.

### Use the aggregation endpoint

After executing the instruction and collecting responses, you can aggregate them server-side:

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/aggregate?group_by=status" \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "instruction_id": "services-f1e2d3c4b5a6a7b8",
    "groups": [
        {
            "group_value": "1",
            "count": 1,
            "aggregate_value": 0.0
        }
    ],
    "total_groups": 1,
    "total_rows": 1
}
```

The `group_by` parameter accepts `status` or `agent_id`. Additional aggregation operations (`sum`, `avg`, `min`, `max`) can be specified with the `op` query parameter, along with `op_column` to specify which column to aggregate.

### Export as CSV

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/export?format=csv" \
  -b "$COOKIE" -o service-results.csv
```

This downloads a CSV file with headers:

```
id,instruction_id,agent_id,timestamp,status,output,error_detail
```

### Export as JSON

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/export?format=json" \
  -b "$COOKIE" -o service-results.json
```

The JSON export returns a structured envelope:

```json
{
    "instruction_id": "services-f1e2d3c4b5a6a7b8",
    "count": 1,
    "responses": [
        {
            "id": 2,
            "instruction_id": "services-f1e2d3c4b5a6a7b8",
            "agent_id": "agent-001",
            "timestamp": 1742300100,
            "status": 1,
            "output": "svc|Spooler|Print Spooler|running|automatic\n...",
            "error_detail": ""
        }
    ]
}
```

Typed results are what make Yuzu's data useful beyond the dashboard. When every column has a declared type, downstream systems -- ClickHouse, Splunk, Grafana, or a simple spreadsheet -- can ingest the data without guessing.

---

## Step 4: Your First Action

So far, every instruction has been a `question` -- read-only, safe to run at any time. Now let's define an `action` that modifies endpoint state: restarting a service.

Because actions change things, they should go through an approval workflow. We will set the approval mode to `role-gated`, which means the instruction enters a pending queue when submitted, and an admin must approve it before it executes.

### Define it in YAML

Create a file called `service-restart.yaml`:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: tutorial.service.restart
  displayName: Restart Service
  version: 1.0.0
  description: Restarts a named service. Requires approval.
spec:
  type: action
  platforms: [windows, linux, darwin]
  execution:
    plugin: services
    action: restart
  parameters:
    type: object
    required: [serviceName]
    properties:
      serviceName:
        type: string
  approval:
    mode: role-gated
  readablePayload: "Restart service '${serviceName}'"
```

Key differences from a question:

- **`type: action`** -- marks this as a state-changing operation.
- **`approval.mode: role-gated`** -- requires an admin to approve before execution proceeds.

### Import it

```bash
curl -s -X POST http://localhost:8080/api/instructions/yaml \
  -b "$COOKIE" \
  --data-urlencode "yaml_source@service-restart.yaml"
```

Expected response:

```html
<div class="alert alert-success">Definition created</div>
```

### Walk through the approval flow

> **You need two accounts for this section.** A reviewer cannot approve or
> reject their own submission — the server rejects self-review with HTTP 400
> (`"reviewer cannot be the same as the submitter"`), and the dashboard shows
> "You submitted this — another reviewer must approve" instead of buttons on
> your own requests. If you have been following along as a single admin,
> create a second operator account now and use it for the approve/reject
> steps below.

**1. Submit the action.**

An operator submits the instruction for execution. Because the approval mode is `role-gated`, it does not execute immediately -- it enters the pending queue. (`role-gated` queues *non-admin* submitters for approval; admins execute directly. To watch the queue while testing as an admin, use a definition with `approval.mode: always` instead.)

**2. Check pending approvals.**

An admin checks how many approvals are waiting:

```bash
curl -s http://localhost:8080/api/approvals/pending/count \
  -b "$COOKIE"
```

Expected response:

```json
{"count":1}
```

**3. List pending approvals.**

```bash
curl -s "http://localhost:8080/api/approvals?status=pending" \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "approvals": [
        {
            "id": "d4e5f6a7-...",
            "definition_id": "tutorial.service.restart",
            "status": "pending",
            "submitted_by": "operator1",
            "submitted_at": 1742300200,
            "reviewed_by": "",
            "reviewed_at": 0,
            "review_comment": "",
            "scope_expression": ""
        }
    ]
}
```

**4. Approve it.**

```bash
curl -s -X POST http://localhost:8080/api/approvals/d4e5f6a7-.../approve \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"comment": "Approved for maintenance window"}'
```

Expected response:

```json
{"status":"approved"}
```

Once approved, the instruction is dispatched to the targeted agents. The approval record is preserved in the audit trail -- who submitted it, who approved it, when, and with what comment.

**5. Reject (alternative).**

If the action should not proceed, reject it instead:

```bash
curl -s -X POST http://localhost:8080/api/approvals/d4e5f6a7-.../reject \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"comment": "Not approved -- outside maintenance window"}'
```

Expected response:

```json
{"status":"rejected"}
```

The full lifecycle is: **submit -> pending -> approve/reject -> execute (if approved)**. Every step is audited.

---

## Step 5: Organizing with InstructionSets

As your library of definitions grows, you need a way to group related instructions and control who can use them. That is what **InstructionSets** are for.

An InstructionSet is the permission boundary for instruction definitions. It declares which roles can author definitions in the set, which roles can execute them, and which roles can approve actions.

### Define it in YAML

Create a file called `service-management-set.yaml`:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionSet
metadata:
  id: tutorial.service-management
  displayName: Service Management Tutorial
  version: 1.0.0
  description: Tutorial set for service inspection and management.
  permissions:
    executeRoles: [endpoint-operator, endpoint-admin]
    authorRoles: [content-author]
    approveRoles: [endpoint-admin]
  contents:
    instructionDefinitions:
      - tutorial.service.inspect
      - tutorial.service.restart
```

The `permissions` block is the key governance feature:

- **`executeRoles`** -- who can dispatch instructions from this set.
- **`authorRoles`** -- who can create or modify definitions in this set.
- **`approveRoles`** -- who can approve actions that require approval.

### Create the set via the API

```bash
curl -s -X POST http://localhost:8080/api/instruction-sets \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tutorial.service-management",
    "description": "Tutorial set for service inspection and management."
  }'
```

Expected response:

```json
{"id":"e5f6a7b8-..."}
```

### List all sets

```bash
curl -s http://localhost:8080/api/instruction-sets \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "sets": [
        {
            "id": "e5f6a7b8-...",
            "name": "tutorial.service-management",
            "description": "Tutorial set for service inspection and management.",
            "created_by": "admin",
            "created_at": 1742300300
        }
    ]
}
```

### Assign definitions to the set

When creating or updating an instruction definition, set the `instruction_set_id` field to the set's ID. This binds the definition to the set's permission rules.

```bash
curl -s -X PUT http://localhost:8080/api/instructions/tutorial.service.inspect \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tutorial.service.inspect",
    "type": "question",
    "plugin": "services",
    "action": "list",
    "description": "Returns the current state of a named service.",
    "instruction_set_id": "e5f6a7b8-..."
  }'
```

Once the granular RBAC system is fully implemented (Phase 3 on the roadmap), these permission declarations will be enforced server-side. For now, the structure is in place so that your definitions are organized and ready for access control from day one.

---

## Step 6: Targeting with Scope Expressions

So far, every command has been broadcast to all connected agents. In production, you need to target specific devices -- all Windows machines, all web servers in production, everything except quarantined endpoints.

Yuzu's **scope engine** provides a filter expression language for this. It is a recursive-descent parser that supports attribute comparisons, tag lookups, wildcards, and boolean combinators.

### Scope expression examples

Target all Windows endpoints:

```
ostype == "windows"
```

Target Linux web servers:

```
ostype == "linux" AND hostname LIKE "web-*"
```

Target production endpoints that are not quarantined:

```
tag:env == "production" AND NOT tag:quarantined == "true"
```

### Validate a scope expression

Before using a scope expression in a command, you can validate its syntax:

```bash
curl -s -X POST http://localhost:8080/api/scope/validate \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"expression": "ostype == \"windows\""}'
```

Expected response for a valid expression:

```json
{"valid":true}
```

Expected response for an invalid expression:

```json
{"valid":false,"error":"expected comparison operator at position 8"}
```

### Estimate how many agents match

Before dispatching to a large fleet, check how many agents the scope expression matches:

```bash
curl -s -X POST http://localhost:8080/api/scope/estimate \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"expression": "ostype == \"windows\""}'
```

Expected response:

```json
{"matched":1,"total":3}
```

This tells you that 1 out of 3 connected agents match the expression. No command is dispatched -- this is a dry run.

### Dispatch with a scope expression

Use the `scope` field in the command request to target specific agents:

```bash
curl -s -X POST http://localhost:8080/api/command \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin": "os_info",
    "action": "os_name",
    "scope": "ostype == \"windows\""
  }'
```

Expected response:

```json
{
    "command_id": "os_info-c4d5e6f7g8h9i0j1",
    "sent_to": 1,
    "status": "dispatched"
}
```

Only agents matching the scope expression receive the command. The server evaluates the expression against each agent's attributes (OS type, hostname, architecture) and tags.

### Supported operators

| Operator | Example | Description |
|---|---|---|
| `==` | `ostype == "windows"` | Exact equality (case-insensitive) |
| `!=` | `ostype != "linux"` | Not equal |
| `LIKE` | `hostname LIKE "web-*"` | Wildcard match (`*` = any chars) |
| `<`, `>`, `<=`, `>=` | `os_version > "10"` | Numeric or string comparison |
| `IN` | `ostype IN ("windows", "linux")` | Value in set |
| `CONTAINS` | `hostname CONTAINS "prod"` | Substring match |
| `AND` | `a == "1" AND b == "2"` | Both must be true |
| `OR` | `a == "1" OR b == "2"` | Either must be true |
| `NOT` | `NOT tag:quarantined == "true"` | Negation |

---

## Step 7: Scheduling Recurring Checks

Running instructions manually is fine for one-off tasks, but many operations need to run on a schedule -- service health checks every 15 minutes, disk space audits every hour, compliance scans every night.

Yuzu's **ScheduleEngine** supports recurring execution with configurable frequency types.

### Create a schedule via the API

Schedule the service inspect instruction to run every 15 minutes:

```bash
curl -s -X POST http://localhost:8080/api/schedules \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Service health check (every 15m)",
    "definition_id": "tutorial.service.inspect",
    "frequency_type": "interval",
    "interval_minutes": 15,
    "scope_expression": "ostype == \"windows\"",
    "requires_approval": false
  }'
```

Expected response:

```json
{"id":"f6a7b8c9-..."}
```

### List all schedules

```bash
curl -s http://localhost:8080/api/schedules \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "schedules": [
        {
            "id": "f6a7b8c9-...",
            "name": "Service health check (every 15m)",
            "definition_id": "tutorial.service.inspect",
            "enabled": true,
            "frequency_type": "interval",
            "next_execution_at": 1742301200,
            "last_executed_at": 0,
            "execution_count": 0
        }
    ]
}
```

### Disable a schedule

```bash
curl -s -X POST http://localhost:8080/api/schedules/f6a7b8c9-.../enable \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"enabled": "false"}'
```

Expected response:

```json
{"enabled":false}
```

### Re-enable a schedule

```bash
curl -s -X POST http://localhost:8080/api/schedules/f6a7b8c9-.../enable \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"enabled": "true"}'
```

### Delete a schedule

```bash
curl -s -X DELETE http://localhost:8080/api/schedules/f6a7b8c9-... \
  -b "$COOKIE"
```

Expected response:

```json
{"deleted":true}
```

### Schedule parameters

| Field | Type | Description |
|---|---|---|
| `name` | string | Human-readable name for the schedule |
| `definition_id` | string | ID of the instruction definition to execute |
| `frequency_type` | string | `"once"`, `"interval"`, `"daily"`, `"weekly"`, `"monthly"` |
| `interval_minutes` | int | Minutes between executions (for `interval` type) |
| `time_of_day` | string | `"HH:MM"` time for daily/weekly/monthly schedules |
| `day_of_week` | int | 0-6 (Sunday=0) for weekly schedules |
| `day_of_month` | int | 1-31 for monthly schedules |
| `scope_expression` | string | Scope expression to target agents |
| `requires_approval` | bool | Whether each scheduled run needs approval |

---

## Step 8: Exporting Results

Yuzu stores every response in its PostgreSQL-backed ResponseStore. You can query, aggregate, and export this data through the REST API.

### Query responses for an instruction

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8" \
  -b "$COOKIE" | python -m json.tool
```

Optional query parameters for filtering:

| Parameter | Description |
|---|---|
| `agent_id` | Filter by specific agent |
| `status` | Filter by response status (integer) |
| `since` | Epoch seconds -- only responses after this time |
| `until` | Epoch seconds -- only responses before this time |
| `limit` | Maximum number of results (default: 100) |
| `offset` | Pagination offset |

Example with filters:

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8?status=1&limit=50&since=1742300000" \
  -b "$COOKIE" | python -m json.tool
```

### Export as CSV

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/export?format=csv" \
  -b "$COOKIE" -o responses.csv
```

The CSV file contains one row per agent response with headers:

```
id,instruction_id,agent_id,timestamp,status,output,error_detail
1,services-f1e2d3c4b5a6a7b8,agent-001,1742300100,1,"svc|Spooler|Print Spooler|running|automatic",""
```

### Export as JSON

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/export?format=json" \
  -b "$COOKIE" -o responses.json
```

### Aggregate responses

Group responses by status and count:

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/aggregate?group_by=status" \
  -b "$COOKIE" | python -m json.tool
```

Expected response:

```json
{
    "instruction_id": "services-f1e2d3c4b5a6a7b8",
    "groups": [
        {"group_value": "1", "count": 3, "aggregate_value": 0.0},
        {"group_value": "2", "count": 1, "aggregate_value": 0.0}
    ],
    "total_groups": 2,
    "total_rows": 4
}
```

Group by agent and compute aggregates:

```bash
curl -s "http://localhost:8080/api/responses/services-f1e2d3c4b5a6a7b8/aggregate?group_by=agent_id&op=count" \
  -b "$COOKIE" | python -m json.tool
```

Supported aggregation operations: `count`, `sum`, `avg`, `min`, `max`. Specify the target column with `op_column` when using `sum`, `avg`, `min`, or `max`.

### Execution tracking

For a higher-level view, query the execution tracker:

```bash
curl -s http://localhost:8080/api/executions?definition_id=tutorial.service.inspect \
  -b "$COOKIE" | python -m json.tool
```

Get a summary with progress percentage:

```bash
curl -s http://localhost:8080/api/executions/EXECUTION_ID/summary \
  -b "$COOKIE" | python -m json.tool
```

View per-agent status:

```bash
curl -s http://localhost:8080/api/executions/EXECUTION_ID/agents \
  -b "$COOKIE" | python -m json.tool
```

Rerun an execution (optionally targeting only failed agents):

```bash
curl -s -X POST http://localhost:8080/api/executions/EXECUTION_ID/rerun \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"scope": "failed_only"}'
```

---

## What's Next

This tutorial covered the core instruction lifecycle: define, import, execute, parameterize, type results, govern with approvals, organize into sets, target with scopes, schedule, and export. Here is where to go from here:

- **Instruction Engine architecture** -- `docs/Instruction-Engine.md` covers the full design, including the content model hierarchy (ProductPack > InstructionSet > InstructionDefinition), the execution substrate, error taxonomy, and concurrency model.

- **Capability map** -- `docs/capability-map.md` tracks all 139 planned capabilities and which ones are implemented. Use this to understand the full scope of what Yuzu is building toward.

- **Roadmap** -- `docs/roadmap.md` has the 126 issues across 17 tracked phases (0–16). The features introduced in this tutorial span Phases 1-3.

- **PolicyFragments and compliance automation (Phase 5)** -- PolicyFragments compose a check instruction, a compliance expression, and a fix instruction into a single unit. Policies bind fragments to triggers and scopes for continuous compliance enforcement.

- **TriggerTemplates for event-driven automation (Phase 4)** -- Instead of schedules, fire instructions in response to events: file changes, service status transitions, event log entries, registry modifications, or agent startup.

- **ProductPacks for content distribution (Phase 7)** -- Bundle InstructionSets, PolicyFragments, and static content into signed, versioned packages that can be distributed to servers and automatically applied.

- **Grafana dashboards** -- `docs/grafana/` contains dashboard templates for visualizing Yuzu metrics. The server exposes a Prometheus-compatible `/metrics` endpoint with `yuzu_server_*` metrics.

- **Analytics integration** -- `docs/clickhouse-setup.md` and `docs/analytics-events.md` cover how to forward Yuzu's structured events and response data to ClickHouse or Splunk for long-term analytics.
