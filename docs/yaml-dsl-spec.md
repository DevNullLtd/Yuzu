# Yuzu YAML DSL Specification

**Version:** v1alpha1
**API Version:** `yuzu.io/v1alpha1`
**Status:** Normative specification
**Audience:** Content authors, integrators, plugin developers
**Basis:** `docs/Instruction-Engine.md` design document

---

## Table of Contents

1. [Overview](#1-overview)
2. [Document Structure](#2-document-structure)
3. [Kind: InstructionDefinition](#3-kind-instructiondefinition)
4. [Kind: InstructionSet](#4-kind-instructionset)
5. [Kind: PolicyFragment (Phase 5)](#5-kind-policyfragment-phase-5)
6. [Kind: Policy (Phase 5)](#6-kind-policy-phase-5)
7. [Kind: TriggerTemplate (Phase 4)](#7-kind-triggertemplate-phase-4)
8. [Kind: ProductPack (Phase 7)](#8-kind-productpack-phase-7)
9. [Expression Language](#9-expression-language)
10. [Parameter Type System](#10-parameter-type-system)
11. [Result Column Type System](#11-result-column-type-system)
12. [Concurrency Model](#12-concurrency-model)
13. [Error Code Taxonomy](#13-error-code-taxonomy)
14. [Substrate Primitive Reference](#14-substrate-primitive-reference)

---

## 1. Overview

Yuzu's YAML DSL defines the content model for the instruction engine. All instruction content -- definitions, grouping, policy, triggers, and distribution bundles -- is authored as YAML documents conforming to this specification.

Every document begins with `apiVersion: yuzu.io/v1alpha1` and a `kind` field that determines its schema. The six kinds form a compositional hierarchy:

```
ProductPack
 +-- InstructionSet[]
      +-- InstructionDefinition[]
           |-- Parameter Schema
           |-- Result Schema
           +-- Execution Spec (plugin + action + defaults)

PolicyFragment
 |-- Check: ref -> InstructionDefinition
 |-- Compliance expression
 |-- Fix: ref -> InstructionDefinition
 +-- PostCheck: ref -> InstructionDefinition

Policy
 |-- Scope (device targeting)
 |-- Fragment ref + parameter bindings
 |-- Trigger refs
 +-- Rollout strategy

TriggerTemplate
 |-- Source type (interval, file, service, event_log, registry, startup)
 |-- Parameter schema
 +-- Debounce config
```

A definition can exist standalone (without a set or pack). Sets are the permission boundary. Packs are the distribution boundary.

---

## 2. Document Structure

Every YAML document MUST contain the following top-level fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `apiVersion` | string | Yes | Must be `yuzu.io/v1alpha1`. |
| `kind` | string | Yes | One of: `InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`. |
| `metadata` | object | Yes | Identity and descriptive fields. Structure varies by kind. |
| `spec` | object | Yes (except InstructionSet) | Kind-specific specification. InstructionSet uses top-level fields instead. |
| `status` | object | No | Runtime status. Set by the server, not by authors. |

---

## 3. Kind: InstructionDefinition

The core unit of the content model. Every ad-hoc command, scheduled task, policy check, and remediation action is an InstructionDefinition.

### 3.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `<scope>.<domain>.<action>` (e.g., `crossplatform.service.inspect`). The `mcp.` prefix is **reserved** and cannot be authored (#2442) — it names MCP approval tickets, whose recall matches on the definition id. |
| `displayName` | string | Yes | -- | Human-readable name shown in the dashboard. |
| `version` | string | Yes | -- | Semantic version (e.g., `1.2.0`). Used for compatibility checks and pack versioning. |
| `description` | string | No | `""` | Detailed description of what this definition does. |
| `tags` | list of string | No | `[]` | Freeform tags for categorization and search. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | `question` (read-only, does not modify state) or `action` (may modify state). Determines approval defaults and UI treatment. |
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `execution` | object | Yes | -- | Execution configuration. See below. |
| `parameters` | object | No | `{}` | JSON Schema subset defining input parameters. See below. |
| `result` | object | No | `{}` | Result schema defining output columns and aggregation. See below. |
| `readablePayload` | string | No | `""` | Human-readable template string for audit display. Supports `${paramName}` interpolation. |
| `gather` | object | No | -- | Gather window configuration. |
| `response` | object | No | -- | Response storage configuration. |
| `approval` | object | No | -- | Approval workflow configuration. |
| `permissions` | object | No | -- | Role-based access control. |
| `compatibility` | object | No | -- | Agent version and plugin requirements. |
| `legacy_shim` | object | No | -- | Auto-generation from plugin descriptors. |
| `visualization` | object | No | -- | Chart configuration for the dashboard's response view. See below. Use `visualizations` (plural) to declare more than one chart. |
| `visualizations` | list of object | No | -- | One or more chart configurations; the canonical multi-chart form. See below. |

#### `spec.execution`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugin` | string | Yes | -- | Plugin identifier (must match a registered plugin's `name` field). |
| `action` | string | Yes | -- | Action name (must exist in the plugin's `actions[]` array). Case-insensitive; normalized to lowercase at creation time and at dispatch. |
| `concurrency` | string | No | `per-device` | Concurrency mode. **Only `per-device` is actually enforced** (server-side); `per-definition`/`per-set`/`global:<N>`/`unlimited` are accepted but unenforced. Not validated — any string is accepted. See [Section 12](#12-concurrency-model). |
| `stagger` | object | No | -- | Stagger configuration for large-fleet dispatch. |
| `minSuccessPercent` | integer | No | `100` | Minimum percentage of agents that must succeed. `0` = best-effort, `100` = all must succeed. |

#### `spec.execution.stagger`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `maxDelaySeconds` | integer | No | `0` | Maximum random delay before execution on each agent. `0` = no stagger (all agents execute immediately). |
| `fixedDelaySeconds` | integer | No | `0` | Fixed delay before execution on each agent, added before the random stagger. `0` = no fixed delay. Total wait = `fixedDelaySeconds` + random(`0`, `maxDelaySeconds`). |

#### `spec.parameters`

A JSON Schema subset. The root object describes the parameter shape.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `required` | list of string | No | `[]` | List of parameter names that must be provided. |
| `properties` | map of string to object | Yes | -- | Parameter definitions. Each key is a parameter name; value is a parameter descriptor. |

Each parameter descriptor supports:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Parameter type. Values: `string`, `boolean`, `int32`, `int64`, `datetime`, `guid`. See [Section 10](#10-parameter-type-system). |
| `displayName` | string | No | -- | Human-readable label for the dashboard form. |
| `description` | string | No | `""` | Parameter description. |
| `default` | varies | No | -- | Default value if not provided. Must match the declared type. The server does not inject it into the dispatched parameters; it only satisfies `required` during `POST /api/instructions/{id}/execute` validation. |
| `validation` | object | No | -- | Validation constraints. See below. Also summarised into the plugin README's Inputs table (Constraints column, e.g. `enum: a, b · minLength 1`) and carried verbatim in the `content/plugin-docs` manifest (`inputs[].constraints`). |

#### `spec.parameters.properties.<name>.validation`

| Field | Type | Applicable Types | Description |
|---|---|---|---|
| `maxLength` | integer | `string` | Maximum string length in bytes (UTF-8). |
| `minLength` | integer | `string` | Minimum string length in bytes (UTF-8). |
| `pattern` | string | `string` | Regular expression the value must match. |
| `enum` | list | `string` | Allowed values. The value must be one of the listed strings. |
| `minimum` | number | `int32`, `int64` | Minimum numeric value (inclusive). |
| `maximum` | number | `int32`, `int64` | Maximum numeric value (inclusive). |

#### `spec.result`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `columns` | list of object | Yes | -- | Result column definitions. |
| `aggregation` | object | No | -- | Server-side aggregation configuration. |

Each column object:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | -- | Column identifier. |
| `type` | string | Yes | -- | Column type. Values: `bool`, `int32`, `int64`, `string`, `datetime`, `guid`, `clob`. See [Section 11](#11-result-column-type-system). |
| `description` | string | No | -- | Documentation only: what the column carries. Rendered into the plugin README's Outputs table and the `content/plugin-docs` manifest by `tools/plugin-doc-gen` (`docs/plugin-readme-standard.md` rule 8). Every server consumer of `result.columns` (`result_envelope.cpp`, `response_templates_engine.cpp`) reads only `name` and `type`; the extra keys pass through the embedded `result_schema` untouched. |
| `values` | list of string | No | -- | Documentation only: the closed vocabulary the column may carry (e.g. `[ok, warning, failing, unknown, unsupported]`). Meaningful only on a `string` column. Not enforced at runtime; `tools/plugin-doc-gen` validates the shape of these four keys (a list where a list is meant, `platforms` drawn from the vocabulary below) and fails its `--check` otherwise. |
| `example` | string | No | -- | Documentation only: one representative value. |
| `platforms` | list of string | No | -- | Documentation only: the platforms on which the column carries a real value, from `windows`, `linux`, `darwin`. Omitted means every platform the definition lists. |

#### `spec.result.aggregation`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `groupBy` | list of string | No | `[]` | Column names to group by when aggregating across agents. |
| `operations` | list of string | No | `[]` | Aggregation operations. Values: `count`, `sum`, `avg`, `min`, `max`. |

#### `spec.gather`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ttlSeconds` | integer | No | `300` | Maximum time (in seconds) the agent has to respond. After this window, the execution is marked as timed out. |

#### `spec.response`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `retentionDays` | integer | No | `90` | Number of days to retain response data in the ResponseStore before TTL cleanup. |

#### `spec.approval`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `auto` | Approval mode. `auto` -- no approval required. `role-gated` -- requires approval from a user with an approved role. `always` -- every execution requires explicit approval. Enforced on the governed `POST /api/instructions/:id/execute` path directly, and on every raw-dispatch surface (`POST /api/command`, MCP `execute_instruction`, and any future dispatch caller) via a compiled, per-`plugin.action` `ExecuteGate` derived strictest-wins from every shipped definition targeting that pair (#1398) -- see `docs/mcp-server.md` and `command_capability.hpp`. |

#### `spec.permissions`

**Advisory content metadata, not enforced by the server.** Neither field has a
server-side representation: `executeRoles`' labels (`endpoint-admin`,
`security-admin`, ...) are a content-authoring convention that matches no
seeded RBAC role (`Administrator`/`PlatformEngineer`/`Operator`/
`ApiTokenManager`/`ITServiceOwner`/`Viewer`/`Reviewer`), and `embed_content.py`
drops the entire `permissions` block at build time -- it never reaches the
running server. Actual execute-time enforcement is `spec.approval.mode` (see
above); actual author-time enforcement is the `InstructionDefinition:Write`
RBAC permission on the create/update route, unrelated to `authorRoles`. Both
fields may still be authored for human-readable documentation of intent, but
neither controls anything at runtime.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `executeRoles` | list of string | No | `[]` | **Advisory only (unenforced) -- see note above.** Documents which roles a content author intends to permit; actual enforcement is `spec.approval.mode`. |
| `authorRoles` | list of string | No | `[]` | **Advisory only (unenforced) -- see note above.** Documents which roles a content author intends to permit to create or modify this definition; actual enforcement is the `InstructionDefinition:Write` RBAC permission. |

#### `spec.compatibility`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minAgentVersion` | string | No | -- | Minimum agent version required to execute this definition. Agents below this version are skipped during dispatch (error `4003`). |
| `requiredPlugins` | list of string | No | `[]` | Plugins that must be loaded on the agent. If any required plugin is missing, the agent is skipped (error `4001`). |

#### `spec.legacy_shim`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `enabled` | boolean | No | `false` | When `true`, this definition was auto-generated from a plugin descriptor. The generated YAML source declares `additionalProperties: {type: string}` (open schema), but the stored `parameter_schema` is `{}`, so these definitions are not validated by `POST /api/instructions/{id}/execute`. |

#### `spec.visualization`

Optional chart configuration consumed by the dashboard's instruction-response views and the `GET /api/v1/executions/{id}/visualization` REST endpoint (issue #253). When omitted, the response view shows the standard tabular layout only — no chart card is rendered.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Chart type. Values: `pie`, `bar`, `column`, `line`, `area`. |
| `processor` | string | Yes | -- | Server-side data transformer. Values: `single_series` (group + count/sum into one series), `multi_series` (group by both label and series fields, producing one series per distinct series value), `datetime_series` (timestamped points, one series per agent or per `seriesField`). |
| `title` | string | No | `""` | Display title rendered above the chart. Static text — parameter interpolation (`${paramName}`) is **not** supported in this revision. |
| `labelField` | integer | Conditional | `0` | 0-based column index used to bucket rows. The index counts the **result columns** declared under `spec.result.columns` (or the implicit columns for built-in plugins like `procfetch` — `PID, Name, Path, SHA-1`). The `Agent` column is **not** counted. Required for `single_series` and `multi_series`. |
| `valueField` | integer | No | `null` | Numeric column to sum into each bucket. When omitted, the processor counts rows. Non-numeric cell values (e.g. `"n/a"`) count as 1, not 0 — this preserves count-mode semantics on mixed columns; spec authors who want strict numeric summation should pre-validate the result schema. |
| `valueLabel` | string | No | `"Count"` | Series name shown in the legend for `single_series`. |
| `seriesField` | integer | Conditional | -- | Column index splitting rows into distinct series for `multi_series` (defaults to `1` if unset) and `datetime_series` (defaults to per-agent series when unset). |
| `xField` | integer or string | No | `"agent_timestamp"` | For `datetime_series`: either a numeric column index or the literal `"agent_timestamp"` to use the response's wall-clock timestamp. |
| `yField` | integer | No | `null` | Numeric column for `datetime_series`; rows count as `1` when omitted. |
| `maxCategories` | integer | No | `0` | When > 0, retain only the top-N buckets by total and collapse the tail into an `Other` bucket. Applies to `single_series`. |
| `whereField` | integer | No | `-1` | 0-based column index for an optional row pre-filter. Rows where the column at this index does not equal `whereEquals` are skipped before bucketing. Use to chart one logical category from a plugin that emits a mixed `key\|value` row layout (e.g. firewall, bitlocker, antivirus). `-1` (or omitted) disables the filter. Applies to `single_series` and `multi_series`. If `whereField` is set without `whereEquals` (or vice versa), the filter is treated as disabled — half-config is rejected silently rather than half-applied. |
| `whereEquals` | string | No | `""` | Required field value when `whereField` is active. Case-sensitive exact match against the field contents — no glob, no regex. |

> **Field naming.** This block uses camelCase, matching the rest of `apiVersion: yuzu.io/v1alpha1`. The engine also accepts the legacy snake_case names (`label_field`, `value_field`, …) as deprecated aliases — they will be removed in a future API version. Author new specs against the camelCase names.

> **Multi-chart definitions.** A definition can declare more than one chart by using the canonical plural form `spec.visualizations: [<vis>, ...]`. The singular `spec.visualization: <vis>` is accepted as syntactic sugar for a single-element list and is normalised at ingest. The dashboard renders all charts as a deck (`<div class="yuzu-chart-deck">`); the REST endpoint takes an optional `?index=N` query parameter (default 0) to address individual charts and includes `chart_index` and `chart_count` in every response payload so callers can iterate.

> **Limitations.** The engine caps each chart at 10 000 underlying response rows; when truncated, the response payload includes `rows_capped: true` so the dashboard can show a banner. The engine also caps total distinct labels at 10 000 (defense-in-depth against a misbehaving plugin emitting unbounded label cardinality).

> **Authoring through the dashboard YAML editor strips visualization.** When saving a definition via the dashboard's CodeMirror editor (`POST /api/instructions/yaml`), the schema-aware extractor (`instruction_yaml::parse_definition_yaml`) indexes `id`, `name`, `plugin`, `action`, `type`, `description`, `concurrency`, `approval` from the YAML source (canonical nested or flat schema) but does NOT extract `spec.visualization` into the indexed `visualization_spec` column. The chart spec is preserved in `yaml_source` (verbatim source of truth) but not indexed, so the chart deck does not render the chart until the definition is re-imported via `POST /api/v1/definitions/import` (JSON envelope, full visualization extraction) or until the next server restart triggers the bundled-content auto-import. Author chart-bearing definitions through the JSON import path or the in-tree `content/definitions/` library, not the editor save. Tracked as a known gap pending yaml-cpp Windows MSVC resolution (#625).

The engine returns a self-contained payload the dashboard's renderer (`/static/yuzu-charts.js`) can draw without a second request:

```json
{
  "data": {
    "chart_type": "pie",
    "title": "Service States",
    "labels": ["running", "stopped", "paused"],
    "series": [{"name": "Count", "data": [42, 7, 1]}],
    "meta": {"responses_total": 50, "responses_succeeded": 50, "responses_failed": 0}
  },
  "meta": {"api_version": "v1"}
}
```

For `datetime_series` the shape replaces `labels` with `x` (epoch-seconds array) and adds `"x_axis": "datetime"`.

Example — count distinct process names across the fleet (plugin `procfetch` emits `PID|Name|Path|SHA-1`; `labelField: 1` selects the `Name` column):

```yaml
spec:
  visualization:
    type: pie
    processor: single_series
    title: Top processes
    labelField: 1
    maxCategories: 8
```

Example — events-over-time per agent (default `xField` uses the response's wall-clock timestamp; one data point per response):

```yaml
spec:
  visualization:
    type: line
    processor: datetime_series
    title: Events per second
```

Example — multiple charts on one definition (issue #587). The dashboard renders both side by side:

```yaml
spec:
  visualizations:
    - type: pie
      processor: single_series
      title: Top processes
      labelField: 1
      maxCategories: 8
    - type: line
      processor: datetime_series
      title: Process count over time
```

#### `spec.responseTemplates`

Optional list of named response-view configurations consumed by the dashboard's filter bar dropdown and the `GET/POST/PUT/DELETE /api/v1/definitions/{id}/response-templates` REST endpoints (issue #254, Phase 8.2). When omitted, the engine synthesises a single `__default__` template from `spec.result.columns` (preferred) or the plugin's column schema, so every definition has at least one selectable view without authoring.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | No | auto | Stable 32-hex id. Auto-generated on POST when omitted. The reserved id `__default__` is rejected — operators cannot author or overwrite the synthesised default. |
| `name` | string | Yes | -- | Operator-facing label shown in the dropdown. Max 200 characters. |
| `description` | string | No | `""` | Optional longer description. Reserved for future tooltip rendering. |
| `columns` | array of strings | No | `[]` | Subset of plugin column names to render. Empty / omitted means "show all". The `Agent` pseudo-column is always shown regardless of this list. |
| `sort` | object | No | -- | `{column: <name>, dir: asc\|desc}`. Defines the initial sort applied when the operator picks the template. The dashboard's column-header click still wins. |
| `filters` | array of objects | No | `[]` | List of `{column, op, value}` clauses. `op` ∈ `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`. The dashboard auto-applies `equals`-op clauses to the URL filter map; other ops are honoured by REST consumers but not auto-applied client-side in this revision. |
| `default` | boolean | No | `false` | When `true` this template replaces the synthesised `__default__` in the dropdown. At most one operator-authored template may be marked `default` per definition. |

Example — a "Failures only" view for a vulnerability scan definition:

```yaml
spec:
  responseTemplates:
    - name: Failures only
      columns: [Severity, Title, Detail]
      sort: {column: Severity, dir: desc}
      filters:
        - {column: Severity, op: equals, value: high}
    - name: Critical view
      default: true
      columns: [Severity, Category, Title]
      filters:
        - {column: Severity, op: equals, value: critical}
```

> **Authoring through the dashboard YAML editor strips response templates.** Same caveat as `spec.visualization` — the extractor used by `POST /api/instructions/yaml` does not index `spec.responseTemplates` into the indexed column. Use `POST /api/v1/definitions/import` (JSON envelope) or the in-tree `content/definitions/` library, or call `POST /api/v1/definitions/{id}/response-templates` directly to author templates against an already-imported definition.

#### `spec.offload`

Optional per-instruction override for the response-offload control plane (issue #255, Phase 8.3). Targets are global config registered through `POST /api/v1/offload-targets` with their own URL, auth (none / bearer / basic / hmac), event filter, and batch size. By default every enabled target whose `event_types` filter matches the fired event receives a copy of the payload. `spec.offload.targets` restricts that fan-out to a named subset for a specific definition.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `targets` | array of strings | No | `[]` | Names of registered offload targets to receive responses for this definition. Empty / omitted means "fan out to every enabled target whose `event_types` matches" (the default behaviour). When set, only targets whose `name` appears here AND whose `event_types` matches receive the event. |

Example — an inventory-collection definition that only ships its responses to the `siem-archive` target (other webhooks/offload targets do not receive these events):

```yaml
spec:
  offload:
    targets: [siem-archive]
```

> **`spec.offload.targets` is not extracted by the dashboard YAML editor or the JSON import endpoint.** The field is preserved verbatim in the `yaml_source` source-of-truth column on `instruction_definitions` but is **not** denormalised into an indexed column and is **not** consulted by the dispatcher in this revision. Authoring this field has no current effect on fan-out behaviour. See the runtime caveat below.

> **Runtime correlation is opt-in.** The `agent.registered` and `execution.completed` events fan out globally to every enabled offload target whose `event_types` filter matches, regardless of `spec.offload.targets`. The store's `OffloadTargetStore::fire_event` accepts an optional `target_filter` argument that callers can use to restrict fan-out to a named subset, but the agent-service dispatch path does not currently extract the filter from the originating definition. Wiring the dispatcher to walk `command_id → execution_id → definition_id → InstructionStore::get_definition` and read `spec.offload.targets` is tracked as a follow-up.

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. Set by the server. |

### 3.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: crossplatform.service.inspect
  displayName: Inspect Service Status
  version: 1.2.0
  description: Returns the current state, startup type, and PID of a named service.
  tags:
    - services
    - operations
spec:
  type: question                         # question (read-only) | action (may modify state)
  platforms:
    - windows
    - linux
    - darwin
  execution:
    plugin: services
    action: inspect
    concurrency: per-device              # only per-device is enforced — see Section 12
    stagger:
      maxDelaySeconds: 0                 # 0 = no stagger
      fixedDelaySeconds: 0               # 0 = no fixed delay
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
      groupBy:
        - state
      operations:
        - count
  readablePayload: "Inspect service '${serviceName}'"
  gather:
    ttlSeconds: 300                      # agent must respond within this window
  response:
    retentionDays: 90
  approval:
    mode: auto                           # auto | role-gated | always
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
    enabled: true                        # auto-generate from plugin descriptor if true
  visualization:                         # optional — omit if no chart is needed
    type: pie
    processor: single_series
    title: Service State Distribution
    labelField: 1                        # 0-based index into spec.result.columns: 1 = state
    maxCategories: 8
status:
  phase: proposed
```

---

## 4. Kind: InstructionSet

The grouping unit and permission boundary. Sets aggregate definitions, policy fragments, and workflow templates under a shared permission model.

### 4.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `<scope>.<domain>.<area>` (e.g., `core.crossplatform.services`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |
| `platforms` | list of string | No | `[]` | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `permissions` | object | No | -- | Set-level role-based access control. |
| `contents` | object | Yes | -- | References to contained items. |
| `defaults` | object | No | -- | Default values applied to contained definitions. |
| `publishing` | object | No | -- | Publishing and visibility configuration. |

#### `metadata.permissions`

**Advisory content metadata, not enforced by the server** -- same status as
`spec.permissions` above (#1398); none of the three fields below has a
server-side representation or reads through to any RBAC check.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `executeRoles` | list of string | No | `[]` | **Advisory only (unenforced).** Documents which roles a content author intends to permit to execute definitions in this set; member definitions' own `spec.approval.mode` is what's actually enforced. |
| `authorRoles` | list of string | No | `[]` | **Advisory only (unenforced).** Documents which roles a content author intends to permit to author or modify definitions in this set; actual enforcement is the `InstructionDefinition:Write` RBAC permission. |
| `approveRoles` | list of string | No | `[]` | **Advisory only (unenforced).** Documents which roles a content author intends to permit to approve executions; actual enforcement is the `Approval:Approve` RBAC permission on the approvals route. |

#### `metadata.contents`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `instructionDefinitions` | list of string | No | `[]` | IDs of InstructionDefinition documents included in this set. |
| `policyFragments` | list of string | No | `[]` | IDs of PolicyFragment documents included in this set. |
| `workflowTemplates` | list of string | No | `[]` | IDs of workflow templates included in this set. |

#### `metadata.defaults`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `approvalMode` | string | No | `auto` | Default approval mode for definitions in this set that do not specify their own. Values: `auto`, `role-gated`, `always`. |
| `responseRetentionDays` | integer | No | `90` | Default response retention for definitions in this set. |
| `targetEstimationRequiredAbove` | integer | No | -- | When the estimated target device count exceeds this threshold, the UI requires the operator to confirm before dispatch. |

#### `metadata.publishing`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `signed` | boolean | No | `false` | Whether this set is cryptographically signed. |
| `visibility` | string | No | `org` | Visibility scope. Values: `org` (visible to the organization), `private` (visible only to authors), `public` (visible to all). |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 4.2 Complete Example

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
      - crossplatform.service.set_start_mode
    policyFragments:
      - fragment.service.must_be_running
    workflowTemplates:
      - workflow.restart_then_verify
  defaults:
    approvalMode: role-gated
    responseRetentionDays: 30
    targetEstimationRequiredAbove: 500
  publishing:
    signed: true
    visibility: org
status:
  phase: proposed
```

---

## 5. Kind: PolicyFragment (Phase 5)

> **Implementation phase:** Phase 5 -- Policy engine. Not yet implemented.

A reusable check/fix block that encapsulates a compliance check, optional remediation, and post-check verification. Fragments are composed into Policies (Section 6) for deployment to device scopes.

### 5.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `fragment.<domain>.<check>` (e.g., `fragment.service.must_be_running`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `inputs` | object | Yes | -- | JSON Schema subset defining input parameters for this fragment. Same schema format as InstructionDefinition `parameters`. |
| `check` | object | Yes | -- | The compliance check to run. |
| `compliance` | object | Yes | -- | Compliance evaluation rules. |
| `fix` | object | No | -- | Optional remediation action. |
| `postCheck` | object | No | -- | Optional post-remediation verification. |
| `debounce` | object | No | -- | Rate-limiting configuration. |
| `exceptionModel` | object | No | -- | Exception and suppression configuration. |

#### `spec.inputs`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `required` | list of string | No | `[]` | Required input parameter names. |
| `properties` | map of string to object | Yes | -- | Input parameter definitions. Each value follows the same schema as InstructionDefinition parameter descriptors. |

#### `spec.check`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the compliance check. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation from fragment inputs. |

#### `spec.compliance`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `expression` | string | Yes | -- | Primary compliance expression. Evaluated against the check result. Uses CEL syntax (Phase 5). Example: `result.state == "running"`. |
| `states` | object | Yes | -- | State mapping expressions. |

#### `spec.compliance.states`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `compliant` | string | Yes | -- | Expression that evaluates to `true` when the device is compliant. Example: `result.state == "running"`. |
| `noncompliant` | string | Yes | -- | Expression that evaluates to `true` when the device is noncompliant. Example: `result.state != "running"`. |
| `error` | string | No | -- | Expression that evaluates to `true` when the check itself failed. Example: `result.error != null`. |

#### `spec.fix`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `when` | string | No | -- | Condition under which remediation is attempted. Supports `${inputs.<name>}` interpolation. Example: `${inputs.autoRemediate} == true`. |
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the remediation action. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation. |

#### `spec.postCheck`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the post-remediation verification check. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation. |

#### `spec.debounce`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minIntervalSeconds` | integer | No | `300` | Minimum interval between consecutive evaluations of this fragment on a single device. Prevents remediation loops. |

#### `spec.exceptionModel`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `allowTemporarySuppressions` | boolean | No | `false` | When `true`, administrators can temporarily suppress this fragment for specific devices. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 5.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  id: fragment.service.must_be_running
  displayName: Service must be running
  version: 1.0.0
  description: Reusable fragment that checks a service and optionally restarts it.
spec:
  platforms:
    - windows
    - linux
    - darwin
  inputs:
    type: object
    required:
      - serviceName
    properties:
      serviceName:
        type: string
      autoRemediate:
        type: boolean
        default: true
  check:
    ref: crossplatform.service.inspect
    with:
      serviceName: ${inputs.serviceName}
  compliance:
    expression: result.state == "running"
    states:
      compliant: result.state == "running"
      noncompliant: result.state != "running"
      error: result.error != null
  fix:
    when: ${inputs.autoRemediate} == true
    ref: crossplatform.service.restart
    with:
      serviceName: ${inputs.serviceName}
  postCheck:
    ref: crossplatform.service.inspect
    with:
      serviceName: ${inputs.serviceName}
  debounce:
    minIntervalSeconds: 300
  exceptionModel:
    allowTemporarySuppressions: true
status:
  phase: proposed
```

---

## 6. Kind: Policy (Phase 5)

> **Implementation phase:** Phase 5 -- Policy engine. **Corrected 2026-09-11 (Gate-of-record pass 5, arch-P5-1): this banner was stale.** `PolicyStore` is implemented and live in production (`server/core/src/policy_store.cpp`, `compliance_routes.cpp`) -- policies are created and evaluated today; remediation is operator-initiated, never automatic (see §16 of `docs/capability-map.md` and `docs/user-manual/policy-engine.md`). What is genuinely not implemented is the `spec.triggers[]` schema documented in this section (`ref:`/`with:` references to a `TriggerTemplate`) -- see the caveat under `spec.triggers[]` below for what the shipped parser actually accepts.

A Policy binds a PolicyFragment to a device scope and a set of triggers. Policies are the deployment unit for compliance enforcement.

### 6.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `policy.<platform>.<target>.<check>` (e.g., `policy.windows.spooler.running`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `scope` | object | Yes | -- | Device targeting configuration. |
| `assignment` | object | No | -- | Management group assignment. |
| `fragment` | object | Yes | -- | PolicyFragment reference and parameter bindings. |
| `triggers` | list of object | No | `[]` | TriggerTemplate references that initiate evaluation. |
| `schedule` | object | No | -- | Cron-based evaluation schedule. |
| `rollout` | object | No | -- | Gradual rollout configuration. |
| `approvals` | object | No | -- | Approval requirements for deployment and changes. |
| `compliance` | object | No | -- | Compliance reporting configuration. |
| `exceptions` | object | No | -- | Device-level exception configuration. |

#### `spec.scope`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `selector` | object | Yes | -- | Device selector. |

#### `spec.scope.selector`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platform` | string | No | -- | Target platform filter. Values: `windows`, `linux`, `darwin`. |
| `tags` | list of string | No | `[]` | Devices must have all listed tags. |

Note: For advanced targeting, use the Scope DSL expression language (Section 9) in the scope expression field of an execution rather than the selector shorthand.

#### `spec.assignment`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `dynamic` | Assignment mode. `dynamic` -- devices matching the scope are continuously included. `static` -- devices are assigned at deployment time and do not change. |
| `managementGroups` | list of string | No | `[]` | Management group names to which this policy is assigned. |

#### `spec.fragment`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the PolicyFragment to bind. |
| `with` | map of string to varies | No | `{}` | Parameter bindings passed to the fragment's `inputs`. |

#### `spec.triggers[]`

Each trigger object:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of a TriggerTemplate. |
| `with` | map of string to varies | No | `{}` | Parameter bindings for the trigger. |

> **Implementation caveat (added 2026-09-11, Gate-of-record pass 5, arch-P5-1): the shipped `PolicyStore` parser does not implement this `ref:`/`with:` schema at all.** It reads each trigger entry for a bare `type:` key (`extract_yaml_value(item_block, "type")`) and, when `type: interval`, an `interval_seconds:` key -- there is no `TriggerTemplate` resolution, no `ref:` lookup, anywhere in `policy_store.cpp`. A trigger object written exactly as this table specifies (`ref:` + optional `with:`, no `type:` key) parses with an empty `trigger_type` and is **silently dropped -- not stored at all**, not even as an unrecognized/errored trigger: `if (!t.trigger_type.empty()) triggers.push_back(...)` (`server/core/src/policy_store.cpp:678-679`) simply skips it. A policy authored per this exact schema therefore has zero triggers in the database and falls back to the 3600-second interval default (see `docs/user-manual/policy-engine.md` § Trigger Configuration). The shipped, working schema is `- type: interval` / `interval_seconds: <seconds>` per-entry -- `type` values other than `interval` are accepted and stored (unlike `ref:`, which is dropped) but do not affect evaluation cadence either. This is a real gap between this normative spec and the implementation, not a documentation nuance: content authored to this table's schema silently does nothing. Tracked as issue #4244.

#### `spec.schedule`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `cron` | string | No | -- | Cron expression for periodic evaluation. Standard 5-field cron syntax. Example: `"*/15 * * * *"`. |
| `timezone` | string | No | `UTC` | IANA timezone name for cron evaluation. |

#### `spec.rollout`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `strategy` | string | No | `immediate` | Rollout strategy. Values: `immediate` (all devices at once), `gradual` (phased rollout). |
| `maxConcurrentPercent` | integer | No | `100` | Maximum percentage of in-scope devices that can be evaluating the policy concurrently. Only meaningful when `strategy` is `gradual`. |

#### `spec.approvals`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `requiredForInitialDeploy` | boolean | No | `false` | When `true`, deploying this policy for the first time requires approval. |
| `requiredForRemediationChange` | boolean | No | `false` | When `true`, changes to the fragment's fix action require approval before taking effect. |

#### `spec.compliance`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `cacheTtlSeconds` | integer | No | `300` | Duration (in seconds) to cache compliance evaluation results before requiring re-evaluation. |
| `responseRetentionDays` | integer | No | `90` | Number of days to retain compliance check response data. |
| `emitEventsOnStateChange` | boolean | No | `false` | When `true`, emit structured events when a device transitions between compliant, noncompliant, and error states. |

#### `spec.exceptions`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `allowDeviceLevelExemption` | boolean | No | `false` | When `true`, administrators can exempt individual devices from this policy. |
| `exemptionMaxDays` | integer | No | -- | Maximum number of days an exemption can remain active. After this period, the exemption expires and the policy resumes enforcement. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 6.2 Complete Example

> **This example's `triggers:` block uses the `ref:`/`with:` schema documented
> above -- see the implementation caveat under `spec.triggers[]`: the shipped
> parser drops these entries (zero triggers stored), and the policy falls back
> to the 3600-second interval default rather than the `ref: trigger.interval.five_minutes` /
> `ref: trigger.service_status_changed` cadence this example implies. This
> example is kept as-is because it is the normative schema, unmodified by an
> implementation gap -- do not copy its `triggers:` block into a real policy
> and expect it to work; use the shipped `type: interval` / `interval_seconds:`
> form from `docs/user-manual/policy-engine.md` instead. *(Added 2026-09-11,
> Gate-of-record pass 5, arch-P5-1.)*

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  id: policy.windows.spooler.running
  displayName: Windows Print Spooler must be running
  version: 1.0.0
  description: Ensures the Spooler service remains in the running state.
spec:
  scope:
    selector:
      platform: windows
      tags:
        - print-enabled
  assignment:
    mode: dynamic
    managementGroups:
      - workstations
  fragment:
    ref: fragment.service.must_be_running
    with:
      serviceName: Spooler
      autoRemediate: true
  triggers:
    - ref: trigger.interval.five_minutes
    - ref: trigger.service_status_changed
      with:
        serviceName: Spooler
  schedule:
    cron: "*/15 * * * *"
    timezone: UTC
  rollout:
    strategy: gradual
    maxConcurrentPercent: 10
  approvals:
    requiredForInitialDeploy: true
    requiredForRemediationChange: true
  compliance:
    cacheTtlSeconds: 300
    responseRetentionDays: 90
    emitEventsOnStateChange: true
  exceptions:
    allowDeviceLevelExemption: true
    exemptionMaxDays: 14
status:
  phase: proposed
```

---

## 7. Kind: TriggerTemplate (Phase 4)

> **Implementation phase:** Phase 4 -- Agent infrastructure. Not yet implemented.

A TriggerTemplate defines an event source that can initiate policy evaluation or instruction execution on the agent.

### 7.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `trigger.<platform>.<source>.<detail>` (e.g., `trigger.windows.eventlog.pattern`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `source` | object | Yes | -- | Event source configuration. |
| `parameters` | object | No | `{}` | JSON Schema subset defining configurable parameters for this trigger. Same schema format as InstructionDefinition `parameters`. |
| `debounce` | object | No | -- | Debounce configuration to prevent trigger storms. |
| `delivery` | object | No | -- | Event delivery configuration. |
| `outputs` | object | No | -- | JSON Schema subset describing the output payload produced when the trigger fires. |

#### `spec.source`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Trigger source type. Values: `interval`, `filesystem`, `service`, `windows-event-log`, `registry`, `agent-startup`. |

Trigger source types:

| Type | Description | Platform |
|---|---|---|
| `interval` | Timer-based, minimum 30 seconds | All |
| `filesystem` | File/directory change notification (ReadDirectoryChangesW / inotify / FSEvents) | All |
| `service` | Service state change notification (SCM / systemd) | Windows, Linux |
| `windows-event-log` | Windows event log record matching | Windows only |
| `registry` | Registry key change notification | Windows only |
| `agent-startup` | Fires once when the agent starts | All |

#### `spec.debounce`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `global` | Debounce mode. `global` -- one debounce timer for all events from this trigger. `keyed` -- separate debounce timers per unique key (computed from `keyExpression`). |
| `keyExpression` | string | No | -- | Expression that computes the debounce key from trigger event fields. Required when `mode` is `keyed`. Supports `${fieldName}` interpolation. |
| `minIntervalSeconds` | integer | No | `60` | Minimum interval between trigger firings. Events arriving within this window after a firing are suppressed. |

#### `spec.delivery`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `local-agent` | Delivery mode. `local-agent` -- trigger is evaluated and delivered locally on the agent. |
| `persistTriggerEvents` | boolean | No | `false` | When `true`, trigger events are persisted to the agent's local KV store for diagnostic purposes. |

#### `spec.outputs`

A JSON Schema subset describing the structured payload produced when the trigger fires. This payload is available to downstream consumers (policy evaluations, instruction parameter bindings).

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `properties` | map of string to object | Yes | -- | Output field definitions. Each value specifies `type` (string, integer, boolean) and optional `description`. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 7.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: TriggerTemplate
metadata:
  id: trigger.windows.eventlog.pattern
  displayName: Windows Event Log Pattern Trigger
  version: 1.0.0
  description: Fires when a matching Windows event log record appears.
spec:
  platforms:
    - windows
  source:
    type: windows-event-log    # interval | filesystem | service | windows-event-log | registry | agent-startup
  parameters:
    type: object
    required:
      - channel
    properties:
      channel:
        type: string
      provider:
        type: string
      eventIds:
        type: array
        items:
          type: integer
      messageRegex:
        type: string
  debounce:
    mode: keyed
    keyExpression: "${channel}:${provider}:${eventId}"
    minIntervalSeconds: 60
  delivery:
    mode: local-agent
    persistTriggerEvents: true
  outputs:
    type: object
    properties:
      timestamp:
        type: string
      channel:
        type: string
      provider:
        type: string
      eventId:
        type: integer
      computer:
        type: string
      message:
        type: string
status:
  phase: proposed
```

---

## 8. Kind: ProductPack (Phase 7)

> **Implementation phase:** Phase 7 -- Scale and integration. Not yet implemented.

A ProductPack is a signed distribution bundle containing instruction sets, definitions, policy fragments, policies, trigger templates, dashboards, and documentation. Packs are the unit of distribution and trust.

### 8.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `pack.<scope>.<name>` (e.g., `pack.core.endpoint-ops`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `publisher` | object | Yes | -- | Publisher identity. |
| `compatibility` | object | Yes | -- | Version and API compatibility requirements. |
| `contents` | object | Yes | -- | References to all items included in the pack. |
| `dependencies` | object | No | -- | Plugin and pack dependencies. |
| `security` | object | Yes | -- | Cryptographic signing and verification. |
| `distribution` | object | No | -- | Archive format and import behavior. |

#### `spec.publisher`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | -- | Publisher name (organization or individual). |
| `contact` | string | No | -- | Contact email address. |

#### `spec.compatibility`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minServerVersion` | string | Yes | -- | Minimum Yuzu server version required to import this pack. |
| `minAgentVersion` | string | Yes | -- | Minimum Yuzu agent version required to execute content from this pack. |
| `requiredApiVersions` | list of string | No | `[]` | API versions that the server must support. Values: `yuzu.io/v1alpha1`. |

#### `spec.contents`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `instructionSets` | list of string | No | `[]` | IDs of InstructionSet documents included in the pack. |
| `instructionDefinitions` | list of string | No | `[]` | IDs of standalone InstructionDefinition documents included in the pack. |
| `policyFragments` | list of string | No | `[]` | IDs of PolicyFragment documents included in the pack. |
| `policies` | list of string | No | `[]` | IDs of Policy documents included in the pack. |
| `triggerTemplates` | list of string | No | `[]` | IDs of TriggerTemplate documents included in the pack. |
| `dashboards` | list of string | No | `[]` | IDs of dashboard definitions included in the pack. |
| `docs` | list of string | No | `[]` | Paths to documentation files included in the pack. |

#### `spec.dependencies`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugins` | list of string | No | `[]` | Agent plugins that must be available to execute content from this pack. |
| `packs` | list of string | No | `[]` | Other ProductPack IDs that this pack depends on. |

#### `spec.security`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `signing` | object | Yes | -- | Signing algorithm and key identification. |
| `signature` | object | Yes | -- | Manifest signature. |
| `checksums` | object | Yes | -- | Manifest integrity checksums. |
| `trustChain` | object | No | -- | Trust chain anchoring the signing key to an organization root key. |
| `revocationListUrl` | string | No | -- | URL of the JSON Certificate Revocation List for checking key revocation status. |

#### `spec.security.signing`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `algorithm` | string | Yes | -- | Signing algorithm. Must be `ed25519`. |
| `keyId` | string | Yes | -- | Identifier of the signing key. Used for key lookup in the trust store. |
| `keyFingerprint` | string | Yes | -- | SHA-256 fingerprint of the signing key. Format: `SHA256:<hex>`. |

#### `spec.security.signature`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `manifestHash` | string | Yes | -- | SHA-256 hash of the pack manifest file. |
| `value` | string | Yes | -- | Base64-encoded Ed25519 signature of the manifest hash. |

#### `spec.security.checksums`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `manifestSha256` | string | Yes | -- | SHA-256 hash of the manifest file. Used for integrity verification before signature check. |

#### `spec.security.trustChain`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `rootKeyFingerprint` | string | No | -- | SHA-256 fingerprint of the organization root key. Format: `SHA256:<hex>`. |
| `signingKeyCertificate` | string | No | -- | Base64-encoded DER certificate of the signing key, signed by the root key. |

#### `spec.distribution`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `format` | string | No | `tar.zst` | Archive format. Must be `tar.zst` (tar archive with Zstandard compression). |
| `importMode` | string | No | `staged` | Import behavior. `staged` -- contents are imported to a staging area and activated after review. `direct` -- contents are imported and activated immediately. |
| `allowPartialImport` | boolean | No | `false` | When `true`, the server imports items that pass validation even if some items fail. When `false`, the entire import is rejected on any validation failure. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 8.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: ProductPack
metadata:
  id: pack.core.endpoint-ops
  displayName: Core Endpoint Operations Pack
  version: 1.0.0
  description: Signed bundle of baseline operational content for core endpoint management.
spec:
  publisher:
    name: Yuzu Core
    contact: platform@example.invalid
  compatibility:
    minServerVersion: 0.9.0
    minAgentVersion: 0.9.0
    requiredApiVersions:
      - yuzu.io/v1alpha1
  contents:
    instructionSets:
      - core.crossplatform.services
      - core.crossplatform.processes
    instructionDefinitions:
      - crossplatform.service.inspect
      - crossplatform.service.restart
      - crossplatform.process.list
      - crossplatform.process.kill
    policyFragments:
      - fragment.service.must_be_running
    policies:
      - policy.windows.spooler.running
    triggerTemplates:
      - trigger.interval.five_minutes
      - trigger.windows.eventlog.pattern
    dashboards:
      - compliance.overview
    docs:
      - docs/pack-overview.md
  dependencies:
    plugins:
      - services
      - processes
      - event_logs
    packs: []
  security:
    signing:
      algorithm: ed25519
      keyId: yuzu-core-release-2026
      keyFingerprint: "SHA256:..."
    signature:
      manifestHash: <sha256-of-manifest>
      value: <base64-ed25519-signature>
    checksums:
      manifestSha256: <sha256>
    trustChain:
      rootKeyFingerprint: "SHA256:..."
      signingKeyCertificate: <base64-der>
    revocationListUrl: "https://packs.yuzu.example/crl.json"
  distribution:
    format: tar.zst
    importMode: staged
    allowPartialImport: false
status:
  phase: proposed
```

---

## 9. Expression Language

### 9.1 Scope DSL

The scope engine (`server/core/src/scope_engine.cpp`) implements a recursive-descent parser for device targeting expressions. This DSL is used in `spec.scope` fields and dashboard filter expressions.

#### Grammar

```
expr       ::= or_expr
or_expr    ::= and_expr ('OR' and_expr)*
and_expr   ::= not_expr ('AND' not_expr)*
not_expr   ::= 'NOT' not_expr | primary
primary    ::= '(' expr ')' | condition
condition  ::= IDENT op value
op         ::= '==' | '!=' | 'LIKE' | '<' | '>' | '<=' | '>=' | 'IN' | 'CONTAINS'
value      ::= QUOTED_STRING | '(' value_list ')' | IDENT
value_list ::= value (',' value)*
```

#### Operators

| Operator | Description | Example |
|---|---|---|
| `==` | Equality | `ostype == "windows"` |
| `!=` | Inequality | `ostype != "linux"` |
| `LIKE` | Wildcard matching (`*` and `?` globbing) | `hostname LIKE "web-*"` |
| `<` | Less than (numeric comparison) | `agent_version < "1.0.0"` |
| `>` | Greater than (numeric comparison) | `cpu_count > "4"` |
| `<=` | Less than or equal | `agent_version <= "0.9.0"` |
| `>=` | Greater than or equal | `agent_version >= "0.9.0"` |
| `IN` | Membership in a value list | `arch IN ("x86_64", "aarch64")` |
| `CONTAINS` | Case-insensitive substring search | `hostname CONTAINS "prod"` |

#### Combinators

| Combinator | Description | Example |
|---|---|---|
| `AND` | Logical conjunction | `ostype == "windows" AND tag:env == "production"` |
| `OR` | Logical disjunction | `hostname LIKE "web-*" OR hostname LIKE "api-*"` |
| `NOT` | Logical negation | `NOT tag:quarantined == "true"` |

#### Features

- Case-insensitive keyword matching (AND, OR, NOT, LIKE, IN, CONTAINS)
- Wildcard LIKE with `*` (match any characters) and `?` (match single character) globbing
- Numeric comparison with `std::from_chars` fallback to `std::stod` (Apple libc++ compatibility)
- Case-insensitive substring search via CONTAINS
- Maximum nesting depth of 10
- `AttributeResolver` callback decouples parsing from data access

#### Examples

```
ostype == "windows" AND tag:env == "production"
hostname LIKE "web-*" OR hostname LIKE "api-*"
arch IN ("x86_64", "aarch64") AND NOT tag:quarantined == "true"
agent_version >= "0.9.0"
```

### 9.2 Planned Scope DSL Extensions

| Extension | Syntax | Use Case |
|---|---|---|
| `MATCHES` | `hostname MATCHES "^web-\\d+$"` | Regex matching for complex patterns |
| `EXISTS` | `EXISTS tag:env` | Tag presence check (no value comparison) |
| `len()` | `len(tag:name) > 5` | String length for validation |
| `startswith()` | `startswith(hostname, "web-")` | Prefix check (more readable than LIKE) |

Note: `EXISTS`, `MATCHES`, `len()`, and `startswith()` are implemented in the scope engine today (the "planned" label predates them). Tag presence lowers to `EXISTS tag:<name>` — see §9.3.

### 9.3 Scope walking — composable scope (`fromResultSet:`)

Scope walking (capability §30, `docs/scope-walking-design.md`) lets a scope target the members of a previously-saved **result set** — Yuzu's composable-scope primitive. A result set is a per-operator, TTL-bounded, lineage-tracked set of device ids built from an earlier query.

**Scope atom.** The scope engine accepts a bare atom `from_result_set:<id-or-alias>` (implemented, `scope_engine.cpp`). It resolves to the members of the referenced set and composes with attribute predicates via `AND` / `OR` / `NOT`. Membership is owner-checked at evaluation: a set the dispatching operator does not own resolves to zero devices (no cross-operator targeting). Offline / stale members drop silently.

```
from_result_set:rs_01HXYZ AND ostype == "windows"
```

**YAML authoring form.** Where a `spec.scope:` block is accepted, the mapping form may carry `fromResultSet:` (a canonical `rs_` id or a per-operator alias), optionally refined by a `selector:` composed with `AND`:

```yaml
spec:
  scope:
    fromResultSet: "windows-chrome-suspects"   # id or per-operator alias
    selector:                                    # optional refinement (AND-ed)
      platform: windows
      tags:
        - production
  assignment:
    mode: static
```

This lowers to the scope-engine string `from_result_set:windows-chrome-suspects AND ostype == "windows" AND EXISTS tag:production` — `selector.platform` → `ostype == "<value>"` (lower-cased); each `selector.tags` entry → `EXISTS tag:<name>` (a presence check, since Yuzu tags are key=value).

**Validation (at YAML load):**

1. `fromResultSet` may not be combined with `assignment.managementGroups` — a result set already defines a fixed device set; layering management-group filtering on top is rejected.
2. When `fromResultSet` is present, `assignment.mode` must be `static` (an omitted mode defaults to static). `dynamic` is rejected — the point of a result set is a fixed target.
3. References resolve at **invocation** time, not load time. An `InstructionDefinition` carrying a `fromResultSet:` that has since expired is still valid YAML; an invocation-time resolution failure (the set is absent, expired, or not owned — including a set deleted in the window between the pre-dispatch owner-check gate and the registry's own membership read, closed as a TOCTOU by #4981 PR-1) is recorded as an `instruction.scope_resolution_failed` audit row (`INSTRUCTION_SCOPE_RESOLUTION_FAILED`) carrying the result-set id and reason, and — as of governance M1, 2026-07-29 — **aborts the entire dispatch**: zero devices are targeted, including devices matched by other scope atoms (a paired `scope.evaluation_aborted` row records `reason=owner_check_failed`, or one of `db_degraded`/`principal_unresolved`/`presence_degraded`/`unresolvable` for the other abort classes — see `docs/user-manual/rest-api.md`'s audit-event table for the full vocabulary). The previous behavior (proceed with only that reference zeroed) inverted to a fleet-wide match under a `NOT` combinator and is gone.
4. `fromResultSet` (id or alias), `selector.platform`, and each `selector.tags` entry must contain only letters, digits, and `_ . : * -` (the scope-ident charset). A space, quote, or operator character is rejected at load — these values are lowered into a scope-engine token, so anything else would produce an unparseable or ambiguous expression. **Choose result-set aliases (`name`) from this charset**; an alias with a space cannot be referenced from a scope.
5. The `scope:` block must use **block form** (`scope:` on its own line, children indented beneath). Inline flow-mapping (`scope: {fromResultSet: x}`) is rejected — the runtime YAML scanner reads only the block form.

> Tag presence (`EXISTS tag:<name>`) requires the tag to have a **non-empty value**; a device carrying a tag with an empty value is treated as not having it.

**Current support (this release):**

- **Aliases** in a `from_result_set:` ref are resolved at the dispatch layer against the dispatching operator's owned sets (a canonical `rs_` id is used verbatim). The `/api/scope/estimate` preview resolves them too.
- **Instruction definitions** validate a `spec.scope` block at import; the operator still supplies the `from_result_set:` scope at dispatch time. (A definition-embedded scope that auto-applies at dispatch is a follow-up.)
- **Policies** do **not** yet support `fromResultSet:` — a policy is evaluated continuously while a result set is TTL-bounded; `create_policy` rejects it with a clear error. (Tracked for a follow-up that adds a policy owner + pinned-set semantics.)

See `docs/scope-walking-design.md` §7 and the Chrome-IR walkthrough (§10).

### 9.4 CEL (Common Expression Language)

Yuzu implements a CEL-compatible expression evaluator (`server/core/src/cel_eval.cpp`) for typed policy evaluation expressions. CEL is not used for device targeting (the scope DSL is simpler and sufficient for that purpose).

**Where CEL applies:**

- `spec.compliance.expression` in PolicyFragments
- `spec.fix.when` conditional expressions in PolicyFragments
- `spec.rollout.condition` for staged rollouts in Policies
- `WorkflowStep.condition` for conditional workflow steps

**Where the scope DSL stays:**

- All device targeting (`spec.scope.selector`)
- `ScopeEngine` evaluation in the dispatch path
- Dashboard filter expressions

#### Type System

| Type | CEL Syntax | Examples |
|---|---|---|
| null | `null` | `result.error == null` |
| bool | `true`, `false` | `result.enabled == true` |
| int | integer literals | `result.count > 5`, `3 + 4` |
| double | floating-point literals | `result.score >= 80.5` |
| string | single or double quotes | `result.status == 'running'` |
| timestamp | `timestamp('...')` | `timestamp('2024-01-15T10:30:00Z')` |
| duration | `duration('...')` | `duration('1h')`, `duration('30m')`, `duration('5s')` |
| list | `[...]` | `result.status in ['running', 'starting']` |

Variables from instruction results are provided as strings and automatically coerced to typed values: `"true"`/`"false"` to bool, integer strings to int, float strings to double, ISO 8601 strings to timestamp.

#### Operators

| Category | Operators |
|---|---|
| Comparison | `==`, `!=`, `<`, `>`, `<=`, `>=` |
| Logical | `&&`, `\|\|`, `!` |
| Arithmetic | `+`, `-`, `*`, `/`, `%` |
| Membership | `in` (e.g., `x in [1, 2, 3]`) |
| Ternary | `condition ? then : else` |

String `+` performs concatenation. Timestamp arithmetic: `timestamp + duration = timestamp`, `timestamp - timestamp = duration`.

#### Built-in Functions

| Function | Description | Example |
|---|---|---|
| `size()` | String length or list size | `result.name.size() > 3` |
| `startsWith()` | String prefix check | `result.path.startsWith('/usr')` |
| `endsWith()` | String suffix check | `result.path.endsWith('.log')` |
| `contains()` | Substring check (case-insensitive) | `result.name.contains('agent')` |
| `matches()` | Regex match (ECMAScript) | `result.host.matches('^web-\\d+$')` |
| `timestamp()` | Parse ISO 8601 string | `timestamp('2024-01-15T10:30:00Z')` |
| `duration()` | Parse duration string | `duration('1h')` |
| `int()` | Cast to integer | `int('42')` |
| `double()` | Cast to double | `double('3.14')` |
| `string()` | Cast to string | `string(42)` |
| `has()` | Check field presence | `has('field_name')` |

#### Backward Compatibility

Legacy compliance expressions using `AND`, `OR`, `NOT`, `contains`, and `startswith` keywords continue to work. The evaluator accepts both CEL syntax (`&&`, `||`, `!`, `.contains()`, `.startsWith()`) and legacy keyword syntax. New fragments are automatically migrated to CEL syntax via `cel::migrate_expression()`.

**Precedence note:** The keyword `NOT` has lower precedence than comparison operators (for backward compatibility), so `NOT result.status == 'failed'` is parsed as `NOT (result.status == 'failed')`. The CEL `!` operator has standard unary precedence, so `!result.status == 'failed'` is parsed as `(!result.status) == 'failed'`. Use parentheses when mixing styles to avoid ambiguity.

#### Safety Limits

| Limit | Value | Purpose |
|---|---|---|
| Max expression length | 4096 chars | Prevents DoS from oversized input |
| Max nesting depth | 64 levels | Prevents stack overflow from deeply nested parens |
| Max list elements | 1000 | Prevents memory exhaustion from large list literals |
| Max regex pattern | 256 chars | Mitigates ReDoS via `matches()` |

#### Examples

```cel
# Basic compliance check
result.status == 'running'

# Typed comparison with arithmetic
result.cpu_percent < 90 && result.memory_mb > 512

# Ternary for computed compliance
result.score >= 80 ? true : false

# Timestamp comparison
timestamp(result.last_check) + duration('1h') > timestamp(result.current_time)

# List membership
result.os in ['windows', 'linux', 'darwin']

# String functions
result.hostname.startsWith('web-') && result.hostname.matches('^web-\\d+$')

# Combined check with duration
result.uptime_seconds > 3600 && result.status == 'running'
```

---

## 10. Parameter Type System

InstructionDefinition parameters and PolicyFragment inputs use the following type set:

| Type | Description | Wire Format | Example |
|---|---|---|---|
| `string` | UTF-8 text | String | `"Spooler"` |
| `boolean` | Boolean flag | `true` or `false` | `true` |
| `int32` | 32-bit signed integer | Numeric string | `"42"` |
| `int64` | 64-bit signed integer | Numeric string | `"9223372036854775807"` |
| `datetime` | ISO 8601 timestamp | String | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | String | `"550e8400-e29b-41d4-a716-446655440000"` |

Parameters are transmitted as `map<string, string>` in the `CommandRequest` protobuf message. `POST /api/instructions/{id}/execute` validates the request's parameter values against the declared type and constraints before dispatch; no other dispatch surface does yet.

### Validation Constraints

| Constraint | Applicable Types | Description |
|---|---|---|
| `maxLength` | `string` | Maximum length in bytes (UTF-8). |
| `minLength` | `string` | Minimum length in bytes (UTF-8). |
| `pattern` | `string` | Regular expression the value must match. |
| `enum` | `string` | List of allowed values. |
| `minimum` | `int32`, `int64` | Minimum value (inclusive). |
| `maximum` | `int32`, `int64` | Maximum value (inclusive). |

---

## 11. Result Column Type System

Result schemas declare typed columns for structured output. These types enable downstream consumption by ClickHouse, Splunk, CSV export, and the dashboard aggregation engine.

| Type | Description | Example Value |
|---|---|---|
| `bool` | Boolean | `true`, `false` |
| `int32` | 32-bit signed integer | `4592` |
| `int64` | 64-bit signed integer | `1710700800000` |
| `string` | UTF-8 text | `"running"` |
| `datetime` | ISO 8601 timestamp | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | `"550e8400-e29b-41d4-a716-446655440000"` |
| `clob` | Character large object -- for large text fields | Multi-line log output, stack traces |

The `clob` type indicates a potentially large text field. The server may apply configurable truncation to `clob` columns to limit storage consumption.

---

## 12. Concurrency Model

**Corrected 2026-08-31 (ADR-1007) — only `per-device` is actually enforced.** An earlier revision
of this section described 5 modes as shipped; a real-usage audit of `content/definitions/*.yaml`
plus a direct read of the dispatch path found that only `per-device` has ever been enforced, and
the other four values are either unspecified or attach exclusively to catalog-only definitions
that never dispatch through the agent path at all. `concurrency_mode` is not validated anywhere in
the load/CRUD path — any string is accepted verbatim, so a typo or an unsupported value is silently
treated as no limit, never rejected.

| Mode | Enforcement | Scope | Status |
|---|---|---|---|
| `per-device` | Server-side (see below) | One execution of this definition per device at a time | **Enforced.** Default. The one mode with real, present-day usage (191 shipped definitions). |
| `per-definition` | None | — | **Not enforced.** Accepted as a YAML value; used only on catalog-only `plugin: server`-class definitions that never dispatch through the agent path — see below. |
| `per-set` | None | — | **Not enforced, and unspecified** — no "set" grouping key is defined anywhere in this spec or the code. Zero real usage. |
| `global:<N>` | None | — | **Not enforced.** Not used in any shipped definition — real content uses the bare literals `global`/`global-singleton` instead, neither of which this or any other syntax ever parsed. |
| `unlimited` | None | No limits | No enforcement needed — this was always the intended behavior. |

### Enforcement (per-device)

Enforced **server-side**, not agent-side as an earlier revision of this spec described — see
ADR-1007 for why (the wire `CommandRequest` carries no `definition_id`, and building agent-side
dedup would require a proto + gateway change with no correctness benefit once the server-side
design is made race-free). The server holds a claim (a dedicated Postgres table, race-free via a
partial unique index — not the `concurrency_locks` an earlier revision of this section described,
which was never built) on `(definition_id, agent_id)` at dispatch time and releases it when that
agent's execution reaches a terminal state. An agent already holding a claim for the same
definition is excluded from the dispatch — for a single-target dispatch this means "no agents
reached"; there is no queueing (an earlier revision of this section claimed an at-limit execution
"enters a wait queue" — no such mechanism has ever existed, agent or server side). The caller may
retry once the in-flight execution completes. Error code `3003`
(`kConcurrencyBlocked`) is registered in the taxonomy for this condition but is not currently
surfaced through the dispatch response — see ADR-1007's follow-ups.

**Not covered:** raw MCP `execute_instruction` and raw REST command dispatch (no `definition_id`
in scope — cannot be gated by definition), and fleet-broadcast dispatch of a `per-device`
definition (`scope: __all__`) — both real, deliberate gaps, not oversights.

**One release exception:** cancelling an execution does not release its claim (no agent-side
cancel/kill path exists, so the claim stays open exactly as if the execution were still running,
until a terminal response or the reconciler's TTL bound — at most one hour — releases it). A
`per-device` definition dispatched via a workflow step releases and renews the same way as any
other dispatch path (a `command_id`-keyed fallback covers it, since workflow-step dispatch still
doesn't correlate a real execution id) — see ADR-1007.

### `plugin: server` / `server_internal` / `_server` definitions

The 42 shipped definitions using `per-definition`/`global`/`global-singleton` are catalog/discovery
metadata for the management API and dashboard, not live execution artifacts — no agent plugin
named `server`/`server_internal`/`_server` exists. Their real functionality (directory sync,
deployment orchestration, policy CRUD, etc.) is implemented by dedicated REST routes calling
dedicated C++ objects directly, which never consult `concurrency_mode`. Where real concurrent-call
protection is needed for one of these operations, it is implemented directly on the handler (see
`DirectorySync::sync_entra`'s re-entrancy guard, ADR-1007) rather than through this DSL field.

### YAML Syntax

```yaml
spec:
  execution:
    concurrency: per-device          # default — the only mode actually enforced
    # concurrency: per-definition    # accepted, NOT enforced — see above
    # concurrency: per-set           # accepted, NOT enforced, unspecified grouping — see above
    # concurrency: unlimited         # no limits (also the practical effect of any unsupported value)
```

---

## 13. Error Code Taxonomy

Errors are categorized into four domains with non-overlapping numeric ranges.

### 1xxx -- Plugin Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 1001 | `PLUGIN_ACTION_NOT_FOUND` | Plugin does not support the requested action | Never |
| 1002 | `PLUGIN_PARAM_INVALID` | Parameter validation failed | Never |
| 1003 | `PLUGIN_PERMISSION_DENIED` | OS-level permission denied (e.g., non-admin) | Never |
| 1004 | `PLUGIN_RESOURCE_MISSING` | Target resource does not exist (service, file, etc.) | Never |
| 1005 | `PLUGIN_OPERATION_FAILED` | Action executed but failed (non-zero exit, exception) | Transient: yes; Deterministic: no |
| 1006 | `PLUGIN_CRASH` | Plugin segfaulted or threw unhandled exception | Never |
| 1007 | `PLUGIN_TIMEOUT` | Plugin did not complete within gather TTL | Yes (once) |

### 2xxx -- Transport Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 2001 | `TRANSPORT_DISCONNECTED` | Agent lost connection during execution | Always |
| 2002 | `TRANSPORT_STREAM_ERROR` | gRPC stream broken mid-response | Always |
| 2003 | `TRANSPORT_RESPONSE_TOO_LARGE` | Response exceeds max message size | Never |

### 3xxx -- Orchestration Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 3001 | `DefinitionNotFound` | The referenced InstructionDefinition does not exist | Never |
| 3002 | `ApprovalRequired` | Execution blocked pending approval | No (awaits human) |
| 3003 | `ConcurrencyBlocked` | Registered for `per-device` claim exclusion; not yet surfaced through the dispatch response (ADR-1007) | Yes (after slot frees) |
| 3004 | `ScopeEmpty` | The resolved target scope matched no agents | Never |
| 3005 | `ScheduleExpired` | The schedule's execution window has passed | Never |

Names above are the taxonomy's actual registered names (`server/core/src/error_codes.cpp`) — this
row set was corrected from a stale naming scheme this table had carried (`ORCH_*` prefixes that
never matched the code). Like 3003, none of 3001/3002/3004/3005 currently has a production call
site that emits it — the retry column states the DESIGNED behavior per the taxonomy entry, not an
observed one.

### 4xxx -- Agent Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 4001 | `AGENT_PLUGIN_NOT_LOADED` | Required plugin not available on agent | Never |
| 4002 | `AGENT_SHUTTING_DOWN` | Agent is in shutdown sequence | Yes (on reconnect) |
| 4003 | `AGENT_VERSION_INCOMPATIBLE` | Agent version below `minAgentVersion` | Never |

### Retry Semantics

| Category | Default Retry | Max Attempts | Backoff |
|---|---|---|---|
| Transport (2xxx) | Always | 3 | Exponential (1s, 2s, 4s) |
| Transient plugin (1005, 1007) | If `retryable: true` in definition | 2 | Linear (5s) |
| Deterministic plugin (1001-1004, 1006) | Never | 0 | -- |
| Agent (4001-4003) | Never (except 4002 on reconnect) | 1 | -- |
| Orchestration (3001-3005) | Per-code as noted | -- | -- |

---

## 14. Substrate Primitive Reference

This section enumerates the stable builtin primitives that content authors target. Each primitive maps to a backing plugin and one or more agent actions. Platform availability is marked per column.

**Status key:**
- **Verified** -- grounded in existing plugin code in `agents/plugins/`
- **Planned** -- in roadmap with GitHub issue
- **Proposed** -- recommended in design document

### 14.1 System and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `system.info` | `os_info` | Y | Y | Y | Verified |
| `system.status` | `status` | Y | Y | Y | Verified |
| `device.identity` | `device_identity` | Y | Y | Y | Verified |
| `hardware.inventory` | `hardware` | Y | Y | Y | Verified |
| `device.hardware.drivers` | `hardware` | Y | Y | - | Verified |
| `device.hardware.system` | `hardware` | Y | Y | Y | Verified |
| `device.tags.get` | `tags` | Y | Y | Y | Verified |
| `device.tags.set` | `tags` | Y | Y | Y | Verified |
| `device.asset_tags.sync` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.status` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.get` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.changes` | `asset_tags` | Y | Y | Y | Verified |
| `agent.health` | `diagnostics` | Y | Y | Y | Verified |
| `agent.restart` | `agent_actions` | Y | Y | Y | Verified |
| `agent.sleep` | agent core | Y | Y | Y | Verified |
| `agent.log.read` | `agent_logging` | Y | Y | Y | Verified |
| `agent.log.key_files` | `agent_logging` | Y | Y | Y | Verified |

### 14.2 Process and Execution

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `process.list` | `processes` | Y | Y | Y | Verified |
| `process.inspect` | `procfetch` | Y | Y | Y | Verified |
| `process.kill` | `processes` | Y | Y | Y | Verified |
| `process.start` | `script_exec` | Y | Y | Y | Proposed |
| `script.run` | `script_exec` | Y | Y | Y | Verified |
| `command.run` | `script_exec` | Y | Y | Y | Verified |

### 14.3 Services and Daemons

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `service.list` | `services` | Y | Y | Y | Verified |
| `service.inspect` | `services` | Y | Y | Y | Proposed |
| `service.start` | `services` | Y | Y | Y | Verified |
| `service.stop` | `services` | Y | Y | Y | Verified |
| `service.restart` | `services` | Y | Y | Y | Verified |
| `service.set_start_mode` | `services` | Y | Y | Y | Verified |

### 14.4 User, Session, and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `user.list` | `users` | Y | Y | Y | Verified |
| `user.logged_on` | `users` | Y | Y | Y | Verified |
| `user.group_members` | `users` | Y | Y | Y | Verified |
| `user.primary_user` | `users` | Y | Y | Y | Verified |
| `user.session_history` | `users` | Y | Y | Y | Verified |
| `user.group_membership` | `users` (ext) | Y | Y | Y | Planned |
| `session.list` | `users` (ext) | Y | Y | Y | Planned |
| `session.active_user` | `users` (ext) | Y | Y | Y | Planned |
| `session.notify` | `interaction` | Y | Y | Y | Verified |
| `session.prompt` | `interaction` | Y | Y | Y | Verified |
| `session.input` | `interaction` | Y | Y | Y | Verified |

### 14.5 Network

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `network.config.get` | `network_config` | Y | Y | Y | Verified |
| `network.route.list` | `network_config` (`routes` action) | Y | Y | Y | Verified |
| `network.connection.list` | `netstat` | Y | Y | Y | Verified |
| `network.socket.owner` | `netstat` (`attribution` action) | Y | Y | Y | Verified |
| `network.dns.flush` | `network_actions` | Y | Y | Y | Verified |
| `network.diagnostics.run` | `network_diag` | Y | Y | Y | Verified |
| `network.probe.icmp` | `netprobe` | Y | Y | Y | Verified |
| `network.probe.tcp` | `netprobe` | Y | Y | Y | Verified |
| `network.probe.dns` | `netprobe` | Y | Y | Y | Verified |
| `network.adapter.enable` | `network_actions` | Y | Y | Y | Verified |
| `network.adapter.disable` | `network_actions` | Y | Y | Y | Verified |
| `network.wifi.list` | `wifi` | Y | Y | Y | Verified |
| `network.wol.wake` | `wol` | Y | Y | Y | Verified |
| `network.wol.check` | `wol` | Y | Y | Y | Verified |
| `network.quarantine` | `quarantine` | Y | Y | - | Planned |

### 14.6 Software and Patching

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `software.inventory` | `installed_apps` | Y | Y | Y | Verified |
| `software.package.inventory` | `msi_packages` | Y | - | Y | Verified |
| `software.uninstall` | `software_actions` | Y | Y | Y | Verified |
| `software.install` | content staging | Y | Y | Y | Planned |
| `software.update` | pkg adapter | Y | Y | Y | Proposed |
| `software.sccm.query` | `sccm` | Y | - | - | Verified |
| `patch.inventory` | `windows_updates` | Y | Y | Y | Verified |
| `patch.pending_reboot` | `windows_updates` | Y | Y | Y | Verified |
| `patch.install` | `patch` | Y | Y | Y | Planned |
| `patch.scan` | `vuln_scan` | Y | Y | Y | Verified |

### 14.7 Filesystem and Content Staging

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `file.list` | `filesystem` | Y | Y | Y | Verified |
| `file.search` | `filesystem` | Y | Y | Y | Verified |
| `file.read` | `filesystem` | Y | Y | Y | Verified |
| `file.write` | `filesystem` (ext) | Y | Y | Y | Planned |
| `file.hash` | `filesystem` | Y | Y | Y | Verified |
| `file.delete` | `filesystem` | Y | Y | Y | Verified |
| `file.exists` | `filesystem` | Y | Y | Y | Verified |
| `file.permissions.inspect` | `filesystem` (ext) | Y | Y | Y | Planned |
| `file.signature.verify` | `filesystem` (ext) | Y | - | Y | Planned |
| `file.temp.create` | SDK (`yuzu_create_temp_file`) | Y | Y | Y | Verified |
| `content.download` | `http_client` | Y | Y | Y | Verified |
| `content.get` | `http_client` | Y | Y | Y | Verified |
| `content.head` | `http_client` | Y | Y | Y | Verified |
| `content.stage` | `content_dist` | Y | Y | Y | Verified |
| `content.execute` | `content_dist` | Y | Y | Y | Verified |
| `content.list_staged` | `content_dist` | Y | Y | Y | Verified |
| `content.cleanup` | `content_dist` | Y | Y | Y | Verified |
| `storage.free` | `disk_space` | Y | Y | Y | Verified |

`storage.free` (`crossplatform.storage.free`) reports `total_bytes`, `free_bytes`, and `percent_used` for a single volume; the `path` parameter selects the volume (default `C:\` on Windows, `/` on Linux/macOS); the free figure is quota-aware caller headroom (`FreeBytesAvailableToCaller` / `f_bavail`); query each volume in a separate call.

### 14.8 Security and Compliance

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `security.antivirus.status` | `antivirus` | Y | Y | Y | Verified |
| `security.firewall.status` | `firewall` | Y | Y | Y | Verified |
| `security.disk_encryption.status` | `bitlocker` | Y | - | - | Verified |
| `security.disk_encryption.status` | LUKS/FileVault adapter | - | Y | Y | Proposed |
| `security.vulnerability.scan` | `vuln_scan` | Y | Y | Y | Verified |
| `security.event_log.query` | `event_logs` | Y | Y | Y | Verified |
| `security.ioc.check` | `ioc` | Y | Y | Y | Planned |
| `security.certificate.inventory` | `certificates` | Y | Y | Y | Planned |

### 14.9 Registry and WMI (Windows)

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `registry.get_value` | `registry` | Y | - | - | Verified |
| `registry.set_value` | `registry` | Y | - | - | Verified |
| `registry.delete_value` | `registry` | Y | - | - | Verified |
| `registry.delete_key` | `registry` | Y | - | - | Verified |
| `registry.key_exists` | `registry` | Y | - | - | Verified |
| `registry.enumerate_keys` | `registry` | Y | - | - | Verified |
| `registry.enumerate_values` | `registry` | Y | - | - | Verified |
| `registry.get_user_value` | `registry` | Y | - | - | Verified |
| `registry.list_profiles` | `registry` | Y | - | - | Verified |
| `wmi.query` | `wmi` | Y | - | - | Verified |
| `wmi.get_instance` | `wmi` | Y | - | - | Verified |
| `rdp_control.set_state` | `rdp_control` | Y | - | - | Verified |
| `rdp_control.status` | `rdp_control` | Y | - | - | Verified |

### 14.10 Agent Key-Value Storage

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `storage.set` | `storage` | Y | Y | Y | Verified |
| `storage.get` | `storage` | Y | Y | Y | Verified |
| `storage.delete` | `storage` | Y | Y | Y | Verified |
| `storage.list` | `storage` | Y | Y | Y | Verified |
| `storage.clear` | `storage` | Y | Y | Y | Verified |

### 14.11 Workflow Primitives

| Primitive | Backing | Status |
|---|---|---|
| `result.filter` | Server-side (ResponseStore) | Planned |
| `result.group_by` | Server-side (ResponseStore) | Planned |
| `result.sort` | Server-side (ResponseStore) | Planned |
| `result.count` | Server-side (ResponseStore) | Planned |
| `workflow.if` | Server orchestrator | Proposed |
| `workflow.foreach` | Server orchestrator | Proposed |
| `workflow.retry` | Server orchestrator | Proposed |

### 14.12 Trigger Primitives

| Primitive | Backing | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `trigger.interval` | Trigger engine | Y | Y | Y | Verified |
| `trigger.filesystem_change` | Trigger engine | Y | Y | Y | Verified |
| `trigger.service_change` | Trigger engine | Y | Y | - | Verified |
| `trigger.windows_event_log` | Trigger engine | Y | - | - | Verified |
| `trigger.registry_change` | Trigger engine | Y | - | - | Verified |
| `trigger.agent_startup` | Agent core | Y | Y | Y | Verified |

### 14.13 Governance Primitives

| Primitive | Backing | Status |
|---|---|---|
| `scope.estimate_targets` | ScopeEngine | Proposed |
| `scope.resolve_devices` | ScopeEngine | Proposed |
| `approval.submit` | ApprovalManager | Planned |
| `approval.approve` | ApprovalManager | Planned |
| `approval.reject` | ApprovalManager | Planned |
| `audit.emit` | AuditStore | Verified |
| `response.persist` | ResponseStore | Verified |
| `response.aggregate` | ResponseStore | Planned |
| `response.export` | Data export | Planned |
| `policy.check` | Policy engine | Verified |
| `policy.fix` | Policy engine | Verified |
| `policy.evaluate` | Policy engine | Verified |
| `policy.recheck` | Policy engine | Verified |

### 14.14 Device Discovery

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `discovery.arp_scan` | `discovery` | Y | Y | Y | Verified |
| `discovery.ping_sweep` | `discovery` | Y | Y | Y | Verified |
| `discovery.port_scan` | `discovery` | Y | Y | Y | Verified |

### 14.15 Timeline Activity Record (TAR)

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `tar.status` | `tar` | Y | Y | Y | Verified |
| `tar.query` | `tar` | Y | Y | Y | Verified |
| `tar.snapshot` | `tar` | Y | Y | Y | Verified |
| `tar.export` | `tar` | Y | Y | Y | Verified |
| `tar.configure` | `tar` | Y | Y | Y | Verified |
| `tar.collect_fast` | `tar` | Y | Y | Y | Verified |
| `tar.collect_slow` | `tar` | Y | Y | Y | Verified |
| `tar.collect_perf` | `tar` | Y | Y | - | Verified |
| `tar.sql` | `tar` | Y | Y | Y | Verified |
| `tar.rollup` | `tar` | Y | Y | Y | Verified |
| `tar.compatibility` | `tar` | Y | Y | Y | Verified |
| `tar.fleet_snapshot` | `tar` | Y | Y | Y | Active |

**`tar.compatibility`** -- Emit the live OS compatibility matrix for every registered capture source (process, tcp, service, user, perf, plus the opt-in procperf, netqual, module, arp, dns). Returns one `header|...` line followed by N `row|source|os|status|capture_method|notes` lines. Status values: `supported` | `constrained` | `planned` | `unsupported`. Read-only static metadata; safe to call at any frequency. Use to verify which sources are wired on the current agent OS before configuring `network_capture_method`; the mechanism actually in force is reported as `network_capture_method_effective` by the `status` action (always `polling` today).

**`tar.collect_perf`** -- Record one device performance sample (CPU/memory/disk/network) into `$Perf_Live`, and — when `procperf_enabled` is set (opt-in, off by default) — one per-application top-N sample into `$ProcPerf_Live` on the same tick (output line `tar|collect_procperf|N|...`). Trigger-driven on the `perf_interval_seconds` cadence (default 30 s; Windows and Linux — macOS records nothing until its collector lands); a manual invocation forces one immediate sample. Note: a tick whose core counter read fails (e.g. a hardened container masking `/proc/stat` on Linux, or an NT-counter read failure on Windows) reports `counters_unavailable` on any OS the registry lists as supported for `perf`/`procperf`, and `unsupported_platform` only where no perf collector exists (macOS today) — so a supported platform whose reads are failing is distinguishable from an unsupported one. The per-source streak is in `tar.status` (`perf_last_status` / `perf_consecutive_failures`, and identically `procperf_last_status` / `procperf_consecutive_failures`). The first sample after agent start is a baseline (records no row). See [the TAR user manual](user-manual/tar.md) for the perf/procperf tiers and their `perf_enabled` / `procperf_enabled` / `perf_interval_seconds` configuration.

**`tar.fleet_snapshot`** -- Enumerate running processes, open network connections, and host-bound IPs and emit a single `fleet_snapshot.v1` JSON document. Each list is capped at 4096 entries; truncation is flagged via `truncated_processes` / `truncated_connections`. Cmdlines are redacted per the active redaction patterns (defaults always apply). When the operator has paused the `process` or `tcp` source, the corresponding list is empty and `process_source_paused` / `tcp_source_paused` markers appear in the document. Consumed by the server-side `FleetTopologyStore` for the `/viz/fleet` 3D renderer (PR ladder 1-11). Dispatched on demand by the server at the topology cache TTL (default 60 s); not typically invoked manually.

### 14.16 Test and Debug

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `testing.chargen.start` | `chargen` | Y | Y | Y | Verified |
| `testing.chargen.stop` | `chargen` | Y | Y | Y | Verified |

**`testing.chargen.start`** -- Start an RFC 864 character generator session for throughput benchmarking. Generates a continuous stream of printable ASCII characters to measure agent-to-server data-plane performance.

**`testing.chargen.stop`** -- Stop all running chargen sessions on the target device.
