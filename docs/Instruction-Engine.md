# Yuzu Instruction Engine — Design & Architecture

**Document status:** Living design document — implementation guide
**Basis:** `dev` branch at commit `dce7f7c` (2026-03-18)
**Audience:** Yuzu contributors and integrators

---

## 1. Epistemic Status

### Verified from implementation

- **Phase 0** complete — HTTPS, OTA updates (`agents/core/src/updater.cpp`), secure temp files (`sdk/include/yuzu/plugin.h`), SDK utilities (`yuzu_table_to_json`, `yuzu_json_to_table`, `yuzu_split_lines`, `yuzu_generate_sequence`).
- **Phase 1** data infrastructure complete — `ResponseStore` (PostgreSQL, TTL-based cleanup, query with filtering/pagination, **aggregation engine** with GROUP BY + COUNT/SUM/AVG/MIN/MAX), `AuditStore` (structured events with principal/action/target/result), `TagStore` (agent-synced and server-set tags, validation), `ScopeEngine` (494 LOC recursive-descent parser, 9 operators, AND/OR/NOT combinators, wildcard LIKE, case-insensitive matching), **data export** (CSV/JSON export with RFC 4180 compliance, generic JSON-to-CSV conversion). All in `server/core/src/`.
- **Phase 2** implemented — `InstructionStore` (full CRUD with YAML source storage, parameter/result schema fields, JSON import/export, InstructionSet CRUD with cascade delete), `ExecutionTracker` (create/query/get executions, per-agent status tracking with UPSERT, aggregate count refresh, auto-status transitions, rerun with failed-only targeting, cancel), `ApprovalManager` (submit/approve/reject with ownership validation — reviewer != submitter, pending count), `ScheduleEngine` (CRUD with frequency validation, evaluate_due for firing, advance_schedule with per-type next-execution computation). All methods backed by PostgreSQL (`InstructionStore`: ADR-0058; `ScheduleEngine`/`ApprovalManager`/`ExecutionTracker`: ADR-0065).
- **30 plugins** across `agents/plugins/`: 24 cross-platform, 4 Windows-only (`bitlocker`, `msi_packages`, `sccm`, `windows_updates`), 2 test/debug (`chargen`, `example`).
- **Plugin ABI** at v4 (`YUZU_PLUGIN_ABI_VERSION`), minimum supported v1 (`YUZU_PLUGIN_ABI_VERSION_MIN`): `YuzuPluginDescriptor` with `abi_version`, `name`, `version`, `description`, `actions[]`, `init`, `shutdown`, `execute`, plus the ABI4 per-OS `YuzuActionDescriptor` capability-matrix fields (append-only; see `sdk/README.md`'s ABI compatibility table and §14.3 below).
- **Wire protocol**: gRPC/Protobuf — `CommandRequest` (plugin + action + parameters + expires_at), `CommandResponse` (status enum: RUNNING/SUCCESS/FAILURE/TIMEOUT/REJECTED, streaming output).
- **Scope DSL grammar**: `expr → or_expr → and_expr → not_expr → primary → condition`. Operators: `==`, `!=`, `LIKE`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`. Max nesting depth 10.
- **Dashboard** — HTMX-based instruction management page (`instruction_ui.cpp`) with tabs for Definitions, Executions, Schedules, Approvals. All load fragments via `hx-get`.

### Proposed in this document

- Unified substrate primitive table (Section 7) — consolidation of per-OS tables.
- Expression language evolution path (Section 8) — extend scope DSL now, adopt CEL for policy in Phase 5.
- Error model with 4-category taxonomy (Section 9).
- Concurrency model — only `per-device` is enforced in practice (Section 10, corrected 2026-08-31 per ADR-1007).
- YAML authoring in dashboard (Section 11).
- File upload patterns (Section 12).
- ProductPack Ed25519 trust chain (Section 13).
- Agent compatibility and rollback (Section 14).
- Legacy command shim (Section 15).
- `service.set_start_mode` primitive (Section 16).
- Scale design for 100K+ agents (Section 17).

---

## 2. Executive Summary

Yuzu's **execution substrate is strong**: 30 plugins, stable C ABI, gRPC streaming, mTLS, and OTA updates are production-ready. The **data infrastructure is built**: response storage, audit logging, device tagging, and scope-based targeting are implemented and tested. The **content plane is scaffolded**: instruction definitions, execution tracking, approvals, and scheduling have struct definitions and DDL but no business logic.

The next step is to wire the scaffolded components into a governed instruction lifecycle — YAML-defined instruction definitions with typed parameter and result schemas, executed through the existing `CommandRequest` wire protocol, tracked by `ExecutionTracker`, stored by `ResponseStore`, and audited by `AuditStore`.

This document is the architectural blueprint for that work.

---

## 3. Current-State Assessment

| Component | File(s) | Status | Notes |
|---|---|---|---|
| **InstructionStore** | `instruction_store.hpp` | Stub | DDL, CRUD signatures, `InstructionDefinition` struct (id, name, version, type, plugin, action, description, enabled, instruction_set_id, gather_ttl, response_ttl, created_by, timestamps). Import/export JSON signatures defined. |
| **ExecutionTracker** | `execution_tracker.hpp` | Stub | `Execution` struct (id, definition_id, status, scope_expression, parameter_values, dispatched_by, agent counts, parent_id, rerun_of). `AgentExecStatus` struct (agent_id, status, timestamps, exit_code, error_detail). `ExecutionSummary` with progress_pct. Rerun and cancel signatures. |
| **ApprovalManager** | `approval_manager.hpp` | Stub | `Approval` struct (id, definition_id, status, submitted_by, reviewed_by, review_comment, scope_expression). Query, approve, reject, pending_count signatures. |
| **ScheduleEngine** | `schedule_engine.hpp` | Stub | `InstructionSchedule` struct (id, name, definition_id, frequency_type, interval_minutes, time_of_day, day_of_week, day_of_month, scope_expression, requires_approval, enabled, next/last execution, execution_count). CRUD + enable/disable signatures. |
| **ScopeEngine** | `scope_engine.cpp` (494 LOC) | **Real** | Full recursive-descent parser. 9 comparison operators. AND/OR/NOT combinators. Wildcard LIKE matching. Numeric comparison with fallback. `AttributeResolver` callback for evaluation. |
| **ResponseStore** | `response_store.hpp` | **Real** | PostgreSQL-backed (ADR-0039). `StoredResponse` with instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at. Query with agent/status/time filtering and pagination. Configurable retention (default 90 days). Background cleanup thread. |
| **AuditStore** | `audit_store.hpp` | **Real** | PostgreSQL-backed (ADR-0040). `AuditEvent` with timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, user_agent, session_id, result. Query with filtering. Retention default 365 days. Background cleanup. |
| **TagStore** | `tag_store.hpp` | **Real** | PostgreSQL-backed (ADR-0050, schema `tag_store`). `DeviceTag` with agent_id, key, value, source ("agent"/"server"/"api"/"mcp"), updated_at. CRUD, sync from agent heartbeat, validation (key 64 chars, value 448 bytes). `agents_with_tag` for scope queries. |
| **Instruction UI** | `instruction_ui.cpp` | **Real** | HTMX page with 4 tabs (Definitions, Executions, Schedules, Approvals). Loads fragments via `hx-get`. Dark theme consistent with dashboard. |

**Overall progress:** 150/184 capabilities done (82%). All 7 phases complete (72/72 issues). Instruction engine fully implemented.

---

## 4. Design Principles

1. **Substrate, not scripts.** Expose stable builtin primitives; keep OS-specific syscalls inside plugin adapters. Content authors should never need to write shell commands.

2. **Everything is an InstructionDefinition.** Ad-hoc commands, scheduled tasks, policy checks, and remediation actions all flow through the same definition → execution → response pipeline.

3. **Cross-platform by default.** Primitives target all three OSes. Platform-specific behavior is declared in the definition's `platforms` field and handled by the plugin layer.

4. **Typed end-to-end.** Parameter schemas validate input before dispatch. Result schemas type output for downstream consumption (ClickHouse, Splunk, CSV export). No untyped string bags at the content layer.

5. **Governed execution.** Every state-changing action can require approval. Every execution is audited. Every response is persisted. The platform enforces organizational policy, not just technical capability.

6. **Composition over complexity.** InstructionSets group definitions. PolicyFragments compose check+fix. Policies bind fragments to triggers. ProductPacks bundle everything for distribution. Each layer adds governance without adding new execution semantics.

7. **Plugin ABI is sacred.** The C boundary in `plugin.h` must remain stable across compiler and platform upgrades. All content-layer evolution happens above this line.

---

## 5. Content Model

```
ProductPack
 └── InstructionSet[]
      └── InstructionDefinition[]
           ├── Parameter Schema
           ├── Result Schema
           └── Execution Spec (plugin + action + defaults)

PolicyFragment
 ├── Check: ref → InstructionDefinition
 ├── Compliance expression
 ├── Fix: ref → InstructionDefinition
 └── PostCheck: ref → InstructionDefinition

Policy
 ├── Scope (device targeting)
 ├── Fragment ref + parameter bindings
 ├── Trigger refs
 └── Rollout strategy

TriggerTemplate
 ├── Source type (interval, file, service, event_log, registry, startup)
 ├── Parameter schema
 └── Debounce config
```

**Hierarchy:** `ProductPack` → `InstructionSet` → `InstructionDefinition`. A definition can exist without a set (standalone) and without a pack (user-created). Sets are the permission boundary. Packs are the distribution boundary.

---

## 6. YAML Schemas

### 6.1 InstructionDefinition

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
    concurrency: per-device              # only per-device is enforced — see Section 10
    stagger:
      maxDelaySeconds: 0                 # 0 = no stagger
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
status:
  phase: proposed
```

### 6.2 InstructionSet

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

### 6.3 PolicyFragment

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

### 6.4 Policy

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

> **Implementation caveat (added 2026-09-10, Gate-of-record pass 4 item 4):** the `triggers:` block above (`ref: trigger.interval.five_minutes`, `ref: trigger.service_status_changed`) shows the **designed** `TriggerTemplate`-reference model — `status: phase: proposed` on this same example marks the whole document as architecture, not a literal schema every field of which is shipped. The `PolicyStore` implementation live on `dev` today does not resolve `ref:`-style trigger template lookups at all; it reads an inline `type:` + `interval_seconds:` pair per trigger entry, and **only `type: interval` has any effect on evaluation cadence** — a `service_status_changed`-shaped trigger (by any syntax) is accepted and stored but does not suppress or gate evaluation; the policy still evaluates on the interval fallback (default 3600s) against its full scope. See `docs/user-manual/policy-engine.md` § Trigger Configuration for the exact shipped schema, its "Common mistake" callout, and tracking issue #4244.

### 6.5 TriggerTemplate

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

### 6.6 ProductPack

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

## 7. Unified Substrate Primitive Table

This table replaces the previous per-OS tables (Sections 9, 10, 11 of the original document) with a single cross-platform view. Each row is a stable builtin name that content authors target. Platform availability is marked per-column.

**Status key:**
- **Verified** — grounded in existing plugin code in `agents/plugins/`
- **Planned** — in roadmap with GitHub issue
- **Proposed** — recommended in this document

### 7.1 System and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `system.info` | `os_info` | Y | Y | Y | Verified | OS name, version, build, kernel |
| `system.status` | `status` | Y | Y | Y | Verified | Agent uptime, resource usage |
| `device.identity` | `device_identity` | Y | Y | Y | Verified | UUID, hostname, domain, FQDN |
| `hardware.inventory` | `hardware` | Y | Y | Y | Verified | CPU, RAM, disk geometry |
| `device.tags.get` | `tags` | Y | Y | Y | Verified | Read scopable/freeform tags |
| `device.tags.set` | `tags` | Y | Y | Y | Verified | Write scopable/freeform tags |
| `agent.health` | `diagnostics` | Y | Y | Y | Verified | Plugin list, uptime, resource stats |
| `agent.restart` | `agent_actions` | Y | Y | Y | Verified | Self-restart |
| `agent.sleep` | agent core | Y | Y | Y | Planned | Pause agent for N seconds |
| `agent.log.read` | `diagnostics` | Y | Y | Y | Planned | Tail agent log, set log level |

### 7.2 Process and Execution

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `process.list` | `processes` | Y | Y | Y | Verified | PID, name, user, CPU, memory |
| `process.inspect` | `procfetch` | Y | Y | Y | Verified | Formatted view with exe hash |
| `process.kill` | `processes` | Y | Y | Y | Verified | Signal/terminate by PID |
| `process.start` | `script_exec` | Y | Y | Y | Proposed | Spawn process (wraps script_exec) |
| `script.run` | `script_exec` | Y | Y | Y | Verified | Inline or file-based script execution |
| `command.run` | `script_exec` | Y | Y | Y | Verified | OS command execution |

### 7.3 Services and Daemons

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `service.list` | `services` | Y | Y | Y | Verified | Name, state, startup type |
| `service.inspect` | `services` | Y | Y | Y | Proposed | Detail view for single service |
| `service.start` | `services` | Y | Y | Y | Verified | Start named service |
| `service.stop` | `services` | Y | Y | Y | Verified | Stop named service |
| `service.restart` | `services` | Y | Y | Y | Verified | Restart named service |
| `service.set_start_mode` | `services` | Y | Y | Y | Proposed | See Section 16 for details |

### 7.4 User, Session, and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `user.list` | `users` | Y | Y | Y | Verified | Local user accounts |
| `user.logged_on` | `users` | Y | Y | Y | Verified | Currently logged-on users |
| `user.group_membership` | `users` (ext) | Y | Y | Y | Planned | Local group members |
| `session.list` | `users` (ext) | Y | Y | Y | Planned | RDP, console, SSH sessions |
| `session.active_user` | `users` (ext) | Y | Y | Y | Planned | Primary/console user |
| `session.notify` | `interaction` | Y | - | - | Planned | Toast notification to user |
| `session.prompt` | `interaction` | Y | - | - | Planned | Yes/No dialog |

### 7.5 Network

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `network.config.get` | `network_config` | Y | Y | Y | Verified | Interfaces, IPs, ARP table |
| `network.route.list` | `network_config` | Y | Y | Y | Verified | Routing table |
| `network.connection.list` | `netstat` | Y | Y | Y | Verified | TCP/UDP connections |
| `network.socket.owner` | `netstat` (`attribution` action) | Y | Y | Y | Verified | Socket → process mapping (folded from the retired sockwho plugin, #3403) |
| `network.dns.flush` | `network_actions` | Y | Y | Y | Verified | Flush DNS cache |
| `network.diagnostics.run` | `network_diag` | Y | Y | Y | Verified | Ping, traceroute |
| `network.adapter.enable` | `network_actions` | Y | Y | Y | Verified | Enable network adapter |
| `network.adapter.disable` | `network_actions` | Y | Y | Y | Verified | Disable network adapter |
| `network.quarantine` | `quarantine` | Y | Y | - | Planned | Isolate device (Phase 3) |

### 7.6 Software and Patching

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `software.inventory` | `installed_apps` | Y | Y | Y | Verified | Installed applications |
| `software.package.inventory` | `msi_packages` | Y | - | - | Verified | MSI package details |
| `software.uninstall` | `software_actions` | Y | Y | Y | Verified | Uninstall by identifier |
| `software.install` | content staging | Y | Y | Y | Planned | Stage + silent install |
| `software.update` | pkg adapter | Y | Y | Y | Proposed | OS package manager update |
| `software.sccm.query` | `sccm` | Y | - | - | Verified | SCCM client integration |
| `patch.inventory` | `windows_updates` | Y | - | - | Verified | Installed/pending updates |
| `patch.install` | `patch` | Y | Y | Y | Planned | Orchestrated patch deploy |
| `patch.scan` | `vuln_scan` | Y | Y | Y | Verified | NVD-based vulnerability scan |

### 7.7 Filesystem and Content Staging

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `file.list` | `filesystem` | Y | Y | Y | Verified | Directory listing |
| `file.search` | `filesystem` | Y | Y | Y | Verified | Search by name pattern |
| `file.read` | `filesystem` | Y | Y | Y | Verified | Read file contents |
| `file.write` | `filesystem` (ext) | Y | Y | Y | Planned | Write/append text |
| `file.hash` | `filesystem` | Y | Y | Y | Verified | SHA-256 hash computation |
| `file.delete` | `filesystem` | Y | Y | Y | Verified | Delete file |
| `file.exists` | `filesystem` | Y | Y | Y | Verified | Path existence check |
| `file.permissions.inspect` | `filesystem` (ext) | Y | Y | Y | Planned | ACL/permission enumeration |
| `file.signature.verify` | `filesystem` (ext) | Y | - | Y | Planned | Authenticode / codesign |
| `file.temp.create` | SDK (`yuzu_create_temp_file`) | Y | Y | Y | Verified | Secure temp file (0600/owner-only DACL) |
| `content.download` | `http_client` | Y | Y | Y | Planned | HTTP GET with hash verify |
| `content.upload` | `http_client` | Y | Y | Y | Planned | Upload file to server |
| `content.stage` | `content_dist` | Y | Y | Y | Planned | Download manifest to staging dir |
| `content.execute` | `content_dist` | Y | Y | Y | Planned | Stage + execute + cleanup |

### 7.8 Security and Compliance

| Primitive | Backing Plugin | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `security.antivirus.status` | `antivirus` | Y | Y | Y | Verified | AV product, definitions age |
| `security.firewall.status` | `firewall` | Y | Y | Y | Verified | Firewall state and rules |
| `security.disk_encryption.status` | `bitlocker` | Y | - | - | Verified | BitLocker status (Windows) |
| `security.disk_encryption.status` | LUKS/FileVault adapter | - | Y | Y | Proposed | Linux LUKS, macOS FileVault |
| `security.vulnerability.scan` | `vuln_scan` | Y | Y | Y | Verified | NVD-backed scan |
| `security.event_log.query` | `event_logs` | Y | Y | Y | Verified | Event/journal log query |
| `security.ioc.check` | `ioc` | Y | Y | Y | Planned | Hash/IP/domain IOC matching |
| `security.certificate.inventory` | `certificates` | Y | Y | Y | Planned | Enumerate system cert stores |

### 7.9 Workflow Primitives

| Primitive | Backing | Status | Notes |
|---|---|---|---|
| `result.filter` | Server-side (ResponseStore) | Planned | Filter response rows by expression |
| `result.group_by` | Server-side (ResponseStore) | Planned | Group + aggregate |
| `result.sort` | Server-side (ResponseStore) | Planned | Multi-column sort |
| `result.count` | Server-side (ResponseStore) | Planned | Count matching rows |
| `workflow.if` | Server orchestrator | Proposed | Branch on expression |
| `workflow.foreach` | Server orchestrator | Proposed | Iterate over result rows |
| `workflow.retry` | Server orchestrator | Proposed | Retry with backoff |

### 7.10 Trigger Primitives

| Primitive | Backing | Win | Linux | macOS | Status | Notes |
|---|---|:---:|:---:|:---:|---|---|
| `trigger.interval` | Trigger engine | Y | Y | Y | Planned | Timer-based (min 30s) |
| `trigger.filesystem_change` | Trigger engine | Y | Y | Y | Planned | ReadDirectoryChangesW / inotify / FSEvents |
| `trigger.service_change` | Trigger engine | Y | Y | - | Planned | SCM / systemd notifications |
| `trigger.windows_event_log` | Trigger engine | Y | - | - | Planned | XPath filter on event log |
| `trigger.registry_change` | Trigger engine | Y | - | - | Planned | Registry key notification |
| `trigger.agent_startup` | Agent core | Y | Y | Y | Planned | Fire on agent boot |

### 7.11 Governance Primitives

| Primitive | Backing | Status | Notes |
|---|---|---|---|
| `scope.estimate_targets` | ScopeEngine | Proposed | Preview device count before dispatch |
| `scope.resolve_devices` | ScopeEngine | Proposed | Return matched agent IDs |
| `approval.submit` | ApprovalManager | Planned | Submit execution for approval |
| `approval.approve` | ApprovalManager | Planned | Approve pending execution |
| `approval.reject` | ApprovalManager | Planned | Reject pending execution |
| `audit.emit` | AuditStore | Verified | Log structured audit event |
| `response.persist` | ResponseStore | Verified | Store command response |
| `response.aggregate` | ResponseStore | Planned | Aggregate across agents |
| `response.export` | Data export | Planned | CSV/JSON export |
| `policy.check` | Policy engine | Planned | Evaluate compliance |
| `policy.fix` | Policy engine | Planned | Execute remediation |
| `policy.evaluate` | Policy engine | Planned | Full check → fix → postcheck cycle |
| `policy.recheck` | Policy engine | Planned | Force re-evaluation |

### 7.12 OS-Specific Native Adapters

These are internal implementation details behind the stable builtins — not directly exposed to content authors.

**Windows:**
Service Control Manager, Event Log API, Registry APIs, WMI/CIM, ReadDirectoryChangesW, Task Scheduler, Certificate Store / CryptoAPI / CNG, Firewall APIs (NetSecurity), BitLocker WMI, WinHTTP / BITS, session/notification APIs, SetupAPI / PnP.

**Linux:**
systemd / D-Bus, inotify, procfs / sysfs, journald / syslog, package managers (apt, dnf, yum, zypper), nftables / iptables, POSIX account/group management, certificate store / OpenSSL, LUKS / dm-crypt.

**macOS:**
launchd, FSEvents, unified logging, system profiler, softwareupdate, codesign / notarization, FileVault, Keychain, user notification frameworks.

---

## 8. Expression Language

### 8.1 Current State: Scope DSL

The scope engine (`server/core/src/scope_engine.cpp`, 494 LOC) implements a recursive-descent parser for device targeting expressions.

**Grammar:**
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

**Examples:**
```
ostype == "windows" AND tag:env == "production"
hostname LIKE "web-*" OR hostname LIKE "api-*"
arch IN ("x86_64", "aarch64") AND NOT tag:quarantined == "true"
agent_version >= "0.9.0"
```

**Features:**
- Case-insensitive keyword matching (AND, OR, NOT, LIKE, IN, CONTAINS)
- Wildcard LIKE with `*` and `?` globbing
- Numeric comparison with `std::from_chars` fallback to `std::stod` (Apple libc++ compat)
- Case-insensitive substring search via CONTAINS
- Max nesting depth of 10
- `AttributeResolver` callback decouples parsing from data access

### 8.2 Planned Extensions to Scope DSL

These extensions keep the current parser and add operators as needed:

| Extension | Syntax | Use Case |
|---|---|---|
| `MATCHES` | `hostname MATCHES "^web-\\d+$"` | Regex matching for complex patterns |
| `EXISTS` | `EXISTS tag:env` | Tag presence check (no value comparison) |
| `len()` | `len(tag:name) > 5` | String length for validation |
| `startswith()` | `startswith(hostname, "web-")` | Prefix check (more readable than LIKE) |

Implementation: add new `TokenType` variants and `CompOp` cases. The parser architecture (tokenizer → recursive descent → AST → evaluator) supports these without structural changes.

### 8.3 CEL Adoption — Implemented

**Status:** Implemented. A CEL-compatible expression evaluator was built from scratch in `server/core/src/cel_eval.cpp` (~1000 LOC), following the same hand-rolled recursive-descent pattern as the existing `scope_engine.cpp` and the prior `compliance_eval.cpp`.

**Approach:** Google's `cel-cpp` library is not available as a vcpkg port and has a heavy dependency chain (abseil, protobuf, RE2, ANTLR4, FlatBuffers) that would be impractical to build from source across all 4 CI platforms. Instead, a CEL-compatible subset was implemented with zero new dependencies — only C++23 standard library facilities.

**Capabilities:** Typed evaluation (null, bool, int64, double, string, timestamp, duration, list), arithmetic operators, comparison operators, logical operators (`&&`/`||`/`!`), ternary (`?:`), `in` operator with list literals, string methods (`size`, `startsWith`, `endsWith`, `contains`, `matches`), timestamp/duration arithmetic, type casting functions, and `has()` for field presence. Full backward compatibility with the previous keyword-based syntax (AND/OR/NOT/contains/startswith).

**Integration:** `compliance_eval.cpp` delegates to `cel::evaluate_bool()` and `cel::validate()`. All callers (policy_store, workflow_engine, server.cpp ConditionEvalFn) work unchanged. Legacy expressions are automatically migrated to CEL syntax at fragment creation time via `cel::migrate_expression()`.

**Where CEL applies:**
- `spec.compliance.expression` in PolicyFragments
- `spec.fix.when` conditional expressions
- `spec.rollout.condition` for staged rollouts
- `WorkflowStep.condition` for conditional workflow steps

**Where the scope DSL stays:**
- All device targeting (`spec.scope.selector`)
- `ScopeEngine` evaluation in dispatch path
- Dashboard filter expressions

---

## 9. Error Model and Partial Failure

### 9.1 Error Code Taxonomy

Errors are categorized into four domains with non-overlapping numeric ranges:

#### 1xxx — Plugin Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 1001 | `PLUGIN_ACTION_NOT_FOUND` | Plugin does not support the requested action | Never |
| 1002 | `PLUGIN_PARAM_INVALID` | Parameter validation failed | Never |
| 1003 | `PLUGIN_PERMISSION_DENIED` | OS-level permission denied (e.g., non-admin) | Never |
| 1004 | `PLUGIN_RESOURCE_MISSING` | Target resource does not exist (service, file, etc.) | Never |
| 1005 | `PLUGIN_OPERATION_FAILED` | Action executed but failed (non-zero exit, exception) | Transient: yes; Deterministic: no |
| 1006 | `PLUGIN_CRASH` | Plugin segfaulted or threw unhandled exception | Never |
| 1007 | `PLUGIN_TIMEOUT` | Plugin did not complete within gather TTL | Yes (once) |

#### 2xxx — Transport Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 2001 | `TRANSPORT_DISCONNECTED` | Agent lost connection during execution | Always |
| 2002 | `TRANSPORT_STREAM_ERROR` | gRPC stream broken mid-response | Always |
| 2003 | `TRANSPORT_RESPONSE_TOO_LARGE` | Response exceeds max message size | Never |

#### 3xxx — Orchestration Errors

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

#### 4xxx — Agent Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 4001 | `AGENT_PLUGIN_NOT_LOADED` | Required plugin not available on agent | Never |
| 4002 | `AGENT_SHUTTING_DOWN` | Agent is in shutdown sequence | Yes (on reconnect) |
| 4003 | `AGENT_VERSION_INCOMPATIBLE` | Agent version below `minAgentVersion` | Never |

### 9.2 Retry Semantics

| Category | Default Retry | Max Attempts | Backoff |
|---|---|---|---|
| Transport (2xxx) | Always | 3 | Exponential (1s, 2s, 4s) |
| Transient plugin (1005, 1007) | If `retryable: true` in definition | 2 | Linear (5s) |
| Deterministic plugin (1001-1004, 1006) | Never | 0 | — |
| Agent (4001-4003) | Never (except 4002 on reconnect) | 1 | — |
| Orchestration (3001-3005) | Per-code as noted | — | — |

### 9.3 Partial Failure

Each InstructionDefinition can specify:

```yaml
spec:
  execution:
    minSuccessPercent: 100    # default: all agents must succeed
    # or: 0 = best-effort, 80 = at least 80% must succeed
```

**Aggregate status computation:**

| Condition | Status |
|---|---|
| All agents succeeded | `succeeded` |
| ≥ minSuccessPercent succeeded | `completed` |
| < minSuccessPercent succeeded, all responded | `failed` |
| Some agents haven't responded, TTL not expired | `running` |
| TTL expired, some agents never responded | `timed_out` |
| Operator cancelled | `cancelled` |
| Mixed success/failure within threshold | `partial` |

Per-agent tracking uses the `AgentExecStatus` struct already defined in `execution_tracker.hpp`:
```cpp
struct AgentExecStatus {
    std::string agent_id;
    std::string status;          // dispatched, running, success, failure, timeout, rejected
    int64_t     dispatched_at;
    int64_t     first_response_at;
    int64_t     completed_at;
    int         exit_code;
    std::string error_detail;    // structured error code + message
};
```

---

## 10. Concurrency Model

**Corrected 2026-08-31 (ADR-1007) — only `per-device` is actually enforced.** See
`docs/yaml-dsl-spec.md` §12 for the full corrected model (mode-by-mode status, why enforcement is
server-side rather than agent-side, the `plugin: server`-class catalog-definition caveat, what
remains unenforced and why). Summary below.

### 10.1 Modes

| Mode | Enforcement | Scope | Status |
|---|---|---|---|
| `per-device` | Server-side | One execution of this definition per device at a time | **Enforced** (default; 191 real shipped definitions use it). |
| `per-definition` | None | — | **Not enforced** — used only on catalog-only definitions with no live dispatch path. |
| `per-set` | None | — | **Not enforced, unspecified** — no grouping key defined anywhere. Zero real usage. |
| `global:<N>` | None | — | **Not enforced** — not used in any shipped definition. |
| `unlimited` | None | No limits | No enforcement needed. |

### 10.2 Implementation

**`per-device` (the only enforced mode):** enforced server-side (not agent-side as originally
designed — `CommandRequest` carries no `definition_id`, and an agent-side design would need a
proto + gateway change with no correctness benefit — see ADR-1007). The server holds a claim on
`(definition_id, agent_id)` in a dedicated Postgres table (`execution_tracker.concurrency_claims`,
race-free via a partial unique index) at dispatch time, excludes any agent already holding one, and
releases the claim on that agent's terminal status. No wait queue exists (agent- or server-side) —
an excluded agent is simply not dispatched to; the caller may retry once the in-flight execution
completes. Error code `3003` is registered for this condition but not yet surfaced through the
dispatch response (ADR-1007 follow-up). Not covered: raw MCP/REST dispatch (no `definition_id` in
scope) and fleet-broadcast dispatch of a `per-device` definition.

**Configuration in YAML:**
```yaml
spec:
  execution:
    concurrency: per-device          # default — the only mode actually enforced
    # concurrency: unlimited         # no limits (also the practical effect of any unsupported value)
```

---

## 11. YAML Authoring in Dashboard

### 11.1 Storage

Instruction definitions are stored in the `InstructionStore` PostgreSQL schema (ADR-0058) with:
- `yaml_source` — `TEXT` column containing the original YAML document (source of truth)
- Denormalized columns (`name`, `version`, `type`, `plugin`, `action`, `enabled`, etc.) parsed from YAML for efficient queries

On save, the server parses `yaml_source`, validates against the JSON Schema, and populates the denormalized columns. The YAML is always preserved verbatim.

### 11.2 UI Modes

The instruction management page (`instruction_ui.cpp`) will offer two editing modes:

**Form mode** (default for simple definitions):
- Input fields for name, description, plugin, action, type
- Parameter builder (add/remove parameter rows with name, type, default, validation)
- Result column builder
- Form submission generates YAML on the server side

**YAML mode** (for power users):
- Textarea with the full YAML document
- Syntax highlighting via a lightweight client-side library (e.g., CodeMirror 6)
- Server-side validation on save with error messages
- Toggle between form and YAML mode preserves content

### 11.3 Validation Pipeline

```
User input (form or YAML)
    ↓
YAML parse (yaml-cpp or nlohmann/json YAML mode)
    ↓
JSON Schema validation (nlohmann/json's json_schema_validator)
    ↓
Semantic validation:
  - Plugin exists in registered plugin list
  - Action exists in plugin's actions array
  - Parameter types match supported set (string, bool, int32, int64, datetime, guid)
  - Result column types match supported set
  - Referenced InstructionSet exists (if specified)
    ↓
Store: YAML → yaml_source column, parsed fields → denormalized columns
    ↓
Audit: log "definition.create" or "definition.update" event
```

### 11.4 Import/Export

**Import:** `POST /api/v1/definitions/import` accepts `multipart/form-data` with `.yaml` or `.json` files. Each file is validated through the pipeline above. Returns success/failure per file.

**Export:** `GET /api/v1/definitions/{id}/export?format=yaml` returns the `yaml_source` verbatim. `format=json` returns the parsed JSON representation.

**Pattern:** Follow the existing HTMX fragment pattern from `settings_ui.cpp` — form submissions use `hx-post` with `hx-swap="innerHTML"` to update a feedback div without full page reload.

---

## 12. File Upload

### 12.1 Existing Pattern

The server already handles multipart file uploads for:
- TLS certificate PEM upload (Settings page)
- OTA agent binary upload (Settings page)

Both use cpp-httplib's built-in multipart parser via `server.Post()` with `req.get_file_value()`.

### 12.2 New Upload Endpoints

| Endpoint | Purpose | Max Size | Validation |
|---|---|---|---|
| `POST /api/v1/definitions/import` | YAML/JSON definition files | 1 MB | YAML parse + JSON Schema |
| `POST /api/v1/packs/import` | ProductPack archives (tar.zst) | 100 MB (configurable) | Signature verify → extract → per-file SHA-256 |
| `POST /api/v1/content/upload` | Content files for staging | 500 MB (configurable) | SHA-256 verification |

### 12.3 Implementation

Size limits are set per-endpoint using cpp-httplib's `set_payload_max_length`:

```cpp
// In server setup, after creating the httplib::Server:
svr.set_payload_max_length(1 * 1024 * 1024);  // global 1MB default

// Override per-route by checking Content-Length in handler:
svr.Post("/api/v1/content/upload", [](const auto& req, auto& res) {
    if (req.body.size() > 500 * 1024 * 1024) {
        res.status = 413;
        return;
    }
    // ... handle upload
});
```

**Validation order:**
1. Size check (reject before reading body if possible)
2. Content-Type check (`multipart/form-data`)
3. File extension check (`.yaml`, `.json`, `.tar.zst`, etc.)
4. Parse/verify content
5. Store to disk or database
6. Audit log the upload event

---

## 13. ProductPack Trust Chain

### 13.1 Algorithm Choice: Ed25519

- **Fast:** ~70,000 signatures/sec on commodity hardware
- **Small:** 32-byte keys, 64-byte signatures
- **No padding attacks:** Unlike RSA, Ed25519 has a single valid signature per message
- **Widely supported:** libsodium, OpenSSL 1.1.1+, BoringSSL

### 13.2 Key Hierarchy

```
Org Root Key (Ed25519)
    │
    │  Signs pack-signing key certificates
    │
    ├── Pack-Signing Key A (Ed25519)
    │       │
    │       └── Signs pack manifests
    │
    └── Pack-Signing Key B (Ed25519)
            │
            └── Signs pack manifests (rotation)
```

**Org root key:** Generated once, stored in HSM (PKCS#11) for production or PEM file for development. Never directly signs packs. Only signs pack-signing key certificates.

**Pack-signing key:** Used to sign pack manifests. Can be rotated by generating a new key and having the root key sign its certificate. Old keys are added to the revocation list.

### 13.3 Pack Signing Flow

```
1. Author creates pack contents (YAML definitions, policies, etc.)
2. Build tool generates manifest.json:
   - SHA-256 hash of each file in the pack
   - Pack metadata (id, version, publisher, compatibility)
3. Sign manifest hash with pack-signing key:
   signature = Ed25519_Sign(signing_key, SHA256(manifest.json))
4. Bundle into tar.zst:
   manifest.json
   manifest.sig      (64-byte Ed25519 signature)
   signing-key.der   (pack-signing key certificate, signed by root)
   definitions/
   policies/
   triggers/
   docs/
```

### 13.4 Import Verification Flow

```
1. Extract tar.zst to temp directory
2. Load signing-key.der
3. Verify signing key certificate against org root key (or trust store)
4. Check signing key not in revocation list (JSON CRL)
5. Load manifest.sig
6. Verify: Ed25519_Verify(signing_key, SHA256(manifest.json), manifest.sig)
7. For each file in manifest.json:
   - Compute SHA-256 of extracted file
   - Compare against manifest hash
   - Reject on mismatch
8. If all pass: import definitions, policies, triggers into database
9. Audit log the import event
```

### 13.5 Key Management

**Self-signing for development:**
```bash
yuzu-server --generate-pack-key --self-signed
# Generates root key + signing key in server config directory
# Dashboard shows warning banner: "Self-signed pack keys in use"
```

Controlled by server config:
```ini
[packs]
require_signed = true          # reject unsigned packs
allow_self_signed = true       # allow self-signed for dev (default: false)
trust_store_path = /etc/yuzu/pack-trust/
revocation_list_url = https://packs.example.com/crl.json
```

**Key rotation:**
1. Generate new signing key
2. Sign its certificate with root key
3. Distribute new key to trust store
4. Add old key fingerprint to revocation list with timestamp
5. Packs signed with old key are still valid until revocation list is updated

---

## 14. Agent Compatibility and Rollback

### 14.1 Per-Definition Compatibility

Each InstructionDefinition declares its requirements:

```yaml
spec:
  compatibility:
    minAgentVersion: 0.9.0      # agent must be at least this version
    requiredPlugins:
      - services                 # agent must have these plugins loaded
```

**Server-side check before dispatch:**
1. Compare agent's `agent_version` (from `RegisterRequest.AgentInfo`) against `minAgentVersion`
2. Compare agent's `plugins[]` list against `requiredPlugins`
3. If incompatible → skip agent, record `REJECTED(4003)` in `AgentExecStatus`

### 14.2 Agent-Side Rejection

If a `CommandRequest` arrives for a plugin or action the agent doesn't have, the agent returns `CommandResponse` with:
- `status = REJECTED`
- `error.code = "4001"` (plugin not loaded) or `"1001"` (action not found)

This is already the current behavior — the instruction engine formalizes it.

### 14.3 Plugin ABI Evolution

The plugin ABI (`plugin.h`) uses a single `abi_version` field, currently `YUZU_PLUGIN_ABI_VERSION = 4` with a minimum supported version `YUZU_PLUGIN_ABI_VERSION_MIN = 1` (ABI4 landed the per-OS `YuzuActionDescriptor` capability-matrix fields for #2204). See `sdk/README.md`'s ABI compatibility table for what each version added and whether it required a rebuild.

**Rules:**
- `YuzuPluginDescriptor` can only grow by appending new fields after the previous version's last field — never reordered or repurposed
- A plugin's `abi_version` must fall inside the closed range `[YUZU_PLUGIN_ABI_VERSION_MIN, YUZU_PLUGIN_ABI_VERSION]`; the agent rejects it at load time otherwise (`plugin_loader.cpp`) — this covers both an older plugin the host has since dropped support for, and a newer plugin declaring an `abi_version` the host doesn't understand yet
- Plugins are never broken by agent upgrades within the supported range — the agent checks `abi_version` at load time, before the plugin's `yuzu_plugin_descriptor()` return value is otherwise trusted

### 14.4 Mixed-Version Fleet

During fleet upgrades, older agents coexist with newer agents:
- Older agents receive ad-hoc `CommandRequest` messages (plugin + action + params) — same as today
- Newer agents receive the same `CommandRequest` — the wire protocol doesn't change
- InstructionDefinitions with `minAgentVersion` higher than an agent's version are simply not dispatched to that agent
- No forced upgrades; the OTA update mechanism is opt-in per rollout configuration

### 14.5 OTA Rollback

The existing OTA updater (`agents/core/src/updater.cpp`) already implements:
1. Download new binary to temp location
2. Verify SHA-256 hash
3. Rename current binary to `.old`
4. Move new binary into place
5. Signal restart
6. On startup, verify new binary works (health check)
7. If health check fails: rename `.old` back to current, restart

No changes needed for instruction engine compatibility.

---

## 15. Legacy Command Shim

### 15.1 Design Decision: No Separate Legacy Path

Every `InstructionDefinition` execution maps 1:1 to a `CommandRequest`:

```
InstructionDefinition.spec.execution.plugin  →  CommandRequest.plugin
InstructionDefinition.spec.execution.action  →  CommandRequest.action
InstructionDefinition parameter values       →  CommandRequest.parameters (map<string,string>)
```

There is no separate "legacy" or "ad-hoc" execution path. Ad-hoc commands sent from the dashboard or API are simply untyped InstructionDefinitions with `additionalProperties: {type: string}` parameter schemas.

### 15.2 Auto-Generation from Plugin Descriptors

Every plugin exposes its capabilities via `YuzuPluginDescriptor`:
- `name` — plugin identifier
- `actions` — null-terminated array of action names

A CLI tool generates stub InstructionDefinitions from plugin descriptors:

```bash
yuzu-admin generate-definitions --output definitions/
# For each plugin:
#   For each action:
#     Emit a YAML InstructionDefinition with:
#       - id: <plugin>.<action>
#       - plugin: <plugin>
#       - action: <action>
#       - parameters: { additionalProperties: { type: string } }  # open schema
#       - result: { columns: [{ name: output, type: string }] }   # raw output
```

### 15.3 Schema Inference Roadmap

**ABI v1 (current):** Plugins don't declare their parameter schemas. Auto-generated definitions use open `additionalProperties`.

**ABI v2 (future):** Add optional `parameter_schema` and `result_schema` fields to `YuzuPluginDescriptor`. Plugins that populate these get fully typed auto-generated definitions. Plugins that don't still get open-schema stubs.

### 15.4 Migration Path

1. **Today:** All commands are ad-hoc (`plugin + action + params`). Works unchanged.
2. **Phase B:** InstructionDefinition CRUD added. Ad-hoc commands continue to work via auto-generated "untyped" definitions.
3. **Over time:** Authors create typed definitions with parameter schemas and result columns. Typed definitions gradually replace untyped stubs.
4. **No breaking change:** The `CommandRequest` wire protocol never changes. The agent doesn't know or care whether the command came from a typed definition or an ad-hoc dispatch.

---

## 16. `service.set_start_mode`

### 16.1 Semantics

Change the startup type of a system service.

**Parameters:**

```yaml
parameters:
  type: object
  required:
    - serviceName
    - mode
  properties:
    serviceName:
      type: string
      description: Name of the service (e.g., "Spooler", "sshd", "com.apple.ftp-proxy")
    mode:
      type: string
      enum:
        - automatic
        - manual
        - disabled
        - masked
      description: |
        Target startup mode. "masked" is Linux-only; maps to "disabled" on other platforms.
```

### 16.2 Platform Implementation

**Windows:**
```cpp
// ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, startType, ...)
// automatic → SERVICE_AUTO_START
// manual    → SERVICE_DEMAND_START
// disabled  → SERVICE_DISABLED
// masked    → SERVICE_DISABLED (with warning: "masked not supported on Windows")
```

**Linux (systemd):**
```bash
# automatic → systemctl enable <service>
# manual    → systemctl disable <service>  (still startable manually)
# disabled  → systemctl disable <service>
# masked    → systemctl mask <service>     (prevents any start, even manual)
```

**macOS:**
```bash
# automatic → launchctl enable system/<service>  (or set Disabled=false in plist)
# manual    → launchctl disable system/<service>
# disabled  → launchctl disable system/<service>
# masked    → disabled (with warning: "masked not supported on macOS")
```

### 16.3 Return Schema

```yaml
result:
  columns:
    - name: serviceName
      type: string
    - name: previousMode
      type: string
    - name: newMode
      type: string
    - name: effectiveMode
      type: string
    - name: warning
      type: string
```

`effectiveMode` may differ from `newMode` if the requested mode isn't supported (e.g., `masked` on Windows returns `effectiveMode: disabled`).

---

## 17. Scale Design

### 17.1 Target: 100K Agents

**Gateway batching:** 10-50 gateway nodes, each handling 2K-10K agent connections. Gateways proxy `Register`, batch `Heartbeat` messages (reducing per-agent RPC overhead), and forward `Subscribe` streams. Defined in `proto/yuzu/gateway/v1/gateway.proto` (GatewayUpstream service).

**Connection state:** In-memory on each gateway. Gateways report stream status to the upstream server. Server maintains a `connected_agents` table with gateway_id, last_heartbeat, and connection quality.

### 17.2 Sub-Second Dispatch

**Scope evaluation:** The scope engine evaluates expressions against all agents in memory. Complexity is O(A × E) where A = agent count and E = expression complexity.

| Fleet Size | Expression Nodes | Estimated Eval Time |
|---|---|---|
| 10K agents | 5 | ~10 ms |
| 100K agents | 5 | ~100 ms |
| 100K agents | 20 | ~400 ms |

Acceptable for interactive use. For very large fleets, scope results can be cached (expressions are deterministic for a given agent attribute snapshot).

**gRPC dispatch:** Non-blocking writes to agent streams. The server iterates matched agents and enqueues `CommandRequest` messages. With 100K matches, this takes ~50ms (gRPC protobuf serialization is fast).

### 17.3 Response Storage at Scale

**PostgreSQL:** `ResponseStore` persists responses in the `response_store` schema on the shared PostgreSQL pool (ADR-0006/0008); MVCC means concurrent reads don't block writes.

**Retention:** TTL-based cleanup runs on a background thread (configurable interval, default 60 min). Expired rows are deleted in batches to avoid long transactions.

**Optional ClickHouse export:** For analytics workloads beyond what the PostgreSQL store is meant to serve, responses can be forwarded to ClickHouse via:
- Direct INSERT over HTTP (server-side batch job)
- Prometheus remote_write (for metrics)
- Kafka intermediate topic (for high-volume environments)

PostgreSQL remains the primary store; ClickHouse is an optional analytics sink.

### 17.4 Definition and Policy Caching

**Definitions:** Read-heavy, write-rare. Server maintains an in-memory LRU cache of parsed InstructionDefinitions. Cache invalidated on create/update/delete. With thousands of definitions, the cache uses ~10-50 MB.

**Policies:** Compiled policy documents are hashed and pushed to agents. Agents cache the policy locally. Re-download only when the server's policy hash changes (checked on heartbeat).

### 17.5 Policy Evaluation Distribution

Policy rules evaluate **agent-side** (distributed across the fleet). The server does not evaluate policies — it only collects compliance status in batches. This means:
- Policy evaluation scales linearly with fleet size (no server bottleneck)
- Compliance status is eventually consistent (agents report on trigger/interval)
- Server aggregates compliance summaries for dashboard display

---

## 18. Data Model and Result Shaping

### 18.1 Canonical Result Envelope

Every instruction execution produces results in this structured format:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionResult
metadata:
  executionId: exec_01J...
  definitionId: crossplatform.service.inspect
  agentId: 28d5...
  timestamp: 2026-03-17T18:20:00Z
spec:
  status: success        # success | failure | partial | timeout | cancelled | rejected
  errorCode: null        # error code from taxonomy (Section 9) if status != success
  durationMs: 182
  columns:
    - name: serviceName
      type: string
    - name: state
      type: string
    - name: startupType
      type: string
    - name: pid
      type: int32
  rows:
    - serviceName: Spooler
      state: running
      startupType: automatic
      pid: 4592
  diagnostics:
    stdout: ""
    stderr: ""
    warnings: []
```

### 18.2 Why This Matters

Without a typed result envelope:
- **Workflow chaining** breaks — downstream definitions can't reference upstream output fields
- **Filtering and pagination** are unreliable — column types affect sort order and comparison
- **Aggregate views** are impossible — you can't `COUNT` or `GROUP BY` untyped strings
- **Policy evaluation** can't compare values — `result.state == "running"` requires knowing `state` is a string
- **Data export** loses fidelity — CSV/JSON export needs column types for formatting
- **Pack portability** suffers — definitions can't declare their output contract

### 18.3 Supported Column Types

| Type | Wire Format | SQLite Type | ClickHouse Type | Notes |
|---|---|---|---|---|
| `bool` | `"true"` / `"false"` | INTEGER (0/1) | UInt8 | |
| `int32` | Decimal string | INTEGER | Int32 | |
| `int64` | Decimal string | INTEGER | Int64 | |
| `string` | UTF-8 | TEXT | String | |
| `datetime` | ISO 8601 | TEXT | DateTime64 | |
| `guid` | UUID string | TEXT | UUID | |
| `clob` | UTF-8 | TEXT | String | Large text, configurable truncation |

---

## 19. Implementation Order

Updated to reflect current state (Phase 0 and 1 complete, Phase 2 scaffolded).

### Phase A — Response Integration (remaining Phase 1 work) :white_check_mark: Complete

1. ~~Wire `ResponseStore` into command dispatch path~~ — done
2. ~~Implement structured result envelope parsing~~ — done
3. ~~Response search HTTP endpoint~~ — done (`GET /api/responses/{id}` with query params)
4. ~~CSV/JSON export endpoints~~ — done (`GET /api/responses/{id}/export?format=csv|json`, `POST /api/export/json-to-csv`)
5. ~~Response aggregation engine~~ — done (`GET /api/responses/{id}/aggregate` with GROUP BY + count/sum/avg/min/max)

### Phase B — Instruction Plane (Phase 2 core)

6. `InstructionStore` business logic — CRUD with YAML source storage
7. Parameter schema validation (JSON Schema via nlohmann-json)
8. Result schema declaration and typed storage
9. Legacy command shim — auto-generate definitions from plugin descriptors
10. YAML authoring UI in dashboard (form mode + YAML mode)
11. Import/export endpoints (`/api/v1/definitions/import`, `/api/v1/definitions/{id}/export`)

### Phase C — Governed Execution

12. `ScheduleEngine` business logic — cron evaluation, scope-based dispatch
13. `ApprovalManager` business logic — submit/approve/reject with ownership rules
14. `ExecutionTracker` business logic — progress tracking, aggregate status computation
15. Rerun/cancel — clone completed executions, send cancel to agents
16. Concurrency enforcement — server-side per-device only (ADR-1007); per-set/per-definition/global remain unenforced

### Phase D — Policy and Triggers (Phases 4-5)

17. Agent-side trigger framework (interval, file, service, event_log, registry, startup)
18. PolicyFragment CRUD — check/fix/postcheck references, compliance expressions
19. Policy assignment to management groups
20. Agent-side policy evaluation — trigger fire → check → fix → postcheck → report
21. CEL adoption for typed compliance expressions
22. Compliance dashboard — fleet posture, per-rule drill-down

### Phase E — Distribution (Phase 7)

23. ProductPack format — tar.zst with manifest.json
24. Ed25519 signing — key generation, manifest signing, verification
25. Trust chain — root key, signing key certificates, revocation list
26. Import/export workflow — upload, verify, extract, store
27. Dependency resolution — required plugins, required packs, version constraints

---

## 20. Design Judgments and Source Notes

### 20.1 What Yuzu Exposes to Content Authors

Expose:
- Stable builtin primitives (Section 7)
- Typed parameter and result schemas
- Result-shaping operators (filter, group, sort, aggregate)
- Trigger templates
- Governance primitives (scope, approval, audit)
- Content-pack metadata and distribution

### 20.2 What Yuzu Does NOT Expose to Content Authors

Do not expose directly:
- Win32 / SCM / Registry / WMI syscalls
- Linux `ioctl` / `procfs` / `dbus-send` internals
- macOS FSEvents / launchd / codesign invocation details
- Arbitrary shell text as the primary authoring model

These remain internal adapters behind stable builtins. Content authors target `service.restart`, not `systemctl restart` or `Restart-Service`.

### 20.3 Permission Boundary

**InstructionSet** is the primary operational permission boundary:
- Users execute definitions within sets
- Authors publish to sets
- Approvers approve set-governed actions
- Packs distribute sets as units of capability

This is cleaner than per-plugin ACLs. The RBAC system (Phase 3) will bind `Principal + Role + SecurableType(InstructionSet) + Operation(Execute|Author|Approve)`.

### 20.4 Minimal Viable Content Plane

A pragmatic MVP includes only:
- `InstructionDefinition` CRUD with YAML storage
- `InstructionSet` grouping
- Structured result envelope
- Response persistence (already done)
- Legacy command shim (auto-generated definitions)
- YAML authoring UI

This is enough to move Yuzu from "plugin executor" to "governed endpoint instruction platform". Scheduling, approvals, policies, and packs are additive — they build on the same definition model without changing the execution semantics.

### 20.5 Key Architectural Decisions Summary

| Decision | Choice | Rationale |
|---|---|---|
| Expression language | Extend scope DSL now; CEL for policy in Phase 5 | Current 494-LOC engine is clean and sufficient for device targeting; CEL justified only for typed policy evaluation |
| Error codes | 4-category 1xxx-4xxx taxonomy | Clear domain separation; non-overlapping ranges; retry semantics per category |
| Partial failure | Configurable `minSuccessPercent`, default 100% | Supports "all must succeed" (compliance) and "best effort" (diagnostics) |
| YAML storage | SQLite TEXT + denormalized columns | Single source of truth; queryable without re-parsing |
| Concurrency default | `per-device` (server-enforced, ADR-1007) | One claim-table round trip per gated dispatch, not per fleet size |
| Pack signing | Ed25519, 3-level key hierarchy | Fast, small signatures; no padding attacks; HSM-compatible |
| Agent compat | `minAgentVersion` per definition, graceful REJECTED | No forced upgrades; mixed-version fleet support |
| Legacy shim | Every definition maps 1:1 to CommandRequest | No separate path; seamless migration from ad-hoc to governed |

### 20.6 Source References

This document is grounded in the following implementation files:

| File | Role |
|---|---|
| `server/core/src/scope_engine.cpp` (494 LOC) | Expression language implementation |
| `server/core/src/scope_engine.hpp` | Expression AST types, parser/evaluator API |
| `server/core/src/instruction_store.hpp` | InstructionDefinition, InstructionSet structs |
| `server/core/src/execution_tracker.hpp` | Execution, AgentExecStatus, ExecutionSummary structs |
| `server/core/src/approval_manager.hpp` | Approval struct, ApprovalManager API |
| `server/core/src/schedule_engine.hpp` | InstructionSchedule struct, ScheduleEngine API |
| `server/core/src/response_store.hpp` | StoredResponse struct, ResponseStore API |
| `server/core/src/audit_store.hpp` | AuditEvent struct, AuditStore API |
| `server/core/src/tag_store.hpp` | DeviceTag struct, TagStore API |
| `server/core/src/instruction_ui.cpp` | HTMX instruction management page |
| `server/core/src/settings_ui.cpp` | File upload UI pattern (TLS certs, OTA binaries) |
| `sdk/include/yuzu/plugin.h` | Plugin ABI v1, command handler signature |
| `proto/yuzu/agent/v1/agent.proto` | CommandRequest/Response, RegisterRequest, AgentInfo |
| `proto/yuzu/common/v1/common.proto` | ScopeExpression, ErrorDetail, Platform, PluginInfo |
| `docs/capability-map.md` | 184 capabilities, 150 done (82%) |
| `docs/roadmap.md` | 72 issues across 7 phases (all complete) |

## Build-time content embedding — there is no filesystem load path

`content/definitions/*.yaml` and `content/packs/*.yaml` are converted to JSON envelopes by `server/core/scripts/embed_content.py` at build time, written into `bundled_content.cpp` as the `kBundledDefinitions` / `kBundledSets` vectors, linked into `yuzu-server`, and reseeded into the shared Postgres `instruction_store` schema on **every** boot via the build-time-trusted import path (ADR-0058; conflict-skip on id existence so operator REST/dashboard edits win — an operator-deleted bundled id stays deleted via a tombstone, never resurrected). The runtime never reads YAML from disk — there is no `--content-dir` flag and none of the install packages ship the YAMLs separately. This is identical on Linux, macOS, and Windows.

**PyYAML is a hard build dependency.** `meson setup` probes `python -c "import yaml"` and fails the configure step if it's missing; `embed_content.py` itself fails the build (non-zero exit) on missing PyYAML, missing `content/` directory, missing required fields in any `InstructionDefinition`, or zero parsed defs. The historical "warn and emit empty bundle" fallback (which silently produced binaries with empty Instructions tabs) was removed. Provision PyYAML with `pip install pyyaml` (Linux/macOS) or `pacman -S python-yaml` (MSYS2).
