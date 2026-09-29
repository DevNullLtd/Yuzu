# Enterprise Endpoint Management Parity Plan

**Version:** 1.0 | **Date:** 2026-03-30 | **Status:** Draft

This document analyzes the capabilities of leading commercial endpoint-management platforms against Yuzu's current state (v0.7.0, 165/184 capabilities done) and defines a phased implementation plan to achieve feature parity.

---

## Part 1: Architectural Comparison

| Dimension | Leading commercial peer | Yuzu v0.7.0 |
|-----------|---------------|-------------|
| **Language** | C# / .NET (server), proprietary scripting language (agent) | C++23 (server+agent), Erlang/OTP (gateway) |
| **Agent Instruction Model** | proprietary scripting language (SQL + control flow) | Plugin ABI (C/C++ shared libraries) |
| **Wire Protocol** | WebSocket Secure (TCP 4000) | gRPC/Protobuf with mTLS |
| **Server Database** | SQL Server (multiple DBs) | SQLite (embedded, WAL mode) |
| **Scaling Architecture** | Switches (50K devices each, 5 per stack) | Erlang/OTP gateway (10K+ tested) |
| **Content Definition** | XML with XSD schema, digital signing | YAML with `yuzu.io/v1alpha1` DSL, Ed25519 signing |
| **Auth Model** | Windows AD (Kerberos), 2FA email | PBKDF2 sessions, OIDC/PKCE, API tokens, mTLS |
| **Content Delivery** | Background Channel (HTTPS) + Nomad P2P | HTTP content staging + execution |
| **Policy Engine — Server side** | Guaranteed State (proprietary-script check/fix) | PolicyStore with CEL expressions + triggers |
| **Policy Engine — Real-time agent-side enforcement** | Guaranteed State (kernel-event-driven enforcement, pre-login activation, offline-capable) | **System Guardian** — agent-side guard engine using kernel-backed user-mode APIs (RegNotifyChangeKeyValue, ETW, WFP, SCM on Windows; inotify/netlink/D-Bus on Linux; Endpoint Security on macOS). As of 2026-09-07: `GuardianEngine`, `BaselineStore`, Windows registry/service/file guards, Linux `guard_systemd`, `/guaranteed-state` UI shipped (59 merged PRs); Spark detection engine (ADR-0021) wired but inert (`prefer_spark` off); macOS not started — see `docs/roadmap.md` Phase 16. |
| **API** | Consumer API (.NET SDK) | REST API v1 (70+ endpoints) + gRPC + MCP |
| **Dashboard** | ASP.NET web portal | HTMX server-rendered + SSE |
| **DMZ Support** | Dedicated DMZ Server (Response Stack) | Gateway node (Erlang, can be DMZ-deployed) |

### Key Architectural Differences

**Yuzu's advantages over commercial peers:**
- **No SQL Server dependency** — SQLite is embedded, zero-ops
- **Cross-platform from day one** — C++23 compiles on Win/Linux/macOS/ARM64
- **gRPC/Protobuf** — strongly typed, bidirectional streaming, native mTLS
- **MCP server** — AI-native fleet management (commercial peers have no equivalent); the tool/resource surface is near-fully self-describing per ADR-1005 Decision 16 (`docs/agentic-first-principle.md` A5) — typed input/output schemas, truthful `readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint` annotations, a handshake orientation blob, and machine-readable specs (OpenAPI, scope-DSL, per-plugin documentation manifests) discoverable via `resources/list` rather than requiring an agent to already know which tool to call (one narrow tracked residual: the streamed-final fallback envelope, #2990 — `retry_after_ms` closed 2026-08 by #3344)
- **Modern auth** — OIDC/PKCE, API tokens, session cookies (vs AD-only)
- **CEL for policy** — industry-standard expression language (vs proprietary peer scripting)
- **Plugin ABI** — compiled native plugins are faster than an interpreted peer language
- **Erlang gateway** — OTP supervision trees, hot code upgrade, fault isolation

**Commercial peers' advantages over Yuzu (gaps to close):**
- **Proprietary peer scripting** — composable agent-side scripting with SQL, tables, control flow
- **Connector framework** — 12 bidirectional integrations (SCCM, Intune, ServiceNow, etc.). *Roadmap Phase 9 was deferred by owner decision 2026-09-07, pending an ADR-1005 Decision 2 review of where connector ingestion belongs (core mechanism vs use-case engine); see `docs/roadmap.md` Phase 9 banner.*
- **Response visualization** — chart types, custom processors, server-side rendering
- **Software catalog** — normalized vendor/title/version with AI auto-curation
- **Nomad P2P** — peer-to-peer content distribution with bandwidth optimization
- **Consumer model** — formal third-party application integration framework
- **Inventory consolidation** — multi-source dedup, normalization, repositories
- **2FA for approvals** — email/token-based second factor
- **Survey/DND** — multi-question surveys, do-not-disturb suppression
- **PowerShell toolkit** — cmdlet library for scripted administration

---

## Part 2: Detailed Gap Analysis

### Already Equivalent or Superior (No Action Needed)

These commercial-peer features have functional equivalents in Yuzu that are as good or better:

| Commercial Peer Feature | Yuzu Equivalent |
|----------------|-----------------|
| Agent registration | 3-tier enrollment (manual, token, platform trust) |
| Heartbeat / keepalive | gRPC Heartbeat RPC with status_tags |
| Agent diagnostics | `diagnostics` plugin + `agent_logging` + `connection_info` |
| Agent updates | OTA via `CheckForUpdate`/`DownloadUpdate` RPCs |
| Plugin extensibility | 44 plugins, C ABI + C++ CRTP wrapper |
| Instruction definitions | YAML DSL with typed parameters + result schemas |
| Instruction sets | InstructionStore with RBAC-scoped sets |
| Instruction scheduling | ScheduleEngine (daily/weekly/monthly/interval) |
| Instruction approval | ApprovalManager (auto/role-gated/always) |
| Instruction progress | ExecutionTracker per-agent status tracking |
| Rerun/cancel | ExecutionTracker rerun + cancel with user attribution |
| Scope expressions | ScopeEngine (10 operators, AND/OR/NOT, regex) |
| Target estimation | `/api/scope/estimate` preview |
| Response persistence | ResponseStore (PostgreSQL, TTL cleanup) |
| Response aggregation | COUNT/SUM/AVG/MIN/MAX with GROUP BY |
| Response export | CSV/JSON export endpoints |
| RBAC | 6 roles, 14 securable types, deny-override |
| Management groups | Hierarchical, static + dynamic membership |
| Audit trail | AuditStore (365-day retention, structured events) |
| Device tagging | TagStore + agent-side tags plugin |
| Custom properties | CustomPropertiesStore (typed, schema-validated) |
| Quarantine | `quarantine` plugin + QuarantineStore |
| IOC checking | `ioc` plugin (IPs, domains, hashes, ports) |
| Certificate mgmt | `certificates` plugin (list/details/delete) |
| Device discovery | `discovery` plugin + DiscoveryStore |
| Content staging | `content_dist` plugin (stage + execute) |
| HTTP client | `http_client` plugin (GET/POST/HEAD + download) |
| Script execution | `script_exec` plugin (PowerShell + bash) |
| File operations | `filesystem` plugin (17 actions) |
| Registry | `registry` plugin (CRUD + per-user) |
| WMI | `wmi` plugin (query + instance) |
| Policy engine — server-side compliance | PolicyStore + CEL + 6 trigger types (poll-based desired-state evaluation; this is the *server* half of guaranteed state — see "Major Gaps" G14 for the agent-side real-time half delivered by System Guardian) |
| Compliance dashboard | Fleet/policy/agent drill-down |
| Agent-side storage | `storage` plugin (SQLite KV) |
| Triggers | 7 types (interval, file, dir, service, eventlog, registry, startup) |
| User interaction | `interaction` plugin (notify, message_box, input) |
| Product packs | ProductPackStore with Ed25519 signing |
| Webhooks | WebhookStore with HMAC-SHA256 signing |
| Notifications | NotificationStore (info/warn/error/success) |
| System health | `/livez`, `/readyz`, ProcessHealthSampler, Prometheus |
| License mgmt | LicenseStore (seats, editions, feature flags) |
| Gateway/DMZ | Erlang/OTP gateway with circuit breaker |
| OIDC SSO | OidcProvider with PKCE, Entra ID discovery |
| AD/Entra sync | DirectorySync via Microsoft Graph |
| API tokens | ApiTokenStore + MCP tiers |
| Software deployment | SoftwareDeploymentStore (stage/deploy/rollback) |
| Patch management | PatchManager (scan/download/install/verify/reboot) |
| Vulnerability scanning | `vuln_scan` plugin + NVD sync |
| Workflows | WorkflowEngine (if/foreach/retry/parallel) |

### Gaps: Not Started in Capability Map (19 items)

These are already tracked as "Not Started" T3 items:

| # | Capability | Commercial Peer Equivalent |
|---|-----------|-------------------|
| 3.8 | Mapped Drive History | Device.GetInbound/OutboundMappedDriveHistory |
| 3.9 | Printer Inventory | Device.GetInbound/OutboundPrinters |
| 4.9 | NetBIOS Lookup | Discovery.LookupNetBiosNames |
| 4.11 | Port Scanning | Discovery.ScanPortsOnDevices |
| 5.5 | Open Windows Enumeration | OperatingSystem.GetRunningApps |
| 8.9 | Patch Inventory Event Generation | Patch.GenerateFullInventoryEvents |
| 9.10 | Application Whitelisting | Security.ModifyQuarantineWhitelist (partial) |
| 10.11 | Directory Hash | FileSystem.GetDirectoryHash |
| 13.5 | P2P Content Distribution | Nomad (full P2P suite) |
| 14.4 | Survey Dialog | Interaction.ShowSurvey |
| 14.5 | Do-Not-Disturb Mode | Interaction.SetDoNotDisturb |
| 14.6 | Active Response Tracking | Interaction.GetActiveResponses |
| 15.5 | Inventory Replication | Inventory.GetLocalReplica |
| 20.6 | Response Templates | Custom response definitions |
| 20.7 | Response Offloading | Consumer offloading |
| 21.5 | Event Source Management | Event subscription configuration |
| 22.7 | Binary Resource Distribution | Background Channel resources |
| 24.4 | Consumer Registration | Consumer application model |
| 24.7 | SDK Libraries | .NET Consumer SDK |

### Gaps: Major Features Commercial Peers Have That Yuzu Lacks Entirely

These are significant capability areas not represented in Yuzu's capability map at all:

| # | Feature | Description | Impact |
|---|---------|-------------|--------|
| G1 | **Connector Framework** | Bidirectional data sync with SCCM, Intune, BigFix, ServiceNow, vCenter, WSUS, Oracle LMS, OpenLM, O365 | HIGH — core enterprise integration |
| G2 | **Response Visualization Engine** | Chart types (Pie, Bar, Column, Line, Area, SmartBar), built-in + custom processors, server-side rendering | MEDIUM — dashboard richness |
| G3 | **Software Catalog & Normalization** | Vendor/Title/Version/Edition normalization, AI auto-curation, third-party software-catalog integration | HIGH — license compliance |
| G4 | **Inventory Repositories** | Multiple named repositories per type, connector-based population, consolidation/dedup/normalization | HIGH — multi-source inventory |
| G5 | **Software Usage Tracking** | Application usage categorization (Used/Rarely Used/Unused), metering data from agents | MEDIUM — license optimization |
| G6 | **Consumer Application Model** | Formal registration of third-party consumers with rate limits, offloading, custom data | MEDIUM — platform extensibility |
| G7 | **2FA for Approvals** | Email/token-based second factor on instruction approval | LOW — security hardening |
| G8 | **Composable Instruction Chains** | Agent-side scripting with SQL, @tables, FOREACH, IF/ELSE, chained method calls | MEDIUM — instruction flexibility |
| G9 | **Data Offloading** | Route response data to external HTTP endpoints in real time | MEDIUM — analytics integration |
| G10 | **PowerShell Toolkit** | Cmdlet library wrapping the management API | LOW — admin convenience |
| G11 | **Branding / White-Label** | Custom logos, colors, names in dashboard | LOW — enterprise customization |
| G12 | **Process/Provider/Sync Logging** | Separate log views for sync jobs, provider operations, infrastructure | LOW — operational visibility |
| G13 | **Multi-Database Architecture** | Separate databases for responses, catalog, inventory, SLA, BI | MEDIUM — scale separation |
| G14 | **System Guardian — Real-Time Agent-Side Guaranteed State** | the category leader's flagship: kernel-event-driven enforcement on Windows (RegNotifyChangeKeyValue, ETW, WFP, SCM), Linux (inotify, netlink, D-Bus, sysctl, audit), macOS (Endpoint Security, fseventsd, launchd). Pre-login activation. Fully offline-capable. Millisecond-level enforcement for event-driven rules. Auditable journal of every detection and remediation. **In flight** — PRs 1-2 shipped (proto, `guaranteed_state_store`, agent `GuardianEngine` scaffolding, `__guard__` dispatch hook); PR 3+ pending per `docs/yuzu-guardian-windows-implementation-plan.md`. PolicyStore alone does *not* deliver this — its 5-minute poll cycle is unacceptable for "this setting must never be in a non-compliant state" use cases (firewall ports, registry-backed security settings, EDR process always-running). Guardian is the agent-side primitive that closes that gap. | **CRITICAL** — this is the headline parity feature for enterprise endpoint management |

---

## Part 3: Implementation Plan

### Prioritization Criteria

1. **Enterprise value** — Features most commonly required in RFP/RFI responses
2. **Competitive differentiation** — What makes Yuzu credibly replace incumbent commercial platforms
3. **Build complexity** — Estimated effort and architectural impact
4. **Dependencies** — What must exist before other things can be built

### Phase 8: Visualization & Response Experience

*Make collected data actionable with charts, templates, and processing pipelines.*

**Duration estimate: 1 sprint**

| Issue | Title | Scope | Depends On |
|-------|-------|-------|------------|
| 8.1 | Response Visualization Engine | Server | — |
| 8.2 | Response Templates | Server | 8.1 |
| 8.3 | Response Offloading (Data Export Streams) | Server | — |

**8.1 — Response Visualization Engine**
- Add chart rendering to instruction response views
- Server-side data transformation (equivalent to comparable platforms' post-processors)
- Built-in processors: SingleSeries, MultiSeries, DateTimeSeries
- Chart types: Pie, Bar, Column, Line, Area (rendered via lightweight JS chart library in HTMX)
- Configuration via `spec.visualization` in InstructionDefinition YAML:
  ```yaml
  spec:
    visualization:
      charts:
        - type: pie
          title: "OS Distribution"
          x: os_name
          y: count
          processor: single_series
  ```
- REST endpoint: `GET /api/v1/executions/{id}/visualization`
- Dashboard: embedded chart cards in execution detail view

**8.2 — Response Templates**
- Named response view configurations (column selection, sort, filter presets)
- Stored per InstructionDefinition in `spec.responseTemplates`
- Default template auto-generated from result schema
- Template CRUD via REST API

**8.3 — Response Offloading**
- Configure external HTTP endpoints to receive response data in real time
- `OffloadTarget` model: URL, auth (bearer/basic/HMAC), event filter, batch size
- Fire-and-forget delivery on background thread (reuse WebhookStore pattern)
- REST: `GET/POST/DELETE /api/v1/offload-targets`
- Per-instruction override: `spec.offload.target` in YAML

---

### Phase 9: Connector Framework & Multi-Source Inventory

*Federate inventory data from external systems. This is the single biggest gap vs. commercial peers.*

**Duration estimate: 2 sprints**

| Issue | Title | Scope | Depends On |
|-------|-------|-------|------------|
| 9.1 | Connector Framework (Core) | Server | — |
| 9.2 | Inventory Repository Model | Server | 9.1 |
| 9.3 | SCCM / ConfigMgr Connector | Server | 9.1 |
| 9.4 | Intune Connector | Server | 9.1 |
| 9.5 | ServiceNow Connector | Server | 9.1 |
| 9.6 | WSUS Connector | Server | 9.1 |
| 9.7 | CSV/File Upload Connector | Server | 9.1 |
| 9.8 | Inventory Consolidation & Normalization | Server | 9.2 |

**9.1 — Connector Framework (Core)**
- `ConnectorStore` (SQLite): connector type, name, config (encrypted credentials), schedule, status
- `ConnectorEngine`: background sync with pluggable connector implementations
- Connector interface:
  ```cpp
  class Connector {
  public:
      virtual std::string type() const = 0;
      virtual SyncResult sync(const ConnectorConfig& config, InventoryRepository& repo) = 0;
      virtual ConnectionTestResult test(const ConnectorConfig& config) = 0;
  };
  ```
- Sync lifecycle: NotStarted → Pending → InProgress → Completed/Failed/Cancelled
- REST: `GET/POST/PUT/DELETE /api/v1/connectors`, `POST /api/v1/connectors/{id}/sync`, `POST /api/v1/connectors/{id}/test`
- Dashboard: Connectors page in Settings with add/edit/delete/test/sync

**9.2 — Inventory Repository Model**
- `RepositoryStore` (SQLite): named repositories per type (inventory, compliance, entitlement)
- Default repository created on first boot (cannot be deleted)
- Connectors bound to repositories
- Consolidation, deduplication, normalization pipeline
- REST: `GET/POST/PUT/DELETE /api/v1/repositories`
- Repository types: Inventory, Compliance, Entitlement (extensible)

**9.3 through 9.7 — Individual Connectors**
Each connector is a self-contained class implementing the Connector interface:
- **SCCM**: SQL query against ConfigMgr database (hardware, software, users, patches)
- **Intune**: Microsoft Graph API (`/deviceManagement/managedDevices`)
- **ServiceNow**: REST API (CMDB CI records, incidents, change requests)
- **WSUS**: SQL query against WSUS database (update status, compliance)
- **CSV/File Upload**: Parse TSV/CSV with column mapping

**9.8 — Inventory Consolidation & Normalization**
- Deduplication by device identity (hostname + MAC + serial)
- Software normalization: vendor/title/version canonicalization
- Hardware normalization: processor model mapping, VM detection
- Consolidation reports: matched vs. unmatched, normalization coverage

---

### Phase 10: Software Catalog & License Compliance

*Normalized software identification for license management and compliance.*

> **Superseded by ADR-0024 (2026-07-06):** the design of record for this phase is now
> `docs/adr/0024-software-licensing-entitlements.md` ("Software Licensing &
> Entitlements", capability §27 — renamed by the same ADR). The sketch below is stale
> where it conflicts (SQLite `CatalogStore` → born-on-Postgres `ProductRegistryStore`;
> manual-only entitlements → five-source entitlement plane; `/api/v1/catalog/*` →
> `/api/v1/sle/*`; usage **collection** becomes opt-in (`--usage-sync-enable`, default
> off) and machine-scope, not on-by-default launch tracking). Per ADR-0024's "Placement
> under ADR-1005", compliance evaluation, the entitlement plane, and usage **reclamation
> verdicts/categories** are re-scoped to the SAM use-case-engine module (Decision 15);
> §27 v1 builds only the in-server discovery mechanism.

**Duration estimate: 1 sprint**

| Issue | Title | Scope | Depends On |
|-------|-------|-------|------------|
| 10.1 | Software Catalog Store | Server | 9.8 |
| 10.2 | Software Usage Tracking | Agent + Server | 10.1 |
| 10.3 | License Entitlements & Compliance | Server | 10.1 |
| 10.4 | Software Tags | Server | 10.1 |

**10.1 — Software Catalog Store**
- `CatalogStore` (SQLite): normalized software entries (vendor, title, version, edition, platform)
- Catalog import from CSV/JSON
- Manual curation UI: merge duplicates, set canonical names
- REST: `GET/POST/PUT /api/v1/catalog/software`

**10.2 — Software Usage Tracking**
- New `software_usage` agent plugin
- Track application launches, run time, last-used timestamp
- Categorize: Used (30d), Rarely Used (90d), Unused (>90d), Unreported
- Report via ReportInventory RPC
- Server-side aggregation: per-title usage across fleet

**10.3 — License Entitlements & Compliance**
- Entitlement records: product, purchased_seats, license_type (per-device/per-user/site/enterprise)
- Compliance calculation: installed_count vs. entitled_count
- Over/under-licensed reporting
- REST: `GET/POST /api/v1/entitlements`
- Dashboard: license compliance summary

**10.4 — Software Tags**
- Server-side tags on software catalog entries (not device tags)
- Used for Management Group rules ("devices with software tagged X")
- REST: `GET/POST/DELETE /api/v1/catalog/software/{id}/tags`

---

### Phase 11: Consumer Model & Platform Extensibility

*Formalize third-party integration as a first-class concept.*

**Duration estimate: 1 sprint**

| Issue | Title | Scope | Depends On |
|-------|-------|-------|------------|
| 11.1 | Consumer Application Registration | Server | — |
| 11.2 | Event Source Management | Server | 11.1 |
| 11.3 | PowerShell Module | External | — |
| 11.4 | Python SDK | External | — |

**11.1 — Consumer Application Registration**
- `ConsumerStore` (SQLite): name, URL, max_concurrent_instructions, offload_target, enabled
- Consumers get scoped API tokens with rate limits
- Custom data field for consumer-specific metadata
- REST: `GET/POST/PUT/DELETE /api/v1/consumers`
- Dashboard: Consumers page in Settings

**11.2 — Event Source Management**
- Configure which system events generate notifications and webhook deliveries
- Event source categories: agent_lifecycle, execution, compliance, security, system
- Per-category enable/disable with severity threshold
- REST: `GET/PUT /api/v1/event-sources`

**11.3 — PowerShell Module**
- `Yuzu.Management` PowerShell module wrapping REST API v1
- Cmdlets: `Get-YuzuAgent`, `Send-YuzuInstruction`, `Get-YuzuCompliance`, etc.
- Authentication: API token via `Connect-YuzuServer`
- Published to PowerShell Gallery

**11.4 — Python SDK**
- `yuzu-sdk` Python package wrapping REST API v1
- Async support via httpx
- Published to PyPI

---

### Phase 12: Remaining Agent Capabilities

*Close the 19 "Not Started" items from the capability map plus commercial-peer-specific agent features.*

**Duration estimate: 1 sprint**

| Issue | Title | Capability | Scope |
|-------|-------|-----------|-------|
| 12.1 | Mapped Drive History | 3.8 | Agent Plugin |
| 12.2 | Printer Inventory | 3.9 | Agent Plugin |
| 12.3 | Port Scanning | 4.11 | Agent Plugin |
| 12.4 | NetBIOS Lookup | 4.9 | Agent Plugin |
| 12.5 | Open Windows Enumeration | 5.5 | Agent Plugin |
| 12.6 | Directory Hash (Recursive) | 10.11 | Agent Plugin |
| 12.7 | Survey Dialog | 14.4 | Agent Plugin |
| 12.8 | Do-Not-Disturb Mode | 14.5 | Agent Plugin |
| 12.9 | Active Response Tracking | 14.6 | Agent Plugin |
| 12.10 | Patch Inventory Event Generation | 8.9 | Agent Plugin |
| 12.11 | Application Whitelisting | 9.10 | Agent Plugin |
| 12.12 | Inventory Replication (Delta Sync) | 15.5 | Agent + Server |
| 12.13 | Binary Resource Distribution | 22.7 | Server |

**12.1 — Mapped Drive History** (Windows)
- New actions in `users` plugin: `mapped_drives`, `mapped_drive_history`
- Query WMI `Win32_MappedLogicalDisk` + Event Log 4624/4634 for historical connections
- Returns: drive_letter, remote_path, username, timestamp, direction (inbound/outbound)

**12.2 — Printer Inventory** (Cross-platform)
- New action in `hardware` plugin: `printers`
- Windows: `EnumPrinters` API. Linux: CUPS `lpstat`. macOS: `lpstat`
- Returns: name, driver, port, status, shared, default, network/local

**12.3 — Port Scanning**
- New action in `discovery` plugin: `scan_ports`
- Parameters: target_ips (comma-separated), ports (range notation: "22,80,443,8000-8100")
- Non-blocking connect with configurable timeout (default 2s)
- Returns: ip, port, status (open/closed/filtered), service_guess

**12.4 — NetBIOS Lookup**
- New action in `discovery` plugin: `netbios_lookup`
- Parameters: ip_addresses (comma-separated)
- Send NetBIOS Name Query (UDP 137) and parse response
- Returns: ip, netbios_name, domain, mac_address

**12.5 — Open Windows Enumeration** (Windows)
- New action in `interaction` plugin: `list_windows`
- `EnumWindows` + `GetWindowText` + `GetWindowThreadProcessId`
- Returns: hwnd, title, process_name, pid, visible, minimized

**12.6 — Directory Hash**
- New action in `filesystem` plugin: `hash_directory`
- Recursive SHA-256 of all file contents, sorted by relative path
- Returns: directory_hash, file_count, total_bytes, elapsed_ms

**12.7 — Survey Dialog** (Windows, Linux)
- Extend `interaction` plugin: `survey` action
- Multi-question form: text, single-choice, multi-choice, rating scale
- Windows: WinForms-style dialog. Linux: zenity --forms
- Returns: structured JSON response with question_id → answer mapping

**12.8 — Do-Not-Disturb Mode**
- Extend `interaction` plugin: `set_dnd` action
- Suppress all notifications/dialogs for configurable duration
- Persisted in agent KV storage
- `get_dnd_status` action returns current state + expiry

**12.9 — Active Response Tracking**
- Extend `interaction` plugin: `list_pending` action
- Returns all outstanding surveys/questions awaiting user input
- Includes interaction_id, type, prompt, issued_at, timeout_at

**12.10 — Patch Inventory Event Generation**
- Extend `windows_updates` plugin: `generate_inventory_events` action
- Emit structured events for each installed/missing patch
- Feed into AnalyticsEventStore for SIEM/compliance integration

**12.11 — Application Whitelisting**
- New `app_control` plugin
- Windows: AppLocker policy query/modification via WMI or PowerShell
- Linux: fapolicyd rules (if available)
- Actions: `get_policy`, `add_rule`, `remove_rule`, `get_blocked_events`

**12.12 — Inventory Replication**
- Agent-side inventory cache in SQLite KV store
- Delta sync: only send changed inventory since last sync
- Server tracks per-agent sync state (last_sync_at, hash)
- Reduces inventory bandwidth for large fleets

**12.13 — Binary Resource Distribution**
- Server-side resource registry (versioned binary blobs)
- Agents pull resources by name + version with hash verification
- Used by instructions that need supporting files (scripts, configs, tools)
- REST: `GET/POST/DELETE /api/v1/resources`

---

### Phase 13: Security Hardening & Operational Polish

*Close remaining security and operational gaps.*

**Duration estimate: 1 sprint**

| Issue | Title | Scope |
|-------|-------|-------|
| 13.1 | 2FA for Instruction Approval | Server |
| 13.2 | Composable Instruction Chains | Agent + Server |
| 13.3 | Process / Sync Logging UI | Server |
| 13.4 | Dashboard Branding | Server |
| 13.5 | MCP Phase 2 (Write Tools) | Server |

**13.1 — 2FA for Instruction Approval**
- TOTP (RFC 6238) second factor for approval workflow
- Per-user TOTP secret stored encrypted in auth store
- QR code enrollment via Settings UI
- Approval endpoint requires `totp_code` parameter when 2FA is enabled
- Fallback: email-based one-time code (requires SMTP config)

**13.2 — Composable Instruction Chains**
This is the closest Yuzu can get to the category leader's proprietary scripting language without building an interpreter. The approach: server-side multi-step instruction composition using the existing WorkflowEngine.

- Workflow definitions in YAML with step chaining:
  ```yaml
  kind: Workflow
  spec:
    steps:
      - instruction: os_info.get_summary
        output_as: os_data
      - instruction: windows_updates.installed
        condition: "os_data.os_type == 'windows'"
        output_as: patches
      - instruction: script_exec.run_text
        parameters:
          language: PowerShell
          script_text: |
            $patches = ConvertFrom-Json '${patches.output}'
            # ... process patches
  ```
- Variables from previous steps available via `${step_name.field}` interpolation
- CEL conditions for conditional execution
- This provides equivalent composability without a new scripting language

**13.3 — Process / Sync Logging UI**
- Dashboard page: `/monitoring`
- Tabs: Connector Sync Log, Scheduled Executions, Infrastructure Log
- Reuse existing AuditStore with category filtering
- HTMX fragments with 30s auto-refresh

**13.4 — Dashboard Branding**
- `BrandingConfig`: logo_url, product_name, primary_color, accent_color
- Stored in RuntimeConfigStore
- Settings UI: branding section with preview
- CSS variables for theme customization

**13.5 — MCP Phase 2 (Write Tools)**
- 6 write/execute tools: `set_tag`, `delete_tag`, `execute_instruction`, `approve_request`, `reject_request`, `quarantine_device`
- Approval workflow integration for destructive operations
- SSE streaming for execution progress

---

### Phase 14: Scale & Enterprise Readiness

*Features needed for very large deployments (>100K devices).*

**Duration estimate: 2 sprints**

| Issue | Title | Scope |
|-------|-------|-------|
| 14.1 | P2P Content Distribution | Agent |
| 14.2 | Multi-Gateway Topology | Gateway + Server |
| 14.3 | Database Sharding (Response Partitioning) | Server |
| 14.4 | vCenter Connector | Server |
| 14.5 | Additional Connectors (BigFix, O365, Oracle) | Server |
| 14.6 | High Availability (Active-Passive) | Server |

**14.1 — P2P Content Distribution**
- Agent mesh for peer content sharing within subnet
- Leader election via mDNS/broadcast
- Content announce/request protocol over UDP
- Cache management: LRU eviction, configurable max size
- Falls back to server download when no peers have content
- Bandwidth throttling to avoid network saturation

**14.2 — Multi-Gateway Topology**
- Server supports multiple gateway registrations
- Gateway affinity: agents assigned to nearest gateway via latency probing
- Gateway failover: agents reconnect to alternate gateway on failure
- Topology view shows all gateways with agent counts

**14.3 — Database Sharding**
- Response data partitioned by time (monthly SQLite files)
- Automatic file rotation and TTL cleanup
- Query router spans partitions transparently
- Reduces WAL contention for high-throughput response collection

**14.4 — vCenter Connector**
- VMware vSphere API integration
- Sync: VMs, ESXi hosts, datastores, clusters, resource pools
- VM-to-agent correlation via hostname or UUID
- Virtual summary reporting (physical hosts, guest count, density)

**14.5 — Additional Connectors**
- BigFix: REST API integration for inventory sync
- Office 365: Microsoft Graph for license/usage data
- Oracle LMS: Database query for Oracle deployment facts

**14.6 — High Availability**
- Active-passive with shared SQLite over network filesystem (NFS/SMB)
- Heartbeat between primary and standby servers
- Automatic failover on primary health check failure
- Gateway re-registration on failover

---

## Part 4: Priority Matrix

| Phase | Priority | Effort | Enterprise Value | Parity Impact |
|-------|----------|--------|------------------|-----------------------|
| **8: Visualization** | HIGH | Small | HIGH | Closes visible UX gap |
| **9: Connectors** | CRITICAL | Large | CRITICAL | #1 gap — every enterprise RFP asks for this. **Deferred 2026-09-07** by owner decision, pending an ADR-1005 Decision 2 placement review (core mechanism vs use-case engine); see `docs/roadmap.md` Phase 9 banner |
| **10: Catalog** | HIGH | Medium | HIGH | License compliance is a primary use case |
| **11: Consumer** | MEDIUM | Medium | MEDIUM | Platform extensibility |
| **12: Agent Caps** | MEDIUM | Medium | LOW-MEDIUM | Completes capability map to 184/184 |
| **13: Polish** | MEDIUM | Medium | MEDIUM | Security + operational maturity |
| **14: Scale** | LOW | Large | HIGH (at scale) | Only needed for 100K+ deployments |
| **15: TAR Dashboard & Scope Walking** | HIGH | Medium | HIGH | Composable scope is Yuzu's product differentiator; commercial peers have no equivalent — TAR page also unifies retention awareness and process-tree forensics |
| **16: System Guardian** | **CRITICAL** | Large | **CRITICAL** | **The headline parity feature** — real-time agent-side guaranteed state. Without this, "policy engine equivalent" is an overclaim. PR ladder defined; first 2 PRs shipped. |

### Recommended Execution Order

```
Phase 8 (Visualization) ──── 1 sprint ──── Immediate visual impact
    │
Phase 9 (Connectors) ─────── DEFERRED 2026-09-07 (owner decision; placement review pending — see docs/roadmap.md)
    │
Phase 10 (Catalog) ────────── 1 sprint ──── Builds on 9.8 normalization
    │
Phase 12 (Agent Caps) ─────── 1 sprint ──── Close capability map to 100%
    │ (parallel)
Phase 11 (Consumer) ────────── 1 sprint ──── Platform extensibility
    │
Phase 13 (Polish) ──────────── 1 sprint ──── Security + UX
    │
Phase 14 (Scale) ───────────── 2 sprints ─── Large deployment readiness
    │
Phase 15 (TAR + Scope Walking) ─ 2 sprints ─ Product differentiator (composable scope)
    │
Phase 16 (System Guardian) ──── 4-6 sprints ─ THE headline parity feature; PRs 1-2 done, PRs 3-17 in ladder
```

**Total estimated effort: ~15-17 sprints (Phases 8-16). Phase 16 is the longest single phase because real-time agent-side enforcement spans three OS platform-specific delivery tracks (Windows-first per `docs/yuzu-guardian-windows-implementation-plan.md`, then Linux, then macOS) and each kernel-event API integration is independently load-bearing.**

---

## Part 5: New Capability Map Entries

After all phases complete, the capability map would grow from 184 to ~225 capabilities:

| New Domain | Capabilities |
|-----------|-------------|
| 25. Connector Framework | Connector CRUD, Sync Engine, Connection Testing, Sync Scheduling, Sync Logging |
| 26. Inventory Repositories | Repository CRUD, Consolidation, Deduplication, Normalization, Multi-Source Merge |
| 27. Software Catalog | Catalog Store, Software Normalization, AI Curation (stub), Usage Tracking, License Entitlements |
| 28. Response Visualization | Chart Rendering, Built-in Processors, Custom Processors, Template Management, **TAR Dashboard Page** (Phase 15.A — Partial), **TAR Process Tree Viewer** (Phase 15.H), **Retention Awareness Surface** (Phase 15.A) |
| 29. Consumer Applications | Consumer Registration, Rate Limiting, Data Offloading, Custom Data |
| **30. Scope Walking & Result Sets** | Result Set Persistence and Lineage (15.B), Composable Scope from Previous Query (15.C), YAML DSL `fromResultSet:` (15.E), Operational Hardening (15.G) |
| **31. System Guardian — Real-Time Agent-Side Guaranteed State** | Kernel-event-driven enforcement primitives, event guards (Registry / SCM / WFP / ETW / inotify / netlink / D-Bus / Endpoint Security), condition guards (process / software / compliance / WMI), pre-login activation, offline-capable cached policy, audit journal, dashboard, push protocol, signing, quarantine integration |

Plus the 19 existing "Not Started" items moved to "Done" = **~225 total, all done**.

---

## Part 6: What We Will NOT Build

Some commercial-peer features are not worth replicating because Yuzu has superior alternatives:

| Commercial Peer Feature | Why Not | Yuzu Alternative |
|----------------|---------|-----------------|
| Proprietary-script language interpreter | Massive effort, proprietary lock-in | WorkflowEngine + script_exec + plugin ABI |
| XML instruction definitions | Legacy format | YAML DSL (cleaner, more readable) |
| Windows-only authentication | Limits platform reach | OIDC/PKCE (universal) |
| SQL Server dependency | Ops burden, licensing cost | SQLite (embedded, zero-ops) |
| .NET Consumer SDK | Platform-specific | REST API + Python SDK + PowerShell module |
| Vendor-specific desktop IDE | Desktop app maintenance burden | Web-based YAML editor (CodeMirror) |
| Nomad (full P2P suite) | Years of engineering | Simpler P2P mesh (Phase 14.1) |
| AI Auto-Curation | Requires ML training data | Manual curation + LLM-assisted (via MCP) |
| Shopping / Self-Service Portal | Full separate product | SoftwareDeploymentStore + approval workflow |
| Experience Analytics | Separate product | Prometheus metrics + Grafana |

---

## Appendix: File Counts for Reference

| Component | Current Files | Current LOC (est.) |
|-----------|:------------:|:------------------:|
| Server core src/ | 174 files | ~45,000 |
| Agent plugins/ | 44 plugins | ~25,000 |
| Proto definitions | 4 .proto files | ~500 |
| Gateway (Erlang) | ~40 files | ~8,000 |
| Tests | 44 test files | ~15,000 |
| **Total** | **~300 files** | **~93,500** |
