# Yuzu Capability Map

**Version:** 4.1 | **Date:** 2026-11-14 | **Status:** v4.1 re-baseline against dev @ 2c49b4ea0 (see Method)

---

## How to Read This Document

Each capability is rated on two axes:

**Implementation Status**
| Icon | Status | Meaning |
|:----:|--------|---------|
| :white_check_mark: | **Done** | Implemented and functional |
| :large_orange_diamond: | **Partial** | Some coverage exists; gaps remain |
| :x: | **Not Started** | No implementation yet |

**Delivery Tier**
| Tier | Label | Meaning |
|------|-------|---------|
| **T1** | Foundation | Core capabilities for a viable endpoint management platform |
| **T2** | Advanced | Enterprise-grade features for production deployments at scale |
| **T3** | Future | Aspirational capabilities for competitive parity with top-tier platforms |

---

## Progress at a Glance

> **Method (reproduce this before trusting the number).** Every figure below is a direct
> tally of the per-entry status icons in the 42 domains that follow — no entry is counted
> outside its own domain, and each entry counts once against its `T1`/`T2`/`T3` tier label.
> Reproduce with:
> `awk '/^### [0-9]+\.[0-9]+/ { if ($0 ~ /:white_check_mark:/) d++; else if ($0 ~ /:large_orange_diamond:/) p++; else if ($0 ~ /:x:/) n++ } END { print d, p, n, d+p+n }' docs/capability-map.md`
> → `223 49 51 323`. Tier tallies (`Foundation`=T1, `Advanced`=T2, `Future`=T3) add the same
> awk pattern filtered on `` `T1` ``/`` `T2` ``/`` `T3` `` → T1 `55 2 2 59`, T2 `156 34 28 218`,
> T3 `12 13 21 46`.
> **v4.1 re-verification (2026-11-14).** A row-by-row audit of this file against the code (taken
> at dev @ 54c5c2b37, 2026-11-13) was applied here and its claims re-checked against the code at
> dev @ 2c49b4ea0, against which the counts were taken. It
> demoted §3.6, §9.7, §10.13 and §20.3, promoted §4.11, §5.4, §27.2, §29.2 and §35.3, corrected
> over-claims and stale line cites across most domains, and added 48 rows for shipped work the
> map did not list (34 Done, 13 Partial, 1 Not Started), including the new domain 42. Counts
> stated in rows (MCP tools, securables, stores, alert rules, plugin directories) were re-counted
> at that commit. The MCP tool figure now counts the `kTools[]` table plus the registry-declared
> tools (220), where earlier versions counted `kTools[]` alone. Rows marked `*(verified <date>)*`
> carry their own evidence and date; an unmarked row was covered by the 2026-11-13 audit but
> keeps its earlier wording where the audit found nothing to change.
> **"Done" counts presence, not per-OS completeness:** a Done row can have a constrained or
> unsupported OS leg, which the row states (Appendix A shows the legs per plugin).
> Four hand-maintained views
> must be updated together whenever a row's icon or tier changes: the headline/tier bars below,
> the per-domain summary table, Appendix A's plugin count, and Appendix B's Foundation tally —
> nothing in `tests/` or CI checks them against the awk yet (tracked as a governance follow-up).

```
Foundation   [==============================--]  55/59 done  (93%) (2 partial)
Advanced     [=======================---------]  156/218 done  (72%) (34 partial)
Future       [========------------------------]  12/46 done  (26%) (13 partial)
─────────────────────────────────────────────────────────────────
Overall      [======================----------]  223/323 done  (69%) (49 partial)
```

| Domain | Total | Done | Partial | Not Started |
|--------|:-----:|:----:|:-------:|:-----------:|
| 1. Agent Lifecycle Management | 9 | 9 | 0 | 0 |
| 2. Command Execution and Orchestration | 13 | 13 | 0 | 0 |
| 3. Device and Endpoint Information | 13 | 11 | 2 | 0 |
| 4. Network Information and Discovery | 13 | 11 | 1 | 1 |
| 5. Process and Service Management | 5 | 2 | 1 | 2 |
| 6. User and Session Management | 6 | 6 | 0 | 0 |
| 7. Software and Application Management | 11 | 7 | 3 | 1 |
| 8. Patch and Update Management | 10 | 4 | 4 | 2 |
| 9. Security and Compliance | 12 | 9 | 3 | 0 |
| 10. File System Operations | 16 | 12 | 2 | 2 |
| 11. Script and Command Execution | 4 | 4 | 0 | 0 |
| 12. Registry and System Configuration | 7 | 5 | 0 | 2 |
| 13. Content Distribution | 5 | 3 | 0 | 2 |
| 14. User Interaction | 6 | 5 | 0 | 1 |
| 15. Inventory and Data Collection | 5 | 4 | 0 | 1 |
| 16. Policy and Compliance Engine | 8 | 7 | 1 | 0 |
| 17. Triggers and Event-Driven Automation | 7 | 5 | 1 | 1 |
| 18. Server: Authentication and Authorization | 18 | 17 | 1 | 0 |
| 19. Server: Device and Group Management | 8 | 7 | 0 | 1 |
| 20. Server: Response Collection and Reporting | 9 | 8 | 1 | 0 |
| 21. Server: Notifications and Audit | 6 | 5 | 0 | 1 |
| 22. Server: System and Infrastructure | 12 | 5 | 4 | 3 |
| 23. Agent-Side Key-Value Storage | 3 | 3 | 0 | 0 |
| 24. Integration and Extensibility | 11 | 9 | 0 | 2 |
| 25. Connector Framework | 5 | 0 | 0 | 5 |
| 26. Inventory Repositories | 4 | 0 | 1 | 3 |
| 27. Software Licensing & Entitlements (SLE) | 6 | 1 | 2 | 3 |
| 28. Response Visualization | 9 | 5 | 2 | 2 |
| 29. Consumer Applications | 4 | 0 | 1 | 3 |
| 30. Scope Walking & Result Sets | 4 | 3 | 1 | 0 |
| 31. System Guardian | 10 | 1 | 7 | 2 |
| 32. DEX — Digital Employee Experience | 7 | 6 | 1 | 0 |
| 33. Network Quality | 4 | 3 | 0 | 1 |
| 34. Device Pages and Live Snapshot | 3 | 3 | 0 | 0 |
| 35. Agent Daily-Sync Inventory (ADR-0016) | 6 | 5 | 0 | 1 |
| 36. `/auto` — Operator Automation | 3 | 3 | 0 | 0 |
| 37. Internal PKI / Certificate Authority | 9 | 8 | 1 | 0 |
| 38. Server Storage Substrate — PostgreSQL | 4 | 4 | 0 | 0 |
| 39. Headless Platform — Engine Principals & On-Behalf-Of (ADR-1005) | 5 | 4 | 0 | 1 |
| **Subtotal (domains 1–39)** | **300** | **217** | **40** | **43** |
| 40. Reflex — Agent-Local Automated Response | 4 | 0 | 0 | 4 |
| 41. Cryptographic Asset Inventory | 8 | 2 | 2 | 4 |
| 42. Endpoint Security Posture | 11 | 4 | 7 | 0 |
| **TOTAL** | **323** | **223** | **49** | **51** |

> **Scaffolded vs production-quality.** The percentages above measure feature presence, not enterprise hardening. "Done" means "implemented and functional" — not "hardened, observable, and proven at large-fleet scale" on every domain. Known gaps at the §-level (e.g. configurable heartbeat in §1.2, unified diagnostics bundle in §1.3, runtime plugin install in §1.5) remain even where a domain is marked Done. The `docs/capability-agentic-audit-2026-05.md` audit (figures as of 2026-05 — its counts predate this v4.1 tally) is the source for the production-quality dimension; subsequent reviews should keep it current.

---

## 1. Agent Lifecycle Management

*Agent registration, health monitoring, self-diagnostics, and remote control.*

### 1.1 Agent Registration and Enrollment :white_check_mark: `T1`

3-tier enrollment model: manual approval (Tier 1), pre-shared tokens (Tier 2), and platform trust (Tier 3, reserved). gRPC `Register` RPC with enrollment token support.

> **Gap:** Tier 3 server-side certificate validation not implemented.

### 1.2 Heartbeat and Session Keepalive :white_check_mark: `T1`

`Heartbeat` RPC with pending command delivery and `status_tags` for lightweight state reporting.

> **Gap:** No configurable agent heartbeat interval from the server side (the interval is the agent's `--heartbeat` flag). The server's heartbeat *timeout* is operator-configurable (`settings_general_routes.cpp`).

### 1.3 Agent Summary and Diagnostics :white_check_mark: `T1`

`diagnostics` and `status` plugins report agent health, uptime, and resource usage. `agent_actions` plugin for self-management.

> **Gap:** No unified diagnostics bundle download (key files, logs).

### 1.4 Agent Version and Update Management :white_check_mark: `T1`

`CheckForUpdate`/`DownloadUpdate` RPCs in agent.proto. Full updater implementation (`agents/core/src/updater.cpp`) with hash verification and platform-specific self-update.

### 1.5 Agent Extensibility Introspection :white_check_mark: `T1`

Plugins reported in `RegisterRequest.AgentInfo.plugins` with name, version, description, and capabilities list.

> **Gap:** No runtime plugin install/uninstall from server. Per-plugin enablement and kill switches exist through `PluginConfigStore` (§18.17).

### 1.6 Agent Sleep and Stagger Control :white_check_mark: `T2`

Stagger control via `CommandRequest.stagger` field. Agents introduce random delay before executing, preventing thundering herd on broadcast.

### 1.7 Agent Logging and Log Retrieval :white_check_mark: `T2`

spdlog-based local logging on the agent. `agent_logging` plugin provides remote log retrieval (`get_log` action, configurable 1-500 lines) and key file listing (`get_key_files` action). Log file discovery from agent config with platform default fallbacks.

### 1.8 Connection and Session Info :white_check_mark: `T1`

Session ID returned on registration. `WatchEvents` tracks connect/disconnect events. `connection_info` action in diagnostics plugin reports server address, TLS status, session ID, gRPC channel state, reconnect count, latency, uptime.

### 1.9 Instruction Execution Statistics :white_check_mark: `T2`

`ExecutionTracker` (ADR-0065: migrated to PostgreSQL, schema `execution_tracker`) aggregation methods: per-agent stats, per-definition stats, fleet summary. REST endpoints: `GET /api/v1/execution-statistics`, `/agents`, `/definitions`. HTMX fragment for dashboard card.

---

## 2. Command Execution and Orchestration

*Dispatching instructions to agents, collecting results, and workflow coordination.*

### 2.1 Single-Agent Command Dispatch :white_check_mark: `T1`

`ExecuteCommand` RPC with streaming response. `SendCommand` in the management API. Operator surfaces: REST `POST /api/v1/commands` (`server/core/src/command_v1_routes.cpp`), MCP `execute_instruction`, and the legacy unversioned `POST /api/command` (`command_routes.cpp`).

### 2.2 Multi-Agent Broadcast :white_check_mark: `T1`

`SendCommandRequest.agent_ids` supports broadcast: an omitted target list means the whole fleet, **except for a `Destructive`-classified (plugin, action) pair**, which requires an explicit non-empty `agent_ids` and refuses `__all__` (#3685); a supplied target argument that names nothing is refused at the shape check, never widened to the fleet (#2500) (`server/core/src/dispatch_target_shape.hpp`, `dispatch_destructive_gate.hpp`). Who is actually reached is decided by one per-device visibility intersection (`dispatch_confined_arms.hpp`); a management group or scope expression is targeting, never an authorization exemption. Scope/filter targeting is also supported: `AgentRegistry::evaluate_scope` (`server/core/src/agent_registry.cpp`, `evaluate_scope_impl`; also accepts `from_result_set:<id>`, §30.2) instantiates an `AttributeResolver` lambda that resolves `ostype`, `hostname`, `arch`, `agent_version`, `tag:X` (in-memory `scopable_tags` plus persistent `TagStore` fallback), and `props.X` (custom properties), composed via the scope DSL's `AND` / `OR` / `NOT`. See `docs/asset-tagging-guide.md` and `docs/scope-walking-design.md` for operator-level usage.

### 2.3 Streaming Command Output :white_check_mark: `T1`

`CommandResponse` streams via gRPC and SSE to the dashboard.

### 2.4 Command Timeout and Expiry :white_check_mark: `T1`

`CommandRequest.expires_at` and `SendCommandRequest.timeout_seconds`.

> **Gap:** No server-side command cancellation mid-execution.

### 2.5 Bidirectional Command Channel :white_check_mark: `T1`

`Subscribe` bidi-streaming RPC as alternative to polling.

### 2.6 Instruction Templates / Definitions :white_check_mark: `T2`

`InstructionStore` with full CRUD. Named, versioned definitions with YAML source, parameter schema (JSON Schema), result schema (typed columns), approval mode, concurrency mode, platform constraints. JSON import/export. Stored in PostgreSQL (ADR-0008).

### 2.7 Instruction Sets (Grouping) :white_check_mark: `T2`

`InstructionSet` CRUD in `InstructionStore`. Named logical groupings with cascade delete. Definitions belong to at most one set. RBAC permissions scoped at set level.

### 2.8 Instruction Hierarchies (Workflows) :white_check_mark: `T2`

`ExecutionTracker` supports parent/child execution hierarchy via `parent_execution_id`. Query children by parent. Follow-up instructions use parent response data as scope input.

Multi-step workflows (`WorkflowEngine`) can be started over REST v1 (`POST /api/v1/workflows/{id}/execute`) and MCP (`execute_workflow`, #2146), which run one shared sequence: every step is checked against the caller before anything is sent, a `supervised`-tier MCP token needs an approval ticket, an idempotency key makes a lost answer safe to repeat (required on MCP), and a run is synchronous, limited to 2 concurrent runs per principal per server process and stopped at 60 seconds. **Gaps:** no asynchronous run (a run holds an HTTP worker until its steps are sent), no sweep of runs left `running` by a crash, and a revoked API token can outlive a revoke on another replica for up to 60 seconds during a run. See ADR-1005, 2026-11-05 entry, "Known residuals".

### 2.9 Instruction Scheduling :white_check_mark: `T2`

`ScheduleEngine` (ADR-0065: migrated to PostgreSQL, schema `schedule_engine`) with frequency types (daily, weekly, monthly, sub-day), scope expressions evaluated dynamically at dispatch, enable/disable toggle, execution history tracking. REST CRUD via `/api/schedules`.

### 2.10 Instruction Approval Workflows :white_check_mark: `T2` *(verified 2026-09-10)*

`ApprovalManager` (ADR-0065: migrated to PostgreSQL, schema `approval_manager`) with submit/approve/reject, ownership validation (reviewer != submitter), pending count, scope expression, and full audit trail. Per-definition approval mode (auto/role-gated/always). *(Spot-checked 2026-09-10, Gate-of-record pass 3 sweep item 5: `approval.approve`/`approval.reject`/`approval.read` all write real `audit_log`/`audit_fn` rows — `server/core/src/server.cpp:17412-17478`, `rest_api_v1.cpp:7284`. "Full audit trail" claim holds.)*

### 2.11 Target Estimation :white_check_mark: `T2`

`ScopeEngine` with the `POST /api/scope/estimate` endpoint, which evaluates a scope expression against connected agents and returns only the matching count (`{matched, total}`, `workflow_routes.cpp`). The list of matching agents comes from `POST /api/v1/scope/preview` and its MCP twin `preview_scope_targets` (fleet-read gated, audited); `POST /api/v1/scope/validate` / MCP `validate_scope` check syntax only.

### 2.12 Instruction Progress Tracking :white_check_mark: `T2`

`ExecutionTracker` with per-agent status tracking (dispatched, responded, success, failure), aggregate progress percentage, summary with agent state counts. Dashboard progress bars via REST API.

### 2.13 Instruction Rerun and Cancellation :white_check_mark: `T2`

`ExecutionTracker` supports rerun (clone with same parameters, optional failed-only targeting) and cancellation with user attribution. REST endpoints: `POST /api/executions/{id}/rerun`, `POST /api/executions/{id}/cancel` (`execution_routes.cpp`), plus the versioned `POST /api/v1/executions/{id}/cancel` and `/rerun` and MCP `cancel_execution` / `record_execution_rerun`. Cancellation is tracker-level: there is no agent-side cancel RPC (§2.4).

---

## 3. Device and Endpoint Information

*Hardware, OS, identity, and classification data from managed endpoints.*

### 3.1 OS Summary :white_check_mark: `T1`

`os_info` plugin (cross-platform). Platform reported in registration.

### 3.2 Hardware Inventory :white_check_mark: `T1`

`hardware` plugin (cross-platform): `baseboard`, `bios`, `chassis`, `disks`, `drivers`, `drivers_inventory`, `machine_id`, `manufacturer`, `memory`, `model`, `processors`, `swap`, `system`.

### 3.3 Device Identity :white_check_mark: `T1`

`device_identity` plugin (`device_name`, `domain`, `ou`). `agent_id` (UUID) in protocol.

> **Gap:** No FQDN-based server-side lookup.

### 3.4 Disk Information :white_check_mark: `T1`

Covered by the `hardware` plugin (`disks`), plus `disk_space` (`free`, all three OSes) and `disk_actions` (`smart`, `volumes`, `partitions`, `topology`; Windows supported, macOS constrained, Linux planned).

### 3.5 Processor Details :white_check_mark: `T1`

Covered by the `hardware` plugin (`processors`).

### 3.6 Device Criticality Classification :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Done → Partial.** There is no dedicated criticality attribute anywhere in the server, agent, content or user manual. `TagStore` has four fixed categories (`role`, `environment`, `location`, `service`; `server/core/src/tag_store.hpp` `kCategoryKeys`), and an operator can write an arbitrary key named `criticality` by convention, but nothing reads or acts on it.

### 3.7 Device Location Tracking :white_check_mark: `T2`

Implemented as a special-purpose tag via the device tagging system (`TagStore`). Set/get location per device using key-value tags.

### 3.8 Mapped Drive History :large_orange_diamond: `T3`

`mapdrive` Echo capture source (`agents/plugins/echo/src/echo_mapdrive_collector.cpp`). Tracks network-share mappings in **both** directions — outbound (drives this host maps to remote shares) and inbound (remote hosts mapping this host's shares, the lateral-movement signal) — via a `direction` column. A one-time init backfill seeds **historical** mappings (`origin='historical'`) from persistent artifacts; the periodic `collect_slow` leg snapshot-diffs current state (`appeared`/`removed`). Windows: outbound `WNetEnumResourceW`; outbound history from registry `Network`/MRU/`MountPoints2` across offline profiles; inbound `NetSessionEnum` (needs local-admin/Server-Operator); inbound history from Security event log 4624/4634. Linux: outbound `/proc/mounts` + `/etc/fstab`; inbound `smbstatus` + Samba logs. On by default (`mapdrive_enabled`) — rows carry usernames + share paths. Queryable via `$MapDrive_Hourly` and `$MapDrive_Daily`. The `shares` plugin is the complement on the serving side: it reports the shares this host serves over SMB/NFS (on Linux as configured, on Windows the live Server-service shares; names and paths, never ACLs), not the mappings and sessions mapdrive observes.

> **Gap:** macOS has an outbound live leg only (`getfsstat`, `classify_macos_mounts`); macOS history and inbound are not collected. Linux inbound requires Samba installed; Windows inbound-history over-captures (all type-3 network logons, not only SMB).

### 3.9 Printer Inventory :white_check_mark: `T3` *(verified 2026-09-15)*

`printing` agent plugin. `printers`/`jobs` enumerate local/connected printers and their not-completed queued jobs via IPP over the CUPS Unix socket (macOS/Linux) or winspool (Windows) — no libcups. `clear_queue` cancels exactly one job (Destructive/Irreversible, admin-or-approval) with no purge-all path; it is supported on Windows and constrained on macOS and Linux, where the agent runs unprivileged and cupsd refuses (403) to cancel a job the agent does not own. See `agents/plugins/printing/README.md`.

### 3.10 Device Tagging (Key-Value Metadata) :white_check_mark: `T2` *(verified 2026-09-10)*

`TagStore` on the PostgreSQL substrate (ADR-0050, schema `tag_store`). Full CRUD: set, get, get_all, delete, check, clear, count. Agent-side `tags` plugin with server-side sync on Register. Validation: key max 64 chars, value max 448 bytes. `agents_with_tag()` for scope queries; typed degrade-distinguishable reads (a store failure never reads as "no tags"). *(Spot-checked 2026-09-10, Gate-of-record pass 3 sweep item 5: `tag_store.hpp` genuinely returns `std::expected<...>`/`std::optional<T>` — "read fine, genuinely nothing here" is type-distinguished from a degrade, with its own `yuzu_server_tag_store_read_degrade_total{reason}` metric. Claim holds.)*

### 3.11 Peripheral Device Inventory :white_check_mark: `T2` *(new row, v4.1)*

`peripherals` plugin: `usb`, `pci` and `thunderbolt` device trees on Windows (SetupAPI), macOS (IOKit) and Linux (`/sys/bus/*`), read-only (`Inventory:Read`), no subprocess. An empty bus answers `<kind>|none`; a read that could not be attempted answers a constrained row, never an empty list. No `pci.ids`/`usb.ids` name database is shipped. *(Evidence: `agents/plugins/peripherals/README.md`.)*

### 3.12 Power, Battery and Thermal Health :white_check_mark: `T2` *(new row, v4.1)*

`power_health` plugin: `battery`, `thermal`, `power_plan` (read-only, `Inventory`) and `set_power_plan`, the only destructive power action (`PowerManagement:Write`, Destructive and reversible via `previous_guid`, AdminOrApproval). Windows and macOS supported; Linux constrained. *(Evidence: `agents/plugins/power_health/README.md`; `docs/user-manual/power-health.md`.)*

### 3.13 Virtualization and Container Facts :white_check_mark: `T2` *(new row, v4.1)*

`virtualization` plugin: `host` (whether the device is a VM, which hypervisor, container membership, from CPUID, DMI/SMBIOS and sysctl reads), `wsl` (WSL distributions, AdminOrApproval) and `runtime_posture` (Linux container-runtime posture over an operator-provided control socket only; the empty default never opens a socket; `Security:Read`). macOS and Linux supported; Windows constrained. *(Evidence: `agents/plugins/virtualization/README.md`; `docs/virtualization-runtime-posture-design.md`.)*

---

## 4. Network Information and Discovery

*Network configuration, connection state, and active discovery.*

### 4.1 IP Address and Interface Enumeration :white_check_mark: `T1`

`network_config` plugin (cross-platform).

### 4.2 TCP Connection Listing :white_check_mark: `T1`

`netstat` plugin (cross-platform).

### 4.3 Listening Endpoint Enumeration :white_check_mark: `T1`

`netstat` plugin (`netstat_list` action; `attribution` adds owning-process
resolution -- folded from the retired sockwho plugin, #3403).

### 4.4 ARP Table :white_check_mark: `T1`

`network_config` plugin `arp` action. Windows supported (`GetIpNetTable2`); macOS (PF_ROUTE sysctl) and Linux (`/proc/net/arp`, IPv4 only) constrained.

### 4.5 DNS Cache Retrieval :white_check_mark: `T1` *(verified 2026-09-10)*

`network_actions` plugin has flush DNS. `dns_cache` action in `network_config` plugin dumps DNS cache (Windows supported: `DnsGetCacheDataTable` via dnsapi.dll; Linux constrained: `resolvectl` via the direct-argv runner; **macOS unsupported**, returns an `unsupported` row). *(Spot-checked 2026-09-10, Gate-of-record pass 3 sweep item 5: `network_actions` plugin's real `acts[]` includes `"flush_dns"` — `agents/plugins/network_actions/src/network_actions_plugin.cpp:99`. Claim holds.)*

### 4.6 WiFi Network Enumeration :white_check_mark: `T2`

`wifi` plugin (Windows supported; macOS and Linux constrained for both actions). `list_networks` scans for visible WiFi networks with SSID, signal strength, security type, channel, and BSSID. `connected` reports the currently connected network. Windows: WlanAPI, Linux: NetworkManager D-Bus (nmcli fallback). macOS: `connected` uses CoreWLAN (`wifi_corewlan.mm`); `list_networks` uses legacy `airport -s`/`system_profiler`. On macOS 14+, Location Services withholds SSID/BSSID from a background daemon, reported as `<ssid-withheld>` on an otherwise-live connection.

### 4.7 Wake-on-LAN :white_check_mark: `T2`

`wol` plugin (cross-platform). `wake` sends magic packet (UDP broadcast, 6×0xFF + 16×MAC) to a target MAC address. `check` verifies reachability natively — unprivileged ICMP echo (`IcmpSendEcho` on Windows, an unprivileged ICMP socket on Linux/macOS) with a TCP-connect fallback on port 443 for hosts/kernels that drop or deny ICMP (Wave 2, ADR-3002) — no subprocess spawn on any platform. `wake` is supported on all three OSes; `check` is constrained on Linux.

### 4.8 Network Diagnostics :white_check_mark: `T1`

`network_diag` plugin (cross-platform). `network_actions` for ping.

### 4.9 NetBIOS / Name Lookup :x: `T3`

Not implemented. Legacy reverse lookup on IP addresses.

### 4.10 ARP Scanning (Subnet Discovery) :white_check_mark: `T3`

`discovery` plugin with `scan_subnet` action. ARP scan + ping sweep of a CIDR subnet to find hosts. Returns IP, MAC address, hostname, and managed/unmanaged status. Windows and macOS supported, Linux constrained: native ARP-table acquisition (`GetIpNetTable2` on Windows, `/proc/net/arp` on Linux, the routing-socket `sysctl` on macOS) + an unprivileged ICMP ping sweep — no subprocess spawn on any platform (Wave 2, ADR-3002). Input validation prevents command injection on CIDR parameter.

### 4.11 Port Scanning :large_orange_diamond: `T3` *(verified 2026-11-14)*

**Regraded 2026-11-14: Not Started → Partial.** The `netprobe` plugin's `tcp` action (all three OSes, non-blocking `connect()` timing) probes ONE port (`port`, default 443, 1-65535) on a small set of operator-chosen hosts and reports round-trip time and loss. There is no port-range or multi-port sweep and no service identification. *(Evidence: `agents/plugins/netprobe/README.md`.)*

### 4.12 Active Network Probing :white_check_mark: `T2` *(new row, v4.1)*

`netprobe` plugin: `icmp`, `tcp` and `dns` timing probes (round-trip time, jitter, loss, DNS resolution time) to operator-chosen targets, on Windows, macOS and Linux, read-only (`Infrastructure:Read`). *(Evidence: `agents/plugins/netprobe/README.md`.)*

### 4.13 Served Shares Inventory :white_check_mark: `T3` *(new row, v4.1)*

`shares` plugin `list`: the shares this host serves over SMB/NFS (names, paths and a few flags, never ACLs), on all three OSes. The serving-side complement of §3.8 mapdrive. *(Evidence: `agents/plugins/shares/README.md`.)*

---

## 5. Process and Service Management

*Enumerate, inspect, and control running processes and system services.*

### 5.1 Process Enumeration :white_check_mark: `T1`

`processes` plugin (cross-platform). `procfetch` for formatted view with executable hash.

### 5.2 Process Termination :x: `T1` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `processes` plugin has no `kill` action. Its full and only action set, quoted from the dispatcher, is `acts[] = {"list", "list_hashed", "list_tree", "query", nullptr}` (`agents/plugins/processes/src/processes_plugin.cpp:301`); an unrecognized action is rejected (`:331`). *(Line cites re-checked 2026-11-14.)* No other plugin declares a process-kill action (`grep -rl '"kill"' agents/plugins/*/src/*.cpp` → 0 hits). **Generic scripting can terminate a process** — `taskkill`/`Stop-Process` (Windows) or `kill` (POSIX) via the `script_exec` plugin's `exec`, `powershell` and `bash` actions — but that is a different contract from a native, governed, RBAC-scoped `processes.kill` action: no dedicated action descriptor, no typed parameters, no per-action authorization classification. *(Evidence: `processes_plugin.cpp:301,331`; previously mis-graded Done.)*

### 5.3 Service Enumeration :white_check_mark: `T1`

`services` plugin (cross-platform).

### 5.4 Service Control :large_orange_diamond: `T1` *(verified 2026-11-14)*

**Regraded 2026-11-14: Not Started → Partial (start-mode only).** The `services` plugin has no immediate start/stop/restart action. Its full and only action set, quoted from the dispatcher, is `acts[] = {"list", "running", "set_start_mode", nullptr}` (the `acts[]` table in `agents/plugins/services/src/services_plugin.cpp`; any other action is rejected). `set_start_mode` changes a service's startup type on **all three OSes**, natively and governed (`Infrastructure:Write`, AdminOrApproval): Windows through the SCM API, macOS `launchctl enable|disable` and Linux `systemctl enable|disable|mask|unmask` through the direct-argv runner (`sudo -n`). That is a different operation from starting, stopping or restarting a running service, which is the half still missing. **Generic scripting can control a service** — `sc.exe`/`Stop-Service`/`Restart-Service` (Windows) or `systemctl` (Linux) via `script_exec` — but that is a different contract from a native, governed, RBAC-scoped service-control action. *(Evidence: `services_plugin.cpp:657,683`; `agents/plugins/services/README.md`. Corrected 2026-09-08 (external audit) from a mis-graded Done; this pass credits the start-mode half.)*

### 5.5 Open Windows Enumeration :x: `T3`

Not implemented. Desktop interaction to enumerate visible application windows.

---

## 6. User and Session Management

*Enumerate users, sessions, and group membership on managed endpoints.*

### 6.1 Logged-On User Enumeration :white_check_mark: `T1`

`users` plugin (cross-platform).

### 6.2 Primary User Determination :white_check_mark: `T2`

`users` plugin `primary_user` action. Identifies primary user via most-frequent-login heuristic. Linux: parses `last` output. macOS: parses `last` output. Windows: queries Event Log 4624 logon events, falls back to registry ProfileList.

### 6.3 Local Group Membership :white_check_mark: `T2`

`users` plugin `local_admins` action lists Administrators group members. `group_members` action enumerates members of any specified local group. Linux: parses `/etc/group` + checks sudo/wheel. Windows: NetLocalGroupGetMembers API. macOS: dscl.

### 6.4 User Connection History :white_check_mark: `T2`

`users` plugin `session_history` action. Historical login/logout records with configurable count (default 50). macOS and Linux supported (`last` via the direct-argv runner); Windows constrained (Security event log 4624/4634 via wevtapi).

### 6.5 Active Session Enumeration :white_check_mark: `T2`

`users` plugin `sessions` action. Lists active interactive sessions (console, RDP, SSH) with user, session type, login time, and state. Cross-platform.

### 6.6 Local User Account Enumeration :white_check_mark: `T2` *(new row, v4.1)*

`users` plugin `local_users` action: the local accounts defined on the device, on Windows, macOS and Linux (`UserManagement:Read`, read-only). *(Evidence: `agents/plugins/users/README.md`.)*

---

## 7. Software and Application Management

*Inventory installed software, manage installations, and control applications.*

### 7.1 Installed Application Inventory :white_check_mark: `T1`

`installed_apps` plugin (cross-platform).

### 7.2 Windows Installer (MSI) Package Inventory :white_check_mark: `T1`

`msi_packages` plugin (Windows MSI / macOS pkgutil). Distinct from `windows_optional_features`: MSI inventories installed software packages, `windows_optional_features` reports the state of built-in Windows OS features (DISM) — neither reads the other's data.

### 7.3 SCCM Integration :white_check_mark: `T2`

`sccm` plugin (Windows).

### 7.4 Software Uninstall :x: `T2` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `software_actions` plugin has no uninstall action. Its full and only action set, quoted from the dispatcher, is `acts[] = {"list_upgradable", "installed_count", nullptr}` (`agents/plugins/software_actions/src/software_actions_plugin.cpp:556`, unrecognized actions rejected at `:578`) — inventory reads, not mutation. `msi_packages` is likewise read-only: `acts[] = {"list", "product_codes", "list_inventory", nullptr}` (`msi_packages_plugin.cpp:473`). **Generic scripting can uninstall software** — `msiexec /x`, package-manager uninstall commands, or vendor uninstallers via `script_exec` — but that is a different contract from a native, governed, RBAC-scoped uninstall action. *(Evidence: `software_actions_plugin.cpp:556,578`, `msi_packages_plugin.cpp:473`; previously mis-graded Done — no evidence text at all, just "`software_actions` plugin" with no action named.)*

### 7.5 Per-User Application Inventory :white_check_mark: `T2`

`installed_apps` plugin extended with per-user hive enumeration (`list_per_user`): each local profile's `Software\Microsoft\Windows\CurrentVersion\Uninstall` is read from the live `HKEY_USERS\<SID>` hive when the user is logged in, falling back to an offline `NTUSER.DAT` mount otherwise — via the shared ladder in `agents/shared/win_profiles.hpp` (#2771), not a literal `HKCU` read (which under the agent's system-context identity resolves to the service account's own profile, not an end user's — see §12.7). Distinguishes system-wide from user-specific installs in output; on Linux/macOS `list_per_user` reports system-scope packages/apps plus (macOS) the calling account's own Homebrew formulae, not a per-profile walk.

### 7.6 Software Deployment (Install/Upgrade) :large_orange_diamond: `T2` *(verified 2026-09-07)*

**Regraded 2026-09-08 (external audit, Codex Astra C2), like §22.3: implemented and tested, not constructed by the server — routes do not register today.** `SoftwareDeploymentStore` (PostgreSQL, ADR-0051) with package registration, deployment lifecycle (staged/deploying/verifying/completed/cancelled/rolled_back/failed), per-agent status tracking. REST endpoints: `GET/POST /api/v1/software-packages`, `GET/POST /api/v1/software-deployments`, `/start`, `/rollback`, `/cancel`. The production registration call passes `nullptr` for this store — `/*sw_deploy_store=*/nullptr` (`server/core/src/server.cpp:22773`) — and route registration is conditional on it (`rest_api_v1.cpp`, gated block). **This is a distinct capability from the live `/auto` Deploy workflow (§36.2)**, which is NOT dormant: `DeploymentRunStore` is constructed at `server.cpp:5520`, `DeploymentRoutes` registers live, and `DeploymentEngine` dispatches `content_dist.stage` then `content_dist.execute_staged` (`deployment_engine.cpp:342,367`) — Yuzu can and does install software today through that path; only this catalog/package-registry API is unreachable. The MCP twins (`list_software_deployments`, `create_software_deployment`, `rollback_software_deployment`, `cancel_software_deployment`) are registered and advertised in `tools/list`, but with no store behind them they answer "unavailable". *(Evidence: `server.cpp:22773`, `deployment_engine.cpp:342,367`; line cites re-checked 2026-11-14; previously mis-graded Done despite the row's own "Dormant" text.)*

### 7.7 Package-Manager Inventory :white_check_mark: `T2` *(new row, v4.1)*

`pkg_inventory` plugin: `managers`, `packages` and `store_packages` — machine-scope package-manager inventory on Windows, macOS and Linux (`Inventory:Read`). Per-user package stores are out of scope. *(Evidence: `agents/plugins/pkg_inventory/README.md`.)*

### 7.8 Language-Runtime Inventory :white_check_mark: `T2` *(new row, v4.1)*

`runtimes` plugin: installed .NET (`dotnet`), JVM (`jvm`) and Python (`python`) runtimes at the standard machine-scope roots, on all three OSes, with no subprocess and no followed symlink. A failed or skipped read is a `<os>:runtimes:<cause>` token and a constrained answer, so zero rows means "none found at the standard roots", never "none installed". Feeds the installed-software daily-sync source (§35.2). *(Evidence: `agents/plugins/runtimes/README.md`.)*

### 7.9 Windows Optional Features :white_check_mark: `T2` *(new row, v4.1)*

`windows_optional_features` plugin: `list` and `info` report built-in Windows OS feature state (enabled/disabled/pending) through a bounded DISM API call; read-only, Windows-only (macOS and Linux unsupported). See §7.2 for how this differs from MSI inventory. *(Evidence: `agents/plugins/windows_optional_features/README.md`.)*

### 7.10 Middleware Inventory :large_orange_diamond: `T3` *(new row, v4.1)*

`middleware` plugin: installed middleware from installer metadata, table-driven, with IBM MQ (`ibm_mq`) as the one product so far; no subprocess. **Linux only** — Windows and macOS are planned. Feeds the installed-software daily-sync source (§35.2). *(Evidence: `agents/plugins/middleware/README.md`.)*

### 7.11 Browser and Profile Inventory :large_orange_diamond: `T3` *(new row, v4.1)*

`browser_inventory` plugin: Chromium-family `browsers` and `profiles`; never an account identifier, history, cookies or bookmarks, and e-mail-shaped values are redacted by value. Forensics securable, default-off, AdminOrApproval, single-target. **Linux only** — Windows and macOS are planned; extensions are a later change. Browser *policy* is §42.5. *(Evidence: `agents/plugins/browser_inventory/README.md`.)*

---

## 8. Patch and Update Management

*Detect, deploy, and track operating system and application patches.*

### 8.1 Installed Update Enumeration :white_check_mark: `T1`

`windows_updates` plugin with `installed` action. Cross-platform: Windows (bounded WMI `Win32_QuickFixEngineering` query, capped at 512 rows, unsorted — WQL has no `ORDER BY` for a data-class query, a disclosed behaviour change from the retired PowerShell path's 50-most-recent-sorted output), Linux (rpm/apt), macOS (system_profiler).

### 8.2 Pending Reboot Detection :white_check_mark: `T1`

`windows_updates` plugin `pending_reboot` action. Cross-platform reboot-pending detection:
Windows (3 registry keys: WindowsUpdate RebootRequired, CBS RebootPending, Session Manager PendingFileRenameOperations),
Linux (reboot-required file + kernel version comparison + needs-restarting fallback),
macOS (softwareupdate restart flag, bounded to a 60s deadline — replaces the plugin's
own prior unbounded `popen()` call, which could hang indefinitely on a headless/offline
Mac). Reports per-source status and aggregate boolean. Windows and Linux supported; macOS constrained.

### 8.3 Patch Deployment :large_orange_diamond: `T2`

`PatchManager::deploy_patch()` (Postgres-backed, ADR-0062) creates a deployment record + a
`pending` per-target row for a KB across one or more agents; `get_deployment()`/
`list_deployments()`/`cancel_deployment()` and REST endpoints for the same. **The scan →
download → install → verify → reboot orchestration workflow itself has no server-side
implementation** — it existed as `PatchManager::execute_deployment()` but had zero production
callers (nothing ever wired a dispatch/OS-lookup callback to it) and was deleted rather than
ported in the store's Postgres migration; see #3669 for the removed tested-but-unwired
implementation. A target's status only advances past `pending` via a direct
`update_target_status()` call, which nothing in this codebase makes today. *(Re-verified
2026-09-07 for the v4.0 baseline: `execute_deployment()` remains absent from
`server/core/src/patch_manager.{hpp,cpp}`; grade unchanged.)*

### 8.4 Patch Status Tracking :large_orange_diamond: `T2`

`PatchManager` tracks per-device deployment status via `PatchDeploymentTarget` — per-agent
status, error message, start/complete timestamps, settable via `update_target_status()` and
queryable via `get_deployment()`/REST. **Deployment-level aggregate counters
(`completed_targets`/`failed_targets`) are set once at creation and never recalculated
afterward** — the only caller of the former `recalculate_deployment_progress()` was
`execute_deployment()` (§8.3), deleted alongside it.

### 8.5 Patch Metadata Retrieval :large_orange_diamond: `T2`

`PatchInfo` stores KB ID, title, severity (Critical/Important/Moderate/Low/Unspecified), release
date, and scan timestamp. `get_fleet_patch_summary()` returns per-KB missing counts.
`get_missing_patches()` and `get_installed_patches()` support severity and agent filtering — all
correctly implemented, but **`record_patches()`, the only method that writes `patch_inventory`,
has no production caller** (verified by grep — pre-existing, predates the Postgres migration),
so every one of these reads returns empty in any real deployment (verified 2026-11-14). See #3676. Agent-side, missing-update data does exist: `windows_updates.missing` (§8.10) reports it per device on demand, but nothing feeds it into `patch_inventory`.

### 8.6 Reboot Management (Post-Patch) :x: `T2`

Reboot orchestration (`PatchManager::execute_deployment()`: pre-reboot `device.interaction.notify`
best-effort user notice, then a cross-platform reboot command — Windows `shutdown /r /t N /c`,
Linux/macOS `shutdown -r +N`) existed but had zero production callers and was removed in the
store's Postgres migration (ADR-0062); see #3669 for the removed tested-but-unwired
implementation. `reboot_delay_seconds`/`reboot_at` are still accepted by
`POST /api/patches/deploy`, clamped, and stored on `PatchDeployment`, but nothing currently acts
on them. *(Re-verified 2026-09-07 for the v4.0 baseline: no reboot-orchestration call site
found; grade unchanged.)*

### 8.7 Update Summary and Compliance Reporting :large_orange_diamond: `T2`

`PatchManager::get_fleet_patch_summary()` returns fleet-wide patch compliance (per-KB missing
agent counts). `get_missing_patches()` with `PatchQuery` filters by agent, severity, status.
Deployment tracking reports `total_targets` (accurate as of creation); `completed_targets`/
`failed_targets` do not auto-update post-creation (§8.4). **Fleet compliance reporting reads the
same never-populated `patch_inventory` table as §8.5** — see that section and #3676.

### 8.8 Patch Connectivity Testing :white_check_mark: `T2`

`patch_connectivity` action in `windows_updates` plugin. Per-target DNS resolution (getaddrinfo), TCP connect (non-blocking socket), latency measurement. Platform-specific defaults: Windows Update/WSUS, apt/yum repos, Apple SWUpdate.

### 8.9 Patch Inventory Event Generation :x: `T3`

Not implemented. Event emission for SIEM/compliance integration.

### 8.10 Missing-Update Detection :white_check_mark: `T2` *(new row, v4.1)*

`windows_updates` plugin `missing` action (definition `device.windows_updates.missing`), supported on all three OSes: Windows through an asynchronous WUA COM search, macOS through `softwareupdate`, Linux through apt and yum. A per-device, on-demand read; it does not populate the server-side `patch_inventory` table behind §8.5/§8.7. *(Evidence: `agents/plugins/windows_updates/README.md`; `content/definitions/windows_updates.yaml`.)*

---

## 9. Security and Compliance

*Antivirus, firewall, encryption, vulnerability scanning, and device quarantine.*

### 9.1 Antivirus Status and Product Detection :white_check_mark: `T1` *(verified 2026-09-10)*

`antivirus` plugin (cross-platform). macOS `products` probes the XProtect
definition bundle (version row; `unknown` when unreadable, never assumed
active) and enumerates endpoint-security system extensions for third-party
EDR/AV; macOS `status` reports XProtect definition version/freshness plus
Remediator/MRT engine versions (`security.antivirus.xprotect_status`). `av_exclusions` reports configured antivirus exclusions on Windows only (registry; macOS and Linux unsupported). *(Spot-checked
2026-09-10, Gate-of-record pass 3 sweep item 5: `antivirus_parsers.hpp:238` defaults
an unreadable field to `"unknown"` rather than guessing — the honest-empty pattern
this claim describes is real in the source. Claim holds.)*

### 9.2 Firewall Status and Rule Enumeration :white_check_mark: `T1`

`firewall` plugin (cross-platform). macOS `state` reports the Application
Firewall (`socketfilterfw --getglobalstate`) as the primary signal, with the
pf packet filter demoted to a secondary row; `rules` lists pf rules. Both
actions also read the unprivileged per-app allow/block list
(`socketfilterfw --listapps`) on `rules`, and the root-only pf anchor list
(`pfctl -s Anchors`) and rule count (`pfctl -s rules`) on both actions —
each degrading to no anchor rows / `ruleset|unknown` rather than a false
answer when the read is refused or incomplete. Windows adds a `ruleset|<n>`
row on both actions via `INetFwRules::get_Count` — `state`'s is the true
policy-wide total, `rules`' is the count of rows actually emitted that call
(capped at 100), a distinct number from `state`'s. Linux probes a fixed
backend ladder — firewalld (sd-bus) → nftables (netlink, kernel-origin-
verified via `nl_pid == 0`) → ufw → iptables — stopping at the first that
answers; a refused or partial read reports `unknown`, never a false-safe
guess, and each backend emits its own `ruleset|<n>` rule count (or
`ruleset|unknown` on an incomplete/refused read).

### 9.3 Disk Encryption Status :white_check_mark: `T1`

`bitlocker` plugin (cross-platform): Windows BitLocker via an in-process
Win32_EncryptableVolume WMI query + per-volume `GetConversionStatus()`
method call (rung 1, no subprocess), Linux LUKS via in-process libblkid
enumeration + plain `/sys/class/block/dm-*/dm/uuid` reads (`list_luks_volumes`,
rung 1, no subprocess), and macOS FileVault (`fdesetup` + per-APFS-volume
`diskutil apfs list`, direct argv through the bounded subprocess runner,
rung 2) — all three dispatched from the plugin's `state` action.

### 9.4 Vulnerability Scanning :large_orange_diamond: `T1`

`vuln_scan` plugin + NVD database sync on server. Server-side matching now uses
real CPE version ranges (`cve`+`cve_match` schema), but **coverage is still
partial**: the NVD sync now backfills the full CVE catalog newest-first
(configurable window via `--nvd-backfill-years`, default 8y, resumable across
restarts, then periodic freshness re-checks), yet match identity is still
product-name based, not vendor/CPE-precise (false positives from name
collisions possible; vendor precision pending ADR-0018). See
`docs/vuln-scan-roadmap.md`.

> **ADR-1005 grandfathered surface #2.** The server-side NVD sync + CVE
> matching is in-server *interpretation* under ADR-1005's boundary test and is
> grandfathered until re-homed into the first use-case engine (UCE) module —
> a strangler migration gated on a matcher-parity milestone (M3) before any
> server-side deletion; see `docs/adr-1005-execution-plan.md`. The agent-side
> `vuln_scan` collection action is *mechanism* and stays core, but the
> plugin's embedded static CVE rule list (`cve_rules.hpp`) and its use as an
> authoritative `cve_scan` finding source are **frozen (no further rule
> updates) and deprecated**. Re-verified 2026-11-14: `VulnFindingStore`
> (`server/core/src/vuln_finding_store.{hpp,cpp}`) is now constructed on Postgres
> (`server.cpp:5563`), but only the health and readiness probes touch it, and
> `VulnFindingStore::reconcile_agent` has **zero production callers** — the store's own
> header says "no engine calls `reconcile_agent` yet (PR 4 lands the matching engine)".
> The modern matcher, finding reconciliation, correlation, attack-path and
> disposition-lifecycle capabilities are **design-only and not implemented**
> (their designs are accepted in ADRs 0018/0023/0029/4001/4004); do
> not read the basic plugin + NVD-sync capability above as covering them. The NVD
> sync work since 2026-09-07 is hardening only (audit, proxy, status card). The
> long-term replacement is engine-published content delivered through the existing
> content-distribution plane.

### 9.5 Event Log Collection :white_check_mark: `T1`

`event_logs` plugin (cross-platform).

### 9.6 Device Quarantine (Network Isolation) :white_check_mark: `T2`

`quarantine` plugin (cross-platform). `quarantine` action isolates device from network, whitelisting management server and optional IPs via firewall rules (prefixed `YuzuQuarantine_`). `unquarantine` removes rules and restores access. `status` checks active quarantine state. `whitelist` adds/removes IPs from active quarantine. Server side (ADR-0047): the containment gate in the shared dispatch path (`dispatch_confined_arms.hpp`), the `QuarantineContainmentReconciler` and the stored-whitelist re-dispatch (`quarantine_reapply.hpp`) are shipped; a degraded containment read fails closed. *(Evidence: `server/core/src/quarantine_containment_reconciler.{hpp,cpp}`, `quarantine_reapply.{hpp,cpp}`.)*

### 9.7 Indicator of Compromise (IOC) Checking :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Done → Partial** — the `domains` check is not cross-platform. `ioc` plugin with `check` action. Matches indicators against local endpoint state: `ip_addresses` checked against active TCP/UDP connections, `domains` (Windows: DNS resolver cache via `DnsGetCacheDataTable`; Linux/macOS: a substring search of `/etc/hosts` only — no DNS cache is read, `agents/plugins/ioc/src/ioc_plugin.cpp` `check_domains`), `file_hashes` (SHA-256) against files on disk, `file_paths` for existence, `ports` for listening services. Cross-platform, all in-process (no `lsof`): Windows (iphlpapi/dnsapi: GetExtendedTcpTable, DnsGetCacheDataTable), Linux (procfs), macOS (libproc).

### 9.8 Certificate Inventory (Get/Delete) :white_check_mark: `T2`

`certificates` plugin with `list`, `details`, and `delete` actions. Enumerates certificates in system stores with thumbprint, subject, issuer, expiry, and key usage. Windows: CryptoAPI (CertOpenStore, CertEnumCertificatesInStore). Linux: PEM files in /etc/ssl/certs/, parsed in-process via libcrypto (no `openssl` shell-out). macOS: System.keychain and SystemRootCertificates.keychain are read natively via SecItem (`SecItemCopyMatching`, no shell-out); the current console user's login keychain still goes through the `launchctl asuser <uid> sudo -n -u <user> security` hop (selectable per query with the `store` param: `System`/`root`/`login`/`all`; the LaunchDaemon has no login keychain of its own). Delete on macOS verifies the certificate is actually absent from the target keychain afterward before reporting success (a tri-state safe delete — command failure, still-present, and an unreadable re-enumeration each block a false "deleted"); `store=root` is rejected as unsupported because SystemRootCertificates.keychain is sealed by System Integrity Protection and cannot be modified. The plugin README grades macOS `delete` constrained (it runs `security delete-certificate` through the subprocess runner); `list`/`details` are supported on all three OSes.

### 9.9 Quarantine Status Tracking :white_check_mark: `T2`

`QuarantineStore` (PostgreSQL backend, schema `quarantine_store`, ADR-0047). Server-side quarantine records with agent_id, status (active/released), quarantined_by, timestamps, whitelist, and reason. `list_quarantined()` for active quarantines, `get_history()` for per-agent quarantine history. REST API endpoints for quarantine/release/status.

### 9.10 Application Whitelisting :large_orange_diamond: `T3`

Partial — read-only posture only (Wave 8 PR8.6; refs #282, `docs/roadmap.md` Issue 12.11). `app_control` plugin with `wdac_policy` and `applocker_policy` actions reports the configured Windows application-control posture: WDAC via the registry (`HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy` values plus the active `.cip` policy files and the legacy `SiPolicy.p7b`, by presence) and AppLocker via a bounded CIM query of `MSFT_ApplockerPolicy` (`agents/shared/wmi_bounded.hpp`) with a `SrpV2` registry fallback; a mode is what the policy is configured to do, not proof that rules apply (the Application Identity service is not read). Windows-only: Linux and macOS declare `unsupported`. **Not implemented:** modifying allow/block lists (`add_rule` / `remove_rule`), `get_blocked_events`, and a Linux fapolicyd leg — #282 stays open for them. This reads an OS-native control's state; it is not EDR-class telemetry (`docs/roadmap.md` Phase 18 "Out of scope").

### 9.11 Persistence (Autoruns) Enumeration :white_check_mark: `T2` *(new row, v4.1)*

`autoruns` plugin: `list` and `catalog` enumerate persistence sources (what starts automatically) on Windows, macOS and Linux, read-only (`Security:Read`). *(Evidence: `agents/plugins/autoruns/README.md`.)*

### 9.12 Execution Artefacts (Windows Forensics) :white_check_mark: `T2` *(new row, v4.1)*

`execution_artifacts` plugin: `shimcache`, `amcache` (InventoryApplicationFile) and `prefetch` execution evidence on Windows (macOS and Linux unsupported). Paths and hashes only, never contents; a bad or over-cap artefact is a constrained row with a named reason, never an empty success. Forensics securable, default-off, AdminOrApproval, single-target; stored rows are served only to holders of global `Forensics:Read` (§20.9). *(Evidence: `agents/plugins/execution_artifacts/README.md`; `docs/execution-artifacts-invariants.md`.)*

---

## 10. File System Operations

*Browse, search, inspect, and manipulate files on managed endpoints.*

### 10.1 File and Directory Listing :white_check_mark: `T1`

`filesystem` plugin (cross-platform, admin-required).

### 10.2 File Search by Name :white_check_mark: `T1`

`filesystem` plugin.

### 10.3 File Content Read (by Line) :white_check_mark: `T1`

`filesystem` plugin `read` action with `offset` (1-based line number) and `limit` (max lines, configurable) parameters for line-range access.

### 10.4 File Hash Computation :white_check_mark: `T1`

`filesystem` plugin.

### 10.5 File Deletion :x: `T1` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `filesystem` plugin has no whole-file delete action. Its full and only action set, quoted from the dispatcher, is `acts[] = {"exists", "list_dir", "file_hash", "create_temp", "create_temp_dir", "read", "get_acl", "get_signature", "find_by_hash", "search_dir", "get_version_info", "search", "replace", "write_content", "append", "delete_lines", nullptr}` (`agents/plugins/filesystem/src/filesystem_plugin.cpp:720-725`, unrecognized actions rejected at `:791`; line cites re-checked 2026-11-14). `delete_lines` removes matching lines *from within* a file's content — it does not delete the file itself. No other plugin declares a generic file-delete action (agent-core's handle-relative `confined_fs` deletion primitive exists, but its consumers delete certificate and scratch files, not arbitrary paths; `disk_actions` is read-only: `smart`/`volumes`/`partitions`/`topology`; `content_dist` stages/executes, it does not delete arbitrary paths). **Generic scripting can delete a file** — `rm`/`Remove-Item` via `script_exec` — but that is a different contract from a native, governed, RBAC-scoped delete action. *(Evidence: `filesystem_plugin.cpp:720-725,791`; previously mis-graded Done — no action named at all in the prior row text.)*

### 10.6 Path Existence Check :white_check_mark: `T1`

`filesystem` plugin.

### 10.7 File Permissions Inspection :white_check_mark: `T2`

`filesystem` plugin `get_acl` action. Windows: full DACL enumeration via GetNamedSecurityInfo — returns each ACE with trustee, access mask, and ace type. Linux/macOS: owner, group and permission bits from `stat()`, plus the extended ACL — the POSIX access/default ACL entries on Linux (`system.posix_acl_*` extended attributes) and the allow/deny entries with principal, rights and inheritance flags on macOS (`acl_get_file`); a filesystem that cannot carry an ACL reports `acl|unsupported`.

### 10.8 Digital Signature Verification :white_check_mark: `T2`

`filesystem` plugin `get_signature` action. Windows: Authenticode verification via WinVerifyTrust — reports signature status (valid, invalid, unsigned, untrusted), signer name, and timestamp. macOS: runs `codesign --verify --deep --strict` and reports an honest macOS status (`valid` = intact seal, `unsigned`, `invalid` = a proven broken seal / bad requirement / corrupt sealed resource, `unknown` = trust/policy/notarization failure or unrecognised diagnostic) — a different vocabulary from Authenticode, since codesign/Gatekeeper model trust differently than WinVerifyTrust; `valid` attests seal integrity, not Gatekeeper/notarization trust. Linux: returns platform-unsupported status.

### 10.9 File Version Info :white_check_mark: `T2`

`get_version_info` action in `filesystem` plugin. Windows: GetFileVersionInfoW/VerQueryValueW for VS_FIXEDFILEINFO + string table. Returns file_version, product_version, company_name, file_description, etc. macOS: reads CFBundleShortVersionString and CFBundleVersion from an app bundle's Info.plist via `plutil -extract` (handles both binary and XML plists), reporting `version_status|not_available` when the target carries no Info.plist or version keys rather than failing. Returns platform-unsupported on Linux.

### 10.10 File Content Search and Replace :white_check_mark: `T2`

Five new actions in `filesystem` plugin: `search` (line-by-line pattern matching, literal or regex), `replace` (atomic temp+rename), `write_content`, `append`, `delete_lines`. All enforce base_dir restrictions. Pattern capped at 256 chars. Binary detection.

### 10.11 Directory Hash (Recursive) :x: `T3`

Not implemented. Integrity verification of directory trees.

### 10.12 Temp File Creation :white_check_mark: `T1`

`yuzu_create_temp_file()` and `yuzu_create_temp_dir()` in SDK with secure permissions (POSIX mkstemps 0600, Windows owner-only DACL). Exposed via filesystem plugin `create_temp`/`create_temp_dir` actions.

### 10.13 File Retrieval (Upload to Server) :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Done → Partial — the protocol cannot start today (#5626, open).** `upload_file` action in `content_dist` plugin, via the PR1.6 one-time upload-grant + authenticated chunked-receive protocol (`docs/adr/3004-artifact-blob-storage.md`) — the legacy unauthenticated `POST /api/v1/file-retrieval` endpoint was removed. Operator mints a grant (`POST /api/v1/upload-grants`); the agent redeems it, streams the file in bounded chunks with per-chunk offset CAS, and commits with a SHA-256 computed from the exact bytes acknowledged. File stored in `{data_dir}/upload-blobs/{retention_class}/{grant_id}`. `GET /api/v1/upload-grants` (list) / `DELETE /api/v1/upload-grants/{id}` (revoke) for management. **Known defect:** the five agent-side `/api/v1/uploads` routes are missing from the pre-routing session gate's exempt list (`is_login_exempt_path`, `server/core/src/web_utils.hpp`), so a request carrying only the grant or session header — which is what the shipped `upload_file` client sends — is refused `401` before the handler runs. Minting a grant succeeds, but the agent cannot redeem it and the grant expires; there is no supported workaround. *(Evidence: `docs/user-manual/rest-api.md` "Uploads", "Known defect (#5626)"; `server/core/src/file_retrieval_routes.cpp`.)*

### 10.14 Find File by Size and Hash :white_check_mark: `T2`

`filesystem` plugin `find_by_hash` action. Searches directory trees for files matching a SHA-256 hash. Used for malware hunting and file integrity verification. Recursive search with configurable root path.

### 10.15 Directory Search by Name :white_check_mark: `T2`

`search_dir` action in `filesystem` plugin. `fs::recursive_directory_iterator` with glob or regex name matching. Parameters: root, pattern, match_type (directories/files/both), max_depth, max_results. Respects base_dir.

### 10.16 Upload Grants and Server Blob Store :large_orange_diamond: `T2` *(new row, v4.1)*

The server half of §10.13 (ADR-3004): `UploadGrantStore` (`server/core/src/upload_grant_store.{hpp,cpp}`), operator routes `POST/GET /api/v1/upload-grants` and `DELETE /api/v1/upload-grants/{id}` with MCP twins `mint_upload_grant`, `list_upload_grants` and `revoke_upload_grant` (`UploadGrant` securable; revoke is audit-first), and the five agent routes under `/api/v1/uploads` (open, chunk, status, commit, cancel) that write to the server-side blob directory. Graded Partial for the same reason as §10.13: the agent routes are refused by the pre-routing session gate (#5626), so no upload can complete today. *(Evidence: `server/core/src/file_retrieval_routes.cpp`, `upload_grant_store.hpp`.)*

---

## 11. Script and Command Execution

*Execute arbitrary scripts and commands on managed endpoints. All three `script_exec` actions (`exec`, `powershell`, `bash`) are classified `Destructive`/`Irreversible`, securable `Execution`, risk tier Critical and AdminOrApproval, so they need an explicit non-empty `agent_ids` (no `__all__`, #3685, see §2.2) and an administrator or an approval (`server/core/src/capability_decls/plugin_action_catalogue_d.hpp`).*

### 11.1 Script Execution (File-Based) :white_check_mark: `T1`

`script_exec` plugin (cross-platform).

### 11.2 Inline Script Execution :white_check_mark: `T1`

`script_exec` plugin accepts inline text.

### 11.3 OS Command Execution :white_check_mark: `T1`

`script_exec` covers this.

### 11.4 Execution Output Streaming :white_check_mark: `T1`

gRPC streaming delivers output in real time.

---

## 12. Registry and System Configuration (Windows)

*Read and modify Windows registry, WMI, and system configuration.*

### 12.1 WMI Query Execution :white_check_mark: `T2`

`wmi` plugin with `query` action. Execute WQL SELECT statements against any WMI namespace with structured property/value output.

### 12.2 WMI Method Invocation :x: `T2` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `wmi` plugin has no method-invocation action (no `ExecMethod`-equivalent). Its full and only action set, quoted from the dispatcher, is `acts[] = {"query", "get_instance", nullptr}` (`agents/plugins/wmi/src/wmi_plugin.cpp:111`) — both read-only. `get_instance` builds `SELECT * FROM <class>` (`:181`) and runs a bounded query; it reads instance properties, it never calls a class method. **Generic scripting can invoke a WMI method** — `Invoke-CimMethod`/`InvokeMethod` via `script_exec` — but that is a different contract from a native, governed, RBAC-scoped method-invocation action. *(Evidence: `wmi_plugin.cpp:111,181`; line cites re-checked 2026-11-14; previously mis-graded Done — the row conflated a class-instance property read with method invocation.)*

### 12.3 WMI Namespace Enumeration :x: `T3` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `wmi` plugin does not enumerate namespaces. The `namespace` parameter is restricted to a fixed three-item allowlist — `root\cimv2`, `root\wmi`, `root\standardcimv2` — validated by `is_valid_wmi_namespace()` (`agents/plugins/wmi/src/wmi_plugin.cpp:62`, called at `:146`); an operator *selects* one of three known namespaces, they cannot discover what namespaces exist on a given host. Only `query`/`get_instance` dispatch (`:111`); there is no `enumerate_namespaces` action. *(Evidence: `wmi_plugin.cpp:62,111,146`; previously mis-graded Done — a configurable parameter restricted to an allowlist is not enumeration.)*

### 12.4 Registry Key/Value Read :white_check_mark: `T2`

`registry` plugin with `get_value` action. Read values from HKLM, HKCU, HKCR, HKU hives with structured type/value output.

### 12.5 Registry Key/Value Write/Delete :white_check_mark: `T2`

`registry` plugin (2.0.0 and later) with `set_value` (all six value types, from text or exact `data_hex` bytes, read-back verified), `delete_value` and `delete_key` (a key with no subkeys by default; from registry 2.1.0 `recursive=true` deletes a whole tree, vetted first by a size bound and a link sweep and then deleted post-order by handle, and `dry_run=true` runs the vet only; it reports the keys and values counted, `counted_keys` / `counted_values`, and no contents). Registry 2.1.0 also adds `apply`: one plan of up to 256 `set_value` / `delete_value` / `create_key` / non-recursive `delete_key` items on HKLM, dry run by default, not transactional, whose reply carries an undo manifest of the previous values (nothing is persisted on the endpoint). Every mutation runs on a handle checked for registry links (one canonical-name-checked open on HKLM and HKU, a component walk otherwise or as the fallback), and each emits an audit line that the server records as a `registry.write` row when the agent stamps the action on its reply (agents from the release that contains #6294; `docs/user-manual/upgrading.md`) and the command id has the shape the server mints for a registry command (the server checks that shape and the stamped action, not a dispatch record, so the rows are asserted by the agent); the row carries the old and new value as raw hex (256 bytes at most), which can contain secrets: the product owner accepted this risk on 2026-10-20 and masking is a planned later change. *(Evidence: `agents/plugins/registry/src/registry_core.hpp`, `registry_win.cpp`, `server/core/src/plugin_result_audit.hpp`.)*

### 12.6 Registry Enumeration :white_check_mark: `T2`

`registry` plugin with `enumerate_keys` and `enumerate_values` actions. `key_exists` for existence checks.

### 12.7 Per-User Registry Operations :white_check_mark: `T2`

`registry` plugin with `list_profiles` (enumerate local profiles: SID, resolved name, profile path, live hive-load state) and `get_user_value` (read a value from a resolved profile's hive) actions, and from registry 2.1.0 `set_user_value` / `delete_user_value` (write or delete a value in a resolved profile's hive, read-back verified; on the offline NTUSER.DAT arm the key is flushed before the unload). All four resolve the target profile via `HKLM\...\ProfileList`; the per-user actions use the live `HKEY_USERS\<SID>` hive when the user is logged in, or load that profile's NTUSER.DAT via `RegLoadKey` as a fallback (unloaded via RAII on every exit path, under a per-call salted mount name; a write's offline arm runs behind the shared default-on hive-file guard). SE_RESTORE_NAME and SE_BACKUP_NAME privileges are required only for that offline fallback, which the agent account already holds — no new privilege grant; using an already-loaded live hive needs no elevated privilege.

The ladder itself lives in `agents/shared/win_profiles.hpp` and is the single implementation for every per-user consumer: `registry`, `installed_apps.list_per_user`, `license_scan`'s per-user surfaces, `echo`'s outbound mapdrive history and `virtualization.wsl`. Its offline arm is serialised process-wide, because privilege enabling acts on the process token and all five plugins load into one agent process.

---

## 13. Content Distribution

*Stage and distribute files, packages, and content to endpoints.*

### 13.1 Server-to-Agent Content Staging :white_check_mark: `T2`

`content_dist` plugin with `stage` action. Download files to agent staging directory with SHA256 hash verification. `list_staged` to inventory staged content. `cleanup` to remove staged files.

### 13.2 Stage and Execute (Deploy + Run) :white_check_mark: `T2`

`content_dist` plugin with `execute_staged` action. Execute previously staged files with optional arguments. Returns exit code and output.

### 13.3 HTTP File Download (Agent-Initiated) :white_check_mark: `T2`

`http_client` plugin with `download` action. Download files from arbitrary URLs with optional SHA256 hash verification. `get` and `head` actions for HTTP requests.

### 13.4 HTTP POST (Agent-Initiated) :x: `T3` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra C1):** the `http_client` plugin has no `post` action. Its full and only action set, quoted from the dispatcher, is `acts[] = {"download", "get", "head", nullptr}` (`agents/plugins/http_client/src/http_client_plugin.cpp:443`; unrecognized actions rejected at `:465`). Fetch-only, no generic outbound POST. (Specialized, narrowly-scoped upload paths exist elsewhere in the product for specific content-distribution/inventory-ingest flows, but those are not a general-purpose agent-initiated HTTP POST primitive.) **Generic scripting can issue an HTTP POST** — `curl`/`Invoke-WebRequest` via `script_exec` — but that is a different contract from a native, governed, RBAC-scoped POST action. *(Evidence: `http_client_plugin.cpp:443,465`; previously mis-graded Done.)*

### 13.5 Peer-to-Peer Content Distribution :x: `T3`

Not implemented. P2P caching to reduce WAN bandwidth. Requires agent mesh networking.

---

## 14. User Interaction

*Display notifications, surveys, and dialogs on endpoint desktops.*

### 14.1 Desktop Notification :white_check_mark: `T2`

`interaction` plugin with `notify` action. Toast/balloon notifications with info/warning/error severity. Cross-platform: ShellNotifyIcon (Windows), notify-send (Linux), osascript (macOS).

### 14.2 Announcement Dialog :white_check_mark: `T2` *(verified 2026-09-10)*

`interaction` plugin with `message_box` action. Modal message box with configurable buttons (ok, okcancel, yesno). Returns the user's button in `response`. On macOS the agent is a GUI-less root LaunchDaemon: when no desktop session can be reached it reports `status|not_reachable` honestly (never a fabricated `response|ok`). Delivering a dialog to the logged-in user's session is a deferred per-session helper. *(Spot-checked 2026-09-10, Gate-of-record pass 3 sweep item 5: `interaction_plugin.cpp:477,490` genuinely returns/writes `not_reachable` rather than fabricating a button click. Claim holds.)*

### 14.3 Question / Confirmation Dialog :white_check_mark: `T2`

`interaction` plugin with `input` action. Text input dialog with configurable prompt and default value. Returns entered text or cancellation. MessageBoxW (Windows), zenity (Linux), osascript (macOS).

### 14.4 Survey Dialog :white_check_mark: `T3` *(verified 2026-09-07)*

Shipped. `interaction` plugin `survey` action — multi-question form via `zenity` (Linux, supported), `powershell_winforms` (Windows, supported), `osascript` (macOS, constrained — no reachable GUI session under the headless/root LaunchDaemon). *(Evidence: `agents/plugins/interaction/src/interaction_plugin.cpp`, `"survey"` action registered ~line 1284, dispatched via `do_survey()`; verified 2026-09-07 — previously mis-graded Not Started.)*

### 14.5 Do-Not-Disturb Mode :white_check_mark: `T3` *(verified 2026-09-07)*

Shipped. `interaction` plugin `set_dnd` action — enables/disables DND with an optional expiry, suppresses `notify` calls while active (`is_dnd_active()` gate in `do_notify()`), and persists state across restarts via the agent's local KV store (`local_kv_store`) on all three platforms. *(Evidence: `agents/plugins/interaction/src/interaction_plugin.cpp`, `"set_dnd"` action ~line 1290, state restore in `init()`; verified 2026-09-07 — previously mis-graded Not Started.)*

### 14.6 Active Response Tracking :x: `T3`

Not implemented. List all active survey/question responses waiting for user input.

---

## 15. Inventory and Data Collection

*Structured inventory collection, storage, querying, and replication.*

### 15.1 Plugin-Based Inventory Reporting :white_check_mark: `T1`

`ReportInventory` RPC with per-plugin data blobs.

### 15.2 Inventory Persistence and Query :white_check_mark: `T1`

`QueryInventory` RPC on management API. Server stores inventory.

> **Gap:** No advanced query language (filtering, joins).

### 15.3 Inventory Table Enumeration :white_check_mark: `T2`

`InventoryStore::list_tables()` returns all distinct inventory "tables" (one per plugin) with agent count and last collection timestamp. REST API endpoint and MCP `list_inventory_tables` tool expose this data.

### 15.4 Inventory Evaluation (Item Lookup) :white_check_mark: `T2`

`inventory_eval.hpp/cpp` evaluation engine. JSON dot-path field extraction, 10 comparison operators including version_gte/version_lte (semver-aware). REST: `POST /api/v1/inventory/evaluate` with conditions array and AND/OR combine.

### 15.5 Inventory Replication (Local Replica) :x: `T3`

Not implemented. Agent-side cache with delta sync.

---

## 16. Policy and Compliance Engine (Server-Side Guaranteed State)

*Define desired-state policies and evaluate compliance on a server-side periodic schedule. **Corrected 2026-09-08 (external audit, Codex Astra residual sweep):** the previous framing here said "auto-remediate" — that overstates the mechanism. `PolicyEvaluator` (`server/core/src/policy_evaluator.hpp`) runs a background `tick()` every **10 seconds**, waits a **15-second grace window** for in-flight check responses, and re-evaluates each policy no more often than its own interval (**3600-second default**, `default_interval_seconds{3600}` in `policy_evaluator.hpp`). **Remediation is operator-gated, never automatic** — the operator manual states this explicitly: "Remediation is never automatic. Detection runs on the schedule above" (`docs/user-manual/policy-engine.md`, "Remediation is never automatic"). Do not conflate this domain with §31 System Guardian: this domain covers the **server-side** half of guaranteed state — definition, fleet-wide compliance evaluation, history, drill-down, with detection on the cadence above and remediation requiring an explicit operator action. Real-time **agent-side** *enforcement* (kernel-event-driven, near-real-time, pre-login, offline-capable, and — for the two live guards — genuinely autonomous remediation) lives entirely in §31 (System Guardian) and is the operational primitive that makes "this setting must never be in a non-compliant state" actually true on disk without an operator in the loop. Due-ness is ONE durable fleet-wide Postgres claim (`PolicyStore::claim_due_policies`, ADR-0056), and `PolicyEvaluator::tick` gates only its `dispatch_due` pass behind the fenced leader (§22.10). Operator actions: `POST /api/policies/{id}/evaluate` (force a check) and `POST /api/policies/{id}/remediate` (the operator-gated fix, `policy_admin_routes.cpp`). *(Evidence: `policy_evaluator.hpp` `default_interval_seconds`; `docs/user-manual/policy-engine.md` "Remediation is never automatic"; `docs/adr/0056-policy-store-postgres-migration.md`; verified 2026-09-07, routes and claim added 2026-11-14.)*

### 16.1 Policy Rules Definition :white_check_mark: `T2`

`PolicyStore` with `PolicyFragment` (check/fix/postCheck pattern) and `Policy` kinds. YAML-defined with CEL compliance expressions. CRUD via REST API.

### 16.2 Policy Evaluation and Enforcement :large_orange_diamond: `T2` *(verified 2026-09-11)*

**Regraded 2026-09-10 (Gate-of-record pass 3, sec-2/UP-16): Done → Partial — interval-only in practice.** **Corrected 2026-09-10 (pass 4, item 3 — the pass 3 wording got the failure mode backwards) and 2026-09-11 (pass 5, sec-P5-1/CHAOS-P5-1/CHAOS-P5-2 — removes a false claim the PO's own pass-4 instruction introduced and adds three more measured parser bugs):** `PolicyStore` tracks per-agent compliance status (compliant, non_compliant, unknown, fixing, error). `trigger_type` is a free-text column (`policy_store.hpp`) and a policy's YAML can name any trigger kind — the store accepts and persists them all without validation (`policy_store.cpp:824`). The due-policy scheduling query is a **`LEFT JOIN`**, type filter in the join condition not the `WHERE` clause (`server/core/src/policy_store.cpp:1473-1480`), so a policy with no `interval` trigger still produces a row with `config_json = NULL`, and `interval_from_config_json(NULL, default_interval_seconds)` falls back to the **3600-second platform default** against the policy's **full declared scope** — silently-hourly, not silently-inert. **What IS surfaced:** the policy-detail and policy-list REST reads genuinely return each trigger's `id`, `type`, and parsed `config` (`compliance_routes.cpp:525,582`) — an operator can fetch a policy and see exactly what was stored. **What is NOT surfaced:** no validation or warning at create time that a declared trigger type has no effect on cadence, and no metric reporting the *effective* interval after the parser's fallbacks — so the diagnostic exists (compare the returned `config` against the cadence you intended) but nothing points you at it proactively. Three further parser fragility bugs (measured 2026-09-11): (1) `extract_yaml_section` keeps only lines *more indented* than `triggers:` (`yaml_scan.cpp`) — the equally-common same-indent list style (`- type:` aligned with `triggers:`) yields **zero triggers**, so a declared `interval_seconds: 86400` silently runs at the 3600s default (**24× over-dispatch**); (2) `std::stoi("5m")` returns `5` rather than erroring (`policy_store.cpp:748`) — a human-readable duration like "5m" becomes 5 *seconds*, not 300 (**60× amplification**); (3) a value outside `int` range is stored as a raw string and `std::stoll`-parsed back at dispatch time (`policy_store.cpp:242,748`) — a sufficiently large but `int64_t`-representable typo dispatches once and then not again for years, while the policy keeps reporting `enabled: true`. Full detail, worked examples, and the "Common mistake" callout: `docs/user-manual/policy-engine.md` § Trigger Configuration. Tracking issue: **#4244** (body corrected 2026-09-11 to remove the same false REST-reads claim this row is now correcting). *(Evidence: `policy_store.hpp`; `policy_store.cpp:242,748,824,1473-1480`; `compliance_routes.cpp:525,582`; `yaml_scan.cpp`; verified 2026-09-11, line cites re-checked 2026-11-14.)*

### 16.3 Policy Assignment to Device Groups :white_check_mark: `T2`

Policies support management group bindings via `PolicyGroupBinding`. Scope expressions for device targeting.

### 16.4 Compliance Summary and Statistics :white_check_mark: `T2` *(verified 2026-09-11)*

`FleetCompliance` aggregate with compliance percentage. Per-policy `ComplianceSummary`. Compliance dashboard with fleet-level and per-policy drill-down to agent-level detail. **Caveat added 2026-09-11 (Gate-of-record pass 5, comp-P5-1): the two summaries have different freshness guarantees — do not assume the per-policy summary is as fresh as the fleet-wide one.** `PolicyStore::compute_fleet_compliance()` demotes any status older than a 24-hour staleness window to `unknown` before aggregating (`kStalenessTtl = 24 * 3600`, `server/core/src/policy_store.cpp:35,1202-1215`: `CASE WHEN last_check_at >= cutoff THEN status ELSE 'unknown' END`). `PolicyStore::get_compliance_summary()` (the **per-policy** `ComplianceSummary`) has no equivalent filter at all — it is a raw `GROUP BY status` over `policy_status` with no `last_check_at` condition (`policy_store.cpp:1159-1180`), so a status computed once and never refreshed (e.g. because a policy's trigger is silently ignored per §16.2, or the agent went offline) counts as fully "compliant"/"non_compliant" indefinitely, with no staleness demotion and no indication of age in the summary itself. The per-agent detail list (`get_policy_agent_statuses`) does expose the raw `last_check_at` timestamp per row, so a consumer *can* compute staleness themselves from that — but the per-policy `ComplianceSummary` numbers do not do this for you. *(Evidence: `policy_store.cpp:35,1159-1180,1202-1215`; verified 2026-09-11, line cites re-checked 2026-11-14.)*

### 16.5 Evaluation History and Audit Trail :white_check_mark: `T2`

`PolicyAgentStatus` tracks last_check_at, last_fix_at, and check_result per agent per policy. Queryable via REST API.

### 16.6 Policy Event Subscriptions :white_check_mark: `T3`

Policy status changes tracked in compliance store. REST API endpoints expose compliance data for external consumption.

### 16.7 Cache Invalidation and Force Re-Evaluation :white_check_mark: `T2`

`invalidate_policy()` resets all agent statuses to pending for a specific policy. `invalidate_all_policies()` for fleet-wide reset. REST endpoints: `POST /api/policies/{id}/invalidate` and `POST /api/policies/invalidate-all`.

### 16.8 Pending Policy Changes Review :white_check_mark: `T2`

Policies support enable/disable toggle for staged deployment. REST endpoints: `POST /api/policies/{id}/enable` and `POST /api/policies/{id}/disable`.

---

## 17. Triggers and Event-Driven Automation

*React to endpoint events in real time: file changes, service state, intervals.*

### 17.1 Interval-Based Trigger :white_check_mark: `T2`

Trigger engine with `interval` type. Timer-based execution with configurable seconds/minutes/hours.

### 17.2 File / Directory Change Trigger :large_orange_diamond: `T2` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra residual sweep):** this is a **5-second `last_write_time` poll, not a kernel-backed filesystem watcher.** `TriggerEngine::file_watch_loop()` wakes every 5 seconds and re-checks each watched path's mtime (`agents/core/src/trigger_engine.cpp:327-332`: "Poll every file_poll_ms_ (5s by default) — but wake at once on stop()"). There is zero use of `inotify`, `FSEvents`, or `ReadDirectoryChangesW` anywhere in `trigger_engine.cpp` (confirmed by grep). The real `TriggerType` enum value is `FileChange` (wire string `"filesystem"`, `trigger_engine.hpp:22-28`) — there is no separate `directory_change` type. Detection latency is therefore up to 5 seconds, not near-instant kernel notification — contrast with Guardian's genuinely kernel-backed `guard_file.cpp` (§31.2, Windows only, detect-only). *(Evidence: `trigger_engine.cpp:327-332`; `trigger_engine.hpp:22-28`; previously mis-graded Done — claimed a mechanism the code does not use.)*

### 17.3 Service Status Change Trigger :white_check_mark: `T2` *(verified 2026-09-07)*

**Note added 2026-09-08 (external audit, Codex Astra residual sweep):** also a poll, not an SCM/systemd event subscription — `TriggerEngine::service_watch_loop()` wakes every **30 seconds** and re-checks each watched service's state (`agents/core/src/trigger_engine.cpp:390-395`: "Poll every 30 seconds — but wake at once on stop()"). The real `TriggerType` enum value is `ServiceStatus` (wire string `"service"`). Kept at Done because the capability genuinely works end-to-end (a service-state change is reliably detected and fires within 30 seconds), it just isn't the event-driven SCM/systemd-notification mechanism the original prose implied. *(Evidence: `trigger_engine.cpp:390-395`.)*

### 17.4 Windows Event Log Trigger :x: `T2` *(verified 2026-09-07)*

**Corrected 2026-09-08 (external audit, Codex Astra residual sweep):** there is no Event Log trigger type. The closed `TriggerType` enum (`agents/core/include/yuzu/agent/trigger_engine.hpp:22-28`) has exactly five values — `Interval`, `FileChange`, `ServiceStatus`, `AgentStartup`, `RegistryChange` — none of them Event Log. An unrecognized trigger-type string silently falls back to `Interval` (`trigger_type_from_string`, `:47`), so a YAML author who writes `event_log` gets an interval poll, not an error and not Event Log filtering. Zero `EvtSubscribe` (or any Windows Event Log API) call sites anywhere in `trigger_engine.cpp`. The `event_logs` *plugin* (§9.5) genuinely **collects** Windows/Linux/macOS event logs on demand — that is a real, working, unrelated capability — but no *trigger* type watches the event log for a matching entry and fires. *(Evidence: `trigger_engine.hpp:22-28,47`; previously mis-graded Done — the row described a trigger type that does not exist in the closed enum.)*

### 17.5 Registry Change Trigger :white_check_mark: `T3`

Trigger engine with `registry` type. React to registry key modifications on Windows.

### 17.6 Agent Startup Trigger :white_check_mark: `T2`

Trigger engine with `agent_startup` type. Execute actions on agent boot.

### 17.7 Trigger Templates (Server-Side) :white_check_mark: `T2`

`TriggerTemplate` YAML kind (`yuzu.io/v1alpha1`) for server-defined trigger configurations. Pre-configured trigger variants managed server-side and pushed to agents.

---

## 18. Server: Authentication and Authorization

*User authentication, role-based access control, and session management.*

### 18.1 Session-Based Authentication :white_check_mark: `T1`

Session-cookie auth with PBKDF2-hashed passwords.

### 18.2 Role-Based Access Control (Two Roles) :white_check_mark: `T1`

*(Verified 2026-11-14.)* RBAC ships **disabled by default** (`rbac_store.cpp` seeds `rbac_enabled='false'`), so this legacy two-role model is the default, not historical. With RBAC off, `admin` has full access and `user` may perform any `Read` except the authorization-topology floor (`kTopologyFloor` in `server/core/src/authz_topology_floor.hpp`: AccessReview, UserManagement, EnginePrincipal, TlsConfig, PluginSigning, ServerConfig, AnalyticsConfig, Enrollment, OidcConfig, Forensics, AuditLog and RevocationSource reads stay admin-only); every non-`Read` operation needs `admin`, apart from a small set of self-service exemptions (`AuthRoutes::require_permission`'s legacy branch). Enabling RBAC (§18.3) switches to the role/securable model, whose seeded system roles include Administrator, ITServiceOwner, PlatformEngineer, Operator, Viewer, Reviewer, ApiTokenManager and ForensicsAnalyst.

### 18.3 Granular RBAC :white_check_mark: `T2`

`RbacStore` (`server/core/src/rbac_store.cpp`, 3356 LOC, PostgreSQL ADR-0041): principals, custom roles, **39 securable types** (the `kRbacSecurables` catalogue in `mcp_server.cpp`, mirrored by `rbac_store.cpp` — from Infrastructure, UserManagement, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog and Response through Forensics, Decommission and RevocationSource) and **8 operations** (Read, Write, Execute, Delete, Approve, Push, Attest, Rotate). RBAC administration (fleet-wide role assignment, the enforcement toggle) is gated by a single administrator predicate with a last-Administrator guard (`rbac_admin_predicate.hpp`). Deny-override, system roles, group-based assignments. Global enable/disable toggle. The dashboard's **Access → Users and roles** page (`/access/users`) lists the server's accounts and lets an administrator add, remove, change the role of and revoke the sessions of an account. The same page shows the role catalogue with each role's permissions, the fleet-wide role assignments (with Assign and Remove), the RBAC enforcement switch, and gives every signed-in user a Your account panel (change password, sign out everywhere), a temporary Your elevation panel and a Check your own permission panel.

### 18.4 Management-Group-Scoped Roles :white_check_mark: `T2`

`ManagementGroupStore` supports group-scoped role assignments. `assign_role()` / `unassign_role()` bind principals to roles within a specific group. `get_visible_agents()` resolves the candidate agent set for a user's group-scoped roles. REST endpoints at `/api/v1/management-groups/{id}/roles` (GET/POST/DELETE). RBAC integration enforces group-scoped visibility on **per-device** routes and, as of #1634, on the **response/execution** list/fan-out family (`query_responses`/`aggregate_responses`, `GET /api/v1/executions/{id}`, `GET /api/v1/events`, `GET /sse/executions/{id}`, MCP `get_execution_status`/`list_executions`) via the ADR-0017 admit-then-filter list gate — see `docs/auth-architecture.md` "Third migration (#1634)". Software-inventory reads (`query_installed_software`, `GET /api/v1/inventory/software`) are also already effectively confined (#3290 Phase 2). Confinement of the remaining list/fan-out surfaces (agent lists, the generic `query_inventory`/`get_agent_inventory` blob routes) is tracked by the same ADR-0017 ladder.

### 18.5 OIDC / SSO Integration :white_check_mark: `T2`

`OidcProvider`: PKCE authorization code flow, OpenID Connect discovery, JWT validation (iss, aud, nonce, exp), Entra ID group claim parsing, group-to-role mapping (`--oidc-admin-group`), token exchange via httplib (the server is Linux-only, ADR-0035; the WinHTTP branch in `oidc_provider.cpp` is vestigial). Endpoints and `jwks_uri` come from the issuer's discovery document, never derived. Verified end to end against Keycloak 26.4.0 (Linux test host, plain `http` and `https` via a TLS-terminating proxy); Microsoft Entra ID is supported by the standard but has not been verified end to end by the project. Login page SSO button active. Runtime-configurable via Settings UI (`POST /api/settings/oidc`) — admin can enter issuer, client_id, client_secret, redirect_uri, and admin_group from the dashboard without server restart - though the swap is process-local and a restart reverts to the CLI/env values. "Test Connection" button validates OIDC discovery and the signing keys. TLS cert verification configurable (`--oidc-skip-tls-verify`).

### 18.6 Active Directory / Entra Integration :white_check_mark: `T2`

`DirectorySync` (ADR-0063: migrated to PostgreSQL, schema `directory_sync`). Entra ID sync via Microsoft Graph API (OAuth2 client credentials flow). Fetches `/users` and `/groups`, stores in Postgres (fail-closed construction; FK + `ON DELETE CASCADE` on memberships, new in this migration). Group-to-role mapping (`configure_group_role_mapping`) maps directory groups to RBAC roles. LDAP sync stub for on-prem AD (full LDAP support planned). REST API endpoints for sync trigger, status, and mapping CRUD. Settings UI section active.

### 18.7 Token-Based API Authentication :white_check_mark: `T2` *(verified 2026-09-07)*

`ApiTokenStore` with **PostgreSQL backend** (`server/core/src/api_token_store.hpp:4`, ADR-0030 — corrected 2026-09-08, external audit Codex Astra residual sweep; the store's own header names its schema `api_token_store` and takes a `pg::PgPool&`, not a SQLite handle; previous row text stale-claimed SQLite). Tokens generated via `POST /api/v1/tokens` with optional expiry. Auth via `Authorization: Bearer` header or `X-Yuzu-Token` header. RBAC permissions: `ApiToken:Read`, `ApiToken:Write`, `ApiToken:Delete`. Tokens support optional `mcp_tier` field for MCP integration (readonly/operator/supervised). Settings UI token management with create/revoke.

### 18.8 Device Authorization Tokens :large_orange_diamond: `T2` *(verified 2026-09-07)*

**Regraded 2026-09-08 (external audit, Codex Astra C2), like §22.3: implemented and tested, not constructed by the server — routes do not register today (`server.cpp:20857`).** `DeviceTokenStore` (PostgreSQL, ADR-0052) with SHA-256 hashed tokens, device_id and definition_id scoping. REST: `GET/POST/DELETE /api/v1/device-tokens`, gated `if (device_token_store)` (`rest_api_v1.cpp:8669`, GET at `:8670`, POST at `:8707`). The production registration call passes `nullptr` for this store — `/*device_token_store=*/nullptr` (`server/core/src/server.cpp:20857`) — so these routes never register in a running deployment. Same dormant family as `LicenseStore`/ADR-0048 (§22.3) and `SoftwareDeploymentStore`/ADR-0051 (§7.6). Ordinary session-cookie and API-token authentication (§18.1, §18.7) are unaffected — this dormancy is scoped to the device-token mechanism only. *(Evidence: `server.cpp:20857`, `rest_api_v1.cpp:8669-8670,8707`; previously mis-graded Done despite the row's own "Dormant" text.)*

### 18.9 HTTPS for Web Dashboard :white_check_mark: `T1`

`httplib::SSLServer` with OpenSSL. CLI flags: `--https`, `--https-port`, `--https-cert`, `--https-key`, `--no-https-redirect`. HTTP-to-HTTPS 301 redirect. Secure cookie flag. Settings UI TLS configuration section.

### 18.10 Two-Factor Authentication :white_check_mark: `T2` *(verified 2026-09-07)*

Shipped (SOC 2 CC6.6 privileged-access MFA ladder). RFC 6238 TOTP + RFC 4648 base32 + `otpauth://` URI builder (`totp.cpp`), per-user enrolment with QR code (`mfa_qr.cpp`), and a step-up gate (`mfa_step_up.cpp`) that blocks high-risk REST/Settings handlers unless `Session::mfa_verified_at` is fresh within `mfa_step_up_window_secs` - API-token/MCP-token principals skip step-up by design (the bearer credential is the step-up moment). Retitled from "...for Approvals" - the shipped scope is login-time TOTP + step-up on privileged handlers generally. The instruction-approval workflow (#285) is now covered as well: approve/reject require an interactive session and an enrolled MFA factor with a fresh proof (#6061, #6079), under their own stricter rule on top of the generic gate. Email-based OTP fallback not found; scope narrower than the original row's aspiration in that respect. The step-up check is now one central chokepoint (`step_up_gate.cpp`, table `step_up_policy.hpp`) enforcing 41 named REST/dashboard routes; it is REST/dashboard only, so MCP tools and the 73 routes still classified `kPendingRuling` are not step-up gated (`docs/auth-architecture.md` "MFA step-up chokepoint"). An MCP step-up table exists (`step_up_mcp_policy.hpp`) but is data only: no production code consults it. **A SAML session cannot satisfy step-up** — it is refused `403` at every step-up-gated route, approvals included (`saml_mfa_unsupported`, #4935), unless the window is disabled; SAML deployments rely on IdP MFA. *(Evidence: `server/core/src/totp.{hpp,cpp}`, `mfa_qr.{hpp,cpp}`, `mfa_step_up.{hpp,cpp}`; verified 2026-09-07 - previously mis-graded Not Started.)*

### 18.11 SAML 2.0 SSO :white_check_mark: `T2` *(new row, v4.1)*

`SamlProvider` (`server/core/src/saml_provider.{hpp,cpp}`, libxml2 + xmlsec): SP-initiated login at `GET /auth/saml/start`, signed-assertion validation against a pinned IdP certificate, audience/recipient/expiry checks, single-use `InResponseTo` replay protection, optional AuthnRequest signing, group-to-role mapping (`--saml-group-attribute`, `--saml-admin-group`) and fine-grained RBAC group provisioning. Requires HTTPS; otherwise left disabled. **Limits:** a SAML session cannot satisfy MFA step-up (§18.10, #4935), JIT elevation does not work for SAML users (§18.14), there is no IdP-metadata fetch, no runtime reconfiguration, no login-page button, and pending-login state is in-process (sticky sessions needed behind a load balancer). Not verified end to end against a named IdP in this map. *(Evidence: `docs/user-manual/authentication.md` SAML capability table.)*

### 18.12 SCIM 2.0 Provisioning and Deprovision Revoke :white_check_mark: `T2` *(new row, v4.1)*

`/scim/v2/{Users,Groups,ServiceProviderConfig,Schemas,ResourceTypes}` behind `--scim-enable` / `--scim-admin-group` (`scim_routes.cpp`, `scim_store.cpp`). Deprovisioning severs every linked identity through one revoke chokepoint (`deprovision_revoke.{hpp,cpp}`, ADR-2001, SOC 2 CC6.8): OIDC and SAML identity links, sessions and API tokens. A SCIM account elevated to admin outside SCIM is deliberately not auto-revoked, and the refusal is loud. *(Evidence: `docs/user-manual/scim-provisioning.md`; `docs/adr/2001-scim-oidc-identity-linkage.md`; alert group `yuzu-scim`.)*

### 18.13 Durable Operator Sessions :white_check_mark: `T2` *(new row, v4.1)*

Operator sessions are durable Postgres rows in `SessionStore` (`server/core/src/session_store.{hpp,cpp}`, HA WS-1/1a), written through from `AuthManager`, with the in-memory map as a generation-gated validate cache. Every durable timestamp is authored from the database clock (`now()`), and elevation/idle/MFA windows are adjudicated against a local monotonic deadline. Durable storage only — this does not make a second server replica safe (§22.10). *(Evidence: `.claude/agents/authdb.md`; `docs/adr/2002-high-availability-architecture.md` §4.)*

### 18.14 Just-in-Time Privilege Elevation :white_check_mark: `T2` *(new row, v4.1)*

`POST /api/v1/elevate` and `POST /api/v1/elevate/revoke`, surfaced as the dashboard's "Your elevation" panel (§18.3). Elevation windows are bounded (`kMaxElevationWindow`; a future-dated proof is rejected). Not available to SAML users, who have no local `users` row. *(Evidence: `server/core/src/auth_routes.cpp`, `auth.cpp`.)*

### 18.15 Periodic Access Reviews (SOC 2 CC6.2) :white_check_mark: `T2` *(new row, v4.1)*

Fleet-wide grant export and attestation campaigns: `/api/v1/access-reviews` (open, list, get, attestations, close, `export` incl. CSV) and MCP `open_access_review`, `list_access_reviews`, `get_access_review`, `record_attestation`, `close_access_review`, `export_access_review`, on the dedicated `AccessReview:Read`/`Attest` securable (Administrator and Reviewer only). Completeness is driven from the grant table (orphans surfaced), the reviewer can never be the subject (fail-closed), every decision is appended, never overwritten, and a `flagged_revoke` decision is evidence only — it never mutates a grant. *(Evidence: `server/core/src/access_review_store.{hpp,cpp}`, `access_review_model.*`; `docs/auth-architecture.md` "Periodic access reviews".)*

### 18.16 API Token Rotation and Service-Scoped Confinement :white_check_mark: `T2` *(new row, v4.1)*

Token rotation: `POST /api/v1/tokens/{id}/rotate` and its confirm step (`ApiToken:Rotate`), with MCP twins `rotate_api_token` and `confirm_api_token_rotation`. Service-scoped tokens are default-deny: a token scoped to a service never reaches fleet-wide data or actions unfiltered, and the global-safe allowlist (`kServiceScopeGlobalSafe`, `service_scope_policy.hpp`) is seeded empty. *(Evidence: `docs/auth-architecture.md` "Service-scoped token fleet-wide confinement"; `docs/adr/1006-service-scope-default-deny.md`.)*

### 18.17 Plugin Configuration, Secrets and Kill Switches :white_check_mark: `T2` *(new row, v4.1)*

`/api/v1/plugin-config` (list, get, set per key, and the per-plugin `kill-switch` with optional `action`/`os`) on the `PluginConfig` and `PluginSecret` securables, with MCP twins `list_plugin_config`, `get_plugin_config`, `set_plugin_config`, `delete_plugin_config`, `set_plugin_secret`, `delete_plugin_secret`, `get_plugin_kill_switch` and `set_plugin_kill_switch`. The Forensics-tier plugins (`browser_inventory`, `execution_artifacts`, `privacy_permissions`, `remote_access_audit`) are seeded default-off. *(Evidence: `server/core/src/plugin_config_parsers.hpp`, `PluginConfigStore::seed_kill_switch_default_off`.)*

### 18.18 KEK Rotation and Secrets Rewrap :white_check_mark: `T2` *(new row, v4.1)*

`/api/v1/secrets/kek/...` routes (`kek_routes.cpp`) and MCP `get_kek_status`, `rotate_kek` and `rewrap_secrets` rotate the key-encryption key behind the `SecretCodec` envelope (ADR-0010, §38.3) and re-wrap the stored secrets under it; a dashboard panel shows the KEK state (`kek_panel_render.cpp`). *(Evidence: `server/core/src/kek_routes.{hpp,cpp}`, `kek_rotate_control.hpp`.)*

---

## 19. Server: Device and Group Management

*Organize endpoints into groups, scope operations, and manage device metadata.*

### 19.1 Agent Listing and Detail View :white_check_mark: `T1`

`ListAgents`, `GetAgent` RPCs. Web dashboard shows agent list.

### 19.2 Agent Lifecycle Events :white_check_mark: `T1`

`WatchEvents` RPC streams connect/disconnect/plugin-load events.

### 19.3 Scope / Filter-Based Device Selection :white_check_mark: `T2`

Recursive-descent `ScopeEngine` parser (`scope_engine.cpp`, 859 lines). 10 binary operators (`==`, `!=`, `LIKE`, `MATCHES`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`) plus 3 extended operators/functions (`EXISTS`, `LEN()`, `STARTSWITH()`), AND/OR/NOT combinators. `MATCHES` uses ECMAScript regex with safe error handling. Attributes: ostype, osver, hostname, arch, fqdn, `tag:*` (plus `props.*` and `agent_version` through the registry resolver, §2.2). Target count via `/api/scope/estimate`; the matching agent list via `/api/v1/scope/preview` (§2.11).

### 19.4 Hierarchical Management Groups :white_check_mark: `T2`

`ManagementGroupStore` with `parent_id` for nesting. `get_children()` returns direct children. `get_ancestor_ids()` / `get_descendant_ids()` traverse the hierarchy. Static membership (manual add/remove) and dynamic membership (a group stores a scope expression; `refresh_dynamic_membership()` replaces the dynamic members with a list of agents the caller resolved, and the server calls it once, at creation, for the auto-created `Service: {name}` groups). Well-known root group. REST CRUD + hierarchy endpoints. Group-scoped role assignments for access control. The `/groups` dashboard page reads the group tree, one group's details and its members through `/fragments/groups/{list,detail,members}` (read-only; members narrowed to the caller's scope).

### 19.5 Device Discovery (Unmanaged Endpoints) :white_check_mark: `T2`

`discovery` agent plugin (`scan_subnet` action) performs ARP scan + ping sweep of CIDR subnets. Server-side `DiscoveryStore` persists discovered devices with IP, MAC, hostname, managed status, discovering agent, and subnet. `mark_managed()` links discovered IPs to enrolled agents. REST API for listing and clearing results.

### 19.6 Custom Properties on Devices :white_check_mark: `T2`

`CustomPropertiesStore` (653 LOC). Typed key-value properties per device: string, int, bool, datetime. Schema CRUD with validation regex. Usable in scope expressions via `props.<key>`. Property validation against schemas. REST API for property and schema CRUD. Key validation (1-64 chars, `[a-zA-Z0-9_.-:]`), value limit 1024 bytes.

### 19.7 Agent Deployment Jobs :x: `T2`

**Not implemented: record-only, scheduled for removal (#6326).** `DeploymentStore` (PostgreSQL) stores job rows and the unversioned `/api/deployment-jobs` routes (`discovery_routes.cpp`) create, list, get and cancel them. Nothing executes a job and no caller advances one past `pending`; the `ssh` and `group_policy` methods are accepted by validation but have no implementation, and `manual` returns a placeholder install command. There is no `/api/v1/deployment-jobs` route. This is distinct from the live `/auto` Deploy workflow (§36.2). *(Regraded 2026-10-22 on the owner's ruling; previously mis-graded Done.)*

### 19.8 Agent Decommission and Data Erasure :white_check_mark: `T2` *(new row, v4.1)*

`DELETE /api/v1/sle/agents/{agent_id}` erases a decommissioned device's stored rows across nine per-agent stores (generic, software and device inventory, app-perf daily, software licensing, app usage, offline endpoint presence, certificate inventory, and the Guardian compliance census) on one scoped `Decommission:Delete` grant (Administrator and ITServiceOwner by default). Audit-before-erase and fail-closed: if the attempt row cannot persist nothing is erased (503 + `Sec-Audit-Failed`); a rolled-back store is reported as a partial 500, never a false success. Erasure does not unenroll — a still-enrolled agent re-creates its rows. REST only, by recorded ADR-1005 exception (#2102): no MCP twin until MCP has a destructive-operation gate. *(Evidence: `server/core/src/agent_decommission.{hpp,cpp}`, `sle_routes.hpp`.)*

---

## 20. Server: Response Collection and Reporting

*Aggregate, filter, paginate, and export command results.*

### 20.1 Real-Time Response Streaming :white_check_mark: `T1`

SSE-based streaming to dashboard. gRPC streaming for programmatic access.

### 20.2 Response Filtering and Pagination :white_check_mark: `T2`

`ResponseStore` on PostgreSQL (ADR-0039). `ResponseQuery` struct: agent_id, status, time range (since/until), limit/offset pagination. Exposed via `GET /api/responses/{instruction_id}` with query parameters.

### 20.3 Response Aggregation :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Done → Partial.** `ResponseStore::aggregate` supports COUNT, SUM, AVG, MIN and MAX, but grouping is by a **single** column from a two-item allow-list (`status`, `agent_id`), the operand column comes from `{timestamp, status, id}`, and the result is computed on demand in SQL, not incrementally as responses arrive. There is no grouping by a response's own result columns. REST endpoint with drill-down from aggregate to raw rows. *(Evidence: `server/core/src/response_store.cpp` `allowed_group_by()` / `allowed_op_column()`, `GROUP BY` at `:1278`.)*

### 20.4 Per-Device Error Tracking :white_check_mark: `T2`

`ResponseStore` persists per-response `error_detail` alongside status. Queryable by agent_id, status code, and time range for error history.

### 20.5 CSV / Data Export :white_check_mark: `T2`

CSV and JSON export endpoints for responses, audit, and inventory data. RFC 4180-compliant CSV. The response export is **buffered in memory under a byte cap**, not chunk-streamed: when the cap cuts the result it appends an in-band truncation trailer row and sets `X-Result-Truncated-By-Cap` (`server/core/src/response_routes.cpp`). Generic JSON-to-CSV conversion (`POST /api/export/json-to-csv`).

### 20.6 Response Templates :white_check_mark: `T2`

Named response-view configurations (column subset, sort order, filter presets) attached to an `InstructionDefinition`. Synthesised `__default__` view derived from `spec.result.columns` (or the plugin's column schema) so every definition has at least one selectable view. REST CRUD at `/api/v1/definitions/{id}/response-templates[/{template_id}]` gated on `InstructionDefinition:Read` (List/Get) and `InstructionDefinition:Write` (POST/PUT/DELETE). Dashboard surfaces the templates as a **View** dropdown in the filter bar; selecting one re-renders the table with the template's column subset, sort order, and equals-op filters auto-applied. YAML authoring via `spec.responseTemplates`. Phase 8.2, issue #254.

### 20.7 Response Offloading :white_check_mark: `T3` *(verified 2026-09-10)*

Operator-registered external HTTP endpoints (*offload targets*) that receive a copy of the `fire_event` stream (`agent.registered`, `execution.completed`, `dex.blast_radius`, `dex.signal`) as it fires. Sibling `OffloadTargetStore` (Postgres schema `offload_target_store`, ADR-0059) wired into `AgentServiceImpl` next to the existing webhook fan-out — every event that fires a webhook also fans out to every enabled offload target whose `event_types` filter matches. Typed auth: none / bearer / basic / hmac (Authorization headers are CRLF-guarded against header injection). Server-side batching: `batch_size > 1` accumulates events into a per-target buffer and flushes on threshold; flush body is JSON of shape `{"events":[…]}`. **Caveat added 2026-09-10 (Gate-of-record pass 3, sweep item 5):** batched (not yet flushed) events are **dropped on destruction**, not persisted or retried — `offload_target_store.cpp:316-320`'s own comment: "Intentionally NOT calling `flush_all()` here — buffered (`batch_size>1`) events not yet flushed are dropped on destruction... Operators needing at-least-once semantics should set `batch_size=1` (immediate dispatch, no buffer) or call `flush_all()` on a graceful [shutdown]." So `batch_size > 1` trades at-least-once delivery for fewer HTTP calls; that tradeoff is real and operator-controllable, but it wasn't previously documented here. REST CRUD at `/api/v1/offload-targets` gated on `Infrastructure:Read`/`Write`. `auth_credential` is `SecretCodec`-encrypted at rest (ADR-0010) and never returned by any read endpoint (a `has_credential` flag reports whether one is configured; paranoia-double-check assertion in REST tests). YAML authoring via `spec.offload.targets` is documented; dispatcher-side correlation (per-instruction filter honouring) deferred to a follow-up. Phase 8.3, issue #255. *(Evidence: `offload_target_store.cpp:316-320`; verified 2026-09-10.)*

### 20.8 Executions-History Ladder and Agentic Event Stream :white_check_mark: `T2` *(new row, v4.0)* *(verified 2026-09-07)*

The `command_id → execution_id` map + `ExecutionEventBus` SSE stream unifying dashboard and REST/MCP execution visibility behind one taxonomy (`/api/v1/events`) — never per-route event formats. `execute_instruction` (REST + MCP) is a tracked-execution producer. A4 error-envelope shape lives in `rest_a4_envelope.hpp`. *(Evidence: `server/core/src/execution_event_bus.{hpp,cpp}`, `execution_tracker.{hpp,cpp}`, `rest_a4_envelope.hpp` + `rest_a4_envelope_http.hpp`; design: `docs/executions-history-ladder.md`; verified 2026-09-07.)*

### 20.9 Forensics Tier on Stored-Response Reads :white_check_mark: `T2` *(new row, v4.1)*

Rows written by plugins on the `Forensics` securable are served only to a caller holding GLOBAL `Forensics:Read` (#4990). `ResponseTierFilter` (`server/core/src/response_tier_filter.hpp`) is a required, default-less parameter on every `ResponseStore` read and is pushed into the SQL, so a filtered row is absent, never marked. The Forensics plugin set is derived from the capability catalogue (`forensics_plugin_set.hpp`); an unresolved visibility decision fails closed as a retryable 503 for every caller class; provenance is server-authored per frame (`response_provenance.hpp`); Forensics failure text reaches every sink only through one sanitizer. The system role `ForensicsAnalyst` holds four fleet-wide read pairs and never gains Execute or Write. There is no management-group-scoped Forensics read tier. Deployment contract: fresh database only, every writer on the new build (`docs/user-manual/upgrading.md` "Deployment contract"). *(Evidence: `docs/authz-model.md` §4 "Reading the stored rows"; `tests/test_forensics_tier_wiring_lexical.py`.)*

---

## 21. Server: Notifications and Audit

*System events, audit trails, and external notification delivery.*

### 21.1 Agent Lifecycle Event Streaming :white_check_mark: `T1`

`WatchEvents` RPC.

### 21.2 Audit Trail of User Actions :white_check_mark: `T2` *(verified 2026-09-07)*

`AuditStore` (migrated to PostgreSQL, ADR-0040/Wave 1.3, PR #2697 — fail-hard writes, degrade→deny reads, SOC-2 evidence chain; verified 2026-09-07 via `pg::PgPool`/`pg::PgMigration` usage in `audit_store.cpp`, previous row text stale-claimed SQLite). Structured events: timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, result. Query with filtering and pagination via `/api/audit` and the versioned `GET /api/v1/audit`; every route or tool returning audit rows is gated on `AuditLog:Read`, which sits in the authorization-topology floor (admin-only regardless of the RBAC toggle). Retention is a clock-guarded, capped prune (`common/include/yuzu/audit_retention_rules.hpp`). Default 365-day retention. The dashboard reads the trail at Access > Audit and reviews (`/access/audit`): exact principal and action filters, a 1 h / 24 h / 7 d window, 50-row pages, and a degraded store shown as such, never as an empty log.

### 21.3 System Notifications :white_check_mark: `T2`

`NotificationStore` (migrated to PostgreSQL; verified 2026-09-07 via `pg::PgPool` constructor in `notification_store.cpp`, previous row text stale-claimed SQLite). Create notifications with level (info/warn/error/success), title, and message. List unread/all, mark as read, dismiss (soft-delete), count unread. The server writes a notification from five producer sites covering four events: first agent enrolment, a failed command (on both the Subscribe and gateway paths), a fleet incident (blast radius) and a DEX alert. Policy violations and deployment completions produce none. The dashboard header bell lists the unread feed and offers Mark read and Dismiss over the three dashboard JSON routes in `rest-api.md` ("Notifications feed"); there is no REST v1 or MCP twin yet.

### 21.4 Event Subscriptions (Webhook) :white_check_mark: `T3`

`WebhookStore` (PostgreSQL; the signing secret is stored through `SecretCodec`, ADR-0010). Register webhooks with URL, event type filter (comma-separated), and HMAC-SHA256 signing secret. Async delivery on a bounded worker pool (`StoreWorkerPool`, 4 threads, 256-deep queue; `webhook_store.hpp`). Events fired: `agent.registered`, `execution.completed`, `dex.blast_radius`, `dex.signal`. No email/SMTP delivery exists (the row was formerly titled "Webhook / Email"), and webhooks have no REST v1 or MCP twin (legacy `/api/webhooks*` only, §24.3). Delivery history with status codes and errors. `fire_event()` dispatches matching webhooks automatically. REST API for webhook CRUD and delivery log.

### 21.5 Event Source Management :x: `T3`

Not implemented. Configure which events generate notifications.

### 21.6 Behavioral-PII Access-Audit Chokepoint :white_check_mark: `T2` *(new row, v4.0)* *(verified 2026-09-07)*

Every behavioural-PII read (device-live-info, process/network drill, DEX perf, etc.) funnels through the single `emit_behavioral_audit` chokepoint (#1647) — with one tracked exception: the REST `device.live.*` incarnation still uses an inline bool-capture (tracked under #1647, open; #1703 was closed unverified in the 2026-07-14 backlog reset — re-confirmed live 2026-11-14 at the `POST /api/v1/dex/devices/{id}/live` handler, `rest_api_v1.cpp:~19381-19490`, which calls `audit_fn` inline; the dashboard's `device.live.*` routes in `device_routes.cpp` do use the chokepoint) — REST fail-closed 503 + `Sec-Audit-Failed` header on an audit-write failure, dashboard/MCP set-and-proceed. Standing invariant: no new PII route may reintroduce an inline bool-capture bypassing the chokepoint. *(Evidence: `server/core/src/rest_audit.hpp` `emit_behavioral_audit`; verified 2026-09-07.)*

---

## 22. Server: System and Infrastructure

*Monitoring, licensing, configuration, and multi-node scaling. **The server is Linux-only** (ADR-0035, accepted 2026-11-10, enforced at configure time in the root `meson.build`); Windows and macOS are agent-only platforms, so any Windows/macOS branch in server code is vestigial.*

### 22.1 System Health Monitoring :white_check_mark: `T2`

Kubernetes-style health probes: `/livez` (200 whenever the process is up; on the plain port 503 while the HTTPS listener is down) and `/readyz` (a gating Postgres-reachability verdict plus `failed_stores` and `degraded` lists and a non-gating `enablement` object), served on both listeners when HTTPS is on (the plain-HTTP redirect port answers them in cleartext); `yuzu-server --healthcheck` probes the HTTPS listener from inside the container. Gateway health endpoint with circuit breaker status. Prometheus `/metrics` endpoint exposes server/agent/gateway metrics. `ProcessHealthSampler` provides process telemetry from Linux `/proc/self`, sampled every 15s (the macOS/Windows branches in `process_health.hpp` are vestigial — the server is Linux-only, ADR-0035). New Prometheus metrics: `yuzu_server_cpu_usage_percent`, `yuzu_server_memory_bytes{type=rss|vss}`, `yuzu_server_open_connections`, `yuzu_server_command_queue_depth`, `yuzu_server_uptime_seconds`. `/health` endpoint includes `system` object with CPU, memory, connections, queue depth. Health dashboard strip shows CPU% and memory.

### 22.2 System Topology View :x: `T2`

No dashboard page. REST only: `GET /api/v1/topology` is a placeholder that returns a static message, not topology data. Regraded ✅ Done → ❌ Not Started. *(Evidence: the `/api/v1/topology` handler in `server/core/src/rest_api_v1.cpp`; no route serves a topology page. The fleet topology view that does exist is §28.7.)*

### 22.3 License Management :large_orange_diamond: `T2` *(verified 2026-09-07)*

`LicenseStore` with seat-based licensing, expiry, edition, feature flags. Soft enforcement with alerts when the seat count is exceeded or expiry is within 30 days (`license_store.cpp:447,458` — no 90% early-warning threshold exists). REST: `GET/POST/DELETE /api/v1/license`, `GET /api/v1/license/alerts`. **Dormant** (ADR-0048) — the store is migrated and tested but not constructed by the server, so these routes do not register today. The MCP twins (`get_platform_license`, `activate_platform_license`, `list_license_alerts`) are registered and advertised but answer "license store unavailable". **Regraded ✅ Done → 🔶 Partial (ADR-0048; regraded 2026-09-07)** — the store's own file header states it is "DELIBERATELY DORMANT on `dev`": nothing in `server.cpp` constructs a `LicenseStore`, so a fully-implemented, fully-tested capability that is not wired up in the running server is not a delivered capability. *(Evidence: `server/core/src/license_store.hpp` header comment; verified 2026-09-07. Not to be confused with §27 Software Licensing & Entitlements — this store is Yuzu's own product licensing, unrelated to customer software-license discovery.)*

### 22.4 Platform Configuration (TTLs, Limits) :white_check_mark: `T2`

`RuntimeConfigStore`. Persistent runtime configuration overrides in PostgreSQL (ADR-0060). Allow-listed keys only, **including one credential** (`oidc_client_secret`, SecretCodec-envelope-encrypted at rest, ADR-0010) - `is_secret_key` gates every emitter (startup log, `GET /api/config`, the `config.update` audit detail, and the `PUT` response echo) so the value is not returned or logged; pre-existing audit rows are redacted when read. Set/get/remove with `updated_by` attribution. **Only some keys take effect without a restart**: the three retention keys are stored-only (not enforced, even after a restart; set the CLI flag or environment variable), DEX-alert keys until a restart or a Settings-UI save, OIDC keys apply ONLY via a Settings-UI save (a restart does not apply them), and `auto_approve_enabled` is never read back from this store - see `docs/user-manual/rest-api.md` "Runtime Configuration". REST API for configuration CRUD. Startup defaults overridden by stored values.

### 22.5 Gateway / Scale-Out Architecture :white_check_mark: `T2`

Full Erlang/OTP gateway (`gateway/` rebar3 project). `yuzu_gw_agent` manages agent connections, `yuzu_gw_upstream` handles server-side gRPC (batch heartbeat, proxy register, command forwarding). `yuzu_gw_heartbeat_buffer` batches heartbeats for efficiency. Circuit breaker for upstream resilience (one per gateway, not per upstream server; several upstream servers per gateway is the intended production shape and is not yet designed end to end - ADR-2002 §7g). Health endpoint with metrics. Supervision tree with restart strategies. EUnit + Common Test suites including scale tests (10K+ agents). Since the Cowboy cutover the agent- and management-facing gRPC listeners run on the gateway's own Cowboy-based gRPC stack (`yuzu_grpc_*`), with a memory shedder (`yuzu_gw_memory_shedder`), heartbeat admission (`yuzu_gw_heartbeat_admission`), an upstream regulator, cluster discovery, management-plane peer authorization (§37.7) and proxy origin trust (§37.9).

### 22.6 Statistics Dashboard :large_orange_diamond: `T2`

No dashboard page. REST only: `GET /api/v1/statistics` returns fleet execution statistics (MCP twin `get_fleet_statistics`). Regraded ✅ Done → 🔶 Partial. *(Evidence: the `/api/v1/statistics` handler in `server/core/src/rest_api_v1.cpp`; no route serves a statistics page.)*

### 22.7 Binary Resource Distribution :x: `T3`

Not implemented. Distribute versioned binary resources via server.

### 22.8 Product Packs (Bundled Definitions) :white_check_mark: `T3`

`ProductPackStore` (1176 LOC). Install multi-document YAML bundles containing InstructionDefinitions, PolicyFragments, Policies, TriggerTemplates. Ed25519 signature verification through OpenSSL EVP (the BCrypt path was removed; the server is Linux-only). Install/uninstall with callback delegation to origin stores. Pack metadata, item tracking, and version management. REST API for pack CRUD.

### 22.9 Database Sharding (Response Partitioning) :x: `T3`

Not implemented. Time-partitioned response storage (PostgreSQL declarative partitioning — the server is Postgres-only, §38) with automatic rotation, TTL cleanup, and transparent cross-partition query routing. `response_store.cpp` uses no partitioning today.

### 22.10 High Availability (ADR-2002) :large_orange_diamond: `T3` *(verified 2026-11-14)*

Design plus a growing set of delivered workstreams, **not live HA — a second server replica is still NOT safe to run.** The safe-to-scale gate in `docs/ha-delivery-matrix.md` is explicitly not lifted: WS-4 (gateway intra-cluster routing — in progress), WS-6 (PKI/CA HA beyond slices 6.1/6.2; 6.1b/6.3 planned), WS-12 (backup/PITR) and WS-13 (gateway failover) are open, as are the registration reconcile on two replicas (#5649) and the per-endpoint circuit breaker (#5648). Not active-passive either: ADR-2002 explicitly disavows that model. **Delivered so far** per the matrix: WS-0 durable command idempotency; WS-1 milestones 1a (durable `SessionStore` with DB-clock authority, §18.13), 1b (`execution_tracker` + command correlation on Postgres) and 1c (the HA-critical store subset); WS-2a-1 transactional `event_outbox` and 2a-2 cross-replica event delivery; WS-3 slices 3.1-3.4 — the fenced, Postgres-backed `LeaderElector` (dedicated connection, session advisory lock, epoch fence) is **constructed at boot** (`server/core/src/server.cpp:9487`) and gates the `FencedLeaderOnly` background loops; WS-4 slices 4.1-4.4 (the fenced `GatewayRouteStore` directory and the gateway routing slices; 4.3a is component-complete but inert until gateway multi-node cluster formation ships, #4555), with WS-4 itself still in progress; WS-5 slices 1-2 (cross-replica presence via `OfflineEndpointStore`, durable cross-replica session resolution); WS-6 slices 6.1 (single CRL publisher, §37.6) and 6.2 (enrollment/pending on Postgres); WS-7 Patroni compose; WS-8 `/readyz` for the monolith; WS-10 10.1/10.2 classification of every background pass in `kBackgroundJobs` (`background_jobs.hpp`: 52 entries — 45 `ReplicaSafe`, 5 `FencedLeaderOnly`, 2 `DisabledUntilFixed` — counted at dev @ 2c49b4ea0 and pinned by `test_background_jobs.cpp`; `docs/ha-background-jobs.md` says 51 and the matrix's WS-10 row still says 40); WS-13 slices 13.0 (spike) and 13.1 (jittered reconnect); and the WS-11 leader-observability subset (#4014, alert group `yuzu-ha-leader`). *(2026-10-11: the production topology is dozens to hundreds of gateways, always at least two servers and a streaming-replication Postgres pair; the gateway-to-server side of that is design only. Explicit backpressure, a per-endpoint breaker with failover, the registration-reconcile decision and herd jitter are open — ADR-2002 §7g, #5647-#5651. Only the breaker's classification of request-fault answers is shipped.)* *(Evidence: `docs/ha-delivery-matrix.md` WS rows and "The safe-to-scale gate"; `server/core/src/leader_elector.{hpp,cpp}`, `leader_gate.hpp`; re-verified 2026-11-14 — the former "one unwired component" wording is withdrawn.)*

### 22.11 Shipped Prometheus Alert Rules :white_check_mark: `T2` *(new row, v4.1)*

`docs/prometheus/yuzu-alerts.yml` ships 212 alert rules in 26 groups (count of `- alert:` entries at HEAD), covering the fleet, commands, gateway, security, SCIM, MCP, dispatch, TLS, PKI, the response store, secrets, auth rotation, Postgres, HA leader, Guardian, audit, bundles, inventory, auth sessions, OTA, executions, enablement, Echo and same-site web writes. Rules are a routed concern: an alert that parses but cannot fire is a defect (`docs/observability-conventions.md`).

### 22.12 Backup and Restore :large_orange_diamond: `T2` *(new row, v4.1)*

The correct procedure — a `pg_dump --format=custom` of the Yuzu database **plus the whole `--ca-dir`** (the CA private key and the secrets KEK files) captured at the same instant, plus `nvd_cves.db`, the update and upload blob directories and `enablement-anchor` — is documented only in `docs/user-manual/server-admin.md` ("Backup recommendation"). `scripts/yuzu-backup.sh` / `yuzu-restore.sh` cover configuration files and the enablement anchor and print a reminder that Postgres and the CA directory must be backed up separately; the script's own header still says it "backs up SQLite databases", and `docs/operations/disaster-recovery.md` still describes backing up SQLite `*.db` files. No PITR/WAL archiving under HA Postgres (HA WS-12 open).

---

## 23. Agent-Side Key-Value Storage

*Persistent key-value store on the agent for cross-instruction state.*

### 23.1 Local Key-Value Storage :white_check_mark: `T2`

`storage` plugin with `set`, `get`, `delete`, `list`, `clear` actions. SQLite-backed persistent key-value store on the agent. Keys namespaced per plugin. Survives agent restarts and upgrades.

### 23.2 Remote Key-Value Access :white_check_mark: `T3`

`storage` plugin actions are dispatchable via server instructions. Server can remotely read/write agent storage via standard command dispatch.

### 23.3 Key Existence Check :white_check_mark: `T2`

`storage` plugin `list` action with optional prefix filter. `get` returns empty result for non-existent keys.

---

## 24. Integration and Extensibility

*External system integration, data exchange, and API surface.*

### 24.1 Plugin SDK (C ABI + C++ Wrapper) :white_check_mark: `T1`

Stable `plugin.h` C ABI with `plugin.hpp` CRTP wrapper. `YUZU_PLUGIN_EXPORT` macro.

### 24.2 gRPC Management API :white_check_mark: `T1`

`ManagementService` with list/get/send/watch/query.

### 24.3 REST / HTTP Management API :white_check_mark: `T2`

About 250 method/path pairs under the versioned `/api/v1/` prefix (a static scan of literal route patterns in `server/core/src`, so a lower bound), covering instructions, executions, commands, schedules, approvals, responses, audit, tags, scope, management groups, tokens, inventory, hardware, DEX, network, PKI, crypto, access reviews, plugin config and more. **Legacy-only families:** webhooks (`/api/webhooks*`), notifications (`/api/notifications*`), patches (`/api/patches*`), custom-property schemas (`/api/property-schemas*`) and policy mutations (`POST/DELETE /api/policies*`) exist only as unversioned `/api/` routes; there is no `/api/v1` twin for them, and `/api/v1/policies` is GET-only — gaps against ADR-1005's "no UI-only or legacy-only capability" rule. Session cookie, OIDC, SAML and API token auth. Cookie-session writes pass one pre-routing same-site gate against the trusted-origin set. OpenAPI spec at `/api/v1/openapi.json` plus a Swagger page. Consistent JSON (A4) error envelopes.

### 24.4 Consumer (External System) Registration :x: `T3`

Not implemented. Register external systems to receive data feeds.

### 24.5 Data Export to External Formats :white_check_mark: `T2`

CSV and JSON export endpoints. RFC 4180-compliant CSV, buffered under a byte cap with a truncation trailer rather than chunk-streamed (§20.5). Generic `json_array_to_csv` converter at `/api/export/json-to-csv`. Response data export with Content-Disposition headers. Audit log and inventory data also exportable via REST API JSON endpoints.

### 24.6 Utility Functions (JSON/Table Conversion) :white_check_mark: `T1`

`yuzu_table_to_json()`, `yuzu_json_to_table()`, `yuzu_split_lines()`, `yuzu_generate_sequence()`, `yuzu_free_string()` in `sdk/include/yuzu/plugin.h` C ABI.

### 24.7 SDK Libraries for External Integrations :x: `T3`

Not implemented. Client libraries wrapping the management API for third-party integration.

### 24.8 MCP Server (Model Context Protocol) :white_check_mark: `T2` *(verified 2026-09-07)*

Embedded MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. Enables AI models (e.g., Claude Desktop) to query fleet status, check compliance, and investigate agents. Phase 1 (historical): 22 read-only tools, 3 resources, 4 prompts. **Re-counted 2026-11-14: 220 tools, 13 resources, 13 prompts.** The tools are 206 entries in the legacy `kTools[]` array in `server/core/src/mcp_server.cpp` plus 14 registry records in `mcp_tools_*.cpp` (containment 1, crypto 7, DEX 3, discovery 1, hardware 2; the boot validator rejects a name present in both). The resources are 12 fixed `kResources[]` URIs plus 1 resource template; the prompts are the 13 `kPrompts[]` entries. The old one-line `awk` over `kTools[]` alone (→ 206) now undercounts because registry records live outside that array; the authoritative served set is the union of the tool-family lists in `server/core/src/mcp_orientation.cpp`, which the family-tether test pins to the live `tools/list`. The surface spans DEX perf twins, Echo, inventory and hardware CI, executions, preflight/deployment/verify, PKI and CRL sources, crypto, access reviews, plugin config, KEK rotation and SLE discovery among others, plus orientation `discover_*` tools for agentic workers. The write surface is broader than the historical single-dispatch note implied, and every tool honours the tier-before-RBAC ordering (§24.9). Seven MCP tools front dormant stores (three license tools, §22.3; four software-deployment tools, §7.6) and answer "unavailable" in production. **A5 annotation status:** the figure last measured was on 2026-09-07 (91/91 tools carrying the four standard spec annotations and an `outputSchema`, with typed-ness not 91/91 — the streamed-final fallback envelope `McpStreamBridge::build_fallback_final()`, #2990, and `list_engine_principals` array items left `additionalProperties:true`). It has not been re-measured against the 220-tool surface; do not read it as describing HEAD.

### 24.9 MCP Authorization Tiers :white_check_mark: `T2`

Three-tier authorization model enforced before RBAC: `readonly` (read-only tools), `operator` (+ tag writes, auto-approved executions), `supervised` (all operations via approval workflow). MCP tokens use existing API token system with `mcp_tier` column. Mandatory expiration (max 90 days, enforced at mint by `ApiTokenStore::validate_human_mint`; engine-principal tokens carry the same ceiling). Kill switch: `--mcp-disable` rejects all MCP requests, `--mcp-read-only` blocks non-read tools.

### 24.10 MCP Settings UI :white_check_mark: `T2`

Settings page section for MCP configuration: enable/disable and Read-only/Full-access, one Save with a confirmation per resulting state, on **Settings → Integrations** (`/settings/integrations`; the same panel also stays on `/settings`). API token creation supports MCP tier dropdown for creating MCP-scoped tokens.

### 24.11 MCP Streamed HTTP Transport :white_check_mark: `T2` *(new row, v4.0)* *(verified 2026-09-07)*

Streamable HTTP transport per ADR-1005 exec-plan Decision 15 / track 2f — sessions, GET SSE, and a progress bridge alongside the original single-request JSON-RPC transport, giving long-running MCP tool calls (e.g. `execute_instruction`) a streamed progress channel joining the executions-history ladder (§20.8) as a third bus consumer. *(Evidence: `server/core/src/mcp_transport.{hpp,cpp}`, `mcp_session.{hpp,cpp}`, `mcp_stream_bridge.{hpp,cpp}`; design: `docs/mcp-server.md`; verified 2026-09-07.)*

---

## 25. Connector Framework

*Bidirectional data sync with external management systems. None of this domain exists (no `ConnectorStore`, no connector sync in `server/core/src`). The nearest shipped features are not inventory connectors: directory sync (Entra Graph + LDAP stub, §18.6), webhooks (§21.4), response offload targets (§20.7), the Integrations settings page, and the agent-side `sccm` plugin (client version and site only, §7.3).*

### 25.1 Connector Registry and Configuration :x: `T2`

Not implemented. Pluggable connector architecture for syncing inventory data from external systems. ConnectorStore with encrypted credentials, sync scheduling, and connection testing.

### 25.2 Connector Sync Engine :x: `T2`

Not implemented. Background sync execution with lifecycle management (NotStarted → Pending → InProgress → Completed/Failed/Cancelled).

### 25.3 SCCM / ConfigMgr Connector :x: `T2`

Not implemented. SQL query integration with ConfigMgr database for hardware, software, user, and patch inventory.

### 25.4 Intune Connector :x: `T2`

Not implemented. Microsoft Graph API integration for managed device inventory and compliance state.

### 25.5 ServiceNow Connector :x: `T2`

Not implemented. REST API integration with ServiceNow CMDB for CI records, incidents, and change requests.

---

## 26. Inventory Repositories

*Named, multi-source inventory partitions with consolidation and normalization.*

### 26.1 Repository Model :x: `T2`

Not implemented. Named repositories per type (inventory, compliance, entitlement) with connector bindings and default repository.

### 26.2 Inventory Consolidation :x: `T2`

Not implemented. Multi-source deduplication by device identity (hostname + MAC + serial). Consolidation reports showing matched vs. unmatched records.

### 26.3 Software Normalization :large_orange_diamond: `T2` *(verified 2026-09-07)*

Partial. `SoftwareCatalogRollup` (`server/core/src/software_catalog_rollup.{hpp,cpp}`) canonicalizes vendor/title/version from the ADR-0016 `installed_software` daily-sync source for the `/inventory` dashboard's catalogue view. **Also shipped (2026-11):** the software title normalisation layer — `SoftwareTitleDimension` (permanent `title_dimension` and `curation_queue`), the hourly `SoftwareNormalizationJob`, a Postgres-persisted alias pack behind a trust-boundary parser, and the curation REST API `/api/v1/inventory/software/normalization/{status,queue,aliases,pack}` plus queue reject (`Inventory:Read`/`Write`, audited, fail-closed). A title is labelled, never guessed: auto-birth is off behind a `static_assert` (`kAutoBirthEnabled`) and the matcher's fuzzy tiers are unused. There is no curation dashboard page. This is the `/inventory`-scoped normalization pipeline (§35.4), not a general-purpose, repository-model-backed consolidation pipeline (§26.1/26.2 remain Not Started — no `Repository` model, no multi-source dedup-by-device-identity). *(Evidence: `server/core/src/software_catalog_rollup.cpp`; verified 2026-09-07 — previously mis-graded Not Started.)*

### 26.4 WSUS / CSV / File Upload Connectors :x: `T2`

Not implemented. WSUS database connector for patch compliance. CSV/TSV file upload connector with configurable column mapping.

---

## 27. Software Licensing & Entitlements (SLE)

*Normalized software identification, agent-discovered software licences, entitlements, and compliance management. The shipped half is discovery: the `license_scan` plugin, the `software_licensing` daily-sync source, `SoftwareLicensingStore`, `GET`/`DELETE /api/v1/sle/agents/{id}` and MCP `query_software_licenses` (§27.6), plus the app-usage read surface (§27.2); see `docs/user-manual/software-licensing.md`. Renamed from "Software Catalog & Licensing" by ADR-0024 ("software catalog" keeps its existing `/inventory` meaning; design of record: `docs/adr/0024-software-licensing-entitlements.md`). Sub-capability descriptions below predate ADR-0024 and are stale where they conflict with it.*

### 27.1 Product Registry :large_orange_diamond: `T2` *(verified 2026-09-07)*

Partial. `ProductRegistryStore` (`server/core/src/product_registry_store.{hpp,cpp}`) ships the canonical-identity plane: a `products` row per canonical identity keyed by the deterministic `product_normalize` norm key, plus `product_aliases` match links recording how each raw `(source, raw_name, raw_publisher)` triple resolved onto a canonical row — `method` + `confidence` persisted so manual curation can layer on later without redesign (ADR-0024 Decision 6), exactly as designed. A curation **API** for aliases has shipped (§26.3: alias create, queue list and reject, pack upload). **Missing:** a curation UI to review/edit aliases, and a dedicated dashboard surface (the discovery flows through `/api/v1/sle/*` and its MCP twin, §27.5). *(Evidence: `server/core/src/product_registry_store.hpp`, `product_normalize.hpp`, `software_curation_routes.hpp`; constructed at `server.cpp:8535`; verified 2026-09-07 — previously mis-graded Not Started. Correction to the source audit brief: this row's evidence is `product_registry_store.cpp`, NOT `license_store.cpp` — the latter is §22.3's unrelated, dormant, Yuzu-self-licensing store.)*

### 27.2 Software Usage Tracking :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Not Started → Partial.** Shipped: the `app_usage` agent plugin (`summary`, `last_used`, `foreground`; Windows and Linux supported, macOS constrained), which reads Echo's `usage` fold read-only and is **machine-scope** (no pid, command line or user name); the ADR-0016 daily-sync source `app_usage` (`agents/core/src/sync_source_app_usage.{hpp,cpp}`) feeding the server `AppUsageStore` (§35.6); and the Forensics-gated read `GET /api/v1/forensics/agents/{id}/app-usage` plus MCP `get_agent_app_usage` (`Forensics:Read` scoped to the device, per-open `app_usage.agent.view` audit that fails closed, 503 on a degraded store). **Collected by default, not opt-in** *(verified 2026-11-14)*: Echo's `usage` source ships `default_enabled = true` (`agents/plugins/echo/src/echo_schema_registry.cpp`, every source on by default since PR #6360), the daily-sync source pushes it every 24 hours, and `app_usage` is not among the four plugins `server.cpp` seeds kill-switched off (`seed_kill_switch_default_off`: `execution_artifacts`, `browser_inventory`, `privacy_permissions`, `remote_access_audit`). The opt-out is the Echo `usage` source switch (`usage_enabled=false` via `echo.configure`). The Forensics gate controls who can READ the data, not whether it is collected: the plugin's actions are `Forensics` Read with an `AdminOrApproval` dispatch gate, its stored responses are served only to `Forensics:Read` holders, and the server read is the audited route above. The formerly cited `--usage-sync-enable` flag does not exist. **Still missing:** the Used / Rarely / Unused / Unreported categorisation and the reclamation verdicts derived from it, which are SAM use-case-engine work (ADR-0024 "Placement under ADR-1005"). *(Evidence: `agents/plugins/app_usage/README.md`, `server/core/src/app_usage_routes.hpp`, `app_usage_store.*`.)*

### 27.3 License Entitlements & Compliance :x: `T2`

Not implemented (the `software_licensing` sync parser explicitly skips entitlement records). Entitlement records (product, metric-typed quantity — seats in v1 — license_type, term/renewal, cost) from five sources. Compliance calculation: installed vs. entitled with over/under-licensed reporting (ADR-0024 Decision 12; non-seat metrics stored faithfully, evaluated per the ADR's Direction ladder).

### 27.4 Software Tags :x: `T2`

Not implemented. Server-side tags on product registry entries for categorization (approved, prohibited, eval). Usable in Management Group rules.

### 27.5 License Compliance Dashboard :x: `T2`

Not implemented, and **re-scoped** by ADR-0024's "Placement under ADR-1005": the per-product compliance summary, the compliance dashboard, and reclamation-candidate identification are **SAM use-case-engine (UCE) module** surfaces, not built in-server. §27 v1 so far ships the in-server discovery **API** only — the raw `/api/v1/sle/*` drill, its `query_software_licenses` MCP twin, and the audited erasure DELETE. **No SLE UI ships yet:** the in-server **Licences (discovery) view** that Decision 9 places in-server is still to be built, and the compliance / entitlement / reclamation views are the UCE module's, which reads the discovery API over the versioned interface.

### 27.6 Detected Software Licences (Discovery API) :white_check_mark: `T2` *(new row, v4.1)*

The discovery slice ADR-0024 places in-server: the `license_scan` agent plugin (`list`, `surfaces`; OS, vendor and per-user licence surfaces; Windows and macOS supported, Linux constrained), the `software_licensing` daily-sync source, `SoftwareLicensingStore` (schema `software_licensing_store`), `GET /api/v1/sle/agents/{id}` (the per-device drill, `SoftwareLicensing:Read` scoped, per-open audit fail-closed) with its audited erasure `DELETE` (§19.8), and MCP `query_software_licenses` (machine-scope facts only, no `user_ref`). Compliance, entitlement and reclamation views are out of scope here (§27.3-27.5). *(Evidence: `server/core/src/sle_routes.{hpp,cpp}`, `software_licensing_store.hpp`; `agents/plugins/license_scan/README.md`; `docs/user-manual/software-licensing.md`.)*

---

## 28. Response Visualization

*Chart rendering, data processing, and template management for instruction responses.*

### 28.1 Response Visualization Engine :white_check_mark: `T2`

Implemented. Server-side data transformation with built-in processors (`single_series`, `multi_series`, `datetime_series`) and an optional row pre-filter (`whereField` / `whereEquals`). Chart types: pie, bar, column, line, area. Configured via `spec.visualization` (singular) or `spec.visualizations` (plural for multi-chart). REST: `GET /api/v1/executions/{id}/visualization?definition_id=<id>&index=<N>` gated on `Response:Read`. Renderer is Apache ECharts 5 (vendored at `server/core/vendor/echarts.min.js`, served as `/static/echarts.min.js`) wrapped by a thin adapter embedded in `server/core/src/charts_js_bundle.cpp` and served at `/static/yuzu-charts.js` that reads `--mds-color-chart-*` Yuzu design tokens at render time. Six chart-bearing demo definitions (vuln_scan, antivirus, bitlocker, firewall, certificates, os_info) ship as `InstructionSet demo.visualization.fleet-posture`, auto-imported on server startup.

### 28.2 Response Templates :white_check_mark: `T2`

Implemented. Named response view configurations stored per `InstructionDefinition` in a `response_templates_spec` JSON column. Synthesised `__default__` view from `spec.result.columns` or plugin schema. REST CRUD + dashboard View dropdown. See §20.6 for the full contract. Phase 8.2, issue #254.

### 28.3 Response Offloading :white_check_mark: `T2` *(verified 2026-09-07)*

Shipped — this row duplicates §20.7 (same capability, filed under two domains during the original outline). See §20.7 for the full description: operator-registered offload targets, typed auth, CRLF-guarded headers, batching, `SecretCodec`-encrypted credentials at rest, REST CRUD at `/api/v1/offload-targets`. *(Evidence: `server/core/src/offload_routes.{hpp,cpp}`; verified 2026-09-07 — previously mis-graded Not Started; the row is kept rather than deleted per the map's "mark, don't remove" convention.)*

### 28.4 Echo Dashboard Page :large_orange_diamond: `T2`

In progress (Phase 15.A retention + 15.D SQL frame; the **15.H process tree viewer shipped 2026-06-18**). A dedicated `/echo` page in the sidebar's **Posture** group. Surfaces, in one place, every operator-facing Echo affordance: ad-hoc SQL against agent warehouses with scope-walking-aware results (`save as result set` for downstream narrowing), retention awareness across the fleet, and the **shipped** process tree viewer (Frame 3, §28.5). The consolidation makes Echo — the headline forensics + inventory capability — a discoverable destination rather than a fragment scattered across other pages. An Echo timeline page and renderers are in code (`echo_timeline_page_ui.cpp`) but stay hidden until the timeline fragments land (`docs/echo-dashboard.md` §5.8). **Capture defaults (verified 2026-11-14):** since PR #6360 (merged 2026-10-23, owner ruling recorded in ADR-3006) every Echo capture source ships `default_enabled = true` on every OS where the source is supported, and upgraded agents were moved to on (Echo schema v8). That includes the privacy-sensitive ones — `dns` (usage-class PII, ADR-0015), `arp`, `usage` (per-executable runs with a per-day user count) and `removable` (whose roll-up keys on device vendor, product and **serial**, `echo_fold_schema.cpp`) — each opt-out per source via `echo.configure <source>_enabled=false` or the Capture sources frame (`agents/plugins/echo/src/echo_schema_registry.cpp`). Design: `docs/echo-dashboard.md`.

### 28.5 Echo Process Tree Viewer :white_check_mark: `T2` *(verified 2026-11-14)*

Shipped 2026-06-18 (Phase 15.H, [#554](https://github.com/DevNullLtd/Yuzu/issues/554)); **rebuilt on the hourly roll-up** after the agent moved to roll-up-only storage (schema v10, #7037), the server to roll-up-only Echo reads (#7318) and the raw-table fallback was removed (#7507). It now reconstructs a **name-level** per-host process tree for one selected hour from that host's local Echo roll-up (`$Process_Hourly`, with `$TCP_Hourly` joined by process name and device-level `$DNS_Hourly`/`$ARP_Hourly` panels, via the read-only `echo.sql` action) — **no seed**, no `/proc`/`CreateToolhelp32Snapshot`/`proc_listallpids` walk, no server-side mirror, no live process probe; an agent without the roll-up store is told to upgrade. A node is a process name per user with that hour's start / stop / abnormal-exit counts; there are **no process ids, command lines, paths or start/exit times**, the parent link is by name (processes sharing a name share one position), and the former Running/Exited states and filters are gone. The tree is built server-side in C++ from flat rows, cycle-safe and capped at 50,000 nodes (`server/core/src/echo_process_tree.{hpp,cpp}`; recursive CTEs are blocked on the agent). Renders as a collapsible tree with a detail panel (name, parent name, user, the hour's counts, the hour's connections, anomaly evidence) plus client-side anomalies-only and text filters. Window presets are Last hour · Last 24 hours · Last 7 days or a custom From/To, resolved to whole hourly buckets with an hour picker (`echo_tree_routes.cpp`). A name-based heuristic and abnormal exits flag anomalies. Viewing the frame needs `Infrastructure:Read`; reconstruction dispatches a live `echo.sql` so it additionally requires `Execution:Execute` + the device's management scope, and the detail cache is keyed by a CSPRNG token bound to the originating operator. This is a deliberate deviation from the original seed-snapshot design. API parity covers the device picker only (`GET /api/v1/echo/process-tree` + MCP `list_echo_process_tree_devices`); the result and detail fragments are deliberately not twinned (`mcp_server.cpp`), so tree parity remains a tracked follow-up ([#1562](https://github.com/DevNullLtd/Yuzu/issues/1562)). Design: `docs/echo-dashboard.md` §5.

### 28.6 Retention Awareness Surface :white_check_mark: `T2`

Shipped (Phase 15.A). Operator-facing aggregate view of every device × source pair where `<source>_enabled=false` — the operational consequence of issue #539's per-source retention pause. Surfaces "paused since" timestamp, live-row count, oldest timestamp; supports one-click re-enable (per-source, the #539 invariant) and a typed-hostname-confirmation purge (agent action `echo.purge_source`, `Infrastructure:Delete`) for the "we have what we need, drop the rows but keep the collector paused" case. Without this surface, operators who disabled a collector for forensic preservation have no way to know which boxes are accumulating non-aging data. Design: `docs/echo-dashboard.md` §3.

### 28.7 Fleet Topology 3D Visualization :large_orange_diamond: `T2` *(verified 2026-09-07)*

Further along than the original 11-PR estimate (`feat/viz-engine` branch, merged to dev 2026-05-15). `/viz/fleet` page renders the fleet as translucent cubes (one per agent) with interior process dots coloured by category (`system`, `browser`, `database`, `web`, `runtime`, `other`). Backed by an aggregating `FleetTopologyStore` (60s LRU-of-2 cache, single-flight refill) producing a `fleet_topology.v1` JSON envelope. REST: `GET /api/v1/viz/fleet/topology` + HTMX fragment `/fragments/viz/fleet/topology`. WASD/orbit/zoom camera, hostname `Sprite` labels, hover tooltip with raycaster, kill switch (`--viz-disable` / `YUZU_VIZ_DISABLE`), `machines_max` DoS cap (default 5000 / ceiling 100000), tier-before-permission ordering, audit actions `viz.fleet_topology` + `viz.fleet_topology.invalidate`. **Verified 2026-09-07: PRs 8 and 9 shipped** (intra-cube localhost edges + cross-machine/external edges — `docs/fleet-viz-invariants.md` "Edge invariants — PR 8", cross-machine edge code in `yuzu-viz.js`). **PR 10 shipped too, but scope changed**: it landed as `fleet_snapshot_json` push-ingestion (`FleetTopologyStore::push_snapshot()`, additive proto field on `HeartbeatRequest`) rather than the originally-planned vulnerability overlay — that overlay does not exist (zero hits for `mode=threat`/`ThreatGraph` in `yuzu-viz.js`; tracks with §28.8 staying Not Started). **PR 11 (LOD/InstancedMesh/scheduler polish) remains open** — only forward-looking comments in `yuzu-viz.js` reference it, no InstancedMesh migration landed. **Also shipped:** a per-host drill-down at `/viz/host/<agent_id>` (a 2D Cytoscape IPC graph plus the Echo process tree; `GET /api/v1/viz/host/{id}/topology` + fragment, `viz_host_page_ui.cpp`). Design: `docs/plans/feat-viz-engine-plan-2026-05-09.md`. Standing invariants: `docs/fleet-viz-invariants.md`.

### 28.8 Threat Graph Mode :x: `T2`

Not implemented. Mode toggle on `/viz/fleet` (`?mode=threat` / `T` shortcut, persisted in `localStorage`) that overlays:
1. **Per-host IPC graph** — all same-host IPC channels, not just TCP loopback. New `EdgeKind` enum on `ConnectionEdge`: `TcpLoopback` (today), `UnixSocket`, `NamedPipe`, `SharedMemory`, `DBus`, `ALPC`, `EbpfMap`. Each renders with a distinct line style + colour. `world_accessible` boolean per edge surfaces a red glow on edges whose endpoints any process can join (Unix socket with `0666`, abstract socket, world-rw `/dev/shm`).
2. **Per-process posture overlay** — composite glyph synthesising vulnerability scan + AV status + signed-binary verification + firewall exposure + disk encryption into a single character (`!` warning, `⚠` high risk, `?` unknown, hidden when hardened). Sprite-child of each process Sphere, reuses PR 6 sprite infrastructure.
3. **Cross-host network graph** with TLS-termination annotation on listening sockets carrying cert subject / issuer / expiry; new `Containerised` scope classification for inter-container traffic on private RFC1918 / Docker default ranges.

Anti-Mythos framing: Yuzu is the defender's mirror of LLM-driven offensive enumeration; operators read the Threat Graph to decide where to insert controls (WAF, IPS, API gateway, VxLAN separation, firewall, network-parser hardening). Design: `docs/plans/threat-graph-roadmap.md`.

### 28.9 Defender Recommendation Engine :x: `T2`

Not implemented. An external **agentic AI worker** (running as a managed per-customer sprint cadence) consumes Threat Graph snapshots and produces hardening recommendations — "insert WAF here", "VxLAN-separate these services", "harden this network parser against direct injection" — posted to a new `recommendations.db` server store via REST + MCP using a service-scoped API token. Recommendations are ghost-overlaid in Threat mode; operators *accept* / *dismiss* / *apply* via the existing approval workflow (`workflows` store). "Apply" calls existing plugin actions (firewall rule add, etc.). Schema: `customer_id`, `generated_by`, `kind` (insert_waf / vxlan_separate / firewall_rule / harden_parser / kill_world_socket), `target_node_ids`, `target_edge_keys`, `rationale`, `status` (open / accepted / dismissed / applied), `yaml_source`. Design: `docs/plans/threat-graph-roadmap.md` § Recommendation engine.

---

## 29. Consumer Applications

*Formal registration and management of external systems consuming Yuzu data.*

### 29.1 Consumer Application Registration :x: `T2`

Not implemented. ConsumerStore for registering third-party applications with scoped API tokens, rate limits, and custom data fields.

### 29.2 Event Source Management :large_orange_diamond: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Not Started → Partial (low confidence).** Per-subscription event-type filtering exists: each webhook (§21.4) and offload target (§20.7) carries an `event_types` comma list, managed from the Integrations page's webhook panel (`webhook_store.hpp`). There is no per-category enable/disable for notifications and no severity thresholds.

### 29.3 PowerShell Module :x: `T3`

Not implemented. `Yuzu.Management` PowerShell module wrapping REST API v1 with cmdlets for fleet management, instruction execution, and compliance queries.

### 29.4 Python SDK :x: `T3`

Not implemented. `yuzu-sdk` Python package wrapping REST API v1 with async support and typed models.

---

## 30. Scope Walking & Result Sets

*The Yuzu product differentiator. Operator working memory is finite; the IT estate is a finite-state automaton with mutating state-table size and mutating per-row state. Real-time discovery via iterative scope narrowing — every query produces a device set that becomes the input scope for the next query or action — is the only realistic interaction model at fleet scale. Reference walkthrough: the Chrome incident-response scenario in `docs/scope-walking-design.md` §10.*

### 30.1 Result Set Persistence and Lineage :white_check_mark: `T2` *(verified 2026-09-07)*

Shipped 2026-05-31 (Phase 15.B; `68427bba`). **Update 2026-09-07: `result_set_store.{cpp,hpp}` is now PostgreSQL** — the Postgres-migration ladder item this row originally flagged is done (verified via `PGconn`/`pg::` usage in `result_set_store.cpp`; part of the broader server-store migration, see §38). The REST surface lives in `rest_api_v1.cpp`. A named, TTL-bounded set of device IDs produced by a query, action result, or operator-curated list — the unit of composable scope. Stable identity (`rs_<ulid>`), optional human-readable per-operator alias, immutable lineage edges that record the chain of `(parent_result_set, narrowing_query)` back to a ground set, source-payload JSON sufficient to live-re-evaluate the producing query without operator re-input. Persisted in the `result_set_store` PostgreSQL schema (ADR-0036; formerly `result_sets.db`) with `ON DELETE CASCADE` member rows; pinning extends TTL beyond the default 1 hour for incident-response sessions; per-operator quotas (10K result sets, 50 pins) and a 5-minute background GC sweep prevent runaway scripts from filling the table. REST: `/api/v1/result-sets/...` covering create-from-inventory/echo/instruction, members, lineage, pin/unpin/re-eval, delete. Audit row per state transition for forensic reconstruction. Design: `docs/scope-walking-design.md` §3, §6, §9.

### 30.2 Composable Scope from Previous Query :white_check_mark: `T2` *(verified 2026-09-10)*

Shipped 2026-05-31 (Phase 15.C; `68427bba`, hardening `4f10a69b`). The Scope Engine grammar gains a third short-circuit kind, `from_result_set:<id-or-alias>`, alongside the existing `__all__` and `group:<name>`. Composes with attribute predicates via `AND`/`OR`/`NOT` so a result set can be the candidate set and the predicate is a real-time refinement against current device attributes. Stale members (offline > 24h, decommissioned, removed from management group) are silently dropped at resolve time with a dashboard-surfaced warning rather than failing the query — operators iterating an IR chain need progress, not a stop. **Corrected 2026-09-10 (Gate-of-record pass 3, sre-1): removed the "audit row records the dropped IDs for forensic completeness" claim — no such audit row exists.** `AgentRegistry::evaluate_scope()` (`server/core/src/agent_registry.cpp:1402+`) and `ResultSetStore::member_set_owned()` (`server/core/src/result_set_store.cpp:590`, whose own comment documents the "stale members drop silently" contract) contain no `audit`/`audit_fn` call anywhere in the drop path. The only result-set audit verbs that exist anywhere in the codebase are `result_set.access`, `result_set.create`, `result_set.delete`, `result_set.pin`, `result_set.unpin` (`server/core/src/rest_api_v1.cpp`) — none of them fire during scope-resolution-time stale-member dropping, which happens deep in `AgentRegistry`, not through a REST route's `audit_fn`. The dashboard-surfaced warning at query time is real; a durable, queryable audit trail of exactly which device IDs were silently excluded is not. Dashboard surfacing: persistent left-rail sidebar of the operator's active result sets, chain breadcrumb above every query frame mirroring the lineage, scope chip in every query/instruction/policy frame for one-click rebinding. Design: `docs/scope-walking-design.md` §4, §8. *(Evidence: `agent_registry.cpp:1402-1460`, `result_set_store.cpp:590`, `rest_api_v1.cpp` verb grep; verified 2026-09-10.)*

### 30.3 YAML DSL `fromResultSet:` Surface :white_check_mark: `T2` *(verified 2026-09-10)*

Shipped 2026-05-31 (Phase 15.E; `e6361a3a`). Instruction/instruction-set paths done; **Policy `fromResultSet:` deferred to PR-E2** (result-set TTL vs. continuous policy evaluation). The `scope:` block in `InstructionDefinition`, `InstructionSet`, and `Policy` gains `fromResultSet:` as a mutually-exclusive (or composable-with-`selector:`) alternative form so YAML-defined automation can target the device set produced by a previous query. Validation rules: `fromResultSet + assignment.managementGroups` rejected at YAML load (a result set already has a fixed device set, layering management-group filtering on top is redundant); `fromResultSet` requires `assignment.mode = static` (the whole point of a result set is a fixed target — `dynamic` re-evaluation against management groups would defeat it). Resolution at instruction *invocation* time, not YAML load time, so a definition carrying `fromResultSet:` is valid YAML even if the referenced set has expired by invocation. Resolution failure surfaces as `INSTRUCTION_SCOPE_RESOLUTION_FAILED` with the result-set ID and reason in the audit row. Design: `docs/scope-walking-design.md` §7. *(Spot-checked 2026-09-10, Gate-of-record pass 3 sweep item 5 — distinguish from §30.2's finding: this audit row IS real, unlike §30.2's now-removed claim. `server/core/src/server.cpp:11548-11559` genuinely constructs an `AuditEvent{action="instruction.scope_resolution_failed", ...}` and calls `audit_store_->log(ev)` on this specific resolution-failure path. Claim holds.)*

### 30.4 Result Set Operational Hardening :large_orange_diamond: `T2`

Largely shipped (Phase 15.G). Shipped: live re-eval (sibling result set), background GC sweep (`ResultSetStore::gc_sweep()` wired in `server.cpp`), per-operator quota/pin caps (`429`/`409`), and Prometheus `yuzu_result_sets_total` / `yuzu_result_sets_alive` / `yuzu_result_set_gc_total` / `yuzu_result_set_quota_rejected`. Remaining: the `yuzu_result_set_resolve_seconds` histogram and a final audit-polish pass. Live re-evaluation produces a *new* result set ID rooted at the original's parent (sibling, not child) — operators can refresh a stale set against current estate state without breaking lineage. Background GC sweep every 5 minutes removes unpinned sets past TTL, cascading to member rows. Per-operator quotas enforced with `429 RESULT_SET_QUOTA` and `409 PIN_LIMIT`. Prometheus metrics — `yuzu_result_sets_total`, `yuzu_result_sets_alive`, `yuzu_result_set_resolve_seconds` histogram by cardinality bucket, GC counter, quota-rejection counter — surface health and runaway-script detection. Audit polish on every state transition. Design: `docs/scope-walking-design.md` §3.3, §9.

---

## 31. System Guardian — Real-Time Agent-Side Guaranteed State

*The agent-side primitive that makes guaranteed state **operationally true** rather than approximately true. PolicyStore (§16) evaluates desired-state rules on a poll-based schedule — typical 5-minute cadence. For security-sensitive settings ("this firewall port must never be open," "this registry value must never change," "this EDR process must always run") a 5-minute window is unacceptable. System Guardian uses **kernel-backed user-mode notification APIs** to detect drift within microseconds of it occurring, remediate it, and journal the event — even when the server is unreachable, even before any user has logged in. This is the headline parity feature against the leading commercial endpoint-management platforms' real-time enforcement engines. Agent runs in user space as SYSTEM (Windows) / root (Linux) / privileged daemon (macOS); no kernel drivers required. Design: `docs/yuzu-guardian-design-v1.1.md`. Windows-first delivery: `docs/yuzu-guardian-windows-implementation-plan.md`.*

### 31.1 Guardian Engine and Wire Protocol :white_check_mark: `T2` *(verified 2026-09-07)*

Shipped — well beyond the PRs 1-2 status this row originally recorded. Agent-side `GuardianEngine` (`agents/core/src/guardian_engine.{hpp,cpp}`) with two-phase startup — `start_local()` pre-network so enforcement is active before the Register RPC, then `sync_with_server()` post-Register. KV namespace `__guardian__` for cached policy. Reserved plugin name `__guard__` intercepted in `agent.cpp` before the plugin match loop (load-time rejection in `plugin_loader.cpp` for defence in depth). Wire contract: `proto/yuzu/guardian/v1/guaranteed_state.proto` with `GuaranteedStateRule`, `GuaranteedStatePush`, `GuaranteedStateEvent`, `GuaranteedStateStatus`, `GuaranteedStateRuleStatus`. Server store: PostgreSQL schema `guaranteed_state_store` (ADR-0038; formerly `guaranteed-state.db`) with immutable event log, plus the `BaselineStore` deployment model (`server/core/src/baseline_store.{hpp,cpp}`) — a **Baseline** is the only deployable unit; push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()` sourced from each deploy's `deployed_snapshot`, not the live member set (`docs/guardian-baseline-model.md`). **Also verified 2026-09-07: ADR-0021 Spark is wired as Guardian's first consumer** — `agents/core/src/agent.cpp:1406` calls `wire_spark_engine()`, and `GuardianEngine::reconcile_rule_locked()` is the sole per-rule arm/disarm chokepoint enforcing mutual exclusion between legacy `IGuard` and `spark_runtime_`. `prefer_spark_` is **false** in production (the literal `/*prefer_spark=*/false` at `agent.cpp:960`), so Spark is wired but inert — legacy `IGuard` remains the sole *live* enforcement path; this does not change any guard row's grade below, since none of them currently attribute live enforcement to Spark. Actions: `push_rules`, `get_status`.

### 31.2 Event Guards — Kernel-Event-Driven Enforcement (Windows) :large_orange_diamond: `T2` *(verified 2026-09-07)*

Partial. **Corrected 2026-09-08 (governance sec-H1/sec-H2/UP-1):** of the four *originally-designed* Windows kernel-backed user-mode guards, **2 of 4 are live and remediation-capable** — Registry Guard and SCM Guard. A bonus File Guard shipped alongside them (not one of the original 4) but is **detection-only**, per its own source comment: `agents/core/src/guard_file.cpp:58` — "Detection-only: a FileGuard never writes (file-content remediation needs Content Distribution; deferred)." Enforce-promotion for the two remediation-capable guards is gated by the single `dangerous_enforce_in_spec` chokepoint (`server/core/src/guardian_rule_spec.cpp:303`):
- **Registry Guard** — shipped, detect + remediate (`agents/core/src/guard_registry.cpp` legacy path, `spark_registry.cpp` Spark-mechanism path). `RegNotifyChangeKeyValue` + `WaitForMultipleObjects` (~0 ms latency); the canonical "registry value must equal X" enforcer.
- **SCM Guard** — shipped, detect + remediate (`agents/core/src/guard_service.cpp`, `spark_service.cpp`). `NotifyServiceStatusChange` (~0 ms latency); enforces "service must remain running/stopped/disabled."
- **File Guard** — shipped, **detect-only, no remediation** (`agents/core/src/guard_file.cpp`, `spark_file.cpp`); not one of the original 4-guard design, delivered alongside it.
- **WFP Guard** — Not implemented. `FwpmFilterSubscribeChanges0` (~0 ms latency); defence-in-depth filter monitor for firewall posture. *(Verified 2026-09-07: no `FwpmFilterSubscribeChanges` call sites in `agents/core/src`.)*
- **ETW Guard** — Not implemented. `OpenTrace` / `ProcessTrace` (~1-5 ms latency); the multiplexed event provider with shared-session pooling per `docs/yuzu-guardian-design-v1.1.md` §8.3 (mandatory because Windows caps system-wide ETW sessions at 64, shared with Defender / EDR). *(Verified 2026-09-07: no `ProcessTrace`/`OpenTrace`/ETW-guard call sites anywhere in `agents/core/src`.)*

**Corrected 2026-09-08 (sec-H1):** the row previously claimed each guard implements a `self_test()` sentinel-probe mechanism on start; that symbol does not exist anywhere in `agents/core` (`grep -rn self_test agents/core` → 0 hits). The real mechanism is the opposite of a self-test: `GuardianEngine::get_status()` (`agents/core/src/guardian_engine.cpp:2889`) reports every rule **conservatively fail-closed** — `compliant_rules=0`, `drifted_rules=0`, every rule counted `errored` — because, per the code's own comment, "`guard_healthy` is a RESERVED wire field whose safe default is 'unknown' (false)... until a real self-test / last-remediation signal exists (deferred...)". So there is no kernel-wiring health probe today; the engine deliberately under-reports rather than claim health it can't prove (consistent with §31.9's "Missing: kernel-wiring health indicator"). Resilience strategies (`Fixed`, `Backoff`, `Escalation`) live in `resilience_strategy.cpp`.

### 31.3 Condition Guards — Periodic Evaluation (All Platforms) :large_orange_diamond: `T2` *(verified 2026-09-07)*

Partial. `spark_interval.cpp` ships a periodic-evaluation mechanism and the Linux service run-state guard (`make_service_guard()` in `agents/core/src/guard_systemd.cpp`, header `agents/core/include/yuzu/agent/guard_systemd.hpp`; Linux-only, §31.4) is a shipped instance of it, plus `spark_disk.cpp` (a disk-condition guard not in the original design). The originally-scoped process/WMI/software/compliance condition guards remain open: Hybrid Process Guard (`Microsoft-Windows-Kernel-Process` ETW + `CreateToolhelp32Snapshot` poll safety net), WMI Guard (arbitrary WMI queries against an evaluator), Software Guard (Registry Uninstall keys + WMI freshness), Compliance Guard (Event Log queries) — none of these four found in `agents/core/src`.

### 31.4 Event Guards — Linux :large_orange_diamond: `T3` *(verified 2026-09-07)*

**Partial.** The **systemd service guard** (`SystemdServiceGuard`, `guard_systemd.{hpp,cpp}`) ships: `org.freedesktop.systemd1` `PropertiesChanged` subscriptions over sd-bus watch a unit's `ActiveState` ("sshd.service must remain running"), **observe-only** in v1 — drift is detected and reported (`platform=linux`); enforcement (mask/stop) is deferred to a polkit-gated change. The remaining Linux event-guard primitives are roadmap:
- **Inotify Guard** — `inotify_add_watch` for file/directory state assertions (config files, certificate files, sshd config).
- **Netlink Guard** — `NETLINK_KOBJECT_UEVENT` for process-tree and device-event monitoring.
- **D-Bus / systemd Guard** — service-state observation **shipped** (above); enforcement + non-systemd fallback remain roadmap.
- **Audit Guard** — Linux audit subsystem (`auditd`) consumer for syscall-level assertions.
- **Sysctl Guard** — periodic check + `/proc/sys/...` write remediation; monitors kernel parameters that drift would indicate compromise.

The systemd service guard landed ahead of the rest of the Linux track (the motivating "keep SSH off" case); the remaining primitives stay gated on the Windows track soaking in production.

### 31.5 Event Guards — macOS :x: `T3` *(verified 2026-09-07)*

Not implemented (PR 17). macOS equivalents using Apple's Endpoint Security (ES) framework — *requires the ES entitlement*, which is a notarised-build / DDM-distributed entitlement that Apple grants per-bundle-ID. Without ES, the macOS guard surface is reduced to `fseventsd`, `launchd` plist polling, and `kqueue` file-watch. Phase 16 macOS delivery is gated on (a) Windows + Linux soak and (b) ES entitlement availability.

### 31.6 State Evaluator and Remediation Engine :large_orange_diamond: `T2` *(verified 2026-09-07)*

Partial. **Corrected 2026-09-08 (governance sec-H2):** Registry/service drift detection **+ remediation** are live behind the `dangerous_enforce_in_spec` denylist chokepoint (`server/core/src/guardian_rule_spec.cpp:303` — confirmed handles `registry-value-equals` and `service-stopped` denials for H1 registry-persistence keys and critical-service stops such as `rpcss`/`dcomlaunch`/the agent's own service). **File is detection-only** — `guard_file.cpp:58` states plainly "a FileGuard never writes"; the chokepoint above covers registry/service only, not file, because there is no file-remediation code path to gate. The decide/emit evaluation core (`agents/core/src/guardian_rule_eval.{hpp,cpp}`) computes `compliant | drift | exempt`-style verdicts per guard type with debounce/recovery-edge handling, but it is wired to the shipped guard types (registry/service remediation-capable, file detect-only), **not** the fully general assertion registry the original design specified (`firewall-port-blocked`, `process-running`, `file-hash-equals`, `kernel-param-equals`, `plist-key-equals` are not found in `agents/core/src`). Remediation methods are **system calls only — no shell-out** for the two remediation-capable guards (per design §14). *(Evidence: `guardian_rule_spec.cpp`, `guardian_rule_eval.cpp`, `guard_file.cpp:58`; verified 2026-09-07/08 — previously mis-graded Not Started, then over-stated file remediation.)*

### 31.7 Audit Journal and Server Store :large_orange_diamond: `T2` *(verified 2026-09-07)*

**Regraded 2026-09-08 (governance sre-H1): Done → Partial — implemented, inert by default.** **Corrected 2026-09-10 (Gate-of-record pass 3, sec-1): the previous fold of this row wrongly claimed the legacy path pushes no events at all — that is false; two distinct mechanisms exist and must be named separately.** Server store shipped and live: `server/core/src/guaranteed_state_store.{hpp,cpp}`, PostgreSQL schema `guaranteed_state_store` (ADR-0038), immutable event log, no FK cascade on rule delete so historical events persist for forensic review.

**Mechanism 1 — live, fire-and-forget event push (works today, NOT gated on Spark).** Every guard — legacy `IGuard` and Spark alike — reports drift/remediation through `GuardianEngine::emit_guard_event()` (`agents/core/src/guardian_engine.cpp:3127`), which calls the currently-wired `event_sink_`. That sink is `Agent::emit_guardian_event()` (`agents/core/src/agent.cpp:~4131-4150`), wired unconditionally whenever `guardian_` exists (`set_event_sink` at `agent.cpp:2330`, not conditioned on `prefer_spark_`): it builds a `__guard__`/`event` `CommandResponse` and writes it over the live Subscribe stream. Server-side, `AgentServiceImpl` ingests exactly this message — a command-id-less `__guard__` response is treated as an unsolicited drift event and routed to `ingest_guardian_response()` (`server/core/src/agent_service_impl.cpp:~1564`). So **legacy guards do push drift events over `__guard__`, and the server does ingest them, live, while the agent is connected.**

**Mechanism 2 — durable local journal + retry-capable outbox (Spark-gated, inert by default).** This is the *only* part that is dormant. The agent-side journal/outbox-drain machinery — `guardian_lifecycle_journal.cpp` + `guardian_journal_format.cpp` (local journal + wire format) and `guardian_outbox_drain_worker.cpp` (the drain-to-server worker), all confirmed compiled in `agents/core/meson.build` — is entirely gated on `prefer_spark_`, which defaults `false` in production: `GuardianEngine::persist_lifecycle_journal_locked()` (`guardian_engine.cpp:1665`) returns immediately `if (!prefer_spark_ || !spark_runtime_ || !lifecycle_journal_)`, and `GuardianEngine::journal_age_stats()` (`guardian_engine.cpp:1984`) likewise returns `std::nullopt` at `!prefer_spark_`. With Spark inert (per §31.1), this durable path's counters are provably zero.

**What this means in practice:** Mechanism 1 has no retry or local durability of its own — per its own source comments, `GuardianEngine::emit_guard_event()` drops the event if the sink isn't wired yet (pre-network arm, `guardian_engine.cpp:3141`: "drop; durable buffering is A3"), and `Agent::emit_guardian_event()` drops it if the Subscribe stream is down (`agent.cpp:4133-4135`: "Drops the event if the link is down between reconnects... durable buffering is A3"). So an event raised while the agent is disconnected from the server is **lost, not queued** — durable, retry-safe delivery is exactly what Mechanism 2 (the Spark-gated outbox) would provide, and it is inert. Graded Partial because the server-store half and the live-connected push half both genuinely work; the durable/retry half does not. *(Evidence: `guardian_engine.cpp:1665,1984,3127,3141`; `agent.cpp:2330,4131-4150`; `agent_service_impl.cpp:~1564`; line cites re-checked 2026-11-14, claims verified 2026-09-10 — corrects the 2026-09-08 fold's false "no push mechanism" claim.)*

### 31.8 Pre-Login Activation and Offline Capability :large_orange_diamond: `T2` *(verified 2026-09-10)*

**Regraded 2026-09-10 (Gate-of-record pass 3, cons-1): Done → Partial** — pre-login activation is solid, but the "offline capability" half over-promised. Pre-login activation works by construction today: the agent runs as a Windows service with `SERVICE_AUTO_START` + `FailureActions` configured at install time (`agents/core/src/main.cpp:536`, `:602-609`, and `agents/core/src/service_win.{hpp,cpp}` for the SCM `ServiceMain`/control-handler dispatcher that actually makes `sc start` succeed — #1822); systemd unit on Linux with `Type=notify` + `Restart=always`; launchd `KeepAlive=true` + `RunAtLoad=true` on macOS. `GuardianEngine::start_local()` runs before the Register RPC, so with the registry/SCM guards shipped (§31.2; the file guard is detect-only, `guard_file.cpp:58`) enforcement begins as soon as the service starts — before any user can log in. Offline capability comes from caching policy in `kv_store.db` under `__guardian__` namespace; enforcement continues with last-known-good rules when the server is unreachable. **Corrected: events raised while disconnected are DROPPED, not queued and flushed.** `GuardianEngine::emit_guard_event()` drops silently if the sink isn't wired (`guardian_engine.cpp:3141`), and `Agent::emit_guardian_event()` drops silently if the Subscribe stream is down (`agent.cpp:4131-4150`: "Drops the event if the link is down between reconnects... durable buffering is A3") — the durable outbox that *would* retain and retry them (§31.7 Mechanism 2) exists but is gated on `prefer_spark_`, which defaults `false` in production. Marked Partial because the service-install/pre-login side is genuinely operational (as of #1822 — before it, `sc start YuzuAgent` failed with error 1053 on every real Windows install) and enforcement itself does continue offline with last-known-good rules, but the audit trail of what happened *while* offline is lossy, not durable, until Spark is the default backend. *(Evidence: `guardian_engine.cpp:3141`; `agent.cpp:4131-4150`; line cites re-checked 2026-11-14, claims verified 2026-09-10 — corrects the prior "queued events flush when the server returns" claim, which no code supports.)*

### 31.9 Dashboard and Approval Workflow :large_orange_diamond: `T2` *(verified 2026-11-14)*

Partial. The Guardian dashboard shipped at `/guardian` (`server/core/src/guardian_page_ui.cpp`, `guardian_ui.cpp` — not the originally-planned `/guaranteed-state` path) with the Baseline draft/deployed lifecycle (deploys are `Push`-gated; editing a deployed Baseline's members reaches agents only via a re-deploy snapshot rewrite — `docs/guardian-baseline-model.md`). **Also shipped:** HTMX rule CRUD (`POST /fragments/guardian/guards`, per-guard enable/update/delete, baseline create/deploy/delete) carrying the YAML source with spec validation through `guardian_rule_spec`, and an "Unhealthy Guards (errored / watch-deaf now)" fleet card with an `unhealthy` filter (`guardian_routes.cpp`). **Missing:** conflict detection between rules (none in `guardian_rule_*`), and a true per-device kernel-wiring health signal — `guard_healthy` is still a reserved wire field and `get_status` reports every rule as errored (§31.2), so "deaf vs. compliant" rests on the Spark watch-deaf counters only. Approval-workflow reuse of the existing `ApprovalManager` is not found in `guardian_*.cpp`. *(Evidence: `server/core/src/guardian_routes.cpp`, `guardian_page_ui.cpp`, `guardian_ui.cpp`; re-verified 2026-11-14.)*

### 31.10 Rule Signing :x: `T2` *(verified 2026-11-14)*

Not implemented (PR 12). HMAC rule signing (HKDF per design §11.2) with per-tenant key stored in `CredWrite`/`CredRead` (Windows), Linux Secret Service / kernel keyring (Linux), Keychain (macOS); agent-side signature validation before activating a rule prevents unauthenticated rule injection. The wire field exists but is unused (`bytes signature = 7; // ... (contract G3, deferred)` in `proto/yuzu/guardian/v1/guaranteed_state.proto`), and `guardian_rule_spec.cpp:394`'s own comment says "full RFC-8785 canonicalisation lands with rule signing"; no HKDF or signed rule-activation code exists in `guardian_rule_spec.*`, `baseline_store.*` or `guardian_engine.*`. **Retitled 2026-11-14** from "Rule Signing and Quarantine Integration": device quarantine shipped outside Guardian — the `quarantine` plugin (`quarantine`/`unquarantine`/`whitelist`/`status`) and the server-side `QuarantineStore`, containment gate and reconciler (§9.6, §9.9, ADR-0047). The original design text for a Guardian-integrated quarantine (WFP block-all at weight 65535, `quarantine.add_exception | remove_exception | lift`, resilience reset on lift) is not what shipped.

---

## 32. DEX — Digital Employee Experience

*Endpoint-experience observation, performance analytics, and upgrade evidence. Shipped 2026-Q2 on the Guardian ingest path (§31.7); previously unmapped in this file. Docs: `docs/dex-signal-catalog.md`, `docs/user-manual/dex.md`, `docs/user-manual/preflight.md`. Presence + compilation of every file cited below was verified 2026-09-07; per-row behavioural detail (signal counts, retention windows) is inherited from the 2026-07 capability-industry review and was not independently re-derived this session. Re-counted 2026-11-14: the DEX surface is 26 MCP tools (23 in `kTools[]` plus 3 score-policy registry records in `mcp_tools_dex.cpp`) and about 25 `/api/v1/dex/*` method/path pairs (static route scan), including `list_dex_signals`, `get_dex_overview`, `list_dex_apps`, `get_dex_perf_cohort_diff`, `list_dex_app_perf_devices` and the score-policy trio.*

### 32.1 Signal Observation Catalogue :white_check_mark: `T2` *(verified 2026-09-07)*

Ruleless observation catalogue (`agents/core/src/dex_signal_catalog.cpp`, engine `dex_observer.cpp`; headers under `agents/core/include/yuzu/agent/`; both confirmed compiled in `agents/core/meson.build`): crashes, hangs, boot/login degradation, device health. Windows carries the full catalogue — **110 event signals** (waves of 20 + 50 + 33 + 7) over 22 event-log channels, shown as 114 server display entries in 13 groups (adding `storage.low` and three `perf.*` breaches) — while macOS is deliberately limited and Linux is server-focused (journald, `/dev/kmsg`, `/proc` perf polling, `statvfs`, `/sys` thermal) (`docs/dex-signal-catalog.md`). Windows poll-and-latch (`dex_win_poll.cpp`) + Linux/macOS collectors (`dex_linux_*.cpp`, `dex_macos_*.cpp`); sustained perf-breach hysteresis (`dex_perf_breach.{hpp,cpp}`).

### 32.2 Continuous Device Performance Telemetry :white_check_mark: `T2` *(verified 2026-09-07)*

Echo `perf` capture source feeding device-level performance rollups; per-app top-N process telemetry; fleet rollup gauges + `/dex` device sparklines. **macOS caveat added 2026-09-08 (external audit, Codex Astra residual sweep):** the per-process counter collector (`agents/plugins/echo/src/echo_proc_perf.cpp`) is Windows/Linux-only — its macOS branch (`:672`, the `!_WIN32 && !__linux__` arm) returns a snapshot with `valid=false` (`:681`) and the source comment states plainly "collect_perf records nothing on this platform yet". So per-app top-N process telemetry is a Windows/Linux capability today — macOS devices get device-level Echo `perf` rollups but no per-app process breakdown. **Per-process version resolution is Windows-only:** `resolve_proc_versions` is a no-op on Linux (`:667`) as well as macOS (`:686`), so Linux samples carry `version=""`. *(Evidence: `server/core/src/dex_perf_ui.cpp`, `dex_perf_rules.hpp`, `dex_perf_model.{hpp,cpp}`, `agents/plugins/echo/src/echo_proc_perf.cpp:667,672,681,686`; line cites re-checked 2026-11-14.)*

### 32.3 App Performance Over Time :white_check_mark: `T2` *(verified 2026-09-07)*

Per-device daily rollups (`server/core/src/app_perf_daily_store.{hpp,cpp}`) feeding fleet aggregates (`app_perf_fleet_store.{hpp,cpp}`) via a shared read model surfaced through REST `/api/v1/dex/perf/*`, MCP twins, and `/fragments/dex/perf/*` (`dex_app_perf_ui.{hpp,cpp}`, `dex_app_perf_model.{hpp,cpp}`, `dex_routes.{hpp,cpp}`). **Inherits both §32.2 gaps:** with no per-process telemetry source on macOS (`echo_proc_perf.cpp:672-681`), macOS devices have no app-perf history to roll up; and because Linux emits no per-process version (`:667`), Linux app-perf rolls up into one unversioned bucket per application. Per-version regression comparison (§32.5) is therefore meaningful only for Windows devices today.

### 32.4 Fleet Blast-Radius Alerting and Signal Routing :white_check_mark: `T2` *(verified 2026-09-07)*

Server-side N-distinct-device incident detector (`server/core/src/dex_blast_radius.{hpp,cpp}`) firing an alert webhook; per-signal operator routing (`dex_alert_router.{hpp,cpp}`).

### 32.5 Upgrade Evidence — Cohort-Paired Before/After Comparison :white_check_mark: `T2` *(verified 2026-09-07)*

`/auto` Verify (§36.3): pure compare engine (`server/core/src/app_perf_compare.{hpp,cpp}`), cohort reader (`app_perf_cohort_reader.hpp`, `app_perf_group_reader.{hpp,cpp}`), REST `/dex/perf/compare` surface confirmed present. Evidential — no verdict/threshold, per `verify_routes.cpp` (§36.3). Deliberately **no floor suppression here**: `kDexCohortFloor` only sets the `small_cohort` flag (`app_perf_compare.cpp:190`; "NOT suppressed" per `app_perf_compare.hpp:34`), which stays on the wire but is never true now that the floor is one device (maintainer ruling 2026-10-14), and the audited `dex.app_perf.compare` read is the control (audit verb documented in `docs/user-manual/rest-api.md`; `verify_routes.cpp:155`).

### 32.6 Behavioral-PII Privacy Engineering :white_check_mark: `T2` *(verified 2026-09-07)*

Cohort-floor suppression on fleet/group app-perf reads (the floor is one device since the maintainer ruling of 2026-10-14: a single-device point is published as a fleet-wide aggregate by application and version with no `agent_id`; only an empty point is suppressed) and audit-on-open per-device lenses (§21.6). *(Referenced from `docs/yuzu-guardian-design-v1.1.md` §24 invariants cited in `CLAUDE.md`; not independently re-derived this session.)*

### 32.7 Experience Scoring and Sentiment :large_orange_diamond: `T3` *(verified 2026-10-14)*

Partly implemented — deliberately narrow. A transparent, decomposed secondary composite (0-100 stability score with its named deductions) is published beside the measured rates and intervals on `GET /api/v1/dex/apps` / `list_dex_apps` and shown, with its decomposition, on the DEX Apps tab; nothing in the product acts on it. The tier edges, tier names, deduction weights, scoring model parameters (event cap, regression ratios, interval confidence level) and per-application overrides are customer-defined policy, persisted as one document under a single runtime-config key, read by every instance (typically within 5 seconds; each instance refreshes at most every 5 seconds while it serves requests, and the policy in use is up to 60 seconds old when the store is unreadable) and named on the Apps payload (`policy`, and `profile` per application; weights and per-application override values are not echoed); the cohort floor and the statistical methods are fixed. The write side ships as `PUT` and `DELETE /api/v1/dex/score-policy` (#6086); the dashboard edits the same policy on the DEX Scoring tab, and the MCP twins ship as `get_dex_score_policy`, `set_dex_score_policy` and `reset_dex_score_policy` (#6087). Opaque composite experience scores and sentiment scoring (which would additionally need the §14.4 survey primitive as an input) remain out.

---

## 33. Network Quality

*Measurement-first device/local-link health lens. Shipped 2026-06; previously unmapped in this file. Doc: `docs/user-manual/network.md`.*

### 33.1 Device Network Heartbeat Facts :white_check_mark: `T2` *(verified 2026-09-07)*

Interval retransmit rate, RTT, and throughput as thin `yuzu.net_*` heartbeat tags, sampled agent-side — **not platform-neutral:** Linux reports throughput, retransmit and RTT (`tcpi_rtt`); Windows reports throughput and whole-stack retransmit but no RTT (`rtt_valid` stays false without ESTATS); macOS reports throughput only (`NET_RT_IFLIST2`; retransmit and RTT not collected). *(Evidence: `agents/core/src/net_quality_sampler.cpp`; `docs/os-capability-matrix.md`; `agents/core/src/net_quality_sampler.{hpp,cpp}`, confirmed compiled in `agents/core/meson.build`. Windows retransmit is whole-stack + unvalidated per `CLAUDE.md`'s routed-concerns table — withheld from the fleet gauge, Linux-only today.)*

### 33.2 Fleet Network Gauges :white_check_mark: `T2` *(verified 2026-09-07)*

`yuzu_fleet_net_*` gauges with a per-OS label (never blended cross-OS, per the routed-concerns invariant). *(Evidence: `server/core/src/network_perf_model.{hpp,cpp}`, `network_perf_rules.hpp`.)*

### 33.3 `/network` Dashboard :white_check_mark: `T2` *(verified 2026-09-07)*

Fleet and per-device network-health page, plus a Discovered-hosts tab (`GET /api/v1/network/discovered-devices`, MCP `list_discovered_devices`, audit verb `network.discovered.view`) and MCP `get_network_fleet` / `list_network_devices`. *(Evidence: `server/core/src/network_routes.{hpp,cpp}`, `network_ui.cpp`; `docs/user-manual/network.md`.)*

### 33.4 Degraded Classification and Per-Destination Localization :x: `T3` *(verified 2026-09-07)*

Deferred — `yuzu.net_degraded` is retired per the routed-concerns table (gauge absent-not-zero); a hard degraded threshold needs a real-fleet baseline first.

---

## 34. Device Pages and Live Snapshot

*The shared per-device surface (`/devices` + `/device?id=`). Shipped 2026-06; previously unmapped in this file. Doc: `docs/user-manual/device-management.md`.*

### 34.1 Fleet List and Device Entity Page :white_check_mark: `T2` *(verified 2026-09-07)*

`/devices` + `/device?id=` with Device info / DEX / Guardian lens tabs. *(Evidence: `server/core/src/device_routes.{hpp,cpp}`, `device_ui.cpp`.)*

### 34.2 Live Snapshot ("Get live info") :white_check_mark: `T2` *(verified 2026-09-07)*

Dispatch-and-poll card grid with 20+ live kinds — process tree, services, users, netconfig, ARP/DNS on Windows, listening/connections, capture sources, hardware disks/memory/processors/drivers, battery, thermal, SMART, volumes, adapters, WiFi, disk free and uptime — each with its own `device.live.<kind>` audit verb, gated on `Execution:Execute` (`server/core/src/device_routes.cpp`).

### 34.3 Agentic REST Parity for Device Surfaces :white_check_mark: `T2` *(verified 2026-09-07)*

REST parity for the live-snapshot surface — though the REST live read (`POST /api/v1/dex/devices/{id}/live`) supports only `kind=uptime|processes`, 2 of the dashboard's 20+ kinds — funneling behavioural-PII reads through the `emit_behavioral_audit` chokepoint (§21.6) — except the REST `device.live.*` route itself, still an inline bool-capture (tracked under #1647, open; #1703 was closed unverified in the 2026-07-14 backlog reset — re-confirmed live 2026-11-14 at `rest_api_v1.cpp:~19381-19490`, `POST /api/v1/dex/devices/{id}/live`) — fail-closed 503 + `Sec-Audit-Failed` when the audit row cannot persist. *(Evidence: `server/core/src/rest_audit.hpp`.)*

---

## 35. Agent Daily-Sync Inventory (ADR-0016)

*Per-source endpoint state pushed daily over `ReportInventory`, hash-skip on no change. Shipped 2026-06; previously unmapped in this file. Docs: `docs/adr/0016-agent-daily-sync-framework.md`, `docs/user-manual/inventory.md`.*

### 35.1 Sync Framework :white_check_mark: `T2` *(verified 2026-09-07)*

`SyncScheduler` (`agents/core/src/sync_scheduler.{hpp,cpp}`) + `LocalDispatcher` (`local_dispatcher.cpp`) — stable per-agent phase spread, hash-skip when unchanged, server `need_full` resend. Shared ingestion seam wired identically on the direct and gateway paths. All confirmed compiled in `agents/core/meson.build`.

### 35.2 Installed-Software Inventory :white_check_mark: `T2` *(verified 2026-09-07)*

Source #1 (`agents/core/src/sync_source_installed_software.{hpp,cpp}`) → born-on-Postgres `SoftwareInventoryStore` (`server/core/src/software_inventory_store.{hpp,cpp}`), normalized rows, server-receipt freshness per the #1685 clock-skew rule. `Inventory` RBAC securable.

### 35.3 Device CI (Hardware/OS Identity) :white_check_mark: `T2` *(verified 2026-11-14)*

**Regraded 2026-11-14: Partial → Done (ingest + read surface shipped).** Source #3 (`agents/core/src/sync_source_device_ci.{hpp,cpp}`) → born-on-Postgres `DeviceInventoryStore` (`server/core/src/device_inventory_store.{hpp,cpp}`) — serial/UUID/MAC, GDPR-personal-data / works-council-relevant per CLAUDE.md's routed-concerns table — with versioned record sections. Read surface: the `/hardware` and `/hardware/ci` dashboard pages, `GET /api/v1/hardware` and `GET /api/v1/hardware/{id}`, the repair routes `POST /api/v1/hardware/{id}/sync` and `POST /api/v1/hardware/sync`, and MCP `list_hardware_ci` / `get_hardware_ci` (registry records in `mcp_tools_hardware.cpp`) plus `sync_hardware_software`; the store is in `/readyz`. Caveat: "CMDB-style" means serial/UUID correlation keys only — there is no external CMDB connector (§25.5). *(Evidence: `server/core/src/hardware_routes.cpp`; `docs/user-manual/inventory.md`.)*

### 35.4 Software Catalogue and `/inventory` Dashboard :white_check_mark: `T2` *(verified 2026-09-07)*

Background catalogue rollup (`server/core/src/software_catalog_rollup.{hpp,cpp}`, cross-referenced from §26.3/§27.1) feeding the `/inventory` dashboard page (`inventory_ui.cpp`).

### 35.5 Multi-Source Consolidation :x: `T2` *(verified 2026-09-07)*

Not implemented — connector-fed sources and identity-merge consolidation remain the §25/§26 gap; confirmed no `Repository`/consolidation model exists (§26.1/26.2 stay Not Started).

Other typed sources: the server's one `kTypedInventorySources` list (`server/core/src/typed_inventory_sources.hpp`) holds six — `installed_software`, `app_perf`, `device_ci`, `software_licensing`, `app_usage` and `certificate_inventory`. The agent ships five `sync_source_*` writers (all but `certificate_inventory`, whose server-side receiver and `CertificateInventoryStore` exist with no agent collector yet, §41.2). `sync_source_app_perf.{hpp,cpp}` feeds §32 DEX; `sync_source_software_licensing.{hpp,cpp}` feeds §27 SLE (§27.6); `app_usage` is §35.6. `runtimes` (§7.8) and `middleware` (§7.10) are not separate sources: they feed the `installed_software` v3 sections through adapters.

### 35.6 App-Usage Inventory Source :white_check_mark: `T2` *(new row, v4.1)*

ADR-0016 source `app_usage`: `agents/core/src/sync_source_app_usage.{hpp,cpp}` reads the `app_usage` plugin's machine-scope fold of Echo's usage data and pushes it daily to the server `AppUsageStore` (`server/core/src/app_usage_store.{hpp,cpp}`). It is a typed source, excluded from generic-store writes and from every generic read. The only read is the Forensics-gated `GET /api/v1/forensics/agents/{id}/app-usage` / MCP `get_agent_app_usage`, with a per-open audit that fails closed (§27.2). *(Evidence: `docs/user-manual/inventory.md`; `docs/adr/0016-agent-daily-sync-framework.md` 2026-09-17 update.)*

---

## 36. `/auto` — Operator Automation (Assess → Act → Verify)

*Pre-flight readiness, gated deployment, and paired-cohort verification. Shipped 2026-06; previously unmapped in this file. Doc: `docs/user-manual/preflight.md`. **Dashboard-only for every mutation:** creating and running a pre-flight, deploying and verifying are reachable only through `/fragments/auto/*`. The REST and MCP twins are read-only — `GET /api/v1/preflight/runs` / MCP `list_preflight_runs`, and `GET /api/v1/deployments[/{id}|/preview]` / MCP `list_deployments`, `get_deployment`, `get_deployment_preview`; the verify comparison's REST read is `/api/v1/dex/perf/compare` (§32.5). That is a gap against ADR-1005's "no UI-only capabilities" rule. (The mutating MCP `create_software_deployment` family belongs to the dormant `SoftwareDeploymentStore`, §7.6, not to `/auto`.)*

### 36.1 Pre-Flight Readiness (ASSESS) :white_check_mark: `T2` *(verified 2026-09-07)*

Born-on-Postgres `PreflightRunStore` (`server/core/src/preflight_run_store.{hpp,cpp}`) + background `PreflightRunner` (`preflight_runner.{hpp,cpp}`) re-dispatching read-only checks to a frozen cohort; `Infrastructure:Read` + `Execution:Execute` gated. *(Evidence: `preflight_eval.cpp`, `preflight_routes.cpp`, `preflight_ui.cpp`.)*

### 36.2 Deploy (ACT) :white_check_mark: `T2` *(verified 2026-09-07)*

Stage+execute on the go-cohort via `content_dist`; born-on-Postgres `DeploymentRunStore` (`server/core/src/deployment_run_store.{hpp,cpp}`) with guarded one-way transitions and an execute-once CAS (per the ladder row in `docs/postgres-migration-ladder.md`). *(Evidence: `deployment_engine.cpp`, `deployment_routes.cpp`, `deployment_ui.cpp`.)*

### 36.3 Verify (EVIDENCE) :white_check_mark: `T2` *(verified 2026-09-07)*

Cohort-paired app-perf before/after comparison (§32.5) closing the ASSESS→ACT→VERIFY loop. Evidential only — no verdict, threshold or gate, and deliberately no cohort floor (the audited compare read replaces suppression; see §32.5). *(Evidence: `server/core/src/verify_routes.{hpp,cpp}`.)*

---

## 37. Internal PKI / Certificate Authority

*Internal CA subsystem. Shipped 2026-05/06; previously represented only as a §1.1 gap note. Doc: `docs/pki-architecture.md`.*

### 37.1 Internal CA and Default Certificates :white_check_mark: `T2` *(verified 2026-09-07)*

`CaStore` (`server/core/src/ca_store.{hpp,cpp}`, PostgreSQL schema `ca_store` — ADR-0053, formerly `ca.db`; key material behind the `KeyProvider` seam, never in the DB); per-install default certs generated on first boot.

### 37.2 Per-Agent mTLS Identity :white_check_mark: `T2` *(verified 2026-09-07)*

Agent-side CSR at enrollment (`agents/core/src/agent_csr.cpp`, `agents/core/include/yuzu/agent/agent_csr.hpp`) → `ServerImpl::sign_agent_csr` (`server/core/src/server.cpp:12530`, wrapping `x509_ca.hpp`'s CSR signer; server-chosen subject/SAN/EKU, the CSR's own requests ignored) → app-layer enforcement. Per CLAUDE.md's routed-concerns table, `sign_agent_csr` is the single shared signer for direct `Register` AND gateway `ProxyRegister`; revoke is serial-scoped.

### 37.3 CA Operations Surface :white_check_mark: `T2` *(verified 2026-09-07)*

REST `/api/v1/ca/*` (public root/CRL by design — confirmed NOT in the TLS chain per the CLAUDE.md-cited PR #2479 finding). *(Evidence: `server/core/src/ca_routes.{hpp,cpp}`.)*

### 37.4 Subordinate-CA Mode :white_check_mark: `T2` *(verified 2026-09-07)*

Built-in root subordinated to an enterprise root: CSR export, chain import + validation. *(Inherits from the 2026-07 review; `CaMode::Subordinate` not independently re-verified this session.)*

### 37.5 Secure-by-Default Distribution :white_check_mark: `T2` *(verified 2026-09-07)*

TLS-by-default images shipped (#1314, merged 2026-06-21). Management-plane SPKI peer-pin + serverAuth EKU + fail-closed boot guard shipped 2026-09-02 (#1422 closed via PR #3905). Management-plane certificate *revocation* has since shipped as an **opt-in** CRL check on the gateway (§37.7): the shipped production `sys.config` sets no `mgmt_crl_source` (only a commented example), so it is off unless an operator configures it. The docker reference configuration (`deploy/docker/reference-gateway-sys.config`, used by the reference-gateway and HA compose files) does set it, and there an unreachable or stale CRL refuses the stream.

### 37.6 Single CRL Publisher :white_check_mark: `T2` *(new row, v4.1)*

`CrlPublisher` (`server/core/src/crl_publisher.{hpp,cpp}`, HA WS-6 slice 6.1) wrapping `CaStore::publish_next_crl` — the single CRL publisher, which reads the revoked set under its table lock; the revoked set is append-only (a trigger keeps revoked rows). The public `GET /api/v1/ca/crl` only serves the latest published CRL and never signs; publishing runs at boot, on the leader-gated freshness tick, and on the revoke and import paths. `is_revoked()`, the mTLS-accept gate, fails closed on any degradation. *(Evidence: `docs/pki-architecture.md` "Catastrophic invariants"; `server.cpp` `crl_publisher_`.)*

### 37.7 Gateway Management-Plane Authorization :large_orange_diamond: `T2` *(new row, v4.1)*

`yuzu_gw_authz:check_mgmt_peer/1` is the sole authorization gate on the gateway's `:50063` management listener, i.e. on fleet command fan-out (ADR 2004, #6016): decode, serverAuth EKU, then `mgmt_peer_auth_mode` — an SPKI pin and/or the byte-exact server URI SAN identity `yuzu://<install>/server` — then a serial deny-list, then an optional CRL check. Everything fails closed; an unset mode is always `pin`. Graded Partial because the CRL check is opt-in (the shipped production config uses `identity` with no `mgmt_crl_source`; the docker reference config sets one) and ADR 2004 is still `status: proposed` while shipped code relies on it. *(Evidence: `gateway/apps/yuzu_gw/src/yuzu_gw_authz.erl`, `yuzu_gw_mgmt_{identity,pins,crl,crl_source}.erl`; `gateway/config/sys.config.prod`; `docs/adr/2004-gateway-mgmt-server-identity.md`.)*

### 37.8 Gateway-Upstream Peer Authorization :white_check_mark: `T2` *(new row, v4.1)*

`GatewayPeerGuardedService` is the sole registration of the server's gateway-upstream service and guards every listener it is reachable on: each upstream RPC checks the transport-authenticated leaf's full-DER SPKI SHA-256 against a pin set fixed at boot, plus serverAuth EKU and the validity window, over a closed fail-closed reason set. Unauthorizable configurations are refused before a port binds; `--insecure-gateway-peer` is the only, boot-time, acknowledged escape. There is no reload or revocation read on this path — withdrawal is remove-the-pin-and-restart. *(Evidence: `server/core/src/gateway_peer_{guard,resolution,pinset,cert}.cpp`; `docs/user-manual/server-admin.md` "Gateway upstream peer authorization".)*

### 37.9 Gateway Origin Trust (Client Address Behind a Proxy) :white_check_mark: `T3` *(new row, v4.1)*

`yuzu_grpc_origin.erl` decides what address the gateway reports for an agent (`gateway_observed_peer`, audit `source_ip`): trust is decided by which peer connected (against the listener's boot-time `origin.sources`), an unusable claim from a trusted proxy yields no observation (never a fallback to the proxy's own address), the gateway overwrites the agent-supplied field unconditionally, and the management listener is never proxied. Attribution, not authentication. *(Evidence: `gateway/apps/yuzu_gw/src/yuzu_grpc_origin.erl`; `docs/user-manual/gateway.md` "Client addresses behind a proxy".)*

---

## 38. Server Storage Substrate — PostgreSQL

*ADR-0006/0007/0008/0010/0012 program: the server's storage substrate is PostgreSQL; the agent stays SQLite. Previously unmapped in this file (supersedes the §22.9 sharding strategy).*

### 38.1 Substrate and Pool :white_check_mark: `T2` *(verified 2026-09-07)*

`server/core/src/pg/`: RAII connection/result/transaction wrappers, a bounded `PgPool` with lease-RAII, `PgMigrationRunner`, `yuzu_pg_*` metrics, `/readyz` conjunction.

### 38.2 Fail-Closed Flip :white_check_mark: `T2` *(verified 2026-09-07)*

The server refuses to start without a reachable Postgres (no SQLite fallback, ADR-0007) — per `CLAUDE.md`'s routed-concerns table, this is a standing invariant enforced at boot.

### 38.3 Secrets at Rest :white_check_mark: `T2` *(verified 2026-09-07)*

Verify-only hashes or `SecretCodec`-envelope-encrypted blobs (ADR-0010) — never plaintext columns. 14 `*_store.cpp` files carry secret-shaped columns; only `webhook_store.cpp` among them was spot-checked this session (the other two checks below are a hash column and a route file) — the rest stand on their ADR-0010 migration-time `security-guardian` reviews, not on a re-audit here. Verified this session: `license_store.hpp` documents `license_key_hash` as a SHA-256 verify-only hash (§22.3); `offload_routes.cpp`'s `auth_credential` is `SecretCodec`-encrypted per its own row text (§20.7); `webhook_store.cpp`'s constructor takes a `pg::SecretCodec&` (its HMAC signing secret is envelope-encrypted, though the pre-existing §21.4 row text doesn't say so explicitly).

### 38.4 Store Migration Ladder :white_check_mark: `T2` *(verified 2026-09-07)*

**Census re-run 2026-11-14** (the 2026-09-07 run found 43 files, 42 on PG, correcting the 2026-07 review's "~27 legacy SQLite stores remain"): `ls server/core/src/*_store.cpp` = 51 files; `grep -lE "PGconn|pg::" server/core/src/*_store.cpp` = 50 of them. The one non-match, `fleet_topology_store.cpp`, holds no direct DB handle of its own (composed from `AuditStore` + `NvdDatabase` reads) — it is not a SQLite store either. **Zero SQLite-only server stores remain.** The sole SQLite-*backed* store is `server/core/src/nvd_db.cpp` (not `*_store.cpp`-named, confirmed via the `sqlite3_open_v2` call at `nvd_db.cpp:221`; the read-only legacy-file probes in `runtime_config_store.cpp:940` and `server.cpp:525` also open SQLite but persist nothing), grandfathered under ADR-1005 as server-side vulnerability interpretation; the vulnerability-management use-case engine that would replace it is design-only (§9.4). Postgres HA plumbing also exists — multi-host DSNs (`pg/multi_host_dsn.hpp`), a retention guard and session advisory locks — but HA itself is not live (§22.10). Graded Done rather than Partial: the migration ladder itself is complete for every intended store; the one remaining SQLite user is a deliberate, documented, out-of-scope exception, not an unfinished migration.

---

## 39. Headless Platform — Engine Principals and On-Behalf-Of Authorization (ADR-1005) *(new domain, v4.0)*

*A distinct principal class for autonomous use-case engine (UCE) modules, and the interim rule that no ingress surface accepts a client-asserted on-behalf-of assertion until server-verifiable delegation ships. Not present in any prior version of this map. Doc: `docs/adr/1005-headless-platform-use-case-engines.md`. **Engine-path code is closed to merge:** the ADR-0032 sequencing interlock (`tests/split_interlock_ledger.json`, gate set a, b, c, d, h) has only cell a (engine principals) green, so nothing that admits a use-case run, mints a grant, writes the release log or serves a use-case result may merge into any binary (§39.5).*

### 39.1 Engine Principal Store :white_check_mark: `T2` *(verified 2026-09-07)*

Born-on-Postgres `EnginePrincipalStore` (`server/core/src/engine_principal_store.{hpp,cpp}`, schema `engine_principal_store`) — a dedicated durable identity (owner, justification, classification, lifecycle) for an autonomous UCE module, separate from `ApiTokenStore` (no secret material lives here; credentials stay hash-only in `ApiTokenStore`). Fail-closed at construction and at the `get_for_auth` runtime chokepoint, which returns a three-state result (Active / not the binary alive-or-not a naive store would return). The administration surface is §39.4. *(Evidence: `server/core/src/engine_principal_store.hpp` header; design: `docs/auth-engine-principals-design.md` §3.1.)*

### 39.2 Principal Class Metric Label :white_check_mark: `T2` *(verified 2026-09-07)*

Closed-set `principal_class` label (`human` / `agent` / `none` / `engine`) for HTTP request metrics, resolved from the session's authenticated `principal_kind`/`auth_source` (not header presentation) — an engine-token request that fails resolution stays `agent`, never `engine`, so the label can't be spoofed by presenting a bearer token shaped like one. *(Evidence: `server/core/src/principal_class.hpp`; design: `docs/observability-conventions.md`.)*

### 39.3 On-Behalf-Of Assertion Guard :white_check_mark: `T2` *(verified 2026-09-07)*

The server rejects — not silently ignores — any on-behalf-of assertion on every ingress surface (REST, MCP, agent gRPC) until Phase 5 server-verifiable delegation ships; a rejected assertion is a hard error, so a header-stamping proxy fails loudly rather than silently impersonating. Per CLAUDE.md's routed-concerns table, the four health-probe paths are the sole exception (so a header-stamping proxy doesn't crash-loop the server). *(Evidence: `server/core/src/on_behalf_guard.hpp`.)*

### 39.4 Engine Principal Administration Surface :white_check_mark: `T2` *(new row, v4.1)*

REST `/api/v1/engine-principals` (create, list, get, roles, credentials mint/rotate/confirm, transfer-owner, revoke, and `/audit/no-admin`) with MCP twins `create_engine_principal`, `list_engine_principals`, `get_engine_principal`, `revoke_engine_principal`, `transfer_engine_principal_owner`, `rotate_engine_credential` and `confirm_engine_rotation`, on the dedicated `EnginePrincipal` securable (kept out of `Security:Read`). Engine principals are default-deny and RBAC-only and cannot hold a system role; their tokens carry a 90-day ceiling; the `principal_class` label `engine` is live (§39.2). *(Evidence: `server/core/src/engine_principal_store.hpp`, `rest_api_v1.cpp`, `mcp_server.cpp`; `docs/adr/0031-engine-principal-store.md`.)*

### 39.5 Use-Case Engine Admission Interlock :x: `T2` *(new row, v4.1)*

Not met. The ADR-0032 merge gate requires cells a, b, c, d and h of `tests/split_interlock_ledger.json` to be green before any engine-path code merges; at HEAD only a (engine principals) is green, and b, c, d and h are red (no `use_case_run_id`, no release log, no capability-declaration registry, and the remaining substrate). Enforced in CI by `tests/test_split_interlock_tripwire.py` and its self-test. The interlock is CLOSED, so no use-case engine can run against the core today. *(Evidence: `tests/split_interlock_ledger.json`; `docs/security-reviews/split-ws0-interlock-certification-2026-09-08.md`.)*

---

## 40. Reflex — Agent-Local Automated Response

*Design-only as of this entry (R0 of the Spark/Reflex/DEX macOS programme, 2026-09-17). Sparks
(ADR-0021, §31) already give the agent a converged, use-case-agnostic detection layer; Reflex is the
third sovereign Spark consumer alongside Guardian (§31, real-time compliance enforcement) and DEX
(§32, curated telemetry) — never a specialization of either. A Reflex is a YAML-authored, agent-local
binding from a Spark to a small chain (≤ 4) of plugin-action Reactions, executed on the device the
instant the Spark fires, with or without server connectivity, deployed only as part of a Reflex Set
(exactly the Baseline grammar — individual Reflexes never deploy alone). Design contract:
`docs/reflex-design.md`; ADR: `docs/adr/0021-spark-reflex-architecture.md` (Decisions 2, 4, 5, 6, 7,
8, 9, 10 and the 2026-09-17 amendment). Design plus the wire contract only: `proto/yuzu/reflex/v1/reflex.proto` is merged and built into `yuzu_proto` (`proto/meson.build`), and the Spark episode edge is Reflex-ready, but no `ReflexEngine`, store, routes or `__reflex__` handler exists on `dev` — every row below stays Not Started. No GitHub tracking issue filed for this domain
as a whole; see `docs/roadmap.md` Phase 20.*

### 40.1 Reflex Set Authoring and Safety/Consent Gates :x: `T2`

Not implemented. YAML-authoritative Reflex Set CRUD; the `dangerous_reactions_in_spec()` safety
chokepoint (extends the existing `dangerous_*_in_spec` doctrine, §24 of
`docs/yuzu-guardian-design-v1.1.md`, fed by `CommandCapabilityRegistry::classify`); the
device-classification consent gate (free-form `device_class` asset tag, `server` | `workstation`,
unclassified = workstation = fail-closed).

### 40.2 Digest-Bound Two-Person Approval and Deploy :x: `T2`

Not implemented. Deploy gated on a dedicated `Reflex:Execute` RBAC permission (never the
Guardian-only `Push` cross-seed array); approval by a principal distinct from both the last content
editor and the deployer, bound to a canonical digest over compiled content + assignment scope,
recomputed and compared at every compile — fail-closed on mismatch.

### 40.3 Agent-Local Spark→Reaction Execution :x: `T2`

Not implemented. `ReflexEngine`, a queued (never inline) SparkEngine consumer that runs a fired
Reflex's Reaction chain locally via the agent's `LocalDispatcher` — authorized once, at deploy time,
by 40.1/40.2, never re-authorized per fire. Wire: reserved plugin name `__reflex__` (`push_sets` /
`get_status` / `status`), mirroring `__guard__`'s two-halves reserved-name interception.

### 40.4 Reflex Outcomes, Observability, and Dashboard :x: `T3`

Not implemented. Outcomes reuse the existing `__guard__`/`event` channel
(`GuaranteedStateEvent.family == "reflex"`), land in a Reflex-only `reflex_outcomes` table (a
deliberate, ADR-amended partial exception to Decision 6's "one event store" — the single ingest
router chokepoint is unaffected). The push itself is a SEPARATE `ReflexSetPush`/generation counter,
an accepted-interim, ADR-amended exception to Decision 8's single compiled per-device document —
not yet folded into it. Reflex outcomes are never surfaced on the executions-history ladder
(agent-local automation, not operator dispatch). Fleet Prometheus families, heartbeat tags, audit
verbs, SOC 2 evidence rows, REST + MCP CRUD, and an HTMX `/reflex` dashboard round-tripping the YAML
— never the model.

---

## 41. Cryptographic Asset Inventory

*Fleet inventory of the cryptographic material and libraries on managed endpoints. Slice 1 (crypto-library presence) merged 2026-10-18; since then the Yuzu-CA certificate counts and crypto dashboard widgets (§41.7), the operator-registered CRL source registry (§41.8, register-only) and the server-side `certificate_inventory` receiver (§41.2) have shipped; the rest is planned. Facts in core; verdicts are use-case-engine territory (`docs/adr/0070-cryptographic-asset-inventory-placement.md`, under ADR-1005 Decision 2): no vulnerable, PQC-readiness, library end-of-life, expiry-risk or framework-mapping verdicts in core, no deprecated or broken algorithms beyond D13's four rules, and no revocation status from OCSP or from URLs a certificate supplies. Third-party revocation is core only through operator-registered CRLs (ADR-0070 D5, as amended). There are two built-in exceptions: those operator-registered CRLs (D5/R1; registration shipped, fetching not yet), and ADR-0070 D13's closed set (the Yuzu-CA windows shipped in §41.7; the fleet-certificate, weak-key and SSH counts are planned): four named weak-key rules; fixed active, expiry, expired, issued and revoked windows (Yuzu-CA revocations by reason, fleet certificates per operator-registered CRLs), with a 52-week per-week issued and revoked series; a count of registered CRLs past their `nextUpdate` (`crl_past_next_update`); and fleet-wide counts of SSH keys observed in use once slice 3's collection is permitted. Each count names its rule or window and the server time it used. Doc: `docs/user-manual/crypto.md`.*

### 41.1 Crypto-Library Presence :white_check_mark: `T2` *(verified 2026-10-17)*

`/crypto` dashboard, `GET /api/v1/crypto/libraries[/devices]` and MCP `get_crypto_libraries` / `list_crypto_library_devices`: which cryptographic libraries (twelve curated families) are installed on which devices, at which versions, derived by deterministic package-name matching over the existing ADR-0016 installed-software inventory (`Inventory:Read`, management-group and service-scope confined, audited as `crypto.libraries.view` / `crypto.libraries.devices`). Concurrent `/crypto` store reads are bounded per process (two in flight; the rest are refused at once as a retryable 503, counted as `yuzu_inventory_read_degrade_total{reason="admission_full"}`). The package NAMES matched come from the hourly catalogue rollup while it is fresh (at most two hours old; `names_source` is `catalogue` and `names_as_of` its refresh time) and are otherwise read live from the inventory (`names_source` is `live`, `names_as_of` null): a name first reported after a catalogue refresh appears after the next one, while counts and versions for listed names are live either way, and an unbuilt catalogue is not an error. Two distinct 503 causes carry `retry_after_ms`: store degraded and capacity in use. Measured on the reference host (about +/-30 percent, host load 3 to 10): on the catalogue path the summary takes about 0.5 to 3.3 s and a drill about 7 ms to 1.9 s from 30,000 to 1.03 million distinct names; on the live path at 15M rows with 30,000 names the summary takes about 1.7 to 2.2 s and a drill about 0.7 to 1.4 s (the skip-scan alone is 0.9 to 1.2 s, about 28 to 36 microseconds per distinct name), which passes its 5 s bound at about 140,000 to 180,000 distinct names, host and load dependent. The per-process cap is two concurrent reads (two concurrent live summaries: p50 about 2.15 s, p95 about 2.42 s, no timeouts); with about 8 replicas against one Postgres (16 concurrent live reads) about half time out, which is a capacity note, not a defect. The refresh's uncapped GROUPING SETS statement takes 219 to 241 s at 3M and 15M rows against its 60 s statement cap (crossed at about 2.7M rows), so on fleets above about 2.7M rows `/crypto` always reads names live until the catalogue rollup is made incremental; a stale catalogue on a fleet with more than about 140,000 to 180,000 distinct names is a bounded 503, never a hang. Package-level evidence only: statically linked, vendored and OS-bundled copies are not visible (Issue 18.7, the agent-side component inventory, ADR-0028, is the planned fix for that invisibility). A separate, earlier measurement of an earlier revision of the query, at 3.0M installed-software rows (2,000 agents x 1,500 packages), is not part of the 2026-10-17 verification: the fleet summary ran in about 0.55 s (about 0.65 s for a 5,000-device confined scope) and a family drill in 0.35 to 0.6 s. *(Evidence: `server/core/src/crypto_library_model.{hpp,cpp}`, `crypto_routes.{hpp,cpp}`, `crypto_ui.cpp`, `crypto_api.cpp`, `SoftwareInventoryStore::software_name_pattern_rollup`; tests `tests/unit/server/test_crypto_*.cpp`.)*

### 41.2 Certificate Inventory (Fleet, Full X.509 Fields) :x: `T2` *(verified 2026-10-17)*

Planned for operators. The endpoint `certificates` plugin (§9.8) lists certificates from a fixed set of stores per device on demand (ADR-0070 D6 lists what it does not read). The server-side half has shipped — the `certificate_inventory` daily-sync receiver and `CertificateInventoryStore` (schema `certificate_inventory_store`, wired on the direct and gateway ingest paths and in `/readyz`) — but no agent collector exists and there is no REST, MCP or dashboard read, so the store stays empty and there is still no fleet-wide, queryable certificate inventory with the full X.509 field set (subject, issuer, SAN, key algorithm and size, validity, usage). *(Evidence: `server/core/src/certificate_inventory_{store,ingestion}.*`; `docs/user-manual/inventory.md` "Certificate inventory".)*

### 41.3 SSH Keys at Rest :x: `T2` *(verified 2026-10-17)*

Planned. Inventory of SSH host keys and user key material on disk (type, size, fingerprint, location), never the key content. Per-device, on-demand `authorized_keys` fingerprints exist through the Forensics-tier `remote_access_audit` plugin (§42.10), which is not a fleet inventory.

### 41.4 SSH Login Evidence :x: `T3` *(verified 2026-10-17)*

Planned. Evidence of SSH logins (who, from where, with which key type) as behavioural-PII-tier data.

### 41.5 Protocol and Configuration Settings :x: `T3` *(verified 2026-10-17)*

Planned. Observed TLS/SSH daemon and system cryptographic-policy settings (enabled protocol versions, cipher and key-exchange lists) collected as facts.

### 41.6 CBOM Export :large_orange_diamond: `T3` *(verified 2026-10-19)*

Partial (library components only). `GET /api/v1/crypto/cbom` and MCP `export_crypto_cbom` export the cryptographic-library inventory (41.1) as a CycloneDX 1.7 JSON bill of materials; algorithms, certificates, keys and protocols (41.2 to 41.5) are not exported yet, and components carry no `purl`, so scanners cannot match them. It carries facts only (ADR-0070 D7).

### 41.7 Yuzu-CA Certificate Counts and Crypto Dashboard Widgets :white_check_mark: `T2` *(new row, v4.1)*

The `/crypto` dashboard widgets over Yuzu's own CA: active, expiring (3/7/14/21/30/60 days), expired (7/30/60/90 days), revoked and issued-in-7-days counts plus a 52-week issued/revoked series, each naming its rule set and the server time used; `GET /api/v1/crypto/ca/stats` and `GET /api/v1/crypto/widgets` with MCP `get_crypto_ca_stats` / `list_crypto_widgets`, and a per-operator layout store (ADR-0071) at `GET/PUT /api/v1/crypto/dashboard/layout` / MCP `get_crypto_dashboard_layout` / `set_crypto_dashboard_layout`. Counts cover only Yuzu's own CA, not fleet certificates; the per-certificate drill (`GET /api/v1/ca/issued`) needs `Security:Read`. *(Evidence: `server/core/src/crypto_widget_catalogue.cpp`, `crypto_dashboard_layout_store.cpp`, `mcp_tools_crypto.cpp`; `docs/user-manual/crypto.md`.)*

### 41.8 Registered CRL Sources :large_orange_diamond: `T3` *(new row, v4.1)*

ADR-0070 D5/R1: operators register third-party CRL sources through `/api/v1/crypto/revocation-sources` (CRUD plus `reset-high-water`) and MCP `register_revocation_source`, `update_revocation_source`, `remove_revocation_source`, `get_revocation_source`, `list_revocation_sources` and `reset_revocation_source_high_water`, on the `RevocationSource` securable (Administrator only). Registration validates the CA PEMs, URLs and egress address classes. **No fetcher has shipped:** in this release `crl_status` always reads `no_crl_fetched`. *(Evidence: `server/core/src/revocation_source_routes.cpp`, `revocation_source_service.hpp`.)*

---

## 42. Endpoint Security Posture *(new domain, v4.1)*

*Read-only posture facts from the endpoint's own security controls, reported as facts, never as verdicts. Every plugin here reports a failed or refused read as `unreadable`/`constrained` with a named token, never as "absent" or "not hardened" — except the disclosed `firmware_posture` cases where a failure cannot be told from an absence (§42.6; #4897, #4900). One plugin (`rdp_control`) also has a gated mutating action. Previously visible only in Appendix A. `app_control` (WDAC/AppLocker posture) stays at §9.10.*

### 42.1 Secure Boot and Code-Integrity Posture :white_check_mark: `T2` *(new row, v4.1)*

`platform_security` plugin: `secure_boot` and `code_integrity`, read-only (`Security:Read`), on Windows, macOS and Linux. A definitive not-present is its own `absent` row; a refused, malformed or oversized read is `unreadable` with a token. macOS `code_integrity` is two literal-argv leaves (`spctl --status`, `csrutil status`). *(Evidence: `agents/plugins/platform_security/README.md`.)*

### 42.2 Exploit-Mitigation and Kernel-Hardening Posture :white_check_mark: `T2` *(new row, v4.1)*

`system_hardening` plugin `posture`: a fixed key allowlist (never an unbounded `/proc/sys` or sysctl walk, never a shell-out), each key reporting a value, `absent` or `unreadable`, on all three OSes (`Security:Read`). *(Evidence: `agents/plugins/system_hardening/README.md`.)*

### 42.3 Management-Plane Posture :white_check_mark: `T2` *(new row, v4.1)*

`mgmt_posture` plugin `posture`: which management plane controls the device, as facts only — macOS MDM enrolment (supported) and Linux sssd/IPA/keytab (constrained); Windows planned (`Inventory:Read`). *(Evidence: `agents/plugins/mgmt_posture/README.md`.)*

### 42.4 Remote Desktop Control :white_check_mark: `T2` *(new row, v4.1)*

`rdp_control` plugin, Windows-only: `status` (read-only) and `set_state`, which enables or disables RDP across the registry, the firewall and TermService (`Security:Write`, risk High, Mutating, AdminOrApproval). *(Evidence: `agents/plugins/rdp_control/README.md`.)*

### 42.5 Managed Browser Policy :large_orange_diamond: `T3` *(new row, v4.1)*

`browser_policy` plugin `policies`: enterprise-managed Chrome, Chromium and Edge policy inventory (`Inventory:Read`). **Linux only** — Windows and macOS are planned. *(Evidence: `agents/plugins/browser_policy/README.md`.)*

### 42.6 Firmware and BIOS Posture :large_orange_diamond: `T2` *(new row, v4.1)*

`firmware_posture` plugin `firmware`: firmware/BIOS vendor, version, release date and update-pending posture (`Security:Read`); fwupd is only ever listed, never asked to install. Windows supported; macOS and Linux constrained, and the README discloses the cases where a failure cannot yet be told from an absence (#4897, #4900). *(Evidence: `agents/plugins/firmware_posture/README.md`.)*

### 42.7 Local Security Policy and sudoers :large_orange_diamond: `T2` *(new row, v4.1)*

`local_security_policy` plugin: `password_policy`, `lockout_policy`, `audit_policy` and `sudoers` (`Security:Read`), never writing host policy (Windows `secedit /export` only, macOS `pwpolicy`, sudoers opened without following links and lexed as sudo 1.9.16 lexes it). Constrained on all three OSes; the README lists the limits (unresolved aliases and includes, other sudo versions, Windows measured on one standalone host). *(Evidence: `agents/plugins/local_security_policy/README.md`.)*

### 42.8 Privacy Permission Grants :large_orange_diamond: `T2` *(new row, v4.1)*

`privacy_permissions` plugin `permissions`: per-app camera, microphone, location and full-disk-access grants — Linux via the agent's own session D-Bus portal, macOS by reading each `TCC.db` in-process, Windows via the ConsentStore registry (offline hives behind the shared hive-file guard). A refusal never collapses into "absent". Forensics securable, default-off, AdminOrApproval, single-target. Constrained on all three OSes; the Linux portal reply is not yet bounded (tracked residual). *(Evidence: `agents/plugins/privacy_permissions/README.md`.)*

### 42.9 Update-Source Trust Posture :large_orange_diamond: `T3` *(new row, v4.1)*

`update_source_trust` plugin `sources`: package and update-source trust posture as facts (`Security:Read`). **Linux apt-family only** — Windows, macOS and rpm/dnf are planned. *(Evidence: `agents/plugins/update_source_trust/README.md`.)*

### 42.10 SSH Inbound-Access Audit :large_orange_diamond: `T2` *(new row, v4.1)*

`remote_access_audit` plugin `list`: `sshd_config` as written (Includes followed), per-account `authorized_keys` SHA-256 fingerprints and option names, and sshd service state — never a key comment, option value, principals list or key-file path. Forensics securable, default-off, AdminOrApproval, single-target. macOS supported, Linux constrained, Windows planned. *(Evidence: `agents/plugins/remote_access_audit/README.md`.)*

### 42.11 Filesystem Mount, Quota and Snapshot Posture :large_orange_diamond: `T3` *(new row, v4.1)*

`filesystem_posture` plugin: `mounts`, per-mount `quotas` subsystem state and snapshot-capable volumes (`snapshots`), read-only (`Inventory:Read`). macOS supported; Windows and Linux constrained. *(Evidence: `agents/plugins/filesystem_posture/README.md`.)*

---

## Appendix A: Plugin Coverage Matrix

*Category labels assigned 2026-09-07 (judgment call, matched to the pre-existing taxonomy below — no canonical category list exists in this file). The 8 rows added in the v4.0 re-baseline (`disk_actions`, `disk_space`, `filesystem_posture`, `license_scan`, `netprobe`, `power_health`, `rdp_control`, `tags`) are `ls`/meson-confirmed additions. *(verified 2026-09-07)* **Re-checked 2026-11-14 against each plugin README's generated Platforms row:** `Y` = supported, `🟡` = the README grades that whole leg constrained, `-` = planned or unsupported. Per-action legs can still be constrained inside a `Y` cell (the plugin README's capability table is authoritative). This matrix is hand-kept and drifts; `tools/capmatrix-gen` exists to generate it.*

| Plugin | Win | Linux | macOS | Category |
|--------|:---:|:-----:|:-----:|----------|
| os_info | Y | Y | Y | System Info |
| hardware | Y | Y | Y | System Info |
| peripherals | Y | Y | Y | System Info |
| device_identity | Y | Y | Y | System Info |
| status | Y | Y | Y | System Info |
| power_health | Y | 🟡 | Y | System Info |
| disk_actions | Y | - | 🟡 | Disk |
| disk_space | Y | Y | Y | Disk |
| processes | Y | Y | Y | Process/Service |
| procfetch | Y | Y | Y | Process/Service |
| services | Y | Y | Y | Process/Service |
| users | Y | Y | Y | User |
| network_config | Y | Y | Y | Network |
| netstat | Y | Y | Y | Network |
| network_diag | Y | Y | Y | Network |
| network_actions | Y | Y | Y | Network |
| wifi | Y | 🟡 | 🟡 | Network |
| wol | Y | Y | Y | Network |
| discovery | Y | 🟡 | Y | Network |
| netprobe | Y | Y | Y | Network |
| installed_apps | Y | Y | Y | Software |
| runtimes | Y | Y | Y | Software |
| msi_packages | Y | - | Y | Software |
| pkg_inventory | Y | Y | Y | Software |
| middleware | - | Y | - | Software |
| windows_updates | Y | Y | Y | Patch |
| software_actions | Y | Y | Y | Software |
| sccm | Y | - | - | Software |
| license_scan | Y | 🟡 | Y | Software |
| browser_policy | - | Y | - | Software |
| antivirus | Y | Y | Y | Security |
| firewall | Y | Y | Y | Security |
| bitlocker | Y | Y | Y | Security |
| event_logs | Y | Y | Y | Security |
| vuln_scan | Y | Y | Y | Security |
| ioc | Y | Y | Y | Security |
| quarantine | Y | Y | Y | Security |
| certificates | Y | Y | Y | Security |
| rdp_control | Y | - | - | Security |
| autoruns | Y | Y | Y | Security |
| app_usage | Y | Y | 🟡 | Security |
| execution_artifacts | Y | - | - | Security |
| app_control | Y | - | - | Security |
| firmware_posture | Y | 🟡 | 🟡 | Security |
| platform_security | Y | Y | Y | Security |
| browser_inventory | - | Y | - | Security |
| local_security_policy | 🟡 | 🟡 | 🟡 | Security |
| privacy_permissions | 🟡 | 🟡 | 🟡 | Security |
| system_hardening | Y | Y | Y | Security |
| filesystem | Y | Y | Y | File System |
| filesystem_posture | 🟡 | 🟡 | Y | File System |
| registry | Y | - | - | System Config |
| wmi | Y | - | - | System Config |
| windows_optional_features | Y | - | - | System Config |
| script_exec | Y | Y | Y | Execution |
| content_dist | Y | Y | Y | Content Dist |
| http_client | Y | Y | Y | Content Dist |
| interaction | Y | Y | Y | User Interaction |
| storage | Y | Y | Y | Agent KV |
| asset_tags | Y | Y | Y | Device Mgmt |
| tags | Y | Y | Y | Device Mgmt |
| printing | Y | Y | Y | Device Mgmt |
| update_source_trust | - | Y | - | Security |
| mgmt_posture | - | 🟡 | Y | Security |
| remote_access_audit | - | 🟡 | Y | Security |
| shares | Y | Y | Y | Network |
| virtualization | 🟡 | Y | Y | System Info |
| agent_logging | Y | Y | Y | Agent Mgmt |
| agent_actions | Y | Y | Y | Agent Mgmt |
| diagnostics | Y | Y | Y | Agent Mgmt |
| echo | Y | Y | Y | Monitoring |
| chargen | Y | Y | Y | Test/Debug |
| example | Y | Y | Y | Test/Debug |

**73 plugin directories: 71 production plugins plus the two test/debug plugins (`chargen`, `example`)**, which appear in the table but are excluded from the headline count (`ls -d agents/plugins/*/` = 73 at HEAD, 2026-11-14). Coverage spans hardware, peripherals, network, security posture, filesystem, registry, WMI, WiFi, WoL, IOC, quarantine, certificates, content distribution, user interaction and more, across cross-platform and Windows-only plugins. Corrections in this pass: `pkg_inventory` Windows is supported (was shown `-`); constrained legs are now shown `🟡` instead of `Y`; and the former `software_usage` "planned" row is removed — usage metering shipped as `app_usage` (§27.2, §35.6). The previous recount history (51 → 71 between 2026-09-15 and 2026-11) is in git history.
---

## Appendix B: Foundation Tier Status

**Foundation tier: 55/59 done (93%), 2 partial, 2 not started** (re-counted 2026-11-14 with the Method awk filtered on `` `T1` ``). Open `T1` items: §5.4 Service Control (Partial — `set_start_mode` only, no immediate start/stop/restart; promoted from Not Started 2026-11-14) and §9.4 Vulnerability Scanning (Partial — the agent-side scan exists; server-side vulnerability management is design-only and not implemented); §5.2 Process Termination and §10.5 File Deletion (Not Started — the named plugins have no native kill or whole-file delete action; see each row's evidence citation). The list below records the gaps closed as of 2026-03-18 (re-baselined 2026-09-07):

- **1.4** Agent OTA updates -- `agents/core/src/updater.cpp`
- **1.8** Connection diagnostics -- `connection_info` action in diagnostics plugin
- **4.5** DNS cache dump -- `dns_cache` action in network_config plugin (Windows and Linux; macOS unsupported, see §4.5)
- **10.3** File read by line range -- `offset`/`limit` params in filesystem plugin
- **10.12** Temp file creation -- `yuzu_create_temp_file()` in SDK
- **18.9** HTTPS for dashboard -- `httplib::SSLServer` with OpenSSL
- **24.6** SDK utility functions -- 4 conversion functions in plugin.h
