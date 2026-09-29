# services

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | System services — enumerate, query, and configure service startup types |
| **Version** | 0.2.0 |
| **Kind** | Action · mutating · gathered (crossplatform.service.list, crossplatform.service.running) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `list` (definition `crossplatform.service.list`) · `running` (definition `crossplatform.service.running`) · `set_start_mode` (definition `crossplatform.service.set_start_mode`) |
| **Security** | `list`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `running`: securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `set_start_mode`: securable `Infrastructure` · operation Write · risk High · dispatch Mutating · approval gate AdminOrApproval |
| **Roles** | execute: `list`: endpoint-admin, endpoint-operator; `running`: endpoint-admin, endpoint-operator; `set_start_mode`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`list` and `running` are reads: each enumerates the OS's service registry — the Service Control Manager on Windows, the systemd unit list on Linux, the launchd job list on macOS — and returns one row per service. `running` is the same enumeration filtered to services currently active (`SERVICE_ACTIVE` on Windows, `--state=running` on Linux, a non-`-` PID on macOS — `launchctl` has no running filter of its own, so the plugin filters after parsing). `set_start_mode` is the plugin's one mutation: it changes a single named service's startup type to automatic, manual, or disabled, translating that three-state input onto whatever the target OS actually supports (Windows' native `ChangeServiceConfig` start type; `systemctl enable`/`disable`/`mask`; or `launchctl enable`/`disable` — macOS has no manual state and refuses the request outright rather than aliasing it to disabled). On macOS, `list`/`running` additionally join a single bulk `launchctl print-disabled system` call against every enumerated label to report an honest startup type — one extra subprocess call total, never one per service (C-1.12). Every Linux/macOS subprocess call runs through the bounded, shell-free argv runner (no `/bin/sh -c` hop); `set_start_mode`'s mutating calls on both platforms are additionally wrapped in `sudo -n --` to match the installer's sudoers grant. The plugin is deliberately not a change-history/diff of service state — that is the separately-implemented TAR service collector (see *Where the data goes*).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Read list/running<br/>Infrastructure.Write + AdminOrApproval set_start_mode]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[services.execute]
  EX --> WIN[Windows leg<br/>EnumServicesStatusExW / QueryServiceConfigW / ChangeServiceConfigW]
  EX --> LIN[Linux leg<br/>runner argv systemctl list-units / sudo -n -- systemctl enable|disable|mask|unmask]
  EX --> MAC[macOS leg<br/>runner argv launchctl list + print-disabled / sudo -n -- launchctl enable|disable]
  WIN & LIN & MAC --> ROWS[pipe rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | ✅ supported · rung 1 · win32_service_api | ✅ supported · rung 2 · runner argv 'launchctl list' | ✅ supported · rung 2 · runner argv 'systemctl list-units' |
| `running` | ✅ supported · rung 1 · win32_service_api | ✅ supported · rung 2 · runner argv 'launchctl list' | ✅ supported · rung 2 · runner argv 'systemctl list-units' |
| `set_start_mode` | ✅ supported · rung 1 · win32_service_api | ✅ supported · rung 2 · runner argv 'sudo -n -- launchctl enable\|disable' | ✅ supported · rung 2 · runner argv 'sudo -n -- systemctl enable\|disable\|mask\|unmask' |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account — LocalSystem today (#1442) | `list`/`running`: none (default account). `set_start_mode`: `SeAssignPrimaryTokenPrivilege` (service control). | 2026-09-07, bare-metal, captured as `SYSTEM` | `list`/`running`: `OpenSCManagerW` failing returns an **empty** service list with no error and no result status set (`services_plugin.cpp:189-191`) — a permission failure reads identically to "this host has zero services". `set_start_mode`: `OpenServiceW`/`ChangeServiceConfigW` failure emits an explicit `error\|access denied changing service '<name>'` row (`services_plugin.cpp:426-429`). |
| macOS | agent daemon — root (shipped LaunchDaemon has no `UserName` key) | `list`/`running`: none. `set_start_mode`: sudoers grant `/bin/launchctl enable system/*`, `/bin/launchctl disable system/*` (the installed grant also covers `bootstrap`/`bootout`, which this plugin does not use). | 2026-09-07, bare-metal, captured **unprivileged** at `euid 501 (jsmith)` — not the root identity the daemon actually runs under | `list`/`running`: a failed `launchctl list` or `launchctl print-disabled` forwards `UNAVAILABLE`/`CONSTRAINED` via `forward_runner_failure` (`services_plugin.cpp:743-745`). `set_start_mode`: a `sudo -n` denial is captured (`merge_stderr=true`, `services_plugin.cpp:375-379`) and threaded into the `error\|...` message by `decide_set_start_mode_outcome`. |
| Linux | agent daemon — unprivileged `yuzu` account | `list`/`running`: none. `set_start_mode`: sudoers grant `/bin/systemctl enable\|disable\|mask\|unmask *` (also `/usr/bin/systemctl` on distros that mirror it). | 2026-09-06, container, captured at `euid 0` — root, not the deployed unprivileged identity | Same `forward_runner_failure` path as macOS; the captured Linux sample shows exactly this on both `list` and `running` (`UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error`, `docs/samples/linux.txt:3,7`) — here caused by `systemctl` not being resolvable in the capture container, not by a privilege denial. `set_start_mode` mirrors macOS. |

Binaries/subprocesses/network: Linux runs `systemctl` (list-units for reads; enable/disable/mask/unmask under `sudo -n --` for the mutation). macOS runs `launchctl` (list, print-disabled for reads; enable/disable under `sudo -n --` for the mutation). Windows uses the native Win32 Service Control Manager API only — no subprocess. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.service.set_start_mode` | `name` | string | yes | - | pattern: ^[a-zA-Z0-9._@-]+$ · minLength 1 · maxLength 256 | The service identifier. On Windows, the short service name (e.g. "Spooler"). On Linux, the systemd unit name (e.g. "nginx.service"). On macOS, the launchd label (e.g. "com.apple.metadata.mds"). |
| `crossplatform.service.set_start_mode` | `mode` | string | yes | - | enum: automatic, manual, disabled | Target startup type. "automatic" starts the service at boot. "manual" prevents auto-start but allows on-demand start. "disabled" prevents the service from starting entirely (Linux: systemctl mask; macOS: launchctl disable). |
<!-- END GENERATED -->

### Outputs

Rows are pipe-delimited, prefixed `svc|`, one row per service. The row **shape** differs by OS, not just the values: Windows and macOS emit exactly the four fields the `result.columns` schema names (`name|display_name|status|startup_type`), but Linux emits only **three** fields (`name|status|description`) — the systemctl leg never derives a startup type, so the fourth column doesn't exist on the Linux wire, and Linux's second/third fields carry different data than the schema's `display_name`/`status` names suggest (`services_plugin.cpp:730-733`; corroborated independently by the server's own parsing comment at `server/core/src/device_routes.cpp:197`). There is no placeholder-row convention: on Windows an enumeration failure silently returns zero rows with no error and no result status (`services_plugin.cpp:186-191`); on Linux/macOS it instead sets a typed `UNAVAILABLE`/`CONSTRAINED` status via `forward_runner_failure` before whatever rows were parsed (`services_plugin.cpp:121-130`). `set_start_mode` never writes the three schema columns as one pipe row: on success it writes three separate lines, `status|ok` / `service|<name>` / `mode|<mode>`; on any failure it writes a single `error|<message>` line and none of the three (`services_plugin.cpp:446-448`, file header comment lines 13-14).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.service.list` — `name|display_name|status|startup_type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows, Linux, macOS | `ADPSvc` | The service's short identifier: a Win32 service name, a systemd unit name, or a launchd label. Values: free text. |
| `display_name` | string | - | Windows, macOS | `Aggregated Data Platform Service (windows) · 1111 (darwin)` | Column 2, whose meaning is OS-specific. On Windows it is the Service Control Manager's human-readable display name. On macOS it holds the launchd job's numeric PID as a string, or "-" when not running (the platform has no per-service display name in `launchctl list`). It is NOT emitted on Linux at all -- the Linux leg's row carries only 3 pipe fields (name, status, description), so this column is absent from the wire, not merely empty. Values: free text (windows) · integer PID or "-" (darwin) · field absent (linux). |
| `status` | string | - | Windows, Linux, macOS | `stopped (windows) · 0 (darwin)` | Column 3, whose meaning is OS-specific. On Windows it is the service's current SCM state. On Linux it is systemd's SUB state from `systemctl list-units`. On macOS it is launchctl's raw last-exit-status code for the job -- an integer as a string, NOT a running/stopped word; use the display_name (PID) column to tell whether a macOS service is currently running. Values: stopped, start_pending, stop_pending, running, continue_pending, pause_pending, paused, unknown (windows) · free text systemd SUB state, e.g. running, dead, exited, failed (linux) · integer exit-status code as a string (darwin). |
| `startup_type` | string | - | Windows, macOS | `manual (windows) · unknown (darwin)` | Column 4: the service's configured startup type. On Windows this is the SCM's 5-state taxonomy. On macOS it is an honest 3-value read derived from a bulk `launchctl print-disabled` join -- a label with no explicit override reports "unknown" rather than a guessed default. It is NOT emitted on Linux at all (no 4th column on the wire), because the systemctl leg does not derive a startup type. Values: automatic, boot, manual, disabled, system, unknown (windows) · automatic, disabled, unknown (darwin) · field absent (linux). |

**`crossplatform.service.running` — `name|display_name|status|startup_type`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows, Linux, macOS | `AppXSvc` | The service's short identifier: a Win32 service name, a systemd unit name, or a launchd label. Values: free text. |
| `display_name` | string | - | Windows, macOS | `AppX Deployment Service (AppXSVC) (windows) · 1111 (darwin)` | Column 2, whose meaning is OS-specific. On Windows it is the Service Control Manager's human-readable display name. On macOS it holds the launchd job's numeric PID as a string, or "-" when not running (the platform has no per-service display name in `launchctl list`). It is NOT emitted on Linux at all -- the Linux leg's row carries only 3 pipe fields (name, status, description), so this column is absent from the wire, not merely empty. Values: free text (windows) · integer PID or "-" (darwin) · field absent (linux). |
| `status` | string | - | Windows, Linux, macOS | `running (windows) · 0 (darwin)` | Column 3, whose meaning is OS-specific. On Windows it is the service's current SCM state (always "running" for this action's filtered result). On Linux it is systemd's SUB state from `systemctl list-units --state=running`. On macOS it is launchctl's raw last-exit-status code for the job -- an integer as a string, NOT a running/stopped word; this action's own running-filter is applied on the PID column, not this one. Values: running (windows, this action always filters to it) · free text systemd SUB state (linux) · integer exit-status code as a string (darwin). |
| `startup_type` | string | - | Windows, macOS | `automatic (windows) · unknown (darwin)` | Column 4: the service's configured startup type. On Windows this is the SCM's 5-state taxonomy. On macOS it is an honest 3-value read derived from a bulk `launchctl print-disabled` join -- a label with no explicit override reports "unknown" rather than a guessed default. It is NOT emitted on Linux at all (no 4th column on the wire), because the systemctl leg does not derive a startup type. Values: automatic, boot, manual, disabled, system, unknown (windows) · automatic, disabled, unknown (darwin) · field absent (linux). |

**`crossplatform.service.set_start_mode` — `status|service|mode`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `ok` | Literal "ok" on a successful mode change. On any failure the plugin instead writes a single "error\|<message>" line and this row does not appear at all. Values: ok (the only value ever emitted). |
| `service` | string | - | Windows, Linux, macOS | `-` | The `name` parameter echoed back unmodified, on a successful mode change only. Values: free text — echoes the name parameter. |
| `mode` | string | - | Windows, Linux, macOS | `-` | The `mode` parameter echoed back unmodified, on a successful mode change only. Values: automatic, disabled (all OS) · manual additionally on windows/linux (darwin rejects it before this row is ever written). |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (default) | UNKNOWN | (empty) | Every successful `list`/`running` read on every OS, and every `set_start_mode` parameter-validation or platform-decision error (missing `name`/`mode`, invalid mode, unsafe name, macOS `manual` rejection) — the plugin never calls `ctx.set_result_status` on these paths (`services_plugin.cpp`, `do_set_start_mode`) |
| `UNAVAILABLE` or `CONSTRAINED` (via `forward_runner_failure`) | typically PARTIAL | e.g. `subprocess_runner:spawn_error` | Linux/macOS `list`/`running` when the `systemctl`/`launchctl` subprocess fails to spawn, times out, is cancelled, or is signaled (`services_plugin.cpp:121-123`); demonstrated live in `docs/samples/linux.txt:3,7` |
| `CONSTRAINED` / `PARTIAL` | partial | `subprocess_runner:deadline` | Linux/macOS `list`/`running`, the runner's deadline elapsed while `systemctl`/`launchctl` was still running, and it was killed |
| `CONSTRAINED` / `PARTIAL` | partial | `subprocess_runner:cancelled` | Linux/macOS `list`/`running`, the `systemctl`/`launchctl` run was cancelled before it finished |
| `CONSTRAINED` / `PARTIAL` | partial | `subprocess_runner:signaled` | Linux/macOS `list`/`running`, the `systemctl`/`launchctl` child was killed by a signal rather than exiting cleanly |
| `OK` / `PARTIAL` | partial | `subprocess_runner:line_limit` | Linux/macOS `list`/`running`, the runner capped `systemctl`/`launchctl` output at its line limit and killed the still-producing child — a deliberate bounded stop, not a failure |
| `CONSTRAINED` | PARTIAL | `services:output_truncated` | Linux/macOS `list`/`running` when the captured subprocess output was cut short by the runner's byte cap but the tool itself exited cleanly (`services_plugin.cpp:124-128`) |
| `CONSTRAINED` | PARTIAL | `services:malformed_launchctl_capture` | macOS `list`/`running` when `launchctl list` exited cleanly but its output is not a well-formed listing: no lines at all, or a first line other than the `PID\tStatus\tLabel` header. No service rows are emitted: the malformed check fires before any row is decoded (`services_parsers.hpp:210-211`), so the caller receives zero `svc\|` rows together with this status, and can tell a failed read from a host with nothing running — before this, a truncated capture read as a genuine "0 services" success. Reported only when no subprocess-runner failure has already set a status (`services_plugin.cpp:758-762`) |

### Where the data goes

- **Instruction result only.** Rows travel the agent's mTLS gRPC channel as the command response into the ResponseStore (`response_retention_days`, default 90 — `server/core/include/yuzu/server/server.hpp:222`), queryable at `/api/responses/{id}`; the dashboard's generic result viewer renders `services` through its key/value fallback schema (`server/core/src/result_parsing.hpp:65`).
- **Device pages "Get live info".** The `services` live-snapshot kind (`device.live.services` audit verb) dispatches `list` directly and re-parses the same 3-vs-4-field row shape described above to render the device card (`server/core/src/device_routes.cpp:79-80,197`; `server/core/src/device_ui.cpp:410`).
- **Not consumed by** daily-sync inventory, TAR, or DEX/metrics — nothing here runs on a schedule; the plugin executes only when dispatched.
- **Sensitivity.** `name`/`display_name` rows name installed services and applications on the host —
  Windows service display names (`Battle.net Update Helper Svc`, `CCleaner 7`, `AsusUpdateCheck` in
  the sample) and macOS launchd labels (`io.tailscale.ipn.macsys.login-item-helper`) are an
  installed-software inventory by another route; Linux systemd unit names carry the same signal.
  `status`/`startup_type` carry nothing beyond that service's own state. Nothing in any row
  identifies a specific device or person.
- **Siblings:** `agents/plugins/tar/src/tar_service_collector.cpp` performs its own, independently implemented service enumeration (the same three OS mechanisms) for TAR's diff-based change detection; it shares no code with this plugin.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.service.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; live snapshot via the device page's `services` kind (`device.live.services`).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash e724207e0989

```
== action=list
svc|ADPSvc|Aggregated Data Platform Service|stopped|manual
svc|ALG|Application Layer Gateway Service|stopped|manual
svc|AppIDSvc|Application Identity|stopped|manual
svc|Appinfo|Application Information|stopped|manual
svc|AppMgmt|Application Management|stopped|manual
svc|AppReadiness|App Readiness|stopped|manual
svc|AppVClient|Microsoft App-V Client|stopped|disabled
svc|AppXSvc|AppX Deployment Service (AppXSVC)|running|automatic
svc|ApxSvc|Windows Virtual Audio Device Proxy Service|stopped|manual
svc|AssignedAccessManagerSvc|AssignedAccessManager Service|stopped|manual
svc|AsusUpdateCheck|AsusUpdateCheck|stopped|automatic
svc|AudioEndpointBuilder|Windows Audio Endpoint Builder|running|automatic
… 12 of 289 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=running
svc|AppXSvc|AppX Deployment Service (AppXSVC)|running|automatic
svc|AudioEndpointBuilder|Windows Audio Endpoint Builder|running|automatic
svc|Audiosrv|Windows Audio|running|automatic
svc|BFE|Base Filtering Engine|running|automatic
svc|BrokerInfrastructure|Background Tasks Infrastructure Service|running|automatic
svc|BTAGService|Bluetooth Audio Gateway Service|running|manual
svc|BthAvctpSvc|AVCTP service|running|manual
svc|bthserv|Bluetooth Support Service|running|manual
svc|camsvc|Capability Access Manager Service|running|automatic
svc|CCleaner7|CCleaner 7|running|automatic
svc|CDPSvc|Connected Devices Platform Service|running|automatic
svc|CertPropSvc|Certificate Propagation|running|manual
… 12 of 115 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=set_start_mode
error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash e724207e0989

```
== action=list
svc|io.tailscale.ipn.macsys.login-item-helper|-|0|unknown
svc|com.apple.SafariHistoryServiceAgent|-|0|unknown
svc|com.apple.progressd|1111|0|unknown
svc|com.apple.enhancedloggingd|-|0|unknown
svc|com.apple.cloudphotod|1012|0|unknown
svc|com.apple.MENotificationService|1099|0|unknown
svc|com.apple.Finder|1186|0|unknown
svc|com.apple.homed|889|0|unknown
svc|com.apple.dataaccess.dataaccessd|1223|0|unknown
svc|com.apple.quicklook|-|0|unknown
svc|com.apple.parentalcontrols.check|-|0|unknown
svc|com.apple.mediaremoteagent|1057|0|unknown
… 12 of 513 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=running
svc|com.apple.progressd|1111|0|unknown
svc|com.apple.cloudphotod|1012|0|unknown
svc|com.apple.MENotificationService|1099|0|unknown
svc|com.apple.Finder|1186|0|unknown
svc|com.apple.homed|889|0|unknown
svc|com.apple.dataaccess.dataaccessd|1223|0|unknown
svc|com.apple.mediaremoteagent|1057|0|unknown
svc|com.apple.FontWorker|1042|0|unknown
svc|com.apple.bird|941|0|unknown
svc|com.apple.knowledgeconstructiond|2105|0|unknown
svc|com.apple.inputanalyticsd|1559|0|unknown
svc|com.apple.GameController.gamecontrolleragentd|974|0|unknown
… 12 of 279 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=set_start_mode
error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash e724207e0989

```
== action=list
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
[rc] 1

== action=running
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
[rc] 1

== action=set_start_mode
error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Linux drops the fourth output column entirely, not just leaves it blank.** The Linux leg emits `svc|name|status|description` (three fields); Windows and macOS emit four. A consumer that indexes the row by the schema's declared column names will misread Linux's `status`/`description` fields as `display_name`/`status`.
2. **A Windows enumeration failure is silently indistinguishable from zero services.** If `OpenSCManagerW` fails, `do_list`'s Windows branch returns an empty list with no error text and no result status set (`services_plugin.cpp:186-191`, `717-723`) — unlike the Linux/macOS legs, which forward a typed `UNAVAILABLE`/`CONSTRAINED` status on the same class of failure.
3. **macOS's `status` field is a raw exit-status code, not a running/stopped word.** Every sample row shows `status=0`, launchctl's last-exit-status column — to tell whether a macOS service is currently running, check the `display_name` (PID) field is not `-`, not this field (`services_plugin.cpp:747-749`; `LaunchdEntry::pid`, `services_parsers.hpp:126-128`).
4. **The macOS row cap already fired in this capture.** `total_seen=517` exceeded `kMaxServiceRows=512`, so the real `list` capture ends with a `svc|__truncated__|-|517|-` sentinel row (`docs/samples/macos.txt:515`) that falls outside this page's 25-row trim; the cap is documented behavior (`services_plugin.cpp:750-756`), not a capture artifact.
5. **No capture exercises `set_start_mode`'s actual mutation.** Every OS's `set_start_mode` sample stops at the parameter-validation rejection (`error|missing required parameter: name`) — the sudo-wrapped `enable`/`disable`/`mask`/`unmask` calls have never been captured live. The Linux `list`/`running` captures also failed outright (`subprocess_runner:spawn_error` — `systemctl` was not resolvable in the capture container), so the Linux 3-field row shape above is verified from source (`services_plugin.cpp:730-733`), not from a captured row.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/services/src/services_macos_launchd.hpp` · `agents/plugins/services/src/services_parsers.hpp` · `agents/plugins/services/src/services_plugin.cpp`
- Definitions: `content/definitions/services.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/agent/test_services_macos.cpp` · `tests/unit/test_services_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
