# windows_updates

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Updates/packages: installed, available, pending-reboot, patch connectivity |
| **Version** | 1.1.0 |
| **Kind** | Collector · read-only · gathered (device.windows_updates.patch_connectivity, device.windows_updates.installed, device.windows_updates.missing, device.windows_updates.pending_reboot) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `installed` (definition `device.windows_updates.installed`) · `missing` (definition `device.windows_updates.missing`) · `patch_connectivity` (definition `device.windows_updates.patch_connectivity`, `workflow.patch_connectivity_audit`) · `pending_reboot` (definition `device.windows_updates.pending_reboot`) |
| **Security** | securable `SoftwareDeployment` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`installed` and `missing` each read update state through a different mechanism per OS and emit
whatever shape that mechanism naturally returns — there is no shared cross-platform schema. `installed`
runs first: a bounded WMI query on Windows, `rpm --last` falling back to `apt list --installed` on
Linux, `system_profiler SPInstallHistoryDataType` on macOS. `missing` mirrors that fan-out with a
different mechanism per OS (WUA COM search, `apt`/`yum`, `softwareupdate -l`). On Windows this is not a
single blocking call: `do_missing` calls `IUpdateSearcher::BeginSearch` (async) then polls
`ISearchJob::get_IsCompleted` every 500ms until it returns true or a 120s deadline elapses
(`windows_updates_plugin.cpp:381-398`) — the real WUA search against the Windows Update service is what
makes this action's measured runtime (~12s in the capture below) far longer than every other action
here, all of which are local reads. `pending_reboot` is
independent of both — three-to-four per-OS existence/comparison checks, each written as its own row,
folded into one trailing `reboot_required` summary row. `patch_connectivity` is the odd one out: a pure
network probe (DNS + TCP, no update-manager call at all) against either the caller's `targets` parameter
or a built-in per-OS default list, so it is the plugin's only action that takes parameters and the only
one whose mechanism is identical on every OS.

This plugin is deliberately never a mutator: it has no install/patch-apply action anywhere in it (that
lives in other plugins, e.g. `sccm`, `software_actions`). It is also deliberately not an exhaustive
history: `installed` is bounded (512 rows on Windows, 50 lines on Linux, 100 matched lines on macOS),
never a full historical log.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: SoftwareDeployment.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[windows_updates.execute]
  EX --> WIN[Windows leg<br/>WMI Win32_QuickFixEngineering<br/>WUA COM async search<br/>registry presence checks<br/>BSD sockets]
  EX --> MAC[macOS leg<br/>system_profiler<br/>softwareupdate -l<br/>BSD sockets]
  EX --> LIN[Linux leg<br/>rpm / apt / yum<br/>filesystem + uname + needs-restarting<br/>BSD sockets]
  WIN & MAC & LIN --> ROWS[rows + typed result status<br/>only on installed/missing] --> RS[(ResponseStore)] --> API[REST /api/responses]
  ROWS -.-> PF["/auto Pre-flight<br/>reboot readiness check"]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `installed` | ✅ supported · rung 1 · wmi_bounded_query | ✅ supported · rung 2 · system_profiler | ✅ supported · rung 2 · rpm+apt |
| `missing` | ✅ supported · rung 1 · wua_com_async_search | ✅ supported · rung 2 · softwareupdate | ✅ supported · rung 2 · apt+yum |
| `patch_connectivity` | ✅ supported · rung 1 · raw_sockets | ✅ supported · rung 1 · raw_sockets | ✅ supported · rung 1 · raw_sockets |
| `pending_reboot` | ✅ supported · rung 1 · registry | 🟡 constrained · rung 2 · softwareupdate | ✅ supported · rung 3 · filesystem+uname+vmlinuz_ls+needs_restarting |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`pending_reboot` / macOS** — bounded (60s deadline) since this migration, but still a slow network call -- no longer able to hang indefinitely on an offline/headless Mac
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None documented in this plugin's code: the WMI query and WUA COM search are daemon-mediated broker calls, and the three registry reads are presence-only `RegOpenKeyExA(..., KEY_READ)` calls against HKLM. | 2026-09-07, bare-metal, `SYSTEM` | `installed`/`missing`: `WMI query failed: ...` / `Failed to ... (0x...)` rows plus `UNAVAILABLE`/`CONSTRAINED`; `pending_reboot`: the affected check's row reads `false` (key not found reads the same as key inaccessible — no distinct refusal shape) |
| macOS | agent daemon, unprivileged | None measured: `system_profiler`, `softwareupdate -l`, and the DNS/TCP probes all returned real data unprivileged. | 2026-09-07, euid 501 (`alex`) | tool spawn/timeout is forwarded via `forward_runner_failure`; a fully-filtered `softwareupdate -l` output returns zero `missing` rows with no explicit refusal marker (see Caveats) |
| Linux | agent daemon (`_yuzu`/`yuzu` per `docs/agent-privilege-model.md`'s general convention — no dedicated row exists for this plugin) | None measured: `rpm`/`apt`/`yum` and the filesystem/kernel checks all ran successfully. Sample was captured as `euid 0` in a container, so this is not evidence the agent's usual non-root identity is sufficient — only that the code makes no explicit privilege check. | 2026-09-06, container, `euid 0` | a spawn/timeout failure is forwarded via `forward_runner_failure`; a clean "nothing to report" exit (e.g. `apt` finding no upgrades) is not distinguishable from a refusal in the row data alone |

No row exists in `docs/agent-privilege-model.md` for `windows_updates`.

Binaries/subprocesses: Linux — `/usr/bin/rpm`, `/usr/bin/apt`, `/usr/bin/yum` (argv, ADR-3002 rung 2)
plus `uname -r` / `ls -t /boot/vmlinuz-*` / `needs-restarting -r` (rung 3 shell strings via `popen`,
grandfathered, tracked #2380). macOS — `/usr/sbin/system_profiler`, `/usr/sbin/softwareupdate` (argv).
Windows — none (in-process WMI/WUA COM/registry). Network: `patch_connectivity`'s DNS resolution + TCP
connect on every OS; `missing`'s Windows WUA search and macOS `softwareupdate -l` call also reach a
vendor update service.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `device.windows_updates.patch_connectivity` | `targets` | string | no | - | - | Comma-separated list of URLs to test connectivity against. If empty, uses platform-default patch servers (e.g. Windows Update endpoints, apt/yum/dnf repos, macOS Software Update). Example: "https://update.microsoft.com,https://download.windowsupdate.com" |
| `device.windows_updates.patch_connectivity` | `timeout_seconds` | int32 | no | 10 | minimum 1 · maximum 60 | TCP connection timeout per target. Default: 10, min: 1, max: 60. |
| `workflow.patch_connectivity_audit` | `targets` | string | no | - | - | Comma-separated list of patch server URLs to test. Leave empty to use platform defaults. |
| `workflow.patch_connectivity_audit` | `timeout_seconds` | int32 | no | 10 | minimum 1 · maximum 60 | TCP connection timeout per target. |
| `workflow.patch_connectivity_audit` | `upload_log_path` | string | no | - | maxLength 4096 | Optional. Path to a local diagnostic log file to upload to the server after the connectivity test. If provided, the log will be uploaded via agent.content_dist.upload_file in a chained step. |
<!-- END GENERATED -->

`patch_connectivity`'s definition (`device.windows_updates.patch_connectivity`) is declared in
`content/definitions/t2_capabilities.yaml`, not in this plugin's own `windows_updates.yaml` — see
Siblings below.

### Outputs

Pipe-delimited rows, one `write_output()` call per line. `installed` and `missing` are **not** a single
stable schema: the field count and the meaning of each field vary by OS, and on Linux by which tool ran
(`rpm` vs its `apt` fallback for `installed`; `apt` vs its `yum` fallback for `missing`). `pending_reboot`
is a stable 3-field `source|pending|detail` shape for every row including the summary. `patch_connectivity`
multiplexes three distinct row shapes (DNS, TCP, summary) as `tag|value` pairs after a shared
`target|<url>|` (or `summary|`) prefix — an unpopulated field is simply absent from that row, never a `-`
placeholder.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`device.windows_updates.installed` — `identifier|description|install_date`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `identifier` | string | - | Windows, Linux, macOS | `KB5122385` | The updated item's identifier: a Windows KB number, an installed Linux package name, or a macOS update/app name. Values: free text. |
| `description` | string | - | Windows | `Update` | A short human-readable label for the item. Populated only on Windows (the WMI Description field); Linux and macOS rows carry only two data fields (identifier + install_date), so this column is always empty there. Values: free text or empty. |
| `install_date` | string | - | Windows, Linux, macOS | `9/1/2026` | The date or version string the source reports, verbatim: Windows WMI InstalledOn, macOS's "Install Date:" text, or Linux's rpm --last date -- but a package VERSION string (not a date) when the apt list --installed fallback ran instead of rpm, since apt has no install-date field. Values: free text (a date string, or a package version on Linux/apt). |

**`device.windows_updates.missing` — `title|severity`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `title` | string | - | Windows, Linux, macOS | `Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.459.91.0) - Current Channel (Broad)` | The available update's title or name. Windows: the WUA update Title. Linux: the package name (apt path) or the raw yum check-update line (yum fallback). macOS: the raw softwareupdate -l line. Values: free text. |
| `severity` | string | - | Windows | `(empty)` | The MSRC severity rating. Populated only on Windows (IUpdate::MsrcSeverity, itself often empty for a non-security update); Linux and macOS have no equivalent field, so this column is always empty there. Values: free text or empty. |

**`device.windows_updates.patch_connectivity` — `target|dns_ok|dns_ms|ip|tcp_ok|tcp_ms|tcp_error|targets_tested|targets_reachable|targets_failed`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `target` | string | - | Windows, Linux, macOS | `https://windowsupdate.microsoft.com` | The target URL tested for connectivity; repeated across its own DNS and TCP result rows. Values: free text (URL). |
| `dns_ok` | bool | - | Windows, Linux, macOS | `True` | Whether DNS resolution of the target host succeeded. |
| `dns_ms` | int32 | - | Windows, Linux, macOS | `3` | DNS resolution time in milliseconds. Values: integer (milliseconds). |
| `ip` | string | - | Windows, Linux, macOS | `128.85.102.70` | Resolved IP address when dns_ok is true; carries the DNS error text instead when dns_ok is false (windows_updates_plugin.cpp:990-992). Values: IP address string, or free-text DNS error on failure. |
| `tcp_ok` | bool | - | Windows, Linux, macOS | `True` | Whether the TCP connect to the target succeeded within timeout_seconds. |
| `tcp_ms` | int32 | - | Windows, Linux, macOS | `160` | TCP connect time in milliseconds. Values: integer (milliseconds). |
| `tcp_error` | string | - | Windows, Linux, macOS | `not observed in any capture (every capture's TCP connects succeeded)` | TCP connect error text, emitted as an additional row only when tcp_ok is false; the row is omitted entirely on a successful connect (windows_updates_plugin.cpp:1002). Values: free text. |
| `targets_tested` | int32 | - | Windows, Linux, macOS | `3` | Total number of targets tested in this run. Values: integer. |
| `targets_reachable` | int32 | - | Windows, Linux, macOS | `3` | Count of targets whose DNS and TCP checks both succeeded. Values: integer. |
| `targets_failed` | int32 | - | Windows, Linux, macOS | `0` | Count of targets that failed DNS resolution or TCP connect. Values: integer. |

**`device.windows_updates.pending_reboot` — `source|pending|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `source` | string | - | Windows, Linux, macOS | `pending_file_rename` | Which check produced this row: a per-check probe name for every row but the last, or the literal "reboot_required" for the trailing summary row. Values: windows_update_reboot, cbs_reboot, pending_file_rename, reboot_required_file, kernel_mismatch, needs_restarting, softwareupdate_restart, reboot_required. |
| `pending` | bool | - | Windows, Linux, macOS | `true` | Whether this specific check (or, on the summary row, any check) found a pending reboot. Values: true, false. |
| `detail` | string | - | Windows, Linux, macOS | `Non-empty value` | Free text explaining a true `pending` on a per-check row (which registry key existed, which kernel versions mismatched); a comma-separated list of the triggering check names on the summary row; empty when `pending` is false. Values: free text or empty. |

**`workflow.patch_connectivity_audit` — `target|dns_ok|dns_ms|tcp_ok|tcp_ms|targets_tested|targets_reachable|targets_failed`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `target` | string | - | all | - | - |
| `dns_ok` | bool | - | all | - | - |
| `dns_ms` | int32 | - | all | - | - |
| `tcp_ok` | bool | - | all | - | - |
| `tcp_ms` | int32 | - | all | - | - |
| `targets_tested` | int32 | - | all | - | - |
| `targets_reachable` | int32 | - | all | - | - |
| `targets_failed` | int32 | - | all | - | - |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNAVAILABLE` / `CONSTRAINED` | PARTIAL | `wmi_bounded:<token>` | `installed`/Windows — the WMI connection or query itself failed |
| `OK` | PARTIAL | `wmi_bounded:row_cap_truncated` | `installed`/Windows — the 512-row cap was hit |
| `OK` | PARTIAL | (forwarded runner outcome, e.g. `subprocess_runner:line_limit`) | `installed`/Linux — `rpm`/`apt` output hit the 50-line cap |
| `UNAVAILABLE` | PARTIAL | `windows_updates:com_init_failed` / `windows_updates:cocreate_updatesession_failed` / `windows_updates:create_searcher_failed` / `windows_updates:begin_search_failed` / `windows_updates:end_search_failed` / `windows_updates:get_updates_failed` | `missing`/Windows — a WUA COM stage failed outright: COM init, update-session creation, searcher creation, `BeginSearch`, `EndSearch`, or enumerating the result's updates collection |
| `CONSTRAINED` | PARTIAL | `windows_updates:search_deadline_exceeded` / `windows_updates:get_result_code_failed` / `windows_updates:search_result_failed` / `windows_updates:get_update_count_failed` | `missing`/Windows — the 120s search deadline elapsed before completion, or a result/count accessor itself failed, leaving the outcome unknown rather than confirmed-zero |
| `OK` | PARTIAL | `windows_updates:search_result_partial` | `missing`/Windows — the search partially succeeded (`orcSucceededWithErrors` or a per-item read failure) |
| `UNAVAILABLE` | PARTIAL | `subprocess_runner:spawn_error` | `missing`/Linux, `missing`/macOS, `installed`/macOS — the child process (rpm/apt/yum, system_profiler, softwareupdate) could not be spawned at all, forwarded via `forward_runner_failure` |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:deadline` / `subprocess_runner:cancelled` / `subprocess_runner:signaled` | `missing`/Linux, `missing`/macOS, `installed`/macOS — the runner's deadline elapsed and the child was killed still running, the run was cancelled before finishing, or the child was killed by a signal rather than a clean exit, forwarded via `forward_runner_failure` |
| (forwarded runner outcome, or none) | — | — | `missing`/Linux, `missing`/macOS, `installed`/macOS — `forward_runner_failure` only reports a status for a genuine spawn/deadline/truncation degradation; a clean tool exit leaves the status `UNDECLARED` |
| — | — | — | `pending_reboot` (all OSes) and `patch_connectivity` (all OSes) never call `set_result_status`; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` for these two actions |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response
  and land in the ResponseStore, queryable at `/api/responses/{id}`. The dashboard renders every action
  of this plugin generically as Agent/Key/Value rows (`result_parsing.hpp`'s `kKeyValuePlugins`), not a
  plugin-specific table.
- **`pending_reboot` also feeds `/auto` Pre-flight.** `preflight_parse.hpp` parses its trailing
  `reboot_required|<bool>|<reasons>` row as an unconditional summary for the "reboot" readiness check.
- **Not consumed by** the daily-sync inventory framework (ADR-0016), TAR, DEX, or metrics.
- **Sensitivity.** `installed`/`missing` rows can name specific installed software indirectly — a
  Windows KB title/description often embeds a product name (e.g. "...for Microsoft Defender
  Antivirus...") — an installed-software signal by another route; `pending_reboot` and
  `patch_connectivity` rows carry nothing beyond boolean/timing/target-URL data and the device id.
- **Siblings:** `content/definitions/t2_capabilities.yaml` (`device.windows_updates.patch_connectivity`,
  the definition that actually declares this action's parameters and result columns) and
  `content/definitions/t2_chaining_examples.yaml` (`workflow.patch_connectivity_audit`, a two-step
  compliance workflow chaining `patch_connectivity` into a log upload). `sccm` and `software_actions`
  cover the mutating side (deploying/applying updates) this plugin deliberately does not.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) →
  `discover_instructions` / `get_definition("device.windows_updates.installed")`. Run:
  `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`, plus the `/auto`
  Pre-flight page for `pending_reboot`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 007b2e86015f

```
== action=installed
update|KB5122385|Update|9/1/2026
update|KB5054156|Update|2/16/2026
update|KB5120998|Update|9/1/2026
update|KB5120997|Update|8/31/2026
[result_status] UNDECLARED / UNKNOWN

== action=missing
available|Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.459.91.0) - Current Channel (Broad)|
[result_status] UNDECLARED / UNKNOWN

== action=pending_reboot
windows_update_reboot|false|
cbs_reboot|false|
pending_file_rename|true|Non-empty value
reboot_required|true|pending_file_rename
[result_status] UNDECLARED / UNKNOWN

== action=patch_connectivity
target|https://windowsupdate.microsoft.com|dns_ok|true|dns_ms|3|ip|128.85.102.70
target|https://windowsupdate.microsoft.com|tcp_ok|true|tcp_ms|160
target|https://update.microsoft.com|dns_ok|true|dns_ms|0|ip|128.85.102.70
target|https://update.microsoft.com|tcp_ok|true|tcp_ms|170
target|https://download.windowsupdate.com|dns_ok|true|dns_ms|7|ip|199.232.54.172
target|https://download.windowsupdate.com|tcp_ok|true|tcp_ms|14
summary|targets_tested|3|targets_reachable|3|targets_failed|0
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 007b2e86015f

```
== action=installed
update|macOS 26.5.1|18/07/2026, 01:41
update|MAContent10_AssetPack_0048_AlchemyPadsDigitalHolyGhost|18/07/2026, 01:44
update|MAContent10_AssetPack_0310_UB_DrumMachineDesignerGB|18/07/2026, 01:44
update|MAContent10_AssetPack_0312_UB_UltrabeatKitsGBLogic|18/07/2026, 01:44
update|MAContent10_AssetPack_0314_AppleLoopsHipHop1|18/07/2026, 01:44
update|MAContent10_AssetPack_0315_AppleLoopsElectroHouse1|18/07/2026, 01:44
update|MAContent10_AssetPack_0316_AppleLoopsDubstep1|18/07/2026, 01:44
update|MAContent10_AssetPack_0317_AppleLoopsModernRnB1|18/07/2026, 01:44
update|MAContent10_AssetPack_0320_AppleLoopsChillwave1|18/07/2026, 01:44
update|MAContent10_AssetPack_0321_AppleLoopsIndieDisco|18/07/2026, 01:44
update|MAContent10_AssetPack_0322_AppleLoopsDiscoFunk1|18/07/2026, 01:44
update|MAContent10_AssetPack_0323_AppleLoopsVintageBreaks|18/07/2026, 01:44
… 12 of 50 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=missing
[result_status] UNDECLARED / UNKNOWN

== action=pending_reboot
softwareupdate_restart|false|
reboot_required|false|
[result_status] UNDECLARED / UNKNOWN

== action=patch_connectivity
target|https://swscan.apple.com|dns_ok|true|dns_ms|12|ip|2.16.176.247
target|https://swscan.apple.com|tcp_ok|true|tcp_ms|22
target|https://swdist.apple.com|dns_ok|true|dns_ms|2|ip|17.253.29.150
target|https://swdist.apple.com|tcp_ok|true|tcp_ms|23
summary|targets_tested|2|targets_reachable|2|targets_failed|0
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 007b2e86015f

```
== action=installed
package|apt|3.0.3
package|autoconf|2.72-3.1
package|automake|1:1.17-4
package|autotools-dev|20240727.1
package|base-files|13.8+deb13u6
package|base-passwd|3.6.7
package|bash|5.2.37-2+b9
package|binutils-aarch64-linux-gnu|2.44-3
package|binutils-common|2.44-3
package|binutils|2.44-3
package|bison|2:3.8.2+dfsg-1+b2
package|bsdutils|1:2.41.5-0+deb13u1
… 12 of 49 rows shown
[result_status] OK / PARTIAL / subprocess_runner:line_limit

== action=missing
available|none|System is up to date
[result_status] UNDECLARED / UNKNOWN

== action=pending_reboot
reboot_required_file|false|
needs_restarting|false|
reboot_required|false|
[result_status] UNDECLARED / UNKNOWN

== action=patch_connectivity
target|https://archive.ubuntu.com|dns_ok|true|dns_ms|37|ip|185.125.190.83
target|https://archive.ubuntu.com|tcp_ok|true|tcp_ms|14
target|https://security.ubuntu.com|dns_ok|true|dns_ms|12|ip|185.125.190.82
target|https://security.ubuntu.com|tcp_ok|true|tcp_ms|19
summary|targets_tested|2|targets_reachable|2|targets_failed|0
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS `missing` can return zero rows with no placeholder.** `do_missing`'s macOS branch only
   writes an `available|none|...` placeholder when `softwareupdate -l`'s raw output is empty
   (`windows_updates_plugin.cpp:569-575`); when the raw output is non-empty but entirely banner/status
   text, `parse_softwareupdate_list` filters every line out (`windows_updates_parsers.hpp:228-243`,
   drops `"Software Update"`/`"Finding"`/`"No new"` lines) and nothing is written at all — exactly what
   the macOS sample above shows for `missing`. A consumer cannot distinguish "no updates" from "the tool
   produced nothing recognisable" for this action on macOS.
2. **`installed`/`missing` have no single field schema.** The `identifier|description|install_date` and
   `title|severity` shapes declared in the definition YAML fit the Windows leg; on Linux and macOS both
   actions emit two data fields, not three (`installed`) or the raw tool line (`missing`/yum and
   macOS), and on Linux `installed`'s third field is a package version, not a date, whenever the `apt`
   fallback ran instead of `rpm` (`windows_updates_plugin.cpp:252-272`).
3. **`installed`'s row order and cap changed with the WMI migration.** The retired PowerShell path
   returned the 50 most-recently-installed hotfixes, newest first; the WMI-sourced path returns up to
   512 rows in whatever order the provider yields (WQL has no `ORDER BY` for a data-class query) —
   disclosed in `windows_updates_plugin.cpp:200-207` and the `wave3-pr33d` changelog entry, not a defect.
4. **The `raw_sockets` mechanism name is ordinary TCP, not `SOCK_RAW`.** `test_dns`/`test_tcp`
   (`windows_updates_plugin.cpp:788-881`) use `getaddrinfo` + a plain `SOCK_STREAM` `connect()`; the
   descriptor's mechanism string is a convention shared across plugins for "direct BSD/Winsock sockets",
   not a literal raw-socket claim.
5. **`missing`'s Windows leg is unverified on real Windows.** The header comment above `do_missing`'s
   WUA branch (`windows_updates_plugin.cpp:309-320`) states it "could not be verified on this
   (non-Windows) host" and was written from the documented COM API surface; `test_windows_updates_win_actions.cpp`
   deliberately exercises only `installed`, not `missing`, to avoid a network-dependent unit test.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/windows_updates/src/windows_updates_parsers.hpp` · `agents/plugins/windows_updates/src/windows_updates_plugin.cpp`
- Definitions: `content/definitions/t2_capabilities.yaml` · `content/definitions/t2_chaining_examples.yaml` · `content/definitions/windows_updates.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/test_windows_updates_parsers.cpp` · `tests/unit/test_windows_updates_posix_actions.cpp` · `tests/unit/test_windows_updates_win_actions.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
