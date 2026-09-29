# autoruns

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Enumerates persistence sources (what starts automatically) across Windows, Linux and macOS |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · on-demand |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `catalog` (definition `crossplatform.autoruns.catalog`) · `list` (definition `crossplatform.autoruns.list`) |
| **Security** | securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`catalog` performs no OS call at all: it walks the plugin's own static `kSourceCatalog` (34 `SourceDecl` entries, `autoruns_catalog.hpp`) and emits one `source|<id>|<support>|-|declared` line per entry — the support level THIS build declares for that source, not a live read result. `list` runs all three per-OS legs (`collect_windows`/`collect_linux`/`collect_macos`) unconditionally on every build; the two legs that are not the build's own OS resolve to `autoruns_legs.hpp`'s foreign-OS stub, which emits `source|<id>|unsupported|0|foreign_os` for every source belonging to that OS — so a `list` capture always names all 34 sources on every OS, never silently omitting a platform's rows. `sources=` filters `list` to a comma-separated `SourceId` allow-list; `catalog` takes no parameters and always reflects the full 34-source catalog.

On its own OS, `list` reads: Windows — `Reg*W` over HKLM (Run/RunOnce/RunOnceEx/StartupApproved/Winlogon Shell+Userinit/AppInit_DLLs/IFEO Debugger) plus every reachable HKU hive via `win_profiles.hpp`'s `with_user_hive` ladder (live hive first, then an offline `RegLoadKeyW` mount under `SeBackupPrivilege`+`SeRestorePrivilege` for a logged-out profile), the Startup folders (common + per-user), `ITaskService` COM for Scheduled Tasks, and a bounded WMI `root\subscription` query for permanent event-subscription bindings. Linux — bounded file reads/directory listings of `/etc/crontab`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`, per-user crontabs, `/etc/anacrontab`, `/var/spool/at`, systemd system/user timer units (rung 1: direct unit-dir reads; rung 2: a `systemctl list-timers` argv fallback, the leg's only subprocess spawn, used only when systemd is present but none of its three unit directories is readable), XDG autostart (system + per-user), `/etc/rc.local`, and an `/etc/init.d` listing (names only). macOS — `CFPropertyListCreateWithData` over launchd plists in `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/System/Library/LaunchDaemons`, `/System/Library/LaunchAgents` and `~/Library/LaunchAgents`; file reads of `/etc/periodic` (listing only) and `/etc/emond.d/rules` (plist walk). macOS Login Items is deliberately never read — the list lives in a private per-user BTM database with no public read API, and this leg does not shell out to `osascript`/`launchctl`/`sfltool` to approximate it.

Every source, on every OS, reports a `source|` status line even when it produced zero `autorun|` rows — an empty directory and a permission-denied read are never conflated (`reason` distinguishes `absent` from `permission_denied` from every other real errno). This plugin never mutates host state: no action opens a write handle, spawns a mutating process, or changes any persistence entry it reports on.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Security.Read<br/>ExecuteGate: None]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[autoruns.execute]
  EX --> WIN[Windows leg<br/>Reg*W HKLM+HKU · ITaskService COM · WMI root\subscription]
  EX --> LIN[Linux leg<br/>cron/anacron/at/systemd/XDG file reads<br/>+ systemctl list-timers argv fallback]
  EX --> MAC[macOS leg<br/>CFPropertyListCreateWithData over launchd plists<br/>+ /etc/periodic, /etc/emond.d reads]
  WIN & LIN & MAC --> ROWS[source| status rows +<br/>autorun| data rows]
  ROWS -- CommandResponse --> RS[(ResponseStore)]
  RS --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `catalog` | ✅ supported · rung 1 · Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | ✅ supported · rung 1 · CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | ✅ supported · rung 1 · file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable |
| `list` | ✅ supported · rung 1 · Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | ✅ supported · rung 1 · CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | ✅ supported · rung 1 · file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`catalog` / Windows** — Pure reflection of this build's static kSourceCatalog declarations for the Windows sources above -- no OS call itself, but the same LocalSystem session this build's ITaskService/WMI mechanism relies on is A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding. See the `list` descriptor's note for the full per-source `list` behaviour this catalog entry declares support for.
- **`catalog` / macOS** — Pure reflection of this build's static kSourceCatalog declarations for the macOS sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism.
- **`catalog` / Linux** — Pure reflection of this build's static kSourceCatalog declarations for the Linux sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism.
- **`list` / Windows** — Reg*W over HKLM plus every reachable HKU hive via win_profiles.hpp's with_user_hive ladder (live hive first; offline RegLoadKeyW under SeBackup/SeRestore -- enabled on the process token for the offline arm only, serialised process-wide by offline_hive_mutex() -- when the profile is not logged in; unload_failed is surfaced as a warning line, never dropped, when RegUnLoadKeyW fails on the way out). ITaskService COM (yuzu::shared::win::ComInit, COINIT_MULTITHREADED, no dedicated STA thread) and a bounded WMI root\\subscription query, one row per __FilterToConsumerBinding joined on the ref Name -- a dangling ref still emits its row, tagged constrained|unresolved_ref, never dropped or collapsed into another binding's row. A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim for the LocalSystem session: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts -- MTA is not a problem for ITaskService here, including as LocalSystem); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding -- the same stock 'SCM Event Log Filter'/'SCM Event Log Consumer' binding the admin session saw, confirming LocalSystem reaches both APIs with no apartment-model or session-identity gap. CoInitializeEx itself failing is the one COM failure this leg cannot render as a real hr_<hex> token (ComInit::ok() exposes no HRESULT) -- reported as the fixed sentinel hr_cominit_failed; every other COM/WMI failure carries the real HRESULT or wmi_bounded.hpp's error token. Zero spawn primitives: schtasks.exe, wmic.exe and PowerShell are never invoked. Real-hardware verification: docs/wave7/rig-checklist-autoruns-win.md's 10-step checklist.
- **`list` / macOS** — File-truth only, rung 1: CFPropertyListCreateWithData over launchd plists (system + per-user LaunchDaemons/LaunchAgents), /etc/periodic directory listings, and /etc/emond.d/rules plists. Login Items is CONSTRAINED -- the list lives in a private per-user BTM database with no public read API; this leg never shells out to osascript, launchctl, or sfltool. A plist's own Disabled key is read, but launchctl print-disabled's separate override database is NOT consulted -- this is file truth, not launchd's live runtime state, a deliberate divergence from a services-style plugin that does read launchctl state. Real capture on this Mac (2026-09-07): mac_system_launchdaemons|supported|422, mac_system_launchagents|supported|456, mac_launchdaemons|supported|2, mac_user_launchagents|supported|1, mac_launchagents|supported|0, mac_periodic|supported|0, mac_emond|supported|0, mac_login_items|constrained|0|btm_private_database_no_public_api -- login items always emits that one constrained status line and zero rows, never a real read attempt (docs/user-manual/autoruns.md has the full `source|` capture).
- **`list` / Linux** — Every acquisition is a bounded local file read or directory listing (read_file_bounded, O_NOFOLLOW on the leaf) except one declared exception: systemd timer enumeration is a tri-state on /run/systemd/system -- absent reports UNSUPPORTED (no_systemd), a stat() error other than ENOENT reports CONSTRAINED (systemd_state_undetermined), and present reads /etc/systemd/system, /usr/lib/systemd/system and /lib/systemd/system directly. Only when systemd is present but all three dirs are unreadable does it fall back to `systemctl list-timers --all --no-pager --no-legend` (rung 2, autoruns/collect_linux#1, docs/agent-spawn-sink-manifest.md), whose rows carry enabled=unknown -- that text has no wants-symlink evidence. A rung-1-scanned timer row can ALSO carry enabled=unknown, even with a real wants-symlink read attempted: if a wants directory consulted for it hit a real I/O error partway through, or hit its entry cap, the matching symlink could be among what wasn't read (#4182); or, with no failed read among the wants directories it actually checked, when /home itself couldn't be fully enumerated, the very set of user wants directories to search is itself incomplete. Real captures (2026-09-07): this Mac reports the Linux source through the foreign-OS stub as lnx_systemd_timers_system|unsupported|0|foreign_os (this build cannot exercise the leg at all); a real ubuntu:24.04 Docker container read lnx_systemd_timers_system|unsupported|0|no_systemd -- the container has no init system at all, so this confirms the absent branch; the rung-2 fallback itself needs a host with systemd present but its unit dirs unreadable, not exercised here. `absent` (ENOENT) on /etc/crontab and /etc/anacrontab reports CONSTRAINED (their absence is itself a real constraint, classify_read_error's required_by_catalog=true); the same ENOENT on every other file/dir source reports SUPPORTED (nothing there is a valid, fully-read answer) -- a genuine read failure (permission_denied or any other errno) always reports CONSTRAINED with that token, never folded into `absent`. lnx_init_d lists /etc/init.d script names only (no runlevel/systemctl wiring cross-check) -- CONSTRAINED by design, per-user reads report owning uid numerically (no NSS/getpwuid_r lookup, no directory-service deadline risk on this read-only path). lnx_systemd_timers_user is likewise always CONSTRAINED (narrow_search_path_coverage) when reportable -- the scanned search-path set omits several standard `systemd --user` unit roots (~/.local/share/systemd/user, /run/systemd/user, /usr/local/{lib,share}/systemd/user, /usr/share/systemd/user), a permanent gap, not a transient failure.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | Agent service account — LocalSystem today (#1442). Every machine-scope read (`Run`/`RunOnce`/`RunOnceEx`, `Winlogon`, `AppInit_DLLs`, IFEO, Startup folders, `ITaskService` Scheduled Tasks, WMI permanent subscriptions) needs no privilege beyond the account's own registry/COM/file-read access. | **None today.** The per-profile `HKU` pass (`win_run_hku`/`win_runonce_hku`/`win_startup_approved`/`win_startup_folder_user` — the last of these opens the same per-user hive only to resolve a possible Startup-folder redirect, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, #4219) shares the same `with_user_hive` ladder as `installed_apps.list_per_user`/`license_scan.list`: a loaded `HKEY_USERS\<sid>` hive is read first with no privilege; the offline `RegLoadKeyW` mount for a logged-out profile rides `SeBackupPrivilege`+`SeRestorePrivilege`, already held by the agent account (`docs/agent-privilege-model.md`'s `autoruns.list`/`autoruns.catalog` row) — no new grant is introduced. | A1's the-rig probe, LocalSystem session, 2026-09-06 (`tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md`; `docs/wave7/rig-checklist-autoruns-win.md`'s 10-step checklist); real-hardware `list`/`catalog` capture pending (`docs/samples/windows.txt:1`). | On a hardened install that strips `SeBackup`/`SeRestore`, machine-scope sources still report; only a logged-out profile's `win_run_hku`/`win_runonce_hku`/`win_startup_approved`/`win_startup_folder_user` rows degrade to a per-sid `privilege_missing` reason, never a dropped row or a false-empty read. |
| macOS | Agent daemon (the shipped LaunchDaemon has no `UserName` key, so launchd runs it as **root** — `docs/agent-privilege-model.md`'s TL;DR — required today for TAR's Endpoint Security client, not for this plugin). This leg's own file reads (launchd plist walk, `/etc/periodic`, `/etc/emond.d`) need no elevation beyond that; the per-user `~/Library/LaunchAgents` walk reads each real account's home directly under `/Users` as the calling (root) account, no further elevation. | None — no sudoers entry, no entitlement. `mac_login_items` is permanently constrained regardless of privilege: the list lives in a private per-user BTM database with no public read API, and this leg deliberately never shells to `osascript`/`launchctl`/`sfltool` to approximate it. | This Mac, bare-metal, 2026-09-08, euid 501 (jsmith) (`docs/samples/macos.txt:1`). | A malformed plist reports constrained with a `malformed` reason; Login Items always reports constrained with a `btm_private_database_no_public_api` reason, on every run, never a real read attempt. |
| Linux | Agent daemon (`yuzu`/unprivileged by the model; a real capture to date ran as root inside a container — see Measured). Every file read/directory listing needs no elevation. | None for rung 1 (direct unit-dir/file reads). The single subprocess in this leg, `systemctl list-timers --all --no-pager --no-legend`, runs as the calling account with no elevation — it is a rung-2 fallback reached only when systemd is present but none of its three unit directories is readable, not a privileged escalation. | Real `ubuntu:24.04` Docker container, euid 0, 2026-09-07 (standalone harness linking the real `collect_linux`, not the shipped `.so` dispatched end-to-end — `docs/user-manual/autoruns.md`); a real end-to-end `list` dispatch through the shipped plugin, and the rung-2 fallback itself, are both pending (`docs/samples/linux.txt:1`). | A real read failure reports constrained with the specific errno reason (e.g. `permission_denied`); a required-by-catalog file (`/etc/crontab`, `/etc/anacrontab`) that is genuinely missing reports constrained with an `absent` reason; the systemd-presence tri-state reports unsupported (`no_systemd`) or constrained (`systemd_state_undetermined`) short of a real unit-dir read. |

Binaries: `systemctl` (Linux, rung-2 fallback only, resolved via `probe_tool_path`, no shell). No network access on any leg. No other subprocess anywhere in this plugin — the Windows and macOS legs spawn nothing at all.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.autoruns.list` | `sources` | string | no | - | - | Comma-separated source ids to filter to. Empty means every source. |
<!-- END GENERATED -->

### Outputs

Two row shapes share one stream, discriminated by field 0 (`row_kind`): a `source|<id>|<supported|constrained|unsupported>|<row_count>|<reason>` status line — exactly one per catalog source, on every action, every OS — and zero or more `autorun|<source_id>|<catalog_version>|<location>|<entry>|<target>|<args>|<enabled>|<scope>|<user>|<signed>|<mtime>` data rows for a source that actually produced entries. A `source|` row only populates the declared `field_1`..`field_4` columns (id/support/row_count/reason) and leaves `field_5`..`field_11` empty; a `autorun|` row uses all eleven. `row_count` is `-` (not `0`) for a `catalog` action's declared-only status line, distinguishing "never executed a read" from a real zero-count `list` collection that genuinely found nothing. A literal `|` inside any text field (`location`, `entry`, `target`, `args`, `user`) is folded to U+2502 (`│`) rather than backslash-escaped, so every row stays a fixed field count under a plain `split('|')` — a consumer never needs an escape-aware splitter to reach a specific field by position. `catalog_version` lets a consumer that stored an `autorun|` row detect a `SourceId` rename/add/remove between agent versions; cross-check it against the version `catalog` reports before comparing row shapes across a fleet.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.autoruns.catalog` — `row_kind|source_id|support|row_count|reason`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | - | all | - | - |
| `source_id` | string | - | all | - | - |
| `support` | string | - | all | - | - |
| `row_count` | string | - | all | - | - |
| `reason` | string | - | all | - | - |

**`crossplatform.autoruns.list` — `row_kind|field_1|field_2|field_3|field_4|field_5|field_6|field_7|field_8|field_9|field_10|field_11`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | - | all | - | - |
| `field_1` | string | - | all | - | - |
| `field_2` | string | - | all | - | - |
| `field_3` | string | - | all | - | - |
| `field_4` | string | - | all | - | - |
| `field_5` | string | - | all | - | - |
| `field_6` | string | - | all | - | - |
| `field_7` | string | - | all | - | - |
| `field_8` | string | - | all | - | - |
| `field_9` | string | - | all | - | - |
| `field_10` | string | - | all | - | - |
| `field_11` | string | - | all | - | - |
<!-- END GENERATED -->

### Result status

Surfaced as `plugin_result_status` on the command response, set via `ctx.set_result_status` or forwarded from a runner failure via `yuzu::agent::forward_runner_failure`. A per-source degraded read (permission denied, a malformed plist, an unreachable hive) is always reported inside that source's own `source|` row first — see Outputs above — and, on `list`, ALSO aggregated into this command-level status via `autoruns:degraded` whenever any source came back `CONSTRAINED`; the rows below are the only paths that set it.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (agent default) | — | — | No `set_result_status` call fires on this path — `catalog` runs, and a `list` run where every source came back `SUPPORTED`/`UNSUPPORTED`. Every per-source outcome, including a degraded one, is also carried in that source's own `source\|` row. |
| `UNAVAILABLE` | `PARTIAL` | `autoruns:exception` | `execute()`'s top-level `catch` — either `catch (const std::exception&)` or `catch (...)` — caught an exception escaping `do_catalog`/`do_list` before any OS-ABI boundary crossing (`autoruns_plugin.cpp:210-219`). No exception may cross the plugin's `extern "C"` boundary, so this is the last-resort backstop, not an expected per-source outcome. |
| `UNAVAILABLE` | `PARTIAL` | `subprocess_runner:spawn_error` | The rung-2 Linux fallback (`systemctl list-timers`, `collect_linux`'s `lnx_systemd_timers_system` branch) could not spawn the child at all, forwarded via `forward_runner_failure` (`autoruns_linux.cpp:941`). |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:deadline` | The same rung-2 fallback's 20s deadline elapsed and the still-running `systemctl` was killed. |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:cancelled` | The same rung-2 fallback's run was cancelled before it finished. |
| `CONSTRAINED` | `PARTIAL` | `subprocess_runner:signaled` | The same rung-2 fallback's `systemctl` child was killed by a signal rather than exiting cleanly. |
| `OK` | `PARTIAL` | `subprocess_runner:line_limit` | The same rung-2 fallback hit the runner's output line cap — a deliberate bounded stop, not a failure; `trim_possibly_truncated_tail` additionally drops a possibly-partial trailing line before parsing (`autoruns_linux.cpp:511-515`). |
| `CONSTRAINED` | `PARTIAL` | `autoruns:degraded` | `do_list` ORs `collect_windows`/`collect_linux`/`collect_macos`'s return values and sets this whenever any source across the three legs emitted `CONSTRAINED` (`autoruns_plugin.cpp:259-266`). On Linux and macOS, three catalog-permanent sources (`lnx_init_d`, `lnx_systemd_timers_user`, `mac_login_items`) are always `CONSTRAINED`, so this status fires on every `list` run on those two platforms regardless of host health — it is NOT by itself evidence of a new degradation there; only Windows's signal varies with live host state. Consult the per-source `source\|` rows for the specific cause on any platform. |

`subprocess_runner:*` is the only subprocess this plugin ever runs anywhere on any OS — the Windows and macOS legs never call `forward_runner_failure` because they never spawn a child process at all.

### Where the data goes

- **Instruction result only.** Every `source|`/`autorun|` row and the command's result status travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`, like any other on-demand plugin dispatch.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing here runs on a schedule; the plugin executes only when an operator, workflow, or MCP client dispatches `crossplatform.autoruns.list` or `crossplatform.autoruns.catalog`.
- **Sensitivity.** `autorun|` rows carry real host paths under a user's profile (`location`/`target` for a per-user Startup-folder entry, a `~/Library/LaunchAgents` plist, or a `/home/<user>/.config/autostart` desktop file) and, on Linux, a numeric `user` uid or, on Windows, the resolved-hive SID — enough to identify a specific account on the device, though never a person's real name directly. `entry`/`target`/`args` name real installed software and real scheduled-task/service names, which is itself an installed-software fingerprint of the endpoint. `signed` is a path judgement only (`apple_system` vs `not_checked`, macOS rows only) — it never reflects a verified code signature, so it must not be read as attesting to a file's trustworthiness.
- **Siblings:** `services.list`/`services.running` and `registry.get_value`/`enumerate_*` cover adjacent but distinct ground — running-service state and arbitrary registry reads respectively — neither is a persistence-source enumerator; `tar.process_tree` and `processes.list` observe what is currently running, not what is configured to start automatically.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.autoruns.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-08 · interactive user (elevated) · leg-hash d105f619923a

```
== action=list
autorun|win_run_hklm|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|SecurityHealth|%windir%\system32\SecurityHealthSystray.exe||unknown|system|-|not_checked|1784160697
autorun|win_run_hklm|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|RtkAudUService|C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf_amd64_c607c18cb15933d8\RtkAudUService64.exe|-background|unknown|system|-|not_checked|1784160697
source|win_run_hklm|supported|2|ok
source|win_runonce_hklm|supported|0|ok
source|win_runonceex_hklm|supported|0|ok
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|Discord|C:\Users\jsmith\AppData\Local\Discord\Update.exe|--processStart Discord.exe|unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|com.poly.lens.client.app|C:\Users\jsmith\AppData\Local\Programs\oz-client\Poly|Lens.exe --openAsHidden|unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|org.whispersystems.signal-desktop|C:\Users\jsmith\AppData\Local\Programs\signal-desktop\Signal.exe|--start-in-tray|unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|Adobe Acrobat Synchronizer|C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe||unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|NordVPN|C:\Program Files\NordVPN\NordVPN.exe|--auto-start|unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|Docker Desktop|C:\Program|Files\Docker\Docker\Docker Desktop.exe|unknown|user|jsmith|not_checked|1787048046
autorun|win_run_hku|1|HKU\S-1-5-21-571721511-16201247-3531262703-1001\Run|electron.app.NordPass|C:\Users\jsmith\AppData\Local\Programs\nordpass\NordPass.exe|"\"--hidden\""|unknown|user|jsmith|not_checked|1787048046
… 12 of 399 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=catalog
catalog|1
source|win_run_hklm|supported|-|declared
source|win_runonce_hklm|supported|-|declared
source|win_runonceex_hklm|supported|-|declared
source|win_run_hku|supported|-|declared
source|win_runonce_hku|supported|-|declared
source|win_startup_approved|supported|-|declared
source|win_winlogon_shell|supported|-|declared
source|win_winlogon_userinit|supported|-|declared
source|win_appinit_dlls|supported|-|declared
source|win_ifeo_debugger|supported|-|declared
source|win_startup_folder_common|supported|-|declared
… 12 of 35 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-08 · euid 501 (jsmith) · leg-hash d105f619923a

```
== action=list
source|win_run_hklm|unsupported|0|foreign_os
source|win_runonce_hklm|unsupported|0|foreign_os
source|win_runonceex_hklm|unsupported|0|foreign_os
source|win_run_hku|unsupported|0|foreign_os
source|win_runonce_hku|unsupported|0|foreign_os
source|win_startup_approved|unsupported|0|foreign_os
source|win_winlogon_shell|unsupported|0|foreign_os
source|win_winlogon_userinit|unsupported|0|foreign_os
source|win_appinit_dlls|unsupported|0|foreign_os
source|win_ifeo_debugger|unsupported|0|foreign_os
source|win_startup_folder_common|unsupported|0|foreign_os
source|win_startup_folder_user|unsupported|0|foreign_os
… 12 of 915 rows shown
[result_status] CONSTRAINED / PARTIAL / autoruns:degraded

== action=catalog
catalog|1
source|win_run_hklm|unsupported|-|declared
source|win_runonce_hklm|unsupported|-|declared
source|win_runonceex_hklm|unsupported|-|declared
source|win_run_hku|unsupported|-|declared
source|win_runonce_hku|unsupported|-|declared
source|win_startup_approved|unsupported|-|declared
source|win_winlogon_shell|unsupported|-|declared
source|win_winlogon_userinit|unsupported|-|declared
source|win_appinit_dlls|unsupported|-|declared
source|win_ifeo_debugger|unsupported|-|declared
source|win_startup_folder_common|unsupported|-|declared
… 12 of 35 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Ubuntu 26.04.1 LTS (x86_64) · bare-metal · 2026-09-10 · euid 1000 · leg-hash d105f619923a

```
== action=catalog
catalog|1
source|win_run_hklm|unsupported|-|declared
source|win_runonce_hklm|unsupported|-|declared
source|win_runonceex_hklm|unsupported|-|declared
source|win_run_hku|unsupported|-|declared
source|win_runonce_hku|unsupported|-|declared
source|win_startup_approved|unsupported|-|declared
source|win_winlogon_shell|unsupported|-|declared
source|win_winlogon_userinit|unsupported|-|declared
source|win_appinit_dlls|unsupported|-|declared
source|win_ifeo_debugger|unsupported|-|declared
source|win_startup_folder_common|unsupported|-|declared
… 12 of 35 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=list
source|win_run_hklm|unsupported|0|foreign_os
source|win_runonce_hklm|unsupported|0|foreign_os
source|win_runonceex_hklm|unsupported|0|foreign_os
source|win_run_hku|unsupported|0|foreign_os
source|win_runonce_hku|unsupported|0|foreign_os
source|win_startup_approved|unsupported|0|foreign_os
source|win_winlogon_shell|unsupported|0|foreign_os
source|win_winlogon_userinit|unsupported|0|foreign_os
source|win_appinit_dlls|unsupported|0|foreign_os
source|win_ifeo_debugger|unsupported|0|foreign_os
source|win_startup_folder_common|unsupported|0|foreign_os
source|win_startup_folder_user|unsupported|0|foreign_os
… 12 of 135 rows shown
[result_status] CONSTRAINED / PARTIAL / autoruns:degraded
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS Login Items has no real read path, by design.** `mac_login_items` always emits `constrained|0|btm_private_database_no_public_api` and zero rows, never a real read attempt — the list lives in a private per-user BTM database with no public API. The only route that exists at all is `osascript` driving System Events, and this leg deliberately does not perform it: zero process spawns anywhere in the macOS leg.
2. **The Linux rung-2 fallback's own code path is unverified on real hardware.** `systemctl list-timers` fires only when systemd is present but all three unit directories (`/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`) are unreadable. No available capture host has produced that state — the real `ubuntu:24.04` container capture has no systemd at all (the tri-state's `absent` branch), so the fallback's parsing (`parse_list_timers_fallback`) is fixture-tested but not yet exercised against a live host.
3. **macOS enablement modelling is file truth, not launchd's live runtime state, and doesn't cover every key.** A plist's own `Disabled` key is read, but `launchctl print-disabled`'s separate override database is never consulted — a job a user has toggled off at runtime, with no `Disabled` key change to the plist itself, still reports `enabled` here (a deliberate divergence from a services-style plugin that does read live launchd state, not an oversight). Separately, `LaunchdFields` (`autoruns_parsers.hpp`) carries no members for `RunAtLoad`, `KeepAlive`, or the `Start`-prefixed keys, so `launchd_row_from_fields` always falls back to `enabled` when `Disabled` is absent regardless of whether any of those keys are present — the `unmodelled` value this schema defines for exactly this "input in a shape not decoded" case never fires on this leg today.
4. **The Linux rung-2 `systemctl` subprocess fallback remains unverified on real hardware.** A real end-to-end `LocalDispatcher` dispatch against the shipped `autoruns.so` on a real Linux host now backs `docs/samples/linux.txt` (2026-09-10) — that gap is closed. But that host's systemd unit directories were all directly readable, so `lnx_systemd_timers_system`'s rung-2 `systemctl list-timers` fallback (via `run_bounded_subprocess`, fires only when systemd is present but every unit directory is unreadable) still has no real-hardware exercise; `parse_list_timers_fallback` remains fixture-tested only.
5. **Windows per-user Startup-folder redirect is resolved against the enumerated profile, not the agent's own environment.** `HKCU\...\Explorer\User Shell Folders\Startup` is populated with a `REG_EXPAND_SZ` value on essentially every Windows profile at creation — redirected or not. `resolve_profile_shell_folder` (`autoruns_parsers.hpp`) expands `%USERPROFILE%`/`%AppData%`/`%LocalAppData%`/`%Username%` tokens against *that profile's own* path/name (never `ExpandEnvironmentStringsW`, which has no notion of a different user's profile), and a small allowlist of genuinely machine-scoped tokens (`SystemDrive`, `SystemRoot`, `windir`, `ProgramData`, `ALLUSERSPROFILE`, `PUBLIC`, `ProgramFiles`, `ProgramFiles(x86)`) via the agent's own environment, since those ARE identical for every user. A token outside that allowlist, or one the lookup can't resolve, reports `constrained` (`startup_redirect_unresolved`) rather than guessing — never a silent, wrong location. Fixed in #4219.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/autoruns/src/autoruns_catalog.hpp` · `agents/plugins/autoruns/src/autoruns_legs.hpp` · `agents/plugins/autoruns/src/autoruns_linux.cpp` · `agents/plugins/autoruns/src/autoruns_macos.cpp` · `agents/plugins/autoruns/src/autoruns_macos.hpp` · `agents/plugins/autoruns/src/autoruns_parsers.hpp` · `agents/plugins/autoruns/src/autoruns_plugin.cpp` · `agents/plugins/autoruns/src/autoruns_win.cpp` · `agents/plugins/autoruns/src/autoruns_win_wmi_join.hpp`
- Definitions: `content/definitions/autoruns.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_autoruns.hpp`
- Tests: `tests/unit/test_autoruns_linux_local.cpp` · `tests/unit/test_autoruns_local_dispatcher.cpp` · `tests/unit/test_autoruns_macos_local.cpp` · `tests/unit/test_autoruns_parsers.cpp` · `tests/unit/test_autoruns_win_local.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
