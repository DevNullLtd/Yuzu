# Timeline Activity Record (TAR)

The TAR plugin continuously captures system state snapshots and records changes as timestamped events in a local SQLite database on each endpoint. It enables retrospective investigation of "what happened on this machine" without requiring pre-configured logging or SIEM integration.

> Engineers maintaining or extending TAR should also read [`docs/tar-implementer.md`](../tar-implementer.md) — it covers the on-disk format, persistence semantics across upgrade/uninstall/reinstall, the post-restart double-capture caveat, and device-impact expectations.

## What TAR captures

TAR monitors these categories of system activity. Processes, network connections, services, user sessions, and device performance are **always-on**. **power** and **removable media** (Wave 6) are the first sources whose configuration ships *enabled* — every source below them is opt-in, and that divergence is deliberate. **Both ship collecting in this release**: **power** (Windows/Linux live subscription; macOS retrospective replay bounded by `power_lookback_seconds`) — an empty `$Power_Live` means no transitions occurred, not that collection has not started; **removable media** (Windows retrospective event-log replay bounded by `removable_lookback_seconds`; Linux/macOS live-only) — an empty `$Removable_Live` means no removable-media activity occurred, not that collection has not started. **usage** (Wave 7) also ships enabled by default alongside them: it derives per-executable run history directly from the always-on `process` source (no separate collector of its own), starting from the first tick after enablement or upgrade — see the `usage_enabled` row below for the access-limitations note. **software**, **ARP**, **DNS**, and **mapped drives** are opt-in (off by default) — software/DNS are Windows-only today (software is machine scope only — ADR-0015 covers ARP/DNS), while **ARP** also runs on Linux (`/proc/net/arp`) and macOS (constrained — a sysctl route-table dump, `entry_type` always reported `unknown`), and **mapdrive** (network-share mappings in both directions, §3.8) also runs on Linux and macOS (constrained on macOS — outbound-live only via `getfsstat`; the username column is always blank, but a credentialed SMB mount source is stored verbatim in `remote_path`; no inbound, no history). Further opt-in and planned sources — per-app performance, module loads, per-connection network quality (`netqual`), and connectivity-transition history (`netconn` — network/Wi-Fi connect/disconnect + internet-capability changes, including a retrospective backfill of OS-retained history from before TAR was enabled; ADR-0020) — are covered under Configuration and the OS compatibility matrix below.

| Category | Collection interval | Events detected |
|----------|-------------------|-----------------|
| **Processes** | **event-driven on Windows** (ETW) **and macOS** (Endpoint Security), gap-free; 60 s poll on Linux | Process started, process stopped |
| **Network connections** | 60 seconds (fast) | Connection opened, connection closed |
| **Services** | 300 seconds (slow) | Service started, stopped, state changed |
| **User sessions** | 300 seconds (slow) | User login, user logout |
| **Software** | 3600 seconds (software) | Application installed, removed, upgraded |
| **Performance** | 30 seconds (perf) | Device CPU/memory/disk/network sample (a scalar reading, not a diff) |
| **ARP** *(opt-in, Windows/Linux/macOS)* | 60 seconds (fast) | ARP / neighbour binding appeared, removed |
| **DNS cache** *(opt-in, Windows)* | 60 seconds (fast) | DNS resolver-cache entry appeared, removed |

Every source except **Performance** and the cursor-model sources (**power**, **removable**, which track a durable log position instead) takes a snapshot of the current state each cycle, compares it to the previous snapshot, and records only the differences as events. This keeps the database compact while providing full visibility into system changes.

The **Software** source diffs the installed-software inventory to record install / uninstall / upgrade events over time — the historical "what was installed or removed on this box, and when" that the point-in-time `installed_apps` inventory cannot answer. On Windows it captures **machine-wide** installs only (the HKLM Uninstall keys, 64-bit and 32-bit) — **machine scope only, no user identity / no PII**. It runs on its own slower trigger (hourly by default — installs are infrequent) and is **off by default** (opt-in): enable it per host with `software_enabled=true` (see `software_enabled` below). The cautious default reflects the posture for a new capture source; the inventory it gathers is asset-management and vulnerability-relevance data with no user identity, like Services and User sessions. It records names, versions, and publisher only — no command lines, no usage data.

The **first run on a host seeds the baseline silently** (it records no events) so an `installed` event always means "installed now", not "was already present when the agent started watching". Linux (dpkg/rpm) and macOS (pkgutil) collectors are planned; the `$Software_*` tables are queryable but stay empty on those platforms until then.

The **Performance** source is different: it is a fixed-cadence *scalar sample*, not an event diff. Each 30-second tick records one row of derived device metrics — CPU busy %, memory used % and commit-charge %, per-IO disk service time (µs) and read/write throughput, and non-loopback network rx/tx throughput. It is collected from raw kernel counters (no PDH, no WMI, no shell-out) and, like all TAR data, **stays on the device** — only aggregates leave the edge. On Windows and Linux it is fully supported (Windows: kernel counters; Linux: procfs); the macOS collector is planned. The first sample after the agent starts is a baseline (it establishes the counter reference and records no row); every subsequent tick records one sample.

## Querying TAR data

### From the Yuzu dashboard

Use the **TAR Query** instruction to search events by time range and type.

### From the REST API

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "query",
  "parameters": {
    "from": "1711000000",
    "to": "1711100000",
    "type": "process",
    "limit": "500"
  }
}
```

### Query parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `from` | No | 0 | Start of time range (Unix epoch seconds) |
| `to` | No | now | End of time range (Unix epoch seconds) |
| `type` | No | all | Filter: `process`, `network`, `service`, or `user` |
| `limit` | No | 1000 | Maximum results (max 10000) |

### Output format

Each event is output as a pipe-delimited line:

```
timestamp|event_type|event_action|snapshot_id|detail_json
```

Example:

```
1711050123|process|started|1711050123001|{"pid":1234,"ppid":1,"name":"nginx","cmdline":"nginx -g daemon off;","user":"www-data"}
1711050123|network|connected|1711050123001|{"proto":"tcp","local_addr":"0.0.0.0","local_port":80,"remote_addr":"10.0.0.5","remote_port":54321,"state":"ESTABLISHED","pid":1234}
1711050423|service|state_changed|1711050423002|{"name":"sshd","display_name":"OpenSSH","status":"stopped","prev_status":"running","startup_type":"automatic","prev_startup_type":"automatic"}
1711050423|user|login|1711050423002|{"user":"admin","domain":"CORP","logon_type":"remote","session_id":"pts/0"}
```

> The `cmdline` field above is shown populated for a **Linux** example. **On Windows (ETW) and macOS, the process feeder is names-only, so `cmdline` is empty** — see the OS compatibility matrix below. On macOS this holds on **both paths**: when the Endpoint Security stream is unavailable the agent falls back to the `KERN_PROC_ALL` sysctl poll, which also blanks `cmdline` (only Linux populates it).

### JSON export

Use the `export` action for JSON output suitable for integration with Splunk, ClickHouse, or ELK:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "export",
  "parameters": { "type": "process", "limit": "100" }
}
```

## Configuration

Use the `configure` action to adjust TAR behavior.

| Setting | Valid range | Default | Description |
|---------|-----------|---------|-------------|
| `retention_days` | 1-365 | 7 | Days to keep events before automatic purge |
| `fast_interval` | 10-3600 | 60 | Seconds between process/network collections |
| `slow_interval` | 30-7200 | 300 | Seconds between service/user collections |
| `software_interval` | `0` or 300-86400 | 3600 | Seconds between software install/uninstall scans. `0` disables the scan trigger entirely (no collection until re-set or agent restart). |
| `redaction_patterns` | JSON array | See below | Patterns for command-line redaction (case-insensitive). **Merged with** the built-in defaults — added to, never replacing them; the defaults cannot be disabled. |
| `process_enabled` | `true` / `false` | `true` | Toggle the process collector on this host |
| `tcp_enabled` | `true` / `false` | `true` | Toggle the network collector on this host |
| `service_enabled` | `true` / `false` | `true` | Toggle the service collector on this host |
| `user_enabled` | `true` / `false` | `true` | Toggle the user-session collector on this host |
| `perf_enabled` | `true` / `false` | `true` | Toggle the device performance sampler on this host |
| `software_enabled` | `true` / `false` | **`false`** | Toggle the software install/uninstall source (`software` → `$Software_*`) on this host. **Off by default** (opt-in) — a cautious posture for a new capture source. On Windows it covers **machine-wide** installs (HKLM) only: **machine scope only, no user identity / no PII** — asset-management and vulnerability-relevance data like Services and User sessions. Set to `true` to opt in. Disabling leaves existing rows queryable. |
| `procperf_enabled` | `true` / `false` | **`false`** | Toggle the per-application top-N sampler on this host. **Off by default** — per-application CPU/working-set reveals which applications run on a device, which is usage-class telemetry under the works-council posture (device-level `perf` carries no per-app identity and stays on by default). Set to `true` to opt in; independent of `perf_enabled`. |
| `netqual_enabled` | `true` / `false` | **`false`** | Toggle the per-connection TCP-quality sampler (`netqual` source → `$NetQual_Live`, plus the per-boot retrospective baseline `$NetQual_Boot`) on this host. **Off by default** — per-connection quality is usage-class telemetry under the works-council posture. Only a coarse destination *class* (`loopback`/`private`/`public`) is stored; raw remote addresses are dropped at the edge and never persisted, and the owning process is recorded as its image name only. Linux, and Windows via TCP ESTATS (ADR-0020) — **Windows needs an elevated agent** (non-elevated records nothing; `tar.status` reports `netqual_capture_method|none`). Set to `true` to opt in; independent of `tcp_enabled`. |
| `netconn_enabled` | `true` / `false` | **`false`** | Toggle the connectivity-transition source (`netconn` → `$NetConn_Live`, ADR-0020). **Off by default** (opt-in). Windows reads the OS-retained NetworkProfile / NCSI / WLAN-AutoConfig event logs, so the FIRST read backfills history from **before TAR was enabled** (or installed) — network connect/disconnect, internet-capability changes, Wi-Fi connect/fail/disconnect with reason codes. Only closed enum tokens and numeric reason codes are stored: **no SSID, BSSID, profile name, interface GUID, or MAC is ever extracted**. Linux/macOS are planned (schema registered, queryable-empty). Set to `true` to opt in. |
| `netconn_lookback_seconds` | integer seconds | **`604800`** (7 days) | How far **before enablement** the `netconn` backfill reads OS-retained connectivity history (ADR-0020 privacy note). Because the *timing* of network/Wi-Fi connect/disconnect events is a presence/working-hours proxy — behavioral data even with SSIDs stripped — enabling `netconn` retroactively ingests a window that predates any monitoring disclosure. Set to **`0`** to disable the retrospective read entirely (the source then records only forward connectivity from the moment it is enabled), for jurisdictions or works-council agreements where pre-notice collection is not permitted. Clamped to `[0, 90 days]`. Applies to the first read after enablement (and after a late enable); once caught up the source reads only forward. |
| `module_enabled` | `true` / `false` | **`false`** | Toggle the image-load / module-stream capture source (`module` source → `$Module_*`). **Off by default** — module-load capture is high-volume usage-class telemetry (every DLL/dylib/`.so` load and driver/kext/kmod load per process, with a code-signing verdict) under the works-council posture. Loaded-image **directories are captured** (the search-order-hijack signal is the path) but the user-profile segment of a path is scrubbed at the edge (`C:\Users\<redacted>\…`); no command line is ever captured. **No data is recorded until a collector for the host's OS ships** — the `$Module_*` tables are queryable but return zero rows until then (M2 Windows ETW, M4/M5 macOS Endpoint Security, M6 Linux auditd; see [`tar-module-loads.md`](../tar-module-loads.md)). Set to `true` to opt in. |
| `arp_enabled` | `true` / `false` | **`false`** | Toggle the ARP / neighbour-table capture source (`arp` source → `$ARP_Live`/`$ARP_Hourly`) on this host (ADR-0015). **Off by default** (opt-in). Captures IP↔MAC bindings per interface for Layer-2 adjacency / ARP-spoofing forensics. Windows (`GetIpNetTable2`, full interface/IP/MAC/entry_type) and Linux (`/proc/net/arp`, same detail) are fully supported; macOS is constrained (`sysctl NET_RT_FLAGS` route-table dump — `entry_type` always reported `unknown`, no interface field). Set to `true` to opt in; collected at `fast_interval`. |
| `power_enabled` | `true` / `false` | **`true`** | Toggle the power capture source (`power` → `$Power_Live`): AC attach/detach and sleep/wake transitions. **On by default** — with `removable`, the first *works-council-class* TAR source to ship enabled. (`process`, `tcp`, `service`, `user` and `perf` have always been on as machine-scope operational telemetry; every source added since 1.5 under the opt-in posture defaults off, and these two are the first of that class to diverge.) The *timing* of sleep/wake and AC events is a presence/working-hours proxy, so the same works-council posture as `netconn` applies: set `power_lookback_seconds=0` for forward-only collection where a retrospective read is not lawful. |
| `power_lookback_seconds` | `0` or up to 7776000 (90 days) | 604800 | How far back the first macOS read replays OS-retained power history (Windows/Linux ignore this key — they are live subscriptions with no history API). **`0` = forward-only** — the control to use where retrospective collection is not lawful; a value that cannot be read is treated as `0`, never as the default. |
| `removable_enabled` | `true` / `false` | **`true`** | Toggle the removable-media capture source (`removable` → `$Removable_Live`): USB/removable attach and detach with device identity, plus executed-from-removable evidence. **On by default** — see `power_enabled` above for what "first" does and does not mean here. Records vendor/product/serial and executed-binary paths, which is identity/usage-class data under the works-council posture. |
| `removable_lookback_seconds` | `0` or up to 7776000 (90 days) | 604800 | How far back the first Windows read backfills OS-retained removable history (Linux/macOS ignore this key — they are live-only, no history API). **`0` = forward-only** — a value that cannot be read is treated as `0`, never as the default. |
| `usage_enabled` | `true` / `false` | **`true`** | Toggle the derived app-usage fold (`usage` source → `$Usage_Live`/`$Usage_Daily`): pairs `process_live` started/stopped events into per-executable runs (`run_usage_fold`, no collector of its own — see `tar-implementer.md` §8). **On by default** — joining `power`/`removable` as a works-council-class source that ships enabled (see the note above for what "first" does and does not mean here). What a device runs and when is a presence/working-hours proxy even though `usage` carries no user column of its own (open runs record a `user` field, folded into a `distinct_users` count on write). Coverage begins once the source reaches its `Active` lifecycle state after enablement or upgrade — strictly forward-only, never a retrospective fold over history that accrued before that point. Set to `false` to opt out; disabling freezes retention rather than accelerating it (like every other TAR source, #539), and existing `usage_daily`/`usage_daily_user`/`usage_live` rows stay queryable until they age out on their own schedules (31-day `usage_daily`/`usage_daily_user`; the fold's own 20000-run open-run cap on `usage_live`). **Access posture (enforced): `usage_live`/`usage_daily`/`usage_daily_user` are queryable ONLY through the Forensics-gated `app_usage` reads**, never through the generic `tar.sql` action — `tar.sql` (`Infrastructure:Read`) denies all three tables (direct name, `$Usage_*` placeholder, alias, or JOIN/subquery), matching the posture this section already documents for `tar_events`. `usage_enabled` and the `tar.status` usage counters are unaffected by this — they report on the fold regardless of how (or whether) the data is subsequently read (issue #4260). |
| `dns_enabled` | `true` / `false` | **`false`** | Toggle the DNS resolver-cache capture source (`dns` source → `$DNS_Live`/`$DNS_Hourly`) on this host (ADR-0015). **Off by default** — the DNS cache reveals which domains a host resolved (**usage-class telemetry under the works-council posture; enabling is audited**). **Device-level state only — no per-process attribution** (the cache carries no PID). **Windows only today** (`DnsGetCacheDataTable`, cache-only — never issues a wire query); Linux/macOS planned. Set to `true` to opt in; collected at `fast_interval`. |
| `mapdrive_enabled` | `true` / `false` | **`false`** | Toggle the mapped-drive capture source (`mapdrive` source → `$MapDrive_Live`/`$MapDrive_Hourly`) on this host (capability-map §3.8). **Off by default** — rows expose usernames and remote share paths (**identity/usage-class telemetry under the works-council posture; enabling is audited**). Records network-share mappings in **both** directions (`direction` column): **outbound** (drives this host maps to remote shares) and **inbound** (remote hosts mapping this host's shares — the lateral-movement signal). Windows + Linux fully; macOS is constrained — outbound live only via `getfsstat` (the username column is always blank, but a credentialed SMB mount source is stored verbatim in `remote_path`; no inbound, no history: honestly out of reach for an unprivileged agent). Inbound needs local-admin/Server-Operator on Windows and Samba on Linux, degrading to empty otherwise. Collected at `slow_interval`. **A one-time historical backfill** seeds *previously* mapped drives (from the registry / fstab / event logs) as `origin='historical'` rows — it runs at agent init, so it materializes on the **first agent restart after you enable this**. Set to `true` to opt in. |
| `perf_interval_seconds` | ≥ 1 | 30 | Seconds between performance samples (device **and** per-app, when each is enabled — they share the tick). `0` disables registration of the perf trigger entirely. **Read at agent startup (trigger registration), not via `tar.configure`** — change it through the agent's KV config / install profile; a running agent picks it up on restart. (To stop perf collection at runtime without a restart, use `perf_enabled=false`.) |
| `network_capture_method` | `polling` (always accepted) plus the methods accepted on the **running host's OS** — e.g. `iphlpapi` on Windows, `procfs` on Linux, `proc_pidfdinfo` on macOS (run `compatibility` for the live list) | `polling` | Network capture mechanism. `polling` is the platform default — the only mechanism actually wired today. Other values are accepted for pre-staging when the corresponding kernel-event collector lands; the agent emits a `warn` line and continues polling. Methods from a *different* OS are rejected. The `status` action reports `network_capture_method_effective` alongside the configured value so the configured-vs-active discrepancy is always explicit. |
| `process_stabilization_exclusions` | JSON array (≤256 × ≤256 chars) | `[]` | Process-name **substrings** (case-insensitive; leading/trailing `*` stripped; `?` and `[abc]` are literals; effective substring must be ≥3 chars) to drop before diffing. Useful for noisy short-lived helpers (CI runners, IDE indexers) that dwarf real activity. **Trade-off: forensic completeness is reduced — anything matching these patterns is invisible to TAR.** |

**Validation rules:**

- When both `fast_interval` and `slow_interval` are provided, `fast_interval` must be less than `slow_interval`.
- `redaction_patterns` and `process_stabilization_exclusions` must each be a JSON array of non-empty strings, with at most **256 elements** of at most **256 characters** each (both feed an O(patterns × command-line-length) scan per process per cycle).
- `process_stabilization_exclusions` matching is **case-insensitive substring**, not real glob. Leading and trailing `*` are stripped; `?` and `[abc]` are treated as literals. The **effective substring** (after stripping `*`) must be at least **3 characters** — a shorter one (e.g. `"a"`, or `"*a*"`, which strips to `"a"`) would match almost every process and is **rejected**. Use a longer substring (`"-helper"`, `"chrome-helper"`). Matching is on the **process name only**, so a binary renamed to contain an approved substring evades capture — exclusions are a noise-reduction convenience, **not a threat-hunting control**.
- `network_capture_method` is validated against the **running host's OS** accept-list, not the union across all platforms — e.g. a Linux agent rejects the Windows-only `iphlpapi`. `polling` is always accepted (the platform default). Run the `compatibility` action to see the live accepted list for a given agent.
- Disabling a collector (`<source>_enabled=false`) **atomically** stops new captures — the disable runs under the collection lock, so an in-flight cycle either completes before the stop takes effect or observes the disabled flag and skips (no extra snapshot slips through). Existing rows remain queryable. On re-enable the source starts from a **clean baseline**: the snapshot-diff state is cleared on disable, so the first collection cycle after re-enable emits a `started` event for every entity currently running/open (an expected one-time rebaseline, not a real-time burst) and **never** ghost `stopped` events for entities that exited during the pause. If the agent database is momentarily busy and the baseline cannot be cleared, the disable is **refused** — the source stays enabled and `configure` returns an error — so a disabled source can never be left with a stale baseline; retry the disable.
  - The interval samplers (`perf` and the opt-in `procperf`) report the **delta** between consecutive readings rather than started/stopped events, and keep that previous reading in memory. Disabling them resets that in-memory baseline under the same collection lock, and the sampler re-checks the disabled flag after taking the lock — so disabling them is equally atomic, and the **first** sample after a re-enable establishes a fresh baseline rather than reporting one row whose averaged rate covers the entire paused window. This matters most for `procperf` (per-application CPU/memory), which is off by default for privacy: no usage row ever spans the period it was disabled.

Example:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "retention_days": "14",
    "fast_interval": "30",
    "user_enabled": "false",
    "process_stabilization_exclusions": "[\"*-helper*\",\"*ide-language-server*\"]"
  }
}
```

## OS compatibility matrix

TAR runs on Windows, Linux, and macOS, but each capture source has platform-specific constraints. Run the `compatibility` action to print the live matrix from the agent itself; the table below is a snapshot for documentation purposes.

| Source | Windows | Linux | macOS |
|--------|---------|-------|-------|
| **process** | supported (`etw`) — `Microsoft-Windows-Kernel-Process` real-time session: **gap-free** start/stop (catches short-lived processes the poll misses), exact timestamps + exit code. **Names only — no command line** (the start event carries none; aligns with the privacy posture). Owning user resolved from the SID at start (empty for processes that exit faster than ETW's ~1s buffer flush — the same limit the poll has). Falls back to the `toolhelp32` poll if the ETW session cannot start. **Boot gap:** processes that start *and* exit before the agent's live session opens are backfilled from a boot **AutoLogger** (a circular, FlushTimer-enabled Kernel-Process `.etl` configured by the InnoSetup installer and `install-agent-user.ps1`, started by the kernel early each boot); the agent reads it directly at startup for events before the live session began (no session stop / no elevation — read access only), de-duplicated per boot. Takes effect from the next boot after install. Boot-window events are **names-only with no user** (the start event carries no user SID — precise attribution would need the Security-Auditing 4688 provider); if the AutoLogger isn't configured, that narrow window is simply not captured. | supported (`procfs`) — `/proc/<pid>/status` and `/proc/<pid>/cmdline`. | constrained (`endpoint_security`) — Endpoint Security `NOTIFY_EXEC`/`NOTIFY_EXIT` stream: **gap-free** start/stop, full image path, accurate ppid, owning user from the audit token. **Names only — no command line** (parity with the Windows ETW posture). Requires a build with the ES SDK present (shipped in both the Command Line Tools and full Xcode SDKs — "needs full Xcode" is a myth; a build-probe defect currently prevents the real client from compiling on any SDK, tracked separately), the `com.apple.developer.endpoint-security.client` entitlement, and root. Falls back to the `KERN_PROC_ALL` sysctl poll when the stream is unavailable (ES SDK not detected at build time, missing entitlement, or non-root) — **the poll is also names-only** (it blanks the `proc_pidpath` image it would otherwise place in `cmdline`), so macOS process rows carry no command line on either path. **Boot gap** (as on Windows): processes alive before the agent's session opens get no `started` row — macOS has no AutoLogger-equivalent backfill. **Not active in current shipped builds** — the Apple entitlement + notarized release pipeline are pending (#1455), so macOS agents poll until then; check `process_capture_method` in `tar.status` to see the live path. |
| **tcp** | supported (`iphlpapi`) — `GetExtendedTcpTable` polled at `fast_interval`. ETW (`Microsoft-Windows-Kernel-Network`) is **planned** for sub-second fidelity; not yet wired. | supported (`procfs`) — `/proc/net/{tcp,tcp6,udp,udp6}`. Connection lifetime below `fast_interval` may be missed. | constrained (`proc_pidfdinfo` + `nstat`) — `proc_listallpids` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` via `libproc` remains the fallback/seed poll (same TOCTOU caveat: short-lived sockets that close before the per-fd query may produce empty rows). Connection **lifecycle is event-driven** via the same `nstat` kernel-control client that serves netqual: `SRC_ADDED`/`SRC_REMOVED` messages fire on open/close. **Not Endpoint Security** — ES has no TCP/socket event notifications, only process exec/exit. |
| **service** | supported (`scm`) — `EnumServicesStatusEx` / `QueryServiceConfig`; full status + startup_type. | constrained (`systemctl`) — `systemctl list-units`; `startup_type` reported as `unknown`. Hosts without systemd (Alpine sysvinit, OpenRC) are unsupported. | constrained (`launchctl`) — `launchctl list`; no startup_type, status binary running/stopped only. |
| **user** | supported (`wts`) — `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW`; interactive, RDP, console. Server Core 2008 R2 minimal installs lack Terminal Services. | constrained (`utmp`) — `getutent`. Containers without `/var/run/utmp` produce no events. `logon_type` inferred from tty (`pts/*` → remote). | constrained (`utmpx`) — `getutxent`. GUI logins are not always reflected. |
| **perf** | supported (`ntcounters`) — `GetSystemTimes`, `GlobalMemoryStatusEx`/`GetPerformanceInfo`, `IOCTL_DISK_PERFORMANCE`, `GetIfTable2`. No PDH, no WMI, no shell-out. Some virtual disks do not answer `IOCTL_DISK_PERFORMANCE` — disk columns read 0 there. | supported (`procfs`) — `/proc/stat`, `/proc/meminfo` (`MemAvailable`), `/proc/diskstats` (whole disks only, fixed 512-byte ABI sectors), `/proc/net/dev` (loopback excluded). No shell-out. `commit_pct` reads 0 under `vm.overcommit_memory=1` (CommitLimit is advisory there); a host with no recognised whole-disk device (some containers) reads 0 in the disk columns — same per-domain degrade as a Windows virtual disk. **Containerized agents report host-wide readings** (`/proc/stat`, `/proc/meminfo` and the CPU count are not cgroup-scoped), so a cgroup-throttled workload can look idle in device perf — run the agent on the host for container fleets. | planned (`host_statistics`) — `host_processor_info` / `host_statistics64` + IOKit. Records nothing until wired. |
| **procperf** | supported (`ntsysinfo`), **opt-in (off by default)** — one `NtQuerySystemInformation(SystemProcessInformation)` snapshot per tick: image name, CPU times, working set for every process. No PDH, no WMI, no per-process handles. Records image **names only — never command lines**; redaction patterns apply to the name (as bare case-insensitive substrings — a pattern meant for a command-line argument can match an image name, so over-matching drops a process from the warehouse entirely). | supported (`procfs`), **opt-in (off by default)** — one `/proc/<pid>/stat` read per process per tick: comm, utime+stime, rss, starttime; no ptrace, no per-process handles. Kernel threads (e.g. `kworker/*`) are included, matching Windows recording the `System` process — they are kernel scheduling infrastructure, not user-app usage, and rss 0 keeps them out of the working-set top-N; one appears in the CPU top-N only when genuinely hot. Names are the kernel's **15-character comm** (at most 15 characters before escaping — `\` and newline are stored kernel-escaped) — the same value the process source records, so procperf rows join `$Process_Live` by name. **Redaction here is best-effort against the 15-byte comm, not a guarantee:** a pattern only redacts reliably when its sensitive substring is a **≤15-byte, prefix-aligned** slice of the comm — the kernel truncates the name to 15 bytes, so a token that falls past byte 15 (`averylongprefix_leak` → comm `averylongprefix`) is physically gone and cannot be matched, and a Windows-style core like `outlook.exe` does not match the extension-less comm `outlook`. As a partial mitigation a pattern core longer than 15 bytes is also matched by its 15-byte prefix, which only ever *adds* redaction (and can over-suppress an unrelated same-prefix app — e.g. `SensitiveApp` also hides `SensitiveAppliance`). Write Linux patterns as ≤15-byte prefix-aligned comm fragments, and treat comm redaction as reducing — not eliminating — per-app exposure; the durable fix (matching a fuller name source than the 15-byte comm) is a tracked follow-up. `version` is always `""` (on-disk version capture is a follow-up). | planned (`libproc`) — `proc_pid_rusage`/`proc_taskinfo`. Records nothing until wired. |
| **module** | planned (`etw`), **opt-in (off by default)** — `Microsoft-Windows-Kernel-Process` image-load events with the code-signing verdict resolved at drain. **Schema registered + queryable now (M1); records nothing until the collector ships (M2).** | planned (`auditd`) — kernel-module loads via `init_module`/`finit_module` (M6). Records nothing until wired. | planned (`endpoint_security`) — `NOTIFY_KEXTLOAD`/`KEXTUNLOAD` + dylibs (M4/M5). Records nothing until wired. |
| **power** | supported (`powerbroadcast`) — suspend/resume + AC transitions via `PowerRegisterSuspendResumeNotification`/`PowerSettingRegisterNotification`; a live subscription, so no history before the agent starts (or before it was last unarmed — a disabled window or restart is reported as an explicit `capture_gap`, never silently backfilled). | supported (`logind`) — systemd-logind `PrepareForSleep` over sd-bus plus power-supply sysfs; live-only, gated on the optional libsystemd dependency (unarmed without it — reported, not silent). | supported (`pmset_log`) — `pmset -g log` retrospective replay, the only leg with real history, bounded by `power_lookback_seconds` (default 7 days; `0` = forward-only). **On by default.** |
| **removable** | supported (`wevtapi`) — OS event log, so this leg has real retained history bounded by `removable_lookback_seconds`. | supported (`udev_netlink`) — udev netlink subscription; live-only, no history. | supported (`diskarbitration`) — DiskArbitration attach/detach callbacks plus a `getfsstat` baseline; live-only, no history API. **On by default.** |
| **software** | supported (`registry`), **opt-in (off by default)** — diffs the registry Uninstall keys on the `tar.software` tick: HKLM 64-bit + WOW6432Node 32-bit (**machine scope only, no user identity / no PII**). `SystemComponent` entries (canonically a `REG_DWORD` set to a non-zero value) are excluded — system components and OS patches are not reported as installed software; names, versions, and publisher only. First run seeds the baseline silently. | planned (`dpkg_rpm`) — dpkg/rpm/pacman diff. Records nothing until wired. | planned (`pkgutil`) — `system_profiler` + pkgutil diff. Records nothing until wired. |
| **arp** | supported (`iphlpapi`), **opt-in (off by default)** — `GetIpNetTable2(AF_UNSPEC)`: ARP + IPv6 neighbour cache; full interface/IP/MAC/entry_type (ADR-0015). | supported (`procfs`), **opt-in (off by default)** — `/proc/net/arp`: IP/MAC/interface, `entry_type` (static/dynamic/incomplete/other) mapped from the Flags column. Capped at 2048 live entries. | constrained (`route_sysctl`), **opt-in (off by default)** — reuses the shared `NET_RT_FLAGS`/`RTF_LLINFO` routing-socket dump; MAC available, `entry_type` always `unknown` (this source distinguishes neither static/permanent nor dynamic/stale/probe entries), no interface field. Capped at 2048 live entries. |
| **dns** | supported (`dnsapi`), **opt-in (off by default)** — `DnsGetCacheDataTable` + cache-only `DnsQuery_W`: name/record_type/data/TTL (ADR-0015). Device-level resolver-cache state; **no per-process attribution**. | planned (`systemd-resolved`) — resolve1 D-Bus / `/etc/hosts` fallback (constrained). Records nothing until wired. | planned (`dscacheutil`) — subprocess; TTL unavailable (`ttl_remaining_s = -1`, constrained). Records nothing until wired. |
| **netqual** *(opt-in)* | constrained (`estats`) — TCP ESTATS (`GetPerTcpConnectionEStats`) per ESTABLISHED connection (ADR-0020). **Requires an elevated agent**: enabling per-connection stats is admin-only, so a non-elevated agent records nothing and `tar.status` reports `netqual_capture_method=none`. RTT is **ms-resolution** (sub-ms LAN RTTs read 0); `retrans`/`segs_out` count **since stats-enable**, not connection start; `lost`/`ca_state` are delta-derived approximations of the Linux gauges. The per-boot `$NetQual_Boot` baseline (since-boot OS counters) is captured non-elevated. | supported (`inetdiag`) — netlink `SOCK_DIAG`/`INET_DIAG` `TCP_INFO`, joined to the owning process by 4-tuple. | constrained (`nstat`) — per-socket `tcp_connection_info` read from the private `com.apple.network.statistics` kernel control (no framework, no entitlement). **Requires root for system-wide flow visibility**: an unprivileged agent sees only its own process's flows, so it records nothing and `tar.status` reports `netqual_capture_method=none` (mirrors the Windows admin-only posture). RTT is **already microsecond-resolution** (no `*1000` conversion needed, unlike Windows ms). `lost` is a **per-tick delta**, like Windows — nstat exposes cumulative `rxretransmit`/`txretransmit`, not an instantaneous loss gauge. `retrans`/`segs_out` are cumulative-since-flow-open context. The struct layout is private/version-unstable; a runtime self-check falls back to `capture_method=none` on mismatch rather than emit wrong values (`docs/darwin-compat.md`). Behavior pending validation on real hardware. |
| **netconn** *(opt-in)* | supported (`wevtapi`) — `EvtQuery` over the OS-retained NetworkProfile / NCSI / WLAN-AutoConfig operational channels (ADR-0020): network connect/disconnect, internet-capability changes, Wi-Fi connect/fail/disconnect + reason codes. The first read **backfills history from before TAR (or the agent) existed** — reach is bounded by `netconn_lookback_seconds` (default 7 days; 0 disables retrospective reads). **Only closed enum tokens + numeric reason codes are stored — no SSID, BSSID, profile name, interface GUID, or MAC.** A missing channel (Server SKU without WLAN) or an ACL-denied channel is skipped (warned once). | planned (`journald`) — NetworkManager/systemd-networkd transitions. Records nothing until wired. | planned (`oslog`) — configd/Wi-Fi subsystem transitions. Records nothing until wired. |
| **mapdrive** | supported (`wnet`/`netapi32`/`registry`), **opt-in (off by default)** — both directions (§3.8). Outbound live `WNetEnumResourceW`; outbound history registry `Network`/MRU/`MountPoints2` across offline profiles — reads each logged-out profile's registry hive, mounting it offline via the same ladder `registry.get_user_value` uses (#2771), capped at 512 profiles like every other consumer of that ladder (a host with more loses outbound history for the profiles past the cap, logged once, not per profile). This is part of the **one-time historical backfill** (§3.8, `mapdrive_enabled` row below) — it runs once, at init, gated by a durable `mapdrive_backfill_done` key, not on a recurring cadence; enabling mapdrive means one pass over every logged-out profile's `NTUSER.DAT` on the first agent (re)start after enabling, not an ongoing background job. Inbound live `NetSessionEnum` (needs local-admin/Server-Operator, degrades to empty); inbound history Security log 4624 network logons. | constrained (`procfs`) — outbound live `/proc/mounts` (no username) + history `/etc/fstab` (ts=0); inbound `smbstatus` + `/var/log/samba` connect logs, both requiring Samba (empty otherwise). | constrained (`getfsstat`) — outbound live only: `getfsstat(2)` mount table filtered to `{nfs, smbfs, cifs, afpfs, webdav}`; the username **column** is always blank (getfsstat exposes no separate credential field), but a credentialed SMB mount source (e.g. `//alice@host/share`) is stored verbatim in `remote_path`, so the account name can still be recovered from there even though the username column is empty — unlike Linux, whose `/proc/mounts` device string never carries a username. No inbound (no `smbutil` integration) and no history (`getfsstat` exposes only the current mount table). |

Status values:

- **supported** — fully wired and exercised in CI.
- **constrained** — works but with a documented limitation.
- **planned** — not yet implemented; `network_capture_method` accepts the value so you can pre-stage configuration.
- **unsupported** — platform cannot supply the data at all (e.g., `service` on a kernel without a service manager).

To get the matrix at runtime (returns one `row|...` line per source/OS pair):

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "compatibility"
}
```

## Security: command-line redaction

TAR automatically redacts sensitive command-line arguments before storing process events. Any command line matching a redaction pattern has its `cmdline` field replaced with `[REDACTED by TAR]`.

> **Windows + macOS (stream) scope.** On Windows the process source is the ETW Kernel-Process feeder; on macOS with the Endpoint Security stream active it is likewise names-only — both capture **image names only, never a command line**. The `cmdline` column is therefore empty for those process rows, and these redaction patterns have **no effect on them** (there is nothing to redact). They still apply to **per-app perf** rows (`procperf`, matched against the image *name*) on all platforms and to **Linux** process command lines (always poll-captured). On Linux, procperf redaction is **best-effort against the kernel's 15-byte comm** — reliable only for a pattern whose sensitive substring is a ≤15-byte, prefix-aligned slice of the comm; a token past byte 15 is truncated away and cannot be matched, and a Windows-style core like `outlook.exe` does not match the extension-less comm `outlook` (see the procperf row in the OS compatibility matrix for the full rules and the over-suppression caveat). Patterns are matched in the **stored, sanitized** spelling: `|` and control bytes are stored as `_` and `\`/newline as `\\`/`\n`, and the operator's pattern is put through that same transform before matching, so `*evil|app*` correctly redacts a process that named itself `evil|app`. Redaction is a **`cmdline` + per-app-perf control only**: it never applies to the process source's `name` column or to netqual owner-process names — an app redacted out of `$ProcPerf_*`/`app_perf` still appears by name in `$Process_Live` (and `$NetQual_Live` if enabled), on every OS. **macOS is names-only on both paths** (ES stream and sysctl poll), so these patterns have nothing to redact there either. If your threat model depends on never storing command-line secrets on Windows/macOS, both the streaming feeder and the macOS poll guarantee that structurally.

Default redaction patterns:

```json
["*password*", "*secret*", "*token*", "*api_key*", "*credential*"]
```

Patterns use case-insensitive substring matching. Leading and trailing `*` are **optional** — they are stripped before matching, so the effective match is always a bare substring (`*password*`, `password*`, and `password` all match any command line containing "password" in any case). Interior `?` and `[abc]` are treated as literals, not glob metacharacters.

**The built-in default patterns always apply and cannot be disabled.** `configure` lets you **add** patterns, but the baseline set (`password`, `secret`, `token`, `api_key`, `credential`) is enforced on every collect path regardless of what is stored. If `redaction_patterns` is set to an array whose elements are all invalid (over-long, non-string) or to `[]`, the built-in defaults are silently restored as the active list rather than leaving redaction disabled — so a corrupt, tampered, or empty config can never cause secrets to be written in plaintext.

To customize:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "redaction_patterns": "[\"*password*\",\"*secret*\",\"*token*\",\"*private_key*\"]"
  }
}
```

## Checking TAR status

The `status` action returns database health information:

```
storage_state|ok
db_health|ok|0
record_count|15234
oldest_timestamp|1710950000
newest_timestamp|1711050423
db_size_bytes|2097152
retention_days|7
config|process_enabled|true
config|process_paused_at|0
config|process_live_rows|18402
config|process_oldest_ts|1710950000
config|tcp_enabled|true
config|tcp_paused_at|0
config|tcp_live_rows|4193
config|tcp_oldest_ts|1710955000
config|service_enabled|true
config|service_paused_at|0
config|service_live_rows|812
config|service_oldest_ts|1710901000
config|user_enabled|true
config|user_paused_at|0
config|user_live_rows|97
config|user_oldest_ts|1710900100
config|module_enabled|false
config|module_paused_at|0
config|module_live_rows|0
config|module_oldest_ts|0
config|software_enabled|false
config|software_paused_at|0
config|software_live_rows|0
config|software_oldest_ts|0
config|arp_enabled|false
config|arp_paused_at|0
config|arp_live_rows|0
config|arp_oldest_ts|0
config|dns_enabled|false
config|dns_paused_at|0
config|dns_live_rows|0
config|dns_oldest_ts|0
retention_guard_declines_total|0
retention_guard_failures_total|0
config|network_capture_method|polling
config|network_capture_method_effective|polling
config|software_interval_seconds|3600
config|software_last_run_ts|1711050000
config|perf_capture_method|procfs
config|procperf_procs_seen|412
config|process_last_status|events_recorded
config|process_consecutive_failures|0
config|process_last_status_at|1711050400
config|tcp_last_status|events_recorded
config|tcp_consecutive_failures|0
config|tcp_last_status_at|1711050400
```

(The sample is abbreviated: `<source>_last_status`, `<source>_consecutive_failures`
and `<source>_last_status_at` appear once per capture source, in registry order.)

**Database health (`db_health`).** `db_health|ok|<epoch>` reports the epoch of
the last tar.db quarantine ever recorded on the device (`0` = never);
`db_health|quarantined|<epoch>` is reported only by the agent process whose
startup quarantined a corrupt database (see "Corrupt-database quarantine" below).
The fact is persisted in `tar_config` (`db_health_last_quarantine_epoch` /
`db_health_last_quarantine_file`, basename only), so it survives restarts.

**Per-source health.** `<source>_last_status` is the terminal outcome token of
the source's most recent collection (`never_ran` until it has run in this agent
process), `<source>_consecutive_failures` counts back-to-back failures, and
`<source>_last_status_at` is the epoch of that outcome (`0` if never). The failure
tokens are `capture_incomplete`, `counters_unavailable`, `cursor_lost`,
`state_unreadable`, `insert_failed` and `state_save_failed`; every other token
(including `source_disabled`, `unsupported_platform` and baseline resets) resets
the streak. The ledger is **process memory only**: an agent restart resets every
source to `never_ran` / `0`, which is not a recovery. When one source hits a fatal
early return in a tick, the sources after it do not run that tick, so read
`<source>_last_status_at` to spot a source that is frozen by an upstream failure
rather than healthy. `perf_capture_method` is the registry capture method for the
running OS (`procfs` on Linux, `ntcounters` on Windows, `none` where there is no
perf collector), and `procperf_procs_seen` is the process count in the last valid
per-process counter snapshot.

**Write failures.** Snapshot-diff sources (`process`, `tcp`, `service`, `user`,
`software`, `arp`, `dns`, `mapdrive`) commit a tick's events and their baseline in
one transaction, so a failed save can never leave events durable against a stale
baseline. When a tick that had events fails, the collector emits
`error|<source> insert failed`; when only a baseline-only save fails (no events
in the diff, the process fallback seed) it emits
`error|<source> state_save_failed`; the software cold-start seed reports on the
software collector's own line, `tar|collect_software|0|state_save_failed`. Either way nothing was persisted and the
next tick re-derives the same delta. `arp`, `dns` and `mapdrive` are non-fatal:
they emit no `error|` line and record the token in the ledger instead.

A block is emitted for every capture source. The opt-in sources report
`<source>_enabled|false` on a fresh agent — `module`, `software` (both shown
above), `procperf`, `netqual`, `netconn`, `arp`, `dns`, and `mapdrive` are off by
default and must be enabled explicitly via `configure` (see the configuration
table above). `netqual_capture_method` reports the per-connection quality
mechanism actually in effect — `inetdiag` (Linux), `estats` (Windows once the
elevation gate has latched active), `estats_pending` (Windows, netqual enabled
but the first collect tick has not yet tested elevation — or netqual is off), or
`none` (Windows non-elevated after the access-denied latch, macOS) — so "opted in
but the agent can't collect" is distinguishable from "off", and a non-elevated
agent never briefly advertises `estats` before flipping to `none`. The
default-ON sources — `process`, `tcp`, `service`, `user`, and `perf` — report
`<source>_enabled|true`. `module_live_rows` stays `0` until a collector for the
host's OS ships; likewise `dns` is **Windows-only today** (planned on
Linux/macOS), so on a Linux or macOS agent `dns_enabled|true` still reports
`dns_live_rows|0`. `arp` is wired on every OS (Linux via `/proc/net/arp`; macOS
constrained via the `NET_RT_FLAGS` sysctl route dump — `entry_type` always
`unknown` there), so `arp_enabled|true` reports real rows there — run the
`compatibility` action to distinguish a supported-but-empty source from a
planned-but-unimplemented one.
`software_last_run_ts` is the wall-clock of the last `collect_software` tick (`0`
if it has not run yet); it is the heartbeat that distinguishes "healthy but no
software changed" (where `software_live_rows` stays low) from "the hourly trigger
never fired".

A `<source>_enabled` value can also read `errored` — automation that scrapes
this output should match three values, not two:

```
config|process_enabled|errored
```

`errored` means the stored value is not the literal `true`/`false` the agent
ever writes (corruption or tampering); the source is fail-closed until it is
re-`configure`d. See the tri-state description below.

`retention_guard_declines_total` counts retention passes this agent declined
(see [The retention clock guard](#the-retention-clock-guard) for the four
triggers and which of them are benign), and
`retention_guard_failures_total` counts tables that
could not be retained at all -- whether the probes could not be read or the
delete itself failed (see "The retention clock guard" below). Both
are always emitted. **Read them together**: a zero declines total only means the
clock is behaving if the failures total is also zero -- a table whose probes fail
every pass has silently stopped being retained, and would otherwise report as
healthy. When either is non-zero, one extra line per affected warehouse table
names the table and its own count:

```
retention_guard|process_hourly|3
retention_guard|tcp_hourly|3
retention_guard_failed|module_hourly|2
retention_guard_failed|__clock_state__|1
retention_guard_declines_total|6
retention_guard_failures_total|2
```

Only tables with a non-zero count appear, so a healthy agent emits just the two
totals. `__clock_state__` is not a table: it reports that the agent could not
persist its own clock reading, which leaves the guard without a comparison point
after the next restart. `__implausible_now__` is also not a table: it reports
that the clock reading **handed to a pass** (not the stored comparison point)
was too far ahead to trust, so the whole pass declined before touching any
table -- see "The retention clock guard" below. The per-table counters are in-memory and reset when the agent restarts
(the clock reading they compare against is persisted, so restarting does not
blind the guard). Scrape this across the fleet to find endpoints whose clocks
need attention -- the agent has no `/metrics` endpoint, so this action is the
fleet-readable signal. The retention-guard counters are **not yet fleet-aggregated**: there is no shipped
instruction or heartbeat tag that rolls these up server-side; surfacing them via
the agent heartbeat is a tracked follow-up. (tar.db corruption, by contrast, is fleet-visible: see "Corrupt-database quarantine" below.)

The four `<source>_*` blocks are emitted per capture source. `<source>_enabled` is one of three values: `true` (collector active), `false` (disabled via `configure`), or `errored`. `errored` means the stored value is not a recognised boolean — `configure` only ever writes `true`/`false`, so an `errored` value indicates the agent's `tar.db` was tampered with or was corrupt and re-initialised (see "Corrupt-database quarantine" below). While an `errored` value persists the agent applies a **fail-closed policy**: the affected source stops collecting (it is treated as `false`, not enabled) and retention skips pruning that source's rows, so any forensic data already captured is preserved. The source stays paused until you re-issue an explicit `configure` for it on that device to clear the value. `<source>_paused_at` is `0` when the source has never been disabled and the wall-clock UTC seconds when it was last transitioned `enabled → disabled`. The reverse transition resets it to `0` — and this includes recovery from `errored`: issuing `configure <source>_enabled=true` on a source whose stored value is `errored` clears `paused_at` to `0` in the same transition, so a recovered source never reports `enabled=true` alongside a stale paused timestamp. `<source>_live_rows` and `<source>_oldest_ts` are the count and minimum timestamp of the per-source `*_live` table at the moment of the status call. Agents older than v0.12.0 do not emit the per-source `paused_at` / `live_rows` / `oldest_ts` lines. In the retention-paused list the dashboard renders a "schema older than server" badge for such an agent's disabled source (and sorts it as the oldest, at the top of the list) rather than hiding it behind a bare `—`; elsewhere a missing `live_rows` / `oldest_ts` still renders `—`.

### Corrupt-database quarantine

When an agent's `tar.db` fails its `PRAGMA integrity_check` at startup, the agent quarantines the corrupt file rather than trusting it: the database and its `-wal`/`-shm` sidecars are renamed aside to `tar.db.corrupt-<epoch>` (etc.) in the same directory, a fresh empty database is initialised in its place, and the agent logs `tar.db.corruption_detected`. `tar.db.corruption_detected` is an agent-local log line (`spdlog`, error level); the quarantine itself reaches the server as a `tar.db.corruption_quarantined` audit row via the heartbeat — see "Fleet visibility" below. Consequences an operator should know:

- **All TAR history on that device is reset** — the new database is empty; prior events live only in the `.corrupt-<epoch>` sidecar.
- **Per-source enable/disable state is reset to defaults** — a source previously paused for forensic preservation is collecting again. After the agent recovers, re-issue any required `configure` toggles, and `status` may briefly show `errored` for a source whose value could not be read.
- **The quarantined file is not auto-deleted.** Recover data from `tar.db.corrupt-<epoch>` before the new database's retention overwrites the device's storage budget — e.g. `sqlite3 tar.db.corrupt-<epoch> ".recover" | sqlite3 recovered.db`, or open it read-only with any SQLite tool — then remove the sidecar manually once recovered. Repeated corruption produces multiple timestamped quarantine files; none are pruned automatically, so an agent with a recurring storage fault can accumulate them — watch the data dir's footprint.

**Fleet visibility.** A quarantine is reported off-device: the tar plugin
publishes `heartbeat.db_corruption_total` (cumulative per agent, monotonic) and
`heartbeat.db_quarantine_last` (`<epoch>:<file>`) in its plugin storage, which the
agent forwards on every heartbeat as `yuzu.plugin.tar.db_corruption_total` /
`yuzu.plugin.tar.db_quarantine_last`. The server exposes
`yuzu_fleet_tar_db_corruption_agents` (see the metrics reference) and writes one
`tar.db.corruption_quarantined` audit row per quarantine. A plugin that failed to
initialise (including TAR when the corrupt file cannot be moved aside) is reported
in the `yuzu.plugins_failed` heartbeat tag and `yuzu_fleet_plugin_init_failed{plugin}`,
which distinguishes "failed to load" from "not installed". The plugin keeps its
count in a private storage record; if that record is present but unreadable the
plugin logs `TAR: db_health.ledger unreadable; not overwriting` and stops updating
the two heartbeat keys rather than resetting the count — `status` still reports
`db_health`, and the agent log carries the warning on every collect_slow tick.

If `tar.db` is corrupt **and** cannot be moved aside (read-only mount, locked file, permissions), the agent fails closed — it refuses to load TAR rather than silently trusting the corrupt database — and logs the reason. Other agent plugins continue running; only TAR is unavailable on that device until the underlying fault is cleared and the agent restarted.

`network_capture_method` is the **configured** value (which may be a value pre-staged ahead of a forthcoming kernel-event collector, or a cross-OS platform API); `network_capture_method_effective` is the mechanism **actually collecting**, which is always `polling` today — no kernel-event collector is wired yet, so every configured value currently collects via polling. The two are reported side by side so `status` can never misrepresent the active capture mechanism to a forensic analyst.

## TAR dashboard page

The Yuzu dashboard includes a dedicated TAR page at `/tar`, reachable from the **TAR** entry in the main navigation bar (visible after authentication). The page is the central operator surface for TAR across the fleet. Phase 15.A delivers the retention-paused source list as the first frame; the scope-walking-aware SQL frame and the process tree viewer drop into placeholder slots in subsequent phases.

### Retention-paused source list

The first frame surfaces every device × source pair where the collector has been disabled (`<source>_enabled=false`). Rows are sorted paused-longest-first so devices accumulating non-aging data the longest float to the top of the list.

**Columns:** device hostname, source pill, paused since (UTC), paused for (coarse age), live rows count, oldest data age.

**Row states.** Beyond a normal paused row (with a timestamp), the table surfaces two conditions and floats both to the top of the list so they aren't missed:

- **"schema older than server" badge** — the agent reported the source disabled but sent no `paused_at` timestamp, i.e. it is a pre-v0.12.0 agent that lacks the field. The row sorts as the oldest entry. **Action:** upgrade the agent so it records the transition time.
- **"value error" badge** — the agent reported a `<source>_enabled` value other than `true`/`false` (e.g. `errored`, or garbage from a corrupt or tampered `tar.db`); the reported value is shown. Previously such a source was silently omitted, hiding a paused/broken collector. **Action:** re-configure the source (`tar.configure <source>_enabled=true`) or inspect the agent's `tar.db`; if tampering is suspected, treat the device as potentially compromised.

**Workflow:**

1. Click **Scan fleet** to dispatch a `tar.status` command to the agents in your management-group scope. The scan-provenance header above the table reports how many agents were dispatched to, how many have responded so far, and how many have all sources collecting normally.
2. Review the table. A row with a high `live_rows` count or a long pause duration may indicate forensic data accumulating without being queried.
3. Click **Re-enable** on a row to dispatch `tar.configure` with `<source>_enabled=true` to that single device. The row drops optimistically; click **Refresh** to reconcile against a fresh scan.
4. Click **Purge data** on a row to **permanently drop** all of that source's stored rows (`<source>_{live,hourly,daily,monthly}`) **without** re-enabling the collector — for "we've preserved what we need; reclaim the disk but keep collection paused." Because this is irreversible you must **type the device hostname** to confirm. The source stays paused and the row remains (with a "Purge dispatched" note); click **Scan fleet** to see the counts drop to zero. If the source was re-enabled since your last scan the agent refuses the purge (`source_not_paused`) and nothing is deleted.

**Purge is destructive and irreversible.** It drops rows for the named source on the named device only — other sources and other devices are untouched. The typed-hostname confirmation is your last checkpoint; there is no undo.

**Permissions:**

- Viewing the page and the retention-paused list requires `Infrastructure:Read`.
- **Scan fleet** requires `Execution:Execute` (it dispatches a fleet-wide command).
- **Re-enable** requires `Execution:Execute` (it dispatches a configure command to a single device).
- **Purge data** requires `Infrastructure:Delete` — a **higher** tier than Re-enable, because it is destructive. It is management-group scope-checked like Re-enable (out-of-scope `device_id` collapses to the same 404). The "only purge a paused source" rule is enforced **on the agent** (it refuses with `source_not_paused` if the source is enabled), so a source re-enabled between your scan and the purge is never dropped. Requires an agent that supports the `tar.purge_source` action (v0.14.0+); an older agent silently no-ops the purge — verify with a fresh **Scan fleet**.
- The per-device **Re-enable** and **Purge data** endpoints are management-group scope-checked — it rejects out-of-scope `device_id` values with the same 404 response as a not-connected agent (no enumeration oracle). The **Scan dispatch and the rendered list**, however, currently gate only on the *global* `Execution:Execute` / `Infrastructure:Read` permission: management-group confinement of these **list/fan-out** views is **not yet effective** (tracked as the ADR-0017 admit-then-filter gate) — under RBAC a confined operator is denied at the global gate rather than shown a narrowed list. When RBAC is **disabled** (the default), reads return the full enrolled fleet; when RBAC is **enabled**, list views require the global permission and per-device routes additionally enforce your management-group role assignments.

**State persistence:** Scan results are held in the server's memory keyed by your username. Restarting the server clears the last-scan reference; click **Scan fleet** again after a restart. Persistence across restarts and multi-server coordination are planned for Phase 15.G operational hardening.

**Audit trail:** Every Scan emits a `tar.status.scan` audit event. Every Re-enable emits `tar.source.reenable` (with `result=success` and `detail` carrying `device_id` and `source` on success, or `result=failure` with `detail` carrying the real reason — `scope_violation` or `agent_not_connected` — on rejected attempts). Every **Purge data** emits `tar.source.purge` (same detail shape; `result=denied` if the `Infrastructure:Delete` permission is missing). Because purge dispatch is fire-and-forget, the number of rows deleted is recorded in the command's **response record**, not the dispatch audit row. See `docs/user-manual/audit-log.md` for the full schema.

### Process tree viewer

The third frame on the `/tar` page reconstructs a **per-host process tree** entirely from that host's local TAR warehouse (`$Process_Live` + `$TCP_Live`) — no extra data is collected, and no other host is involved.

**Workflow:**

1. **Pick a live host** from the dropdown (only connected agents in your scope are listed). Selecting one reconstructs the default **Last 10m** window.
2. **Choose a timescale** — the preset chips **On boot · On agent install · Last minute · Last 10m · Last hour · Last day**, or type a **custom From/To (UTC)** range and click **Apply**. Setting From == To gives a true point-in-time tree.
3. **Read the tree.** Each row shows a running/exited dot, PID, name, owning user, and — when the process has connections — an inline network summary of remote `IP:port` endpoints (public/internet egress is highlighted). Dozens of identical-name siblings (e.g. `svchost.exe`) collapse into one `name ×N` row you can expand.
4. **Click any process** to open the **detail panel on the right**: path, command line, user, start time, full connection list, and any anomaly evidence.
5. **Filter** with the toolbar: **All / Running / Exited**, an **Anomalies only** toggle, and a text box that matches name, PID, or remote IP. Filters combine and apply instantly (no reload).

**What "anomalies" means here:** the viewer flags **suspicious parent→child spawns** — a common-document or browser application (Word, Excel, Outlook, Chrome, Edge, …) launching a shell or LOLBin (`powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, …). This is computed on the server from the TAR data; it is heuristic, name-based, and deliberately conservative.

**Honest limitations:**

- **No seed.** The tree is replayed from the retained `$Process_Live` events only. A process whose `started` event has aged out of the live-tier cap (or that started before the oldest retained row) may not appear; the banner states the observation window.
- **`On boot` / `On agent install` are proxies.** TAR stores no boot or install timestamp, so these anchors are derived from the retained events (install ≈ oldest retained row; boot ≈ the most recent root-process start).
- **Windows is names-only.** On Windows the process feeder is ETW (Kernel-Process), which captures image **names only** — so per-process **path and command line are blank** on Windows (they are populated on Linux/macOS). Loaded libraries/DLLs are not captured by TAR on any platform.

**Permissions:** viewing the frame requires `Infrastructure:Read`. Reconstructing a tree dispatches a read-only `tar.sql` to the device, so it additionally requires `Execution:Execute` and the device must be inside your management scope. The access is audited as `tar.process_tree.read` — once when the query is dispatched (recorded even if the device is offline) and again on a successful reconstruction (recording the time window, node/anomaly counts, the OS data-class, and whether connection data was shown). The device is the audit event's target.

## Forcing an immediate snapshot

The `snapshot` action triggers an immediate full collection of all **enabled** capture sources (including opt-in `arp`/`dns` when on), useful before a maintenance window or at the start of an investigation:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "snapshot"
}
```

**Partial captures never fabricate events.** If a subprocess-backed leg (`systemctl`/`launchctl`/`smbstatus`/`journalctl`/`wevtutil`) or a procfs/`getfsstat` read fails or is truncated mid-capture, that tick's diff is skipped and the prior baseline is retained — no appeared/removed events are fabricated from a partial read. A rate-limited warning is logged and the source's `<source>_last_status` reads `capture_incomplete` with `<source>_consecutive_failures` counting the streak in `tar.status`.

## Performance impact

TAR is designed for minimal performance overhead:

- **Fast collection** (processes + network): typically completes in under 100ms
- **Slow collection** (services + users): typically completes in under 200ms
- **Performance sampling**: a handful of kernel-counter reads every 30s; one row written per sample. The `$Perf_Live` 7-day window holds ~20,000 rows (~1-2 MB) per endpoint at the default cadence.
- **Database size**: varies by system activity; a typical endpoint generates 1-5 MB per day (plus the ~1-2 MB perf window)
- **CPU**: negligible between collection cycles; brief spike during snapshot + diff
- **Automatic purge**: old events are removed on the rollup tick (every 900 s).
  Each tier's window comes from the schema registry's per-granularity default,
  **not** from the `retention_days` configure key -- that key is stored and
  reported by `status` but is not what the warehouse tiers prune against.

### The retention clock guard

Time-based retention deletes rows older than `now - <tier retention>`, where
`now` is read from the **endpoint's own clock** -- the clock in a fleet most
likely to be wrong. A dead CMOS battery, a long suspend, a cloned VM, or a boot
before NTP converges all produce a reading that marks every row in a warehouse
table expired at once, and an unguarded delete then takes the whole forensic
window with it.

A retention pass first refuses to act at all if the clock reading **handed to
it** is implausible (too far ahead to be trusted into arithmetic) -- the whole
pass declines before anything is persisted or any table is examined, and
retention resumes once a sane reading arrives.

Per table, the pass then either declines (deletes nothing from that table,
counts the decline) or proceeds, based on the same **fact set** each time --
the combination of which of these four conditions hold for this table on
this pass:

  1. it would delete **every** datable row of that table;
  2. more than **a fixed 30 days** elapsed since the previous pass;
  3. the stored reading is **ahead** of the current clock;
  4. there is **no stored reading at all** -- the first pass after an agent
     upgrade or a restore.

  A table declines whenever this pass's fact set **differs from what was last
  reported** for it. An **identical repeat** is a suppressed, capped drain, so
  a warehouse that is legitimately all-expired still ages out -- at the cost
  of one rollup tick (900 s) per distinct anomaly, not one per pass. A
  **different** anomaly arriving while one is still being worked off (e.g. the
  table starts wiping while a corrupt-reading decline is still active) reports
  again rather than deleting silently. Trigger 4 is the one exception: it is
  never recorded, so a table that keeps failing to persist its own comparison
  point declines **every** pass rather than being suppressed after the first --
  a missing comparison point is not an anomaly whose fact set can safely repeat
  unreported.

  **What to do:** for 4, nothing. The reading is a single `tar_config` key
  shared by every source and table, so it is expected once per agent -- but note
  EVERY enabled time-based table declines in that one pass, so the total jumps
  by the table count, not by 1. It recurs only if the agent cannot WRITE that
  key at all (read-only or full disk), which is the safe direction and is what
  `retention_guard_failures_total` is for. For 2 and 3, check the endpoint's
  clock and its uptime; see
  [the runbook](../ops-runbooks/audit-store-clock-guard.md) for the audit twin
  of this triage.

  The 30 days is **absolute, not derived from the tier's retention window**: how
  far the clock moved has nothing to do with how long that tier keeps rows, and
  scaling it to the window put the threshold at a year on the monthly tier,
  where it could never fire. Elapsed time cannot tell a jump from a dark laptop,
  so the threshold sits past the point where an outage is itself remarkable -- a
  laptop off over a long weekend reports nothing; one off for a month declines
  one tick. The reading is persisted in `tar_config`, so trigger 2 still fires
  on the first pass after an agent restart, including one that *booted* with a
  wrong RTC.
- **Every accepted pass deletes at most 5,000 rows per table**, oldest first
  (~480k/day/table at the 900 s cadence, far above any endpoint's growth rate).
  A wipe the guard chose to allow ages out at a paced rate rather than in one
  statement.
- Rows timestamped implausibly far in the future -- more than a day ahead, i.e.
  written while the clock was already skewed forward -- are excluded from the
  "would this delete everything?" question. Without that, one such row would
  disarm the guard permanently.

**Row-count retention is deliberately unguarded, but it is capped.** The tiers
that trim to a fixed row ceiling do so with no clock involved, so no clock
reading can make them delete more than they always would -- hence no guard and
no decline. They ARE capped at the same 5,000 rows per table per pass, for a
different reason: the whole retention batch runs under one held database lock,
and an uncapped prune over a large excess would stall every collector on the
endpoint. A big backlog now drains over a few rollup ticks instead.

**A paused or errored source is skipped before the guard is consulted**, so it
neither deletes nor records a decline -- an operator who paused a source for
forensics never sees a clock-anomaly signal from it.

**What this does and does not promise.** The cap is the half that always
applies: it bounds every delete unconditionally. The detectors are best-effort,
and the outcome test in particular is defeated by any row written after the
clock moved -- which `do_rollup` reliably produces, since `run_aggregation` runs
first and mints rows into the very tables retention then reads. That is why the
elapsed-time check is persisted. Taken together the guard converts an
instantaneous wipe of the device's forensic window into a paced one plus a
counter; it does not guarantee every clock anomaly is detected, and a
persistently wrong clock will still drain the window over several ticks.

The operator surface is `retention_guard_declines_total` and
`retention_guard_failures_total` (plus the per-table `retention_guard|<table>|<n>`
and `retention_guard_failed|<table>|<n>` lines) in the `status` action, described
above. A non-zero declines total has four possible causes, listed in
[The retention clock guard](#the-retention-clock-guard). One of them is benign
and expected after an agent upgrade; the rest mean the endpoint's clock moved,
it was dark longer than the threshold, or the stored reading was ahead of the
clock. Elapsed time cannot separate those, so check the host's time
synchronisation *and* its uptime history. A non-zero failures total means retention has stopped for that table
for a reason that is not the clock: either its probes could not be read, or its
delete failed. What happens to the REST of the pass depends on the error. One
that aborts the transaction itself (a disk-full, an I/O error) rolls the whole
pass back, and every table queued in it is reported -- including row-count
tables, which are otherwise outside the guard. An error that leaves the
transaction intact -- one table with a corrupt index, say -- fails only that
table, and the healthy tables in the same pass still have their deletions
committed. That distinction exists because stopping on every error meant one
permanently-broken table halted retention for the whole endpoint, for ever.

If that rollback ITSELF fails and the database is left inside the transaction,
the agent **closes the TAR database**. Every later write on a connection stuck in
an uncommittable transaction would be reported durable and then lost at restart,
so it fails all of them closed instead. `tar status` then returns non-zero and
emits an `error|` line followed by `storage_state|offline`, and nothing else --
every `config|` line is withheld. Collection and retention are both stopped on
that endpoint until the agent restarts. **Historical data normally stays
readable**: the close affects only the read-write connection, so `tar sql` can
still query what was already collected. The error line says which of those two
cases you are in -- the read-only connection is itself optional at open time, and
on the rare endpoint where it never opened, `tar sql` cannot read the history
either, so the line says that instead of promising a read path that is not there.
This needs a disk-level fault to reach, but read `storage_state` before trusting
any other line in that output.

In the dashboard, the capture-sources frame surfaces that error line verbatim
rather than a generic failure, so the reason and the recovery advice reach the
operator on the frame they opened to ask why the device's data is missing.

**Known dead band.** Because the threshold is a fixed 30 days, a forward clock
error smaller than that trips neither detector on a table whose own window is
shorter:
the step check is below its floor, and the outcome test is separately defeated
by the rollup minting fresh rows before retention runs. In that band the table
drains at the capped rate with no decline and no counter. The cap still bounds
the damage; the detection does not fire. This is the deliberate cost of not
reporting every switched-off laptop as a clock anomaly. Retention resumes automatically, paced, once the
condition clears.

> **Upgrade note (device perf sampling; per-app sampling is opt-in).** On
> upgrade to this release, every Windows agent continues **device** performance
> sampling (`perf_enabled` defaults to `true`, 30-second cadence — unchanged
> from the prior release). **Linux agents BEGIN device performance sampling on
> upgrade to this release**: the Linux `perf` collector (procfs) is new, and
> because `perf_enabled` is default-ON, `$Perf_Live` rows start accruing on
> Linux hosts at the same 30-second cadence with no operator action — a real,
> operator-visible data-collection change on Linux fleets (set
> `perf_enabled=false` per host to opt out; the data is device-level with no
> user identity, the same class as the Windows rows). **Per-application**
> sampling (`procperf_enabled`, now implemented on Windows and Linux) is
> a new, distinct telemetry category — per-app CPU/working-set by image name —
> and ships **off by default**: it is not collected until an operator opts in,
> because it is usage-class data subject to works-council/DPA review (see
> `docs/enterprise-readiness-soc2-first-customer.md`). To enable it, set
> `procperf_enabled=true` via the `configure` action (fleet-wide or per-device).
> The same applies to `netqual_enabled` (per-connection TCP quality, Linux +
> Windows) and `module_enabled` (image-load capture) — both ship **off by
> default**. On
> upgrade to this release `tar.status` now correctly reports these opt-in
> sources as `<source>_enabled|false` on an agent that has never set them (a
> previous release misreported them as `true` even though nothing was being
> collected); if you parse `tar.status` to inventory active sources, expect
> `module_enabled`, `procperf_enabled`, and `netqual_enabled` to read `false`
> unless you have explicitly opted in. No data collection changes on upgrade
> from these opt-in sources (the one collection change this release does make
> is Linux device perf starting automatically — see the start of this note).
> Warehouse tables added by a new release are now created on every database open
> (previously a pre-existing `tar.db` missed tables introduced after it was
> first created), so no manual table-creation step is needed on upgrade.
>
> **`arp_enabled` / `dns_enabled` are new this release (ADR-0015) and also ship
> off by default.** Expect both to read `false` in `tar.status` on upgrade; the
> new `$ARP_*` / `$DNS_*` warehouse tables are created automatically and stay
> empty until you opt in. **ARP now collects on Windows, Linux, and macOS as of
> this release** (previously Windows-only) — if you already set
> `arp_enabled=true` fleet-wide (e.g. while only Windows agents could collect),
> upgrading Linux/macOS agents starts them collecting neighbour IP/MAC records
> (plus interface on Linux; macOS has no interface field) at the next
> `fast_interval` tick, with no separate notice. Set
> `arp_enabled=false` before upgrading any endpoint where that new collection
> is not yet approved, then re-enable once it is. DNS remains Windows-only, so
> there is no DNS collection change on upgrade. **GUI note:** after enabling a source
> (Capture-sources frame or `configure`), the first rows appear at the next
> `fast_interval` tick (default 60 s) — an empty panel immediately after enabling
> is expected, not a fault.

> **Upgrade note (new `software` source — OFF by default).** This
> release adds the `software` install/uninstall source, which ships **off by
> default** (opt-in) — a cautious posture for a new capture source. On Windows it
> captures **machine-wide** inventory (HKLM Uninstall —
> asset-management / vulnerability-relevance data, **machine scope only, with no
> user identity / no PII**, like Services and User sessions). On upgrade,
> `tar.status` gains a `config|software_*`
> block per agent (Windows: live values; Linux/macOS: zero rows, collector planned)
> **plus** the global `software_interval_seconds` and `software_last_run_ts`
> lines. **Automation
> that parses `tar.status` by field count or terminal-field detection must be
> updated** to tolerate these additional lines. The source is **off by default**,
> so opt in per host with `software_enabled=true`. See
> `docs/enterprise-readiness-soc2-first-customer.md` for the data-handling
> classification.

> **Upgrade note (Windows process capture → ETW). BREAKING for `cmdline`
> consumers.** On upgrade, the Windows process source switches from the
> 60-second snapshot-diff poll to an event-driven ETW Kernel-Process feeder.
> Three operator-visible changes:
> - **`cmdline` is now empty for Windows process rows** (the feeder is
>   names-only). Any dashboard, SIEM export, or Guardian rule that relied on the
>   Windows process command line will see an empty field after upgrade. **Linux is
>   unchanged** (the poll still captures command lines there). **macOS is now
>   names-only on both paths** — the Endpoint Security stream and the sysctl poll —
>   so `cmdline` is empty there too (the poll blanks the `proc_pidpath` image it
>   would otherwise store). This is intentional (works-council / data-minimization
>   posture) and not reversible by configuration — see the redaction section.
> - **Live capture is active from the next agent start** — gap-free during the
>   live session, so short-lived processes the poll missed now appear, and
>   `$Process_Live` holds more rows (cap raised to 100000). (One narrow seam: at
>   the boot→live handoff, events in the window between the agent sampling its
>   boot/live boundary and the live provider becoming active can fall in neither
>   the backfill nor the live stream — tracked as a follow-up.) If the ETW session
>   cannot start, the agent
>   logs the reason and falls back to the `toolhelp32` poll automatically; if the
>   session later dies it self-heals to the poll. On Windows the death signal is
>   immediate (the ETW `ProcessTrace` returns). On **macOS** the Endpoint Security
>   client exposes no liveness API, so the agent treats a prolonged TOTAL silence
>   (no exec/exit for ~1h) as presumed-dead and re-arms the poll then — the
>   threshold is deliberately long because a NOTIFY-only client cannot distinguish a
>   dead stream from a legitimately quiet host, and a false trip drops a healthy
>   stream to the inferior poll. The active path is reported by the `status` action
>   as `process_capture_method` (`etw` or `polling` on Windows; `endpoint_security`
>   or `polling` on macOS). Once it has fallen back to the poll, stream capture is
>   **not** re-established until the agent restarts (so `process_capture_method=polling`
>   on a host that should be streaming indicates a prior session failure — restart
>   the agent to retry). Two drop counters: `process_stream_dropped` is the
>   **userspace ring-overflow** count (the drain tick fell behind; renamed from
>   `process_etw_dropped` this release, now cross-platform), and
>   `process_stream_kernel_dropped` is the **kernel/provider-side** drop count
>   (Endpoint Security `seq_num` gaps on macOS; 0 on Windows ETW, which exposes no
>   per-message sequence here).
> - **macOS parity gap (fork-without-exec).** The Endpoint Security stream
>   subscribes `NOTIFY_EXEC`/`NOTIFY_EXIT` only, so a child that forks but never
>   execs is invisible until it exits (Windows ETW fires on every process create).
>   Capturing it via `NOTIFY_FORK` is deferred (#1455) — adding it naively would
>   double-count the overwhelmingly common fork→exec case.
> - **Boot-window backfill requires the boot AutoLogger**, configured by the
>   production InnoSetup installer (scoped to the `advanced` component that ships
>   `tar.dll`) and by the developer install path (`install-agent-user.ps1`). A
>   **reboot is required** for the AutoLogger to take effect: on a fresh install,
>   or when upgrading from a release that did not configure it, boot-window
>   backfill (the narrow window of processes that start *and* exit before the
>   agent's session opens) is absent until after the next reboot. A minimal
>   install that omits the `advanced` component does not configure the
>   AutoLogger. Boot-window events are names-only with **no user**.
>
> To disable Windows process capture entirely (ETW and poll), set
> `process_enabled=false` via `configure`; there is no separate "disable ETW but
> keep polling" switch today. While disabled, the live ETW session keeps running
> but its buffered events are drained-and-discarded each cycle, so no process
> activity from the paused window is persisted when you re-enable. As with every
> snapshot-diff source, re-enabling `process_enabled` clears the stored baseline,
> so the first cycle after re-enable does not emit ghost `stopped` events for
> processes that exited during the pause (it re-bases on the live process set).
- **WAL mode**: SQLite Write-Ahead Logging ensures reads never block writes

## Warehouse Query System

TAR includes a typed data warehouse that replaces the legacy flat `tar_events` table with structured, tiered tables optimized for different query time horizons.

### Warehouse tables

Table names use `$`-prefixed identifiers (e.g., `$Process_Live`) which the agent translates to real SQLite table names at execution time. Each capture source has multiple granularity tiers:

| Source | Live | Hourly | Daily | Monthly |
|--------|:----:|:------:|:-----:|:-------:|
| **Process** | `$Process_Live` (100000 rows) | `$Process_Hourly` (24h) | `$Process_Daily` (31d) | `$Process_Monthly` (12mo) |
| **TCP** | `$TCP_Live` (5000 rows) | `$TCP_Hourly` (24h) | `$TCP_Daily` (31d) | `$TCP_Monthly` (12mo) |
| **Service** | `$Service_Live` (5000 rows) | `$Service_Hourly` (24h) | -- | -- |
| **User** | `$User_Live` (5000 rows) | -- | `$User_Daily` (31d) | -- |
| **Power** | `$Power_Live` (20000 rows) | -- | -- | -- |
| **Removable** | `$Removable_Live` (20000 rows) | -- | -- | -- |
| **Perf** | `$Perf_Live` (7d, time-based) | `$Perf_Hourly` (31d) | -- | -- |
| **ProcPerf** | `$ProcPerf_Live` (7d, time-based) | `$ProcPerf_Hourly` (31d, per app) | -- | -- |
| **Module** | `$Module_Live` (100000 rows) | `$Module_Hourly` (24h) | `$Module_Daily` (31d) | `$Module_Monthly` (12mo) |
| **Software** | `$Software_Live` (5000 rows) | -- | `$Software_Daily` (31d) | `$Software_Monthly` (12mo) |
| **ARP** *(opt-in)* | `$ARP_Live` (5000 rows) | `$ARP_Hourly` (24h) | — | — |
| **DNS** *(opt-in)* | `$DNS_Live` (5000 rows) | `$DNS_Hourly` (24h) | — | — |
| **NetQual** *(opt-in)* | `$NetQual_Live` (100000 rows) | — | — | — |
| **NetQual boot** *(opt-in)* | `$NetQual_Boot` (400 rows — one per boot) | — | — | — |
| **NetConn** *(opt-in)* | `$NetConn_Live` (20000 rows) | — | — | — |
| **MapDrive** *(opt-in)* | `$MapDrive_Live` (5000 rows) | `$MapDrive_Hourly` (24h) | — | — |

The `$Module_*` tables are **registered and queryable now (M1), but empty** — they return zero rows until the OS-specific collector ships (M2 Windows ETW, M4/M5 macOS Endpoint Security, M6 Linux auditd) and `module_enabled=true` is set. See [`tar-module-loads.md`](../tar-module-loads.md) for the ladder.

The `$Software_*` tables are populated on **Windows** when the source is enabled (off by default — opt in with `software_enabled=true`); on **Linux/macOS** they are registered and queryable but empty until those collectors ship.

- **Live** tables hold the most recent raw events with a row cap (oldest rows are evicted): **5000 rows** for TCP / Service / User, and **100000 rows for `$Process_Live`** — raised because the Windows ETW feeder is event-driven (every start/stop, including short-lived processes) and fills a 5000-row window far faster than the old 60-second poll did, so a larger raw window keeps a meaningful history before rows roll up into the hourly/daily/monthly count tiers. **Exception: `$Perf_Live` and `$ProcPerf_Live` are time-based (7 days), not row-capped** — a fixed-cadence sampler keeps a *time window*, so raising `perf_interval_seconds` must not shrink the history it covers.
- **Hourly** tables aggregate counts and summaries per hour, retained for 24 hours (perf/procperf hourly: 31 days).
- **Daily** tables aggregate per day, retained for 31 days.
- **Monthly** tables aggregate per month, retained for 12 months.
- Service only has live and hourly tiers. User only has live and daily tiers. Perf and ProcPerf have live and hourly tiers. Software has live, daily, and monthly tiers (no hourly — installs are infrequent).

### Key columns by table type

**Process tables:** `ts`, `name`, `pid`, `ppid`, `cmdline`, `user`, `action` (started/stopped). Aggregated tiers add `start_count`, `stop_count`. **`cmdline` is empty on Windows (ETW) and on macOS** (names-only feeders — see the OS compatibility matrix and the command-line redaction section); it is populated on **Linux only**. macOS is names-only on **both** paths (the Endpoint Security stream and the sysctl-poll fallback).

**TCP tables:** `ts`, `process_name`, `pid`, `remote_addr`, `remote_port`, `local_port`, `proto`, `state`. Aggregated tiers add `connect_count`.

**Service tables:** `ts`, `name`, `status`, `prev_status`, `action` (started/stopped/state_changed). Hourly tier adds `change_count`.

**User tables:** `ts`, `user`, `domain`, `logon_type`, `action` (login/logout). Daily tier adds `login_count`.

**Perf tables:** `ts`, `cpu_pct`, `mem_used_pct`, `commit_pct`, `disk_read_bps`, `disk_write_bps`, `disk_read_lat_us`, `disk_write_lat_us`, `net_rx_bps`, `net_tx_bps` (all numeric; rates are bytes/sec, latencies are µs per I/O). `$Perf_Hourly` carries per-hour `samples`, `cpu_avg`/`cpu_max`, `mem_avg`/`mem_max`, `commit_avg`, and avg/max throughput and latency columns. Collection is trigger-driven (`tar.collect_perf`, every `perf_interval_seconds`), so the audit trail for perf is the `configure` action that enables/paces it, not a per-sample dispatch record.

**`collect_perf` status tokens.** `sample_recorded`, `baseline` (first tick after start), `source_disabled`, `unsupported_platform` (no perf collector for this OS: macOS today) and `counters_unavailable` (the OS has a perf collector but the counter read failed; the same token is used for `procperf`).

**ProcPerf tables:** `ts`, `name` (image name only — **never a command line**), `instances`, `cpu_pct`, `ws_bytes`. Each tick records the **top 10 applications by CPU plus the top 10 by working set** (union, ≤ 20 rows), aggregated across same-name processes (`instances` = how many). `cpu_pct` is the app's share of *total machine capacity* — one saturated core on an 8-core box reads 12.5, matching `$Perf_Live` and Task Manager. `$ProcPerf_Hourly` aggregates per `(hour, name)`: `samples`, `instances_max`, `cpu_avg`/`cpu_max`, `ws_avg_bytes`/`ws_max_bytes`. Apps matching a redaction pattern are never recorded. Example — yesterday's CPU-hungriest apps on a device:

```sql
SELECT name, MAX(cpu_max) AS peak, AVG(cpu_avg) AS typical
FROM $ProcPerf_Hourly GROUP BY name ORDER BY peak DESC LIMIT 10
```

**Software tables:** `$Software_Live` carries `ts`, `snapshot_id`, `action` (installed/removed/upgraded), `name`, `version`, `prev_version` (populated only for `upgraded`), `publisher`, `install_date` — **machine scope only, no user identity / no PII**. The daily/monthly tiers carry `day_ts` (or `month_ts`), `name`, `install_count`, `remove_count`, `upgrade_count`. Example — everything installed or removed on a device in the last 30 days:

```sql
SELECT ts, action, name, version, prev_version, publisher
FROM $Software_Live
WHERE action IN ('installed','removed','upgraded')
ORDER BY ts DESC
```

**NetQual tables** *(opt-in, ADR-0020)*: `$NetQual_Live` carries `ts`, `snapshot_id`, `proto` (tcp/tcp6), `remote_bucket` (the **only** destination field — a coarse class: `loopback`/`private`/`public`/`unknown`; the raw address is never stored), `process_name` (image name only), `rtt_us`, `rtt_var_us` (jitter), `lost` (current-conditions loss gauge — the sort key), `retrans`, `segs_out`, `ca_state` (0=Open … 4=Loss). `$NetQual_Boot` is the per-boot retrospective baseline: `ts` (agent start), `snapshot_id`, `boot_ts`, `window_s` (the pre-TAR window length this boot), `retrans_segs`, `segs_out`, `estab_resets` (since-boot TCP totals), and `if_in_errors`/`if_in_discards`/`if_out_errors`/`if_out_discards`/`if_in_octets`/`if_out_octets` (non-loopback interface totals). Since-boot totals are coarse **context**, never a current-loss verdict.

**NetConn table** *(opt-in, ADR-0020)*: `$NetConn_Live` carries `ts` (the **event's** own timestamp — backfilled rows predate TAR), `snapshot_id`, `action` (`connected`/`disconnected`/`wifi_connected`/`wifi_connect_failed`/`wifi_disconnected`/`capability_changed`), `channel` (`networkprofile`/`ncsi`/`wlan`), `category` (`public`/`private`/`domain`, or empty), `capability` (`none`/`local`/`internet`, or empty), `iface_kind` (`wifi` or empty), `reason_code` (WLAN disconnect/fail reason or NCSI change reason). Every text column is a closed enum token — **no SSID, BSSID, profile name, GUID, or MAC is ever stored**. Example — connectivity/Wi-Fi drops on a device, including before TAR was enabled:

```sql
SELECT ts, action, channel, capability, reason_code
FROM $NetConn_Live
WHERE action IN ('disconnected','wifi_disconnected','wifi_connect_failed','capability_changed')
ORDER BY ts DESC
```

**MapDrive tables** *(opt-in — capability-map §3.8):* `$MapDrive_Live` carries `ts`, `snapshot_id`, `action` (`appeared`/`removed` for live snapshot-diff, `historical` for the init backfill), `direction` (`outbound`/`inbound`), `local_mount`, `remote_path`, `remote_host`, `username`, `provider`, and `origin` (`live`/`historical`). The `origin` column separates historically-inferred mappings (seeded once from the registry / fstab / event logs, carrying the artifact's timestamp or `0`) from live-observed ones; a currently-mapped persistent drive legitimately appears as **both** a `historical` and a live `appeared` row. `$MapDrive_Hourly` carries `hour_ts`, `direction`, `local_mount`, `remote_path`, `remote_host`, `appear_count`, `remove_count`. Example — every previously and currently mapped drive, both directions:

```sql
SELECT ts, direction, local_mount, remote_path, remote_host, username, origin, action
FROM $MapDrive_Live
ORDER BY ts DESC
```

### Querying with SQL

Use the `tar.sql` action to execute SELECT queries against warehouse tables:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "sql",
  "parameters": {
    "sql": "SELECT name, pid, cmdline FROM $Process_Live ORDER BY ts DESC LIMIT 50"
  }
}
```

Pre-built queries are available in `content/definitions/tar_warehouse.yaml`, covering common use cases like recent processes, TCP connections by process, listening ports, hourly summaries, service state changes, user sessions, and process trees.

### Rollup aggregation

The warehouse automatically runs a rollup aggregation cycle every 15 minutes. Each cycle:

1. Aggregates live-tier data into hourly summaries
2. Aggregates hourly data into daily summaries
3. Aggregates daily data into monthly summaries
4. Enforces retention limits on each tier

To force an immediate rollup, use the `tar.rollup` action.

### Safety controls

SQL queries are validated at multiple levels:

- **Server-side:** Only SELECT statements are permitted. A keyword blocklist rejects INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, and REINDEX.
- **Agent-side:** Queries run on a dedicated **read-only** SQLite connection guarded by a `sqlite3` authorizer. Only `SELECT` against registry-known warehouse tables is permitted (reference them by the `$`-prefixed names: `$Process_Live`, `$TCP_Hourly`, etc.); `PRAGMA`, `ATTACH`, schema-table reads (`sqlite_master`), writes, and recursive CTEs are denied at prepare time. `$`-prefixed names are translated to physical names only outside string literals and comments. Only a single statement is allowed, and queries exceeding 4KB are rejected. A blocked query returns `query rejected: operation or table not permitted` — for schema discovery use the `$`-prefixed warehouse table names rather than `PRAGMA`/`sqlite_master`.

## Data storage

TAR events are stored in `{data_dir}/tar.db` (SQLite), where `data_dir` is the agent's configured data directory. The database uses:

- WAL journal mode for concurrent performance
- `busy_timeout=5000` for thread safety
- `secure_delete=ON` to zero deleted data
- Indexes on `timestamp`, `(event_type, timestamp)`, and `snapshot_id`
