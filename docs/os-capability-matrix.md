# OS capability matrix

**What this is:** a per-capability × per-OS snapshot of what the Yuzu **agent**
actually collects/enforces on Windows, Linux, and macOS — the thing that was
missing when the `/network` tab showed no data on a Windows-only fleet (the
collector was Linux-only and nothing surfaced that gap). It now covers the
whole agent surface, grouped into sections: **agent core**, **Guardian guards**,
**Spark detection mechanisms**, **DEX**, **TAR warehouse capture sources**,
**inventory / daily-sync sources**, **live device snapshot**, **security posture
& file/certificate surfaces**, **network quality**, and every **agent plugin**
(58).

**Read this first — accuracy & drift.** This is a *curated snapshot*, and a
hand-maintained matrix drifts from code exactly the way the gap above happened.
Each row therefore cites its **source of truth in code**; trust the code over this
table, and when you change per-OS support, update both. The durable fix is to
**generate** this matrix from the machine-readable per-OS metadata that already
exists (see [Make this self-maintaining](#make-this-self-maintaining)) — treat
this doc as the interim, not the destination.

Legend: ✅ Full · 🟡 Partial / constrained · 🔜 Planned/spike · ⛔ None

For **TAR capture sources** the cells map directly to the registry enum
`OsSupportStatus` (`tar_schema_registry.hpp:56`): `kSupported` → ✅,
`kSupportedConstrained` → 🟡, `kPlanned` → 🔜, `kUnsupported` → ⛔ (no source
currently uses `kUnsupported` — every macOS/Linux gap is `kPlanned`,
pre-staged/queryable-empty, not hard-unsupported).

_Last re-verified against code: 2026-07-21 (all rows re-checked against the cited
sources on the consolidated macOS-parity branch; see [Verification](#verification))._
_Last hand-updated: 2026-08-24 (network_config native-leg migration). Scope note:
only the `network_config` rows were re-verified against source on that date — the
full-matrix re-verification stamp above deliberately still reads 2026-07-21, because
no other row was re-checked._

## Matrix

One table, split into sections by the bold divider rows. Some capability rows are
powered by a plugin that also has its own row in the **Agent plugins** section at
the foot — the capability row states the *feature's* per-OS depth, the plugin row
states the plugin's overall per-OS build/availability; they are consistent, not
duplicates.

| Capability / component | Windows | Linux | macOS | Source of truth |
|---|:---:|:---:|:---:|---|
| **━━ Agent core ━━** | | | | |
| **Agent core** (enroll, heartbeat, plugin host, triggers, KV, mTLS) | ✅ | ✅ | ✅ | `agents/core/` builds + enrolls on all three |
| **━━ Guardian guards — agent-side enforcement (Guaranteed State) ━━** | | | | The engine dispatches exactly **three** guard families in `guardian_engine.cpp` (`start_guard_for_rule_locked`, by `rule.spark().type()`). No process/firewall/launchd guard exists. `IGuard` interface: `agents/core/include/yuzu/agent/guard.hpp` |
| **Guardian — registry guard** (`registry-change` / `registry-value-equals`) | ✅ enforce | ⛔ | ⛔ | `guard_registry.cpp` / `RegistryGuard`: full impl under `#ifdef _WIN32` (advapi32 watch; enforce recreates key chain + rewrites value). Non-Windows `start()`→`false` no-op (covers Linux **and** macOS). Support array `registry_support::kHives = {HKLM,HKCU,HKCR,HKU}` (`guard_registry.hpp:43`), H2-cross-checked vs published schema enum |
| **Guardian — file guard** (`file-change` / `file-exists`, `file-hash-equals`) | 🟡 observe-only | ⛔ | ⛔ | `guard_file.cpp` / `FileGuard`: Windows impl (`ReadDirectoryChangesW` + bounded SHA-256) is **detection-only by design — it never writes on any platform** (content remediation is deferred to Content Distribution). Non-Windows `start()`→`false` no-op (Linux + macOS) |
| **Guardian — service run-state guard** (`service-status-change` / `service-running`, `service-stopped`) | ✅ enforce | 🟡 observe-only | ⛔ | Factory `make_service_guard()` (`guard_systemd.cpp:157`): Linux → `SystemdServiceGuard` (sd-bus watch; **enforce explicitly DEFERRED**, governance-gated — an enforce rule logs a downgrade), else → `ServiceGuard`. Windows `ServiceGuard` (`guard_service.cpp`, SCM `NotifyServiceStatusChangeW` + `StartServiceW`/`ControlService`) enforces; macOS falls to the `ServiceGuard` no-op stub. Support array `service_support::kStates = {running,stopped}` (`guard_service.hpp:56`) |
| **━━ Spark detection mechanisms (ADR-0021) ━━** | | | | The ADR-0021 reflex layer that will *replace* the legacy `IGuard` path above. `make_{file,registry,service}_mechanism()` in `spark_mechanism.hpp` returns `nullptr` off-platform (type left unregistered). **Not yet live as a detection path:** rung 7 wired Guardian as the first consumer (`GuardianEngine::reconcile_rule_locked()`), and rung 7.7a wires `wire_spark_engine()` at agent boot (`agent.cpp` — lifecycle-only), but `prefer_spark_` defaults `false`, so legacy `IGuard` remains the sole live detection path |
| **SparkEngine mechanisms** (file / registry / service; observe-only) | ✅ file + registry + service | 🟡 service only — **and NONE in a container** (see note) | ⛔ none | File/Registry are Windows-only; Service is Win-SCM + Linux-sd-bus; macOS none. **Registered ≠ functional:** a mechanism that starts but cannot bind its OS facility is marked INERT and EXCLUDED from the capability CSV (`sd_bus_open_system()` failing in `spark_service.cpp`; `OpenSCManager` denied; threadpool/IOCP failing). On Windows, a Registry sweeper or File worker that fails three consecutive passes at runtime is also marked INERT and excluded, because it cannot serve watches until a pass succeeds (its watches are still accepted), and is counted again once a pass succeeds. A Service mechanism's worker death is deliberately refuse-not-inert: it stops accepting new watches but never sets `inert`, so `service` stays in the CSV (`spark_service.cpp:974-987` Linux, `:2431-2441` Windows). **The container case is common:** `Dockerfile.agent` installs `libsystemd0` but a container has **no system bus**, so a containerised Linux agent registers Service INERT and ends up with **zero** spark capability (`spark_running=1`, empty `spark_mechs` CSV, no `{os=linux,mechanism=*}` series). Fleet view `yuzu_fleet_spark_mechanisms{os,mechanism}`; an inert mechanism shows as a per-mechanism GAP: `yuzu_fleet_spark_reporting{os}` exceeding that one mechanism's series, for an OS where every agent is expected to run it (query in `docs/user-manual/metrics.md`; the Linux form uses `os="linux", mechanism="service"`, and macOS has no detector because it has no mechanism by design, so nothing is published to compare). Do NOT compare `_reporting` with the SUM over mechanisms: a healthy Windows agent counts once in each of file, registry and service, so the sum is about 3N against N reporting, and `file` dropped fleet-wide still sums to about 2N (on Windows it stays quiet until the average agent has lost more than two of its three mechanisms, so it cannot detect one inert mechanism; on Linux it fires only while at least one agent still reports `service`, because an all-inert fleet publishes no mechanism series at all and the comparison then returns nothing) |
| **━━ DEX — Digital Employee Experience ━━** | | | | Server-side coverage map `dex_obs_platforms()` (`dex_routes.cpp:132-174`) is the hand-maintained mirror, drift-net-tested vs the agent collectors. Catalogue: `docs/dex-signal-catalog.md`; defs `dex_signal_catalog.cpp` |
| **DEX — reliability signals** (crashes, hangs, service/boot, storage, kernel faults, perf/thermal, …) | ✅ (~110 event types + state-poll) | 🟡 (17 obs_types) | 🟡 (16 obs_types) | Win: `dex_observer.cpp`/`dex_win_poll.cpp` — the catalogue IS the `EvtSubscribe` set (22 channels, waves 1–4). Linux: `dex_linux_collector.cpp` + `dex_linux_{proc,storage,journal,kmsg,sysfs}.cpp` (perf trio + storage/uptime + journald crash/hung + kernel panic/OOM/disk/fs/MCE/hung-task + thermal). macOS **real & shipped** (`kMacEmitted` = 16 catalogued obs_types, pinned by the `dex_obs_platforms()` drift-net in `test_dex_routes.cpp`; `process.resource_limit` is deliberately excluded from the taxonomy): `dex_macos_collector.cpp` + `dex_macos_{signals,oslog,iokit}.cpp` (DiagnosticReports `.ips` crashes/hangs/panics/jetsam, OSLog service-crash/wifi-drop/daemon-errors at **Error and Fault** level — `oslog_predicate()` requests both, reaching Fault-level `com.apple.apfs` `fs.corruption` — IOKit SMART/battery/storage/thermal/mem-pressure); covers ~10/11 headings unprivileged |
| **DEX — performance telemetry** (sustained-breach CPU/mem/disk levels — the `perf.*` trio) | ✅ | ✅ | ⛔ | Win `dex_win_poll.cpp` + Linux `/proc` both drive `dex_perf_breach.cpp` for all three. macOS emits **no** `perf.cpu_sustained`/`perf.memory_pressure`/`perf.disk_latency_high` (only adjacent state signals: thermal-throttle, mem-pressure warning, storage-low). Separately, the TAR `perf` source samples levels on Win+Linux (see TAR section) — macOS there is `kPlanned` too |
| **DEX — per-app file version** (the `(name, version)` identity) | ✅ real on-disk version | ⛔ (emits `""`) | 🟡 crash/hang via `.ips` | Win: `GetFileVersionInfoW` + `VS_FIXEDFILEINFO` (`tar_proc_perf.cpp:415-456`). Linux (`:630`) has no handle-free version source → `""` unknown bucket. macOS `process.crashed`/`process.hung` now read `CFBundleShortVersionString` from the `.ips` (header `app_version`, else body `bundleInfo`) via `ips_app_version()` (`dex_macos_signals.cpp`); macOS procperf (`:650`) still emits `""`. All normalized by `canon_version` |
| **DEX — per-app performance over time** (B1 per-device daily + B2 fleet aggregate, by `(app, version, day)`) | ✅ | 🟡 (samples; version `""`) | ⛔ (no data) | Fed by the TAR proc-perf sampler → `app_perf` daily-sync source (`sync_source_app_perf.cpp`) → server `AppPerfDailyStore` (B1) → `AppPerfRollup`/`AppPerfFleetStore` (B2). macOS `read_proc_counters()` returns `valid=false` (`tar_proc_perf.cpp:643`) — records nothing; server plumbing is platform-agnostic and lights up when the macOS collector lands. **Constraint for that future collector:** the dashboard cross-links crash/hang and perf on the raw process-name key with no normalization (an exact match — see `docs/user-manual/dex.md` "Apps"); a macOS procperf collector must emit the same process name the `.ips` crash `procName` carries (row above) — the UNTRUNCATED executable basename, the same shape `tar_proc_es.cpp`'s `path_basename(executable_path)` already produces, NOT the `MAXCOMLEN`-truncated `kp_proc.p_comm` the `KERN_PROC_ALL` poll fallback (`process_enum.cpp`) uses for its existing macOS process enumeration — those two existing macOS name sources already disagree with each other for any name over ~15 characters (common among macOS helper processes, e.g. "Google Chrome Helper (Renderer)"), so modeling a future procperf collector on the truncated `KERN_PROC_ALL` precedent would silently reproduce the exact join-miss this constraint exists to prevent |
| **━━ TAR warehouse capture sources ━━** | | | | **Authoritative & machine-readable:** `tar_schema_registry.cpp` `build_sources()` — 15 sources, per-OS `OsSupportStatus` + notes + `capture_method`. Enable flag is uniformly `<name>_enabled` in `tar_config`; 7 sources on by default (incl. `power`/`removable`, works-council-class), 8 opt-in (off). Implementer guide: `docs/tar-implementer.md` |
| **TAR — process** (`$Process`) · *on* | ✅ etw | ✅ procfs | 🟡 endpoint_security | Win ETW Kernel-Process (Toolhelp fallback), names-only, no cmdline; Linux `/proc/<pid>/{status,cmdline}`; macOS ES NOTIFY_EXEC/EXIT where entitled else `KERN_PROC_ALL` poll. Collectors `tar_proc_stream.cpp`/`tar_proc_etw.cpp`/`tar_proc_es.cpp` |
| **TAR — tcp** (`$TCP`) · *on* | ✅ iphlpapi | ✅ procfs | 🟡 nstat + proc poll | Win `GetExtendedTcpTable`/UDP poll; Linux `/proc/net/{tcp,udp}*` (short lifetimes may be missed); macOS sub-second TCP connect/close is event-driven via `nstat` (`com.apple.network.statistics` kctl `SRC_ADDED`/`SRC_REMOVED`), with `proc_pidfdinfo` demoted to fallback/seed + UDP (ES has no inet-socket events). `tar_network_collector.cpp`/`tar_netqual_nstat.cpp` |
| **TAR — service** (`$Service`) · *on* | ✅ scm | 🟡 systemctl | 🟡 launchctl | Win SCM (display_name/status/startup_type); Linux `systemctl list-units` (startup_type unknown; non-systemd hosts unsupported); macOS `launchctl list` (running/stopped only). `tar_service_collector.cpp` |
| **TAR — user** (`$User`) · *on* | ✅ wts | 🟡 utmp | 🟡 utmpx | Win WTS sessions (interactive/RDP/console); Linux `/var/run/utmp` (empty without utmp; type inferred from tty); macOS `getutxent` (GUI logins not always reflected). `tar_user_collector.cpp` |
| **TAR — perf** (`$Perf`) · *on* | ✅ ntcounters | ✅ procfs | 🔜 host_statistics | Win `GetSystemTimes`/`GlobalMemoryStatusEx`/disk IOCTL/`GetIfTable2` (no PDH/WMI); Linux `/proc/{stat,meminfo,diskstats,net/dev}`; macOS `host_statistics64`+IOKit **planned** (queryable-empty). `tar_perf.cpp` |
| **TAR — power** (sleep/wake + AC transitions) (`$Power`) · *on, works-council* | 🔜 powerbroadcast | 🔜 logind | 🔜 pmset_log | Win `PowerRegisterSuspendResumeNotification`/`WM_POWERBROADCAST` live subscription; Linux systemd-logind `PrepareForSleep` sd-bus + power-supply sysfs (gated on libsystemd); macOS `pmset -g log` retrospective replay, cursor-model. **All three planned — schema registered, collector lands separately.** `power_enabled`, first works-council-class source to ship enabled (with removable). |
| **TAR — removable** (USB/removable attach-detach + exec-from-removable) (`$Removable`) · *on, works-council* | ✅ wevtapi | 🟡 udev_netlink | 🟡 diskarbitration | Win `EvtQuery` over Partition/Diagnostic (+Kernel-PnP/Configuration, Storsvc/Diagnostic), real retained history bounded by `removable_lookback_seconds`; Linux udev netlink monitor (block subsystem), live-only, cursor-model; macOS DiskArbitration DADiskAppeared/Disappeared callbacks + `getfsstat` baseline, live-only. `removable_enabled`, works-council-class (device vendor/product/serial + executed-binary path/pid). `tar_removable_collector.cpp` |
| **TAR — procperf** (`$ProcPerf`) · *opt-in* | ✅ ntsysinfo | ✅ procfs | 🔜 libproc | Win `NtQuerySystemInformation` + least-privilege version read; Linux `/proc/[pid]/stat` (version always `""`); macOS `proc_pid_rusage` **planned**. `procperf_enabled`. `tar_proc_perf.cpp` |
| **TAR — netqual** (`$NetQual`) · *opt-in* | 🟡 estats | ✅ inetdiag | 🟡 nstat | Linux netlink SOCK_DIAG TCP_INFO (non-root, `ss -ti`-equivalent); Win TCP ESTATS (ADR-0020) **admin-only** — non-elevated records nothing (`netqual_capture_method=none`); macOS `nstat` per-flow `SRC_DESC`/`SRC_COUNTS` via the `com.apple.network.statistics` kctl (`kSupportedConstrained`) — **root required** for system-wide visibility else `netqual_capture_method=none` (no silent partial), private struct guarded by a runtime wire-layout self-check. `netqual_enabled`. `tar_netqual.hpp`/`tar_netqual_boot.cpp`/`tar_netqual_nstat.cpp` |
| **TAR — module** (`$Module`) · *opt-in* | ✅ etw | 🔜 auditd | 🔜 endpoint_security | Win ETW image-load + WinVerifyTrust signing; Linux kmod via auditd (`.so` needs eBPF, deferred; M6); macOS ES KEXT/dylib (M4/M5) — both **planned**. `module_enabled`. `tar_module_etw.cpp`/`tar_module_stream.cpp` |
| **TAR — software** (install/uninstall events) (`$Software`) · *opt-in* | ✅ registry | 🔜 dpkg_rpm | 🔜 pkgutil | Win registry Uninstall keys diffed (HKLM 64/32-bit; machine scope only; #1620); Linux dpkg/rpm/pacman and macOS `system_profiler`/pkgutil **planned** (fast-follow). `software_enabled`. Distinct from the daily *inventory* sync row (events vs point-in-time). `tar_software_collector.cpp` |
| **TAR — arp** (`$ARP`) · *opt-in* | ✅ iphlpapi | ✅ procfs | 🟡 route_sysctl | Win `GetIpNetTable2` (full mac/entry_type); Linux `/proc/net/arp`; macOS route sysctl is constrained (mac present, entry_type `unknown`, no interface). `arp_enabled` (ADR-0015). `tar_arp_collector.cpp` |
| **TAR — dns** (cache) (`$DNS`) · *opt-in* | ✅ dnsapi | 🔜 systemd-resolved | 🔜 dscacheutil | Win `DnsGetCacheDataTable` (name/type/data/TTL); Linux resolve1 D-Bus (hosts-file fallback) and macOS `dscacheutil` (no TTL) **planned**. Device-level usage-class PII, names-only. `dns_enabled` (ADR-0015). `tar_dns_collector.cpp` |
| **TAR — netconn** (connectivity-transition timeline) (`$NetConn`) · *opt-in* | ✅ wevtapi | 🔜 journald | 🔜 oslog | Win EvtQuery over NetworkProfile/NCSI/WLAN-AutoConfig channels (allow-listed fields); Linux NetworkManager/networkd journal and macOS configd/Wi-Fi OSLog **planned**. `netconn_enabled`. `tar_netconn_win.cpp` |
| **TAR — mapdrive** (network-share mappings) (`$MapDrive`) · *opt-in* | ✅ wnet | 🟡 procfs | 🟡 getfsstat | Win WNet outbound + NetSessionEnum inbound (+ history); Linux `/proc/mounts` cifs/nfs (username unavailable) + `smbstatus`; macOS `getfsstat` is outbound-live-only (no username, inbound, or history). `mapdrive_enabled`. `tar_mapdrive_collector.cpp` |
| **━━ Inventory & daily-sync sources (→ central Postgres) ━━** | | | | Agent daily-sync framework `sync_scheduler.cpp` pushes per-source state over `ReportInventory` (hash-skip), reusing plugins via `LocalDispatcher`. ADR-0016 |
| **Installed-software inventory** | ✅ | ✅ | ✅ | `sync_source_installed_software.cpp` reuses `installed_apps` `list_inventory` (Win registry; Linux dpkg/rpm/pacman/**apk**; macOS `system_profiler` apps + `pkgutil` receipts, kind=pkg/ecosystem=macos_pkgutil). Blob contract v2 (kind/ecosystem/EVR/arch/packager + rpm/macOS signature_status + distro; honest-empty; macOS app rows also carry a native CFBundle/SecStaticCode publisher + signed/unsigned read, #2273 — no `codesign` subprocess). Machine-scope only. Server `SoftwareInventoryStore` |
| **Software-licence detection (SLE)** | ✅ (WMI `SoftwareLicensingProduct` + Office C2R + `ProbeSpec` + per-user hives/files) | 🟡 (rpm/dpkg declared-licence classification — no lapse detection; RHEL entitlement + FlexLM `.lic` expiry authoritative) | 🟡 (`_MASReceipt` + machine-scope vendor plists — `probable` confidence only) | Per-OS TUs `license_scan/src/licensing_{win,linux,macos}.cpp` (Windows WMI probe via the shared `agents/shared/wmi_bounded.hpp`); `sync_source_software_licensing.cpp` → `SoftwareLicensingStore` (ADR-0024). Detail: `docs/user-manual/software-licensing.md`. Java + SWID tags are the fast-follow (#2112) |
| **Device-identity inventory** (serial, UUID, BIOS, CPU/RAM/disk, MAC, OS) | ✅ | ✅ | ✅ | `sync_source_device_ci.cpp` reuses `hardware`/`device_identity`/`os_info`/`network_config`. `hardware` `system`: Win WMI `Win32_BIOS`/`Win32_ComputerSystemProduct`; Linux `/sys/class/dmi/id/product_{serial,uuid}` (0400 → needs `cap_dac_read_search`; `unknown` without it); macOS native IOKit `IOPlatformExpertDevice` (`IOServiceGetMatchingService`/`IORegistryEntryCreateCFProperty`; `IOPlatformUUID` ≠ SMBIOS UUID). Machine-scope only. Server `DeviceInventoryStore` |
| **━━ Live device snapshot ("Get live info") ━━** | | | | Device page dispatch-and-poll snapshot; each kind has its own `device.live.<kind>` audit verb. `docs/user-manual/device-management.md` |
| **Live — process tree + per-process connections** | ✅ tree + conn join | 🟡 tree; conn join absent | 🟡 tree | `processes/list_tree` (`proc\|pid\|ppid\|name\|sha256\|path`, all OSes) joined by PID to `network_diag/connections` (owning PID via `GetExtendedTcpTable`, Windows). Linux `/proc/net/tcp` exposes inode not pid → no join |
| **Live — ARP / neighbour table** | ✅ | 🟡 | 🟡 | `network_config/arp`: Windows `GetIpNetTable2`; Linux `/proc/net/arp` — constrained: IPv4 ARP only, no IPv6 neighbours (those live in `RTM_GETNEIGH`), and non-Ethernet and incomplete (non-`ATF_COM`) entries are skipped; macOS PF_ROUTE `RTF_LLINFO` sysctl, de-duplicated — constrained because that dump carries no interface name or static/dynamic type, both emitted as `-` |
| **Live — DNS resolver cache** | ✅ | ⛔ (no portable resolver cache) | ⛔ (OS exposes no resolver-cache contents; `dscacheutil -cachedump` defunct on macOS 26) | `network_config/dns_cache` (`DnsGetCacheDataTable` on Windows; macOS returns an honest `dns_cache\|unsupported` sentinel, no shell-out — see `darwin-compat.md`) |
| **Live — disk space** | ✅ | ✅ | ✅ | `disk_space` plugin `free` action; `GetDiskFreeSpaceExW` on Windows, `statvfs` on POSIX |
| **Live — Wi-Fi current connection** | ✅ | 🟡 | 🟡 | `wifi/connected` — Win `WlanQueryInterface`, Linux NetworkManager D-Bus (sd-bus) with `nmcli`/`iwconfig` argv fallbacks, macOS `wifi_corewlan.mm` `corewlan_current_connection` (CoreWLAN `CWWiFiClient`/`CWInterface`, first `.mm` TU; pure `format_connected_record` in `wifi_corewlan.hpp`). Linux 🟡: the D-Bus rung is declared `constrained` — it has not been exercised against a real Wi-Fi radio, and it reports the device interface rather than the NetworkManager profile name in the connection column. macOS 🟡: association/RSSI/channel/security read, but SSID/BSSID are withheld from a background daemon by Location Services on 14+ (`<ssid-withheld>`) — replaces the dead `airport -I` path |
| **━━ Security posture & file/certificate surfaces ━━** | | | | Posture reads + signed-artifact/certificate actions; each row cites its per-OS legs |
| **Antivirus posture** (`antivirus` plugin: `products` + `status` + `av_exclusions`) | ✅ SecurityCenter2 products + Defender status (in-process WMI) + Defender exclusion lists (in-process registry) | 🟡 process/dir detection + `status` now has a real leg (ClamAV liveness + rung-1 definitions mtime; CrowdStrike/Sophos presence-only) | 🟡 `products`: XProtect bundle version + endpoint-security system-extension enumeration (`systemextensionsctl`, unprivileged) + process fallback; `status`: XProtect definition version + bundle mtime + Remediator/MRT — **no real-time-protection state** (macOS exposes no queryable equivalent), `av\|XProtect\|active` is a definitions-readable proxy, not a running-protection read; `av_exclusions` unsupported (Windows-only concept) | `agents/plugins/antivirus/src/antivirus_plugin.cpp`; pure parsers/renderers `antivirus_parsers.hpp` (`parse_plist_version`/`parse_sysext_list`/`sysext_av_state`/`decode_wsc_product_state`/`render_wsc_products`/`render_defender_status`/`render_exclusion_lines`) tested every host |
| **Firewall posture** (`firewall` plugin: `state` + `rules`) | ✅ per-profile via `INetFwPolicy2` COM (rung 1, native — no `netsh` shell-out), plus a `ruleset\|<n>` rule count on both actions (`state`: `INetFwRules::get_Count`, the true policy-wide total; `rules`: the count of rows actually emitted this call, capped at 100 — a distinct number from `state`'s) | ✅ backend autodetect, firewalld (rung 1, bounded sd-bus) → nftables (rung 1, bounded `NETLINK_NETFILTER` — read-only table/chain/rule enumeration, no libnftnl/libmnl dependency) → ufw → iptables (rung 2, `run_bounded_subprocess` argv, structured per-backend rows) | 🟡 `state`: Application Firewall primary (`socketfilterfw --getglobalstate`, unprivileged; `mode\|block_all` when State = 2) + pf secondary (`pfctl -s info`, root — `unknown` without it), plus pf anchor list (`pfctl -s Anchors`) and rule count (`pfctl -s rules`), both root-only and `unknown`/empty without it; `rules`: per-app allow/block list (`socketfilterfw --listapps`, unprivileged — `app\|<path>\|<allow\|block\|unknown>` rows) + pf rule lines (`pfctl -s rules`, root) + the same pf anchors and rule count — all via `run_bounded_subprocess` (rung 2, no shell) | `agents/plugins/firewall/src/firewall_plugin.cpp` `state`/`rules` legs; pure parsers `firewall_parsers.hpp` (tested every host) |
| **Digital-signature verification** (`filesystem.get_signature`) | ✅ | ⛔ | ✅ | Win: WinVerifyTrust (Authenticode: valid/invalid/unsigned/untrusted) in `filesystem_plugin.cpp`. macOS: `codesign --verify --deep --strict` mapped to valid/unsigned/invalid/unknown by `classify_codesign_result` in `agents/plugins/filesystem/src/filesystem_macos_sig.hpp` (macOS `valid` = seal integrity, not Gatekeeper/notarization trust). Linux emits platform-unsupported |
| **File version info** (`filesystem.get_version_info`) | ✅ | ⛔ | ✅ | Win: `GetFileVersionInfoW`/`VerQueryValueW` (VS_FIXEDFILEINFO + string table) in `filesystem_plugin.cpp`. macOS: CFBundleShortVersionString/CFBundleVersion from the bundle Info.plist via `plutil -extract`, mapped by `classify_plutil_extract` in `filesystem_macos_sig.hpp` (binary + XML plists; `version_status\|not_available` when absent). Linux emits platform-unsupported |
| **Certificate store — login-keychain read** (`certificates.list`/`details` `store=login`/`all`) | ⛔ | ⛔ | ✅ | macOS-specific: reads the console user's login keychain via `launchctl asuser <uid> sudo -n -u <user> -- security find-certificate` (root-only; see `docs/agent-privilege-model.md`) as a pre-split argv through the bounded subprocess runner (rung 2, #3406 — no shell; the home directory is resolved in-process), built by `build_login_keychain_read_argv` in `agents/shared/macos_console_user.hpp`, invoked from `agents/plugins/certificates/src/certificates_plugin.cpp`. Windows machine stores (CryptoAPI) and Linux `/etc/ssl/certs` have no per-user login-keychain equivalent for this hop |
| **Certificate delete — verified / SIP-aware** (`certificates.delete`) | ✅ | ✅ | ✅ | Win: CryptoAPI store delete; Linux: `unlinkat` of the matching PEM entry on a held `/etc/ssl/certs` dirfd after a pre-unlink identity recheck (#3245). macOS: `security delete-certificate` on `System.keychain` then a re-enumeration that reports `deleted` only on a positively-proven absence (`classify_delete_verdict` in `agents/shared/macos_console_user.hpp`); `store=root` rejected (SystemRootCertificates.keychain is SIP-sealed) in `certificates_plugin.cpp` |
| **━━ Network quality (`/network`) ━━** | | | | Measurement-first device/local-link health lens. `net_quality_sampler.cpp`; `docs/user-manual/network.md` "Platform coverage" |
| **Network quality** (throughput / retransmit / RTT) | 🟡 throughput + retransmit (no RTT) | ✅ all three | 🟡 throughput only | Win `GetIfTable2` throughput + `GetTcpStatisticsEx` system-wide interval retransmit (**measurement-first, not loss-validated** — withheld from the fleet retransmit aggregate); RTT needs ESTATS (admin+overhead) → 🔜. Linux has all three. macOS `NET_RT_IFLIST2` throughput only (`read_net_counters()` sums non-loopback `if_data64` rx/tx, differenced per heartbeat); retransmit + RTT deferred — global `net.inet.tcp.stats` reads all-zero on modern macOS → 🔜 |
| **━━ Agent plugins (64) — per-plugin build/availability ━━** | | | | Per-OS via platform macros / per-OS TUs (`agents/plugins/*/src/*`). 45 fully cross-platform, 7 Windows-only (`rdp_control`, `registry`, `sccm`, `wmi`, `windows_optional_features`, `execution_artifacts`, `app_control`), 8 uneven (`tar` — richest on Windows; `msi_packages` — Win+macOS, no Linux; `disk_actions` — Win+macOS, Linux declared unimplemented; `power_health` — Windows the only full leg; `wifi` — Windows full, Linux/macOS constrained; `filesystem_posture` — Linux constrained, Windows/macOS full; `firmware_posture` — Windows full, Linux/macOS constrained; `pkg_inventory` — macOS full, Windows and Linux `managers` declared planned, Linux `packages` unsupported by design), 2 macOS-constrained (`interaction` — GUI-less daemon; `app_usage` — macOS `usage` fold inherits TAR's process source's names-only constraint, ES entitlement absent -> poll granularity), 2 Linux-only (`browser_inventory` — Wave 10 P2a-3; `runtimes` — Wave 10 PR10.1-b; macOS/Windows legs are PLANNED placeholders, each follows as its own PR). "Full" = the plugin builds and its core actions work on that OS; a plugin can be cross-platform yet expose a few OS-specific actions (noted). (Re-tallied 2026-09-17: the prior "3 uneven" count omitted power_health/wifi/filesystem_posture, which are not ✅✅✅ either — pre-existing drift, corrected here. `peripherals` moved from uneven to cross-platform once its Windows leg shipped, Wave 9 PR9.1a2. Wave 8 PR8.1-a1 adds `platform_security` (cross-platform; macOS `secure_boot` is a declared no-op, SIP reported under `code_integrity`); Wave 8 PR8.4 adds `firmware_posture` (uneven); Wave 10 PR10.1-b adds `runtimes` (Linux-only) and Wave 10 P2a-3 adds `browser_inventory`; Wave 10 PR10.1-c adds `pkg_inventory` (uneven); Wave 8 PR8.1-b adds `system_hardening` (cross-platform): 64 plugins.) |
| agent_actions | ✅ | ✅ | ✅ | portable — no platform macros |
| agent_logging | ✅ | ✅ | ✅ | `_WIN32`/`__APPLE__`/Linux branches all implemented |
| antivirus | ✅ | ✅ | ✅ | Defender/WMI (in-process, no more `powershell`) + exclusion-registry read · ClamAV+Falcon+Sophos with a real `status` leg · macOS real probes — XProtect bundle version + endpoint-security system-extension enumeration (`antivirus_plugin.cpp`, parsers `antivirus_parsers.hpp`), no longer a hardcoded assertion (posture depth: the **Antivirus posture** row) |
| app_control | ✅ | ⛔ | ⛔ | Windows-only read-only application-control posture (Wave 8 PR8.6; refs #282): `wdac_policy` = registry `Control\CI\Policy` values + the active `.cip` policy-file listing; `applocker_policy` = `wmi_bounded.hpp` CIM `MSFT_ApplockerPolicy` with a `SrpV2` registry fallback. Off-Windows both actions are declared `unsupported`; `applocker_policy` is declared constrained (CIM property names and SrpV2 layout unverified on an AppLocker-configured host); add_rule/remove_rule/get_blocked_events and a Linux fapolicyd leg are not implemented |
| app_usage | ✅ | 🟡 | ✅ | machine-scope usage evidence, read-only over TAR's `usage` fold (`tar.db`, `PRAGMA query_only`) — never writes it. `summary`/`last_used` on Linux/Windows via TAR process/procfs and process/etw; macOS constrained — inherits the process source's names-only constraint, ES entitlement absent falls back to poll granularity. `foreground` is unimplemented on all three OSes (schema gap, not a platform gap; promoted by the user-context-bridge roadmap) — see `agents/plugins/app_usage/README.md` |
| asset_tags | ✅ | ✅ | ✅ | portable — `std::filesystem` only |
| autoruns | ✅ | ✅ | ✅ | Linux: file reads of cron/anacron/at/systemd unit dirs/XDG autostart, `systemctl list-timers` argv fallback only when no unit dir is readable. macOS: `CFPropertyListCreateWithData` over launchd plists, `/etc/periodic`, `/etc/emond.d`; Login Items CONSTRAINED (private BTM database, no public read API). Windows: `Reg*W` over HKLM + every HKU via `win_profiles` `with_user_hive`, ITaskService COM, bounded WMI `root\subscription` query — zero spawn primitives (no `schtasks.exe`/`wmic.exe`/PowerShell); real-hardware LocalSystem probe in `tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md` |
| bitlocker | ✅ | ✅ | ✅ | BitLocker via in-process Win32_EncryptableVolume WMI (rung 1, no subprocess) · LUKS via in-process libblkid + `/sys/class/block/dm-*/dm/uuid` reads (rung 1, no subprocess) · FileVault `fdesetup` + per-APFS-volume `diskutil apfs list` via direct argv through the bounded runner (rung 2; encrypted/not_encrypted/unknown, parser `bitlocker_macos_apfs.hpp`) |
| browser_inventory | 🔜 | 🟡 | 🔜 | Chromium-family browser/profile inventory. Forensics securable, default-off via the server plugin-config kill switch, single-target. Linux this wave: `browsers` presence-only, `profiles` a real read of each browser's `Local State` JSON under `~/.config/{google-chrome,chromium,microsoft-edge}`. macOS/Windows legs and the per-profile `extensions` action are PLANNED — each follows as its own PR; see `agents/plugins/browser_inventory/README.md` |
| certificates | ✅ | ✅ | ✅ | full per-OS blocks (`_WIN32`/`__linux__`/`__APPLE__`); Linux now parses in-process via libcrypto (rung 1); macOS System/SystemRoot keychains read natively via SecItem (rung 1), login keychain reads via a pre-split argv through the bounded runner (rung 2, #3406 — the former Decision-7 governed-shell path is retired); macOS depth — login-keychain read + verified SIP-aware delete — in the **Security posture** section rows |
| chargen | ✅ | ✅ | ✅ | portable — RFC 864 generator |
| content_dist | ✅ | ✅ | ✅ | `_WIN32` vs POSIX; HTTPS gated on OpenSSL build option, not OS. `execute_staged` on Linux is CONSTRAINED, not unconditional: shebang-interpreted (`#!`) staged payloads are rejected (B6 fd-exec is incompatible with the kernel's binfmt_script re-open) — native executables only. Per-action detail: the generated plugin-action table below |
| device_identity | ✅ | ✅ | ✅ | all three branches implemented |
| diagnostics | ✅ | ✅ | ✅ | portable — `std::filesystem` checks |
| discovery | ✅ | ✅ | ✅ | all three legs are native (`GetIpNetTable2` / `/proc/net/arp` / sysctl routing table), and the sweep uses a shared unprivileged ICMP socket, constrained on Linux by `net.ipv4.ping_group_range` |
| disk_actions | ✅ | ⛔ | 🟡 | `smart`/`volumes`, both read-only; every device and volume handle is opened with no access rights at all on Windows. Windows: `smart` via `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty`, `StorageDeviceSeekPenaltyProperty`, and `StorageDeviceProtocolSpecificProperty` NVMe log page 0x02) — health figures are **NVMe-only**, and `IOCTL_STORAGE_PREDICT_FAILURE` is deliberately unused because it fails `ERROR_INVALID_FUNCTION` on NVMe; `volumes` via `FindFirstVolumeW` + `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` + `GetVolumePathNamesForVolumeNameW`. Built with MSVC and exercised against two live NVMe drives (C:→PhysicalDrive0, D:→PhysicalDrive1). macOS: IOKit identity and NVMe-SMART capability only — health attributes need a private, undocumented Apple interface, so health reads `unknown`; `volumes` resolves the physical disk by walking the IOKit provider chain, so an APFS synthesized container reports the underlying drive. Linux: **not implemented** — no mechanism could be bound against real hardware (only virtualised disks reachable), declared rather than written from documentation. `volumes` is deliberately not a third volume inventory: it carries only the physical↔logical join that `hardware.disks` and `filesystem_posture.mounts` do not. |
| disk_space | ✅ | ✅ | ✅ | linux/apple/win branches; `#else` unsupported only |
| event_logs | ✅ | ✅ | ✅ | win/linux/apple branches, natively acquired on Windows and Linux (ADR-3002 rung-1 migration): Windows reads wevtapi `EvtQuery`/`EvtRender` in-process (bounded `EvtNext` wait, typed permission_denied/unavailable/constrained statuses); Linux reads a bounded `sd_journal` walk behind the `systemd_guard` feature, falling back to a bounded pre-split `journalctl` argv when compiled out or the journal is unreachable. macOS `log show` runs under the bounded `SubprocessRunner` with a hard wall-clock deadline (no built-in timeout in the tool), classified by pure `event_logs_macos.hpp` (`decide_log_show_output`) — a timed-out/degraded run surfaces a sentinel row + non-zero rc, never a silent empty result |
| example | ✅ | ✅ | ✅ | portable — sample plugin |
| execution_artifacts | ✅ | ⛔ | ⛔ | Windows-only forensics reads (ShimCache, Amcache `InventoryApplicationFile`, Prefetch). Off-Windows every action returns the fixed `<action>\|unsupported\|windows_only_artefact` sentinel, rc 1 — `execution_artifacts_plugin.cpp`'s `#else` branch. `Forensics` securable, `AdminOrApproval`, single-target, default-off via the server plugin-config kill switch; see `agents/plugins/execution_artifacts/README.md` |
| filesystem | ✅ | ✅ | ✅ | `_WIN32` vs POSIX. `get_signature`/`get_version_info` now Win + macOS (Linux platform-unsupported) — depth in the **Security posture** section rows |
| filesystem_posture | 🟡 | ✅ | ✅ | `mounts`/`quotas`/`snapshots`, all volume-level, read-only inventory. Linux: `/proc/self/mountinfo`, `quotactl(Q_GETFMT)`, Btrfs/LVM snapshot capability (not a live inventory). macOS: `getmntinfo`, no per-user/group APFS quota equivalent, APFS snapshot enumeration. Windows: `mounts` (`FindFirstVolumeW`/`GetVolumeInformationW`/`GetDriveTypeW`/`GetDiskFreeSpaceExW`), `quotas` (`IDiskQuotaControl`, read-only) and `snapshots` (`IVssBackupComponents::Query` — VSS, **requires administrative rights**; LocalSystem today per #1442, and `permission_denied` — not an empty set — under an unprivileged account). Built with MSVC and exercised on a live Windows host; the populated-quota path is not asserted.
| firewall | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| firmware_posture | ✅ | 🟡 | 🟡 | One read-only `firmware` action, rung 1 on every leg, no spawn: BIOS/firmware vendor, version, release date and update-pending posture. Windows: WMI `Win32_BIOS` (`Manufacturer`, `SMBIOSBIOSVersion`, `ReleaseDate`) through the bounded helper plus the raw SMBIOS type-0 table from `GetSystemFirmwareTable('RSMB')`. Linux: sysfs DMI (`/sys/class/dmi/id/bios_*`) plus fwupd `GetDevices`/`GetUpgrades` over sd-bus (`libsystemd` is a system dependency, never vcpkg); constrained because the populated-DMI shape is not captured from a physical host, a reachable system bus with no fwupd daemon reports `update_pending` `unavailable` (a state, not a failure), and a system bus that cannot be opened reads `update_pending` `unreadable` with `fwupd:bus_open:<errno>`. macOS: IODeviceTree `/rom` and `/chosen` through IOKit plus `sysctlbyname` `hw.model`; constrained because only Apple Silicon is verified (no `/rom`, version is an iBoot tag, no release date, no update verdict). The Windows leg was probed on the-rig as SYSTEM. Securable `Security`, operation `Read`; see `agents/plugins/firmware_posture/README.md` |
| hardware | ✅ | ✅ | ✅ | linux/apple/win branches throughout |
| http_client | ✅ | ✅ | ✅ | `_WIN32` vs POSIX; HTTPS gated on OpenSSL build option |
| installed_apps | ✅ | ✅ | ✅ | linux/apple/win branches (feeds inventory sync) |
| interaction | ✅ | ✅ | 🟡 | win/apple/linux branches. macOS caveat: as a GUI-less root LaunchDaemon `message_box` can't reach a WindowServer session — the `osascript` leg reports an honest `status\|not_reachable` (never a fabricated `response\|ok`), decoded via pure `interaction_parsers.hpp` in `interaction_plugin.cpp`; delivering the dialog to the logged-in user is a deferred per-session helper |
| ioc | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| license_scan | ✅ | ✅ | ✅ | per-OS TUs `licensing_{win,linux,macos}.cpp` (feeds SLE sync) |
| msi_packages | ✅ | ⛔ | ✅ | Win MSI (`MsiEnumProductsA`); macOS `pkgutil --pkgs`/`--pkg-info` receipts (reverse-domain id / derived name / version / install location) — pure parser `msi_packages_macos.hpp` + `__APPLE__` branch in `msi_packages_plugin.cpp` (500-pkg cap, `__truncated__` sentinel); Linux `#else` → "platform not supported" |
| netprobe | ✅ | ✅ | ✅ | `_WIN32` vs POSIX portable sockets |
| netstat | ✅ | ✅ | ✅ | linux/apple/win branches. `attribution` action additionally resolves the owning process's name/path (folds the retired sockwho plugin in, #3403) |
| network_actions | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `flush_dns` runs both `dscacheutil -flushcache` **and** `killall -HUP mDNSResponder` (the load-bearing reset), honest status from real exit codes (`network_actions_plugin.cpp`) |
| network_config | ✅ | ✅ | ✅ | win/linux/apple throughout, no `/bin/sh` on any leg. Linux rtnetlink + `/proc/net/arp`; macOS getifaddrs + `SIOCGIFMEDIA` link speed + PF_ROUTE + SCDynamicStore. `arp` is now live on Linux and macOS; `dns_cache` stays an honest `unsupported` sentinel on macOS (`network_config_plugin.cpp`) |
| network_diag | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| os_info | ✅ | ✅ | ✅ | linux/apple/win branches |
| peripherals | ✅ | ✅ | ✅ | USB/PCI/Thunderbolt bus inventory. macOS + Linux full (IOKit / sysfs, both rung 1). Windows: usb/pci full via SetupAPI (`SetupDiGetClassDevsW` + `SPDRP_HARDWAREID`/`COMPATIBLEIDS`), rung 1; thunderbolt constrained — string-heuristic identification (DEVICEDESC contains Thunderbolt/USB4), no dedicated Thunderbolt device class in SetupAPI, same constrained shape as the Linux leg |
| pkg_inventory | 🔜 | 🔜 | ✅ | Machine-scope package-manager inventory, read-only, zero subprocess. `managers`: macOS Homebrew prefix layout over both `/opt/homebrew` and `/usr/local`; the Linux leg (tool presence + manager config facts, identity/config only) is declared `planned` and follows as its own PR. `packages`: macOS Homebrew Cellar/Caskroom directory names; Linux is `unsupported` by design (`installed_apps` owns the Linux roster). Windows legs are declared `planned` (Chocolatey/winget follow as their own PR). See `agents/plugins/pkg_inventory/README.md` |
| power_health | ✅ | 🟡 | 🟡 | Windows is the only full leg: battery via GetSystemPowerStatus + CallNtPowerInformation, thermal via PDH `\Thermal Zone Information(*)`, and power_plan/set_power_plan via PowrProf. macOS has battery (IOPS) and a thermal *pressure enum* (NSProcessInfo), never a temperature; power schemes are unsupported (no named schemes; IOPMSetPMPreferences is SPI, deliberately not adopted). Linux has battery and thermal via `/sys`; power schemes are planned (platform_profile) |
| printing | ✅ | ✅ | ✅ | `printers`/`jobs` are read-only IPP over the CUPS Unix socket (cpp-httplib, no libcups) on macOS/Linux, winspool on Windows. `clear_queue` cancels exactly one job id (Destructive/Irreversible, admin-or-approval) — supported on Windows (cancel measured only under Administrators and SYSTEM; a least-privileged identity is unmeasured), constrained on Linux (only a container-root/@SYSTEM-equivalent principal was measured cancelling a non-owned job, and the production Linux agent runs unprivileged), constrained on macOS (cupsd's Cancel-Job authorisation for a non-owned job is unmeasured). See `agents/plugins/printing/README.md` |
| processes | ✅ | ✅ | ✅ | win/linux/apple branches (point-in-time enum; streaming capture is under TAR `process`) |
| procfetch | ✅ | ✅ | ✅ | linux/apple/win branches |
| quarantine | ✅ | ✅ | ✅ | full per-OS blocks; Linux covers IPv4 and IPv6 (honest `note\|ipv6_unavailable` on hosts with no IPv6 stack), macOS verifies pf is actually ENABLED and not merely loaded, and status on all three platforms reports partial/degraded containment rather than a clean `active` (#3282, #3283, #3285). Windows containment now blocks via profile-default policy rather than named Block rules, so the loopback/whitelist Allow rules actually take effect once quarantined (#3284) — see docs/quarantine-windows-firewall-precedence.md |
| rdp_control | ✅ | ⛔ | ⛔ | Windows-only. Off-Windows returns an honest `rdp_control\|unsupported` sentinel (macOS names Screen Sharing); state-changing `set_state` reports terminal FAILURE, read-only `status` rc=0 — `rdp_control_plugin.cpp` `#ifndef _WIN32` branch |
| registry | ✅ | ⛔ | ⛔ | Windows-only (advapi32). Off-Windows returns an honest `registry\|unsupported` sentinel (reads rc=0; mutating `set_value`/`delete_*` report terminal FAILURE — no false success) — `registry_plugin.cpp` `#ifndef _WIN32` branch. `list_profiles` (PR1.7) enumerates local profiles via ProfileList/HKEY_USERS. `get_user_value` resolves the target profile via ProfileList and reads the live `HKEY_USERS\<SID>` hive when the user is logged in, falling back to an offline `RegLoadKey` mount (SeBackup/SeRestore privileges, required only for that fallback) when not. The ladder lives in `agents/shared/win_profiles.hpp` and is shared with `installed_apps.list_per_user`, `license_scan`'s per-user surfaces and `tar`'s mapdrive history (#2771) |
| runtimes | 🔜 | ✅ | 🔜 | `dotnet`/`jvm` installed-runtime inventory, read-only and zero-subprocess (rung 1). Linux only: directory-name walks, `release` file reads and a `bin/java` probe for release-less homes over an injected root (`runtimes_linux_parsers.hpp`), skipping network mounts read from `/proc/self/mountinfo`. Coverage: the standard roots only (`/usr/share/dotnet`, `/usr/lib/dotnet`, `/usr/lib64/dotnet`; `/usr/lib/jvm`, `/opt/java`, `/usr/lib64/jvm`, `/var/opt/java`), so `supported` with no rows means none found there, not none installed (an Oracle-RPM `/usr/java`, `/opt/jdk-*`, SDKMAN and bundled runtimes are not walked). macOS and Windows are declared `planned`; until those legs ship those hosts answer `status\|<action>\|unsupported\|<os>:planned`. See `agents/plugins/runtimes/README.md` |
| sccm | ✅ | ⛔ | ⛔ | Windows-only. macOS returns an honest `sccm\|unsupported` (points at Jamf/MDM); Linux `installed\|false` + "platform not supported" — `sccm_plugin.cpp` `__APPLE__` branch |
| script_exec | ✅ | ✅ | ✅ | win/apple/linux. Different action sets per OS (`bash` POSIX-only; powershell/cmd on Windows) |
| services | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `list`/`running` now emit `startup_type` (automatic/disabled/unknown) from a bulk `launchctl print-disabled` join (parser `services_macos_launchd.hpp`); `set_start_mode` rejects `manual` (launchd is binary enable/disable) |
| software_actions | ✅ | ✅ | ✅ | win/linux/apple branches |
| status | ✅ | ✅ | ✅ | linux/apple/win branches |
| storage | ✅ | ✅ | ✅ | portable — persistent KV store |
| tags | ✅ | ✅ | ✅ | portable — `std::filesystem` |
| **tar** | ✅ | 🟡 | 🟡 | Uneven by design — richest on Windows (ETW/dnsapi/registry), `/proc`-based on Linux, ES + scattered branches on macOS. Per-source depth is the **TAR warehouse capture sources** section above (`tar_schema_registry.cpp`) |
| users | ✅ | ✅ | ✅ | linux/apple/win branches. macOS `local_users` now adds real `last_logon` (`last -y`) and a tri-state `console_state` GUI-login flag (`SCDynamicStoreCopyConsoleUser`, shared `macos_console_user.hpp`); Windows `primary_user`/`session_history` now read the Security channel natively via wevtapi, and the POSIX account tools run as bounded argv invocations instead of a shell |
| vuln_scan | ✅ | ✅ | ✅ | linux/apple/win branches |
| wifi | ✅ | 🟡 | 🟡 | win/linux/apple all implemented; Linux 🟡 and macOS 🟡 — both declare `constrained` (see the generated block); macOS `connected` via CoreWLAN (`wifi_corewlan.mm`), `list_networks` legacy `airport -s`/`system_profiler` (connection depth: the **Live — Wi-Fi current connection** row) |
| windows_optional_features | ✅ | ⛔ | ⛔ | Windows-only: DISM API `DismOpenSession(DISM_ONLINE_IMAGE)` + `DismGetFeatures`/`DismGetFeatureInfo` for both `list` and `info` — verified live on the-rig under `NT AUTHORITY\SYSTEM`. Off-Windows both actions are declared `unsupported` — DISM has no Linux/macOS equivalent |
| windows_updates | ✅ | ✅ | ✅ | update history / rpm+apt / `system_profiler` install history (Linux/mac report installed-package history) |
| wmi | ✅ | ⛔ | ⛔ | Windows-only (`#ifndef _WIN32` → not available) |
| wol | ✅ | ✅ | ✅ | `wol_plugin.cpp` — `_WIN32` vs POSIX portable UDP broadcast (wake); `check` reachability is native on every platform (unprivileged ICMP echo with a TCP-connect fallback on port 443, ADR-3002 rung 1) — no subprocess spawn, no `ping` shell-out |

## Why gaps happen (and how to not get surprised again)

Per-OS support is **implicit and scattered**: a `#if defined(_WIN32)` here, a
no-op stub there, a `kPlanned` enum in one registry. Nothing forced it to the
surface, so a Windows-only fleet can hit a feature that was quietly Linux-only.
When adding or changing a collector/guard/plugin, assume the **other** platforms
are a deliberate decision you must record — in code (a stub + comment), in the
relevant user-manual "Platform coverage" section, and in this matrix.

## Generated: ABI4 per-action capability declarations (#2204)

PR1.1 builds the generator this doc's "Make this self-maintaining" section
below used to propose only as a follow-up issue: `tools/capmatrix-gen`
dlopens each built plugin's `YuzuPluginDescriptor` (ABI4,
`sdk/include/yuzu/plugin.h`) and emits the block below from its
`action_descriptors` array. `scripts/ci/check-capability-matrix.sh` regenerates
and byte-diffs this block on every Linux CI leg, in **RATCHET mode**: the
"Undeclared plugins" count must never grow, and it is not enough for a PR to
merely shrink it — the script exits 1 on a *lower* count too until
`RATCHET_BASELINE_UNDECLARED` is lowered to match in the same change, so the
adoption gain is sticky rather than leaving room for a later regression back
up to the old baseline.

Adoption is now **complete**: all 62 plugins the CI gate tracks populate
`action_descriptors`, so the undeclared count and `RATCHET_BASELINE_UNDECLARED`
are both **0** and the "Undeclared plugins" section below is empty. From here
the ratchet is equivalent to a hard fail — a new plugin directory landing
without descriptors grows the count above 0 and fails the Linux leg.

The generator is also the completeness check: `capmatrix-gen` hard-errors on
any mismatch between a plugin's `actions()` list and its `action_descriptors`
array *before* it writes anything, so a declaration that silently omits an
action cannot reach this table.

**Rung legend** (the table's Rung column below): 1 = native OS interface
(zero processes, best) · 2 = argv runner · 3 = governed shell (two-plus
processes, worst) — rung states *how* a leg acquires its capability per
docs/adr/3002-acquisition-ladder.md, never how mature or hardened the
implementation is.

<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with
     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| agent_actions | set_log_level | linux | supported | 1 | spdlog_runtime | - |
| agent_actions | set_log_level | macos | supported | 1 | spdlog_runtime | - |
| agent_actions | set_log_level | windows | supported | 1 | spdlog_runtime | - |
| agent_actions | info | linux | supported | 1 | agent_config_read | - |
| agent_actions | info | macos | supported | 1 | agent_config_read | - |
| agent_actions | info | windows | supported | 1 | agent_config_read | - |
| agent_logging | get_log | linux | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_log | macos | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_log | windows | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_key_files | linux | supported | 1 | /proc/self/exe symlink + std::filesystem metadata | - |
| agent_logging | get_key_files | macos | supported | 1 | _NSGetExecutablePath + realpath(3) + std::filesystem metadata | - |
| agent_logging | get_key_files | windows | supported | 1 | GetModuleFileNameA + std::filesystem metadata | - |
| antivirus | products | linux | supported | 2 | pgrep+filesystem_probe | - |
| antivirus | products | macos | supported | 2 | plistbuddy+systemextensionsctl+pgrep | - |
| antivirus | products | windows | supported | 1 | wmi_securitycenter2 | - |
| antivirus | status | linux | supported | 2 | pgrep+stat | ClamAV liveness+definitions mtime; CrowdStrike/Sophos presence-only |
| antivirus | status | macos | supported | 2 | plistbuddy+stat | - |
| antivirus | status | windows | supported | 1 | wmi_defender_status | - |
| antivirus | av_exclusions | linux | unsupported | - | - | Windows-only concept |
| antivirus | av_exclusions | macos | unsupported | - | - | Windows-only concept |
| antivirus | av_exclusions | windows | supported | 1 | win32_registry | permission_denied sentinel on ACL'd key, never a silent empty list |
| app_control | wdac_policy | linux | unsupported | - | - | Windows-only concept; Linux fapolicyd is a separate, unimplemented leg of #282 |
| app_control | wdac_policy | macos | unsupported | - | - | Windows-only concept; macOS app-trust (Gatekeeper/SIP) is outside this plugin's scope |
| app_control | wdac_policy | windows | supported | 1 | RegEnumValueW HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy + std::filesystem listing of %SystemRoot%\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip | Rig-verified 2026-09-21 (Windows 11 Pro 10.0.26200, LocalSystem): CI\\Policy holds EmodePolicyRequired, SkuPolicyRequired, VerifiedAndReputablePolicyState (0 reads 'disabled') and SAC_PreviousState (0xffffffff reads 'unmodelled'), and 8 default .cip policies are listed; only VerifiedAndReputablePolicyState=0 was observed, other values are mapped per documentation and unverified on hardware. An unmodelled value is reported 'unmodelled'; an unreadable key is constrained or permission_denied, never absent. The multiple-policy-format CiPolicies\\Active files and the legacy System32 SiPolicy.p7b are reported by presence only; a single-format policy held only on the EFI system partition is not visible |
| app_control | applocker_policy | linux | unsupported | - | - | Windows-only concept; Linux fapolicyd is a separate, unimplemented leg of #282 |
| app_control | applocker_policy | macos | unsupported | - | - | Windows-only concept; macOS app-trust (Gatekeeper/SIP) is outside this plugin's scope |
| app_control | applocker_policy | windows | constrained | 1 | wmi_bounded run_bounded_wmi_query root\\StandardCimv2\\Security\\ApplicationControl MSFT_ApplockerPolicy; registry walk of HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\<collection> when the class is absent, empty or failing | Rig-verified 2026-09-21 (Windows 11 Pro 10.0.26200, LocalSystem): the CIM namespace root\\StandardCimv2\\Security\\ApplicationControl does NOT exist on this host (WBEM_E_INVALID_NAMESPACE 0x8004100e), so the SrpV2 registry walk runs and, with no AppLocker policy configured, reports 'none'. The CIM property names (Collection/EnforcementMode/RuleCount) and the SrpV2 rule-collection layout are UNVERIFIED on a host with AppLocker configured, so CIM-sourced modes report unmodelled (the registry numbering is not assumed for them) and a policy delivered outside the SrpV2 key (for example by MDM) is not read. An enforced mode is the configured mode, not proof the rules apply (the Application Identity service is not read). The CIM namespace is caller-side allowlisted |
| app_usage | summary | linux | supported | 1 | tar.db usage_daily (derived from TAR process/procfs) | - |
| app_usage | summary | macos | constrained | 1 | tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll) | inherits the process source's names-only constraint; ES entitlement absent -> poll granularity |
| app_usage | summary | windows | supported | 1 | tar.db usage_daily (derived from TAR process/etw) | - |
| app_usage | last_used | linux | supported | 1 | tar.db usage_daily (derived from TAR process/procfs) | - |
| app_usage | last_used | macos | constrained | 1 | tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll) | inherits the process source's names-only constraint; ES entitlement absent -> poll granularity |
| app_usage | last_used | windows | supported | 1 | tar.db usage_daily (derived from TAR process/etw) | - |
| app_usage | foreground | linux | constrained | 1 | not captured | foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change |
| app_usage | foreground | macos | constrained | 1 | not captured | foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change |
| app_usage | foreground | windows | constrained | 1 | not captured | foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change |
| asset_tags | sync | linux | supported | 1 | local_json_store | - |
| asset_tags | sync | macos | supported | 1 | local_json_store | - |
| asset_tags | sync | windows | supported | 1 | local_json_store | - |
| asset_tags | status | linux | supported | 1 | local_json_store | - |
| asset_tags | status | macos | supported | 1 | local_json_store | - |
| asset_tags | status | windows | supported | 1 | local_json_store | - |
| asset_tags | get | linux | supported | 1 | local_json_store | - |
| asset_tags | get | macos | supported | 1 | local_json_store | - |
| asset_tags | get | windows | supported | 1 | local_json_store | - |
| asset_tags | changes | linux | supported | 1 | local_json_store | - |
| asset_tags | changes | macos | supported | 1 | local_json_store | - |
| asset_tags | changes | windows | supported | 1 | local_json_store | - |
| autoruns | list | linux | supported | 1 | file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable | Every acquisition is a bounded local file read or directory listing (read_file_bounded, O_NOFOLLOW on the leaf) except one declared exception: systemd timer enumeration is a tri-state on /run/systemd/system -- absent reports UNSUPPORTED (no_systemd), a stat() error other than ENOENT reports CONSTRAINED (systemd_state_undetermined), and present reads /etc/systemd/system, /usr/lib/systemd/system and /lib/systemd/system directly. Only when systemd is present but all three dirs are unreadable does it fall back to `systemctl list-timers --all --no-pager --no-legend` (rung 2, autoruns/collect_linux#1, docs/agent-spawn-sink-manifest.md), whose rows carry enabled=unknown -- that text has no wants-symlink evidence. A rung-1-scanned timer row can ALSO carry enabled=unknown, even with a real wants-symlink read attempted: if a wants directory consulted for it hit a real I/O error partway through, or hit its entry cap, the matching symlink could be among what wasn't read (#4182); or, with no failed read among the wants directories it actually checked, when /home itself couldn't be fully enumerated, the very set of user wants directories to search is itself incomplete. Real captures (2026-09-07): this Mac reports the Linux source through the foreign-OS stub as lnx_systemd_timers_system\|unsupported\|0\|foreign_os (this build cannot exercise the leg at all); a real ubuntu:24.04 Docker container read lnx_systemd_timers_system\|unsupported\|0\|no_systemd -- the container has no init system at all, so this confirms the absent branch; the rung-2 fallback itself needs a host with systemd present but its unit dirs unreadable, not exercised here. `absent` (ENOENT) on /etc/crontab and /etc/anacrontab reports CONSTRAINED (their absence is itself a real constraint, classify_read_error's required_by_catalog=true); the same ENOENT on every other file/dir source reports SUPPORTED (nothing there is a valid, fully-read answer) -- a genuine read failure (permission_denied or any other errno) always reports CONSTRAINED with that token, never folded into `absent`. lnx_init_d lists /etc/init.d script names only (no runlevel/systemctl wiring cross-check) -- CONSTRAINED by design, per-user reads report owning uid numerically (no NSS/getpwuid_r lookup, no directory-service deadline risk on this read-only path). lnx_systemd_timers_user is likewise always CONSTRAINED (narrow_search_path_coverage) when reportable -- the scanned search-path set omits several standard `systemd --user` unit roots (~/.local/share/systemd/user, /run/systemd/user, /usr/local/{lib,share}/systemd/user, /usr/share/systemd/user), a permanent gap, not a transient failure. |
| autoruns | list | macos | supported | 1 | CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | File-truth only, rung 1: CFPropertyListCreateWithData over launchd plists (system + per-user LaunchDaemons/LaunchAgents), /etc/periodic directory listings, and /etc/emond.d/rules plists. Login Items is CONSTRAINED -- the list lives in a private per-user BTM database with no public read API; this leg never shells out to osascript, launchctl, or sfltool. A plist's own Disabled key is read, but launchctl print-disabled's separate override database is NOT consulted -- this is file truth, not launchd's live runtime state, a deliberate divergence from a services-style plugin that does read launchctl state. Real capture on this Mac (2026-09-07): mac_system_launchdaemons\|supported\|422, mac_system_launchagents\|supported\|456, mac_launchdaemons\|supported\|2, mac_user_launchagents\|supported\|1, mac_launchagents\|supported\|0, mac_periodic\|supported\|0, mac_emond\|supported\|0, mac_login_items\|constrained\|0\|btm_private_database_no_public_api -- login items always emits that one constrained status line and zero rows, never a real read attempt (docs/user-manual/autoruns.md has the full `source\|` capture). |
| autoruns | list | windows | supported | 1 | Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | Reg*W over HKLM plus every reachable HKU hive via win_profiles.hpp's with_user_hive ladder (live hive first; offline RegLoadKeyW under SeBackup/SeRestore -- enabled on the process token for the offline arm only, serialised process-wide by offline_hive_mutex() -- when the profile is not logged in; unload_failed is surfaced as a warning line, never dropped, when RegUnLoadKeyW fails on the way out). ITaskService COM (yuzu::shared::win::ComInit, COINIT_MULTITHREADED, no dedicated STA thread) and a bounded WMI root\\subscription query, one row per __FilterToConsumerBinding joined on the ref Name -- a dangling ref still emits its row, tagged constrained\|unresolved_ref, never dropped or collapsed into another binding's row. A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim for the LocalSystem session: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts -- MTA is not a problem for ITaskService here, including as LocalSystem); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding -- the same stock 'SCM Event Log Filter'/'SCM Event Log Consumer' binding the admin session saw, confirming LocalSystem reaches both APIs with no apartment-model or session-identity gap. CoInitializeEx itself failing is the one COM failure this leg cannot render as a real hr_<hex> token (ComInit::ok() exposes no HRESULT) -- reported as the fixed sentinel hr_cominit_failed; every other COM/WMI failure carries the real HRESULT or wmi_bounded.hpp's error token. Zero spawn primitives: schtasks.exe, wmic.exe and PowerShell are never invoked. Real-hardware verification: docs/wave7/rig-checklist-autoruns-win.md's 10-step checklist. |
| autoruns | catalog | linux | supported | 1 | file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable | Pure reflection of this build's static kSourceCatalog declarations for the Linux sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism. |
| autoruns | catalog | macos | supported | 1 | CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | Pure reflection of this build's static kSourceCatalog declarations for the macOS sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism. |
| autoruns | catalog | windows | supported | 1 | Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | Pure reflection of this build's static kSourceCatalog declarations for the Windows sources above -- no OS call itself, but the same LocalSystem session this build's ITaskService/WMI mechanism relies on is A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding. See the `list` descriptor's note for the full per-source `list` behaviour this catalog entry declares support for. |
| bitlocker | state | linux | supported | 1 | libblkid+sysfs | - |
| bitlocker | state | macos | supported | 2 | fdesetup+diskutil | - |
| bitlocker | state | windows | supported | 1 | wmi_encryptable_volume | - |
| browser_inventory | browsers | linux | constrained | 1 | fixed system binary path presence (/opt/google/chrome/chrome, /opt/microsoft/msedge/msedge, /usr/lib/chromium/chromium) | presence-only; no version/channel detection in this package |
| browser_inventory | browsers | macos | planned | 1 | /Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers | follows as its own PR |
| browser_inventory | browsers | windows | planned | 1 | ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs | follows as its own PR |
| browser_inventory | profiles | linux | supported | 1 | ~/.config/{google-chrome,chromium,microsoft-edge}/Local State JSON read | - |
| browser_inventory | profiles | macos | planned | 1 | /Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers | follows as its own PR |
| browser_inventory | profiles | windows | planned | 1 | ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs | follows as its own PR |
| certificates | list | linux | supported | 1 | libcrypto X509 (in-process PEM parse) | - |
| certificates | list | macos | supported | 2 | SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login) | System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner |
| certificates | list | windows | supported | 1 | CryptoAPI (CertEnumCertificatesInStore) | - |
| certificates | details | linux | supported | 1 | libcrypto X509 (in-process PEM parse) | - |
| certificates | details | macos | supported | 2 | SecItem (System/root, in-process) + security find-certificate argv via subprocess runner (login) | System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo session hop, run as a pre-split argv through the bounded subprocess runner |
| certificates | details | windows | supported | 1 | CryptoAPI (CertEnumCertificatesInStore) | - |
| certificates | delete | linux | supported | 1 | libcrypto X509 match + held-dirfd openat/fstatat/unlinkat with pre-unlink identity recheck | - |
| certificates | delete | macos | constrained | 2 | security delete-certificate via subprocess runner | SystemRootCertificates.keychain is sealed under SIP and rejected outright; only System/MY store deletes are supported |
| certificates | delete | windows | supported | 1 | CryptoAPI (CertDeleteCertificateFromStore) | - |
| chargen | chargen_start | linux | supported | 1 | in-process | - |
| chargen | chargen_start | macos | supported | 1 | in-process | - |
| chargen | chargen_start | windows | supported | 1 | in-process | - |
| chargen | chargen_stop | linux | supported | 1 | in-process | - |
| chargen | chargen_stop | macos | supported | 1 | in-process | - |
| chargen | chargen_stop | windows | supported | 1 | in-process | - |
| content_dist | stage | linux | supported | 1 | httplib_tls | - |
| content_dist | stage | macos | supported | 1 | httplib_tls | - |
| content_dist | stage | windows | constrained | 1 | httplib_tls | requires OpenSSL to be found at build time; HTTPS unavailable if absent |
| content_dist | execute_staged | linux | constrained | 2 | subprocess_runner:staged_payload | shebang-interpreted (#!) staged payloads are rejected -- B6 fd-exec (execveat O_CLOEXEC) is incompatible with the kernel's binfmt_script re-open; native executables only |
| content_dist | execute_staged | macos | supported | 2 | subprocess_runner:staged_payload | - |
| content_dist | execute_staged | windows | supported | 2 | subprocess_runner:staged_payload | - |
| content_dist | list_staged | linux | supported | 1 | std_filesystem | - |
| content_dist | list_staged | macos | supported | 1 | std_filesystem | - |
| content_dist | list_staged | windows | supported | 1 | std_filesystem | - |
| content_dist | cleanup | linux | supported | 1 | std_filesystem | - |
| content_dist | cleanup | macos | supported | 1 | std_filesystem | - |
| content_dist | cleanup | windows | supported | 1 | std_filesystem | - |
| content_dist | upload_file | linux | supported | 1 | httplib_tls | - |
| content_dist | upload_file | macos | supported | 1 | httplib_tls | - |
| content_dist | upload_file | windows | constrained | 1 | httplib_tls | requires OpenSSL to be found at build time; HTTPS unavailable if absent |
| device_identity | device_name | linux | supported | 1 | gethostname(3) | - |
| device_identity | device_name | macos | supported | 1 | gethostname(3) | - |
| device_identity | device_name | windows | supported | 1 | GetComputerNameExA | - |
| device_identity | domain | linux | supported | 1 | /etc/resolv.conf read + sd-bus org.freedesktop.sssd.infopipe ListDomains [fallback: run_bounded_subprocess(realm list); further fallback: /etc/sssd/sssd.conf read] | - |
| device_identity | domain | macos | supported | 2 | run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) [fallback: gethostname(3) + getaddrinfo(AI_CANONNAME)] | - |
| device_identity | domain | windows | supported | 1 | NetGetJoinInformation | - |
| device_identity | ou | linux | supported | 2 | run_bounded_subprocess(realm list) [fallback: /etc/sssd/sssd.conf read] | - |
| device_identity | ou | macos | supported | 2 | run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) | - |
| device_identity | ou | windows | supported | 1 | GetComputerObjectNameA | - |
| diagnostics | log_level | linux | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | log_level | macos | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | log_level | windows | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | certificates | linux | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | certificates | macos | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | certificates | windows | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | connection_info | linux | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| diagnostics | connection_info | macos | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| diagnostics | connection_info | windows | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| discovery | scan_subnet | linux | constrained | 1 | /proc/net/arp + unprivileged SOCK_DGRAM ICMP | the ICMP sweep needs net.ipv4.ping_group_range to admit the agent's gid; ARP-only results with a CONSTRAINED/PARTIAL status otherwise, or UNAVAILABLE/PARTIAL when the ICMP socket cannot be created at all. netlink RTM_GETNEIGH is a recorded future promotion over /proc/net/arp |
| discovery | scan_subnet | macos | supported | 1 | sysctl NET_RT_FLAGS/RTF_LLINFO + SOCK_DGRAM ICMP | - |
| discovery | scan_subnet | windows | supported | 1 | GetIpNetTable2 + IcmpSendEcho | - |
| disk_actions | smart | linux | unsupported | - | - | not implemented in this change: no mechanism could be bound, because every Linux host available for the spike exposed virtualised disks only (WSL2 reports four 'Virtual Disk' SCSI nodes and no /dev/nvme* character devices), and shipping an NVME_IOCTL_ADMIN_CMD path written from documentation but never exercised is exactly how a dead leg reaches production. Binding it needs a Linux host with real storage, or a VM with disk passthrough; neither was reachable when this shipped |
| disk_actions | smart | macos | constrained | 1 | IOKit IOBlockStorageDevice device characteristics | reports device identity (model, medium type) and whether the device advertises NVMe SMART, but NOT the health attributes themselves: wear, available spare and the critical-warning flag are reachable only through Apple's private IONVMeSMARTUserClient selector interface, which is undocumented and version-fragile, so health reports 'unknown' on this platform rather than a guess |
| disk_actions | smart | windows | supported | 1 | IOCTL_STORAGE_QUERY_PROPERTY (StorageDeviceProperty + StorageDeviceSeekPenaltyProperty + StorageDeviceProtocolSpecificProperty, NVMe log page 0x02) | the device handle is opened with zero access rights, which an unprivileged service account may do; wear and spare figures come from the NVMe SMART/Health log and are therefore reported only for NVMe devices, with SATA and USB drives reporting identity and media type but 'unknown' health |
| disk_actions | volumes | linux | unsupported | - | - | not implemented in this change: the physical-to-logical join is only meaningful alongside a bound smart leg, and the Linux smart leg is deferred with it |
| disk_actions | volumes | macos | constrained | 1 | IOKit IOMedia provider walk + getmntinfo_r_np(3) MNT_NOWAIT | one row per IOMedia object, keyed on that object's BSD name, carrying the physical whole disk that backs it and any mount points it serves; the physical disk is resolved by walking the IOKit provider chain, so a volume inside a synthesized APFS container correctly reports the underlying drive rather than the container; a media object that maps nothing -- a whole disk serving no mount point -- is omitted, because this action carries only the physical-to-logical join and such a row has no join to carry |
| disk_actions | volumes | windows | constrained | 1 | FindFirstVolumeW + IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS + GetVolumePathNamesForVolumeNameW | maps volumes to the physical drives backing them; a volume spanning several drives (a spanned or striped dynamic volume) reports every drive it touches, and a volume with no assigned drive letter or mount point reports '-' for mount points rather than being omitted |
| disk_space | free | linux | supported | 1 | statvfs(2) | - |
| disk_space | free | macos | supported | 1 | statfs(2) | - |
| disk_space | free | windows | supported | 1 | GetDiskFreeSpaceExW | - |
| event_logs | errors | linux | supported | 1 | sd_journal (bounded local read, PRIORITY<=err) | falls back to a bounded journalctl argv invocation (rung 2) when libsystemd is compiled out (-Dsystemd_guard) or the journal is unreachable |
| event_logs | errors | macos | supported | 2 | log_show | requires root or a real login session to open the local unified-log data store -- a non-root headless process gets EX_NOPERM/77 regardless of Full Disk Access (docs/darwin-compat.md); no gap in production, which runs as a root LaunchDaemon |
| event_logs | errors | windows | supported | 1 | wevtapi (EvtQuery/EvtRender, Level=2, bounded EvtNext) | - |
| event_logs | query | linux | supported | 1 | sd_journal (bounded local read, keyword match) | falls back to a bounded journalctl argv invocation (rung 2) when libsystemd is compiled out (-Dsystemd_guard) or the journal is unreachable |
| event_logs | query | macos | supported | 2 | log_show | requires root or a real login session to open the local unified-log data store -- a non-root headless process gets EX_NOPERM/77 regardless of Full Disk Access (docs/darwin-compat.md); no gap in production, which runs as a root LaunchDaemon |
| event_logs | query | windows | supported | 1 | wevtapi (EvtQuery/EvtRender, bounded EvtNext) | - |
| example | ping | linux | supported | 1 | in-process | - |
| example | ping | macos | supported | 1 | in-process | - |
| example | ping | windows | supported | 1 | in-process | - |
| example | echo | linux | supported | 1 | in-process | - |
| example | echo | macos | supported | 1 | in-process | - |
| example | echo | windows | supported | 1 | in-process | - |
| execution_artifacts | shimcache | linux | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | shimcache | macos | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | shimcache | windows | supported | 1 | RegQueryValueExW HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache (local bounded reader, 16 MiB) | Windows 10/11 layout only ('win10' header scheme, DWORD 0x34 or 0x30); no exec-flag bit exists in this layout, so every row's insert_flag is '-'. A1's real capture (the-rig, 2026-09-06) was 7886 bytes, well under the 16 MiB bound, and parsed with the header-size DWORD reading 0x34 |
| execution_artifacts | amcache | linux | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | amcache | macos | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | amcache | windows | constrained | 1 | copy Amcache.hve(+.LOG1/.LOG2) then RegLoadAppKeyW; whole sequence serialised by offline_hive_mutex | A1's the-rig probe (2026-09-06) found the copy succeeds as a PLAIN Copy-Item in every session tested (admin and LocalSystem) — the sharing violation that would require CreateFile(FILE_SHARE_READ\|WRITE\|DELETE, FILE_FLAG_BACKUP_SEMANTICS) + SeBackupPrivilege was never hit, so that fallback path is unexercised on this hardware. RegLoadAppKeyW does NOT require SeBackupPrivilege: it succeeded (LSTATUS 0x00000000) with the privilege explicitly disabled via AdjustTokenPrivileges, in both the admin session and under LocalSystem, against all 8889 real InventoryApplicationFile subkeys. Reported CONSTRAINED because the plain-copy path is a best-effort acquisition method not guaranteed on every host (a locked/exclusively-held hive on another machine could still need the backup-semantics fallback), not because anything failed on the probe host |
| execution_artifacts | prefetch | linux | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | prefetch | macos | unsupported | - | - | Windows-only artefact; no equivalent exists |
| execution_artifacts | prefetch | windows | supported | 1 | CreateFileW read + ntdll RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF) | A1's the-rig LocalSystem probe (2026-09-06): GetProcAddress resolved both ntdll entry points to non-null addresses in every session (admin and LocalSystem); all four decompression attempts across the three real MAM .pf captures returned NTSTATUS 0x00000000 (STATUS_SUCCESS) from both RtlGetCompressionWorkSpaceSize (workspace size 166495 bytes, format COMPRESSION_FORMAT_XPRESS_HUFF, engine standard) and RtlDecompressBufferEx, with every decompressed payload's bytes 4-7 reading 'SCCA'. Real captures parsed as prefetch format version 31 (Windows 10/11), not version 30 as originally planned — see execution_artifacts_parsers.hpp's file header |
| filesystem | exists | linux | supported | 1 | std::filesystem | - |
| filesystem | exists | macos | supported | 1 | std::filesystem | - |
| filesystem | exists | windows | supported | 1 | std::filesystem | - |
| filesystem | list_dir | linux | supported | 1 | std::filesystem | - |
| filesystem | list_dir | macos | supported | 1 | std::filesystem | - |
| filesystem | list_dir | windows | supported | 1 | std::filesystem | - |
| filesystem | file_hash | linux | supported | 2 | subprocess_runner:sha256sum/sha1sum | - |
| filesystem | file_hash | macos | supported | 2 | subprocess_runner:shasum | - |
| filesystem | file_hash | windows | supported | 1 | bcrypt | - |
| filesystem | create_temp | linux | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp | macos | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp | windows | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp_dir | linux | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | create_temp_dir | macos | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | create_temp_dir | windows | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | read | linux | supported | 1 | std::ifstream | - |
| filesystem | read | macos | supported | 1 | std::ifstream | - |
| filesystem | read | windows | supported | 1 | std::ifstream | - |
| filesystem | get_acl | linux | constrained | 1 | posix_stat | stat()-only basic owner/group/permission bits; no ACL/ACE enumeration |
| filesystem | get_acl | macos | constrained | 1 | posix_stat | stat()-only basic owner/group/permission bits; no ACL/ACE enumeration |
| filesystem | get_acl | windows | supported | 1 | win32_acl | - |
| filesystem | get_signature | linux | unsupported | - | - | - |
| filesystem | get_signature | macos | supported | 2 | subprocess_runner:codesign | - |
| filesystem | get_signature | windows | supported | 1 | wintrust | - |
| filesystem | find_by_hash | linux | supported | 2 | std::filesystem+subprocess_runner:sha256sum | - |
| filesystem | find_by_hash | macos | supported | 2 | std::filesystem+subprocess_runner:shasum | - |
| filesystem | find_by_hash | windows | supported | 1 | std::filesystem+bcrypt | - |
| filesystem | search_dir | linux | supported | 1 | std::filesystem+std::regex | - |
| filesystem | search_dir | macos | supported | 1 | std::filesystem+std::regex | - |
| filesystem | search_dir | windows | supported | 1 | std::filesystem+std::regex | - |
| filesystem | get_version_info | linux | unsupported | - | - | - |
| filesystem | get_version_info | macos | supported | 2 | subprocess_runner:plutil | - |
| filesystem | get_version_info | windows | supported | 1 | win32_version_info | - |
| filesystem | search | linux | supported | 1 | std::ifstream+std::regex | - |
| filesystem | search | macos | supported | 1 | std::ifstream+std::regex | - |
| filesystem | search | windows | supported | 1 | std::ifstream+std::regex | - |
| filesystem | replace | linux | supported | 1 | atomic_write_file | - |
| filesystem | replace | macos | supported | 1 | atomic_write_file | - |
| filesystem | replace | windows | supported | 1 | atomic_write_file | - |
| filesystem | write_content | linux | supported | 1 | atomic_write_file | - |
| filesystem | write_content | macos | supported | 1 | atomic_write_file | - |
| filesystem | write_content | windows | supported | 1 | atomic_write_file | - |
| filesystem | append | linux | supported | 1 | std::ofstream | - |
| filesystem | append | macos | supported | 1 | std::ofstream | - |
| filesystem | append | windows | supported | 1 | std::ofstream | - |
| filesystem | delete_lines | linux | supported | 1 | atomic_write_file | - |
| filesystem | delete_lines | macos | supported | 1 | atomic_write_file | - |
| filesystem | delete_lines | windows | supported | 1 | atomic_write_file | - |
| filesystem_posture | mounts | linux | constrained | 1 | /proc/self/mountinfo + statvfs(3) | capacity columns are omitted for network filesystems (nfs/cifs/smb/ceph/afs and network FUSE mounts) because a statvfs against an unreachable server blocks the dispatch worker indefinitely; the mount itself is still listed |
| filesystem_posture | mounts | macos | supported | 1 | getmntinfo(3) MNT_NOWAIT | - |
| filesystem_posture | mounts | windows | constrained | 1 | FindFirstVolumeW + GetVolumeInformationW + GetDriveTypeW + GetDiskFreeSpaceExW | enumerates local volumes only; a mapped network drive is not a volume and is not listed, and no per-mount option string exists so that column reads '-' |
| filesystem_posture | quotas | linux | constrained | 1 | quotactl(2) Q_GETFMT | reports per-mount quota-subsystem state only; per-user and per-group limits are not enumerated, and a mount whose source is not a block device (overlay, tmpfs, network) reports no_block_device; a walk in which every probed device returns EPERM/EACCES reports permission_denied rather than a generic degradation |
| filesystem_posture | quotas | macos | constrained | 1 | getattrlist(2) ATTR_VOL_QUOTA_SIZE/ATTR_VOL_RESERVED_SIZE | volume-level quota and reserved size only; per-user and per-group quotas do not exist on APFS (quotactl returns ENOTSUP on every APFS mount while succeeding on HFS+), so no per-identity rows are reported; a volume the agent may not read reports permission_denied |
| filesystem_posture | quotas | windows | constrained | 1 | IDiskQuotaControl (dskquota.h) | volume quota state and default limit/threshold only, opened read-only; per-user quota entries are not enumerated; a volume that denies the query reports permission_denied; a build whose SDK lacks dskquota.h reports unavailable; compiled and linked on a live Windows host but not asserted against one with quotas configured, so the populated-quota path is unexercised |
| filesystem_posture | snapshots | linux | constrained | 1 | /proc/self/mountinfo btrfs subvol + device-mapper source detection | reports snapshot-capable volumes and the mounted btrfs subvolume identity, not a snapshot inventory: a device-mapper source may be dm-crypt, dm-multipath or dm-integrity rather than a snapshot-capable LV, enumerating unmounted btrfs snapshots needs CAP_SYS_ADMIN via BTRFS_IOC_TREE_SEARCH, and telling an LVM snapshot LV from a linear LV needs a device-mapper DM_TABLE_STATUS ioctl -- none of which this read-only plugin performs |
| filesystem_posture | snapshots | macos | supported | 1 | fs_snapshot_list(2) | one row per (mount point, snapshot): an APFS snapshot visible under two mount points of the same volume lineage is reported under each |
| filesystem_posture | snapshots | windows | constrained | 1 | IVssBackupComponents::Query (VSS) | enumerates VSS shadow copies machine-wide, one row per snapshot, reporting its snapshot ID and shadow-copy device path but no size or per-file content; REQUIRES ADMINISTRATIVE RIGHTS -- the agent runs as LocalSystem today so this succeeds; under an unprivileged service account CreateVssBackupComponents returns E_ACCESSDENIED and the action reports permission_denied rather than an empty snapshot set; any VSS failure is reported distinctly from a genuinely empty set and degrades the result status |
| firewall | state | linux | supported | 1 | firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) | - |
| firewall | state | macos | supported | 2 | socketfilterfw/pfctl via run_bounded_subprocess | - |
| firewall | state | windows | supported | 1 | INetFwPolicy2 COM (per-profile FirewallEnabled) | - |
| firewall | rules | linux | supported | 1 | firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) | - |
| firewall | rules | macos | supported | 2 | pfctl via run_bounded_subprocess | - |
| firewall | rules | windows | supported | 1 | INetFwPolicy2 COM (INetFwRules enumeration) | - |
| firmware_posture | firmware | linux | constrained | 1 | /sys/class/dmi/id/{bios_vendor,bios_version,bios_date,bios_release} + fwupd org.freedesktop.fwupd GetDevices/GetUpgrades over the sd-bus system bus | the fwupd leg needs libsystemd at build time (a system dependency, never vcpkg); without it update_pending reads unreadable with the fwupd:not_built token and the sysfs rows remain. Hosts without DMI (containers, some VMs) report the DMI fields absent and a reachable system bus with no fwupd daemon reports update_pending unavailable: neither is a failure. A system bus that cannot be opened (a container without the bus socket) reads update_pending unreadable with fwupd:bus_open:<errno> and the action CONSTRAINED (or PERMISSION_DENIED when the connect is refused). The populated-DMI shape is not captured from a physical Linux host |
| firmware_posture | firmware | macos | constrained | 1 | IOKit IORegistryEntryFromPath IODeviceTree:/rom then IODeviceTree:/chosen, IORegistryEntryCreateCFProperty under ScopedIOObject/ScopedCFRef, plus sysctlbyname hw.model | verified on Apple Silicon only (Mac16,10, macOS 26.6.2): there IODeviceTree:/rom does not exist and the version is IODeviceTree:/chosen system-firmware-version (an iBoot tag such as mBoot-18000.161.10, not a BIOS date); the Intel /rom version/release-date/vendor keys are UNVERIFIED on hardware. release_date reads absent on Apple Silicon and update_pending is not reported |
| firmware_posture | firmware | windows | supported | 1 | WMI Win32_BIOS via wmi_bounded run_bounded_wmi_query + GetSystemFirmwareTable('RSMB') SMBIOS type 0 | - |
| hardware | manufacturer | linux | supported | 1 | /sys/class/dmi/id/sys_vendor | - |
| hardware | manufacturer | macos | supported | 1 | sysctlbyname(hw.manufacturer) | - |
| hardware | manufacturer | windows | supported | 1 | WMI Win32_ComputerSystem.Manufacturer | - |
| hardware | model | linux | supported | 1 | /sys/class/dmi/id/product_name | - |
| hardware | model | macos | supported | 1 | sysctlbyname(hw.model) | - |
| hardware | model | windows | supported | 1 | WMI Win32_ComputerSystem.Model | - |
| hardware | bios | linux | supported | 1 | /sys/class/dmi/id/bios_vendor + bios_version + bios_date | - |
| hardware | bios | macos | supported | 2 | run_bounded_subprocess(system_profiler SPHardwareDataType) + native parser (hardware_macos_bios.hpp) | - |
| hardware | bios | windows | supported | 1 | WMI Win32_BIOS | - |
| hardware | processors | linux | supported | 1 | /proc/cpuinfo | - |
| hardware | processors | macos | supported | 1 | sysctlbyname(machdep.cpu.*, hw.*cpu*) | - |
| hardware | processors | windows | supported | 1 | WMI Win32_Processor | - |
| hardware | memory | linux | constrained | 2 | run_bounded_subprocess(dmidecode -t memory) | falls back to the aggregate MemTotal from /proc/meminfo (no per-DIMM detail) when dmidecode is unavailable or unprivileged |
| hardware | memory | macos | constrained | 1 | sysctlbyname(hw.memsize) | aggregate total only, no per-DIMM breakdown (macOS has no public per-DIMM API) |
| hardware | memory | windows | supported | 1 | WMI Win32_PhysicalMemory | - |
| hardware | disks | linux | supported | 1 | /sys/block/*/{size,device/model} native walk | - |
| hardware | disks | macos | supported | 2 | run_bounded_subprocess(system_profiler SPStorageDataType SPNVMeDataType SPSerialATADataType -json) + native parser (hardware_disks_macos.hpp) | - |
| hardware | disks | windows | supported | 1 | WMI Win32_DiskDrive | - |
| hardware | drivers | linux | supported | 1 | /proc/modules | - |
| hardware | drivers | macos | unsupported | - | - | - |
| hardware | drivers | windows | supported | 1 | WMI Win32_PnPSignedDriver | - |
| hardware | system | linux | supported | 1 | /sys/class/dmi/id/product_serial + product_uuid | - |
| hardware | system | macos | supported | 1 | IOServiceGetMatchingService(IOPlatformExpertDevice) + IORegistryEntryCreateCFProperty(kIOPlatformSerialNumberKey/kIOPlatformUUIDKey) | - |
| hardware | system | windows | supported | 1 | WMI Win32_BIOS.SerialNumber + Win32_ComputerSystemProduct.UUID | - |
| http_client | download | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | download | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | download | windows | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | windows | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | windows | supported | 1 | cpp-httplib (native sockets) | - |
| installed_apps | list | linux | supported | 2 | dpkg-query/rpm/pacman via bounded argv runner | - |
| installed_apps | list | macos | supported | 2 | system_profiler via bounded argv runner + native CFBundle enrichment | - |
| installed_apps | list | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| installed_apps | query | linux | supported | 2 | dpkg-query/rpm/pacman via bounded argv runner | - |
| installed_apps | query | macos | supported | 2 | system_profiler via bounded argv runner | - |
| installed_apps | query | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| installed_apps | list_per_user | linux | supported | 2 | dpkg-query/rpm/pacman via bounded argv runner | - |
| installed_apps | list_per_user | macos | supported | 2 | system_profiler + brew via bounded argv runner | - |
| installed_apps | list_per_user | windows | supported | 1 | Reg*W enumeration of HKU\\<SID>'s Uninstall key, mounting NTUSER.DAT via RegLoadKeyW when not already loaded | - |
| installed_apps | list_inventory | linux | supported | 2 | dpkg-query/rpm/pacman/apk via bounded argv runner | - |
| installed_apps | list_inventory | macos | supported | 2 | system_profiler + pkgutil via bounded argv runner + native SecCode/CFBundle enrichment | - |
| installed_apps | list_inventory | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| interaction | notify | linux | supported | 2 | notify_send | - |
| interaction | notify | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | notify | windows | supported | 1 | shell_notifyicon | - |
| interaction | message_box | linux | supported | 2 | zenity | - |
| interaction | message_box | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | message_box | windows | supported | 1 | messageboxw | - |
| interaction | input | linux | supported | 2 | zenity | - |
| interaction | input | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | input | windows | supported | 3 | powershell_inputbox | - |
| interaction | survey | linux | supported | 2 | zenity | - |
| interaction | survey | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | survey | windows | supported | 3 | powershell_winforms | - |
| interaction | set_dnd | linux | supported | 1 | local_kv_store | - |
| interaction | set_dnd | macos | supported | 1 | local_kv_store | - |
| interaction | set_dnd | windows | supported | 1 | local_kv_store | - |
| ioc | check | linux | supported | 1 | procfs | - |
| ioc | check | macos | supported | 1 | libproc | UDP rows carry an empty state (no fabricated "LISTEN") — a real UDP listener still matches a port check, but its detail text differs from a TCP match; a port shared by more than one process (SO_REUSEPORT, prefork) reports the pid of one arbitrarily-chosen owner in its match detail, not every owner |
| ioc | check | windows | supported | 1 | iphlpapi_dnsapi | - |
| license_scan | list | linux | constrained | 2 | rpm/dpkg-query/openssl via bounded argv runner | declared-licence classification only (no lapse detection) for pkg_metadata; entitlement_certs' authoritative expiry still depends on the openssl CLI being present |
| license_scan | list | macos | constrained | 1 | filesystem_probe(glob+plist) | binary (bplist00) Info.plist files are not parsed; falls back to the bundle name with an empty version |
| license_scan | list | windows | supported | 1 | wmi+win32_registry | - |
| license_scan | surfaces | linux | constrained | 2 | rpm/dpkg-query/openssl via bounded argv runner | declared-licence classification only (no lapse detection) for pkg_metadata; entitlement_certs' authoritative expiry still depends on the openssl CLI being present |
| license_scan | surfaces | macos | constrained | 1 | filesystem_probe(glob+plist) | binary (bplist00) Info.plist files are not parsed; falls back to the bundle name with an empty version |
| license_scan | surfaces | windows | supported | 1 | wmi+win32_registry | - |
| msi_packages | list | linux | unsupported | - | - | - |
| msi_packages | list | macos | supported | 2 | pkgutil via bounded argv runner | - |
| msi_packages | list | windows | supported | 1 | msi_api | - |
| msi_packages | product_codes | linux | unsupported | - | - | - |
| msi_packages | product_codes | macos | supported | 2 | pkgutil via bounded argv runner | - |
| msi_packages | product_codes | windows | supported | 1 | msi_api | - |
| netprobe | icmp | linux | constrained | 1 | SOCK_DGRAM ICMP ping socket | requires net.ipv4.ping_group_range to admit the process group; reports not-permitted otherwise |
| netprobe | icmp | macos | supported | 1 | SOCK_DGRAM ICMP ping socket | - |
| netprobe | icmp | windows | supported | 1 | IcmpSendEcho | - |
| netprobe | tcp | linux | supported | 1 | non-blocking connect() timing | - |
| netprobe | tcp | macos | supported | 1 | non-blocking connect() timing | - |
| netprobe | tcp | windows | supported | 1 | non-blocking connect() timing | - |
| netprobe | dns | linux | supported | 1 | getaddrinfo | - |
| netprobe | dns | macos | supported | 1 | getaddrinfo | - |
| netprobe | dns | windows | supported | 1 | getaddrinfo | - |
| netstat | netstat_list | linux | supported | 1 | /proc/net/{tcp,udp}[6] | - |
| netstat | netstat_list | macos | supported | 1 | libproc | - |
| netstat | netstat_list | windows | supported | 1 | GetExtendedTcpTable/GetExtendedUdpTable | - |
| netstat | attribution | linux | supported | 1 | /proc/net/* + /proc/[pid]/{comm,exe,fd} | - |
| netstat | attribution | macos | supported | 1 | libproc | - |
| netstat | attribution | windows | supported | 1 | IP Helper API + QueryFullProcessImageNameW | - |
| network_actions | flush_dns | linux | constrained | 2 | resolvectl/systemd-resolve via bounded argv runner (sudo -n) | requires resolvectl (systemd-resolved) or the legacy systemd-resolve CLI; an honest failure is reported if neither is present |
| network_actions | flush_dns | macos | supported | 2 | dscacheutil + killall via bounded argv runner (sudo -n) | - |
| network_actions | flush_dns | windows | supported | 2 | ipconfig via bounded argv runner | - |
| network_actions | ping | linux | supported | 2 | system ping via bounded argv runner | - |
| network_actions | ping | macos | supported | 2 | system ping via bounded argv runner | - |
| network_actions | ping | windows | supported | 2 | system ping.exe via bounded argv runner | - |
| network_config | adapters | linux | supported | 1 | rtnetlink (RTM_GETLINK) | - |
| network_config | adapters | macos | supported | 1 | getifaddrs + SIOCGIFMEDIA | - |
| network_config | adapters | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | ip_addresses | linux | supported | 1 | rtnetlink (RTM_GETADDR/RTM_GETROUTE) | - |
| network_config | ip_addresses | macos | supported | 1 | getifaddrs + PF_ROUTE sysctl | - |
| network_config | ip_addresses | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | dns_servers | linux | supported | 1 | /etc/resolv.conf read | - |
| network_config | dns_servers | macos | supported | 1 | SCDynamicStore | - |
| network_config | dns_servers | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | proxy | linux | constrained | 1 | environment variables | reads the *_proxy variables from the agent process's own environment only; a system-wide, desktop-session or package-manager proxy the agent did not inherit is not reported |
| network_config | proxy | macos | constrained | 1 | SCDynamicStoreCopyProxies | reports the HTTP proxy and PAC URL, checking the primary network service first and then each scoped per-interface service; HTTPS/SOCKS/FTP proxies are not reported, so a host configured with only those reads as none |
| network_config | proxy | windows | supported | 1 | WinHttpGetIEProxyConfigForCurrentUser | - |
| network_config | dns_cache | linux | constrained | 2 | resolvectl via direct-argv runner | falls back to systemd-resolve statistics, or reports unavailable, when resolvectl is absent |
| network_config | dns_cache | macos | unsupported | - | - | - |
| network_config | dns_cache | windows | supported | 1 | DnsGetCacheDataTable (dnsapi.dll) | - |
| network_config | arp | linux | constrained | 1 | /proc/net/arp | IPv4 ARP entries only; /proc/net/arp carries no IPv6 neighbours (they live in the RTM_GETNEIGH table), and non-Ethernet or incomplete entries are not reported |
| network_config | arp | macos | constrained | 1 | PF_ROUTE sysctl RTF_LLINFO | ip and mac only; the interface name and static/dynamic type are not carried by the RTF_LLINFO dump and are emitted as '-' |
| network_config | arp | windows | supported | 1 | GetIpNetTable2 | - |
| network_diag | listening | linux | supported | 1 | /proc/net/tcp[6] | - |
| network_diag | listening | macos | supported | 1 | libproc | a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one arbitrarily-chosen owning PID, not one row per owner |
| network_diag | listening | windows | supported | 1 | GetExtendedTcpTable | - |
| network_diag | connections | linux | supported | 1 | /proc/net/tcp[6] | - |
| network_diag | connections | macos | supported | 1 | libproc | a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one arbitrarily-chosen owning PID, not one row per owner |
| network_diag | connections | windows | supported | 1 | GetExtendedTcpTable | - |
| os_info | os_name | linux | supported | 1 | /etc/os-release | - |
| os_info | os_name | macos | supported | 1 | SystemVersion.plist + sysctlbyname | - |
| os_info | os_name | windows | supported | 1 | Reg*W CurrentVersion\\ProductName + build-number correction | - |
| os_info | os_version | linux | supported | 1 | uname(2) | - |
| os_info | os_version | macos | supported | 1 | uname(2) + SystemVersion.plist + sysctlbyname | - |
| os_info | os_version | windows | supported | 1 | RtlGetVersion (ntdll) | - |
| os_info | os_build | linux | supported | 1 | /proc/version | - |
| os_info | os_build | macos | supported | 1 | SystemVersion.plist + sysctlbyname | - |
| os_info | os_build | windows | supported | 1 | Reg*W CurrentBuildNumber + UBR | - |
| os_info | os_arch | linux | supported | 1 | uname(2) | - |
| os_info | os_arch | macos | supported | 1 | uname(2) | - |
| os_info | os_arch | windows | supported | 1 | GetNativeSystemInfo | - |
| os_info | uptime | linux | supported | 1 | /proc/uptime | - |
| os_info | uptime | macos | supported | 1 | sysctl(2) KERN_BOOTTIME | - |
| os_info | uptime | windows | supported | 1 | GetTickCount64 | - |
| peripherals | usb | linux | supported | 1 | /sys/bus/usb/devices sysfs attribute reads | - |
| peripherals | usb | macos | supported | 1 | IOKit IOServiceMatching(IOUSBHostDevice) | - |
| peripherals | usb | windows | supported | 1 | SetupAPI SetupDiGetClassDevsW(USB enumerator) + SPDRP_HARDWAREID/COMPATIBLEIDS | - |
| peripherals | pci | linux | supported | 1 | /sys/bus/pci/devices sysfs attribute reads | - |
| peripherals | pci | macos | supported | 1 | IOKit IOServiceMatching(IOPCIDevice) | - |
| peripherals | pci | windows | supported | 1 | SetupAPI (PCI enumerator) | - |
| peripherals | thunderbolt | linux | constrained | 1 | /sys/bus/thunderbolt/devices sysfs reads | walk verified against a sysfs fixture tree only; no live Linux venue with a Thunderbolt bus in this run |
| peripherals | thunderbolt | macos | supported | 1 | IOKit IOServiceMatching(IOThunderboltSwitch) | - |
| peripherals | thunderbolt | windows | constrained | 1 | SetupAPI PCI enumerator, DEVICEDESC contains Thunderbolt/USB4 | string-heuristic identification; no Thunderbolt device class in SetupAPI |
| pkg_inventory | managers | linux | planned | 1 | tool presence + /var/lib/dpkg/arch, /etc/apt/sources.list.d count, /etc/yum.repos.d count, /etc/dnf/dnf.conf, /etc/pacman.conf + pacman.d/mirrorlist, /etc/apk/repositories + /etc/apk/arch | follows as its own PR |
| pkg_inventory | managers | macos | supported | 1 | Homebrew prefix layout: Library/Taps, Cellar, Caskroom | - |
| pkg_inventory | managers | windows | planned | 1 | ProgramData\\chocolatey lib/ walk + Program Files\\WindowsApps DesktopAppInstaller folder presence for winget; follows as its own PR | - |
| pkg_inventory | packages | linux | unsupported | 1 | none by design | installed_apps.get_inventory_linux owns the Linux package roster |
| pkg_inventory | packages | macos | supported | 1 | Cellar/<formula>/<version>, Caskroom/<cask>/<version> directory names | - |
| pkg_inventory | packages | windows | planned | 1 | chocolatey lib/<id>/<id>.nuspec via libxml2; follows as its own PR | - |
| platform_security | secure_boot | linux | supported | 1 | efivarfs reads of /sys/firmware/efi/efivars/SecureBoot-* and SetupMode-* (4-byte attributes + 1 data byte; errno-classified absent/unreadable) | - |
| platform_security | secure_boot | macos | unsupported | - | - | no public API; SIP reported under code_integrity |
| platform_security | secure_boot | windows | supported | 1 | HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State registry (UEFISecureBootEnabled) | - |
| platform_security | code_integrity | linux | supported | 1 | securityfs reads of /sys/kernel/security/lsm and /sys/kernel/security/lockdown (errno-classified absent/unreadable) | - |
| platform_security | code_integrity | macos | supported | 2 | spctl --status + csrutil status via run_bounded_subprocess | - |
| platform_security | code_integrity | windows | supported | 1 | HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy, Control\\DeviceGuard and Control\\Lsa\\LsaCfgFlags registry values | - |
| power_health | battery | linux | constrained | 1 | /sys/class/power_supply uevent parsing | fixture-verified; no live Linux venue in this run |
| power_health | battery | macos | supported | 1 | IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList | IOPS is used deliberately over the AppleSmartBattery IORegistry node, which is present, matched and active even on a battery-less Mac mini and would report a phantom battery; the battery-PRESENT path is fixture-tested and UNVERIFIED on real Mac battery hardware — the run host was a desktop |
| power_health | battery | windows | supported | 1 | GetSystemPowerStatus + CallNtPowerInformation(SystemBatteryState) | no-system-battery path measured live on the-rig (BatteryFlag=128); the battery-PRESENT path is now verified on real hardware (HP ZBook Firefly, PR #4009 review), which is what caught the AC-resting state being reported as unknown rather than not_charging |
| power_health | thermal | linux | constrained | 1 | /sys/class/thermal zone parsing | fixture-verified; no live Linux venue in this run |
| power_health | thermal | macos | constrained | 1 | NSProcessInfo.thermalState + IOPMGetThermalWarningLevel | reports a 4-level thermal-pressure enum, never a temperature reading |
| power_health | thermal | windows | constrained | 1 | PDH \\Thermal Zone Information(*)\\Temperature | zero live counter instances is the measured normal case on desktop hardware (the-rig, 2026-09-04); reports no_thermal_zones_exposed as an explicit success, never an error or a fabricated zero |
| power_health | power_plan | linux | planned | 1 | platform_profile | declared only; not implemented in this package |
| power_health | power_plan | macos | unsupported | - | - | macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted |
| power_health | power_plan | windows | supported | 1 | PowrProf PowerEnumerate + PowerReadFriendlyName + PowerGetActiveScheme | 4 schemes verified live on the-rig, 2026-09-04 (agrees with powercfg /list) |
| power_health | set_power_plan | linux | planned | 1 | platform_profile | declared only; not implemented in this package |
| power_health | set_power_plan | macos | unsupported | - | - | macOS has no named power schemes; IOPMSetPMPreferences is SPI — not adopted |
| power_health | set_power_plan | windows | supported | 1 | PowrProf PowerSetActiveScheme | - |
| printing | printers | linux | supported | 1 | IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib) | localhost:631 fallback for reads when no socket is found |
| printing | printers | macos | supported | 1 | IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib) | localhost:631 fallback for reads when no socket is found |
| printing | printers | windows | supported | 1 | winspool EnumPrintersW level 2 | - |
| printing | jobs | linux | supported | 1 | IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket | localhost:631 fallback for reads when no socket is found |
| printing | jobs | macos | supported | 1 | IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket | localhost:631 fallback for reads when no socket is found |
| printing | jobs | windows | supported | 1 | winspool EnumJobsW level 2 | - |
| printing | clear_queue | linux | constrained | 1 | IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred | measured in a Debian/Ubuntu cupsd container: container root/@SYSTEM (SystemGroup root lpadmin) cancelling another user's job succeeds (status 0x0000, I93-7) — but the production Linux agent runs unprivileged (docs/agent-privilege-model.md), never root or @SYSTEM, so an ordinary non-owning cancel is correctly refused (403) before Cancel-Job is ever reached; reliable only for a job the agent's own identity owns |
| printing | clear_queue | macos | constrained | 1 | IPP Cancel-Job on one job id over the CUPS Unix socket with Authorization: PeerCred | PROVISIONAL — cupsd.conf Cancel-Job policy requires @OWNER/@AUTHKEY(system.print.operator)/@admin/@lpadmin (no @SYSTEM); header accepted by cupsd, authorisation outcome for a non-owned job UNMEASURED |
| printing | clear_queue | windows | supported | 1 | winspool SetJobW JOB_CONTROL_CANCEL on one job id | cancel measured only under Administrators and SYSTEM (SYSTEM is today's agent identity, #1442); a least-privileged identity cancelling any job (its own or another user's) is unmeasured, and that a PRINTER_ACCESS_USE handle suffices for it is an extrapolation - see docs/agent-privilege-model.md |
| processes | list | linux | supported | 1 | /proc enumeration | - |
| processes | list | macos | supported | 1 | sysctl(KERN_PROC_ALL) | - |
| processes | list | windows | supported | 1 | CreateToolhelp32Snapshot | - |
| processes | list_hashed | linux | supported | 1 | /proc enumeration + readlink(/proc/<pid>/exe) + SHA-256 | - |
| processes | list_hashed | macos | supported | 1 | sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256 | - |
| processes | list_hashed | windows | supported | 1 | CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256 | - |
| processes | list_tree | linux | supported | 1 | /proc enumeration + readlink(/proc/<pid>/exe) + SHA-256 | - |
| processes | list_tree | macos | supported | 1 | sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256 | - |
| processes | list_tree | windows | supported | 1 | CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256 | - |
| processes | query | linux | supported | 1 | /proc enumeration | - |
| processes | query | macos | supported | 1 | sysctl(KERN_PROC_ALL) | - |
| processes | query | windows | supported | 1 | CreateToolhelp32Snapshot | - |
| procfetch | procfetch_fetch | linux | supported | 1 | /proc enumeration + OpenSSL EVP SHA-1 | - |
| procfetch | procfetch_fetch | macos | supported | 1 | libproc (proc_listpids/proc_pidpath) + OpenSSL EVP SHA-1 | - |
| procfetch | procfetch_fetch | windows | supported | 1 | CreateToolhelp32Snapshot + BCrypt SHA-1 | - |
| quarantine | quarantine | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | quarantine | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | quarantine | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | unquarantine | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | unquarantine | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | unquarantine | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | status | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | status | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | status | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | whitelist | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | whitelist | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | whitelist | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| rdp_control | set_state | linux | unsupported | - | - | - |
| rdp_control | set_state | macos | unsupported | - | - | - |
| rdp_control | set_state | windows | supported | 1 | Win32 registry + INetFwPolicy2 COM + SCM | - |
| rdp_control | status | linux | unsupported | - | - | - |
| rdp_control | status | macos | unsupported | - | - | - |
| rdp_control | status | windows | supported | 1 | Win32 registry + INetFwPolicy2 COM + SCM | - |
| registry | get_value | linux | unsupported | - | - | - |
| registry | get_value | macos | unsupported | - | - | - |
| registry | get_value | windows | supported | 1 | win32_registry | - |
| registry | set_value | linux | unsupported | - | - | - |
| registry | set_value | macos | unsupported | - | - | - |
| registry | set_value | windows | supported | 1 | win32_registry | - |
| registry | delete_value | linux | unsupported | - | - | - |
| registry | delete_value | macos | unsupported | - | - | - |
| registry | delete_value | windows | supported | 1 | win32_registry | - |
| registry | delete_key | linux | unsupported | - | - | - |
| registry | delete_key | macos | unsupported | - | - | - |
| registry | delete_key | windows | supported | 1 | win32_registry | - |
| registry | key_exists | linux | unsupported | - | - | - |
| registry | key_exists | macos | unsupported | - | - | - |
| registry | key_exists | windows | supported | 1 | win32_registry | - |
| registry | enumerate_keys | linux | unsupported | - | - | - |
| registry | enumerate_keys | macos | unsupported | - | - | - |
| registry | enumerate_keys | windows | supported | 1 | win32_registry | - |
| registry | enumerate_values | linux | unsupported | - | - | - |
| registry | enumerate_values | macos | unsupported | - | - | - |
| registry | enumerate_values | windows | supported | 1 | win32_registry | - |
| registry | get_user_value | linux | unsupported | - | - | - |
| registry | get_user_value | macos | unsupported | - | - | - |
| registry | get_user_value | windows | supported | 1 | win32_registry+hive_mount | - |
| registry | list_profiles | linux | unsupported | - | - | - |
| registry | list_profiles | macos | unsupported | - | - | - |
| registry | list_profiles | windows | supported | 1 | win32_registry | - |
| runtimes | dotnet | linux | supported | 1 | /usr/share/dotnet, /usr/lib/dotnet, /usr/lib64/dotnet shared/<framework>/<version> and sdk/<version> directory walk; network mounts skipped via /proc/self/mountinfo | - |
| runtimes | dotnet | macos | planned | 1 | /usr/local/share/dotnet/shared walk | planned; the action answers a single unsupported status row on this OS |
| runtimes | dotnet | windows | planned | 1 | NDP release-key table + dotnet InstalledVersions + Program Files walk | planned; the action answers a single unsupported status row on this OS |
| runtimes | jvm | linux | supported | 1 | <home>/release file reads under /usr/lib/jvm, /opt/java, /usr/lib64/jvm, /var/opt/java (bin/java probe when a home has no release); network mounts skipped via /proc/self/mountinfo | - |
| runtimes | jvm | macos | planned | 1 | /Library/Java/JavaVirtualMachines/*/Contents/Info.plist JavaVM dict + Contents/Home/release | planned; the action answers a single unsupported status row on this OS |
| runtimes | jvm | windows | planned | 1 | JavaSoft keys + Program Files\\Java walk | planned; the action answers a single unsupported status row on this OS |
| sccm | client_version | linux | unsupported | - | - | - |
| sccm | client_version | macos | unsupported | - | - | - |
| sccm | client_version | windows | supported | 1 | registry+scm | - |
| sccm | site | linux | unsupported | - | - | - |
| sccm | site | macos | unsupported | - | - | - |
| sccm | site | windows | supported | 1 | registry+com_dispatch | - |
| script_exec | exec | linux | supported | 2 | subprocess_runner:direct_argv | - |
| script_exec | exec | macos | supported | 2 | subprocess_runner:direct_argv | - |
| script_exec | exec | windows | supported | 2 | subprocess_runner:direct_argv | - |
| script_exec | powershell | linux | unsupported | - | - | - |
| script_exec | powershell | macos | unsupported | - | - | - |
| script_exec | powershell | windows | supported | 3 | subprocess_runner:powershell_encodedcommand | - |
| script_exec | bash | linux | supported | 3 | subprocess_runner:bash_c | - |
| script_exec | bash | macos | supported | 3 | subprocess_runner:bash_c | - |
| script_exec | bash | windows | unsupported | - | - | - |
| services | list | linux | supported | 2 | runner argv 'systemctl list-units' | - |
| services | list | macos | supported | 2 | runner argv 'launchctl list' | - |
| services | list | windows | supported | 1 | win32_service_api | - |
| services | running | linux | supported | 2 | runner argv 'systemctl list-units' | - |
| services | running | macos | supported | 2 | runner argv 'launchctl list' | - |
| services | running | windows | supported | 1 | win32_service_api | - |
| services | set_start_mode | linux | supported | 2 | runner argv 'sudo -n -- systemctl enable\|disable\|mask\|unmask' | - |
| services | set_start_mode | macos | supported | 2 | runner argv 'sudo -n -- launchctl enable\|disable' | - |
| services | set_start_mode | windows | supported | 1 | win32_service_api | - |
| software_actions | list_upgradable | linux | supported | 2 | apt/yum check-update via bounded argv runner | - |
| software_actions | list_upgradable | macos | supported | 2 | softwareupdate -l via bounded argv runner | - |
| software_actions | list_upgradable | windows | constrained | 2 | winget via bounded argv runner | winget is a PER-USER App Execution Alias under %LOCALAPPDATA%; under the shipped LocalSystem service account that path does not exist, so this leg resolves only when the agent runs in a user-session context. An unresolvable winget reports UNAVAILABLE, never a clean empty result |
| software_actions | installed_count | linux | supported | 2 | dpkg-query/rpm via bounded argv runner | - |
| software_actions | installed_count | macos | supported | 2 | pkgutil --pkgs via bounded argv runner | - |
| software_actions | installed_count | windows | supported | 1 | native Reg*W subkey count of the Uninstall key | reads only the default (64-bit) registry view, matching the powershell payload it replaced; 32-bit applications registered under WOW6432Node are not counted |
| status | version | linux | supported | 1 | in-process (compiled version constants) | - |
| status | version | macos | supported | 1 | in-process (compiled version constants) | - |
| status | version | windows | supported | 1 | in-process (compiled version constants) | - |
| status | info | linux | supported | 1 | uname(2) + gethostname(3) | - |
| status | info | macos | supported | 1 | uname(2) + gethostname(3) | - |
| status | info | windows | supported | 1 | GetNativeSystemInfo + GetComputerNameA | - |
| status | health | linux | supported | 1 | /proc/self/status VmRSS + steady_clock | - |
| status | health | macos | supported | 1 | task_info(MACH_TASK_BASIC_INFO) + steady_clock | - |
| status | health | windows | supported | 1 | K32GetProcessMemoryInfo + steady_clock | - |
| status | plugins | linux | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | plugins | macos | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | plugins | windows | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | modules | linux | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | modules | macos | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | modules | windows | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | connection | linux | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | connection | macos | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | connection | windows | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | switch | linux | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | switch | macos | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | switch | windows | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | config | linux | supported | 1 | in-process agent config (agent.*) | - |
| status | config | macos | supported | 1 | in-process agent config (agent.*) | - |
| status | config | windows | supported | 1 | in-process agent config (agent.*) | - |
| storage | set | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | set | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | set | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | get | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | get | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | get | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | delete | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | delete | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | delete | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | list | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | list | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | list | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | clear | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| storage | clear | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| storage | clear | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| system_hardening | posture | linux | supported | 1 | allowlisted /proc/sys reads (open/read, errno-classified absent/unreadable; a missing key is absent only when statfs confirms its nearest existing directory is procfs) | - |
| system_hardening | posture | macos | supported | 1 | allowlisted sysctlbyname reads (kern.securelevel/coredump/sugid_coredump/bootargs) | - |
| system_hardening | posture | windows | supported | 1 | HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel mitigation registry + GetProcessMitigationPolicy (agent process) | Rig-verified 2026-09-21: MitigationOptions/MitigationAuditOptions are ABSENT on a default Windows 11 install (rows read `absent`, not a failure); a present value decodes as 16 two-bit nibbles (dep, sehop, aslr_bottom_up, aslr_high_entropy and cfg confirmed on hardware); GetProcessMitigationPolicy succeeds for DEP/ASLR/CFG on x64. |
| tags | set | linux | supported | 1 | local_json_store | - |
| tags | set | macos | supported | 1 | local_json_store | - |
| tags | set | windows | supported | 1 | local_json_store | - |
| tags | get | linux | supported | 1 | local_json_store | - |
| tags | get | macos | supported | 1 | local_json_store | - |
| tags | get | windows | supported | 1 | local_json_store | - |
| tags | get_all | linux | supported | 1 | local_json_store | - |
| tags | get_all | macos | supported | 1 | local_json_store | - |
| tags | get_all | windows | supported | 1 | local_json_store | - |
| tags | delete | linux | supported | 1 | local_json_store | - |
| tags | delete | macos | supported | 1 | local_json_store | - |
| tags | delete | windows | supported | 1 | local_json_store | - |
| tags | check | linux | supported | 1 | local_json_store | - |
| tags | check | macos | supported | 1 | local_json_store | - |
| tags | check | windows | supported | 1 | local_json_store | - |
| tags | clear | linux | supported | 1 | local_json_store | - |
| tags | clear | macos | supported | 1 | local_json_store | - |
| tags | clear | windows | supported | 1 | local_json_store | - |
| tags | count | linux | supported | 1 | local_json_store | - |
| tags | count | macos | supported | 1 | local_json_store | - |
| tags | count | windows | supported | 1 | local_json_store | - |
| tar | status | linux | supported | 1 | sqlite | - |
| tar | status | macos | supported | 1 | sqlite | - |
| tar | status | windows | supported | 1 | sqlite | - |
| tar | query | linux | supported | 1 | sqlite | - |
| tar | query | macos | supported | 1 | sqlite | - |
| tar | query | windows | supported | 1 | sqlite | - |
| tar | snapshot | linux | constrained | 2 | procfs+systemctl+dpkg_rpm(planned) | software inventory collection is PLANNED (dpkg/rpm not yet wired) on Linux; service enumeration runs bounded argv (rung 2) via the shared subprocess runner |
| tar | snapshot | macos | constrained | 2 | endpoint_security+nstat+launchctl+getfsstat+pkgutil(planned) | software collection is PLANNED on macOS; mapdrive is wired but outbound-live-only (getfsstat, no username, no inbound, no history); service enumeration runs bounded argv (rung 2) via the shared subprocess runner; process/tcp fall back to a poll without the Endpoint Security entitlement or nstat root privilege |
| tar | snapshot | windows | supported | 1 | etw+iphlpapi+scm+wts+wnet+wevtapi+registry | - |
| tar | export | linux | supported | 1 | sqlite | - |
| tar | export | macos | supported | 1 | sqlite | - |
| tar | export | windows | supported | 1 | sqlite | - |
| tar | configure | linux | supported | 1 | sqlite | - |
| tar | configure | macos | supported | 1 | sqlite | - |
| tar | configure | windows | supported | 1 | sqlite | - |
| tar | collect_fast | linux | constrained | 1 | procfs | dns opt-in sub-source is PLANNED (no-op) on Linux; arp opt-in sub-source is native (procfs, /proc/net/arp); core process/network/netqual collection is native |
| tar | collect_fast | macos | constrained | 1 | endpoint_security+nstat+route_sysctl | process/tcp fall back to a KERN_PROC_ALL/proc_pidfdinfo poll without the Endpoint Security entitlement or nstat root privilege; dns opt-in sub-source is PLANNED (no-op) on macOS; arp opt-in sub-source is native but constrained (route_sysctl, entry_type always 'unknown') |
| tar | collect_fast | windows | supported | 1 | etw+iphlpapi | - |
| tar | collect_slow | linux | constrained | 2 | systemctl+utmp | service enumeration runs bounded argv (rung 2) via the shared subprocess runner; startup_type reads 'unknown'; netconn opt-in source is PLANNED (no-op) on Linux |
| tar | collect_slow | macos | constrained | 2 | launchctl+utmpx+getfsstat | service enumeration runs bounded argv (rung 2) via the shared subprocess runner; no startup_type; mapdrive opt-in source is wired but outbound-live-only (getfsstat, no username, no inbound, no history); netconn opt-in source is PLANNED (no-op) on macOS |
| tar | collect_slow | windows | supported | 1 | scm+wts+wnet+wevtapi | - |
| tar | collect_perf | linux | supported | 1 | procfs | - |
| tar | collect_perf | macos | planned | 1 | host_statistics | - |
| tar | collect_perf | windows | supported | 1 | ntcounters | - |
| tar | collect_software | linux | planned | 2 | dpkg_rpm | - |
| tar | collect_software | macos | planned | 2 | pkgutil | - |
| tar | collect_software | windows | supported | 1 | registry | - |
| tar | rollup | linux | supported | 1 | sqlite | - |
| tar | rollup | macos | supported | 1 | sqlite | - |
| tar | rollup | windows | supported | 1 | sqlite | - |
| tar | sql | linux | supported | 1 | sqlite | - |
| tar | sql | macos | supported | 1 | sqlite | - |
| tar | sql | windows | supported | 1 | sqlite | - |
| tar | compatibility | linux | supported | 1 | sqlite | - |
| tar | compatibility | macos | supported | 1 | sqlite | - |
| tar | compatibility | windows | supported | 1 | sqlite | - |
| tar | fleet_snapshot | linux | supported | 1 | procfs | - |
| tar | fleet_snapshot | macos | constrained | 1 | libproc(proc_pidfdinfo) | inherent TOCTOU between pid enumeration and per-fd query; short-lived sockets may be missed |
| tar | fleet_snapshot | windows | supported | 1 | iphlpapi+win32_process_enum | - |
| tar | purge_source | linux | supported | 1 | sqlite | - |
| tar | purge_source | macos | supported | 1 | sqlite | - |
| tar | purge_source | windows | supported | 1 | sqlite | - |
| users | logged_on | linux | supported | 1 | utmp (setutent/getutent) | - |
| users | logged_on | macos | supported | 2 | runner argv 'who' | - |
| users | logged_on | windows | supported | 1 | WTSEnumerateSessionsW + WTSQuerySessionInformationW | - |
| users | sessions | linux | supported | 2 | runner argv 'w -h' | - |
| users | sessions | macos | supported | 2 | runner argv 'w -h' | - |
| users | sessions | windows | supported | 1 | WTSEnumerateSessionsW + WTSQuerySessionInformationW | - |
| users | local_users | linux | supported | 2 | /etc/passwd read + runner argv 'lastlog -u <user>' per account | - |
| users | local_users | macos | supported | 2 | runner argv 'dscl . -list/-read UserShell/RealName' + 'last -y -1 <user>' per account | - |
| users | local_users | windows | supported | 1 | NetUserEnum | - |
| users | local_admins | linux | supported | 1 | getgrnam(sudo/wheel) + getpwuid(0) | - |
| users | local_admins | macos | supported | 2 | runner argv 'dscl . -read /Groups/admin GroupMembership' | - |
| users | local_admins | windows | supported | 1 | NetLocalGroupGetMembers | - |
| users | group_members | linux | supported | 1 | getgrnam + /etc/passwd primary-group scan | - |
| users | group_members | macos | supported | 2 | runner argv 'dscl . -read /Groups/<name> GroupMembership' | - |
| users | group_members | windows | supported | 1 | NetLocalGroupGetMembers | - |
| users | primary_user | linux | supported | 2 | runner argv 'last -F' (max_lines=200 cap) | - |
| users | primary_user | macos | supported | 2 | runner argv 'last' (max_lines=200 cap) | - |
| users | primary_user | windows | supported | 1 | wevtapi (EvtQuery/EvtRender, Security 4624) | falls back to a native ProfileList registry enumeration (no login count) when the Security channel is inaccessible |
| users | session_history | linux | supported | 2 | runner argv 'last -F -n <count>' | - |
| users | session_history | macos | supported | 2 | runner argv 'last -n <count>' | - |
| users | session_history | windows | constrained | 1 | wevtapi (EvtQuery/EvtRender, Security 4624/4634) | requires an elevated token to read the Security channel; reports an error otherwise |
| vuln_scan | scan | linux | supported | 3 | popen(pkg-manager+iptables/nft/ufw) | - |
| vuln_scan | scan | macos | supported | 3 | popen(system_profiler/brew+security-checks) | - |
| vuln_scan | scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | cve_scan | linux | supported | 3 | popen(dpkg-query/rpm/pacman/apk) | - |
| vuln_scan | cve_scan | macos | supported | 3 | popen(system_profiler/brew) | - |
| vuln_scan | cve_scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | config_scan | linux | supported | 3 | popen(iptables/nft/ufw)+procfs | - |
| vuln_scan | config_scan | macos | supported | 3 | popen(spctl/fdesetup/csrutil/socketfilterfw) | - |
| vuln_scan | config_scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | summary | linux | supported | 3 | popen(pkg-manager+iptables/nft/ufw) | - |
| vuln_scan | summary | macos | supported | 3 | popen(system_profiler/brew+security-checks) | - |
| vuln_scan | summary | windows | supported | 1 | win32_registry | - |
| vuln_scan | inventory | linux | supported | 3 | popen(dpkg-query/rpm/pacman/apk) | - |
| vuln_scan | inventory | macos | supported | 3 | popen(system_profiler/brew) | - |
| vuln_scan | inventory | windows | supported | 1 | win32_registry | - |
| wifi | list_networks | linux | constrained | 1 | NetworkManager D-Bus (sd-bus) | reads NetworkManager's cached AccessPoints and does not itself initiate a scan (falls through to nmcli, which rescans, when NM reports no finished scan); then falls back to nmcli via the argv runner (rung 2), then an iw/iwlist text dump. Not yet exercised against a real Wi-Fi radio |
| wifi | list_networks | macos | constrained | 2 | airport -s / system_profiler via argv runner | airport was removed in macOS 14 (Sonoma); the system_profiler SPAirPortDataType fallback needs Location Services authorisation a background daemon may lack, so an unauthorised modern host yields no networks and an honest wifi\|info sentinel |
| wifi | list_networks | windows | supported | 1 | WlanGetAvailableNetworkList | - |
| wifi | connected | linux | constrained | 1 | NetworkManager D-Bus (sd-bus) | reports the device interface (e.g. wlan0) in the connection column rather than the NetworkManager profile name; falls back to nmcli via the argv runner (rung 2), then an iwconfig ESSID/Signal blob. Not yet exercised against a real Wi-Fi radio |
| wifi | connected | macos | constrained | 1 | CoreWLAN | Location Services (macOS 14+) may withhold SSID/BSSID from a background daemon |
| wifi | connected | windows | supported | 1 | WlanQueryInterface | - |
| windows_optional_features | list | linux | unsupported | - | - | Windows-only: DISM has no Linux/macOS equivalent |
| windows_optional_features | list | macos | unsupported | - | - | Windows-only: DISM has no Linux/macOS equivalent |
| windows_optional_features | list | windows | supported | 1 | DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo | verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08 |
| windows_optional_features | info | linux | unsupported | - | - | Windows-only: DISM has no Linux/macOS equivalent |
| windows_optional_features | info | macos | unsupported | - | - | Windows-only: DISM has no Linux/macOS equivalent |
| windows_optional_features | info | windows | supported | 1 | DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo | verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08 |
| windows_updates | installed | linux | supported | 2 | rpm+apt | - |
| windows_updates | installed | macos | supported | 2 | system_profiler | - |
| windows_updates | installed | windows | supported | 1 | wmi_bounded_query | - |
| windows_updates | missing | linux | supported | 2 | apt+yum | - |
| windows_updates | missing | macos | supported | 2 | softwareupdate | - |
| windows_updates | missing | windows | supported | 1 | wua_com_async_search | - |
| windows_updates | pending_reboot | linux | supported | 3 | filesystem+uname+vmlinuz_ls+needs_restarting | - |
| windows_updates | pending_reboot | macos | constrained | 2 | softwareupdate | bounded (60s deadline) since this migration, but still a slow network call -- no longer able to hang indefinitely on an offline/headless Mac |
| windows_updates | pending_reboot | windows | supported | 1 | registry | - |
| windows_updates | patch_connectivity | linux | supported | 1 | raw_sockets | - |
| windows_updates | patch_connectivity | macos | supported | 1 | raw_sockets | - |
| windows_updates | patch_connectivity | windows | supported | 1 | raw_sockets | - |
| wmi | query | linux | unsupported | - | - | - |
| wmi | query | macos | unsupported | - | - | - |
| wmi | query | windows | supported | 1 | wmi | - |
| wmi | get_instance | linux | unsupported | - | - | - |
| wmi | get_instance | macos | unsupported | - | - | - |
| wmi | get_instance | windows | supported | 1 | wmi | - |
| wol | wake | linux | supported | 1 | raw UDP broadcast socket | - |
| wol | wake | macos | supported | 1 | raw UDP broadcast socket | - |
| wol | wake | windows | supported | 1 | raw UDP broadcast socket | - |
| wol | check | linux | constrained | 1 | SOCK_DGRAM ICMP ping socket + TCP-connect fallback | requires net.ipv4.ping_group_range to admit the process group for ICMP; falls back to a TCP connect on port 443, and reports CONSTRAINED if neither mechanism is usable |
| wol | check | macos | supported | 1 | SOCK_DGRAM ICMP ping socket + TCP-connect fallback | - |
| wol | check | windows | supported | 1 | IcmpSendEcho + TCP-connect fallback | - |

**Undeclared plugins** (ABI<4, or ABI4 with no capability declarations yet — RATCHET: this count must never grow):

_none — every built plugin has adopted the ABI4 capability descriptor._
<!-- END GENERATED -->

## Make this self-maintaining

The truth already exists machine-readable; the durable fix is to render the matrix
from it rather than hand-curate:

- **TAR sources** — `tar_schema_registry.cpp` already declares
  `OsSupportStatus::{kSupported,kSupportedConstrained,kPlanned,kUnsupported}` *per
  source per OS* with a notes string. This is the model the rest should follow.
- **Guards** — the per-type support arrays (`registry_support::kHives`,
  `service_support::kStates`) + the `make_service_guard()` platform switch + the
  three-family dispatch in `guardian_engine.cpp`.
- **Spark mechanisms** — `make_{file,registry,service}_mechanism()` returning
  `nullptr` off-platform + the runtime INERT marking; already surfaced fleet-wide
  as `yuzu_fleet_spark_mechanisms{os,mechanism}`.
- **DEX signals** — the server-side coverage map `dex_obs_platforms()`
  (`dex_routes.cpp:132-174`, drift-net-tested) + the signal catalogue
  (`docs/dex-signal-catalog.md`, `dex_signal_catalog.*`).
- **Plugins** — per-OS is a mechanical scan of platform macros / per-OS TUs under
  `agents/plugins/*/src/`; a Windows-only plugin has a `#ifndef _WIN32` "not
  available" no-op.

**Status:** the generator machinery landed (PR1.1, [above](#generated-abi4-per-action-capability-declarations-2204))
as `tools/capmatrix-gen` + the `check-capability-matrix.sh` CI drift gate, reading
the ABI4 `YuzuPluginDescriptor.action_descriptors` array rather than any of the
four sources above directly. What's left is per-source/per-plugin **adoption** —
TAR, Guards, Spark, and DEX each still expose their per-OS truth through their
own hand-maintained structure (`OsSupportStatus`, the per-type support arrays,
`dex_obs_platforms()`); wiring each into `action_descriptors` so the *rest of
this page* (not just the generated block) renders from code is the remaining
follow-up. An in-product *Settings → Coverage* page reading the same array
remains a further possible step. Until every source is wired through, this page
is still the single place to look for the hand-curated sections above — keep it
honest.

## Verification

_2026-07-17 re-verification._ Every section above was re-checked against its cited
source of truth (not carried forward from the prior snapshot):

- **TAR** — all **13** registered sources read from `tar_schema_registry.cpp`
  `build_sources()`; the enum is four-valued (`kSupportedConstrained` added to the
  legend). The prior snapshot listed only arp/dns/software.
- **Guards** — confirmed exactly **three** families; corrected the **file guard**
  to observe-only (it never enforces on any platform, including Windows).
- **Spark** — corrected the "rung 2/3" note: rung 7 wired Guardian as consumer,
  but `prefer_spark_` defaults `false` with no `wire_spark_engine()` call sites, so
  legacy `IGuard` is still the only live path.
- **DEX** — macOS collector confirmed **real & shipped** (16 catalogued
  obs_types via `dex_macos_{signals,oslog,iokit}.cpp` — 17 raw, with
  `process.resource_limit` excluded from the taxonomy, per the
  `dex_obs_platforms()` drift-net; the reliability-signals cell says 16);
  source-of-truth updated to the `dex_obs_platforms()` coverage map.
- **Plugins** — all **49** enumerated (CLAUDE.md's "47/49" reconciled to 49): 43
  fully cross-platform, **4** Windows-only (`rdp_control`, `registry`, `sccm`,
  `wmi`), **2** uneven (`tar`; and `msi_packages` — now Win+macOS via `pkgutil`
  receipts, Linux still unimplemented). (The 43 became **42** in the 2026-07-21
  pass below once `interaction` moved to macOS-constrained; both tallies still
  sum to 49.)

_2026-07-21 macOS-parity consolidation._ This pass documents the macOS parity
batch **landing in the same PR as this restructure** — every cited capability
ships in the consolidated branch this doc describes, so each row is verifiable
against the code in the same diff. Cell moves and honesty corrections, each
verified against the cited code:

- **`msi_packages`** ⛔→✅ on macOS (`pkgutil` receipts; `msi_packages_macos.hpp`)
  — the one plugin that leaves the Windows-only set.
- **Network quality** ⛔→🟡 (throughput only) on macOS via `NET_RT_IFLIST2`
  (`net_quality_sampler.cpp`); retransmit + RTT deferred.
- **TAR — netqual** 🔜→🟡 on macOS — registry `netqual` now
  `kSupportedConstrained` via the `nstat` kctl client (`tar_netqual_nstat.cpp`,
  root-gated); **TAR — tcp** stays 🟡 but is now `nstat` event-driven (the stale
  "ES is the planned replacement" note corrected — ES has no inet-socket events).
- **DEX — per-app file version** ⛔→🟡 on macOS — `process.crashed`/`.hung` read a
  real `CFBundleShortVersionString` from the `.ips` (`dex_macos_signals.cpp`);
  procperf stays version-less. **DEX reliability signals** unchanged (16 catalogued
  obs_types on macOS, per the `dex_obs_platforms()` drift-net) but OSLog now
  pre-filters Error+Fault, reaching apfs `fs.corruption`.
- **`interaction`** ✅→🟡 on macOS — honest `not_reachable` from a GUI-less root
  daemon, no longer a fabricated `response|ok`.
- **New rows:** **Antivirus posture** (macOS 🟡 — real XProtect/EDR probes, no
  real-time-protection state) and **Live — Wi-Fi current connection** (macOS 🟡 —
  CoreWLAN, SSID/BSSID withheld from a daemon).
- **Honesty-only** (cell unchanged): `wol` `check` (native ICMP + TCP-connect
  fallback, no subprocess; was a false `unreachable`), `wifi connected`
  (CoreWLAN vs dead `airport -I`), `flush_dns`
  (dual-step + real exit codes), `registry`/`sccm`/`rdp_control` off-Windows
  sentinels (no false success on writes), `bitlocker`/`services`/`users`/
  `network_config` macOS enrichments, DNS-cache `unsupported` sentinel.

Not folded in: #2254 (per-OS DEX catalogue **health score**) is a server-side
scoring change and moves no agent capability cell.

_2026-07-21 review-round corrections_ (the #2243 review findings, resolved on the
consolidated branch):

- **Duplicate legacy table removed.** The pre-restructure table (and its trailing
  network-row blockquote) had been left in wholesale after the sectioned matrix,
  and the two disagreed on several cells; the sectioned table is now the only one.
  The blockquote's per-cell caveats live inline in the **Network quality** row.
- **New section grafted:** *Security posture & file/certificate surfaces* —
  Antivirus posture, Firewall posture, digital-signature verification and file
  version info (`filesystem`, Win + macOS), and the two macOS certificate rows
  (login-keychain read, verified SIP-aware delete).
- **Antivirus macOS cell reconciled to 🟡** (the honest reading: real
  XProtect/system-extension probes, but no queryable real-time-protection state)
  — the legacy table's ✅ was the drifted claim.
- **Plugin tally re-derived from the table:** 42 fully cross-platform,
  4 Windows-only, 2 uneven (`tar`, `msi_packages`), 1 macOS-constrained
  (`interaction`) = 49.
- **Spark note un-staled:** rung 7.7a *does* wire `wire_spark_engine()` at boot
  (lifecycle-only); the sole-live-path claim now hangs on `prefer_spark_=false`,
  not on a nonexistent call site.
- **TAR `tcp` macOS `capture_method` verified:** the registry now lists `nstat`
  (primary) + `proc_pidfdinfo` (fallback/seed) — the schema matches the shipped
  mechanism.
