# DEX Signal Catalogue

The Guardian DEX observer collects **110 reliability / employee-experience
signals** (wave 1: 20, wave 2: +50, wave 3: +33, wave 4: +7) from Windows
endpoints as ruleless observations (`rule_id = "__observation__"`, `event_type` =
the obs_type below). One catalogue-driven engine (`agents/core/src/dex_observer.cpp`)
arms one kernel-filtered `EvtSubscribe` per channel (22 channels); the signal
set, field extraction, privacy minimisations, and per-type rate caps all live
in `agents/core/src/dex_signal_catalog.cpp`. **Adding a signal is one catalogue
entry + one extractor + fixtures — zero server change** (the projection reads
the uniform `detail_json` keys generically, the `/dex` signal panel GROUP-BYs
whatever types exist, and unknown types render with a raw-label fallback under
"Other"). The dashboard groups the catalogue into 13 display groups; the
server-side mirror is `dex_signal_groups()` in `dex_routes.cpp` — keep it in
sync (the paired drift-net tests fail loudly if not). The server display
catalogue totals **114** entries: the 110 Windows event-catalogue types **+
`storage.low`** (one display entry, now emitted by all three platforms from
separate sources — the macOS IOKit poll, the Windows state poll, and the Linux
`/proc`+`statvfs` collector, see those sections below; it began macOS-only) **+
the three A3 `perf.*` sustained-breach types** (`perf.cpu_sustained`,
`perf.memory_pressure`, `perf.disk_latency_high` — the "Performance" display
family, Windows state poll + the Linux `/proc` poll, which emits all three: cpu
and memory from `/proc/stat`+`/proc/meminfo` and disk-latency from the
`/proc/diskstats` await breach (ordinary disks only — exotic/fabric storage is
excluded), see below).
The Windows *event* catalogue is 110; the state-poll signals (`storage.low`,
battery via `hw.error`, the `perf.*` breaches) ride alongside it without
catalogue entries, exactly like the macOS and Linux poll mechanisms.

Channels that do not exist on a given SKU fail to arm individually and are
logged + skipped (per-channel isolation; e.g. PushNotifications-Platform is
absent on some builds) — the catalogue row then honestly reads zero for that
device while other devices still report.

**Machine-readable access to one family.** `GET /api/v1/dex/catalogue/group`
and the MCP twin `get_dex_catalogue_group` (#4035, api-parity #2146 Batch A)
each take a `name` parameter that must **exactly** match one of the 13
display-group names `dex_signal_groups()` defines (e.g. `App reliability`,
`System stability`, `Network`) — the same names the `/dex` Catalogue dashboard
tab's family cards use. An unknown name is rejected (`404` on REST,
`kInvalidParams` on MCP) rather than silently returning an empty result. See
`docs/user-manual/rest-api.md` "DEX (Digital Employee Experience)" for the
full response shape.

## Uniform observation shape

Every signal maps onto the same shape — on the wire (`detail_json`), in the
projection (`guardian_observations`), and in the dashboard:

| Field | Meaning | Examples |
|---|---|---|
| `subject` | The failing entity | `chrome.exe`, `Spooler`, `HQ-Laser-3`, `KB5055555`, `CorpNet` |
| `reason` | Machine-ish failure code | `0xC0000005`, `0x80070643`, `7031`, `timeout` |
| `symbolic` | Human name for reason | `ACCESS_VIOLATION`, `WIFI_DISCONNECT` |
| `component` | Secondary entity | `ntdll.dll` (faulting module), NIC description, MAC |
| `metric` | Numeric payload where the signal IS a number | boot duration ms |
| `version` | Failing app's version on crash/hang signals, canonicalised to the 4-group quad by `yuzu::util::canon_version` — Windows WER `AppVersion`, macOS `.ips` `app_version` / `bundleInfo.CFBundleShortVersionString`; `""` = the shared unknown bucket (Linux; unversioned binaries) | `3.2.1.0` |

`process.crashed` additionally dual-emits the legacy slice-1 keys
(`process`/`exception_code`/`faulting_module`) for the PR #1311 transition;
remove once that window closes.

## Wave 1 — the first 20 signals

| # | obs_type | Channel / Provider / Event IDs | DEX meaning | Cap (events/h) | Privacy minimisation | Verified |
|---|---|---|---|---|---|---|
| 1 | `process.crashed` | Application / Application Error / 1000 | App crash | 120 | `AppPath` never extracted | **live** (canary + real Win11 record) |
| 2 | `process.hung` | Application / Application Hang / 1002 | App not responding | 120 | — | fixture |
| 3 | `service.crashed` | System / Service Control Manager / 7031, 7034 | Service died unexpectedly | 60 | — | fixture + UAT canary |
| 4 | `service.start_failed` | System / Service Control Manager / 7000 | Service failed to start | 60 | — | fixture + UAT canary |
| 5 | `os.bugcheck` | System / WER-SystemErrorReporting **and** BugCheck / 1001 | BSOD | 30 | — | fixture |
| 6 | `os.power_loss` | System / Kernel-Power / 41 | Unexpected reboot (6008 deliberately excluded — co-fires with 41, would double-count) | 30 | — | fixture |
| 7 | `display.driver_reset` | System / Display / 4101 | GPU TDR (screen freeze/flash) | 60 | — | fixture |
| 8 | `hw.error` | System / WHEA-Logger / any id, Level ≤ 3 | Hardware (CPU/PCIe/memory) error | 30 | — | fixture |
| 9 | `disk.error` | System / disk / 7, 11, 51, 153 | Failing disk I/O (bad block / controller / paging / retried) | 30 | — | **real record** (event 11 added after a live box showed its disk failures land there) |
| 10 | `fs.corruption` | System / Ntfs **and** Microsoft-Windows-Ntfs / 55 | Filesystem corruption | 30 | — | fixture |
| 11 | `memory.exhausted` | System / Resource-Exhaustion-Detector / 2004 | Commit-charge exhaustion | 12 | — | fixture |
| 12 | `os.boot` | Diagnostics-Performance/Operational / 100 | Boot duration (ms, every boot — trendable) | 30 | — | fixture |
| 13 | `update.failed` | System / WindowsUpdateClient / 20 | Patch install failure | 30 | KB title kept (corp patch info) | fixture |
| 14 | `app_install.failed` | Application / MsiInstaller / 11708 | MSI install failure | 60 | — | fixture |
| 15 | `logon.temp_profile` | Application / User Profiles Service / 1511, 1508 | Temp profile / profile load failure | 12 | **username never extracted** | fixture |
| 16 | `gpo.failed` | System / GroupPolicy / 1125, 1129 | Group Policy processing failure | 12 | — | fixture |
| 17 | `network.wifi_drop` | WLAN-AutoConfig/Operational / 8003 | Wi-Fi disconnect (reason text kept) | 60 | SSID kept (network infra) | fixture |
| 18 | `network.dns_timeout` | System / DNS Client Events / 1014 | Name resolution failing | 30 | **queried hostname never extracted** (browsing behavior) | fixture |
| 19 | `network.ip_conflict` | System / Tcpip / 4199 | IP address conflict | 12 | — | fixture |
| 20 | `print.failed` | PrintService/Admin / 372 | Print failure (top helpdesk driver) | 60 | **document name + owner never extracted**; printer kept | fixture |

"fixture" = the extractor is pinned by a unit fixture encoding the provider's
manifest field layout; field-name drift on a real box degrades gracefully
(empty `subject`, occurrence still counted).

**Real-record verification (2026-06-10):** full-chain fixtures captured from a
live Win11 26100 box now pin `process.crashed` (slice 1), `service.crashed`
(7031), `service.start_failed` (7000 incl. the `%%1053` message-resource form),
`os.power_loss` (41), `os.boot` (100, 64.9 s boot), `update.failed` (20),
`app_install.failed` (11708), `network.wifi_drop` (8003 — **Level 4**, which is
why that spec carries no level filter), and `disk.error` (11). `process.hung`
is canary-verified through the live pipeline (synthetic 1002). Still
manifest-pinned (no local specimen exists — they require a BSOD, hardware
fault, FS corruption, DNS outage, etc.): `os.bugcheck`, `display.driver_reset`,
`hw.error`, `fs.corruption`, `memory.exhausted`, `logon.temp_profile`,
`gpo.failed`, `network.dns_timeout`, `network.ip_conflict`, `print.failed` —
each degrades to a counted occurrence if its field layout drifts.

**Dashboard visibility contract:** the `/dex` All-signals panel lists every
catalogued type, fired or not (quiet types as muted real-zero rows), so
operators see what the fleet monitors — `kDexCatalogueOrder` in
`dex_routes.cpp` is the server-side mirror of this table; keep both in sync
when adding a signal.

## Wave 2 — +50 signals (2026-06-10), by display group

Sources marked **real** are pinned by full-chain fixtures captured from a live
Win11 26100 box; the rest are manifest-best-effort and covered by the
whole-catalogue graceful-degradation test (empty/reordered fields → counted
occurrence, never a crash).

| Group | obs_type | Source | Notes / privacy |
|---|---|---|---|
| Boot, start-up & shutdown | `boot.degraded_app` | Diag-Perf/Op 101 **real** | subject=Name, metric=DegradationTime ms; **Path dropped** |
| | `boot.degraded_driver` | Diag-Perf 102 | same shape |
| | `boot.degraded_service` | Diag-Perf 103 **real** | same shape |
| | `boot.degraded_device` | Diag-Perf 109 | same shape |
| | `os.shutdown` | Diag-Perf 200 **real** | metric=ShutdownTime ms |
| | `shutdown.degraded` | Diag-Perf 203 **real** | app delaying shutdown |
| | `os.standby` | Diag-Perf 300 | occurrence + best-effort metric |
| | `os.standby_degraded` | Diag-Perf 301, 302 | resume slowed |
| | `logon.slow_subscriber` | Winlogon 6005, 6006 (Application) | e.g. GPClient — classic slow logon |
| | `os.uptime_report` | EventLog 6013 **real** | metric=uptime s (first numeric positional) |
| System stability | `os.dirty_shutdown` | EventLog 6008 **real** | co-fires with Kernel-Power 41 — never sum both |
| | `os.time_unsynced` | Time-Service 36, 47 **real** | metric=UnsynchronizedTimeSeconds |
| | `os.activation_failed` | Security-SPP 8198 (Application) | license activation |
| | `os.vss_error` | VSS 8193 (Application) | shadow-copy errors |
| | `fs.hive_recovered` | Kernel-General 5 | **hive path dropped** (ntuser.dat ⇒ username) |
| | `fs.autochk_ran` | Wininit 1001 (Application) | chkdsk output blob dropped |
| App reliability | `process.crashed_managed` | .NET Runtime 1026 **real** | app + exception TYPE only; **stack frames never shipped**; pairs with 1000 — crash counts use `process.crashed` alone |
| | `app.sxs_error` | SideBySide 33, 35, 59 | missing VC-runtime class; paths → basename |
| | `app.activation_failed` | Immersive-Shell / TWinUI 5973 | store-app activation |
| | `app.com_failed` | DistributedCOM 10005, 10010 | **10016 noise excluded** |
| | `app.error_popup` | Application Popup 26 **real** | the dialog the user actually saw (Caption+Message clipped) |
| | `app.shutdown_blocked` | RestartManager 10006 | **FullPath dropped** |
| Service health | `service.hung` | SCM 7022 | |
| | `service.start_timeout` | SCM 7009 **real** | params REVERSED vs 7000 (param2=service) |
| | `service.logon_failed` | SCM 7038 | **logon account dropped** |
| | `service.recovery_failed` | SCM 7032 | |
| Hardware & storage | `disk.smart_failure` | disk 52 | SMART predictive failure |
| | `disk.port_reset` | storahci + stornvme 129 | reset storms = dying disk/cable |
| | `fs.write_lost` | Ntfs 50 | delayed-write data loss |
| | `fs.database_corrupt` | ESENT 447, 454, 467 | **db paths dropped**, owner process kept |
| | `hw.device_start_failed` | Kernel-PnP/Configuration 411 **real** | DeviceInstanceId/DriverName/Status |
| | `hw.cpu_throttled` | Kernel-Processor-Power 37 | firmware thermal/power cap |
| Network | `network.wifi_connect_failed` | WLAN-AutoConfig 8002 **real** | SSID + FailureReason |
| | `network.dhcp_failed` | Dhcp-Client/Admin 1001, 1002 | |
| | `network.vpn_failed` | RasClient 20227 (Application) | **dialing user (insert %1) never read** |
| | `network.smb_failed` | SmbClient/Connectivity 30803 | server name kept (corp infra) |
| | `network.name_conflict` | NetBT 4319 | |
| Identity & logon | `logon.no_dc` | NETLOGON 5719 | domain kept |
| | `security.kerberos_error` | Security-Kerberos 4 | SPN/clock problems |
| | `logon.profile_locked` | User Profiles Service 1530 | **profile (≈person) not extracted** |
| | `logon.folder_redirect_failed` | Folder Redirection 502 | **folder paths dropped** |
| Security & protection | `security.rtp_disabled` | Defender 5001 | |
| | `security.threat_detected` | Defender 1116 | threat name kept; **file path + user dropped** |
| | `security.av_update_failed` | Defender 2001 **real** | Data names contain SPACES ('Error Code') |
| | `security.tamper_blocked` | Defender 5013 | |
| Updates & installs | `app_uninstall.failed` | MsiInstaller 11725 | same "Product: X --" parse as 11708 |
| | `app_install.appx_failed` | AppXDeployment-Server 404 **real** | PackageFullName + ErrorCode |
| | `update.transfer_failed` | Bits-Client 61 **real** | job name kept; **url dropped**; decimal `hr` → HRESULT hex |
| Printing | `print.driver_install_failed` | PrintService/Admin 215 | |
| | `print.plugin_failed` | PrintService/Admin 808 | dll → basename |

## Wave 3 — +33 signals (2026-06-10), the identity / remote-work / management lens

Real-record pins from the live box: Power-Troubleshooter 1 (**WakeDuration ms
metric** → resume-speed trend), User32 1074 (**param7 = initiating user,
dropped**; process basename + reason kept), TPM-WMI 1801 / Biometrics 1014 /
MDM 844 (validating the any-id + level≤2 pattern for providers whose error ids
vary), AAD 1097 (decimal `Error` → HRESULT hex; **ErrorMessage never shipped —
can embed UPNs**).

| Group | New types |
|---|---|
| Boot, start-up & shutdown | `boot.fast_startup_failed` (Kernel-Boot 29), `os.resume_report` (Power-Troubleshooter 1, metric), `os.restart_initiated` (User32 1074, user dropped) |
| System stability | `os.shadow_copies_lost` (volsnap 25), `os.crashdump_disabled` (volmgr 46), `display.dwm_exited` (DWM 9009) |
| App reliability | `process.file_access_failure` (1005, file path dropped), `app.push_notification_error` (WPN any-err), `app.file_association_reset` (Shell-Core 62), `app.staterepo_error` (StateRepository any-err) |
| Service health | `service.dependency_failed` (SCM 7001) |
| File system | `fs.flush_failed` (Ntfs 57) |
| Hardware & storage | `hw.user_driver_error` (UMDF 10110/10111), `hw.tpm_error` (TPM-WMI any-err) |
| Network | `network.port_exhaustion` (Tcpip 4227/4231), `network.smb_write_lost` (mrxsmb 50), `network.dns_register_failed` (DNS-Client 8015/8016), `session.rdp_disconnected` (TS-LSM 24/39/40 — **user + client address dropped**) |
| Identity & logon | `logon.winlogon_terminated` (4005), `logon.machine_trust_failed` (NETLOGON 3210), `logon.biometric_error` (any-err), `logon.hello_error` (any-err), `logon.aad_token_error` (AAD 1097/1098), `security.auth_error` (LsaSrv 40960/40961) |
| Security & protection | `security.tls_alert` (Schannel 36874/36887), `security.threat_action_failed` (Defender 1119), `security.rtp_error` (3002), `security.bitlocker_error` (any-err), `security.cert_enroll_failed` (AutoEnrollment 6/13) |
| Updates & installs | `update.check_failed` (WUC 16/25), `update.download_failed` (WUC 31) |
| Policy & management | `gpo.cse_failed` (GroupPolicy 1085), `mgmt.mdm_error` (DeviceManagement any-err) — `gpo.failed` moved into this group |

Deliberately still excluded: Security-channel logon events (privilege-gated),
Task Scheduler (channel disabled by default), DCOM 10016 + WMI-Activity 5858
(noise), app start-times / audio glitches / NCSI (need ETW collectors, not
event IDs — collector-gated future work).

## Wave 4 — +7 signals (2026-06-22), power-management + driver reliability

Real-record-pinned from a live HP ZBook Firefly 14 G8 (Win11 26100). The driving
case: a Wi-Fi adapter cycling D3 low-power thousands of times in a fortnight, a
hundreds-per-month Modern-standby exit count, and unclean reboots the user
recovered by holding the power button. DEX now **captures and surfaces** each of
these as FACTS — it does not infer the root cause (that is the operator's job).

| obs_type / change | Source | Extract | Notes / privacy |
|---|---|---|---|
| `os.power_loss` (enhanced, NOT new) | Kernel-Power 41 `PowerButtonTimestamp` | reason `power button` when the timestamp is non-zero (the button was pressed before the unclean reboot — the classic hold-to-recover-from-a-hard-hang), `power loss` when zero (sudden supply loss); `LongPowerButtonPressDetected=true` ⇒ the 4-second forced hold. bugcheck path unchanged. | **real** — pins the live record's `PowerButtonTimestamp=134266075744470540`, `BugcheckCode=0`. A factual discriminator, no inference. |
| `os.modern_standby_exit` | Kernel-Power 507 | `metric` = **deep-idle (DRIPS) residency %** (`DripsResidencyInUs/DurationInUs`); `reason` = the provider's numeric exit Reason; sentence carries the standby duration. 0% means the platform never reached deep idle while "asleep". | **real** — `DripsResidencyInUs=0` of a 17.4 s standby ⇒ 0%. Fires every resume; the near-empty `os.standby`(300) path often doesn't fire on Modern-Standby boxes, so 507 fills a real gap rather than duplicating it. No PII. |
| `network.adapter_driver_dump` | Netwtw10 **7025 only** (classic, positional) | `subject` = adapter (Data[1]), `component` = NDIS device (Data[0]), `reason` = `d3-dump`. | **real** — `Intel(R) Wi-Fi 6 AX201 160MHz` / `\Device\NDMP5`. **Vendor-coupled**: `Netwtw*` is the Intel Wi-Fi driver; the provider name tracks driver generation and the IDs are Intel-specific — there is no vendor-neutral event-log signal for D3 thrash (the generic version needs an ETW D-state collector, which the catalogue defers). 7026 is the paired completion record and co-fires, so only 7025 is catalogued (cataloguing both would double-count each incident, cf. the 6008/41 exclusion). A thrashing adapter storms past the cap; the overflow is dropped with the one-warn-per-hour log line (a count-preserving summary is deferred — see Rate caps). No PII. |
| `hw.driver_load_failed` | Kernel-PnP 219 | `subject` = the driver basename (`FailureName`, e.g. `WUDFRd`), `component` = the device instance id (`DriverName`, kept — hardware identity, no user content), `reason` = decimal `Status` → hex NTSTATUS. | **real** — `\Driver\WUDFRd` / `0xC0000365`. **Distinct from `hw.device_start_failed` (PnP 411)** — a driver failing to *load* vs a device failing to *start*. |
| `hw.battery_error` | Kernel-Power 521 | Emits ONLY when `ErrorBatteryCount` or `AbandonedBatteryCount` > 0; a benign battery-count change (all-zero) **self-suppresses** in the extractor (`SignalObservation::suppress` → `extract_signal` returns nullopt) so the type carries only real faults. `metric` = count of faulted batteries; `reason` = `error`/`abandoned`. | **real** (suppress path pinned from the healthy live record). Complements the state-poll wear signal (`hw.error` subject=`battery`, full-charge < 80% of design) — wear vs an error/abandoned state. |

**Batch 2 — cheap additions on already-armed channels** (no new `EvtSubscribe`):

| obs_type | Source | Extract | Notes / privacy |
|---|---|---|---|
| `service.unresponsive` | SCM 7011 | `subject` = service (`param2` — **params REVERSED** vs 7022, exactly like 7009), `reason` = the timeout ms. Runtime unresponsiveness (a service stopped answering a control), distinct from `service.hung` (7022 = hung on *starting*). | **real** — `param2="HPAudioAnalytics"`. NOT folded into `service.hung`: that extractor reads `param1` (which here is the timeout `30000`), so a fold would mis-extract the subject. |
| `service.shutdown_failed` | SCM 7043 | `subject` = service (`param1`, normal SCM layout); a trailing `Binary` is skipped. | **real** — `param1="Windows Biometric Service"`. |
| `network.adapter_reset` | Microsoft-Windows-NDIS 10317 | `subject` = `AdapterName`, `reason` = `MiniportEventEnum` (the provider's numeric event code, surfaced verbatim — no public text map). | **real** — `AdapterName="Microsoft Wi-Fi Direct Virtual Adapter #2"`. **Vendor-NEUTRAL**: NDIS is the generic networking layer, so it fires for **any** NIC — the generic complement to the Intel-specific `network.adapter_driver_dump`. *Caveat:* virtual adapters (Wi-Fi Direct / Hyper-V / VPN) also raise 10317 and can be noisier than physical NICs — `AdapterName` makes that visible and the rate cap bounds volume. No PII. |

**The `suppress` primitive (new).** `SignalObservation::suppress` lets an extractor
veto a matched event that empty/benign fields cannot confirm as a real signal —
`extract_signal` returns `nullopt`, so it never emits. `hw.battery_error` is the
first user (Kernel-Power 521 fires on every battery-count change, mostly benign);
the catalogue's graceful-degradation test allows the listed suppressing types to
return `nullopt` on empty fields rather than counting a non-event.

## Windows state poll (shipped 2026-06-12 — `dex_win_poll.cpp`)

The event engine is blind to bad *states* the OS never logs: a volume filling
up and a battery wearing out have no Event Log record. `dex_win_poll` is the
Windows analogue of the macOS IOKit poll — a companion thread owned by the
Windows DEX observer (started only when at least one event channel armed),
sleeping to the earliest next-due poll and polling on three cadences with the
same **poll-and-latch** discipline (emit on the transition INTO a bad state,
suppress while it persists, re-arm on recovery; the latch replaces a rate
cap). First poll on the first tick, never at-arm. BRD rows 20–21
(`docs/dex-brd-coverage.md`, slice D1) + rows 13–15/124 (slice A3).

| obs_type | Source | Cadence | Threshold |
|---|---|---|---|
| `storage.low` | `GetDiskFreeSpaceExW` over lettered `DRIVE_FIXED` volumes (per-volume latch; unreadable/locked volumes skipped — never a signal) | 10 min | >= 90% used OR < 5 GiB free (identical to macOS) |
| `hw.error` (subject=`battery`) | battery device interface + `IOCTL_BATTERY_QUERY_INFORMATION` (DesignedCapacity / FullChargedCapacity / CycleCount; `GENERIC_READ` only) | hourly | full-charge < 80% of design (identical to macOS); no battery / zero design capacity never emits |
| `perf.cpu_sustained` | `GetSystemTimes` cumulative busy % (`dex_perf_breach.cpp`) | 120 s sample | avg >= 90% busy for 5 consecutive samples (10 min); re-arm < 70% for 3 |
| `perf.memory_pressure` | `GetPerformanceInfo` commit charge vs limit (commit, not physical RAM — high physical use is normal caching; commit near the limit means allocations fail) | 120 s sample | >= 90% of commit limit for 10 min; re-arm < 80% for 3 samples |
| `perf.disk_latency_high` | `IOCTL_DISK_PERFORMANCE` per-IO service time summed over physical disks (zero IOs in an interval reads 0 ms — an idle disk is healthy) | 120 s sample | avg >= 25 ms/IO for 10 min; re-arm < 15 ms for 3 samples |

The A3 `perf.*` rows (slice A3, 2026-06-12) are **sustained-breach hysteresis**
latches (`dex_perf_breach.{hpp,cpp}`): a breach needs the full sustain window
of consecutive bad samples to fire ONCE with the window average as `metric`,
then re-arms only after consecutive valid samples below the (lower) exit
threshold — flap-proof and bounded at ~4 observations/hour/type worst case. An
invalid sample (read failure, reboot counter reset) resets the streaks but
never clears the latch. Thresholds are hardcoded sane defaults until F1 makes
them operator-tunable (the D3 blast-radius precedent). The A1 TAR perf
warehouse is the *history* of these same counters; this is the *alerting* leg
(the BRD's "real-time + historical + alerting" decomposition).

The decision functions are pure and unit-tested on every host
(`test_dex_win_poll.cpp`, `test_dex_perf_breach.cpp`); the Win32 mechanism is
the impure shell, mirroring the macOS pure-parser/impure-engine split.

## Privacy / works-council contract

Extractors drop user content **at the edge, before anything leaves the
device**: DNS queried names, print document names/owners, profile usernames,
image paths; on Linux, `storage.low` emits the backing-device identifier (`sda1`,
or the ZFS pool), never the mount path. What is never extracted can never be
exfiltrated or mis-scoped.
This is the data-minimisation half of the co-determination posture (see memory
`project-telemetry-privacy-works-council`); the per-device drill-down is
additionally permission-gated and audit-logged server-side. Remaining product
gaps (per-category collection toggles, individual-view kill switch,
pseudonymization, operator-set retention) are tracked as roadmap items, not
solved here.

## Rate caps

Each obs_type carries `max_per_hour`; the engine counts per fixed hour-bucket and
emits at most `cap` events per (type, hour), dropping the overflow with ONE warn
per (type, bucket). Storm-prone providers (WHEA corrected-error loops, failing
disks issuing retry storms, Wi-Fi flaps, the wave-4 D3-dump thrash) cannot flood
the wire or the Guardian event store. Caps are deliberately generous for genuine
incident rates.

Both the Windows observer and the Linux collector share the pure, every-CI-leg-
tested `DexRateLimiter` (`dex_rate_limiter.{hpp,cpp}`) — the Windows observer no
longer carries its own inline bucket. (The macOS collector's bespoke cap table is
a tracked follow-up.)

> A storm *summary* — surfacing the suppressed overflow count as one observation
> rather than dropping it silently — was scoped and deliberately **deferred**: as
> a same-obs_type row it aliased every obs_type-keyed consumer (blast-radius,
> alert routing, the app/health aggregations). A correct re-design (a dedicated
> reserved obs_type + a `yuzu_fleet_dex_rate_cap_*` metric) is tracked as its own
> slice. Today the cap drops the overflow with the one-warn-per-hour log line.

## macOS collector (shipped — `dex_macos_collector.cpp`)

The shape is OS-neutral, so the macOS collector reuses the SAME obs_type strings,
the SAME uniform `detail_json` keys, and the SAME wire mapping
(`signal_observation_to_event`) — **zero server or dashboard change**; the
signals render with their existing friendly labels and group under the existing
display groups, with `platform="macos"` driving the by-OS panel. The collector is
a drop-in `ISignalObserver` behind `make_dex_observer()` (`__APPLE__` branch),
using FOUR privilege-light mechanisms that need **neither an Endpoint Security
entitlement nor Full Disk Access** (the agent user's own
`~/Library/Logs/DiagnosticReports`, the world-readable
`/Library/Logs/DiagnosticReports`, the unified log via `log show`, and
`diskutil`/`system_profiler` are all readable unprivileged):

1. a **kqueue `EVFILT_VNODE` folder-watch** over both DiagnosticReports
   directories — idle until a report is written, then a rescan parses the new
   file. ReportCrash writes atomically via a hidden `.<name>.ips` temp + rename,
   so the watcher **skips all dotfiles** and only ever reads the final, complete
   report (this avoids a half-written read AND a temp-path/final-path
   double-count);
2. a periodic **`sysctl(KERN_BOOTTIME)`** read → the `os.uptime_report` scalar;
3. a periodic **unified-log poll** (`dex_macos_oslog.{hpp,cpp}`): on the same 60 s
   kqueue timer it runs `log show --start <checkpoint> --predicate <p> --style
   ndjson`, parses each JSON log event, and advances a checkpoint (with a
   boundary-second dedup set for the inclusive `--start`). Deliberately a bounded
   poll, NOT a persistent `log stream` child and NOT the Objective-C `OSLogStore`
   framework — keeps the agent pure C++ and NFR-friendly (~0.7 s/poll; logd does
   the filtering server-side so the agent never sees the firehose). This is the
   macOS analogue of the Windows single `EvtSubscribe` mechanism: it unlocks the
   "an event happened" signals that land in the log rather than in report files;
4. an **IOKit/system-tool poll** (`dex_macos_iokit.{hpp,cpp}`): two cadences —
   hourly `diskutil info` + `system_profiler SPPowerDataType` (battery/SMART,
   slow-changing) and every 10 min `df` + `pmset -g therm` + `memory_pressure -Q`
   (disk/thermal/memory, fluctuating). Emits **only on a transition into a bad
   state** (poll-and-diff: latch on, suppress while it persists, re-arm on
   recovery) — these are STATE not events. Covers Hardware & storage (which the
   unified log doesn't) plus the employee-felt "full / hot / low-memory" states.

The fiddly extraction is in the pure, framework-free `dex_macos_signals.cpp` /
`dex_macos_oslog.cpp` / `dex_macos_iokit.cpp` (an `.ips` is two concatenated JSON
documents; an ndjson log line is one JSON object; `diskutil`/`system_profiler`
output is `Key: value` text), unit-tested on every host (incl. MSVC) against
**real captured records** from a macOS 26.5 / Apple Silicon box
(`test_dex_macos.cpp`).

The signals below reuse existing Windows obs_types wherever one fits (friendly
labels + correct heading for free), giving **coverage of ~10 of the 11 DEX
headings unprivileged**. "live" = seen end-to-end on `/dex`; "real-record" =
parser pinned to a captured record; "best-effort" = parser written to the known
shape, awaiting a real failure specimen (the macOS analogue of the Windows
manifest fixtures — a healthy box has no failures to fire them).

The **11th heading, Security, is reachable unprivileged but not yet shipped**:
XProtect detections and Gatekeeper blocks (→ `security.threat_detected`) live in
the unified log (`XProtect*` / `syspolicyd`, readable without an entitlement —
ESF is NOT required), but a healthy box only logs *scan activity* and unrelated
"blocked" noise, so writing a low-false-positive parser needs a real detection /
block specimen first. It is the next best-effort branch; shipping a guessed
parser now would mistake routine scans for detections.

| Heading | obs_type | macOS source | Status |
|---|---|---|---|
| Service/App Health | `process.crashed` | `.ips` crash (309/109/385) | **live** |
| | `service.crashed` | unified log: launchd abnormal exit | **live** |
| | `process.hung` | `.ips` spin/hang (288/388) | fixture |
| | `process.resource_limit` | `.diag` cpu/wakeups/disk-write budget (macOS-only, "Other") | **live** |
| System Stability | `os.bugcheck` | `.ips` kernel panic (210/110) | fixture |
| | `memory.exhausted` | `.ips` JetsamEvent (298, kill) + `memory_pressure -Q` <10% free (warning) | real-record |
| Boot/startup/shutdown | `os.uptime_report` | `sysctl kern.boottime` | **live** |
| Network | `network.wifi_drop` | unified log: symptomsd LQM / data-stall degradation | real-record |
| Updates & installs | `update.failed` | unified log: softwareupdated error/fault | best-effort |
| Printing | `print.failed` | unified log: cupsd error/fault | best-effort |
| Policy & management | `mgmt.mdm_error` | unified log: mdmclient error/fault | best-effort |
| Identity & logon | `logon.no_dc` | unified log: opendirectoryd error/fault | best-effort |
| File system | `fs.corruption` | unified log: `com.apple.apfs` error/fault | best-effort |
| Hardware & storage | `disk.smart_failure` | IOKit poll: `diskutil` SMART != Verified | real-record |
| | `hw.error` (battery) | IOKit poll: `system_profiler` battery condition / capacity <80% | real-record |
| | `storage.low` | IOKit poll: `df` Data volume >=90% full or <5 GiB free ("Disk nearly full"; same obs_type + thresholds as the Windows state poll) | real-record |
| | `hw.cpu_throttled` | IOKit poll: `pmset -g therm` CPU speed cap <100% | real-record |

**Boot duration (deliberately NOT shipped):** macOS exposes boot *start*
(`kern.boottime`) but no clean unprivileged boot-*complete* marker — the UI-ready
events (loginwindow/WindowServer) age out of the unified-log store within days, so
they can't be differenced on a long-uptime machine, and there is no boot-duration
event to parse. Rather than ship a fragile, unvalidatable parser, `os.boot`
(duration) stays Windows-only; the Boot heading carries `os.uptime_report` on
macOS.

**Two fidelity notes (honest, vs Windows):** (1) `service.crashed` — launchd logs
EVERY service exit, not only unexpected ones (Windows SCM 7031/7034 fire only on
unexpected termination), so this is broader; it filters to abnormal exits and the
rate cap clips a flapping service. (2) The error/fault-level system-process
signals (update/print/mdm/logon/fs) are **occurrence-based and tightly
predicated**: macOS over-uses "Error" level, so they fire only on real
daemon-level failures (a routine client error — bad printer, missing user — logs
at Default level and is correctly ignored), and the **raw eventMessage is never
shipped** (it can carry usernames/paths) — only "this subsystem failed on this
device". Lower per-signal richness, but low false-positive and privacy-safe.

**Privacy at the edge (same contract as Windows):** a crash report's `procPath`,
`parentProc`, thread register state, and image paths are NEVER surfaced — only
basenames; OSLog raw messages from sensitive daemons are never shipped. Pinned by
`[dex_macos][privacy]` tests.

**Battery health now has a Windows like-for-like** (the Windows state poll,
2026-06-12): both platforms ride the generic `hw.error` obs_type with
subject="battery" and the same below-80%-of-design threshold, so they render
identically under Hardware without a server change. A dedicated
`hw.battery_degraded` obs_type + label remains a future polish (needs a
`dex_signal_groups()` + drift-net edit).

## Linux collector (shipped — `dex_linux_collector.cpp`, `dex_linux_proc.cpp`, `dex_linux_storage.cpp`, `dex_linux_journal.cpp`, `dex_linux_kmsg.cpp`)

A drop-in `ISignalObserver` behind `make_dex_observer()` (`__linux__` branch), targeting
**headless Linux servers** with three privilege-light mechanisms (no elevated access):

1. a **periodic `/proc` poll** (`dex_linux_proc.cpp`): `/proc/stat` busy%, `/proc/meminfo`
   commit%, and `/proc/diskstats` per-I/O service time (await, summed over whole physical
   disks) feed `perf.cpu_sustained`, `perf.memory_pressure` and `perf.disk_latency_high` on the
   SAME sustained-breach hysteresis + thresholds as the Windows state poll (reused
   `dex_perf_breach`, incl. the 25 ms disk threshold) — completing the Windows cpu/mem/disk perf
   trio on Linux; `/proc/uptime` feeds the hourly `os.uptime_report` reboot/uptime heartbeat (the
   same cross-platform `uptime_observation` builder macOS/Windows use);
1b. a **`/sys` thermal poll** (`dex_linux_sysfs.cpp`): the per-core
   `thermal_throttle/core_throttle_count` counters, summed across CPUs — an increase since the
   last poll latches `hw.cpu_throttled` (poll-and-latch on entry, the Windows
   Kernel-Processor-Power 37 analogue); no thermal-throttle interface (VM / non-x86) simply never
   emits;
2. a **`statvfs` storage poll** (`dex_linux_storage.cpp`): `storage.low` (>=90% used or <5 GiB
   free) over real local block-backed filesystems (ext*/xfs/btrfs/zfs/f2fs; pseudo, read-only
   and network fstypes excluded);
3. a **journald reader** (`dex_linux_journal.cpp` + `dex_linux_kmsg.cpp`): a slow-cadence
   `journalctl --after-cursor -o json` poll (cursor-checkpointed, no libsystemd). Two record
   families are classified onto EXISTING obs_types. **systemd-structured** records (keyed on a
   stable `MESSAGE_ID`, `dex_linux_journal.cpp`): `service.crashed` (a unit failed: the "Failed
   with result" / unit-failed messages), `service.hung` (the SAME unit-failed entry routed by
   `UNIT_RESULT="watchdog"` — a `WatchdogSec` timeout is a hang, not a crash; one entry, no
   double-emit) and `process.crashed` (a `systemd-coredump` entry — coverage depends on
   systemd-coredump being the active core handler). A low-volume `SYSLOG_IDENTIFIER=chronyd`
   clause adds `os.time_unsynced` (chrony's "Can't synchronise: no selectable sources" / large-step
   markers — the noisy source online/offline lines produce no observation; the raw message, which
   carries NTP source IPs, is never shipped). **kernel ring-buffer**
   lines (`_TRANSPORT=kernel`, free text with NO `MESSAGE_ID`, so classified by anchored substring
   markers in `dex_linux_kmsg.cpp`): `memory.exhausted` (OOM-killer), `os.bugcheck` (a fatal
   `Kernel panic - not syncing` only — a survivable Oops/soft-lockup is deliberately NOT mapped, to
   keep the BSOD-equivalent rate honest), `os.dirty_shutdown` (ext4/xfs journal-recovery at mount =
   the prior shutdown was unclean — the reliable "did it die" evidence, since a panic line rarely
   survives the reboot), `disk.error` (block-layer / buffer I/O error, subject = backing device),
   `fs.corruption` (ext4/xfs/btrfs metadata error, subject = device), and `process.hung` (the
   hung-task watchdog). A per-`(type, subject)` debounce collapses a flapping unit/process/device;
   the dedup map is age-evicted each poll so it stays bounded by the trailing window, not daemon
   uptime.

It reuses the existing obs_type strings, uniform `detail_json` keys and wire mapping, so the
signals render in the same `/dex` display groups with **no change to the live rendering path**
(`dex_signal_groups()` / `dex_signal_label()` already carry every reused type), `platform="linux"`
driving the by-OS panel. The one server-side touch is the curated per-OS **coverage map**
`dex_obs_platforms()` (`dex_routes.cpp`), which gains the new Linux obs_types so the Catalogue
attributes them to Linux even before they fire — keep it in sync with these collectors.

**Coverage is Performance + Hardware/storage + App/Service reliability + System stability +
Boot/uptime.** Workstation-only headings (battery, Wi-Fi, display/WM, GUI app dialogs, .NET) are
**N/A on a headless server**, not gaps — score against the server-applicable denominator.

**`storage.low` subject is the backing-device identifier, NEVER the mount path** — a mount path
carries usernames / tenant / project names (`/home/alice/...`), which must not leave the device
(§Privacy). For a `/dev/*` device that is the basename (`sda1`, `vg0-root`); for a ZFS dataset
(whose `/proc/mounts` source is the dataset path, leaf = per-user) it is the **pool** (`tank`,
`rpool`), never the leaf. Pinned by `[dex][privacy]` tests that call the same
`storage_low_observation` chokepoint the collector calls (subject / sentence / `detail_json`
asserted free of any path component).

**journald egress is comm/unit-only.** `process.crashed` ships the process **comm**, never
`COREDUMP_EXE` (a full binary path that can embed a user/tenant directory); `memory.exhausted`
ships the OOM **victim comm**, never the kernel memory figures (total-vm / anon-rss / file-rss) or
the rest of the raw `MESSAGE`; `service.crashed` ships the unit name + `UNIT_RESULT` code only.
Pinned by `[dex][linux][journal][privacy]` tests asserting subject / sentence / `detail_json` are
free of the EXE path and the memory figures.

The **kernel ring-buffer** signals are the same: only infra-safe fields leave the device — the
backing-**device** identifier (`disk.error` / `fs.corruption` / `os.dirty_shutdown`), the blocked
process **comm** (`process.hung`), a short reason code (`io-error`, `medium-error`, `fs-error`,
`journal-recovery`, `machine-check`, `panic`). The raw kernel `MESSAGE` — which carries inode/block
numbers, sector/op detail, the accessing `comm`, and kernel addresses — is NEVER shipped. Pinned by
`[dex][linux][kmsg][privacy]` tests.

**Deployment notes:** `storage.low` uses a fixed 5 GiB-free floor, so small cloud/VM root volumes
can read as low until thresholds are operator-configurable (F1). Inside an **unmodified
container** `/proc` reflects the *host*, so the collector targets host/VM deployment. `statvfs`
excludes network *fstypes*, but a hung local block device (iSCSI/NBD/failing disk) can still stall
the poll — a bounded statvfs is a tracked follow-up. The journald source **no-ops on a non-systemd
host** (the `journalctl` shell-out yields nothing); `process.crashed` specifically requires
**systemd-coredump** as the active core handler — on a host using `apport` (the Ubuntu default)
coredumps are not journaled, so that signal stays silent until the core handler is changed (this is
host configuration, not a Yuzu setting). `os.time_unsynced` covers **chrony** today; the
`systemd-timesyncd` "sync lost" state has no stable journal marker and is a follow-up.
`service.dependency_failed` is deferred: the "Dependency failed for X" line carries no `MESSAGE_ID`,
so catching it needs either a high-volume all-`systemd` fetch or a separate `--grep` pipe, and the
**root** failure is already captured as `service.crashed`.

**Status legend (Linux) — narrower than macOS.** On the Linux rows "live" means the
**agent-emit or pure-parser was verified on a real event** (via safe error injection or a
real watchdog timeout), NOT seen end-to-end on `/dex` — the Linux collector has **not yet
been observed landing on `/dex`** during a live-fire (the live-fires ran the agent against
an offline server to pass the enrollment gate, so the emit was proven but the dashboard
arrival was not). This is deliberately narrower than the macOS "live" = end-to-end-on-`/dex`
definition; the per-row parenthetical states the exact evidence. `fixture` rows use the
documented kernel format string and await a real specimen.

| Heading | obs_type | Linux source | Status |
|---|---|---|---|
| Performance | `perf.cpu_sustained` | `/proc/stat` busy% >=90% sustained | live |
| Performance | `perf.memory_pressure` | `/proc/meminfo` commit% >=90% | live |
| Performance | `perf.disk_latency_high` | `/proc/diskstats` await >=25 ms/IO sustained (whole disks) | live (parser + real-field-layout verified; sustained-state, not single-fired) |
| Hardware & storage | `storage.low` | `statvfs` >=90% used; subject = device/pool | live |
| Boot / uptime | `os.uptime_report` | `/proc/uptime` (hourly scalar) | live |
| App / service reliability | `service.crashed` | journald unit-failed / "Failed with result" | live |
| App / service reliability | `service.hung` | journald unit-failed `UNIT_RESULT="watchdog"` (WatchdogSec timeout) | live (agent emit verified on a real watchdog timeout) |
| System stability | `os.time_unsynced` | journald chronyd "Can't synchronise: no selectable sources" | live (chrony format captured; not single-fired) |
| App / service reliability | `process.crashed` | journald `systemd-coredump` (where active handler) | live |
| System stability | `memory.exhausted` | journald kernel OOM-killer | live |
| System stability | `os.bugcheck` | journald kernel `Kernel panic - not syncing` (fatal only) | fixture (panic reboots — can't self-fire) |
| System stability | `os.dirty_shutdown` | journald ext4/xfs journal-recovery at mount | live (loopback-snapshot injection) |
| Hardware & storage | `disk.error` | journald block-layer / buffer I/O error; subject = device | live (dm-error + scsi_debug injection; agent emit verified) |
| Hardware & storage | `hw.error` | journald `mce: [Hardware Error]` / machine-check | fixture (no `mce-inject` on the dev box) |
| Hardware & storage | `hw.cpu_throttled` | `/sys` `core_throttle_count` increase (poll-and-latch) | live (parser + real-field-layout verified; counter rarely increments) |
| File system | `fs.corruption` | journald ext4/xfs/btrfs metadata error; subject = device | live (debugfs corruption injection) |
| App / service reliability | `process.hung` | journald kernel hung-task watchdog | fixture (documented format) |

## macOS: what more is possible with ESF / Network Extension / other entitlements

The unprivileged collector above covers ~10 of 11 headings. Acquiring privileges
buys **fidelity and a few otherwise-hard signals — NOT breadth** (breadth is
already reachable). Evidence gathered on the dev box (2026-06-11):

**Endpoint Security** (reachable to *validate* via root + the Apple-shipped
`/usr/bin/eslogger`, which carries `com.apple.developer.endpoint-security.client`
— so ES needs root + FDA, NOT a custom Apple-granted entitlement to prototype;
productionising needs an ES System Extension + that distribution entitlement,
standard for this vendor class). ES exposes **104 event types**. DEX upgrades:
- **Identity & logon — the biggest win:** `login_login/logout`,
  `lw_session_login/logout`, `openssh_login`, `su`, `sudo`, `authentication`,
  `authorization_judgement` — high-fidelity *structured* login/auth events, far
  better than the best-effort opendirectoryd-error signal above.
- **Security:** `xp_malware_detected/remediated` (XProtect), `gatekeeper_user_override`
  — authoritative vs scraping `syspolicy` logs.
- **Policy & management:** `profile_add/remove`.
- **Service/App Health + File system:** `exec`/`exit` (gap-free) + file events —
  mostly *completeness*; the report/log channels already catch user-visible
  failures, so the extra is largely DEX-noise (and a firehose to filter).
- **Cost beyond engineering:** ES gives file-level + real-time login/exec
  visibility — a surveillance-*capability* escalation an EU works council treats
  very differently from reading crash reports (co-determination triggers on
  capability, not intent). Gate behind explicit customer/MDM opt-in.

**Network Extension** (content filter / transparent proxy — entitlement + System
Extension + MDM): the only thing buying *new* network capability — per-flow /
per-app connectivity, **DNS-resolution timing**, latency. Collides with the
no-continuous-streaming NFR (aggregate on-device). Note: much network *experience*
is already unprivileged — `symptomsd` LQM/data-stalls (shipped above) + the
`networkQuality` CLI — so this is only for the deepest per-flow KPIs.

**MetricKit (`MXMetricManager`) — the one we CANNOT have:** the ideal APM feed
(per-app launch time, hang rate, responsiveness, CPU/disk exceptions) is
**per-app opt-in** — no API lets a fleet agent pull it for third-party apps. No
privilege unlocks it. Approximations: agent-side aggregated sampling
(`top`/`proc_pid_rusage`, unprivileged but NFR-heavy) or an embeddable Yuzu SDK.

**Root / privileged IOKit:** `powermetrics` (detailed CPU/GPU/thermal/power),
`spindump` (reliable hangs) — deepen System Stability / Hardware. **MDM authority:**
the authoritative Policy & management source vs scraping `mdmclient`. **Full Disk
Access:** other users' crash reports + full `OSLogStore` history — marginal.

**Bottom line:** privileges deepen Identity/Security/Management fidelity and add
per-flow network + complete process/file telemetry; they do **not** add headings
and are **not required** for the ~10/11 unprivileged coverage. The one hard ceiling
is clean per-app APM (MetricKit), which no entitlement crosses.

Linux: the journald reliability signals (systemd unit failures, `systemd-coredump`
crashes, the OOM-killer) are **shipped** — see the Linux collector section above.

## Wire + read-model invariants

- **No proto change** for new signals: `detail_json` is keyed by `event_type`
  (route a′); the gateway forwards `GuaranteedStateEvent` opaquely.
- The projection (`guardian_observations`, migration {7}) is written **inside
  the event transaction** — duplicate `event_id` rolls back both (at-least-once
  dedup - the dedup-by-`event_id` mechanism itself, not the lifecycle journal's
  overall delivery guarantee; see `docs/user-manual/guaranteed-state.md`'s
  "Reconnect replay traffic" section for that), and the reaper deletes
  projection rows in lockstep with events.
- Observations are facts, not alerts: severity is uniformly `info`; DEX applies
  its own framing and ignores Guardian severity.
- The headline dashboard rate stays **crash-free devices** (crash-scoped);
  other signals get their own panels. Rates always pair with coverage
  (reporting Windows agents) and show "—" when the denominator is missing.

## Testing methodology & evidence hygiene

Extractors are verified two ways: pure unit fixtures (the field layouts encoded
from provider manifests / real captured records) and a live **injection sweep**
that writes synthetic events through the real `EvtSubscribe` path to confirm the
end-to-end agent→server→`/dex` flow. Only **classic registered event sources**
can be written this way (`Write-EventLog`); manifest providers
(`Microsoft-Windows-*`) cannot be spoofed — which is also the security property
that makes forged DEX signals hard.

**Evidence-integrity rule (do this only on isolated rigs):** an injection sweep
writes events from sources like `Service Control Manager`, `Tcpip`, `NETLOGON`,
`disk`, and Defender into the host's *real* System/Application logs. On a managed
production endpoint that would contaminate SIEM pipelines, trip EDR/IDS rules (a
synthetic `machine-trust-failed` or threat detection reads as a real attack
indicator), and corrupt forensic evidence. **Run injection sweeps only on
isolated lab/test machines that are not managed endpoints, not ingested by a
customer SIEM, and not a potential forensic-evidence source.** To exercise the
collector on a real endpoint, trigger or wait for *genuine* events (restart a
test service, run a disk check) rather than injecting security-provider events.
