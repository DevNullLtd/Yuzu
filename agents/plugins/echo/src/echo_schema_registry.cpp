/**
 * echo_schema_registry.cpp -- Capture source definitions, DDL generation and
 *                            $-name translation.
 *
 * Roll-up is the only storage model. A source's hourly / daily / monthly tiers are not
 * declared here: build_sources() derives them from fold_sources() (echo_fold_schema.cpp),
 * so a tier's column list exists exactly once. What the registry declares by hand is what
 * the fold does not own: the OS support rows, `netqual_boot` and the `usage` tables.
 */

#include "echo_schema_registry.hpp"

#include "echo_fold_schema.hpp"

#include <algorithm>
#include <format>
#include <sstream>
#include <unordered_set>

namespace yuzu::echo {

namespace {

// ── Source definitions ──────────────────────────────────────────────────────

// Default retention of a derived tier, in seconds. The fold tiers replaced the raw table,
// so the summary tiers carry the whole record: 90 days hourly, 180 days daily, a year monthly.
constexpr int64_t kHourlyRetentionSec = 7776000;
constexpr int64_t kDailyRetentionSec = 15552000;
constexpr int64_t kMonthlyRetentionSec = 31536000;

// Append the hourly / daily / monthly granularity of every fold source: the bucket column
// first, then the view's columns in view order, copied from the one declaration.
void append_fold_tiers(std::vector<CaptureSourceDef>& sources) {
    for (const auto& fold : fold_sources()) {
        if (fold.own_tables)
            continue;
        const auto src = std::find_if(sources.begin(), sources.end(),
                                      [&](const CaptureSourceDef& s) { return s.name == fold.name; });
        if (src == sources.end())
            continue;
        for (const auto tier : fold.tiers) {
            GranularityDef g;
            g.suffix = tier;
            g.retention_type = RetentionType::kTimeBased;
            g.retention_default = tier == "hourly"  ? kHourlyRetentionSec
                                  : tier == "daily" ? kDailyRetentionSec
                                                    : kMonthlyRetentionSec;
            g.columns.push_back({ts_column_for_suffix(tier), "INTEGER"});
            g.columns.insert(g.columns.end(), fold.columns.begin(), fold.columns.end());
            src->granularities.push_back(std::move(g));
        }
    }
}

const std::vector<CaptureSourceDef>& build_sources() {
    static const std::vector<CaptureSourceDef> sources = [] {
    std::vector<CaptureSourceDef> s = {
        // ── Process ─────────────────────────────────────────────────────
        {
            .name = "process",
            .dollar_name = "Process",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "etw",
                 "ETW Microsoft-Windows-Kernel-Process (gap-free start/stop, "
                 "names-only, owning user resolved from the SID at start) is the "
                 "primary feeder; CreateToolhelp32Snapshot poll is the fallback "
                 "if the ETW session cannot start. No command line is captured."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/<pid>/status and /proc/<pid>/cmdline."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "endpoint_security",
                 "Endpoint Security NOTIFY_EXEC/EXIT stream (gap-free, full image "
                 "path, accurate ppid, owning user from the audit token) where the "
                 "ES SDK was detected at build time and the entitlement + root are "
                 "present at runtime (com.apple.developer.endpoint-security.client). "
                 "Falls back to the KERN_PROC_ALL sysctl poll otherwise. Names-only "
                 "on BOTH paths — no command line (works-council posture); the poll "
                 "blanks the proc_pidpath image it would otherwise place in cmdline."},
            },
            .granularities = {},
        },

        // ── TCP ─────────────────────────────────────────────────────────
        {
            .name = "tcp",
            .dollar_name = "TCP",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "iphlpapi",
                 "GetExtendedTcpTable / GetExtendedUdpTable — polled at the "
                 "fast collector interval. ETW Microsoft-Windows-Kernel-Network "
                 "is planned (capture_method='etw') for sub-second connect/close "
                 "fidelity; not yet wired. Sockets first seen already closing "
                 "(TIME_WAIT and the like) are recorded once per hour per "
                 "process/remote."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/net/{tcp,tcp6,udp,udp6}. Connection lifetime "
                 "below the fast interval may be missed. Sockets first seen "
                 "already closing (TIME_WAIT and the like) are recorded once "
                 "per hour per process/remote."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "nstat",
                 "PRIMARY tcp-lifecycle source: com.apple.network.statistics "
                 "kctl (nstat) SRC_ADDED/SRC_REMOVED, the same client the "
                 "netqual source uses for its quality leg (roadmap 2.2). "
                 "System-wide flow visibility needs root; an unprivileged agent "
                 "sees only its own flows and reports the honest 'none' rather "
                 "than a partial capture. The wire structs are transcribed from "
                 "XNU bsd/net/ntstat.h at the 13.3 floor and gated on a runtime "
                 "length self-check that fails closed to the poll on mismatch. "
                 "Endpoint Security has NO tcp/inet socket events "
                 "(NOTIFY_EXEC/EXIT only), so it is not a replacement here."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "proc_pidfdinfo",
                 "Fallback/seed poll: proc_listallpids + "
                 "proc_pidfdinfo(PROC_PIDFDSOCKETINFO) via libproc — always for "
                 "udp; for tcp only while the nstat event stream above is "
                 "unavailable (not root, socket/layout failure, or self-failed). "
                 "Inherent TOCTOU between pid enumeration and per-fd query — "
                 "short-lived sockets that close before the per-fd query may "
                 "produce empty rows."},
            },
            .granularities = {},
        },

        // ── Service ─────────────────────────────────────────────────────
        {
            .name = "service",
            .dollar_name = "Service",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "scm",
                 "EnumServicesStatusEx / QueryServiceConfig. Captures "
                 "display_name, status, startup_type."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "systemctl",
                 "systemctl list-units. startup_type is reported as 'unknown' "
                 "(would require a second systemctl call per unit). Hosts "
                 "without systemd (Alpine sysvinit, OpenRC) are unsupported."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "launchctl",
                 "launchctl list — no startup_type, status is binary "
                 "running/stopped only."},
            },
            .granularities = {},
        },

        // ── User ────────────────────────────────────────────────────────
        {
            .name = "user",
            .dollar_name = "User",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "wts",
                 "WTSEnumerateSessionsW + WTSQuerySessionInformationW — "
                 "captures interactive, RDP, console. Requires Terminal "
                 "Services (always present on supported Windows; absent on "
                 "Server Core 2008 R2 minimal installs). WTSEnumerateSessionsExW "
                 "is the recommended successor for new code but is not yet wired."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "utmp",
                 "Reads /var/run/utmp via getutent. Containers running with "
                 "no /var/run/utmp produce no events. logon_type is remote "
                 "when ut_host is set and is not an X display (:...)."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "utmpx",
                 "getutxent. logon_type is remote when ut_host is set and is "
                 "not an X display (:...). "
                 "GUI logins are not always reflected in utmpx."},
            },
            .granularities = {},
        },

        // ── Perf (BRD A1 — continuous device performance sampling) ──────
        // One derived row per sample interval (default 30 s): CPU %, memory
        // used/commit %, summed disk throughput + per-IO latency, summed
        // non-loopback network throughput. Raw samples stay on-device
        // (ADR-0004); the hourly tier carries avg/max for trend queries.
        {
            .name = "perf",
            .dollar_name = "Perf",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,  "ntcounters",
                 "Raw kernel counters — GetSystemTimes, GlobalMemoryStatusEx + "
                 "GetPerformanceInfo, IOCTL_DISK_PERFORMANCE, GetIfTable2. "
                 "No PDH, no WMI, no shell-out. Some virtual disks do not "
                 "answer IOCTL_DISK_PERFORMANCE — disk columns read 0 there."},
                {"linux",   OsSupportStatus::kSupported,  "procfs",
                 "/proc/stat (aggregate jiffies, DEX busy conventions), "
                 "/proc/meminfo (MemAvailable; commit_pct reads 0 under "
                 "vm.overcommit_memory=1 — CommitLimit is advisory there), "
                 "/proc/diskstats (whole disks only, 512-byte ABI sectors), "
                 "/proc/net/dev (non-loopback). No shell-out."},
                {"macos",   OsSupportStatus::kPlanned,    "host_statistics",
                 "host_processor_info / host_statistics64 + IOKit counters."},
            },
            .granularities = {},
        },

        // ── BRD A2: top-N per-application resource samples ───────────────
        // Rides the same collect_perf tick as the device sampler; aggregated
        // by IMAGE NAME (app-level — per-PID detail lives on process_live),
        // top-10 by CPU ∪ top-10 by working set per tick (<= 20 rows/30 s).
        // NAMES ONLY — no command lines (privacy default); operator redaction
        // patterns apply to the name; own `procperf_enabled` toggle so per-app
        // visibility can be disabled while device-level sampling stays on.
        {
            .name = "procperf",
            .dollar_name = "ProcPerf",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,  "ntsysinfo",
                 "One NtQuerySystemInformation(SystemProcessInformation) "
                 "snapshot per tick — image name, CPU times, working set for "
                 "every process; no PDH, no WMI. The per-app file version is "
                 "the bounded exception: a least-privilege OpenProcess on each "
                 "top-N representative only (<= 2N/tick), failures → empty."},
                {"linux",   OsSupportStatus::kSupported,  "procfs",
                 "One /proc/[pid]/stat pass per tick — comm, utime+stime, rss, "
                 "starttime, flags; no ptrace, no per-process handles. Names are "
                 "the kernel's 15-char comm (joins process_live). version is "
                 "always '' (on-disk version capture is a follow-up)."},
                {"macos",   OsSupportStatus::kPlanned,    "libproc",
                 "proc_pid_rusage / proc_taskinfo per sysctl PID list."},
            },
            .granularities = {},
        },

        // ── netqual (BRD Workstream E — per-connection TCP quality) ──────
        // One row per (tick, ESTABLISHED connection): smoothed RTT + jitter
        // + a CURRENT-loss gauge (tcpi_lost) + lifetime retrans/segs context,
        // joined to the owning process. Co-sampled with the `tcp` source so it
        // shares the snapshot_id (joins to process/perf on ts). Only a coarse
        // destination CLASS (`remote_bucket`) is stored — never the raw remote
        // address — and collection carries its own toggle + per-tick
        // top-N cap (collector slice). Row-count retention bounds storage
        // deterministically regardless of connection churn.
        {
            .name = "netqual",
            .dollar_name = "NetQual",
            .os_support = {
                {"linux",   OsSupportStatus::kSupported, "inetdiag",
                 "netlink SOCK_DIAG / INET_DIAG TCP_INFO dump (the interface "
                 "`ss -ti` uses — no packet capture, no CAP_NET_ADMIN: a "
                 "non-root agent reads system TCP_INFO), joined to the "
                 "connection's owning process by 4-tuple."},
                {"windows", OsSupportStatus::kSupportedConstrained, "estats",
                 "TCP ESTATS (Get/SetPerTcpConnectionEStats) over the "
                 "ESTABLISHED table (ADR-0020). Constraints: enabling stats is "
                 "admin-only, so a non-elevated agent records NOTHING (status "
                 "reports netqual_capture_method=none); RTT is ms-resolution "
                 "(sub-ms LAN RTTs read 0); retrans/segs_out count since "
                 "stats-enable, not connection start; lost/ca_state are "
                 "delta-derived approximations of the Linux gauges."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "nstat",
                 "com.apple.network.statistics kctl (nstat) SRC_DESC/SRC_COUNTS "
                 "per tcp flow, the same client the tcp source's lifecycle leg "
                 "uses (roadmap 2.2). Constraints: system-wide flow visibility "
                 "needs root — an unprivileged agent sees only its own flows "
                 "and netqual_capture_method honestly reports none rather than "
                 "a partial capture; rtt/rtt_var are believed microseconds "
                 "already (no *1000, unlike Windows' ms-resolution ESTATS); "
                 "lost is a per-tick delta off the cumulative retransmit "
                 "counter, never the lifetime total; a runtime wire-layout "
                 "self-check falls back to capture_method=none on any mismatch "
                 "rather than emit a plausible-but-wrong number (the private, "
                 "unversioned nstat struct layout is this source's largest "
                 "risk — see the roadmap 2.1 spike memo)."},
            },
            .granularities = {
                // Boot baseline (ADR-0020): ONE row per boot, written at plugin
                // init from cumulative-since-boot OS counters (Windows:
                // GetTcpStatisticsEx2 v4+v6 + GetIfTable2 non-loopback totals).
                // It summarizes network quality over the window BEFORE Echo was
                // running this boot (window_s = ts - boot_ts) — no provisioning,
                // no elevation. SIGNAL DISCIPLINE: a since-boot retrans/segs
                // ratio is coarse retrospective CONTEXT, never a current-loss
                // verdict (the device-aggregate ratio was disproven for live
                // signals — see NetQualRow). No rollup; `boot` is not a rollup
                // suffix, so the aggregator skips it and retention orders by ts.
                {
                    .suffix = "boot",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 400, // ~a year of daily reboots
                    .columns = {
                        {"ts",              "INTEGER"}, // t_live (agent start)
                        {"snapshot_id",     "INTEGER"},
                        {"boot_ts",         "INTEGER"},
                        {"window_s",        "INTEGER"}, // pre-Echo window length
                        {"retrans_segs",    "INTEGER"}, // since boot, v4+v6
                        {"segs_out",        "INTEGER"}, // since boot, v4+v6
                        {"estab_resets",    "INTEGER"},
                        {"if_in_errors",    "INTEGER"}, // non-loopback totals
                        {"if_in_discards",  "INTEGER"},
                        {"if_out_errors",   "INTEGER"},
                        {"if_out_discards", "INTEGER"},
                        {"if_in_octets",    "INTEGER"},
                        {"if_out_octets",   "INTEGER"},
                    },
                },
            },
        },

        // ── Module / image loads (M1 — docs/echo-module-loads.md) ──────────
        // What loads INTO a process: DLL / dylib / .so + driver / kext / kmod
        // loads, each with a signing verdict — the DLL-search-order-hijack,
        // injection, and BYOVD surface $Process cannot answer. `module_dir` IS
        // captured (the hijack signal is the path, not a command line — a narrow,
        // deliberate divergence from the names-only process posture; no cmdline).
        // M1 registered the schema queryable-empty; the Windows collector (M2, ETW)
        // has shipped, macOS ES (M4/M5) and Linux auditd kmod (M6) are kPlanned. The high-
        // volume edge risk-filter that really bounds module_live ships with the
        // first collector; own `module_enabled` toggle, on by default.
        {
            .name = "module",
            .dollar_name = "Module",
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "etw",
                 "Microsoft-Windows-Kernel-Process image-load events (IMAGE "
                 "keyword 0x40, events 5/6) on a dedicated ETW session; driver "
                 "loads surface as kernel image-loads (System pid). Signing is "
                 "verified out-of-band at drain on a no-reparse handle (WinVerifyTrust "
                 "+ the verification-chain signer, cached; catalog lookup "
                 "(CryptCATAdmin) when there is no embedded signature); an image on a "
                 "network path or behind a symlink/junction is never verified and reads "
                 "unknown. Ordinary loads are stored once per hour per "
                 "loader/module/folder; unloads are not stored. "
                 "module_dir is scrubbed of user-profile prefixes "
                 "before storage. CodeIntegrity/Operational (3033/3034) blocked-load "
                 "overlay is M3."},
                {"linux", OsSupportStatus::kPlanned, "auditd",
                 "Kernel-module loads via auditd init_module/finit_module (kmod "
                 "only in v1; /proc/modules seed). Shared-object (.so) loads need "
                 "eBPF and are deferred to a separate track. Wired in M6."},
                {"macos", OsSupportStatus::kPlanned, "endpoint_security",
                 "ES NOTIFY_KEXTLOAD/KEXTUNLOAD (first-class) plus user-space "
                 "dylibs via NOTIFY_MMAP (constrained) on the SAME ES client the "
                 "process source uses; code-signing identity (team id / cdhash) "
                 "rides the message, so signing needs no extra call. Wired in "
                 "M4/M5."},
            },
            .granularities = {},
        },

        // ── Software install/uninstall events (Phase 8 Wave 1) ────────────────
        // Diffs the installed-software inventory on the `echo.software` tick
        // (hourly default) and records install/remove/upgrade events over time —
        // the historical "what was installed/removed on this box, when" the
        // point-in-time installed_apps inventory cannot answer. MACHINE SCOPE ONLY
        // (HKLM Uninstall): an event is the host's software, never attributed to a
        // Windows profile, so the capture carries no user identity / personal data
        // (#1620). Ships enabled; an operator can turn it off per host via
        // echo.configure software_enabled=false.
        //
        // Windows captures machine-wide (HKLM Uninstall 64-bit + WOW6432Node 32-bit).
        // Linux (dpkg/rpm) and macOS (pkgutil) are kPlanned (queryable-empty) until a
        // fast-follow wires the installed_apps enumeration into a collector.
        {
            .name = "software",
            .dollar_name = "Software",
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "registry",
                 "Registry Uninstall keys, polled-and-diffed on the echo.software "
                 "tick: HKLM 64-bit + WOW6432Node 32-bit (machine scope only). "
                 "SystemComponent entries are skipped. No command line / no usage "
                 "data — names, versions, publisher only."},
                {"linux",   OsSupportStatus::kPlanned, "dpkg_rpm",
                 "dpkg-query / rpm -qa / pacman -Q diff (reuse of the installed_apps "
                 "enumeration). Wired in a fast-follow."},
                {"macos",   OsSupportStatus::kPlanned, "pkgutil",
                 "system_profiler SPApplicationsDataType + pkgutil diff (reuse of "
                 "the installed_apps enumeration). Wired in a fast-follow."},
            },
            .granularities = {},
        },

        // ── ARP / address-resolution table (ADR-0015) ─────────────────────
        // Host L2 adjacency: IP<->MAC bindings per interface. Snapshot-diff
        // appeared/removed keyed on the (interface, ip_address, mac_address)
        // binding — a changing entry_type on the same binding is a value update,
        // not churn. Ships enabled. Windows
        // (GetIpNetTable2), Linux (/proc/net/arp) and macOS (NET_RT_FLAGS
        // sysctl, constrained) are all wired (see docs/echo-implementer.md
        // "Adding a capture source").
        {
            .name = "arp",
            .dollar_name = "ARP",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "iphlpapi",
                 "GetIpNetTable2(AF_UNSPEC) — the kernel ARP / IPv6 neighbour "
                 "cache. Full interface/ip/mac/entry_type. Polled at the fast "
                 "collector interval."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "/proc/net/arp — kernel ARP table (IPv4). Flags column mapped "
                 "to entry_type (static/dynamic/incomplete/other; ATF_PERM "
                 "checked before ATF_COM so a permanent+resolved entry reads "
                 "'static'). Capped at kArpEntryCap=2048 live entries; the "
                 "truncation warn fires only when an entry is actually dropped, "
                 "not merely when the count reaches the cap."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "route_sysctl",
                 "Reuses agents/shared/route_sysctl_arp.hpp's NET_RT_FLAGS / "
                 "RTF_LLINFO routing-socket dump (the same mechanism native "
                 "discovery's scan_subnet uses). MAC is available; entry_type "
                 "is always reported 'unknown' — this source distinguishes "
                 "neither static/permanent nor dynamic/stale/probe entries, "
                 "unlike the Windows/Linux legs. No interface field (the "
                 "shared record carries none). Capped at kArpEntryCap=2048 "
                 "live entries."},
            },
            .granularities = {},
        },

        // ── DNS resolution cache (ADR-0015) ───────────────────────────────
        // Host DNS resolver-cache STATE (not per-process queries — the cache is
        // system-wide and carries no pid; per-process attribution via the
        // Microsoft-Windows-DNS-Client ETW provider is a deferred follow-up, so
        // never join dns_live to a process by pid). Snapshot-diff appeared/removed
        // keyed on the (name, record_type, data) resolution; ttl_remaining_s is a
        // value field and is NOT part of the diff key (it decrements every tick
        // and must not churn). Windows only here; Linux/macOS kPlanned.
        {
            .name = "dns",
            .dollar_name = "DNS",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "dnsapi",
                 "DnsGetCacheDataTable — the DNS client resolver cache. Full "
                 "name/record_type/data/TTL. Polled at the fast collector "
                 "interval."},
                {"linux",   OsSupportStatus::kPlanned,             "systemd-resolved",
                 "systemd-resolved cache via the resolve1 D-Bus interface where "
                 "present; falls back to /etc/hosts (source='hosts_file'). Hosts "
                 "without systemd-resolved yield hosts-file entries only "
                 "(constrained). Wired in the Linux follow-up."},
                {"macos",   OsSupportStatus::kPlanned,             "dscacheutil",
                 "dscacheutil -cachedump subprocess. TTL is unavailable "
                 "(ttl_remaining_s reported -1, constrained). Wired in the macOS "
                 "follow-up."},
            },
            .granularities = {},
        },

        // ── netconn (ADR-0020 — connectivity-transition timeline) ─────────
        // One row per OS-logged network transition: network connect/disconnect
        // (NetworkProfile 10000/10001), NCSI internet-capability changes
        // (4042), Wi-Fi connect/fail/disconnect + reason (WLAN-AutoConfig
        // 8001/8002/8003). Windows reads the OS-RETAINED operational event
        // logs (EvtQuery), so the first backfill reaches days-to-weeks BEFORE
        // Echo — or the agent — existed on the box: this is the retrospective
        // "was the network flapping before we started watching?" source.
        // PRIVACY: an allow-list parser extracts ONLY the enum/numeric fields
        // below; SSID, BSSID, profile names, interface GUIDs and MACs are
        // never extracted and the raw event XML is never persisted (stricter
        // than the wifi plugin — this table ships fleet-wide).
        {
            .name = "netconn",
            .dollar_name = "NetConn",
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "wevtapi",
                 "EvtQuery over the NetworkProfile / NCSI / WLAN-AutoConfig "
                 "operational channels (default-enabled ~1MB circular logs — "
                 "history depth is event-rate-dependent, typically days to "
                 "weeks). Backfill at init from the last high-water mark, "
                 "incremental reads on the slow cadence. A missing or "
                 "ACL-denied channel degrades to fewer rows, never an error."},
                {"linux",   OsSupportStatus::kPlanned,   "journald",
                 "NetworkManager / systemd-networkd connectivity transitions "
                 "from the journal."},
                {"macos",   OsSupportStatus::kPlanned,   "oslog",
                 "configd/Wi-Fi subsystem transitions via OSLog."},
            },
            .granularities = {},
        },

        // ── Mapped drives (capability-map §3.8) ───────────────────────────
        // Network-share mappings in BOTH directions, distinguished by the
        // `direction` column: `outbound` = drives THIS host maps to remote
        // shares; `inbound` = remote hosts mapping THIS host's shares (the
        // lateral-movement signal §3.8 calls out). Live snapshot-diff emits
        // appeared/removed keyed on (direction, local_mount, remote_path,
        // remote_host, username); `provider` is a value-only field (not keyed).
        // A one-time init backfill seeds PAST mappings from persistent OS
        // artifacts (Windows registry Network/MRU/MountPoints2 + Security
        // event log; Linux fstab + Samba logs) as `origin='historical'` rows
        // — the `origin` column separates historically-inferred from
        // live-observed, and `historical` rows bypass the live diff entirely.
        // Ships enabled. macOS is outbound-live only
        // via getfsstat — no inbound, no history (honestly out of reach for
        // an unprivileged agent; see the macOS os_support row below).
        {
            .name = "mapdrive",
            .dollar_name = "MapDrive",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,            "wnet",
                 "Outbound live: WNetOpenEnumW/WNetEnumResourceW + WNetGetUserW "
                 "(unprivileged). Outbound history: HKCU\\Network + Map Network "
                 "Drive MRU + MountPoints2 across offline profiles, ts = subkey "
                 "last-write. Inbound live: NetSessionEnum L502→L10 — needs "
                 "local-admin / Server-Operator, degrades to empty on "
                 "ERROR_ACCESS_DENIED. Inbound history: Security event log 4624 "
                 "(logon_type=3 network) via wevtutil, ts = event time."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "procfs",
                 "Outbound live: /proc/mounts fstype∈{cifs,smb3,nfs,nfs4,"
                 "fuse.sshfs} (username unavailable). Outbound history: /etc/fstab "
                 "cifs/nfs entries (ts=0). Inbound live: smbstatus -b — needs Samba "
                 "installed + read access, degrades to empty otherwise. Inbound "
                 "history: /var/log/samba connect events (bounded tail), journalctl "
                 "-u smbd fallback."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "getfsstat",
                 "Outbound live only: getfsstat(2) mount table filtered to "
                 "network fstypes {nfs, smbfs, cifs, afpfs, webdav}. The dedicated "
                 "username column is always blank (getfsstat exposes no separate "
                 "credential field) — but unlike Linux's /proc/mounts, a "
                 "credentialed SMB mount source (e.g. //alice@host/share) is "
                 "surfaced VERBATIM in remote_path, so the account name is still "
                 "observable there even though the username column is empty. No "
                 "inbound (no smbutil integration) and no history (getfsstat "
                 "exposes only the current mount table, nothing historical) — "
                 "honestly out of reach for an unprivileged agent."},
            },
            .granularities = {},
        },

        // ── power (cursor-model seam, echo_cursor.hpp) — sleep/wake/AC-power
        // transitions. RAW CAPTURE ROWS ONLY, no rollups (P-008 — a mirror/aggregate
        // shape was contradictory for a low-volume host-lifecycle source;
        // netconn's live-only shape is the precedent). Replay idempotence via
        // the UNIQUE record_key index below (echo_cursor.hpp rule 3), not
        // cursor arithmetic.
        //
        // Every capture source ships default_enabled = TRUE (registry-wide
        // invariant, test_echo_schema_registry.cpp). The retrospective-reach
        // control is power_lookback_seconds (default 604800s / 7 days,
        // 0 = forward-only): it lets an operator suppress historical backfill
        // without disabling the source outright — same shape as
        // netconn_lookback_seconds (ADR-0020).
        //
        // os_support: mechanisms are the 2026-09-04 measured bindings
        // (hardware-probe measurement, Wave 6); the collector ships in this
        // same PR (echo_power_collector.cpp) -- PR #4017 review, minor #12.
        {
            .name = "power",
            .dollar_name = "Power",
            .default_enabled = true,
            .os_support = {
                {"windows", OsSupportStatus::kSupportedConstrained, "powerbroadcast",
                 "Suspend/resume + AC transitions via "
                 "PowerRegisterSuspendResumeNotification / WM_POWERBROADCAST, "
                 "cursor-model (echo_cursor.hpp)."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "logind",
                 "systemd-logind PrepareForSleep sd-bus signal + power-supply "
                 "sysfs/udev, cursor-model. Gated by "
                 "the optional libsystemd dep (YUZU_HAVE_LIBSYSTEMD)."},
                {"macos",   OsSupportStatus::kSupported, "pmset_log",
                 "`pmset -g log` retrospective replay (measured working "
                 "unprivileged on this Mac 2026-09-04, 9,629 lines: "
                 "hardware-probe measurement, Wave 6), cursor-model."},
            },
            .granularities = {},
        },

        // ── removable (cursor-model seam, echo_cursor.hpp) — removable-media
        // attach/detach transitions, plus exec_from_removable correlation
        // (process_enum.hpp's ProcessInfo::exec_path, P-004). RAW CAPTURE ROWS ONLY,
        // no rollups (P-008, same rationale as power above). `image_path` +
        // `pid` are typed identity-adjacent columns (P-004) — `evidence` and
        // `record_key` are forensic/value fields only, never identity
        // carriers. Replay idempotence via the UNIQUE record_key index below.
        //
        // Ships default_enabled = TRUE like every capture source.
        // removable_lookback_seconds (default 604800s, 0 = forward-only)
        // governs historical backfill the same way.
        //
        // os_support: mechanisms are the 2026-09-04 measured bindings
        // (hardware-probe measurement, Wave 6); collectors land wave 2.
        {
            .name = "removable",
            .dollar_name = "Removable",
            .default_enabled = true,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "wevtapi",
                 "EvtQuery over Microsoft-Windows-Partition/Diagnostic (+ "
                 "Kernel-PnP/Configuration, Storsvc/Diagnostic), channels "
                 "measured LIVE on the-rig 2026-09-04; the roadmap's "
                 "DriverFrameworks-UserMode channel is disabled by default "
                 "and is NOT the binding (hardware-probe measurement, Wave 6)."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "udev_netlink",
                 "udev netlink monitor (block subsystem, removable), "
                 "cursor-model."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "diskarbitration",
                 "DiskArbitration DADiskAppeared/Disappeared callbacks "
                 "(headers confirmed in the CLT SDK, hardware-probe measurement, Wave 6), "
                 "cursor-model."},
            },
            .granularities = {},
        },
        // ── registry (cursor-model seam, echo_cursor.hpp) — registry value and key
        // changes under a curated persistence/policy watch list (HKLM and each
        // loaded HKU hive): what changed, with its new value and the old value's type and
        // size. Raw capture rows only, no rollups (P-008, same rationale as power above).
        // Mechanism: a RegNotifyChangeKeyValue subtree watch + a per-root baseline diff
        // (echo_state `registry:<root>`) say WHAT changed; a write-only
        // Kernel-Registry ETW session says WHO, by correlation on value name, type,
        // size and time window. actor_pid / actor_image hold the correlated writer
        // (a lead to verify, not proof) and are 0 / '' when none is named; `detail`
        // says why (attr:corr | ambiguous | none | degraded | off | lost-restart).
        // Values are stored UNMASKED: `data` (the new value) is readable through echo.sql;
        // `prev_data` is empty, the old value's type and size are kept instead. Retention is
        // a row count.
        // Replay idempotence via the UNIQUE record_key index below.
        {
            .name = "registry",
            .dollar_name = "Registry",
            .default_enabled = true,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "regnotify+etw",
                 "RegNotifyChangeKeyValue subtree watch + baseline diff (what changed: the new "
                 "value up to 512 bytes, and the old value's type and size) and a write-only "
                 "Kernel-Registry ETW session that names the writing "
                 "process by correlation; cursor-model (echo_cursor.hpp). Without an elevated "
                 "agent the session cannot open and rows carry attr:off."},
                {"linux",   OsSupportStatus::kUnsupported, "",
                 "The Windows registry does not exist on this platform."},
                {"macos",   OsSupportStatus::kUnsupported, "",
                 "The Windows registry does not exist on this platform."},
            },
            .granularities = {},
        },

        // ── Usage (Wave 7 PR7.2b) — DERIVED from `process`: a checked_
        // transaction fold (echo_usage.cpp usage_fold_in) pairs started/
        // stopped by (pid, exe_key) into runs; usage_live holds OPEN runs
        // (deleted when closed), usage_daily the per-executable daily
        // aggregate. No collector, no roll-up tiers of its own; the fold is
        // fed the process events inside the process fold's transaction.
        // DEFAULT-ON per
        // Alex's 2026-09-04 ruling (see docs/user-manual/echo.md).
        // usage_daily_user (per-day username membership) and the two
        // UNIQUE indexes (usage_live(pid, exe_key), usage_daily(day_ts,
        // exe_key)) are created by echo_db.cpp's v6 migration, NOT here --
        // usage_daily_user's PRIMARY KEY(day_ts, exe_key, user) shape (no
        // `id` column) does not fit the generic per-tier layout below.
        {
            .name = "usage",
            .dollar_name = "Usage",
            .default_enabled = true,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "derived_process",
                 "Derived from the process source (ETW feeder); names-only, no cmdline."},
                {"linux",   OsSupportStatus::kSupported, "derived_process",
                 "Derived from the process source (/proc); comm names are 15-char truncated."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "derived_process",
                 "Derived from the process source; inherits its ES-or-poll granularity."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Backstop only. The fold bounds the open set itself
                    // (cap_open_runs, 20000, oldest closed as `capped` and
                    // ACCOUNTED in expired_runs); this generic prune firing
                    // would delete open runs unaccounted, so it is set far
                    // above the fold's cap and must never be the operative bound.
                    .retention_default = 200000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"pid",         "INTEGER"},
                        {"exe_key",     "TEXT"},
                        {"user",        "TEXT"},
                        {"start_ts",    "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days, as process_daily
                    .columns = {
                        {"day_ts",          "INTEGER"},
                        {"exe_key",         "TEXT"},
                        {"run_count",       "INTEGER"},
                        {"total_seconds",   "INTEGER"},
                        {"first_seen",      "INTEGER"},
                        {"last_seen",       "INTEGER"},
                        {"distinct_users",  "INTEGER"},
                        {"superseded_runs", "INTEGER"},
                        {"expired_runs",    "INTEGER"},
                        // No fold_hwm replay-guard column (Wave 7 PR7.2's
                        // original shape): checked_transaction (echo_db.hpp)
                        // makes a partial commit of this fold structurally
                        // impossible, so there is nothing for a replay guard
                        // to guard against -- see echo_usage.cpp's file banner.
                    },
                },
            },
        },
    };
    append_fold_tiers(s);
    return s;
    }();
    return sources;
}

// Build the $-name -> real table name map once.
const std::unordered_map<std::string, std::string>& dollar_name_map() {
    static const auto map = [] {
        std::unordered_map<std::string, std::string> m;
        for (const auto& src : build_sources()) {
            for (const auto& g : src.granularities) {
                // $Process_Live -> process_live
                std::string dollar = std::format("${}_{}",
                    src.dollar_name,
                    std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(g.suffix[0])))) +
                    std::string(g.suffix.substr(1)));
                std::string real = std::format("{}_{}", src.name, g.suffix);
                m[dollar] = real;
            }
            // $Process_Live and friends: the retired raw tables answer with an empty view.
            if (is_legacy_live_shim(std::format("{}_live", src.name)))
                m[std::format("${}_Live", src.dollar_name)] = std::format("{}_live", src.name);
        }
        return m;
    }();
    return map;
}

// Reverse map: real table name -> (source index, granularity index)
struct TableRef {
    size_t source_idx;
    size_t gran_idx;
};

const std::unordered_map<std::string, TableRef>& table_ref_map() {
    static const auto map = [] {
        std::unordered_map<std::string, TableRef> m;
        const auto& srcs = build_sources();
        for (size_t si = 0; si < srcs.size(); ++si) {
            for (size_t gi = 0; gi < srcs[si].granularities.size(); ++gi) {
                std::string real = std::format("{}_{}", srcs[si].name, srcs[si].granularities[gi].suffix);
                m[real] = {si, gi};
            }
        }
        return m;
    }();
    return map;
}

} // namespace

// ── Public API ──────────────────────────────────────────────────────────────

// The single mapping from a support level to its operator-facing name.
// do_compatibility() (echo_plugin.cpp) derives its `compatibility` action
// output from this instead of keeping a private duplicate switch (#2204
// unification) — YuzuSupportLevel is the descriptor's own enum, and
// OsSupportStatus's values are pinned 1:1 to it (see the header comment).
std::string_view support_level_name(OsSupportStatus status) {
    switch (to_yuzu_support_level(status)) {
    case YUZU_SUPPORT_SUPPORTED:
        return "supported";
    case YUZU_SUPPORT_CONSTRAINED:
        return "constrained";
    case YUZU_SUPPORT_PLANNED:
        return "planned";
    case YUZU_SUPPORT_UNSUPPORTED:
        return "unsupported";
    case YUZU_SUPPORT_UNDECLARED:
        break; // never produced by a registry row; fall through to the default below
    }
    return "undeclared";
}

// Get the timestamp column name for a granularity suffix. Public since #2361:
// the retention clock guard in `run_retention` needs the same column the DDL
// indexes and the retention delete filters on, and a second copy of
// this mapping in the aggregator would be a silent divergence waiting to happen.
std::string_view ts_column_for_suffix(std::string_view suffix) {
    if (suffix == "live")    return "ts";
    if (suffix == "hourly")  return "hour_ts";
    if (suffix == "daily")   return "day_ts";
    if (suffix == "monthly") return "month_ts";
    return "ts";
}

const std::vector<CaptureSourceDef>& capture_sources() {
    return build_sources();
}

bool source_default_enabled(std::string_view source_name) {
    for (const auto& src : build_sources()) {
        if (src.name == source_name)
            return src.default_enabled;
    }
    return true; // unknown source → the always-on default
}

std::vector<std::string> accepted_capture_methods(std::string_view source_name) {
    std::vector<std::string> methods;
    for (const auto& src : build_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& os : src.os_support) {
            if (os.status == OsSupportStatus::kUnsupported)
                continue;
            std::string m{os.capture_method};
            if (std::find(methods.begin(), methods.end(), m) == methods.end()) {
                methods.push_back(std::move(m));
            }
        }
    }
    std::sort(methods.begin(), methods.end());
    return methods;
}

std::string_view current_platform_os() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "";
#endif
}

std::vector<std::string> accepted_capture_methods_for_os(std::string_view source_name,
                                                         std::string_view os) {
    std::vector<std::string> methods;
    for (const auto& src : build_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& sup : src.os_support) {
            if (sup.os != os)
                continue;
            if (sup.status == OsSupportStatus::kUnsupported)
                continue;
            std::string m{sup.capture_method};
            if (std::find(methods.begin(), methods.end(), m) == methods.end())
                methods.push_back(std::move(m));
        }
    }
    std::sort(methods.begin(), methods.end());
    return methods;
}

std::optional<OsSupportStatus> os_support_status(std::string_view source_name,
                                                 std::string_view os) {
    const auto rank = [](OsSupportStatus s) {
        switch (s) {
            case OsSupportStatus::kSupported: return 3;
            case OsSupportStatus::kSupportedConstrained: return 2;
            case OsSupportStatus::kPlanned: return 1;
            default: return 0;
        }
    };
    std::optional<OsSupportStatus> best;
    for (const auto& src : capture_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& sup : src.os_support) {
            if (sup.os != os)
                continue;
            if (!best || rank(sup.status) > rank(*best))
                best = sup.status;
        }
    }
    return best;
}

std::string_view supported_capture_method(std::string_view source_name, std::string_view os) {
    for (const auto& src : capture_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& sup : src.os_support) {
            if (sup.os == os && (sup.status == OsSupportStatus::kSupported ||
                                 sup.status == OsSupportStatus::kSupportedConstrained))
                return sup.capture_method;
        }
    }
    return "none";
}

std::string effective_network_capture_method([[maybe_unused]] std::string_view configured) {
    // The collect_fast NETWORK leg — `enumerate_connections()` — always polls,
    // regardless of the stored `network_capture_method`: the per-OS platform
    // APIs (procfs / iphlpapi / proc_pidfdinfo) ARE the polling implementation,
    // and the kPlanned kernel-event methods (etw / endpoint_security) are
    // accepted for pre-staging but not yet collected. So every configured value
    // maps to an effective mechanism of "polling". (This is ONLY the fast
    // network leg: the separate `tcp` lifecycle and `netqual` sources DO use a
    // live kernel-event mechanism on macOS — nstat — reported through their own
    // `*_capture_method` status keys, not this one.) When a kernel-event
    // collector lands for THIS leg, branch on `configured` (and live session
    // state, as the process collector does with `etw_active_`) here -- this is
    // the single source of truth the `status` action reports (issue #1528).
    return "polling";
}

std::string generate_warehouse_ddl() {
    std::ostringstream ddl;
    for (const auto& src : build_sources()) {
        for (const auto& g : src.granularities) {
            std::string table_name = std::format("{}_{}", src.name, g.suffix);
            // The roll-up tiers are VIEWS over `<table>_r` tables (generate_fold_ddl creates
            // both). A CREATE TABLE here would collide with the view, and an index on a view
            // fails the whole batch ("views may not be indexed") on EVERY open.
            if (is_fold_view(table_name))
                continue;

            ddl << "CREATE TABLE IF NOT EXISTS " << table_name << " (\n";
            ddl << "    id INTEGER PRIMARY KEY AUTOINCREMENT";

            for (const auto& col : g.columns) {
                ddl << ",\n    " << col.name << " " << col.sql_type;
                // Numeric columns default to 0, text to '' — all NOT NULL.
                if (col.sql_type == "INTEGER" || col.sql_type == "REAL") {
                    ddl << " NOT NULL DEFAULT 0";
                } else {
                    ddl << " NOT NULL DEFAULT ''";
                }
            }
            ddl << "\n);\n";

            // Index on the timestamp column
            auto ts_col = ts_column_for_suffix(g.suffix);
            ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_{1} ON {0}({1});\n",
                               table_name, ts_col);
            ddl << "\n";
        }
    }
    return ddl.str();
}

std::optional<std::string> translate_dollar_name(std::string_view dollar_name) {
    auto& map = dollar_name_map();
    auto it = map.find(std::string(dollar_name));
    if (it != map.end())
        return it->second;
    return std::nullopt;
}

bool is_queryable_table(std::string_view real_table_name) {
    // Built once from the registry: every typed warehouse table (the
    // table_ref_map keys) plus the two base config/state tables. tar_events is
    // deliberately excluded — schema v3 drops it, so allowlisting it would turn
    // its "no such table" error into a weak existence oracle distinct from the
    // generic authorizer denial (#760 UP-8).
    static const std::unordered_set<std::string> allowed = [] {
        // echo_cursor joins them (S3): without it a wedged cursor source is
        // entirely unobservable -- no reset path exists, and the only remedy is
        // deleting echo.db, which destroys every OTHER source's history too.
        // Reading it exposes a source name, a position and updated_at; the
        // cursor payload is the source's own bookkeeping, not captured content --
        // with one exception: the registry cursor row holds, for about one tick, the
        // rendered new value of changes whose writer is not settled yet (and the old
        // value only when the baseline came from an older build).
        // echo_state carries the registry baselines (`registry:<root>`: type, size and
        // a hash per value; an older build also wrote a rendered prefix), readable here
        // consistently with registry_live's own unmasked values;
        // purge_source("registry") erases the table, the cursor row and
        // every `registry:%` state row in one transaction.
        std::unordered_set<std::string> s{"echo_state", "echo_config", "echo_cursor"};
        for (const auto& [real, ref] : table_ref_map())
            s.insert(real);
        // #4260: app-usage tables are read ONLY through the Forensics-gated
        // single-target app_usage plugin reads, never through generic echo.sql
        // (Infrastructure:Read). Remove them from the allowlist after the loop
        // above so the SQLite authorizer (echo_query_authorizer) denies every
        // access path -- direct name, $Usage_* placeholder, alias, JOIN, or
        // subquery -- post-translation, matching the tar_events #760 UP-8
        // no-oracle reasoning this function already documents.
        for (const char* usage_table : {"usage_live", "usage_daily", "usage_daily_user"})
            s.erase(usage_table);
        // The retired raw tables' shim views: a stored `$X_Live` query still reads an (empty)
        // relation instead of failing at the authorizer.
        for (const auto& shim : legacy_live_shim_names())
            s.insert(shim);
        return s;
    }();
    return allowed.contains(std::string(real_table_name));
}

std::vector<std::string> all_dollar_names() {
    std::vector<std::string> names;
    for (const auto& [dollar, real] : dollar_name_map()) {
        names.push_back(dollar);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::vector<std::string> columns_for_table(const std::string& real_table_name) {
    if (is_legacy_live_shim(real_table_name)) {
        // `process_live` -> the source `process`: the legacy column list, `id` first.
        std::vector<std::string> cols{"id"};
        for (const auto& c : legacy_live_columns(
                 std::string_view{real_table_name}.substr(0, real_table_name.size() - 5)))
            cols.emplace_back(c.name);
        return cols;
    }
    auto& refs = table_ref_map();
    auto it = refs.find(real_table_name);
    if (it == refs.end())
        return {};

    const auto& src = build_sources()[it->second.source_idx];
    const auto& gran = src.granularities[it->second.gran_idx];

    std::vector<std::string> cols;
    cols.reserve(gran.columns.size() + 1);
    cols.emplace_back("id"); // M14: include DDL-generated id column
    for (const auto& c : gran.columns) {
        cols.emplace_back(c.name);
    }
    return cols;
}

} // namespace yuzu::echo
