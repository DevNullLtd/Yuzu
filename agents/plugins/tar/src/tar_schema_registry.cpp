/**
 * tar_schema_registry.cpp -- Capture source definitions, DDL generation,
 *                            $-name translation, and rollup/retention SQL.
 */

#include "tar_schema_registry.hpp"

#include <algorithm>
#include <format>
#include <sstream>
#include <unordered_set>

namespace yuzu::tar {

namespace {

// ── Source definitions ──────────────────────────────────────────────────────

// Common columns present in all live tables (id, ts, snapshot_id are implicit
// in DDL generation; we list the data columns here).
// "action" is the event type (started/stopped, connected/disconnected, etc.)

const std::vector<CaptureSourceDef>& build_sources() {
    static const std::vector<CaptureSourceDef> sources = {
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Raised 5k→100k for the gap-free ETW stream on Windows (the
                    // poll produced far fewer rows). ~100k × ~150 B ≈ ~15 MB
                    // bounded; the hourly/daily/monthly count rollups carry the
                    // long tail. Non-Windows poll simply never fills it.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"pid",         "INTEGER"},
                        {"ppid",        "INTEGER"},
                        {"name",        "TEXT"},
                        {"cmdline",     "TEXT"},
                        {"user",        "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",     "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",      "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",    "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
            },
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
                 "fidelity; not yet wired."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/net/{tcp,tcp6,udp,udp6}. Connection lifetime "
                 "below the fast interval may be missed."},
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",           "INTEGER"},
                        {"snapshot_id",  "INTEGER"},
                        {"action",       "TEXT"},
                        {"proto",        "TEXT"},
                        {"local_addr",   "TEXT"},
                        {"local_port",   "INTEGER"},
                        {"remote_addr",  "TEXT"},
                        {"remote_host",  "TEXT"},
                        {"remote_port",  "INTEGER"},
                        {"state",        "TEXT"},
                        {"pid",          "INTEGER"},
                        {"process_name", "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400,
                    .columns = {
                        {"hour_ts",          "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400,
                    .columns = {
                        {"day_ts",           "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000,
                    .columns = {
                        {"month_ts",         "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
            },
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",                "INTEGER"},
                        {"snapshot_id",       "INTEGER"},
                        {"action",            "TEXT"},
                        {"name",              "TEXT"},
                        {"display_name",      "TEXT"},
                        {"status",            "TEXT"},
                        {"prev_status",       "TEXT"},
                        {"startup_type",      "TEXT"},
                        {"prev_startup_type", "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400,
                    .columns = {
                        {"hour_ts",        "INTEGER"},
                        {"name",           "TEXT"},
                        {"status_changes", "INTEGER"},
                        {"last_status",    "TEXT"},
                    },
                },
            },
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
                 "no /var/run/utmp produce no events. logon_type is inferred "
                 "from tty name (pts/* -> remote)."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "utmpx",
                 "getutxent. logon_type inferred from tty (ttys* -> remote). "
                 "GUI logins are not always reflected in utmpx."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"user",        "TEXT"},
                        {"domain",      "TEXT"},
                        {"logon_type",  "TEXT"},
                        {"session_id",  "TEXT"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400,
                    .columns = {
                        {"day_ts",      "INTEGER"},
                        {"user",        "TEXT"},
                        {"domain",      "TEXT"},
                        {"login_count", "INTEGER"},
                        {"logout_count","INTEGER"},
                    },
                },
            },
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 604800, // 7 days of 30 s samples ≈ 20k rows
                    .columns = {
                        {"ts",                "INTEGER"},
                        {"snapshot_id",       "INTEGER"},
                        {"cpu_pct",           "REAL"},
                        {"mem_used_pct",      "REAL"},
                        {"commit_pct",        "REAL"},
                        {"disk_read_bps",     "INTEGER"},
                        {"disk_write_bps",    "INTEGER"},
                        {"disk_read_lat_us",  "INTEGER"},
                        {"disk_write_lat_us", "INTEGER"},
                        {"net_rx_bps",        "INTEGER"},
                        {"net_tx_bps",        "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"hour_ts",            "INTEGER"},
                        {"samples",            "INTEGER"},
                        {"cpu_avg",            "REAL"},
                        {"cpu_max",            "REAL"},
                        {"mem_avg",            "REAL"},
                        {"mem_max",            "REAL"},
                        {"commit_avg",         "REAL"},
                        {"read_bps_avg",       "INTEGER"},
                        {"write_bps_avg",      "INTEGER"},
                        {"read_lat_us_avg",    "INTEGER"},
                        {"write_lat_us_avg",   "INTEGER"},
                        {"read_lat_us_max",    "INTEGER"},
                        {"write_lat_us_max",   "INTEGER"},
                        {"rx_bps_avg",         "INTEGER"},
                        {"tx_bps_avg",         "INTEGER"},
                    },
                },
            },
        },

        // ── BRD A2: top-N per-application resource samples ───────────────
        // Rides the same collect_perf tick as the device sampler; aggregated
        // by IMAGE NAME (app-level — per-PID detail lives on process_live),
        // top-10 by CPU ∪ top-10 by working set per tick (<= 20 rows/30 s).
        // NAMES ONLY — no command lines (privacy default); operator redaction
        // patterns apply to the name; own `procperf_enabled` toggle so per-app
        // visibility can be disabled while device-level sampling stays on
        // (works-council posture).
        {
            .name = "procperf",
            .dollar_name = "ProcPerf",
            // Opt-in (works-council posture): a fresh agent reports it disabled
            // on tar.status, matching the explicit "false" collection gate.
            .default_enabled = false,
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 604800, // 7 days × ≤20 rows/30 s ≈ 400k small rows
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"name",        "TEXT"},
                        {"version",     "TEXT"},
                        {"instances",   "INTEGER"},
                        {"cpu_pct",     "REAL"},
                        {"ws_bytes",    "INTEGER"},
                        {"is_kthread",  "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days, per (hour, app)
                    .columns = {
                        {"hour_ts",       "INTEGER"},
                        {"name",          "TEXT"},
                        {"version",       "TEXT"},
                        {"is_kthread",    "INTEGER"},
                        {"samples",       "INTEGER"},
                        {"instances_max", "INTEGER"},
                        {"cpu_avg",       "REAL"},
                        {"cpu_max",       "REAL"},
                        {"ws_avg_bytes",  "INTEGER"},
                        {"ws_max_bytes",  "INTEGER"},
                    },
                },
            },
        },

        // ── netqual (BRD Workstream E — per-connection TCP quality) ──────
        // One row per (tick, ESTABLISHED connection): smoothed RTT + jitter
        // + a CURRENT-loss gauge (tcpi_lost) + lifetime retrans/segs context,
        // joined to the owning process. Co-sampled with the `tcp` source so it
        // shares the snapshot_id (joins to process/perf on ts). Only a coarse
        // destination CLASS (`remote_bucket`) is stored — never the raw remote
        // address — and collection carries its own opt-in toggle + per-tick
        // top-N cap (collector slice). Row-count retention bounds storage
        // deterministically regardless of connection churn.
        {
            .name = "netqual",
            .dollar_name = "NetQual",
            // Opt-in (usage-class per-connection telemetry): disabled on a fresh
            // agent, matching the explicit "false" collection gate.
            .default_enabled = false,
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
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Per-connection rows are far more numerous than the device
                    // perf tier; the collector's per-tick top-N cap is the real
                    // bound, this row cap is the deterministic storage backstop.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",            "INTEGER"},
                        {"snapshot_id",   "INTEGER"},
                        {"proto",         "TEXT"},
                        {"remote_bucket", "TEXT"},
                        {"process_name",  "TEXT"},
                        {"rtt_us",        "INTEGER"},
                        {"rtt_var_us",    "INTEGER"},
                        {"lost",          "INTEGER"},
                        {"retrans",       "INTEGER"},
                        {"segs_out",      "INTEGER"},
                        {"ca_state",      "INTEGER"},
                    },
                },
                // Boot baseline (ADR-0020): ONE row per boot, written at plugin
                // init from cumulative-since-boot OS counters (Windows:
                // GetTcpStatisticsEx2 v4+v6 + GetIfTable2 non-loopback totals).
                // It summarizes network quality over the window BEFORE TAR was
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
                        {"window_s",        "INTEGER"}, // pre-TAR window length
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

        // ── Module / image loads (M1 — docs/tar-module-loads.md) ──────────
        // What loads INTO a process: DLL / dylib / .so + driver / kext / kmod
        // loads, each with a signing verdict — the DLL-search-order-hijack,
        // injection, and BYOVD surface $Process cannot answer. `module_dir` IS
        // captured (the hijack signal is the path, not a command line — a narrow,
        // deliberate divergence from the names-only process posture; no cmdline).
        // M1 registers the schema queryable-empty; collectors are kPlanned until
        // M2 (Windows ETW), M4/M5 (macOS ES), M6 (Linux auditd kmod). The high-
        // volume edge risk-filter that really bounds module_live ships with the
        // first collector; opt-in (module_enabled, default off) like procperf.
        {
            .name = "module",
            .dollar_name = "Module",
            // Opt-in (~100× process volume; ships disabled until an operator
            // turns it on). default_enabled=false is what discharges the M1 §13
            // condition that module_enabled must NOT read as true before a
            // collector exists — it makes tar.status, retention, and the
            // paused_at transition all agree the source starts disabled.
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "etw",
                 "Microsoft-Windows-Kernel-Process image-load events (IMAGE "
                 "keyword 0x40, events 5/6) on a dedicated ETW session; driver "
                 "loads surface as kernel image-loads (System pid). Signing is "
                 "verified out-of-band at drain (WinVerifyTrust + CryptQueryObject "
                 "signer, cached); module_dir is scrubbed of user-profile prefixes "
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // The edge risk-filter (unsigned/kernel/blocked at full
                    // fidelity; signed system modules first-seen-then-count) is
                    // the real bound; this row cap is the deterministic backstop.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",            "INTEGER"},
                        {"snapshot_id",   "INTEGER"},
                        {"action",        "TEXT"},
                        {"pid",           "INTEGER"},
                        {"process_name",  "TEXT"},
                        {"module_name",   "TEXT"},
                        {"module_dir",    "TEXT"},
                        {"signed_state",  "TEXT"},
                        {"signer",        "TEXT"},
                        {"is_kernel",     "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",       "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",     "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
            },
        },

        // ── Software install/uninstall events (Phase 8 Wave 1) ────────────────
        // Diffs the installed-software inventory on the `tar.software` tick
        // (hourly default) and records install/remove/upgrade events over time —
        // the historical "what was installed/removed on this box, when" the
        // point-in-time installed_apps inventory cannot answer. MACHINE SCOPE ONLY
        // (HKLM Uninstall): an event is the host's software, never attributed to a
        // Windows profile, so the capture carries no user identity / personal data
        // (#1620). Opt-in (default_enabled=false): shipped disabled as the cautious
        // posture for a new capture source — an operator turns it on per host via
        // tar.configure software_enabled=true.
        //
        // Windows captures machine-wide (HKLM Uninstall 64-bit + WOW6432Node 32-bit).
        // Linux (dpkg/rpm) and macOS (pkgutil) are kPlanned (queryable-empty) until a
        // fast-follow wires the installed_apps enumeration into a collector.
        {
            .name = "software",
            .dollar_name = "Software",
            // Opt-in (cautious new-source posture): a fresh agent reports it disabled
            // on tar.status, matching the explicit "false" collection gate.
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "registry",
                 "Registry Uninstall keys, polled-and-diffed on the tar.software "
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Install/uninstall is very low-volume — 5000 rows holds years
                    // of change history on a normal endpoint.
                    .retention_default = 5000,
                    .columns = {
                        {"ts",           "INTEGER"},
                        {"snapshot_id",  "INTEGER"},
                        {"action",       "TEXT"}, // installed, removed, upgraded
                        {"name",         "TEXT"},
                        {"version",      "TEXT"},
                        {"prev_version", "TEXT"}, // populated only for 'upgraded'
                        {"publisher",    "TEXT"},
                        {"install_date", "TEXT"}, // registry InstallDate (YYYYMMDD) where present
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",        "INTEGER"},
                        {"name",          "TEXT"},
                        {"install_count", "INTEGER"},
                        {"remove_count",  "INTEGER"},
                        {"upgrade_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",      "INTEGER"},
                        {"name",          "TEXT"},
                        {"install_count", "INTEGER"},
                        {"remove_count",  "INTEGER"},
                        {"upgrade_count", "INTEGER"},
                    },
                },
            },
        },

        // ── ARP / address-resolution table (ADR-0015) ─────────────────────
        // Host L2 adjacency: IP<->MAC bindings per interface. Snapshot-diff
        // appeared/removed keyed on the (interface, ip_address, mac_address)
        // binding — a changing entry_type on the same binding is a value update,
        // not churn. Opt-in (default_enabled=false): low-PII infrastructure data
        // but shipped disabled per the standing capture-source posture. Windows
        // (GetIpNetTable2), Linux (/proc/net/arp) and macOS (NET_RT_FLAGS
        // sysctl, constrained) are all wired (see docs/tar-implementer.md
        // "Adding a capture source").
        {
            .name = "arp",
            .dollar_name = "ARP",
            .default_enabled = false,
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"interface",   "TEXT"},
                        {"ip_address",  "TEXT"},
                        {"mac_address", "TEXT"},
                        {"entry_type",  "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"interface",    "TEXT"},
                        {"ip_address",   "TEXT"},
                        {"mac_address",  "TEXT"},
                        {"appear_count", "INTEGER"},
                        {"remove_count", "INTEGER"},
                    },
                },
            },
        },

        // ── DNS resolution cache (ADR-0015) ───────────────────────────────
        // Host DNS resolver-cache STATE (not per-process queries — the cache is
        // system-wide and carries no pid; per-process attribution via the
        // Microsoft-Windows-DNS-Client ETW provider is a deferred follow-up, so
        // never join dns_live to a process by pid). Snapshot-diff appeared/removed
        // keyed on the (name, record_type, data) resolution; ttl_remaining_s is a
        // value field and is NOT part of the diff key (it decrements every tick
        // and must not churn). Opt-in (usage-class PII — reveals visited domains).
        // Windows only here; Linux/macOS kPlanned.
        {
            .name = "dns",
            .dollar_name = "DNS",
            .default_enabled = false,
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",              "INTEGER"},
                        {"snapshot_id",     "INTEGER"},
                        {"action",          "TEXT"},
                        {"name",            "TEXT"},
                        {"record_type",     "TEXT"},
                        {"data",            "TEXT"},
                        {"ttl_remaining_s", "INTEGER"},
                        {"source",          "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"name",         "TEXT"},
                        {"record_type",  "TEXT"},
                        {"appear_count", "INTEGER"},
                        {"remove_count", "INTEGER"},
                    },
                },
            },
        },

        // ── netconn (ADR-0020 — connectivity-transition timeline) ─────────
        // One row per OS-logged network transition: network connect/disconnect
        // (NetworkProfile 10000/10001), NCSI internet-capability changes
        // (4042), Wi-Fi connect/fail/disconnect + reason (WLAN-AutoConfig
        // 8001/8002/8003). Windows reads the OS-RETAINED operational event
        // logs (EvtQuery), so the first backfill reaches days-to-weeks BEFORE
        // TAR — or the agent — existed on the box: this is the retrospective
        // "was the network flapping before we started watching?" source.
        // PRIVACY: an allow-list parser extracts ONLY the enum/numeric fields
        // below; SSID, BSSID, profile names, interface GUIDs and MACs are
        // never extracted and the raw event XML is never persisted (stricter
        // than the wifi plugin — this table ships fleet-wide). Opt-in like
        // every usage-class source.
        {
            .name = "netconn",
            .dollar_name = "NetConn",
            .default_enabled = false,
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 20000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"}, // connected/disconnected/wifi_connected/
                                                 // wifi_connect_failed/wifi_disconnected/
                                                 // capability_changed
                        {"channel",     "TEXT"}, // networkprofile/ncsi/wlan
                        {"category",    "TEXT"}, // public/private/domain ("" when n/a)
                        {"capability",  "TEXT"}, // none/local/internet ("" when n/a)
                        {"iface_kind",  "TEXT"}, // wifi ("" when unknown)
                        {"reason_code", "INTEGER"}, // WLAN reason / NCSI change reason
                    },
                },
            },
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
        // Opt-in (default_enabled=false): rows expose usernames + share paths
        // (identity/usage-class PII), shipped disabled per the standing
        // capture-source posture (like arp/dns). macOS is outbound-live only
        // via getfsstat — no inbound, no history (honestly out of reach for
        // an unprivileged agent; see the macOS os_support row below).
        {
            .name = "mapdrive",
            .dollar_name = "MapDrive",
            .default_enabled = false,
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"}, // appeared, removed, historical
                        {"direction",   "TEXT"}, // outbound, inbound
                        {"local_mount", "TEXT"},
                        {"remote_path", "TEXT"},
                        {"remote_host", "TEXT"},
                        {"username",    "TEXT"},
                        {"provider",    "TEXT"},
                        {"origin",      "TEXT"}, // live, historical
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"direction",    "TEXT"},
                        {"local_mount",  "TEXT"},
                        {"remote_path",  "TEXT"},
                        {"remote_host",  "TEXT"},
                        {"appear_count", "INTEGER"},
                        {"remove_count", "INTEGER"},
                    },
                },
            },
        },

        // ── power (cursor-model seam, tar_cursor.hpp) — sleep/wake/AC-power
        // transitions. LIVE TIER ONLY, no rollups (P-008 — a mirror/aggregate
        // shape was contradictory for a low-volume host-lifecycle source;
        // netconn's live-only shape is the precedent). Replay idempotence via
        // the UNIQUE record_key index below (tar_cursor.hpp rule 3), not
        // cursor arithmetic.
        //
        // ALEX RULING 2026-09-04 (overrides peer finding P-005 and the
        // Architect's prior adoption of it): power AND removable ship
        // default_enabled = TRUE. NOT the first default-on sources in the
        // product -- process/tcp/service/user/perf have always been on, as
        // machine-scope operational telemetry, and this file's own test
        // (test_tar_schema_registry.cpp) asserts it. These are the first
        // WORKS-COUNCIL-CLASS sources to ship enabled: of the eight added
        // since 1.5 under the opt-in posture (procperf, netqual, module,
        // software, arp, dns, netconn, mapdrive) every one defaults OFF, and
        // power/removable are the first of THAT class to diverge. That divergence from the
        // standing works-council opt-in posture is DELIBERATE and must be
        // documented plainly in the user-manual pages and changelog, not
        // quietly. The retrospective-reach control is retained:
        // power_lookback_seconds (default 604800s / 7 days, 0 = forward-only)
        // still lets an operator suppress historical backfill without
        // disabling the source outright — same shape as netconn_lookback_
        // seconds (ADR-0020).
        //
        // os_support: mechanisms are the 2026-09-04 measured bindings
        // (hardware-probe measurement, Wave 6); the collector ships in this
        // same PR (tar_power_collector.cpp) -- PR #4017 review, minor #12.
        {
            .name = "power",
            .dollar_name = "Power",
            .default_enabled = true,
            .unique_key_column = "record_key",
            .os_support = {
                {"windows", OsSupportStatus::kSupportedConstrained, "powerbroadcast",
                 "Suspend/resume + AC transitions via "
                 "PowerRegisterSuspendResumeNotification / WM_POWERBROADCAST, "
                 "cursor-model (tar_cursor.hpp)."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "logind",
                 "systemd-logind PrepareForSleep sd-bus signal + power-supply "
                 "sysfs/udev, cursor-model. Gated by "
                 "the optional libsystemd dep (YUZU_HAVE_LIBSYSTEMD)."},
                {"macos",   OsSupportStatus::kSupported, "pmset_log",
                 "`pmset -g log` retrospective replay (measured working "
                 "unprivileged on this Mac 2026-09-04, 9,629 lines: "
                 "hardware-probe measurement, Wave 6), cursor-model."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 20000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"}, // sleep, wake, ac_attached,
                                                 // ac_detached, capture_gap
                        {"detail",      "TEXT"},
                        {"record_key",  "TEXT"}, // UNIQUE — replay idempotence
                    },
                },
            },
        },

        // ── removable (cursor-model seam, tar_cursor.hpp) — removable-media
        // attach/detach transitions, plus exec_from_removable correlation
        // (process_enum.hpp's ProcessInfo::exec_path, P-004). LIVE TIER ONLY,
        // no rollups (P-008, same rationale as power above). `image_path` +
        // `pid` are typed identity-adjacent columns (P-004) — `evidence` and
        // `record_key` are forensic/value fields only, never identity
        // carriers. Replay idempotence via the UNIQUE record_key index below.
        //
        // Ships default_enabled = TRUE — see the ALEX RULING note on `power`
        // above; same divergence, same documentation obligation.
        // removable_lookback_seconds (default 604800s, 0 = forward-only)
        // governs historical backfill the same way.
        //
        // os_support: mechanisms are the 2026-09-04 measured bindings
        // (hardware-probe measurement, Wave 6); collectors land wave 2.
        {
            .name = "removable",
            .dollar_name = "Removable",
            .default_enabled = true,
            .unique_key_column = "record_key",
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
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 20000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"}, // attached, detached,
                                                 // present_at_baseline,
                                                 // exec_from_removable,
                                                 // capture_gap
                        {"device_key",  "TEXT"},
                        {"vendor",      "TEXT"},
                        {"product",     "TEXT"},
                        {"serial",      "TEXT"},
                        {"bus",         "TEXT"},
                        {"volume",      "TEXT"},
                        {"size_bytes",  "INTEGER"},
                        {"image_path",  "TEXT"},    // typed identity column (P-004)
                        {"pid",         "INTEGER"}, // typed identity column (P-004)
                        {"evidence",    "TEXT"},    // forensic/value only — not identity
                        {"record_key",  "TEXT"},    // UNIQUE — replay idempotence
                    },
                },
            },
        },
        // ── Usage (Wave 7 PR7.2b) — DERIVED from `process`: a checked_
        // transaction fold (tar_usage.cpp run_usage_fold) pairs started/
        // stopped by (pid, exe_key) into runs; usage_live holds OPEN runs
        // (deleted when closed), usage_daily the per-executable daily
        // aggregate. No collector, no rollup_sql; the fold is driven from
        // collect_fast after the process insert and carries its own gap
        // check against process_live's row-cap prune. DEFAULT-ON per
        // Alex's 2026-09-04 ruling (see docs/user-manual/tar.md).
        // usage_daily_user (per-day username membership) and the two
        // UNIQUE indexes (usage_live(pid, exe_key), usage_daily(day_ts,
        // exe_key)) are created by tar_db.cpp's v6 migration, NOT here --
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
                        // original shape): checked_transaction (tar_db.hpp)
                        // makes a partial commit of this fold structurally
                        // impossible, so there is nothing for a replay guard
                        // to guard against -- see tar_usage.cpp's file banner.
                    },
                },
            },
        },
    };
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
// do_compatibility() (tar_plugin.cpp) derives its `compatibility` action
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
// indexes and `retention_sql`'s time branch filters on, and a second copy of
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

            // Extra indexes for live tables
            if (g.suffix == "live" && src.name == "process") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(name);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "tcp") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_remote ON {0}(remote_addr);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "software") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(name);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "module") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(module_name);\n",
                                   table_name);
                // The canonical "unsigned image loaded in the last 24h" query
                // filters signed_state; index it so that scan stays cheap once a
                // collector populates module_live.
                ddl << std::format(
                    "CREATE INDEX IF NOT EXISTS idx_{0}_signed_state ON {0}(signed_state);\n",
                    table_name);
            }

            // Cursor-model replay idempotence (tar_cursor.hpp rule 3): a
            // source that declares unique_key_column gets a UNIQUE index on
            // it for the live tier, so INSERT OR IGNORE makes a replayed
            // event a no-op instead of a duplicate row.
            if (g.suffix == "live" && !src.unique_key_column.empty()) {
                ddl << std::format(
                    "CREATE UNIQUE INDEX IF NOT EXISTS {0}_record_key_uq ON {0}({1});\n",
                    table_name, src.unique_key_column);
            }

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
        // tar_cursor joins them (S3): without it a wedged cursor source is
        // entirely unobservable -- no reset path exists, and the only remedy is
        // deleting tar.db, which destroys every OTHER source's history too.
        // Reading it exposes a source name, a position and updated_at; the
        // cursor payload is the source's own bookkeeping, not captured content.
        std::unordered_set<std::string> s{"tar_state", "tar_config", "tar_cursor"};
        for (const auto& [real, ref] : table_ref_map())
            s.insert(real);
        // #4260: app-usage tables are read ONLY through the Forensics-gated
        // single-target app_usage plugin reads, never through generic tar.sql
        // (Infrastructure:Read). Remove them from the allowlist after the loop
        // above so the SQLite authorizer (tar_query_authorizer) denies every
        // access path -- direct name, $Usage_* placeholder, alias, JOIN, or
        // subquery -- post-translation, matching the tar_events #760 UP-8
        // no-oracle reasoning this function already documents.
        for (const char* usage_table : {"usage_live", "usage_daily", "usage_daily_user"})
            s.erase(usage_table);
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

std::string rollup_sql(std::string_view source_name, std::string_view target_suffix) {
    // ── Process rollups ─────────────────────────────────────────────────
    if (source_name == "process") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO process_hourly (hour_ts, name, user, start_count, stop_count)
SELECT (ts / 3600) * 3600, name, user,
       SUM(CASE WHEN action = 'started' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'stopped' THEN 1 ELSE 0 END)
FROM process_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name, user)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO process_daily (day_ts, name, user, start_count, stop_count)
SELECT (hour_ts / 86400) * 86400, name, user,
       SUM(start_count), SUM(stop_count)
FROM process_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, name, user)";
        }
        if (target_suffix == "monthly") {
            // M2: Use strftime for calendar-month boundaries instead of fixed 30-day approximation
            return R"(INSERT INTO process_monthly (month_ts, name, user, start_count, stop_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER), name, user,
       SUM(start_count), SUM(stop_count)
FROM process_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), name, user)";
        }
    }

    // ── TCP rollups ─────────────────────────────────────────────────────
    if (source_name == "tcp") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO tcp_hourly (hour_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT (ts / 3600) * 3600, remote_addr, remote_port, proto, process_name,
       SUM(CASE WHEN action = 'connected' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'disconnected' THEN 1 ELSE 0 END)
FROM tcp_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, remote_addr, remote_port, proto, process_name)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO tcp_daily (day_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT (hour_ts / 86400) * 86400, remote_addr, remote_port, proto, process_name,
       SUM(connect_count), SUM(disconnect_count)
FROM tcp_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, remote_addr, remote_port, proto, process_name)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO tcp_monthly (month_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       remote_addr, remote_port, proto, process_name,
       SUM(connect_count), SUM(disconnect_count)
FROM tcp_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), remote_addr, remote_port, proto, process_name)";
        }
    }

    // ── Service rollups ─────────────────────────────────────────────────
    if (source_name == "service") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO service_hourly (hour_ts, name, status_changes, last_status)
SELECT (ts / 3600) * 3600, name,
       SUM(CASE WHEN action = 'state_changed' THEN 1 ELSE 0 END),
       (SELECT s2.status FROM service_live s2
        WHERE s2.name = service_live.name AND s2.ts >= ? AND s2.ts < ?
        ORDER BY s2.ts DESC LIMIT 1)
FROM service_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name)";
        }
    }

    // ── User rollups ────────────────────────────────────────────────────
    if (source_name == "user") {
        if (target_suffix == "daily") {
            return R"(INSERT INTO user_daily (day_ts, user, domain, login_count, logout_count)
SELECT (ts / 86400) * 86400, user, domain,
       SUM(CASE WHEN action = 'login' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'logout' THEN 1 ELSE 0 END)
FROM user_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 86400) * 86400, user, domain)";
        }
    }

    // ── Perf rollups (BRD A1) ───────────────────────────────────────────
    if (source_name == "perf") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO perf_hourly (hour_ts, samples, cpu_avg, cpu_max, mem_avg, mem_max, commit_avg,
    read_bps_avg, write_bps_avg, read_lat_us_avg, write_lat_us_avg,
    read_lat_us_max, write_lat_us_max, rx_bps_avg, tx_bps_avg)
SELECT (ts / 3600) * 3600, COUNT(*),
       AVG(cpu_pct), MAX(cpu_pct), AVG(mem_used_pct), MAX(mem_used_pct), AVG(commit_pct),
       CAST(AVG(disk_read_bps) AS INTEGER), CAST(AVG(disk_write_bps) AS INTEGER),
       CAST(AVG(disk_read_lat_us) AS INTEGER), CAST(AVG(disk_write_lat_us) AS INTEGER),
       MAX(disk_read_lat_us), MAX(disk_write_lat_us),
       CAST(AVG(net_rx_bps) AS INTEGER), CAST(AVG(net_tx_bps) AS INTEGER)
FROM perf_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600)";
        }
    }

    // ── Per-app perf rollups (BRD A2) — per (hour, app name, version) ────
    // is_kthread rides the GROUP BY as an identity column (module_hourly's
    // is_kernel precedent) — never aggregated, since every instance sharing
    // one (name, version) group agrees on it (derive_proc_samples OR's it
    // across instances of the same name).
    if (source_name == "procperf") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO procperf_hourly (hour_ts, name, version, is_kthread, samples,
    instances_max, cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes)
SELECT (ts / 3600) * 3600, name, version, is_kthread, COUNT(*), MAX(instances),
       AVG(cpu_pct), MAX(cpu_pct),
       CAST(AVG(ws_bytes) AS INTEGER), MAX(ws_bytes)
FROM procperf_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name, version, is_kthread)";
        }
    }

    // ── Module / image-load rollups (M1) — per (module, signer, sig, kernel) ──
    // load_count counts 'loaded' events only; 'seed'/'blocked'/'unloaded' stay
    // visible at full fidelity in module_live and are not folded into the count.
    if (source_name == "module") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO module_hourly (hour_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT (ts / 3600) * 3600, module_name, signer, signed_state, is_kernel,
       SUM(CASE WHEN action = 'loaded' THEN 1 ELSE 0 END)
FROM module_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, module_name, signer, signed_state, is_kernel)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO module_daily (day_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT (hour_ts / 86400) * 86400, module_name, signer, signed_state, is_kernel,
       SUM(load_count)
FROM module_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, module_name, signer, signed_state, is_kernel)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO module_monthly (month_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       module_name, signer, signed_state, is_kernel,
       SUM(load_count)
FROM module_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), module_name, signer, signed_state, is_kernel)";
        }
    }

    // ── Software rollups (Phase 8 Wave 1) — per name ─────────────────────────
    // Counts install/remove/upgrade events per application name (machine scope
    // only). The count tier is "how many install events", not "by which build"
    // (that detail stays at full fidelity in software_live).
    if (source_name == "software") {
        if (target_suffix == "daily") {
            return R"(INSERT INTO software_daily (day_ts, name, install_count, remove_count, upgrade_count)
SELECT (ts / 86400) * 86400, name,
       SUM(CASE WHEN action = 'installed' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'upgraded' THEN 1 ELSE 0 END)
FROM software_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 86400) * 86400, name)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO software_monthly (month_ts, name, install_count, remove_count, upgrade_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       name,
       SUM(install_count), SUM(remove_count), SUM(upgrade_count)
FROM software_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), name)";
        }
    }

    // ── ARP rollups (ADR-0015) — per (interface, ip, mac) binding ────────
    if (source_name == "arp") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO arp_hourly (hour_ts, interface, ip_address, mac_address, appear_count, remove_count)
SELECT (ts / 3600) * 3600, interface, ip_address, mac_address,
       SUM(CASE WHEN action = 'appeared' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END)
FROM arp_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, interface, ip_address, mac_address)";
        }
    }

    // ── DNS rollups (ADR-0015) — per (name, record_type) ─────────────────
    if (source_name == "dns") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO dns_hourly (hour_ts, name, record_type, appear_count, remove_count)
SELECT (ts / 3600) * 3600, name, record_type,
       SUM(CASE WHEN action = 'appeared' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END)
FROM dns_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name, record_type)";
        }
    }

    // ── Mapped-drive rollups (capability-map §3.8) — per (direction, mount, remote) ──
    // Only live appeared/removed transitions roll up. `historical` backfill rows
    // are EXCLUDED by the action filter: a backfill row can carry a RECENT artifact
    // timestamp (registry last-write, event-log time) that lands inside the current
    // hour, so without the filter its group would emit a $MapDrive_Hourly row with
    // both counts zero. `username` is intentionally dropped from the hourly grain
    // (aggregate-by-mapping, matching process_hourly which drops pid/cmdline).
    if (source_name == "mapdrive") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO mapdrive_hourly (hour_ts, direction, local_mount, remote_path, remote_host, appear_count, remove_count)
SELECT (ts / 3600) * 3600, direction, local_mount, remote_path, remote_host,
       SUM(CASE WHEN action = 'appeared' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END)
FROM mapdrive_live
WHERE ts >= ? AND ts < ? AND action IN ('appeared', 'removed')
GROUP BY (ts / 3600) * 3600, direction, local_mount, remote_path, remote_host)";
        }
    }

    return {};
}

std::string retention_sql(const std::string& real_table_name, int64_t now_epoch) {
    auto& refs = table_ref_map();
    auto it = refs.find(real_table_name);
    if (it == refs.end())
        return {};

    const auto& src = build_sources()[it->second.source_idx];
    const auto& gran = src.granularities[it->second.gran_idx];

    if (gran.retention_type == RetentionType::kRowCount) {
        // H6: Use OFFSET boundary instead of NOT IN anti-pattern — O(n) vs O(n*k)
        return std::format(
            "DELETE FROM {} WHERE id <= "
            "(SELECT id FROM {} ORDER BY id DESC LIMIT 1 OFFSET {})",
            real_table_name, real_table_name, gran.retention_default);
    } else {
        // NEITHER BRANCH'S SQL RUNS IN PRODUCTION as of #2361. `run_retention`
        // builds both the time-based and the row-count DELETE at the caller so it
        // can bound them -- the time-based one because an unbounded age delete is
        // the wipe the clock guard exists to prevent, the row-count one because
        // the whole batch runs under one held database mutex. This function is
        // now called ONLY as an `.empty()` probe for "is this a retention-bearing
        // table?", plus the text these tests pin.
        //
        // Kept, and kept byte-identical, because `test_tar_warehouse.cpp` and
        // `test_tar_perf.cpp` pin this exact SQL text. So a future author who
        // "fixes" either formula HERE gets a green suite and no behaviour change
        // whatsoever -- change `run_retention` instead.
        int64_t cutoff = now_epoch - gran.retention_default;
        auto ts_col = ts_column_for_suffix(gran.suffix);
        return std::format(
            "DELETE FROM {} WHERE {} < {}",
            real_table_name, ts_col, cutoff);
    }
}

} // namespace yuzu::tar
