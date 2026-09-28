#include "dex_types.hpp"

/// @file dex_types.cpp
/// Definitions for the PURE DEX signal-catalogue accessors and health/roll-up
/// COMPUTATION declared in `dex_types.hpp` (ADR-0031 WS-A4). Relocated
/// VERBATIM from the presentation TU `dex_routes.cpp`, where they were
/// defined despite being declared in this store-free/httplib-free header
/// (PR-1 F1 fix, Fable review 2026-09-28) — `dex_read_model.cpp` (core) was
/// linking against a presentation TU's object file for `dex_signal_groups`,
/// `dex_family_rollup`, `dex_family_health_deduction`, `dex_compute_health`,
/// `dex_catalogued_type_count`, `dex_obs_platforms` and `dex_family_index`,
/// invisible to the seam gate (`scripts/ci/check-seam-closure.py`), which only
/// checks include closure, not link closure. `dex_routes.cpp`'s own callers
/// (the dashboard fragment renderers) are unaffected — they call the same
/// declarations, now satisfied from this TU instead (ODR-safe relocation, not
/// a duplication). No logic changes.

#include <algorithm>

namespace yuzu::server {

// The catalogued signal types (114 today), GROUPED for display — the server-side mirror
// of the agent catalogue (dex_signal_catalog.cpp; keep in sync when adding a
// signal). The All-signals panel renders EVERY entry, fired or not, so
// operators see what the fleet is monitoring — not just what happened to fire
// in the window. Types present in the DB but absent here (a newer agent's
// signal) are appended under "Other" with the raw-label fallback, so the panel
// never hides data.

const std::vector<DexSignalGroup>& dex_signal_groups() {
    static const std::vector<DexSignalGroup> kGroups = {
        {"App reliability",
         {"process.crashed", "process.hung", "process.crashed_managed",
          "process.file_access_failure", "app.sxs_error", "app.activation_failed",
          "app.com_failed", "app.error_popup", "app.shutdown_blocked",
          "app.push_notification_error", "app.file_association_reset", "app.staterepo_error"}},
        {"Boot, start-up & shutdown",
         {"os.boot", "boot.degraded_app", "boot.degraded_driver", "boot.degraded_service",
          "boot.degraded_device", "boot.fast_startup_failed", "os.shutdown",
          "shutdown.degraded", "os.restart_initiated", "os.standby", "os.standby_degraded",
          "os.modern_standby_exit", "os.resume_report", "os.uptime_report"}},
        {"Service health",
         {"service.crashed", "service.start_failed", "service.start_timeout", "service.hung",
          "service.unresponsive", "service.logon_failed", "service.recovery_failed",
          "service.shutdown_failed", "service.dependency_failed"}},
        {"System stability",
         {"os.bugcheck", "os.power_loss", "os.dirty_shutdown", "os.time_unsynced",
          "os.activation_failed", "os.vss_error", "os.shadow_copies_lost",
          "os.crashdump_disabled", "display.driver_reset", "display.dwm_exited",
          "memory.exhausted"}},
        {"Hardware & storage",
         {"hw.error", "hw.device_start_failed", "hw.driver_load_failed", "hw.user_driver_error",
          "hw.cpu_throttled", "hw.battery_error", "hw.tpm_error", "disk.error",
          "disk.smart_failure", "disk.port_reset", "storage.low"}},
        {"Performance",
         {"perf.cpu_sustained", "perf.memory_pressure", "perf.disk_latency_high"}},
        {"File system",
         {"fs.corruption", "fs.write_lost", "fs.flush_failed", "fs.database_corrupt",
          "fs.hive_recovered", "fs.autochk_ran"}},
        {"Network",
         {"network.wifi_drop", "network.wifi_connect_failed", "network.adapter_driver_dump",
          "network.adapter_reset", "network.dns_timeout", "network.dns_register_failed",
          "network.dhcp_failed",
          "network.vpn_failed", "network.smb_failed", "network.smb_write_lost",
          "network.ip_conflict", "network.name_conflict", "network.port_exhaustion",
          "session.rdp_disconnected"}},
        {"Identity & logon",
         {"logon.temp_profile", "logon.profile_locked", "logon.slow_subscriber",
          "logon.folder_redirect_failed", "logon.no_dc", "logon.winlogon_terminated",
          "logon.machine_trust_failed", "logon.biometric_error", "logon.hello_error",
          "logon.aad_token_error", "security.kerberos_error", "security.auth_error"}},
        {"Security & protection",
         {"security.rtp_disabled", "security.rtp_error", "security.threat_detected",
          "security.threat_action_failed", "security.av_update_failed",
          "security.tamper_blocked", "security.tls_alert", "security.bitlocker_error",
          "security.cert_enroll_failed"}},
        {"Updates & installs",
         {"update.failed", "update.check_failed", "update.download_failed",
          "update.transfer_failed", "app_install.failed", "app_uninstall.failed",
          "app_install.appx_failed"}},
        {"Policy & management",
         {"gpo.failed", "gpo.cse_failed", "mgmt.mdm_error"}},
        {"Printing",
         {"print.failed", "print.driver_install_failed", "print.plugin_failed"}},
    };
    return kGroups;
}

std::size_t dex_catalogued_type_count() {
    std::size_t n = 0;
    for (const auto& g : dex_signal_groups())
        n += g.types.size();
    return n;
}

// Per-obs_type platform coverage — which OSes collect a signal type today. Windows
// is the whole EvtSubscribe catalogue; Linux (dex_linux_*) and macOS (dex_macos_*)
// collect the subsets below. THIN explicit map (the one bit of new grouping) — keep
// in sync with the agent collectors; a schema↔catalogue cross-check test guards it.
std::vector<std::string> dex_obs_platforms(const std::string& obs_type) {
    static const char* const kLinux[] = {
        // poll_perf: /proc/stat + /proc/meminfo + /proc/diskstats breaches (all three
        // via the SAME win::breach_update used on Windows) + statvfs storage + uptime
        "perf.cpu_sustained", "perf.memory_pressure", "perf.disk_latency_high", "storage.low",
        "os.uptime_report",
        // poll_throttle: sysfs thermal-throttle counter (dex_linux_sysfs → dex_linux_collector)
        "hw.cpu_throttled",
        // systemd-structured journal records (dex_linux_journal)
        "process.crashed", "service.crashed", "service.hung", "os.time_unsynced",
        // kernel-transport journal lines, classified by dex_linux_kmsg
        // (classify_kernel_message, delegated from parse_journal_line)
        "memory.exhausted", "os.bugcheck", "os.dirty_shutdown", "disk.error", "fs.corruption",
        "hw.error", "process.hung"};
    // The Linux DEX observer (dex_linux_collector) drives all of the above: poll_perf
    // (the /proc CPU + memory + diskstats breach trio — perf.disk_latency_high is the
    // /proc/diskstats await breach, as live as cpu/mem on any ordinary sd*/nvme*/mmcblk
    // disk; only exotic/fabric storage is excluded, dex_linux_proc.hpp is_whole_disk) +
    // statvfs storage + the sysfs throttle counter + the journald poll, whose every
    // `_TRANSPORT=kernel` line is delegated to dex_linux_kmsg's classify_kernel_message
    // (so the kmsg-classified types ARE emitted at runtime via journald, not a separate
    // unwired reader). Keep this map and the drift-net test in test_dex_routes.cpp in
    // lockstep with the collectors — they are hand-maintained because the server suite
    // can't introspect the agent (durable fix: generate from the collector registries).
    static const char* const kMac[] = {
        "process.crashed", "process.hung",  "os.bugcheck",     "memory.exhausted",
        "os.uptime_report", "disk.smart_failure", "hw.error",  "storage.low",
        "hw.cpu_throttled", "service.crashed",    "network.wifi_drop", "update.failed",
        "print.failed",     "mgmt.mdm_error",     "logon.no_dc",       "fs.corruption"};
    auto in = [&](const char* const* arr, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i)
            if (obs_type == arr[i])
                return true;
        return false;
    };
    std::vector<std::string> out;
    out.emplace_back("windows"); // the catalogue IS the Windows EvtSubscribe set
    if (in(kLinux, std::size(kLinux)))
        out.emplace_back("linux");
    if (in(kMac, std::size(kMac)))
        out.emplace_back("macos");
    return out;
}

// One family's rollup over the window (events, active count, blast radius, leader).
// #4035: DexFamilyRollup itself moved to dex_types.hpp (external linkage, no longer
// tied to any one TU's anonymous namespace) so dex_read_model.cpp can build the
// same rollup without a second copy (Rule 1) — this stays the ONE definition of
// the function, now implementing the header's declared struct.
DexFamilyRollup dex_family_rollup(const DexSignalGroup& g,
                                  const std::vector<DexSignalCount>& signals) {
    DexFamilyRollup r;
    r.total = static_cast<int>(g.types.size());
    r.benign = std::string(g.name) == "Boot, start-up & shutdown";
    for (const char* t : g.types) {
        const DexSignalCount* c = nullptr;
        for (const auto& s : signals)
            if (s.obs_type == t) {
                c = &s;
                break;
            }
        if (!c)
            continue;
        r.events += c->count;
        if (c->count > 0)
            ++r.active;
        if (c->distinct_devices > r.max_signal_devices)
            r.max_signal_devices = c->distinct_devices; // #1374: max, not union (see field doc)
        if (!r.top || c->count > r.top->count)
            r.top = c;
    }
    return r;
}

// The composite-score weighting policy (mockup dex-health-score.html). Names MUST
// match dex_signal_groups(). `severity` = how much a failure of this family hurts
// experience; the four multipliers are the server-chosen weighting PRESETS. This
// is policy (transparent + shown), not data — the DATA is the measured impact rate.
const std::vector<DexFamilyWeight>& dex_family_weights() {
    static const std::vector<DexFamilyWeight> w = {
        {"App reliability", "high", 1.0, 1.3, 1.1, 0.8},
        {"System stability", "high", 1.0, 1.6, 0.9, 0.9},
        {"Network", "med", 1.0, 0.8, 1.5, 0.9},
        {"Service health", "med", 1.0, 1.2, 1.0, 0.9},
        {"Updates & installs", "med", 1.0, 1.0, 1.1, 1.0},
        {"Security & protection", "high", 1.0, 0.8, 0.7, 2.2},
        {"Identity & logon", "med", 1.0, 0.9, 1.2, 1.6},
        {"Hardware & storage", "med", 1.0, 1.4, 0.8, 0.9},
        {"Performance", "med", 1.0, 1.1, 1.5, 0.7},
        {"Printing", "low", 1.0, 0.6, 1.6, 0.6},
        {"Boot, start-up & shutdown", "low", 1.0, 0.9, 1.5, 0.7},
        {"Policy & management", "low", 1.0, 0.9, 0.9, 1.3},
        {"File system", "low", 1.0, 1.3, 0.7, 0.9},
    };
    return w;
}
double dex_severity_points(const std::string& sev) {
    return sev == "high" ? 12.0 : (sev == "med" ? 6.0 : 2.0);
}
double dex_preset_mult(const DexFamilyWeight& fw, const std::string& preset) {
    if (preset == "stability")
        return fw.m_stability;
    if (preset == "productivity")
        return fw.m_productivity;
    if (preset == "security")
        return fw.m_security;
    return fw.m_default;
}

// The composite-health computation, shared by the Health page and the Overview
// hub's health teaser. score = 100 − Σ deductions; -1 when N<=0 (suppressed, no
// reporting agents → no fabricated 100).
// #4035: DexHealthResult moved to dex_types.hpp (same rationale as
// DexFamilyRollup above) so dex_read_model.cpp's health-score builder shares
// this exact computation instead of a second copy (Rule 1).
DexHealthResult dex_compute_health(const std::vector<DexSignalCount>& signals, int64_t N,
                                   const std::string& preset) {
    DexHealthResult r;
    if (N <= 0)
        return r;
    double total = 0.0;
    for (const auto& fw : dex_family_weights()) {
        const DexSignalGroup* g = nullptr;
        for (const auto& grp : dex_signal_groups())
            if (std::string(grp.name) == fw.name) {
                g = &grp;
                break;
            }
        const DexFamilyRollup rr = g ? dex_family_rollup(*g, signals) : DexFamilyRollup{};
        // #1374: largest single-signal device radius, not the family union (see field doc).
        double impact = static_cast<double>(rr.max_signal_devices) / static_cast<double>(N);
        if (impact > 1.0)
            impact = 1.0;
        const double ded = dex_severity_points(fw.severity) * dex_preset_mult(fw, preset) * impact;
        r.deds.push_back({fw.name, fw.severity, ded});
        total += ded;
    }
    r.score = std::clamp(100.0 - total, 0.0, 100.0);
    return r;
}

// One family's deduction — the per-family term of dex_compute_health above, factored
// out so the Catalogue's per-card score is provably the SAME number (default preset).
double dex_family_health_deduction(const DexSignalGroup& g,
                                   const std::vector<DexSignalCount>& signals, int64_t N) {
    if (N <= 0)
        return 0.0;
    const DexFamilyRollup rr = dex_family_rollup(g, signals);
    // #1374: impact uses the largest single-signal device radius, not the family
    // union — documented in the methodology so the number and label agree. A union
    // would deduct more for disjoint-device families; this stays the (intentionally
    // approximate, cross-family-overlapping) secondary composite.
    double impact = static_cast<double>(rr.max_signal_devices) / static_cast<double>(N);
    if (impact > 1.0)
        impact = 1.0;
    for (const auto& fw : dex_family_weights())
        if (std::string(fw.name) == g.name)
            return dex_severity_points(fw.severity) * dex_preset_mult(fw, "default") * impact;
    return 0.0;
}

// obs_type → family index (into dex_signal_groups), or -1.
int dex_family_index(const std::string& obs_type) {
    int fi = 0;
    for (const auto& g : dex_signal_groups()) {
        for (const char* t : g.types)
            if (obs_type == t)
                return fi;
        ++fi;
    }
    return -1;
}

} // namespace yuzu::server
