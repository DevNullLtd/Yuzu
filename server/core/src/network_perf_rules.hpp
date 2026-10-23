#pragma once

/// @file network_perf_rules.hpp
/// Single source of truth for validating the agent-supplied NETWORK heartbeat
/// facts and for the perf-pressure co-occurrence threshold. Shared by the
/// Prometheus rollup (AgentHealthStore::recompute_metrics) and the /network
/// read model (network_perf_model.cpp) so the gauges and the dashboard can
/// never disagree about the same heartbeat sample.
///
/// Reuses the forged-value-safe numeric parser, nearest-rank and
/// percentile-rank helpers from dex_perf_rules.hpp (yuzu::server::detail) — the
/// same generic math, not duplicated. The forged-value posture is identical:
/// values are agent-supplied strings; accept only finite, non-negative,
/// full-token parses; percentages CLAMP (a >100% claim is a lie, not an
/// outlier); unbounded quantities REJECT above a sanity ceiling (clamping would
/// still poison the average with the ceiling value); inf/nan/negative/garbage
/// → nullopt, which the caller MUST treat as "did not report", never 0.
///
/// THE EDGE SHIPS FACTS, NEVER A VERDICT. `net_degraded` is RETIRED (measurement-
/// first): agents no longer emit it (the absolute-ratio threshold was disproven;
/// a calibrated one needs real-fleet baseline data — a later slice). The parser +
/// `kNetTagDegraded` stay for mixed-version rolling upgrades, but the value is
/// dormant. `net_device_under_pressure()` is a measured CO-OCCURRENCE threshold
/// used only to COUNT "this box is also under perf strain right now" — it is NOT
/// a causal verdict and NOT a Guardian trigger.

#include "dex_perf_rules.hpp"

#include <optional>
#include <string>

namespace yuzu::server::detail {

/// Heartbeat status-tag keys carrying the thin, fixed-cardinality network
/// facts. The agent emits these (gated by `--dex-disable` today; a dedicated
/// per-category `netqual_enabled` toggle arrives with the per-destination
/// warehouse slice); the
/// server side must never spell them inline. Dimensioned per-app / per-dest
/// detail deliberately stays in the device warehouse — NOT on the heartbeat.
inline constexpr const char* kNetTagRttP50Ms = "yuzu.net_rtt_p50_ms";
inline constexpr const char* kNetTagRetransPct = "yuzu.net_retrans_pct";
inline constexpr const char* kNetTagThroughputBps = "yuzu.net_throughput_bps";
inline constexpr const char* kNetTagDegraded = "yuzu.net_degraded";

/// Sanity ceilings — reject absurd-but-finite forged claims (absent != zero).
inline constexpr double kNetMaxSaneRttMs = 6.0e4;          ///< 60 s RTT
inline constexpr double kNetMaxSaneThroughputBps = 1.0e12; ///< 1 TB/s

/// MEASURED co-occurrence perf-pressure thresholds — for the "also under device
/// pressure" COUNT only, never a verdict. The disk arm matches the existing
/// perf.disk_latency_high catalogue arm (25 ms/IO) so the two stay consistent.
inline constexpr double kNetPressureCpuPct = 85.0;
inline constexpr double kNetPressureCommitPct = 90.0;
inline constexpr double kNetPressureDiskLatMs = 25.0;

/// Smoothed RTT (ms): latency-like — no clamp, reject absurd-but-finite.
inline std::optional<double> parse_net_rtt_ms(const std::string& s) {
    return parse_perf_tag(s, 0.0, kNetMaxSaneRttMs);
}
/// TCP retransmission (%): percentage — clamp lies to 100, reject garbage.
inline std::optional<double> parse_net_retrans_pct(const std::string& s) {
    return parse_perf_tag(s, 100.0, 1.0e6);
}
/// Device throughput (bytes/s): unbounded — no clamp, reject absurd-but-finite.
inline std::optional<double> parse_net_throughput_bps(const std::string& s) {
    return parse_perf_tag(s, 0.0, kNetMaxSaneThroughputBps);
}

/// Parse the net_degraded boolean fact. Accepts "1"/"true"/"0"/"false".
/// nullopt on anything else — a missing/garbage fact is "unknown", which the
/// model treats as not-degraded for counting, but the distinction is preserved
/// here so a future caller can tell "absent" from "explicitly false".
inline std::optional<bool> parse_net_degraded(const std::string& s) {
    if (s == "1" || s == "true")
        return true;
    if (s == "0" || s == "false")
        return false;
    return std::nullopt;
}

/// MEASURED co-occurrence threshold: is this device ALSO showing device-perf
/// strain right now? Used only to COUNT the "also under device pressure" band
/// on the /network overview and to flag drill rows. NOT a verdict, NOT a
/// trigger. A nullopt sub-metric simply does not contribute (absent != strain).
inline bool net_device_under_pressure(const std::optional<double>& cpu_pct,
                                      const std::optional<double>& commit_pct,
                                      const std::optional<double>& disk_lat_ms) {
    return (cpu_pct && *cpu_pct >= kNetPressureCpuPct) ||
           (commit_pct && *commit_pct >= kNetPressureCommitPct) ||
           (disk_lat_ms && *disk_lat_ms >= kNetPressureDiskLatMs);
}

} // namespace yuzu::server::detail
