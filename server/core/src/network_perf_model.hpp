#pragma once

/// @file network_perf_model.hpp
/// /network fleet read model — PURE aggregation over per-device current
/// heartbeat NETWORK facts, joined with the device's perf sample and a
/// server-resolved app-instability flag. Computed at request time over
/// registry/store state — ZERO new storage. Validation and percentile ranking
/// come from network_perf_rules.hpp (which reuses dex_perf_rules.hpp), shared
/// with the Prometheus rollup so a device is parsed identically for both. NOTE:
/// these cards are OS-blended (one fleet distribution); the yuzu_fleet_net_*
/// gauges are split per `os`, so on a mixed fleet an aggregate here differs from
/// any single gauge series by design (Win + Linux rates are not comparable).
///
/// THE EDGE SHIPS FACTS; this model COUNTS co-occurrence (network ∩ device ∩
/// app) but NEVER attributes a cause. The causal verdict ("it's the network")
/// is a deliberate post-v1 OVERLAY — a contained deterministic rule for
/// automation + an agentic colleague for deep-dive. Nothing here blames.
///
/// Honesty rules: a metric nobody reported is ABSENT (std::nullopt), never 0;
/// every aggregate carries its reporting population; RTT carries its OWN
/// denominator (devices that report smoothed RTT — fewer than the total today,
/// because Windows RTT is coarser/absent pending the ESTATS-vs-ETW spike), so
/// an RTT average over Linux devices is never presented as fleet-wide truth.

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One device's current network facts + the co-occurrence inputs (its perf
/// sample + a server-resolved app-instability flag). Values are already
/// validated through network_perf_rules.hpp by the provider; nullopt = the
/// device did not report that metric this cycle.
struct NetPerfDevice {
    std::string agent_id;
    std::string platform; ///< "windows"/"linux"/"macos"/... — display + honest denominators
    std::optional<double> rtt_ms;         ///< smoothed RTT p50 (Linux today; Windows may be absent)
    std::optional<double> retrans_pct;
    std::optional<double> throughput_bps;
    bool net_degraded{false};             ///< the device's measured network-degraded fact
    // co-occurrence inputs (NOT network metrics, never aggregated as such):
    std::optional<double> cpu_pct;
    std::optional<double> commit_pct;
    std::optional<double> disk_lat_ms;
    bool app_unstable{false}; ///< server-resolved: recent crash/hang for this device (DEX store)
    std::string cohort;       ///< resolved value for the requested tag key; "" = untagged
};

/// Provider result: every ONLINE device (reporting or not — the not-reporting
/// drill needs the complement), plus the tag keys available for the cohort
/// picker. Assembled in server.cpp from AgentHealthStore + AgentRegistry +
/// TagStore + the DEX store; a struct (not store deps) keeps the model pure.
struct NetPerfSnapshot {
    std::vector<NetPerfDevice> devices;
    std::vector<std::string> available_keys;
    std::string cohort_key;
};

/// Provider seam: resolve a snapshot for one cohort tag key ("" = no cohort
/// resolution needed). May be empty in tests / degraded wiring.
using NetPerfFn = std::function<NetPerfSnapshot(const std::string& cohort_key)>;

/// One metric's fleet stats. Only constructed when n > 0 (absent-not-zero).
struct NetPerfStat {
    double avg{0.0};
    double p50{0.0};
    double p90{0.0};
    double max{0.0};
    int64_t n{0};
};

/// Measured co-occurrence over the net_degraded devices — COUNTS, never blame.
/// `also_device` and `also_app` MAY overlap (a device can be both); only
/// `network_only` is a clean complement (degraded AND not-pressure AND
/// not-app-unstable). The four counts are reported as facts; no sum is implied.
struct NetCooccurrence {
    int64_t degraded{0};     ///< devices reporting net_degraded
    int64_t also_device{0};  ///< … and under device perf pressure
    int64_t also_app{0};     ///< … and showing app instability
    int64_t network_only{0}; ///< … and neither (network signal stands alone)
};

/// Fleet-now: an OS-blended rollup over the same per-device facts the per-OS
/// yuzu_fleet_net_* gauges carry, plus the honest denominators and the
/// co-occurrence headline.
struct NetPerfFleetNow {
    std::optional<NetPerfStat> rtt;
    std::optional<NetPerfStat> retrans;
    std::optional<NetPerfStat> throughput;
    int64_t reporting{0};     ///< devices contributing at least one net metric
    int64_t rtt_reporting{0}; ///< the honest RTT denominator (devices with smoothed RTT)
    int64_t online{0};        ///< total devices in the snapshot
    NetCooccurrence cooc;     ///< the overview headline
    /// Distinct tag keys available for the cohort picker (mirrors
    /// `NetPerfSnapshot::available_keys` — carried through here, ADR-0031
    /// WS-A4, so a public-API caller with no access to the raw snapshot can
    /// still populate the cohort-key picker; see DexPerfSnapshot's analogous
    /// field for the existing REST/MCP precedent).
    std::vector<std::string> available_keys;
};

NetPerfFleetNow net_perf_fleet_now(const NetPerfSnapshot& snap);

/// Sort/selection metrics for the devices drill. Anything else → kRtt.
enum class NetPerfMetric { kRtt, kRetrans, kThroughput };
NetPerfMetric net_perf_metric_from_token(const std::string& token);
const char* net_perf_metric_token(NetPerfMetric m);

/// Co-occurrence band filter for the overview drills (click a band → its
/// devices). kNone = the ordinary worst-by-metric drill.
enum class NetCoocFilter { kNone, kDegradedAll, kAlsoDevice, kAlsoApp, kNetworkOnly };

/// Map a co-occurrence band token to its filter. Single source of truth shared
/// by the fragment, the REST handler, and the MCP tool (an unrecognised token —
/// including "" — resolves to kNone). Anything else → kNone.
NetCoocFilter net_cooc_from_token(const std::string& token);

/// One row of the devices drill. Carries the co-occurring FACTS inline
/// (under_pressure, app_unstable) so the table shows the correlation at a
/// glance — without asserting a cause. `fleet_pctile` is the device's
/// percentile rank for the sort metric across reporting devices; -1 if the
/// device did not report that metric.
struct NetPerfDeviceRow {
    std::string agent_id;
    std::string platform;
    std::string cohort;
    std::optional<double> rtt_ms;
    std::optional<double> retrans_pct;
    std::optional<double> throughput_bps;
    bool net_degraded{false};
    bool under_pressure{false};
    bool app_unstable{false};
    int fleet_pctile{-1};
};

/// The ONE device list that serves every /network drill:
///  - `not_reporting=true` → devices with NO net metric this cycle (ANY
///    platform — network telemetry is cross-platform, unlike Windows-only perf),
///    sorted by agent_id.
///  - `cooc != kNone`      → net_degraded devices in that co-occurrence band,
///    ordered worst-first by `metric` (rows missing the metric sort last).
///  - otherwise            → devices reporting `metric`, worst first.
/// `cohort_filter` ("" = the untagged residual) further narrows; nullopt = no
/// cohort filtering. `limit` caps rows (callers pass a validated 1..500).
std::vector<NetPerfDeviceRow> net_perf_device_list(const NetPerfSnapshot& snap, NetPerfMetric metric,
                                                   bool not_reporting, NetCoocFilter cooc,
                                                   const std::optional<std::string>& cohort_filter,
                                                   int limit);

} // namespace yuzu::server
