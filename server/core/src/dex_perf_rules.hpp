#pragma once

/// @file dex_perf_rules.hpp
/// Single source of truth for how agent-supplied perf heartbeat tags are
/// validated and how fleet percentiles are ranked. Shared by the Prometheus
/// rollup (`AgentHealthStore::recompute_metrics`, A4) and the F2a in-product
/// read model (`dex_perf_model.cpp`) so the /metrics gauges and the /dex
/// Performance tab can never disagree about the same heartbeat sample.
///
/// Forged-value posture (A4 + grill round, 2026-06-12): values are
/// agent-supplied strings. `std::stod` does NOT throw on "inf"/"nan" — it
/// returns the non-finite value, which one rogue agent could use to poison a
/// fleet-wide stat for every operator. Accept only finite, non-negative
/// values. Percentages have a semantic bound, so a >100% claim CLAMPS (it is
/// a lie, not an outlier); latency has no bound, so an absurd-but-finite
/// claim (1e308 ms/IO) is REJECTED above a sanity ceiling — clamping would
/// still poison the average with the ceiling value.

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::detail {

/// Heartbeat status-tag keys carrying the A4 device perf sample. The agent
/// emits these (agents/core heartbeat, dex_disable-gated); the server side
/// must never spell them inline.
inline constexpr const char* kPerfTagCpuPct = "yuzu.perf_cpu_pct";
inline constexpr const char* kPerfTagCommitPct = "yuzu.perf_commit_pct";
inline constexpr const char* kPerfTagDiskLatMs = "yuzu.perf_disk_lat_ms";

/// Beyond-absurd per-IO latency ceiling: 1000 s per IO.
inline constexpr double kPerfMaxSaneLatMs = 1.0e6;

/// Parse one agent-supplied numeric tag value. `clamp_hi > 0` clamps the
/// accepted value (percentages); `reject_above` drops absurd-but-finite
/// claims (latency). Returns nullopt on empty/garbage/non-finite/negative/
/// rejected input — the caller must treat that as "did not report", never 0.
///
/// Full-token parse (governance G3): stod("42.5xyz") returns 42.5, and stod
/// is LC_NUMERIC-sensitive — under a comma-decimal global locale "42.5"
/// silently parses as 42 (value distortion, not rejection). Requiring
/// pos == size() rejects both. stod+pos rather than from_chars because
/// libc++ on Apple Clang 15 lacks floating-point from_chars.
inline std::optional<double> parse_perf_tag(const std::string& s, double clamp_hi,
                                            double reject_above) {
    if (s.empty() || s.size() > 32)
        return std::nullopt;
    try {
        std::size_t pos = 0;
        const double v = std::stod(s, &pos);
        if (pos == s.size() && std::isfinite(v) && v >= 0.0 && v <= reject_above)
            return clamp_hi > 0.0 ? (std::min)(v, clamp_hi) : v;
    } catch (...) {}
    return std::nullopt;
}

inline std::optional<double> parse_perf_cpu_pct(const std::string& s) {
    return parse_perf_tag(s, 100.0, 1.0e6);
}
inline std::optional<double> parse_perf_commit_pct(const std::string& s) {
    return parse_perf_tag(s, 100.0, 1.0e6);
}
inline std::optional<double> parse_perf_disk_lat_ms(const std::string& s) {
    return parse_perf_tag(s, 0.0, kPerfMaxSaneLatMs);
}

/// True nearest-rank percentile (the QUANTILE direction: p → value): index
/// ceil(p·n)−1 into a SORTED, non-empty vector. floor((n−1)·p) looks similar
/// but under-reports high percentiles in small fleets (n=2 → p90 = the MIN) —
/// the A4 grill fix, pinned by tests. See percentile_rank for the inverse.
inline double nearest_rank(const std::vector<double>& sorted_vals, double p) {
    assert(!sorted_vals.empty()); // documented precondition — both callers guard
    const auto n = sorted_vals.size();
    const auto idx = static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
    return sorted_vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
}

/// Percentile RANK (the inverse direction: value → rank): the share of
/// reported values ≤ v, as 0..100. This is "this device sits at the fleet's
/// Nth percentile" — a different question from nearest_rank's quantile, and
/// the two deliberately coexist (G3 architect: keep the contrast explicit).
/// Returns -1 on an empty population.
inline int percentile_rank(const std::vector<double>& sorted_vals, double v) {
    if (sorted_vals.empty())
        return -1;
    const auto at_or_below = static_cast<double>(
        std::upper_bound(sorted_vals.begin(), sorted_vals.end(), v) - sorted_vals.begin());
    return static_cast<int>(at_or_below / static_cast<double>(sorted_vals.size()) * 100.0);
}

/// Normalize an agent-reported OS string (an `AgentSession::os` value, e.g.
/// "Windows 11", "linux", "Darwin") into the closed token set the DEX perf
/// surfaces key on: "windows" | "linux" | "macos" | "" (unrecognized/unknown).
/// Case-insensitive prefix match — `starts_with`, NOT `find`: "darwin"
/// CONTAINS "win", so a substring match would misclassify every macOS agent
/// as Windows (the G4 UP-1 bug this function exists to fix, once, in one
/// place, instead of duplicated inline at every call site).
inline std::string dex_perf_os_from_session(std::string_view raw) {
    std::string os(raw);
    for (auto& c : os)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (os.starts_with("win"))
        return "windows";
    if (os.starts_with("lin"))
        return "linux";
    if (os.starts_with("darwin") || os.starts_with("macos"))
        return "macos";
    return "";
}

/// Does this normalized OS token (see dex_perf_os_from_session) have a real
/// heartbeat perf collector today? Windows and Linux both do (TAR perf
/// capture source, `tar_perf.cpp`); macOS is `kPlanned` (all-invalid stub)
/// until the agent-side collector lands. This is the ONE fact the
/// not-reporting drill and the per-OS denominators key on — flip macOS to
/// `true` here, and only here, once its collector ships.
inline bool dex_perf_os_collects(std::string_view os) {
    return os == "windows" || os == "linux";
}

} // namespace yuzu::server::detail
