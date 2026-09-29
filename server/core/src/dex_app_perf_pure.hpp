#pragma once

/// @file dex_app_perf_pure.hpp
/// PURE half of the DEX app-perf-over-time read model (ADR-0031 WS-A4,
/// DexPerfApi / Seam 2) — split out of `dex_app_perf_model.hpp` (PR #4582
/// review pattern: the abstract `dex_perf_api.hpp` must include ONLY this
/// header, never the store-coupled `dex_app_perf_builders.hpp`) so the
/// seam's abstract header names no store type. `dex_app_perf_model.hpp`
/// keeps re-including BOTH this file and the core-only
/// `dex_app_perf_builders.hpp`, so every existing caller of that umbrella
/// header is unaffected (ODR-safe relocation, not a duplication — mirrors
/// the `dex_types.hpp` / `dex_read_model.hpp` / `dex_read_builders.hpp`
/// precedent from the DEX signals seam).
///
/// Everything here is store-free and httplib-free: `AppPerfTrendPoint`,
/// `AppPerfVersionSummary`, `AppPerfDeviceVersion`, `AppPerfDeviceApp` are
/// pure PODs — even though the FUNCTIONS that PRODUCE some of them (in
/// `dex_app_perf_builders.hpp`) take a raw store row, the produced structs
/// themselves reference no store type. `app_perf_version_summaries` is pure
/// top to bottom (its input is already this file's own `AppPerfTrendPoint`).
///
/// Honesty rules carried from the rest of DEX:
///   - a percentile that falls in the OPEN top histogram bucket is a FLOOR, not
///     an exact value (`HistPctile::lower_bound`) — render "≥ value", never the
///     boundary as if exact;
///   - a row stamped under a different histogram scheme than the running
///     `kAppPerfHistVersion` has its percentiles WITHHELD (`hist_stale`), never
///     reinterpreted under the current buckets;
///   - the exact fleet mean (`cpu_sum/device_count`) and exact maxima are always
///     carried alongside the bucket-resolution percentiles for callers that need
///     a precise number.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// A percentile read off a fixed-bucket histogram. `value` is the LOWER EDGE of
/// the bucket the percentile falls in (bucket-resolution approximation, not an
/// exact quantile). `lower_bound` is true iff that bucket is the OPEN top bucket
/// (`[last_boundary, +∞)`) — then `value` is a floor and must render "≥ value".
struct HistPctile {
    double value{0.0};
    bool lower_bound{false};
};

/// PURE: the p-th percentile (p in [0,1]) of a fixed-bucket histogram, by the
/// same nearest-rank DIRECTION as `detail::nearest_rank` (the quantile reading,
/// p → value) so the two perf surfaces share one convention. `boundaries` are
/// the N half-open `[lo, hi)` cut points (→ N+1 buckets); `hist` is the per-bucket
/// counts and MUST have `boundaries.size() + 1` entries. Returns `std::nullopt`
/// when the population is empty OR `hist`/`boundaries` sizes disagree (a corrupt
/// or wrong-scheme row — defence-in-depth beneath the caller's `hist_version`
/// check). WS callers pass their byte boundaries widened to double (≤ 8 GiB is
/// exact in double).
[[nodiscard]] std::optional<HistPctile>
percentile_from_hist(const std::vector<std::int64_t>& hist, const std::vector<double>& boundaries,
                     double p);

/// One point of a fleet app-perf trend: a single `(version, day)` B2 row reduced
/// to exact means/maxima + bucket-resolution p50/p95. `hist_stale` flags a row
/// whose stored `hist_version` != `kAppPerfHistVersion` — its percentiles are
/// withheld (all four `std::nullopt`), the exact mean/max still stand.
struct AppPerfTrendPoint {
    std::string version;
    std::int64_t day{0};
    std::int64_t device_count{0};
    double cpu_mean{0.0}; ///< exact fleet mean of per-device daily CPU% averages
    double cpu_max{0.0};  ///< exact fleet max of per-device daily CPU% averages
    std::optional<HistPctile> cpu_p50;
    std::optional<HistPctile> cpu_p95;
    std::int64_t ws_mean{0}; ///< exact fleet mean of per-device daily working-set bytes
    std::int64_t ws_max{0};
    std::optional<HistPctile> ws_p50;
    std::optional<HistPctile> ws_p95;
    bool hist_stale{false};
    /// Set by BOTH the fleet and group paths: this (version, day) point covered
    /// fewer than the statistical floor (`kDexCohortFloor`) of devices, so its stats
    /// are suppressed (means/percentiles cleared) and only `device_count` is honest.
    /// A sub-floor aggregate singles out one operator's behaviour even without an
    /// agent_id (works-council / GDPR singling-out), whether it is fleet-wide or a
    /// named-group slice — so the fleet path floors too, not just the group path.
    bool suppressed{false};
};

/// One application VERSION reduced across the window — the row the dashboard
/// per-version table renders. Built by `app_perf_version_summaries` from the
/// `(version, day)` trend points: the HEADLINE stats are the LATEST day present
/// (current state), and `cpu_series` is the chronological daily mean over the
/// window (the "over time" sparkline). Keeping the reduction pure + here (not in
/// the route) means the dashboard and any future summary surface agree.
struct AppPerfVersionSummary {
    std::string version;
    std::int64_t latest_day{0};   ///< most recent day present for this version
    std::int64_t device_count{0}; ///< latest day's distinct-device count (honest even when suppressed)
    std::int64_t day_count{0};    ///< days this version appears in the window
    bool suppressed{false};       ///< latest day sub-floor (group path) → stats withheld
    bool hist_stale{false};       ///< latest day stamped under a different histogram scheme
    double cpu_mean{0.0};         ///< latest day exact fleet/group mean CPU%
    double cpu_max{0.0};
    std::optional<HistPctile> cpu_p95;
    std::int64_t ws_mean{0};
    /// Chronological daily cpu_mean over NON-suppressed days — the sparkline.
    /// A cleared (suppressed) day is skipped, never plotted as a real 0.
    std::vector<double> cpu_series;
};

/// PURE: reduce `(version, day)` trend points (the output of
/// `app_perf_fleet_trend`/`app_perf_group_trend`, ordered `(version, day)`) to one
/// summary per version. The headline is the latest day; the sparkline series skips
/// suppressed days (a cleared mean is not a real 0). Versions are returned in
/// first-seen order. Robust to unsorted input: it groups by version key, the
/// headline picks the max day, and the sparkline series is sorted chronologically.
[[nodiscard]] std::vector<AppPerfVersionSummary>
app_perf_version_summaries(const std::vector<AppPerfTrendPoint>& points);

// ── Per-device drill (B1, audited PII) — pure output shapes only ─────────────
//
// The single-device companion to the fleet/group trend. The PRODUCING function
// (`app_perf_device_summaries`, dex_app_perf_builders.hpp) takes raw B1 rows, but
// these output structs reference no store type, so they live here.

/// One application VERSION on a single device, reduced across the retained window.
/// The window aggregates are sample-weighted (so days with more 30 s samples weigh
/// more); the maxima are plain maxima; `cpu_series` is the chronological daily
/// `cpu_avg` — the "over time" sparkline.
struct AppPerfDeviceVersion {
    std::string version;            ///< canon version ("" = unknown)
    std::int64_t latest_day{0};     ///< most recent day present for this version
    std::int64_t day_count{0};      ///< distinct days this version appears in the window
    std::int64_t instances_max{0};  ///< peak concurrent process count over the window
    double cpu_avg{0.0};            ///< sample-weighted mean of daily cpu_avg over the window
    double cpu_max{0.0};            ///< max daily cpu_max over the window
    std::int64_t ws_avg{0};         ///< sample-weighted mean of daily ws_avg over the window
    std::int64_t ws_max{0};         ///< max daily ws_max over the window
    std::vector<double> cpu_series; ///< chronological daily cpu_avg — the sparkline
};

/// One application on a single device, grouping its versions. `peak_cpu_avg` is the
/// max window `cpu_avg` across the app's versions — it ranks the app in the table
/// (resource-significant first). `latest_day` is the most recent day across versions.
struct AppPerfDeviceApp {
    std::string app_name;
    std::int64_t latest_day{0};
    double peak_cpu_avg{0.0};
    std::vector<AppPerfDeviceVersion> versions; ///< newest-day first
};

} // namespace yuzu::server
