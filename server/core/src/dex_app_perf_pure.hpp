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

#include "dex_stats.hpp" // DexInterval — the one interval shape (pure, store-free)

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
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
    /// The floor is one device (maintainer ruling 2026-10-14), so this is only ever
    /// true for a point no device contributed to; the flag stays on the wire.
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

// ── Per-version crash and hang join (the fleet app-perf report) ──────────────
//
// Joins the per-(version, day) performance series with the crash and hang
// observations of the same application.
//
//   - BREADTH: `crashes`, `hangs` and `affected_devices` (the devices with a
//     crash OR a hang) are fleet-wide event and device counts, always present.
//     They cover every reporting device, not only the sampled ones.
//   - EXPOSURE cohort = `exposure_devices`: devices with retained
//     resource-significant samples for the version in the window (a selected
//     subset, not a census). Unknown (no sample rows) is carried as null and is
//     never zero. When it is known, `exposed_crashes`/`exposed_hangs` are the
//     events on exposed devices and the rate is those events per exposed device
//     over the window, so numerator and denominator describe one population; the
//     rate ratio is published when both versions have a known, positive exposure.
//
// This join carries no device floor (maintainer ruling 2026-10-14, named in the
// routed Guardian/DEX row and the SOC 2 exemption); the per-(version, day) point
// floor of `points[]` is unchanged.
//
// Renderer duties for any panel built on this report: print the cohort beside
// every figure; the absence of a version row is not the absence of failures;
// the rate is per exposed device over the window, not per day of use.
//
// The join and the serializer live here, once, so the REST and MCP transports
// cannot drift.

/// Window length for the crash and hang read, in days, before the observation
/// retention clamp (the effective value is reported on the wire).
inline constexpr int kAppPerfFailureWindowDays = 30;

/// Most versions one report joins (the newest by canonical version); the rest are
/// dropped and `versions_truncated` is set.
inline constexpr std::size_t kAppPerfVersionJoinCap = 20;

/// One version's crash and hang counts as the store read returns them. The
/// `exposed_*` counts are the events on devices that also have exposure rows;
/// `exposure_devices` is nullopt when the version has no exposure rows at all.
struct AppPerfVersionFailureRow {
    std::string version;
    std::optional<std::int64_t> exposure_devices;
    std::int64_t crashes{0};
    std::int64_t hangs{0};
    std::int64_t affected_devices{0};
    std::int64_t exposed_crashes{0};
    std::int64_t exposed_hangs{0};
};

/// One version row of the report: the performance summary plus the failure
/// figures. An absent optional means unknown, never zero.
struct AppPerfVersionRow {
    AppPerfVersionSummary perf;
    std::int64_t affected_devices{0};
    std::int64_t crashes{0}; ///< fleet-wide, always present
    std::int64_t hangs{0};   ///< fleet-wide, always present
    std::optional<std::int64_t> exposure_devices; ///< nullopt = exposure unknown
    std::optional<std::int64_t> exposed_crashes;  ///< nullopt only when exposure is unknown
    std::optional<std::int64_t> exposed_hangs;
    /// Exposed events per exposed device over the window; nullopt when exposure
    /// is unknown or zero.
    std::optional<DexInterval> failure_rate;
    std::string previous_version;            ///< "" = none
    std::optional<DexInterval> failure_rate_ratio; ///< this version / previous version
};

/// The whole report: the unchanged trend points plus the joined version rows.
struct AppPerfFleetReport {
    std::vector<AppPerfTrendPoint> points;
    std::vector<AppPerfVersionRow> versions;
    bool versions_truncated{false};
    int failure_window_days{0};
    int stat_failures{0}; ///< statistics that returned nothing on valid input
};

/// PURE: numeric group-wise order of canonical four-part versions ("a.b.c.d"),
/// a shorter version padded with zeros. "" (the unknown bucket) is less than
/// every other version.
[[nodiscard]] bool app_perf_canon_version_less(std::string_view a, std::string_view b);

/// The versions a report covers: see `app_perf_newest_versions`.
struct AppPerfNewestVersions {
    std::vector<std::string> versions;
    bool truncated{false}; ///< more distinct versions existed than the cap
};

/// PURE: the distinct versions of `points`, newest first by canonical version
/// (the string breaks numeric ties, so the order never depends on input order),
/// capped at `kAppPerfVersionJoinCap`. The ONE selection: the join keeps exactly
/// these rows and the failure read is asked for exactly these versions, so a
/// version dropped from the report is never counted.
[[nodiscard]] AppPerfNewestVersions
app_perf_newest_versions(const std::vector<AppPerfTrendPoint>& points);

/// PURE: build the report from the trend points and the failure rows. Versions
/// are ordered newest first by canonical version and capped at
/// `kAppPerfVersionJoinCap`; "" (unknown) is kept but never chains as a previous
/// version. A version with no failure row reads as zero failures with unknown
/// exposure.
[[nodiscard]] AppPerfFleetReport
app_perf_version_failure_join(std::vector<AppPerfTrendPoint> points,
                              const std::vector<AppPerfVersionFailureRow>& failures,
                              int failure_window_days);

/// PURE: the `versions[]` JSON array for `report`, at full double precision
/// (never a two-decimal formatter). An unbounded upper bound is null with
/// `unbounded: true`.
[[nodiscard]] std::string dex_app_perf_versions_json(const AppPerfFleetReport& report);

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
