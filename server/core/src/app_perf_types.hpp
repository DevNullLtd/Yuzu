#pragma once

/// @file app_perf_types.hpp
/// PURE value types for the DEX app-perf-over-time family (ADR-0031 WS-A4,
/// DexPerfApi / Seam 2) — leaf PODs relocated OUT of the B1/B2 store headers
/// so the abstract `dex_perf_api.hpp` can name them without dragging
/// `app_perf_daily_store.hpp` / `app_perf_fleet_store.hpp` (which pull
/// `pg::PgPool`) along. Mirrors the `dex_types.hpp` precedent from the DEX
/// signals seam (PR #4582).
///
/// This header is store-free and httplib-free BY CONSTRUCTION: only
/// `<cstdint>` / `<string>`. `app_perf_daily_store.hpp` and
/// `app_perf_fleet_store.hpp` now `#include` THIS one and keep re-exporting
/// these types transitively, so every existing includer is unaffected
/// (ODR-safe relocation, not a duplication).
///
/// NOT relocated here: `AppPerfFleetRow` (`app_perf_fleet_store.hpp`) stays a
/// genuine store-row type — it carries the raw per-`(version,day)` histogram
/// arrays the `kDexCohortFloor` suppression must apply to BEFORE anything
/// crosses the seam, so it is deliberately NOT exposed by `DexPerfApi`'s
/// abstract methods (only the floor-applied `AppPerfTrendPoint` is). It is
/// listed in `check-seam-closure.py`'s `EXTRA_STORE_TYPE_TOKENS` so a future
/// accidental leak of it into an abstract header is caught, not silently
/// passed (PR #4582 review; `AppPerfDailyRow` is NOT relocated either, for the
/// same reason — the single-target device drill's per-day rows never cross
/// the abstract boundary as raw store rows).

#include <cstdint>
#include <string>

namespace yuzu::server {

/// One device's per-`(app,version)` retained daily row, reduced to the fields
/// the version-row "which devices" drill serializes. Relocated verbatim from
/// `app_perf_daily_store.hpp` (was `AppPerfVersionDeviceRow` there).
struct AppPerfVersionDeviceRow {
    std::string agent_id;
    std::int64_t last_day{0}; ///< most recent day this device reported this (app,version)
    std::int64_t samples{0};
    double cpu_avg{0.0};       ///< that day's share-of-capacity CPU%
    std::int64_t ws_avg_bytes{0};
};

/// One retained app name + its distinct-version/last-seen summary — the
/// `/dex/perf/apps` picker row. Relocated verbatim from `app_perf_fleet_store.hpp`
/// (was `AppPerfAppSummary` there).
struct AppPerfAppSummary {
    std::string app_name;
    std::int64_t versions{0}; ///< distinct retained versions
    std::int64_t last_day{0}; ///< most recent UTC-midnight epoch day with data
};

} // namespace yuzu::server
