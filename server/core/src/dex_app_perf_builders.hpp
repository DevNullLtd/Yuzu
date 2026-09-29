#pragma once

/// @file dex_app_perf_builders.hpp
/// CORE-ONLY half of the DEX app-perf-over-time read model (ADR-0031 WS-A4,
/// DexPerfApi / Seam 2). Split out of `dex_app_perf_model.hpp` (mirrors the
/// `dex_read_builders.hpp` precedent from the DEX signals seam) so the pure
/// half — `dex_app_perf_pure.hpp` — carries no store-type token and can sit
/// behind the ABSTRACT `dex_perf_api.hpp` seam with a genuinely store-type-free
/// include closure.
///
/// This header includes the B1/B2 store headers it needs (`AppPerfDailyRow`,
/// `AppPerfFleetRow`) and is included ONLY by store-reaching TUs: the seam impl
/// (`dex_perf_api.cpp`), the definitions TU (`dex_app_perf_model.cpp`), and the
/// parity test. `dex_device_app_perf_json` (absorbed here from the DEX signals
/// seam's `dex_read_builders.hpp`, which only ever parked it pending this
/// seam's arrival — PR #4582 comment: "Seam 2 (app-perf drill) serializer")
/// now has exactly ONE caller, `LocalDexPerfApi::device_app_perf_json`
/// (`dex_perf_api.cpp`) — `rest_api_v1.cpp`/`mcp_server.cpp` were rewired off
/// the raw serializer onto `DexPerfApi::device_app_perf_json` and no longer
/// include this header at all. It is NEVER included by `dex_perf_api.hpp` or
/// any presentation TU.
///
/// `AppPerfProviders` (the pre-seam callback-bundle interface) is RETIRED
/// (#4626) — DexPerfApi never reused or exposed it (a Fable review of the
/// original seam-build plan found its `.cohort`/`CohortRead`/`AppPerfCohortFn`
/// members are VerifyApi's OWN test-double input shape — `verify_api.cpp`'s
/// real production wiring takes an `AppPerfCohortReader*` instead, a
/// different shape entirely — so formalizing `AppPerfProviders` would have
/// dragged a test-only type into this seam's closure). The individual
/// `AppPerfXxxFn` provider typedefs below are now ALSO production-orphaned
/// (no production caller builds one — `AppPerfProviders` was their only
/// consumer, and it is retired): they, plus `CohortRead`/`AppPerfCohortFn`,
/// have been relocated to `tests/unit/server/test_dex_perf_api_double.hpp`
/// (`AppPerfXxxFn`, reused by `FnDexPerfApi::Providers`) and
/// `tests/unit/server/test_verify_api_double.hpp` (`CohortRead`/
/// `AppPerfCohortFn`, `FnVerifyApi`'s own input shape) — see those files for
/// the live definitions.

#include "app_perf_compare.hpp"     // AppPerfCohortRow (the VERIFY compare input shape)
#include "app_perf_daily_store.hpp" // AppPerfDailyRow (per-device drill)
#include "app_perf_fleet_store.hpp" // AppPerfFleetRow
#include "app_perf_hist.hpp"        // bucket scheme + kAppPerfHistVersion
#include "app_perf_types.hpp"       // AppPerfAppSummary, AppPerfVersionDeviceRow
#include "dex_app_perf_pure.hpp"    // HistPctile, AppPerfTrendPoint, AppPerfVersionSummary, ...

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// `kAppPerfParamCap` / `app_perf_param_valid` live in `app_perf_compare.hpp`
/// (ADR-0031 WS-A4 #4250) — still visible here transitively via this file's own
/// `#include "app_perf_compare.hpp"` above, so no existing caller changes.

/// PURE (over a store-row input): reduce retained B2 rows (as returned by
/// `get_app_fleet_perf`, ordered `(version, day)`) to trend points, one per row.
/// The single place the fleet mean + percentile + `hist_version` gate AND the
/// `kDexCohortFloor` suppression are applied, so REST/MCP/UI cannot drift. Rows
/// with `device_count <= 0` yield zero means (never a divide); rows with
/// `device_count < kDexCohortFloor` are suppressed (count only) — a sub-floor
/// fleet aggregate singles out an operator.
[[nodiscard]] std::vector<AppPerfTrendPoint>
app_perf_fleet_trend(const std::vector<AppPerfFleetRow>& rows);

/// PURE (over a store-row input): the GROUP variant — the same build + percentile
/// + `hist_version` gate as the fleet path, with the statistical-floor suppression
/// applied at the caller's `floor` (the dashboard/REST/MCP pass `kDexCohortFloor`).
/// A management group is a set of SPECIFIC devices, so a small-N group aggregate
/// is de-facto individual behaviour (works-council); any point with
/// `device_count < floor` is marked `suppressed` with its means/percentiles
/// cleared (only the honest `device_count` survives). Shares the build + floor
/// helpers with `app_perf_fleet_trend`, so the group and fleet percentile +
/// suppression conventions are IDENTICAL.
[[nodiscard]] std::vector<AppPerfTrendPoint>
app_perf_group_trend(const std::vector<AppPerfFleetRow>& rows, std::int64_t floor);

/// PURE (over a store-row input): reduce ONE device's retained B1 daily rows (as
/// returned by `AppPerfDailyStore::get_agent_app_perf`, ordered
/// `(app_name, version, day)`) into per-app/per-version window summaries for the
/// device drill. Window means are sample-weighted (`cpu_avg`/`ws_avg` weighted by
/// `samples`); a window whose total sample count is zero falls back to an
/// unweighted mean so a malformed-but-present row still shows an honest number
/// rather than 0. Apps are ordered by peak window `cpu_avg` desc (tiebreak
/// `app_name` asc); versions within an app are newest-day first. Robust to
/// unsorted input (groups by key, sorts the series chronologically).
///
/// Precondition: `rows` are canon-merged as `AppPerfDailyStore::get_agent_app_perf`
/// returns them — every numeric finite, non-negative, and bounded (`samples` ≤
/// `kMaxSamples`, so the `int64` sample-weight sum cannot overflow), and unique on
/// `(app_name, version, day)`. Finiteness is load-bearing: the resource-ranking sort
/// compares `double cpu_avg`, which is a valid strict-weak order only for finite
/// values (a NaN would be `std::sort` UB); key-uniqueness keeps `day_count` an honest
/// distinct-day count. The store is the sole writer and enforces all of this on the
/// apply path; this pure fn does not re-validate.
[[nodiscard]] std::vector<AppPerfDeviceApp>
app_perf_device_summaries(const std::vector<AppPerfDailyRow>& rows);

// ── Seam-2 (app-perf drill) shared serializer — names AppPerfDailyRow, so it
//    lives here (NOT in the pure dex_app_perf_pure.hpp or dex_perf_api.hpp).
//    Absorbed from the DEX signals seam's dex_read_builders.hpp (PR #4582
//    parked it here explicitly pending this seam). Its ONE caller is
//    LocalDexPerfApi::device_app_perf_json (dex_perf_api.cpp) — see this
//    file's own banner above; rest_api_v1.cpp's GET /dex/devices/{id}/app-perf
//    handler and mcp_server.cpp's get_dex_device_app_perf reach it only
//    transitively, through DexPerfApi::device_app_perf_json, not directly.
/// Shared JSON serializer for the per-device B1 app-perf drill. `rows` is
/// whatever `DexPerfApi`'s device backing read returned (`LocalDexPerfApi`'s
/// `device_rows()`, `FnDexPerfApi::Providers::device` in tests); empty
/// `app_filter` means "every app". `audit_persisted` per
/// `dex_device_score_json`'s contract (dex_read_model.hpp) — omitted (default
/// true) on success, set false only when the MCP caller's own audit write is
/// known to have failed.
std::string dex_device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                                     const std::vector<AppPerfDailyRow>& rows,
                                     bool audit_persisted = true);

// `AppPerfProviders` (the pre-seam callback-bundle interface DexRoutes/
// RestApiV1/McpServer used to build these providers into) is RETIRED (#4626)
// — every production consumer now routes through `DexPerfApi`/
// `make_local_dex_perf_api` (dex_perf_api_local.hpp) instead. The individual
// `AppPerfXxxFn` provider typedefs (+ `CohortRead`/`AppPerfCohortFn`) that
// used to live here are now production-orphaned and have been relocated to
// `tests/unit/server/test_dex_perf_api_double.hpp` / `test_verify_api_double.hpp`
// respectively — see this file's own banner above.

} // namespace yuzu::server
