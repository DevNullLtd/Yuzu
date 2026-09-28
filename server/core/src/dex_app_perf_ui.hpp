#pragma once

/// @file dex_app_perf_ui.hpp
/// Slice-2 dashboard renderers for DEX app-perf-over-time — the app picker + the
/// per-(app,version) trend table (fleet B2 or named-group B1). PURE free functions
/// over the reduced model (`app_perf_version_summaries`), so the HTMX surface, the
/// REST endpoints, and the MCP tools all read the SAME numbers. Declared here (not
/// in the already-large dex_routes.hpp) so the renderer + its scope-selector type
/// stay a small, separately-testable unit.
///
/// #4626 Concern B: includes the PURE halves directly (`dex_app_perf_pure.hpp`
/// for `AppPerfVersionSummary`/`AppPerfDeviceApp`, `app_perf_types.hpp` for
/// `AppPerfAppSummary`/`AppPerfVersionDeviceRow`) rather than the store-coupled
/// umbrella `dex_app_perf_model.hpp` (which also pulls `dex_app_perf_builders.hpp`
/// — the B1/B2 store headers) — this header + `dex_app_perf_ui.cpp` are enrolled
/// in `scripts/ci/check-seam-closure.py`'s `dex_perf` family, so a store
/// `#include` here is now lint-caught, not just reviewed.

#include "app_perf_types.hpp"    // AppPerfAppSummary, AppPerfVersionDeviceRow
#include "dex_app_perf_pure.hpp" // AppPerfVersionSummary, AppPerfDeviceApp

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// One management group offered in the app-perf scope selector (id + display
/// name). Sourced from `ManagementGroupStore::list_groups` via the DexRoutes
/// `GroupListFn` — a plain struct so the renderer stays pure/testable. Deliberately
/// NO member count: counting per group would be an N+1 over the store on every
/// render (`list_groups` carries no count); the selector shows names only.
struct DexGroupOption {
    std::string id;
    std::string name;
};

/// PURE: the app picker — every application with retained fleet perf history, each
/// row a drill into its per-version trend. `truncated` adds the honest cap note.
/// `q` (default "" = unfiltered) case-insensitive substring-filters by app name.
/// `platform` ("windows"|"linux", default "" = all) filters by a NAME-SUFFIX
/// heuristic (".exe" = windows, anything else = linux) — `AppPerfAppSummary`
/// (app_perf_fleet_store.hpp) carries no real platform column today, so this is a
/// best-effort fallback, not authoritative; the rendered note says so. `sort`
/// selects "last_seen" (default, most-recent-first), "name" (A-Z), or "versions"
/// (most retained versions first); an unrecognized token falls back to "last_seen".
std::string render_dex_app_perf_picker(const std::vector<AppPerfAppSummary>& apps, bool truncated,
                                       int window_days, const std::string& q = "",
                                       const std::string& platform = "",
                                       const std::string& sort = "");

/// PURE: the per-(app,version) perf-over-time table. `versions` is the reduced
/// per-version summary (`app_perf_version_summaries` over the trend points) —
/// already narrowed to `active_version` UPSTREAM (by the caller passing `version`
/// into the same `DexPerfApi::app_fleet_trend`/`group_trend`/`tag_trend` call the
/// REST twin uses, mirroring `GET /dex/perf/app?version=`) when one is selected;
/// `versions` then carries just that one entry. `active_version` empty (the default) = all
/// versions, unnarrowed. `scope_group_id` empty = whole fleet; non-empty = the
/// named-group rollup (the suppression cells render for sub-floor points).
/// `groups` populates the scope selector; `group_floor` is shown in the
/// suppression caption. Version filtering is click-through, not a dropdown (the
/// candidate values are exactly the rows already on screen): each version row's
/// label links to `?version=<v>`, narrowing; a filtered view shows a single row
/// plus an "All versions" link back to `?version=` cleared.
///
/// `model_values` (distinct device-model cohort values sourced from
/// `DexPerfApi::fleet_snapshot(kDexDefaultCohortKey)` via `dex_perf_cohorts()`
/// — the SAME derivation the public `GET /api/v1/dex/perf/cohorts` resource
/// uses, #4857 D1) populates a SECOND, independent scope selector alongside
/// the management-group one. Unlike `groups`, an empty `model_values` does NOT
/// silently hide the selector — `fleet_snapshot` has no degrade channel, so it
/// never renders a claimed "degraded" state. An unwired `DexPerfApi` does NOT
/// reach this note: the caller (dex_routes.cpp's route handler) returns an
/// "unavailable" placeholder before ever populating `model_values` in that
/// case. The empty-list case this note actually covers is NOT uniformly
/// "devices reporting with no `model` tag value" (governance round-2, G8-2)
/// — it is equally reached when zero devices report anything this cycle at
/// all (a genuinely empty fleet snapshot), so the rendered text is
/// deliberately neutral over both causes: "Model: no device-model values in
/// the current fleet snapshot." rather than a selector. `active_model` mirrors `scope_group_id`'s
/// convention (empty = unfiltered). The two scopes are MUTUALLY EXCLUSIVE in
/// this slice (group takes precedence — see dex_routes.cpp's route handler);
/// selecting one clears the other via the emitted links so a caller can never
/// land on a URL naming both from this UI (a hand-edited URL naming both is
/// still handled: the route resolves it to the group scope, never silently
/// combining the two).
std::string render_dex_app_perf_trend(const std::string& app_name,
                                      const std::vector<AppPerfVersionSummary>& versions,
                                      const std::string& scope_group_id,
                                      const std::vector<DexGroupOption>& groups,
                                      std::int64_t group_floor, int window_days,
                                      const std::string& active_version = "",
                                      const std::vector<std::string>& model_values = {},
                                      const std::string& active_model = "");

/// PURE: the version-row "which devices" drill — one row per device that
/// reported `(app_name, version)` among its retained top-N resource consumers,
/// its most recent CPU/working-set sample and last-seen day. NOT a census (see
/// the file-level top-N caveat on the trend table's own foot note) — a device
/// absent here may still run this exact app-version, just not among its top
/// resource consumers that day. An empty `devices` renders an honest combined
/// explanation covering BOTH reasons a version-row drill can legitimately be
/// empty: no device's top-N ever named it, OR this version's per-device (B1)
/// data has aged past its 31-day retention even though the fleet trend (B2)
/// covers up to 180 days — the two stores retain independently, so a >31-day
/// trend point returning zero devices is expected, not a bug. `truncated` adds
/// the honest cap note (the highest-CPU devices are kept, the rest dropped).
/// Returned content is a bare block (no outer `<table>`/`<tr>` wrapper) — the
/// caller (dex_routes.cpp) wraps it in whatever shell its own htmx swap target
/// needs (today: a `<tr><td colspan>` row inserted after the clicked version
/// row).
std::string render_dex_app_perf_version_devices(const std::vector<AppPerfVersionDeviceRow>& devices,
                                                bool truncated);

/// PURE: the per-DEVICE app-perf drill (B1) — one application per group, its
/// versions as sub-rows, with a CPU-over-time sparkline and window aggregates.
/// Sits inline inside the device drill's perf panel (in-place swap, no back-link —
/// peer of the live procperf table, NOT the full-pane fleet picker). `apps` is the
/// reduced model (`app_perf_device_summaries`); an empty `apps` renders the honest
/// empty state (the caller already mapped a store degrade to a 503 + note). Single
/// device → exact daily values (no percentiles, no cohort floor — it is behind the
/// `dex.device.app_perf.view` audit gate). Per-version crashes/hangs are deferred
/// (a separate central crash-store join), noted in the foot.
std::string render_dex_device_app_perf(const std::vector<AppPerfDeviceApp>& apps);

} // namespace yuzu::server
