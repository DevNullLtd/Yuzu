#pragma once

/// @file dex_perf_api.hpp
/// The SIXTH per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4) — `DexPerfApi`, covering the DEX **app-perf-over-time**
/// surface: the `/api/v1/dex/perf/*` resources (minus `/compare`, already
/// `VerifyApi`) plus `GET /api/v1/dex/devices/{id}/app-perf`. The sequel to the
/// DEX **signals/experience** seam (`DexApi`, PR #4582) — this is DEX's SECOND
/// abstract seam, not a widening of the first (the two cut by RESOURCE
/// sub-namespace + DATA CLASS: identity/experience signal reads vs
/// heartbeat-now + retained percentile-series performance reads).
///
/// Abstract, store-type-free BY CONSTRUCTION: it includes only the pure
/// `dex_perf_model.hpp` (heartbeat-now, F2a) + `dex_app_perf_pure.hpp`
/// (percentile-series output shapes, F2b — NOT the store-coupled umbrella
/// `dex_app_perf_model.hpp`, which also pulls the core-only builders) +
/// `app_perf_types.hpp` (the two floor-free/no-suppression row types that
/// legitimately cross the seam verbatim) + std. Its transitive include closure
/// NAMES NO STORE TYPE (`AppPerfDailyRow`, `AppPerfFleetRow`, `PgPool`, …) —
/// matching its five sibling abstract headers and enforced by
/// check-seam-closure.py's abstract-header store-type probe.
///
/// A PR #4582 external review found the DEX signals seam's OWN abstract header
/// failed this exact property (a shared model header bundled pure structs WITH
/// store-pointer-taking builder declarations) — this seam applies that lesson
/// from its first commit: `dex_app_perf_model.hpp` is split into a pure half
/// (`dex_app_perf_pure.hpp`, what this header includes) and a core-only half
/// (`dex_app_perf_builders.hpp`, forward-declares the stores + holds the
/// `AppPerfFleetRow`/`AppPerfDailyRow`-taking builders — included only by the
/// impl `dex_perf_api.cpp` and the store-reaching consumers).
///
/// ── Which row types cross the seam, and why (the seam's own leak-boundary) ──
/// `AppPerfVersionDeviceRow` (the version-devices drill) and `AppPerfAppSummary`
/// (the app picker) are RELOCATED pure PODs (`app_perf_types.hpp`) that DO cross
/// this seam verbatim — both resources are floor-FREE / no-suppression-needed
/// (the drill already names `agent_id`; the picker carries no per-agent identity
/// at all), so there is no floor/audit gate for a raw row to bypass.
/// `AppPerfFleetRow` (the raw B2 aggregate, carrying histogram arrays) and
/// `AppPerfDailyRow` (the raw B1 per-device row) do NOT cross — the fleet/group/
/// tag trend resources apply `kDexCohortFloor` suppression to `AppPerfFleetRow`
/// BEFORE anything crosses (the impl returns the already-floor-adjusted, pure
/// `AppPerfTrendPoint`), and the per-device drill returns its JSON already
/// serialized (`device_app_perf_json`) rather than naming `AppPerfDailyRow` in
/// this header at all — the ONE store-reaching serializer that touches it stays
/// core-only (`dex_app_perf_builders.hpp`).
///
/// Each method == ONE public DEX app-perf resource so a presentation/MCP caller
/// consumes only what the public, versioned core API serves (ADR-0031 B3,
/// INV-31-4 "no private core API") — a local in-process implementation today
/// (`LocalDexPerfApi`, dex_perf_api.cpp), a core HTTP client after the WS-B2
/// cutover.
///
/// Deliberately NOT in this seam:
///   - `GET /api/v1/dex/perf/compare` is the `VerifyApi` seam (the `/auto`
///     VERIFY before/after comparison) — a DIFFERENT data class (cohort-PAIRED,
///     evidential, deliberately floor-free) with its own pure model
///     (`app_perf_compare.hpp`), not this seam's `AppPerfProviders::cohort`
///     (dead in production; see `dex_app_perf_builders.hpp`'s banner).
///   - `GET /api/v1/dex/devices/{id}/live` is a bounded live-registry poll, not
///     a stored read at all (`DexApi`'s own scope note; still unowned).
///
/// ── Why ONE seam for heartbeat-now (F2a) AND app-perf-over-time (F2b) ──
/// A single consumer class already held both halves, before this seam existed
/// (`dex_routes.hpp`'s now-removed `PerfFn` + `app_perf_providers_` members);
/// ONE securable
/// (`GuaranteedState:Read`) and ONE floor constant (`kDexCohortFloor`,
/// `dex_perf_model.hpp`) is consumed by BOTH — splitting them would put the
/// floor's owner and a consumer in different seams; and the heartbeat-now half
/// is thin (effectively one `snapshot(cohort_key)`-shaped read), too small for
/// its own family. The cut is by DATA CLASS (both are performance
/// measurements, distinct from `DexApi`'s identity/experience signals), not by
/// URL shape or by which store backs them (a `/dex/perf/*` URL prefix is NOT
/// itself an architecture argument — see the caveat this exact framing drew in
/// review).
///
/// LINK RESIDUAL (WS-B2, tracked like #4579 — not yet filed separately): the
/// heartbeat-now pure transforms (`dex_perf_fleet_now` etc., `dex_perf_model.cpp`)
/// and the app-perf-over-time pure transforms (`app_perf_fleet_trend` etc.,
/// `dex_app_perf_model.cpp`) are already core-side TUs — this seam does not
/// reintroduce the DEX-signals-seam's presentation-TU link residual.
///
/// ── Consumer rewire status (disclosed, not silent) ──
/// The REST (`rest_api_v1.cpp`) and MCP (`mcp_server.cpp`) consumers are
/// REWIRED through this seam — all 9 `/api/v1/dex/perf/*` handlers + the
/// `/api/v1/dex/devices/{id}/app-perf` drill, and their 9 MCP tool twins +
/// `get_dex_device_app_perf`, call `dex_perf_api->method(...)` /
/// `dex_perf_api_->method(...)` exclusively (zero remaining direct
/// `app_perf_providers.<member>()`/`dex_perf_fn()` calls in either file —
/// grep-verified). This mirrors DexApi's own first-commit shape (PR #4582,
/// 241e835f5): the REST+MCP rewire lands together with the seam build.
///
/// #4626 completed the dashboard rewire (`dex_routes.cpp`'s F2a/F2b
/// fragments, `dex_perf_ui.cpp`, `dex_app_perf_ui.{hpp,cpp}`) — mirroring how
/// #4576 completed `DexApi`'s own dashboard deferral. `AppPerfProviders` (the
/// pre-seam provider bundle) is RETIRED — this seam's `dex_perf_api` instance
/// is now the SOLE consumer for every surface (REST, MCP, dashboard).
/// GAP-1 CLOSED (#4857, architect D1 ruling): the model-picker's device-model
/// scope-selector values are no longer a standalone `DexRoutes::TagValuesFn`
/// reading `TagStore` outside this seam — `DexRoutes` now derives them from
/// THIS seam's own `fleet_snapshot(kDexDefaultCohortKey)`, via the SAME
/// `dex_perf_cohorts()` helper the `GET /api/v1/dex/perf/cohorts` resource
/// uses, so the dashboard picker and the public REST resource can never list
/// different values. `fleet_snapshot` has no degrade channel (see its own doc
/// comment), so a genuine empty cohort list is never rendered as a claimed
/// "degraded" state — it is disclosed as "Model: no device-model values in
/// the current fleet snapshot." instead, deliberately neutral wording since
/// the empty case covers BOTH devices reporting with no `model` tag AND zero
/// devices reporting anything at all this cycle (governance round-2, G8-2 —
/// the earlier "no reporting device carries a model tag" wording falsely
/// presupposed reporting devices existed). An unwired `dex_perf_api_` does NOT reach this
/// code path at all: `DexRoutes`'s route handler returns an "unavailable"
/// placeholder from its trend fetch before ever calling `fleet_snapshot`
/// (see `dex_routes.cpp`'s F2a fragment handler).
/// See `dex_app_perf_builders.hpp`'s banner for why VerifyApi's `.cohort`
/// input shape specifically is not folded into this seam (a Fable review of
/// the plan found it dead in production and would drag VerifyApi's types
/// into this closure). `check-seam-closure.py`'s `dex_perf` family now
/// enforces the dashboard consumer TUs too (`dex_perf_ui.cpp`,
/// `dex_app_perf_ui.{hpp,cpp}`), narrowing the gap to `network`'s
/// five-consumer-enforced posture — `dex_routes.cpp`/`.hpp` itself stays
/// OUTSIDE the enforced set (it also registers the still-store-coupled
/// DEX-SIGNALS fragments, out of this seam's scope; see the script's own
/// comment on that family entry).

#include "app_perf_types.hpp"    // AppPerfAppSummary, AppPerfVersionDeviceRow — floor-free, cross verbatim
#include "dex_app_perf_pure.hpp" // AppPerfTrendPoint et al. (F2b percentile-series output shapes)
#include "dex_perf_model.hpp"    // DexPerfSnapshot et al. (F2a heartbeat-now; already pure pre-seam)

#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The in-process public DEX app-perf-over-time API. Each method == one public
/// REST/MCP resource, so presentation/MCP consume only what the public,
/// versioned core API serves (ADR-0031 B3, INV-31-4) — a local in-process
/// client today, a core HTTP client after the WS-B2 cutover.
class DexPerfApi {
public:
    virtual ~DexPerfApi() = default;

    // ── Heartbeat-NOW (F2a) — thin pass-through to the registry-backed
    //    snapshot; the caller applies the SAME pure transforms
    //    (dex_perf_fleet_now / dex_perf_cohorts / dex_perf_cohort_diff /
    //    dex_perf_device_list, dex_perf_model.hpp) it does today. ──

    /// Backs GET /api/v1/dex/perf/{fleet,cohorts,cohort-diff,devices} — all four
    /// resources derive from ONE snapshot for a cohort key ("" = no cohort
    /// resolution needed, the `/fleet` resource's own convention).
    [[nodiscard]] virtual DexPerfSnapshot fleet_snapshot(const std::string& cohort_key) const = 0;

    // ── App-perf-over-time (F2b, Postgres B1/B2) — each method returns the
    //    ALREADY floor-applied / already-serialized shape; no raw store row
    //    (AppPerfFleetRow, AppPerfDailyRow) ever crosses this boundary.
    //    `nullopt` is the AUTHORITATIVE read degrade (store/pool/query failure
    //    OR, for the group/tag variants, member/tag resolution failure) —
    //    every caller (REST 503, MCP internal-error) treats it as such, never
    //    as "no data" (that is an engaged-but-empty vector, a normal PRESENT
    //    value). ──

    /// GET /api/v1/dex/perf/apps — the picker: apps with retained fleet data.
    /// `truncated` (out-param) set when the cap clipped the list.
    [[nodiscard]] virtual std::optional<std::vector<AppPerfAppSummary>>
    apps(bool& truncated) const = 0;

    /// GET /api/v1/dex/perf/app?app=&version= — the fleet trend for one app
    /// (`version` empty = every version). `kDexCohortFloor` suppression is
    /// APPLIED INSIDE the impl before returning (never the raw `AppPerfFleetRow`).
    [[nodiscard]] virtual std::optional<std::vector<AppPerfTrendPoint>>
    app_fleet_trend(const std::string& app, const std::string& version) const = 0;

    /// GET /api/v1/dex/perf/app/devices?app=&version= — the version-row "which
    /// devices" drill. FLOOR-FREE (every row already names an agent_id — see
    /// the routed-concern doc's DEX row): returns the relocated pure
    /// `AppPerfVersionDeviceRow` verbatim. `visible_agent_ids` mirrors the
    /// ADR-0017 admit-then-filter contract — `nullopt` = unfiltered, engaged
    /// (INCLUDING empty) = restrict to exactly these agent_ids, pushed into the
    /// underlying store query, NEVER a post-fetch filter. `truncated` (out-param)
    /// set when the cap clipped the list to the highest-CPU devices.
    [[nodiscard]] virtual std::optional<std::vector<AppPerfVersionDeviceRow>>
    app_version_devices(const std::string& app, const std::string& version,
                        const std::optional<std::vector<std::string>>& visible_agent_ids,
                        bool& truncated) const = 0;

    /// GET /api/v1/dex/perf/group?group_id=&app=&version= — the management-group
    /// trend: the on-the-fly B1 aggregate over the group's members, with
    /// `kDexCohortFloor` suppression APPLIED INSIDE the impl (a named group is a
    /// set of specific devices, so a small-N aggregate is de-facto individual
    /// behaviour — works-council). `nullopt` = the aggregate read failed OR the
    /// B1 `group_reader_` is unwired OR the group/tag store is unwired OR the
    /// member-resolution read degraded (`ManagementGroupStore::get_members_checked`
    /// returned `nullopt` — store-not-open / pool-acquire-timeout / query-error,
    /// #1762, fixed). `LocalDexPerfApi` resolves members via the checked twin,
    /// not the fail-soft `get_members()`, so a degraded member read now fails
    /// closed to `nullopt` instead of rendering as an empty trend — the SAME
    /// contract `tag_trend` below already has via `TagStore`, which returns
    /// `std::optional` and fails closed on a degraded tag read.
    [[nodiscard]] virtual std::optional<std::vector<AppPerfTrendPoint>>
    group_trend(const std::string& group_id, const std::string& app,
               const std::string& version) const = 0;

    /// GET /api/v1/dex/perf/tag?key=&value=&app=&version= — the SAME on-the-fly
    /// B1 aggregate as `group_trend`, membership resolved via a device tag value
    /// instead of a management-group id. Same floor, same degrade contract.
    [[nodiscard]] virtual std::optional<std::vector<AppPerfTrendPoint>>
    tag_trend(const std::string& tag_key, const std::string& tag_value, const std::string& app,
             const std::string& version) const = 0;

    /// GET /api/v1/dex/devices/{id}/app-perf (+ MCP get_dex_device_app_perf) —
    /// the audited per-device B1 drill. Returns the ALREADY-SERIALIZED response
    /// body (the raw `AppPerfDailyRow` rows never cross this header — the one
    /// serializer that names that type, `dex_device_app_perf_json`, is
    /// core-only). `nullopt` = read degrade. This method does NOT itself
    /// audit — exactly like `DexApi`'s builder-backed methods, the caller's OWN
    /// fail-closed (REST) / set-and-proceed (MCP) `dex.device.app_perf.view`
    /// audit (before or after the call, per its existing per-transport
    /// contract) stays authoritative; adding audit here would duplicate or
    /// reorder it. `audit_persisted` is threaded straight through to the
    /// serializer (per `dex_device_app_perf_json`'s own contract) — REST never
    /// passes `false` (it fails closed before reaching this call at all); MCP's
    /// set-and-proceed posture passes its own audit-write outcome so the body
    /// carries `audit_persisted:false` on a lost evidence row, MCP's only
    /// channel for that signal (no `Sec-Audit-Failed` header on this transport).
    [[nodiscard]] virtual std::optional<std::string>
    device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                         bool audit_persisted = true) const = 0;

    /// The SUMMARY-shaped twin of `device_app_perf_json` above — a core-side
    /// PROJECTION of the SAME public resource (`GET /api/v1/dex/devices/{id}/
    /// app-perf`, INV-31-4-compliant: identical underlying B1 data, a pure
    /// summariser over it), added for the `/fragments/dex/device/app-perf`
    /// dashboard drill (#4626), which renders `AppPerfDeviceApp` rows directly
    /// rather than consuming the already-serialized JSON body. The impl MUST
    /// derive this from the SAME raw-row read `device_app_perf_json` uses —
    /// neither method derives from the other (see `LocalDexPerfApi`'s shared
    /// private helper) — so the two can never disagree on what a device's
    /// retained B1 rows say. `nullopt` = read degrade (same authoritative
    /// contract as every other over-time method above).
    [[nodiscard]] virtual std::optional<std::vector<AppPerfDeviceApp>>
    device_app_summaries(const std::string& agent_id) const = 0;
};

} // namespace yuzu::server
