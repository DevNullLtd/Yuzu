#pragma once

/// @file dex_api.hpp
/// The FIFTH per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4), covering the DEX **signals / experience-score**
/// surface — the GuaranteedStateStore-backed `/api/v1/dex/*` resources.
/// Abstract, ZERO store-shaped dependencies — it includes only the pure
/// `dex_read_model.hpp` (pure model structs + model-only serializers, which
/// pulls `dex_types.hpp`, the relocated DEX leaf PODs) + std. Its transitive
/// include closure NAMES NO STORE TYPE (`GuaranteedStateStore`,
/// `AppPerfDailyRow`, …) — matching its four sibling abstract headers and
/// enforced by check-seam-closure.py's abstract-header store-type probe. This
/// held only after PR #4582 split the store-reaching `build_dex_*_model(...)`
/// builders out of `dex_read_model.hpp` into the core-only
/// `dex_read_builders.hpp`; before that this header transitively named
/// `GuaranteedStateStore`. So a future presentation-side client can include
/// this without dragging the server's `guaranteed_state_store.hpp` (a
/// CATASTROPHIC Guardian/Guaranteed-State header) or `dex_routes.hpp` (which
/// pulls `<httplib.h>`) along.
///
/// Each method == ONE public DEX signals resource so a presentation/MCP caller
/// consumes only what the public, versioned core API serves (ADR-0031 B3,
/// INV-31-4 "no private core API") — a local in-process implementation today
/// (`LocalDexApi`, dex_api.cpp), a core HTTP client after the WS-B2 cutover.
/// Adding a method here without a corresponding public REST/MCP resource would
/// reintroduce a private core API and defeat the seam.
///
/// SCOPE — this seam fronts the DEX **signals / experience-score** resources:
/// the per-device experience score + signal summary, the fleet signal rollup /
/// per-signal drill / per-OS coverage, the app blast-radius / stability list,
/// the catalogue-group / health / trends / overview read models, and the raw
/// per-device signal history + single-observation detail. The cut is by
/// RESOURCE sub-namespace + DATA CLASS (identity/experience signal reads),
/// distinct from the app-perf-over-time percentile-series class below.
///
/// Deliberately NOT in this seam:
///   - `GET /api/v1/dex/perf/compare` is ALREADY the `VerifyApi` seam (the
///     `/auto` VERIFY before/after comparison) — NOT a future surface.
///   - the remaining `/api/v1/dex/perf/*` resources and
///     `GET /api/v1/dex/devices/{id}/app-perf` are the app-perf-over-time
///     (percentile-series) data class — the planned `DexPerfApi` (Seam 2).
///   - `GET /api/v1/dex/devices/{id}/live` is a bounded live-registry poll, not
///     a stored read at all (its own tiny seam later).
///
/// The store-backed factory (`make_local_dex_api`) lives in the core-only
/// `dex_api_local.hpp` — this header names no store type at all.
///
/// ── DERIVATION CONTRACT (why the method params are what they are) ──
/// The impl derives `since` from `window` via
/// `dex_iso_since(dex_window_to_days(window))` and obtains the cross-store
/// `DexFleet` denominator from an injected `FleetFn` — exactly as today's
/// handlers do — so neither `since` nor `DexFleet` appears in this abstract
/// interface. NONE of `app`/`overview`/`signal_detail` takes a `visible`
/// (ADR-0017 admit-then-filter set) parameter — WS-A4 PR-1's Gate 7 fix
/// round tried threading one through `app`/`overview` (resolved from a
/// per-caller resolver, `resolve_dex_visible`/`dex_visible_fn_`) and reverted
/// it: the resolver was dormant for a management-group-confined-only caller
/// (REST/MCP's `perm_fn` gate on all three routes is GLOBAL-only, so a
/// confined-only operator never reached it) and wrongly narrowed a
/// JIT-elevated administrator to their BASE identity's grant instead of the
/// unfiltered view elevation earns. A per-row `visible` filter on `app`/
/// `overview` was ALSO never a real fix even where it did run: it would
/// filter only the returned `devices[]`/`top_devices[]` ROWS while leaving
/// every AGGREGATE field (crash/hang counts, health/score distribution,
/// …) fleet-wide regardless — a caller could reasonably (and wrongly) read
/// the aggregate as scoped to their own visible devices. `signal_detail`
/// never had this parameter at all for the same reason — see its own doc
/// comment.

#include <optional>
#include <string>
#include <vector>

#include "dex_read_model.hpp"

namespace yuzu::server {

/// The `GET /api/v1/dex/signals/{obs_type}` composite read model — the four
/// per-obs_type aggregations the handler assembles (subjects, per-OS split,
/// most-affected devices, per-day trend). No shared builder existed for this
/// route (its JSON was assembled inline from four raw store reads); this seam
/// bundles those raw, pure rows so the handler serializes them unchanged.
struct DexSignalDetailModel {
    std::vector<DexSubjectCount> subjects;
    std::vector<DexOsCrashCount> by_os;
    std::vector<DexDeviceCrashCount> devices;
    std::vector<DexDayCrashCount> by_day;
};

/// The in-process public DEX signals API. Each method == one public REST/MCP
/// resource, so presentation/MCP consume only what the public, versioned core
/// API serves (ADR-0031 B3, INV-31-4) — a local in-process client today, a
/// core HTTP client after the WS-B2 cutover. Every method degrades exactly as
/// its underlying builder does when the store is unavailable (empty/`-1`
/// model, never a throw) so the handler's own store-unavailable 503 guard
/// stays the authoritative degrade signal.
class DexApi {
public:
    virtual ~DexApi() = default;

    // ── Builder-backed resources (thin wraps of the shared build_dex_*_model
    //    helpers; `since`/`fleet` derived in the impl) ──

    /// GET /api/v1/dex/devices/{id} — per-device experience score + signal summary.
    [[nodiscard]] virtual DexDeviceScoreModel
    device_score(const std::string& agent_id, const std::string& window) const = 0;

    /// GET /api/v1/dex/devices/{id}/history — per-device raw signal history.
    [[nodiscard]] virtual DexDeviceHistoryModel
    device_history(const std::string& agent_id, const std::string& window) const = 0;

    /// GET /api/v1/dex/devices/{id}/observations/{event_id} — one observation,
    /// `nullopt` when absent OR owned by a different device (same 404 either way).
    [[nodiscard]] virtual std::optional<GuardianObservationRow>
    observation(const std::string& agent_id, const std::string& event_id) const = 0;

    /// GET /api/v1/dex/app?name= — per-app blast radius: crash/hang counts,
    /// faulting modules, exceptions, and the affected-devices list — ALL
    /// fleet-wide, with no per-caller confinement (see this header's own
    /// doc comment on why a `visible` parameter was tried and removed).
    [[nodiscard]] virtual DexAppModel app(const std::string& process_name,
                                          const std::string& window) const = 0;

    /// GET /api/v1/dex/apps — app-centric stability list (no per-agent identity).
    [[nodiscard]] virtual DexAppsModel apps(const std::string& window) const = 0;

    /// GET /api/v1/dex/catalogue?os=&window= — the Catalogue View 1 family
    /// cards + fleet coverage + the "Other (uncatalogued)" list (ADR-0031
    /// WS-A4 PR-1 / Fraser decision 1: the first public resource for the
    /// per-family health score / online-denominator coverage the dashboard
    /// fragment previously computed with no REST/MCP twin).
    [[nodiscard]] virtual DexCatalogueModel
    catalogue(const std::string& os_filter, const std::string& window) const = 0;

    /// GET /api/v1/dex/catalogue/group?name=&os= — one signal family's members;
    /// `nullopt` for an unknown family name (the caller's 404).
    [[nodiscard]] virtual std::optional<DexCatalogueGroupModel>
    catalogue_group(const std::string& group_name, const std::string& os_filter,
                    const std::string& window) const = 0;

    /// GET /api/v1/dex/health?weighting= — derived composite health score.
    [[nodiscard]] virtual DexHealthModel health(const std::string& weighting,
                                                const std::string& window) const = 0;

    /// GET /api/v1/dex/trends — cross-OS + per-family trend source data.
    [[nodiscard]] virtual DexTrendsModel trends(const std::string& window) const = 0;

    /// GET /api/v1/dex/overview — /dex landing fleet summary: health/score
    /// distribution, top apps, and the most-affected top-devices list — ALL
    /// fleet-wide, with no per-caller confinement (same rationale as
    /// `app` above).
    [[nodiscard]] virtual DexOverviewModel overview(const std::string& window) const = 0;

    // ── Builder-less resources (raw store reads, previously assembled inline in
    //    the handler; the seam returns the pure rows, the handler serializes) ──

    /// GET /api/v1/dex/signals?os= — whole-catalogue rollup (one row per obs_type).
    [[nodiscard]] virtual std::vector<DexSignalCount>
    signals(const std::string& window, const std::string& os_filter) const = 0;

    /// GET /api/v1/dex/scope — per-OS signal coverage.
    [[nodiscard]] virtual std::vector<DexOsScope> scope(const std::string& window) const = 0;

    /// GET /api/v1/dex/signals/{obs_type}?os=&limit= — one signal type's
    /// drill-down: subjects/by_os/devices/by_day are ALL fleet-wide
    /// aggregates (the `devices[]` "most-affected" list is a top-`limit`
    /// ranking over the WHOLE fleet, not a per-agent row set a caller could
    /// safely narrow) — no `visible` parameter, matching `app`/`overview`
    /// above, and for the same reason: a post-limit per-row filter on
    /// `devices[]` alone (tried in an earlier WS-A4 PR-1 fix round) left
    /// `subjects`/`by_os`/`by_day` fleet-wide for EVERY caller regardless
    /// of confinement, and top-N-then-filter meant a confined caller could
    /// see FEWER than `limit` devices while never being told the aggregate
    /// above included excluded ones. Both REST and MCP gate this resource
    /// on `GuaranteedState:Read` + a service-scoped-token denial (this
    /// header's own doc comment) — nothing left for a `visible` parameter
    /// to do here.
    [[nodiscard]] virtual DexSignalDetailModel
    signal_detail(const std::string& obs_type, const std::string& window,
                  const std::string& os_filter, int limit) const = 0;
};

} // namespace yuzu::server
