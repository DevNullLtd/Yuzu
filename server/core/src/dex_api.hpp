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
/// interface. `visible` (the caller's ADR-0017 admit-then-filter set)
/// remains on `app`/`overview` for a NON-aggregate consumer that genuinely
/// confines its own device list (today: none — the WS-A4 PR-1 Gate 7 fix
/// round pinned the REST/MCP handlers to a GLOBAL-only
/// `AuthRoutes::require_fleet_read` admit and now always pass `nullptr`
/// here; see each method's own doc comment below for the constraint on any
/// FUTURE non-null caller). `signal_detail` DROPPED its `visible` parameter
/// entirely in that same fix round — see its own doc comment for why a
/// per-row filter was never safe for that method's `subjects`/`by_os`/
/// `by_day` aggregates in the first place.

#include <optional>
#include <set>
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

    /// GET /api/v1/dex/app?name= — per-app blast radius. `visible`, if
    /// non-null, filters ONLY the returned `devices[]` ROWS — it does NOT,
    /// and cannot, confine the crash/hang-count AGGREGATES this model also
    /// carries (there is no per-caller SQL slice of a fleet-wide rollup).
    /// ADR-0017 INV-3 / the `software_catalog` ruling: a caller with an
    /// ENGAGED (confined) visible set must NOT pass it here — it would
    /// either leak the aggregate fleet-wide while only narrowing the device
    /// list (a caller could reasonably read the aggregate as "for my
    /// devices"), or, if a future change also confined the aggregate, do so
    /// per-caller in a way no other caller of the same underlying data would
    /// agree with. The REST/MCP handlers (WS-A4 PR-1 Gate 7 fix round) never
    /// reach this call with an engaged scope — they refuse it at the gate
    /// (`refuse_confined_aggregate_read`/`refuse_confined_dex_aggregate`)
    /// and always pass `nullptr`. This parameter survives ONLY for the
    /// dashboard fragment rewire (PR-2, issue TBD) to decide the fate of —
    /// do not widen its use before that decision is made.
    [[nodiscard]] virtual DexAppModel app(const std::string& process_name,
                                          const std::string& window,
                                          const std::set<std::string>* visible) const = 0;

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

    /// GET /api/v1/dex/overview — /dex landing fleet summary. `visible`, if
    /// non-null, filters ONLY the returned top-devices ROWS — it does NOT,
    /// and cannot, confine the health/score/distribution AGGREGATES this
    /// model also carries. Same ADR-0017 INV-3 constraint, same PR-2-only
    /// survival, as `app`'s `visible` parameter above — see its doc comment
    /// for the full rationale. The REST/MCP handlers always pass `nullptr`.
    [[nodiscard]] virtual DexOverviewModel
    overview(const std::string& window, const std::set<std::string>* visible) const = 0;

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
    /// safely narrow). ADR-0031 WS-A4 PR-1 originally added a `visible`
    /// parameter here (a post-limit per-row filter — see the removed doc
    /// text this replaces, in git history) to close a fleet-wide
    /// `devices[]` disclosure on REST `GET /api/v1/dex/signals/{obs_type}` +
    /// MCP `get_dex_signal_detail`. The WS-A4 PR-1 Gate 7 fix round
    /// (arch-1/sec8-1/sec8-2, Fraser decision: "aggregates GLOBAL-ONLY")
    /// REMOVED it again: filtering only `devices[]` post-limit left the
    /// `subjects`/`by_os`/`by_day` aggregates fleet-wide for EVERY caller
    /// regardless of confinement (a leak, not a fix), and top-N-then-filter
    /// also meant a confined caller could see FEWER than `limit` devices
    /// while still not being told the aggregate above included excluded
    /// devices — a shape ADR-0017 INV-3 / the `software_catalog` ruling
    /// (docs/adr/0017-management-group-confinement-list-reads.md
    /// ~:289-298) says a fleet-wide rollup must not offer at all. Both REST
    /// and MCP now refuse ANY engaged (confined) `require_fleet_read` scope
    /// outright (403 / permission-denied) before ever reaching this method,
    /// so it is called only on an unfiltered (global) admit — there is
    /// nothing left for a `visible` parameter to do here.
    [[nodiscard]] virtual DexSignalDetailModel
    signal_detail(const std::string& obs_type, const std::string& window,
                  const std::string& os_filter, int limit) const = 0;
};

} // namespace yuzu::server
