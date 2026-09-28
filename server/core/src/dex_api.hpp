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
/// interface. `visible` (the caller's ADR-0017 admit-then-filter set) DOES
/// appear where a resource confines its device list: it is resolved from the
/// authenticated request by the handler's `FleetReadFn` gate
/// (`AuthRoutes::require_fleet_read`'s composed `VisibleSet`, WS-A4 PR-1 fix
/// round) and threaded in, since it depends on the caller's identity, not
/// the store.

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

    /// GET /api/v1/dex/app?name= — per-app blast radius; `visible` confines the
    /// affected-devices list (nullptr = unconfined / global Read).
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

    /// GET /api/v1/dex/overview — /dex landing fleet summary; `visible` confines
    /// the top-devices list (nullptr = unconfined / global Read).
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
    /// drill-down. `visible` confines the `devices[]` list (nullptr =
    /// unconfined / global Read; present-EMPTY = deny-all rows), the SAME
    /// admit-then-filter shape as `app`/`overview` above (ADR-0031 WS-A4
    /// PR-1 decision 3 — closes the fleet-wide `devices[]` disclosure on
    /// REST `GET /api/v1/dex/signals/{obs_type}` + MCP `get_dex_signal_detail`,
    /// the two routes that previously called this method with no confinement
    /// at all while the dashboard's own `/fragments/dex/catalogue/signal`
    /// fragment already post-filtered its `devices[]` by the caller's
    /// visible set).
    ///
    /// `limit` is applied to the store read FIRST (top-N most-affected
    /// devices by event count), and `visible` filters THAT already-limited
    /// set — never the reverse. This matches the pre-existing dashboard
    /// fragment's own filter order (`dex_read_model.cpp`'s `app`/`overview`
    /// builders filter post-limit the same way) so a byte-identical rendered
    /// device list survives the rewire. The consequence: a confined caller
    /// may see FEWER than `limit` devices even when more of their own
    /// visible devices exhibit the signal — a device ranked outside the
    /// store's top-`limit` is never fetched at all, so it cannot be
    /// re-admitted by widening the visible set. Only `devices[]` is
    /// filtered; `subjects`/`by_os`/`by_day` stay fleet-wide aggregates with
    /// no per-agent identity (unchanged; whether THOSE aggregates should
    /// also floor/confine is a separate, undecided follow-up).
    [[nodiscard]] virtual DexSignalDetailModel
    signal_detail(const std::string& obs_type, const std::string& window,
                  const std::string& os_filter, int limit,
                  const std::set<std::string>* visible) const = 0;
};

} // namespace yuzu::server
