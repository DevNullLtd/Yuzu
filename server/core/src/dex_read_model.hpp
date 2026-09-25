#pragma once

/// @file dex_read_model.hpp
/// The PURE half of the DEX read-model layer: the model structs shared by REST,
/// MCP and the dashboard fragments, plus the model-only JSON serializers
/// (`dex_*_json`) that take one of those structs. **This header names NO store
/// type** — no `GuaranteedStateStore`, no `AppPerfDailyRow`, no store header,
/// no `<httplib.h>`, no `mcp_jsonrpc.hpp` — so it can sit behind the ABSTRACT
/// `dex_api.hpp` seam with a genuinely store-type-free include closure, exactly
/// like the four sibling abstract headers (ADR-0031 WS-A4; the store-type-free
/// property is enforced by check-seam-closure.py's abstract-header probe).
///
/// The store-reaching `build_dex_*_model(GuaranteedStateStore*, …)` builders
/// were SPLIT OUT into the core-only `dex_read_builders.hpp` (FortitudeEtc
/// review on PR #4582): before the split this header bundled them WITH the
/// pure structs, so `dex_api.hpp` transitively named `GuaranteedStateStore`
/// and was NOT store-type-free like its siblings. `dex_device_app_perf_json`
/// (the per-device app-perf drill serializer, which names the
/// `AppPerfDailyRow` store-row type) briefly lived in `dex_read_builders.hpp`
/// too, but has since been absorbed into the DexPerfApi seam's own
/// `dex_app_perf_builders.hpp` (ADR-0031 WS-A4, the sixth family) — its real
/// home, since it belongs to the app-perf-over-time surface, not DEX signals.
///
/// `DexFleet`/`DexSignalGroup` and the DEX leaf value types (DexSignalCount,
/// DexEntitySummary, GuardianObservationRow, …) live in the pure `dex_types.hpp`
/// (included below). Rule 1 (`docs/api-twin-recipe.md` §1): REST/MCP/the HTML
/// fragment serialize from ONE function so their shapes cannot drift.

#include "dex_types.hpp" // ADR-0031 WS-A4: DEX leaf value types + DexFleet/DexSignalGroup (pure)

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

// ── MCP-only gap #1: per-device DEX score (/fragments/device/dex, GET /api/v1/dex/devices/{id}) ──

/// The per-device DEX read model: the experience score (-1 = unavailable, no
/// store) + this device's own signal summary. Mirrors the REST handler's
/// existing shape (`rest_api_v1.cpp`'s `GET /dex/devices/{id}`) exactly — this
/// struct is what that handler now builds and what the MCP twin reuses.
struct DexDeviceScoreModel {
    std::string agent_id;
    std::string window; ///< echoes the validated "24h"|"7d"|"30d"|"all" token
    int score{-1};
    std::vector<DexSignalCount> signals;
    /// #4855: true when the underlying signal-summary read DEGRADED (store
    /// closed / pool-acquire timeout / query error) rather than genuinely
    /// finding no signals — `score` stays -1 and `signals` stays empty in
    /// this case too, but a caller MUST check this field first: a degraded
    /// model must never be served/rendered as a healthy "no data" result.
    /// Deliberately NOT serialized by `dex_device_score_json` (see its own
    /// comment) — callers translate it into their own surface's degrade
    /// response (lens placeholder / REST 503 / MCP retryable error) BEFORE
    /// ever reaching the serializer.
    bool degraded{false};
};

/// (`build_dex_device_score_model` — the store-reaching builder — is declared in
/// `dex_read_builders.hpp`.)
///
/// Shared JSON serializer — REST (`rest_api_v1.cpp`) and MCP (`mcp_server.cpp`)
/// both call this so the two response shapes cannot drift (Rule 1). Returns a
/// JSON OBJECT body (`{"agent_id":...,"window":...,"score":...,"signals":[...]}`)
/// — callers wrap it in their own envelope (`ok_json`/`tool_result`).
/// `audit_persisted` is the MCP-only evidence-gap signal (§4 of the recipe:
/// MCP has no `Sec-Audit-Failed` header channel, so a dropped audit row is
/// surfaced in the body instead) — REST never passes `false` here since it
/// fails closed (503) before reaching this call at all; the field is omitted
/// entirely when `true` (default), matching `get_dex_signal_detail`'s
/// established shape ("absent on success — consumers key on absence").
///
/// #4855 guard: `model.degraded` is NEVER a JSON key here (a degraded read
/// has no honest wire shape to serve — every caller must translate it into
/// its own surface's degrade response before ever calling this). Debug-mode
/// asserts a caller never reaches this serializer with a degraded model;
/// release builds fall through to the plain score/signals fields (which are
/// already -1/empty on a degraded model, so the worst a release build can
/// do is the pre-#4855 "unavailable" shape — never a fabricated 100).
std::string dex_device_score_json(const DexDeviceScoreModel& model, bool audit_persisted = true);

// (MCP-only gap #2: the per-device app-perf drill serializer
// `dex_device_app_perf_json` names the `AppPerfDailyRow` store-row type, so it
// lives in `dex_app_perf_builders.hpp` (the DexPerfApi seam, ADR-0031 WS-A4
// sixth family), not here — keeping this header store-type-free.)

// ── New twin #1: app blast-radius (/fragments/dex/app, GET /api/v1/dex/app?name=) ──

/// The per-app drill-down read model: crash/hang summary + faulting modules +
/// exception codes + the affected-device list. Mirrors
/// `render_dex_app_fragment`'s data exactly (Rule 1 refactor target).
struct DexAppModel {
    std::string process_name;
    std::string window;
    DexEntitySummary summary; ///< crashes/hangs/signals/distinct_devices/first_seen/last_seen
    std::vector<DexModuleCrashCount> modules;
    std::vector<DexExceptionCount> exceptions;
    /// Affected devices, ALREADY confined to `visible` when non-null (an
    /// out-of-scope device's id is never present — not merely filtered client
    /// side) — same admit-then-filter posture as the fragment's own loop.
    std::vector<DexDeviceCrashCount> devices;
};

/// Shared JSON serializer (Rule 1). `audit_persisted` per `dex_device_score_json`'s contract.
/// (`build_dex_app_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_app_json(const DexAppModel& model, bool audit_persisted = true);

// ── New twin #2: app-centric stability list (/fragments/dex/apps, GET /api/v1/dex/apps) ──

/// The whole-fleet apps-by-reliability list — no per-agent identity (a
/// distinct-device COUNT per app, never an agent_id), so this capability
/// carries no confinement and no audit, matching the fragment's own posture.
struct DexAppsModel {
    std::string window;
    std::vector<DexAppCrashCount> apps; ///< top 100 by the store's own ranking
};

std::string dex_apps_json(const DexAppsModel& model);

// ── New twin #3: catalogue-group / signal family (/fragments/dex/catalogue/group, GET /api/v1/dex/catalogue/group) ──

/// One catalogued type's row in a family drill-down.
struct DexCatalogueGroupTypeRow {
    std::string obs_type;
    bool monitored{false}; ///< a connected, in-scope platform collects this type
    std::string coverage_platforms; ///< comma-joined, e.g. "linux, windows"; "" when not monitored
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};

/// The family drill-down read model — mirrors `render_dex_catalogue_group_fragment`.
/// No per-agent identity, so no confinement/audit (aggregate exemption, same as
/// the fragment's own posture — it uses the plain global `perm_fn_`, not
/// `deny_service_scoped_`).
struct DexCatalogueGroupModel {
    std::string group_name;
    std::string os;     ///< resolved scope token: "all"|"windows"|"linux"|"macos"
    std::string window;
    int monitored_count{0};
    int total_type_count{0};
    double health_score{-1.0}; ///< -1 = suppressed (nothing monitored, or the scoped denominator is 0)
    int64_t active_events{0};
    int64_t max_signal_devices{0}; ///< largest single signal's distinct-device count (#1374, not the union)
    std::vector<DexCatalogueGroupTypeRow> types;
};

/// (`build_dex_catalogue_group_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_catalogue_group_json(const DexCatalogueGroupModel& model);

// ── New twin #4: per-device signal history (/fragments/dex/device, GET /api/v1/dex/devices/{id}/history) ──

/// One row of a device's raw signal history. Deliberately RAW facts (no
/// pre-formatted "what happened" display string, which is HTML-fragment-only
/// presentation logic per `history_detail()` in `dex_routes.cpp`'s anonymous
/// namespace) — a machine caller derives its own summary from `subject`/
/// `reason`/`symbolic`/`metric` rather than parsing a formatted string.
struct DexDeviceHistoryRow {
    std::string event_id;
    std::string observed_at;
    std::string obs_type;
    std::string subject;
    std::string reason;
    std::string symbolic;
    std::string component;
    double metric{0.0};
};

/// Behavioral PII — every call is audit-logged (dex.device.view), same verb
/// as the score-only capability (#4035 AC: this is a deliberate verb reuse —
/// the fragment at `dex_routes.cpp:2878` already audits its OWN distinct
/// signal-history capability under this exact verb, so REST/MCP match their
/// own fragment's ground truth rather than inventing a second verb).
struct DexDeviceHistoryModel {
    std::string agent_id;
    std::string window;
    DexEntitySummary summary;
    std::vector<DexDeviceHistoryRow> history; ///< up to 100, newest first
};

/// (`build_dex_device_history_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_device_history_json(const DexDeviceHistoryModel& model,
                                    bool audit_persisted = true);

// ── New twin #5: single-observation detail (/fragments/dex/observation, GET /api/v1/dex/devices/{id}/observations?event_id=) ──

// (`build_dex_observation_model` — the store-reaching lookup — is in `dex_read_builders.hpp`.)
/// Shared JSON serializer for one observation — every captured projection
/// field, same fields `render_dex_observation_fragment` lays out.
std::string dex_observation_json(const GuardianObservationRow& obs, bool audit_persisted = true);

// ── New twin #6: health score (/fragments/dex/health, GET /api/v1/dex/health) ──

struct DexHealthDeduction {
    std::string name;
    std::string severity; ///< "high"|"med"|"low"
    double deduction{0.0};
};

/// The composite-health read model — no per-agent identity (a fleet-wide
/// composite score), so no confinement/audit, matching the fragment's own
/// posture.
struct DexHealthModel {
    std::string weighting; ///< resolved preset: default|stability|productivity|security
    std::string window;
    int64_t reporting{0};      ///< N = fleet.windows_online (the scoring denominator)
    double crash_free_pct{-1.0}; ///< -1 when reporting == 0 (no fabricated number)
    int64_t total_crashes{0};
    double score{-1.0};   ///< -1 = suppressed (reporting == 0)
    std::string band;     ///< "excellent"|"good"|"fair"|"poor"; "" when suppressed
    std::vector<DexHealthDeduction> deductions; ///< catalogue order (not sorted by size)
};

/// (`build_dex_health_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_health_json(const DexHealthModel& model);

// ── New twin #7: trends (/fragments/dex/trends, GET /api/v1/dex/trends) ──

struct DexTrendsOsCard {
    std::string platform; ///< "windows"|"macos"|"linux"
    bool live{false};     ///< a collector has reported anything in-window (or Windows always-live)
    int64_t distinct_types{0};
    int64_t total_events{0};
};

/// One signal family's per-day event counts, aligned index-for-index with the
/// model's own `days` list.
struct DexTrendsFamily {
    std::string name;
    std::vector<int64_t> counts;
    int64_t total{0};
};

/// The cross-OS + per-family trends read model — no per-agent identity, so no
/// confinement/audit, matching the fragment's own posture.
struct DexTrendsModel {
    std::string window;
    int64_t total_catalogued_types{0};
    double crash_free_pct{-1.0}; ///< Windows-only; -1 when fleet.windows_online == 0
    int64_t windows_reporting{0};
    std::vector<DexTrendsOsCard> os_cards; ///< windows, macos, linux (fixed order)
    std::vector<std::string> days;         ///< YYYY-MM-DD, ascending, from the day matrix
    std::vector<DexTrendsFamily> families; ///< dex_signal_groups() order
};

/// (`build_dex_trends_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_trends_json(const DexTrendsModel& model);

// ── New twin #8: overview (/fragments/dex/overview, GET /api/v1/dex/overview) ──

struct DexOverviewSegment {
    std::string os;
    int devices{0};
    int avg_experience{-1}; ///< -1 when the segment has no scoreable device
};
struct DexOverviewOsRow {
    std::string platform;
    int64_t reporting{0};       ///< Windows-only today; 0 elsewhere
    double crash_free_pct{-1.0}; ///< Windows-only; -1 elsewhere / no reporting agents
    int64_t distinct_types{0};
    int64_t total_events{0};
};
struct DexOverviewDayCrash {
    std::string day;
    int64_t crashes{0};
};

/// The fleet-overview read model — the `/dex` landing page's fleet summary.
/// `top_devices` is ALREADY confined to `visible` when non-null (an
/// out-of-scope device's id is never present), same admit-then-filter
/// posture as the fragment's own loop; every other field is a fleet
/// aggregate carrying no per-agent identity.
struct DexOverviewModel {
    std::string window;
    // Experience (per-device score distribution + Device/App/Network composite).
    int overall_experience{-1}; ///< median of scoreable connected devices; -1 = none
    int device_score{-1}, app_score{-1}, network_score{-1};
    int great{0}, fair{0}, poor{0}; ///< per-device experience bucket counts
    /// #4855: connected devices whose per-device score came back -1 — either
    /// no store, or (the case this counter exists for) a degraded read on
    /// that specific device. Counted so a fleet-wide read hiccup surfaces as
    /// "N device(s) could not be scored" instead of silently thinning the
    /// `great`/`fair`/`poor`/median population, which would read as a
    /// healthier fleet than is actually known.
    int unscored{0};
    int64_t coverage_monitored{0}, coverage_total{0};
    std::vector<DexOverviewSegment> segments; ///< by normalised OS
    // Reliability -- measured.
    double crash_free_pct{-1.0}; ///< -1 when windows_reporting == 0
    int64_t windows_reporting{0};
    double crashes_per_1k_device_days{-1.0}; ///< -1 when undefined (no window or no reporting agents)
    int64_t total_crashes{0};
    int64_t devices_impacted{0};
    int64_t total_online{0};
    // Explore teaser figures.
    int64_t active_signal_types{0};
    double health_score{-1.0};
    int64_t os_reporting_count{0};
    // Crashes per day + top lists.
    std::vector<DexOverviewDayCrash> crashes_by_day;
    std::vector<DexAppCrashCount> top_apps;
    std::vector<DexDeviceCrashCount> top_devices; ///< confined, see struct doc
    std::vector<DexOverviewOsRow> os_table;
};

/// (`build_dex_overview_model` — the store-reaching builder — is in `dex_read_builders.hpp`.)
std::string dex_overview_json(const DexOverviewModel& model, bool audit_persisted = true);

} // namespace yuzu::server
