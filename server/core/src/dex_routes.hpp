#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type
#include "dex_view_types.hpp" // ADR-0031 WS-A4 prep: DexAgentResponse + DexDispatchFn/DexResponsesFn/
                              // DexAuditFn + dex_iso_since/dex_signal_label -- hoisted store-free so a
                              // family (e.g. device) can use these without the whole DEX surface

/// @file dex_routes.hpp
/// DEX (Digital Employee Experience) dashboard — the RELIABILITY lens over the
/// 110-signal catalogue (crashes, hangs, service failures, device stability,
/// boot/resume performance, network/identity/security/update/print signals;
/// docs/dex-signal-catalog.md).
/// A capability-limited READ MODEL over the one Guardian event store
/// (guardian_observations projection): it reinterprets ruleless observations as
/// fleet reliability. Separate from /guardian (which authors + enforces); this
/// surface is read-only. The headline rate stays the industry-standard
/// crash-free-devices number; other signals get their own panels.
///
/// Product UI: HTMX, server-rendered, dark-theme only. Reuses the shared
/// full-page shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*`
/// component CSS — same chrome as the Guardian detail pages.
///
/// NO MOCK DATA (Dave, 2026-06-09): every panel renders real aggregations from
/// GuaranteedStateStore or an explicit "no data" placeholder — never fabricated
/// or sample values. The crash-free-% / per-1k-device-days RATES (which need the
/// cross-store fleet-size denominator from the agent registry) are a follow-up
/// increment; this overview ships the absolute, store-backed facts.

#include <yuzu/server/auth.hpp>

#include "authz_gates.hpp" // authz::FleetReadGate -- the version-devices fragment's gate
#include "dex_app_perf_ui.hpp" // DexGroupOption + the app-perf render decls
#include "dex_perf_api.hpp" // ADR-0031 WS-A4 (sixth family): the public in-process DEX app-perf-over-time API seam (#4626)
#include "dex_perf_model.hpp"
#include "dex_types.hpp" // ADR-0031 WS-A4: DexFleet/DexSignalGroup + DEX leaf value types (pure)
#include "dex_window.hpp" // ADR-0031 WS-A4: dex_window_to_days/dex_iso_since/dex_normalize_os_filter (pure)
#include "dex_read_builders.hpp" // PR #4582 FIX 4: re-export dex_device_score (relocated here) to this header's callers

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class GuaranteedStateStore;
class HttpRouteSink;

// `DexFleet`/`DexSignalGroup` and the signal-catalogue accessors
// (`dex_signal_groups` / `dex_catalogued_type_count` / `dex_family_index`) were
// relocated to the pure `dex_types.hpp` (included above) for the ADR-0031 WS-A4
// DexApi seam (PR #4582 FIX 4) — re-exported here transitively, so every
// existing caller is unaffected while dex_read_model.cpp can call them without
// this httplib-coupled header.

/// Friendly display label for an obs_type — hoisted to `dex_view_types.hpp`
/// (store-free; see that header for the doc comment).

// `dex_window_to_days` / `dex_iso_since` / `dex_normalize_os_filter` — the shared
// window-selector + OS-filter resolvers — are now declared in the pure
// `dex_window.hpp` (included above), so the core `DexApi` impl can resolve a
// window/os token without pulling this httplib-coupled header. Re-exported here
// transitively; every existing caller is unaffected.

/// Render the DEX overview fragment (the content hx-get'd into the page shell):
/// headline rate + coverage + crash facts + top apps / modules / devices + per-OS
/// + trend, all from the crash projection. `since` is an ISO-8601 cutoff
/// ('' = all retained); `window_days` is the window length used for the
/// per-1k-device-days denominator (0 = "all", which suppresses that rate as
/// ill-defined). `fleet` supplies the cross-store denominator. `store` may be null
/// (renders the no-data placeholder). Pure + free so it is unit-testable directly.
std::string render_dex_overview_fragment(const GuaranteedStateStore* store,
                                         const std::string& since, int window_days, DexFleet fleet,
                                         const std::set<std::string>* visible = nullptr);

// The PURE catalogue/health helpers `dex_obs_platforms`, `dex_family_rollup`
// (+ `DexFamilyRollup`), `dex_family_health_deduction`, and `dex_compute_health`
// (+ `DexHealthResult`) — plus the store-reaching `dex_device_score` — were
// relocated (PR #4582 FIX 4): the pure ones to `dex_types.hpp`, `dex_device_score`
// to the core-only `dex_read_builders.hpp` (both included above), so
// dex_read_model.cpp can call them without this httplib-coupled header. They are
// re-exported here transitively, so this header's existing callers are
// unaffected; the definitions are unchanged in their .cpp.

/// Catalogue View 1 — the 13 family cards (mockup dex-catalogue-coverage.html).
/// COVERAGE-first: a family lights when a CONNECTED platform (scoped by `os_filter`:
/// "all"|"windows"|"linux"|"macos") collects one of its types — not merely when a
/// signal fired. Each card carries a roll-up health score (100 − the family's
/// dex_compute_health deduction). `fleet.connected_os` is the "all" scope. Pure + free.
std::string render_dex_catalogue_fragment(const GuaranteedStateStore* store,
                                          const std::string& since, int window_days,
                                          const DexFleet& fleet, const std::string& os_filter);

/// Catalogue View 2 — one family's signals. COVERAGE-first, like the grid: every
/// catalogued type is shown, marked MONITORED (a connected platform in scope
/// collects it — lit even at zero events) or NOT COLLECTED (no platform in view
/// emits it — dimmed, never read as "healthy"). `group_name` is allowlisted
/// against dex_signal_groups(); `fleet.connected_os` is the "all" coverage scope;
/// `os_filter` ("all"|"windows"|"linux"|"macos") is the OS lens — shown as in-view
/// chips so it both persists across the drill AND is changeable in place.
std::string render_dex_catalogue_group_fragment(const GuaranteedStateStore* store,
                                                const std::string& since, int window_days,
                                                const std::string& group_name,
                                                const DexFleet& fleet,
                                                const std::string& os_filter = "all");

/// Catalogue View 3 — one signal type's drill-down (subjects, OS split, devices,
/// trend), over the generic per-obs_type read-model. `obs_type` is SQL-bound +
/// HTML-escaped; cross-OS captions are derived live (no stale coverage counts).
/// `os_filter` is carried only to restore the family grid's OS lens on the back-link.
std::string render_dex_catalogue_signal_fragment(const GuaranteedStateStore* store,
                                                 const std::string& since, int window_days,
                                                 const std::string& obs_type,
                                                 const std::string& os_filter = "all",
                                                 const std::set<std::string>* visible = nullptr);

/// Health score — the derived/SECONDARY composite (score = 100 − Σ weighted
/// per-family deductions; every deduction traces to a measured rate). `weighting`
/// is one of the allowlisted presets (default/stability/productivity/security);
/// `fleet` supplies the reporting-agent denominator (score suppressed when 0).
std::string render_dex_health_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet,
                                       const std::string& weighting);

/// Trends — cross-OS comparison (scope derived live from dex_os_signal_scope) +
/// per-family small-multiples + a family×day activity heatmap (within-row scaled).
std::string render_dex_trends_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet);

/// Per-app drill-down fragment for `process_name` — crash + hang blast radius
/// (devices) + faulting modules + exception codes + affected devices. `window`
/// is the selector TOKEN ("24h"/"7d"/"30d"/"all"; default-resolved like the
/// overview) so the drill-down is scoped to the SAME window as the row that
/// linked here — counts match (governance C-S1/UP-11). Pure + free so it is
/// unit-testable directly against a seeded store.
std::string render_dex_app_fragment(const GuaranteedStateStore* store,
                                    const std::string& process_name, const std::string& window,
                                    const std::set<std::string>* visible = nullptr);

/// Per-device drill-down fragment for `agent_id` — the unified multi-signal
/// history (closes the deferred UP-4: friendly labelled rows, not raw
/// __observation__ events). This is behavioral PII (which apps a person runs);
/// the route gates it on Read and audit-logs each open. `window` is the selector
/// TOKEN (window-scoped to match the linking overview row). Pure + free so it is
/// unit-testable directly. `perf_snap` (PR2, may be null) feeds the vs-fleet/
/// cohort percentile strips; null omits the strips section (feature unwired).
std::string render_dex_device_fragment(const GuaranteedStateStore* store,
                                       const std::string& agent_id, const std::string& window,
                                       const DexPerfSnapshot* perf_snap = nullptr);

/// Single-observation detail panel — the device-history row click target. Lays
/// out every captured projection field (subject / code / symbolic / component /
/// metric / device / platform / exact timestamp / event id) for one event. Pure
/// + free so it is unit-testable directly against a `GuardianObservationRow`.
/// (This is the panel Option-D enrichment later extends with `extra{}` fields.)
std::string render_dex_observation_fragment(const GuardianObservationRow& obs);

/// Applications list — the dedicated app-centric DEX lens (a new top-level
/// subnav tab). Ranks apps by reliability signals (crashes + hangs) keyed on the
/// process image, each row drilling to the per-app blast-radius view. `since` is
/// the ISO cutoff; `window_days` drives the chips + drill links. Pure + free so
/// it is unit-testable directly against a seeded store. (Per-app performance,
/// version, and non-crash signal attribution are follow-on slices.)
std::string render_dex_apps_fragment(const GuaranteedStateStore* store, const std::string& since,
                                     int window_days);

// ── A4: device perf sparklines (federated TAR query) ────────────────────────

/// `DexAgentResponse` — hoisted to `dex_view_types.hpp` (store-free; see that
/// header for the doc comment).

/// One parsed hourly perf point out of the device's TAR edge warehouse
/// (`$Perf_Hourly` — see agents/plugins/tar perf tier, BRD A1).
struct DexPerfPoint {
    std::int64_t hour_ts{0};
    double cpu_avg{0.0};      ///< % busy, clamped 0..100
    double mem_avg{0.0};      ///< % physical used, clamped 0..100
    double disk_lat_ms{0.0};  ///< worse of read/write avg per-IO service time
};

/// PURE: parse the `tar.sql` pipe-delimited output (`__schema__|col|…` header +
/// data rows) into perf points, chronologically sorted. Defensive against
/// agent-controlled bytes: columns are located by NAME from the schema line,
/// non-finite/negative numbers are rejected per-field, malformed rows are
/// skipped, and at most 200 rows are read. Returns empty on an `error|…`
/// payload or a missing schema line.
std::vector<DexPerfPoint> parse_dex_perf_output(const std::string& output);

/// PURE: render the device-performance panel (per-metric sparkline SVG +
/// now/min/max facts) from parsed points. Empty input renders the honest
/// "no history" note. Server-rendered SVG — no JS, CSP-safe.
std::string render_dex_perf_panel(const std::vector<DexPerfPoint>& points);

// ── F2a PR2: device drill perf extensions ────────────────────────────────────

// `DexProcPerfRow` — relocated to the pure `dex_perf_model.hpp` (#4626 Concern
// B) so `dex_perf_ui.cpp` can include that header alone instead of this
// httplib-coupled one. Re-exported here transitively (dex_perf_model.hpp is
// already included above), so every existing caller of THIS header is
// unaffected.

/// PURE: parse the canned per-app `tar.sql` output (same defensive contract as
/// parse_dex_perf_output: columns by NAME from the `__schema__|…` line,
/// non-finite/negative rejected per-field, malformed rows skipped, ≤100 rows,
/// empty on `error|…`). cpu percentages clamp to 0..100 (a lie, not an
/// outlier); working-set bytes above 1 PiB are rejected as forged.
std::vector<DexProcPerfRow> parse_dex_procperf_output(const std::string& output);

/// PURE: render the per-application panel from parsed rows. App names link to
/// the existing app reliability drill (per-app perf ↔ per-app crashes cross-
/// link). Empty input renders the SOFT truthful empty state: the device's
/// read-only query surface deliberately hides plugin config, so the server
/// cannot distinguish "procperf disabled (the default)" from "enabled, no
/// rollup yet" — the message says both honestly (the crisp distinction needs
/// the tar-plugin source_state meta table, a filed follow-up).
std::string render_dex_procperf_panel(const std::vector<DexProcPerfRow>& rows,
                                      const std::string& window);

/// PURE: render the "this device vs fleet & cohort" percentile strips —
/// current heartbeat values against the CURRENT registry distributions
/// (now-vs-now; no retained history). Cohort comparison is withheld below the
/// kDexCohortFloor with an honest caption; a non-reporting device renders an
/// honest note, never empty bars.
std::string render_dex_device_perf_context(const DexPerfDeviceContext& ctx,
                                           const std::string& cohort_key,
                                           const std::string& window);

// ── F2a: fleet Performance tab (now-view over registry heartbeat state) ─────

/// PURE: the /fragments/dex/perf content — fleet-now cards (same stats as the
/// yuzu_fleet_perf_* gauges, via the shared dex_perf_rules) + the cohort
/// benchmarking tables for `snap.cohort_key`. Every aggregate is a drill: the
/// metric cards open the worst-devices list, the Reporting card opens the
/// not-reporting list, cohort rows open their device list. NO window chips —
/// the page is a now-view (trend charts are F2b, Postgres-gated).
std::string render_dex_perf_fragment(const DexPerfSnapshot& snap, int window_days);

/// F2c: the A-vs-B cohort comparison result (the table the two cohort pickers
/// on the Performance tab load into). Renders each metric's p50 for both
/// cohorts + the delta (A relative to B, B the baseline), honouring
/// found/suppressed; pure render over dex_perf_cohort_diff.
std::string render_dex_perf_cohort_diff_fragment(const DexPerfSnapshot& snap,
                                                 const std::string& cohort_a,
                                                 const std::string& cohort_b, int window_days);

/// PURE: the /fragments/dex/perf/devices drill — the ONE device list serving
/// every Performance-page drill (worst-by-metric / not-reporting / cohort
/// membership). Rows link to the per-device drill-down.
std::string render_dex_perf_devices_fragment(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                             bool not_reporting,
                                             const std::optional<std::string>& cohort_filter,
                                             int limit, int window_days,
                                             const std::set<std::string>* visible = nullptr);

/// DEX routes — /dex (page shell) + /fragments/dex/overview (HTMX fragment).
class DexRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate (wraps
    /// require_scoped_permission). Gates every PER-DEVICE drill (`/fragments/dex/device`
    /// + `/perf` + `/procperf`) so an operator can only open a device inside their
    /// management scope — the same gate the `/device` routes use. May be empty → the
    /// per-device routes fall back to the global `perm_fn` gate (legacy posture).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// Resolve the set of agent_ids VISIBLE to `username`, following the SAME policy
    /// as `/api/agents` (`get_visible_agents_json`): returns `std::nullopt` when the
    /// caller sees the whole fleet (global Infrastructure:Read OR RBAC disabled), else
    /// the set of agent_ids in the caller's management groups. Used to filter the
    /// device-id-rendering lists so an out-of-scope operator can't enumerate other
    /// teams' device ids. MUST replicate the global-read branch — a bare
    /// `get_visible_agents` would blank an admin who is in no management group. May be
    /// empty → no list filtering (legacy posture).
    using VisibleSetFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;

    /// Supplies the cross-store fleet denominator (avoids an AgentRegistry
    /// incomplete-type dep — same callback trick GuardianRoutes uses for agents
    /// JSON). May be empty → rates degrade to the "no data" state.
    using FleetFn = std::function<DexFleet()>;

    /// Audit hook — used to log per-device drill-down opens (behavioral PII).
    /// Hoisted to `dex_view_types.hpp` as `DexAuditFn` (store-free; see that
    /// header for the full doc comment) — aliased here so `DexRoutes::AuditFn`
    /// keeps resolving for every existing includer, with ONE definition.
    using AuditFn = DexAuditFn;

    /// A4: dispatch a plugin command to specific agents. Hoisted to
    /// `dex_view_types.hpp` as `DexDispatchFn` (store-free; see that header for
    /// the full doc comment) — aliased here so `DexRoutes::DispatchFn` keeps
    /// resolving for every existing includer, with ONE definition.
    using DispatchFn = DexDispatchFn;

    /// A4: read the stored responses for a command_id. Hoisted to
    /// `dex_view_types.hpp` as `DexResponsesFn` (store-free; see that header
    /// for the full doc comment, incl. the #1634 seam-scoping note) — aliased
    /// here so `DexRoutes::ResponsesFn` keeps resolving for every existing
    /// includer, with ONE definition.
    using ResponsesFn = DexResponsesFn;

    /// ADR-0031 WS-A4 (sixth family): the public in-process DEX app-perf-over-
    /// time API seam (`dex_perf_api.hpp`) — backs BOTH the F2a heartbeat-now
    /// fragments (`fleet_snapshot`) and the F2b over-time fragments (`apps`/
    /// `app_fleet_trend`/`app_version_devices`/`group_trend`/`tag_trend`/
    /// `device_app_perf_json`/`device_app_summaries`), replacing `PerfFn`/
    /// `AppPerfProviders` (#4626). `nullptr` (the default) degrades every
    /// consuming fragment to an honest "unavailable" placeholder — matching
    /// server.cpp's own posture of constructing `dex_perf_api` UNCONDITIONALLY
    /// and letting each method collapse a null/degraded backing store to
    /// `nullopt` individually (see `dex_perf_api.hpp`'s own doc comment).
    using DexPerfApiPtr = std::shared_ptr<const DexPerfApi>;

    /// F2b: the management groups offered in the app-perf scope selector (id +
    /// name + member count), sourced from ManagementGroupStore::list_groups. May
    /// be empty → the scope selector is omitted (whole-fleet only).
    using GroupListFn = std::function<std::vector<DexGroupOption>()>;

    /// The version-drill "which devices" fragment's SOLE authorization gate —
    /// the injected-callback twin of `AuthRoutes::require_fleet_read`
    /// (authz_gates.hpp), identical shape/contract to `RestApiV1::FleetReadFn` /
    /// `McpServer::FleetReadFn` (server.cpp wires the SAME conversion lambda into
    /// all three surfaces so they cannot drift). Deliberately NOT `perm_fn_` +
    /// `resolve_visible` (this file's pre-existing `VisibleSetFn`, username-keyed
    /// on `Infrastructure:Read`) — that pairing is the exact confinement gap this
    /// gate exists to avoid for a route whose rows carry `agent_id` (see the
    /// fragment's own registration comment). Trailing optional dep, appended
    /// after `group_list_fn` to keep every existing `register_routes` call site
    /// source-stable; `{}` (the default) makes the new fragment answer an honest
    /// "unavailable" placeholder rather than silently falling back to a weaker
    /// gate — an unwired gate is misconfiguration, never "no filter" (matches
    /// `RestApiV1`/`McpServer`'s own unwired contract for the identical seam,
    /// adapted to this dashboard surface's 200-not-503 fragment posture since
    /// htmx drops 4xx/5xx bodies).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// Register the DEX routes. The page shell is auth-only static chrome; the
    /// data-bearing fragments gate on GuaranteedState:Read (same securable as the
    /// Guardian read surface — a dedicated DEX:Read perm is deferred). `store` may
    /// be null (fragments render the no-data placeholder); `fleet_fn`/`audit_fn`/
    /// `dispatch_fn`/`responses_fn` may be empty (the device perf panel then
    /// degrades to an honest "unavailable" note).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         ScopedPermFn scoped_perm_fn = {},
                         VisibleSetFn visible_set_fn = {}, DexPerfApiPtr dex_perf_api = {},
                         GroupListFn group_list_fn = {}, FleetReadFn fleet_read_fn = {});

    /// HttpRouteSink overload — same registration against the polymorphic seam so
    /// the handlers are unit-testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         ScopedPermFn scoped_perm_fn = {},
                         VisibleSetFn visible_set_fn = {}, DexPerfApiPtr dex_perf_api = {},
                         GroupListFn group_list_fn = {}, FleetReadFn fleet_read_fn = {});

private:
    /// Deny a service-scoped API token on a fleet-wide fragment that names more
    /// than one agent_id — the SEC-2/SEC-3 confinement-gap class:
    /// `resolve_visible`'s VisibleSetFn is username-keyed and does not confine
    /// a service token whose principal resolves to an unscoped grant. Writes the
    /// 403 FIRST (mirrors GuardianRoutes::deny_service_scoped_ — a throwing
    /// audit_fn_ must not be able to suppress the 403), audits after via the
    /// shared try_persist_audit kernel. `target_type` defaults to
    /// "GuaranteedState" (every caller but the per-signal fragment, whose
    /// dex.signal.view contract — the REST/MCP twins, and audit-log.md — uses
    /// "ObsType"; gov Gate 4 consistency review: the denial row must match its
    /// own verb's established target_type, not silently diverge from it).
    /// Returns true iff denied (caller returns immediately); false means the
    /// caller should proceed to perm_fn_.
    [[nodiscard]] bool deny_service_scoped_(const httplib::Request& req, httplib::Response& res,
                                            const std::string& action,
                                            const std::string& audit_detail,
                                            const std::string& target_type = "GuaranteedState") const;

    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    VisibleSetFn visible_set_fn_;
    GuaranteedStateStore* store_{};
    FleetFn fleet_fn_;
    AuditFn audit_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    DexPerfApiPtr dex_perf_api_;
    GroupListFn group_list_fn_;
    FleetReadFn fleet_read_fn_;
};

} // namespace yuzu::server
