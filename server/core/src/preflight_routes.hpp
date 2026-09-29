#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file preflight_routes.hpp
/// The `/auto` PRE-FLIGHT page: a config section (per-check parameters +
/// thresholds) → run across a cohort → a go/no-go result GROUPED BY DEVICE
/// (Pass / Failed / Warn-only / Incomplete, with summary pills + "Failed by"
/// chips). Interim manual surface for the agentic upgrade-lifecycle; the
/// orchestrator drives the same checks + thresholds headless later. Reached at
/// /auto by URL — deliberately NOT a nav tab yet.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx CORE attrs only (the
/// dashboard CSP blocks hx-on / unsafe-eval). Reuses the shared full-page shell
/// (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS.
///
/// Live checks: app(version min/max) / os_version / arch / free-disk / reboot.
/// Runs are PERSISTED (PreflightRunStore) + revisitable from a saved-runs rail; a
/// background runner re-dispatches to reconnecting stragglers until the window
/// closes. Staged-artifact checks (installer integrity / rollback / config backup)
/// arrive in a later slice. Thresholds → verdict are applied server-side
/// (preflight_parse.hpp) — the SAME pure compute_device_results path for the live
/// render and the runner's persist.
///
/// AUTH / scope (IDOR-safe by construction):
///   * `/auto` shell is auth-only chrome; the config/result fragments gate on
///     global Infrastructure:Read.
///   * RUN gates on Infrastructure:Read + Execution:Execute. The cohort is FROZEN
///     at creation = `devices_fn(username) ∩ group members ∩ os filter`
///     (operator-visible set), so dispatch only reaches in-scope devices.
///   * RESULT poll / revisit reads the FROZEN cohort (NOT re-resolved) via
///     `get_run(run_id, viewer)` — OWNER-SCOPED at the store seam, so another
///     operator's run is indistinguishable from not-found (no existence oracle).
///     An offline frozen target stays "incomplete", never drops from the
///     denominator. DELETE is owner-scoped at the seam + gates Execution:Execute.
/// Machine-health facts (OS/arch/reboot/disk/app-version), NOT behavioural PII →
/// the dispatch audit (`preflight.run` / `preflight.run.delete`) is set-and-proceed.

#include <yuzu/server/auth.hpp>

#include "device_routes.hpp"   // DeviceRow
#include "dex_routes.hpp"      // DexRoutes::AuditFn
#include "preflight_parse.hpp" // Verdict, Bucket, PreflightCheckResponses, PreflightDeviceResult

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

// PreflightTarget / PreflightDeviceCheck / PreflightDeviceResult now live in the
// pure layer (preflight_parse.hpp, namespace `preflight`) so routes, the runner,
// and the store share ONE verdict model.

/// PURE: the config section (scope + per-check params/thresholds + Run) and an
/// empty results container. `groups` = (id, name) for the scope dropdown.
/// `recent` = (run_id, label) of the viewer's recent runs for the saved-runs rail.
std::string render_auto_config(const std::vector<std::pair<std::string, std::string>>& groups,
                               const std::vector<std::pair<std::string, std::string>>& recent);

/// PURE: the saved-runs rail as its own swap target (#auto-rail) — a clickable
/// button per run + a confirm-guarded delete (hx-confirm, CSP-safe). The delete
/// route re-renders this standalone after removing a run. `recent` = (run_id,
/// label) of the viewer's own runs.
std::string render_auto_rail(const std::vector<std::pair<std::string, std::string>>& recent);

/// PURE: the result GROUPED BY DEVICE (Pass / Failed / Warn-only / Incomplete),
/// with bucket + failure-type client-side filters (CSP-safe inline JS). Summary
/// pills + "Failed by" chip counts are derived here from `devices`.
/// `config_summary` is the one-line threshold recap; `repoll_url` non-empty → the
/// wrapper self-polls. When `repoll_url` is empty: `run_complete` true → "Complete",
/// false → "still running in the background" (page-poll capped; the run continues
/// server-side, reopen from the rail to refresh). `degrade_note` (#2691 finding 10)
/// non-empty → an honest banner that `devices` is the last known-good state, not a
/// fresh read — the poll degraded and is retrying, not "these devices are done."
std::string render_auto_results(const std::vector<preflight::PreflightDeviceResult>& devices,
                                const std::string& config_summary, const std::string& scope_label,
                                const std::string& repoll_url, bool run_complete,
                                const std::string& run_id, const std::string& degrade_note = {});

/// PURE: an honest note body (no devices in scope, missing seam, etc.).
std::string render_auto_note(const std::string& message);

class PreflightRunStore; // server/core/src/preflight_run_store.hpp
struct PreflightRunRow;  //   "
class HttpRouteSink;     // server/core/src/http_route_sink.hpp

/// PURE: one saved run as a JSON object — the REST (`GET
/// /api/v1/preflight/runs`) + MCP (`list_preflight_runs`) twin of the
/// saved-runs-rail data. Structured fields, not `render_auto_rail`'s
/// flattened display label — an API caller wants `go`/`warn`/`nogo`/
/// `incomplete` as counts, not a pre-formatted string. No httplib.h; both
/// surfaces call this SAME function so the JSON shape cannot drift between
/// them (api-twin-recipe.md Rule 1).
nlohmann::json preflight_run_row_json(const PreflightRunRow& r);

/// `/auto` routes — page shell + config/rail fragment + run creation + result
/// poll. Runs persist (PreflightRunStore); a running run renders live, a complete
/// run renders the stored grid; reads are owner-scoped (created_by).
class PreflightRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;
    using GroupsFn = std::function<std::vector<std::pair<std::string, std::string>>()>;
    using GroupMembersFn = std::function<std::vector<std::string>(const std::string& group_id)>;
    /// 6-param shared command_dispatch_fn — execution_id carried so responses
    /// correlate via query_by_execution (the runner reuses the SAME ids).
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;
    /// Collect each applicable check's per-agent best response for a run (wraps
    /// preflight::collect_check_responses over the ResponseStore). Used for the
    /// LIVE render of a running run.
    using CollectFn = std::function<std::vector<preflight::PreflightCheckResponses>(
        const std::string& run_id,
        const std::vector<std::pair<std::string, std::string>>& applicable)>;
    using AuditFn = DexRoutes::AuditFn;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         GroupsFn groups_fn, GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                         CollectFn collect_fn, AuditFn audit_fn, PreflightRunStore* run_store);

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         GroupsFn groups_fn, GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                         CollectFn collect_fn, AuditFn audit_fn, PreflightRunStore* run_store);

private:
    /// Deny a service-scoped API token on an `/auto` Pre-flight surface that
    /// scopes by `session->username` alone (the run rail, result poll, and
    /// delete) — SEC-2/SEC-3 confinement-gap class: `ApiToken::principal_id`
    /// ("username... who created it") means a service-scoped token shares its
    /// creating human's username, so username-only owner-scoping does not
    /// confine it to its OWN service the way `token_scope_service` requires.
    /// A token scoped to e.g. "printers" would otherwise read/delete/enumerate
    /// a fleet-wide run its own principal created interactively. Writes the
    /// 403 FIRST, audits after via the shared try_persist_audit kernel, under
    /// `action` (gov Gate 6 enterprise-readiness: the delete route's denial
    /// must land under its own `preflight.run.delete` verb, not the generic
    /// `preflight.run` — a SIEM rule keyed on the delete verb would otherwise
    /// see zero denials while they were actually occurring). Returns true iff
    /// denied (caller returns immediately).
    [[nodiscard]] bool deny_service_scoped_(const httplib::Request& req, httplib::Response& res,
                                            const std::string& action,
                                            const std::string& audit_detail,
                                            // `permission` defaults EMPTY (#3167
                                            // — gov-fix, Gate 8, #2298 PR 3
                                            // hardening round's clause):
                                            // kServiceScopeGlobalSafe is
                                            // compile-time-empty, so no grant
                                            // admits a service-scoped caller on
                                            // this surface — naming one is a
                                            // false self-remediation claim the
                                            // routed-concern MUST clause
                                            // forbids. Do not reintroduce one.
                                            const std::string& permission = "") const;

    AuthFn auth_fn_;
    PermFn perm_fn_;
    DevicesFn devices_fn_;
    GroupsFn groups_fn_;
    GroupMembersFn group_members_fn_;
    DispatchFn dispatch_fn_;
    CollectFn collect_fn_;
    AuditFn audit_fn_;
    PreflightRunStore* run_store_{nullptr};

    /// Render a run's result block: RUNNING → live (collect + compute), COMPLETE
    /// → stored grid. Self-repolls while running + pending + under the poll cap.
    std::string render_run(const PreflightRunRow& run, int attempt);

    // Unit-test seam (#2691 finding 10): render_run and its inputs (run_store_,
    // collect_fn_) are private, and the degraded-read fallback this fix added
    // had no test at this layer. Test-only; grants no runtime surface. See
    // tests/unit/server/test_preflight_routes.cpp.
    friend struct PreflightRoutesTestAccess;
};

} // namespace yuzu::server
