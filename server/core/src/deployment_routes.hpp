#pragma once

/// @file deployment_routes.hpp
/// The `/auto` DEPLOY stage — the ACT half that follows the pre-flight ASSESS
/// stage on the SAME page. As soon as a pre-flight run has a go-cohort (≥1 device
/// in bucket go/warn — the run need NOT be complete), "Deploy go-cohort" stages +
/// executes an installer on the cleared-so-far devices; a re-deploy of the same run
/// covers new/failed devices and skips already-installed ones. The cohort is only
/// ever fully-evaluated cleared devices (a still-evaluating device is incomplete,
/// never go/warn), so a mid-run deploy is safe. Fragments live under
/// `/fragments/auto/deploy*` so the whole lifecycle is one page; the deploy panel
/// swaps into a `#auto-deploy` container beside the pre-flight result.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx CORE attrs only (CSP
/// blocks hx-on). Reuses the shared full-page shell + `.gp-*` CSS.
///
/// AUTH / scope:
///   * config gates SoftwareDeployment:Read; the result poll gates
///     SoftwareDeployment:Read+Execute (it ADVANCES the mutating engine, not just
///     renders); run gates Infrastructure:Read+SoftwareDeployment:Execute; delete
///     gates SoftwareDeployment:Execute.
///   * Execute-once is per-deployment, so a create-time resume guard
///     (find_running_for_run + a partial unique index) re-attaches a duplicate
///     'Deploy' to the in-flight run instead of re-installing the cohort.
///   * The cohort is the SOURCE pre-flight run's go-cohort, read OWNER-SCOPED
///     (`PreflightRunStore::get_run(run, viewer)`), then re-intersected with
///     `devices_fn(viewer)` — so a deployment can only target devices the operator
///     both pre-flight-cleared AND currently sees.
///   * The execute step MUTATES, so the engine re-authorizes every advance
///     (`devices_fn(viewer) ∩ cohort`) and dispatches execute at most once per
///     device (claim-before-dispatch). A device out of scope is skipped, never run.
/// Machine-health / operational, not behavioural PII → set-and-proceed audit
/// (`deployment.create` / `deployment.advance` / `deployment.delete`).

#include <yuzu/server/auth.hpp>

#include "authz_model.hpp"           // authz::VisibleSet
#include "deployment_engine.hpp"     // deployment::PollFn / DispatchFn / EngineDeps
#include "deployment_run_store.hpp"  // DeploymentRow / DeploymentDeviceRow
#include "device_routes.hpp"         // DeviceRow
#include "dex_routes.hpp"            // DexRoutes::AuditFn

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

class PreflightRunStore;
class HttpRouteSink;

// ── PURE render functions (defined in deployment_ui.cpp) ─────────────────────

/// The deploy config panel for a source run: cohort recap + artifact fields
/// (url/filename/sha256/args) + a confirm-guarded "Stage + deploy" button + an
/// empty results container. `cohort` = the count of go+warn devices the run cleared.
std::string render_deploy_config(const std::string& run_id, const std::string& run_name,
                                 int go_count, int warn_count);

/// PURE: the deploy-config go/warn preview as a JSON object — the REST (`GET
/// /api/v1/deployments/preview`) + MCP (`get_deployment_preview`) twin of
/// `render_deploy_config`'s underlying data. No httplib.h; both surfaces call
/// this SAME function so the JSON shape cannot drift (api-twin-recipe.md
/// Rule 1).
nlohmann::json deploy_preview_json(const std::string& run_id, const std::string& run_name,
                                   int go_count, int warn_count);

/// The deployment progress, AGGREGATE-FIRST: a KPI strip (targeted / succeeded /
/// executing / in-flight / failed / skipped) + a progress bar, then the device
/// list grouped problem-first (Failed → Skipped → Executing → In-flight →
/// Succeeded; the Succeeded group folds to a count). Self-polls while in flight.
std::string render_deploy_results(const DeploymentRow& dep,
                                  const std::vector<DeploymentDeviceRow>& devices,
                                  const std::string& repoll_url);

/// An honest note body (no go-cohort, store unavailable, bad artifact, etc.).
std::string render_deploy_note(const std::string& message);

/// `/auto` deploy routes. Holds the engine deps (store + poll + dispatch) and the
/// source pre-flight store (to read the go-cohort at create).
class DeploymentRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;
    using DispatchFn = deployment::DispatchFn;
    using PollFn = deployment::PollFn;
    using AuditFn = DexRoutes::AuditFn;
    /// The caller's Execution:Execute visible set (#1788) — same seam every other
    /// operator-facing dispatch surface (RestApiV1/WorkflowRoutes/BundleOrchestrator/
    /// McpServer/DashboardRoutes) is wired with. See `caller_from_session`'s doc
    /// comment for why an unwired callback must fail closed here too.
    using ExecVisibleFn = std::function<yuzu::server::authz::VisibleSet(const auth::Session&)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         DispatchFn dispatch_fn, PollFn poll_fn, AuditFn audit_fn,
                         PreflightRunStore* preflight_store, DeploymentRunStore* deploy_store,
                         ExecVisibleFn exec_visible_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         DispatchFn dispatch_fn, PollFn poll_fn, AuditFn audit_fn,
                         PreflightRunStore* preflight_store, DeploymentRunStore* deploy_store);

private:
    /// Deny a service-scoped API token on a `/auto` Deploy surface that scopes
    /// by `session->username` alone (the config form, result poll, delete, and
    /// create) — SEC-2/SEC-3 confinement-gap class, same as PreflightRoutes'
    /// deny_service_scoped_: `ApiToken::principal_id` ("username... who
    /// created it") means a service-scoped token shares its creating human's
    /// username, so username-only owner-scoping does not confine it to its
    /// OWN service. The result-poll route additionally re-invokes the
    /// deployment engine's mutating advance() tick on every call (unlike a
    /// pure read) — denying it here narrows exposure (stops further devices
    /// being admitted to an in-flight deployment on later ticks); the create
    /// route (`POST /fragments/auto/deploy/run`) closes the fleet-wide
    /// creation gap directly (external review, PR #3156 — this call site was
    /// missing for a time after the other three landed). Writes the 403
    /// FIRST, audits after via the shared
    /// try_persist_audit kernel, under `action`. `target_type` defaults to
    /// "SoftwareDeployment" (the `.advance`/`.delete` verbs' own established
    /// success-path target_type per audit-log.md); the config-view call site
    /// passes "Scope" explicitly, matching its own documented shape — governance
    /// finding: this previously hardcoded "Scope" for all three call sites,
    /// silently diverging from `.advance`/`.delete`'s documented contract, the
    /// same class DexRoutes::deny_service_scoped_ already parametrizes for.
    /// Returns true iff denied (caller returns immediately).
    [[nodiscard]] bool deny_service_scoped_(const httplib::Request& req, httplib::Response& res,
                                            const std::string& action,
                                            const std::string& audit_detail,
                                            const std::string& target_type =
                                                "SoftwareDeployment",
                                            // `permission` defaults EMPTY
                                            // (gov-fix, Gate 8, #2298 PR 3
                                            // hardening round):
                                            // kServiceScopeGlobalSafe is
                                            // compile-time-empty, so no grant
                                            // admits a service-scoped caller
                                            // on this surface — a non-empty
                                            // default was the same false
                                            // self-remediation claim the
                                            // routed-concern MUST clause
                                            // forbids. Do not reintroduce one.
                                            const std::string& permission = "") const;

    AuthFn auth_fn_;
    PermFn perm_fn_;
    DevicesFn devices_fn_;
    AuditFn audit_fn_;
    ExecVisibleFn exec_visible_fn_;
    PreflightRunStore* preflight_store_{nullptr};
    DeploymentRunStore* deploy_store_{nullptr};
    deployment::EngineDeps engine_;

    /// The live session's dispatch identity — never `.system = true`: every
    /// deployment advance here is operator-triggered, so the chokepoint must
    /// authorize it against that operator's own grants, not admit it
    /// unconditionally as a background dispatcher would. `exec_visible` is
    /// populated from `exec_visible_fn_`, exactly like every sibling
    /// operator-facing surface — an unwired callback fails closed to
    /// `authz::deny_all()` (present-empty), NEVER the default-constructed
    /// `nullopt` (unfiltered): `dispatch_caller.hpp`'s contract reserves
    /// `nullopt` for a genuine `.system = true` background dispatcher, and
    /// `devices_fn(viewer)`'s cohort narrowing below is a DIFFERENT
    /// authorization dimension (`Infrastructure:Read`/flat group-membership)
    /// from `Execution:Execute`'s ancestor-aware RBAC visibility — it does not
    /// substitute for this chokepoint-level intersection (#1788 gov finding).
    yuzu::server::DispatchCaller caller_from_session(const auth::Session& session) const;

    /// Advance a deployment one tick (re-auth from the live session) and render its
    /// progress block; self-repolls while in flight + under the page-poll cap.
    /// `caller` is the live session's dispatch identity (principal + role);
    /// `caller.principal` doubles as the owner-scoped `viewer` for the store
    /// reads below — the two were always the same value, now carried as one.
    std::string advance_and_render(const std::string& deployment_id,
                                   const yuzu::server::DispatchCaller& caller, int attempt);
};

} // namespace yuzu::server
