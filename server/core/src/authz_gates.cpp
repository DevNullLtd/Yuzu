#include "authz_gates.hpp"

#include "auth_routes.hpp"
#include "authz_model.hpp"
#include "authz_topology_floor.hpp" // #4031: topology_floor_applies — see this gate's floor-check block
#include "mcp_policy.hpp" // mcp::tier_allows — #3290 Phase 2 caller-class parity with require_permission/require_list_read
#include "rest_a4_envelope_http.hpp"
#include "service_scope_policy.hpp" // authz::kServiceTagKey — #3289 single confinement-key definition

#include <yuzu/metrics.hpp> // MetricsRegistry — #4031 topology-floor-denied counter

#include <unordered_set>

namespace yuzu::server {

std::expected<authz::ListAuthority, authz::GateFailure>
AuthRoutes::require_fleet_read(const httplib::Request& req, httplib::Response& res,
                               const std::string& securable_type, const std::string& operation) {
    auto session = require_auth(req, res);
    if (!session)
        // require_auth already wrote the 401 response (unaudited — matches
        // require_admin/require_permission's existing convention: audit
        // trail begins at the first post-authentication decision, not at
        // require_auth itself).
        return std::unexpected(authz::GateFailure::Unauthenticated);

    const std::string perm = securable_type + ":" + operation;

    // Structurally Read-only (mirrors require_list_read): the legacy-open
    // AdmitAll branch below has no MCP approval-ticket check (that only
    // fires inside require_permission's own mcp_tier branch), so a mutation
    // must never reach it through this gate.
    if (operation != "Read") {
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read gate accepts Read operations only: " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403,
                                          "fleet read gate accepts Read operations only",
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    }

    // #3290 Phase 2 — caller-class parity with require_permission/
    // require_list_read (this gate previously had none of the branches
    // below, which is a security regression once a route actually migrates
    // onto it: an engine principal under RBAC-off would otherwise fall
    // through to authorize_list_read's legacy-open AdmitAll, and a
    // JIT-elevated operator with no underlying RBAC grant would otherwise
    // 403 at the management-group axis below). Canon order (routed-concern
    // "Service-scoped API token confinement" clause 2): elevated -> engine
    // -> mcp_tier -> service -> RBAC.

    // JIT admin elevation: same semantics as require_permission/
    // require_list_read — full admin for the elevation window, no
    // underlying grant needed, and never reachable by a service-scoped
    // token (elevate_session never runs for MCP/service tokens). Do NOT
    // call authorize_list_read for an elevated session: it has no elevation
    // concept, so an elevated session with zero RBAC grants would otherwise
    // be denied (the regression the first #3038 fix attempt shipped,
    // closed in require_list_read and mirrored here).
    if (auth::is_elevated(*session) && session->token_scope_service.empty())
        return authz::ListAuthority(std::nullopt); // TOP — unfiltered

    // Engine principals have NO legacy or service-scoped authority — their
    // only authority is an explicit RBAC assignment (design §4.2
    // default-deny). authorize_list_read's own legacy-open branch would
    // otherwise hand an engine credential fleet-wide read the moment RBAC
    // is disabled (the default) — resolve engine sessions here, RBAC-only,
    // or deny. Mirrors require_list_read's engine branch, not
    // require_permission's: this gate has no service-scope allow-list
    // concept for a belt-and-braces corrupted-row check to guard, since an
    // engine session never reaches the service axis below (it returns
    // here). A successful admit stays TOP — "current engine grants are
    // fleet-wide only" (require_list_read), no per-tag scoping concept
    // applies to engine principals.
    if (session->principal_kind == "engine") {
        if (!rbac_store_ || !rbac_store_->is_open()) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "engine principal denied: RBAC store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                                  .permission = perm}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Degraded);
        }
        if (!rbac_store_->is_rbac_enabled() ||
            !rbac_store_->check_permission(session->username, securable_type, operation)) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "engine principal denied " + perm);
            res.status = 403;
            res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                              detail::A4ErrorOpts{.permission = perm}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Forbidden);
        }
        return authz::ListAuthority(std::nullopt); // TOP — fleet-wide only
    }

    // MCP-tier tokens: tier policy precedes RBAC (matches
    // require_permission/require_list_read). Deny-or-fall-through ONLY — an
    // allowed tier continues below with its creator's role/authority, this
    // branch never admits on its own (routed-concern clause 2: a tier-admit
    // that bypasses the service check would reopen the flip on every route
    // at once).
    if (!session->mcp_tier.empty() &&
        !mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "MCP token tier '" + session->mcp_tier + "' does not allow " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "MCP token tier does not allow " + perm,
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    }

    // ── management-group axis: RbacStore::authorize_list_read (ADR-0017),
    // reused as the subordinate primitive — never rewritten. ──────────────
    if (!rbac_store_ || !rbac_store_->is_open()) {
        // Infrastructure unavailable, not a real authorization decision —
        // Degraded/503, aligned with the three sibling
        // "authorization store unavailable" sites in auth_routes.cpp (the
        // engine-principal RBAC-store-unavailable branches; grep the quoted
        // string): same wording, same status code. The 403/Forbidden this
        // used to return was the outlier — a caller doing exponential
        // backoff on 503 would never retry a transient RBAC-store hiccup
        // that surfaced as a permanent-looking 403 (fjarvis/Kimi K2.7, PR
        // #3216 follow-up review). retry_after_ms matches this function's
        // own two Degraded branches below (tag-store unavailable/degraded),
        // not the auth_routes.cpp siblings, which don't set it — this
        // branch is Degraded now, so it carries the same retry signal as
        // every other Degraded branch here. The deliberate DenyAll
        // weakening (implementation plan §2c) now covers only the
        // management-group axis's real-deny-vs-in-query-store-error
        // ambiguity below, not this null-store case.
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: RBAC store unavailable");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                              .permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Degraded);
    }

    // Decision (#2298 PR 3, "the flip"): preserve `require_permission`'s
    // service branch hard-403 when RBAC enforcement is not in effect. The
    // service-tag axis below is RBAC-independent — without this check, a
    // disabled-RBAC service-scoped session would get a NARROWED (non-empty,
    // via the tag axis alone) result here, a capability that session never
    // had through `require_permission`. Same predicate
    // (`rbac_enforcement_in_effect`, not raw `is_rbac_enabled()`) as
    // `require_permission`'s service branch, so the two gates can never
    // disagree on a corrupt/degraded store. `rbac_store_` is known non-null
    // and open here (the check above already returned Degraded otherwise).
    if (!session->token_scope_service.empty() && !rbac_enforcement_in_effect(rbac_store_)) {
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: service-scoped token requires RBAC to be enabled");
        res.status = 403;
        // No `.permission` (#3290 D5, routed-concern clause 5): granting
        // `perm` does not fix "RBAC disabled" — same shape as
        // require_permission's identical branch.
        res.set_content(detail::a4_denial(res, 403,
                                          "service-scoped tokens require RBAC to be enabled"),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    }

    // #4031 topology floor (authz_topology_floor.hpp): RbacStore::authorize_
    // list_read's own legacy-open branch (rbac_store.cpp) returns AdmitAll
    // UNCONDITIONALLY once RBAC enforcement is off, with no floor check of
    // its own — RbacStore is a data-layer primitive and must not depend on
    // Session, so it cannot apply a role-based floor itself (see
    // require_list_read's doc comment, auth_routes.hpp, which names this
    // exact gap and warns that a FUTURE floored securable routed through
    // that sibling gate "must re-apply the floor explicitly — do not assume
    // this wrapper inherits it for free"). This gate had the identical gap,
    // latent until now: every prior caller (Inventory/Execution/Response/
    // Schedule:Read) is unfloored, so nothing exercised it. #4031's
    // Enrollment:Read migration (docs/auth-architecture.md's "Fifth
    // migration") is the first floored securable ever routed through
    // require_fleet_read — without this check, a disabled-RBAC deployment
    // (the default) would silently widen GET /api/v1/enrollment/pending-agents
    // from admin-only back to any authenticated session, undoing exactly the
    // widening authz_topology_floor.hpp's (Enrollment, Read) entry (84cdfcc06)
    // was added to prevent. Mirrors require_permission's own legacy-branch
    // floor check (auth_routes.cpp) — same predicate, same audit-reason
    // prefix, same counter — but does not share code with it: the two
    // functions' surrounding control flow differs enough (this gate already
    // branched on `rbac_enforcement_in_effect` above for the service-scope
    // case) that a shared helper was judged higher-risk than a second,
    // narrowly-scoped copy of a five-line predicate. Placed after the
    // service-scope hard-403 above (a service-scoped session under RBAC-off
    // is already denied there, floored or not) and before the management-
    // group axis below, so it runs exactly once per request and only for the
    // ordinary (non-elevated, non-engine, tier-allowed, non-service) case a
    // floored securable can actually reach.
    if (!rbac_enforcement_in_effect(rbac_store_) && topology_floor_applies(securable_type, operation) &&
        auth::effective_role(*session) != auth::Role::admin) {
        const std::string reason = "topology floor: non-admin role denied " + perm +
                                   (session->mcp_tier.empty()
                                        ? ""
                                        : " (mcp_tier=" + session->mcp_tier + ")");
        audit_log(req, "auth.fleet_read_required", "denied", "", "", reason);
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_topology_floor_denied_total", {{"permission", perm}}).increment();
        }
        res.status = 403;
        res.set_content(
            detail::a4_denial(res, 403, "admin role required", detail::A4ErrorOpts{.permission = perm}),
            "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    }

    // Null/not-yet-open management-group store: rbac_store_/tag_store_ each
    // get an explicit pre-check turning "store unavailable" into a retryable
    // 503 before any real decision is attempted; this axis had none.
    // authorize_list_read's own helpers (resolve_perm_groups/
    // expand_visible_set) already null-check mgmt_group_store_ internally
    // and fail closed to DenyAll — never a crash, never a partial admit —
    // but DenyAll renders as 403 below, indistinguishable from "this caller
    // genuinely has no grant." A caller doing exponential backoff on 503
    // would never retry a transient store-construction gap that looks like a
    // permanent deny (unhappy-path finding UP-1, governance run 2026-08-20).
    // NOTE: this closes only the null/not-open half — a mid-query degrade
    // (the store opens fine but a later read fails) still renders as 403
    // here, because it is indistinguishable from a real DenyAll inside
    // authorize_list_read's own return value; that is the SAME deliberate
    // weakening implementation plan §2c accepts for every other
    // authorize_list_read caller (plugin_config_routes.cpp, the upload-grants
    // resolver in server.cpp), not a new gap this gate introduces, and fixing
    // it is a separate, larger change to the shared primitive.
    if (!mgmt_group_store_ || !mgmt_group_store_->is_open()) {
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: management-group store unavailable");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                              .permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Degraded);
    }

    // Spelled via deny_all() rather than relying on the switch below to
    // always overwrite the implicit nullopt(TOP) default — defense-in-depth
    // against a future non-exhaustive edit to ListReadDecision's cases
    // (cpp-safety, governance run 2026-08-17).
    authz::VisibleSet mgmt_scope = authz::deny_all();
    auto mgmt_authz = rbac_store_->authorize_list_read(session->username, securable_type, operation,
                                                       mgmt_group_store_);
    switch (mgmt_authz.decision) {
    case ListReadDecision::DenyAll:
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: no management-group grant for " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    case ListReadDecision::AdmitAll:
        mgmt_scope = std::nullopt; // TOP — unfiltered
        break;
    case ListReadDecision::AdmitScoped:
        mgmt_scope = std::unordered_set<std::string>(mgmt_authz.visible_agents.begin(),
                                                     mgmt_authz.visible_agents.end());
        break;
    }

    // ── service-scope axis: TOP for a non-service session (so a non-service
    // caller's result is byte-identical to authorize_list_read alone). ────
    authz::VisibleSet service_scope;
    if (!session->token_scope_service.empty()) {
        if (!tag_store_) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "fleet read blocked: tag store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503,
                                              "tag store unavailable, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Degraded);
        }
        // agents_with_tag is the ADR-0050 typed read
        // (std::expected<…, TagReadError>) — it distinguishes "genuinely no
        // agents tagged" (engaged, possibly empty) from "the tag store
        // degraded" (unexpected), superseding the pre-migration
        // agents_with_tag_checked/B-2b split. The axis must fail closed to
        // GateFailure::Degraded on the latter — never read a degraded store
        // as an empty-but-legitimate service, and never collapse Degraded
        // into Forbidden (the 503-vs-403 distinction this gate exists for).
        auto tagged = tag_store_->agents_with_tag(std::string(authz::kServiceTagKey),
                                                  session->token_scope_service);
        if (!tagged) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "fleet read blocked: tag store degraded resolving service scope");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "tag store degraded, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Degraded);
        }
        service_scope = std::unordered_set<std::string>(tagged->begin(), tagged->end());
    }

    return authz::ListAuthority(authz::meet(mgmt_scope, service_scope));
}

bool AuthRoutes::confine_agent_target(const httplib::Request& req, httplib::Response& res,
                                      const std::string& securable_type,
                                      const std::string& operation, const std::string& agent_id) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    const std::string perm = securable_type + ":" + operation;

    // #2437/#2500 omitted-vs-empty rule: an empty agent_id is a caller bug
    // (a route that should have required the param but didn't), not "no
    // target to check" — never fall through to an admit for it.
    // `require_scoped_permission`'s service branch had this exact
    // degenerate shape (an empty agent_id skipped its only comparison and
    // fell through to `return true`); that was closed at #2298 PR 3 §3b
    // (auth_routes.cpp) — this gate was built to not repeat it, not to fix
    // a bug still live there.
    if (agent_id.empty()) {
        audit_log(req, "auth.agent_target_required", "denied", "", "",
                  "agent target blocked: empty agent_id");
        res.status = 400;
        res.set_content(detail::a4_denial(res, 400, "agent_id is required",
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return false;
    }

    // Confinement-axis only (see the declaration's doc comment): a
    // non-service session has no service scope to confine against, so this
    // axis is TOP. The RBAC/ITServiceOwner decision is require_scoped_permission's
    // job (NOT require_permission's — that function never consults
    // mgmt_group_store_ and would incorrectly reject a management-group-
    // scoped-only caller; the identical defect class fjarvis's PR #3216
    // review blocked one level up, in auth_routes.hpp), not re-checked here.
    if (session->token_scope_service.empty())
        return true;

    if (!tag_store_) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent target blocked: tag store unavailable");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "tag store unavailable, cannot verify scope",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000}),
                        "application/json");
        return false;
    }
    // ADR-0050 typed read — degrade maps to the 503 branch below, never to
    // the not-in-service Forbidden (same reasoning as require_fleet_read).
    auto tagged = tag_store_->agents_with_tag(std::string(authz::kServiceTagKey),
                                              session->token_scope_service);
    if (!tagged) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent target blocked: tag store degraded resolving service scope");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "tag store degraded, cannot verify scope",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000}),
                        "application/json");
        return false;
    }
    const authz::VisibleSet service_scope{
        std::unordered_set<std::string>(tagged->begin(), tagged->end())};
    if (!authz::in_scope(service_scope, agent_id)) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent is not in service '" + session->token_scope_service + "'");
        res.status = 403;
        res.set_content(
            detail::a4_denial(res, 403,
                              "agent is not in service '" + session->token_scope_service + "'",
                              detail::A4ErrorOpts{.permission = perm}),
            "application/json");
        return false;
    }
    return true;
}

} // namespace yuzu::server
