#include "forensics_visibility.hpp"

#include <string>
#include <unordered_set>

#include <yuzu/server/auth.hpp>

#include "auth_routes.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "management_group_store.hpp"
#include "rbac_store.hpp"

namespace yuzu::server {

ForensicsVisibility resolve_forensics_visible(const ForensicsVisibilityDeps& deps,
                                              const httplib::Request& req) {
    if (!deps.auth_routes)
        return std::unexpected(ForensicsUnknown::Unwired); // nothing may be proven

    const std::string securable{kForensicsSecurable};
    // 1. Global proof. Quiet (no cookie-session denial row), but it IS the gate's own decision:
    //    elevation, engine principals, MCP tier, service scope, RBAC and the RBAC-off admin-only
    //    floor are all decided inside it. The gate's response is kept in a scratch object only to
    //    tell an unavailable authorization store (503) from a definitive refusal (401/403).
    httplib::Response gate_response;
    if (deps.auth_routes->probe_permission(req, gate_response, securable, "Read"))
        return ForensicsVisibility{std::in_place, std::nullopt}; // Granted, global
    if (gate_response.status == 503)
        return std::unexpected(ForensicsUnknown::RbacUnavailable);

    // 2. A management-group-scoped grant, only meaningful while enforcement is in effect (with it
    //    off there are no scoped grants, and Forensics:Read is admin-only through step 1).
    if (!deps.rbac_store)
        return std::unexpected(ForensicsUnknown::Unwired);
    if (!rbac_enforcement_in_effect(deps.rbac_store))
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied
    if (!deps.mgmt_store)
        return std::unexpected(ForensicsUnknown::Unwired);
    const auto session = deps.auth_routes->resolve_session(req);
    if (!session)
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied
    // These callers' authority is not "the user's own scoped grants": a service-scoped token is
    // default-denied fleet data, an engine principal resolves RBAC-only against global grants, and
    // an MCP-tier token is bounded by its tier before RBAC. Reading the owner's scoped grants for
    // them would widen them, so they get nothing beyond the global proof above.
    if (!session->token_scope_service.empty() || session->is_engine() || !session->mcp_tier.empty())
        return ForensicsVisibility{std::in_place, authz::deny_all()}; // Denied

    auto visible = deps.rbac_store->visible_agents_for_permission(session->username, securable,
                                                                   "Read", deps.mgmt_store);
    if (!visible)
        return std::unexpected(ForensicsUnknown::ScopeReadFailed); // never nullopt, never "none"
    return ForensicsVisibility{
        std::in_place, authz::VisibleSet{std::unordered_set<std::string>(visible->begin(), visible->end())}};
}

} // namespace yuzu::server
