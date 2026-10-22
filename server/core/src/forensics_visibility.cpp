#include "forensics_visibility.hpp"

#include <string>
#include <unordered_set>

#include <yuzu/server/auth.hpp>

#include "auth_routes.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "management_group_store.hpp"
#include "rbac_store.hpp"

namespace yuzu::server {

authz::VisibleSet resolve_forensics_visible(const ForensicsVisibilityDeps& deps,
                                            const httplib::Request& req) {
    if (!deps.auth_routes)
        return authz::deny_all(); // unwired: nothing may be proven

    const std::string securable{kForensicsSecurable};
    // 1. Global proof. Quiet (no response, no cookie-session denial row), but it IS the gate's own
    //    decision: elevation, engine principals, MCP tier, service scope, RBAC and the RBAC-off
    //    admin-only floor are all decided inside it.
    if (deps.auth_routes->has_permission(req, securable, "Read"))
        return std::nullopt;

    // 2. A management-group-scoped grant, only meaningful while enforcement is in effect (with it
    //    off there are no scoped grants, and Forensics:Read is admin-only through step 1).
    if (!deps.rbac_store || !deps.mgmt_store || !rbac_enforcement_in_effect(deps.rbac_store))
        return authz::deny_all();
    const auto session = deps.auth_routes->resolve_session(req);
    if (!session)
        return authz::deny_all();
    // These callers' authority is not "the user's own scoped grants": a service-scoped token is
    // default-denied fleet data, an engine principal resolves RBAC-only against global grants, and
    // an MCP-tier token is bounded by its tier before RBAC. Reading the owner's scoped grants for
    // them would widen them, so they get nothing beyond the global proof above.
    if (!session->token_scope_service.empty() || session->is_engine() || !session->mcp_tier.empty())
        return authz::deny_all();

    auto visible = deps.rbac_store->visible_agents_for_permission(session->username, securable,
                                                                   "Read", deps.mgmt_store);
    if (!visible)
        return authz::deny_all(); // degraded read: fail closed, never nullopt
    return authz::VisibleSet{std::unordered_set<std::string>(visible->begin(), visible->end())};
}

} // namespace yuzu::server
