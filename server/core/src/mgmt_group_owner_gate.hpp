#pragma once

#include "management_group_store.hpp"
#include "rbac_admin_predicate.hpp"

#include <yuzu/server/auth.hpp>

#include <string>
#include <string_view>
#include <vector>

/// @file mgmt_group_owner_gate.hpp
/// THE "caller owns this management group" arm of the group role-assignment gates.
///
/// Seven call sites decide it: the REST routes `GET`/`POST`/`DELETE
/// /api/v1/management-groups/{id}/roles` and the REST service-scoped token mint
/// (`rest_api_v1.cpp`), and the MCP tools `list_management_group_roles` /
/// `assign_management_group_role` and the MCP service-scoped token mint (`mcp_server.cpp`). Each
/// is a compound gate: a fleet-wide permission, OR the caller holding `ITServiceOwner` on the
/// group in question. This header is the one place the second half is decided, so the seven
/// cannot drift apart. EXTEND it, never copy the loop back into a handler (routed concerns:
/// "Service-scoped API token confinement" clause 4, "Authentication, RBAC, headers, tokens" and
/// "MCP server architecture").
///
/// The owner arm is a DATA check (assignment rows), not an RBAC grant: it holds with RBAC off and
/// is scoped to one group. It is therefore refused for every session class that must not obtain
/// authority from a membership row:
///   - a service-scoped token (`token_scope_service` non-empty) on either surface: confinement
///     takes precedence over the minter's own rows (guardian-confinement-2298 PR3 §3e);
///   - an engine-classed session (`Session::is_engine()`) on either surface: engine principals
///     resolve authority through RBAC grants only, never a membership fallback;
///   - on REST only, any session with a non-empty `mcp_tier`: REST has no maker-checker flow to
///     fall back on, the same rule `rbac_admin_predicate.hpp` applies to `kRest`. MCP leaves the
///     tier to the tool ladder, and every `/mcp/v1/` session has a non-empty tier, so a tier rule
///     there would delete the documented owner arm of both tools.
///
/// `surface` has NO default argument, by design (the `RbacAdminSurface` rule, #520): a caller
/// must state which transport it serves.
namespace yuzu::server {

/// Pure: may this session use the owner arm on this surface at all?
[[nodiscard]] inline bool owner_arm_eligible(const auth::Session& session,
                                             RbacAdminSurface surface) {
    if (!session.token_scope_service.empty())
        return false;
    if (session.is_engine())
        return false;
    if (surface == RbacAdminSurface::kRest && !session.mcp_tier.empty())
        return false;
    return true;
}

/// Pure: do these assignment rows say `username` is an `ITServiceOwner` of the group they came
/// from? Only a `user` principal row counts; a group or engine principal never does.
[[nodiscard]] inline bool holds_group_owner_role(const std::vector<GroupRoleAssignment>& rows,
                                                 std::string_view username) {
    for (const auto& gr : rows) {
        if (gr.principal_type == "user" && gr.principal_id == username &&
            gr.role_name == "ITServiceOwner")
            return true;
    }
    return false;
}

/// Thin shell: is the caller admitted by the owner arm of `group_id`? The group's rows are read
/// only when the session is eligible.
[[nodiscard]] inline bool group_owner_admits(const ManagementGroupStore& store,
                                             const std::string& group_id,
                                             const auth::Session& session,
                                             RbacAdminSurface surface) {
    return owner_arm_eligible(session, surface) &&
           holds_group_owner_role(store.get_group_roles(group_id), session.username);
}

} // namespace yuzu::server
