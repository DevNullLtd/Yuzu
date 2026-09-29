#pragma once

/// @file management_group_model.hpp
/// Shared PURE builder functions for the management-group REST+MCP twins
/// (api-parity #2146 Batch B4) - `docs/api-twin-recipe.md` §1 Rule 1: "REST,
/// MCP, and the HTML dashboard fragment must call the same function to build
/// the response body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` - every
/// function here is callable from both `rest_api_v1.cpp` and
/// `mcp_server.cpp` with zero transport dependency, so the two JSON shapes
/// cannot drift apart by construction. Colocate-with-store per the recipe's
/// `discover_routes.hpp` precedent would also be legal here, but a dedicated
/// file matches B3's `execution_statistics_model.hpp` precedent for this same
/// api-parity programme.
///
/// Adversarial-review fix (#2146 Batch B4, review round): `get_management_group`
/// and `update_management_group`'s REST handlers and MCP twins each
/// hand-rolled their own copy of this JSON, the exact anti-pattern this doc's
/// §1 names (`network_routes.cpp`'s duplicated stat-row builders).

#include <string>
#include <vector>

#include "management_group_store.hpp" // ManagementGroup / ManagementGroupMember

namespace yuzu::server {

/// One group's full detail + member list - `GET /api/v1/management-groups/{id}`
/// and its MCP twin `get_management_group`.
std::string management_group_detail_json(const ManagementGroup& g,
                                          const std::vector<ManagementGroupMember>& members);

/// The update-success ack - `PUT /api/v1/management-groups/{id}` and its MCP
/// twin `update_management_group`. `audit_ok` defaults true for REST (which
/// has no `audit_persisted` body field, relying instead on its
/// `Sec-Audit-Failed` header per the per-surface audit fail-mode table); MCP
/// passes its real `audit_fn` result so a dropped audit row surfaces in the
/// only channel MCP has for it. One function either way - the deliberate
/// REST/MCP fail-mode difference is a parameter, not a second copy.
inline std::string management_group_update_ack_json(bool audit_ok = true) {
    return audit_ok ? R"({"updated":true})" : R"({"updated":true,"audit_persisted":false})";
}

} // namespace yuzu::server
