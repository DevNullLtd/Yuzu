#pragma once

/// #4990: who may read Forensics-plugin rows out of the response store.
///
/// `resolve_forensics_visible` is the ONE production resolver behind every operator surface's
/// `ForensicsVisibilityFn`. Its answer is an ADR-0033 `authz::VisibleSet`:
///   * `nullopt`      = the caller holds a global `Forensics:Read` (may read every Forensics row)
///   * present subset = RBAC enforcement is on and the caller holds a management-group-scoped
///                      `Forensics:Read`: only those agents' Forensics rows
///   * present EMPTY  = no Forensics row (no grant, unwired, degraded, or a caller class that never
///                      carries per-agent authority here). Also the answer for every error.
///
/// Deliberately NOT modelled on `response_visible_set_fn`, which returns `nullopt` whenever RBAC is
/// off: right for `Response:Read` (an unconfined read), wrong here, where a global grant is the only
/// thing that may admit, and with RBAC off `Forensics:Read` is floored to administrators
/// (`authz_topology_floor.hpp`). The global proof therefore goes through
/// `AuthRoutes::has_permission` (the quiet twin of `require_permission`, the only gate family that
/// carries the floor) and NEVER through `require_fleet_read` / `probe_fleet_read` /
/// `authorize_list_read`, which admit every authenticated caller when enforcement is off.
///
/// Unwired means present-empty: `tier_filter_for` turns a missing resolver into `deny_all()`, and a
/// missing plugin set into a filter that refuses every row.

#include <functional>

#include <httplib.h>

#include "authz_model.hpp"
#include "response_tier_filter.hpp"

namespace yuzu::server {

class AuthRoutes;
class ManagementGroupStore;
class RbacStore;

/// Per-request resolver wired once in `server.cpp` and passed to each surface.
using ForensicsVisibilityFn = std::function<authz::VisibleSet(const httplib::Request&)>;

/// The stores the production resolver reads. Borrowed; any null member makes the answer
/// present-empty (never "unrestricted").
struct ForensicsVisibilityDeps {
    AuthRoutes* auth_routes{nullptr};
    const RbacStore* rbac_store{nullptr};
    const ManagementGroupStore* mgmt_store{nullptr};
};

/// The production resolver. Order is load-bearing:
///   1. `AuthRoutes::has_permission(req, "Forensics", "Read")` true => `nullopt` (global). This
///      already decides JIT elevation, engine principals (RBAC-only), MCP tier, service scope
///      (a service-scoped token never proves Forensics) and the RBAC-off legacy floor.
///   2. else, only when RBAC enforcement is in effect and the caller is an ordinary session (not a
///      service-scoped token, not an engine principal, not an MCP-tier token):
///      `RbacStore::visible_agents_for_permission` => that subset. A store failure => present-empty.
///   3. else present-empty.
/// Step 2 skips caller classes the global probe treats specially because their authority is not
/// "the minting user's grants": using the owner's scoped grants for them would widen them.
[[nodiscard]] authz::VisibleSet resolve_forensics_visible(const ForensicsVisibilityDeps& deps,
                                                          const httplib::Request& req);

/// The filter a surface passes to every `ResponseStore` read: the resolver's answer applied to the
/// Forensics plugin set. An unwired resolver (empty `fn`) is `deny_all()`; an unwired plugin set
/// (`nullptr`, impossible in production because boot refuses without one) refuses every row.
[[nodiscard]] inline ResponseTierFilter tier_filter_for(const httplib::Request& req,
                                                        const ForensicsVisibilityFn& fn,
                                                        const ForensicsPluginSet* plugins) {
    if (!plugins)
        return ResponseTierFilter::refuse_unwired();
    return ResponseTierFilter::exclude(*plugins, fn ? fn(req) : authz::deny_all());
}

} // namespace yuzu::server
