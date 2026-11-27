#pragma once

#include <optional>
#include <string>
#include <vector>

#include "agent_registry.hpp"
#include "gateway_route_store.hpp"

/// @file guardian_directory_route.hpp
/// HA WS-5 (#5685) - the route-directory decision behind the Guardian heartbeat reconcile's send
/// on a replica whose own session for the agent cannot deliver.
///
/// The reconcile flow only reaches its send for an agent this replica holds a session for. That
/// session can lack a delivery path of its own (`AgentRegistry::needs_directory_consult`: empty
/// `gateway_node` and no stream), which is the shape a session adopted from a gateway replay has
/// until its re-announced CONNECTED reaches THIS replica. `AgentRegistry::send_to` returns false
/// for it, so before this seam the push was silently undelivered. For exactly that shape this
/// reads the agent's durable route once and names the cluster that owns it.
///
/// Every refusal fails CLOSED, and each is a distinct, tested outcome:
///  - `unreadable`: the directory read degraded. Nothing may be sent; the caller aborts the
///    reconcile as degraded (an unreadable store is never read as "no route").
///  - `no_route`: no routable row, or a row that does not describe THIS replica's session
///    (another session id, no session, an expired lease, no cluster). Sending would queue the
///    push for a superseded registration's cluster while reporting success.
///  - `routed`: the row is `routable` (DB clock), names a cluster, and its `session_id` equals
///    the session this replica holds for the agent.
///  - `not_needed`: the local session can deliver (or no store is wired): the caller sends
///    through the registry exactly as before. A direct-connected agent never has a route row.
///
/// Pure of side effects: it sends and counts nothing. It takes no registry lock across the
/// Postgres read (each registry call is its own short lock).
namespace yuzu::server {

struct GuardianDirectoryRoute {
    enum class Kind { not_needed, unreadable, no_route, routed };
    Kind kind{Kind::not_needed};
    std::string cluster_id; ///< set only for `routed`
};

[[nodiscard]] inline GuardianDirectoryRoute
resolve_guardian_directory_route(const detail::AgentRegistry& registry, GatewayRouteStore* store,
                                 const std::string& agent_id) {
    if (store == nullptr || !store->is_open() || !registry.needs_directory_consult(agent_id))
        return {GuardianDirectoryRoute::Kind::not_needed, {}};
    const std::vector<std::string> ids{agent_id};
    auto routes = store->lookup_routes(ids);
    if (!routes)
        return {GuardianDirectoryRoute::Kind::unreadable, {}};
    const std::string local_session = registry.session_id_of(agent_id);
    for (const auto& rr : *routes) {
        if (rr.route.agent_id != agent_id || !rr.routable || !rr.route.cluster_id ||
            !rr.route.session_id || local_session.empty() || *rr.route.session_id != local_session)
            continue;
        return {GuardianDirectoryRoute::Kind::routed, *rr.route.cluster_id};
    }
    return {GuardianDirectoryRoute::Kind::no_route, {}};
}

} // namespace yuzu::server
