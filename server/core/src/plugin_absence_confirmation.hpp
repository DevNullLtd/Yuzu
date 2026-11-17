#pragma once

/// @file plugin_absence_confirmation.hpp
/// The production confirmation reader for `AgentRegistry::ids_missing_plugin` (#5685 follow-up).
///
/// A plugin-absence read from the presence store is only a CANDIDATE: it was true of the session
/// that published the list. The registry withholds the agent only while this reader confirms that
/// the agent's ROUTABLE route-directory row still names that same session, so a restarted agent
/// (whose registration rewrote the row before it was handed its new session) is no longer judged by
/// its previous session's list. Fail OPEN everywhere: a degraded read returns `nullopt`, and the
/// registry then withholds nothing cross-replica.
///
/// A named factory, not a lambda in `server.cpp`, so that the wiring test exercises the production
/// predicate against the real store. The two stores stay single-schema owners and are composed
/// here in C++ (no cross-schema SQL, ADR-0012 section 3).

#include "gateway_route_store.hpp"
#include "offline_endpoint_types.hpp"

#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>

namespace yuzu::server {

/// Borrowed `store`: it must outlive every call of the returned function (the caller unwires the
/// reader before the store is destroyed, after every dispatch thread is joined).
[[nodiscard]] inline RouteSessionConfirmFn make_route_session_confirmer(GatewayRouteStore& store) {
    return [&store](std::span<const PluginAbsence> claims)
               -> std::optional<std::unordered_set<std::string>> {
        auto confirmed = store.confirm_sessions(claims);
        if (!confirmed)
            return std::nullopt;
        return std::unordered_set<std::string>(std::make_move_iterator(confirmed->begin()),
                                               std::make_move_iterator(confirmed->end()));
    };
}

} // namespace yuzu::server
