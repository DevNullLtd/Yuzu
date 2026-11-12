#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "agent_registry.hpp"
#include "gateway_route_store.hpp"

/// @file dispatch_route_fallback.hpp
/// HA WS-4 slice 4.2b Task C — wires `GatewayRouteStore::lookup_routes` (Task
/// A) into the confined-dispatch arm walk (`dispatch_confined_arms.hpp`) as a
/// FALLBACK-ONLY consult.
///
/// ACCEPTANCE PROPERTY: this changes ZERO monolith routing outcomes. It fires
/// ONLY when the existing dispatch resolution finds NO local
/// `AgentRegistry` session for a target agent (a "local miss") — a
/// direct-connected agent NEVER gets a `GatewayRouteStore` row (only the
/// gateway-service writer path, Tasks A/B, writes rows), so on today's
/// single-replica monolith a local miss means the agent is genuinely absent
/// and this consult only ever CONFIRMS "no route", never overrides a
/// locally-known agent's existing routing decision.
///
/// `GatewayRouteFallback` is built ONCE PER DISPATCH (never an
/// `AgentRegistry`/`ServerImpl` member — one instance per
/// `ConfinedDispatchSink`) and threaded, via `std::shared_ptr` closure
/// capture, into TWO `ConfinedDispatchSink` fields at each sink-construction
/// site (`dispatch_scope_ladder.hpp`'s `wire_and_dispatch_confined`,
/// `ServerImpl::make_confined_dispatch_sink`): `prepare_route_fallback` (the
/// BATCHED read, called once per arm walk by `dispatch_confined_arms`, never
/// per agent) and `send_to` (the per-id consult + queue). The batching and
/// lock-avoidance contract lives entirely in `prepare()` below — `send_to`
/// itself never touches the store, only the already-computed result.
namespace yuzu::server {

class GatewayRouteFallback {
public:
    GatewayRouteFallback(yuzu::server::detail::AgentRegistry& registry, GatewayRouteStore* store)
        : registry_(registry), store_(store) {}

    /// ONE batched `GatewayRouteStore::lookup_routes` call (never per-id) for
    /// whichever `candidates` have no local session right now. The
    /// local-session check is a cheap in-memory `AgentRegistry::get_session`
    /// per candidate — each such call acquires and releases the registry
    /// mutex on its own and returns before this method ever reaches the
    /// store; the Postgres read below never runs with any registry lock
    /// held. Returns true iff the read ITSELF degraded
    /// (`store_unavailable`/`db_error`) — as opposed to a successful read
    /// that simply found nothing routable for a locally-missing candidate
    /// (that is a definite no-route, not a degradation). A no-op (returns
    /// false, touches nothing) when `store` is null (directory not wired —
    /// e.g. `forward_legacy_command`'s Broadcast-only sink, which never
    /// calls this at all) or every candidate is locally known.
    [[nodiscard]] bool prepare(const std::vector<std::string>& candidates) {
        if (store_ == nullptr)
            return false;
        std::vector<std::string> missing;
        missing.reserve(candidates.size());
        for (const auto& aid : candidates)
            if (!registry_.get_session(aid))
                missing.push_back(aid);
        if (missing.empty())
            return false;
        auto res = store_->lookup_routes(missing);
        if (!res)
            return true; // degraded read — caller surfaces route_unreadable
        for (auto& rr : *res)
            if (rr.routable && rr.route.cluster_id)
                routable_[rr.route.agent_id] = *rr.route.cluster_id;
        return false;
    }

    /// Batched-result consult for one id, called from `send_to`.
    /// `std::nullopt` means "this dispatch's directory read did not resolve
    /// `agent_id` as routable" (locally known, absent from the directory
    /// entirely, present-but-not-routable per `RoutableRoute::routable`, or
    /// `prepare()` was never called / degraded) — the caller falls back to
    /// the normal local `AgentRegistry::send_to`, which for a genuinely
    /// local-miss agent correctly reports failure (a definite no-route).
    [[nodiscard]] std::optional<std::string> cluster_for(const std::string& agent_id) const {
        auto it = routable_.find(agent_id);
        return it == routable_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }

private:
    yuzu::server::detail::AgentRegistry& registry_;
    GatewayRouteStore* store_;
    std::unordered_map<std::string, std::string> routable_; // agent_id -> cluster_id
};

} // namespace yuzu::server
