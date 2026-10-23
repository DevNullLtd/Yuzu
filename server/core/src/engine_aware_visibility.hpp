#pragma once

// Username-keyed visibility and dispatch-permission resolvers that `ServerImpl` binds into its
// route seams. Each decision depends only on the two stores and the username, so they live here as
// free functions, not as `ServerImpl` members: that keeps them unit-testable against real stores
// (ServerImpl is not unit-constructible).
//
// THE ENGINE RULE (#6204). An engine principal (`engine:<slug>`) has RBAC-only authority
// (docs/auth-engine-principals-design.md §4.2): the legacy-open fallback that admits every human
// when RBAC is off must never apply to it. With RBAC off an engine sees no agents and is refused;
// with RBAC on it follows the ordinary grant evaluation. A NEW username-keyed resolver must take the
// same fact (`authz::is_engine_principal_name`).
//
// Each resolver makes ONE enforcement read of its own: two `rbac_enforcement_in_effect` reads could
// disagree across a concurrent toggle and let an engine fall through both branches to the full fleet.
// `ManagementGroupStore::get_visible_agents` consults its own RBAC probe on top of that read, so for a
// HUMAN the two can differ across a toggle (unchanged from before this header existed); an engine
// stays empty on both reads, because `get_visible_agents` refuses the `engine:` prefix in its
// legacy-open branch.
//
// Return conventions (ADR-0033 §1): `std::nullopt` = unfiltered (whole fleet); a present-EMPTY set
// = deny-all. A degraded or absent store narrows to empty, never to `nullopt`.

#include "authz_model.hpp"
#include "management_group_store.hpp"
#include "rbac_store.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace yuzu::server::visibility {

/// The `has_permission` binder `classify_and_authorize_dispatch` needs. Legacy-open (RBAC loaded and
/// explicitly off) admits every HUMAN principal and refuses an engine principal.
[[nodiscard]] inline bool dispatch_permission(const RbacStore* rbac, std::string_view principal,
                                              std::string_view securable,
                                              authz::Operation op) {
    if (!rbac_enforcement_in_effect(rbac))
        return !authz::is_engine_principal_name(principal);
    return rbac != nullptr &&
           rbac->check_permission(std::string(principal), std::string(securable),
                                  std::string(authz::to_string(op)));
}

/// The single per-agent Response:Read predicate. FAILS CLOSED on a load-failed store
/// (`rbac_enforcement_in_effect` is true for a null/!is_open() store, so the scoped check denies).
[[nodiscard]] inline bool response_agent_in_scope(const RbacStore* rbac,
                                                  const ManagementGroupStore* mgmt,
                                                  const std::string& username,
                                                  const std::string& agent_id) {
    if (!rbac_enforcement_in_effect(rbac))
        return !authz::is_engine_principal_name(username);
    return rbac != nullptr &&
           rbac->check_scoped_permission(username, "Response", "Read", agent_id, mgmt);
}

/// The agent list (`agents` is the registry's JSON array) filtered to what `username` may see.
/// Taken BY VALUE so the unfiltered path returns it with a move, not a deep copy of the fleet.
[[nodiscard]] inline nlohmann::json visible_agents_json(nlohmann::json agents,
                                                        const RbacStore* rbac,
                                                        const ManagementGroupStore* mgmt,
                                                        const std::string& username) {
    const bool enforced = rbac_enforcement_in_effect(rbac);
    if (!enforced && authz::is_engine_principal_name(username))
        return nlohmann::json::array();
    // #1498: restrict whenever enforcement is in effect (a missing/load-failed store counts); only a
    // loaded-and-explicitly-disabled store returns the full fleet to a human.
    if (enforced) {
        // A global Infrastructure:Read grant sees the whole fleet even under RBAC-on.
        const bool global_read = rbac != nullptr && rbac->is_open() &&
                                 rbac->check_permission(username, "Infrastructure", "Read");
        if (!global_read) {
            // No management-group store to resolve against: fail closed, never the fleet.
            if (mgmt == nullptr)
                return nlohmann::json::array();
            // ADR-0042: a degraded store (nullopt) -> empty visible set (fail closed).
            auto visible = mgmt->get_visible_agents(username);
            std::set<std::string> visible_set;
            if (visible)
                visible_set.insert(visible->begin(), visible->end());
            nlohmann::json filtered = nlohmann::json::array();
            for (const auto& a : agents)
                if (a.contains("agent_id") && visible_set.count(a["agent_id"].get<std::string>()))
                    filtered.push_back(a);
            return filtered;
        }
    }
    return agents;
}

/// Visible-agent SET for device-id-rendering lists. `nullopt` = the whole fleet (global
/// Infrastructure:Read, or RBAC off for a human); else the caller's management-group members.
[[nodiscard]] inline std::optional<std::set<std::string>>
infrastructure_visible_set(const RbacStore* rbac, const ManagementGroupStore* mgmt,
                           const std::string& username) {
    const bool enforced = rbac_enforcement_in_effect(rbac);
    if (!enforced && authz::is_engine_principal_name(username))
        return std::set<std::string>{};
    if (enforced) {
        const bool global_read = rbac != nullptr && rbac->is_open() &&
                                 rbac->check_permission(username, "Infrastructure", "Read");
        if (!global_read) {
            // No management-group store to resolve against: fail closed, never the fleet.
            if (mgmt == nullptr)
                return std::set<std::string>{};
            // ADR-0042: nullopt from the store means DEGRADED -> an EMPTY confined set (sees
            // nothing), NOT nullopt here (which would mean "sees the whole fleet").
            auto v = mgmt->get_visible_agents(username);
            if (!v)
                return std::set<std::string>{};
            return std::set<std::string>(v->begin(), v->end());
        }
    }
    return std::nullopt; // global read or RBAC disabled -> sees all
}

/// Response:Read-visible set for the dashboard facet/scope surfaces. Permission-specific (via
/// `visible_agents_for_permission`), unlike `get_visible_agents`, which is permission-agnostic.
[[nodiscard]] inline std::optional<std::set<std::string>>
response_visible_set(const RbacStore* rbac, const ManagementGroupStore* mgmt,
                     const std::string& username) {
    if (!rbac_enforcement_in_effect(rbac)) {
        if (authz::is_engine_principal_name(username))
            return std::set<std::string>{};
        return std::nullopt;
    }
    const bool global_read =
        rbac != nullptr && rbac->is_open() && rbac->check_permission(username, "Response", "Read");
    if (global_read)
        return std::nullopt; // global Response:Read sees all (#1715(b))
    if (rbac == nullptr || mgmt == nullptr)
        return std::set<std::string>{}; // fail closed: no store to resolve against
    auto v = rbac->visible_agents_for_permission(username, "Response", "Read", mgmt);
    if (!v)
        return std::set<std::string>{}; // degraded -> fail closed, never nullopt
    return std::set<std::string>(v->begin(), v->end());
}

} // namespace yuzu::server::visibility
