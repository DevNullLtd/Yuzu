#pragma once

/// @file schedule_arming_check.hpp
/// The ONE decision rule for re-verifying a schedule's arming principal at
/// fire time (D7/PLAN-003, BR-003).
///
/// WHY THIS FILE EXISTS — it replaces a MIRROR, and mirrors drift. The rule
/// previously lived inline in server.cpp's `ScheduleRunner::Deps.arming_check`
/// lambda, with a hand-copied second version in
/// `tests/unit/server/test_operator_surface_twins.cpp` carrying the comment
/// "any change to the real lambda's decision rule must be mirrored here too,
/// or this test stops proving anything about the shipped seam". It had already
/// stopped: the BR-003 `system_reserved` branch — the confused-deputy fix —
/// landed in the lambda and never reached the copy, so the fix was untested
/// and freely revertible while the test stayed green. A shared pure function
/// makes that class of drift unrepresentable, matching the single-copy
/// discipline `dispatch_confined_arms.hpp` already applies to the dispatch
/// intersection.
///
/// FAIL-CLOSED on every unresolved input. A schedule must never dispatch
/// under authority the server cannot presently confirm:
///   * an unclassified or ambiguous `plugin.action` — ADR-0033 §2, "a missing
///     or unparseable classification means the capability does not exist",
///     never a permissive default;
///   * a `system_reserved` capability (BR-003) — a schedule is OPERATOR-
///     authored but fires through `command_dispatch_fn`, which dispatches as
///     `DispatchCaller{.system = true}`, and the chokepoint's system_reserved
///     guard only refuses NON-system callers. Without this branch an operator
///     who may not dispatch `tar.fleet_snapshot` directly could schedule it —
///     the definition ships operator-referencable — and the fire would reach
///     the fleet under system authority. Refused here, where the operator's
///     provenance is still known;
///   * a missing or unopened `RbacStore`.
///
/// RBAC legacy-open (`rbac_enforcement_in_effect()` false) ADMITS, matching
/// every other authz call site's posture.

#include "command_capability.hpp"
#include "rbac_store.hpp"

#include <string>

namespace yuzu::server {

/// Decide whether `principal` may still arm `plugin.action`. `rbac` may be
/// null (denies). Pure with respect to its inputs — no metrics, no logging,
/// no audit: the caller owns those, so this can be exercised directly in a
/// unit test with a real registry and a `:memory:` store.
[[nodiscard]] inline bool schedule_arming_permitted(const CommandCapabilityRegistry& registry,
                                                    const RbacStore* rbac,
                                                    const std::string& principal,
                                                    const std::string& plugin,
                                                    const std::string& action) {
    const auto classified = registry.classify(plugin, action);
    if (!classified)
        return false;
    if (classified->system_reserved)
        return false;
    if (rbac == nullptr || !rbac->is_open())
        return false;
    if (!rbac_enforcement_in_effect(rbac))
        return true;
    return rbac->check_permission(principal, std::string(classified->securable),
                                  std::string(yuzu::server::authz::to_string(classified->operation)));
}

} // namespace yuzu::server
