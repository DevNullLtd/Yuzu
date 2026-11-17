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
///     who may not dispatch `echo.fleet_snapshot` directly could schedule it —
///     the definition ships operator-referencable — and the fire would reach
///     the fleet under system authority. Refused here, where the operator's
///     provenance is still known;
///   * a missing or unopened `RbacStore`.
///
/// RBAC legacy-open (`rbac_enforcement_in_effect()` false) mirrors `require_permission`'s
/// legacy rule: a READ-class pair admits any human, but every NON-Read pair needs the
/// principal's CURRENT legacy admin role (WP06 F53: before this, a creator demoted from admin
/// - or whose JIT elevation had lapsed - kept firing mutating schedules with fleet reach
/// forever). An engine principal (`engine:<slug>`) is never admitted there: its only authority
/// is an explicit RBAC grant (#6204). The admin bit is a RESOLVED INPUT (the caller reads the
/// creator's role from the auth store AT FIRE TIME, never cached, unresolvable = false), which
/// keeps this function pure. This is the ONLY place the schedule seam applies that rule: the
/// dispatch permission binder's and the visibility composer's legacy-open admits are
/// deliberately left as they are (other surfaces rely on route-level gates), because this check
/// runs first at every fire and `derive_dispatch_caller_for_username` stamps
/// `principal_is_admin` fresh for the AdminOrApproval pairs. Do not "fix" it a second way.

#include "command_capability.hpp"
#include "rbac_store.hpp"

#include <string>

namespace yuzu::server {

/// Decide whether `principal` may still arm `plugin.action`. `rbac` may be
/// null (denies). `principal_is_legacy_admin`: the principal's current legacy role is admin. Pure with respect to its inputs — no metrics, no logging,
/// no audit: the caller owns those, so this can be exercised directly in a
/// unit test with a real registry and a `:memory:` store.
[[nodiscard]] inline bool schedule_arming_permitted(const CommandCapabilityRegistry& registry,
                                                    const RbacStore* rbac,
                                                    const std::string& principal,
                                                    const std::string& plugin,
                                                    const std::string& action,
                                                    bool principal_is_legacy_admin) {
    const auto classified = registry.classify(plugin, action);
    if (!classified)
        return false;
    if (classified->system_reserved)
        return false;
    if (rbac == nullptr || !rbac->is_open())
        return false;
    if (!rbac_enforcement_in_effect(rbac))
        // Legacy-open (RBAC off): never an engine principal; a non-Read pair needs the
        // creator's CURRENT admin role (mirrors require_permission's legacy rule, WP06 F53).
        return !yuzu::server::authz::is_engine_principal_name(principal) &&
               (classified->operation == yuzu::server::authz::Operation::Read ||
                principal_is_legacy_admin);
    return rbac->check_permission(principal, std::string(classified->securable),
                                  std::string(yuzu::server::authz::to_string(classified->operation)));
}

} // namespace yuzu::server
