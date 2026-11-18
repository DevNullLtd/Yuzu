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
///   * a missing or unopened `RbacStore` (UNAVAILABLE: the occurrence is held, not denied).
///
/// RBAC legacy-open (`rbac_enforcement_in_effect()` false) applies the legacy rule of
/// `require_permission` for non-Read operations (a mirror of it for this seam, not a call into
/// it): a READ-class pair admits any human, but every NON-Read pair needs the
/// principal's CURRENT legacy admin role (a creator demoted from admin, or whose JIT elevation
/// lapsed, no longer arms a mutating schedule). An engine principal (`engine:<slug>`) is never admitted there: its only authority
/// is an explicit RBAC grant (#6204). The admin answer is a LAZY INPUT (`LegacyAdminFn`: the caller reads the
/// creator's role from the auth store AT FIRE TIME, never cached, only when needed) and the
/// result is tri-state - `unexpected` means the store could not answer and the caller HOLDS. This is the ONLY place the schedule seam applies that rule: the
/// dispatch permission binder's and the visibility composer's legacy-open admits are
/// deliberately left as they are (other surfaces rely on route-level gates), because this check
/// runs first at every fire and `derive_dispatch_caller_for_username` stamps
/// `principal_is_admin` fresh for the AdminOrApproval pairs. Do not "fix" it a second way.

#include "command_capability.hpp"
#include "rbac_store.hpp"

#include <yuzu/server/auth_db.hpp>

#include <expected>
#include <functional>
#include <cstdint>
#include <string>

namespace yuzu::server {

/// The arming decision: `true` = may arm, `false` = DENIED, `unexpected(why)` = the answer could NOT
/// be determined (a transient auth-store fault): the caller HOLDS the occurrence and retries, it
/// never records "authority denied" for an infrastructure fault. A plain `bool` converts to it, so
/// a callback returning `bool` is a valid arming check.
using ArmingResult = std::expected<bool, std::string>;

/// The most UNAVAILABLE arming answers one background tick spends before it stops asking. Each
/// costs up to a pooled-connection timeout on the single shared tick thread; with the store
/// evidently down, a tick that kept asking per held schedule would starve everything behind it
/// (and the outbox delivery sharing that thread). The remaining occurrences stay due: nothing is
/// advanced, denied or lost; the next tick asks the ones not currently held.
inline constexpr int kMaxArmingUnavailablePerTick = 3;

/// How long a scheduled occurrence whose arming answer was UNAVAILABLE is left alone before it is
/// asked again. The scheduler skips a held schedule WITHOUT asking and WITHOUT spending the per-tick
/// cap, so the schedules behind it (a Read-pair one needs no store read at all) still run during
/// the outage. Nothing is advanced, denied or lost: when the hold lapses the schedule is asked again.
inline constexpr std::int64_t kArmingHoldSeconds = 90;

/// The creator's CURRENT legacy admin role, evaluated LAZILY (only when the decision needs it:
/// RBAC off, a non-Read pair, a non-engine principal), so the auth store is not read for a Read
/// pair or under enforced RBAC. `unexpected` = the store could not answer.
using LegacyAdminFn = std::function<ArmingResult()>;

/// The arming answer for a creator whose auth-store lookup FAILED with `e`. An account that does
/// not exist, or a stored name the store will never accept, can never resolve: a definitive DENIAL
/// (the caller audits it and advances), not a fault - holding on it would re-ask forever. Any
/// other error is a store fault: UNAVAILABLE (held).
[[nodiscard]] inline ArmingResult legacy_admin_lookup_failure(AuthDBError e) {
    if (e == AuthDBError::UserNotFound || e == AuthDBError::InvalidUsername)
        return false;
    return std::unexpected(std::string("auth store error"));
}

/// Decide whether `principal` may still arm `plugin.action`. `rbac` may be
/// null (denies). Pure with respect to its inputs - no metrics, no logging,
/// no audit: the caller owns those, so this can be exercised directly in a
/// unit test with a real registry and a `:memory:` store.
[[nodiscard]] inline ArmingResult schedule_arming_permitted(const CommandCapabilityRegistry& registry,
                                                            const RbacStore* rbac,
                                                            const std::string& principal,
                                                            const std::string& plugin,
                                                            const std::string& action,
                                                            const LegacyAdminFn& legacy_admin) {
    const auto classified = registry.classify(plugin, action);
    if (!classified)
        return false;
    if (classified->system_reserved)
        return false;
    // A missing or unopened store cannot ANSWER: HOLD (never a recorded denial for an
    // infrastructure fault). Nothing is dispatched either way.
    if (rbac == nullptr || !rbac->is_open())
        return std::unexpected(std::string("rbac store not available"));
    if (!rbac_enforcement_in_effect(rbac)) {
        // Legacy-open (RBAC off): never an engine principal; a non-Read pair needs the creator's
        // CURRENT admin role (the same rule `require_permission`'s legacy branch applies to
        // non-Read operations). Read pairs never consult the auth store.
        if (yuzu::server::authz::is_engine_principal_name(principal))
            return false;
        if (classified->operation == yuzu::server::authz::Operation::Read)
            return true;
        return legacy_admin ? legacy_admin() : ArmingResult{false};
    }
    // Enforced RBAC: a pool timeout, an open breaker or a query error is UNAVAILABLE (held), a
    // definitive "no" is a denial. The Boolean `check_permission` would fold both into false.
    return rbac->check_permission_checked(
        principal, std::string(classified->securable),
        std::string(yuzu::server::authz::to_string(classified->operation)));
}

} // namespace yuzu::server
