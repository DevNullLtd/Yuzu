#pragma once

/// @file live_zero_reach_outcome.hpp
/// Maps the dispatch classifier's `ZeroReachCause` onto the live read's `LiveOutcome`, so the REST
/// route and the MCP tool count the same cause under the same `outcome` label.
///
/// This is deliberately a separate header from `live_outcome.hpp`: that one is pure
/// (standard-library-only) and sits in the `device` seam-closure family, and this one includes
/// the dispatch classifier. It is not enrolled in any seam family.
///
/// The switch has NO `default:` so a new `ZeroReachCause` is a -Wswitch build failure until it
/// is given an outcome.

#include "dispatch_zero_reach.hpp"
#include "live_outcome.hpp"
#include "scoped_gate_outcome.hpp"

namespace yuzu::server::live {

/// `Generic` (nothing sent and no more specific cause: the device is offline, or a residual
/// race) is `kUnavailable`; every named cause has its own outcome whose token equals
/// `zero_reach_token(cause)`.
[[nodiscard]] constexpr LiveOutcome live_outcome_for(ZeroReachCause cause) noexcept {
    switch (cause) {
    case ZeroReachCause::Denied:
        return LiveOutcome::kDispatchDenied;
    case ZeroReachCause::InvalidScope:
        return LiveOutcome::kInvalidScope;
    case ZeroReachCause::ContainmentUnreadable:
        return LiveOutcome::kContainmentUnreadable;
    case ZeroReachCause::RouteUnreadable:
        return LiveOutcome::kRouteUnreadable;
    case ZeroReachCause::OsGateUnreadable:
        return LiveOutcome::kOsGateUnreadable;
    case ZeroReachCause::Quarantined:
        return LiveOutcome::kQuarantined;
    case ZeroReachCause::PluginNotFound:
        return LiveOutcome::kPluginNotFound;
    case ZeroReachCause::KillSwitchedOs:
        return LiveOutcome::kKillSwitchedOs;
    case ZeroReachCause::TargetResolutionFailed:
        return LiveOutcome::kTargetResolutionFailed;
    case ZeroReachCause::NoTargets:
        return LiveOutcome::kNoTargets;
    case ZeroReachCause::Generic:
        return LiveOutcome::kUnavailable;
    }
    return LiveOutcome::kUnavailable; // unreachable for a valid enumerator; keeps the function total
}

/// The outcome label of a REFUSED re-decision of the per-device scoped gate (#7110: both gates are
/// decided again after the `requested` row). A definitive denial is a withdrawn permission; a
/// gate that could not read its authority (the gate answered 503, or an RBAC or management-group
/// read failed) is `gate_unreadable`, which is NOT a revocation and is retryable; a session that no
/// longer resolves is `caller_unresolved`. `Admitted` is not a refusal and is never passed here;
/// it maps to `kInternal` so the function stays total. No `default:`: a new enumerator is a
/// build failure until it is given an outcome.
[[nodiscard]] constexpr LiveOutcome live_outcome_for(ScopedGateOutcome outcome) noexcept {
    switch (outcome) {
    case ScopedGateOutcome::Denied:
        return LiveOutcome::kPermissionRevoked;
    case ScopedGateOutcome::Unauthenticated:
        return LiveOutcome::kCallerUnresolved;
    case ScopedGateOutcome::Unavailable:
    case ScopedGateOutcome::MgmtGroupReadDegraded:
    case ScopedGateOutcome::RbacReadDegraded:
        return LiveOutcome::kGateUnreadable;
    case ScopedGateOutcome::Admitted:
        return LiveOutcome::kInternal;
    }
    return LiveOutcome::kInternal; // out-of-range value: refuse to name it a revocation
}

} // namespace yuzu::server::live
