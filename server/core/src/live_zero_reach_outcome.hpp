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
    case ZeroReachCause::Generic:
        return LiveOutcome::kUnavailable;
    }
    return LiveOutcome::kUnavailable; // unreachable for a valid enumerator; keeps the function total
}

} // namespace yuzu::server::live
