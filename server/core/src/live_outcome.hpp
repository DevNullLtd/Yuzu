#pragma once

/// @file live_outcome.hpp
/// PURE closed vocabulary for the per-device live read (REST `POST /api/v1/dex/devices/{id}/live`
/// and MCP `get_device_live`): the outcome token and the two metric label sets.
///
/// `yuzu_server_live_requests_total{surface, kind, outcome}` takes every label value from this
/// header, never from caller input, so its cardinality is bounded by construction:
///   - `surface` is `to_token(LiveSurface)`: rest | mcp;
///   - `kind` is `kind_label()`: uptime | processes | unknown (anything else collapses to unknown);
///   - `outcome` is `to_token(LiveOutcome)`.
///
/// Header-only, no includes beyond the standard library, enrolled in the `device` seam-closure
/// family. The `to_token` switches deliberately have NO `default:` so that a new enumerator is a
/// -Wswitch build failure until it is given a token.

#include <array>
#include <cstddef>
#include <string_view>

namespace yuzu::server::live {

/// Which surface served the read. The metric label `surface`.
enum class LiveSurface {
    kRest,
    kMcp,
};

[[nodiscard]] constexpr std::string_view to_token(LiveSurface s) noexcept {
    switch (s) {
    case LiveSurface::kRest:
        return "rest";
    case LiveSurface::kMcp:
        return "mcp";
    }
    return "rest"; // unreachable for a valid enumerator; keeps the function total
}

/// The metric label `kind`: the two kinds the surfaces serve, else `unknown` (a caller-supplied
/// kind is never used as a label value).
[[nodiscard]] constexpr std::string_view kind_label(std::string_view kind) noexcept {
    if (kind == "uptime")
        return "uptime";
    if (kind == "processes")
        return "processes";
    return "unknown";
}

/// How a live read ended. A CLOSED set: the metric label `outcome`.
enum class LiveOutcome {
    kOk,
    kNotConfigured,        ///< a required seam (response store, dispatch, caller) is not wired
    kGateRefused,          ///< a permission or scope gate refused the caller
    kBadKind,              ///< the kind is not one the surface serves
    kUnavailable,          ///< nothing was sent and no more specific cause applies (device offline)
    kOverBudgetPrincipal,  ///< StreamBudget per-principal cap
    kOverBudgetSurface,    ///< StreamBudget surface cap
    kOverBudgetGlobal,     ///< StreamBudget global cap, or draining
    kAuditFailed,          ///< the `requested` audit row could not be written (fail closed)
    kPermissionRevoked,    ///< a grant was withdrawn between the first check and the re-decision
    kCallerUnresolved,     ///< the caller could not be re-derived at the re-decision
    kDispatchDenied,       ///< the dispatch chokepoint refused the (plugin, action) pair
    kInvalidScope,         ///< zero-reach cause
    kContainmentUnreadable, ///< zero-reach cause
    kRouteUnreadable,      ///< zero-reach cause
    kOsGateUnreadable,     ///< zero-reach cause
    kQuarantined,          ///< zero-reach cause
    kPluginNotFound,       ///< zero-reach cause
    kKillSwitchedOs,       ///< zero-reach cause
    kDeviceFailed,         ///< a terminal failure row came back from the device
    kDeviceError,          ///< the device answered with an `error|` line
    kOutputTooLarge,       ///< the device output exceeded the byte cap and the surface refuses
    kTimeout,              ///< nothing at all came back from the device inside the poll budget
    kStoreDegraded,        ///< every poll read of the response store degraded
    kInternal,             ///< an unexpected exception
    kTierRefused,          ///< the MCP tier does not allow the Execute pair
    kReadOnlyRefused,      ///< refused under --mcp-read-only
    kApprovalRefused,      ///< a token that requires approval for this tool
    kShuttingDown,         ///< the server is draining or stopping; the read was refused or abandoned
    kIncomplete,           ///< the device sent output but never a terminal row inside the budget
    kGateUnreadable,       ///< the permission store could not be read at the re-decision (not a revocation)
};

[[nodiscard]] constexpr std::string_view to_token(LiveOutcome o) noexcept {
    switch (o) {
    case LiveOutcome::kOk:
        return "ok";
    case LiveOutcome::kNotConfigured:
        return "not_configured";
    case LiveOutcome::kGateRefused:
        return "gate_refused";
    case LiveOutcome::kBadKind:
        return "bad_kind";
    case LiveOutcome::kUnavailable:
        return "unavailable";
    case LiveOutcome::kOverBudgetPrincipal:
        return "over_budget_principal";
    case LiveOutcome::kOverBudgetSurface:
        return "over_budget_surface";
    case LiveOutcome::kOverBudgetGlobal:
        return "over_budget_global";
    case LiveOutcome::kAuditFailed:
        return "audit_failed";
    case LiveOutcome::kPermissionRevoked:
        return "permission_revoked";
    case LiveOutcome::kCallerUnresolved:
        return "caller_unresolved";
    case LiveOutcome::kDispatchDenied:
        return "dispatch_denied";
    case LiveOutcome::kInvalidScope:
        return "invalid_scope";
    case LiveOutcome::kContainmentUnreadable:
        return "containment_unreadable";
    case LiveOutcome::kRouteUnreadable:
        return "route_unreadable";
    case LiveOutcome::kOsGateUnreadable:
        return "os_gate_unreadable";
    case LiveOutcome::kQuarantined:
        return "quarantined";
    case LiveOutcome::kPluginNotFound:
        return "plugin_not_found";
    case LiveOutcome::kKillSwitchedOs:
        return "kill_switched_os";
    case LiveOutcome::kDeviceFailed:
        return "device_failed";
    case LiveOutcome::kDeviceError:
        return "device_error";
    case LiveOutcome::kOutputTooLarge:
        return "output_too_large";
    case LiveOutcome::kTimeout:
        return "timeout";
    case LiveOutcome::kStoreDegraded:
        return "store_degraded";
    case LiveOutcome::kInternal:
        return "internal";
    case LiveOutcome::kTierRefused:
        return "tier_refused";
    case LiveOutcome::kReadOnlyRefused:
        return "read_only_refused";
    case LiveOutcome::kApprovalRefused:
        return "approval_refused";
    case LiveOutcome::kShuttingDown:
        return "shutting_down";
    case LiveOutcome::kIncomplete:
        return "incomplete";
    case LiveOutcome::kGateUnreadable:
        return "gate_unreadable";
    }
    return "internal"; // unreachable for a valid enumerator; keeps the function total
}

/// Every enumerator, in declaration order, so a test (and any exporter that pre-registers label
/// values) can walk the closed set. The `static_assert` ties its length to the last enumerator:
/// a new enumerator appended after `kGateUnreadable` must update both, and the `to_token`
/// switch above refuses to compile until it has a token.
inline constexpr std::array<LiveOutcome, 31> kAllLiveOutcomes = {
    LiveOutcome::kOk,
    LiveOutcome::kNotConfigured,
    LiveOutcome::kGateRefused,
    LiveOutcome::kBadKind,
    LiveOutcome::kUnavailable,
    LiveOutcome::kOverBudgetPrincipal,
    LiveOutcome::kOverBudgetSurface,
    LiveOutcome::kOverBudgetGlobal,
    LiveOutcome::kAuditFailed,
    LiveOutcome::kPermissionRevoked,
    LiveOutcome::kCallerUnresolved,
    LiveOutcome::kDispatchDenied,
    LiveOutcome::kInvalidScope,
    LiveOutcome::kContainmentUnreadable,
    LiveOutcome::kRouteUnreadable,
    LiveOutcome::kOsGateUnreadable,
    LiveOutcome::kQuarantined,
    LiveOutcome::kPluginNotFound,
    LiveOutcome::kKillSwitchedOs,
    LiveOutcome::kDeviceFailed,
    LiveOutcome::kDeviceError,
    LiveOutcome::kOutputTooLarge,
    LiveOutcome::kTimeout,
    LiveOutcome::kStoreDegraded,
    LiveOutcome::kInternal,
    LiveOutcome::kTierRefused,
    LiveOutcome::kReadOnlyRefused,
    LiveOutcome::kApprovalRefused,
    LiveOutcome::kShuttingDown,
    LiveOutcome::kIncomplete,
    LiveOutcome::kGateUnreadable,
};
static_assert(kAllLiveOutcomes.size() ==
                  static_cast<std::size_t>(LiveOutcome::kGateUnreadable) + 1,
              "kAllLiveOutcomes must list every LiveOutcome enumerator");

} // namespace yuzu::server::live
