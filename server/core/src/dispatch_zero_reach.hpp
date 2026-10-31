#pragma once

// dispatch_zero_reach.hpp -- classify WHY a dispatch reached nobody.
//
// NEW v1 routes and MCP tools call `classify_zero_reach` when a confined
// dispatch returns `sent == 0`. It is the single copy for new callers; extend
// `ZeroReachCause` and the cascade HERE, never fork a sixth hand-written copy.
//
// The five LEGACY sites keep their own hand-written copies ON PURPOSE and are
// deliberately not refactored onto this header (routed concern "Dispatch
// zero-reach cause discrimination"): mcp_server.cpp (`execute_instruction`),
// command_routes.cpp (`/api/command`), server.cpp (legacy forward),
// workflow_routes.cpp and dashboard_routes.cpp. This header changes none of them.
//
// Pure: no I/O, no logging, no store access. Reads only a
// `ConfinedDispatchOutcome` and one bool.
//
// FIXED priority order (first match wins). Copied from the MCP
// `execute_instruction` cascade (mcp_server.cpp, the `if (dispatch_outcome.
// scope_parse_error)` chain starting near line 19661):
//
//   1. invalid_scope            outcome.scope_parse_error set     permanent
//   2. containment_unreadable   outcome.containment_unreadable    retryable
//   3. route_unreadable         outcome.route_unreadable          retryable
//   4. os_gate_unreadable       outcome.os_gate_unreadable        retryable
//   5. quarantined              denied_quarantined_count > 0      permanent
//   6. plugin_not_found         unknown_plugin_count > 0          permanent
//   7. kill_switched_os         kill_switched_os_count > 0        permanent
//   8. no_agents_reached        catch-all                         retryable
//
// `> 0`, not "== every target": a mixed failure (some quarantined, some
// offline) is still not "just offline", and understating a permanent cause as
// retryable is the worse mistake.
//
// PROTECTIVE ACTIONS (common/include/yuzu/protective_actions.hpp,
// `is_protective_action`): a protective action never yields os_gate_unreadable,
// plugin_not_found or kill_switched_os. The legacy cascades do not consult a
// protective flag; there the exemption is applied upstream of the cascade (for
// instance `AgentRegistry::ids_missing_plugin` returns an empty set for a
// protective action). `protective_action` here is defence in depth: if one of
// those three signals still arrived on a protective dispatch, it is ignored
// rather than reported as a cause that must never apply to it. It does NOT
// suppress invalid_scope, containment_unreadable, route_unreadable or
// quarantined.
//
// Where the five legacy sites DISAGREE with this order or membership (read from
// the code, not reconciled; this header implements the MCP order):
//   - invalid_scope: present at mcp_server.cpp, workflow_routes.cpp and
//     dashboard_routes.cpp (first in each). Absent from the post-dispatch
//     cascade of command_routes.cpp (it answers a bad scope earlier from
//     `ladder.parse_error`, which also yields a body without `reason`) and of
//     the server.cpp legacy-forward cascade (Broadcast-only, no scope).
//   - os_gate_unreadable: a fourth-position branch in the post-dispatch cascade
//     at mcp_server.cpp, workflow_routes.cpp and dashboard_routes.cpp, but in
//     command_routes.cpp and server.cpp (legacy forward) it is a refusal made
//     BEFORE targeting, ahead of the cascade, and is skipped when the
//     containment gate is fail-closed so containment wins. The relative order
//     of the remaining causes is the same at all five.
//   - containment_unreadable: command_routes.cpp and server.cpp test
//     `containment_gate.fail_closed`; the other three test
//     `outcome.containment_unreadable`.
//   - catch-all: only mcp_server.cpp gives it a token (`no_agents_reached`) and
//     a retry hint (5000 ms). command_routes.cpp, server.cpp and
//     workflow_routes.cpp answer with no `reason`; command_routes.cpp and
//     server.cpp also carry no `retry_after_ms`; dashboard_routes.cpp keeps a
//     plain message. The retryable flag below follows the MCP site.

#include "dispatch_confined_arms.hpp"

#include <string_view>

namespace yuzu::server {

/// Closed set of reasons a dispatch can reach zero agents. `Generic` is the
/// catch-all (unreachable targets, or a residual race); every other value is a
/// specific, named cause.
enum class ZeroReachCause {
    InvalidScope,
    ContainmentUnreadable,
    RouteUnreadable,
    OsGateUnreadable,
    Quarantined,
    PluginNotFound,
    KillSwitchedOs,
    Generic,
};

/// Classify a zero-reach outcome. Call only when nothing was sent; the function
/// does not read `outcome.sent` and does not decide whether the dispatch was a
/// zero-reach one. `protective_action` is `is_protective_action(plugin, action)`
/// for the dispatched pair (see the banner for what it suppresses).
[[nodiscard]] inline ZeroReachCause classify_zero_reach(const ConfinedDispatchOutcome& outcome,
                                                        bool protective_action) noexcept {
    if (outcome.scope_parse_error)
        return ZeroReachCause::InvalidScope;
    if (outcome.containment_unreadable)
        return ZeroReachCause::ContainmentUnreadable;
    if (outcome.route_unreadable)
        return ZeroReachCause::RouteUnreadable;
    if (!protective_action && outcome.os_gate_unreadable)
        return ZeroReachCause::OsGateUnreadable;
    if (outcome.denied_quarantined_count > 0)
        return ZeroReachCause::Quarantined;
    if (!protective_action && outcome.unknown_plugin_count > 0)
        return ZeroReachCause::PluginNotFound;
    if (!protective_action && outcome.kill_switched_os_count > 0)
        return ZeroReachCause::KillSwitchedOs;
    return ZeroReachCause::Generic;
}

/// Stable wire token for a cause: the `status` string of MCP
/// `execute_instruction` and the `reason` string of the REST 503 bodies.
[[nodiscard]] constexpr std::string_view zero_reach_token(ZeroReachCause cause) noexcept {
    switch (cause) {
    case ZeroReachCause::InvalidScope:
        return "invalid_scope";
    case ZeroReachCause::ContainmentUnreadable:
        return "containment_unreadable";
    case ZeroReachCause::RouteUnreadable:
        return "route_unreadable";
    case ZeroReachCause::OsGateUnreadable:
        return "os_gate_unreadable";
    case ZeroReachCause::Quarantined:
        return "quarantined";
    case ZeroReachCause::PluginNotFound:
        return "plugin_not_found";
    case ZeroReachCause::KillSwitchedOs:
        return "kill_switched_os";
    case ZeroReachCause::Generic:
        return "no_agents_reached";
    }
    return "no_agents_reached";
}

/// True when retrying the same request can succeed (the MCP site pairs these
/// with `retry_after_ms` 5000); false when the cause is a caller error or a
/// permanent policy withhold (the MCP site pairs these with `retry_after_ms`
/// null). Generic is retryable, matching MCP: it mixes an offline device
/// (retryable) with a residual approval-denial race (permanent).
[[nodiscard]] constexpr bool zero_reach_retryable(ZeroReachCause cause) noexcept {
    switch (cause) {
    case ZeroReachCause::ContainmentUnreadable:
    case ZeroReachCause::RouteUnreadable:
    case ZeroReachCause::OsGateUnreadable:
    case ZeroReachCause::Generic:
        return true;
    case ZeroReachCause::InvalidScope:
    case ZeroReachCause::Quarantined:
    case ZeroReachCause::PluginNotFound:
    case ZeroReachCause::KillSwitchedOs:
        return false;
    }
    return false;
}

} // namespace yuzu::server
