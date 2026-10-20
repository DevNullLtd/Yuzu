#pragma once

#include <string>

#include "agent_registry.hpp" // DispatchDenial / DispatchDenialReason, authz::to_string

/// @file dispatch_denial_text.hpp
/// The ONE helper that turns a `DispatchDenial` from the shared dispatch
/// chokepoint (`classify_and_authorize_dispatch`, via
/// `AuthorizeDispatchFn`) into an operator-readable message and remediation.
///
/// One helper, four intended callers: MCP's pre-dispatch dry run
/// (`mcp_server.cpp`), `POST` and `DELETE /api/v1/quarantine` (#6065 PR-Q), and -- in a
/// later change, not here -- the two REST copies in `command_routes.cpp` and
/// `server.cpp` that still spell these strings themselves. Those two are
/// folded in by #6065 PR-C, not by PR-Q. Until then REST serves the MCP-worded
/// remediation for `ApprovalRequired` (`DenialSurface::kRest` is accepted but
/// not yet consulted); PR-C owns the REST wording.
///
/// The returned class is surface-NEUTRAL (`DispatchDenialClass`): MCP maps it
/// to its JSON-RPC constants (`kInvalidParams` / `kPermissionDenied` /
/// `kInternalError`, `mcp_server.cpp` locals), REST maps it to 400 / 403 /
/// 500.
///
/// `DenialSurface` has NO default value, by design (the `RbacAdminSurface`
/// pattern): a new caller must say which surface it is, so wording that
/// later diverges per surface cannot silently inherit the wrong one. It is
/// accepted and unused today; PR-C differentiates the wording.

namespace yuzu::server {

enum class DenialSurface { kRest, kMcp };

enum class DispatchDenialClass { kInvalidParams, kPermissionDenied, kInternal };

/// #3687: the (class, message, remediation) a dispatch authorization dry run
/// answers with for each `detail::DispatchDenialReason` the shared chokepoint
/// can produce. `kApprovalRequired` (-32006) is deliberately NOT used for
/// `ApprovalRequired` on MCP -- that code's established contract (the
/// `approval_required_error` closure in `mcp_server.cpp`) MUST carry
/// `approval_id`/`status_url` for a caller to poll, and this dry run mints no
/// ticket (Decision 7: "no new ticket-mint surface"); `kPermissionDenied`
/// plus the machine-readable `reason` (added by the caller) carries the
/// discrimination instead. Every interpolated value below is either a server
/// literal, an already-classified `securable`/`operation` (bounded, closed
/// vocabularies, never caller text), or the caller's OWN `plugin`/`action`
/// arguments already bounds-checked above the call site.
struct DispatchDenialText {
    DispatchDenialClass cls;
    std::string message;
    std::string remediation;
};

[[nodiscard]] inline DispatchDenialText
describe_dispatch_denial(yuzu::server::detail::DispatchDenialReason reason,
                         const std::string& plugin, const std::string& action,
                         const yuzu::server::detail::DispatchDenial& denial,
                         DenialSurface /*surface*/) {
    using Reason = yuzu::server::detail::DispatchDenialReason;
    using Cls = DispatchDenialClass;
    switch (reason) {
    case Reason::Unclassified:
    case Reason::Ambiguous:
        // Byte-identical message to the C8 pre-mint site's own ClassifyMiss
        // arm and to REST's `/api/command` classification-error arm
        // (server.cpp) -- one literal, three call sites.
        return {Cls::kInvalidParams, "unknown or ambiguous plugin.action",
                "confirm the plugin/action name via discover_plugins or "
                "discover_instructions and re-call"};
    case Reason::AnonymousOperator:
        // `denial.securable`/`.operation` ARE populated for this reason
        // (DispatchDenial's own doc comment, agent_registry.hpp) but an
        // empty principal reaching here means caller_fn/derive_dispatch_caller
        // failed to resolve an identity for an authenticated session --
        // a wiring fault, not a caller mistake, so the remediation says so.
        return {Cls::kPermissionDenied,
                "dispatch denied: the caller has no resolved identity for " +
                    denial.securable + ":" +
                    std::string(yuzu::server::authz::to_string(denial.operation)),
                "this indicates a server-side identity-derivation fault, not a caller "
                "mistake; contact an administrator"};
    case Reason::Forbidden:
        // Same "permission denied: securable:operation" wording REST's
        // generic bucket already uses for this reason (server.cpp) -- kept
        // identical so an operator who has seen the REST message recognizes
        // this one.
        return {Cls::kPermissionDenied,
                "permission denied: " + denial.securable + ":" +
                    std::string(yuzu::server::authz::to_string(denial.operation)),
                "the dispatching caller lacks this grant; request it, or dispatch as "
                "a caller who holds it"};
    case Reason::ApprovalRequired:
        return {Cls::kPermissionDenied,
                "approval required for " + plugin + "." + action +
                    " — this action requires either an admin caller or a redeemed "
                    "approval ticket that this dispatch does not carry",
                "re-call using a supervised-tier MCP token, which mints and polls an "
                "approval ticket for this class of call, or dispatch as an admin caller"};
    case Reason::KillSwitched:
        return {Cls::kPermissionDenied,
                "dispatch denied: the per-action kill switch is OFF for " + plugin + "." +
                    action,
                "an operator has thrown an emergency stop for this plugin.action "
                "(set_plugin_kill_switch / PUT .../kill-switch); it must be re-enabled "
                "before this call can dispatch"};
    }
    // No default: arm -- so a future 7th reason is a -Werror=switch build
    // failure here, not a silent generic fallback.
    return {Cls::kInternal, "dispatch denied", {}};
}

} // namespace yuzu::server
