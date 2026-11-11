#pragma once

// dispatch_denial.hpp -- the typed refusal of ServerImpl::build_classified_command.
//
// Lives in its own header (moved verbatim from agent_registry.hpp) so the
// dispatch layer (`dispatch_confined_arms.hpp`, which agent_registry.hpp's
// consumers include) can carry a `DispatchDenial` on `ConfinedDispatchOutcome`
// without including the registry. agent_registry.hpp includes this header, so
// every existing consumer of the names below compiles unchanged.

#include <cstdint>
#include <string>
#include <string_view>

#include "authz_model.hpp"

namespace yuzu::server::detail {

/// Why `ServerImpl::build_classified_command` refused a dispatch. Every
/// value is counted separately by the caller (ADR-0033 §2: "never a
/// permissive default") — `Unclassified`/`Ambiguous` mirror
/// `ClassificationError` 1:1; `AnonymousOperator`/`Forbidden` are this
/// package's own authorization arm.
enum class DispatchDenialReason : uint8_t {
    Unclassified,      ///< No `CommandCapability` row matches `plugin.action`
                       ///< (also raised for a row whose `execute_gate` parsed
                       ///< as `ExecuteGate::Unspecified` — #1398 defense in
                       ///< depth; see `command_capability.hpp`. That should be
                       ///< IMPOSSIBLE by construction — every fragment's own
                       ///< compile-time sweep makes an omitted `.execute_gate`
                       ///< a build failure — so reaching this arm at runtime
                       ///< means that sweep itself is broken, not that this
                       ///< row is merely unclassified in the ordinary sense).
    Ambiguous,         ///< Two+ fragments independently declared the same row.
    AnonymousOperator, ///< `caller.system == false` with an empty `principal`.
    Forbidden,         ///< Classified, but `caller` may not issue it — either an
                       ///< operator lacking the resolved securable/operation, or
                       ///< ANY operator attempting a `system_reserved` row.
    ApprovalRequired,  ///< #1398: classified and RBAC-authorized, but `cap
                       ///< .execute_gate` requires proof of an approval
                       ///< decision (`DispatchCaller::approval_provenance`)
                       ///< the caller does not carry — `AdminOrApproval`
                       ///< additionally admits an effective-admin caller with
                       ///< no provenance at all; `AlwaysApproval` never does.
                       ///< Deliberately AFTER `Forbidden` in evaluation order:
                       ///< approval is never a substitute for a missing RBAC
                       ///< grant, only for the ADDITIONAL gate on top of one.
    KillSwitched,      ///< Classified and authorized, but the per-action kill
                       ///< switch is OFF for this `plugin.action` (or the config
                       ///< store is degraded, which `action_allowed` reports as
                       ///< disabled — never as enabled; never a protective
                       ///< action — `yuzu::protective`). Deliberately DISTINCT
                       ///< from `Forbidden`: this is an operator-thrown
                       ///< emergency stop, not an authorization verdict, and an
                       ///< incident review needs to tell the two apart.
};

/// A refused dispatch. `securable`/`operation` are populated only once
/// classification itself succeeded — `Unclassified`/`Ambiguous` carry no
/// resolved securable, there is nothing to name yet (a caller
/// logging/auditing a denial must branch on `reason` before trusting
/// `securable`). `AnonymousOperator` and `Forbidden` are raised AFTER
/// classification resolved, so both DO name the securable the caller failed
/// to satisfy — that is what makes the audit line actionable.
///
/// `securable` owns its characters rather than viewing `CommandCapability`'s
/// static storage: a denial is the exceptional path, and the consumers
/// concatenate it into operator-facing messages.
struct DispatchDenial {
    DispatchDenialReason reason;
    std::string securable;
    authz::Operation operation{authz::Operation::Read};
};

/// The ONE string form of a `DispatchDenialReason` — snake_case, matching
/// the existing `yuzu_server_dispatch_denied_total{reason=...}` metric label
/// values (unchanged by #1398; this function only deduplicates the mapping,
/// it does not relabel anything already in production dashboards/alerts).
/// Used for BOTH the metric label and the route-local audit detail
/// (`server.cpp`'s `/api/command` handler) — an incident review needs the
/// SAME string in both places to correlate a metric spike with the audit
/// rows that produced it, and a single source avoids the two silently
/// drifting apart the way a hand-duplicated switch invites. No `default:`
/// case (see `authz::to_string` in `authz_model.hpp` for the same pattern)
/// so `-Werror=switch` catches a future `DispatchDenialReason` enumerator
/// added here without a matching label.
[[nodiscard]] constexpr std::string_view to_string(DispatchDenialReason reason) {
    switch (reason) {
        case DispatchDenialReason::Unclassified: return "unclassified";
        case DispatchDenialReason::Ambiguous: return "ambiguous";
        case DispatchDenialReason::AnonymousOperator: return "anonymous_operator";
        case DispatchDenialReason::Forbidden: return "forbidden";
        case DispatchDenialReason::ApprovalRequired: return "approval_required";
        case DispatchDenialReason::KillSwitched: return "kill_switched";
    }
    return "";
}

} // namespace yuzu::server::detail
