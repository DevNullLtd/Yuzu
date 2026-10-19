#pragma once

/// @file approver_assurance.hpp
///
/// Who may DECIDE an approval ticket (#6061, four-eyes MVP PR1). Approving or
/// rejecting is the human half of a four-eyes control: the whole point is that a
/// second PERSON, interactively authenticated, looked at the request. A bearer
/// credential (API token, MCP token) is a replayable secret held by automation
/// or by the very agentic worker that raised the request, and an ADR-0031 engine
/// principal is a machine by definition, so neither can stand in for that
/// person -- even when RBAC grants the principal `Approval:Approve`.
///
/// This header is the ONE predicate for that class decision. The REST approve and
/// reject routes (`approval_routes.cpp`, which the dashboard also drives) and the
/// MCP `approve_request` / `reject_request` handlers (`mcp_server.cpp`) all call
/// it; a second copy is the drift the dispatch-targeting and topology-floor
/// chokepoints exist to prevent. It decides CLASS only. The freshness half --
/// MFA step-up -- is `require_mfa_step_up` (mfa_step_up.hpp), reached through a
/// `StepUpFn`; the two are deliberately separate because step-up returns TRUE
/// for `api_token` / `mcp_token` sessions (the bearer "is" the step-up moment),
/// so it can never be the gate that refuses a bearer.
///
/// Positive allow-list, not a deny-list: a seventh `auth_source` added later is
/// refused here until someone decides it is an interactive, human, cookie-backed
/// session. SAML passes this class check and is then refused by step-up
/// (`saml_session_no_mfa_this_release`) while step-up is enabled -- documented
/// behaviour, not a gap to patch here.
///
/// Pure decision code: no I/O, no store access, no response mutation.

#include <yuzu/server/auth.hpp>

#include <string>
#include <string_view>

namespace yuzu::server::approval {

/// Why a session may not decide an approval. `kNone` == allowed (class only).
enum class ApproverRefusal {
    kNone,
    kEnginePrincipal,      ///< ADR-0031 engine principal (machine identity)
    kNonHumanPrincipal,    ///< principal_kind != "human"
    kNonInteractiveSession ///< bearer (api_token / mcp_token) or any unrecognised auth_source
};

/// Stable, machine-readable prefix of the A4 `message` on every refusal. Pinned
/// by the tests; an agentic worker keys off `<prefix>:<reason>` rather than
/// parsing prose. Do not reword.
inline constexpr std::string_view kApproverAssuranceMessage = "approver_assurance_required";

/// Stable reason token for `r` (the part after the colon in the message).
[[nodiscard]] constexpr std::string_view approver_refusal_reason(ApproverRefusal r) noexcept {
    switch (r) {
    case ApproverRefusal::kNone:
        return "none";
    case ApproverRefusal::kEnginePrincipal:
        return "engine_principal";
    case ApproverRefusal::kNonHumanPrincipal:
        return "non_human_principal";
    case ApproverRefusal::kNonInteractiveSession:
        return "non_interactive_session";
    }
    return "non_interactive_session"; // unreachable; fail closed on a future enumerator
}

/// Full A4 `message` for a refusal: "approver_assurance_required:<reason>".
[[nodiscard]] inline std::string approver_refusal_message(ApproverRefusal r) {
    std::string m(kApproverAssuranceMessage);
    m += ':';
    m += approver_refusal_reason(r);
    return m;
}

/// Class check. Engine is tested first so an engine session is always reported
/// as such, whatever else about it is also wrong.
[[nodiscard]] inline ApproverRefusal check_approver_class(const auth::Session& s) noexcept {
    if (s.is_engine())
        return ApproverRefusal::kEnginePrincipal;
    if (s.principal_kind != "human")
        return ApproverRefusal::kNonHumanPrincipal;
    if (s.auth_source != "local" && s.auth_source != "oidc" && s.auth_source != "saml")
        return ApproverRefusal::kNonInteractiveSession;
    return ApproverRefusal::kNone;
}

} // namespace yuzu::server::approval
