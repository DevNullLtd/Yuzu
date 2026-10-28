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
/// chokepoints exist to prevent. It decides CLASS, and names the refusal
/// reasons of the second half. The freshness half is `require_enrolled_fresh_mfa`
/// (mfa_step_up.hpp, #6079): an ENROLLED factor with a proof no older than the approver
/// window (at most 300 s), reached through the route's `approver_mfa_fn`. It is deliberately NOT
/// `require_mfa_step_up`, which returns TRUE for `api_token` / `mcp_token` sessions,
/// for un-enrolled accounts and when the window is 0, so it can never be the gate
/// that refuses a bearer or an un-enrolled approver.
///
/// Positive allow-list, not a deny-list: a seventh `auth_source` added later is
/// refused here until someone decides it is an interactive, human, cookie-backed
/// session. SAML passes this class check and is then refused (#4935). Which refusal the
/// caller sees depends on whether the generic step-up check answers first; each reason has its
/// own condition under which the typed approver refusal is what surfaces:
///   - `mfa_not_enrolled`: always typed (the generic check passes an un-enrolled account);
///   - `saml_mfa_unsupported` and `account_unavailable`: typed with the step-up window at 0,
///     otherwise the generic check refuses a SAML session, or a deleted or deactivated
///     account, first (whatever the enforcement mode); `account_unavailable` also surfaces
///     when the account is removed between the central step-up check's read and the approver
///     rule's read;
///   - `mfa_proof_missing` (an SSO login with no MFA amr): typed with the step-up window at 0
///     or when `--mfa-enforcement` does not cover the caller's role.
/// A SAML session carries no MFA attestation in this release -- documented behaviour,
/// not a gap to patch here.
///
/// Pure decision code: no I/O, no store access, no response mutation.

#include "mfa_factor_state.hpp"

#include <yuzu/server/auth.hpp>

#include <string>
#include <string_view>

namespace yuzu::server::approval {

/// Why a session may not decide an approval. `kNone` == allowed (class only).
enum class ApproverRefusal {
    kNone,
    kEnginePrincipal,      ///< ADR-0031 engine principal (machine identity)
    kNonHumanPrincipal,    ///< principal_kind != "human"
    kNonInteractiveSession, ///< bearer (api_token / mcp_token) or any unrecognised auth_source
    kMfaNotEnrolled,        ///< local account with no enrolled MFA factor (#6079)
    kMfaProofMissing,       ///< SSO login whose IdP asserted no MFA method (#6079)
    kSamlMfaUnsupported,    ///< SAML sessions carry no MFA attestation (#4935, #6079)
    kMfaProofStale,         ///< proof older than the window or stamped before the enrolment (#6079)
    kAccountUnavailable     ///< account deactivated or no longer exists (#6079)
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
    case ApproverRefusal::kMfaNotEnrolled:
        return "mfa_not_enrolled";
    case ApproverRefusal::kMfaProofMissing:
        return "mfa_proof_missing";
    case ApproverRefusal::kSamlMfaUnsupported:
        return "saml_mfa_unsupported";
    case ApproverRefusal::kMfaProofStale:
        return "mfa_proof_stale";
    case ApproverRefusal::kAccountUnavailable:
        return "account_unavailable";
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

/// The refusal for a factor state that `require_enrolled_fresh_mfa` turned away
/// with `kRefuse`. `kEnrolledLocal` / `kIdpAttested` / `kStoreUnavailable` are not
/// refusals of this kind (the route handles the latter itself as a 503) and map to
/// `kNone`; the route coerces a `kNone` it receives for a `kRefuse` to
/// `kMfaNotEnrolled`, so an unmapped state still refuses.
[[nodiscard]] constexpr ApproverRefusal refusal_for_factor(MfaFactorState f) noexcept {
    switch (f) {
    case MfaFactorState::kNotEnrolled:
        return ApproverRefusal::kMfaNotEnrolled;
    case MfaFactorState::kNoIdpProof:
        return ApproverRefusal::kMfaProofMissing;
    case MfaFactorState::kSamlUnsupported:
        return ApproverRefusal::kSamlMfaUnsupported;
    case MfaFactorState::kNotInteractive:
        return ApproverRefusal::kNonInteractiveSession;
    case MfaFactorState::kAccountUnavailable:
        return ApproverRefusal::kAccountUnavailable;
    case MfaFactorState::kEnrolledLocal:
    case MfaFactorState::kIdpAttested:
    case MfaFactorState::kStoreUnavailable:
        return ApproverRefusal::kNone;
    }
    return ApproverRefusal::kNone; // unreachable; the route coerces kNone-on-refuse to refuse
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
