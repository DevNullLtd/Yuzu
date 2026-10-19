#pragma once

/// @file mfa_factor_state.hpp
///
/// Vocabulary for the approver MFA gate (#6079): what second factor a session
/// stands on, the approver freshness ceiling, and the gate's outcome. Pure
/// value types and constexpr helpers (no I/O, no store access) so that
/// `approver_assurance.hpp` can name the states without pulling in AuthDB.
/// The probe and the gate that produce these live in `mfa_step_up.hpp`.

#include <algorithm>
#include <cstdint>

namespace yuzu::server {

/// The second factor a session stands on, as seen by the approver gate. The
/// zero value is the refusing one: a value-initialised state never admits.
enum class MfaFactorState : std::uint8_t {
    kNotEnrolled = 0,   ///< local account with no enrolled factor (or an unreadable account row)
    kEnrolledLocal,     ///< local account with an enrolled TOTP factor
    kIdpAttested,       ///< OIDC session carrying an IdP `amr`-seeded proof
    kNoIdpProof,        ///< OIDC session with no usable `amr`-seeded proof
    kSamlUnsupported,   ///< SAML carries no MFA attestation in this release (#4935)
    kNotInteractive,    ///< any other auth_source (bearer, engine, unknown)
    kStoreUnavailable,  ///< the enrolment read failed (outage or undecryptable secret)
};

/// `enrolled_at_ms` is meaningful only for `kEnrolledLocal` (0 otherwise).
struct MfaFactorProbe {
    MfaFactorState state{MfaFactorState::kNotEnrolled};
    std::int64_t enrolled_at_ms{0};
};

/// Hard ceiling on how old an MFA proof may be to decide an approval. A
/// configured `--mfa-step-up-window-secs` can only tighten it.
inline constexpr int kApproverStepUpCeilingSecs = 300;

/// Effective approver window: the configured step-up window capped at the
/// ceiling, and the ceiling itself when the setting is 0 (gate disabled for
/// other routes) or negative.
[[nodiscard]] constexpr int approver_step_up_window(int configured) noexcept {
    return configured > 0 ? (std::min)(configured, kApproverStepUpCeilingSecs)
                          : kApproverStepUpCeilingSecs;
}

/// What `require_enrolled_fresh_mfa` did. Only `kPass` lets the request
/// proceed; the zero value is `kRefuse`, so a value-initialised outcome (an
/// unset closure result) never admits.
struct ApproverMfaOutcome {
    enum class Kind : std::uint8_t {
        kRefuse = 0,       ///< no usable second factor; nothing was written to the response
        kStoreUnavailable, ///< the enrolment read failed; nothing was written to the response
        kChallengeWritten, ///< the proof is stale or predates the enrolment; a 401 was written
        kPass,             ///< enrolled and fresh
    };
    Kind kind{Kind::kRefuse};
    MfaFactorState factor{MfaFactorState::kNotEnrolled};
};

static_assert(ApproverMfaOutcome{}.kind == ApproverMfaOutcome::Kind::kRefuse,
              "a value-initialised outcome must refuse");

} // namespace yuzu::server
