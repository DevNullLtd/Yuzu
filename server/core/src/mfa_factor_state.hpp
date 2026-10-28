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
    kNotEnrolled = 0,    ///< local account with no enrolled factor
    kEnrolledLocal,      ///< local account with an enrolled TOTP factor
    kIdpAttested,        ///< OIDC session carrying an IdP `amr`-seeded proof
    kNoIdpProof,         ///< OIDC session with no usable `amr`-seeded proof
    kSamlUnsupported,    ///< SAML carries no MFA attestation in this release (#4935)
    kNotInteractive,     ///< any other auth_source (bearer, engine, unknown)
    kStoreUnavailable,   ///< the enrolment read failed (outage, undecryptable secret, or an
                         ///< enrolled row with no usable enrolment instant)
    kAccountUnavailable, ///< local session whose account is deactivated, deleted or malformed
};

/// `enrolled_at_ms` is meaningful only for `kEnrolledLocal` (0 otherwise; a probe never
/// reports `kEnrolledLocal` with a non-positive value).
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
        kProofClockSkew,   ///< an SSO proof dated after the database clock; nothing was written
                           ///< to the response (a server-side clock fault, not a store fault)
        kPass,             ///< enrolled and fresh
    };
    Kind kind{Kind::kRefuse};
    MfaFactorState factor{MfaFactorState::kNotEnrolled};
};

static_assert(ApproverMfaOutcome{}.kind == ApproverMfaOutcome::Kind::kRefuse,
              "a value-initialised outcome must refuse");

// Pin the enumerator values. `handle_review` (approval_routes.cpp) switches on Kind and sends
// every enumerator it does not name through its `default:` refuse arm, so a new enumerator
// would silently refuse with the generic 403 (fail closed) instead of getting its own arm.
// Reordering the five, or inserting one before kPass, fails the build here. APPENDING one
// does NOT: the five values stay unchanged. In either case the next editor must add a `case`
// to `handle_review`, add a row to the Sec-Audit-Failed table in test_approval_routes.cpp,
// and extend these pins.
namespace approver_mfa_kind_pin {
using Kind = ApproverMfaOutcome::Kind;
static_assert(static_cast<int>(Kind::kRefuse) == 0 &&
                  static_cast<int>(Kind::kStoreUnavailable) == 1 &&
                  static_cast<int>(Kind::kChallengeWritten) == 2 &&
                  static_cast<int>(Kind::kProofClockSkew) == 3 &&
                  static_cast<int>(Kind::kPass) == 4,
              "ApproverMfaOutcome::Kind changed: update handle_review's switch "
              "(approval_routes.cpp) and its tests, then these pins");
} // namespace approver_mfa_kind_pin

} // namespace yuzu::server
