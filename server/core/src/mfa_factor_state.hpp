#pragma once

/// @file mfa_factor_state.hpp
///
/// Vocabulary for the approver MFA gate (#6079): what second factor a session
/// stands on, the approver freshness ceiling, and the gate's outcome. Pure
/// value types and constexpr helpers (no I/O, no store access) so that
/// `approver_assurance.hpp` can name the states without pulling in AuthDB.
/// The probe and the gate that produce these live in `mfa_step_up.hpp`.
///
/// Also home to the two pure judgements every MFA gate shares, so that no gate keeps a
/// private copy of either rule: `judge_local_mfa_binding` (is the stored proof bound to the
/// factor that is enrolled right now) and `durable_proof_age` (is it inside the window on
/// the database clock). Neither performs I/O or reads a clock; the caller supplies the
/// durable read and the current factor generation.

#include <yuzu/server/auth.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string_view>

namespace httplib {
struct Request;
} // namespace httplib

namespace yuzu::server {

/// The second factor a session stands on, as seen by the approver gate. The
/// zero value is the refusing one: a value-initialised state never admits.
enum class MfaFactorState : std::uint8_t {
    kNotEnrolled = 0,   ///< local account with no enrolled factor
    kEnrolledLocal,     ///< local account with an enrolled TOTP factor
    kIdpAttested,       ///< OIDC session carrying an IdP `amr`-seeded proof
    kNoIdpProof,        ///< OIDC session with no usable `amr`-seeded proof
    kSamlUnsupported,   ///< SAML carries no MFA attestation in this release (#4935)
    kNotInteractive,    ///< any other auth_source (bearer, engine, unknown)
    kStoreUnavailable,  ///< the enrolment read failed (outage, undecryptable secret, or an
                        ///< enrolled row with no usable factor generation)
    kAccountUnavailable, ///< local session whose account is deactivated, deleted or malformed
};

/// `factor_gen`, `db_now_ms` and `binding_enforced` are meaningful only for `kEnrolledLocal`
/// (0 / 0 / true otherwise; a probe never reports `kEnrolledLocal` with a non-positive
/// `factor_gen`). They are read from `AuthDB::MfaStatus` in the same statement: `factor_gen` is
/// the account's database-owned factor generation, `db_now_ms` the database clock at that
/// read, and `binding_enforced` false once the generation trigger has been observed not firing.
struct MfaFactorProbe {
    MfaFactorState state{MfaFactorState::kNotEnrolled};
    std::int64_t factor_gen{0};
    std::int64_t db_now_ms{0};
    bool binding_enforced{true};
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

/// How a local session's stored MFA proof relates to the factor enrolled right now.
enum class LocalMfaBinding : std::uint8_t {
    kBound,       ///< the proof records exactly the current factor generation
    kNoProof,     ///< the durable row carries no proof (absent row, other principal, or 0 instant)
    kUnbound,     ///< a proof with no generation (legacy row, or a write the rebind guard unbound)
    kMismatch,    ///< bound to a generation that is no longer the account's
    kUnavailable, ///< the durable read is degraded or unusable: no decision can be made (503)
    kUnenforced,  ///< the generation trigger is not observed in force: no decision (503)
};

struct LocalMfaBindingJudgement {
    LocalMfaBinding kind{LocalMfaBinding::kUnavailable};
    /// The audit / remediation token for a refusal; empty for `kBound`.
    std::string_view reason{};
};

/// The ONE binding decision (a second copy in any gate is the drift this seam exists to
/// remove). Pure: `durable` is the caller's per-request read of the session's stored proof,
/// `current_factor_gen` the account's generation read for the same request, and
/// `binding_enforced` the same read's `MfaStatus::binding_enforced`. Precedence is fixed:
/// an unusable read (including a row whose database clock is non-positive) and an
/// unenforced trigger both make the proof undecidable, before any statement about the proof
/// itself; then absence, then missing binding, then inequality. Equality is the only
/// `kBound`; a generation is never ordered (a proof bound to a higher value than the
/// account's is as foreign as a lower one).
[[nodiscard]] constexpr LocalMfaBindingJudgement
judge_local_mfa_binding(const auth::DurableMfaProof& durable, std::int64_t current_factor_gen,
                        bool binding_enforced) noexcept {
    using Source = auth::DurableMfaProof::Source;
    if (durable.source == Source::kUnavailable ||
        (durable.source == Source::kRow && durable.db_now_ms <= 0))
        return {LocalMfaBinding::kUnavailable, "mfa_proof_unavailable"};
    if (!binding_enforced)
        return {LocalMfaBinding::kUnenforced, "mfa_binding_unenforced"};
    if (durable.source != Source::kRow || durable.mfa_verified_ms <= 0)
        return {LocalMfaBinding::kNoProof, "mfa_proof_missing"};
    if (durable.mfa_factor_gen <= 0)
        return {LocalMfaBinding::kUnbound, "proof_factor_unbound"};
    if (current_factor_gen <= 0 || durable.mfa_factor_gen != current_factor_gen)
        return {LocalMfaBinding::kMismatch, "proof_factor_mismatch"};
    return {LocalMfaBinding::kBound, {}};
}

/// Result of `durable_proof_age`.
struct DurableProofAge {
    bool fresh{false};
    /// Whole seconds (age_ms / 1000, floored) on the database clock; -1 when the row yields
    /// no usable age (absent, no proof, future-dated, non-positive database clock).
    long long age_secs{-1};
};

/// Age of the stored proof on the DATABASE clock against `window_ms`. Fresh only for a `kRow`
/// with a proof whose age `db_now_ms - mfa_verified_ms` lies in [0, window_ms] (inclusive at
/// both ends: the same millisecond is age 0, exactly the window is fresh, one more is not).
/// Anything else, a future-dated instant included, is not fresh. No skew allowance and no
/// replica clock: a suspended host or paused VM cannot stretch it.
[[nodiscard]] constexpr DurableProofAge durable_proof_age(const auth::DurableMfaProof& durable,
                                                          long long window_ms) noexcept {
    if (durable.source != auth::DurableMfaProof::Source::kRow || durable.mfa_verified_ms <= 0 ||
        durable.db_now_ms <= 0)
        return {};
    const long long age_ms = durable.db_now_ms - durable.mfa_verified_ms;
    if (age_ms < 0)
        return {};
    return {age_ms <= window_ms, age_ms / 1000};
}

/// The per-request read of the stored MFA proof of the session that authenticated `req`
/// (`AuthRoutes::durable_mfa_proof_for` in production). The step-up gates take it as an injected
/// provider, exactly like `MfaStatusFn`, so the decision stays pure and a test supplies a fake.
using DurableProofFn =
    std::function<auth::DurableMfaProof(const httplib::Request&, const auth::Session&)>;

/// What the generic step-up gate admitted, for the one handler that mutates a factor under that
/// admission (the two `kFactorCredential` rows): the account's CURRENT factor generation as the
/// gate read it, to be compared again inside the mutation's own transaction. `local` is true only
/// when a local account was judged (enrolled or not); every other principal class leaves it false,
/// and a value-initialised admission admits nothing. For an enrolled account the bound-proof
/// judgement made `factor_gen` equal to the proof's; for an un-enrolled one (cancelling a
/// provisional enrolment) it is the generation as read (0 for a never-enrolled account).
struct StepUpAdmission {
    bool local{false};
    std::int64_t factor_gen{0};
};

/// What `require_enrolled_fresh_mfa` did. Only `kPass` lets the request
/// proceed; the zero value is `kRefuse`, so a value-initialised outcome (an
/// unset closure result) never admits.
struct ApproverMfaOutcome {
    enum class Kind : std::uint8_t {
        kRefuse = 0,       ///< no usable second factor; nothing was written to the response
        kStoreUnavailable, ///< the enrolment read failed; nothing was written to the response
        kChallengeWritten, ///< the proof is stale, unbound, or bound to another factor
                           ///< generation; a 401 was written
        kProofClockSkew,   ///< an SSO proof dated after the database clock; nothing was written
                           ///< to the response (a server-side clock fault, not a store fault)
        kPass,             ///< enrolled and fresh
    };
    Kind kind{Kind::kRefuse};
    MfaFactorState factor{MfaFactorState::kNotEnrolled};
};

static_assert(ApproverMfaOutcome{}.kind == ApproverMfaOutcome::Kind::kRefuse,
              "a value-initialised outcome must refuse");
static_assert(LocalMfaBindingJudgement{}.kind == LocalMfaBinding::kUnavailable,
              "a value-initialised judgement must be the undecidable one, never kBound");

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
