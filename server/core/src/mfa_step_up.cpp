/// @file mfa_step_up.cpp — see header for the gate contract.

#include "mfa_step_up.hpp"

#include "step_up_gate.hpp"
#include "web_utils.hpp" // audit_token / log_safe: session.username is IdP- or operator-controlled

#include <yuzu/metrics.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <string_view>

namespace yuzu::server {

bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db, int window_secs,
                         const StepUpAuditFn& audit_fn, const std::string& action_label,
                         std::string_view mfa_enforcement, yuzu::MetricsRegistry* metrics) {
    // Thin wrapper: the decision lives in decide_step_up (step_up_gate.cpp, pure), the wire
    // shape in render_step_up_refusal. The in-handler gate speaks the REST envelope on every
    // surface, and on an htmx request render_step_up_refusal also sets the error toast (every
    // non-MCP surface does). The Settings handlers' own toast call is guarded against setting a
    // second HX-Trigger.
    const auto verdict = decide_step_up(session, auth_db, window_secs, mfa_enforcement);
    if (verdict.passed())
        return true;
    emit_step_up_refusal_effects(req, verdict, audit_fn, action_label, {}, metrics);
    render_step_up_refusal(req, res, verdict, StepUpSurface::kRest);
    return false;
}

namespace detail {

ProofAge mfa_proof_age(const auth::Session& session, std::chrono::seconds effective_window) {
    // Compute proof age against the LOCAL MONOTONIC anchor derived at
    // cache-populate from the DB clock (ADR-2002 §4 DB-clock authority, WS-1/1a):
    // `steady_mfa_verified` is set to `steady_now - (db_now - mfa_verified_ms)` in
    // derive_session_deadlines, immune to local wall skew/steps. Its {} sentinel
    // means "no usable MFA proof" — derive sets it {} for BOTH an absent proof AND
    // a FUTURE-DATED proof (`mfa_verified_ms > db_now`, a backward DB step below
    // the proof instant → fail CLOSED, never a spurious-fresh window). So the
    // future-dated rejection is already applied; this just reads the sentinel.
    ProofAge out;
    const auto now = std::chrono::steady_clock::now();
    out.no_proof = session.steady_mfa_verified.time_since_epoch().count() == 0;
    const auto age = out.no_proof ? std::chrono::seconds::max()
                                  : std::chrono::duration_cast<std::chrono::seconds>(
                                        now - session.steady_mfa_verified);
    // Suspend backstop (parity with is_elevated / validate, ADR-2002 §4 / design-
    // review H5 + LOW-1): the freshness age above is on steady_clock, which pauses
    // across host/VM suspend — so a stale proof could read fresh after a resume.
    // Also require the ABSOLUTE (wall) proof age not be grossly past the window,
    // consulted only with the generous auth::kWallSanitySkew slack so a merely
    // clock-SKEWED (non-suspended) replica is never affected (only a long suspend,
    // where wall advanced far past the window while steady froze, trips it).
    const auto wall_age = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - session.mfa_verified_at);
    out.wall_stale = wall_age > effective_window + auth::kWallSanitySkew;
    out.fresh = !out.no_proof && age <= effective_window && !out.wall_stale;
    // Audit detail: `age` may be seconds::max() in the no-proof case; report -1.
    out.age_secs = out.no_proof ? -1 : age.count();
    out.age_ms = out.no_proof ? -1
                              : std::chrono::duration_cast<std::chrono::milliseconds>(
                                    now - session.steady_mfa_verified)
                                    .count();
    return out;
}

void write_step_up_challenge(const httplib::Request& req, httplib::Response& res,
                             const auth::Session& session, bool is_oidc,
                             const StepUpAuditFn& audit_fn, const std::string& action_label,
                             long long age_secs, int window_secs, std::string_view extra_detail) {
    // The approver gate's challenge speaks the same envelope as the generic gate: one verdict,
    // one renderer (`render_step_up_refusal`, which carries the local-vs-SSO challenge URL and
    // the correlation id) and one audit writer (`emit_step_up_refusal_effects`). Only the audit
    // detail suffix is the approver gate's own. The subject is neutralised (CWE-117) by
    // emit_step_up_refusal_effects for every step-up refusal.
    StepUpVerdict verdict;
    verdict.decision = StepUpDecision::kChallenge;
    verdict.is_oidc = is_oidc;
    verdict.user = session.username;
    verdict.age_secs = age_secs;
    verdict.window_secs = window_secs;
    std::string suffix;
    if (!extra_detail.empty()) {
        suffix += ' ';
        suffix += extra_detail;
    }
    emit_step_up_refusal_effects(req, verdict, audit_fn, action_label, suffix, nullptr);
    render_step_up_refusal(req, res, verdict, StepUpSurface::kRest);
}

} // namespace detail

MfaFactorProbe probe_mfa_factor(const auth::Session& session, AuthDB& auth_db) {
    if (session.auth_source == "saml")
        return {MfaFactorState::kSamlUnsupported, 0};
    if (session.auth_source == "oidc") {
        // An SSO identity has no local `users` row to consult; its only evidence is the
        // `amr`-seeded proof /auth/callback stamped on the session.
        const bool has_proof = session.steady_mfa_verified.time_since_epoch().count() != 0;
        return {has_proof ? MfaFactorState::kIdpAttested : MfaFactorState::kNoIdpProof, 0};
    }
    if (session.auth_source != "local")
        return {MfaFactorState::kNotInteractive, 0};

    auto status = auth_db.mfa_status(session.username);
    if (!status) {
        if (is_store_unavailable(status.error()))
            return {MfaFactorState::kStoreUnavailable, 0};
        // mfa_status reads active rows only: a deactivated or deleted account (or a name that
        // is not a valid username) is a different remedy from "not enrolled", so it gets its
        // own state. Still a refusal; never a pass.
        if (status.error() == AuthDBError::UserNotFound ||
            status.error() == AuthDBError::InvalidUsername)
            return {MfaFactorState::kAccountUnavailable, 0};
        return {MfaFactorState::kNotEnrolled, 0};
    }
    if (!status->enrolled)
        return {MfaFactorState::kNotEnrolled, 0};
    // `enrolled` implies a non-NULL enrolment instant, which reads back as a positive epoch
    // ms. A non-positive value would silently skip the pre-enrolment proof check in
    // require_enrolled_fresh_mfa, so it is treated as an unreadable row (fail closed).
    if (status->enrolled_at_ms <= 0)
        return {MfaFactorState::kStoreUnavailable, 0};
    return {MfaFactorState::kEnrolledLocal, status->enrolled_at_ms};
}

ApproverMfaOutcome require_enrolled_fresh_mfa(const httplib::Request& req, httplib::Response& res,
                                              const auth::Session& session, AuthDB& auth_db,
                                              int configured_window_secs,
                                              const StepUpAuditFn& audit_fn,
                                              const std::string& action_label,
                                              const auth::DurableMfaProof& durable,
                                              yuzu::MetricsRegistry* metrics) {
    using Kind = ApproverMfaOutcome::Kind;
    using Source = auth::DurableMfaProof::Source;
    const auto probe = probe_mfa_factor(session, auth_db);
    const auto store_unavailable = [&](const char* what) -> ApproverMfaOutcome {
        spdlog::error("require_enrolled_fresh_mfa: {}({}) unavailable - failing closed", what,
                      log_safe(session.username));
        if (metrics) {
            metrics->counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}})
                .increment();
        }
        return {Kind::kStoreUnavailable, MfaFactorState::kStoreUnavailable};
    };
    switch (probe.state) {
    case MfaFactorState::kEnrolledLocal:
    case MfaFactorState::kIdpAttested:
        break;
    case MfaFactorState::kStoreUnavailable:
        return store_unavailable("mfa_status");
    default:
        return {Kind::kRefuse, probe.state};
    }
    // A degraded durable-proof read cannot tell a fresh proof from an over-age one: refuse
    // as unavailable (503, retryable), never as "no proof" (401 step-up the user cannot fix).
    if (durable.source == Source::kUnavailable)
        return store_unavailable("durable mfa proof");

    // One window for the age test and the challenge: min(configured, 300 s).
    const int window_secs = approver_step_up_window(configured_window_secs);
    const long long window_ms = static_cast<long long>(window_secs) * 1000;
    const auto proof = detail::mfa_proof_age(session, std::chrono::seconds(window_secs));

    // The ceiling is hard to the millisecond and has NO suspend/skew allowance. The monotonic
    // anchor in `session` is suspend-blind and `mfa_proof_age`'s wall backstop tolerates
    // auth::kWallSanitySkew (5 min), so on their own a proof 10 s old on the steady clock and
    // 450 s old in elapsed time passes a 300 s window. A kRow closes that: age = db_now -
    // mfa_verified in ONE SELECT on the database clock, which a paused VM cannot stretch. The
    // cached monotonic check is kept as well (a stricter, never a looser, second condition),
    // so both clocks must agree the proof is in the window. The replica's raw system_clock is
    // never consulted. An SSO session's durable instant is the IdP `iat` clamped to this
    // replica's clock at login, so a replica running ahead of the database can store a proof
    // the database reads as future-dated. A future-dated durable instant is refused here; for
    // a freshly minted or loaded session the same condition has already left no cached proof
    // (derive_session_deadlines), which probe_mfa_factor reports before this point (an SSO
    // session: mfa_proof_missing). kAbsent (no durable session, or another principal's) has no
    // proof to age. kUnavailable (a degraded read, or no SessionStore attached) was refused
    // above, so only kRow and kAbsent reach here.
    bool within_window = false;
    std::int64_t proof_ms = 0;
    bool has_proof = false;
    long long age_secs = proof.age_secs;
    if (durable.source == Source::kRow) {
        proof_ms = durable.mfa_verified_ms;
        has_proof = proof_ms > 0;
        const long long durable_age_ms = durable.db_now_ms - durable.mfa_verified_ms;
        const bool durable_fresh = has_proof && durable_age_ms >= 0 && durable_age_ms <= window_ms;
        within_window = durable_fresh && !proof.no_proof && proof.age_ms <= window_ms;
        if (has_proof && durable_age_ms >= 0)
            age_secs = std::max<long long>(proof.age_secs, durable_age_ms / 1000);
    }

    // A local proof stamped before the CURRENT enrolment was made under a factor that has
    // since been cleared (disable / reset) or replaced; it says nothing about this one.
    // Equal passes: both instants are authored by the same database clock at ms resolution.
    const bool predates =
        probe.state == MfaFactorState::kEnrolledLocal && has_proof && proof_ms < probe.enrolled_at_ms;

    if (within_window && !predates)
        return {Kind::kPass, probe.state};

    detail::write_step_up_challenge(req, res, session, session.auth_source == "oidc",
                                    audit_fn, action_label, age_secs, window_secs,
                                    predates ? "reason=proof_predates_enrolment"
                                             : std::string_view{});
    return {Kind::kChallengeWritten, probe.state};
}

bool amr_asserts_mfa(const std::vector<std::string>& amr) {
    // RFC 8176 method references that constitute (or imply) a factor
    // beyond a shared secret, plus Entra's non-standard "mfa" aggregate.
    // Matches the allowlist documented in docs/auth-mfa-design.md "OIDC
    // interop". Deliberately EXCLUDED:
    //   - "pwd": the single factor step-up exists to strengthen.
    //   - "pin"/"user": single-factor presence/knowledge (device-unlock PIN,
    //     "user presence") — not a second factor. Admitting them let a
    //     non-MFA login satisfy the gate (governance UP-7). "sms"/"tel" are
    //     weak but ARE a possession-based second factor, so they stay; a
    //     future --mfa-oidc-amr-strong flag can tighten further.
    static constexpr std::string_view kMfaMethods[] = {"mfa",  "otp", "hwk", "face",
                                                       "fpt",  "iris", "sms", "swk",
                                                       "tel"};
    for (const auto& m : amr) {
        for (const auto& known : kMfaMethods) {
            if (m == known) {
                return true;
            }
        }
    }
    return false;
}

bool mfa_enforcement_protects(std::string_view mode, auth::Role role) {
    if (mode == "required") {
        return true;
    }
    if (mode == "admin-only") {
        return role == auth::Role::admin;
    }
    // "optional", or any value CLI validation should have rejected → not
    // enforced. Fail-safe: an unexpected mode never silently locks anyone
    // out, and CLI11 IsMember already rejects unknown values at startup.
    return false;
}

} // namespace yuzu::server
