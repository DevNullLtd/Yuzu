/// @file mfa_step_up.cpp — see header for the gate contract.

#include "mfa_step_up.hpp"

#include "step_up_gate.hpp"

#include <httplib.h>

#include <string_view>

namespace yuzu::server {

bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db, int window_secs,
                         const StepUpAuditFn& audit_fn, const std::string& action_label,
                         std::string_view mfa_enforcement, yuzu::MetricsRegistry* metrics) {
    // Thin wrapper: the decision lives in decide_step_up (step_up_gate.cpp, pure), the wire
    // shape in render_step_up_refusal. The in-handler gate speaks the REST envelope on every
    // surface and adds no htmx toast (the Settings handlers add their own).
    const auto verdict = decide_step_up(session, auth_db, window_secs, mfa_enforcement);
    if (verdict.passed())
        return true;
    emit_step_up_refusal_effects(req, verdict, audit_fn, action_label, {}, metrics);
    render_step_up_refusal(req, res, verdict, StepUpSurface::kRest);
    return false;
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
