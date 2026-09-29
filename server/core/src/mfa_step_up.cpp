/// @file mfa_step_up.cpp — see header for the gate contract.

#include "mfa_step_up.hpp"

#include "rest_a4_envelope.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string_view>

namespace yuzu::server {

bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db, int window_secs,
                         const StepUpAuditFn& audit_fn, const std::string& action_label,
                         std::string_view mfa_enforcement, yuzu::MetricsRegistry* metrics) {
    // Escape hatch — operator disabled the gate. Treated as fresh.
    if (window_secs <= 0) {
        return true;
    }

    // Bearer-credential principals are step-up-exempt by design. Token
    // issuance was the step-up moment; the token itself does not
    // re-prompt. Mirrors the /auth-and-authz skill's documented scope.
    //
    // `engine_token` (auth-engine-principals-design.md §6) is deliberately
    // NOT added here, even though it is also a bearer credential. It falls
    // through to the local `mfa_status()` lookup below, which returns
    // `UserNotFound` (an engine session has no `users` row) and fails
    // CLOSED. That is the correct posture, not an oversight: an engine
    // session has no MFA-enrolled user to step up, so it must never be
    // treated as already-proven the way a human-attributed api_token/
    // mcp_token session is (§9's structural-denial posture). Do not extend
    // this exemption to engine_token.
    if (session.auth_source == "api_token" || session.auth_source == "mcp_token") {
        return true;
    }

    // SAML sessions carry no local `users` row (create_saml_session never
    // writes one) and no MFA attestation in this release. The gate stays
    // CLOSED — SAML sessions may NOT bypass step-up — but we return an
    // honest denial rather than falling through to mfa_status() which
    // would fail (UserNotFound) and emit a confusing "auth_db unavailable"
    // message. Do NOT add an exemption here; SAML MFA attestation is
    // deferred to a follow-up slice.
    //
    // `auth_source == "engine_token"` never matches this branch (an engine
    // session's auth_source is exactly "engine_token", never "saml") — it
    // falls through to the local `mfa_status()` lookup below and fails
    // closed there, same correct posture as the api_token/mcp_token
    // comment above.
    if (session.auth_source == "saml") {
        const auto cid = detail::make_correlation_id();
        nlohmann::json envelope = {
            {"error",
             {{"code", 403},
              {"message", "MFA step-up is not available for SAML sessions in this release"},
              {"correlation_id", cid},
              {"remediation",
               "Re-authenticate via SAML at /auth/saml/start to obtain a fresh session; "
               "MFA attestation for SAML is deferred to a future release"}}},
            {"meta",
             {{"api_version", "v1"},
              {"mfa_step_up_required", false}}}};
        res.status = 403;
        res.set_content(envelope.dump(), "application/json");
        if (audit_fn) {
            try {
                (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint",
                               action_label,
                               "user=" + session.username +
                                   " reason=saml_session_no_mfa_this_release");
            } catch (const std::exception& ex) {
                spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
            } catch (...) {
                spdlog::warn("mfa_step_up: audit emission threw non-std exception");
            }
        }
        return false;
    }

    // OIDC/SSO sessions (PR3) carry no local `users` row, so the
    // enrollment lookup below would return `UserNotFound` and — were we
    // to run it — fail closed and lock every SSO operator out of the
    // gated endpoints (the PR #1199 HIGH the old blanket exemption
    // guarded). Instead we skip the local lookup entirely and gate the
    // OIDC session purely on `session.mfa_verified_at`, which
    // /auth/callback seeds from the IdP `amr` claim. A local TOTP step-up
    // is meaningless for an external identity, so the remediation steers
    // the operator back through SSO (see the source-specific challenge
    // URL on the failure path below).
    // `engine_token` never equals "oidc", so `is_oidc` is false for an engine
    // session — it takes the `!is_oidc` branch below and hits the local
    // `mfa_status()` lookup, which fails closed (UserNotFound), matching the
    // two comments above.
    const bool is_oidc = session.auth_source == "oidc";

    if (!is_oidc) {
        // Look up the local user's MFA enrollment status. Distinguish:
        //
        //   (a) store error / user-deleted-mid-request (`!status`) — fail
        //       CLOSED: the gate cannot evaluate, so the request is
        //       denied. Fail-open here would let an attacker exploit
        //       auth_db transients (lock contention, corrupted row,
        //       deleted-then-requested user) to bypass step-up on every
        //       gated site. Governance Gate 4 UP-4 / unhappy-path
        //       BLOCKING.
        //
        //   (b) user not enrolled (`!status->enrolled`) — fall through to
        //       the existing role/permission gate. Under
        //       `mfa_enforcement != optional` such a user is required to
        //       enrol at login (PR3), so a not-enrolled local session
        //       reaching here implies `optional` mode.
        auto status = auth_db.mfa_status(session.username);
        if (!status) {
            // Fail closed. Emit a distinct audit verb so SRE can grep for
            // store-error events vs legitimate stale-session denials.
            //
            // ★ SECURITY (architect BLOCK, Postgres migration): this branch
            // already fails closed for EVERY `mfa_status` error (never falls
            // to the `!status->enrolled` pass-through below) — the tri-state
            // `SecretUnavailable`/`QueryFailed` outcomes are folded into the
            // same deny. The only refinement is the wire status: a
            // store/decrypt outage is 503 (retryable, distinct from "please
            // step up"), never the 401 challenge that implies a fresh proof
            // would fix it.
            const bool store_unavailable = is_store_unavailable(status.error());
            if (audit_fn) {
                try {
                    (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint",
                                   action_label,
                                   "user=" + session.username +
                                       " reason=mfa_status_unavailable (fail-closed)");
                } catch (const std::exception& ex) {
                    spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
                } catch (...) {
                    spdlog::warn("mfa_step_up: audit emission threw non-std exception");
                }
            }
            spdlog::error("require_mfa_step_up: mfa_status({}) failed — failing closed",
                          session.username);
            if (store_unavailable) {
                nlohmann::json envelope_503 = {
                    {"error",
                     {{"code", 503},
                      {"message", "authentication store is temporarily unavailable"},
                      {"correlation_id", detail::make_correlation_id()},
                      {"remediation", "retry shortly or contact an administrator"}}},
                    {"meta", {{"api_version", "v1"}, {"mfa_step_up_required", true}}}};
                res.status = 503;
                res.set_content(envelope_503.dump(), "application/json");
                if (metrics) {
                    metrics->counter("yuzu_auth_secret_unavailable_total", {{"route", "mfa_stepup"}})
                        .increment();
                }
                return false;
            }
            nlohmann::json envelope_fail = {
                {"error",
                 {{"code", 401},
                  {"message", "MFA step-up required"},
                  {"correlation_id", detail::make_correlation_id()},
                  {"remediation",
                   "auth_db unavailable — retry shortly or contact an administrator"}}},
                {"meta",
                 {{"api_version", "v1"},
                  {"mfa_step_up_required", true},
                  {"challenge_url", "/login/mfa/stepup"}}}};
            res.status = 401;
            res.set_content(envelope_fail.dump(), "application/json");
            return false;
        }
        if (!status->enrolled) {
            return true;
        }
    }

    // Compute proof age against the LOCAL MONOTONIC anchor derived at
    // cache-populate from the DB clock (ADR-2002 §4 DB-clock authority, WS-1/1a):
    // `steady_mfa_verified` is set to `steady_now - (db_now - mfa_verified_ms)` in
    // derive_session_deadlines, immune to local wall skew/steps. Its {} sentinel
    // means "no usable MFA proof" — derive sets it {} for BOTH an absent proof AND
    // a FUTURE-DATED proof (`mfa_verified_ms > db_now`, a backward DB step below
    // the proof instant → fail CLOSED, never a spurious-fresh window). So the
    // future-dated rejection is already applied; this just reads the sentinel.
    const auto now = std::chrono::steady_clock::now();
    const bool no_proof = session.steady_mfa_verified.time_since_epoch().count() == 0;

    // OIDC sessions whose IdP did not attest MFA carry no seeded proof
    // (no `amr` → `/auth/callback` never set `mfa_verified_at`). Whether
    // that PASSES depends on enforcement, symmetric with how a local user
    // is treated (Hermes adversarial + cyber A4/B1, governance UP-6):
    //   - mode does NOT protect this principal's role (e.g. `optional`, or
    //     `admin-only` for a non-admin) → PASS. There is no factor to step
    //     up; gating would 401 → `/auth/oidc/start` → silent re-SSO → same
    //     `amr`-less token → 401 … an infinite lockout loop for every
    //     non-MFA IdP (the PR #1199 HIGH / UP-5). This keeps the default
    //     deployment safe and is never weaker than the PR2 blanket exempt.
    //   - mode DOES protect this role (`required`, or `admin-only` for an
    //     admin) → step up (fall through to the 401 below, challenge =
    //     re-SSO). The operator asked for MFA on this principal; an SSO
    //     login the IdP did not MFA must re-authenticate. If the IdP never
    //     asserts `amr` this is a deployment misconfiguration, recoverable
    //     by restarting in `optional` (docs/ops-runbooks/auth-db-recovery
    //     .md) — the same "you required MFA but provided no way to satisfy
    //     it" footgun a local `required` deployment has.
    // An OIDC session that DOES carry an `amr`-seeded proof always falls
    // through to the freshness check below regardless of mode.
    if (is_oidc && no_proof && !mfa_enforcement_protects(mfa_enforcement, session.role)) {
        return true;
    }

    const auto age = no_proof ? std::chrono::seconds::max()
                              : std::chrono::duration_cast<std::chrono::seconds>(
                                    now - session.steady_mfa_verified);
    // Hard wall-clock ceiling on the step-up window (ADR-2002 §4 mitigation (b),
    // parity with JIT elevation's kMaxElevationWindow). The effective freshness
    // window is min(configured window_secs, kMaxMfaStepUpWindowSecs): a proof
    // older than the hard ceiling never counts, regardless of a large/misconfigured
    // window_secs — a defense-in-depth bound independent of the operator setting,
    // mirroring is_elevated()'s `(elevated_until - issued) <= kMaxElevationWindow`.
    // (mfa_verified_at is the issued-at anchor.) The residual smaller-backward-
    // clock-step risk — which this ceiling, like JIT's, does not resist because
    // `age` is computed against `now` — is the WS-11 DB-clock-integrity monitor's
    // job (see the reap clock-anomaly signal), the same residual JIT carries.
    constexpr std::int64_t kMaxMfaStepUpWindowSecs = 24 * 3600; // 24h backstop
    const auto effective_window =
        std::chrono::seconds((std::min<std::int64_t>)(window_secs, kMaxMfaStepUpWindowSecs));
    // Suspend backstop (parity with is_elevated / validate, ADR-2002 §4 / design-
    // review H5 + LOW-1): the freshness age above is on steady_clock, which pauses
    // across host/VM suspend — so a stale proof could read fresh after a resume.
    // Also require the ABSOLUTE (wall) proof age not be grossly past the window,
    // consulted only with the generous auth::kWallSanitySkew slack so a merely
    // clock-SKEWED (non-suspended) replica is never affected (only a long suspend,
    // where wall advanced far past the window while steady froze, trips it).
    const auto wall_age = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - session.mfa_verified_at);
    const bool wall_stale = wall_age > effective_window + auth::kWallSanitySkew;
    if (!no_proof && age <= effective_window && !wall_stale) {
        return true;
    }

    // Step-up required. Build the 401 A4 envelope with the extra
    // `meta.mfa_step_up_required` + `meta.challenge_url` fields the
    // dashboard JS / agentic-worker client uses to drive the
    // re-prompt flow. The challenge differs by identity source: a local
    // session re-proves via the TOTP step-up endpoint; an OIDC session
    // has no local secret, so it must re-authenticate through SSO to
    // refresh the IdP MFA assertion.
    const char* challenge_url = is_oidc ? "/auth/oidc/start" : "/login/mfa/stepup";
    const char* remediation =
        is_oidc ? "Re-authenticate via SSO to refresh the identity provider's MFA assertion, "
                  "then retry"
                : "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry";
    const auto cid = detail::make_correlation_id();
    nlohmann::json envelope = {
        {"error",
         {{"code", 401},
          {"message", "MFA step-up required"},
          {"correlation_id", cid},
          {"remediation", remediation}}},
        {"meta",
         {{"api_version", "v1"},
          {"mfa_step_up_required", true},
          {"challenge_url", challenge_url}}}};
    res.status = 401;
    res.set_content(envelope.dump(), "application/json");

    // Audit. `age` may be seconds::max() in the no-proof case — clamp
    // to a printable bound (window_secs * 1000) so the audit detail
    // stays grep-friendly.
    long long age_secs = no_proof ? -1 : age.count();
    std::string detail_str = "user=" + session.username +
                             " age_secs=" + std::to_string(age_secs) +
                             " window_secs=" + std::to_string(window_secs);
    if (audit_fn) {
        try {
            (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint", action_label,
                           detail_str);
        } catch (const std::exception& ex) {
            spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
        } catch (...) {
            spdlog::warn("mfa_step_up: audit emission threw non-std exception");
        }
    }
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
