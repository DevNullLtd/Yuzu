#pragma once

/// @file mfa_step_up.hpp
///
/// Step-up gate for high-risk REST + Settings handlers (PR2 of the MFA
/// ladder; SOC 2 CC6.6 — privileged access requires fresh proof of
/// presence). PR1 established `Session::mfa_verified_at` as the
/// timestamp of the most recent successful MFA proof on a session;
/// this helper compares it against `cfg.mfa_step_up_window_secs` and
/// blocks the caller if the proof is stale.
///
/// Contract: returns true if the caller may proceed; false means the
/// helper has already written a 401 + A4 envelope to `res` and the
/// caller MUST return immediately without further response mutation
/// or audit emission.
///
/// Skips entirely (returns true) for:
///   - API token / MCP token principals — the bearer credential IS
///     the step-up moment (per `/auth-and-authz` skill, "MFA on every
///     API-token call" is explicitly out of scope; token issuance
///     happened with full MFA).
///   - Sessions belonging to users without MFA enrolled — consistent
///     with PR1's enforcement model (`optional` mode only kicks in
///     once a user opts into MFA).
///   - `window_secs == 0` — operator-disabled the gate (escape hatch
///     for diagnostic / break-glass scenarios; emits a startup WARN
///     in main.cpp).
///
/// Requires step-up (returns false) when:
///   - principal is a local session ("local" auth_source) AND user is
///     MFA-enrolled, OR principal is an OIDC session (PR3 — no local
///     enrollment lookup; gated purely on the `amr`-seeded timestamp);
///     AND
///   - `now - session.mfa_verified_at > window_secs`
///
/// OIDC interop (PR3): an OIDC session carries no local `users` row, so
/// the enrollment lookup is skipped for it. Its `mfa_verified_at` is
/// seeded in /auth/callback from the IdP `amr` claim (see
/// `amr_asserts_mfa` below). A session whose IdP login did not attest MFA
/// — or whose attestation is older than the window — fails the gate; the
/// remediation points the operator back through SSO (`/auth/oidc/start`)
/// rather than the local `/login/mfa/stepup` flow, which has no secret to
/// verify for an external identity.
///
/// Side effects on failure:
///   - `res.status = 401`
///   - `res.body` = A4 envelope: `{"error":{"code":401,"message":
///     "MFA step-up required","correlation_id":"req-...",
///     "remediation":"<source-specific>"},"meta":{"api_version":"v1",
///     "mfa_step_up_required":true,"challenge_url":"<source-specific>"}}`
///     where the challenge_url is `/login/mfa/stepup` for local sessions
///     and `/auth/oidc/start` for OIDC sessions.
///   - emits audit row: `mfa.step_up.required`, result=`error`,
///     target_type=`Endpoint`, target_id=`<action_label>`, detail=
///     username + age of last MFA proof in seconds.

#include "rest_a4_envelope.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace yuzu {
class MetricsRegistry; // yuzu/metrics.hpp — observability counters (optional)
}

namespace yuzu::server {

/// Audit callback typedef — matches `RestApiV1::AuditFn` shape so
/// step-up audit emission is wire-identical to neighbouring handlers.
/// Return value is currently discarded (`mfa.step_up.required` is a
/// trace event; the access denial is the primary signal), but the
/// typedef keeps the signature uniform across the codebase.
using StepUpAuditFn = std::function<bool(const httplib::Request&,
                                         const std::string& action,
                                         const std::string& result,
                                         const std::string& target_type,
                                         const std::string& target_id,
                                         const std::string& detail)>;

/// `metrics` (optional — nullptr is a no-op) increments
/// `yuzu_auth_secret_unavailable_total{route="mfa_stepup"}` on the fail-
/// closed 503 branch (store/decrypt outage), so an operator can see this
/// gate's outage rate on the same series as the other fail-closed auth
/// routes (sre BLOCKING, governance hardening round).
bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db,
                         int window_secs, const StepUpAuditFn& audit_fn,
                         const std::string& action_label,
                         std::string_view mfa_enforcement = "optional",
                         yuzu::MetricsRegistry* metrics = nullptr);

/// True if the IdP `amr` claim attests a multi-factor (or otherwise
/// strong) authentication that should seed a session's MFA-verified
/// timestamp. The allowlist follows RFC 8176 plus Entra's non-standard
/// `mfa` value, per docs/auth-mfa-design.md "OIDC interop". `pwd`
/// (password-only) and the single-factor `pin`/`user` are deliberately
/// excluded. Free function so PR3's /auth/callback wiring is unit-testable
/// without standing up an OIDC provider.
bool amr_asserts_mfa(const std::vector<std::string>& amr);

/// Single source of truth for the `--mfa-enforcement` predicate: does the
/// given mode require MFA for a principal of `role`? `required` → every
/// role; `admin-only` → admins only; anything else (`optional` or an
/// unexpected value) → not enforced (fail-safe). Shared by the `/login`
/// enrollment bootstrap and the Settings self-target disable guard so the
/// `required || (admin-only && admin)` logic lives in exactly one place
/// (governance arch-S1 — was duplicated and drift-prone).
bool mfa_enforcement_protects(std::string_view mode, auth::Role role);

/// Per-surface adapter — wires AuthDB + window_secs + audit_fn into a
/// 3-argument callable that downstream `register_routes` overloads can
/// take alongside auth_fn/perm_fn/audit_fn. Lives in this header so
/// rest_api_v1, settings_routes, and tests construct identical
/// closures.
using StepUpFn = std::function<bool(const httplib::Request&,
                                    httplib::Response&,
                                    const auth::Session&,
                                    const std::string& action_label)>;

} // namespace yuzu::server
