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
/// `require_mfa_step_up` is a thin wrapper over `decide_step_up` +
/// `render_step_up_refusal` (step_up_gate.hpp); the same decision is also
/// applied ahead of the handler by the step-up chokepoint for the routes
/// `step_up_policy.hpp` classifies as kRequired.
///
/// Contract: returns true if the caller may proceed; false means the
/// helper has already written the refusal envelope for the verdict (a 401,
/// 403 or 503; the 403 is a SAML session or an engine principal; see
/// `render_step_up_refusal` in step_up_gate.hpp) to `res`
/// and the caller MUST return immediately without further response
/// mutation or audit emission.
///
/// Denies (returns false, 403, reason `engine_principal_denied`) engine principals
/// (`Session::is_engine()`) before anything else, the `window_secs <= 0` hatch and any store
/// read included: an engine principal has no `users` row and no operator to re-prove, and a
/// step-up-gated route is operator-only whatever RBAC grant the engine holds.
///
/// Skips entirely (returns true) for:
///   - API token / MCP token principals: the bearer credential IS the step-up moment
///     (per `/auth-and-authz` skill, "MFA on every API-token call" is
///     explicitly out of scope; token issuance happened with full MFA).
///   - Sessions belonging to users without MFA enrolled — consistent
///     with PR1's enforcement model (`optional` mode only kicks in
///     once a user opts into MFA).
///   - `window_secs <= 0`: operator-disabled the gate (escape hatch
///     for diagnostic / break-glass scenarios; emits a startup WARN
///     in main.cpp).
///
/// Requires step-up (returns false) when:
///   - principal is a local session ("local" auth_source) AND user is
///     MFA-enrolled, OR principal is an OIDC session (PR3 — no local
///     enrollment lookup; gated on the `amr`-seeded timestamp); AND
///   - `now - session.mfa_verified_at > window_secs`
///
/// OIDC interop (PR3): an OIDC session carries no local `users` row, so
/// the enrollment lookup is skipped for it. Its `mfa_verified_at` is
/// seeded in /auth/callback from the IdP `amr` claim (see
/// `amr_asserts_mfa` below). A session whose IdP attestation is older than
/// the window fails the gate. A session whose IdP login did not attest MFA
/// at all carries no proof: it fails the gate only when `--mfa-enforcement`
/// protects its role (`required`, or `admin-only` for an admin); under
/// `optional` it passes, because gating it would loop through SSO with the
/// same amr-less token forever (`decide_step_up`, step_up_gate.cpp). The
/// remediation points the operator back through SSO (`/auth/oidc/start`)
/// rather than the local `/login/mfa/stepup` flow, which has no secret to
/// verify for an external identity.
///
/// Side effects on failure (shown for a stale proof; the status and text for the other
/// verdicts are chosen per verdict in step_up_gate.cpp):
///   - `res.status = 401`
///   - `res.body` = A4 envelope: `{"error":{"code":401,"message":
///     "MFA step-up required","correlation_id":"req-...",
///     "remediation":"<source-specific>"},"meta":{"api_version":"v1",
///     "mfa_step_up_required":true,"challenge_url":"<source-specific>"}}`
///     where the challenge_url is `/login/mfa/stepup` for local sessions
///     and `/auth/oidc/start` for OIDC sessions.
///   - emits audit row: `mfa.step_up.required`, result=`error`,
///     target_type=`Endpoint`, target_id=`<action_label>`, detail=
///     stale or absent proof: `user=<name> age_secs=<n> window_secs=<n>`; every other refusal:
///     `user=<name> reason=<token>`. A central-chokepoint row appends ` cid=<id>
///     stage=pre_authz`; a row written by an in-handler call carries neither.

#include "mfa_factor_state.hpp"
#include "rest_a4_envelope.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <chrono>
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

/// Classify the second factor `session` stands on (see `MfaFactorState`). The
/// session's OWN factor only: an OIDC or bearer session is never looked up by
/// username, so an unrelated local account that happens to share the name cannot
/// lend it a factor. Only a `local` session reads the store (`mfa_status`), and a
/// store outage or undecryptable secret is `kStoreUnavailable`, never "not enrolled".
[[nodiscard]] MfaFactorProbe probe_mfa_factor(const auth::Session& session, AuthDB& auth_db);

/// Approver gate (#6079): the caller must stand on an enrolled factor AND hold a
/// proof no older than `approver_step_up_window(configured_window_secs)`. Unlike
/// `require_mfa_step_up` there is no `window_secs <= 0` escape hatch, no bearer
/// exemption, no pass for an un-enrolled account and no enforcement-dependent OIDC
/// pass. A local proof stamped before the current enrolment (the factor was cleared
/// and re-enrolled since) does not count.
///
/// The ceiling is hard and measured on the database clock. `durable` is the caller's
/// authoritative read of the session's stored proof (`AuthManager::read_durable_mfa_proof`):
/// with a `kRow` the proof age is `db_now_ms - mfa_verified_ms` and must lie in
/// [0, window] with no skew allowance, in addition to the cached monotonic check, so a
/// suspended host or paused VM (which freezes the monotonic anchor) cannot extend it.
/// `kUnavailable` is `kStoreUnavailable` (503), which includes an `AuthManager` with no
/// SessionStore attached (never reachable in a serving process: the server refuses to boot
/// without Postgres); `kAbsent` is a challenge. No replica clock stands in for the database
/// clock, so there is no store-less fallback.
///
/// Only `kChallengeWritten` writes to `res` (the 401 step-up envelope plus one
/// `mfa.step_up.required` row; the challenge reports the EFFECTIVE window).
/// `kStoreUnavailable` also increments `yuzu_auth_secret_unavailable_total{route="approval"}`
/// when `metrics` is set.
[[nodiscard]] ApproverMfaOutcome
require_enrolled_fresh_mfa(const httplib::Request& req, httplib::Response& res,
                           const auth::Session& session, AuthDB& auth_db,
                           int configured_window_secs, const StepUpAuditFn& audit_fn,
                           const std::string& action_label,
                           const auth::DurableMfaProof& durable,
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

namespace detail {

/// Result of ageing a session's MFA proof on the cached monotonic anchor. The same age
/// arithmetic exists in two copies that must stay in step: this one, whose only production
/// consumer is the approver gate (`require_enrolled_fresh_mfa`, which uses the monotonic half
/// and adds its own durable, database-clock ceiling on top), and the generic gate's own copy in
/// `decide_step_up` (step_up_gate.cpp), which is what `require_mfa_step_up` and the central
/// chokepoint decide on.
struct ProofAge {
    bool no_proof{true};   ///< no usable proof: absent, or future-dated (derive left it {})
    bool fresh{false};     ///< a proof exists, is within the window, and is not wall-stale
    long long age_secs{-1}; ///< whole seconds on the monotonic anchor; -1 when `no_proof`
    /// Milliseconds on the monotonic anchor; -1 when `no_proof`. `fresh` compares the
    /// whole-second age (a proof 300.5 s old is still fresh in a 300 s window); a caller
    /// needing a hard ceiling compares this instead. The approver gate compares it (with
    /// `no_proof`) and adds its own durable, database-clock ceiling; it does not consult
    /// `wall_stale`.
    long long age_ms{-1};
    bool wall_stale{false}; ///< the absolute (wall) proof age is grossly past the window
};

/// Age `session`'s proof against `effective_window` (monotonic anchor plus the wall
/// suspend backstop; see the definition). The wall figure (`wall_stale`) is computed from the
/// replica's system_clock but is not decisional for the approver gate, which ignores it.
[[nodiscard]] ProofAge mfa_proof_age(const auth::Session& session, std::chrono::seconds effective_window);

/// Write the 401 step-up envelope (challenge_url differs for OIDC vs local) and emit
/// one `mfa.step_up.required` row. `extra_detail`, when non-empty, is appended to the
/// row's detail. An audit failure or throw is logged and otherwise ignored.
void write_step_up_challenge(const httplib::Request& req, httplib::Response& res,
                             const auth::Session& session, bool is_oidc,
                             const StepUpAuditFn& audit_fn, const std::string& action_label,
                             long long age_secs, int window_secs,
                             std::string_view extra_detail = {});

} // namespace detail

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
