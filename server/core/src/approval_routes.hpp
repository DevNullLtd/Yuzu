#pragma once

/// @file approval_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-9) — the 4-route Approval API: list/query pending
/// approval tickets, pending-count, and approve/reject one by id. One
/// owning store (`ApprovalManager`, ADR-0009/0065 — a Postgres-backed
/// one-time approval-ticket store; NOT the ADR-1005/0033 "core-owned
/// approval primitive", which is a separate, not-yet-built, design-only
/// mechanism for capability-declared `requires_approval` gates — see
/// `docs/adr/0033-access-control-spine.md` §4. `ApprovalManager` predates
/// that ADR and is one of the four pre-existing per-feature approval
/// surfaces its Context section (not "Alternatives considered") names, not
/// an instance of the future primitive).
/// Every handler body is copied verbatim from server.cpp; the changes are
/// the receiver (`web_server_->` -> `sink.`), the gate closure
/// (`require_permission` -> `deps.perm_fn`), the member access
/// (`approval_manager_.` -> `deps.approval_manager->`), the session
/// resolution (`auth_routes_->resolve_session` -> `deps.resolve_session_fn`),
/// the audit call (`audit_log(...)` -> `deps.audit_fn(...)`), and the event
/// emission (`emit_event(...)` -> `deps.emit_event_fn(...)`).
///
/// Routes (4) — gate in parens, all backed by `deps.approval_manager`
/// (`ApprovalManager`), none uses `auth_fn` (only `perm_fn`, which
/// internally resolves the session):
///   GET  /api/approvals                  (perm_fn Approval:Read)
///   GET  /api/approvals/pending/count    (perm_fn Approval:Read)
///   POST /api/approvals/:id/approve      (perm_fn Approval:Approve + approver assurance)
///   POST /api/approvals/:id/reject       (perm_fn Approval:Approve + approver assurance)
///
/// APPROVER ASSURANCE (#6061, four-eyes MVP PR1) -- approve/reject, in this
/// order, each step failing closed BEFORE anything is mutated:
///   1. `perm_fn` (Approval:Approve) -- the RBAC gate, unchanged.
///   2. The session is re-resolved; an unresolvable one is a 503 A4 envelope
///      (#4128). It used to become reviewer "unknown", which can never equal a
///      real `submitted_by` and so defeated the separation-of-duties check.
///   2b. SAME-SITE GATE (`WriteGate`, #6061 SG-1): a cookie-authorised POST
///      must name this site in Origin/Referer (403, `csrf.denied` row, before
///      anything else is touched). Token callers are exempt from it and are
///      refused by the class check instead.
///   3. Class check (`approver_assurance.hpp`): interactive local/OIDC/SAML
///      cookie session, `principal_kind == "human"`, not an engine principal.
///      A bearer or engine caller gets a 403 A4 envelope whose message is
///      `approver_assurance_required:<reason>`.
///   4. `deps.approver_mfa_fn` (#6079) -- an ENROLLED second factor with a proof no
///      older than the approver window (at most 300 s): `require_enrolled_fresh_mfa`,
///      NOT `require_mfa_step_up`
///      (that one passes un-enrolled accounts and bearers and honours a window of
///      0). Its outcome is switched on, and every non-pass leaves the ticket
///      untouched: a stale or enrolment-predating proof -> the 401 it wrote, plus
///      a ticket-specific `denied` row (`approver_assurance:mfa_proof_stale`); an
///      unreadable enrolment -> 503 (`retry_after_ms`) plus an `error` row; no
///      usable factor (not enrolled, no SSO attestation, SAML, a deactivated or
///      deleted account) -> 403
///      `approver_assurance_required:<reason>` plus a `denied` row. An UNWIRED
///      `approver_mfa_fn` is a 503, not a skip: this is the one place a null
///      closure must not read as "no step-up required". If a refusal's audit row
///      cannot be persisted the refusal still stands and the response carries
///      `Sec-Audit-Failed: true`.
///   5. AUDIT BEFORE MUTATE (#5823): an `attempted` row is written first; if it
///      does not persist the response is a 503 (`Sec-Audit-Failed: true`) and
///      the ticket is left pending. The post-decision `success` / `denied` row
///      is kept as well, so a decision leaves two rows. The `attempted` and
///      `success` rows carry the detail `approver_assurance:enrolled_fresh_mfa`,
///      which also marks a row written after the enrolled-factor requirement.
///
/// TICKET ID IN AUDIT ROWS: the path segment is attacker-shaped (`[^/]+`), so a
/// segment that is not 1-128 of `[A-Za-z0-9_-]` is audited and logged as the
/// fixed `target_id` `invalid-id`, never as the raw bytes. The refusals above
/// keep their order and status; past the gate such an id is answered 400
/// `approval not found` with a `denied` row (detail `invalid_approval_id`) and
/// the store is not asked.
/// The store's reviewer != submitted_by check is untouched and still runs last.
///
/// STORE-UNAVAILABLE ASYMMETRY (preserved verbatim, not a defect introduced
/// by this move): GET /api/approvals and both POST routes answer a 503
/// envelope (`{"error":{"code":503,...}}`) when `approval_manager` is
/// null; GET /api/approvals/pending/count instead answers 200 with
/// `{"count":0}` — a degraded pending-count reads as "nothing pending"
/// rather than an error, matching the original inline code exactly.
///
/// AUDIT ASYMMETRY (also preserved verbatim): GET /api/approvals and GET
/// .../pending/count are both pure reads and unaudited. The store-
/// unavailable 503 on all three gated-past routes is unaudited (it returns
/// before `deps.audit_fn` is ever reached), as is the unresolvable-session 503.
/// The class-check refusal writes a `denied` row through `emit_behavioral_audit`;
/// the MFA-gate refusals (step 4) write a ticket-specific `denied` / `error` row
/// the same way. For those ticket-specific rows a failed write sets
/// `Sec-Audit-Failed: true` on the response while the 403 / 503 / 401 still
/// stands and the ticket is untouched. The gate's OWN `mfa.step_up.required` row
/// (left on a stale proof by `detail::write_step_up_challenge`) is best effort: a
/// failure to write it is logged and never surfaced in the response. Past those,
/// approve/reject write an `"attempted"` row BEFORE the store call (fail closed, see
/// above) and then audit BOTH outcomes — a denied review (e.g. the store's
/// self-approval segregation-of-duties block) is audited as `"denied"`
/// with `result.error()` as the detail, and a successful one as
/// `"success"` — and additionally emit an `approval.approved`/
/// `approval.rejected` event on success only (never on denial). The
/// post-decision row's persist result is still discarded: the mutation has
/// happened and cannot be undone, and the pre-mutation row is the evidence
/// that is guaranteed.
///
/// `log_safe` (used by approve/reject's denial-path log line) reuses the
/// existing `web_utils.hpp` promotion from #2542 PR-7 (`instruction_routes.cpp`
/// needed the same helper first) rather than a second, competing promotion —
/// this PR originally promoted it into its own `log_safe.hpp`, but that
/// collided with PR-7's independent promotion of the identical function into
/// a different header; reconciled at merge time by dropping this PR's copy.

#include "mfa_factor_state.hpp" // ApproverMfaOutcome

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yuzu::server {
class HttpRouteSink;
class ApprovalManager;
} // namespace yuzu::server

namespace yuzu::server::approval {

/// Construction deps for `register_approval_routes`. Every closure/pointer
/// is bound once at start_web_server() time in server.cpp and never
/// reseated. Deliberately carries no `AuthFn` — none of these 4 handlers
/// calls `require_auth` directly; `perm_fn` is bound to a
/// `require_permission` wrapper, which resolves the session internally —
/// matching the original inline code exactly. `resolve_session_fn` is
/// separate from `perm_fn`: approve/reject need the CALLER's identity (the
/// reviewer) even when no gate blocks the request, which `perm_fn`'s bool
/// return cannot carry.
struct Deps {
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Resolves the caller's session without gating — mirrors
    /// `AuthRoutes::resolve_session`. Returns `std::nullopt` for an
    /// unauthenticated/unresolvable request. approve/reject treat that as a
    /// 503 and leave the ticket untouched (#4128): this closure is called a
    /// SECOND time, independent of perm_fn's own internal session resolution,
    /// so a session evicted between the two calls (or a Postgres
    /// session-store brownout) can make it fail after the gate passed, and
    /// falling back to a placeholder reviewer would defeat the self-approval
    /// segregation-of-duties check in `ApprovalManager::set_review_status`
    /// (a placeholder can never equal a real `submitted_by`). The resolved
    /// session is also what the approver-assurance class check reads.
    using ResolveSessionFn =
        std::function<std::optional<auth::Session>(const httplib::Request&)>;
    /// Bool-returning audit contract, same shape as
    /// `custom_properties::Deps::AuditFn` / server.cpp's hoisted `audit_fn`
    /// closure. approve/reject FAIL CLOSED on the pre-mutation `attempted` row
    /// (503, no mutation, #5823); the post-decision `denied`/`success` rows
    /// discard the return value (`(void)audit_fn(...)`) because the mutation
    /// has already happened by then.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Same shape as `command::Deps::EmitEventFn` — always called with the
    /// default `Severity::kInfo` (the original inline code never overrode
    /// it here), so the 4-argument overload of `ServerImpl::emit_event` is
    /// the one this binds to.
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req,
                                           const nlohmann::json& attrs,
                                           const nlohmann::json& payload_data)>;

    PermFn perm_fn;
    ResolveSessionFn resolve_session_fn;
    AuditFn audit_fn;
    EmitEventFn emit_event_fn;
    /// The approver MFA gate (server.cpp binds `require_enrolled_fresh_mfa` to
    /// AuthDB + `--mfa-step-up-window-secs` + the audit sink + `/metrics`). On
    /// `kChallengeWritten` it has already written the 401 and the handler must
    /// return. An EMPTY closure is NOT permissive: approve/reject answer 503 so a
    /// wiring regression cannot silently drop the second-factor requirement of a
    /// four-eyes control. A server with no AuthDB binds a closure that answers
    /// `kStoreUnavailable`, never `kPass`.
    using ApproverMfaFn =
        std::function<ApproverMfaOutcome(const httplib::Request&, httplib::Response&,
                                         const auth::Session&, const std::string& action_label)>;
    ApproverMfaFn approver_mfa_fn;
    /// `Config::csrf_trusted_origins` (normalised at boot) for the same-site
    /// write gate on approve/reject (`WriteGate::refuse_cross_site`,
    /// `audited_write.hpp`) -- extra origins a cookie-authorised POST may
    /// legitimately come from (a TLS-terminating reverse proxy). Empty means
    /// only the request's own Host is same-site.
    std::vector<std::string> csrf_trusted_origins;
    /// `ServerImpl::approval_manager_`. Null -> every route degrades per the
    /// STORE-UNAVAILABLE ASYMMETRY documented above (this file's header).
    ApprovalManager* approval_manager{nullptr};
};

/// Register all 4 Approval API routes against `sink`.
void register_approval_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::approval
