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
///   POST /api/approvals/:id/approve      (perm_fn Approval:Approve)
///   POST /api/approvals/:id/reject       (perm_fn Approval:Approve)
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
/// before `deps.audit_fn` is ever reached). approve/reject audit BOTH
/// outcomes past that point — a denied review (e.g. the store's
/// self-approval segregation-of-duties block) is audited as `"denied"`
/// with `result.error()` as the detail, and a successful one as
/// `"success"` — and additionally emit an `approval.approved`/
/// `approval.rejected` event on success only (never on denial).
///
/// `log_safe` (used by approve/reject's denial-path log line) reuses the
/// existing `web_utils.hpp` promotion from #2542 PR-7 (`instruction_routes.cpp`
/// needed the same helper first) rather than a second, competing promotion —
/// this PR originally promoted it into its own `log_safe.hpp`, but that
/// collided with PR-7's independent promotion of the identical function into
/// a different header; reconciled at merge time by dropping this PR's copy.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

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
    /// unauthenticated/unresolvable request; callers here treat that as
    /// reviewer `"unknown"`, matching the original inline code exactly
    /// (this is NOT an authorization decision — `perm_fn` already ran
    /// first and is the actual gate). KNOWN GAP (#4128, pre-existing,
    /// confirmed byte-identical on origin/dev before this extraction): this
    /// closure is called a SECOND time, independent of perm_fn's own
    /// internal session resolution — if this call alone fails (a session
    /// evicted between the two calls, or a Postgres session-store brownout)
    /// while perm_fn's gate already passed, the resulting `"unknown"`
    /// reviewer can bypass the self-approval segregation-of-duties check in
    /// `ApprovalManager::set_review_status`, since `"unknown"` can never
    /// equal a real `submitted_by`. Not fixed by this mechanical move; see
    /// #4128 for the real remedy.
    using ResolveSessionFn =
        std::function<std::optional<auth::Session>(const httplib::Request&)>;
    /// Bool-returning audit contract, same shape as
    /// `custom_properties::Deps::AuditFn` / server.cpp's hoisted `audit_fn`
    /// closure. All four call sites here (approve/reject, each on both
    /// their denial and success path) discard the return value
    /// (`(void)audit_fn(...)`), matching the original inline code's
    /// `(void)audit_log(...)`.
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
    /// `ServerImpl::approval_manager_`. Null -> every route degrades per the
    /// STORE-UNAVAILABLE ASYMMETRY documented above (this file's header).
    ApprovalManager* approval_manager{nullptr};
};

/// Register all 4 Approval API routes against `sink`.
void register_approval_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::approval
