#pragma once

#include <string>

#include "authz_model.hpp" // yuzu::server::authz::VisibleSet

/// @file dispatch_caller.hpp
/// PLAN-006 (verified): `ServerImpl::dispatch_confined` and the three
/// dispatch typedefs that feed it — `McpServer::DispatchFn`,
/// `DashboardRoutes::DispatchFn`, `WorkflowRoutes::CommandDispatchFn` — used
/// to carry only the caller's `exec_visible` VISIBILITY filter, never the
/// caller's IDENTITY. `dispatch_scope_ladder.hpp` can only recover a
/// principal from `ex->dispatched_by` for owner-scoped `from_result_set`
/// expressions; every other dispatch reached the seam anonymously even
/// though the handler had authenticated a real Session moments earlier
/// (CDX-P1-03/K-3 declined to widen the typedefs for this, judging the
/// benefit an audit-completeness LOW — see the comment this struct now
/// answers, at `server.cpp`'s `dispatch_confined`).
///
/// `DispatchCaller` is that missing identity, threaded alongside
/// `exec_visible` through the SAME injection point every surface already
/// uses (`ExecVisibleFn` → `CallerFn`). This header adds no behaviour: it is
/// pure plumbing so a later chokepoint wave can authorize on `principal`
/// instead of merely filtering on `exec_visible`.
namespace yuzu::server {

/// #1398: whether a dispatch is provably covered by an existing approval
/// decision — see `DispatchCaller::approval_provenance`'s doc comment below
/// for the full contract (the three closed stamping sites). A free enum,
/// not nested in `DispatchCaller`, so `ApprovalProvenance::Ticket` reads the
/// same way `ExecuteGate::AdminOrApproval` (`command_capability.hpp`) does
/// at every comparison site.
enum class ApprovalProvenance : uint8_t {
    None,
    Ticket,
    GovernedPipeline,
};

/// The caller behind a confined dispatch. `principal`/`principal_role` are
/// EMPTY for a call site that has no caller at all — see `system` below —
/// and for one that has a caller but has not yet been wired to identify it
/// (a defaulted/unwired `CallerFn` fails closed on `exec_visible`, never on
/// `principal`: an empty principal alongside a deny-all `exec_visible` is
/// indistinguishable in effect from a wired-but-anonymous caller, and that
/// is deliberate — the VISIBILITY filter is what does the denying here, not
/// the identity field).
struct DispatchCaller {
    /// STABLE authorization principal — mirrors `auth::Session::username`.
    /// Empty when unknown (unwired CallerFn) or not applicable (`system`).
    std::string principal;
    /// Mirrors `auth::role_to_string(auth::Session::role)`. Empty under the
    /// same conditions as `principal`.
    std::string principal_role;
    /// The caller's Execution:Execute visible set (#1788). `nullopt` means
    /// unfiltered — reserved for callers that have deliberately opted out of
    /// confinement (background/system dispatch); every operator-facing
    /// surface's unwired fallback is a PRESENT-EMPTY set (deny-all), never
    /// `nullopt`. See each surface's `CallerFn` doc comment for its specific
    /// fail-closed contract.
    yuzu::server::authz::VisibleSet exec_visible;
    /// True ONLY for a background/system dispatcher that has no session at
    /// all (a policy-engine tick, a scheduled fire with no operator in the
    /// loop, ...). Set explicitly at each such call site — never a default
    /// stand-in for "principal happens to be empty" — so a background
    /// dispatch is a deliberate, greppable statement rather than a value
    /// that merely looks the same as an unwired one.
    bool system = false;

    /// #1398: mirrors `auth::effective_role(session) == auth::Role::admin`
    /// — JIT-elevation-aware, matching the SAME check the governed
    /// `POST /api/instructions/:id/execute` path already uses for its
    /// `role-gated` bypass (`workflow_routes.cpp`). Consulted by
    /// `classify_and_authorize_dispatch`'s `ExecuteGate::AdminOrApproval`
    /// arm. Deliberately NOT derived from `principal_role` (a string,
    /// unaffected by elevation) — computed once per caller derivation, not
    /// re-derived from `principal_role` at the chokepoint, so the chokepoint
    /// never has to parse a role string back into a decision.
    bool principal_is_admin = false;

    /// #1398: whether THIS dispatch is provably covered by an existing
    /// approval decision, consulted by `classify_and_authorize_dispatch`'s
    /// `ExecuteGate::AdminOrApproval`/`AlwaysApproval` arms. `Ticket` means a
    /// real `ApprovalManager` ticket was consumed for this exact dispatch;
    /// `GovernedPipeline` means the caller is a pipeline whose OWN
    /// independent governance (re-authorization, guarded transitions, full
    /// audit) is accepted as the substitute control (#1398 design doc,
    /// Decision 5) — deliberately a DISTINCT value from `Ticket` so neither
    /// an audit reader nor a future maintainer can mistake one for the
    /// other. Trust-by-construction, exactly like `system` above: set ONLY
    /// at these three production sites, closed list —
    ///   1. `CommandOutboxDelivery::deliver` (`command_outbox_delivery.cpp`,
    ///      WS-3 3.3) — `Ticket` when the outbox occurrence carries a non-empty
    ///      `approval_id`, `None` otherwise. This SUPERSEDES the former
    ///      `ScheduleRunner::dispatch_tracked` site: scheduled fires no longer
    ///      dispatch inline — `ScheduleRunner` records the `approval_id` on the
    ///      outbox row at enqueue time and the delivery loop stamps the
    ///      provenance here at send time (a re-authorized AlwaysApproval action
    ///      still clears the #1398 ExecuteGate because the approval that
    ///      admitted the occurrence already happened).
    ///   2. MCP `execute_instruction` / `quarantine_device` handlers
    ///      (`mcp_server.cpp`) — `Ticket`, stamped only after
    ///      `approval_ticket_just_consumed` is true (supervised tier).
    ///   3. `DeploymentEngine` / `DeploymentRoutes` (`deployment_engine.cpp`
    ///      / `deployment_routes.cpp`) — `GovernedPipeline` on their
    ///      content_dist dispatches.
    /// `BundleOrchestrator::dispatch()` (`bundle_orchestrator.cpp`) is NOT a
    /// fourth stamping site — it is a pass-through conduit: REST/MCP
    /// `execute_bundle` derive provenance at one of the three sites above
    /// (site 2, via `approval_ticket_just_consumed`) and thread it in as a
    /// parameter, same as `principal`/`exec_visible`. `ServerImpl::
    /// derive_dispatch_caller_for_username` stamps ONLY `principal_is_admin`
    /// (see that field's comment above), never this one — do not confuse the
    /// two; a caller can be admin-stamped there and still reach the gate
    /// with `approval_provenance == None`.
    /// A fifth stamping site (or a new pass-through conduit) is a diff
    /// against this stated list, not a silent addition — if you are adding
    /// one, update this comment too.
    ApprovalProvenance approval_provenance = ApprovalProvenance::None;
};

/// Build the `DispatchCaller` for a STORED username with no live session —
/// today only `ScheduleRunner`'s fire path, which re-resolves the schedule
/// creator's authority from a bare string at fire time. Pure so the one
/// decision that matters is directly testable:
///
/// `principal_resolves == false` (the account no longer exists, the auth
/// store errored, or no auth store is wired) returns an EMPTY-principal,
/// deny-all caller — which `build_classified_command` refuses as
/// `AnonymousOperator` BEFORE any permission check runs, independent of the
/// RBAC on/off toggle. This is the ADR-0033 §1 rule ("an unresolvable,
/// missing or unparseable input for a filter that applies denies") applied
/// to the authenticated-actor filter, and it is load-bearing precisely on
/// the RBAC-off default posture: every OTHER dispatch surface derives its
/// caller from a live `auth::Session`, which a deleted account cannot
/// produce, so this resolver is the only place where "the account still
/// exists" must be enforced explicitly rather than falling out of
/// authentication. (Round-2 review finding on #3133: an earlier version
/// returned the bare username with legacy-open visibility here, so a
/// deleted creator's schedule kept firing unfiltered on a default install.)
[[nodiscard]] inline DispatchCaller caller_for_stored_username(const std::string& username,
                                                               bool principal_resolves,
                                                               std::string principal_role,
                                                               authz::VisibleSet exec_visible,
                                                               bool principal_is_admin = false) {
    if (!principal_resolves)
        return DispatchCaller{.exec_visible = authz::deny_all()};
    return DispatchCaller{.principal = username,
                          .principal_role = std::move(principal_role),
                          .exec_visible = std::move(exec_visible),
                          .system = false,
                          .principal_is_admin = principal_is_admin};
}

} // namespace yuzu::server
