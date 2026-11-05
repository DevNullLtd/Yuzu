#pragma once

/// @file workflow_execute_routes.hpp
/// `POST /api/v1/workflows/{id}/execute` — the REST v1 twin of the legacy
/// `POST /api/workflows/{id}/execute` and of MCP `execute_workflow` (#2146 batch B, ledger row
/// `post.api-workflows-param-execute`). A thin transport over `workflow_execute.hpp`'s shared
/// sequence: this file owns the surface gate (`Workflow:Execute`), body parsing, the principal
/// -> `DispatchCaller` derivation and the HTTP/A4 mapping, and nothing else.
///
/// Registered from `WorkflowRoutes::register_routes` (one call), with copies of the deps the
/// legacy execute route already uses, so a harness that wires `WorkflowRoutes` gets both.

#include "workflow_execute.hpp"
#include "workflow_routes.hpp"

#include <functional>
#include <memory>

namespace yuzu::server {

class HttpRouteSink;

/// Ports, not pointers: `WorkflowRoutes::register_routes` adapts its store pointers into these
/// once, and a test supplies fakes (the real `InstructionStore` and `ApprovalManager` are
/// Postgres-backed). Each `*_available` function is evaluated per request, so a store that
/// closes after boot is seen.
struct WorkflowExecuteRouteDeps {
    WorkflowRoutes::PermFn perm_fn;
    WorkflowRoutes::AuditFn audit_fn;
    /// The persist-reporting sink (true == written, or audit off). When unset the plain
    /// `audit_fn` is used and counted as persisted: the established audit-off contract.
    WorkflowRoutes::PersistAuditFn persist_audit_fn;
    std::shared_ptr<const WorkflowApi> workflow_api;
    WorkflowRunFn workflow_run; ///< unset == engine not available
    std::function<bool()> instruction_store_open; ///< unset == not available
    std::function<bool()> approval_gate_available; ///< unset == not available
    WorkflowInstructionLookupFn lookup;
    WorkflowClassifyFn classify;
    /// The shared chokepoint dry run (server.cpp's `authorize_dispatch`); unset == dispatch not
    /// available (503, nothing done).
    WorkflowAuthorizeFn authorize;
    /// The credential liveness check the run asks before each step; unset == no check (test
    /// harnesses only; production always wires it).
    WorkflowRoutes::RevalidateFn revalidate;
    /// The wait before the single retry of an indeterminate credential check; the default is the
    /// production value, a test shortens it.
    std::chrono::milliseconds reauthorize_retry_delay{kReauthorizeRetryDelay};
    WorkflowRoutes::CommandDispatchFn command_dispatch_fn;
    WorkflowRoutes::ConcurrencyDispatchFn command_dispatch_fn_concurrency;
    WorkflowRoutes::CallerFn caller_fn;
    yuzu::MetricsRegistry* metrics{nullptr};
    /// THE shared held-open budget (ADR-0034): a synchronous run holds its worker for up to
    /// `kWorkflowSyncBudget`, so it leases from the same instance as every streaming surface
    /// (`SseSurface::kWorkflowRun`). nullptr = unmetered (test harnesses only; production always
    /// wires it).
    detail::StreamBudget* stream_budget{nullptr};
    /// True while the server is draining. A run is refused then (`StreamBudget::try_acquire` does
    /// not consult its own closing flag). Unset = never draining (test harnesses).
    std::function<bool()> draining;
};

void register_workflow_execute_v1_route(HttpRouteSink& sink, WorkflowExecuteRouteDeps deps);

} // namespace yuzu::server
