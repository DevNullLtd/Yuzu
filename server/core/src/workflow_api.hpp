#pragma once

/// @file workflow_api.hpp
/// The EIGHTH per-family in-process API seam for the presentation/core/
/// engine split (ADR-0031, WS-A4), covering the multi-step-workflow READ
/// surface plus (since #2146 batch B) the execute mutator — the Postgres-backed
/// `WorkflowEngine`'s `GET /api/v1/workflows`, `GET /api/v1/workflows/{id}`, `GET /api/v1/workflow-executions` and
/// `GET /api/v1/workflow-executions/{id}` resources (and their MCP twins
/// `list_workflows`/`get_workflow`/`list_workflow_executions`/
/// `get_workflow_execution`). Abstract, ZERO store-shaped dependencies — it
/// includes only the pure, std-only `workflow_types.hpp` and `authz_model.hpp`
/// plus std headers, so this header can be included by a future
/// presentation-side client without dragging the server's `WorkflowEngine` (a
/// Postgres-backed store, `workflow_engine.hpp`) along.
///
/// The four read methods == the four public REST v1 resources above (plus their
/// MCP twins), and `execute_workflow` == `POST /api/v1/workflows/{id}/execute` (plus its twin), so a presentation/MCP caller consumes only what the public,
/// versioned core API serves (ADR-0031 B3, INV-31-4 "no private core API") —
/// a local in-process implementation today (`LocalWorkflowApi`,
/// `workflow_api.cpp`), a core HTTP client after the WS-B2 cutover. Adding a
/// method here without a corresponding public REST/MCP resource would
/// reintroduce a private core API and defeat the point of the seam.
///
/// The store-backed factory (`make_local_workflow_api`) lives in the
/// core-only `workflow_api_local.hpp` — this header names no store type at
/// all, not even by forward declaration, so a presentation TU including it
/// cannot reach one.
///
/// `execute_workflow` (#2146 batch B, the workflow-execute twins `POST
/// /api/v1/workflows/{id}/execute` / MCP `execute_workflow`) is the one MUTATOR in this seam. It
/// was previously excluded on purpose; adding it is an architect-reviewed change. It is a thin
/// wrap of `WorkflowEngine::execute`: the caller supplies the per-step dispatch callback, so the
/// confinement, approval-mode, targeting and audit decisions stay in the shared
/// `workflow_execute.hpp` sequence both transports run, not in this interface. A method that
/// takes an in-process callback is NOT HTTP-shaped: it works for the local implementation and
/// will have to be rethought (the engine, not the presentation tier, must own step dispatch)
/// when the WS-B2 core HTTP client replaces `LocalWorkflowApi`. This is not cutover-ready and is
/// not claimed to be.
///
/// Deliberately still NOT in this seam: the legacy unversioned `POST /api/workflows` (create),
/// `DELETE /api/workflows/{id}` and `POST /api/workflows/{id}/execute` mutators, and the legacy
/// unversioned GET routes (`GET /api/workflows`, `GET /api/workflows/{id}`,
/// `GET /api/workflow-executions/{id}`) — a SEPARATE, deliberately untouched
/// capability with no public REST v1/MCP twin of their own (create and delete) or
/// sharing the SAME store call as their v1 twin without themselves being the
/// versioned resource (the legacy GETs; `workflow_routes.cpp` keeps its own
/// `WorkflowEngine*` wiring for them, unaffected by this seam — mirrors the
/// `schedule` family's precedent for its own legacy `/api/schedules`
/// mutators, #4334-style: there is nothing to carve out of an enforced TU
/// here, since these routes were never in it). The legacy execute route keeps its own
/// handler and its own (fail-open when unwired) approval pre-check; only the v1 twin and the
/// MCP tool run the shared fail-closed sequence.

#include "authz_model.hpp" // authz::VisibleSet: the caller's admitted agent set (pure, store-free)
#include "workflow_types.hpp"

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The in-process public workflow-read API. Each method == one public
/// REST v1 / MCP resource, so presentation/MCP consume only what the public,
/// versioned core API serves (ADR-0031 B3, INV-31-4) — a local in-process
/// client today, a core HTTP client after the WS-B2 cutover.
class WorkflowApi {
public:
    virtual ~WorkflowApi() = default;

    /// The workflow list behind `GET /api/v1/workflows` / MCP
    /// `list_workflows`. `std::unexpected` distinguishes a real store
    /// failure (including an engine that failed to open) from a genuinely
    /// empty table — every caller must surface this as a degrade, never as
    /// "no workflows". The error string is INTERNAL (a store/pool
    /// diagnostic, not sanitized for display); a caller rendering it to an
    /// operator or returning it over REST/MCP MUST run it through
    /// `genericize_db_error(...)` first, exactly as the REST v1 and MCP
    /// callers already do.
    [[nodiscard]] virtual std::expected<std::vector<Workflow>, std::string>
    list_workflows(const WorkflowQuery& q) const = 0;

    /// The single-workflow detail behind `GET /api/v1/workflows/{id}` / MCP
    /// `get_workflow`. `nullopt` = a successful read finding none (or the
    /// workflow is soft-deleted, ADR-0064). `std::unexpected` is a genuine
    /// read failure — never treat it as "not found".
    [[nodiscard]] virtual std::expected<std::optional<Workflow>, std::string>
    get_workflow(const std::string& id) const = 0;

    /// The workflow-execution detail behind
    /// `GET /api/v1/workflow-executions/{id}` / MCP
    /// `get_workflow_execution`. Same `nullopt`-vs-`unexpected` contract as
    /// `get_workflow` above. The caller MUST gate the record with
    /// `workflow_execution_visible()` (`workflow_model.hpp`) before building
    /// a response from it — this method has no confinement of its own.
    [[nodiscard]] virtual std::expected<std::optional<WorkflowExecution>, std::string>
    get_workflow_execution(const std::string& id) const = 0;

    /// The workflow-execution LIST behind `GET /api/v1/workflow-executions` / MCP
    /// `list_workflow_executions`: metadata rows only, newest first (or each workflow's newest run,
    /// `q.latest_per_workflow`). `scope` is the caller's composed fleet-read scope from
    /// `fleet_read_fn` (`nullopt` = unfiltered, engaged-empty = deny-all) and has NO default on
    /// purpose: a run is returned only if it has at least one agent in `scope`, decided in the
    /// store BEFORE `ORDER BY`/`LIMIT` (ADR-0017 INV-3), so a caller can never be handed a row
    /// `workflow_execution_visible()` would refuse and a page can never be consumed by invisible
    /// rows. `std::unexpected` is a genuine store failure (incl. a statement timeout), never an
    /// empty page — surface it as a degrade, through `genericize_db_error(...)` like the methods
    /// above.
    [[nodiscard]] virtual std::expected<WorkflowExecutionPage, std::string>
    list_workflow_executions(const WorkflowExecutionListQuery& q,
                             const authz::VisibleSet& scope) const = 0;

    /// Start one execution of `workflow_id` against `agent_ids` — a thin wrap of
    /// `WorkflowEngine::execute`. The engine admits the run (creates the execution row and the
    /// pending step rows in one transaction, re-proving the workflow is not soft-deleted),
    /// then calls `dispatch_fn` for each step SYNCHRONOUSLY on the calling thread, including
    /// retry sleeps, and returns the execution id once the step loop has finished. A failed
    /// step is recorded in the execution, not returned here.
    ///
    /// This method has NO authorization, confinement, approval-mode or audit logic of its own:
    /// every caller MUST run the shared sequence in `workflow_execute.hpp`, which decides all
    /// of that BEFORE this call and supplies a `dispatch_fn` that confines each step to the
    /// caller. Calling it directly would dispatch to the named agents unconfined.
    ///
    /// `std::unexpected` carries the engine's own text: a `kDbErrorPrefix` store failure
    /// (genericize before display) or "workflow not found: ..." / "workflow has no steps".
    [[nodiscard]] virtual std::expected<std::string, std::string>
    execute_workflow(const std::string& workflow_id, const std::vector<std::string>& agent_ids,
                     StepDispatchFn dispatch_fn, ConditionEvalFn condition_fn) const = 0;
};

} // namespace yuzu::server
