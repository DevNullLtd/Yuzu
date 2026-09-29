#pragma once

/// @file workflow_api.hpp
/// The EIGHTH per-family in-process API seam for the presentation/core/
/// engine split (ADR-0031, WS-A4), covering the multi-step-workflow READ
/// surface — the Postgres-backed `WorkflowEngine`'s `GET /api/v1/workflows`,
/// `GET /api/v1/workflows/{id}` and `GET /api/v1/workflow-executions/{id}`
/// resources (and their MCP twins `list_workflows`/`get_workflow`/
/// `get_workflow_execution`). Abstract, ZERO store-shaped dependencies — it
/// includes only the pure `workflow_types.hpp` + std headers, so this header
/// can be included by a future presentation-side client without dragging the
/// server's `WorkflowEngine` (a Postgres-backed store, `workflow_engine.hpp`)
/// along.
///
/// The three methods == the three public REST v1 resources above (plus their
/// MCP twins), so a presentation/MCP caller consumes only what the public,
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
/// Deliberately NOT in this seam: the legacy unversioned `POST /api/workflows`
/// (create), `DELETE /api/workflows/{id}` and
/// `POST /api/workflows/{id}/execute` mutators, and the legacy unversioned
/// GET routes (`GET /api/workflows`, `GET /api/workflows/{id}`,
/// `GET /api/workflow-executions/{id}`) — a SEPARATE, deliberately untouched
/// capability with no public REST v1/MCP twin of their own (the mutators) or
/// sharing the SAME store call as their v1 twin without themselves being the
/// versioned resource (the legacy GETs; `workflow_routes.cpp` keeps its own
/// `WorkflowEngine*` wiring for both, unaffected by this seam — mirrors the
/// `schedule` family's precedent for its own legacy `/api/schedules`
/// mutators, #4334-style: there is nothing to carve out of an enforced TU
/// here, since these routes were never in it).

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
};

} // namespace yuzu::server
