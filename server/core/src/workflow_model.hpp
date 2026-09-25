#pragma once

/// @file workflow_model.hpp
/// Shared, pure JSON row builders for the WorkflowEngine read surface
/// (workflow list/detail, workflow-execution detail) — REST v1
/// (`workflow_routes.cpp`) and MCP (`mcp_server.cpp`) call these SAME
/// functions so their JSON shapes cannot drift from each other by
/// construction (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include, no store include. ADR-0031
/// WS-A4's eighth family (`WorkflowApi`, `workflow_api.hpp`) relocated the
/// pure `Workflow`/`WorkflowExecution`/`WorkflowStepResult` types this file
/// needs out of the store-coupled `workflow_engine.hpp` into `workflow_
/// types.hpp` — this file now includes only that pure header, so it is
/// genuinely I/O-free AND store-free, unlike its earlier state. (An earlier
/// version of this file claimed "pure, I/O-free" while also holding the
/// schedule-family builder and `#include`ing both `schedule_engine.hpp` and
/// `workflow_engine.hpp` — that claim was false by the WS-A4 seam's own bar;
/// the seventh family split the schedule builder out into `schedule_model.
/// hpp` first, and this eighth family finishes the job for `workflow`
/// itself.)
///
/// #4030: executions/workflows/schedules read-twin programme.

#include "authz_model.hpp" // authz::VisibleSet / authz::in_scope
#include "workflow_types.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// List-row shape for `GET /api/workflows` / `GET /api/v1/workflows` / MCP
/// `list_workflows` — per-step summary (no `yaml_source`). Unlike the
/// pre-existing legacy `/api/workflows` list handler, this always includes
/// `retry_delay_seconds` per step (the legacy list omits it while the legacy
/// single-item route includes it — a pre-existing field drift within that
/// one file, not something #4030's new v1/MCP twin should carry forward).
nlohmann::json workflow_row_json(const Workflow& w);

/// Single-item detail shape for `GET /api/workflows/{id}` /
/// `GET /api/v1/workflows/{id}` / MCP `get_workflow` — full step list plus
/// `yaml_source`.
nlohmann::json workflow_detail_json(const Workflow& w);

/// Detail shape for `GET /api/workflow-executions/{id}` /
/// `GET /api/v1/workflow-executions/{id}` / MCP `get_workflow_execution` —
/// per-step results. `agent_ids_json`/`WorkflowStepResult::result_json` are
/// stored as JSON-text columns; this builder parses them permissively
/// (`nlohmann::json::parse(..., nullptr, false)`, matching the legacy
/// route's own tolerance for malformed/legacy rows) rather than failing the
/// whole response over one bad column.
///
/// `scope`, when engaged (non-nullopt), restricts the emitted `agent_ids`
/// array to `authz::in_scope(scope, id)` members (workflow-execution
/// confinement decision, #4030 — a caller confined by `fleet_read_fn` sees
/// only in-scope agent ids). `std::nullopt` is unrestricted, matching every
/// other `VisibleSet` consumer in the tree.
///
/// CALLERS MUST GATE THE RECORD FIRST via `workflow_execution_visible()`
/// below -- this builder only ever field-filters `agent_ids`; it has no way
/// to withhold `status`/`current_step`/`steps[]` for a caller with zero
/// visibility into the execution (#4030 Gate 8 fix, security-guardian Gate
/// 2 finding: the original cut called this builder unconditionally for any
/// id the caller supplied).
nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope);

/// Is `we` visible at all to a caller confined to `scope`? `WorkflowExecution`
/// carries no `dispatched_by` field (unlike `Execution`) — there is
/// deliberately NO ownership fallback here: visibility is
/// `has_visible_agent`-only. A caller who dispatched a workflow but has
/// since been re-scoped out of every one of its target agents loses
/// visibility to it — a consequence of the data model the fix accepts
/// rather than papers over (#4030 Gate 8 fix). `std::nullopt` scope is
/// always visible (unconfined/fleet-wide caller). A malformed/absent
/// `agent_ids_json` fails CLOSED (not visible) for a confined caller rather
/// than silently admitting.
///
/// Full scan, no early exit — mirrors `execution_scope_rules.hpp`'s
/// `execution_visible()` anti-timing-oracle rationale: an early `return
/// true` on the first in-scope id makes wall-clock time a function of WHERE
/// in `agent_ids` the first visible entry falls, a scan-length existence
/// oracle on the admit path.
[[nodiscard]] bool workflow_execution_visible(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope);

/// Confined `agent_ids` array for a workflow execution — parses
/// `agent_ids_json` permissively and narrows to `authz::in_scope(scope,
/// id)` members. Factored out so `workflow_execution_detail_json` and the
/// legacy `GET /api/workflow-executions/:id` route (which keeps its own,
/// differently-shaped response envelope and is therefore not migrated onto
/// the builder above) compute the SAME confined array rather than risking
/// two hand-copied loops drifting apart (#4030 Gate 8 fix).
nlohmann::json confined_workflow_agent_ids_json(const std::string& agent_ids_json,
                                                const authz::VisibleSet& scope);

/// Confined per-step `result` value — parses `result_json` permissively (a
/// parse failure embeds as JSON `null`, never the literal nlohmann
/// `<discarded>` sentinel text that an un-guarded embed produces, #4030
/// Gate 8 fix / Gate 4 unhappy-path finding UP-2) and, when `confined` is
/// true, strips the `agents_reached` key from the result (handles both the
/// single-object and the foreach-expanded array shape
/// `WorkflowEngine::execute` can produce, `workflow_engine.cpp`). That key
/// is the raw fleet-wide dispatch count for the step's FULL target-agent
/// list (`workflow_routes.cpp`'s `dispatch_fn`, `{"agents_reached", sent}`)
/// — not the confined caller's visible subset — so emitting it verbatim to
/// a confined caller discloses the true out-of-scope agent count by simple
/// arithmetic, the same disclosure class this file's sibling KPI strip
/// guards against for `Execution` (`workflow_routes.cpp`, the "#1712"
/// comment on `render_results`'s `total_agent_count`). Shared by
/// `workflow_execution_detail_json` and the legacy route for the same
/// no-drift reason as `confined_workflow_agent_ids_json` above.
nlohmann::json confined_workflow_step_result_json(const std::string& result_json, bool confined);

} // namespace yuzu::server
