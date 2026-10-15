#pragma once

/// @file execution_model.hpp
/// Shared, pure JSON row builders for the ExecutionTracker/ResponseStore read
/// surface (executions list, per-agent status expansion, KPI summary,
/// execution-scoped responses) — REST v1 (`rest_api_v1.cpp`) and MCP
/// (`mcp_server.cpp`) call these SAME functions so their JSON shapes cannot
/// drift from each other by construction (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include — pure, I/O-free. Each function
/// takes only the domain struct(s) the caller has already fetched (and
/// already applied confinement/visibility decisions to, via
/// `execution_scope_rules.hpp`'s `execution_visible`/`confined_projection`)
/// and returns `nlohmann::json`.
///
/// #4030: executions/workflows/schedules read-twin programme.

#include "execution_tracker.hpp"
#include "response_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// One row of a resolved, already-confined execution-list read. The caller
/// is responsible for resolving `definition_name` (an
/// `InstructionStore::get_definition` lookup — memoize per request, the
/// fragment's own per-row lookup is an accepted N+1 at its LIMIT 50; a v1
/// list route capped at 500 must not repeat it unmemoized) and
/// `error_preview` (a truncated `last_error_detail` — taken from
/// `ConfinedCounts::last_error_detail` under confinement, never the raw
/// `Execution::last_error_detail`, which is unconfined fleet-wide data).
/// This struct is the FINAL, display-ready shape, not a re-derivation seam.
struct ExecutionListRow {
    std::string id;
    std::string definition_id;
    std::string definition_name; // empty if unresolved/unknown
    std::string status;
    std::string dispatched_by;
    int64_t dispatched_at{0};
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t completed_at{0};
    std::string rerun_of;
    std::string error_preview; // truncated last_error_detail; empty if none
};

/// `GET /fragments/executions`'s fuller field set (definition name + error
/// preview + the agents_success/agents_failure split) reconciled onto REST
/// v1's new `GET /api/v1/executions` list route and MCP's widened
/// `list_executions` tool (#4030).
nlohmann::json execution_list_row_json(const ExecutionListRow& row);

/// Per-agent status/duration row for the execution-detail per-agent
/// expansion (`?include=agents` on `GET /api/v1/executions/{id}` and MCP
/// `get_execution_status`'s `include` param) — same field set as the
/// pre-existing legacy `GET /api/executions/{id}/agents` route
/// (`server.cpp:17291`), so #4030's new v1/MCP surface is a genuine twin of
/// it rather than a third independent shape.
nlohmann::json execution_agent_status_json(const AgentExecStatus& a);

/// KPI summary (succeeded/failed counts + p50/p95 duration in ms) computed
/// from a set of already-fetched, already-confined `AgentExecStatus` rows.
/// Only TERMINAL rows (success/failure/timeout/rejected — matches
/// `execution_scope_rules.hpp::confined_projection`'s definition of
/// "responded") with a usable `completed_at >= dispatched_at` contribute a
/// duration sample; an agent still `running` has no duration yet and must
/// not skew the percentile.
struct ExecutionKpi {
    int total{0};
    int succeeded{0};
    int failed{0};
    double p50_ms{0};
    double p95_ms{0};
    /// false when no terminal row had a usable duration (e.g. every agent
    /// still running) — the fragment's own "—" fallback for this case.
    bool has_duration_data{false};
};
[[nodiscard]] ExecutionKpi compute_execution_kpi(const std::vector<AgentExecStatus>& agents);
nlohmann::json execution_kpi_json(const ExecutionKpi& k);

/// One row of a resolved, already-confined child-execution read (`GET
/// /api/v1/executions/{id}/children`, the legacy `GET
/// /api/executions/{id}/children`, and MCP `get_execution_children` -
/// #2146 A2-R1). Deliberately the narrower field set the legacy route has
/// always returned (`id`/`status`/`dispatched_at`) - the caller has already
/// applied `execution_scope_rules.hpp`'s `execution_visible` to `c`
/// independently of its parent's own visibility (a visible parent does not
/// by itself authorize enumerating a child dispatched by, or targeting,
/// someone else).
nlohmann::json execution_child_row_json(const Execution& c);

/// Execution-scoped response row for `GET /api/v1/executions/{id}/responses`
/// ONLY. *(Correction, #2146 A2-R2: this doc comment previously claimed
/// FIELD-SET PARITY with MCP `query_responses` on the grounds that
/// `query_responses` built its row inline with the same 5 fields --
/// `query_responses` now calls the WIDER `response_query_row_json`
/// (`response_query_model.hpp`, which adds id/instruction_id/error_detail/
/// plugin/received_at_ms) on BOTH its instruction_id and execution_id
/// paths, so that parity claim no longer holds and would be a stale-comment
/// truth defect if left as written.)* This function remains the narrower,
/// execution-ID-keyed shape (agent_id/execution_id/status/output/timestamp)
/// for the `/api/v1/executions/{id}/responses` REST route specifically --
/// out of scope for A2-R2 (a different, already-shipped capability keyed on
/// execution_id, not instruction_id). Retrofitting THIS route onto the
/// wider builder, or removing this function in favor of it, is a separate,
/// future decision, not something A2-R2 does -- tracked as #4647.
nlohmann::json execution_response_row_json(const StoredResponse& r);

} // namespace yuzu::server
