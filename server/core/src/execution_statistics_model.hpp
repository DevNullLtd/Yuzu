#pragma once

/// @file execution_statistics_model.hpp
/// Shared PURE builder functions for the execution/fleet statistics REST+MCP
/// twins (api-parity #2146 Batch B3) — `docs/api-twin-recipe.md` §1 Rule 1:
/// "REST, MCP, and the HTML dashboard fragment must call the same function to
/// build the response body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` —
/// every function here is callable from both `rest_api_v1.cpp` and
/// `mcp_server.cpp` with zero transport dependency, so the two JSON shapes
/// cannot drift apart by construction.
///
/// **Formatting note (load-bearing):** every function here returns a plain
/// `std::format`-built string rather than an `nlohmann::json` object,
/// DELIBERATELY. `rest_api_v1.cpp`'s pre-existing `JObj::add(key, double)`
/// formats every double as fixed `{:.2f}` (two decimal places, always —
/// `100.0` serializes as `"100.00"`). `nlohmann::json`'s own number
/// serializer uses a shortest-round-trip algorithm instead, which does NOT
/// reproduce that convention for a whole-valued double (`100.0` would dump
/// as `"100.0"`, not `"100.00"`) — routing these fields through
/// `nlohmann::json` would silently reshape the existing REST wire format the
/// moment the REST handlers below are switched to call this shared builder.
/// Matching `{:.2f}` exactly here keeps the REST responses byte-identical
/// pre/post this refactor.
///
/// #2146 Batch B3 is the first consumer: `GET /api/v1/execution-statistics`
/// (+ `/agents`, `/definitions`) and `GET /api/v1/statistics` previously
/// built their JSON inline in the REST handler with no MCP caller — this
/// file promotes each block to a named, shared function per the recipe's §8
/// worked example (`software_deployment_row_json`).

#include <string>

#include "execution_tracker.hpp" // FleetExecutionSummary/AgentExecutionStats/DefinitionExecutionStats

namespace yuzu::server {

/// Flat execution-summary object — `GET /api/v1/execution-statistics`
/// (capability 1.9) and its MCP twin `get_execution_statistics`.
/// `{"total_executions","executions_today","active_agents",
/// "overall_success_rate","avg_duration_seconds"}`.
std::string fleet_execution_summary_json(const FleetExecutionSummary& s);

/// Fleet-dashboard shape — `GET /api/v1/statistics` (capability 22.6) and its
/// MCP twin `get_fleet_statistics`. Same underlying `FleetExecutionSummary`
/// as `fleet_execution_summary_json` above, reshaped: execution fields nest
/// under `"executions"`, `active_agents` stays top-level. Deliberately a
/// DIFFERENT function/shape, not a rename — the two REST routes are
/// independent API contracts that happen to share a data source today.
std::string fleet_statistics_json(const FleetExecutionSummary& s);

/// One row — `GET /api/v1/execution-statistics/agents` and its MCP twin
/// `get_execution_statistics_by_agent`.
std::string agent_execution_stats_row_json(const AgentExecutionStats& s);

/// One row — `GET /api/v1/execution-statistics/definitions` and its MCP twin
/// `get_execution_statistics_by_definition`.
std::string definition_execution_stats_row_json(const DefinitionExecutionStats& s);

} // namespace yuzu::server
