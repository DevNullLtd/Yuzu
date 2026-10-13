#pragma once

/// @file workflow_execution_list_model.hpp
/// Shared, pure model for the workflow-execution LIST — `GET /api/v1/workflow-executions` and the
/// MCP twin `list_workflow_executions`. REST (`workflow_routes.cpp`) and MCP (`mcp_server.cpp`)
/// call these SAME functions, so the accepted parameters, their bounds and the row shape cannot
/// drift between the two (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include, no store include (it includes only the pure
/// `workflow_types.hpp` / `list_keyset.hpp`). The SQL that answers a validated query lives with the
/// store (`build_execution_page_sql`, workflow_engine.hpp) — this file never sees a statement.
///
/// STRICT INPUT (the sibling v1 lists ignore unknown keys; this route does not): an unknown or
/// repeated parameter, an out-of-vocabulary `status`, a malformed `workflow_id`/`since`/`until`/
/// `cursor`, `since` after `until`, or `cursor` together with `latest_per_workflow` is refused,
/// never ignored — a mistyped filter must not silently read as "all runs". The one leniency is
/// `limit`: below 1 or non-integer is refused, above `kWorkflowExecutionListMax` is clamped, like
/// the sibling lists. Error messages name the parameter, never echo a caller value.

#include "workflow_types.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

/// `w1:<started_at>:<base64url(id)>` — see `keyset::encode_cursor`.
inline constexpr std::string_view kWorkflowExecutionCursorPrefix = "w1:";
inline constexpr int kWorkflowExecutionListDefaultLimit = 50;
inline constexpr std::size_t kWorkflowIdMaxLen = 128;
/// Upper bound for `since`/`until` (epoch seconds): 2^53, the largest integer a JSON client holds
/// exactly.
inline constexpr std::int64_t kWorkflowExecutionTimeMax = 9007199254740992;

/// One raw query parameter, in request order. A repeated key appears more than once.
using RawParam = std::pair<std::string, std::string>;

/// The REST parser: raw key/value pairs in, a validated query or the 400 message out.
[[nodiscard]] std::expected<WorkflowExecutionListQuery, std::string>
parse_workflow_execution_list_params(const std::vector<RawParam>& params);

/// The MCP parser: the `arguments` object in, a validated query or the `kInvalidParams` message
/// out. Same bounds as the REST parser; additionally every present argument must have its JSON
/// type (`limit`/`since`/`until` integers, `latest_per_workflow` a boolean, the rest strings).
[[nodiscard]] std::expected<WorkflowExecutionListQuery, std::string>
parse_workflow_execution_list_args(const nlohmann::json& args);

/// One list row: id, workflow_id, workflow_name, workflow_deleted, status, current_step,
/// started_at, completed_at. No agent ids, step results or fleet-size-bearing field, ever.
[[nodiscard]] nlohmann::json workflow_execution_summary_json(const WorkflowExecutionSummary& s);

/// `page.rows` as a JSON array of `workflow_execution_summary_json`.
[[nodiscard]] nlohmann::json workflow_execution_rows_json(const WorkflowExecutionPage& page);

/// The page's `next_cursor`: a string token when more rows exist, JSON null otherwise.
[[nodiscard]] nlohmann::json workflow_execution_next_cursor_json(const WorkflowExecutionPage& page);

} // namespace yuzu::server
