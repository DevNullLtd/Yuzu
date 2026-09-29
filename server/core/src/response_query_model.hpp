#pragma once

/// @file response_query_model.hpp
/// Shared, pure JSON row builders for the command/instruction-ID-keyed
/// response query/aggregate/export surface (#2146 A2-R2) -- REST v1
/// (`rest_api_v1.cpp`'s `GET /api/v1/responses/{instruction_id}` family) and
/// MCP (`mcp_server.cpp`'s `query_responses` / `aggregate_responses` tools)
/// call these SAME functions so their JSON shapes cannot drift from each
/// other by construction (`docs/api-twin-recipe.md` Rule 1).
///
/// Distinct from `execution_model.hpp`'s `execution_response_row_json` --
/// that builder serves a DIFFERENT, already-shipped surface (the
/// execution-ID-keyed `GET /api/v1/executions/{id}/responses` twin, and
/// `query_responses`'s `execution_id` path before this PR). This file's
/// `response_query_row_json` is deliberately WIDER (adds `id`,
/// `instruction_id`, `error_detail`, `plugin`, `received_at_ms` on top of
/// `execution_response_row_json`'s agent_id/execution_id/status/output/
/// timestamp) and is now what `query_responses` calls on BOTH its
/// instruction_id and execution_id paths (#2146 A2-R2) -- see the file
/// comment on `execution_response_row_json` for why that builder was left
/// narrower rather than widened or removed.
///
/// The legacy unversioned routes (`response_routes.cpp`'s `GET
/// /api/responses/{instruction_id}`, `.../aggregate`, `.../export`) are NOT
/// retrofitted onto these builders -- they are frozen read-only reference
/// code for this PR (out of scope to touch), so a byte-for-byte "same
/// function" claim across all three surfaces does not hold for them. REST
/// v1 and MCP are the two callers this file exists to keep from drifting
/// from EACH OTHER; the legacy route remains a third, independent, frozen
/// copy of a narrower field set by explicit choice, not oversight.
///
/// No httplib.h, no MCP-specific include -- pure, I/O-free.

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "response_store.hpp"

namespace yuzu::server {

/// One response row for the instruction/command-ID-keyed query surface:
/// legacy `GET /api/responses/{instruction_id}` mirrors this field set by
/// convention (not by calling this function -- see file comment), its v1
/// twin `GET /api/v1/responses/{instruction_id}` calls it directly, and MCP
/// `query_responses` calls it for both its instruction_id and execution_id
/// paths. Superset of the legacy REST route's hand-rolled shape
/// (id/instruction_id/agent_id/timestamp/status/output/error_detail) plus:
///   - `execution_id` -- the dispatch-correlation field `query_responses`
///     has always emitted (unchanged by this PR);
///   - `plugin` / `received_at_ms` -- genuinely useful, non-sensitive
///     correlation/debugging metadata already on `StoredResponse` (#2146
///     A2-R2 judgment call: exposed because they help a caller reconcile
///     agent-claimed vs. server-received time and disambiguate which
///     plugin produced a row on a multi-step instruction; `ttl_expires_at`
///     and `plugin_result_status` were deliberately left OFF this row --
///     the former is pure retention housekeeping with no caller-facing
///     value, the latter is a second, narrower status code this PR's brief
///     did not ask for and every existing consumer already has `status`).
[[nodiscard]] nlohmann::json response_query_row_json(const StoredResponse& r);

/// One aggregate-group result row for `GET .../aggregate` (legacy + v1) and
/// MCP `aggregate_responses`. Matches the legacy route's hand-rolled shape
/// exactly (`group_value`/`count`/`aggregate_value`) -- no widening needed
/// here, `AggregationResult` carries nothing else.
[[nodiscard]] nlohmann::json response_aggregate_row_json(const AggregationResult& r);

/// CSV header row for the v1 export surface (`GET
/// /api/v1/responses/{instruction_id}/export?format=csv`). Unlike the
/// legacy export's 7-column CSV (which this PR does not touch), the v1 CSV
/// export carries the SAME field set as `response_query_row_json` -- this
/// is a brand-new endpoint with no positional-column consumer to keep
/// compatible, so there is no reason to ship a narrower CSV next to the
/// richer JSON shape on the same route.
inline constexpr std::string_view kResponseExportCsvHeader =
    "id,instruction_id,agent_id,execution_id,status,output,error_detail,timestamp,plugin,"
    "received_at_ms\r\n";

/// One RFC-4180-escaped CSV row (via `data_export::csv_escape`), in
/// `kResponseExportCsvHeader`'s column order.
[[nodiscard]] std::string response_export_csv_row(const StoredResponse& r);

} // namespace yuzu::server
