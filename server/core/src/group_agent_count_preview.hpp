#pragma once

/// @file group_agent_count_preview.hpp
/// Shared REST+MCP model for the create-group agent-count preview (#4033,
/// #2146 Batch A) — see the NOTE below for why "shared" stops at REST+MCP
/// and does not extend to the dashboard fragment. `/fragments/create-group-
/// form` (dashboard_routes.cpp) queries `ResponseStore::facet_agent_count`
/// inline; this pair of PURE functions (no httplib.h, no mcp_jsonrpc.hpp) is
/// the SAME logic factored out so `GET /api/v1/management-groups/agent-count-
/// preview` and its MCP twin `preview_management_group_agent_count` call it
/// too — recipe Rule 1 (docs/api-twin-recipe.md §1): REST and MCP cannot
/// drift from EACH OTHER on "what counts as a filter" or "empty filters
/// means a genuine zero" by construction. The fragment is NOT a third party
/// to that construction — see NOTE.
///
/// NOTE: the dashboard fragment (`DashboardRoutes::parse_filters`,
/// dashboard_routes.cpp) is NOT refactored onto `resolve_group_preview_filters`
/// by this PR — it stays on its own `httplib::Request`-coupled `f_<column>`
/// param extraction (out of scope; the fragment's behaviour is unchanged).
/// `resolve_group_preview_filters` exists so the NEW REST/MCP surfaces share
/// ONE column-name -> FacetFilter{col_idx,value} resolver with each other,
/// using the SAME mangled-key convention (`mangle_column_key`) the fragment's
/// `f_<column>` params already use, so a caller who has seen the dashboard's
/// URLs recognises the REST/MCP filter keys immediately.

#include "response_store.hpp" // FacetFilter

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

class ResponseStore;

/// Lowercase `column_name`, replacing ' '/'-' with '_' — the SAME mangling
/// `DashboardRoutes::parse_filters`'s `f_<column>` query-param convention
/// applies (dashboard_routes.cpp). E.g. "Local Addr" -> "local_addr".
std::string mangle_column_key(std::string_view column_name);

/// Resolve `plugin`'s mangled filter keys (see `mangle_column_key`) into
/// `FacetFilter{col_idx,value}` pairs against `columns_for_plugin(plugin)`'s
/// column layout (result_parsing.hpp; column 0 is always "Agent" and is
/// never itself filterable). An unrecognised key is silently skipped —
/// mirrors `DashboardRoutes::parse_filters`'s behaviour for an unknown
/// `f_<x>` param (an unfilterable/misspelled field just contributes no
/// filter, rather than erroring the whole preview).
std::vector<FacetFilter> resolve_group_preview_filters(
    const std::string& plugin, const std::vector<std::pair<std::string, std::string>>& fields);

/// PURE: the create-group agent-count preview — mirrors
/// `/fragments/create-group-form`'s own derivation exactly: empty `filters`
/// is a GENUINE `0` (no scoped count to report — never a store call, matching
/// the fragment's "filters.empty() -> agent_count = 0" branch), never a
/// degrade. Otherwise defers to `ResponseStore::facet_agent_count`'s own
/// degrade-distinguishable contract (`nullopt` = store/pool/query failure,
/// NEVER conflated with a genuine 0 match count). `store == nullptr` with a
/// non-empty `filters` is ALSO `nullopt` (unconfigured — same posture as a
/// degraded store, so a caller cannot tell "store unwired" from "store
/// down", which is the right answer: both are "cannot answer right now").
/// `agent_scope`: `nullopt` = unfiltered (global grant / elevated / RBAC
/// off); engaged (including empty) = filter to exactly these agents.
std::optional<std::int64_t>
group_agent_count_preview(ResponseStore* store, const std::string& command_id,
                          const std::vector<FacetFilter>& filters,
                          const std::optional<std::vector<std::string>>& agent_scope);

} // namespace yuzu::server
