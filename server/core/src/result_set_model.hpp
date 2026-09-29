#pragma once

/// @file result_set_model.hpp
/// PURE JSON builder shared between REST (`rest_api_v1.cpp`'s result-set
/// routes) and MCP (the result-set MCP tools, #2146 Batch B2) so the two
/// surfaces' `ResultSet` wire shape cannot drift (api-twin-recipe.md Rule 1
/// — same discipline as `deploy_preview_json`/`preflight_run_row_json`).
/// No httplib.h dependency.

#include "result_set_store.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// The full `ResultSet` row as REST/MCP both serve it: id, name,
/// owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id
/// (empty string when unset — a ground set has no parent), source_kind,
/// status (string form), source_execution_id, device_count.
nlohmann::json result_set_json(const ResultSet& r);

} // namespace yuzu::server
