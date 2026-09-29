#pragma once

/// @file offload_target_model.hpp
/// Shared PURE builder functions for the offload-target REST+MCP twins
/// (api-parity #2146 Batch B5) - `docs/api-twin-recipe.md` §1 Rule 1: "REST,
/// MCP, and the HTML dashboard fragment must call the same function to build
/// the response body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` - every
/// function here is callable from both `offload_routes.cpp` and
/// `mcp_server.cpp` with zero transport dependency, so the two JSON shapes
/// cannot drift apart by construction.
///
/// Adversarial-review fix (#2146 Batch B5, review round): `list_offload_targets`,
/// `get_offload_target`, and `list_offload_target_deliveries`'s REST handlers
/// and MCP twins each hand-rolled their own copy of this JSON - the exact
/// anti-pattern this doc's §1 names (`network_routes.cpp`'s duplicated
/// stat-row builders). `offload_routes.cpp`'s own `target_to_json` existed but
/// sat inside an anonymous namespace (internal linkage), structurally
/// uncallable from `mcp_server.cpp`.

#include "offload_target_store.hpp" // OffloadTarget / OffloadDelivery

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// One target row - `GET /api/v1/offload-targets`'s list, `GET
/// /api/v1/offload-targets/{id}`, and their MCP twins `list_offload_targets`/
/// `get_offload_target`. `auth_credential` is intentionally never in
/// `OffloadTarget` to begin with (write-only, envelope-encrypted at rest,
/// ADR-0010) - no redaction needed here.
nlohmann::json offload_target_json(const OffloadTarget& t);

/// One delivery-history row - `GET /api/v1/offload-targets/{id}/deliveries`
/// and its MCP twin `list_offload_target_deliveries`.
nlohmann::json offload_delivery_json(const OffloadDelivery& d);

} // namespace yuzu::server
