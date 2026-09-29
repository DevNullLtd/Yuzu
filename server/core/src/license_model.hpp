#pragma once

/// @file license_model.hpp
/// Shared PURE builder functions for the platform-license REST+MCP twins
/// (api-parity #2146 Batch B5) - `docs/api-twin-recipe.md` §1 Rule 1: "REST,
/// MCP, and the HTML dashboard fragment must call the same function to build
/// the response body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` - every
/// function here is callable from both `rest_api_v1.cpp` and
/// `mcp_server.cpp` with zero transport dependency, so the two JSON shapes
/// cannot drift apart by construction.
///
/// Adversarial-review fix (#2146 Batch B5, review round): `get_platform_license`
/// and `list_license_alerts`'s REST handlers and MCP twins each hand-rolled
/// their own copy of this JSON - the exact anti-pattern this doc's §1 names
/// (`network_routes.cpp`'s duplicated stat-row builders). Concrete proof of
/// the cost: `list_license_alerts` drifted between the two copies mid-
/// development (a missing `license_id` field caught and hand-patched on
/// both sides separately) before this fix.

#include <cstdint>

#include "license_store.hpp" // License / LicenseAlert

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// The active-license detail shape - `GET /api/v1/license` and its MCP twin
/// `get_platform_license`, for the case a license IS activated. The
/// `{"status":"none"}` no-license case is a distinct, trivial literal on
/// both surfaces and is not routed through this builder.
nlohmann::json platform_license_json(const License& lic, int64_t days_remaining);

/// One alert row - `GET /api/v1/license/alerts` and its MCP twin
/// `list_license_alerts`.
nlohmann::json license_alert_json(const LicenseAlert& a);

} // namespace yuzu::server
