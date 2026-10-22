#pragma once

/// @file openapi_spec_access.hpp
///
/// Thin external-linkage accessor for the OpenAPI 3.0 spec JSON. The spec
/// itself (`openapi_spec()`) is a large hand-maintained raw string defined in
/// an anonymous namespace in `rest_api_v1.cpp` (TU-local by design — see the
/// comment there on why it is a raw string rather than an nlohmann::json
/// initializer list). This header exists so `GET /api/v1/discover/routes`
/// (`discover_routes.cpp`) and its MCP twin (`discover_routes` tool,
/// `mcp_server.cpp`) can subset the SAME document `/api/v1/openapi.json`
/// serves, instead of maintaining a second copy that would drift from it.

#include <string>

namespace yuzu::server {

/// Returns the exact JSON body `GET /api/v1/openapi.json` serves by default. It is the full
/// document without the per-group guides (`tags[].x-yuzu-guide`), which are prose for the
/// /swagger page. The MCP resource `yuzu://openapi` and the discover tools serve exactly this
/// form; only `?guides=true` (see `openapi_spec_with_guides_json()`) differs from it.
const std::string& openapi_spec_json();

/// Removes `x-yuzu-guide` from every top-level tag of `full` and re-serialises it. Returns `full`
/// unchanged, and sets `*fell_back`, when it cannot be parsed or has no `tags` array. The pure
/// derivation behind `openapi_spec_json()`, exposed so the fallback can be tested.
std::string openapi_strip_guides(const std::string& full, bool* fell_back = nullptr);

/// The full document including the guides: what `GET /api/v1/openapi.json?guides=true`
/// serves and what the /swagger page loads.
const std::string& openapi_spec_with_guides_json();

} // namespace yuzu::server
