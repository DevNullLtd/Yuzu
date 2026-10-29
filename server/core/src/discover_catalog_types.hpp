#pragma once

/// @file discover_catalog_types.hpp
/// The `/discover/*` catalogue value type (`DiscoveryDoc`) and `build_routes_catalog`, the one
/// builder whose only input is the OpenAPI JSON (no store or registry argument), split out of
/// `discover_routes.hpp` so the MCP registry lane (`mcp_tools_discovery.cpp`) can name them
/// without including `instruction_store.hpp` / `rbac_store.hpp` (ADR-0031 seam closure, #6558).
/// Not to be confused with `discovery_types.hpp`, which holds the network-discovery
/// (discovered-hosts) row types. `discover_routes.hpp` re-includes this header, so
/// existing includers are unaffected, and the definition of `build_routes_catalog`
/// stays in `discover_routes.cpp`.

#include <string>

namespace yuzu::server {

/// A built discovery response plus its content-derived ETag. Mirrors
/// guardian::SchemaCatalog (guardian_schema_registry.hpp) — same shape, same
/// FNV-1a content-hash idiom (build_discovery_doc in discover_routes.cpp) —
/// but not reused directly since that type lives in the `guardian` namespace
/// for a different catalog.
struct DiscoveryDoc {
    std::string json; ///< serialised JSON body
    std::string etag; ///< strong ETag, e.g. "\"<hex>\"" — changes iff `json` changes
};

/// `/discover/routes`. Subsets the OpenAPI document
/// (`yuzu::server::openapi_spec_json()`, openapi_spec_access.hpp) to
/// {method, path, summary, tags, description} per operation. Carries
/// `"source":"openapi"` plus a caveat string: the OpenAPI document is
/// hand-maintained, not generated from the live route table, and can
/// under-report. `openapi_json` is the OpenAPI document body, normally
/// the default form without the per-group guides (caller
/// supplies it so this function has no direct dependency on rest_api_v1.*).
DiscoveryDoc build_routes_catalog(const std::string& openapi_json);

} // namespace yuzu::server
