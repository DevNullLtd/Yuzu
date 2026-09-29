#pragma once

/// @file api_token_model.hpp
/// Shared PURE builder functions for the API-token REST+MCP twins (api-parity
/// #2146 Batch B4) - `docs/api-twin-recipe.md` §1 Rule 1: "REST, MCP, and the
/// HTML dashboard fragment must call the same function to build the response
/// body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` - every function here is
/// callable from both `rest_api_v1.cpp` and `mcp_server.cpp` with zero
/// transport dependency, so the two JSON shapes cannot drift apart by
/// construction.
///
/// Adversarial-review fix (#2146 Batch B4, review round): `list_api_tokens`
/// and `create_api_token`'s REST handlers and MCP twins each hand-rolled
/// their own copy of this JSON, the exact anti-pattern this doc's §1 names
/// (`network_routes.cpp`'s duplicated stat-row builders).

#include <string>

#include "api_token_store.hpp" // ApiToken

namespace yuzu::server {

/// One token row - `GET /api/v1/tokens`'s list and its MCP twin
/// `list_api_tokens`. Raw secrets are never in `ApiToken` to begin with
/// (verify-only hash, ADR-0010) - no redaction needed here.
std::string api_token_list_item_json(const ApiToken& t);

/// The mint-response ack - `POST /api/v1/tokens` and its MCP twin
/// `create_api_token`. `audit_ok` defaults true for REST (no
/// `audit_persisted` body field, relies on `Sec-Audit-Failed` header per the
/// per-surface audit fail-mode table); MCP passes its real `audit_fn` result.
/// One function either way - the deliberate REST/MCP fail-mode difference is
/// a parameter, not a second copy.
std::string api_token_create_ack_json(const std::string& token, const std::string& name,
                                      const std::string& scope_service, bool audit_ok = true);

} // namespace yuzu::server
