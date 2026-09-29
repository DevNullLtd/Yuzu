#pragma once

/// @file software_deployment_model.hpp
/// Shared PURE builder function for the software-deployment REST+MCP twins
/// (api-parity #2146 Batch B5) - `docs/api-twin-recipe.md` §1 Rule 1 and §8's
/// own worked example, which names this exact file/function as the
/// prescribed fix for this exact domain. No `httplib.h`, no
/// `mcp_jsonrpc.hpp` - callable from both `rest_api_v1.cpp` and
/// `mcp_server.cpp` with zero transport dependency, so the two JSON shapes
/// cannot drift apart by construction.
///
/// Adversarial-review fix (#2146 Batch B5, review round): `list_software_deployments`'s
/// REST handler and MCP twin each hand-rolled their own copy of this JSON -
/// the exact anti-pattern this doc's §1 names, and the one §8's worked
/// example uses this domain to illustrate as "step 1" before adding a twin.
/// This PR shipped the twin without that step; this file closes the gap.

#include "software_deployment_store.hpp" // SoftwareDeployment

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// One deployment row - `GET /api/v1/software-deployments` and its MCP twin
/// `list_software_deployments`.
nlohmann::json software_deployment_row_json(const SoftwareDeployment& d);

} // namespace yuzu::server
