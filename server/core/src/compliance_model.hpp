#pragma once

/// @file compliance_model.hpp
/// Pure shared builders for the compliance/policy read surface (api-parity
/// #4034, `docs/api-twin-recipe.md` Rule 1). No `httplib.h`, no
/// `mcp_jsonrpc.hpp` — `compliance_routes.cpp`'s new `/api/v1/compliance*`
/// `/api/v1/polic*` REST handlers, `mcp_server.cpp`'s MCP tool dispatch, and
/// the two `/fragments/compliance/*` HTML renderers all call these so the
/// three surfaces cannot drift from each other by construction.
///
/// `confined_policy_compliance` exists so the ADR-0017 admit-then-filter
/// confinement logic for `GET /api/v1/compliance/{id}` and its MCP twin
/// `get_policy_agent_statuses` (routed-concerns' `authorize_list_read`/
/// `require_fleet_read` MUST for a fan-out read of per-agent data) is a
/// single pure, unit-testable function rather than duplicated inline in each
/// handler — the harness for both surfaces runs with a null `PolicyStore`
/// (no live Postgres), so this is the ONLY place the confinement behaviour
/// itself is actually exercised by a test (`test_compliance_model.cpp`).

#include "authz_model.hpp"
#include "compliance_types.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace yuzu::server {

/// Fleet-wide compliance percentages — `GET /api/compliance` /
/// `GET /api/v1/compliance` / MCP `get_fleet_compliance`'s shape.
nlohmann::json fleet_compliance_json(const FleetCompliance& fc);

/// Per-policy compliance breakdown — the "summary"/"compliance" sub-object on
/// `GET /api/compliance/{id}`, `GET /api/policies/{id}`,
/// `GET /api/v1/compliance/{id}`, `GET /api/v1/policies/{id}`, and MCP
/// `get_compliance_summary`'s shape.
nlohmann::json compliance_summary_json(const ComplianceSummary& cs);

/// One row of a per-policy agent-status fan-out — `GET /api/compliance/{id}`'s
/// `"agents"` array element / `GET /api/v1/compliance/{id}` / MCP
/// `get_policy_agent_statuses`'s per-row shape.
nlohmann::json policy_agent_status_json(const PolicyAgentStatus& s);

/// A policy list row — `GET /api/policies` / `GET /api/v1/policies` row
/// shape (superset of MCP `list_policies`'s narrower 5-field row, which
/// stays as-is — see #4034's PR description for why that tool is not
/// widened to match).
nlohmann::json policy_list_row_json(const Policy& p);

/// A policy-fragment list row — `GET /api/policy-fragments` /
/// `GET /api/v1/policy-fragments` / MCP `list_policy_fragments`'s row shape.
nlohmann::json policy_fragment_list_row_json(const PolicyFragment& f);

/// Single-policy detail — `GET /api/policies/{id}` / `GET /api/v1/policies/{id}`
/// / MCP `get_policy`'s shape. Built on top of `policy_list_row_json` plus the
/// detail-only fields. `remediation_available` is resolved by the caller (a
/// fragment-lookup I/O step) and passed in — this builder stays pure.
nlohmann::json single_policy_detail_json(const Policy& p, const ComplianceSummary& cs,
                                         bool remediation_available);

/// The confined view of one policy's per-agent statuses: `visible` is
/// `statuses` filtered to `scope` (unfiltered/TOP when `scope` is `nullopt`),
/// and `summary` is the compliance tally over exactly `visible` — never the
/// store's own unfiltered aggregate. `get_compliance_summary` and
/// `get_policy_agent_statuses` read the SAME `policy_store.policy_status
/// WHERE policy_id = $1` predicate (verified against `policy_store.cpp`), so
/// tallying from the already-fetched, already-filtered statuses list is
/// byte-identical to the store's own aggregate for an unfiltered (TOP)
/// caller, and is the ONLY honest answer for a confined one — a confined
/// caller must never see a fleet-wide count for agents it cannot itself
/// list (the same principle `GET /api/v1/executions/{id}`'s confined
/// projection applies to execution counts).
struct ConfinedPolicyCompliance {
    std::vector<PolicyAgentStatus> visible;
    ComplianceSummary summary;
};
ConfinedPolicyCompliance confined_policy_compliance(const std::vector<PolicyAgentStatus>& statuses,
                                                     const authz::VisibleSet& scope,
                                                     const std::string& policy_id);

} // namespace yuzu::server
