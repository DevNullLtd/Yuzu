#pragma once

/// @file compliance_api.hpp
/// The THIRD per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4), copying the merged `network_api.hpp`/
/// `verify_api.hpp` templates verbatim in shape. Abstract, ZERO store-shaped
/// dependencies — only the pure `compliance_types.hpp` types + std headers,
/// so this header can be included by a future presentation-side client
/// without dragging the server's `PolicyStore`/`pg::` layer along.
///
/// The method set == the public REST resources it stands in front of, 1:1
/// (INV-31-4 "no private core API" — a method here without a corresponding
/// public REST/MCP resource would reintroduce a private core API and defeat
/// the point of the seam):
///   - `list_fragments`          <-> `GET /api/v1/policy-fragments`          (MCP `list_policy_fragments`)
///   - `list_policies`           <-> `GET /api/v1/policies`                 (MCP `list_policies`)
///   - `get_policy`              <-> `GET /api/v1/policies/{id}`            (MCP `get_policy`)
///   - `fleet_compliance`        <-> `GET /api/v1/compliance`               (MCP `get_fleet_compliance`)
///   - `compliance_summary`      <-> `GET /api/v1/compliance/{id}`'s "summary" (MCP `get_compliance_summary`)
///   - `policy_agent_statuses`   <-> `GET /api/v1/compliance/{id}`'s "agents" (MCP `get_policy_agent_statuses`)
///
/// `get_policy` is deliberately COMPOSITE: the public route/tool assembles
/// policy + compliance_summary + a fail-soft fragment lookup for
/// `remediation_available` in one call (`single_policy_detail_json`'s shape,
/// `compliance_model.hpp`). There is no public `GET /policy-fragments/{id}`
/// resource, so a `get_fragment(id)` seam method would itself be a private
/// core API — that lookup stays INSIDE the impl (compliance_api.cpp).
/// `GET /api/v1/compliance/{id}` deliberately stays TWO seam calls
/// (`compliance_summary` + `policy_agent_statuses`), never one composite
/// method, so the consumer tallies the summary from its OWN CONFINED status
/// set (`confined_policy_compliance`, `compliance_model.hpp`) rather than the
/// store's unfiltered fleet-wide aggregate — collapsing the two into a single
/// seam call would force every confined caller back onto the unfiltered
/// number.
///
/// The store-backed factory (`make_local_compliance_api`) lives in the
/// core-only `compliance_api_local.hpp` — this header names no store type at
/// all, not even by forward declaration, so a presentation TU including it
/// cannot reach one.

#include <expected>
#include <optional>
#include <string>
#include <vector>

#include "compliance_types.hpp"

namespace yuzu::server {

/// The in-process public compliance/policy API. Method set == the public
/// REST/MCP resources listed in the file banner above, so presentation/MCP
/// consume only what the public, versioned core API serves (ADR-0031 B3,
/// INV-31-4) — a local in-process client today, a core HTTP client after the
/// WS-B2 cutover.
class ComplianceApi {
public:
    virtual ~ComplianceApi() = default;

    /// The policy-fragment list — the shape `GET /api/v1/policy-fragments`
    /// serves. `PolicyReadError::kDegraded` on a store read failure (ADR-0036
    /// — never collapsed into an empty list).
    [[nodiscard]] virtual std::expected<std::vector<PolicyFragment>, PolicyReadError>
    list_fragments(const FragmentQuery& q) const = 0;

    /// The policy list — the shape `GET /api/v1/policies` serves.
    [[nodiscard]] virtual std::expected<std::vector<Policy>, PolicyReadError>
    list_policies(const PolicyQuery& q) const = 0;

    /// Single-policy detail — the composite shape `GET /api/v1/policies/{id}`
    /// serves (see the file banner's COMPOSITE note). `nullopt` on the
    /// present-but-not-found case (`id` does not name a policy); `kDegraded`
    /// on a genuine store-read failure.
    [[nodiscard]] virtual std::expected<std::optional<PolicyDetail>, PolicyReadError>
    get_policy(const std::string& id) const = 0;

    /// Fleet-wide compliance percentages — the shape `GET /api/v1/compliance`
    /// serves.
    [[nodiscard]] virtual std::expected<FleetCompliance, PolicyReadError>
    fleet_compliance() const = 0;

    /// Per-policy compliance breakdown — the shape
    /// `GET /api/v1/compliance/{id}`'s "summary" sub-object serves. This is
    /// the store's own UNFILTERED aggregate; a confined caller must instead
    /// tally from its OWN filtered `policy_agent_statuses()` result via
    /// `confined_policy_compliance` (`compliance_model.hpp`) rather than
    /// serve this value directly.
    [[nodiscard]] virtual std::expected<ComplianceSummary, PolicyReadError>
    compliance_summary(const std::string& policy_id) const = 0;

    /// Per-agent status fan-out for one policy — the shape
    /// `GET /api/v1/compliance/{id}`'s "agents" array serves.
    ///
    /// ── CONFINEMENT WARNING (mirrors verify_api.hpp's PII policy-split
    /// banner) — READ BEFORE ADDING A CONSUMER ──
    /// This returns the store's UNFILTERED, fleet-wide rows — including
    /// operator-authored `check_result` for every agent, regardless of the
    /// caller's own management-group confinement. This is a fan-out read of
    /// per-agent data (routed-concerns' `authorize_list_read`/
    /// `require_fleet_read` MUST, ADR-0017 World A) — EVERY consumer of this
    /// method MUST apply BOTH: (1) the fleet-read gate
    /// (`FleetReadFn`/`require_fleet_read`) before calling, and (2) the
    /// `confined_policy_compliance` filter (`compliance_model.hpp`) on the
    /// result — never serialize this method's return value directly to a
    /// confinable caller. Those two are UNIVERSAL MUSTs. The
    /// `compliance.agent_statuses.view` audit is also required on every
    /// consumer, but its failure-handling is PER-CHANNEL (rest_audit.hpp): the
    /// REST route fails CLOSED (503 on audit-persist failure), the MCP tool
    /// sets `audit_persisted:false` in its body and proceeds, and the dashboard
    /// signals the gap via a response header — do not restate MCP/dashboard as
    /// fail-closed. The seam itself is a store-free DATA PROVIDER only; auth,
    /// confinement and audit live in the consumer (route/MCP handler), not
    /// here.
    /// NOTE: two PRE-EXISTING consumers do not yet fully satisfy this contract
    /// and are tracked separately (kept byte-identical by this seam, NOT
    /// introduced here): the legacy `GET /api/compliance/{id}` route serves
    /// unfiltered rows on `perm_fn_` alone (#4333), and the dashboard
    /// compliance fragments have no RBAC gate AND emit no audit (#4042) — the
    /// per-channel description above is the contract a CONFORMING consumer
    /// follows; these fragments are the non-conforming exception. The MUST above is the
    /// contract every conforming/new consumer meets and the target those two
    /// are being brought to.
    [[nodiscard]] virtual std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
    policy_agent_statuses(const std::string& policy_id) const = 0;
};

} // namespace yuzu::server
