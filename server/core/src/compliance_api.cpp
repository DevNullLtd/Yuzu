#include "compliance_api_local.hpp"

#include "policy_store.hpp"

#include <utility>

namespace yuzu::server {

/// Store-backed `ComplianceApi` implementation — the compliance/policy read
/// surface's store-reaching assembly (previously duplicated inline between
/// `compliance_routes.cpp`'s handlers and `mcp_server.cpp`'s tool dispatch),
/// moved verbatim behind the seam so it is independently testable (ADR-0031
/// WS-A4). Behaviour preserved exactly: every method is a thin forward to the
/// matching `PolicyStore` read, and `get_policy` assembles the SAME
/// three-read composite (`get_policy`, then `get_compliance_summary`, then a
/// fail-soft `get_fragment` lookup for `remediation_available`) the REST
/// handler (`compliance_routes.cpp`) and the MCP tool (`mcp_server.cpp`)
/// both build inline today.
class LocalComplianceApi final : public ComplianceApi {
public:
    explicit LocalComplianceApi(PolicyStore& store) : store_(store) {}

    LocalComplianceApi(const LocalComplianceApi&) = delete;
    LocalComplianceApi& operator=(const LocalComplianceApi&) = delete;

    [[nodiscard]] std::expected<std::vector<PolicyFragment>, PolicyReadError>
    list_fragments(const FragmentQuery& q) const override {
        return store_.query_fragments(q);
    }

    [[nodiscard]] std::expected<std::vector<Policy>, PolicyReadError>
    list_policies(const PolicyQuery& q) const override {
        return store_.query_policies(q);
    }

    [[nodiscard]] std::expected<std::optional<PolicyDetail>, PolicyReadError>
    get_policy(const std::string& id) const override {
        auto policy_res = store_.get_policy(id);
        if (!policy_res)
            return std::unexpected(policy_res.error());
        if (!*policy_res)
            return std::optional<PolicyDetail>{std::nullopt};

        const Policy& policy = **policy_res;
        auto cs_res = store_.get_compliance_summary(id);
        if (!cs_res)
            return std::unexpected(cs_res.error());

        // Remediation is only offered where the bound fragment defines a
        // fix_instruction — mirrors the legacy REST/MCP handlers' own
        // fail-soft posture (a degraded fragment read reads as "not
        // offered", not as a distinct error — this only gates a UI/agentic
        // affordance, not a grant/enforce decision).
        bool remediation_available = false;
        auto frag_res = store_.get_fragment(policy.fragment_id);
        if (frag_res && *frag_res)
            remediation_available = !(*frag_res)->fix_instruction.empty();

        PolicyDetail detail;
        detail.policy = policy;
        detail.summary = *cs_res;
        detail.remediation_available = remediation_available;
        return std::optional<PolicyDetail>{std::move(detail)};
    }

    [[nodiscard]] std::expected<FleetCompliance, PolicyReadError>
    fleet_compliance() const override {
        return store_.get_fleet_compliance();
    }

    [[nodiscard]] std::expected<ComplianceSummary, PolicyReadError>
    compliance_summary(const std::string& policy_id) const override {
        return store_.get_compliance_summary(policy_id);
    }

    [[nodiscard]] std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
    policy_agent_statuses(const std::string& policy_id) const override {
        return store_.get_policy_agent_statuses(policy_id);
    }

private:
    PolicyStore& store_;
};

std::shared_ptr<ComplianceApi> make_local_compliance_api(PolicyStore& store) {
    return std::make_shared<LocalComplianceApi>(store);
}

} // namespace yuzu::server
