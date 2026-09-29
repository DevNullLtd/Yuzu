#pragma once

/// @file test_compliance_api_double.hpp
/// FnComplianceApi — a test-only `ComplianceApi` adapter backed by
/// `std::function` per method (mirrors `test_verify_api_double.hpp`'s
/// `FnVerifyApi`, generalized to the compliance seam's six-method surface).
/// A route/MCP handler test (Task B of this family's ladder) constructs one
/// with only the methods it exercises wired; an unwired method returns the
/// AUTHORITATIVE-degrade `PolicyReadError::kDegraded` rather than an empty
/// result, so a test that forgets to wire a method it actually calls fails
/// loudly instead of silently reading "nothing found".
///
/// NOT for production use — the production factory is
/// `make_local_compliance_api` (compliance_api_local.hpp).

#include "compliance_api.hpp"

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnComplianceApi final : public yuzu::server::ComplianceApi {
public:
    using ListFragmentsFn = std::function<std::expected<std::vector<yuzu::server::PolicyFragment>,
                                                         yuzu::server::PolicyReadError>(
        const yuzu::server::FragmentQuery&)>;
    using ListPoliciesFn = std::function<std::expected<std::vector<yuzu::server::Policy>,
                                                        yuzu::server::PolicyReadError>(
        const yuzu::server::PolicyQuery&)>;
    using GetPolicyFn = std::function<std::expected<std::optional<yuzu::server::PolicyDetail>,
                                                     yuzu::server::PolicyReadError>(
        const std::string&)>;
    using FleetComplianceFn =
        std::function<std::expected<yuzu::server::FleetCompliance, yuzu::server::PolicyReadError>()>;
    using ComplianceSummaryFn =
        std::function<std::expected<yuzu::server::ComplianceSummary, yuzu::server::PolicyReadError>(
            const std::string&)>;
    using PolicyAgentStatusesFn =
        std::function<std::expected<std::vector<yuzu::server::PolicyAgentStatus>,
                                    yuzu::server::PolicyReadError>(const std::string&)>;

    ListFragmentsFn list_fragments_fn;
    ListPoliciesFn list_policies_fn;
    GetPolicyFn get_policy_fn;
    FleetComplianceFn fleet_compliance_fn;
    ComplianceSummaryFn compliance_summary_fn;
    PolicyAgentStatusesFn policy_agent_statuses_fn;

    [[nodiscard]] std::expected<std::vector<yuzu::server::PolicyFragment>,
                                yuzu::server::PolicyReadError>
    list_fragments(const yuzu::server::FragmentQuery& q) const override {
        if (!list_fragments_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return list_fragments_fn(q);
    }

    [[nodiscard]] std::expected<std::vector<yuzu::server::Policy>, yuzu::server::PolicyReadError>
    list_policies(const yuzu::server::PolicyQuery& q) const override {
        if (!list_policies_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return list_policies_fn(q);
    }

    [[nodiscard]] std::expected<std::optional<yuzu::server::PolicyDetail>,
                                yuzu::server::PolicyReadError>
    get_policy(const std::string& id) const override {
        if (!get_policy_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return get_policy_fn(id);
    }

    [[nodiscard]] std::expected<yuzu::server::FleetCompliance, yuzu::server::PolicyReadError>
    fleet_compliance() const override {
        if (!fleet_compliance_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return fleet_compliance_fn();
    }

    [[nodiscard]] std::expected<yuzu::server::ComplianceSummary, yuzu::server::PolicyReadError>
    compliance_summary(const std::string& policy_id) const override {
        if (!compliance_summary_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return compliance_summary_fn(policy_id);
    }

    [[nodiscard]] std::expected<std::vector<yuzu::server::PolicyAgentStatus>,
                                yuzu::server::PolicyReadError>
    policy_agent_statuses(const std::string& policy_id) const override {
        if (!policy_agent_statuses_fn)
            return std::unexpected(yuzu::server::PolicyReadError::kDegraded);
        return policy_agent_statuses_fn(policy_id);
    }
};

} // namespace yuzu::server::test
