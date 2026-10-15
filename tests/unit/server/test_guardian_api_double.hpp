#pragma once

/// @file test_guardian_api_double.hpp
/// FnGuardianApi — a test-only `GuardianApi` adapter backed by plain
/// `std::function`s, mirroring `FnWorkflowApi`/`FnScheduleApi`/`FnVerifyApi`.
/// Lets a route/MCP test inject an ARBITRARY result for any of the eight
/// methods — including a store degrade (`std::unexpected`/`nullopt`) —
/// without standing up a real `GuaranteedStateStore`/`BaselineStore`/
/// Postgres connection, and (its real purpose) lets a seam-bypass tripwire
/// test wire a DISTINGUISHING double alongside a real, separately-answering
/// store at the same id/key, so a REST/MCP handler silently reverted to call
/// the raw store directly answers DIFFERENTLY than one still calling the
/// seam — see the tripwire TEST_CASEs in test_rest_guaranteed_state.cpp /
/// test_mcp_server.cpp that use this double for the mechanism this exists
/// to prove.
///
/// An unwired (default-constructed, empty `std::function`) field answers
/// with the SAME "unavailable" shape `LocalGuardianApi` uses for a null
/// backing store, so a test that only cares about ONE method can leave the
/// other seven at their default-empty without accidentally exercising an
/// unrelated code path.
///
/// NOT for production use — the production factory is
/// `make_local_guardian_api` (guardian_api_local.hpp).

#include "guardian_api.hpp"

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnGuardianApi final : public yuzu::server::GuardianApi {
public:
    using ListRulesFn =
        std::function<std::expected<std::vector<yuzu::server::GuaranteedStateRuleRow>, std::string>()>;
    using GetRuleFn = std::function<std::expected<
        std::optional<yuzu::server::GuaranteedStateRuleRow>, yuzu::server::GuaranteedStateReadError>(
        const std::string&)>;
    using StatusFn = std::function<std::optional<yuzu::server::GuardianStatusRollup>(
        const std::optional<std::vector<std::string>>&)>;
    using AgentStatusFn =
        std::function<std::optional<yuzu::server::GuardianAgentStatusRollup>(const std::string&)>;
    using RuleStatusFn = std::function<std::optional<std::vector<yuzu::server::GuardianRuleAgentStatusRow>>(
        const std::string&)>;
    using DeviceGuardsFn = std::function<std::optional<std::vector<yuzu::server::GuardianDeviceGuardRow>>(
        const std::string&)>;
    using DeviceComplianceFn =
        std::function<std::optional<yuzu::server::GuardianDeviceComplianceRollup>(
            const std::string&, const std::string&, bool*, bool*)>;
    using ListEventsFn = std::function<std::vector<yuzu::server::GuaranteedStateEventRow>(
        const yuzu::server::GuaranteedStateEventQuery&)>;

    FnGuardianApi(ListRulesFn list_rules_fn = {}, GetRuleFn get_rule_fn = {},
                 StatusFn status_fn = {}, AgentStatusFn agent_status_fn = {},
                 RuleStatusFn rule_status_fn = {}, DeviceGuardsFn device_guards_fn = {},
                 DeviceComplianceFn device_compliance_fn = {}, ListEventsFn list_events_fn = {})
        : list_rules_fn_(std::move(list_rules_fn)), get_rule_fn_(std::move(get_rule_fn)),
          status_fn_(std::move(status_fn)), agent_status_fn_(std::move(agent_status_fn)),
          rule_status_fn_(std::move(rule_status_fn)), device_guards_fn_(std::move(device_guards_fn)),
          device_compliance_fn_(std::move(device_compliance_fn)),
          list_events_fn_(std::move(list_events_fn)) {}

    [[nodiscard]] std::expected<std::vector<yuzu::server::GuaranteedStateRuleRow>, std::string>
    list_rules() const override {
        if (!list_rules_fn_)
            return std::unexpected(std::string{"FnGuardianApi: list_rules unwired"});
        return list_rules_fn_();
    }

    [[nodiscard]] std::expected<std::optional<yuzu::server::GuaranteedStateRuleRow>,
                                yuzu::server::GuaranteedStateReadError>
    get_rule(const std::string& rule_id) const override {
        if (!get_rule_fn_)
            return std::unexpected(yuzu::server::GuaranteedStateReadError::kDegraded);
        return get_rule_fn_(rule_id);
    }

    [[nodiscard]] std::optional<yuzu::server::GuardianStatusRollup>
    status(const std::optional<std::vector<std::string>>& agent_scope) const override {
        if (!status_fn_)
            return std::nullopt;
        return status_fn_(agent_scope);
    }

    [[nodiscard]] std::optional<yuzu::server::GuardianAgentStatusRollup>
    agent_status(const std::string& agent_id) const override {
        if (!agent_status_fn_)
            return std::nullopt;
        return agent_status_fn_(agent_id);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::GuardianRuleAgentStatusRow>>
    rule_status(const std::string& rule_id) const override {
        if (!rule_status_fn_)
            return std::nullopt;
        return rule_status_fn_(rule_id);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::GuardianDeviceGuardRow>>
    device_guards(const std::string& agent_id) const override {
        if (!device_guards_fn_)
            return std::nullopt;
        return device_guards_fn_(agent_id);
    }

    [[nodiscard]] std::optional<yuzu::server::GuardianDeviceComplianceRollup>
    device_compliance(const std::string& baseline_name, const std::string& agent_id,
                      bool* store_degraded, bool* pii_access_began) const override {
        if (!device_compliance_fn_) {
            *store_degraded = true;
            *pii_access_began = false;
            return std::nullopt;
        }
        return device_compliance_fn_(baseline_name, agent_id, store_degraded, pii_access_began);
    }

    [[nodiscard]] std::vector<yuzu::server::GuaranteedStateEventRow>
    list_events(const yuzu::server::GuaranteedStateEventQuery& q) const override {
        if (!list_events_fn_)
            return {};
        return list_events_fn_(q);
    }

private:
    ListRulesFn list_rules_fn_;
    GetRuleFn get_rule_fn_;
    StatusFn status_fn_;
    AgentStatusFn agent_status_fn_;
    RuleStatusFn rule_status_fn_;
    DeviceGuardsFn device_guards_fn_;
    DeviceComplianceFn device_compliance_fn_;
    ListEventsFn list_events_fn_;
};

} // namespace yuzu::server::test
