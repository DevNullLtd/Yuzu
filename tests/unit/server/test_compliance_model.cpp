/**
 * test_compliance_model.cpp — pure unit tests for compliance_model.hpp
 * (api-parity #4034). No httplib, no PolicyStore/Postgres — every function
 * under test takes plain domain structs and returns nlohmann::json, so this
 * is the ONLY place `confined_policy_compliance`'s actual filter+tally
 * behaviour is exercised (ComplianceHarness in test_compliance_routes.cpp
 * always runs with policy_store=nullptr, matching the pre-existing #3559
 * item 3 gap, so it cannot reach this logic at all).
 */

#include "compliance_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <unordered_set>

using namespace yuzu::server;

namespace {

FleetCompliance make_fleet_compliance() {
    FleetCompliance fc;
    fc.total_checks = 200;
    fc.compliant = 185;
    fc.non_compliant = 8;
    fc.unknown = 5;
    fc.fixing = 2;
    fc.error = 0;
    fc.compliance_pct = 92.5;
    return fc;
}

ComplianceSummary make_summary() {
    ComplianceSummary cs;
    cs.policy_id = "pol_1";
    cs.compliant = 42;
    cs.non_compliant = 3;
    cs.unknown = 5;
    cs.fixing = 1;
    cs.error = 0;
    cs.total = 51;
    return cs;
}

PolicyAgentStatus make_status(std::string agent_id, std::string status) {
    PolicyAgentStatus s;
    s.policy_id = "pol_1";
    s.agent_id = std::move(agent_id);
    s.status = std::move(status);
    s.last_check_at = 1710936000;
    s.last_fix_at = 0;
    s.check_result = R"({"realtime_protection": true})";
    return s;
}

Policy make_policy() {
    Policy p;
    p.id = "pol_1";
    p.name = "baseline-security";
    p.description = "Baseline security posture";
    p.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n";
    p.fragment_id = "frag_1";
    p.scope_expression = "tag:environment = 'production'";
    p.enabled = true;
    p.created_at = 1710849600;
    p.updated_at = 1710849600;
    p.inputs = {{"pol_1", "threshold", "90"}};
    PolicyTrigger t;
    t.id = 1;
    t.policy_id = "pol_1";
    t.trigger_type = "interval";
    t.config_json = R"({"interval_seconds":300})";
    p.triggers = {t};
    p.management_groups = {"eu-production"};
    return p;
}

PolicyFragment make_fragment() {
    PolicyFragment f;
    f.id = "frag_1";
    f.name = "ensure-defender-enabled";
    f.description = "Verify Windows Defender is active";
    f.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n";
    f.check_instruction = "security.defender-status";
    f.check_compliance = "result.enabled == true";
    f.fix_instruction = "security.enable-defender";
    f.post_check_instruction = "";
    f.created_at = 1710849600;
    f.updated_at = 1710849600;
    return f;
}

} // namespace

TEST_CASE("fleet_compliance_json: all seven fields, matching legacy /api/compliance shape",
          "[compliance][model]") {
    auto j = fleet_compliance_json(make_fleet_compliance());
    CHECK(j.at("compliance_pct").get<double>() == 92.5);
    CHECK(j.at("total_checks").get<int64_t>() == 200);
    CHECK(j.at("compliant").get<int64_t>() == 185);
    CHECK(j.at("non_compliant").get<int64_t>() == 8);
    CHECK(j.at("unknown").get<int64_t>() == 5);
    CHECK(j.at("fixing").get<int64_t>() == 2);
    CHECK(j.at("error").get<int64_t>() == 0);
    CHECK(j.size() == 7);
}

TEST_CASE("compliance_summary_json: all six fields, matching legacy summary shape",
          "[compliance][model]") {
    auto j = compliance_summary_json(make_summary());
    CHECK(j.at("compliant").get<int64_t>() == 42);
    CHECK(j.at("non_compliant").get<int64_t>() == 3);
    CHECK(j.at("unknown").get<int64_t>() == 5);
    CHECK(j.at("fixing").get<int64_t>() == 1);
    CHECK(j.at("error").get<int64_t>() == 0);
    CHECK(j.at("total").get<int64_t>() == 51);
    // Deliberately no "policy_id" — matches the legacy nested "summary"
    // sub-object shape, not the top-level get_compliance_summary MCP tool
    // (which adds policy_id as a sibling field, not through this builder).
    CHECK(j.size() == 6);
}

TEST_CASE("policy_agent_status_json: five fields, matching legacy agents[] row",
          "[compliance][model]") {
    auto j = policy_agent_status_json(make_status("agent-01", "compliant"));
    CHECK(j.at("agent_id").get<std::string>() == "agent-01");
    CHECK(j.at("status").get<std::string>() == "compliant");
    CHECK(j.at("last_check_at").get<int64_t>() == 1710936000);
    CHECK(j.at("last_fix_at").get<int64_t>() == 0);
    CHECK(j.at("check_result").get<std::string>() == R"({"realtime_protection": true})");
    CHECK(j.size() == 5);
}

TEST_CASE("policy_list_row_json: identity/scope/inputs/triggers, matching legacy /api/policies row",
          "[compliance][model]") {
    auto j = policy_list_row_json(make_policy());
    CHECK(j.at("id").get<std::string>() == "pol_1");
    CHECK(j.at("name").get<std::string>() == "baseline-security");
    CHECK(j.at("description").get<std::string>() == "Baseline security posture");
    CHECK(j.at("fragment_id").get<std::string>() == "frag_1");
    CHECK(j.at("scope_expression").get<std::string>() == "tag:environment = 'production'");
    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("inputs").at("threshold").get<std::string>() == "90");
    REQUIRE(j.at("triggers").size() == 1);
    CHECK(j.at("triggers")[0].at("type").get<std::string>() == "interval");
    CHECK(j.at("triggers")[0].at("config").at("interval_seconds").get<int>() == 300);
    REQUIRE(j.at("management_groups").size() == 1);
    CHECK(j.at("management_groups")[0].get<std::string>() == "eu-production");
    CHECK(j.at("created_at").get<int64_t>() == 1710849600);
    CHECK(j.at("updated_at").get<int64_t>() == 1710849600);
    // Deliberately no "yaml_source"/"remediation_available"/"compliance" —
    // those are single_policy_detail_json's job, not the list row's.
    CHECK_FALSE(j.contains("yaml_source"));
}

TEST_CASE("policy_fragment_list_row_json: nine fields, matching legacy fragments[] row",
          "[compliance][model]") {
    auto j = policy_fragment_list_row_json(make_fragment());
    CHECK(j.at("id").get<std::string>() == "frag_1");
    CHECK(j.at("name").get<std::string>() == "ensure-defender-enabled");
    CHECK(j.at("check_instruction").get<std::string>() == "security.defender-status");
    CHECK(j.at("check_compliance").get<std::string>() == "result.enabled == true");
    CHECK(j.at("fix_instruction").get<std::string>() == "security.enable-defender");
    CHECK(j.at("post_check_instruction").get<std::string>() == "");
    CHECK(j.at("created_at").get<int64_t>() == 1710849600);
    CHECK(j.at("updated_at").get<int64_t>() == 1710849600);
    CHECK(j.size() == 9);
}

TEST_CASE("single_policy_detail_json: policy_list_row_json fields plus the three detail-only ones",
          "[compliance][model]") {
    auto p = make_policy();
    auto cs = make_summary();
    auto j = single_policy_detail_json(p, cs, /*remediation_available=*/true);
    // Base fields — same builder as the list row (Rule 1: not re-derived).
    CHECK(j.at("id").get<std::string>() == "pol_1");
    CHECK(j.at("name").get<std::string>() == "baseline-security");
    CHECK(j.at("scope_expression").get<std::string>() == "tag:environment = 'production'");
    // Detail-only additions.
    CHECK(j.at("yaml_source").get<std::string>() == p.yaml_source);
    CHECK(j.at("remediation_available").get<bool>() == true);
    CHECK(j.at("compliance").at("compliant").get<int64_t>() == 42);
    CHECK(j.at("compliance").at("total").get<int64_t>() == 51);
}

TEST_CASE("single_policy_detail_json: remediation_available is exactly what the caller passes",
          "[compliance][model]") {
    auto j = single_policy_detail_json(make_policy(), make_summary(),
                                       /*remediation_available=*/false);
    CHECK(j.at("remediation_available").get<bool>() == false);
}

TEST_CASE("confined_policy_compliance: nullopt scope (TOP) keeps every row and tallies all five "
          "statuses",
          "[compliance][model][security]") {
    std::vector<PolicyAgentStatus> statuses = {
        make_status("a1", "compliant"),   make_status("a2", "compliant"),
        make_status("a3", "non_compliant"), make_status("a4", "unknown"),
        make_status("a5", "fixing"),      make_status("a6", "error"),
    };
    auto out = confined_policy_compliance(statuses, /*scope=*/std::nullopt, "pol_1");
    CHECK(out.visible.size() == 6);
    CHECK(out.summary.policy_id == "pol_1");
    CHECK(out.summary.compliant == 2);
    CHECK(out.summary.non_compliant == 1);
    CHECK(out.summary.unknown == 1);
    CHECK(out.summary.fixing == 1);
    CHECK(out.summary.error == 1);
    CHECK(out.summary.total == 6);
}

TEST_CASE("confined_policy_compliance: engaged-empty scope (deny-all) admits nothing",
          "[compliance][model][security]") {
    std::vector<PolicyAgentStatus> statuses = {make_status("a1", "compliant"),
                                               make_status("a2", "non_compliant")};
    authz::VisibleSet deny_all{std::unordered_set<std::string>{}}; // PRESENT, empty
    auto out = confined_policy_compliance(statuses, deny_all, "pol_1");
    CHECK(out.visible.empty());
    CHECK(out.summary.total == 0);
    CHECK(out.summary.compliant == 0);
}

TEST_CASE("confined_policy_compliance: a partial scope filters rows AND tallies only the "
          "visible subset — never the store's unfiltered aggregate",
          "[compliance][model][security]") {
    std::vector<PolicyAgentStatus> statuses = {
        make_status("a1", "compliant"),
        make_status("a2", "compliant"),     // out of scope
        make_status("a3", "non_compliant"), // out of scope
    };
    authz::VisibleSet scope{std::unordered_set<std::string>{"a1"}};
    auto out = confined_policy_compliance(statuses, scope, "pol_1");
    REQUIRE(out.visible.size() == 1);
    CHECK(out.visible[0].agent_id == "a1");
    CHECK(out.summary.total == 1);
    CHECK(out.summary.compliant == 1);
    CHECK(out.summary.non_compliant == 0); // NOT 1 — a2/a3 must not leak into the tally
}
