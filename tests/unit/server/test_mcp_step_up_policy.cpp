/**
 * test_mcp_step_up_policy.cpp: the MCP step-up policy table
 * (server/core/src/step_up_mcp_policy.hpp) against the REAL MCP tool catalogue.
 *
 * L2 of the step-up tripwire: every tool whose `kToolSecurityRows` operation is not `Read` has
 * exactly one row, no row is stale, every exempt reason is from the named class list, and every
 * REST twin the table names exists in the REST table and is not classified stronger than the
 * tool. The catalogue is read through `mcp_server_testonly.hpp`'s accessors, so adding a
 * non-Read tool without a row fails here by tool name. Pure data: no Postgres, no sockets.
 */

#include "../../../server/core/src/step_up_mcp_policy.hpp"
#include "mcp_server_testonly.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <iterator>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

std::vector<std::string_view> non_read_tools() {
    std::vector<std::string_view> tools;
    for (const auto& r : mcp::tool_security_rows_for_test()) {
        if (r.operation != "Read")
            tools.push_back(r.name);
    }
    return tools;
}

std::string join(const std::vector<std::string_view>& v) {
    std::string out;
    for (const auto s : v) {
        if (!out.empty())
            out += ", ";
        out += std::string(s);
    }
    return out;
}

std::size_t pending_rows() {
    std::size_t n = 0;
    for (const auto& e : kMcpStepUpPolicy)
        n += (e.cls == StepUpClass::kPendingRuling) ? 1 : 0;
    return n;
}

// Pending rows not on kMcpPendingBecauseRestTwinRequired.
std::size_t baseline_pending_rows() {
    std::size_t n = 0;
    for (const auto& e : kMcpStepUpPolicy)
        n += (e.cls == StepUpClass::kPendingRuling && !mcp_pending_because_rest_twin_required(e.tool))
                 ? 1
                 : 0;
    return n;
}

// Pending rows that ARE on kMcpPendingBecauseRestTwinRequired.
std::size_t second_list_pending_rows() {
    return pending_rows() - baseline_pending_rows();
}

} // namespace

TEST_CASE("mcp step-up policy: every non-Read tool has a row", "[stepup][mcp][policy]") {
    const auto tools = non_read_tools();
    REQUIRE_FALSE(tools.empty());
    const auto missing = mcp_step_up_unclassified_tools(tools);
    INFO("tools with no kMcpStepUpPolicy row: " << join(missing));
    CHECK(missing.empty());
}

TEST_CASE("mcp step-up policy: no row is stale", "[stepup][mcp][policy]") {
    const auto stale = mcp_step_up_stale_rows(non_read_tools());
    INFO("rows for a tool that is gone or is now Read: " << join(stale));
    CHECK(stale.empty());
}

TEST_CASE("mcp step-up policy: a row names a SERVED tool", "[stepup][mcp][policy]") {
    const auto served = mcp::tool_names_for_test();
    const std::set<std::string> served_set(served.begin(), served.end());
    for (const auto& e : kMcpStepUpPolicy) {
        INFO("tool: " << std::string(e.tool));
        CHECK(served_set.count(std::string(e.tool)) == 1);
    }
}

TEST_CASE("mcp step-up policy: the lookup finds each row once and refuses a near miss",
          "[stepup][mcp][policy]") {
    std::set<std::string> seen;
    for (const auto& e : kMcpStepUpPolicy) {
        INFO("tool: " << std::string(e.tool));
        CHECK(seen.insert(std::string(e.tool)).second);
        CHECK(mcp_step_up_policy_for(e.tool) == &e);
    }
    CHECK(mcp_step_up_policy_for("") == nullptr);
    CHECK(mcp_step_up_policy_for("create_api_toke") == nullptr);
    CHECK(mcp_step_up_policy_for("create_api_token ") == nullptr);
    CHECK(mcp_step_up_policy_for("list_agents") == nullptr); // a Read tool has no row
}

TEST_CASE("mcp step-up policy: every kExempt reason is from the named class list",
          "[stepup][mcp][policy]") {
    for (const auto& e : kMcpStepUpPolicy) {
        INFO("tool: " << std::string(e.tool) << " reason: " << std::string(e.reason));
        if (e.cls == StepUpClass::kExempt) {
            const auto& list = step_up_mcp_detail::kMcpExemptReasons;
            CHECK(std::find(list.begin(), list.end(), e.reason) != list.end());
        }
    }
}

TEST_CASE("mcp step-up policy: every class and reason is one the table may carry",
          "[stepup][mcp][policy]") {
    for (const auto& e : kMcpStepUpPolicy) {
        INFO("tool: " << std::string(e.tool));
        CHECK((e.cls == StepUpClass::kExempt || e.cls == StepUpClass::kPendingRuling));
        if (e.cls == StepUpClass::kPendingRuling)
            CHECK(e.reason == step_up_detail::kPendingReason);
    }
}

TEST_CASE("mcp step-up policy: the baseline ceiling equals the baseline pending count (it only "
          "goes down)",
          "[stepup][mcp][policy]") {
    CHECK(baseline_pending_rows() == kMcpPendingBaselineMax);
    CHECK(kMcpPendingBaselineMax == 44);
}

namespace {

// The exact tool-name set of the BASELINE pending rows (the frozen set: kPendingRuling and not on
// kMcpPendingBecauseRestTwinRequired), sorted. kMcpPendingBaselineMax alone only bounds how MANY
// rows are pending, so swapping one pending tool for another would pass; this list pins WHICH
// ones. Resolving a row (moving it to kExempt with a named reason) means deleting its entry here
// AND lowering kMcpPendingBaselineMax in the same change. A NEW tool is never added here: classify
// it kExempt with a named reason, or, only if its REST twin is kRequired, list it on
// kMcpPendingBecauseRestTwinRequired, which is checked against the REST table.
constexpr std::string_view kBaselineMcpPending[] = {
    "activate_platform_license",
    "add_management_group_member",
    "approve_request",
    "assign_engine_role",
    "assign_management_group_role",
    "assign_rbac_role",
    "confirm_api_token_rotation",
    "confirm_engine_rotation",
    "create_api_token",
    "create_engine_principal",
    "create_guardian_rule",
    "create_management_group",
    "create_offload_target",
    "create_software_deployment",
    "delete_guardian_rule",
    "delete_offload_target",
    "delete_plugin_config",
    "delete_plugin_secret",
    "import_ca_chain",
    "issue_code_signing_cert",
    "mint_engine_credential",
    "mint_upload_grant",
    "push_guardian_rules",
    "quarantine_device",
    "reject_request",
    "revoke_api_token",
    "revoke_certificate",
    "revoke_engine_principal",
    "revoke_upload_grant",
    "rewrap_secrets",
    "rollback_software_deployment",
    "rotate_api_token",
    "rotate_engine_credential",
    "rotate_kek",
    "set_plugin_config",
    "set_plugin_kill_switch",
    "set_plugin_secret",
    "set_rbac_enforcement",
    "transfer_engine_principal_owner",
    "unassign_engine_role",
    "unassign_rbac_role",
    "unlock_account",
    "update_guardian_rule",
    "update_management_group",
};

} // namespace

TEST_CASE("mcp step-up policy: every baseline kPendingRuling tool is in the pinned baseline list",
          "[stepup][mcp][policy]") {
    std::set<std::string_view> pinned(std::begin(kBaselineMcpPending),
                                      std::end(kBaselineMcpPending));
    for (const auto& e : kMcpStepUpPolicy) {
        if (e.cls != StepUpClass::kPendingRuling || mcp_pending_because_rest_twin_required(e.tool))
            continue;
        INFO("baseline pending tool not in the pinned list: " << std::string(e.tool));
        CHECK(pinned.count(e.tool) == 1);
    }
}

TEST_CASE("mcp step-up policy: the pinned baseline list is sorted, unique and moves with the count",
          "[stepup][mcp][policy]") {
    std::set<std::string_view> seen;
    std::string_view prev;
    for (const auto tool : kBaselineMcpPending) {
        INFO("tool: " << std::string(tool));
        CHECK(seen.insert(tool).second);
        CHECK(prev < tool);
        prev = tool;
        // Every listed tool is still a baseline pending row: a resolved row must leave this list,
        // and a second-list tool must not be here.
        const auto it = std::find_if(std::begin(kMcpStepUpPolicy), std::end(kMcpStepUpPolicy),
                                     [&](const auto& e) { return e.tool == tool; });
        REQUIRE(it != std::end(kMcpStepUpPolicy));
        CHECK(it->cls == StepUpClass::kPendingRuling);
        CHECK_FALSE(mcp_pending_because_rest_twin_required(tool));
    }
    CHECK(std::size(kBaselineMcpPending) == baseline_pending_rows());
    CHECK(std::size(kBaselineMcpPending) == kMcpPendingBaselineMax);
}

TEST_CASE("mcp step-up policy: every post-baseline (second-list) tool is pending with a kRequired "
          "REST twin and is not in the baseline",
          "[stepup][mcp][policy]") {
    REQUIRE(kMcpPendingBecauseRestTwinRequired.size() == 2);
    CHECK(kMcpPendingBecauseRestTwinRequired[0] == "raise_guardian_policy_generation");
    CHECK(kMcpPendingBecauseRestTwinRequired[1] == "set_runtime_config");
    std::set<std::string_view> baseline(std::begin(kBaselineMcpPending),
                                        std::end(kBaselineMcpPending));
    std::set<std::string_view> seen;
    std::string_view prev;
    for (const auto tool : kMcpPendingBecauseRestTwinRequired) {
        INFO("second-list tool: " << std::string(tool));
        CHECK(seen.insert(tool).second);
        CHECK(prev < tool);
        prev = tool;
        // (a) its row in the MCP table is kPendingRuling
        const auto* row = mcp_step_up_policy_for(tool);
        REQUIRE(row != nullptr);
        CHECK(row->cls == StepUpClass::kPendingRuling);
        // (b) its REST-twin fields resolve to a kRequired REST row
        REQUIRE_FALSE(row->rest_method.empty());
        const auto* twin = step_up_policy_for(row->rest_method, row->rest_pattern);
        REQUIRE(twin != nullptr);
        CHECK(twin->cls == StepUpClass::kRequired);
        // (c) it is not also in the baseline list
        CHECK(baseline.count(tool) == 0);
    }
}

TEST_CASE("mcp step-up policy: the pending rows are the baseline plus the post-baseline list",
          "[stepup][mcp][policy]") {
    // Many baseline tools ALSO have a kRequired twin (they are pending because no MCP consumer
    // enforces kRequired yet), so the second list is not the only such group. What is checked here
    // is the count identity; the second-list case above checks each entry's twin.
    // 46 pending rows = 44 baseline + 2 second-list.
    CHECK(pending_rows() == kMcpPendingBaselineMax + kMcpPendingBecauseRestTwinRequired.size());
    CHECK(pending_rows() == 46);
    CHECK(baseline_pending_rows() + second_list_pending_rows() == pending_rows());
    CHECK(second_list_pending_rows() == kMcpPendingBecauseRestTwinRequired.size());
    // The MCP table shape: 65 rows, 19 exempt, 46 pending.
    CHECK(std::size(kMcpStepUpPolicy) == 65);
    std::size_t exempt = 0;
    for (const auto& e : kMcpStepUpPolicy)
        exempt += (e.cls == StepUpClass::kExempt) ? 1 : 0;
    CHECK(exempt == 19);
}

TEST_CASE("mcp step-up policy: a twin exists in the REST table and the tool is never weaker",
          "[stepup][mcp][policy]") {
    for (const auto& e : kMcpStepUpPolicy) {
        INFO("tool: " << std::string(e.tool));
        CHECK(e.rest_method.empty() == e.rest_pattern.empty());
        if (e.rest_method.empty())
            continue;
        INFO("twin: " << std::string(e.rest_method) << " " << std::string(e.rest_pattern));
        const auto* twin = step_up_policy_for(e.rest_method, e.rest_pattern);
        REQUIRE(twin != nullptr);
        if (twin->cls == StepUpClass::kRequired || twin->cls == StepUpClass::kPendingRuling)
            CHECK(e.cls != StepUpClass::kExempt);
    }
}

TEST_CASE("mcp step-up policy: the pure cross-check reports a missing and a stale row",
          "[stepup][mcp][policy]") {
    auto tools = non_read_tools();
    REQUIRE_FALSE(tools.empty());
    // Drop one real tool: its row is now stale. Add one invented tool: it is unclassified.
    const std::string_view dropped = tools.back();
    tools.pop_back();
    tools.push_back("zz_invented_write_tool");
    const auto missing = mcp_step_up_unclassified_tools(tools);
    const auto stale = mcp_step_up_stale_rows(tools);
    REQUIRE(missing.size() == 1);
    CHECK(missing.front() == "zz_invented_write_tool");
    REQUIRE(stale.size() == 1);
    CHECK(stale.front() == dropped);
}
