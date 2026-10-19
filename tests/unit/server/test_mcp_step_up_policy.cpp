/**
 * test_mcp_step_up_policy.cpp — the MCP step-up policy table
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

TEST_CASE("mcp step-up policy: kMcpPendingRulingMax equals the pending row count and may only "
          "be lowered",
          "[stepup][mcp][policy]") {
    CHECK(pending_rows() == kMcpPendingRulingMax);
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
