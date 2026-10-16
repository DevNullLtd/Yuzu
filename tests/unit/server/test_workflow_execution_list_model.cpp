/**
 * test_workflow_execution_list_model.cpp -- the pure REST+MCP model for the workflow-execution
 * list (workflow_execution_list_model.hpp): strict parameter parsing for both transports, the row
 * shape and the cursor token. No database, no transport. The SQL text is pinned in
 * test_workflow_engine.cpp (`build_execution_page_sql`).
 */

#include "workflow_execution_list_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

std::expected<WorkflowExecutionListQuery, std::string>
rest(std::vector<RawParam> p) {
    return parse_workflow_execution_list_params(p);
}

std::string valid_cursor() {
    return keyset::encode_cursor(kWorkflowExecutionCursorPrefix, {1735689600, "run-1"});
}

} // namespace

TEST_CASE("workflow execution list params: no parameters gives the defaults",
          "[workflow][executions][list_model]") {
    for (const auto& q : {rest({}), parse_workflow_execution_list_args(json::object()),
                          parse_workflow_execution_list_args(json(nullptr))}) {
        REQUIRE(q.has_value());
        CHECK(q->workflow_id.empty());
        CHECK(q->status.empty());
        CHECK_FALSE(q->since.has_value());
        CHECK_FALSE(q->until.has_value());
        CHECK(q->limit == kWorkflowExecutionListDefaultLimit);
        CHECK_FALSE(q->after.has_value());
        CHECK_FALSE(q->latest_per_workflow);
    }
}

TEST_CASE("workflow execution list params: every valid filter parses identically over REST and MCP",
          "[workflow][executions][list_model]") {
    const auto r = rest({{"workflow_id", "Wf_1-b"},
                         {"status", "failed"},
                         {"since", "100"},
                         {"until", "200"},
                         {"limit", "7"},
                         {"cursor", valid_cursor()}});
    const auto m = parse_workflow_execution_list_args(json{{"workflow_id", "Wf_1-b"},
                                                           {"status", "failed"},
                                                           {"since", 100},
                                                           {"until", 200},
                                                           {"limit", 7},
                                                           {"cursor", valid_cursor()}});
    for (const auto& q : {r, m}) {
        REQUIRE(q.has_value());
        CHECK(q->workflow_id == "Wf_1-b");
        CHECK(q->status == "failed");
        CHECK(q->since == 100);
        CHECK(q->until == 200);
        CHECK(q->limit == 7);
        REQUIRE(q->after.has_value());
        CHECK(q->after->key == 1735689600);
        CHECK(q->after->id == "run-1");
    }
    // latest_per_workflow alone, and with the other filters, is fine.
    CHECK(rest({{"latest_per_workflow", "true"}})->latest_per_workflow);
    CHECK_FALSE(rest({{"latest_per_workflow", "false"}})->latest_per_workflow);
    CHECK(parse_workflow_execution_list_args(json{{"latest_per_workflow", true}, {"status", "failed"}})
              ->latest_per_workflow);
    // since == until is an empty window, not an error.
    CHECK(rest({{"since", "5"}, {"until", "5"}}).has_value());
}

TEST_CASE("workflow execution list params: limit is clamped above and refused below",
          "[workflow][executions][list_model]") {
    CHECK(rest({{"limit", "500"}})->limit == 500);
    CHECK(rest({{"limit", "501"}})->limit == 500);
    CHECK(rest({{"limit", "9223372036854775807"}})->limit == 500);
    CHECK(rest({{"limit", "1"}})->limit == 1);
    CHECK(parse_workflow_execution_list_args(json{{"limit", 100000}})->limit == 500);
    for (const char* bad : {"0", "-1", "abc", "", "1.5", " 5", "5 ", "+5", "9223372036854775808"})
        CHECK_FALSE(rest({{"limit", bad}}).has_value());
    for (const auto& bad : {json{{"limit", 0}}, json{{"limit", -3}}, json{{"limit", "5"}},
                            json{{"limit", 1.5}}, json{{"limit", true}}, json{{"limit", nullptr}},
                            json{{"limit", 18446744073709551615ULL}}})
        CHECK_FALSE(parse_workflow_execution_list_args(bad).has_value());
}

TEST_CASE("workflow execution list params: unknown and repeated keys are refused not ignored",
          "[workflow][executions][list_model]") {
    // A typo must never read as "all runs". The message is fixed text: the caller's key is never
    // reflected into the response.
    const auto fixed = rest({{"zzz", "1"}});
    REQUIRE_FALSE(fixed.has_value());
    CHECK(fixed.error().find("allowed:") != std::string::npos);
    for (const char* key : {"workflow-id", "workflowId", "Status", "page", "offset", "", "limit "}) {
        const auto q = rest({{key, "x"}});
        INFO(key);
        REQUIRE_FALSE(q.has_value());
        CHECK(q.error() == fixed.error());
    }
    CHECK_FALSE(rest({{"limit", "5"}, {"limit", "6"}}).has_value());
    CHECK_FALSE(rest({{"status", "failed"}, {"status", "failed"}}).has_value());
    CHECK_FALSE(rest({{"workflow_id", "a"}, {"limit", "5"}, {"workflow_id", "b"}}).has_value());
    // The unknown key wins even beside valid ones.
    CHECK_FALSE(rest({{"status", "failed"}, {"bogus", "1"}}).has_value());

    CHECK_FALSE(parse_workflow_execution_list_args(json{{"workflow-id", "x"}}).has_value());
    CHECK_FALSE(parse_workflow_execution_list_args(json{{"status", "failed"}, {"bogus", 1}})
                    .has_value());
    CHECK_FALSE(parse_workflow_execution_list_args(json::array()).has_value());
    CHECK_FALSE(parse_workflow_execution_list_args(json("text")).has_value());
}

TEST_CASE("workflow execution list params: malformed values are refused",
          "[workflow][executions][list_model]") {
    const std::string too_long(kWorkflowIdMaxLen + 1, 'a');
    const std::string cursor_too_long(keyset::kCursorMaxBytes + 1, 'A');
    const std::vector<std::vector<RawParam>> bad{
        {{"workflow_id", ""}},
        {{"workflow_id", too_long}},
        {{"workflow_id", "has space"}},
        {{"workflow_id", "a/b"}},
        {{"workflow_id", "a'b"}},
        {{"workflow_id", "caf\xc3\xa9"}},
        {{"workflow_id", std::string("a\0b", 3)}},
        {{"status", ""}},
        {{"status", "FAILED"}},
        {{"status", "done"}},
        {{"status", "failed,running"}},
        {{"since", "-1"}},
        {{"since", "9007199254740993"}}, // 2^53 + 1
        {{"until", "-1"}},
        {{"until", "x"}},
        {{"since", "10"}, {"until", "9"}},
        {{"cursor", ""}},
        {{"cursor", "garbage"}},
        {{"cursor", "c1:5:YWJj"}}, // another list's token
        {{"cursor", cursor_too_long}},
        {{"latest_per_workflow", "TRUE"}},
        {{"latest_per_workflow", "1"}},
        {{"latest_per_workflow", ""}},
        {{"latest_per_workflow", "true"}, {"cursor", valid_cursor()}},
    };
    for (const auto& params : bad) {
        INFO(params.front().first << "=" << params.front().second.substr(0, 20));
        CHECK_FALSE(rest(params).has_value());
    }
    // The bounds are inclusive at the edge.
    CHECK(rest({{"workflow_id", std::string(kWorkflowIdMaxLen, 'a')}}).has_value());
    CHECK(rest({{"since", "9007199254740992"}}).has_value());
    CHECK(rest({{"since", "0"}}).has_value());

    const std::vector<json> bad_args{
        json{{"workflow_id", 5}},        json{{"workflow_id", ""}},        json{{"status", 1}},
        json{{"status", "nope"}},        json{{"since", "10"}},            json{{"since", 1.5}},
        json{{"since", -1}},             json{{"since", 9007199254740993LL}},
        json{{"until", true}},           json{{"cursor", 5}},              json{{"cursor", "garbage"}},
        json{{"latest_per_workflow", "true"}}, json{{"latest_per_workflow", 1}},
        json{{"since", 10}, {"until", 9}},
        json{{"latest_per_workflow", true}, {"cursor", valid_cursor()}},
    };
    for (const auto& a : bad_args) {
        INFO(a.dump());
        CHECK_FALSE(parse_workflow_execution_list_args(a).has_value());
    }
}

TEST_CASE("workflow execution list rows: the row shape carries no agent-bearing field",
          "[workflow][executions][list_model]") {
    WorkflowExecutionSummary s;
    s.id = "run-1";
    s.workflow_id = "wf-1";
    s.workflow_name = "Patch Tuesday";
    s.workflow_deleted = true;
    s.status = "failed";
    s.current_step = 3;
    s.started_at = 100;
    s.completed_at = 160;
    const auto j = workflow_execution_summary_json(s);
    CHECK(j == json{{"id", "run-1"},
                    {"workflow_id", "wf-1"},
                    {"workflow_name", "Patch Tuesday"},
                    {"workflow_deleted", true},
                    {"status", "failed"},
                    {"current_step", 3},
                    {"started_at", 100},
                    {"completed_at", 160}});
    for (const char* leak : {"agent_ids", "agents_reached", "steps", "agent_count"})
        CHECK_FALSE(j.contains(leak));
}

TEST_CASE("workflow execution list rows: the page renders its rows and a cursor only when more exist",
          "[workflow][executions][list_model]") {
    WorkflowExecutionPage page;
    CHECK(workflow_execution_rows_json(page) == json::array());
    CHECK(workflow_execution_next_cursor_json(page).is_null());

    WorkflowExecutionSummary s;
    s.id = "run-9";
    s.started_at = 1735689600;
    page.rows.push_back(s);
    CHECK(workflow_execution_rows_json(page).size() == 1);
    CHECK(workflow_execution_next_cursor_json(page).is_null()); // no sentinel row, no cursor

    page.next = keyset::Position{s.started_at, s.id};
    const auto token = workflow_execution_next_cursor_json(page);
    REQUIRE(token.is_string());
    // The token is a position only: feeding it back yields exactly that position.
    const auto back = rest({{"cursor", token.get<std::string>()}});
    REQUIRE(back.has_value());
    REQUIRE(back->after.has_value());
    CHECK(*back->after == *page.next);
}
