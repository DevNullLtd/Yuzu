/**
 * test_workflows_page_routes.cpp -- the Workflows page's fragments through TestRouteSink with
 * fake gates and in-memory API doubles. No database: what is proved here is each route's own
 * contract (which single gate it calls, what a denial becomes, which note a degraded store
 * renders, what bytes a non-owner schedule row carries). That the real gates yield the right
 * id sets is the [pg] authz test.
 */

#include "test_route_sink.hpp"
#include "test_schedule_api_double.hpp"
#include "test_workflow_api_double.hpp"
#include "workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

struct Fx {
    // Fake gates: counts and last (securable, operation) pair, so a test can prove a route
    // calls exactly its own gate and never the other one.
    int perm_calls{0};
    int fleet_calls{0};
    std::string perm_type, perm_op;
    bool perm_grant{true};
    std::string username{"alice"};
    std::string token_scope_service;
    std::vector<std::string> audit_actions;

    int list_calls{0};
    WorkflowQuery seen_query;
    std::expected<std::vector<Workflow>, std::string> workflows{std::vector<Workflow>{}};
    std::expected<ScheduleListResult, std::string> schedules{ScheduleListResult{}};

    WorkflowRoutes routes;
    yuzu::server::test::TestRouteSink sink; // declared AFTER the route owner (see the sink header)

    Fx() {
        WorkflowRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = username;
            s.token_scope_service = token_scope_service;
            return s;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& op) -> bool {
            ++perm_calls;
            perm_type = t;
            perm_op = op;
            if (!perm_grant) {
                res.status = 403;
                res.set_content("{\"error\":{\"code\":403,\"message\":\"missing Workflow:Read "
                                "for role r-secret\"}}",
                                "application/json");
                return false;
            }
            return true;
        };
        d.fleet_read_fn = [this](const httplib::Request&, httplib::Response&, const std::string&,
                                 const std::string&) -> authz::FleetReadGate {
            ++fleet_calls;
            return {true, std::nullopt};
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
            audit_actions.push_back(action);
        };
        d.workflow_api = std::make_shared<yuzu::server::test::FnWorkflowApi>(
            [this](const WorkflowQuery& q) {
                ++list_calls;
                seen_query = q;
                return workflows;
            },
            yuzu::server::test::FnWorkflowApi::GetFn{},
            yuzu::server::test::FnWorkflowApi::GetExecutionFn{});
        d.schedule_api = std::make_shared<yuzu::server::test::FnScheduleApi>(
            [this](const ScheduleQuery&) { return schedules; });
        routes.register_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& target) {
        auto res = sink.Get(target);
        REQUIRE(res);
        return res;
    }
};

InstructionSchedule sched(const std::string& id, const std::string& name) {
    InstructionSchedule s;
    s.id = id;
    s.name = name;
    s.definition_id = "def-" + id;
    s.frequency_type = "daily";
    s.enabled = true;
    s.next_execution_at = 1700000000;
    s.execution_count = 3;
    s.created_by = "alice";
    return s;
}

} // namespace

// The Schedules tab on /instructions swaps this fragment into #tab-schedules, so its default
// bytes are a contract: the page's `view=page` branch must never change them.
TEST_CASE("/fragments/schedules: the default view is byte-identical to the Schedules tab's",
          "[workflow][workflows][page][schedules]") {
    Fx fx;
    fx.schedules = ScheduleListResult{{sched("s1", "Nightly <b>")}, false};
    auto res = fx.get("/fragments/schedules");
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->body ==
          "<section class=\"panel\"><div class=\"hd\"><h2>Schedules</h2></div>"
          "<div class=\"tw\"><table><thead><tr><th>Name</th><th>Frequency</th><th>Enabled</th>"
          "<th>Next Run</th><th>Count</th><th></th></tr></thead><tbody>"
          "<tr><td>Nightly &lt;b&gt;</td><td><code>daily</code></td><td>Yes</td>"
          "<td>1700000000</td><td>3</td><td class=\"act\"><button class=\"btn btn-danger btn-sm\" "
          "hx-delete=\"/api/schedules/s1\" hx-target=\"#tab-schedules\" hx-swap=\"innerHTML\" "
          "hx-confirm=\"Delete schedule?\">Delete</button></td></tr></tbody></table></div>"
          "</section>");
}

// ── /fragments/workflows (F1) ───────────────────────────────────────────────

namespace {

Workflow workflow(const std::string& id, const std::string& name, int steps = 2) {
    Workflow w;
    w.id = id;
    w.name = name;
    w.description = "desc of " + name;
    for (int i = 0; i < steps; ++i) {
        WorkflowStep s;
        s.index = i;
        s.instruction_id = "inst-" + std::to_string(i);
        s.label = "Step " + std::to_string(i);
        w.steps.push_back(s);
    }
    return w;
}

} // namespace

TEST_CASE("/fragments/workflows: a permitted caller gets the list through its one gate",
          "[workflow][workflows][page]") {
    Fx fx;
    fx.workflows = std::vector<Workflow>{workflow("wf-1", "Patch Tuesday")};
    auto res = fx.get("/fragments/workflows");
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(has(res->body, "data-workflow-id=\"wf-1\""));
    CHECK(has(res->body, "1. Step 0"));
    CHECK(has(res->body, "inst-1"));
    // Single gate: Workflow:Read through perm_fn, exactly the v1 list's, never the fleet gate.
    CHECK(fx.perm_calls == 1);
    CHECK(fx.perm_type == "Workflow");
    CHECK(fx.perm_op == "Read");
    CHECK(fx.fleet_calls == 0);
    // A read of definitions writes no audit row (as the v1 twin).
    CHECK(fx.audit_actions.empty());
    // One past the 100 shown, so truncation is known and not guessed.
    CHECK(fx.seen_query.limit == 101);
    CHECK(fx.seen_query.name_filter.empty());
}

TEST_CASE("/fragments/workflows: a refusal is a 200 note that leaks nothing from the gate",
          "[workflow][workflows][page][security]") {
    Fx fx;
    fx.perm_grant = false;
    auto res = fx.get("/fragments/workflows");
    CHECK(res->status == 200); // htmx drops 4xx bodies
    CHECK(has(res->body, "data-denied=\"true\""));
    CHECK(has(res->body, "You do not have permission to view workflows."));
    CHECK_FALSE(has(res->body, "r-secret"));
    CHECK_FALSE(has(res->body, "Workflow:Read"));
    CHECK(fx.list_calls == 0); // the store is never read for a refused caller
}

TEST_CASE("/fragments/workflows: a store failure is a degraded note, never an empty list",
          "[workflow][workflows][page]") {
    Fx fx;
    fx.workflows = std::unexpected(std::string{"pool exhausted (internal, must not render)"});
    auto res = fx.get("/fragments/workflows");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-degraded=\"true\""));
    CHECK(has(res->body, "This is not an empty list."));
    CHECK_FALSE(has(res->body, "No workflows yet."));
    CHECK_FALSE(has(res->body, "pool exhausted"));
}

TEST_CASE("/fragments/workflows: an unwired seam is the same degraded note",
          "[workflow][workflows][page]") {
    // Deps are built per case, so register a route owner with the seam absent.
    WorkflowRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    WorkflowRoutes::Deps d;
    d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    routes.register_routes(sink, std::move(d));
    auto res = sink.Get("/fragments/workflows");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-degraded=\"true\""));
    CHECK_FALSE(has(res->body, "No workflows yet."));
}

TEST_CASE("/fragments/workflows: an empty store says so", "[workflow][workflows][page]") {
    Fx fx;
    auto res = fx.get("/fragments/workflows");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-state=\"empty\""));
    CHECK(has(res->body, "No workflows yet."));
}

TEST_CASE("/fragments/workflows: the 101st row is a truncation sentinel, not a row",
          "[workflow][workflows][page]") {
    Fx fx;
    std::vector<Workflow> many;
    for (int i = 0; i < 101; ++i)
        many.push_back(workflow("wf-" + std::to_string(i), "W" + std::to_string(i), 0));
    fx.workflows = many;
    auto res = fx.get("/fragments/workflows");
    CHECK(has(res->body, "data-count=\"100\""));
    CHECK(has(res->body, "data-truncated=\"1\""));
    CHECK(has(res->body, "Showing the first 100 workflows."));
    CHECK(has(res->body, "data-workflow-id=\"wf-99\""));
    CHECK_FALSE(has(res->body, "data-workflow-id=\"wf-100\""));

    many.pop_back(); // exactly 100: complete, no note
    fx.workflows = many;
    res = fx.get("/fragments/workflows");
    CHECK(has(res->body, "data-count=\"100\""));
    CHECK(has(res->body, "data-truncated=\"0\""));
    CHECK_FALSE(has(res->body, "Showing the first"));
}

TEST_CASE("/fragments/workflows: markup in a name, label or instruction id is escaped",
          "[workflow][workflows][page][security]") {
    Fx fx;
    auto w = workflow("wf-<i>", "<img src=x onerror=1>");
    w.description = "<img src=x onerror=1>";
    w.steps[0].label = "<img src=x onerror=1>";
    w.steps[0].instruction_id = "<img src=x onerror=1>";
    fx.workflows = std::vector<Workflow>{w};
    auto res = fx.get("/fragments/workflows");
    CHECK_FALSE(has(res->body, "<img"));
    CHECK(has(res->body, "&lt;img src=x onerror=1&gt;"));
}

// ── /fragments/schedules?view=page (F4) ─────────────────────────────────────

TEST_CASE("/fragments/schedules?view=page: refusals are 200 notes; the default view still 403s",
          "[workflow][workflows][page][schedules][security]") {
    Fx fx;
    fx.perm_grant = false;
    auto page = fx.get("/fragments/schedules?view=page");
    CHECK(page->status == 200);
    CHECK(has(page->body, "data-denied=\"true\""));
    CHECK(has(page->body, "You do not have permission to view schedules."));
    CHECK_FALSE(has(page->body, "r-secret"));
    // The default view (the Instructions Schedules tab) keeps its own contract.
    auto def = fx.get("/fragments/schedules");
    CHECK(def->status == 403);
}

TEST_CASE("/fragments/schedules?view=page: a service-scoped token is denied before the gate and audited",
          "[workflow][workflows][page][schedules][security]") {
    Fx fx;
    fx.token_scope_service = "printers";
    auto res = fx.get("/fragments/schedules?view=page");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-denied=\"true\""));
    CHECK(fx.perm_calls == 0); // the service-scoped deny runs first, as the default view's
    REQUIRE(fx.audit_actions.size() == 1);
    CHECK(fx.audit_actions[0] == "schedule.list.access_denied");
}

TEST_CASE("/fragments/schedules?view=page: the owner flag is server-computed and a non-owner row "
          "carries a boolean only",
          "[workflow][workflows][page][schedules][security]") {
    Fx fx;
    auto mine = sched("s-mine", "Mine");
    mine.frequency_type = "interval";
    mine.interval_minutes = 15;
    mine.scope_expression = "tag:prod";
    mine.requires_approval = true;
    mine.parameter_values = R"({"a":"1","b":"2"})";
    auto theirs = sched("s-theirs", "Theirs");
    theirs.created_by = "bob-the-creator";
    theirs.frequency_type = "interval";
    theirs.interval_minutes = 17;
    theirs.scope_expression = "SECRET-EXPR";
    theirs.requires_approval = true;
    theirs.parameter_values = R"({"k":"v-SECRET"})";
    auto orphan = sched("s-orphan", "Orphan"); // #4131: created_by is empty
    orphan.created_by.clear();
    orphan.scope_expression = "ORPHAN-EXPR";
    fx.schedules = ScheduleListResult{{mine, theirs, orphan}, false};

    auto res = fx.get("/fragments/schedules?view=page");
    CHECK(res->status == 200);
    const auto& b = res->body;
    CHECK(has(b, "data-schedule-id=\"s-mine\" data-owner=\"1\""));
    CHECK(has(b, "data-schedule-id=\"s-theirs\" data-owner=\"0\""));
    CHECK(has(b, "data-schedule-id=\"s-orphan\" data-owner=\"0\"")); // nobody's, even for "alice"
    CHECK(has(b, "tag:prod"));
    CHECK(has(b, "Every 15 minutes"));
    CHECK(has(b, "2 parameters"));
    CHECK(has(b, "Approval required"));
    // Nothing of another user's schedule reaches the bytes except the boolean and the type.
    CHECK_FALSE(has(b, "bob-the-creator"));
    CHECK_FALSE(has(b, "SECRET-EXPR"));
    CHECK_FALSE(has(b, "ORPHAN-EXPR"));
    CHECK_FALSE(has(b, "v-SECRET"));
    CHECK_FALSE(has(b, "Every 17 minutes"));
    CHECK(has(b, "Targeted"));
    // The whole list is one gate call and one seam read.
    CHECK(fx.perm_calls == 1);
    CHECK(fx.perm_type == "Schedule");
    CHECK(fx.perm_op == "Read");
    CHECK(fx.fleet_calls == 0);
}

TEST_CASE("/fragments/schedules?view=page: count, last run and the partial-list note",
          "[workflow][workflows][page][schedules]") {
    Fx fx;
    auto s = sched("s1", "Nightly");
    s.last_executed_at = 1700003600;
    s.execution_count = 42;
    fx.schedules = ScheduleListResult{{s}, true};
    auto res = fx.get("/fragments/schedules?view=page");
    CHECK(has(res->body, "<td>42</td>"));
    CHECK(has(res->body, "data-epoch-ms=\"1700003600000\""));
    CHECK(has(res->body, "Showing a partial list - more schedules exist than can be displayed."));
    CHECK(has(res->body, "data-truncated=\"1\""));
}

TEST_CASE("/fragments/schedules?view=page: a store failure is a degraded note, not an empty list",
          "[workflow][workflows][page][schedules]") {
    Fx fx;
    fx.schedules = std::unexpected(std::string{"pool exhausted (internal, must not render)"});
    auto res = fx.get("/fragments/schedules?view=page");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-degraded=\"true\""));
    CHECK(has(res->body, "temporarily unavailable"));
    CHECK_FALSE(has(res->body, "No schedules configured."));
    CHECK_FALSE(has(res->body, "pool exhausted"));
}

TEST_CASE("/fragments/schedules?view=page: an empty list and markup in names are handled",
          "[workflow][workflows][page][schedules][security]") {
    Fx fx;
    auto res = fx.get("/fragments/schedules?view=page");
    CHECK(has(res->body, "No schedules configured."));

    auto s = sched("s1", "<img src=x onerror=1>");
    s.definition_id = "<img src=x onerror=1>";
    s.scope_expression = "<img src=x onerror=1>";
    fx.schedules = ScheduleListResult{{s}, false};
    res = fx.get("/fragments/schedules?view=page");
    CHECK_FALSE(has(res->body, "<img"));
}
