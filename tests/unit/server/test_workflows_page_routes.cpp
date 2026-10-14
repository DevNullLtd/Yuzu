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

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
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
    bool fleet_grant{true};
    yuzu::server::authz::VisibleSet fleet_scope{std::nullopt};
    std::string username{"alice"};
    std::string token_scope_service;
    std::vector<std::string> audit_actions;

    int list_calls{0};
    WorkflowQuery seen_query;
    std::expected<std::vector<Workflow>, std::string> workflows{std::vector<Workflow>{}};
    std::expected<ScheduleListResult, std::string> schedules{ScheduleListResult{}};

    // Runs (WF-2): the list and detail doubles, with what the route handed the seam.
    int runs_calls{0};
    WorkflowExecutionListQuery seen_run_query;
    yuzu::server::authz::VisibleSet seen_run_scope{std::nullopt};
    std::expected<WorkflowExecutionPage, std::string> runs{WorkflowExecutionPage{}};
    int exec_calls{0};
    std::expected<std::optional<WorkflowExecution>, std::string> exec{std::nullopt};
    std::expected<std::optional<Workflow>, std::string> def{std::nullopt};

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
        d.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                                 const std::string&) -> authz::FleetReadGate {
            ++fleet_calls;
            if (!fleet_grant) {
                res.status = 403;
                res.set_content("{\"error\":{\"code\":403,\"message\":\"missing Workflow:Read "
                                "for role r-secret\"}}",
                                "application/json");
                return {false, {}};
            }
            return {true, fleet_scope};
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
            [this](const std::string&) { return def; },
            [this](const std::string&) {
                ++exec_calls;
                return exec;
            },
            [this](const WorkflowExecutionListQuery& q, const yuzu::server::authz::VisibleSet& sc) {
                ++runs_calls;
                seen_run_query = q;
                seen_run_scope = sc;
                return runs;
            });
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

// ── /fragments/workflow-runs (F2) and /fragments/workflow-runs/{id} (F3) ─────

namespace {

WorkflowExecutionSummary run_row(const std::string& id, const std::string& wf,
                                 const std::string& status = "completed") {
    WorkflowExecutionSummary r;
    r.id = id;
    r.workflow_id = wf;
    r.workflow_name = "Name of " + wf;
    r.status = status;
    r.started_at = 1700000000;
    r.completed_at = 1700000072;
    return r;
}

WorkflowExecution run_exec(const std::string& id, const std::string& agents = R"(["a1","a2"])") {
    WorkflowExecution e;
    e.id = id;
    e.workflow_id = "wf-1";
    e.status = "completed";
    e.agent_ids_json = agents;
    e.started_at = 1700000000;
    e.completed_at = 1700000072;
    WorkflowStepResult s0;
    s0.step_index = 0;
    s0.instruction_id = "inst-0";
    s0.status = "success";
    s0.result_json = R"({"status":"dispatched","command_id":"c","agents_reached":2})";
    s0.started_at = 1700000000;
    s0.completed_at = 1700000012;
    e.step_results.push_back(s0);
    WorkflowStepResult s1;
    s1.step_index = 1;
    s1.instruction_id = "inst-1";
    s1.status = "failed";
    s1.result_json = R"({"error":"no agents reached for inst-1"})";
    e.step_results.push_back(s1);
    return e;
}

} // namespace

TEST_CASE("/fragments/workflow-runs: fleet_read_fn is the sole gate and its scope reaches the seam",
          "[workflow][workflows][page][runs]") {
    Fx fx;
    fx.fleet_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"a1"}};
    fx.runs = WorkflowExecutionPage{{run_row("r1", "wf-1")}, std::nullopt, false};
    auto res = fx.get("/fragments/workflow-runs?latest_per_workflow=true&limit=500");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-run-id=\"r1\""));
    CHECK(has(res->body, "data-confined=\"1\""));
    CHECK(fx.fleet_calls == 1);
    CHECK(fx.perm_calls == 0); // never stacked with perm_fn
    CHECK(fx.runs_calls == 1);
    CHECK(fx.seen_run_query.latest_per_workflow);
    CHECK(fx.seen_run_query.limit == 500);
    CHECK(fx.seen_run_scope.has_value());
    CHECK(fx.audit_actions.empty());
}

TEST_CASE("/fragments/workflow-runs: a refusal is a 200 note and the store is not read",
          "[workflow][workflows][page][runs][security]") {
    Fx fx;
    fx.fleet_grant = false;
    auto res = fx.get("/fragments/workflow-runs");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-denied=\"true\""));
    CHECK(has(res->body, "You do not have permission to view workflow runs."));
    CHECK_FALSE(has(res->body, "r-secret"));
    CHECK(fx.runs_calls == 0);
    CHECK(fx.perm_calls == 0);
}

TEST_CASE("/fragments/workflow-runs: unknown, repeated and malformed parameters are refused, not ignored",
          "[workflow][workflows][page][runs]") {
    Fx fx;
    for (const char* target : {"/fragments/workflow-runs?since=1", "/fragments/workflow-runs?cursor=x",
                               "/fragments/workflow-runs?limit=5&limit=6",
                               "/fragments/workflow-runs?status=bogus",
                               "/fragments/workflow-runs?workflow_id=a%20b",
                               "/fragments/workflow-runs?nonsense=<script>"}) {
        auto res = fx.get(target);
        CHECK(res->status == 200);
        CHECK(has(res->body, "data-invalid=\"true\""));
        CHECK(has(res->body, "Unknown or invalid run filter."));
        CHECK_FALSE(has(res->body, "<script>"));
    }
    CHECK(fx.runs_calls == 0);
}

TEST_CASE("/fragments/workflow-runs: a store failure is a degraded note, an empty page says no runs",
          "[workflow][workflows][page][runs]") {
    Fx fx;
    fx.runs = std::unexpected(std::string{"statement timeout (internal)"});
    auto res = fx.get("/fragments/workflow-runs");
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-degraded=\"true\""));
    CHECK(has(res->body, "Run history unavailable, retry shortly."));
    CHECK_FALSE(has(res->body, "statement timeout"));
    CHECK_FALSE(has(res->body, "No runs yet."));

    fx.runs = WorkflowExecutionPage{};
    auto empty = fx.get("/fragments/workflow-runs");
    CHECK(has(empty->body, "No runs yet."));
    fx.fleet_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"a1"}};
    auto confined = fx.get("/fragments/workflow-runs");
    CHECK(has(confined->body, "No runs include devices in your scope."));
}

TEST_CASE("/fragments/workflow-runs/{id}: gate, audit and the confined projection",
          "[workflow][workflows][page][runs]") {
    Fx fx;
    fx.exec = run_exec("r1");
    Workflow w = workflow("wf-1", "Patch Tuesday", 2);
    w.steps[0].label = "Preflight <b>";
    fx.def = w;
    auto res = fx.get("/fragments/workflow-runs/r1");
    CHECK(res->status == 200);
    CHECK(has(res->body, "1. Preflight &lt;b&gt;"));
    CHECK(has(res->body, "2. Step 1")); // label from the definition (step 1 has one)
    CHECK(has(res->body, "Patch Tuesday"));
    CHECK(has(res->body, "Dispatched"));
    CHECK_FALSE(has(res->body, "run-wide"));
    CHECK(has(res->body, "Reached 2 devices"));
    CHECK(has(res->body, "no agents reached for inst-1"));
    CHECK(has(res->body, "1 of 2"));
    CHECK(fx.fleet_calls == 1);
    CHECK(fx.perm_calls == 0);
    REQUIRE(fx.audit_actions.size() == 1);
    CHECK(fx.audit_actions[0] == "workflow_execution.detail.fetch");

    // A confined caller: run-wide copy, no reach count, only its own devices counted.
    fx.fleet_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"a1"}};
    auto c = fx.get("/fragments/workflow-runs/r1");
    CHECK(c->status == 200);
    CHECK(has(c->body, "Dispatched (run-wide)"));
    CHECK(has(c->body, "Devices in your scope"));
    CHECK_FALSE(has(c->body, "Reached"));
    CHECK_FALSE(has(c->body, "a2"));
}

TEST_CASE("/fragments/workflow-runs/{id}: hidden and unknown ids answer with identical bytes",
          "[workflow][workflows][page][runs][security]") {
    Fx fx;
    fx.fleet_scope = yuzu::server::authz::VisibleSet{std::unordered_set<std::string>{"mine"}};
    fx.exec = run_exec("r-hidden", R"(["other-1","other-2"])");
    auto hidden = fx.get("/fragments/workflow-runs/r-hidden");
    const size_t audits_after_hidden = fx.audit_actions.size();
    fx.exec = std::optional<WorkflowExecution>{};
    auto unknown = fx.get("/fragments/workflow-runs/r-unknown");
    CHECK(hidden->status == 404);
    CHECK(unknown->status == 404);
    CHECK(hidden->body == unknown->body);
    CHECK_FALSE(has(hidden->body, "r-hidden"));
    CHECK_FALSE(has(hidden->body, "other-1"));
    // The hidden fetch is audited as a denial; the unknown one writes nothing (as the v1 route).
    REQUIRE(audits_after_hidden == 1);
    CHECK(fx.audit_actions[0] == "workflow_execution.detail.fetch");
    CHECK(fx.audit_actions.size() == 1);
}

TEST_CASE("/fragments/workflow-runs/{id}: a refusal and a failure are 200 notes",
          "[workflow][workflows][page][runs]") {
    Fx fx;
    fx.fleet_grant = false;
    auto denied = fx.get("/fragments/workflow-runs/r1");
    CHECK(denied->status == 200);
    CHECK(has(denied->body, "data-denied=\"true\""));
    CHECK(fx.exec_calls == 0);
    CHECK(fx.audit_actions.empty()); // the gate audits its own denial

    fx.fleet_grant = true;
    fx.exec = std::unexpected(std::string{"pool exhausted (internal)"});
    auto degraded = fx.get("/fragments/workflow-runs/r1");
    CHECK(degraded->status == 200);
    CHECK(has(degraded->body, "data-degraded=\"true\""));
    CHECK_FALSE(has(degraded->body, "pool exhausted"));
}

TEST_CASE("/fragments/workflow-runs/{id}: stored text is escaped and an unknown shape says no detail",
          "[workflow][workflows][page][runs][security]") {
    Fx fx;
    WorkflowExecution e = run_exec("r1");
    e.step_results[1].result_json = R"({"error":{"agent":"out-of-scope-9","text":"<img src=x onerror=1>"}})";
    WorkflowStepResult s2;
    s2.step_index = 2;
    s2.instruction_id = "<img src=x onerror=1>";
    s2.status = "skipped";
    s2.result_json = R"({"reason":"something <b>new</b>"})";
    e.step_results.push_back(s2);
    fx.exec = e;
    auto res = fx.get("/fragments/workflow-runs/r1");
    CHECK(res->status == 200);
    CHECK_FALSE(has(res->body, "out-of-scope-9"));
    CHECK_FALSE(has(res->body, "<img"));
    CHECK_FALSE(has(res->body, "<b>new"));
    CHECK(has(res->body, "No detail."));
}
