/**
 * test_workflows_page_render.cpp -- the Workflows page's definitions and schedules renderers
 * (workflows_page_render.hpp). Pure string-in, string-out: no store, no gate, no clock.
 *
 * Pinned: the markup contract the controller reads, the exact notes, the step policy pill,
 * the cadence text for every frequency type, that every user string is escaped, and that a
 * non-owner schedule row never prints the scope, the interval, the approval flag or the
 * parameter count even when a buggy route filled them in.
 */

#include "workflows_page_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server::operate_pages;

namespace {

constexpr const char* kPlant = "<img src=x onerror=1>";

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

WorkflowStepView step(int index, const std::string& instruction) {
    WorkflowStepView s;
    s.index = index;
    s.instruction_id = instruction;
    return s;
}

WorkflowRowView wf(const std::string& id, const std::string& name) {
    WorkflowRowView w;
    w.id = id;
    w.name = name;
    return w;
}

ScheduleRowView sched(const std::string& id, bool owner) {
    ScheduleRowView s;
    s.id = id;
    s.name = "Nightly";
    s.definition_id = "def-1";
    s.frequency_type = "interval";
    s.enabled = true;
    s.next_execution_at = 1'700'000'000;
    s.execution_count = 4;
    s.owner = owner;
    return s;
}

} // namespace

TEST_CASE("workflows render: an empty list says so and carries the empty state",
          "[ui][workflows][render]") {
    const auto html = render_workflows_list({});
    CHECK(has(html, "data-state=\"empty\""));
    CHECK(has(html, "No workflows yet."));
    CHECK(has(html, "Ask an administrator to add one."));
    CHECK_FALSE(has(html, "<table"));
}

TEST_CASE("workflows render: a row carries its id and name, and its steps ride in the hidden store",
          "[ui][workflows][render]") {
    WorkflowListView v;
    auto w = wf("wf-1", "Patch Tuesday");
    w.description = "Patch then verify";
    auto s0 = step(0, "inst-a");
    s0.label = "Preflight";
    auto s1 = step(1, "inst-b"); // no label: the instruction id is the title
    s1.condition = "ostype == 'windows'";
    s1.retry_count = 2;
    s1.retry_delay_seconds = 30;
    s1.foreach_source = "previous.hosts";
    s1.on_failure = "continue";
    w.steps = {s0, s1};
    v.rows = {w};
    const auto html = render_workflows_list(v);

    CHECK(has(html, "data-state=\"ok\" data-count=\"1\" data-truncated=\"0\""));
    CHECK(has(html, "class=\"row\" tabindex=\"0\" aria-selected=\"false\" data-workflow-id=\"wf-1\" "
                    "data-workflow-name=\"Patch Tuesday\""));
    CHECK(has(html, "Patch then verify"));
    CHECK(has(html, "<div class=\"ops-steps-store\" hidden>"));
    CHECK(has(html, "<div data-steps-for=\"wf-1\" data-name=\"Patch Tuesday\">"));
    CHECK(has(html, "1. Preflight"));
    CHECK(has(html, "2. inst-b"));
    CHECK(has(html, "if ostype == &#39;windows&#39;"));
    CHECK(has(html, "up to 2 retries, 30 s apart"));
    CHECK(has(html, "for each previous.hosts"));
    CHECK(has(html, "<span class=\"pill idle\">Continue</span>"));
    CHECK(has(html, "<span class=\"pill idle\">Abort</span>")); // empty on_failure is abort
}

TEST_CASE("workflows render: truncation is stated, with the page cap", "[ui][workflows][render]") {
    WorkflowListView v;
    v.rows = {wf("wf-1", "A")};
    v.truncated = true;
    v.page_cap = 100;
    const auto html = render_workflows_list(v);
    CHECK(has(html, "data-truncated=\"1\""));
    CHECK(has(html, "Showing the first 100 workflows."));
}

TEST_CASE("workflows render: every user string is escaped, none reaches the markup raw",
          "[ui][workflows][render]") {
    WorkflowListView v;
    auto w = wf(kPlant, kPlant);
    w.description = kPlant;
    auto s = step(0, kPlant);
    s.label = kPlant;
    s.condition = kPlant;
    s.foreach_source = kPlant;
    s.on_failure = kPlant;
    w.steps = {s};
    v.rows = {w};
    const auto html = render_workflows_list(v);
    CHECK_FALSE(has(html, "<img"));
    CHECK(has(html, "&lt;img src=x onerror=1&gt;"));
}

TEST_CASE("workflows render: the step policy pill never guesses", "[ui][workflows][render]") {
    CHECK(step_policy("").label == "Abort");
    CHECK(step_policy("abort").label == "Abort");
    CHECK(step_policy("continue").label == "Continue");
    CHECK(step_policy("skip_remaining").label == "Skip remaining");
    CHECK(step_policy("retry_forever").label == "retry_forever");
    CHECK(step_policy("retry_forever").cls == "idle");
}

TEST_CASE("schedules render: the cadence is the one the scheduler applies",
          "[ui][workflows][render]") {
    CHECK(cadence_text("once", 0) == "Once");
    CHECK(cadence_text("interval", 15) == "Every 15 minutes");
    CHECK(cadence_text("interval", 1) == "Every minute");
    CHECK(cadence_text("interval", 0) == "Repeats on an interval");
    CHECK(cadence_text("daily", 60) == "Daily (every 24 hours)");
    CHECK(cadence_text("weekly", 60) == "Weekly (every 7 days)");
    CHECK(cadence_text("monthly", 60) == "Monthly (every 30 days)");
    CHECK(cadence_text("fortnightly", 0) == "fortnightly");
}

TEST_CASE("schedules render: an owner row shows its targeting, interval and flags",
          "[ui][workflows][render]") {
    ScheduleListView v;
    auto s = sched("s1", true);
    s.interval_minutes = 15;
    s.targeted = true;
    s.scope_expression = "tag:prod";
    s.requires_approval = true;
    s.parameter_count = 2;
    v.rows = {s};
    const auto html = render_schedules_page(v);
    CHECK(has(html, "data-schedule-id=\"s1\" data-owner=\"1\""));
    CHECK(has(html, "Every 15 minutes"));
    CHECK(has(html, "tag:prod"));
    CHECK(has(html, "Approval required"));
    CHECK(has(html, "2 parameters"));
    CHECK(has(html, "<span class=\"pill ok\">Enabled</span>"));
    CHECK(has(html, "<td>4</td>")); // Count
}

TEST_CASE("schedules render: a non-owner row carries a boolean and nothing else",
          "[ui][workflows][render]") {
    ScheduleListView v;
    auto s = sched("s2", false);
    s.targeted = true;
    // A route bug that filled the owner-only fields must still print none of them.
    s.interval_minutes = 17;
    s.scope_expression = "SECRET-SCOPE";
    s.requires_approval = true;
    s.parameter_count = 9;
    v.rows = {s};
    const auto html = render_schedules_page(v);
    CHECK(has(html, "data-owner=\"0\""));
    CHECK(has(html, "Targeted"));
    CHECK(has(html, "Repeats on an interval"));
    CHECK_FALSE(has(html, "SECRET-SCOPE"));
    CHECK_FALSE(has(html, "Every 17 minutes"));
    CHECK_FALSE(has(html, "Approval required"));
    CHECK_FALSE(has(html, "parameters"));

    s.targeted = false;
    v.rows = {s};
    CHECK(has(render_schedules_page(v), "All devices"));
}

TEST_CASE("schedules render: dates show a dash when unset, and a missing next run reads as a fired one-time",
          "[ui][workflows][render]") {
    ScheduleListView v;
    auto s = sched("s3", true);
    s.next_execution_at = 0;
    s.last_executed_at = 0;
    v.rows = {s};
    const auto html = render_schedules_page(v);
    CHECK(has(html, "<td class=\"tm\">-</td><td class=\"tm\">-</td>"));
    CHECK_FALSE(has(html, "data-epoch-ms"));
}

TEST_CASE("schedules render: partial list, empty list and escaping", "[ui][workflows][render]") {
    ScheduleListView v;
    v.truncated = true;
    auto empty = render_schedules_page(v);
    CHECK(has(empty, "Showing a partial list - more schedules exist than can be displayed."));
    CHECK(has(empty, "No schedules configured."));

    auto s = sched(kPlant, true);
    s.name = kPlant;
    s.definition_id = kPlant;
    s.targeted = true;
    s.scope_expression = kPlant;
    v.rows = {s};
    v.truncated = false;
    const auto html = render_schedules_page(v);
    CHECK_FALSE(has(html, "<img"));
    CHECK(has(html, "&lt;img src=x onerror=1&gt;"));
}

// ── runs (WF-2) ─────────────────────────────────────────────────────────────

TEST_CASE("runs render: run and step pills follow the documented vocabulary",
          "[ui][workflows][render][runs]") {
    CHECK(run_status_pill("pending").label == "Pending");
    CHECK(run_status_pill("running").cls == "info");
    CHECK(run_status_pill("completed").cls == "ok");
    CHECK(run_status_pill("failed").cls == "bad");
    CHECK(run_status_pill("cancelled").label == "Cancelled");
    CHECK(run_status_pill("weird").label == "weird");
    CHECK(run_step_pill("pending", false).label == "Waiting");
    CHECK(run_step_pill("success", false).label == "Dispatched");
    CHECK(run_step_pill("success", true).label == "Dispatched (run-wide)");
    CHECK(run_step_pill("skipped", true).label == "Skipped");
    CHECK(run_step_pill("failed", true).cls == "bad");
}

TEST_CASE("runs render: duration is a dash unless both instants are set and ordered",
          "[ui][workflows][render][runs]") {
    CHECK(duration_text(0, 100) == "-");
    CHECK(duration_text(100, 0) == "-");
    CHECK(duration_text(100, 99) == "-");
    CHECK(duration_text(100, 145) == "45s");
    CHECK(duration_text(100, 172) == "1m 12s");
    CHECK(duration_text(0 + 1, 1 + 7380) == "2h 3m");
}

TEST_CASE("runs render: the list carries ids for the controller and escapes names",
          "[ui][workflows][render][runs]") {
    RunListView v;
    RunRowView r;
    r.id = "r1";
    r.workflow_id = "wf-1";
    r.workflow_name = "<img src=x onerror=1>";
    r.status = "completed";
    r.started_at = 1700000000;
    r.completed_at = 1700000072;
    r.workflow_deleted = true;
    v.rows.push_back(r);
    const std::string html = render_runs_list(v);
    CHECK(html.find("data-run-id=\"r1\"") != std::string::npos);
    CHECK(html.find("data-workflow-id=\"wf-1\"") != std::string::npos);
    CHECK(html.find("data-c=\"status\"") != std::string::npos);
    CHECK(html.find("data-c=\"started\"") != std::string::npos);
    CHECK(html.find("Workflow deleted") != std::string::npos);
    CHECK(html.find("<img") == std::string::npos);
    CHECK(html.find("1m 12s") != std::string::npos);
}

TEST_CASE("runs render: step detail comes from known shapes only",
          "[ui][workflows][render][runs]") {
    RunDetailView v;
    v.id = "r1";
    v.status = "failed";
    v.device_count = 2;
    auto step = [&](int i, const char* status, const char* result) {
        RunStepView s;
        s.index = i;
        s.title = "t" + std::to_string(i);
        s.status = status;
        s.result_json = result;
        v.steps.push_back(s);
    };
    step(0, "skipped", R"({"reason":"previous step failed"})");
    step(1, "skipped", R"({"reason":"made up <b>"})");
    step(2, "failed", R"({"error":"boom"})");
    step(3, "failed", R"({"error":{"agent":"agent-secret"}})");
    step(4, "failed", "not json");
    step(5, "success", R"([{"agents_reached":2},{"agents_reached":3}])");
    const std::string html = render_run_detail(v);
    CHECK(html.find("previous step failed") != std::string::npos);
    CHECK(html.find("made up") == std::string::npos);
    CHECK(html.find("boom") != std::string::npos);
    CHECK(html.find("agent-secret") == std::string::npos);
    CHECK(html.find("Reached 5 devices") != std::string::npos);
    CHECK(html.find("3 of 6") != std::string::npos);

    v.confined = true;
    const std::string c = render_run_detail(v);
    CHECK(c.find("Reached") == std::string::npos);
    CHECK(c.find("Dispatched (run-wide)") != std::string::npos);
    CHECK(c.find("Devices in your scope") != std::string::npos);
}
