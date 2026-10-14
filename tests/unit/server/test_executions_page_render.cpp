/**
 * test_executions_page_render.cpp -- the Executions page's list and panel renderers
 * (executions_page_render.hpp). Pure string-in, string-out: no store, no gate, no clock, so
 * these run in the non-PG suite.
 *
 * What is pinned is the contract the controller (yuzu-operate.js) reads, not the whole
 * markup: container and row attributes, the exact notes, the pill per state, and that a
 * confined view never prints a field the route did not pass (the struct carries only what
 * the route projected).
 */

#include "executions_page_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <vector>

using namespace yuzu::server::operate_pages;

namespace {

constexpr int64_t kAt = 1'700'000'000;

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos;
         at = hay.find(needle, at + needle.size()))
        ++n;
    return n;
}

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

ExecRow make_row(const std::string& id, const std::string& status) {
    ExecRow r;
    r.id = id;
    r.definition_id = "def-" + id;
    r.definition_name = "Name " + id;
    r.status = status;
    r.dispatched_by = "alice";
    r.agents_targeted = 5;
    r.agents_responded = 2;
    r.agents_success = 2;
    r.dispatched_at = kAt;
    return r;
}

} // namespace

TEST_CASE("executions_page_render: derive_state maps every status exactly",
          "[ui][executions][render]") {
    struct Case {
        const char* status;
        int failure;
        int responded;
        const char* cls;
        const char* label;
    };
    const Case cases[] = {
        {"running", 0, 0, "info", "Running"},
        {"running", 2, 3, "info", "Running"},
        {"succeeded", 0, 5, "ok", "Succeeded"},
        {"cancelled", 0, 1, "idle", "Cancelled"},
        {"pending", 0, 0, "warn", "Pending"},
        {"completed", 0, 5, "ok", "Completed"},
        {"completed", 2, 5, "warn", "2 failed"},
        {"completed", 5, 5, "bad", "5 failed"},
        {"foo", 0, 0, "idle", "foo"},
    };
    for (const auto& c : cases) {
        INFO(c.status << " failure=" << c.failure << " responded=" << c.responded);
        const auto s = derive_state(c.status, c.failure, c.responded);
        CHECK(s.cls == c.cls);
        CHECK(s.label == c.label);
        // The raw status is always recoverable from the hover text.
        const std::string tail = std::string("status=") + c.status;
        CHECK(s.title.size() >= tail.size());
        CHECK(s.title.compare(s.title.size() - tail.size(), tail.size(), tail) == 0);
    }
    CHECK(derive_state("completed", 2, 5).title == "Completed, 2 failed, status=completed");
}

TEST_CASE("executions_page_render: list rows carry the attributes the controller reads",
          "[ui][executions][render]") {
    ExecListView v;
    auto failed = make_row("e-failed", "completed");
    failed.agents_failure = 2;
    failed.agents_responded = 5;
    failed.last_error_detail = std::string(300, 'x');
    auto rerun = make_row("e-rerun", "pending");
    rerun.rerun_of = "e-failed";
    rerun.agents_responded = 0;
    rerun.agents_success = 0;
    v.rows = {make_row("e-run", "running"), failed, rerun};

    const auto html = render_exec_list(v);
    CHECK(has(html, "<div class=\"ops-list\" data-state=\"ok\" data-count=\"3\" "
                    "data-confined=\"0\" data-truncated=\"0\">"));
    CHECK(count_of(html, "<tr class=\"row\"") == 3);
    CHECK(has(html, "data-execution-id=\"e-run\" data-execution-status=\"running\" "
                    "data-def=\"def-e-run\""));
    CHECK(has(html, "<span class=\"pill info\" title=\"Running, status=running\">Running</span>"));
    CHECK(has(html, "<span class=\"pill warn\" title=\"Completed, 2 failed, "
                    "status=completed\">2 failed</span>"));
    CHECK(has(html, "<span class=\"nm\" title=\"def-e-run\">Name e-run</span>"));
    CHECK(has(html, "2 of 5</span>"));
    // The preview is clipped to 80 bytes plus an ellipsis; the full text is the title, once.
    CHECK(has(html, "<span class=\"pv\" title=\"" + std::string(300, 'x') + "\">" +
                        std::string(80, 'x') + "\xE2\x80\xA6</span>"));
    CHECK(count_of(html, std::string(300, 'x')) == 1);
    // A re-run record says nothing was sent; a clean running row has no preview.
    CHECK(has(html, "Re-run record. Nothing was sent to devices."));
    CHECK(count_of(html, "Re-run record.") == 1);
    // Time cell: epoch for the local text, ISO for the title and the no-JS fallback.
    CHECK(has(html, "data-epoch-ms=\"1700000000000\" title=\"2023-11-14T22:13:20Z\""));
    CHECK_FALSE(has(html, "class=\"ops-foot"));
}

TEST_CASE("executions_page_render: the truncation foot only appears when rows were dropped",
          "[ui][executions][render]") {
    ExecListView v;
    v.rows = {make_row("a", "running")};
    CHECK_FALSE(has(render_exec_list(v), "ops-foot"));
    v.truncated = true;
    const auto html = render_exec_list(v);
    CHECK(has(html, "data-truncated=\"1\""));
    CHECK(has(html, "Showing the 1 most recent. Older executions are not listed."));
}

TEST_CASE("executions_page_render: the empty note says what is true for the caller",
          "[ui][executions][render]") {
    ExecListView v;
    // Unfiltered, unconfined: the fleet has none, and the way to make one is linked.
    auto html = render_exec_list(v);
    CHECK(has(html, "data-state=\"empty\" data-count=\"0\""));
    CHECK(has(html, "No executions yet."));
    CHECK(has(html, "<a class=\"lnk\" href=\"/instructions\">Dispatch an instruction from "
                    "Instructions</a>"));
    // Filtered: not "none exist", and no link.
    v.filtered = true;
    html = render_exec_list(v);
    CHECK(has(html, "No executions match these filters."));
    CHECK_FALSE(has(html, "No executions yet."));
    CHECK_FALSE(has(html, "/instructions"));
    // Confined: a scope-truthful note, no link.
    v.filtered = false;
    v.confined = true;
    html = render_exec_list(v);
    CHECK(has(html, "data-confined=\"1\""));
    CHECK(has(html, "No executions visible in your scope."));
    CHECK_FALSE(has(html, "/instructions"));
}

TEST_CASE("executions_page_render: every server string is escaped", "[ui][executions][render]") {
    const std::string evil = "\"><img src=x onerror=1>";
    ExecRow r = make_row(evil, "completed");
    r.definition_id = evil;
    r.definition_name = evil;
    r.dispatched_by = evil;
    r.last_error_detail = evil;
    r.agents_failure = 1;
    r.rerun_of = evil;
    ExecListView lv;
    lv.rows = {r};
    ExecSelectedView sv;
    sv.row = r;
    sv.scope_expression = evil;
    sv.parameter_values = evil;
    for (const auto& html : {render_exec_list(lv), render_exec_selected(sv)}) {
        CHECK_FALSE(has(html, "<img"));
        CHECK_FALSE(has(html, "\"><img"));
        CHECK(has(html, "&lt;img"));
        CHECK_FALSE(has(html, "onerror=1>"));
    }
}

TEST_CASE("executions_page_render: the selected panel lays out the execution",
          "[ui][executions][render]") {
    ExecSelectedView v;
    v.row = make_row("0123456789abcdef0123", "running");
    v.row.rerun_of = "fedcba9876543210fedc";
    v.scope_expression = "group:ops";
    v.parameter_values = "{\"a\":1}";
    const auto html = render_exec_selected(v);
    CHECK(has(html, "<div data-slot=\"selected\" data-execution-id=\"0123456789abcdef0123\" "
                    "data-execution-status=\"running\" data-confined=\"0\">"));
    CHECK(has(html, "<h2>Selected execution</h2>"));
    CHECK(has(html, "<span>Devices</span><b>2 of 5 responded</b>"));
    // Lineage links to the page's own deep link, showing 12 characters.
    CHECK(has(html, "<a class=\"lnk mono\" href=\"/executions?id=fedcba9876543210fedc\">"
                    "fedcba987654</a>"));
    CHECK(has(html, "<code class=\"blk\">group:ops</code>"));
    CHECK(has(html, "<code class=\"blk\">{&quot;a&quot;:1}</code>"));
    // Running: progress at 40 percent (2 of 5), and the JSON responses link.
    CHECK(has(html, "style=\"width:40%\""));
    CHECK(has(html, "40% of targeted devices have responded"));
    CHECK(has(html, "href=\"/api/v1/executions/0123456789abcdef0123/responses?limit=1000\" "
                    "target=\"_blank\" rel=\"noopener\""));
    // Not finished: an em dash, not a 1970 date.
    CHECK(has(html, "<span>Finished</span><b>&mdash;</b>"));
}

TEST_CASE("executions_page_render: terminal panels have no progress bar, finished shows a time",
          "[ui][executions][render]") {
    ExecSelectedView v;
    v.row = make_row("e1", "cancelled");
    v.completed_at = kAt + 58;
    auto html = render_exec_selected(v);
    CHECK_FALSE(has(html, "class=\"prog\""));
    CHECK(has(html, "data-epoch-ms=\"1700000058000\""));
    CHECK(has(html, "<span class=\"pill idle\""));
    // No scope recorded: a dash, never an empty code block.
    CHECK(has(html, "<span>Scope</span><span class=\"faint\">&mdash;</span>"));
    CHECK_FALSE(has(html, "<code class=\"blk\"></code>"));
}

TEST_CASE("executions_page_render: a pending re-run with no targets renders zero progress",
          "[ui][executions][render]") {
    ExecSelectedView v;
    v.row = make_row("e1", "pending");
    v.row.agents_targeted = 0;
    v.row.agents_responded = 0;
    const auto html = render_exec_selected(v);
    CHECK(has(html, "style=\"width:0%\""));
    CHECK(has(html, "0% of targeted devices have responded"));
}

TEST_CASE("executions_page_render: a confined panel prints only the redaction it was handed",
          "[ui][executions][render]") {
    ExecSelectedView v;
    v.confined = true;
    v.row = make_row("e1", "completed");
    v.scope_expression = "(redacted - confined view)";
    v.parameter_values = "(redacted - confined view)";
    const auto html = render_exec_selected(v);
    CHECK(has(html, "data-confined=\"1\""));
    CHECK(has(html, "<span>Scope (confined)</span>"));
    CHECK(count_of(html, "(redacted - confined view)") == 2);
}
