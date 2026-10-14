/**
 * test_operate_pages_ui.cpp — static pins for the Operate pages' templates, shared CSS and
 * embedded controller (Approvals and Executions).
 *
 * Pure string checks, no server and no store. What they guard is the part a rendering
 * unit test cannot see: CSP hygiene (no inline handlers, no dynamic-code sinks, eval
 * disabled), tokens-only CSS, MSVC's raw-literal bound, and that the page template still
 * carries every hook the controller binds (a dropped `data-f` throws in the browser).
 */

#include "operate_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <vector>

extern const char* const kApprovalsPageHtml;
extern const char* const kExecutionsPageHtml;
extern const char* const kWorkflowsPageHtml;
namespace yuzu::server {
extern const std::string kYuzuOperateJs;
} // namespace yuzu::server

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

bool has(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}

struct Page {
    const char* name;
    std::string html;
};

std::vector<Page> pages() {
    return {{"approvals", kApprovalsPageHtml},
            {"executions", kExecutionsPageHtml},
            {"workflows", kWorkflowsPageHtml}};
}

} // namespace

TEST_CASE("operate pages: no inline handlers and no hx-on and htmx eval disabled",
          "[ui][operate][pages]") {
    for (const auto& p : pages()) {
        INFO(p.name);
        CHECK(count_of(p.html, "hx-on") == 0);
        for (const char* attr : {" onclick=", " onkeydown=", " onkeyup=", " onload=", " onchange=",
                                 " oninput=", " onsubmit=", " onerror=", " onfocus="})
            CHECK_FALSE(has(p.html, attr));
        CHECK_FALSE(has(p.html, "javascript:"));
        CHECK(has(p.html, "<meta name=\"htmx-config\" content='{\"allowEval\":false}'>"));
        CHECK(count_of(p.html, "src=\"/static/yuzu-operate.js\"") == 1);
        // Sign out is hx-post, so the page must load htmx for the shell.
        CHECK(has(p.html, "src=\"/static/htmx.js\""));
        CHECK(count_of(p.html, "<!--yuzu:shell-->") == 1);
    }
}

TEST_CASE("operate pages: the shared CSS is tokens only and under the raw-literal bound",
          "[ui][operate][pages]") {
    const std::string css(yuzu::server::kOperateCss);
    static const std::regex hex(R"(#[0-9a-fA-F]{3,8}\b)");
    CHECK_FALSE(std::regex_search(css, hex));
    CHECK_FALSE(has(css, "box-shadow"));
    CHECK_FALSE(has(css, "text-transform"));
    static const std::regex literal_family(R"(font-family:\s*(?!var\())");
    CHECK_FALSE(std::regex_search(css, literal_family));
    // MSVC C2026 is 16,380 bytes; leave headroom for Executions' rules.
    CHECK(css.size() < 15000);
    CHECK(css.size() > 500);
    // Operate's own class family stays prefixed.
    CHECK(has(css, ".ops-grid"));
}

TEST_CASE("operate pages: the embedded controller is CSP-clean and bounded",
          "[ui][operate][pages]") {
    const auto& js = yuzu::server::kYuzuOperateJs;
    REQUIRE(js.size() >= 2000);
    CHECK(js.find('\0') == std::string::npos);
    // No dynamic-code or raw-markup sinks.
    for (const char* sink : {"eval(", "new Function(", "document.write", "javascript:",
                             "insertAdjacentHTML", "outerHTML", "setTimeout(\"", "setInterval(\""})
        CHECK_FALSE(has(js, sink));
    // The only innerHTML sinks are the eight server-rendered fragment hosts (the Approvals
    // list, the Executions list, the Selected execution panel, the Workflows list, the
    // Schedules list, the hidden newest-run-per-workflow store, the Latest run panel and the
    // Recent runs list); nothing else assigns markup (the workflow steps panel is filled by
    // cloning nodes, and the Last run / Result cells by cloning run-row cells). Each is
    // written from a 200 body only.
    CHECK(count_of(js, ".innerHTML") == 8);
    CHECK(count_of(js, "runsStore.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "runBody.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "recentBody.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "host.innerHTML = res.html;") == 2);
    CHECK(count_of(js, "panel.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "wfHost.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "scHost.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "stepsBody.replaceChildren(block.cloneNode(true));") == 1);
    CHECK(has(js, "if (res.status !== 200) {"));
    // Bounded fetch, built inside try/catch so an old browser degrades to no timeout.
    CHECK(has(js, "var FETCH_TIMEOUT_MS = 15000;"));
    CHECK(has(js, "try { return AbortSignal.timeout(ms); } catch (e) { return undefined; }"));
    CHECK(has(js, "var sig = timeoutSignal(FETCH_TIMEOUT_MS);"));
    // A late response never overwrites a newer one.
    CHECK(has(js, "var mine = ++seq;"));
    CHECK(has(js, "if (mine !== seq) return;"));
    CHECK(has(js, "var mine = ++lseq;"));
    CHECK(has(js, "if (mine !== lseq) return;"));
    CHECK(has(js, "var mine = ++wseq;"));
    CHECK(has(js, "if (mine !== wseq) return;"));
    CHECK(has(js, "var mine = ++sseq;"));
    CHECK(has(js, "if (mine !== sseq) return;"));
    CHECK(has(js, "var mine = ++dseq;"));
    CHECK(has(js, "if (mine !== dseq) return;"));
    CHECK(has(js, "var mine = ++rseq;"));
    CHECK(has(js, "if (mine !== rseq) return;"));
    CHECK(has(js, "var mine = ++qseq;"));
    CHECK(has(js, "if (mine !== qseq) return;"));
    // Every non-200 list answer maps to fixed copy; the body is never shown.
    CHECK(has(js, "'Could not load. Check your connection and retry.'"));
    CHECK(has(js, "'Your session has expired. Sign in again.'"));
    CHECK(has(js, "'You do not have permission to view ' + what + '.'"));
    CHECK(has(js, "the server reported a problem. Retry shortly."));
    // A 200 note has no list, so the previous list's count chip and confined-view note go.
    CHECK(has(js, "else { chip.hidden = true; confinedNote.hidden = true; }"));
}

TEST_CASE("operate pages: the Approvals template carries every hook the controller binds",
          "[ui][operate][pages]") {
    const std::string html(kApprovalsPageHtml);
    const auto& js = yuzu::server::kYuzuOperateJs;

    // Every field(detail, '<name>') the controller reads exists in the template.
    static const std::regex field_ref(R"(field\(detail, '([a-z-]+)'\))");
    std::set<std::string> wanted;
    for (std::sregex_iterator it(js.begin(), js.end(), field_ref), end; it != end; ++it)
        wanted.insert((*it)[1].str());
    CHECK(wanted.size() >= 20);
    for (const auto& name : wanted) {
        INFO("data-f=" << name);
        CHECK(has(html, "data-f=\"" + name + "\""));
    }

    // Hosts and the filter group.
    for (const char* id : {"id=\"ap-list\"", "id=\"ap-detail\"", "id=\"ap-pending\""})
        CHECK(has(html, id));
    CHECK(has(html, "<input type=\"radio\" name=\"ast\" value=\"pending\" checked>"));
    CHECK(has(html, "<input type=\"radio\" name=\"ast\" value=\"\">All"));
    for (const char* v : {"approved", "rejected", "expired"})
        CHECK(has(html, std::string("name=\"ast\" value=\"") + v + "\""));
    // The page asks the fragment contract's URL.
    CHECK(has(js, "'/fragments/approvals?view=page&status=' + encodeURIComponent(status)"));
}

TEST_CASE("operate pages: Approvals copy is exact and claims no second person",
          "[ui][operate][pages]") {
    const std::string html(kApprovalsPageHtml);
    CHECK(has(html, "<title>Yuzu — Approvals</title>"));
    CHECK(has(html, "<h1>Approvals</h1>"));
    // Four-eyes is a username comparison, not a person: the copy says so.
    CHECK(has(html, "Dispatch requests waiting for a decision by a different user account."));
    CHECK_FALSE(has(html, "second person"));
    CHECK(has(html, "You submitted this — another reviewer must approve"));
    CHECK(has(html, "Decisions are made from the Approvals tab on the Instructions page."));
    CHECK(has(html, "Pending requests are expired 7 days after submission, when the next request "
                    "is submitted; until then they stay listed."));
    CHECK(has(html, "The parameter values are not stored with this request."));
    CHECK(has(html, "The requesting agent must re-call the tool with this approval id for it to "
                    "run."));
    // Read-only: no decision control exists in the page body (the shell's own Sign out and
    // search buttons sit before the shell end marker).
    const auto body_at = html.find("<!--/yuzu:shell-->");
    REQUIRE(body_at != std::string::npos);
    const auto body = html.substr(body_at);
    CHECK_FALSE(has(body, ">Approve<"));
    CHECK_FALSE(has(body, ">Reject<"));
    CHECK_FALSE(has(body, "<button"));
    CHECK_FALSE(has(body, "<dialog"));
}

TEST_CASE("operate pages: the Executions template carries every hook the controller binds",
          "[ui][operate][pages]") {
    const std::string html(kExecutionsPageHtml);
    const auto& js = yuzu::server::kYuzuOperateJs;

    for (const char* id : {"id=\"exec-list\"", "id=\"exec-selected\"", "id=\"exec-chip\"",
                           "id=\"exec-confined\"", "id=\"f-def\"", "id=\"f-def-hint\""})
        CHECK(has(html, id));
    // Status filter: All is the checked, empty-valued default; the five states follow.
    CHECK(has(html, "<input type=\"radio\" name=\"est\" value=\"\" checked>All"));
    for (const char* v : {"running", "succeeded", "completed", "cancelled", "pending"})
        CHECK(has(html, std::string("name=\"est\" value=\"") + v + "\""));
    CHECK(has(html, "<option value=\"\">All instructions</option>"));
    // The controller asks exactly the fragment contract's URLs.
    CHECK(has(js, "'/fragments/executions?view=page'"));
    CHECK(has(js, "'/detail?view=page'"));
    CHECK(has(js, "'/api/instructions?limit=500'"));
    CHECK(has(js, "timeoutSignal(10000)"));
    // Every non-200 detail answer maps to fixed copy (the body is never shown).
    CHECK(has(js, "'This execution was not found, or part of it is outside your scope.'"));
    CHECK(has(js, "'You do not have permission to view this execution.'"));
    CHECK(has(js, "'Execution tracker degraded, retry shortly.'"));
    CHECK(has(js, "if (res.status !== 200) { panelNote(detailCopy(res.status)); return; }"));
    // No auto-select: the detail read (one audit row) happens on a click, Enter/Space or
    // an explicit ?id= only.
    CHECK(count_of(js, "showDetail(") == 3);
    CHECK(has(js, "if (wantId) showDetail(wantId);"));
    // No polling and no live stream in the read-only pages.
    CHECK_FALSE(has(js, "setInterval("));
    CHECK_FALSE(has(js, "EventSource"));
}

TEST_CASE("operate pages: Executions copy is exact and read-only", "[ui][operate][pages]") {
    const std::string html(kExecutionsPageHtml);
    CHECK(has(html, "<title>Yuzu — Executions</title>"));
    CHECK(has(html, "<h1>Executions</h1>"));
    CHECK(has(html, "Instruction dispatches and their per-device results."));
    CHECK(has(html, "Select an execution to see its scope, parameters and responses."));
    CHECK(has(html, "<b>Confined view.</b> You can see executions you dispatched and "
                    "executions that reached devices in your scope. Counts cover your devices "
                    "only; scope and parameters are redacted."));
    CHECK(has(html, "Instruction list unavailable; filter by status only."));
    const auto body_at = html.find("<!--/yuzu:shell-->");
    REQUIRE(body_at != std::string::npos);
    const auto body = html.substr(body_at);
    CHECK_FALSE(has(body, "<button"));
    CHECK_FALSE(has(body, "<dialog"));
    CHECK_FALSE(has(body, ">Cancel execution"));
    CHECK_FALSE(has(body, ">Re-run"));
}

TEST_CASE("operate pages: the Workflows template carries every hook the controller binds",
          "[ui][operate][pages]") {
    const std::string html(kWorkflowsPageHtml);
    const auto& js = yuzu::server::kYuzuOperateJs;

    for (const char* id : {"id=\"wf-list\"", "id=\"sc-list\"", "id=\"wf-steps\"",
                           "id=\"wf-steps-title\"", "id=\"wf-steps-body\"",
                           "id=\"wf-runs-store\"", "id=\"wf-run-body\"", "id=\"wf-recent-det\"",
                           "id=\"wf-recent-body\""})
        CHECK(has(html, id));
    CHECK(has(html, "<body data-page=\"workflows\">"));
    // Runs: the exact fragment contract's URLs, the id always percent-encoded.
    CHECK(has(js, "'/fragments/workflow-runs?latest_per_workflow=true&limit=500'"));
    CHECK(has(js, "'/fragments/workflow-runs/' + encodeURIComponent(id)"));
    CHECK(has(js, "'/fragments/workflow-runs?limit=10&workflow_id=' + encodeURIComponent(selectedId)"));
    // Run rows are matched by attribute value, never interpolated into a selector.
    CHECK(has(js, "r.getAttribute('data-workflow-id') === wid"));
    CHECK(has(js, "if ($('.ops-list', runsStore)) loadRuns();"));
    // The controller asks exactly the fragment contract's URLs.
    CHECK(has(js, "'/fragments/workflows'"));
    CHECK(has(js, "'/fragments/schedules?view=page'"));
    CHECK(has(js, "workflows: workflowsController"));
    // A selection is a clone of the hidden step store, compared by attribute, never by selector.
    CHECK(has(js, "b.getAttribute('data-steps-for') === id"));
    // A denied panel is not polled on return: each refresh would be a denial audit row.
    CHECK(has(js, "if ($('.ops-list', wfHost)) loadWorkflows();"));
    CHECK(has(js, "if ($('.ops-list', scHost)) loadSchedules();"));
    CHECK_FALSE(has(js, "setInterval("));
}

TEST_CASE("operate pages: Workflows copy is exact and read-only", "[ui][operate][pages]") {
    const std::string html(kWorkflowsPageHtml);
    CHECK(has(html, "<title>Yuzu — Workflows</title>"));
    CHECK(has(html, "<h1>Workflows</h1>"));
    // Schedules do not start workflows: the subtitle must not say they do.
    CHECK(has(html, "Multi-step workflows and their runs. Schedules below run a single "
                    "instruction on a repeat."));
    CHECK(has(html, "Select a workflow to see its steps."));
    const auto body_at = html.find("<!--/yuzu:shell-->");
    REQUIRE(body_at != std::string::npos);
    const auto body = html.substr(body_at);
    CHECK_FALSE(has(body, "<button"));
    CHECK_FALSE(has(body, "<dialog"));
    // Nothing the code cannot do is drawn.
    for (const char* never : {"Run now", "New workflow", "Second Tuesday", "2 failed", "Wait "})
        CHECK_FALSE(has(body, never));
}
