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
extern const std::string kYuzuDialogJs;
extern const std::string kYuzuCss;
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
        // The dialog module loads first (deferred scripts run in order); toasts are polite.
        // Every Operate page carries both: Workflows has actions now.
        const auto dlg = p.html.find("src=\"/static/yuzu-dialog.js\" defer");
        REQUIRE(dlg != std::string::npos);
        CHECK(dlg < p.html.find("src=\"/static/yuzu-operate.js\""));
        CHECK(count_of(p.html, "id=\"toasts\" aria-live=\"polite\"") == 1);
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
    // The only innerHTML sinks are the seven server-rendered fragment hosts (the Approvals
    // list, the Executions list, the Workflows list, the Schedules list, the hidden
    // newest-run-per-workflow store, the Latest run panel and the Recent runs list); nothing
    // else assigns markup. The Selected and Device results panels take parsed [data-slot]
    // nodes through DOMParser + replaceChildren, the workflow steps panel is filled by
    // cloning nodes, and the Last run / Result cells by cloning run-row cells. Each is
    // written from a 200 body only.
    CHECK(count_of(js, ".innerHTML") == 7);
    CHECK(count_of(js, "runsStore.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "runBody.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "recentBody.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "host.innerHTML = res.html;") == 2);
    CHECK(count_of(js, "wfHost.innerHTML = res.html;") == 1);
    CHECK(count_of(js, "scHost.innerHTML = res.html;") == 1);
    CHECK(has(js, "new DOMParser().parseFromString(html, 'text/html')"));
    CHECK(has(js, "applySlots(res.html);"));
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
    CHECK_FALSE(has(html, "Decisions are made from the Approvals tab"));
    CHECK(has(html, "Pending requests are expired 7 days after submission, when the next request "
                    "is submitted; until then they stay listed."));
    CHECK(has(html, "The parameter values are not stored with this request."));
    CHECK(has(html, "The requesting agent must re-call the tool with this approval id for it to "
                    "run."));
    // Decisions: one Approve and one Reject button, both inside a hidden container the
    // controller reveals only for a pending, not-own row under data-can-decide="1".
    const auto body_at = html.find("<!--/yuzu:shell-->");
    REQUIRE(body_at != std::string::npos);
    const auto body = html.substr(body_at);
    CHECK(count_of(body, "data-act=\"approve\"") == 1);
    CHECK(count_of(body, "data-act=\"reject\"") == 1);
    CHECK(has(body, "<div class=\"btns\" data-f=\"actions\" hidden>\n<button type=\"button\" "
                    "class=\"btn btn-primary\" data-act=\"approve\">Approve</button>"));
    CHECK_FALSE(has(body, "<dialog"));
    const auto& js = yuzu::server::kYuzuOperateJs;
    CHECK(has(js, "'yuzu:approvals-changed'"));
    CHECK(has(js, "'/' + kind"));
    CHECK(has(js, "maxlength: 1000"));
    CHECK(has(js, "list.getAttribute('data-can-decide') === '1'"));
    // An excluded reviewer (#6062) keeps the decision container (the store lets an excluded
    // root REJECT) and loses only the Approve button; the submitter loses both.
    CHECK(has(js, "field(detail, 'actions').hidden = !(pending && !mine && canDecide);"));
    CHECK(has(js, "field(detail, 'excluded').hidden = !(pending && !mine && excluded && canDecide);"));
    CHECK(has(js, "d.excluded === '1'"));
    CHECK(has(js, "approveBtn.hidden = excluded || d.unreadable === '1';"));
    CHECK_FALSE(has(js, "!(pending && !mine && !excluded && canDecide)"));
    // The dialog copy does not claim the reviewer saw everything when the summary was cut.
    CHECK(has(js, "d.request && d.shortened === '1' ?"));
    CHECK(has(js, "The summary above is shortened and is for orientation only; it does not show the "));
    CHECK(has(js, "The summary above is for orientation. What you approve is the whole request as "));
    // The Approve POST carries only a comment and matches id + pending status, so no copy may
    // promise that the request cannot change after the decision (digest-pinned Approve is a
    // PR3 entry condition in ADR-1009).
    // The wording that remains is pinned too (both branches end the same way).
    CHECK(has(js, "the whole request as stored under the digest ' +\n          'shown.' :"));
    CHECK(has(js, "'stored under the digest shown.' :"));
    CHECK_FALSE(has(js, "cannot change after your decision"));
    CHECK_FALSE(has(js, "frozen under the digest"));
    CHECK_FALSE(has(js, "it is frozen on the request"));
    // Never claims the summary IS the whole effect.
    CHECK_FALSE(has(js, "exactly the effect shown"));
    // An unreadable request hides Approve only (#6062): Reject stays so the row can be cleared.
    CHECK(has(js, "var approveBtn = $('button[data-act=\"approve\"]', detail);"));
    // A bound ticket's frozen request fills the detail panel and the decision dialog as
    // text (#6062): a hidden row revealed by the controller, written with textContent.
    CHECK(has(body, "data-f=\"request-row\" hidden"));
    CHECK(has(body, "data-f=\"request\""));
    CHECK(has(body, "data-f=\"excluded\" hidden"));
    CHECK(has(body, "You are excluded from approving this request. You can still reject it."));
    CHECK(has(js, "requestEl.textContent = request;"));
    CHECK(has(js, "factRow('Requested effect', d.request, true)"));
    // The dialog shows the whole frozen request, not a 5em scroll box (#6062).
    CHECK(has(js, "reqRow.lastChild.className = 'req';"));
    CHECK(has(std::string(yuzu::server::kOperateCss), ".dlg-facts code.req{max-height:50vh;white-space:pre-wrap;text-align:left}"));
    CHECK_FALSE(has(js, "onclick"));
}

TEST_CASE("operate pages: the Approvals dialog shows an approver refusal's remediation (#6079)",
          "[ui][operate][pages]") {
    const auto& js = yuzu::server::kYuzuOperateJs;
    // The helper is guarded on BOTH the message prefix and a string remediation, and the one
    // use is the 403 branch of the decide dialog; its error text is a textContent sink.
    CHECK(count_of(js, "function approverRefusalText(env)") == 1);
    CHECK(has(js, "e.message.indexOf('approver_assurance_required:') === 0"));
    CHECK(has(js, "typeof e.remediation === 'string' && e.remediation) return e.remediation;\n      return '';"));
    CHECK(has(js, "if (r.status === 403) return approverRefusalText(r.data) ||"));
    // The text reaches the page through textContent only (the toast sink the comment relies on).
    CHECK(has(js, "t.textContent = msg;"));
    CHECK(has(js, "'You do not have permission to decide approvals.'"));
}

TEST_CASE("operate pages: the Executions template carries every hook the controller binds",
          "[ui][operate][pages]") {
    const std::string html(kExecutionsPageHtml);
    const auto& js = yuzu::server::kYuzuOperateJs;

    for (const char* id : {"id=\"exec-list\"", "id=\"exec-selected\"", "id=\"exec-devices\"",
                           "id=\"exec-chip\"", "id=\"exec-stats\"",
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
    CHECK(count_of(js, "showDetail(") == 5); // definition, click, deep link, live refresh, post-cancel
    CHECK(has(js, "if (wantId) showDetail(wantId);"));
    // No polling. Live updates: exactly one EventSource, on the page's own detail stream,
    // started only from a fresh detail response that says running|pending.
    CHECK_FALSE(has(js, "setInterval("));
    CHECK(count_of(js, "new EventSource(") == 1);
    CHECK(has(js, "'/sse/executions/' + encodeURIComponent(id)"));
    CHECK(has(js, "var MIN_GAP_MS = 3000;"));
    CHECK(has(js, "var LARGE_GAP_MS = 15000;"));
    CHECK(has(js, "gapMs = targeted > 2000 ? LARGE_GAP_MS : MIN_GAP_MS;"));
    CHECK(has(js, "var running = status === 'running' || status === 'pending';"));
    CHECK(has(js, "} else if (running) {"));
    CHECK(has(js, "mine.readyState === 2"));
    CHECK(has(js, "window.addEventListener('pagehide', stopLive);"));
    // Completion closes the stream and reads once; the stream close never clears the timer
    // it is about to set (refreshNow owns that).
    CHECK(has(js, "closeStream();\n        setChip('');\n        refreshNow();"));
    CHECK(has(js, "Live updates unavailable."));
    // A live transition re-stamps the server's own pill vocabulary; `status-badge` has no
    // CSS on this page and would strip the pill's tone and shape.
    CHECK(has(js, "badge.className = 'pill ' + TONES[dom] + ' per-agent-status';"));
    CHECK_FALSE(has(js, "status-badge"));
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
    // The page itself carries no controls or dialogs: Cancel is rendered per selection by the
    // detail fragment and the dialog is built by yuzu-dialog.js.
    CHECK_FALSE(has(body, "<button"));
    CHECK_FALSE(has(body, "<dialog"));
    CHECK_FALSE(has(body, ">Cancel execution"));
    CHECK_FALSE(has(body, ">Re-run"));
    const std::string js(yuzu::server::kYuzuOperateJs);
    CHECK(has(js, "button[data-act=\"cancel\"]"));
    CHECK(has(js, "var url = '/api/executions/' + encodeURIComponent(id) + '/cancel';"));
    CHECK(has(js, "if (r.status === 409) return r.message ||"));
    CHECK(has(js, "sel.getAttribute('data-can-cancel') === '0'"));
}

// -- Shared dialog module (static/yuzu-dialog.js + the Dialog block of yuzu.css) ---------

TEST_CASE("dialog module: bundle shape, CSP-clean, bounded request",
          "[ui][operate][dialog]") {
    const auto& js = yuzu::server::kYuzuDialogJs;
    REQUIRE(js.size() >= 4000);
    CHECK(js.find('\0') == std::string::npos);
    CHECK(has(js, "window.YuzuDialog = { confirm: confirm, form: form, request: request };"));
    CHECK(has(js, "showModal()"));
    // No markup or dynamic-code sink of any kind: every string is textContent.
    for (const char* sink : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function(",
                             "document.write", "javascript:", "setTimeout(\"", "setInterval(\""})
        CHECK_FALSE(has(js, sink));
    // Bounded fetch, built inside try/catch so an old browser degrades to no timeout.
    CHECK(has(js, "try { init.signal = AbortSignal.timeout(prep.timeoutMs); } catch (e)"));
    CHECK(has(js, "? ms : 15000;"));  // the default stays 15 s
    CHECK(has(js, "credentials: 'same-origin', cache: 'no-store'"));
    // One dialog at a time.
    CHECK(has(js, "Promise.reject(new Error('dialog busy'))"));
}

TEST_CASE("dialog module: request maps both error shapes and the step-up contract",
          "[ui][operate][dialog]") {
    const auto& js = yuzu::server::kYuzuDialogJs;
    // {"error":"<string>"} (approvals routes) and {"error":{"message":"..."}} (A4 envelope).
    CHECK(has(js, "typeof data.error === 'string'"));
    CHECK(has(js, "typeof data.error.message === 'string'"));
    // Only the TOTP/recovery-code challenge is prompted for; anything else goes to sign-in.
    CHECK(has(js, "meta.mfa_step_up_required === true"));
    CHECK(has(js, "challenge !== '/login/mfa/stepup'"));
    CHECK(has(js, "location.assign('/login')"));
    // A network failure or timeout never throws and never claims nothing changed.
    CHECK(has(js, "The request may not have applied."));
    // Secrets are cleared on error and on close.
    CHECK(has(js, "cleaners.push(function () { input.value = ''; });"));
}

TEST_CASE("dialog module: the CSS block is tokens-only and styles the module's own slots",
          "[ui][operate][dialog]") {
    const auto& css = yuzu::server::kYuzuCss;
    const auto at = css.find("/* ===== Dialog (shared:");
    REQUIRE(at != std::string::npos);
    const auto end = css.find("\n\n", at);
    const std::string block = css.substr(at, end == std::string::npos ? std::string::npos : end - at);
    static const std::regex hex(R"(#[0-9a-fA-F]{3,8}\b)");
    CHECK_FALSE(std::regex_search(block, hex));
    for (const char* sel : {"dialog.dlg {", "dialog.dlg::backdrop", ".dlg > h2", ".dlg > .b ",
                            ".dlg .err", ".dlg > .f"})
        CHECK(has(block, sel));
    // The module builds exactly the slots the CSS names.
    const auto& js = yuzu::server::kYuzuDialogJs;
    for (const char* cls : {"el('dialog', 'dlg')", "el('div', 'b')", "el('div', 'f')", "el('p', 'err')"})
        CHECK(has(js, cls));
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
    // A run detail still in flight must not land on a newly selected workflow: selecting (or
    // losing the selection) invalidates the detail token before the new panel is resolved.
    // A cut-off latest-per-workflow list never reads as "Not run".
    CHECK(has(js, "(cut ? 'Unknown'"));
    CHECK(has(js, "dseq++; // a detail still in flight belongs to the workflow just left"));
    CHECK(has(js, "if (!block) { dseq++; selectedId = ''; markSelected(); return false; }"));
}

TEST_CASE("operate pages: Workflows copy is exact and the action hooks are in the template",
          "[ui][operate][pages]") {
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
    // The page offers New workflow and Delete as hidden buttons the controller reveals from
    // the probed hints; Run now is a per-row button rendered with the definitions fragment.
    CHECK(has(body, "id=\"wf-new\" hidden>New workflow</button>"));
    CHECK(has(body, "id=\"wf-del\" hidden>Delete</button>"));
    CHECK(has(body, "id=\"sc-new\" hidden>New schedule</button>"));
    CHECK_FALSE(has(body, "Run now"));
    // The dialog module loads before the controller.
    const auto dlg = body.find("/static/yuzu-dialog.js");
    const auto ctl = body.find("/static/yuzu-operate.js");
    REQUIRE(dlg != std::string::npos);
    REQUIRE(ctl != std::string::npos);
    CHECK(dlg < ctl);
    CHECK_FALSE(has(body, "<dialog"));
    // Nothing the code cannot do is drawn.
    for (const char* never : {"Second Tuesday", "2 failed", "Wait "})
        CHECK_FALSE(has(body, never));
}

TEST_CASE("operate pages: the Workflows action controller keeps its guards",
          "[ui][operate][pages]") {
    const auto& js = yuzu::server::kYuzuOperateJs;
    // Run: a bare-array device list (and the object shape), 200 shown / 500 selected, the
    // textarea fallback ids validated client side, its own 8 s request, a bounded 5 s poll.
    CHECK(has(js, "Array.isArray(data) ? data : (data && Array.isArray(data.agents)"));
    CHECK(has(js, "var AGENT_SHOW_MAX = 200;"));
    CHECK(has(js, "var AGENT_SELECT_MAX = 500;"));
    CHECK(has(js, "var AGENT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;"));
    CHECK(has(js, "var RUN_POST_TIMEOUT_MS = 8000;"));
    CHECK(has(js, "var RUN_POLL_MS = 5000;"));
    CHECK(has(js, "var RUN_POLL_MAX_MS = 600000;"));
    CHECK(has(js, "timeoutSignal(RUN_POST_TIMEOUT_MS)"));
    CHECK(has(js, "if (Date.now() - started > RUN_POLL_MAX_MS) {"));
    CHECK(has(js, "if (r.status === 403) { showFallback("));
    // The Run control is disabled while its run is watched, and that state is re-applied after
    // every render; a second Run is also refused in the handler itself.
    CHECK(has(js, "setReason(b, can('run') && !watched, watched"));
    CHECK(has(js, "if (!window.YuzuDialog || polling[id] || !can('run')) return;"));
    CHECK(has(js, "if (polling[id]) return;"));
    // The copy never claims the run was stopped or that it finished when it may still run.
    CHECK(has(js, "The run may keep running on the server."));
    CHECK_FALSE(has(js, "keeps running on the server"));
    // A key on the row's own button is the button's, not a row selection.
    CHECK(has(js, "if (e.target && e.target.tagName === 'BUTTON') return;"));
    // New workflow posts the YAML as JSON; delete is the id-only DELETE; neither is retried.
    CHECK(has(js, "'/api/workflows', { json: { yaml_source: v.yaml } }"));
    CHECK(has(js, "YuzuDialog.request('DELETE', '/api/workflows/' + encodeURIComponent(id))"));
    CHECK(has(js, "'/api/workflows/' + encodeURIComponent(id) + '/execute'"));
    // Every control is a render hint: the server routes stay the gate.
    CHECK(has(js, "'data-can-' + name"));
    CHECK_FALSE(has(js, "setInterval("));
}

TEST_CASE("operate pages: the schedule action controller keeps its guards",
          "[ui][operate][pages]") {
    const auto& js = yuzu::server::kYuzuOperateJs;
    // Enable arms a schedule that runs unattended: a confirm that says so, Disable is one click.
    CHECK(has(js, "if (!want) { setScheduleEnabled(id, false); return; }"));
    CHECK(has(js, "and runs without anyone present."));
    // The routes answer 200 when the owner scope changed nothing: the stored state is re-read.
    CHECK(has(js, "row.getAttribute('data-enabled') === '1'"));
    CHECK(has(js, "The schedule was not changed. Only its creator can enable or disable it."));
    CHECK(has(js, "r.data.deleted === false"));
    // New schedule: empty targets need the explicit All devices acknowledgement, the instruction
    // list needs its own grant, and a mandatory summary (with approval mode) comes last.
    CHECK(has(js, "if (!v.scope_expression.trim() && v.all_ack !== 'yes')"));
    CHECK(has(js, "'/api/instructions?enabled_only=1&limit=500'"));
    CHECK(has(js, "Choosing an instruction needs the InstructionDefinition:Read permission."));
    CHECK(has(js, "'Instruction approval mode: ' + mode"));
    CHECK(has(js, "at the next scheduler tick (about now)"));
    CHECK(has(js, "can still be refused when it '"));
    CHECK(has(js, "one-time credentials"));
    CHECK(has(js, "title: 'Create this schedule?'"));
    CHECK(has(js, "'/api/schedules', { json: body }"));
}
