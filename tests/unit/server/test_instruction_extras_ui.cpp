/**
 * test_instruction_extras_ui.cpp -- pins for the Instructions extras UI: the page
 * template still carries every control that existed before (nothing lost), the new
 * hooks the controller binds exist, and the controller itself is CSP-clean and routes
 * every destructive or fan-out action through the shared dialog.
 */

#include "instruction_definition_model.hpp"
#include "instruction_extras_render.hpp"
#include "sensitive_instruction_params.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

extern const char* const kInstructionPageHtml;
extern const char* const kInstructionEditorHtml;
namespace yuzu::server {
extern const std::string kYuzuOperateExtrasJs;
}

namespace ex = yuzu::server::instruction_extras;
using yuzu::server::InstructionDefinition;
using yuzu::server::InstructionSet;
using yuzu::server::ResponseTemplate;

namespace {
std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string_view::npos; at = hay.find(needle, at + needle.size()))
        ++n;
    return n;
}
bool has(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}
} // namespace

TEST_CASE("instruction extras ui: nothing the page had before is lost",
          "[ui][instruction_extras]") {
    const std::string page(kInstructionPageHtml);
    // Tabs and their hosts.
    for (const char* s : {"showTab('definitions',this)", "showTab('executions',this)",
                          "showTab('schedules',this)", "showTab('approvals',this)",
                          "id=\"tab-definitions\"", "id=\"tab-executions\"",
                          "hx-get=\"/fragments/schedules\"", "hx-get=\"/fragments/approvals\"",
                          "id=\"editor-host\""})
        CHECK(has(page, s));
    // The Execute form: definition select, parameters, scope, history and the legacy handler.
    for (const char* s : {"id=\"exec-def-select\"", "id=\"exec-params-fields\"", "id=\"exec-scope\"",
                          "id=\"exec-btn\"", "onclick=\"executeInstruction()\"", "id=\"exec-result\"",
                          "hx-get=\"/fragments/executions\"", "function executeInstruction()",
                          "function loadExecAgents()", "function onDefSelected("})
        CHECK(has(page, s));
    // SSE results and the EventSource lifecycle.
    CHECK(has(page, "new EventSource("));
    // Editor: Form tab, YAML tab, preview and validate.
    const std::string editor(kInstructionEditorHtml);
    for (const char* s : {"id=\"form-mode\"", "id=\"yaml-mode\"", "id=\"yaml-editor\"",
                          "id=\"yaml-preview\"", "id=\"yaml-errors\""})
        CHECK(has(editor, s));
}

TEST_CASE("instruction extras ui: the legacy inline dispatcher refuses to run without the module",
          "[ui][instruction_extras]") {
    // If yuzu-operate-extras.js (the only place the confirmation dialog lives) fails to load,
    // the inline executeInstruction() would be a one-click dispatch to the whole scope.
    const std::string page(kInstructionPageHtml);
    const auto fn = page.find("function executeInstruction()");
    REQUIRE(fn != std::string::npos);
    const auto guard = page.find("window.__yuzuExtrasReady", fn);
    const auto first_fetch = page.find("fetch('/api/instructions/'", fn);
    REQUIRE(guard != std::string::npos);
    REQUIRE(first_fetch != std::string::npos);
    CHECK(guard < first_fetch); // refused BEFORE any request is built or sent
}

TEST_CASE("instruction definition detail: secret_params comes from the shared list, and the "
          "export omits it",
          "[ui][instruction_extras][model]") {
    InstructionDefinition d;
    d.id = "x";
    const auto detail = yuzu::server::instruction_definition_detail_json(d);
    REQUIRE(detail.contains("secret_params"));
    REQUIRE(detail["secret_params"].is_array());
    std::vector<std::string> got;
    for (const auto& k : detail["secret_params"])
        got.push_back(k.get<std::string>());
    std::vector<std::string> want;
    for (auto k : yuzu::server::kRedactedInstructionParamKeys)
        want.emplace_back(k);
    CHECK(got == want);
    CHECK_FALSE(yuzu::server::instruction_definition_export_json(d).contains("secret_params"));
}

TEST_CASE("instruction extras ui: the page loads the dialog before the controller and hooks it",
          "[ui][instruction_extras]") {
    const std::string page(kInstructionPageHtml);
    const auto dlg = page.find("src=\"/static/yuzu-dialog.js\" defer");
    const auto ext = page.find("src=\"/static/yuzu-operate-extras.js\" defer");
    REQUIRE(dlg != std::string::npos);
    REQUIRE(ext != std::string::npos);
    CHECK(dlg < ext);
    CHECK(has(page, "<body data-page=\"instructions\">"));
    for (const char* s : {"id=\"ox-target-mode\"", "id=\"ox-expr\"", "id=\"ox-expr-note\"",
                          "data-ox=\"expr-validate\"", "data-ox=\"expr-preview\""})
        CHECK(has(page, s));
    // New markup adds no hx-on and no new inline handler.
    CHECK_FALSE(has(page, "hx-on"));
    const auto from = page.find("id=\"ox-target-mode\"");
    const auto to = page.find("id=\"ox-expr-note\"");
    REQUIRE(from < to);
    const auto block = page.substr(from, to - from);
    CHECK_FALSE(has(block, "onclick="));
    CHECK_FALSE(has(block, "onchange="));
}

TEST_CASE("instruction extras ui: the controller is CSP-clean and gates every write behind a dialog",
          "[ui][instruction_extras]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    REQUIRE(js.size() > 2000);
    CHECK(js.find('\0') == std::string::npos);
    for (const char* sink : {"eval(", "new Function(", "document.write", "javascript:",
                             "insertAdjacentHTML", "outerHTML", ".innerHTML", "setTimeout(\"",
                             "setInterval(\""})
        CHECK_FALSE(has(js, sink));
    // Every mutating call goes through the shared request helper (bounded, step-up aware),
    // never a bare fetch. The one exception in the file is the Result sets controller's read of
    // the producers fragment (HTML, which the JSON helper cannot carry); it is allowed by its
    // exact text only, and no other fetch call may exist.
    {
        std::string without_producers_read = js;
        const std::string producers_read = "window.fetch('/fragments/result-sets/producers', init)";
        const auto at = without_producers_read.find(producers_read);
        REQUIRE(at != std::string::npos);
        without_producers_read.erase(at, producers_read.size());
        CHECK_FALSE(has(without_producers_read, "fetch("));
    }
    // Destructive actions confirm first.
    CHECK(has(js, "title: 'Delete instruction set'"));
    CHECK(has(js, "title: 'Delete response template'"));
    CHECK(has(js, "title: 'Dispatch instruction'"));
    // Secret parameters are write-only password inputs.
    // ... classified by the server's shared list, never a copy in the page script.
    CHECK_FALSE(has(js, "grant_secret"));
    CHECK(has(js, "d.secret_params"));
    // Execute is held until the detail loads, and the dispatch confirmation refuses without it.
    CHECK(has(js, "if (btn) btn.disabled = true;"));
    CHECK(has(js, "The instruction details have not loaded yet."));
    CHECK(has(js, "window.__yuzuExtrasReady = true;"));
    CHECK(has(js, "inp.type = 'password';"));
    // A pending-approval answer never claims the instruction ran.
    CHECK(has(js, "Nothing has run yet."));
    // The preview denial is stated as a permission, not as zero matches.
    CHECK(has(js, "Previewing a scope needs the Infrastructure read permission."));
    CHECK(has(js, "Preview unavailable. This is not zero matches."));
    // Typed confirmation when the expression was not previewed.
    CHECK(has(js, "Type DISPATCH to send it."));
}

TEST_CASE("instruction extras ui: the Approvals tab buttons surface a 401/403 instead of dropping it (#6061)",
          "[ui][instruction_extras][approvals_fragment_routes]") {
    const auto& whole = yuzu::server::kYuzuOperateExtrasJs;
    // The file holds two IIFEs. Only the first boots on the Instructions page (it returns at
    // the `page !== 'instructions'` guard); the second boots the dashboard and Result sets
    // controllers only. The listener must sit inside the first, or it never attaches here.
    const auto guard = whole.find("if (page !== 'instructions' || !D) return;");
    const auto second = whole.find("/* Dashboard and Result sets controllers");
    REQUIRE(guard != std::string::npos);
    REQUIRE(second != std::string::npos);
    REQUIRE(guard < second);
    const std::string js = whole.substr(guard, second - guard);
    // The listener is registered exactly once in the file, and in that first IIFE.
    CHECK(count_of(whole, "#6061: the Approvals tab's") == 1);
    CHECK(count_of(js, "#6061: the Approvals tab's") == 1);
    CHECK(has(js, "doc.body.addEventListener('htmx:responseError'"));
    // The tab's buttons are hx-swap="none" POSTs and htmx drops a 4xx body, so the controller
    // listens for the error, scoped to the two decide routes.
    CHECK(has(js, R"(/^\/api\/approvals\/[^\/]+\/(approve|reject)$/)"));
    CHECK(has(js, "x.status !== 401 && x.status !== 403"));
    // A step-up 401 reuses the dialog helper's code prompt and replay.
    CHECK(has(js, "mfa_step_up_required === true"));
    CHECK(has(js, "D.request('POST', path, { json: {} })"));
    CHECK(has(js, "new CustomEvent('refreshApprovals')"));
    // Same wording as the Approvals page.
    CHECK(has(js, "You do not have permission to decide approvals."));
    CHECK(has(js, "Your session expired; sign in again."));
    CHECK_FALSE(has(js, "hx-on"));
}

TEST_CASE("instruction extras ui: both 403 branches of the Approvals tab show an approver refusal's remediation (#6079)",
          "[ui][instruction_extras][approvals_fragment_routes]") {
    const auto& whole = yuzu::server::kYuzuOperateExtrasJs;
    // Same scope trap as the #6061 case above: the edit must sit in the FIRST IIFE, which is
    // the only one that boots on the Instructions page.
    const auto guard = whole.find("if (page !== 'instructions' || !D) return;");
    const auto second = whole.find("/* Dashboard and Result sets controllers");
    REQUIRE(guard != std::string::npos);
    REQUIRE(second != std::string::npos);
    REQUIRE(guard < second);
    const std::string js = whole.substr(guard, second - guard);
    // The helper is defined once in the first IIFE, guarded on the message prefix AND a string
    // remediation, so any other 403 keeps its own message.
    CHECK(count_of(whole, "function approverRefusalText(env)") == 1);
    CHECK(count_of(js, "function approverRefusalText(env)") == 1);
    CHECK(has(js, "e.message.indexOf('approver_assurance_required:') === 0"));
    CHECK(has(js, "typeof e.remediation === 'string' && e.remediation"));
    // Initial 403 and the 403 returned after the step-up retry: both use it, each reading its
    // own envelope (the parsed response text, then the dialog helper's r.data).
    CHECK(has(js, "toast(approverRefusalText(env) || msg || 'You do not have permission to decide approvals.', 'error');"));
    CHECK(has(js, "toast(approverRefusalText(r.data) || r.message || 'You do not have permission to decide approvals.', 'error');"));
    CHECK(count_of(js, "approverRefusalText(") == 3); // definition + the two call sites
}

TEST_CASE("instruction extras ui: sets panel and set select stamp controls only when allowed",
          "[ui][instruction_extras]") {
    InstructionSet a;
    a.id = "set-1";
    a.name = "Ops <script>";
    std::vector<ex::SetRow> rows{{a, 3}};

    const auto ro = ex::render_instruction_sets_panel(rows, false);
    CHECK_FALSE(has(ro, "data-ox="));
    CHECK(has(ro, "Ops &lt;script&gt;"));

    const auto rw = ex::render_instruction_sets_panel(rows, false, true, true);
    CHECK(has(rw, "data-ox=\"set-new\""));
    CHECK(has(rw, "data-ox=\"set-delete\""));
    CHECK(has(rw, "data-set-members=\"3\""));
    CHECK_FALSE(has(rw, "<script>"));

    const auto only_new = ex::render_instruction_sets_panel(rows, false, true, false);
    CHECK(has(only_new, "data-ox=\"set-new\""));
    CHECK_FALSE(has(only_new, "data-ox=\"set-delete\""));

    // A set id that no longer lists stays visible instead of reading as unassigned.
    const auto sel = ex::render_set_select("def\"x", "gone-set-id", {a});
    CHECK(has(sel, "data-def-id=\"def&quot;x\""));
    CHECK(has(sel, "value=\"gone-set-id\" selected"));
    const auto unassigned = ex::render_set_select("d", "", {a});
    CHECK(has(unassigned, "<option value=\"\" selected>"));
}

TEST_CASE("instruction extras ui: templates panel names the built-in default and escapes",
          "[ui][instruction_extras]") {
    ResponseTemplate t;
    t.id = "aa11";
    t.name = "Brief \"view\"";
    t.columns = {"a"};
    t.sort_column = "a";
    t.sort_dir = "desc";
    const auto ro = ex::render_templates_panel("def1", "Disk <usage>", {t}, false);
    CHECK(has(ro, "Default (built in)"));
    CHECK(has(ro, "Disk &lt;usage&gt;"));
    CHECK_FALSE(has(ro, "data-ox="));
    const auto rw = ex::render_templates_panel("def1", "Disk", {t}, true);
    CHECK(has(rw, "data-ox=\"tpl-new\""));
    CHECK(has(rw, "data-ox=\"tpl-edit\""));
    CHECK(has(rw, "data-ox=\"tpl-delete\""));
    // The edit payload is an attribute-escaped JSON object.
    CHECK(has(rw, "data-tpl=\"{&quot;columns&quot;"));
    CHECK(has(rw, "data-tpl-name=\"Brief &quot;view&quot;\""));
}

TEST_CASE("instruction extras ui: templates panel has a heading naming the definition and a Close",
          "[ui][instruction_extras]") {
    for (const bool can_write : {false, true}) {
        const auto h = ex::render_templates_panel("def1", "Disk <usage>", {}, can_write);
        CHECK(has(h, "<h2>Response templates: Disk &lt;usage&gt;</h2>"));
        // Close empties the host; plain inline handler, no hx-on, and no data-ox hook (a
        // read-only panel carries none).
        CHECK(has(h, "aria-label=\"Close response templates\""));
        CHECK(has(h, "getElementById('ox-templates').replaceChildren()\""));
        CHECK_FALSE(has(h, "hx-on"));
    }
    // Every state of the panel sits inset inside the library panel that hosts it.
    for (const auto& h : {ex::render_templates_denied(), ex::render_templates_degraded(),
                          ex::render_templates_not_found()})
        CHECK(has(h, "style=\"margin:12px 16px\" data-panel=\"response-templates\""));
}

TEST_CASE("instruction extras ui: the library filter form repeats and escapes its values",
          "[ui][instruction_extras]") {
    const auto f = ex::render_library_filter_form("a\"b", "os_info", "");
    CHECK(has(f, "hx-get=\"/fragments/instructions\""));
    CHECK(has(f, "value=\"a&quot;b\""));
    CHECK_FALSE(has(f, "hx-on"));
    CHECK_FALSE(has(f, "onclick"));
}
