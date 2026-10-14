/**
 * test_instruction_extras_ui.cpp -- pins for the Instructions extras UI: the page
 * template still carries every control that existed before (nothing lost), the new
 * hooks the controller binds exist, and the controller itself is CSP-clean and routes
 * every destructive or fan-out action through the shared dialog.
 */

#include "instruction_extras_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

extern const char* const kInstructionPageHtml;
extern const char* const kInstructionEditorHtml;
namespace yuzu::server {
extern const std::string kYuzuOperateExtrasJs;
}

namespace ex = yuzu::server::instruction_extras;
using yuzu::server::InstructionSet;
using yuzu::server::ResponseTemplate;

namespace {
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
    // never a bare fetch.
    CHECK_FALSE(has(js, "fetch("));
    // Destructive actions confirm first.
    CHECK(has(js, "title: 'Delete instruction set'"));
    CHECK(has(js, "title: 'Delete response template'"));
    CHECK(has(js, "title: 'Dispatch instruction'"));
    // Secret parameters are write-only password inputs.
    CHECK(has(js, "var SECRET_PARAMS = { grant_secret: true, grant_id: true };"));
    CHECK(has(js, "inp.type = 'password';"));
    // A pending-approval answer never claims the instruction ran.
    CHECK(has(js, "Nothing has run yet."));
    // The preview denial is stated as a permission, not as zero matches.
    CHECK(has(js, "Previewing a scope needs the Infrastructure read permission."));
    CHECK(has(js, "Preview unavailable. This is not zero matches."));
    // Typed confirmation when the expression was not previewed.
    CHECK(has(js, "Type DISPATCH to send it."));
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

TEST_CASE("instruction extras ui: the library filter form repeats and escapes its values",
          "[ui][instruction_extras]") {
    const auto f = ex::render_library_filter_form("a\"b", "os_info", "");
    CHECK(has(f, "hx-get=\"/fragments/instructions\""));
    CHECK(has(f, "value=\"a&quot;b\""));
    CHECK_FALSE(has(f, "hx-on"));
    CHECK_FALSE(has(f, "onclick"));
}
