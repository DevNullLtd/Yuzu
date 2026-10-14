/**
 * test_operate_extras_ui.cpp — pins for the Operate extras page assets: the
 * shared ox- CSS chunk, the Dashboard markup that hosts the scope helper and
 * the TAR history form, and the embedded controller script.
 *
 * Pure string checks over compiled-in assets (no store, no process, no clock).
 */

#include <catch2/catch_test_macros.hpp>

#include "operate_extras_ui.hpp"
#include "sensitive_instruction_params.hpp"
#include "result_sets_ui.hpp"

#include <cstring>
#include <regex>
#include <string>

extern const char* const kDashboardIndexHtml;
extern const char* const kTarPageHtml;

namespace yuzu::server {
extern const std::string kYuzuOperateExtrasJs;
}

namespace {

bool has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// The ox- helper panel's markup, cut out of the baked Dashboard page.
std::string scope_panel_markup() {
    const std::string page = kDashboardIndexHtml;
    const auto a = page.find("id=\"ox-scope\"");
    const auto b = page.find("class=\"scope-panel\"", a);
    REQUIRE(a != std::string::npos);
    REQUIRE(b != std::string::npos);
    return page.substr(a, b - a);
}

} // namespace

TEST_CASE("operate extras: the shared CSS chunk stays under the MSVC literal ceiling",
          "[ui][operate_extras]") {
    // C2026 is 16,380 bytes; rawcheck.py holds the working ceiling at 16,000.
    CHECK(std::strlen(YUZU_OX_CSS) < 15000);
    // Tokens only: no hex colour literal.
    CHECK_FALSE(std::regex_search(std::string(YUZU_OX_CSS),
                                  std::regex("#[0-9a-fA-F]{3,8}\\b")));
}

TEST_CASE("operate extras: the Dashboard page hosts the controller and the scope helper",
          "[ui][operate_extras]") {
    const std::string page = kDashboardIndexHtml;
    CHECK(has(page, "<body data-page=\"dashboard\" data-secret-params=\""));
    CHECK(has(page, "src=\"/static/yuzu-operate-extras.js\""));
    CHECK(has(page, "id=\"ox-expr\""));
    CHECK(has(page, "id=\"ox-validate\""));
    CHECK(has(page, "id=\"ox-preview\""));
    CHECK(has(page, "id=\"ox-kinds\""));
    CHECK(has(page, "id=\"ox-tar-open\""));
    // The shared chunk is spliced into the page's own head.
    CHECK(has(page, ".ox-panel{"));
    // The shared dialog module loads before the controller that calls it.
    const auto d = page.find("src=\"/static/yuzu-dialog.js\"");
    REQUIRE(d != std::string::npos);
    CHECK(d < page.find("src=\"/static/yuzu-operate-extras.js\""));
    // The picker stays: Send still consumes it.
    CHECK(has(page, "hx-get=\"/fragments/scope-list\""));
    CHECK(has(page, "id=\"scope-input\""));
}

TEST_CASE("operate extras: new Dashboard markup carries no hx-on and no inline handler",
          "[ui][operate_extras][security]") {
    const auto panel = scope_panel_markup();
    CHECK_FALSE(has(panel, "hx-on"));
    CHECK_FALSE(std::regex_search(panel, std::regex("\\son[a-z]+\\s*=")));
    // The TAR history button is new markup too.
    const std::string page = kDashboardIndexHtml;
    const auto a = page.find("id=\"ox-tar-open\"");
    REQUIRE(a != std::string::npos);
    const auto tag = page.substr(a, page.find('>', a) - a);
    CHECK_FALSE(std::regex_search(tag, std::regex("\\son[a-z]+\\s*=")));
    CHECK_FALSE(has(tag.c_str(), "hx-on"));
}

TEST_CASE("operate extras: the controller never writes server data as markup",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    CHECK_FALSE(js.empty());
    // ".innerHTML" is the property sink; the bare word also appears as htmx's `swap: 'innerHTML'`
    // option in the Instructions controller, which writes nothing itself.
    for (const char* banned : {".innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                               "eval(", "new Function", "setTimeout(\"", "setInterval(\""}) {
        INFO("banned construct: " << banned);
        CHECK_FALSE(has(js, banned));
    }
    // Every request goes through the shared helper (15 s bound, step-up, 401 redirect) and no
    // second dialog or fetch implementation lives here.
    CHECK(has(js, "window.YuzuDialog.request("));
    CHECK_FALSE(has(js, "showModal"));
    // The only raw fetch is the producer picker's HTML fragment, and it is bounded.
    CHECK(js.find("fetch(") == js.rfind("fetch("));
    CHECK(has(js, "window.fetch('/fragments/result-sets/producers', init)"));
    CHECK(has(js, "AbortSignal.timeout(15000)"));
}

TEST_CASE("operate extras: the scope helper uses the real routes and bounds its output",
          "[ui][operate_extras]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    CHECK(has(js, "/api/v1/scope/validate"));
    CHECK(has(js, "/api/v1/scope/preview"));
    CHECK(has(js, "/api/v1/discover/scope-kinds"));
    // No fragment, no estimate route (unconfined and fail-open, F3).
    CHECK_FALSE(has(js, "/api/scope/estimate"));
    CHECK(has(js, "PREVIEW_IDS = 25"));
    // The preview route's caution text promises an approval rule that does not
    // exist: the field is never read.
    CHECK_FALSE(has(js, ".warning"));
    // Validate is syntax only.
    CHECK(has(js, "Unknown attributes are refused on Send."));
}

TEST_CASE("operate extras: fan-out confirm, history masking and the 403 listener are wired",
          "[ui][operate_extras]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    CHECK(has(js, "'htmx:confirm'"));
    CHECK(has(js, "issueRequest(true)"));
    CHECK(has(js, "'htmx:responseError'"));
    CHECK(has(js, "/api/dashboard/tar-execute"));
    // History and the confirm echo both pass typed text through the mask.
    CHECK(has(js, "body.dataset.secretParams"));
    CHECK(has(js, "(hidden: the secret parameter list is unavailable)"));
    CHECK(has(js, "var shown = maskSecrets(cmd);"));
    CHECK(has(js, "window.addHistory(shown,"));
    // The raw command is never handed to History, and History is not fed from a status alone.
    CHECK_FALSE(has(js, "window.addHistory(cmd"));
    CHECK(has(js, "['Command', maskSecrets(cmd)]"));
    // The TAR form explains the substring blocklist (S10).
    CHECK(has(js, "updated_at or created_by"));
    // The SQL is shown before it is sent.
    CHECK(has(js, "'Run this query?'"));
}

TEST_CASE("operate extras: History is fed only by a dispatched send and never replays a masked "
          "command",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    const std::string page = kDashboardIndexHtml;
    // A 2xx is not a send (refusals answer 200): the hook waits for the server's own marker.
    const auto hook = js.find("form.addEventListener('htmx:afterRequest'");
    REQUIRE(hook != std::string::npos);
    const auto marker = js.find("getResponseHeader('X-Yuzu-Dispatched')", hook);
    const auto add = js.find("window.addHistory(", hook);
    REQUIRE(marker != std::string::npos);
    REQUIRE(add != std::string::npos);
    CHECK(marker < add);
    // An entry whose text changed under the mask is flagged.
    CHECK(has(js, "shown !== cmd"));
    // The page stores the flag and refuses to replay a flagged entry: the check comes before the
    // placeholder text is put in the box and before the send.
    CHECK(has(page, "function addHistory(cmd, scope, masked)"));
    CHECK(has(page, "masked: !!masked"));
    CHECK(has(page, "div.setAttribute('data-masked', '1')"));
    const auto click = page.find("if (this.getAttribute('data-masked') === '1')");
    const auto fill = page.find("getElementById('instr-input').value = this.getAttribute('data-cmd')");
    const auto send = page.find("sendInstruction();", fill);
    REQUIRE(click != std::string::npos);
    REQUIRE(fill != std::string::npos);
    REQUIRE(send != std::string::npos);
    CHECK(click < fill);
    CHECK(fill < send);
    CHECK(has(page, "which History does not keep. Type it again to send it."));
}

TEST_CASE("operate extras: an expression send omits scope-input and needs a preview or a retype",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    // S8: choosing the expression disables scope-input and enables scope_expression.
    CHECK(has(js, "scopeField.disabled = !!e"));
    CHECK(has(js, "exprField.disabled = !e"));
    const std::string page = kDashboardIndexHtml;
    CHECK(has(page, "name=\"scope_expression\" id=\"ox-scope-expression\" value=\"\" disabled"));
    // Rule 8: reaches the send only through a same-expression preview or a typed retype.
    CHECK(has(js, "previewed.expression === expr"));
    CHECK(has(js, "Retype the expression to confirm."));
    CHECK(has(js, "v.typed.trim() === expr"));
    // The route's 400 reason is shown, read as text.
    CHECK(has(js, "DOMParser"));
    CHECK(has(js, "[data-reason]"));
}

TEST_CASE("operate extras: the Result sets page hosts the producers and the controller",
          "[ui][operate_extras]") {
    const std::string page = yuzu::server::kResultSetsPageHtml;
    CHECK(has(page, "<body data-page=\"result-sets\">"));
    CHECK(has(page, "id=\"ox-rs-instr\""));
    CHECK(has(page, "id=\"ox-rs-inv\""));
    CHECK(has(page, "id=\"ox-rs-tar\""));
    const auto d = page.find("src=\"/static/yuzu-dialog.js\"");
    REQUIRE(d != std::string::npos);
    CHECK(d < page.find("src=\"/static/yuzu-operate-extras.js\""));
    // CSP: the page carries no inline handler and no hx-on.
    CHECK_FALSE(has(page, "hx-on"));
    CHECK_FALSE(std::regex_search(page, std::regex("\\son(click|change|submit)\\s*=")));
}

TEST_CASE("operate extras: result set producers call the real REST routes and confirm first",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    CHECK(has(js, "/api/v1/result-sets/from-instruction-result"));
    CHECK(has(js, "/api/v1/result-sets/from-inventory-query"));
    CHECK(has(js, "/api/v1/result-sets/from-tar-query"));
    CHECK(has(js, "/re-eval"));
    CHECK(has(js, "/fragments/result-sets/producers"));
    // A fan-out or re-run is confirmed with what it will do.
    CHECK(has(js, "'Run this instruction?'"));
    CHECK(has(js, "'Run this query?'"));
    CHECK(has(js, "the existing set is unchanged"));
    // The after-dispatch store fault must tell the operator not to re-send.
    CHECK(has(js, "FAULT_AFTER_DISPATCH"));
    CHECK(has(js, "Do not send it again"));
}

TEST_CASE("operate extras: the TAR page's Ad-hoc SQL frame is retired and points to Result sets",
          "[ui][operate_extras]") {
    const std::string page = kTarPageHtml;
    // Nothing of the old form or its script survives.
    for (const char* gone : {"id=\"tar-sql-run\"", "id=\"tar-sql-text\"", "id=\"tar-sql-scope\"",
                             "id=\"tar-sql-include-empty\"", "/api/v1/result-sets/from-tar-query",
                             "Scope-walking SQL frame"}) {
        INFO("retired: " << gone);
        CHECK_FALSE(has(page, gone));
    }
    // The page says where it went; the destination carries every field the frame had.
    CHECK(has(page, "href=\"/result-sets\""));
    CHECK(has(page, "From TAR query"));
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    CHECK(has(js, "/api/v1/result-sets/from-tar-query"));
    CHECK(has(js, "label: 'SQL (SELECT only)'"));
    CHECK(has(js, "name: 'parent'"));
    CHECK(has(js, "name: 'name'"));
    CHECK(has(js, "include_empty:"));
}

TEST_CASE("operate extras: the masked-parameter list is the server's own classification",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    // The masking code keeps no key list of its own (a second copy drifts from the server's).
    CHECK_FALSE(has(js, "grant_secret|grant_id"));
    // The page-rendered attribute is exactly kRedactedInstructionParamKeys, in order.
    std::string expected;
    for (auto key : yuzu::server::kRedactedInstructionParamKeys) {
        if (!expected.empty())
            expected += ',';
        expected += std::string(key);
    }
    CHECK(std::string(YUZU_OX_SECRET_PARAMS) == expected);
    const std::string page = kDashboardIndexHtml;
    CHECK(page.find("data-secret-params=\"" + expected + "\"") != std::string::npos);
}

TEST_CASE("operate extras: Send fails closed until the confirmation script has loaded",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    const std::string page = kDashboardIndexHtml;
    // The page holds every Send at htmx:confirm unless the script's ready flag is set, so a
    // missing script or YuzuDialog never leaves a one-click fleet send.
    const auto guard = page.find("instrForm.addEventListener('htmx:confirm'");
    REQUIRE(guard != std::string::npos);
    const auto guard_end = page.find("});", guard);
    const std::string block = page.substr(guard, guard_end - guard);
    CHECK(has(block, "window.__yuzuDashboardConfirmReady"));
    CHECK(has(block, "e.preventDefault()"));
    // The script sets the flag only when the dialog module exists.
    CHECK(has(js, "if (window.YuzuDialog) window.__yuzuDashboardConfirmReady = true;"));
}
