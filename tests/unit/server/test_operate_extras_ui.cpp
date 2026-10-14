/**
 * test_operate_extras_ui.cpp — pins for the Operate extras page assets: the
 * shared ox- CSS chunk, the Dashboard markup that hosts the scope helper and
 * the TAR history form, and the embedded controller script.
 *
 * Pure string checks over compiled-in assets (no store, no process, no clock).
 */

#include <catch2/catch_test_macros.hpp>

#include "operate_extras_ui.hpp"
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
    CHECK(has(page, "<body data-page=\"dashboard\">"));
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
    for (const char* banned : {"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
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
    CHECK_FALSE(has(js, "warning"));
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
    CHECK(has(js, "grant_secret|grant_id"));
    CHECK(has(js, "window.addHistory(maskSecrets(cmd)"));
    CHECK(has(js, "['Command', maskSecrets(cmd)]"));
    // The TAR form explains the substring blocklist (S10).
    CHECK(has(js, "updated_at or created_by"));
    // The SQL is shown before it is sent.
    CHECK(has(js, "'Run this query?'"));
}

TEST_CASE("operate extras: an expression send omits scope-input and needs a preview or a retype",
          "[ui][operate_extras][security]") {
    const auto& js = yuzu::server::kYuzuOperateExtrasJs;
    // S8: choosing the expression disables scope-input and enables scope_expression.
    CHECK(has(js, "scopeField.disabled = !!e"));
    CHECK(has(js, "exprField.disabled = !e"));
    const std::string page = kDashboardIndexHtml;
    CHECK(has(page.c_str(), "name=\"scope_expression\" id=\"ox-scope-expression\" value=\"\" disabled"));
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
