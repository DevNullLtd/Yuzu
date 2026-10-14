/**
 * test_dialog_module.cpp -- static pins for the shared dialog module (static/yuzu-dialog.js)
 * and the Dialog block of yuzu.css. Pure string checks: CSP hygiene, bounded request,
 * the step-up contract and the CSS/JS slot agreement.
 */

#include <catch2/catch_test_macros.hpp>

#include <regex>
#include <string>
#include <string_view>

namespace yuzu::server {
extern const std::string kYuzuDialogJs;
extern const std::string kYuzuCss;
} // namespace yuzu::server

namespace {
bool has(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}
} // namespace

// -- Shared dialog module (static/yuzu-dialog.js + the Dialog block of yuzu.css) ---------

TEST_CASE("dialog module: bundle shape, CSP-clean, bounded request",
          "[ui][dialog]") {
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
    CHECK(has(js, "try { init.signal = AbortSignal.timeout(15000); } catch (e)"));
    CHECK(has(js, "credentials: 'same-origin', cache: 'no-store'"));
    // One dialog at a time.
    CHECK(has(js, "Promise.reject(new Error('dialog busy'))"));
}

TEST_CASE("dialog module: request maps both error shapes and the step-up contract",
          "[ui][dialog]") {
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
          "[ui][dialog]") {
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
