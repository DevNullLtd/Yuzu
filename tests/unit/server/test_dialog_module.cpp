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
    // Bounded fetch, built inside try/catch so an old browser degrades to no timeout. The
    // default stays 15 s; a caller may widen it, but only inside a closed range, so a bad
    // value can never disable the bound.
    CHECK(has(js, "try { init.signal = AbortSignal.timeout(prep.timeoutMs); } catch (e)"));
    CHECK(has(js, "(typeof ms === 'number' && ms >= 1000 && ms <= 300000) ? ms : 15000;"));
    CHECK(has(js, "credentials: 'same-origin', cache: 'no-store'"));
    // One dialog at a time.
    CHECK(has(js, "Promise.reject(new Error('dialog busy'))"));
}

TEST_CASE("dialog module: request is same-origin only and replays byte-identical content",
          "[ui][dialog]") {
    const auto& js = yuzu::server::kYuzuDialogJs;
    // The url is resolved against the page and refused unless it is same-origin.
    CHECK(has(js, "new URL(String(url), location.href)"));
    CHECK(has(js, "u.origin !== location.origin"));
    CHECK(has(js, "Only same-origin requests are allowed."));
    // The body is serialised once; the MFA replay re-sends that snapshot, not live opts.
    CHECK(has(js, "var prep = prepare(opts);"));
    CHECK(has(js, "return send(method, url, prep);"));
    CHECK_FALSE(has(js, "return rawRequest(method, url, opts);"));
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
    // Secrets are cleared on error and on close, and a password field is not spell-checked.
    CHECK(has(js, "cleaners.push(function () { input.value = ''; });"));
    CHECK(has(js, "if (spec.type === 'password') input.setAttribute('spellcheck', 'false');"));
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
