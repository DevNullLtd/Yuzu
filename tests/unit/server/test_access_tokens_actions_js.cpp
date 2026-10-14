/**
 * @file test_access_tokens_actions_js.cpp
 * @brief String pins on the Tokens and principals write glue (yuzu-tokens-actions.js) and on the
 *        template parts it depends on. The repo has no JS runner, so these prove a token is
 *        present or absent, not that a branch runs; no executing browser test backs this glue yet
 *        (listed as unverified in the PR body).
 *
 * Pinned, in order of consequence:
 *   - the secret has one owner (the reveal strip, via textContent) and no timer discards it;
 *   - a second secret cannot be minted over an unstored one;
 *   - every REST path is the documented route, built only from a charset-checked, percent-encoded id;
 *   - every mutation goes through YuzuDialog.form with a submit hook (a refusal keeps the dialog);
 *   - no markup sink, storage, console, raw fetch, or navigation other than the login redirect.
 */

#include "access_tokens_ui.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuTokensActionsJs;
}

using Catch::Matchers::ContainsSubstring;

namespace {
const std::string& js() { return yuzu::server::kYuzuTokensActionsJs; }

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1))
        ++n;
    return n;
}
} // namespace

TEST_CASE("actions glue: no markup sink, storage, console, raw fetch or stray navigation",
          "[access-tokens][js][writes]") {
    for (const char* bad : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "localStorage", "sessionStorage", "hx-on", "XMLHttpRequest",
                            "console.", "fetch(", ".href", "window.open", "setAttribute('href'",
                            "setAttribute('src'", "javascript:", "document.cookie", "history.", "location.replace",
                            "location.assign", "postMessage", "navigator.sendBeacon", "indexedDB"}) {
        INFO(bad);
        CHECK_THAT(js(), !ContainsSubstring(bad));
    }
    CHECK_THAT(js(), ContainsSubstring("'use strict'"));
}

TEST_CASE("actions glue: a revealed secret has no timer, one owner, and one way out",
          "[access-tokens][js][writes][secret]") {
    // No clock discards an unsaved secret (a timer can fire while the operator is still copying).
    for (const char* bad : {"setTimeout", "setInterval", "requestAnimationFrame", "60000", "visibilitychange",
                            "Cleared automatically"}) {
        INFO(bad);
        CHECK_THAT(js(), !ContainsSubstring(bad));
    }
    // The strip is cleared by the explicit acknowledgement, and on pagehide so it never reaches bfcache.
    CHECK_THAT(js(), ContainsSubstring("act === 'reveal-stored'"));
    CHECK_THAT(js(), ContainsSubstring("window.addEventListener('pagehide'"));
    // Leaving the page with an unstored secret asks first.
    CHECK_THAT(js(), ContainsSubstring("window.addEventListener('beforeunload'"));
    CHECK_THAT(js(), ContainsSubstring("if (secretShown) { e.preventDefault(); e.returnValue = ''; }"));
    // The secret reaches the DOM only through textContent on the one code element.
    CHECK(count_of(js(), "code.textContent = secret;") == 1);
    CHECK_THAT(js(), ContainsSubstring("code.textContent = '';"));
    // The response object that carried it is emptied as it is read, for the enveloped token routes.
    CHECK(count_of(js(), "r.data = null;") == 1);
    CHECK_THAT(js(), ContainsSubstring("var d = r.data && r.data.data;"));  // token routes: enveloped
    // A secret is never copied into an attribute, dataset, URL or flash message.
    CHECK_THAT(js(), !ContainsSubstring("dataset.secret"));
    CHECK_THAT(js(), !ContainsSubstring("setAttribute('data-"));
    CHECK_THAT(js(), !ContainsSubstring("flash(secret"));
    CHECK_THAT(js(), !ContainsSubstring("title = secret"));
    // Copy failure is stated, and the text stays selectable.
    CHECK_THAT(js(), ContainsSubstring("Copy failed. Select the text."));
}

TEST_CASE("actions glue: every secret-minting action refuses while an unstored secret is showing",
          "[access-tokens][js][writes][secret]") {
    // token-new, token-rotate, principal-mint, principal-rotate: four, no more, no fewer.
    CHECK(count_of(js(), "if (blockedBySecret()) return;") == 4);
    CHECK_THAT(js(), ContainsSubstring("before creating another."));
    // Confirm secrets are write-only password fields: never prefilled, never spell-checked (dialog).
    CHECK(count_of(js(), "type: 'password', autocomplete: 'off'") == 2);
    CHECK_THAT(js(), !ContainsSubstring("type: 'password', autocomplete: 'off', value"));
}

TEST_CASE("actions glue: every route is the documented REST v1 route and the dashboard twins are not used",
          "[access-tokens][js][writes][routes]") {
    for (const char* lit : {"'tokens'", "'tokens/'", "'/rotate'", "'/confirm'", "'engine-principals'",
                            "'engine-principals/'", "'/credentials'", "'/credentials/rotate'",
                            "'/credentials/confirm'", "'/transfer-owner'", "'/roles'", "'/roles/'"}) {
        INFO(lit);
        CHECK_THAT(js(), ContainsSubstring(lit));
    }
    CHECK_THAT(js(), ContainsSubstring("var API = '/api/v1/';"));
    // The dashboard twins lack a step-up; this page must never call them.
    CHECK_THAT(js(), !ContainsSubstring("/api/settings/"));
    // Methods: one per route family, as documented.
    // POST: token new/rotate/confirm (3); principal new/mint/rotate/confirm/transfer (5); role assign.
    CHECK(count_of(js(), "method: 'POST'") == 9);
    CHECK(count_of(js(), "method: 'DELETE'") == 3);  // token, principal, role
}

TEST_CASE("actions glue: every id reaches a path only after a charset check and percent-encoding",
          "[access-tokens][js][writes][urlsafety]") {
    // The charsets mirror the routes' own.
    CHECK_THAT(js(), ContainsSubstring("var TOKEN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;"));
    CHECK_THAT(js(), ContainsSubstring("var PRINCIPAL = /^engine:[a-z0-9._-]{1,128}$/;"));
    CHECK_THAT(js(), ContainsSubstring("var SLUG = /^[a-z0-9._-]{1,128}$/;"));
    CHECK_THAT(js(), ContainsSubstring("function seg(v) { return encodeURIComponent(v); }"));
    // Every line that builds a request path may add only literals, seg(...) and the literal tail.
    std::size_t path_lines = 0;
    std::size_t at = 0;
    while ((at = js().find("API + ", at)) != std::string::npos) {
        const auto eol = js().find('\n', at);
        std::string line = js().substr(at, eol - at);
        at = eol;
        ++path_lines;
        line = std::regex_replace(line, std::regex(R"(\(tail \|\| ''\))"), "");
        line = std::regex_replace(line, std::regex(R"(seg\([^)]*\))"), "");
        line = std::regex_replace(line, std::regex(R"('[^']*')"), "");
        INFO(line);
        // What is left may be `API`, `+`, `,` and punctuation - never another identifier.
        CHECK_FALSE(std::regex_search(line.substr(std::string("API + ").size()), std::regex(R"([A-Za-z_]{2,})")));
    }
    CHECK(path_lines >= 6);
    // The page helpers refuse an id outside its charset before building anything.
    CHECK_THAT(js(), ContainsSubstring("if (!TOKEN_ID.test(id || ''))"));
    CHECK_THAT(js(), ContainsSubstring("if (!PRINCIPAL.test(id || ''))"));
    CHECK_THAT(js(), ContainsSubstring("!SLUG.test(d.slug || '')"));
    // A reload URL takes a re-checked principal id, encoded.
    CHECK_THAT(js(), ContainsSubstring("if (PRINCIPAL.test(id)) load(DETAIL + '?id=' + seg(id), 'side-principal');"));
}

TEST_CASE("actions glue: every mutation is a dialog form with a submit hook, so a refusal keeps the dialog",
          "[access-tokens][js][writes]") {
    CHECK(count_of(js(), "D.form(") == 1);   // inside mutate()
    CHECK_THAT(js(), !ContainsSubstring("D.confirm("));
    CHECK(count_of(js(), "D.request(") == 1);
    CHECK_THAT(js(), ContainsSubstring("return r.message || 'The request failed (HTTP ' + r.status + ').';"));
    // A 5xx on a credential write may have changed state: the detail is reloaded, never retried.
    CHECK_THAT(js(), ContainsSubstring("function refreshOnFail(id) { return function (r) { if (r.status >= 500) reloadDetail(id); }; }"));
    CHECK(count_of(js(), "onFail: refreshOnFail(d.principalId)") == 3);
    // A dropped audit row on a successful change is surfaced, persistently.
    CHECK_THAT(js(), ContainsSubstring("if (r.auditFailed) auditBanner();"));
}

TEST_CASE("actions glue: copy and limits match the matrix", "[access-tokens][js][writes]") {
    // Settings' confirm sentences, verbatim.
    CHECK_THAT(js(), ContainsSubstring("Applications using this token will lose access."));
    CHECK_THAT(js(), ContainsSubstring("This is TERMINAL - never un-revocable; recovery mints a successor."));
    // MCP tokens: one hour short of 90 days; default overlap 7 days; ttl days 1..90.
    CHECK_THAT(js(), ContainsSubstring("var MCP_MAX_HOURS = 2159;"));
    CHECK_THAT(js(), ContainsSubstring("value: String(7 * DAY)"));
    CHECK_THAT(js(), ContainsSubstring("wholeNumber(v.days, 1, 90)"));
    // The recovery sentence names the 2-minute window and the way out after it.
    CHECK_THAT(js(), ContainsSubstring("Rotate again within 2 minutes to get the same secret."));
    CHECK_THAT(js(), ContainsSubstring("After that, revoke the new"));
    // expires_at comes from the server clock plus page-measured elapsed time.
    CHECK_THAT(js(), ContainsSubstring("serverNow() + h * 3600"));
    // A byte size may be large: whole numbers up to 15 digits stay exact in a JS Number.
    CHECK_THAT(js(), ContainsSubstring("/^\\d{1,15}$/.test(t)"));
    CHECK_THAT(js(), ContainsSubstring("Number(root.dataset.now)"));
}

TEST_CASE("tokens page: the write template parts - htmx history off, strip outside every fragment, scripts in order",
          "[access-tokens][js][writes]") {
    const std::string t = kAccessTokensTemplate;
    // History and eval are disabled before htmx loads, so no page snapshot (and no secret in the DOM)
    // is ever written to localStorage.
    const auto meta = t.find("<meta name=\"htmx-config\" content='{\"allowEval\":false,\"historyEnabled\":false}'>");
    const auto htmx = t.find("<script src=\"/static/htmx.js\">");
    REQUIRE(meta != std::string::npos);
    REQUIRE(htmx != std::string::npos);
    CHECK(meta < htmx);
    // Script order: htmx, dialog, read glue, write glue; the last three deferred (run in order).
    const auto d = t.find("/static/yuzu-dialog.js\" defer");
    const auto r = t.find("/static/yuzu-tokens.js\" defer");
    const auto w = t.find("/static/yuzu-tokens-actions.js\" defer");
    REQUIRE(d != std::string::npos);
    REQUIRE(r != std::string::npos);
    REQUIRE(w != std::string::npos);
    CHECK((htmx < d && d < r && r < w));
    // The strip: hidden until a secret exists, a labelled region, an explicit acknowledgement, no timer.
    const auto strip = t.find("<section id=\"reveal\" class=\"reveal\" role=\"region\" aria-label=\"Newly created secret\" hidden>");
    REQUIRE(strip != std::string::npos);
    CHECK_THAT(t, ContainsSubstring("I have stored this"));
    CHECK_THAT(t, !ContainsSubstring("countdown"));
    CHECK_THAT(t, !ContainsSubstring("seconds"));
    // It sits before the split, and outside every panel a fragment can refresh.
    CHECK(strip < t.find("<div class=\"split\">"));
    CHECK(strip < t.find("id=\"tokens-body\""));
    CHECK(strip < t.find("id=\"principals-body\""));
    CHECK(strip < t.find("id=\"side-principal\""));
    // The secret element starts empty.
    CHECK_THAT(t, ContainsSubstring("<code id=\"reveal-secret\" hidden></code>"));
}
