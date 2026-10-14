/**
 * @file test_access_tokens_js.cpp
 * @brief String pins on the Tokens and principals template and its embedded glue script. The
 *        repo has no JS runner, so these prove a token is present, not that a branch runs;
 *        behaviour is exercised by the headless-browser run recorded in the PR body.
 */

#include "access_tokens_render.hpp"
#include "access_tokens_ui.hpp"
#include "app_shell.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuTokensJs;
}

using Catch::Matchers::ContainsSubstring;

TEST_CASE("tokens glue: no HTML-string injection, no storage, no write path",
          "[access-tokens][js]") {
    const std::string& js = yuzu::server::kYuzuTokensJs;
    for (const char* bad : {"innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "localStorage", "sessionStorage", "hx-on",
                            "XMLHttpRequest", "'POST'", "'DELETE'", "'PUT'", "method:"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
}

TEST_CASE("tokens glue: the one direct fetch is bounded, same-origin and uncached",
          "[access-tokens][js]") {
    const std::string& js = yuzu::server::kYuzuTokensJs;
    CHECK_THAT(js, ContainsSubstring("/api/v1/engine-principals/audit/no-admin"));
    CHECK_THAT(js, ContainsSubstring("credentials: 'same-origin'"));
    CHECK_THAT(js, ContainsSubstring("cache: 'no-store'"));
    CHECK_THAT(js, ContainsSubstring("AbortSignal.timeout(10000)"));
    // Exactly one fetch call site.
    std::size_t n = 0;
    for (std::size_t p = js.find("fetch("); p != std::string::npos; p = js.find("fetch(", p + 1))
        ++n;
    CHECK(n == 1);
}

TEST_CASE("tokens glue: every URL sink takes a fixed path, and data reaches it only as an encoded query",
          "[access-tokens][js][urlsafety]") {
    const std::string& js = yuzu::server::kYuzuTokensJs;
    for (const char* bad : {".href", "window.open", "setAttribute('href'", "setAttribute('src'",
                            ".src =", "hx-get", "hx-post", "hx-delete", "document.location",
                            "location.replace", "location.href"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
    // The only navigation is the fixed login redirect.
    std::size_t nav = 0;
    for (std::size_t p = js.find("location.assign("); p != std::string::npos;
         p = js.find("location.assign(", p + 1)) {
        CHECK(js.compare(p, std::string("location.assign('/login')").size(), "location.assign('/login')") == 0);
        ++nav;
    }
    CHECK(nav == 2);
    // The one data-derived URL is the principal id, appended after '?id=' and percent-encoded;
    // the state toggle is clamped to the two literals.
    CHECK_THAT(js, ContainsSubstring("side.dataset.src + '?id=' + encodeURIComponent(id)"));
    CHECK_THAT(js, ContainsSubstring("(b.dataset.state === 'all' ? 'all' : 'active')"));
    // Every ajax() call site: a clamped literal, a static data-src, or the encoded id above.
    std::size_t calls = 0;
    for (std::size_t p = js.find("ajax("); p != std::string::npos; p = js.find("ajax(", p + 1))
        ++calls;
    CHECK(calls == 6);  // definition, its htmx.ajax body, 4 call sites
}

TEST_CASE("tokens glue: principals are requested only for an effective administrator",
          "[access-tokens][js]") {
    const std::string& js = yuzu::server::kYuzuTokensJs;
    CHECK_THAT(js, ContainsSubstring("dataset.effectiveAdmin === '1'"));
    CHECK_THAT(js, ContainsSubstring("principalsAsked"));
    // Ids reach a URL only through encodeURIComponent.
    CHECK_THAT(js, ContainsSubstring("encodeURIComponent(id)"));
    // The error handlers are keyed on the panel's own data attributes and send 401 to login.
    for (const char* token : {"htmx:responseError", "htmx:sendError", "data-denied", "dataset.denied",
                              "dataset.unavailable", "location.assign('/login')", "Sec-Audit-Failed",
                              "textContent"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("tokens glue: the strip never prints a clean result it did not read",
          "[access-tokens][js]") {
    const std::string& js = yuzu::server::kYuzuTokensJs;
    CHECK_THAT(js, ContainsSubstring("This is not a clean result."));
    CHECK_THAT(js, ContainsSubstring("No violations found in the roles and grants the server could read."));
    CHECK_THAT(js, ContainsSubstring("typeof d.ok !== 'boolean'"));
    CHECK_THAT(js, ContainsSubstring("Treat it as a security incident."));
    // Not a green pill: the clean state is a neutral note.
    CHECK_THAT(js, !ContainsSubstring("pill ok"));
}

TEST_CASE("tokens page: the template is inline-free, single-shell and under the MSVC literal cap",
          "[access-tokens][js]") {
    const std::string t = kAccessTokensTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_THAT(t, !ContainsSubstring("hx-post"));
    CHECK_THAT(t, !ContainsSubstring("hx-delete"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    CHECK(std::strlen(kAccessTokensTemplate) < 15000);

    std::vector<std::string> srcs;
    const std::regex script_src(R"RX(<script src="([^"]+)")RX");
    for (std::sregex_iterator it(t.begin(), t.end(), script_src), end; it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/yuzu-tokens.js"});
}

TEST_CASE("tokens page: the template's sentences are byte-equal to the renderer's constants",
          "[access-tokens][js]") {
    const std::string t = kAccessTokensTemplate;
    using namespace yuzu::server::access_tokens;
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kTokensDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kTokensUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kPrincipalsDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kPrincipalsUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kDetailUnavailable) + "\""));
    // Principals and the detail panel are NOT load-triggered: the script asks only for admins.
    CHECK_THAT(t, ContainsSubstring("hx-get=\"/fragments/access/tokens/list\" hx-trigger=\"load\""));
    CHECK_THAT(t, !ContainsSubstring("hx-get=\"/fragments/access/principals"));
}
