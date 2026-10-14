/**
 * @file test_access_js.cpp
 * @brief String pins on the Access page template and its embedded glue script. The repo has
 *        no JS runner, so these prove a token is present, not that a branch executes; the
 *        behaviour itself is exercised by the headless browser run recorded in the PR body.
 */

#include "access_render.hpp"
#include "access_ui.hpp"
#include "app_shell.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuAccessJs;
}

using Catch::Matchers::ContainsSubstring;

TEST_CASE("access glue: the denied and unavailable mapping is keyed on the panel's data attributes",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* token : {"htmx:responseError", "htmx:sendError", "data-denied",
                              "dataset.denied", "dataset.unavailable", "location.assign('/login')",
                              "data-act=\"reload\"", "dataset.src", "textContent"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
}

TEST_CASE("access glue: no HTML-string injection and no action wiring in the read-only page",
          "[access][js]") {
    const std::string& js = yuzu::server::kYuzuAccessJs;
    for (const char* bad : {"innerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "hx-on", "fetch(", "XMLHttpRequest"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
}

TEST_CASE("access page: the template is inline-free, single-shell and under the MSVC literal cap",
          "[access][js]") {
    const std::string t = kAccessUsersTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    CHECK(std::strlen(kAccessUsersTemplate) < 15000);

    // The scripts are exactly these two, both same-origin.
    std::vector<std::string> srcs;
    const std::regex script_src(R"re(<script src="([^"]+)")re");
    for (std::sregex_iterator it(t.begin(), t.end(), script_src), end; it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/yuzu-access.js"});
}

TEST_CASE("access page: the template's sentences are byte-equal to the renderer's constants",
          "[access][js]") {
    const std::string t = kAccessUsersTemplate;
    using namespace yuzu::server::access;
    CHECK_THAT(t, ContainsSubstring("data-denied=\"" + std::string(kUsersDenied) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kUsersUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring("data-unavailable=\"" + std::string(kDetailUnavailable) + "\""));
    CHECK_THAT(t, ContainsSubstring(std::string(kSelectUser)));
    // Both panels name their own refetch source for the Retry button.
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/users/list\""));
}
