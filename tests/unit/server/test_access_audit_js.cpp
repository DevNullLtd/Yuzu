/**
 * @file test_access_audit_js.cpp
 * @brief String pins on the Audit and reviews page template and its embedded glue script. The
 *        repo has no JS runner, so these prove a token is present, not that a branch executes;
 *        the behaviour itself is exercised by the headless browser run recorded in the PR body.
 */

#include "access_audit_render.hpp"
#include "access_audit_ui.hpp"
#include "app_shell.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <regex>
#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuAuditJs;
}

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server::access_audit;

TEST_CASE("audit glue: the row toggle is keyboard-state aware and writes no markup",
          "[access-audit][js]") {
    const std::string& js = yuzu::server::kYuzuAuditJs;
    for (const char* token : {"data-act=\"toggle-row\"", "aria-expanded", "result-detail", "expanded",
                              "classList.toggle"}) {
        INFO(token);
        CHECK_THAT(js, ContainsSubstring(token));
    }
    for (const char* bad : {"innerHTML", "insertAdjacentHTML", "eval(", "new Function",
                            "document.write", "hx-on", "fetch(", "XMLHttpRequest"}) {
        INFO(bad);
        CHECK_THAT(js, !ContainsSubstring(bad));
    }
}

TEST_CASE("audit page: the template is inline-free, single-shell and under the MSVC literal cap",
          "[access-audit][js]") {
    const std::string t = kAccessAuditTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_THAT(t, !ContainsSubstring("hx-post"));
    CHECK_THAT(t, !ContainsSubstring("hx-put"));
    CHECK_THAT(t, !ContainsSubstring("hx-delete"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    CHECK(std::strlen(kAccessAuditTemplate) < 15000);

    std::vector<std::string> srcs;
    const std::regex script_src(R"re(<script src="([^"]+)")re");
    for (std::sregex_iterator it(t.begin(), t.end(), script_src), end; it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/yuzu-access.js",
                                           "/static/yuzu-audit.js"});
}

TEST_CASE("audit page: the template's sentences are byte-equal to the renderer's constants",
          "[access-audit][js]") {
    const std::string t = kAccessAuditTemplate;
    const auto attr = [&](const char* name, std::string_view v) {
        CHECK_THAT(t, ContainsSubstring(std::string(name) + "=\"" + std::string(v) + "\""));
    };
    attr("data-denied", kLogDenied);
    attr("data-unavailable", kLogUnavailable);
    attr("data-unavailable", kSampleUnavailable);
    attr("data-denied", kRetentionDenied);
    attr("data-unavailable", kRetentionUnavailable);
    // Every panel that can be refused names the fragment it reloads from.
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/audit/log?range=24h\""));
    CHECK_THAT(t, ContainsSubstring("data-src=\"/fragments/access/audit/retention\""));
}

TEST_CASE("audit page: the sample is never drawn on load and the filter form is a GET",
          "[access-audit][js]") {
    const std::string t = kAccessAuditTemplate;
    // Only the log loads itself; the sample (which writes an audit row) and the retention
    // read (a different permission) wait for a click.
    const std::regex load(R"re(hx-trigger="load")re");
    CHECK(std::distance(std::sregex_iterator(t.begin(), t.end(), load), std::sregex_iterator()) == 1);
    CHECK_THAT(t, ContainsSubstring("id=\"audit-log\" hx-get=\"/fragments/access/audit/log?range=24h\" "
                                    "hx-trigger=\"load\""));
    CHECK_THAT(t, ContainsSubstring("hx-get=\"/fragments/access/audit/sample\""));
    CHECK_THAT(t, ContainsSubstring("hx-get=\"/fragments/access/audit/retention\""));
    CHECK_THAT(t, ContainsSubstring("<form class=\"toolbar\" id=\"audit-filters\""));
    CHECK_THAT(t, !ContainsSubstring("method=\"post\""));
}
