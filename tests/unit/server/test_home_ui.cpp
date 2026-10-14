/// @file test_home_ui.cpp
/// Page pins for /home: one h1, one shell block, no handlers or hx-on, only the
/// htmx script, tokenised CSS, literals under the MSVC cap, and exactly the
/// fragment URLs the page is allowed to load.

#include "home_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <regex>
#include <string>

namespace {

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST_CASE("home page: one h1, one shell block, Home breadcrumb, no nav item active", "[home][ui]") {
    const std::string html(kHomeHtml);
    CHECK(count_of(html, "<h1") == 1);
    CHECK(count_of(html, "<!--yuzu:shell-->") == 1);
    CHECK(count_of(html, "<!--/yuzu:shell-->") == 1);
    CHECK(count_of(html, "<b>Home</b>") >= 1);
    // Home is reached from the logo, so no sidebar entry is lit.
    CHECK(count_of(html, "shell-nav on") == 0);
    CHECK(count_of(html, "href=\"/home\" aria-label=\"Yuzu home\"") == 1);
    CHECK(count_of(html, "fetch('/api/me')") == 1);
}

TEST_CASE("home page: no handlers, no hx-on, no innerHTML, only the htmx script", "[home][ui]") {
    const std::string tpl(kHomeTemplate);
    CHECK(count_of(tpl, "hx-on") == 0);
    CHECK(count_of(tpl, " onclick=") == 0);
    CHECK(count_of(tpl, "innerHTML") == 0);
    CHECK(count_of(tpl, "<script") == 1);
    CHECK(count_of(tpl, "<script src=\"/static/htmx.js\"></script>") == 1);

    const std::string html(kHomeHtml);
    CHECK(count_of(html, "hx-on") == 0);
    CHECK(count_of(html, " onclick=") == 0);
    // Every external script is htmx; the shell's own script is inline.
    std::regex src(R"(<script[^>]*\ssrc=\"([^\"]*)\")");
    for (std::sregex_iterator it(html.begin(), html.end(), src), end; it != end; ++it)
        CHECK((*it)[1].str() == "/static/htmx.js");
}

TEST_CASE("home page: loads exactly the summary and the three panel fragments", "[home][ui]") {
    const std::string tpl(kHomeTemplate);
    CHECK(count_of(tpl, "hx-get=") == 4);
    CHECK(count_of(tpl, "hx-get=\"/fragments/home/summary\"") == 1);
    for (const char* id : {"policies", "activity", "health"}) {
        const std::string frag = std::string("hx-get=\"/fragments/home/") + id + "\"";
        CHECK(count_of(tpl, frag) == 1);
        // The fragment answers a full <section id="home-..."> for an outerHTML swap.
        CHECK(count_of(tpl, std::string("id=\"home-") + id + "\"") == 1);
    }
    // No polling: Refresh is a plain link.
    CHECK(count_of(tpl, "every ") == 0);
    CHECK(count_of(tpl, "href=\"/home\">Refresh</a>") == 1);
}

TEST_CASE("home page: CSS is tokenised and every literal is under the MSVC cap", "[home][ui]") {
    const std::string css(kHomeCss);
    CHECK(css.size() < 16000);
    CHECK(std::strlen(kHomeTemplate) < 16000);
    CHECK_FALSE(std::regex_search(css, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(css.find("rgb(") == std::string::npos);
    // Everything is scoped under the home- prefix or reuses shared classes.
    CHECK(css.find(".split") == std::string::npos);
    CHECK(css.find(".side2") == std::string::npos);
}
