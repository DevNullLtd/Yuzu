/**
 * @file test_groups_page.cpp
 * @brief The Groups and enrolment page: routes (gate, redirect, headers, fail-fast Deps) and
 *        the template's structural contract. Real `TestRouteSink`, no socket.
 */

#include "app_shell.hpp"
#include "groups_routes.hpp"
#include "groups_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using yuzu::server::test::TestRouteSink;
namespace groups = yuzu::server::groups;

namespace {

groups::Deps deps_with_session(bool signed_in) {
    groups::Deps d;
    d.auth_fn = [signed_in](const httplib::Request&,
                            httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
        if (!signed_in)
            return std::nullopt;
        yuzu::server::auth::Session s;
        s.username = "admin";
        return s;
    };
    return d;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

} // namespace

TEST_CASE("groups routes: an unbound Deps member is refused at registration", "[groups][page]") {
    TestRouteSink sink;
    CHECK_THROWS_AS(groups::register_groups_routes(sink, groups::Deps{}), std::invalid_argument);
}

TEST_CASE("groups routes: /groups needs a session and redirects to /login without one",
          "[groups][page]") {
    TestRouteSink anon;
    groups::register_groups_routes(anon, deps_with_session(false));
    auto res = anon.Get("/groups");
    REQUIRE(res);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login");
    CHECK(res->body.empty());

    TestRouteSink user;
    groups::register_groups_routes(user, deps_with_session(true));
    res = user.Get("/groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("Groups and enrolment"));
}

TEST_CASE("groups routes: the glue script is served no-cache as JavaScript", "[groups][page]") {
    TestRouteSink sink;
    groups::register_groups_routes(sink, deps_with_session(true));
    auto res = sink.Get("/static/yuzu-groups.js");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/javascript; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-cache, no-store, must-revalidate");
    CHECK_THAT(res->body, ContainsSubstring("htmx:responseError"));
}

TEST_CASE("groups page: only the enrolment fragments that already exist are loaded",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    std::vector<std::string> gets;
    for (std::sregex_iterator it(t.begin(), t.end(), std::regex(R"re(hx-get="([^"]+)")re")), end;
         it != end; ++it)
        gets.push_back((*it)[1].str());
    CHECK(gets == std::vector<std::string>{"/fragments/settings/pending",
                                           "/fragments/settings/auto-approve",
                                           "/fragments/settings/tokens"});
    // The three element ids the legacy renderers bake into their hx-target.
    for (const char* id : {"id=\"pending-section\"", "id=\"auto-approve-section\"",
                           "id=\"token-section\""})
        CHECK_THAT(t, ContainsSubstring(id));
    // Pending refreshes live, as the Settings panel does.
    CHECK_THAT(t, ContainsSubstring("sse-connect=\"/events\""));
    CHECK_THAT(t, ContainsSubstring("sse:pending-agent"));
}

TEST_CASE("groups page: htmx-config precedes the htmx script (htmx reads it once, at load)",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    const auto meta = t.find("<meta name=\"htmx-config\"");
    const auto htmx = t.find("<script src=\"/static/htmx.js\">");
    REQUIRE(meta != std::string::npos);
    REQUIRE(htmx != std::string::npos);
    CHECK(meta < htmx);
    // No history snapshot of a revealed one-time token; no eval.
    CHECK_THAT(t, ContainsSubstring("{\"allowEval\":false,\"historyEnabled\":false}"));
    // The baked page keeps the same order.
    const std::string baked = kGroupsHtml;
    CHECK(baked.find("<meta name=\"htmx-config\"") < baked.find("<script src=\"/static/htmx.js\">"));
}

TEST_CASE("groups page: no inline handlers or style, same-origin scripts only, one shell",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_THAT(t, !ContainsSubstring("yuzu-dialog"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(std::strlen(kGroupsTemplate) < 15000);

    std::vector<std::string> srcs;
    for (std::sregex_iterator it(t.begin(), t.end(), std::regex(R"re(<script src="([^"]+)")re")), end;
         it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/sse.js",
                                           "/static/yuzu-groups.js"});

    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    const std::string baked = kGroupsHtml;
    CHECK(count_of(baked, std::string(yuzu::server::shell::kShellBegin)) == 1);
    CHECK(count_of(baked, "fetch('/api/me')") == 1);
}

TEST_CASE("groups page: every loader panel carries its own denied and unavailable sentence",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    CHECK(count_of(t, "data-denied=\"") == 3);
    CHECK(count_of(t, "data-unavailable=\"") == 3);
    CHECK(count_of(t, "data-src=\"") == 3);
    CHECK_THAT(t, ContainsSubstring("This is not an empty list."));
}

TEST_CASE("groups page: the Groups entry is first in Estate and lights up on /groups",
          "[groups][page]") {
    const auto groups_nav = yuzu::server::shell::nav_groups();
    const yuzu::server::shell::NavGroup* estate = nullptr;
    for (const auto& g : groups_nav)
        if (g.title == "Estate")
            estate = &g;
    REQUIRE(estate != nullptr);
    REQUIRE_FALSE(estate->items.empty());
    CHECK(estate->items[0].key == "groups");
    CHECK(estate->items[0].href == "/groups");
    CHECK(estate->items[0].label == "Groups and enrolment");
    CHECK_FALSE(estate->items[0].admin_only);
    // No new nav group was added for it.
    CHECK(groups_nav.size() >= 4);
    const std::string baked = kGroupsHtml;
    CHECK_THAT(baked, ContainsSubstring("<a class=\"shell-nav on\" href=\"/groups\""));
}
