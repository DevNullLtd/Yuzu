/**
 * @file test_groups_page.cpp
 * @brief The Groups and enrolment page: routes (gate, redirect, headers, fail-fast Deps) and
 *        the template's structural contract. Real `TestRouteSink`, no socket.
 */

#include "app_shell.hpp"
#include "groups_render.hpp"
#include "groups_routes.hpp"
#include "groups_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using yuzu::server::test::TestRouteSink;
namespace groups = yuzu::server::groups;

namespace {

// Injectable boundary for the fragments: every closure reads and records through this.
struct Fakes {
    bool perm_ok = true;
    int perm_calls = 0;
    int fleet_calls = 0;
    int group_reads = 0;
    int member_reads = 0;
    std::optional<std::unordered_set<std::string>> scope; // nullopt = unfiltered
    bool fleet_admit = true;
    std::optional<std::vector<yuzu::server::ManagementGroup>> groups =
        std::vector<yuzu::server::ManagementGroup>{};
    std::optional<std::unordered_map<std::string, std::size_t>> counts =
        std::unordered_map<std::string, std::size_t>{};
    std::expected<std::optional<yuzu::server::ManagementGroup>, std::string> group =
        std::optional<yuzu::server::ManagementGroup>{};
    std::optional<std::vector<yuzu::server::ManagementGroupMember>> members =
        std::vector<yuzu::server::ManagementGroupMember>{};
};

groups::Deps deps_with_session(bool signed_in, std::shared_ptr<Fakes> f = std::make_shared<Fakes>()) {
    groups::Deps d;
    d.auth_fn = [signed_in](const httplib::Request&,
                            httplib::Response&) -> std::optional<yuzu::server::auth::Session> {
        if (!signed_in)
            return std::nullopt;
        yuzu::server::auth::Session s;
        s.username = "admin";
        return s;
    };
    d.perm_fn = [f](const httplib::Request&, httplib::Response& res, const std::string& type,
                    const std::string& op) {
        ++f->perm_calls;
        CHECK(type == "ManagementGroup");
        CHECK(op == "Read");
        if (!f->perm_ok)
            res.status = 403;
        return f->perm_ok;
    };
    d.fleet_read_fn = [f](const httplib::Request&, httplib::Response& res, const std::string& type,
                          const std::string& op) {
        ++f->fleet_calls;
        CHECK(type == "ManagementGroup");
        CHECK(op == "Read");
        if (!f->fleet_admit) {
            res.status = 403;
            return yuzu::server::authz::FleetReadGate{.admitted = false};
        }
        return yuzu::server::authz::FleetReadGate{.admitted = true, .scope = f->scope};
    };
    d.list_groups_fn = [f] {
        ++f->group_reads;
        return f->groups;
    };
    d.group_fn = [f](const std::string&) {
        ++f->group_reads;
        return f->group;
    };
    d.members_fn = [f](const std::string&) {
        ++f->member_reads;
        return f->members;
    };
    d.member_counts_fn = [f] { return f->counts; };
    return d;
}

yuzu::server::ManagementGroup make_group(std::string id, std::string name, std::string parent = {},
                                         std::string type = "static") {
    yuzu::server::ManagementGroup g;
    g.id = std::move(id);
    g.name = std::move(name);
    g.parent_id = std::move(parent);
    g.membership_type = std::move(type);
    return g;
}

yuzu::server::ManagementGroupMember make_member(std::string agent) {
    yuzu::server::ManagementGroupMember m;
    m.group_id = "0a";
    m.agent_id = std::move(agent);
    m.source = "static";
    return m;
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

    // Each member is required on its own.
    using D = groups::Deps;
    const std::vector<std::function<void(D&)>> unbind = {
        [](D& d) { d.auth_fn = nullptr; },          [](D& d) { d.perm_fn = nullptr; },
        [](D& d) { d.fleet_read_fn = nullptr; },    [](D& d) { d.list_groups_fn = nullptr; },
        [](D& d) { d.group_fn = nullptr; },         [](D& d) { d.members_fn = nullptr; },
        [](D& d) { d.member_counts_fn = nullptr; },
    };
    for (const auto& f : unbind) {
        auto d = deps_with_session(true);
        f(d);
        TestRouteSink s;
        CHECK_THROWS_AS(groups::register_groups_routes(s, std::move(d)), std::invalid_argument);
    }
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

TEST_CASE("groups page: the group list and the existing enrolment fragments are loaded",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    std::vector<std::string> gets;
    const std::regex hx_get(R"re(hx-get="([^"]+)")re");
    for (std::sregex_iterator it(t.begin(), t.end(), hx_get), end; it != end; ++it)
        gets.push_back((*it)[1].str());
    CHECK(gets == std::vector<std::string>{"/fragments/groups/list", "/fragments/settings/pending",
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

TEST_CASE("groups page: htmx-config precedes the htmx script (htmx reads it once; at load)",
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

TEST_CASE("groups page: no inline handlers or style; same-origin scripts only; one shell",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    CHECK_THAT(t, !ContainsSubstring("<style"));
    CHECK_THAT(t, !ContainsSubstring("hx-on"));
    CHECK_THAT(t, !ContainsSubstring("yuzu-dialog"));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(\son[a-z]+\s*=)")));
    CHECK_FALSE(std::regex_search(t, std::regex(R"(#[0-9a-fA-F]{3,8}\b)")));
    CHECK(std::strlen(kGroupsTemplate) < 15000);

    std::vector<std::string> srcs;
    const std::regex script_src(R"re(<script src="([^"]+)")re");
    for (std::sregex_iterator it(t.begin(), t.end(), script_src), end; it != end; ++it)
        srcs.push_back((*it)[1].str());
    CHECK(srcs == std::vector<std::string>{"/static/htmx.js", "/static/sse.js",
                                           "/static/yuzu-groups.js"});

    CHECK(t.find(std::string(yuzu::server::shell::kShellBegin) +
                 std::string(yuzu::server::shell::kShellEnd)) != std::string::npos);
    const std::string baked = kGroupsHtml;
    CHECK(count_of(baked, std::string(yuzu::server::shell::kShellBegin)) == 1);
    CHECK(count_of(baked, "fetch('/api/me')") == 1);
}

// #grp-list is a hook other code relies on: it keeps its id and now loads the list fragment.
TEST_CASE("groups page: #grp-list keeps its id and loads the group list; #grp-side holds the placeholder",
          "[groups][page]") {
    for (const std::string& page : {std::string(kGroupsTemplate), std::string(kGroupsHtml)}) {
        const auto at = page.find("id=\"grp-list\"");
        REQUIRE(at != std::string::npos);
        CHECK(count_of(page, "id=\"grp-list\"") == 1);
        const auto end = page.find("</section>", at);
        REQUIRE(end != std::string::npos);
        const auto panel = page.substr(at, end - at);
        CHECK_THAT(panel, ContainsSubstring("<h2>Management groups</h2>"));
        CHECK_THAT(panel, ContainsSubstring("hx-get=\"/fragments/groups/list\""));
        CHECK_THAT(panel, ContainsSubstring("hx-trigger=\"load\""));
        CHECK_THAT(panel, !ContainsSubstring("/settings"));

        CHECK(count_of(page, "id=\"grp-side\"") == 1);
        const auto side = page.find("id=\"grp-side\"");
        const auto side_end = page.find("</div>\n      <section", side);
        REQUIRE(side_end != std::string::npos);
        CHECK_THAT(page.substr(side, side_end - side),
                   ContainsSubstring(std::string(groups::kSelectGroup)));
    }
}

TEST_CASE("groups page: every loader panel carries its own denied and unavailable sentence",
          "[groups][page]") {
    const std::string t = kGroupsTemplate;
    CHECK(count_of(t, "data-denied=\"") == 5);
    CHECK(count_of(t, "data-unavailable=\"") == 5);
    CHECK(count_of(t, "data-src=\"") == 5);
    CHECK_THAT(t, ContainsSubstring("This is not an empty list."));
}

TEST_CASE("groups page: the template's group-panel sentences are the renderer's constants",
          "[groups][page]") {
    // The template is a const char* literal and cannot name the constexpr views, so pin them.
    const std::string t = kGroupsTemplate;
    // The list and the selected-group panels share the denied sentence, so it appears twice.
    CHECK(count_of(t, "data-denied=\"" + std::string(groups::kGroupsDenied) + "\"") == 2);
    CHECK(count_of(t, "data-unavailable=\"" + std::string(groups::kGroupsUnavailable) + "\"") == 1);
    CHECK(count_of(t, "data-unavailable=\"" + std::string(groups::kDetailUnavailable) + "\"") == 1);
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
    // No new nav group was added for it: the five groups the shell already had.
    std::vector<std::string> titles;
    for (const auto& g : groups_nav)
        titles.emplace_back(g.title);
    CHECK(titles == std::vector<std::string>{"Operate", "Posture", "Estate", "Access", "System"});
    const std::string baked = kGroupsHtml;
    CHECK_THAT(baked, ContainsSubstring("<a class=\"shell-nav on\" href=\"/groups\""));
}

// ---- Fragments ---------------------------------------------------------------------------

TEST_CASE("groups fragments: the list is gated and honest about a failed read and always no-store",
          "[groups][page][fragment]") {
    auto f = std::make_shared<Fakes>();
    TestRouteSink sink;
    groups::register_groups_routes(sink, deps_with_session(true, f));

    SECTION("a refused caller gets the gate's 403 with no-store and no store read") {
        f->perm_ok = false;
        auto res = sink.Get("/fragments/groups/list");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(f->group_reads == 0);
    }
    SECTION("a failed list read is a 200 failbox, not an empty tree") {
        f->groups = std::nullopt;
        auto res = sink.Get("/fragments/groups/list");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    SECTION("a failed count read is a failbox, never a column of zeros") {
        f->groups = std::vector<yuzu::server::ManagementGroup>{make_group("0a", "A")};
        f->counts = std::nullopt;
        auto res = sink.Get("/fragments/groups/list");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    SECTION("both reads answer: the table, with counts") {
        f->groups = std::vector<yuzu::server::ManagementGroup>{make_group("0a", "A")};
        f->counts = std::unordered_map<std::string, std::size_t>{{"0a", 4}};
        auto res = sink.Get("/fragments/groups/list");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK_THAT(res->body, ContainsSubstring("<td>4</td>"));
        CHECK(f->fleet_calls == 0);
    }
}

TEST_CASE("groups fragments: detail validates the id before any gate or read",
          "[groups][page][fragment]") {
    auto f = std::make_shared<Fakes>();
    TestRouteSink sink;
    groups::register_groups_routes(sink, deps_with_session(true, f));

    SECTION("a malformed id is a 400 text/plain, no-store, with no gate and no read") {
        auto res = sink.Get("/fragments/groups/detail?id=ZZ");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("Content-Type") == "text/plain; charset=utf-8");
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(f->perm_calls == 0);
        CHECK(f->group_reads == 0);
    }
    SECTION("no id is the select placeholder, still gated") {
        auto res = sink.Get("/fragments/groups/detail");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(f->perm_calls == 1);
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kSelectGroup)));
        CHECK(f->group_reads == 0);
    }
    SECTION("a refused caller") {
        f->perm_ok = false;
        auto res = sink.Get("/fragments/groups/detail?id=0a");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(f->group_reads == 0);
    }
    SECTION("a failed read keeps its own Retry") {
        f->group = std::unexpected(std::string("down"));
        auto res = sink.Get("/fragments/groups/detail?id=0a");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("data-gact=\"reload\" data-target=\"grp-side\""));
    }
    SECTION("no such group") {
        auto res = sink.Get("/fragments/groups/detail?id=0a");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kNoSuchGroup)));
    }
    SECTION("found with a parent: the parent's name; an unresolvable parent: its id") {
        f->group = std::optional<yuzu::server::ManagementGroup>{make_group("0a", "Child", "0b")};
        // group_fn answers every id with the same group here, so the parent resolves to "Child".
        auto res = sink.Get("/fragments/groups/detail?id=0a");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("<span>Parent</span><b>Child</b>"));

        TestRouteSink sink2;
        auto d = deps_with_session(true, f);
        int call = 0;
        d.group_fn = [&call](const std::string&)
            -> std::expected<std::optional<yuzu::server::ManagementGroup>, std::string> {
            if (call++ == 0)
                return std::optional<yuzu::server::ManagementGroup>{make_group("0a", "Child", "0b")};
            return std::unexpected(std::string("parent read failed"));
        };
        groups::register_groups_routes(sink2, std::move(d));
        auto res2 = sink2.Get("/fragments/groups/detail?id=0a");
        REQUIRE(res2);
        CHECK_THAT(res2->body, ContainsSubstring("<span>Parent</span><b>0b</b>"));
    }
}

TEST_CASE("groups fragments: members are narrowed to the caller's scope with no excluded figure",
          "[groups][page][fragment]") {
    auto f = std::make_shared<Fakes>();
    f->group = std::optional<yuzu::server::ManagementGroup>{make_group("0a", "G")};
    f->members = std::vector<yuzu::server::ManagementGroupMember>{make_member("a1"), make_member("a2"),
                                                                  make_member("a3")};
    TestRouteSink sink;
    groups::register_groups_routes(sink, deps_with_session(true, f));

    SECTION("a malformed id is a 400 before the gate") {
        auto res = sink.Get("/fragments/groups/members?id=ZZ");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("Content-Type") == "text/plain; charset=utf-8");
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(f->fleet_calls == 0);
        CHECK(f->member_reads == 0);
    }
    SECTION("a refused caller: the gate's 403 with no-store and no read") {
        f->fleet_admit = false;
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
        CHECK(f->group_reads == 0);
        CHECK(f->member_reads == 0);
    }
    SECTION("scope {a1}: exactly a1, the scope sentence, and nothing about a2 or a3") {
        f->scope = std::unordered_set<std::string>{"a1"};
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("Members (1)"));
        CHECK_THAT(res->body, ContainsSubstring("<code>a1</code>"));
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kScopedMembers)));
        CHECK_THAT(res->body, !ContainsSubstring("a2"));
        CHECK_THAT(res->body, !ContainsSubstring("a3"));
        CHECK_THAT(res->body, !ContainsSubstring("3"));
        CHECK_THAT(res->body, !ContainsSubstring("not shown"));
    }
    SECTION("an engaged EMPTY scope: zero rows, the sentence, no figure") {
        f->scope = std::unordered_set<std::string>{};
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("Members (0)"));
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kScopedMembers)));
        for (const char* gone : {"a1", "a2", "a3", "3", "not shown"})
            CHECK_THAT(res->body, !ContainsSubstring(gone));
    }
    SECTION("no scope: all rows and no scope sentence; perm_fn is never consulted") {
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring("Members (3)"));
        CHECK_THAT(res->body, !ContainsSubstring(std::string(groups::kScopedMembers)));
        CHECK(f->perm_calls == 0);
        CHECK(f->fleet_calls == 1);
    }
    SECTION("no such group: the members read never happens") {
        f->group = std::optional<yuzu::server::ManagementGroup>{};
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kNoSuchGroup)));
        CHECK(f->member_reads == 0);
    }
    SECTION("a failed members read is a failbox") {
        f->members = std::nullopt;
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    }
    SECTION("a dynamic group with no rows says membership is not computed") {
        f->group = std::optional<yuzu::server::ManagementGroup>{make_group("0a", "G", {}, "dynamic")};
        f->members = std::vector<yuzu::server::ManagementGroupMember>{};
        auto res = sink.Get("/fragments/groups/members?id=0a");
        REQUIRE(res);
        CHECK_THAT(res->body, ContainsSubstring(std::string(groups::kDynamicNoMembers)));
    }
}
