/**
 * @file test_groups_render.cpp
 * @brief Groups page: the pure group tree and the list / detail / members renderers. No store,
 *        no route, no clock.
 */

#include "groups_render.hpp"
#include "url_attr_scan.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <regex>
#include <set>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::groups;

namespace {

constexpr const char* kXss = "<img src=x onerror=1>";

ManagementGroup grp(std::string id, std::string name, std::string parent = {},
                    std::string type = "static") {
    ManagementGroup g;
    g.id = std::move(id);
    g.name = std::move(name);
    g.parent_id = std::move(parent);
    g.membership_type = std::move(type);
    g.created_by = "tester";
    g.created_at = 0;
    g.updated_at = 0;
    return g;
}

ManagementGroupMember member(std::string agent, std::string source = "static") {
    ManagementGroupMember m;
    m.group_id = "aa";
    m.agent_id = std::move(agent);
    m.source = std::move(source);
    return m;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

std::vector<std::string> ids_of(const std::vector<TreeRow>& rows) {
    std::vector<std::string> out;
    for (const auto& r : rows)
        out.push_back(r.group->id);
    return out;
}

// Post-condition every tree must meet: every input group exactly once, depth within the cap.
void check_complete(const std::vector<ManagementGroup>& in, const std::vector<TreeRow>& rows) {
    REQUIRE(rows.size() == in.size());
    std::set<std::string> seen;
    for (const auto& r : rows) {
        CHECK(seen.insert(r.group->id).second);
        CHECK(r.depth >= 0);
        CHECK(r.depth <= kTreeDepthCap);
    }
}

} // namespace

TEST_CASE("group_tree: root first, then by name, children by name, depth increments",
          "[groups][render]") {
    const std::vector<ManagementGroup> in = {
        grp("0c", "Zulu", "000000000000"),    grp("0a", "Alpha", "000000000000"),
        grp("000000000000", "Root"),          grp("0b", "Beta", "0a"),
        grp("0d", "Lonely", "0000dead0000"), // orphan: parent not in the list
    };
    const auto rows = group_tree(in);
    check_complete(in, rows);
    REQUIRE(rows.size() == 5);
    CHECK(rows[0].group->id == "000000000000");
    CHECK(rows[0].depth == 0);
    // Root's children by name (Alpha, Zulu), Alpha's child nested under Alpha.
    CHECK(ids_of(rows)[1] == "0a");
    CHECK(rows[1].depth == 1);
    CHECK(ids_of(rows)[2] == "0b");
    CHECK(rows[2].depth == 2);
    CHECK(ids_of(rows)[3] == "0c");
    // The orphan stays a visible top-level row.
    const auto orphan = std::find_if(rows.begin(), rows.end(),
                                     [](const TreeRow& r) { return r.group->id == "0d"; });
    REQUIRE(orphan != rows.end());
    CHECK(orphan->depth == 0);
}

TEST_CASE("group_tree: a rootless cycle and an over-deep chain are swept in, never dropped",
          "[groups][render]") {
    SECTION("2-cycle") {
        const std::vector<ManagementGroup> in = {grp("0a", "A", "0b"), grp("0b", "B", "0a")};
        const auto rows = group_tree(in);
        check_complete(in, rows);
        CHECK(rows[0].depth == 0);
    }
    SECTION("self parent") {
        const std::vector<ManagementGroup> in = {grp("0a", "A", "0a")};
        check_complete(in, group_tree(in));
    }
    SECTION("20-deep chain") {
        std::vector<ManagementGroup> in;
        in.push_back(grp("000000000000", "Root"));
        for (int i = 1; i < 20; ++i)
            in.push_back(grp("0" + std::to_string(100 + i), "G" + std::to_string(100 + i),
                             i == 1 ? "000000000000" : "0" + std::to_string(100 + i - 1)));
        REQUIRE(in.size() == 20);
        const auto rows = group_tree(in);
        check_complete(in, rows);
        const int deepest = std::max_element(rows.begin(), rows.end(),
                                             [](const TreeRow& a, const TreeRow& b) {
                                                 return a.depth < b.depth;
                                             })->depth;
        CHECK(deepest == kTreeDepthCap);
        // The overflow was re-rooted.
        CHECK(std::count_if(rows.begin(), rows.end(), [](const TreeRow& r) { return r.depth == 0; }) >=
              2);
    }
    SECTION("deterministic") {
        const std::vector<ManagementGroup> in = {grp("0a", "A", "0b"), grp("0b", "B", "0a"),
                                                 grp("0c", "C")};
        CHECK(ids_of(group_tree(in)) == ids_of(group_tree(in)));
    }
}

TEST_CASE("is_group_id: 1-64 lowercase hex only", "[groups][render]") {
    CHECK(is_group_id("0"));
    CHECK(is_group_id("000000000000"));
    CHECK(is_group_id(std::string(64, 'a')));
    CHECK_FALSE(is_group_id(""));
    CHECK_FALSE(is_group_id("ABC"));
    CHECK_FALSE(is_group_id(std::string(65, 'a')));
    CHECK_FALSE(is_group_id(".."));
    CHECK_FALSE(is_group_id("a/b"));
    CHECK_FALSE(is_group_id("xyz"));
}

TEST_CASE("render_group_list: rows, select buttons, type pill, counts, escaping", "[groups][render]") {
    GroupList l;
    l.groups = {grp("000000000000", "Root"), grp("0a", std::string("Dyn") + kXss, "000000000000", "dynamic")};
    l.member_counts = {{"000000000000", 7}};
    const auto html = render_group_list(l);
    CHECK(count_of(html, "data-gact=\"select\"") == 2);
    CHECK_THAT(html, ContainsSubstring("data-id=\"000000000000\""));
    CHECK_THAT(html, ContainsSubstring("<span class=\"pill tag\">dynamic</span>"));
    CHECK_THAT(html, ContainsSubstring("<td>7</td>"));
    CHECK_THAT(html, ContainsSubstring("<td>0</td>")); // absent from the map
    CHECK_THAT(html, ContainsSubstring("<span class=\"d1\">"));
    CHECK_THAT(html, !ContainsSubstring("<img"));
    CHECK_THAT(html, ContainsSubstring("&lt;img"));
}

TEST_CASE("render_group_list: cap, empty and unavailable stay distinct", "[groups][render]") {
    SECTION("501 groups -> 500 rows and a note") {
        GroupList l;
        for (int i = 0; i < 501; ++i)
            l.groups.push_back(grp("0" + std::to_string(1000 + i), "G" + std::to_string(1000 + i)));
        const auto html = render_group_list(l);
        CHECK(count_of(html, "data-gact=\"select\"") == 500);
        CHECK_THAT(html, ContainsSubstring("first 500 of 501"));
    }
    SECTION("empty") {
        const auto html = render_group_list(GroupList{});
        CHECK_THAT(html, ContainsSubstring("No groups."));
        CHECK_THAT(html, !ContainsSubstring("failbox"));
    }
    SECTION("unavailable") {
        const auto html = render_group_list(Unavailable{});
        CHECK_THAT(html, ContainsSubstring("class=\"failbox\" role=\"alert\""));
        CHECK_THAT(html, ContainsSubstring("data-gact=\"reload\" data-target=\"grp-list\""));
        CHECK_THAT(html, !ContainsSubstring("<table"));
        CHECK_THAT(html, !ContainsSubstring("No groups."));
    }
}

TEST_CASE("render_group_detail: fields, parent forms, dynamic rule", "[groups][render]") {
    SECTION("static group with a resolved parent") {
        GroupDetail d{grp("0a", "Child", "0b"), std::string("Parent Name")};
        d.group.description = "About";
        d.group.created_at = 86400;
        const auto html = render_group_detail(d);
        for (const char* label : {"Name", "Type", "Parent", "Description", "Created by", "Created",
                                  "Updated"})
            CHECK_THAT(html, ContainsSubstring(std::string("<span>") + label + "</span>"));
        CHECK_THAT(html, ContainsSubstring("Parent Name"));
        CHECK_THAT(html, ContainsSubstring("About"));
        CHECK_THAT(html, ContainsSubstring("1970-01-02 00:00 UTC"));
        CHECK_THAT(html, !ContainsSubstring("<span>Rule</span>"));
    }
    SECTION("unresolved parent shows the id; no parent says so") {
        const auto unresolved = render_group_detail(GroupDetail{grp("0a", "Child", "0b"), std::nullopt});
        CHECK_THAT(unresolved, ContainsSubstring("<b>0b</b>"));
        const auto none = render_group_detail(GroupDetail{grp("0a", "Child"), std::nullopt});
        CHECK_THAT(none, ContainsSubstring("No parent"));
        CHECK_THAT(none, ContainsSubstring("<b>None</b>"));
    }
    SECTION("dynamic group shows the stored rule and the honest note") {
        auto g = grp("0a", "Dyn", {}, "dynamic");
        g.scope_expression = "os == 'linux'";
        const auto html = render_group_detail(GroupDetail{g, std::nullopt});
        CHECK_THAT(html, ContainsSubstring("<span>Rule</span>"));
        CHECK_THAT(html, ContainsSubstring("<code>os == &#39;linux&#39;</code>"));
        CHECK_THAT(html, ContainsSubstring(std::string(kRuleNote)));
    }
    SECTION("escaping") {
        auto g = grp("0a", kXss);
        g.description = kXss;
        g.created_by = kXss;
        const auto html = render_group_detail(GroupDetail{g, std::nullopt});
        CHECK_THAT(html, !ContainsSubstring("<img"));
    }
}

TEST_CASE("render_group_detail: NotFound, Unavailable and the placeholder are distinct",
          "[groups][render]") {
    const auto nf = render_group_detail(NotFound{});
    const auto un = render_group_detail(Unavailable{});
    const auto sel = render_select_group();
    CHECK_THAT(nf, ContainsSubstring(std::string(kNoSuchGroup)));
    CHECK_THAT(nf, !ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring("data-gact=\"reload\" data-target=\"grp-side\""));
    CHECK_THAT(un, !ContainsSubstring("hx-get"));
    CHECK_THAT(sel, ContainsSubstring(std::string(kSelectGroup)));
    CHECK(nf != un);
    CHECK(nf != sel);
    CHECK(un != sel);
}

TEST_CASE("render_group_detail: the members loader shell is its own panel", "[groups][render]") {
    const auto html = render_group_detail(GroupDetail{grp("0a", "G"), std::nullopt});
    CHECK_THAT(html, ContainsSubstring("id=\"grp-members\""));
    CHECK_THAT(html, ContainsSubstring("hx-trigger=\"load\""));
    const auto urls = yuzu::test::url_attr_values(html);
    REQUIRE(urls.size() == 1);
    CHECK(urls[0] == "/fragments/groups/members?id=0a");
    CHECK_THAT(html, ContainsSubstring("data-src=\"/fragments/groups/members?id=0a\""));
    CHECK_THAT(html, ContainsSubstring("data-denied=\""));
    CHECK_THAT(html, ContainsSubstring("data-unavailable=\""));
}

TEST_CASE("render_members: rows, links, source, heading count", "[groups][render]") {
    MembersView v;
    v.membership_type = "static";
    v.rows = {member("agent a&b", "static"), member("agent-2", "dynamic")};
    const auto html = render_members(v);
    CHECK_THAT(html, ContainsSubstring("Members (2)"));
    const auto urls = yuzu::test::url_attr_values(html);
    REQUIRE(urls.size() == 2);
    CHECK(urls[0] == "/hardware/ci?id=agent%20a%26b");
    CHECK_THAT(html, ContainsSubstring("<td>dynamic</td>"));
    CHECK_THAT(html, !ContainsSubstring(std::string(kScopedMembers)));
}

TEST_CASE("render_members: a scoped caller sees the fixed sentence and no excluded-row figure",
          "[groups][render]") {
    MembersView v;
    v.membership_type = "static";
    v.scoped = true;
    v.rows = {member("a1")};
    auto html = render_members(v);
    CHECK_THAT(html, ContainsSubstring("Members (1)"));
    CHECK_THAT(html, ContainsSubstring(std::string(kScopedMembers)));
    CHECK_THAT(html, !ContainsSubstring("not shown"));

    v.rows.clear();
    html = render_members(v);
    CHECK_THAT(html, ContainsSubstring("Members (0)"));
    CHECK_THAT(html, ContainsSubstring(std::string(kScopedMembers)));
    CHECK_THAT(html, ContainsSubstring("No members."));

    v.scoped = false;
    CHECK_THAT(render_members(v), !ContainsSubstring(std::string(kScopedMembers)));
}

TEST_CASE("render_members: cap, empty copy and unavailable", "[groups][render]") {
    SECTION("201 rows -> 200 drawn with a note") {
        MembersView v;
        v.membership_type = "static";
        for (int i = 0; i < 201; ++i)
            v.rows.push_back(member("ag" + std::to_string(i)));
        const auto html = render_members(v);
        CHECK(count_of(html, "/hardware/ci?id=") == 200);
        CHECK_THAT(html, ContainsSubstring("first 200 of 201"));
        CHECK_THAT(html, ContainsSubstring("Members (201)"));
    }
    SECTION("empty dynamic group says membership is not computed") {
        MembersView v;
        v.membership_type = "dynamic";
        CHECK_THAT(render_members(v), ContainsSubstring(std::string(kDynamicNoMembers)));
    }
    SECTION("empty static group") {
        MembersView v;
        v.membership_type = "static";
        const auto html = render_members(v);
        CHECK_THAT(html, ContainsSubstring("No members."));
        CHECK_THAT(html, !ContainsSubstring(std::string(kDynamicNoMembers)));
    }
    SECTION("unavailable is a failbox, never a count") {
        const auto html = render_members(Unavailable{});
        CHECK_THAT(html, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(html, ContainsSubstring("data-gact=\"reload\" data-target=\"grp-members\""));
        CHECK_THAT(html, !ContainsSubstring("0"));
        CHECK_THAT(html, !ContainsSubstring("<table"));
    }
    SECTION("not found") {
        const auto html = render_members(NotFound{});
        CHECK_THAT(html, ContainsSubstring(std::string(kNoSuchGroup)));
        CHECK_THAT(html, !ContainsSubstring("role=\"alert\""));
    }
}

TEST_CASE("renderers: no mutating control in any state", "[groups][render]") {
    GroupList l;
    l.groups = {grp("000000000000", "Root"), grp("0a", "Dyn", "000000000000", "dynamic")};
    MembersView mv;
    mv.membership_type = "static";
    mv.scoped = true;
    mv.rows = {member("a1")};
    const std::vector<std::string> outputs = {
        render_group_list(l),
        render_group_list(GroupList{}),
        render_group_list(Unavailable{}),
        render_group_detail(GroupDetail{l.groups[1], std::string("Root")}),
        render_group_detail(NotFound{}),
        render_group_detail(Unavailable{}),
        render_select_group(),
        render_members(mv),
        render_members(MembersView{}),
        render_members(NotFound{}),
        render_members(Unavailable{}),
    };
    const std::regex handler(R"(\son[a-z]+\s*=)");
    for (const auto& html : outputs) {
        for (const char* banned : {"hx-post", "hx-put", "hx-delete", "<form", "hx-on"})
            CHECK_THAT(html, !ContainsSubstring(banned));
        CHECK_FALSE(std::regex_search(html, handler));
        // No button carries an hx-get: a Retry is the page's own data-gact=reload.
        for (auto p = html.find("<button"); p != std::string::npos; p = html.find("<button", p + 1))
            CHECK(html.substr(p, html.find('>', p) - p).find("hx-get") == std::string::npos);
    }
}
