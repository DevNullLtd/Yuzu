/**
 * @file test_access_render.cpp
 * @brief Pure tests for the Access renderers (access_render.{hpp,cpp}): the Users list and
 *        the Account panel of /access/users.
 *
 * What these pin, in order of how much a regression would hurt:
 *   - a store that did not answer is never drawn as an empty table (Unavailable != empty);
 *   - every user-controlled byte is escaped in text AND attributes, and `?username=` is
 *     percent-encoded (an `oidc:<iss>#<sub>` principal carries a `#`);
 *   - this read-only half offers no mutation control, and never touches credential bytes;
 *   - an SSO/SCIM row is never offered a local-account control.
 */

#include "access_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
using namespace yuzu::server::access;

namespace {

std::size_t count_of(std::string_view hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

auth::UserEntry user(std::string name, auth::Role role = auth::Role::user,
                     std::string source = "local") {
    auth::UserEntry u;
    u.username = std::move(name);
    u.role = role;
    u.identity_source = std::move(source);
    return u;
}

/// The `<tr data-username="NAME">...</tr>` of one row (NAME already escaped as rendered).
std::string row_of(const std::string& html, const std::string& escaped_name) {
    const std::string open = "<tr data-username=\"" + escaped_name + "\">";
    const auto b = html.find(open);
    REQUIRE(b != std::string::npos);
    return html.substr(b, html.find("</tr>", b) - b);
}

std::string list_html(std::vector<auth::UserEntry> users, std::string self = "alice") {
    return render_users_list(UsersList{std::move(users), std::move(self)});
}

std::string detail_html(auth::UserEntry u, bool is_self = false) {
    return render_user_detail(UserDetail{std::move(u), is_self});
}

/// Every rendered state of both panels, for the corpus-wide hygiene cases.
std::vector<std::string> every_output() {
    return {
        list_html({user("alice", auth::Role::admin), user("bob"), user("oidc:https://x/y#sub", auth::Role::user, "oidc")}),
        list_html({}),
        render_users_list(Unavailable{}),
        detail_html(user("bob")),
        detail_html(user("alice", auth::Role::admin), true),
        detail_html(user("oidc:https://x/y#sub", auth::Role::user, "oidc")),
        render_user_detail(NotFound{}),
        render_user_detail(Unavailable{}, "/fragments/access/users/detail?username=bob"),
        render_select_user(),
    };
}

} // namespace

// ── Users list ──────────────────────────────────────────────────────────────

TEST_CASE("access list: one row per user, four columns, Manage encodes the username",
          "[access][render]") {
    const auto html = list_html({user("alice", auth::Role::admin), user("bob"),
                                 user("oidc:https://x/y#sub", auth::Role::user, "oidc")});
    CHECK(count_of(html, "<th") == 4); // User, Source, Account role, actions
    CHECK(count_of(html, "<tr data-username=") == 3);
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">3 accounts</span>"));
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/access/users/detail?username=bob\""));
    CHECK_THAT(html, ContainsSubstring("username=oidc%3Ahttps%3A%2F%2Fx%2Fy%23sub\""));
    CHECK_THAT(html, ContainsSubstring("hx-target=\"#acc-detail\""));
    // The page's own two roles, as the legacy account role.
    CHECK_THAT(row_of(html, "alice"), ContainsSubstring("<span class=\"pill tag\">admin</span>"));
    CHECK_THAT(row_of(html, "bob"), ContainsSubstring("<span class=\"pill tag\">user</span>"));
}

TEST_CASE("access list: a single account is not pluralised", "[access][render]") {
    CHECK_THAT(list_html({user("alice")}), ContainsSubstring("<span class=\"sub\">1 account</span>"));
}

TEST_CASE("access list: the caller's own row is a pill with no Manage control", "[access][render]") {
    const auto html = list_html({user("alice", auth::Role::admin), user("bob")}, "alice");
    const auto self = row_of(html, "alice");
    CHECK_THAT(self, ContainsSubstring("Current user"));
    CHECK_THAT(self, !ContainsSubstring("Manage"));
    CHECK_THAT(self, !ContainsSubstring("hx-get"));
    CHECK_THAT(row_of(html, "bob"), ContainsSubstring("Manage"));
    CHECK_THAT(row_of(html, "bob"), !ContainsSubstring("Current user"));
}

TEST_CASE("access list: every non-local source is labelled and flagged as auto-provisioned",
          "[access][render]") {
    struct Case {
        const char* source;
        const char* label; // rendered pill text
        bool titled;       // carries the "Auto-provisioned via SSO" title
    };
    const Case cases[] = {{"local", "Local", false}, {"oidc", "OIDC", true}, {"saml", "SAML", true},
                          {"ad", "AD", true},        {"scim", "SCIM", true},
                          {"foo<x>", "foo&lt;x&gt;", true}};
    for (const auto& c : cases) {
        INFO(c.source);
        const auto html = list_html({user("u1", auth::Role::user, c.source)});
        const auto row = row_of(html, "u1");
        CHECK_THAT(row, ContainsSubstring(std::string(">") + c.label + "</span>"));
        CHECK((row.find("Auto-provisioned via SSO") != std::string::npos) == c.titled);
        // The row is kept and still has its Manage control, whatever the source.
        CHECK_THAT(row, ContainsSubstring("Manage"));
    }
}

TEST_CASE("access list: rows past the render cap are dropped and the banner says so",
          "[access][render]") {
    std::vector<auth::UserEntry> users;
    for (std::size_t i = 0; i < kUsersRenderCap + 1; ++i)
        users.push_back(user("u" + std::to_string(i)));
    const auto html = list_html(std::move(users));
    CHECK(count_of(html, "<tr data-username=") == kUsersRenderCap);
    CHECK_THAT(html, ContainsSubstring("Showing the first 500 of 501 accounts."));
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">501 accounts</span>"));
    CHECK_THAT(html, !ContainsSubstring("u500\""));
    // At the cap exactly: no banner.
    std::vector<auth::UserEntry> exact;
    for (std::size_t i = 0; i < kUsersRenderCap; ++i)
        exact.push_back(user("u" + std::to_string(i)));
    CHECK_THAT(list_html(std::move(exact)), !ContainsSubstring("Showing the first"));
}

TEST_CASE("access list: an empty answer is a true empty, never the unavailable text",
          "[access][render]") {
    const auto html = list_html({});
    CHECK_THAT(html, ContainsSubstring("<thead>"));
    CHECK_THAT(html, ContainsSubstring("No active accounts were returned."));
    CHECK_THAT(html, !ContainsSubstring(std::string(kUsersUnavailable)));
    CHECK_THAT(html, !ContainsSubstring("role=\"alert\""));
}

TEST_CASE("access list: an unanswered store is a red box with Retry and no table",
          "[access][render]") {
    const auto html = render_users_list(Unavailable{});
    CHECK_THAT(html, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(html, ContainsSubstring(std::string(kUsersUnavailable)));
    CHECK_THAT(html, ContainsSubstring("data-act=\"reload\" data-target=\"acc-users\""));
    CHECK_THAT(html, !ContainsSubstring("<table"));
    CHECK_THAT(html, !ContainsSubstring("<tr"));
    CHECK_THAT(html, !ContainsSubstring("No active accounts"));
}

// ── Account panel ───────────────────────────────────────────────────────────

TEST_CASE("access detail: a local account shows its role in a disabled select", "[access][render]") {
    const auto html = detail_html(user("bob", auth::Role::admin));
    CHECK_THAT(html, ContainsSubstring("<h2 class=\"long\">bob</h2>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">Local account</span>"));
    CHECK_THAT(html, ContainsSubstring("<select id=\"acc-role\" disabled>"));
    CHECK_THAT(html, ContainsSubstring("<option value=\"admin\" selected>Admin</option>"));
    CHECK_THAT(html, ContainsSubstring("<option value=\"user\">User</option>"));
    CHECK(count_of(html, "<option") == 2);
    CHECK_THAT(html, ContainsSubstring("cannot be changed from this page yet"));
    // The role the account actually holds is the selected one, for either value.
    CHECK_THAT(detail_html(user("bob", auth::Role::user)),
               ContainsSubstring("<option value=\"user\" selected>User</option>"));
}

TEST_CASE("access detail: the caller's own account says why the role is fixed", "[access][render]") {
    const auto html = detail_html(user("alice", auth::Role::admin), /*is_self=*/true);
    CHECK_THAT(html, ContainsSubstring("You cannot change your own role."));
    CHECK_THAT(html, ContainsSubstring("disabled"));
}

TEST_CASE("access detail: an SSO account is labelled and carries the SSO reason",
          "[access][render]") {
    const auto html = detail_html(user("oidc:https://x/y#sub", auth::Role::user, "oidc"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">OIDC account</span>"));
    CHECK_THAT(html, ContainsSubstring("Not available for SSO or SCIM accounts here."));
    CHECK_THAT(html, !ContainsSubstring("from this page yet"));
}

TEST_CASE("access detail: not found, unavailable and unselected are three different panels",
          "[access][render]") {
    const auto nf = render_user_detail(NotFound{});
    const auto un = render_user_detail(Unavailable{}, "/fragments/access/users/detail?username=bob");
    const auto sel = render_select_user();

    CHECK_THAT(nf, ContainsSubstring("No such user"));
    CHECK_THAT(nf, !ContainsSubstring("role=\"alert\""));

    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kDetailUnavailable)));
    CHECK_THAT(un, ContainsSubstring("hx-get=\"/fragments/access/users/detail?username=bob\""));
    CHECK_THAT(un, !ContainsSubstring("No such user"));

    CHECK_THAT(sel, ContainsSubstring(std::string(kSelectUser)));
    CHECK_THAT(sel, !ContainsSubstring("role=\"alert\""));
    CHECK(nf != un);
    CHECK(nf != sel);

    // No retry URL: no Retry button at all (a button that does nothing is worse than none).
    CHECK_THAT(render_user_detail(Unavailable{}), !ContainsSubstring("<button"));
}

// ── Hygiene across every state ──────────────────────────────────────────────

TEST_CASE("access render: this read-only half offers no mutation control", "[access][render]") {
    static const std::regex mut(R"re(data-act="(add|remove|role|revoke)"|hx-(post|put|delete|patch)|Reset password|Unlock|elevat)re",
                                std::regex::icase);
    for (const auto& html : every_output()) {
        CHECK_FALSE(std::regex_search(html, mut));
        CHECK_THAT(html, !ContainsSubstring("Add user"));
        CHECK_THAT(html, !ContainsSubstring("Remove"));
    }
}

TEST_CASE("access render: no inline handlers, hx-on or javascript: URLs", "[access][render]") {
    static const std::regex bad(R"re(\son[a-z]+\s*=|hx-on|javascript:)re", std::regex::icase);
    for (const auto& html : every_output())
        CHECK_FALSE(std::regex_search(html, bad));
}

TEST_CASE("access render: credential material on the row is never read", "[access][render]") {
    auto u = user("bob");
    u.salt_hex = "cafebabe5a17";
    u.hash_hex = "deadbeefhash";
    const auto list = list_html({u});
    const auto det = detail_html(u);
    for (const auto& html : {list, det}) {
        CHECK_THAT(html, !ContainsSubstring("cafebabe5a17"));
        CHECK_THAT(html, !ContainsSubstring("deadbeefhash"));
    }
}

TEST_CASE("access render: hostile usernames and sources are escaped in text and attributes",
          "[access][render]") {
    const std::string nasty = "<script>alert(1)</script>\"'&";
    const std::string nasty_esc = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;";
    const auto list = list_html({user(nasty, auth::Role::user, nasty)});
    const auto det = detail_html(user(nasty, auth::Role::user, nasty));
    for (const auto& html : {list, det}) {
        CHECK_THAT(html, ContainsSubstring(nasty_esc));
        CHECK_THAT(html, !ContainsSubstring("<script>"));
        CHECK_THAT(html, !ContainsSubstring("alert(1)</script>"));
    }
    // The attribute form, exactly: data-username and the title's identity_source.
    CHECK_THAT(list, ContainsSubstring("<tr data-username=\"" + nasty_esc + "\">"));
    CHECK_THAT(list, ContainsSubstring("identity_source=" + nasty_esc + ")\""));

    // An embedded NUL and a 10 KB name survive without truncating the document.
    const std::string nul("a\0b", 3);
    const auto with_nul = list_html({user(nul)});
    CHECK_THAT(with_nul, ContainsSubstring("</table>"));
    CHECK_THAT(with_nul, ContainsSubstring("username=a%00b\""));
    const auto big = list_html({user(std::string(10 * 1024, 'x'))});
    CHECK_THAT(big, ContainsSubstring("</table>"));
    // Cell text, the data attribute and the Manage URL.
    CHECK(count_of(big, std::string(10 * 1024, 'x')) == 3);
}

TEST_CASE("access url_q: RFC 3986 unreserved kept, everything else uppercase %XX",
          "[access][render]") {
    CHECK(url_q("AZaz09-._~") == "AZaz09-._~");
    CHECK(url_q("oidc:https://x/y#sub") == "oidc%3Ahttps%3A%2F%2Fx%2Fy%23sub");
    CHECK(url_q("a b&c=d") == "a%20b%26c%3Dd");
    CHECK(url_q("\xE2\x82\xAC") == "%E2%82%AC"); // bytes, not chars
    CHECK(url_q("").empty());
}

TEST_CASE("access source_label: the five known sources, empty for anything else",
          "[access][render]") {
    CHECK(source_label("local") == "Local");
    CHECK(source_label("oidc") == "OIDC");
    CHECK(source_label("saml") == "SAML");
    CHECK(source_label("ad") == "AD");
    CHECK(source_label("scim") == "SCIM");
    CHECK(source_label("").empty());
    CHECK(source_label("OIDC").empty()); // tokens are lower-case in the store
    CHECK(source_label("ldap").empty());
}
