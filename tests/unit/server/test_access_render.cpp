/**
 * @file test_access_render.cpp
 * @brief Pure tests for the Access renderers (access_render.{hpp,cpp}): the Users list and
 *        the Account panel of /access/users.
 *
 * What these pin, in order of how much a regression would hurt:
 *   - a store that did not answer is never drawn as an empty table (Unavailable != empty);
 *   - every user-controlled byte is escaped in text AND attributes, and `?username=` is
 *     percent-encoded (an `oidc:<iss>#<sub>` principal carries a `#`);
 *   - the write controls (add, remove, change role, revoke) appear only where the server would
 *     accept them: never on the caller's own row, and never a local-account control on an SSO row;
 *   - credential bytes are never touched.
 */

#include "access_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
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

RbacRole role(std::string name, std::string description, bool is_system = true) {
    RbacRole r;
    r.name = std::move(name);
    r.description = std::move(description);
    r.is_system = is_system;
    return r;
}

Permission perm(std::string type, std::string op, std::string effect = "allow") {
    Permission p;
    p.securable_type = std::move(type);
    p.operation = std::move(op);
    p.effect = std::move(effect);
    return p;
}

PrincipalRole grant(std::string type, std::string id, std::string role) {
    PrincipalRole g;
    g.principal_type = std::move(type);
    g.principal_id = std::move(id);
    g.role_name = std::move(role);
    return g;
}

AssignmentsView view_of(std::vector<PrincipalRole> rows, std::string self = "alice", bool can_assign = true,
                        std::vector<std::string> assignable = {"Operator", "Viewer"}) {
    AssignmentsView v;
    v.rows = std::move(rows);
    v.self = std::move(self);
    v.can_assign = can_assign;
    v.assignable = std::move(assignable);
    return v;
}

std::string assign_html(AssignmentsView v, std::size_t cap = kAssignmentsRenderCap) {
    return render_assignments(std::move(v), cap);
}

/// The `<tr ...>...</tr>` of the Nth data row.
std::string nth_row(const std::string& html, std::size_t n) {
    std::size_t at = 0;
    for (std::size_t i = 0; i <= n; ++i) {
        at = html.find("<tr data-principal-type=", i == 0 ? 0 : at + 1);
        REQUIRE(at != std::string::npos);
    }
    return html.substr(at, html.find("</tr>", at) - at);
}

std::string roles_html(std::vector<RbacRole> roles) {
    return render_roles_list(RolesList{std::move(roles)});
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
        roles_html({role("Operator", "Run things"), role("Op/erator", "x")}),
        render_roles_list(Unavailable{}),
        render_role_permissions(RolePerms{"Operator", {perm("Tag", "Read"), perm("Tag", "Write", "deny")}}),
        render_role_permissions(RolePerms{"Operator", {}}),
        render_role_permissions(NotFound{}),
        render_role_permissions(Unavailable{}, "/fragments/access/roles/permissions?role=Operator"),
        render_select_role(),
        assign_html(view_of({grant("user", "bob", "Viewer"), grant("group", "ops", "Operator")})),
        assign_html(view_of({})),
        render_assignments(Unavailable{}),
        render_your_account("alice", "local"),
        render_your_account("oidc:https://x/y#sub", "oidc"),
    };
}

} // namespace

// ── Users list ──────────────────────────────────────────────────────────────

TEST_CASE("access list: one row per user, four columns, Manage encodes the username",
          "[access][render]") {
    const auto html = list_html({user("alice", auth::Role::admin), user("bob"),
                                 user("oidc:https://x/y#sub", auth::Role::user, "oidc")});
    CHECK(count_of(html, "<th>") == 5); // User, Source, Account role, RBAC roles, actions
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

TEST_CASE("access detail: a local account shows its role in an enabled select", "[access][render]") {
    const auto html = detail_html(user("bob", auth::Role::admin));
    CHECK_THAT(html, ContainsSubstring("<h2 class=\"long\">bob</h2>"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">Local account</span>"));
    CHECK_THAT(html, ContainsSubstring("<select id=\"acc-role\"><option"));
    CHECK_THAT(html, ContainsSubstring("<option value=\"admin\" selected>Admin</option>"));
    CHECK_THAT(html, ContainsSubstring("<option value=\"user\">User</option>"));
    CHECK(count_of(html, "<option") == 2);
    // The role the account actually holds is the selected one, for either value.
    CHECK_THAT(detail_html(user("bob", auth::Role::user)),
               ContainsSubstring("<option value=\"user\" selected>User</option>"));
}

TEST_CASE("access detail: the caller's own account says why the role is fixed", "[access][render]") {
    const auto html = detail_html(user("alice", auth::Role::admin), /*is_self=*/true);
    CHECK_THAT(html, ContainsSubstring("You cannot change your own role."));
    CHECK_THAT(html, ContainsSubstring("<select id=\"acc-role\" disabled title=\""));
    // Nothing that would end or remove the session the caller is using.
    CHECK_THAT(html, !ContainsSubstring("data-act="));
}

TEST_CASE("access detail: an SSO account is labelled and carries the SSO reason",
          "[access][render]") {
    const auto html = detail_html(user("oidc:https://x/y#sub", auth::Role::user, "oidc"));
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">OIDC account</span>"));
    CHECK_THAT(html, ContainsSubstring("Not available for SSO or SCIM accounts here."));
    CHECK_THAT(html, ContainsSubstring("<select id=\"acc-role\" disabled title=\""));
    // The sessions route takes a principal, so Revoke stays; the local-account routes refuse
    // an SSO principal, so role change and Remove are not offered.
    CHECK_THAT(html, ContainsSubstring("data-act=\"revoke\""));
    CHECK_THAT(html, !ContainsSubstring("data-act=\"role\""));
    CHECK_THAT(html, !ContainsSubstring("data-act=\"remove\""));
}

TEST_CASE("access detail: the write controls follow the account's source and identity",
          "[access][render]") {
    struct Case {
        const char* source;
        bool self;
        bool role, revoke, remove;
    };
    // local/other, own/not own -> which of the three detail controls render.
    const Case cases[] = {
        {"local", false, true, true, true},   {"local", true, false, false, false},
        {"oidc", false, false, true, false},  {"saml", false, false, true, false},
        {"ad", false, false, true, false},    {"scim", false, false, true, false},
        {"foo<x>", false, false, true, false},
    };
    for (const auto& c : cases) {
        INFO(c.source << (c.self ? " (self)" : ""));
        const auto html = detail_html(user("bob", auth::Role::user, c.source), c.self);
        CHECK((html.find("data-act=\"role\"") != std::string::npos) == c.role);
        CHECK((html.find("data-act=\"revoke\"") != std::string::npos) == c.revoke);
        CHECK((html.find("data-act=\"remove\"") != std::string::npos) == c.remove);
    }
}

TEST_CASE("access list: Add user is in the header; Remove only on a local row that is not the caller's",
          "[access][render]") {
    const auto html = list_html({user("alice", auth::Role::admin), user("bob"),
                                 user("oidc:https://x/y#sub", auth::Role::user, "oidc")});
    CHECK_THAT(html, ContainsSubstring("data-act=\"add\">Add user</button>"));
    CHECK_THAT(row_of(html, "bob"), ContainsSubstring("data-act=\"remove\" data-username=\"bob\""));
    CHECK_THAT(row_of(html, "alice"), !ContainsSubstring("data-act="));
    // SSO: the local delete route would refuse the principal, so no Remove is drawn.
    CHECK_THAT(row_of(html, "oidc:https://x/y#sub"), !ContainsSubstring("data-act="));
    CHECK(count_of(html, "data-act=\"remove\"") == 1);
    // An unavailable store offers no Add: the form could not show the list it changes.
    CHECK_THAT(render_users_list(Unavailable{}), !ContainsSubstring("data-act=\"add\""));
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

TEST_CASE("access render: only buttons with data-act mutate; no htmx verb and nothing out of scope",
          "[access][render]") {
    // Mutations are script-driven through the dialog module: no hx-post/put/delete/patch.
    static const std::regex bad(R"re(hx-(post|put|delete|patch)|Reset password|Unlock|elevat)re",
                                std::regex::icase);
    for (const auto& html : every_output())
        CHECK_FALSE(std::regex_search(html, bad));
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
    // Cell text, the row's data attribute, the Manage URL, the Remove button's data attribute and
    // the derived RBAC-roles cell's data attribute.
    CHECK(count_of(big, std::string(10 * 1024, 'x')) == 5);
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

// ── Roles and role permissions ───────────────────────────────────────────────

TEST_CASE("access roles: one row per role, a View button only for an addressable name",
          "[access][render]") {
    const auto html = roles_html({role("Operator", "Execute and manage"), role("Custom", "mine", false)});
    CHECK(count_of(html, "<tr data-role=") == 2);
    CHECK_THAT(html, ContainsSubstring("<span class=\"sub\">2 roles</span>"));
    CHECK_THAT(html, ContainsSubstring(
                         "hx-get=\"/fragments/access/roles/permissions?role=Operator\" "
                         "hx-target=\"#acc-role-perms\""));
    // Only the seeded roles are "Built-in".
    CHECK(count_of(html, "Built-in") == 1);
    CHECK_THAT(roles_html({role("Solo", "d")}), ContainsSubstring("<span class=\"sub\">1 role</span>"));
}

TEST_CASE("access roles: a name that is not a plain segment gets no request URL, ever",
          "[access][render]") {
    // Path and query metacharacters, dot segments, over-long, embedded NUL, SQL/HTML noise.
    const std::string long_name(65, 'a');
    for (const std::string& name :
         {std::string("Op/erator"), std::string(".."), std::string("."), std::string("./x?"),
          std::string("../y"), std::string("a b"), std::string("a&b=c"), std::string("a#b"),
          long_name, std::string("a\0b", 3), std::string("<script>")}) {
        INFO(name);
        const auto html = roles_html({role(name, "d")});
        CHECK_THAT(html, !ContainsSubstring("hx-get"));
        CHECK_THAT(html, ContainsSubstring("Name not addressable"));
        CHECK_THAT(html, !ContainsSubstring("<script>"));
    }
    // And a plain one is encoded as a query value, not merely escaped.
    CHECK_THAT(roles_html({role("A.b-c_1", "d")}), ContainsSubstring("?role=A.b-c_1\""));
}

TEST_CASE("access roles: is_addressable_name is the REST route's charset minus dot-only names",
          "[access][render]") {
    for (const char* ok : {"a", "Administrator", "A.b-c_9", "...x", "x...", "a..b"})
        CHECK(is_addressable_name(ok));
    for (const char* bad : {"", ".", "..", "...", "a/b", "a b", "a%2e", "a?b", "a#b", "\xC3\xA9"})
        CHECK_FALSE(is_addressable_name(bad));
    CHECK(is_addressable_name(std::string(64, 'a')));
    CHECK_FALSE(is_addressable_name(std::string(65, 'a')));
    CHECK_FALSE(is_addressable_name(std::string("a\0b", 3)));
}

TEST_CASE("access roles: descriptions and names are escaped; an unreadable catalogue is not a table",
          "[access][render]") {
    const std::string nasty = "<script>alert(1)</script>\"'&";
    const std::string nasty_esc = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;";
    const auto html = roles_html({role(nasty, nasty)});
    CHECK_THAT(html, ContainsSubstring(nasty_esc));
    CHECK_THAT(html, !ContainsSubstring("<script>"));
    CHECK_THAT(html, ContainsSubstring("<tr data-role=\"" + nasty_esc + "\">"));
    // A 10 KB description does not truncate the document.
    CHECK_THAT(roles_html({role("R", std::string(10 * 1024, 'x'))}), ContainsSubstring("</table>"));

    // An unanswered store and an empty answer (the store seeds seven roles) are both the red
    // box: an empty role list reads as "nobody has any access".
    for (const auto& bad : {render_roles_list(Unavailable{}), roles_html({})}) {
        CHECK_THAT(bad, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(bad, ContainsSubstring(std::string(kRolesUnavailable)));
        CHECK_THAT(bad, ContainsSubstring("data-act=\"reload\" data-target=\"acc-roles\""));
        CHECK_THAT(bad, !ContainsSubstring("<table"));
    }
}

TEST_CASE("access role permissions: grouped by area, counts computed, a deny row says so",
          "[access][render]") {
    const auto html = render_role_permissions(RolePerms{
        "Operator",
        {perm("Tag", "Read"), perm("Tag", "Write"), perm("Execution", "Execute"),
         perm("Tag", "Delete", "deny")}});
    CHECK_THAT(html, ContainsSubstring("Operator permissions"));
    CHECK_THAT(html, ContainsSubstring("4 permissions across 2 areas"));
    CHECK_THAT(html, ContainsSubstring("<td class=\"mono\">Tag</td><td>Read, Write, Delete (deny)</td>"));
    CHECK_THAT(html, ContainsSubstring("<td class=\"mono\">Execution</td><td>Execute</td>"));
    // A different fixture gives different numbers: the line is computed, not fixed text.
    CHECK_THAT(render_role_permissions(RolePerms{"R", {perm("A", "Read")}}),
               ContainsSubstring("1 permission across 1 area"));
}

TEST_CASE("access role permissions: unknown, empty, unreadable and unselected are four panels",
          "[access][render]") {
    const auto nf = render_role_permissions(NotFound{});
    const auto empty = render_role_permissions(RolePerms{"R", {}});
    const auto un = render_role_permissions(Unavailable{}, "/fragments/access/roles/permissions?role=R");
    const auto sel = render_select_role();
    CHECK_THAT(nf, ContainsSubstring("No such role"));
    CHECK_THAT(empty, ContainsSubstring("This role holds no permissions."));
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kRolePermsUnavailable)));
    CHECK_THAT(un, ContainsSubstring("hx-get=\"/fragments/access/roles/permissions?role=R\""));
    CHECK_THAT(sel, ContainsSubstring(std::string(kSelectRole)));
    for (const auto& h : {nf, empty, sel})
        CHECK_THAT(h, !ContainsSubstring("<table"));
    CHECK_THAT(un, !ContainsSubstring("<table"));
    CHECK(nf != empty);
    CHECK(nf != un);
    // No retry URL: no Retry button.
    CHECK_THAT(render_role_permissions(Unavailable{}), !ContainsSubstring("<button"));
    // Escaping of store-sourced area and operation strings.
    const auto x = render_role_permissions(RolePerms{"<b>", {perm("<i>", "\"op\"")}});
    CHECK_THAT(x, ContainsSubstring("&lt;b&gt; permissions"));
    CHECK_THAT(x, ContainsSubstring("&lt;i&gt;"));
    CHECK_THAT(x, ContainsSubstring("&quot;op&quot;"));
    CHECK_THAT(x, !ContainsSubstring("<i>"));
}

// ── Role assignments ─────────────────────────────────────────────────────────

TEST_CASE("access assignments: Remove is drawn only for a plain user grant the server would accept",
          "[access][render]") {
    const std::vector<PrincipalRole> rows = {
        grant("user", "bob", "Viewer"),                      // 0 removable
        grant("user", "oidc:https://x/y#sub", "Viewer"),     // 1 not a plain segment
        grant("group", "it-ops", "Operator"),                // 2 group
        grant("engine", "engine:ci", "Operator"),            // 3 engine
        grant("user", "alice", "Administrator"),             // 4 own Administrator
        grant("user", "alice", "Viewer"),                    // 5 own non-admin grant
        grant("user", "..", "Viewer"),                       // 6 dot segment
        grant("user", "./x?", "Viewer"),                     // 7 hostile
        grant("user", "../y", "Viewer"),                     // 8 hostile
        grant("user", "bob", "Op/erator"),                   // 9 role not a segment
    };
    const auto html = assign_html(view_of(rows, "alice"));
    CHECK_THAT(nth_row(html, 0), ContainsSubstring("data-act=\"unassign\""));
    CHECK_THAT(nth_row(html, 5), ContainsSubstring("data-act=\"unassign\""));
    for (const std::size_t i : {1u, 2u, 3u, 6u, 7u, 8u, 9u}) {
        INFO("row " << i);
        CHECK_THAT(nth_row(html, i), !ContainsSubstring("data-act="));
        CHECK_THAT(nth_row(html, i), ContainsSubstring("Not removable here"));
    }
    CHECK_THAT(nth_row(html, 2), ContainsSubstring("Group grants are not removable"));
    // The caller's own Administrator grant is shown, disabled, with the reason.
    const auto own = nth_row(html, 4);
    CHECK_THAT(own, ContainsSubstring("disabled title=\"You cannot remove your own Administrator assignment"));
    CHECK_THAT(own, !ContainsSubstring("data-act="));
    CHECK(count_of(html, "data-act=\"unassign\"") == 2);
}

TEST_CASE("access assignments: a viewer who cannot administer sees the table and no controls",
          "[access][render]") {
    const auto html = assign_html(view_of({grant("user", "bob", "Viewer")}, "carol", /*can_assign=*/false));
    CHECK_THAT(html, !ContainsSubstring("data-act="));
    CHECK_THAT(html, !ContainsSubstring("Assign role"));
    CHECK_THAT(html, ContainsSubstring("<td class=\"long\">bob</td>"));
}

TEST_CASE("access assignments: the Assign button carries exactly the offered roles, or is disabled",
          "[access][render]") {
    const auto with = assign_html(view_of({}, "alice", true, {"Operator", "Viewer"}));
    CHECK_THAT(with, ContainsSubstring("data-act=\"assign\" data-roles=\"Operator,Viewer\""));
    const auto none = assign_html(view_of({}, "alice", true, {}));
    CHECK_THAT(none, ContainsSubstring("disabled title=\"The role list could not be read"));
    CHECK_THAT(none, !ContainsSubstring("data-act=\"assign\""));
}

TEST_CASE("access assignments: past the cap the table is cut, the banner states the true count, data-capped says so",
          "[access][render]") {
    std::vector<PrincipalRole> rows;
    for (int i = 0; i < 4; ++i)
        rows.push_back(grant("user", "u" + std::to_string(i), "Viewer"));
    const auto capped = assign_html(view_of(rows), 3);
    CHECK(count_of(capped, "<tr data-principal-type=") == 3);
    CHECK_THAT(capped, ContainsSubstring("Showing the first 3 of 4 grants."));
    CHECK_THAT(capped, ContainsSubstring("data-total=\"4\" data-capped=\"1\""));
    CHECK_THAT(capped, !ContainsSubstring("u3\""));
    // At the cap exactly: not capped, no banner.
    const auto exact = assign_html(view_of(rows), 4);
    CHECK(count_of(exact, "<tr data-principal-type=") == 4);
    CHECK_THAT(exact, ContainsSubstring("data-total=\"4\" data-capped=\"0\""));
    CHECK_THAT(exact, !ContainsSubstring("Showing the first"));
}

TEST_CASE("access assignments: a true empty is a table that says so; an unread table is a red box",
          "[access][render]") {
    const auto empty = assign_html(view_of({}));
    CHECK_THAT(empty, ContainsSubstring("data-total=\"0\" data-capped=\"0\""));
    CHECK_THAT(empty, ContainsSubstring("No role assignments yet."));
    CHECK_THAT(empty, !ContainsSubstring("role=\"alert\""));
    const auto un = render_assignments(Unavailable{});
    CHECK_THAT(un, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(un, ContainsSubstring(std::string(kAssignmentsUnavailable)));
    CHECK_THAT(un, ContainsSubstring("data-act=\"reload\" data-target=\"acc-assignments\""));
    // No table at all: the page script reads "no table" as "do not derive any count".
    CHECK_THAT(un, !ContainsSubstring("<table"));
    CHECK_THAT(un, !ContainsSubstring("data-assignments"));
}

TEST_CASE("access assignments: principals, ids and roles are escaped in text and every data attribute",
          "[access][render]") {
    const std::string nasty = "<script>alert(1)</script>\"'&";
    const std::string nasty_esc = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;";
    const auto html = assign_html(view_of({grant(nasty, nasty, nasty)}));
    CHECK_THAT(html, !ContainsSubstring("<script>"));
    CHECK_THAT(nth_row(html, 0), ContainsSubstring("data-principal-type=\"" + nasty_esc + "\" data-principal-id=\"" +
                                                   nasty_esc + "\" data-role=\"" + nasty_esc + "\""));
    // An SSO principal: '#' and '/' are left alone by HTML escaping, and the id never reaches a URL here.
    const auto sso = assign_html(view_of({grant("user", "oidc:https://x/y#sub", "Viewer")}));
    CHECK_THAT(sso, ContainsSubstring("data-principal-id=\"oidc:https://x/y#sub\""));
    CHECK_THAT(sso, !ContainsSubstring("href="));
    CHECK_THAT(sso, !ContainsSubstring("hx-"));
}

TEST_CASE("access derived cells: the Users and Roles tables ship 'Not shown' hooks, never a count",
          "[access][render]") {
    const auto users = list_html({user("bob"), user("oidc:https://x/y#sub", auth::Role::user, "oidc")});
    CHECK_THAT(users, ContainsSubstring("<td class=\"wrap\" data-rbac-for=\"bob\">Not shown</td>"));
    CHECK_THAT(users, ContainsSubstring("data-rbac-for=\"oidc:https://x/y#sub\">Not shown</td>"));
    CHECK_THAT(users, ContainsSubstring("<th>RBAC roles</th>"));
    const auto roles = roles_html({role("Operator", "d")});
    CHECK_THAT(roles, ContainsSubstring("<td class=\"r\" data-assigned-for=\"Operator\">Not shown</td>"));
    CHECK_THAT(roles, ContainsSubstring("<th class=\"r\">Assigned</th>"));
}

TEST_CASE("access hint: may_attempt_rbac_admin follows the base role on a local cookie session only",
          "[access][render]") {
    auto s = [](auth::Role role, std::string source = "local") {
        auth::Session x;
        x.role = role;
        x.auth_source = std::move(source);
        return x;
    };
    CHECK(may_attempt_rbac_admin(s(auth::Role::admin)));
    CHECK_FALSE(may_attempt_rbac_admin(s(auth::Role::user)));
    CHECK_FALSE(may_attempt_rbac_admin(s(auth::Role::admin, "oidc")));
    CHECK_FALSE(may_attempt_rbac_admin(s(auth::Role::admin, "saml")));
    CHECK_FALSE(may_attempt_rbac_admin(s(auth::Role::admin, "api_token")));
    auto scoped = s(auth::Role::admin);
    scoped.token_scope_service = "payments";
    CHECK_FALSE(may_attempt_rbac_admin(scoped));
    auto mcp = s(auth::Role::admin);
    mcp.mcp_tier = "operator";
    CHECK_FALSE(may_attempt_rbac_admin(mcp));
    auto engine = s(auth::Role::admin);
    engine.principal_kind = "engine";
    CHECK_FALSE(may_attempt_rbac_admin(engine));
    // A JIT elevation makes the EFFECTIVE role admin but not the base role: no hint.
    auto elevated = s(auth::Role::user);
    elevated.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
    CHECK_FALSE(may_attempt_rbac_admin(elevated));
}

// ── Your account ─────────────────────────────────────────────────────────────

TEST_CASE("access account: Change password only for a local account; the disabled control carries a reason",
          "[access][render]") {
    const auto local = render_your_account("alice", "local");
    CHECK_THAT(local, ContainsSubstring("data-act=\"pw-change\""));
    CHECK_THAT(local, ContainsSubstring("data-act=\"signout-all\""));
    CHECK_THAT(local, ContainsSubstring("<span class=\"sub\">alice</span>"));
    for (const char* source : {"oidc", "saml", "api_token", "mcp_token", "engine_token", ""}) {
        INFO(source);
        const auto other = render_your_account("alice", source);
        CHECK_THAT(other, !ContainsSubstring("pw-change"));
        CHECK_THAT(other, ContainsSubstring("managed by your identity provider"));
        CHECK_THAT(other, ContainsSubstring("data-act=\"signout-all\""));
    }
    // The unbuilt control has no action, only a reason.
    CHECK_THAT(local, ContainsSubstring("disabled title=\"Not available yet\">Sign out all other sessions"));
    CHECK(count_of(local, "data-act=") == 2);
}

TEST_CASE("access account: the username is escaped", "[access][render]") {
    const auto html = render_your_account("<b>\"x\"</b>", "local");
    CHECK_THAT(html, ContainsSubstring("&lt;b&gt;&quot;x&quot;&lt;/b&gt;"));
    CHECK_THAT(html, !ContainsSubstring("<b>"));
}
