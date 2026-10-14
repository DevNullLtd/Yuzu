/**
 * @file test_access_routes.cpp
 * @brief HTTP-level coverage of access_routes.{hpp,cpp}, driven in-process through
 *        TestRouteSink (no acceptor). Every closure is injected and re-read per call.
 *
 * Pinned, in order of consequence:
 *   - the admin gate (quiet for cookie sessions) runs BEFORE the store is read (a denied caller costs no read);
 *   - the page itself makes no gate call (no page-level probe, so the page adds nothing to
 *     what its panels do);
 *   - a store that did not answer is a 200 red box, never an empty table;
 *   - `oidc:<iss>#<sub>` survives the `?username=` round trip;
 *   - an empty session username is refused, not rendered;
 *   - `register_access_routes` binds the REAL `probe_admin` (lexical gate over server.cpp),
 *     because every case here stubs the gate and would pass with a permissive lambda.
 */

#include "access_render.hpp"
#include "access_routes.hpp"
#include "access_ui.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <sstream>
#include <utility>
#include <vector>
#include <stdexcept>
#include <string>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;

namespace {

constexpr const char* kDenyBody = R"({"error":{"code":403,"message":"admin role required"}})";
constexpr const char* kPermDenyBody = R"({"error":{"code":403,"message":"permission required"}})";

RbacRole role(std::string name, std::string description) {
    RbacRole r;
    r.name = std::move(name);
    r.description = std::move(description);
    r.is_system = true;
    return r;
}

PrincipalRole grant(std::string type, std::string id, std::string role) {
    PrincipalRole g;
    g.principal_type = std::move(type);
    g.principal_id = std::move(id);
    g.role_name = std::move(role);
    return g;
}

Permission perm(std::string type, std::string op, std::string effect = "allow") {
    Permission p;
    p.securable_type = std::move(type);
    p.operation = std::move(op);
    p.effect = std::move(effect);
    return p;
}

auth::UserEntry user(std::string name, std::string source = "local",
                     auth::Role role = auth::Role::user) {
    auth::UserEntry u;
    u.username = std::move(name);
    u.identity_source = std::move(source);
    u.role = role;
    return u;
}

// `sink` is LAST: its handlers capture `this` and must not outlive the other members.
struct Harness {
    bool admin_allow{true};
    int admin_calls{0};
    bool session_present{true};
    std::string session_username{"alice"};
    auth::Role session_role{auth::Role::admin};
    std::string session_source{"local"};
    std::string session_kind{"human"};
    std::string session_mcp_tier;
    int list_calls{0};
    std::expected<std::vector<auth::UserEntry>, std::string> list_result{
        std::vector<auth::UserEntry>{user("alice", "local", auth::Role::admin), user("bob")}};
    // The permission gate records every (securable, operation) it is asked about.
    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_asked;
    int roles_calls{0};
    std::expected<std::vector<RbacRole>, std::string> roles_result{std::vector<RbacRole>{
        role("Administrator", "Full access to all operations"), role("Viewer", "Read-only")}};
    int assigns_calls{0};
    std::expected<std::vector<PrincipalRole>, std::string> assigns_result{std::vector<PrincipalRole>{
        grant("user", "bob", "Viewer"), grant("group", "ops", "Operator")}};
    // Every audit row the routes write: (action, result, target_type, target_id, detail).
    bool audit_persists{true};
    std::vector<std::vector<std::string>> audits;
    int perms_calls{0};
    std::string perms_asked_role;
    std::expected<std::vector<Permission>, std::string> perms_result{std::vector<Permission>{
        perm("Tag", "Read"), perm("Tag", "Write")}};
    yuzu::server::test::TestRouteSink sink;

    access::Deps deps() {
        access::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_username;
            s.role = session_role;
            s.auth_source = session_source;
            s.principal_kind = session_kind;
            s.mcp_tier = session_mcp_tier;
            return s;
        };
        d.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (admin_allow)
                return true;
            res.status = 403;
            res.set_content(kDenyBody, "application/json");
            return false;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& type,
                           const std::string& op) {
            perm_asked.emplace_back(type, op);
            if (perm_allow)
                return true;
            res.status = 403;
            res.set_content(kPermDenyBody, "application/json");
            return false;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action, const std::string& result,
                            const std::string& target_type, const std::string& target_id,
                            const std::string& detail) {
            audits.push_back({action, result, target_type, target_id, detail});
            return audit_persists;
        };
        d.list_users_fn = [this]() {
            ++list_calls;
            return list_result;
        };
        d.list_roles_fn = [this]() {
            ++roles_calls;
            return roles_result;
        };
        d.list_assignments_fn = [this]() {
            ++assigns_calls;
            return assigns_result;
        };
        d.role_permissions_fn = [this](const std::string& r) {
            ++perms_calls;
            perms_asked_role = r;
            return perms_result;
        };
        return d;
    }
    void wire() { access::register_access_routes(sink, deps()); }
};

} // namespace

TEST_CASE("access routes: registration fails fast when any dependency is unbound",
          "[access][routes]") {
    using Member = std::function<void(access::Deps&)>;
    const std::vector<Member> unbind = {
        [](access::Deps& d) { d.auth_fn = nullptr; },
        [](access::Deps& d) { d.admin_fn = nullptr; },
        [](access::Deps& d) { d.perm_fn = nullptr; },
        [](access::Deps& d) { d.audit_fn = nullptr; },
        [](access::Deps& d) { d.list_users_fn = nullptr; },
        [](access::Deps& d) { d.list_roles_fn = nullptr; },
        [](access::Deps& d) { d.role_permissions_fn = nullptr; },
        [](access::Deps& d) { d.list_assignments_fn = nullptr; },
    };
    for (const auto& f : unbind) {
        Harness h;
        auto d = h.deps();
        f(d);
        CHECK_THROWS_AS(access::register_access_routes(h.sink, d), std::invalid_argument);
    }
}

TEST_CASE("access routes: the page redirects without a session and makes no gate or store call",
          "[access][routes]") {
    Harness h;
    h.wire();

    h.session_present = false;
    auto res = h.sink.dispatch("GET", "/access/users");
    REQUIRE(res);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login");

    h.session_present = true;
    res = h.sink.dispatch("GET", "/access/users");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("/access/users"));
    CHECK_THAT(res->body, ContainsSubstring(std::string(access::kUsersDenied)));
    // No page-level probe: the page costs no audited denial of its own.
    CHECK(h.admin_calls == 0);
    CHECK(h.list_calls == 0);
    CHECK(h.perm_asked.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("access routes: the page draws Your account from the session, and only there",
          "[access][routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.dispatch("GET", "/access/users");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("<span class=\"sub\">alice</span>"));
    CHECK_THAT(res->body, ContainsSubstring("data-act=\"pw-change\""));
    CHECK_THAT(res->body, !ContainsSubstring("yuzu:account"));

    // An SSO session has no local password to change; a hostile name is escaped.
    h.session_source = "oidc";
    h.session_username = "<i>bob</i>";
    res = h.sink.dispatch("GET", "/access/users");
    REQUIRE(res);
    CHECK_THAT(res->body, !ContainsSubstring("pw-change"));
    CHECK_THAT(res->body, ContainsSubstring("&lt;i&gt;bob&lt;/i&gt;"));
    CHECK_THAT(res->body, !ContainsSubstring("<i>bob</i>"));
}

TEST_CASE("access routes: a denied caller gets the gate's response and the store is never read",
          "[access][routes]") {
    Harness h;
    h.admin_allow = false;
    h.wire();
    for (const char* path :
         {"/fragments/access/users/list", "/fragments/access/users/detail?username=bob"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == kDenyBody);
    }
    CHECK(h.list_calls == 0);
}

TEST_CASE("access routes: list renders rows, is not cacheable and reads once", "[access][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/users/list");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("<tr data-username=\"bob\">"));
    CHECK_THAT(res->body, ContainsSubstring("Current user")); // alice is the caller
    CHECK(h.list_calls == 1);
}

TEST_CASE("access routes: an unanswered store is a 200 red box, never an empty table",
          "[access][routes]") {
    Harness h;
    h.list_result = std::unexpected(std::string("pq: connection refused at 10.0.0.5"));
    h.wire();
    for (const char* path :
         {"/fragments/access/users/list", "/fragments/access/users/detail?username=bob"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
        // The store's own text is log-only.
        CHECK_THAT(res->body, !ContainsSubstring("connection refused"));
    }
}

TEST_CASE("access routes: detail with no username is the placeholder", "[access][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/users/detail");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring(std::string(access::kSelectUser)));
    CHECK(h.list_calls == 0);
}

TEST_CASE("access routes: detail finds an SSO principal through the encoded query",
          "[access][routes]") {
    Harness h;
    const std::string principal = "oidc:https://idp.example/realm#sub-1";
    h.list_result = std::vector<auth::UserEntry>{user("alice"), user(principal, "oidc")};
    h.wire();
    const auto res = h.sink.dispatch(
        "GET", "/fragments/access/users/detail?username=" + access::url_q(principal));
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("OIDC account"));
    CHECK_THAT(res->body, !ContainsSubstring("No such user"));
}

TEST_CASE("access routes: detail distinguishes not found, self and another account",
          "[access][routes]") {
    Harness h;
    h.wire();

    auto res = h.sink.dispatch("GET", "/fragments/access/users/detail?username=ghost");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("No such user"));
    CHECK_THAT(res->body, !ContainsSubstring("role=\"alert\""));

    res = h.sink.dispatch("GET", "/fragments/access/users/detail?username=alice");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("You cannot change your own role."));

    res = h.sink.dispatch("GET", "/fragments/access/users/detail?username=bob");
    REQUIRE(res);
    CHECK_THAT(res->body, !ContainsSubstring("You cannot change your own role."));
}

TEST_CASE("access routes: an empty session username is refused, not rendered", "[access][routes]") {
    Harness h;
    h.session_username = "";
    h.wire();
    for (const char* path :
         {"/fragments/access/users/list", "/fragments/access/users/detail?username=bob"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(h.list_calls == 0);
}

TEST_CASE("access routes: the static glue is served uncached", "[access][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/static/yuzu-access.js");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/javascript; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-cache, no-store, must-revalidate");
    CHECK_THAT(res->body, ContainsSubstring("htmx:responseError"));
}

// ── Roles ────────────────────────────────────────────────────────────────────

TEST_CASE("access routes: roles/list asks for exactly UserManagement:Read, the REST twin's pair",
          "[access][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/list");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->body, ContainsSubstring("<tr data-role=\"Administrator\">"));
    CHECK(h.roles_calls == 1);
    REQUIRE(h.perm_asked.size() == 1);
    CHECK(h.perm_asked[0] == std::make_pair(std::string("UserManagement"), std::string("Read")));
    CHECK(h.admin_calls == 0); // not the account-role gate
}

TEST_CASE("access routes: roles fragments are refused by the gate before any store read",
          "[access][routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    for (const char* path : {"/fragments/access/roles/list", "/fragments/access/roles/permissions?role=Viewer"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body == kPermDenyBody);
    }
    CHECK(h.roles_calls == 0);
    CHECK(h.perms_calls == 0);
}

TEST_CASE("access routes: an unanswered role store is a 200 red box that never carries the store text",
          "[access][routes]") {
    Harness h;
    h.roles_result = std::unexpected(std::string("ERROR: relation rbac.roles PGRES_FATAL_ERROR"));
    h.wire();
    for (const char* path : {"/fragments/access/roles/list", "/fragments/access/roles/permissions?role=Viewer"}) {
        INFO(path);
        const auto res = h.sink.dispatch("GET", path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
        CHECK_THAT(res->body, !ContainsSubstring("PGRES"));
    }
    // A fault on the catalogue read is never "no such role", and never reaches the permission read.
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/permissions?role=Viewer");
    CHECK_THAT(res->body, !ContainsSubstring("No such role"));
    CHECK(h.perms_calls == 0);
}

TEST_CASE("access routes: role permissions distinguishes unknown, unreadable and empty",
          "[access][routes]") {
    Harness h;
    h.wire();

    auto res = h.sink.dispatch("GET", "/fragments/access/roles/permissions?role=Viewer");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("2 permissions across 1 area"));
    CHECK(h.perms_asked_role == "Viewer");

    // The catalogue answered and does not hold it: "No such role", and the permission read
    // is never made for a name the catalogue does not hold.
    h.perms_calls = 0;
    res = h.sink.dispatch("GET", "/fragments/access/roles/permissions?role=Ghost");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("No such role"));
    CHECK(h.perms_calls == 0);

    // The permission read faulted: unavailable, never "holds no permissions".
    h.perms_result = std::unexpected(std::string("pq: timeout"));
    res = h.sink.dispatch("GET", "/fragments/access/roles/permissions?role=Viewer");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(res->body, !ContainsSubstring("holds no permissions"));
    CHECK_THAT(res->body, !ContainsSubstring("pq: timeout"));
    CHECK_THAT(res->body, ContainsSubstring("hx-get=\"/fragments/access/roles/permissions?role=Viewer\""));

    // A true empty answer is its own sentence.
    h.perms_result = std::vector<Permission>{};
    res = h.sink.dispatch("GET", "/fragments/access/roles/permissions?role=Viewer");
    CHECK_THAT(res->body, ContainsSubstring("This role holds no permissions."));
}

TEST_CASE("access routes: a malformed ?role= is refused before the gate and every store read",
          "[access][routes]") {
    Harness h;
    h.wire();
    // Missing, empty, dot segments, path and query metacharacters, over-long, NUL, encoded dots.
    const std::string long_name(65, 'a');
    for (const std::string& q :
         {std::string(""), std::string("?role="), std::string("?role=."), std::string("?role=.."),
          std::string("?role=..%2Fy"), std::string("?role=.%2Fx%3F"), std::string("?role=a%20b"),
          std::string("?role=a%00b"), std::string("?role=%2E%2E"), "?role=" + long_name}) {
        INFO(q);
        const auto res = h.sink.dispatch("GET", "/fragments/access/roles/permissions" + q);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->get_header_value("Cache-Control") == "no-store");
    }
    CHECK(h.perm_asked.empty());
    CHECK(h.roles_calls == 0);
    CHECK(h.perms_calls == 0);
}

// ── Role assignments ─────────────────────────────────────────────────────────

TEST_CASE("access routes: assignments asks for exactly AccessReview:Read, never UserManagement:Read",
          "[access][routes]") {
    Harness h;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK(res->get_header_value("Content-Type") == "text/html; charset=utf-8");
    REQUIRE(h.perm_asked.size() == 1);
    CHECK(h.perm_asked[0] == std::make_pair(std::string("AccessReview"), std::string("Read")));
    CHECK(h.admin_calls == 0);
}

TEST_CASE("access routes: a refused assignments caller costs no read and no audit row", "[access][routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body == kPermDenyBody);
    CHECK(h.assigns_calls == 0);
    CHECK(h.roles_calls == 0);
    CHECK(h.audits.empty()); // the gate audits its own denial
}

TEST_CASE("access routes: an engine session is refused with one denied audit row and no read",
          "[access][routes]") {
    for (const char* source : {"engine_token", "other"}) {
        INFO(source);
        Harness h;
        h.session_source = source;
        if (std::string(source) == "other")
            h.session_kind = "engine"; // either discriminator is enough
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.assigns_calls == 0);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0] == std::vector<std::string>{"rbac.assignments.list", "denied", "AccessReview", "",
                                                      "engine_session_denied"});
    }
}

TEST_CASE("access routes: a successful assignments read writes the REST twin's audit row with the full count",
          "[access][routes]") {
    Harness h;
    std::vector<PrincipalRole> many;
    for (std::size_t i = 0; i < access::kAssignmentsRenderCap + 5; ++i)
        many.push_back(grant("user", "u" + std::to_string(i), "Viewer"));
    h.assigns_result = many;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audits.size() == 1);
    // The count is the table the store returned, not the capped table drawn.
    CHECK(h.audits[0] == std::vector<std::string>{"rbac.assignments.list", "success", "AccessReview", "",
                                                  "count=" + std::to_string(many.size())});
    CHECK_THAT(res->body, ContainsSubstring("Showing the first 2000 of 2005 grants."));
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("access routes: a lost audit row flags the response and still draws the panel", "[access][routes]") {
    Harness h;
    h.audit_persists = false;
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_THAT(res->body, ContainsSubstring("<table data-assignments"));
}

TEST_CASE("access routes: an unread grant table is a 200 red box with no audit row and no store text",
          "[access][routes]") {
    Harness h;
    h.assigns_result = std::unexpected(std::string("PGRES_FATAL_ERROR: relation principal_roles"));
    h.wire();
    const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("role=\"alert\""));
    CHECK_THAT(res->body, !ContainsSubstring("<table"));
    CHECK_THAT(res->body, !ContainsSubstring("PGRES"));
    CHECK(h.audits.empty());
}

TEST_CASE("access routes: Assign is offered to a local account admin only, with the closed role list",
          "[access][routes]") {
    Harness h;
    // The catalogue holds ITServiceOwner and a custom role; neither is offered.
    h.roles_result = std::vector<RbacRole>{role("Administrator", "d"), role("ITServiceOwner", "d"),
                                           role("Operator", "d"), role("Auditor.eu", "d"),
                                           role("PlatformEngineer", "d"), role("ApiTokenManager", "d"),
                                           role("Viewer", "d"), role("Reviewer", "d")};
    h.wire();
    auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    // The literal six, in catalogue order. A fixed list on purpose: comparing with the array the
    // code reads would stay green if someone added ITServiceOwner to it.
    CHECK_THAT(res->body, ContainsSubstring("data-roles=\"Administrator,Operator,PlatformEngineer,"
                                            "ApiTokenManager,Viewer,Reviewer\""));
    CHECK_THAT(res->body, !ContainsSubstring("ITServiceOwner,"));
    CHECK_THAT(res->body, !ContainsSubstring("Auditor.eu"));

    // A Reviewer-style caller (account role user) reads the table and is offered nothing, and the
    // catalogue is not even read for them.
    Harness r;
    r.session_role = auth::Role::user;
    r.wire();
    res = r.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("<table data-assignments"));
    CHECK_THAT(res->body, !ContainsSubstring("data-act="));
    CHECK(r.roles_calls == 0);

    // An unreadable catalogue disables the button with a reason instead of offering nothing silently.
    Harness u;
    u.roles_result = std::unexpected(std::string("down"));
    u.wire();
    res = u.sink.dispatch("GET", "/fragments/access/roles/assignments");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("disabled title=\"The role list could not be read"));
}

TEST_CASE("access routes: no hint for an SSO, token, MCP or engine-class session", "[access][routes]") {
    struct Case {
        const char* source;
        const char* tier;
    };
    for (const Case c : {Case{"oidc", ""}, Case{"saml", ""}, Case{"api_token", ""}, Case{"mcp_token", "operator"},
                         Case{"local", "readonly"}}) {
        INFO(c.source << "/" << c.tier);
        Harness h;
        h.session_source = c.source;
        h.session_mcp_tier = c.tier;
        h.wire();
        const auto res = h.sink.dispatch("GET", "/fragments/access/roles/assignments");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK_THAT(res->body, !ContainsSubstring("data-act=\"assign\""));
        CHECK_THAT(res->body, !ContainsSubstring("data-act=\"unassign\""));
    }
}
