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
#include <stdexcept>
#include <string>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;

namespace {

constexpr const char* kDenyBody = R"({"error":{"code":403,"message":"admin role required"}})";

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
    int list_calls{0};
    std::expected<std::vector<auth::UserEntry>, std::string> list_result{
        std::vector<auth::UserEntry>{user("alice", "local", auth::Role::admin), user("bob")}};
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
        d.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&) { return true; };
        d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                        const std::string&, const std::string&, const std::string&) {
            return true;
        };
        d.list_users_fn = [this]() {
            ++list_calls;
            return list_result;
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
