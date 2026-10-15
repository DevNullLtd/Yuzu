/**
 * @file test_access_tokens_authz.cpp
 * @brief [pg] persona matrix for the Access pages (Tokens and principals; Users), driven through
 *        the REAL AuthRoutes gates (require_auth / probe_admin / probe_permission) over a real
 *        RbacStore, ApiTokenStore and AuditStore. test_access_tokens_routes.cpp stubs the
 *        gates; this file is what proves the wiring admits and refuses the right callers.
 *
 * Personas (cookie sessions unless stated): Administrator (RBAC off), plain user (RBAC off),
 * RBAC-on user holding ApiTokenManager, RBAC-on user holding nothing, RBAC-on account
 * administrator WITHOUT EnginePrincipal:Read, RBAC-on non-administrator WITH it (Viewer), an
 * administrator's MCP-tier bearer. For each: the token filter actually applied, whether the
 * principal list is admitted (EnginePrincipal:Read, as the REST twin), and the denied-access
 * rows written (none for a refused cookie session: the panels auto-load).
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_routes.hpp"
#include "access_tokens_routes.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <string>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

yuzu::test::PgTestTemplate tokens_page_tpl{"rbacstore_tokenspage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (tokens page) template: store failed to migrate/seed");
}};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct Rig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    int principal_reads{0};
    int user_reads{0};
    yuzu::server::test::TestRouteSink sink;  // LAST: handlers capture `this`

    explicit Rig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, audit_pool{{.conninfo = dsn, .size = 2}},
          audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(audit_store.is_open());
        REQUIRE(auth_mgr.upsert_user("root", "correct-horse-battery-staple", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("alice", "correct-horse-battery-staple", auth::Role::user));
        REQUIRE(auth_mgr.upsert_user("bob", "correct-horse-battery-staple", auth::Role::user));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);

        // One token per owner, so the filter applied is visible in the body.
        REQUIRE(api_tokens->create_token("alice-ci", "alice", now_epoch() + 3600).has_value());
        REQUIRE(api_tokens->create_token("bob-ci", "bob", now_epoch() + 3600).has_value());
        REQUIRE(api_tokens->create_token("root-ci", "root", now_epoch() + 3600).has_value());

        access_tokens::Deps d;
        d.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        d.perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                           const std::string& o) { return ar->probe_permission(q, r, t, o); };
        d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                        const std::string&, const std::string&, const std::string&) { return true; };
        d.rbac_enforced_fn = [this] { return rbac_enforcement_in_effect(&rbac); };
        d.now_fn = [] { return now_epoch(); };
        d.list_tokens_fn = [this](const std::string& f) { return api_tokens->list_tokens(f); };
        d.list_principals_fn = [this]() -> std::expected<std::vector<EnginePrincipalRow>, std::string> {
            ++principal_reads;
            return std::vector<EnginePrincipalRow>{};
        };
        d.all_roles_fn = []() -> std::expected<std::vector<PrincipalRole>, std::string> {
            return std::vector<PrincipalRole>{};
        };
        d.get_principal_fn = [this](const std::string&)
            -> std::expected<std::optional<EnginePrincipalRow>, std::string> {
            ++principal_reads;
            return std::optional<EnginePrincipalRow>{};
        };
        d.active_credentials_fn = [](const std::string&) -> std::expected<std::vector<ApiToken>, std::string> {
            return std::vector<ApiToken>{};
        };
        d.principal_roles_fn = [](const std::string&) -> std::expected<std::vector<PrincipalRole>, std::string> {
            return std::vector<PrincipalRole>{};
        };
        d.revoke_detail_fn = [](const std::string&) -> std::expected<access_tokens::RevokeDetail, std::string> {
            return access_tokens::RevokeDetail{};
        };
        access_tokens::register_access_tokens_routes(sink, std::move(d));

        access::Deps u;
        u.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        u.admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->probe_admin(q, r);
        };
        u.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&) { return true; };  // unused by the Users routes
        u.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                        const std::string&, const std::string&, const std::string&) { return true; };
        u.list_users_fn = [this]() -> std::expected<std::vector<auth::UserEntry>, std::string> {
            ++user_reads;
            return std::vector<auth::UserEntry>{};
        };
        access::register_access_routes(sink, std::move(u));
    }

    std::unique_ptr<httplib::Response> get_cookie(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json", {{"Cookie", "yuzu_session=" + token}});
    }
    std::unique_ptr<httplib::Response> get_bearer(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Authorization", "Bearer " + token}});
    }
    int denied_rows() {
        auto rows = audit_store.query({});
        REQUIRE(rows.has_value());
        int n = 0;
        for (const auto& r : *rows)
            if (r.result == "denied")
                ++n;
        return n;
    }
};

constexpr const char* kTokens = "/fragments/access/tokens/list";
constexpr const char* kPrincipals = "/fragments/access/principals/list";
constexpr const char* kDetail = "/fragments/access/principals/detail?id=engine:bot";

} // namespace

TEST_CASE("tokens page authz: Administrator with RBAC off sees every owner and the principals",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.auth_mgr.create_local_session_for_test("root", auth::Role::admin, true);

    auto res = r.get_cookie(kTokens, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    for (const char* n : {"alice-ci", "bob-ci", "root-ci"})
        CHECK_THAT(res->body, ContainsSubstring(n));
    CHECK_THAT(res->body, ContainsSubstring("data-effective-admin=\"1\""));
    CHECK_THAT(res->body, ContainsSubstring("data-rbac-enforced=\"0\""));

    res = r.get_cookie(kPrincipals, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.principal_reads == 1);
    CHECK_THAT(res->body, ContainsSubstring("data-check=\"1\""));  // holds AuditLog:Read
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("tokens page authz: a plain user with RBAC off sees only their own tokens and is "
          "refused the principals with no audit row",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.auth_mgr.create_local_session_for_test("alice", auth::Role::user, true);

    // Opening the page and loading the token list writes no denied row.
    auto res = r.get_cookie("/access/tokens", cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    res = r.get_cookie(kTokens, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("alice-ci"));
    CHECK_THAT(res->body, !ContainsSubstring("bob-ci"));
    CHECK_THAT(res->body, !ContainsSubstring("root-ci"));
    CHECK_THAT(res->body, ContainsSubstring("data-effective-admin=\"0\""));
    CHECK(r.denied_rows() == 0);

    // The page loads the principals panel for everyone: the gate (EnginePrincipal:Read, floored
    // to administrators with RBAC off) refuses before any read, and a refused cookie session
    // leaves no denial row because the panel auto-loads.
    for (const char* p : {kPrincipals, kDetail}) {
        res = r.get_cookie(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    CHECK(r.principal_reads == 0);
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("tokens page authz: RBAC on and ApiTokenManager sees own tokens only (the filter follows "
          "the account role, not the grant)",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "ApiTokenManager"}).has_value());
    const auto cookie = r.auth_mgr.create_local_session_for_test("alice", auth::Role::user, true);

    auto res = r.get_cookie(kTokens, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("alice-ci"));
    CHECK_THAT(res->body, !ContainsSubstring("bob-ci"));
    CHECK_THAT(res->body, ContainsSubstring("data-rbac-enforced=\"1\""));

    res = r.get_cookie(kPrincipals, cookie);
    REQUIRE(res);
    CHECK(res->status == 403);  // ApiTokenManager carries no EnginePrincipal:Read
    CHECK(r.principal_reads == 0);
}

TEST_CASE("principals authz: RBAC on and an account administrator WITHOUT EnginePrincipal:Read is "
          "refused before any read (the REST twin's decision)",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    const auto cookie = r.auth_mgr.create_local_session_for_test("root", auth::Role::admin, true);

    for (const char* p : {kPrincipals, kDetail}) {
        const auto res = r.get_cookie(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    CHECK(r.principal_reads == 0);
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("principals authz: RBAC on and a non-administrator holding EnginePrincipal:Read is admitted "
          "and told not to run the REST check without AuditLog:Read",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    // Seeded Viewer holds EnginePrincipal:Read; give a role with that only, to isolate it.
    REQUIRE(r.rbac.create_role({"PrincipalReader", "reads engine principals", false}).has_value());
    REQUIRE(r.rbac.set_permission({"PrincipalReader", "EnginePrincipal", "Read", "allow"}).has_value());
    REQUIRE(r.rbac.assign_role({"user", "alice", "PrincipalReader"}).has_value());
    const auto cookie = r.auth_mgr.create_local_session_for_test("alice", auth::Role::user, true);

    auto res = r.get_cookie(kPrincipals, cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.principal_reads == 1);
    CHECK_THAT(res->body, ContainsSubstring("data-check=\"0\""));  // no AuditLog:Read
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("tokens page authz: RBAC on and a user with no ApiToken:Read is refused with no token read "
          "and no denial row",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    const auto cookie = r.auth_mgr.create_local_session_for_test("bob", auth::Role::user, true);

    const auto res = r.get_cookie(kTokens, cookie);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_THAT(res->body, !ContainsSubstring("bob-ci"));
    CHECK(r.denied_rows() == 0);  // the panel auto-loads: a refused cookie session is not audited
}

TEST_CASE("tokens page authz: an administrator's MCP-tier bearer gets own tokens only and no "
          "principals",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    auto raw = r.api_tokens->create_token("root-mcp", "root", now_epoch() + 3600, "", "readonly");
    REQUIRE(raw.has_value());

    auto res = r.get_bearer(kTokens, *raw);
    REQUIRE(res);
    // A readonly tier admits ApiToken:Read and the fragment never widens to other owners.
    REQUIRE(res->status == 200);
    CHECK_THAT(res->body, ContainsSubstring("root-ci"));
    CHECK_THAT(res->body, !ContainsSubstring("alice-ci"));
    CHECK_THAT(res->body, !ContainsSubstring("bob-ci"));
    CHECK_THAT(res->body, ContainsSubstring("data-effective-admin=\"0\""));

    res = r.get_bearer(kPrincipals, *raw);
    REQUIRE(res);
    CHECK(res->status == 403);  // never an MCP-tier bearer, whatever the grant
    CHECK(r.principal_reads == 0);
}

TEST_CASE("users page authz: a refused cookie session leaves no denial row; a refused token does",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    constexpr const char* kUsers = "/fragments/access/users/list";

    const auto alice = r.auth_mgr.create_local_session_for_test("alice", auth::Role::user, true);
    auto res = r.get_cookie(kUsers, alice);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(r.user_reads == 0);
    CHECK(r.denied_rows() == 0);

    const auto root = r.auth_mgr.create_local_session_for_test("root", auth::Role::admin, true);
    res = r.get_cookie(kUsers, root);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.user_reads == 1);

    // An administrator's MCP-tier bearer is refused by the admin gate and keeps its denial row.
    auto raw = r.api_tokens->create_token("root-mcp", "root", now_epoch() + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    res = r.get_bearer(kUsers, *raw);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(r.user_reads == 1);
    CHECK(r.denied_rows() == 1);
}

TEST_CASE("principals authz: a plain API-token bearer is refused by the real gate and keeps its denial row",
          "[pg][access-tokens][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, tokens_page_tpl);
    Rig r{db_.dsn()};
    // RBAC off: EnginePrincipal:Read is floored to administrators. A non-administrator's token is
    // not a browser session, so the quiet probe does not withhold its denial row.
    auto raw = r.api_tokens->create_token("alice-api", "alice", now_epoch() + 3600);
    REQUIRE(raw.has_value());
    const auto res = r.get_bearer(kPrincipals, *raw);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(r.principal_reads == 0);
    CHECK(r.denied_rows() == 1);
}
