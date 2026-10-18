/**
 * @file test_access_authz.cpp
 * @brief [pg] persona matrix for the Users and roles fragments, driven through the REAL AuthRoutes
 *        gates (require_auth / probe_admin / require_permission) over a real RbacStore and
 *        AuditStore. test_access_routes.cpp stubs the gates; this file proves the production
 *        wiring admits and refuses the right callers, with RBAC off (the shipped default) and on.
 *
 * Personas (cookie sessions): Administrator and plain user with RBAC off; with RBAC on a user
 * holding Viewer, one holding Reviewer, one holding nothing. For each: which fragments answer,
 * whether the store behind a refused fragment was ever read, and the audit rows written.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_routes.hpp"
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

#include <cstdint>
#include <expected>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using Catch::Matchers::ContainsSubstring;
using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using pg::PgPool;

namespace {

yuzu::test::PgTestTemplate access_page_tpl{"rbacstore_accesspage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (access page) template: store failed to migrate/seed");
}};

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
    int user_reads{0};
    std::vector<std::string> route_audits; // "action/result" written by the fragments themselves
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

        access::Deps d;
        d.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        d.admin_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->probe_admin(q, r); // what server.cpp binds: no denial row for a cookie session
        };
        d.perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                           const std::string& o) { return ar->require_permission(q, r, t, o); };
        d.audit_fn = [this](const httplib::Request&, const std::string& action, const std::string& result,
                            const std::string&, const std::string&, const std::string&) {
            route_audits.push_back(action + "/" + result);
            return true;
        };
        d.list_users_fn = [this]() -> std::expected<std::vector<auth::UserEntry>, std::string> {
            ++user_reads;
            return auth_mgr.list_users();
        };
        d.list_roles_fn = [this]() { return rbac.list_roles_checked(); };
        d.role_permissions_fn = [this](const std::string& r) { return rbac.get_role_permissions_checked(r); };
        d.list_assignments_fn = [this]() { return rbac.list_all_principal_roles_checked(); };
        d.enforcement_state_fn = [this]() -> std::expected<access::EnforcementView, std::string> {
            access::EnforcementView v;
            v.enabled = rbac.is_rbac_enabled();
            v.degraded = rbac.rbac_enabled_view_degraded();
            return v;
        };
        d.deny_service_scoped_fn = [this](const httplib::Request& q, httplib::Response& r,
                                          const std::string& action, const std::string& message,
                                          const std::string& type, const std::string& id) {
            return ar->deny_service_scoped_session(q, r, action, message, type, id);
        };
        access::register_access_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json", {{"Cookie", "yuzu_session=" + token}});
    }
    std::unique_ptr<httplib::Response> get_bearer(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json", {{"Authorization", "Bearer " + token}});
    }
    std::string cookie(const std::string& user, auth::Role role) {
        return auth_mgr.create_local_session_for_test(user, role, true);
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

constexpr const char* kUsers = "/fragments/access/users/list";
constexpr const char* kRoles = "/fragments/access/roles/list";
constexpr const char* kPerms = "/fragments/access/roles/permissions?role=Viewer";
constexpr const char* kAssign = "/fragments/access/roles/assignments";
constexpr const char* kEnforce = "/fragments/access/enforcement";

} // namespace

TEST_CASE("access authz: Administrator with RBAC off reads every panel and may attempt the writes",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    const auto c = r.cookie("root", auth::Role::admin);

    for (const char* p : {kUsers, kRoles, kPerms, kAssign, kEnforce}) {
        INFO(p);
        const auto res = r.get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    const auto assign = r.get(kAssign, c);
    CHECK_THAT(assign->body, ContainsSubstring("data-act=\"assign\""));
    // The real catalogue, filtered to the closed assignable list: six names, never ITServiceOwner.
    CHECK_THAT(assign->body,
               ContainsSubstring("data-roles=\"Administrator,ApiTokenManager,Operator,PlatformEngineer,Reviewer,Viewer\""));
    CHECK_THAT(r.get(kEnforce, c)->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK(r.denied_rows() == 0);
    // The grant-table read leaves its own audit row, exactly as its REST twin.
    CHECK(r.route_audits == std::vector<std::string>{"rbac.assignments.list/success",
                                                    "rbac.assignments.list/success"});
}

TEST_CASE("access authz: a plain user with RBAC off is refused every admin panel before any read",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    const auto c = r.cookie("alice", auth::Role::user);

    // The page itself opens (each panel is gated on its own fragment).
    const auto page = r.get("/access/users", c);
    REQUIRE(page);
    CHECK(page->status == 200);
    CHECK_THAT(page->body, ContainsSubstring("alice"));

    for (const char* p : {kUsers, kRoles, kPerms, kAssign}) {
        INFO(p);
        const auto res = r.get(p, c);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(r.user_reads == 0);
    CHECK(r.route_audits.empty()); // no success row for a refused caller
    // One gate denial per refused fragment, except Users: its admin probe is quiet for a cookie session.
    CHECK(r.denied_rows() == 3);

    // The enforcement state is session-only (its REST twin /api/v1/me), and the switch is not live.
    const auto enf = r.get(kEnforce, c);
    REQUIRE(enf);
    CHECK(enf->status == 200);
    CHECK_THAT(enf->body, !ContainsSubstring("data-act=\"enforce\""));
}

TEST_CASE("access authz: a service-scoped token is denied the fleet-wide enforcement state",
          "[pg][access][authz][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    const std::int64_t exp = 0; // non-expiring: the test must not depend on the wall clock
    const auto scoped = r.api_tokens->create_token("svc", "root", exp, "payments", "");
    const auto plain = r.api_tokens->create_token("plain", "root", exp);
    REQUIRE(scoped.has_value());
    REQUIRE(plain.has_value());

    const auto denied = r.get_bearer(kEnforce, *scoped);
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK_THAT(denied->body, !ContainsSubstring("<input"));
    // Clause 5: the deny must not name a permission that would not admit the caller.
    CHECK_THAT(denied->body, !ContainsSubstring("\"permission\""));
    CHECK(r.denied_rows() == 1);

    // A token that is not service-scoped keeps the session-only read.
    const auto ok = r.get_bearer(kEnforce, *plain);
    REQUIRE(ok);
    CHECK(ok->status == 200);

    // An MCP-tier token is not service-scoped either: the read is session-only, as its twin
    // GET /api/v1/me is, so the deny is keyed on the service scope alone.
    const auto mcp = r.api_tokens->create_token("mcp", "root", exp, "", "readonly");
    REQUIRE(mcp.has_value());
    const auto mcp_res = r.get_bearer(kEnforce, *mcp);
    REQUIRE(mcp_res);
    CHECK(mcp_res->status == 200);
}

TEST_CASE("access authz: RBAC on, a user holding only Viewer reads the catalogue but not the grant table",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Viewer"}).has_value());
    const auto c = r.cookie("alice", auth::Role::user);

    CHECK(r.get(kRoles, c)->status == 200);
    CHECK(r.get(kPerms, c)->status == 200);
    // The grant table is authorization topology: AccessReview:Read, which Viewer does not hold.
    const auto grants = r.get(kAssign, c);
    REQUIRE(grants);
    CHECK(grants->status == 403);
    CHECK_THAT(grants->body, !ContainsSubstring("<table"));
    CHECK(r.get(kUsers, c)->status == 403); // the account list is admin-only whatever the grants
    CHECK(r.user_reads == 0);
    CHECK(r.route_audits.empty());
    // No Assign or enforcement control for anyone who is not an account admin.
    CHECK_THAT(r.get(kEnforce, c)->body, !ContainsSubstring("data-act=\"enforce\""));
}

TEST_CASE("access authz: RBAC on, a Reviewer reads the grant table but is offered no write",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Reviewer"}).has_value());
    const auto c = r.cookie("alice", auth::Role::user);

    const auto grants = r.get(kAssign, c);
    REQUIRE(grants);
    CHECK(grants->status == 200);
    CHECK_THAT(grants->body, ContainsSubstring("alice"));
    CHECK_THAT(grants->body, !ContainsSubstring("data-act=\"assign\""));
    CHECK_THAT(grants->body, !ContainsSubstring("data-act=\"unassign\""));
    CHECK(r.route_audits == std::vector<std::string>{"rbac.assignments.list/success"});
}

TEST_CASE("access authz: RBAC on, a user with no role gets the loud denial on every permission-gated panel",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled()); // a vacuous pass here would be the RBAC-off case again
    const auto c = r.cookie("bob", auth::Role::user);

    for (const char* p : {kRoles, kPerms, kAssign}) {
        INFO(p);
        const auto res = r.get(p, c);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, ContainsSubstring("permission"));
    }
    CHECK(r.get(kUsers, c)->status == 403);
    CHECK(r.user_reads == 0);
    CHECK(r.route_audits.empty());
    CHECK(r.denied_rows() == 3); // Roles, Role permissions, Role assignments; the Users probe is quiet
}

TEST_CASE("access authz: RBAC on, an Administrator grant keeps the page usable for the account that flipped it",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "root", "Administrator"}).has_value());
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    const auto c = r.cookie("root", auth::Role::admin);

    for (const char* p : {kUsers, kRoles, kPerms, kAssign, kEnforce}) {
        INFO(p);
        const auto res = r.get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    CHECK_THAT(r.get(kAssign, c)->body, ContainsSubstring("data-act=\"assign\""));
    CHECK_THAT(r.get(kEnforce, c)->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(r.get(kEnforce, c)->body, ContainsSubstring("checked")); // enforcement is on
}

TEST_CASE("access authz: RBAC on, a base admin with NO grant is refused the RBAC-gated panels",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    const auto c = r.cookie("root", auth::Role::admin);

    // The account list is gated on the account role (admin_fn); the catalogue and the grant
    // table follow the RBAC grants, which this account does not hold.
    CHECK(r.get(kUsers, c)->status == 200);
    CHECK(r.get(kRoles, c)->status == 403);
    CHECK(r.get(kAssign, c)->status == 403);
    CHECK(r.route_audits.empty());
}

TEST_CASE("access authz: a request with no session is refused by every fragment and reads nothing",
          "[pg][access][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, access_page_tpl);
    Rig r{db_.dsn()};
    for (const char* p : {kUsers, kRoles, kPerms, kAssign, kEnforce}) {
        INFO(p);
        const auto res = r.sink.dispatch("GET", p);
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(r.user_reads == 0);
    CHECK(r.route_audits.empty());
}
