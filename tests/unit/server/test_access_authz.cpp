/**
 * @file test_access_authz.cpp
 * @brief [pg] persona matrix for the Users and roles fragments, driven through the REAL AuthRoutes
 *        gates (require_auth / probe_admin / require_permission) over a real RbacStore, AuthDB
 *        (on the same database, as production) and AuditStore. test_access_routes.cpp stubs the
 *        gates and the hint; this file proves the production wiring admits and refuses the right
 *        callers, with RBAC off (the shipped default) and on.
 *
 * Personas (cookie sessions): Administrator and plain user with RBAC off; with RBAC on a user
 * holding Viewer, one holding Reviewer, one holding nothing, an account administrator with and
 * without the Administrator grant, a base user holding the grant, a principal holding the grant
 * with no auth.users row, a JIT-elevated user, and an unanswerable authority check. For each:
 * which fragments answer, whether the store behind a refused fragment was ever read, the audit
 * rows written, and (#6034) whether Assign role and the enforcement switch are drawn live,
 * disabled with a reason, or not at all. The Rig binds the same `rbac_admin_hint` symbol
 * server.cpp binds, never a stub; the hint-equals-route equality lives in test_rbac_admin_hint.cpp.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_routes.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_admin_predicate.hpp"
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_auth_db_rbac_pg_template.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <ctime>
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

struct Rig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    // AuthDB + RbacStore on ONE database, as production: the hint's regime check JOINs
    // rbac_store.principal_roles to auth.users. The AuthManager above stays in-memory (it only
    // mints the sessions); every account is mirrored into the AuthDB so the durable row exists.
    yuzu::test::AuthDbPg adb{0, false, &yuzu::test::auth_db_rbac_pg_template};
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

    Rig()
        : rbac{adb.pool()}, audit_pool{{.conninfo = adb.dsn(), .size = 2}}, audit_store{audit_pool} {
        REQUIRE(rbac.is_open());
        REQUIRE(audit_store.is_open());
        const std::pair<const char*, auth::Role> accounts[] = {
            {"root", auth::Role::admin}, {"alice", auth::Role::user}, {"bob", auth::Role::user}};
        for (const auto& [name, role] : accounts) {
            REQUIRE(auth_mgr.upsert_user(name, "correct-horse-battery-staple", role));
            REQUIRE(adb->upsert_user(name, "hash", "salt", role).has_value());
        }
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
        // The SAME symbol server.cpp binds, over the same store pair: the page is drawn from the
        // authority the A2/A1 routes apply, never from a stub.
        d.rbac_admin_hint_fn = [this](const auth::Session& s) {
            return rbac_admin_hint(s, adb.get(), &rbac, RbacAdminSurface::kRest);
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
    Rig r;
    const auto c = r.cookie("root", auth::Role::admin);

    for (const char* p : {kUsers, kRoles, kPerms, kAssign, kEnforce}) {
        INFO(p);
        const auto res = r.get(p, c);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    const auto assign = r.get(kAssign, c);
    CHECK_THAT(assign->body, ContainsSubstring("data-act=\"assign\""));
    // The real catalogue, filtered to the closed assignable list: seven names, never ITServiceOwner.
    CHECK_THAT(assign->body,
               ContainsSubstring("data-roles=\"Administrator,ApiTokenManager,ForensicsAnalyst,Operator,"
                                 "PlatformEngineer,Reviewer,Viewer\""));
    CHECK_THAT(r.get(kEnforce, c)->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK(r.denied_rows() == 0);
    // The grant-table read leaves its own audit row, exactly as its REST twin.
    CHECK(r.route_audits == std::vector<std::string>{"rbac.assignments.list/success",
                                                    "rbac.assignments.list/success"});
}

TEST_CASE("access authz: a plain user with RBAC off is refused every admin panel before any read",
          "[pg][access][authz]") {
    Rig r;
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
    Rig r;
    r.rbac.set_rbac_enabled(true);
    const auto exp = static_cast<std::int64_t>(std::time(nullptr)) + 3600; // an MCP-tier token needs a bounded TTL
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

TEST_CASE("access authz: RBAC off, a durable administrator's plain API token is drawn the live "
          "controls and its MCP-tier token is not (the real session fields reach the hint)",
          "[pg][access][authz][security]") {
    Rig r; // RBAC off: the predicate admits root's durable admin row for a session that carries no tier
    REQUIRE_FALSE(r.rbac.is_rbac_enabled());
    const auto exp = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
    const auto plain = r.api_tokens->create_token("plain", "root", exp);
    const auto mcp = r.api_tokens->create_token("mcp", "root", exp, "", "readonly");
    REQUIRE(plain.has_value());
    REQUIRE(mcp.has_value());

    // P12 by design: a plain token's gates never read auth_source, so the switch and the Assign
    // button are drawn live (every click is re-gated by its route).
    const auto plain_enf = r.get_bearer(kEnforce, *plain);
    REQUIRE(plain_enf);
    CHECK(plain_enf->status == 200);
    CHECK_THAT(plain_enf->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(plain_enf->body, !ContainsSubstring("Only a durable Administrator can change this."));
    const auto plain_assign = r.get_bearer(kAssign, *plain);
    REQUIRE(plain_assign);
    CHECK(plain_assign->status == 200);
    CHECK_THAT(plain_assign->body, ContainsSubstring("data-act=\"assign\""));

    // P9: the MCP tier is a structural deny on the REST surface, so a session that dropped
    // `mcp_tier` on its way to the hint would draw live controls here and fail these bodies.
    const auto mcp_enf = r.get_bearer(kEnforce, *mcp);
    REQUIRE(mcp_enf);
    CHECK(mcp_enf->status == 200);
    CHECK_THAT(mcp_enf->body, !ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(mcp_enf->body, ContainsSubstring("disabled title=\"Only a durable Administrator can change this.\""));
    const auto mcp_assign = r.get_bearer(kAssign, *mcp);
    REQUIRE(mcp_assign);
    CHECK_THAT(mcp_assign->body, !ContainsSubstring("data-act=\"assign\""));
    CHECK_THAT(mcp_assign->body, !ContainsSubstring(">Assign role<"));
}

TEST_CASE("access authz: RBAC on, a user holding only Viewer reads the catalogue but not the grant table",
          "[pg][access][authz]") {
    Rig r;
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
    // No live Assign or enforcement control without a durable Administrator grant.
    CHECK_THAT(r.get(kEnforce, c)->body, !ContainsSubstring("data-act=\"enforce\""));
}

TEST_CASE("access authz: RBAC on, a Reviewer reads the grant table but is offered no write",
          "[pg][access][authz]") {
    Rig r;
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
    Rig r;
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
    Rig r;
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

TEST_CASE("access authz: RBAC on, a base admin with NO grant is refused the RBAC-gated panels and offered no switch",
          "[pg][access][authz]") {
    Rig r;
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.is_rbac_enabled());
    const auto c = r.cookie("root", auth::Role::admin);

    // The account list is gated on the account role (admin_fn); the catalogue and the grant
    // table follow the RBAC grants, which this account does not hold.
    CHECK(r.get(kUsers, c)->status == 200);
    CHECK(r.get(kRoles, c)->status == 403);
    CHECK(r.get(kAssign, c)->status == 403);
    CHECK(r.route_audits.empty());

    // #6034: the server would refuse this account's PUT /api/v1/rbac/enforcement (no durable
    // Administrator grant), so the switch is drawn disabled with the honest reason, not live.
    const auto enf = r.get(kEnforce, c);
    REQUIRE(enf);
    CHECK(enf->status == 200);
    CHECK_THAT(enf->body, !ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(enf->body, ContainsSubstring("disabled title=\"Only a durable Administrator can change this.\""));
}

TEST_CASE("access authz: RBAC on, a base USER holding the Administrator grant is offered both controls (#6034)",
          "[pg][access][authz]") {
    Rig r;
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Administrator"}).has_value());
    REQUIRE(r.rbac.assign_role({"user", "bob", "Viewer"}).has_value());
    const auto c = r.cookie("alice", auth::Role::user); // the account role is `user`

    const auto assign = r.get(kAssign, c);
    REQUIRE(assign);
    CHECK(assign->status == 200);
    CHECK_THAT(assign->body, ContainsSubstring("data-act=\"assign\""));
    CHECK_THAT(assign->body, ContainsSubstring("data-act=\"unassign\"")); // bob's Viewer grant is removable
    const auto enf = r.get(kEnforce, c);
    REQUIRE(enf);
    CHECK_THAT(enf->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(enf->body, ContainsSubstring("checked"));
}

TEST_CASE("access authz: RBAC on, an SSO-style principal with the grant but no auth.users row is offered nothing (P7)",
          "[pg][access][authz]") {
    Rig r;
    r.rbac.set_rbac_enabled(true);
    // carol exists as a session in the in-memory manager only: no durable auth.users row.
    REQUIRE(r.auth_mgr.upsert_user("carol", "correct-horse-battery-staple", auth::Role::user));
    REQUIRE(r.rbac.assign_role({"user", "carol", "Administrator"}).has_value());
    const auto c = r.cookie("carol", auth::Role::user);

    // The grant admits her to the grant table (AccessReview:Read) but the A2/A1 routes would
    // refuse her: the regime check needs an active auth.users row. No control is drawn.
    const auto assign = r.get(kAssign, c);
    REQUIRE(assign);
    CHECK(assign->status == 200);
    CHECK_THAT(assign->body, !ContainsSubstring("data-act="));
    CHECK_THAT(r.get(kEnforce, c)->body, !ContainsSubstring("data-act=\"enforce\""));
}

TEST_CASE("access authz: a JIT-elevated user without a durable grant is offered no control (P8)",
          "[pg][access][authz]") {
    for (const bool rbac_on : {false, true}) {
        INFO("rbac_on=" << rbac_on);
        Rig r;
        r.rbac.set_rbac_enabled(rbac_on);
        const auto c = r.cookie("alice", auth::Role::user);
        REQUIRE(r.auth_mgr.elevate_session(c, std::chrono::seconds(300)).has_value());

        // Elevation lifts the permission gate (the grant table is readable) ...
        const auto assign = r.get(kAssign, c);
        REQUIRE(assign);
        CHECK(assign->status == 200);
        // ... but never the durable-Administrator predicate the writes apply.
        CHECK_THAT(assign->body, !ContainsSubstring("data-act="));
        CHECK_THAT(r.get(kEnforce, c)->body, !ContainsSubstring("data-act=\"enforce\""));
    }
}

TEST_CASE("access authz: an unreadable authority check disables the controls with the reason, never hides them (P13)",
          "[pg][access][authz]") {
    Rig r;
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Administrator"}).has_value());
    const auto c = r.cookie("alice", auth::Role::user);
    {
        // The predicate still answers from principal_roles; the regime check's auth.users JOIN
        // cannot run, which is exactly the route's 503.
        auto lease = r.adb.pool().acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), "ALTER TABLE auth.users RENAME TO users_hint_gone",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    const std::string reason(access::kAdminUnconfirmed);
    const auto assign = r.get(kAssign, c);
    REQUIRE(assign);
    CHECK(assign->status == 200);
    CHECK_THAT(assign->body, ContainsSubstring("disabled title=\"" + reason + "\""));
    CHECK_THAT(assign->body, !ContainsSubstring("data-act=\"assign\""));
    const auto enf = r.get(kEnforce, c);
    REQUIRE(enf);
    CHECK_THAT(enf->body, ContainsSubstring("disabled title=\"" + reason + "\""));
    CHECK_THAT(enf->body, !ContainsSubstring("data-act=\"enforce\""));
    CHECK_THAT(enf->body, !ContainsSubstring("Only a durable Administrator can change this."));
}

TEST_CASE("access authz: drawing the controls writes no audit row of its own beyond the grant-table read",
          "[pg][access][authz]") {
    Rig r;
    r.rbac.set_rbac_enabled(true);
    REQUIRE(r.rbac.assign_role({"user", "alice", "Administrator"}).has_value());
    const auto c = r.cookie("alice", auth::Role::user);
    const int denied_before = r.denied_rows();

    // The enforcement fragment has no audit write of its own: the hint must add none.
    CHECK_THAT(r.get(kEnforce, c)->body, ContainsSubstring("data-act=\"enforce\""));
    CHECK(r.route_audits.empty());
    CHECK(r.denied_rows() == denied_before);

    // A refused persona's hint is silent too (no denial row, no route row).
    const auto b = r.cookie("bob", auth::Role::user);
    CHECK_THAT(r.get(kEnforce, b)->body, !ContainsSubstring("data-act=\"enforce\""));
    CHECK(r.route_audits.empty());
    CHECK(r.denied_rows() == denied_before);
    {
        auto rows = r.audit_store.query({});
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("access authz: a request with no session is refused by every fragment and reads nothing",
          "[pg][access][authz]") {
    Rig r;
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
