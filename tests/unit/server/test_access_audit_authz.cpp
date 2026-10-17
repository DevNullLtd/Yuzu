/**
 * @file test_access_audit_authz.cpp
 * @brief [pg] persona matrix for the Audit and reviews page, driven through the REAL AuthRoutes
 *        gates over a real RbacStore and AuditStore. test_access_audit_routes.cpp stubs the
 *        gate; this file proves the production wiring admits and refuses the right callers.
 *
 * The case that matters most: a signed-in non-admin with RBAC OFF (the shipped default) is
 * refused the audit trail. That is the #5771 floor (`AuditLog:Read` in kTopologyFloor); the page
 * adds nothing of its own, so removing the floor row turns the legacy-user cases red here.
 *
 * Personas (cookie sessions): Administrator (RBAC off), plain user (RBAC off), and with RBAC on
 * an Operator (holds AuditLog:Read, not ServerConfig:Read), a Reviewer (AccessReview only) and
 * a Viewer (AuditLog:Read). For each: status per fragment, whether the store was read, and the
 * denied-access rows written.
 *
 * Needs YUZU_TEST_POSTGRES_DSN (SKIPs without it); run serially.
 */

#include "access_audit_routes.hpp"
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

yuzu::test::PgTestTemplate audit_page_tpl{"rbacstore_auditpage", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("rbac (audit page) template: store failed to migrate/seed");
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
    int reads{0};
    yuzu::server::test::TestRouteSink sink;  // LAST: handlers capture `this`

    explicit Rig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, audit_pool{{.conninfo = dsn, .size = 2}},
          audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(audit_store.is_open());
        for (const char* u : {"root", "alice", "bob", "carol"})
            REQUIRE(auth_mgr.upsert_user(u, "correct-horse-battery-staple",
                                         std::string(u) == "root" ? auth::Role::admin
                                                                  : auth::Role::user));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit_store,
                                          &*mgmt_bundle, nullptr, nullptr, oidc_mu, oidc_provider);

        access_audit::Deps d;
        d.auth_fn = [this](const httplib::Request& q, httplib::Response& r) {
            return ar->require_auth(q, r);
        };
        d.perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                           const std::string& o) { return ar->require_permission(q, r, t, o); };
        d.quiet_perm_fn = [this](const httplib::Request& q, httplib::Response& r, const std::string& t,
                                 const std::string& o) { return ar->probe_permission(q, r, t, o); };
        d.audit_fn = [this](const httplib::Request&, const std::string&, const std::string&,
                            const std::string&, const std::string&, const std::string&) {
            return true;
        };
        d.query_fn = [this](const AuditQuery& q, std::size_t* p) {
            ++reads;
            return audit_store.query(q, p);
        };
        d.retention_days_fn = [] { return 365; };
        d.now_fn = [] { return now_epoch(); };
        access_audit::register_access_audit_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& path, const std::string& token) {
        return sink.dispatch("GET", path, {}, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }
    std::string session(const char* user, auth::Role role) {
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
    void assign(const char* user, const char* role) {
        REQUIRE(rbac.assign_role({"user", user, role}).has_value());
    }
};

constexpr const char* kLog = "/fragments/access/audit/log";
constexpr const char* kSample = "/fragments/access/audit/sample";
constexpr const char* kRetention = "/fragments/access/audit/retention";

} // namespace

TEST_CASE("audit page authz: Administrator with RBAC off reads the log, the sample and retention",
          "[pg][access-audit][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, audit_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.session("root", auth::Role::admin);

    auto res = r.get("/access/audit", cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    for (const char* p : {kLog, kSample, kRetention}) {
        INFO(p);
        res = r.get(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 200);
    }
    CHECK_THAT(r.get(kRetention, cookie)->body, ContainsSubstring("<b>365 days</b>"));
    CHECK(r.reads == 2);  // log + sample
    CHECK(r.denied_rows() == 0);
}

TEST_CASE("audit page authz: a plain user with RBAC off is refused the audit trail (#5771 floor)",
          "[pg][access-audit][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, audit_page_tpl);
    Rig r{db_.dsn()};
    const auto cookie = r.session("alice", auth::Role::user);

    // Opening the page costs no denial: each panel is gated by its own fragment.
    auto res = r.get("/access/audit", cookie);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(r.denied_rows() == 0);

    for (const char* p : {kLog, kSample, kRetention}) {
        INFO(p);
        res = r.get(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_THAT(res->body, !ContainsSubstring("<table"));
    }
    CHECK(r.reads == 0);
    // The log auto-loads, so its refusal is a quiet probe (no row for a cookie session); the
    // sample and retention panels run on request and keep the loud gate.
    CHECK(r.denied_rows() == 2);
}

TEST_CASE("audit page authz: RBAC on, Operator and Viewer read the log but not retention",
          "[pg][access-audit][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, audit_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    r.assign("alice", "Operator");
    r.assign("carol", "Viewer");

    for (const auto& [user, role] : {std::pair{"alice", "Operator"}, std::pair{"carol", "Viewer"}}) {
        INFO(role);
        const auto cookie = r.session(user, auth::Role::user);
        auto res = r.get(kLog, cookie);
        REQUIRE(res);
        CHECK(res->status == 200);
        res = r.get(kRetention, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);  // ServerConfig:Read is Administrator-only
    }
    CHECK(r.reads == 2);
    CHECK(r.denied_rows() == 2);
}

TEST_CASE("audit page authz: RBAC on, a Reviewer holds AccessReview only and is refused the log",
          "[pg][access-audit][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db_, audit_page_tpl);
    Rig r{db_.dsn()};
    r.rbac.set_rbac_enabled(true);
    r.assign("bob", "Reviewer");
    const auto cookie = r.session("bob", auth::Role::user);

    for (const char* p : {kLog, kSample}) {
        INFO(p);
        const auto res = r.get(p, cookie);
        REQUIRE(res);
        CHECK(res->status == 403);  // AccessReview:Read does not satisfy AuditLog:Read
    }
    CHECK(r.reads == 0);
    CHECK(r.denied_rows() == 1);  // the sample only; the auto-loading log is probed quietly
}
