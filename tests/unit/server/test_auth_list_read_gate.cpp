/**
 * test_auth_list_read_gate.cpp — coverage for AuthRoutes::require_list_read
 * (ADR-0017, #3038 fix): the session-class ladder for the flat list-read
 * gate a fleet-wide aggregate route uses as its SOLE authorization gate.
 *
 * Scope: the session-class branches ABOVE the RBAC delegate (Read-only
 * structural check, JIT elevation, MCP tier, service-scoped token, no-store
 * legacy), plus a smoke test of the delegate itself. Two things are
 * DELIBERATELY not duplicated here:
 *   - Engine-principal cases live in test_engine_principal_integration.cpp,
 *     next to EngineRbacGateFixture — its PG engine-principal machinery
 *     (EnginePrincipalStore + referent-check wiring) is nontrivial to
 *     replicate and already exists there.
 *   - The RBAC combining lattice (DenyAll/AdmitAll/AdmitScoped, INV-1..INV-7)
 *     is owned by test_list_read_confinement.cpp, which tests
 *     RbacStore::authorize_list_read directly — this file only asserts that
 *     require_list_read delegates to it correctly for the ordinary case.
 */

#include "auth_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — shared PG-backed ApiTokenStore helper
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_rbac_store_pg_helper.hpp" // RbacStorePg — RbacStore is PG-only (ADR-0041)

#include "../test_helpers.hpp" // PgTestTemplate, pg_admin_dsn_env

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>

using namespace yuzu::server;

namespace {

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// AuditStore, for the ONE test below that asserts on require_list_read's own
// denial audit-row content — every other test in this file passes
// audit_store=nullptr (a no-op audit sink), which is deliberate (the ladder
// logic under test doesn't depend on audit persistence). Mirrors
// test_authz_topology_floor.cpp's FloorFixture/authz_floor_audit_tpl pattern.
yuzu::test::PgTestTemplate list_read_gate_audit_tpl{
    "listreadgateaudit", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::AuditStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("listreadgateaudit template: store failed to migrate");
    }};

/// Wires a real AuthRoutes with a real (PG-backed, ADR-0041) RbacStore
/// (present, RBAC disabled by default — tests toggle via
/// rbac_store.set_rbac_enabled) and a PG-backed ApiTokenStore, so each test
/// only has to mint a session/token and call require_list_read directly.
/// mgmt_group_store is deliberately null —
/// AdmitScoped needs a real ManagementGroupStore and is exercised at the
/// route level in test_rest_guaranteed_state.cpp, not here; a null mgmt
/// store still lets DenyAll/AdmitAll resolve correctly (resolve_perm_groups
/// fails closed to DenyAll on a null store, same outcome as "no grant").
struct ListReadGateFixture {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::RbacStorePg rbac_bundle_;
    RbacStore& rbac_store = *rbac_bundle_;
    yuzu::test::ApiTokenStorePg api_tokens;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    ListReadGateFixture() {
        REQUIRE(rbac_store.is_open());
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac_store, api_tokens.get(),
                                          /*audit_store=*/nullptr,
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    httplib::Request session_request(const std::string& username, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", role));
        auto token = auth_mgr.create_local_session(username, role, /*mfa_verified=*/true);
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    /// Mirrors the production `/api/v1/elevate` route, minus the eligibility/
    /// MFA-step-up gates that route itself owns.
    httplib::Request elevated_session_request(const std::string& username) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", auth::Role::user));
        auto token = auth_mgr.create_local_session(username, auth::Role::user,
                                                    /*mfa_verified=*/true);
        REQUIRE(auth_mgr.elevate_session(token, std::chrono::seconds(300)).has_value());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    static httplib::Request token_request(const std::string& raw) {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + raw);
        return req;
    }
};

} // namespace

TEST_CASE("require_list_read — JIT-elevated session admitted unfiltered without any RBAC "
          "grant (the fix for the SEC-7 regression the first #3038 fix attempt shipped)",
          "[pg][auth_routes][adr0017]") {
    ListReadGateFixture fix;
    // RBAC ON, but the user holds no grant of any kind — elevation alone must
    // still admit, and require_list_read must NOT call authorize_list_read
    // for an elevated session (which would deny a grant-less caller).
    fix.rbac_store.set_rbac_enabled(true);
    auto req = fix.elevated_session_request("elevated_user");
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Read");
    CHECK(gate.admitted);
    CHECK_FALSE(gate.scope.has_value()); // unfiltered
}

TEST_CASE("require_list_read — a non-Read operation is denied structurally",
          "[pg][auth_routes][adr0017]") {
    ListReadGateFixture fix;
    auto req = fix.session_request("plain_user", auth::Role::user);
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Write");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
}

TEST_CASE("require_list_read — every valid MCP tier (readonly/operator/supervised) is "
          "allowed for Read; ApiTokenStore::create_token itself rejects any other tier "
          "string at mint time (mcp::is_valid_tier), so a Read-only list-read gate has NO "
          "reachable tier-denial case for a real minted token — verified empirically: an "
          "earlier version of this test tried to mint a token with an invalid tier and "
          "REQUIRE(raw.has_value()) failed",
          "[pg][auth_routes][adr0017][mcp]") {
    ListReadGateFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("test_user", "password1234", auth::Role::admin));
    for (const std::string tier : {"readonly", "operator", "supervised"}) {
        auto raw = fix.api_tokens->create_token("mcp-lr-" + tier, "test_user", now_epoch() + 3600,
                                                "", tier);
        REQUIRE(raw.has_value());
        auto req = ListReadGateFixture::token_request(*raw);
        httplib::Response res;
        auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Read");
        INFO("tier=" << tier);
        // RBAC is disabled by default on a fresh RbacStore — falls through
        // the tier check into authorize_list_read's legacy-open AdmitAll.
        CHECK(gate.admitted);
        CHECK_FALSE(gate.scope.has_value());
    }
}

TEST_CASE("require_list_read — a service-scoped token is denied outright (no per-agent "
          "target to scope it against, unlike require_scoped_permission)",
          "[pg][auth_routes][adr0017]") {
    ListReadGateFixture fix;
    REQUIRE(fix.auth_mgr.upsert_user("test_user", "password1234", auth::Role::admin));
    auto raw = fix.api_tokens->create_token("scoped-lr", "test_user", now_epoch() + 3600,
                                            "finance-svc", "");
    REQUIRE(raw.has_value());
    auto req = ListReadGateFixture::token_request(*raw);
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
}

TEST_CASE("require_list_read — no rbac_store wired admits unfiltered (exact legacy "
          "semantics of require_permission's rbac_store_==nullptr short-circuit)",
          "[auth_routes][adr0017]") {
    Config cfg;
    auth::AuthManager auth_mgr;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, /*rbac_store=*/nullptr, /*api_token_store=*/nullptr,
                 /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    REQUIRE(auth_mgr.upsert_user("plain_user", "password1234", auth::Role::user));
    auto token =
        auth_mgr.create_local_session("plain_user", auth::Role::user, /*mfa_verified=*/true);
    httplib::Request req;
    req.headers.emplace("Cookie", "yuzu_session=" + token);
    httplib::Response res;
    auto gate = ar.require_list_read(req, res, "GuaranteedState", "Read");
    CHECK(gate.admitted);
    CHECK_FALSE(gate.scope.has_value());
}

TEST_CASE("require_list_read — ordinary RBAC delegate: no grant denies, a global grant "
          "admits unfiltered (smoke only; the full combining lattice is covered by "
          "test_list_read_confinement.cpp)",
          "[pg][auth_routes][adr0017]") {
    ListReadGateFixture fix;
    fix.rbac_store.set_rbac_enabled(true);

    SECTION("no grant anywhere -> DenyAll -> 403") {
        auto req = fix.session_request("no_grant_user", auth::Role::user);
        httplib::Response res;
        auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Read");
        CHECK_FALSE(gate.admitted);
        CHECK(res.status == 403);
    }

    SECTION("a global grant -> AdmitAll -> unfiltered") {
        REQUIRE(fix.rbac_store.create_role({.name = "GsReader", .description = "d"}).has_value());
        REQUIRE(fix.rbac_store
                    .set_permission({"GsReader", "GuaranteedState", "Read", "allow"})
                    .has_value());
        REQUIRE(fix.rbac_store.assign_role({"user", "global_user", "GsReader"}).has_value());
        auto req = fix.session_request("global_user", auth::Role::user);
        httplib::Response res;
        auto gate = fix.ar->require_list_read(req, res, "GuaranteedState", "Read");
        CHECK(gate.admitted);
        CHECK_FALSE(gate.scope.has_value());
    }
}

TEST_CASE("require_list_read — a DenyAll denial writes a real audit row (governance "
          "Gate 6 follow-up: every other test in this file uses a no-op audit_store, "
          "so nothing previously asserted on require_list_read's own audit content)",
          "[pg][auth_routes][adr0017][audit]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    yuzu::test::PostgresTestDb audit_db{list_read_gate_audit_tpl};
    INFO("[audit db] status (blank == ok): " << audit_db.error());
    REQUIRE(audit_db.available());
    yuzu::server::pg::PgPool audit_pool{{.conninfo = audit_db.dsn(), .size = 2}};
    AuditStore audit_store{audit_pool};
    REQUIRE(audit_store.is_open());

    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    REQUIRE(rbac_store.is_open());
    rbac_store.set_rbac_enabled(true); // enforcement in effect; no roles/grants created
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    AuthRoutes ar(cfg, auth_mgr, &rbac_store, /*api_token_store=*/nullptr, &audit_store,
                 /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                 /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

    REQUIRE(auth_mgr.upsert_user("audited_no_grant_user", "password1234", auth::Role::user));
    auto token = auth_mgr.create_local_session("audited_no_grant_user", auth::Role::user,
                                               /*mfa_verified=*/true);
    httplib::Request req;
    req.headers.emplace("Cookie", "yuzu_session=" + token);
    httplib::Response res;
    auto gate = ar.require_list_read(req, res, "GuaranteedState", "Read");
    REQUIRE_FALSE(gate.admitted);
    REQUIRE(res.status == 403);

    auto rows = audit_store.query(
        AuditQuery{.action = "auth.permission_required", .limit = 1});
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    CHECK(rows->front().result == "denied");
    CHECK(rows->front().detail.find("GuaranteedState:Read") != std::string::npos);
}
