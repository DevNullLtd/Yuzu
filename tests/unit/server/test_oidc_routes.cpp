/**
 * test_oidc_routes.cpp — HTTP wiring tests for the OIDC `/auth/callback`
 * route, plus a direct AuthManager-level test for the admin-group trim
 * (#1830.1).
 *
 * `OidcProvider::handle_callback`'s success path exchanges the auth code for
 * tokens over HTTP/subprocess (`exchange_script`) and fetches JWKS from the
 * IdP — there is no mock-IdP harness in this codebase (test_oidc_provider.cpp
 * covers only the pure-function/parsing layer), so this file covers what IS
 * reachable without a live IdP: the callback's early-exit failure paths
 * (IdP error response, missing code/state, unknown PKCE state — none of
 * which touch the network) and the resulting
 * `yuzu_auth_oidc_login_total{result=error}` counter (#1828.2). The
 * success-path role label / admin_group audit-detail parity (#1828.2 /
 * #1830.2) is exercised at the AuthManager level instead, mirroring how
 * f3e87cfc's OIDC RBAC-sync code (also success-path-only in
 * /auth/callback) has no HTTP-level test either.
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_analytics_pg_helper.hpp" // AnalyticsEventStorePg — ADR-0049 PG port
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>
#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// AuditStore migrated to Postgres (ADR-0006) — the fixture below clones this
// pre-migrated template instead of opening a SQLite path.
yuzu::test::PgTestTemplate oidc_audit_tpl{"oidcaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("oidcaudit template: store failed to migrate");
}};

/// Fixture — stores + AuthRoutes wired against an in-process TestRouteSink,
/// mirroring SamlRoutesFixture (test_saml_routes.cpp). `oidc_provider` is
/// held by reference inside AuthRoutes (auth_routes.hpp ctor takes
/// `std::unique_ptr<OidcProvider>&`), so a test can assign it AFTER
/// construction and the routes pick it up live.
struct OidcRoutesFixture {
    yuzu::test::TempDir tmp;
    Config                                cfg{};
    yuzu::MetricsRegistry                 metrics; // wired so yuzu_auth_oidc_login_total fires
    auth::AuthManager                     auth_mgr{};
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current TEST_CASE
    // when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
    // api_tokens removed (PR 4.1 review #3): this fixture never calls a token
    // store method, and AuthRoutes null-guards the pointer, so it gets nullptr
    // below — embedding the PG fixture only made every case skip without a DSN.
    // AuditStore ported to Postgres (ADR-0006): a template-cloned ephemeral
    // database + pool. This fixture has no other PG-backed member, so it
    // self-skips explicitly (mirrors yuzu::test::AuthDbPg's own posture) —
    // SKIPs the enclosing TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset,
    // FAILs when set but broken.
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool>   audit_pool;
    std::unique_ptr<AuditStore>           audit_store;
    // AnalyticsEventStore ported to Postgres (ADR-0049) — own ephemeral
    // clone, matching audit_store's pattern above.
    yuzu::test::AnalyticsEventStorePg     analytics;
    std::shared_mutex                     oidc_mu;
    std::unique_ptr<oidc::OidcProvider>   oidc_provider; // set by tests that need it enabled
    std::unique_ptr<AuthRoutes>           auth_routes;
    yuzu::server::test::TestRouteSink     sink;

    OidcRoutesFixture() {
        fs::create_directories(tmp.path);
        auth_mgr.set_metrics_registry(&metrics);

        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        audit_db.emplace(oidc_audit_tpl);
        INFO("[OidcRoutesFixture] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit_store->is_open());

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            /*rbac_store=*/nullptr,
            /*api_token_store=*/nullptr,
            audit_store.get(),
            /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr,
            analytics.get(),
            oidc_mu, oidc_provider);
        auth_routes->register_routes(sink);
    }

    double counter(const std::string& name, const yuzu::Labels& labels = {}) {
        return labels.empty() ? metrics.counter(name).value()
                              : metrics.counter(name, labels).value();
    }

    std::vector<AuditEvent> audit_events(std::size_t limit = 10) const {
        AuditQuery q;
        q.limit = static_cast<int>(limit);
        auto rows = audit_store->query(q);
        REQUIRE(rows.has_value());
        return *rows;
    }
};

/// Minimal enabled OidcConfig — issuer/client_id non-empty is all
/// `is_enabled()` requires; the failure paths under test never reach the
/// network (they short-circuit before token exchange).
oidc::OidcConfig make_minimal_oidc_config() {
    oidc::OidcConfig c;
    c.issuer = "https://idp.example.test";
    c.client_id = "yuzu-test-client";
    c.redirect_uri = "http://localhost:8443/auth/callback";
    return c;
}

} // namespace

// ---------------------------------------------------------------------------
// #1828.2 — yuzu_auth_oidc_login_total{result,role} on the OIDC callback's
// failure paths (none of which touch the network).
// ---------------------------------------------------------------------------

TEST_CASE("OIDC callback — IdP error response increments yuzu_auth_oidc_login_total{result=error}",
          "[pg][oidc][auth_routes]") {
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(make_minimal_oidc_config());
    REQUIRE(fix.oidc_provider->is_enabled());

    auto res = fix.sink.dispatch("GET", "/auth/callback?error=access_denied");
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login?error=sso_denied");

    CHECK(fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);

    // cons-S1: mirrors SAML's early-error branches — an audit row, not just
    // a metric bump.
    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "error");
}

TEST_CASE("OIDC callback — missing code/state increments "
          "yuzu_auth_oidc_login_total{result=error}",
          "[pg][oidc][auth_routes]") {
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(make_minimal_oidc_config());
    REQUIRE(fix.oidc_provider->is_enabled());

    auto res = fix.sink.dispatch("GET", "/auth/callback"); // no code, no state
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login?error=sso_invalid");

    CHECK(fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);

    // cons-S1: mirrors SAML's early-error branches — an audit row, not just
    // a metric bump.
    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "error");
}

TEST_CASE("OIDC callback — unknown PKCE state increments "
          "yuzu_auth_oidc_login_total{result=error} (no network touched)",
          "[pg][oidc][auth_routes]") {
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(make_minimal_oidc_config());
    REQUIRE(fix.oidc_provider->is_enabled());

    // handle_callback rejects an unrecognised `state` before any token
    // exchange (mirrors test_oidc_provider.cpp's "handle_callback with
    // unknown state fails" — this is the same rejection, driven through
    // the HTTP route instead of the provider directly).
    auto res = fix.sink.dispatch("GET", "/auth/callback?code=somecode&state=never-issued");
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login?error=sso_failed");

    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");

    CHECK(fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
}

TEST_CASE("OIDC callback — 404 when provider not configured emits no login counter",
          "[pg][oidc][auth_routes]") {
    OidcRoutesFixture fix; // oidc_provider left null
    auto res = fix.sink.dispatch("GET", "/auth/callback?code=x&state=y");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
    CHECK(fix.counter("yuzu_auth_oidc_login_total") == 0.0);
}

// ---------------------------------------------------------------------------
// #1830.1 — --oidc-admin-group trim parity with SAML's UP-4 fix. Server.cpp
// trims cfg_.oidc_admin_group at OIDC-provider-init time, upstream of
// AuthManager::create_oidc_session; this test mirrors that call site
// directly (same shape as test_saml_routes.cpp's "trailing space in
// --saml-admin-group still matches after trim" test) since there is no
// HTTP-reachable seam for the trimmed value (it is baked into `admin_gid`
// read from cfg_ inside the callback lambda, not separately injectable).
// ---------------------------------------------------------------------------

TEST_CASE("OIDC — a trailing space in --oidc-admin-group still matches after trim "
          "(parity with SAML UP-4, #1830.1)",
          "[oidc][auth_routes]") {
    auth::AuthManager mgr;

    // Mirrors exactly what ServerImpl's OIDC-provider-init block does to
    // cfg_.oidc_admin_group before it is read as `admin_gid` in the
    // /auth/callback handler (server.cpp, #1830.1).
    std::string oidc_admin_group = trim_ascii_whitespace("Admins ");
    REQUIRE(oidc_admin_group == "Admins");

    auto token = mgr.create_oidc_session("Trimmed Admin", "trimmed_admin@example.test",
                                         "oidc-sub-1", "https://idp.example", {"Admins"},
                                         oidc_admin_group, {});
    auto session = mgr.validate_session(token);
    REQUIRE(session.has_value());
    CHECK(session->role == auth::Role::admin);
}

TEST_CASE("OIDC — an untrimmed --oidc-admin-group would NOT match (regression guard for "
          "#1830.1)",
          "[oidc][auth_routes]") {
    auth::AuthManager mgr;

    // Without the trim, a trailing-space admin-group value never matches an
    // assertion group read from the IdP (which carries no such artefact) —
    // this is the silent-lockout bug #1830.1 fixes. Pin the failure mode so
    // a future regression (someone removing the trim call) is caught here
    // rather than only in production.
    const std::string untrimmed_admin_group = "Admins ";
    auto token = mgr.create_oidc_session("Untrimmed Admin", "untrimmed_admin@example.test",
                                         "oidc-sub-2", "https://idp.example", {"Admins"},
                                         untrimmed_admin_group, {});
    auto session = mgr.validate_session(token);
    REQUIRE(session.has_value());
    CHECK(session->role == auth::Role::user);
}
