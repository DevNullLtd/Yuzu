/**
 * test_oidc_routes.cpp — HTTP wiring tests for the OIDC `/auth/callback`
 * route, plus a direct AuthManager-level test for the admin-group trim
 * (#1830.1).
 *
 * (The binding tests at the end of this file DO have a loopback IdP: test_oidc_mock_idp.hpp.)
 *
 * `OidcProvider::handle_callback`'s success path exchanges the auth code for
 * tokens over HTTP and fetches JWKS from the IdP. The early cases in this
 * file need no IdP and cover the callback's early-exit failure paths
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
#include "oidc_writer_gate.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "session_store.hpp"
#include "test_oidc_mock_idp.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>
#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <thread>
#include <chrono>
#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

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

TEST_CASE("OIDC callback — an IdP error with line breaks cannot forge a log line or an audit "
          "detail - and the response is unchanged",
          "[pg][oidc][auth_routes][log_fold][security]") {
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(make_minimal_oidc_config());
    REQUIRE(fix.oidc_provider->is_enabled());

    // Unauthenticated, no IdP involved: both parameters are attacker-chosen. The error carries
    // LF plus the audit detail's own separators; the description carries LF and the Unicode breaks.
    yuzu::test::LogCapture cap;
    auto res = fix.sink.dispatch(
        "GET", "/auth/callback?error=x%0AFORGED%3Brole%3Dadmin&error_description=a%0Ab%C2%85c"
               "%E2%80%A8d%E2%80%A9e");
    cap.stop();
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login?error=sso_denied");
    CHECK(res->body.empty());

    const auto logs = cap.text();
    CAPTURE(logs);
    const auto at = logs.find("OIDC error from IdP");
    REQUIRE(at != std::string::npos);
    const auto rest = logs.substr(at);
    CHECK(std::count(rest.begin(), rest.end(), '\n') == 1); // only the terminator
    CHECK(logs.find("\nFORGED") == std::string::npos);
    CHECK(logs.find("\xC2\x85") == std::string::npos);
    CHECK(logs.find("\xE2\x80\xA8") == std::string::npos);
    CHECK(logs.find("\xE2\x80\xA9") == std::string::npos);

    const auto events = fix.audit_events();
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "error");
    CAPTURE(events.front().detail);
    CHECK(events.front().detail == "idp error: x_FORGED_role_admin");
    CHECK(events.front().detail.find('\n') == std::string::npos);
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
    // The callback requires the initiating-browser binding cookie, so this request carries one
    // (any value: an unknown state is rejected before the binding is compared); without it the
    // request would be refused earlier and never reach the provider.
    auto res = fix.sink.dispatch("GET", "/auth/callback?code=somecode&state=never-issued", {},
                                 "application/json",
                                 {{"Cookie", "__Host-yuzu_oidc_bind=" + std::string(64, 'a')}});
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

// ---------------------------------------------------------------------------
// Initiating-browser binding on /auth/oidc/start + /auth/callback.
//
// Two "browsers" (cookie jars) drive the real routes against one provider. Browser A starts a
// flow and finishes it; browser B opens the same callback URL. A fixture that merely checks the
// happy path would stay green with the binding deleted: every refusal case below asserts the IdP
// was NEVER asked to exchange the code (`token_calls`), and the success cases assert a session
// cookie.
// ---------------------------------------------------------------------------

namespace {

/// A browser: a cookie jar that honours Set-Cookie (including Max-Age=0 deletion).
struct Browser {
    std::map<std::string, std::string> jar;

    void absorb(const httplib::Response& res) {
        for (auto [it, end] = res.headers.equal_range("Set-Cookie"); it != end; ++it) {
            const std::string& sc = it->second;
            const auto semi = sc.find(';');
            const std::string nv = sc.substr(0, semi);
            const auto eq = nv.find('=');
            if (eq == std::string::npos)
                continue;
            const std::string name = nv.substr(0, eq), value = nv.substr(eq + 1);
            if (sc.find("Max-Age=0") != std::string::npos || value.empty())
                jar.erase(name);
            else
                jar[name] = value;
        }
    }
    std::unordered_map<std::string, std::string> headers() const {
        if (jar.empty())
            return {};
        std::string c;
        for (const auto& [k, v] : jar)
            c += (c.empty() ? "" : "; ") + k + "=" + v;
        return {{"Cookie", c}};
    }
};

std::vector<std::string> set_cookies(const httplib::Response& res) {
    std::vector<std::string> out;
    for (auto [it, end] = res.headers.equal_range("Set-Cookie"); it != end; ++it)
        out.push_back(it->second);
    return out;
}

oidc::OidcConfig flow_cfg(const std::string& token_endpoint) {
    oidc::OidcConfig c;
    c.issuer = "https://idp.example.test";
    c.client_id = "yuzu-test-client";
    c.redirect_uri = "https://yuzu.example.test/auth/callback";
    c.authorization_endpoint = c.issuer + "/authorize"; // explicit: no discovery (no network)
    c.token_endpoint = token_endpoint;
    // Explicit and refused instantly: were the per-field rule to regress, a flow fails here
    // instead of reaching a real discovery fetch.
    c.jwks_uri = "http://127.0.0.1:1/jwks";
    // The mock IdPs listen on loopback, which the egress policy refuses by default.
    c.allow_private_networks = true;
    return c;
}

} // namespace

// The rig below runs a loopback token endpoint (a real httplib acceptor thread and client), which
// crashes the ThreadSanitizer build (#438 class): every route case that needs it is compiled out
// there. The cases that reach no network sit after the #endif.
#ifndef YUZU_OIDC_MOCK_IDP_TSAN

namespace {

bool has_cookie_named(const httplib::Response& res, const std::string& prefix) {
    for (const auto& c : set_cookies(res))
        if (c.starts_with(prefix))
            return true;
    return false;
}

bool binding_cookie_cleared(const httplib::Response& r) {
    for (const auto& c : set_cookies(r))
        if (c.starts_with("__Host-yuzu_oidc_bind=;") && c.find("Max-Age=0") != std::string::npos)
            return true;
    return false;
}

struct Started {
    std::string state;
    std::string jwt; ///< the id_token the loopback IdP will return for THIS flow
};

struct BindingRig {
    yuzu::server::test::MockIdp idp;
    OidcRoutesFixture fix;
    oidc::OidcConfig cfg;

    BindingRig() {
        cfg = flow_cfg(idp.token_endpoint());
        fix.oidc_provider = std::make_unique<oidc::OidcProvider>(cfg);
        fix.cfg.oidc_redirect_uri = cfg.redirect_uri;
    }

    std::unique_ptr<httplib::Response> get(Browser& b, const std::string& path) {
        auto r = fix.sink.dispatch("GET", path, {}, "application/json", b.headers());
        REQUIRE(r != nullptr);
        b.absorb(*r);
        return r;
    }

    /// `b` visits /auth/oidc/start; returns the flow's state and a matching signed id_token.
    Started start(Browser& b, const std::string& sub = "alice-sub") {
        auto r = get(b, "/auth/oidc/start");
        REQUIRE(r->status == 302);
        const auto loc = r->get_header_value("Location");
        Started s;
        s.state = yuzu::server::test::url_query_param(loc, "state");
        const auto nonce = yuzu::server::test::url_query_param(loc, "nonce");
        REQUIRE_FALSE(s.state.empty());
        s.jwt = yuzu::server::test::sign_and_register_rs256(
            *fix.oidc_provider, "kid-" + s.state.substr(0, 8),
            yuzu::server::test::id_token_payload(cfg, nonce, sub));
        REQUIRE_FALSE(s.jwt.empty());
        return s;
    }

    /// `b` visits the callback URL of flow `s` (a GET navigation).
    std::unique_ptr<httplib::Response> callback(Browser& b, const Started& s) {
        idp.set_id_token(s.jwt);
        return get(b, "/auth/callback?code=the-code&state=" + s.state);
    }

    std::string last_audit_detail() {
        const auto ev = fix.audit_events(1);
        REQUIRE_FALSE(ev.empty());
        return ev.front().detail;
    }
};

} // namespace

TEST_CASE("OIDC binding route: start sets the binding cookie (https: __Host-, Secure) and keeps "
          "the secret out of the URL",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a;
    auto r = rig.get(a, "/auth/oidc/start");
    REQUIRE(r->status == 302);
    const auto cookies = set_cookies(*r);
    REQUIRE(cookies.size() == 1);
    const auto& c = cookies[0];
    const std::string prefix = "__Host-yuzu_oidc_bind=";
    REQUIRE(c.starts_with(prefix));
    const auto secret = c.substr(prefix.size(), 64);
    CHECK(secret.size() == 64);
    for (const char* attr : {"; Path=/", "; HttpOnly", "; SameSite=Lax", "; Max-Age=600", "; Secure"})
        CHECK(c.find(attr) != std::string::npos);
    CHECK(c.find("Domain") == std::string::npos); // __Host- forbids it
    CHECK(c.find("SameSite=None") == std::string::npos);
    CHECK(r->get_header_value("Location").find(secret) == std::string::npos);
}

TEST_CASE("OIDC binding route: on plain http the cookie is unprefixed and not Secure, "
          "and the callback reads that same name only",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    rig.fix.cfg.https_enabled = false;
    Browser a;
    const auto s = rig.start(a);
    REQUIRE(a.jar.count("yuzu_oidc_bind") == 1);
    const auto cookies = set_cookies(*rig.get(a, "/auth/oidc/start"));
    REQUIRE(cookies.size() == 1);
    CHECK(cookies[0].starts_with("yuzu_oidc_bind="));
    CHECK(cookies[0].find("Secure") == std::string::npos);
    CHECK(cookies[0].find("__Host-") == std::string::npos);
    // A request carrying only the https-mode name does not satisfy a plain-http callback.
    Browser wrong;
    wrong.jar["__Host-yuzu_oidc_bind"] = std::string(64, 'a');
    auto r = rig.callback(wrong, s);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(rig.idp.token_calls.load() == 0);
}

TEST_CASE("OIDC binding route: a bound flow completes, clears the cookie and a replay is refused",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    REQUIRE(a.jar.count("__Host-yuzu_oidc_bind") == 1);
    const std::string cookie_at_start = a.jar["__Host-yuzu_oidc_bind"];

    auto ok = rig.callback(a, flow);
    CHECK(ok->status == 302);
    CHECK(ok->get_header_value("Location") == "/home");
    CHECK(has_cookie_named(*ok, "yuzu_session="));
    // The binding cookie is single-use: cleared on the success exit.
    CHECK(binding_cookie_cleared(*ok));
    CHECK(a.jar.count("__Host-yuzu_oidc_bind") == 0);
    CHECK(rig.idp.token_calls.load() == 1);

    // Replay with the cookie value restored: the pending flow is gone.
    Browser replayer;
    replayer.jar["__Host-yuzu_oidc_bind"] = cookie_at_start;
    auto again = rig.callback(replayer, flow);
    CHECK(again->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*again, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 1); // no second exchange
}

TEST_CASE("OIDC binding route: a callback URL opened in a browser without the cookie is refused "
          "and the initiating browser still completes",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a, b;
    const auto flow = rig.start(a);

    // B has NO binding cookie (never started this flow).
    auto r = rig.callback(b, flow);
    CHECK(r->status == 302);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(b.jar.count("yuzu_session") == 0);
    CHECK(rig.idp.token_calls.load() == 0); // the code was never exchanged
    CHECK(rig.last_audit_detail() == "reason=browser_binding_missing");
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);

    // The refusal did not consume the pending flow: the initiating browser finishes inside TTL.
    auto ok = rig.callback(a, flow);
    CHECK(ok->get_header_value("Location") == "/home");
    CHECK(has_cookie_named(*ok, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 1);
}

TEST_CASE("OIDC binding route: a browser holding its own cookie is refused on another browser's flow, "
          "keeps its cookie, and neither flow is consumed",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a, b;
    const auto a_flow = rig.start(a);
    const auto b_flow = rig.start(b); // B started a sign-in of its own
    const std::string b_cookie = b.jar["__Host-yuzu_oidc_bind"];
    REQUIRE(b_cookie.size() == 64);

    // B opens A's callback URL: B's cookie is for B's flow, not A's.
    auto r = rig.callback(b, a_flow);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 0);
    CHECK(rig.last_audit_detail() == "reason=browser_binding_mismatch");
    // B's cookie matched nothing, so it was not spent.
    CHECK_FALSE(binding_cookie_cleared(*r));
    REQUIRE(b.jar.count("__Host-yuzu_oidc_bind") == 1);
    CHECK(b.jar["__Host-yuzu_oidc_bind"] == b_cookie);

    // Neither flow was consumed: B finishes its own, and A finishes A's.
    CHECK(rig.callback(b, b_flow)->get_header_value("Location") == "/home");
    CHECK(rig.callback(a, a_flow)->get_header_value("Location") == "/home");
    CHECK(rig.idp.token_calls.load() == 2);
}

TEST_CASE("OIDC binding route: only the exact cookie name counts",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    const std::string secret = a.jar["__Host-yuzu_oidc_bind"];
    // A cookie whose name merely ENDS in the binding name does not count.
    Browser suffixed;
    suffixed.jar["foo__Host-yuzu_oidc_bind"] = secret;
    auto r = rig.callback(suffixed, flow);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(rig.idp.token_calls.load() == 0);
    CHECK(rig.last_audit_detail() == "reason=browser_binding_missing");
    // The session cookie is not a binding.
    Browser sess;
    sess.jar["yuzu_session"] = secret;
    CHECK(rig.callback(sess, flow)->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(rig.idp.token_calls.load() == 0);
    // The genuine browser still completes (neither request consumed the flow).
    CHECK(rig.callback(a, flow)->get_header_value("Location") == "/home");
}

TEST_CASE("OIDC binding route: a callback that matches no pending flow leaves the binding cookie alone",
          "[pg][oidc][oidc_binding][auth_routes]") {
    // A callback that matches no pending flow leaves the cookie in place, so a sign-in the
    // visitor has in progress is not disturbed.
    BindingRig rig;
    for (const char* path : {"/auth/callback?error=access_denied", "/auth/callback",
                             "/auth/callback?code=c&state=zzz"}) {
        CAPTURE(path);
        Browser b;
        b.jar["__Host-yuzu_oidc_bind"] = std::string(64, 'c');
        auto r = rig.get(b, path);
        CHECK_FALSE(binding_cookie_cleared(*r));
        CHECK(b.jar.count("__Host-yuzu_oidc_bind") == 1);
    }
    // A browser mid-sign-in survives those requests and still completes its own flow.
    Browser a;
    const auto flow = rig.start(a);
    (void)rig.get(a, "/auth/callback?error=access_denied");
    (void)rig.get(a, "/auth/callback?code=c&state=zzz");
    REQUIRE(a.jar.count("__Host-yuzu_oidc_bind") == 1);
    CHECK(rig.callback(a, flow)->get_header_value("Location") == "/home");
}

TEST_CASE("OIDC binding route: a failure after the binding matched still clears the cookie",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    rig.idp.set_id_token("not-a-jwt");
    auto r = rig.get(a, "/auth/callback?code=c&state=" + flow.state);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(binding_cookie_cleared(*r)); // the flow was consumed, so the cookie is spent
    CHECK(a.jar.count("__Host-yuzu_oidc_bind") == 0);
}

TEST_CASE("OIDC binding route: the IdP's GET callback is not subject to a same-origin rule",
          "[pg][oidc][oidc_binding][auth_routes]") {
    // The legitimate callback arrives as a top-level navigation: the Lax cookie rides
    // along, Referer may be the IdP or absent. The binding is the protection; a same-origin
    // requirement on this route would break every login.
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    rig.idp.set_id_token(flow.jwt);
    auto h = a.headers();
    h["Referer"] = "https://idp.example.test/signin";
    h["Origin"] = "https://idp.example.test";
    auto r = rig.fix.sink.dispatch("GET", "/auth/callback?code=c&state=" + flow.state, {},
                                   "application/json", h);
    REQUIRE(r != nullptr);
    CHECK(r->get_header_value("Location") == "/home");
}

// ---------------------------------------------------------------------------
// Discovery (#5692): the routes against an IdP whose endpoints and JWKS come ONLY from its
// discovery document (no explicit endpoint, no add_test_jwks_key).
// ---------------------------------------------------------------------------

namespace {

struct DiscoveryRig {
    yuzu::server::test::MockIdp idp;
    OidcRoutesFixture fix;
    oidc::OidcConfig cfg;

    explicit DiscoveryRig(bool explicit_authorize = false) {
        cfg.issuer = idp.base();
        cfg.client_id = "yuzu-test-client";
        cfg.redirect_uri = "https://yuzu.example.test/auth/callback";
        cfg.allow_private_networks = true; // the mock IdP listens on loopback
        if (explicit_authorize)
            cfg.authorization_endpoint = idp.base() + "/authorize";
        fix.oidc_provider = std::make_unique<oidc::OidcProvider>(cfg);
        fix.cfg.oidc_redirect_uri = cfg.redirect_uri;
    }

    std::unique_ptr<httplib::Response> get(Browser& b, const std::string& path) {
        auto r = fix.sink.dispatch("GET", path, {}, "application/json", b.headers());
        REQUIRE(r != nullptr);
        b.absorb(*r);
        return r;
    }

    /// The callback request the IdP would send the browser to for the flow `start` began.
    std::string callback_path(const httplib::Response& start) {
        const auto back = idp.follow_authorize(start.get_header_value("Location"));
        REQUIRE(back.starts_with(cfg.redirect_uri + "?"));
        return "/auth/callback" + back.substr(cfg.redirect_uri.size());
    }
};

} // namespace

TEST_CASE("OIDC discovery route: a full login works with endpoints and JWKS from discovery alone",
          "[pg][oidc][oidc_discovery][auth_routes]") {
    DiscoveryRig rig;
    Browser a;
    auto start = rig.get(a, "/auth/oidc/start");
    REQUIRE(start->status == 302);
    CHECK(start->get_header_value("Location").starts_with(rig.idp.base() + "/authorize?"));
    CHECK(a.jar.count("__Host-yuzu_oidc_bind") == 1);

    auto cb = rig.get(a, rig.callback_path(*start));
    CHECK(cb->status == 302);
    CHECK(cb->get_header_value("Location") == "/home");
    CHECK(has_cookie_named(*cb, "yuzu_session="));
    const auto events = rig.fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login");
    CHECK(events.front().result == "ok");
    CHECK(rig.idp.discovery_calls.load() == 1);
    CHECK(rig.idp.jwks_calls.load() == 1);
}

TEST_CASE("OIDC discovery route: discovery down at login start answers 500 with no cookie - no "
          "redirect and no stored flow",
          "[pg][oidc][oidc_discovery][auth_routes]") {
    DiscoveryRig rig;
    rig.idp.with([](yuzu::server::test::MockIdp& m) { m.discovery_status = 500; });
    Browser a;
    auto r = rig.get(a, "/auth/oidc/start");
    CHECK(r->status == 500);
    CHECK(r->get_header_value("Location").empty());
    CHECK(set_cookies(*r).empty());
    CHECK(rig.fix.oidc_provider->pending_flow_count_for_test() == 0);
    const auto body = nlohmann::json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body["error"].value("code", 0) == 500);
}

TEST_CASE(
    "OIDC discovery route: discovery down at the callback is a refused sign-in - audited as a "
    "failure - with no session",
    "[pg][oidc][oidc_discovery][auth_routes]") {
    DiscoveryRig rig(/*explicit_authorize=*/true); // the start needs no discovery
    rig.idp.with([](yuzu::server::test::MockIdp& m) { m.discovery_status = 500; });
    Browser a;
    auto start = rig.get(a, "/auth/oidc/start");
    REQUIRE(start->status == 302);
    auto cb = rig.get(a, rig.callback_path(*start));
    CHECK(cb->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*cb, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 0); // never got as far as the token endpoint
    const auto events = rig.fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");
}

// ---------------------------------------------------------------------------
// IdP-controlled JSON of the wrong type (#5692): the provider answers with an error, never an
// exception, so the route still audits the failure, counts it and spends the binding cookie.
// ---------------------------------------------------------------------------

namespace {

std::string forged_jwt(const std::string& header_json, const std::string& payload_json) {
    const auto b64 = [](const std::string& s) {
        return oidc::OidcProvider::base64url_encode(std::vector<uint8_t>(s.begin(), s.end()));
    };
    return b64(header_json) + "." + b64(payload_json) + "." + b64("sig");
}

} // namespace

TEST_CASE(
    "OIDC binding route: IdP JSON of the wrong type is a failed sign-in that is audited - counted "
    "and spends the binding cookie",
    "[pg][oidc][oidc_binding][oidc_discovery][auth_routes]") {
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    // The key `start` registered for this flow: lets a SIGNED token reach the claims parser.
    const std::string kid = "kid-" + flow.state.substr(0, 8);
    const std::string payload = yuzu::server::test::id_token_payload(rig.cfg, "n");

    SECTION("a header whose alg is a number") {
        rig.idp.set_id_token(forged_jwt(R"({"alg":123,"kid":")" + kid + R"("})", payload));
    }
    SECTION("a header whose alg is an array") {
        rig.idp.set_id_token(forged_jwt(R"({"alg":[],"kid":")" + kid + R"("})", payload));
    }
    SECTION("a header whose kid is null") {
        rig.idp.set_id_token(forged_jwt(R"({"alg":"RS256","kid":null})", payload));
    }
    SECTION("a header whose kid is a number") {
        rig.idp.set_id_token(forged_jwt(R"({"alg":"RS256","kid":5})", payload));
    }
    SECTION("a token-endpoint error body whose error is a number") {
        rig.idp.with([](yuzu::server::test::MockIdp& m) { m.token_body = R"({"error":5})"; });
    }
    SECTION("a token-endpoint error body whose error_description is null") {
        rig.idp.with([](yuzu::server::test::MockIdp& m) {
            m.token_body = R"({"error":"invalid_grant","error_description":null})";
        });
    }
    SECTION("a signed token whose aud is an array holding a number") {
        auto claims = nlohmann::json::parse(payload);
        claims["aud"] = nlohmann::json::array({123});
        rig.idp.set_id_token(yuzu::server::test::rs256_sign(kid, claims.dump()));
    }
    SECTION("a document that throws something the parsers do not catch (number overflow)") {
        rig.idp.with([](yuzu::server::test::MockIdp& m) {
            m.token_body = R"({"id_token":"x","pad":1e999})";
        });
    }

    auto r = rig.get(a, "/auth/callback?code=c&state=" + flow.state);
    CHECK(r->status == 302);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(binding_cookie_cleared(*r)); // the flow was matched and spent
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 1);
    const auto events = rig.fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
}

// create_oidc_session returns an EMPTY token when the durable session row cannot be written
// (ADR-0007 fail-safe). The callback must treat that as a failed sign-in: no cookie, no ok audit
// row, no ok counter.
TEST_CASE(
    "OIDC binding route: a session that cannot be persisted is a failed sign-in - not a success",
    "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    yuzu::server::SessionStore store{*rig.fix.audit_pool};
    REQUIRE(store.is_open());
    rig.fix.auth_mgr.set_session_store(&store);
    // Declared after `store`, so it is destroyed first: the manager never outlives its store.
    struct Detach {
        auth::AuthManager& mgr;
        ~Detach() { mgr.set_session_store(nullptr); }
    } detach{rig.fix.auth_mgr};

    // Control: with the store intact the same flow signs in.
    Browser ok_browser;
    const auto ok_flow = rig.start(ok_browser, "alice-sub");
    auto ok = rig.callback(ok_browser, ok_flow);
    REQUIRE(ok->get_header_value("Location") == "/home");
    REQUIRE(has_cookie_named(*ok, "yuzu_session="));

    // Fault: drop the durable session schema so the next INSERT fails.
    {
        auto lease = rig.fix.audit_pool->acquire();
        REQUIRE(lease);
        yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                      std::vector<std::string>{});
    }
    Browser b;
    const auto flow = rig.start(b, "bob-sub");
    auto r = rig.callback(b, flow);
    CHECK(r->status == 302);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(binding_cookie_cleared(*r));

    const auto events = rig.fix.audit_events(10);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");
    CHECK(events.front().detail == "reason=session_create_failed");
    const auto ok_rows = std::count_if(events.begin(), events.end(), [](const AuditEvent& e) {
        return e.action == "auth.oidc_login" && e.result == "ok";
    });
    CHECK(ok_rows == 1); // only the control login: the failed one wrote no ok row
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
}

TEST_CASE("OIDC route: a provider swap does not wait for an in-flight sign-in start",
          "[pg][oidc][oidc_discovery][oidc_lease][auth_routes]") {
    // /auth/oidc/start runs lazy discovery (network I/O). It used to hold the shared oidc_mu_
    // for all of it, so a Settings save (exclusive lock) waited for the slowest fetch and every
    // new sign-in waited behind that save. Now the route holds a lease, not the lock.
    DiscoveryRig rig;
    rig.idp.hold_discovery();
    Browser a;
    // Declared BEFORE the worker and its release guard: if a failing check unwinds the test,
    // the guard releases the held fetch (so the worker's lease ends) before this provider's
    // destructor, which waits for that lease, runs.
    std::unique_ptr<oidc::OidcProvider> unpublished;
    std::atomic<int> start_status{0};
    std::thread worker([&] {
        auto r = rig.fix.sink.dispatch("GET", "/auth/oidc/start", {}, "application/json",
                                       a.headers());
        start_status.store(r ? r->status : -1);
    });
    // Declared after `worker`, so it runs first on any exit (a failing REQUIRE included): the
    // held fetch is released and the thread joined before anything it captured is destroyed.
    struct ReleaseAndJoin {
        yuzu::server::test::MockIdp& idp;
        std::thread& t;
        ~ReleaseAndJoin() {
            idp.release_discovery();
            if (t.joinable())
                t.join();
        }
    } release_and_join{rig.idp, worker};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (rig.idp.discovery_calls.load() < 1 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    REQUIRE(rig.idp.discovery_calls.load() == 1); // the request is inside its fetch

    // What the Settings save does: take the exclusive lock, swap, release, retire.
    {
        // try_lock may fail spuriously, so retry for a bounded time; a request that really held
        // the lock for its whole fetch (the old behavior) never lets go while discovery is held.
        std::unique_lock exclusive(rig.fix.oidc_mu, std::defer_lock);
        const auto lock_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!exclusive.try_lock() && std::chrono::steady_clock::now() < lock_deadline)
            std::this_thread::yield();
        REQUIRE(exclusive.owns_lock()); // the in-flight request does not hold the lock
        unpublished = std::move(rig.fix.oidc_provider);
        rig.fix.oidc_provider = std::make_unique<oidc::OidcProvider>(rig.cfg);
    }
    oidc::OidcProvider::drain_retired();
    oidc::OidcProvider::retire(std::move(unpublished)); // returns although the request is live
    CHECK(oidc::OidcProvider::retired_count_for_test() == 1);

    rig.idp.release_discovery();
    worker.join();
    CHECK(start_status.load() == 302); // the request finished on the provider it started with
    oidc::OidcProvider::drain_retired();
    CHECK(oidc::OidcProvider::retired_count_for_test() == 0);
}

TEST_CASE("OIDC route: a Settings swap during an in-flight callback does not wait for it and "
          "the callback is then refused - no session under the replaced configuration",
          "[pg][oidc][oidc_discovery][oidc_lease][auth_routes]") {
    // /auth/callback does the token POST and the JWKS fetch (the long network I/O). Two things
    // must hold, for each IdP step the callback can be stuck in:
    //  (1) the route holds a lease, not oidc_mu_, so the exclusive swap of a Settings save is
    //      not delayed by the callback (this is the callback half of the lock finding);
    //  (2) a callback that finishes after the save replaced the provider is REFUSED before any
    //      group, role or session work: the operator changed the configuration (an admin group,
    //      the issuer), and no session may be minted under the old one after the save returned.
    DiscoveryRig rig;
    oidc::OidcProvider::drain_retired();
    const bool stuck_in_token_post = GENERATE(true, false);
    CAPTURE(stuck_in_token_post);
    Browser a;
    auto start = rig.get(a, "/auth/oidc/start");
    REQUIRE(start->status == 302);
    const std::string callback = rig.callback_path(*start);

    // Declared before the worker and its guard (see the start test above for the ordering).
    std::unique_ptr<oidc::OidcProvider> unpublished;
    if (stuck_in_token_post)
        rig.idp.hold_token();
    else
        rig.idp.hold_jwks();
    std::unique_ptr<httplib::Response> callback_res;
    std::thread worker([&] {
        callback_res = rig.fix.sink.dispatch("GET", callback, {}, "application/json", a.headers());
    });
    struct ReleaseAndJoin {
        yuzu::server::test::MockIdp& idp;
        std::thread& t;
        ~ReleaseAndJoin() {
            idp.release_token();
            idp.release_jwks();
            if (t.joinable())
                t.join();
        }
    } release_and_join{rig.idp, worker};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    const auto step_calls = [&] {
        return stuck_in_token_post ? rig.idp.token_calls.load() : rig.idp.jwks_calls.load();
    };
    while (step_calls() < 1 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    REQUIRE(step_calls() == 1); // the callback is inside the IdP step

    {
        std::unique_lock exclusive(rig.fix.oidc_mu, std::defer_lock);
        const auto lock_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!exclusive.try_lock() && std::chrono::steady_clock::now() < lock_deadline)
            std::this_thread::yield();
        REQUIRE(exclusive.owns_lock()); // (1) the in-flight callback does not hold the lock
        unpublished = std::move(rig.fix.oidc_provider);
        // The "save": a new provider (a changed admin group would live in rig.fix.cfg).
        rig.fix.cfg.oidc_admin_group = "a-different-admin-group";
        rig.fix.oidc_provider = std::make_unique<oidc::OidcProvider>(rig.cfg);
    }
    oidc::OidcProvider::retire(std::move(unpublished)); // returns although the callback is live
    CHECK(oidc::OidcProvider::retired_count_for_test() == 1);

    rig.idp.release_token();
    rig.idp.release_jwks();
    worker.join();
    REQUIRE(callback_res != nullptr);
    CHECK(callback_res->status == 302);
    CHECK(callback_res->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*callback_res, "yuzu_session=")); // (2) no session was minted
    const auto events = rig.fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");
    CHECK(events.front().detail == "reason=provider_replaced");
    CHECK(binding_cookie_cleared(*callback_res)); // the flow was matched and spent
    // No login succeeded at any point: not merely "the newest row is a failure".
    const auto all_events = rig.fix.audit_events(20);
    CHECK(std::count_if(all_events.begin(), all_events.end(), [](const AuditEvent& e) {
              return e.action == "auth.oidc_login" && e.result == "ok";
          }) == 0);
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
    // The role label a wrongly minted login would carry is not known here, so none may exist.
    for (const char* role : {"admin", "user"})
        CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "ok"}, {"role", role}}) ==
              0.0);
    oidc::OidcProvider::drain_retired();
    CHECK(oidc::OidcProvider::retired_count_for_test() == 0);
}

TEST_CASE("OIDC route: a Settings swap between the first provider check and the session mint "
          "leaves no usable session - the minted one is invalidated and no cookie is set",
          "[pg][oidc][oidc_lease][auth_routes]") {
    // The second provider check (made right after create_oidc_session) exists for the span the
    // first one cannot cover: the group sync, the SCIM read and the durable session write. The
    // test seam runs the "save" (exclusive lock, swap, retire) in exactly that span.
    DiscoveryRig rig;
    oidc::OidcProvider::drain_retired();
    yuzu::server::SessionStore store{*rig.fix.audit_pool};
    REQUIRE(store.is_open());
    rig.fix.auth_mgr.set_session_store(&store);
    // Declared after `store`, so it is destroyed first: the manager never outlives its store.
    struct Detach {
        auth::AuthManager& mgr;
        ~Detach() { mgr.set_session_store(nullptr); }
    } detach{rig.fix.auth_mgr};

    const auto durable_rows = [&] {
        auto lease = rig.fix.audit_pool->acquire();
        REQUIRE(lease);
        auto r = yuzu::server::pg::exec_params(lease.get(),
                                               "SELECT count(*) FROM session_store.sessions",
                                               std::vector<std::string>{});
        return std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
    };

    // Control: with no save in the span the same flow signs in and leaves one durable row.
    {
        Browser c;
        auto start = rig.get(c, "/auth/oidc/start");
        REQUIRE(start->status == 302);
        auto ok = rig.fix.sink.dispatch("GET", rig.callback_path(*start), {}, "application/json",
                                        c.headers());
        REQUIRE(ok != nullptr);
        REQUIRE(ok->get_header_value("Location") == "/home");
        REQUIRE(has_cookie_named(*ok, "yuzu_session="));
        REQUIRE(durable_rows() == 1);
    }

    std::unique_ptr<oidc::OidcProvider> unpublished;
    rig.fix.auth_routes->set_after_first_provider_check_for_test([&] {
        std::unique_lock exclusive(rig.fix.oidc_mu); // the callback holds a lease, not this lock
        unpublished = std::move(rig.fix.oidc_provider);
        rig.fix.cfg.oidc_admin_group = "a-different-admin-group";
        rig.fix.oidc_provider = std::make_unique<oidc::OidcProvider>(rig.cfg);
    });
    Browser b;
    auto start = rig.get(b, "/auth/oidc/start");
    REQUIRE(start->status == 302);
    // The hook swaps AFTER handle_callback accepted the flow and the first check passed.
    auto res = rig.fix.sink.dispatch("GET", rig.callback_path(*start), {}, "application/json",
                                     b.headers());
    REQUIRE(res != nullptr);
    CHECK(res->status == 302);
    CHECK(res->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*res, "yuzu_session="));
    CHECK(binding_cookie_cleared(*res));
    CHECK(durable_rows() == 1); // only the control login's row: the minted one was deleted

    const auto events = rig.fix.audit_events(20);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().action == "auth.oidc_login_failed");
    CHECK(events.front().result == "failure");
    CHECK(events.front().detail == "reason=provider_replaced;post_mint=true");
    CHECK(std::count_if(events.begin(), events.end(), [](const AuditEvent& e) {
              return e.action == "auth.oidc_login" && e.result == "ok";
          }) == 1); // the control login only
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);
    oidc::OidcProvider::retire(std::move(unpublished));
    oidc::OidcProvider::drain_retired();
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN

TEST_CASE("OIDC route: the landing page and the sign-in start wait at the writer gate while a "
          "Settings save is waiting for the OIDC lock",
          "[pg][oidc][oidc_lease][oidc_gate][auth_routes]") {
    // Pins the WIRING of the writer gate in auth_routes.cpp (#5692 UP-13): deleting a
    // `reader_pass()` there brings writer starvation back with every other test still green.
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(flow_cfg("http://127.0.0.1:1/token"));
    fix.cfg.oidc_redirect_uri = "https://yuzu.example.test/auth/callback";
    auto& gate = yuzu::server::oidc::OidcWriterGate::instance();
    REQUIRE(gate.waiting_for_test() == 0);
    for (const std::string path : {std::string("/home"), std::string("/auth/oidc/start")}) {
        CAPTURE(path);
        std::optional<yuzu::server::oidc::OidcWriterGate::Ticket> ticket;
        ticket.emplace(gate); // a save waiting for the exclusive lock
        std::atomic<bool> done{false};
        std::unique_ptr<httplib::Response> res;
        Browser b;
        std::thread worker([&] {
            res = fix.sink.dispatch("GET", path, {}, "application/json", b.headers());
            done = true;
        });
        struct ReleaseAndJoin {
            std::optional<yuzu::server::oidc::OidcWriterGate::Ticket>& tk;
            std::thread& t;
            ~ReleaseAndJoin() {
                tk.reset();
                if (t.joinable())
                    t.join();
            }
        } release_and_join{ticket, worker};
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CHECK_FALSE(done.load()); // held at the gate
        ticket.reset();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!done.load() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(done.load());
        worker.join();
        REQUIRE(res != nullptr);
    }
}

TEST_CASE("OIDC binding route: a digest failure at login start answers 500 with no cookie and no redirect",
          "[pg][oidc][oidc_binding][oidc_hash_failure][auth_routes]") {
    // start_auth_flow throws when SHA-256 fails; the route must turn that into a plain refusal,
    // never a redirect to the IdP without a binding cookie. Reaches no network.
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(flow_cfg("http://127.0.0.1:1/token"));
    fix.cfg.oidc_redirect_uri = "https://yuzu.example.test/auth/callback";
    fix.oidc_provider->set_binding_digest_failure_for_test(true);
    Browser b;
    auto r = fix.sink.dispatch("GET", "/auth/oidc/start", {}, "application/json", b.headers());
    REQUIRE(r != nullptr);
    CHECK(r->status == 500);
    CHECK(r->get_header_value("Location").empty());
    CHECK(set_cookies(*r).empty());
    // The A4 error envelope: a correlation id and a body carrying the status.
    CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
    const auto body = nlohmann::json::parse(r->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body.contains("error"));
    CHECK(body["error"].value("code", 0) == 500);
    CHECK_FALSE(body["error"].value("correlation_id", std::string{}).empty());
}

TEST_CASE("OIDC binding route: a digest failure at the callback is audited as unavailable, "
          "refuses with the generic redirect and keeps the flow and the cookie",
          "[pg][oidc][oidc_binding][oidc_hash_failure][auth_routes]") {
    // Reaches no network: every callback below is refused before a token exchange.
    OidcRoutesFixture fix;
    fix.oidc_provider = std::make_unique<oidc::OidcProvider>(flow_cfg("http://127.0.0.1:1/token"));
    fix.cfg.oidc_redirect_uri = "https://yuzu.example.test/auth/callback";
    const auto flow = fix.oidc_provider->start_auth_flow();
    const auto state = yuzu::server::test::url_query_param(flow.url, "state");
    REQUIRE_FALSE(state.empty());
    const std::string path = "/auth/callback?code=c&state=" + state;
    const std::unordered_map<std::string, std::string> cookie{
        {"Cookie", "__Host-yuzu_oidc_bind=" + flow.binding_secret}};

    fix.oidc_provider->set_binding_digest_failure_for_test(true);
    auto r = fix.sink.dispatch("GET", path, {}, "application/json", cookie);
    fix.oidc_provider->set_binding_digest_failure_for_test(false);
    REQUIRE(r != nullptr);
    CHECK(r->status == 302);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(set_cookies(*r).empty()); // nothing was proved, so nothing is cleared
    auto events = fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().detail == "reason=browser_binding_unavailable");

    // The refusal consumed nothing: a mismatching cookie on the same flow is still a mismatch
    // (not an unknown state), audited with its own reason.
    auto wrong = fix.sink.dispatch("GET", path, {}, "application/json",
                                   {{"Cookie", "__Host-yuzu_oidc_bind=" + std::string(64, 'e')}});
    REQUIRE(wrong != nullptr);
    CHECK(wrong->get_header_value("Location") == "/login?error=sso_failed");
    events = fix.audit_events(1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.front().detail == "reason=browser_binding_mismatch");
}
