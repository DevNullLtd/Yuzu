/**
 * test_oidc_routes.cpp — HTTP wiring tests for the OIDC `/auth/callback`
 * route, plus a direct AuthManager-level test for the admin-group trim
 * (#1830.1).
 *
 * (The binding tests at the end of this file DO have a loopback IdP: test_oidc_mock_idp.hpp.)
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
#include "test_oidc_mock_idp.hpp"
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
// flow and finishes it; browser V is handed A's callback URL. A fixture that merely checks the
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

oidc::OidcConfig flow_cfg(const std::string& token_endpoint) {
    oidc::OidcConfig c;
    c.issuer = "https://idp.example.test";
    c.client_id = "yuzu-test-client";
    c.redirect_uri = "https://yuzu.example.test/auth/callback";
    c.authorization_endpoint = c.issuer + "/authorize"; // skips discovery (no network)
    c.token_endpoint = token_endpoint;
    return c;
}

} // namespace

// The rig below runs a loopback token endpoint (a real httplib acceptor thread and client), which
// crashes the ThreadSanitizer build (#438 class): every route case that needs it is compiled out
// there. The cases that reach no network sit after the #endif.
#ifndef YUZU_OIDC_MOCK_IDP_TSAN

namespace {

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

    /// `b` visits the callback URL of flow `s` (a cross-site GET).
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
    CHECK(ok->get_header_value("Location") == "/");
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
    Browser a, v;
    const auto flow = rig.start(a);

    // V has NO binding cookie (never started this flow).
    auto r = rig.callback(v, flow);
    CHECK(r->status == 302);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(v.jar.count("yuzu_session") == 0);
    CHECK(rig.idp.token_calls.load() == 0); // the code was never exchanged
    CHECK(rig.last_audit_detail() == "reason=browser_binding_missing");
    CHECK(rig.fix.counter("yuzu_auth_oidc_login_total", {{"result", "error"}, {"role", "none"}}) ==
          1.0);

    // The refusal did not consume the pending flow: the initiating browser finishes inside TTL.
    auto ok = rig.callback(a, flow);
    CHECK(ok->get_header_value("Location") == "/");
    CHECK(has_cookie_named(*ok, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 1);
}

TEST_CASE("OIDC binding route: a visitor holding ITS OWN cookie is refused on another flow, keeps "
          "its cookie, and neither flow is consumed",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a, v;
    const auto a_flow = rig.start(a);
    const auto v_flow = rig.start(v); // V legitimately started a login of its own
    const std::string v_cookie = v.jar["__Host-yuzu_oidc_bind"];
    REQUIRE(v_cookie.size() == 64);

    // V is sent A's callback URL: V's cookie is for V's flow, not A's.
    auto r = rig.callback(v, a_flow);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK_FALSE(has_cookie_named(*r, "yuzu_session="));
    CHECK(rig.idp.token_calls.load() == 0);
    CHECK(rig.last_audit_detail() == "reason=browser_binding_mismatch");
    // V's cookie matched nothing, so it was not spent.
    CHECK_FALSE(binding_cookie_cleared(*r));
    REQUIRE(v.jar.count("__Host-yuzu_oidc_bind") == 1);
    CHECK(v.jar["__Host-yuzu_oidc_bind"] == v_cookie);

    // Neither flow was consumed: V finishes its own, and A finishes A's.
    CHECK(rig.callback(v, v_flow)->get_header_value("Location") == "/");
    CHECK(rig.callback(a, a_flow)->get_header_value("Location") == "/");
    CHECK(rig.idp.token_calls.load() == 2);
}

TEST_CASE("OIDC binding route: only the exact cookie name counts",
          "[pg][oidc][oidc_binding][auth_routes]") {
    BindingRig rig;
    Browser a;
    const auto flow = rig.start(a);
    const std::string secret = a.jar["__Host-yuzu_oidc_bind"];
    // A cookie that merely ENDS in the binding name cannot shadow it.
    Browser shadow;
    shadow.jar["foo__Host-yuzu_oidc_bind"] = secret;
    auto r = rig.callback(shadow, flow);
    CHECK(r->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(rig.idp.token_calls.load() == 0);
    CHECK(rig.last_audit_detail() == "reason=browser_binding_missing");
    // The session cookie is not a binding.
    Browser sess;
    sess.jar["yuzu_session"] = secret;
    CHECK(rig.callback(sess, flow)->get_header_value("Location") == "/login?error=sso_failed");
    CHECK(rig.idp.token_calls.load() == 0);
    // The genuine browser still completes (neither probe consumed the flow).
    CHECK(rig.callback(a, flow)->get_header_value("Location") == "/");
}

TEST_CASE("OIDC binding route: a callback that matches no pending flow leaves the binding cookie alone",
          "[pg][oidc][oidc_binding][auth_routes]") {
    // The callback is reachable by any cross-site GET. It must not delete the cookie of a
    // visitor who is mid-login, or that visitor's own IdP return would then fail.
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
    // A visitor mid-login survives those requests and still completes its own flow.
    Browser v;
    const auto flow = rig.start(v);
    (void)rig.get(v, "/auth/callback?error=access_denied");
    (void)rig.get(v, "/auth/callback?code=c&state=zzz");
    REQUIRE(v.jar.count("__Host-yuzu_oidc_bind") == 1);
    CHECK(rig.callback(v, flow)->get_header_value("Location") == "/");
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

TEST_CASE("OIDC binding route: the IdP's cross-site GET callback is not subject to a same-origin rule",
          "[pg][oidc][oidc_binding][auth_routes]") {
    // The legitimate callback arrives as a top-level cross-site navigation: the Lax cookie rides
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
    CHECK(r->get_header_value("Location") == "/");
}

#endif // !YUZU_OIDC_MOCK_IDP_TSAN

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
}
