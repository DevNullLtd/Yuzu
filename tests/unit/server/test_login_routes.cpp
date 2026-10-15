/// @file test_login_routes.cpp
/// HTTP-level coverage for the landing and sign-in routes on AuthRoutes
/// (`GET /home`, `GET /login`, `POST /logout` from the landing page), driven
/// in-process through TestRouteSink. No Postgres: sessions live in the
/// AuthManager's in-memory map and every store pointer is null, so these run
/// without YUZU_TEST_POSTGRES_DSN. Pins the behaviours the delta fixes:
/// `next` is a validated key (never a path or URL), a signed-out visitor gets
/// the form, a signed-in one the signed-in region, sign-in never auto-redirects,
/// `/login` forwards to the one sign-in form, and sign-out returns to it.

#include "auth_routes.hpp"
#include "home_ui.hpp"
#include "oidc_provider.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

struct Harness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty unless a case sets one
    std::unique_ptr<AuthRoutes> ar;
    yuzu::server::test::TestRouteSink sink;

    Harness() {
        cfg.https_enabled = false;
        // No user rows: the cases mint sessions directly, so no password hash is computed.
    }

    void wire() {
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                          /*api_token_store=*/nullptr, /*audit_store=*/nullptr,
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
        ar->register_routes(sink);
    }

    std::unordered_map<std::string, std::string> cookie(const std::string& user, auth::Role role) {
        const auto tok = auth_mgr.create_local_session_for_test(user, role, /*mfa=*/false);
        REQUIRE_FALSE(tok.empty());
        return {{"Cookie", "yuzu_session=" + tok}};
    }
};

bool has(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }

} // namespace

TEST_CASE("GET /home signed out: the sign-in form, no session needed, never cached", "[login][home][route]") {
    Harness h;
    h.wire();
    auto r = h.sink.Get("/home");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(has(r->get_header_value("Cache-Control"), "no-store"));
    CHECK(has(r->body, "id=\"signin\" aria-label=\"Sign in\" data-next=\"\">"));
    CHECK_FALSE(has(r->body, "aria-label=\"Signed in\""));
    CHECK_FALSE(has(r->body, "signin-notice"));
    // A signed-out visitor sees neither the server name nor the version.
    CHECK(has(r->body, "<span class=\"srv\"></span>"));
    CHECK_FALSE(has(r->body, "version "));
    CHECK_FALSE(has(r->body, "&middot;"));
    // No single sign-on without a provider; no two-factor note under the default enforcement.
    CHECK_FALSE(has(r->body, "single sign-on"));
    CHECK_FALSE(has(r->body, "two-factor"));
}

TEST_CASE("GET /home?next=<key>: a known key drives the notice; paths, URLs and unknown keys are ignored",
          "[login][home][route][next]") {
    Harness h;
    h.wire();

    auto known = h.sink.Get("/home?next=devices");
    REQUIRE(known);
    CHECK(known->status == 200);
    CHECK(has(known->body, "data-next=\"devices\">"));
    CHECK(has(known->body, "<div class=\"note\" id=\"signin-notice\">Sign in to open <b>Devices</b>.</div>"));

    for (const std::string bad : {"nope", "/devices", "%2Fdevices", "https://evil.example/", "//evil.example",
                                  "devices%0A", "Devices", ""}) {
        INFO("next=" << bad);
        auto r = h.sink.Get("/home?next=" + bad);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(has(r->body, "data-next=\"\">"));
        CHECK_FALSE(has(r->body, "signin-notice"));
        CHECK_FALSE(has(r->body, "evil.example"));
    }
}

TEST_CASE("GET /home signed in: the signed-in region in place; Open Console or Open <area>; no redirect",
          "[login][home][route][next]") {
    Harness h;
    h.wire();
    const auto hdrs = h.cookie("dave.rae", auth::Role::admin);

    auto r = h.sink.Get("/home", hdrs);
    REQUIRE(r);
    // Sign-in never auto-redirects: the page answers 200 with the region, never a 30x.
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Location").empty());
    CHECK(has(r->body, "aria-label=\"Signed in\""));
    CHECK(has(r->body, "<div class=\"who\"><b>dave.rae</b><span>Administrator</span></div>"));
    CHECK(has(r->body, "id=\"open-area\" href=\"/\">Open Console</a>"));
    CHECK(has(r->body, "hx-post=\"/logout\">Sign out</button>"));
    CHECK(has(r->body, "You are signed in. Open the Console, or pick an area below."));
    CHECK_FALSE(has(r->body, "id=\"signin\""));
    CHECK_FALSE(has(r->body, "<form"));

    auto next = h.sink.Get("/home?next=compliance", hdrs);
    REQUIRE(next);
    CHECK(next->status == 200);
    CHECK(next->get_header_value("Location").empty());
    CHECK(has(next->body, "id=\"open-area\" href=\"/compliance\">Open Compliance</a>"));

    auto bad = h.sink.Get("/home?next=https://evil.example/", hdrs);
    REQUIRE(bad);
    CHECK(bad->status == 200);
    CHECK(has(bad->body, "id=\"open-area\" href=\"/\">Open Console</a>"));
    CHECK_FALSE(has(bad->body, "evil.example"));

    auto viewer = h.sink.Get("/home", h.cookie("alice", auth::Role::user));
    REQUIRE(viewer);
    CHECK(has(viewer->body, "<div class=\"who\"><b>alice</b><span>Viewer</span></div>"));
}

TEST_CASE("GET /home: the SSO link appears only with a configured identity provider, the two-factor note only under enforcement",
          "[login][home][route]") {
    Harness h;
    oidc::OidcConfig oc;
    oc.issuer = "https://login.example/tenant/v2.0";
    oc.client_id = "client";
    h.oidc_provider = std::make_unique<oidc::OidcProvider>(oc);
    h.cfg.mfa_enforcement = "required";
    h.wire();
    auto r = h.sink.Get("/home");
    REQUIRE(r);
    CHECK(has(r->body, "<a class=\"btn\" id=\"btn-sso\" href=\"/auth/oidc/start\">Sign in with single sign-on</a>"));
    CHECK(has(r->body, "If two-factor is on for your account, you will be asked for a code next."));
}

TEST_CASE("GET /home?error=: a known SSO error code renders its message for a signed-out visitor only",
          "[login][home][route]") {
    Harness h;
    h.wire();
    auto out = h.sink.Get("/home?error=sso_denied");
    REQUIRE(out);
    CHECK(has(out->body, "aria-live=\"polite\">SSO sign-in was denied by the identity provider</div>"));
    auto unknown = h.sink.Get("/home?error=%3Cb%3Ex%3C%2Fb%3E");
    REQUIRE(unknown);
    CHECK(has(unknown->body, "aria-live=\"polite\">SSO error</div>"));
    CHECK_FALSE(has(unknown->body, "<b>x</b>")); // the code is never echoed
    auto in = h.sink.Get("/home?error=sso_denied", h.cookie("dave.rae", auth::Role::admin));
    REQUIRE(in);
    CHECK_FALSE(has(in->body, "denied by the identity provider"));
}

TEST_CASE("GET /login forwards to the landing page, keeping only a validated next key and a known error code",
          "[login][route][next]") {
    Harness h;
    h.wire();
    const std::pair<std::string, std::string> expected[] = {
        {"/login", "/home"},
        {"/login?next=devices", "/home?next=devices"},
        {"/login?next=/devices", "/home"},
        {"/login?next=https://evil.example/", "/home"},
        {"/login?next=nope", "/home"},
        {"/login?error=sso_failed", "/home?error=sso_failed"},
        {"/login?error=saml", "/home?error=saml"},
        {"/login?error=%3Cscript%3E", "/home"},
        {"/login?error=SSO_FAILED", "/home"},
        {"/login?next=devices&next=/evil", "/home?next=devices"},
        {"/login?next=devices%20", "/home"},
        {"/login?next=tar&error=sso_invalid", "/home?next=tar&error=sso_invalid"},
    };
    for (const auto& [path, location] : expected) {
        INFO(path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == location);
    }
}

TEST_CASE("POST /logout from the landing page returns to the sign-in panel", "[login][home][route]") {
    Harness h;
    h.wire();
    auto hdrs = h.cookie("dave.rae", auth::Role::admin);
    hdrs.emplace("HX-Request", "true");
    auto r = h.sink.dispatch("POST", "/logout", "", "application/json", hdrs);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Redirect") == "/home");
    CHECK(has(r->get_header_value("Set-Cookie"), "Max-Age=0"));
    // The session is gone: the landing page now shows the form again.
    auto after = h.sink.Get("/home", {{"Cookie", hdrs["Cookie"]}});
    REQUIRE(after);
    CHECK(after->status == 200);
    CHECK(has(after->body, "id=\"signin\" aria-label=\"Sign in\""));
    CHECK_FALSE(has(after->body, "aria-label=\"Signed in\""));
}
