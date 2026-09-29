/// @file test_page_routes.cpp
/// HTTP-level coverage for the page-shell/static-asset route module (#2542)
/// — driven in-process through TestRouteSink (no httplib acceptor, #438),
/// mirroring test_plugin_config_routes.cpp's Harness shape. None of these
/// 25 routes touches Postgres (no store), so every case here runs without
/// YUZU_TEST_POSTGRES_DSN.

#include "page_routes.hpp"
#include "test_route_sink.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// All providers injected and re-read per call, mirroring
/// test_plugin_config_routes.cpp's Harness shape. `registry` defaults to
/// null — the /api/help* 503-on-null-registry cases rely on that.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    bool session_present{true};
    std::string session_username{"alice"};

    std::atomic<bool> viz_disabled{false};
    const yuzu::server::detail::AgentRegistry* registry{nullptr};

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        page::Deps deps;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::admin;
            return s;
        };
        deps.viz_disabled = &viz_disabled;
        deps.registry = registry;
        page::register_page_routes(sink, deps);
    }
};

} // namespace

// ── Static assets (12) + / (1): no gate, pure constant-serving ───────────

namespace {
struct AssetExpectation {
    std::string path;
    std::string content_type;
    std::string cache_control_substr;
};

const std::vector<AssetExpectation> kStaticAssets = {
    {"/static/yuzu.css", "text/css; charset=utf-8", "no-cache"},
    {"/static/icons.svg", "image/svg+xml", "max-age=3600"},
    {"/static/htmx.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/sse.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/echarts.min.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/three.module.min.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/three-orbit-controls.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/yuzu-viz.js", "application/javascript; charset=utf-8", "no-cache"},
    {"/static/yuzu-viz-host.js", "application/javascript; charset=utf-8", "no-cache"},
    {"/static/cytoscape.min.js", "application/javascript; charset=utf-8", "max-age=86400"},
    {"/static/fonts/InterVariable.woff2", "font/woff2", "max-age=2592000"},
    {"/static/yuzu-charts.js", "application/javascript; charset=utf-8", "max-age=86400"},
};
} // namespace

TEST_CASE("page_routes: every static asset serves 200 with the right Content-Type and a "
          "non-empty body, ungated",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    for (const auto& a : kStaticAssets) {
        INFO("path: " << a.path);
        auto r = h.sink.Get(a.path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Content-Type") == a.content_type);
        CHECK(r->get_header_value("Cache-Control").find(a.cache_control_substr) !=
              std::string::npos);
        CHECK_FALSE(r->body.empty());
    }
}

TEST_CASE("page_routes: / serves the dashboard shell, ungated", "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_FALSE(r->body.empty());
}

// ── Legacy redirects (2) ──────────────────────────────────────────────────

TEST_CASE("page_routes: /chargen and /procfetch redirect to /, ungated",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto r1 = h.sink.Get("/chargen");
    REQUIRE(r1);
    CHECK(r1->status == 302);
    CHECK(r1->get_header_value("Location") == "/");

    auto r2 = h.sink.Get("/procfetch");
    REQUIRE(r2);
    CHECK(r2->status == 302);
    CHECK(r2->get_header_value("Location") == "/");
}

// ── /api/help* (4): perm_fn(Infrastructure, Read) ─────────────────────────

TEST_CASE("page_routes: every /api/help* route gates on Infrastructure:Read and denies without it",
          "[server][routes][page_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto check = [&](const std::string& path) {
        INFO("path: " << path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(h.last_perm_type == "Infrastructure");
        CHECK(h.last_perm_op == "Read");
    };

    check("/api/help");
    check("/api/help/html");
    check("/api/help/autocomplete");
    check("/api/help/palette");
}

TEST_CASE("page_routes: /api/help* answers 503 without crashing when the registry is null",
          "[server][routes][page_routes]") {
    Harness h; // registry stays null — a dereference would crash; 503 must never reach it
    h.wire();

    for (const std::string path :
        {"/api/help", "/api/help/html", "/api/help/autocomplete?q=x", "/api/help/palette?q=x"}) {
        INFO("path: " << path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 503);
    }
}

TEST_CASE("page_routes: /api/help* serves real registry output when perm allows and the "
          "registry is wired",
          "[server][routes][page_routes]") {
    yuzu::server::detail::EventBus bus;
    yuzu::MetricsRegistry metrics;
    yuzu::server::detail::AgentRegistry registry(bus, metrics);

    Harness h;
    h.registry = &registry;
    h.wire();

    auto help = h.sink.Get("/api/help");
    REQUIRE(help);
    CHECK(help->status == 200);
    CHECK(help->get_header_value("Content-Type") == "application/json");
    auto j = json::parse(help->body);
    CHECK(j.contains("plugins"));
    CHECK(j.contains("commands"));
    CHECK(j["plugins"].is_array());

    auto html = h.sink.Get("/api/help/html");
    REQUIRE(html);
    CHECK(html->status == 200);
    CHECK(html->get_header_value("Content-Type") == "text/html");

    // Empty ?q short-circuits to an empty body before ever touching the registry.
    auto ac_empty = h.sink.Get("/api/help/autocomplete");
    REQUIRE(ac_empty);
    CHECK(ac_empty->status == 200);
    CHECK(ac_empty->body.empty());

    auto ac = h.sink.Get("/api/help/autocomplete?q=fi");
    REQUIRE(ac);
    CHECK(ac->status == 200);
    CHECK(ac->get_header_value("Content-Type") == "text/html");

    auto palette_empty = h.sink.Get("/api/help/palette");
    REQUIRE(palette_empty);
    CHECK(palette_empty->status == 200);
    CHECK(palette_empty->body.empty());

    auto palette = h.sink.Get("/api/help/palette?q=fi");
    REQUIRE(palette);
    CHECK(palette->status == 200);
    CHECK(palette->get_header_value("Content-Type") == "text/html");
}

// ── /help, /tar, /result-sets, /instructions (help/tar/result-sets/viz/instructions) ──

TEST_CASE("page_routes: /help serves the help page, ungated", "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/help");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_FALSE(r->body.empty());
}

TEST_CASE("page_routes: /tar, /result-sets, /instructions deny without auth (redirect to /login)",
          "[server][routes][page_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    for (const std::string path : {"/tar", "/result-sets", "/instructions"}) {
        INFO("path: " << path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 302);
        CHECK(r->get_header_value("Location") == "/login");
    }
}

TEST_CASE("page_routes: /tar, /result-sets, /instructions serve 200 when authed",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto tar = h.sink.Get("/tar");
    REQUIRE(tar);
    CHECK(tar->status == 200);
    CHECK(tar->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_FALSE(tar->body.empty());

    auto rs = h.sink.Get("/result-sets");
    REQUIRE(rs);
    CHECK(rs->status == 200);
    CHECK(rs->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_FALSE(rs->body.empty());

    auto instr = h.sink.Get("/instructions");
    REQUIRE(instr);
    CHECK(instr->status == 200);
    CHECK(instr->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK_FALSE(instr->body.empty());
}

// ── /viz/fleet + /viz/host/:id (auth + kill switch) ───────────────────────

TEST_CASE("page_routes: /viz/fleet and /viz/host/:id deny without auth before the kill switch "
          "is even consulted",
          "[server][routes][page_routes]") {
    Harness h;
    h.session_present = false;
    h.viz_disabled.store(true); // even disabled, auth must be checked first
    h.wire();

    auto fleet = h.sink.Get("/viz/fleet");
    REQUIRE(fleet);
    CHECK(fleet->status == 302);
    CHECK(fleet->get_header_value("Location") == "/login");

    auto host = h.sink.Get("/viz/host/abc123");
    REQUIRE(host);
    CHECK(host->status == 302);
    CHECK(host->get_header_value("Location") == "/login");
}

TEST_CASE("page_routes: /viz/fleet and /viz/host/:id answer 503 when the kill switch is set, "
          "with the null-safe deps.viz_disabled contract honoured",
          "[server][routes][page_routes]") {
    Harness h;
    h.viz_disabled.store(true);
    h.wire();

    auto fleet = h.sink.Get("/viz/fleet");
    REQUIRE(fleet);
    CHECK(fleet->status == 503);
    CHECK(fleet->body.find("disabled by an administrator") != std::string::npos);

    auto host = h.sink.Get("/viz/host/abc123");
    REQUIRE(host);
    CHECK(host->status == 503);
    CHECK(host->body.find("disabled by an administrator") != std::string::npos);
}

TEST_CASE("page_routes: a null deps.viz_disabled is treated as not-disabled, never crashes",
          "[server][routes][page_routes]") {
    // Bypass Harness's own atomic entirely — wire Deps by hand with a null
    // viz_disabled pointer to exercise the Deps null-safety contract itself.
    page::Deps deps;
    deps.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "alice";
        s.role = auth::Role::admin;
        return s;
    };
    deps.perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    deps.viz_disabled = nullptr;
    deps.registry = nullptr;
    yuzu::server::test::TestRouteSink sink2;
    page::register_page_routes(sink2, deps);

    auto r = sink2.Get("/viz/fleet");
    REQUIRE(r);
    CHECK(r->status == 200);

    // The header doc describes the null-safe contract as shared by BOTH viz
    // routes — exercise /viz/host/:id here too, not just /viz/fleet.
    auto host = sink2.Get("/viz/host/abc123");
    REQUIRE(host);
    CHECK(host->status == 200);
}

TEST_CASE("page_routes: /viz/fleet serves 200 when authed and enabled",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/viz/fleet");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(r->get_header_value("Cache-Control").find("no-cache") != std::string::npos);
    CHECK_FALSE(r->body.empty());
}

TEST_CASE("page_routes: /viz/host/:id substitutes the sanitised agent id into the page",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/viz/host/abc-123.DEF");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/html; charset=utf-8");
    CHECK(r->get_header_value("Cache-Control").find("no-cache") != std::string::npos);
    CHECK(r->body.find("abc-123.DEF") != std::string::npos);
    CHECK(r->body.find("{{AGENT_ID}}") == std::string::npos);
}

TEST_CASE("page_routes: /viz/host/:id rejects a malformed agent id with 400",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    // '!' is outside the allow-list (a-z A-Z 0-9 dash underscore dot).
    auto r = h.sink.Get("/viz/host/bad!id");
    REQUIRE(r);
    CHECK(r->status == 400);
    CHECK(r->body == "invalid agent_id");
}

// ── Registration order / shape ────────────────────────────────────────────

TEST_CASE("page_routes: registers exactly 25 routes, with /viz/fleet reachable independently "
          "of /viz/host/:id (the documented registration order — /viz/fleet before the "
          "per-host regex — never lets one swallow the other)",
          "[server][routes][page_routes]") {
    Harness h;
    h.wire();

    CHECK(h.sink.route_count() == 25);

    auto fleet = h.sink.Get("/viz/fleet");
    REQUIRE(fleet);
    CHECK(fleet->status == 200);
    // The fleet page never carries the host page's substitution token.
    CHECK(fleet->body.find("{{AGENT_ID}}") == std::string::npos);

    auto host = h.sink.Get("/viz/host/somehost1");
    REQUIRE(host);
    CHECK(host->status == 200);
    CHECK(host->body.find("somehost1") != std::string::npos);
}
