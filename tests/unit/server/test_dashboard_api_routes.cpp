/// @file test_dashboard_api_routes.cpp
/// HTTP-level coverage for the 7-route dashboard/API module (#2542
/// follow-up) — driven in-process through TestRouteSink (no httplib
/// acceptor, #438), mirroring test_page_routes.cpp's / test_plugin_config_
/// routes.cpp's Harness shape.
///
/// Split by whether a case needs a live Postgres-backed store (`RbacStore`,
/// `AuditStore`, `AnalyticsEventStore` have no virtual seam — `Deps`'
/// pointers are concrete per this package's spec — so anything past the
/// gate that touches a real store needs Postgres):
///   - Permission/auth-gate denial, the `/api/agents` gate-ORDER proof, and
///     every null-store degrade/fallback response run WITHOUT Postgres —
///     each one returns before the handler would dereference the store.
///   - `/api/export/json-to-csv` and `/api/scope/validate` are pure
///     (no store at all) and are fully covered without Postgres.
///   - The RBAC-enabled `/api/me` shape, a real `/api/audit` query
///     round-trip, and the real `/api/analytics/{status,recent}` shapes are
///     `[pg]`, gated behind YUZU_TEST_POSTGRES_DSN.

#include "dashboard_api_routes.hpp"
#include "test_route_sink.hpp"

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"

#include "test_analytics_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <stdexcept>
#include <string>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

/// All providers injected and re-read per call, mirroring
/// test_page_routes.cpp's Harness shape. Every store pointer defaults to
/// null — every case that must NOT need Postgres relies on that.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    bool session_present{true};
    std::string session_username{"alice"};
    auth::Role session_role{auth::Role::user};

    RbacStore* rbac_store{nullptr};
    AuditStore* audit_store{nullptr};
    AnalyticsEventStore* analytics_store{nullptr};

    /// Defaults to a harmless no-op: register_dashboard_api_routes() now
    /// REQUIRES this bound (throws otherwise, see the dedicated fail-fast
    /// test below, which deliberately bypasses this default). A test that
    /// cares about the returned shape overrides this field explicitly.
    dashboard_api::Deps::VisibleAgentsJsonFn visible_agents_json_fn =
        [](const std::string&) { return json::object(); };
    std::string last_visible_agents_username;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        dashboard_api::Deps deps;
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
            s.role = session_role;
            return s;
        };
        deps.visible_agents_json_fn = [this](const std::string& username) {
            last_visible_agents_username = username;
            return visible_agents_json_fn(username);
        };
        deps.rbac_store = rbac_store;
        deps.audit_store = audit_store;
        deps.analytics_store = analytics_store;
        dashboard_api::register_dashboard_api_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("dashboard_api_routes: registers exactly 7 routes",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 7);
}

// ── GET /api/me: auth_fn only ──────────────────────────────────────────────

TEST_CASE("dashboard_api_routes: /api/me denies without auth", "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("dashboard_api_routes: /api/me reports session info with rbac_enabled:false when "
          "rbac_store is unset",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // rbac_store stays null
    h.session_username = "alice";
    h.session_role = auth::Role::admin;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["username"] == "alice");
    CHECK(j["display_name"] == "alice"); // falls back to username when unset
    CHECK(j["rbac_enabled"] == false);
    CHECK(j["rbac_role"] == "Administrator");
}

TEST_CASE("dashboard_api_routes: /api/me falls back to the legacy-role mapping for a Viewer "
          "session with no rbac_store",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_role = auth::Role::user;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    auto j = json::parse(r->body);
    CHECK(j["rbac_enabled"] == false);
    CHECK(j["rbac_role"] == "Viewer");
}

// ── GET /api/agents: perm_fn(Infrastructure, Read) THEN auth_fn ────────────

TEST_CASE("dashboard_api_routes: /api/agents calls perm_fn before auth_fn — a denial "
          "short-circuits before the session lookup runs (call-ORDER proof only: this "
          "harness's mock perm_fn denies with 403 unconditionally, which is what makes 403 "
          "vs 401 legible here; the REAL require_permission resolves auth internally and "
          "answers 401 for a session-less caller regardless of order — see the route's own "
          "comment in dashboard_api_routes.cpp)",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.perm_allow = false;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/api/agents");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: /api/agents denies with 401 when perm passes but no session",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Get("/api/agents");
    REQUIRE(r);
    CHECK(r->status == 401);
    // The permission gate still ran (and passed) before the 401.
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: register_dashboard_api_routes rejects an unset "
          "visible_agents_json_fn at registration time — fail-fast at boot, not a "
          "per-request 503 (a caller wiring bug should crash startup, not silently "
          "degrade one route forever)",
          "[server][routes][dashboard_api_routes]") {
    yuzu::server::test::TestRouteSink sink;
    dashboard_api::Deps deps; // visible_agents_json_fn deliberately left unset
    REQUIRE_THROWS_AS(dashboard_api::register_dashboard_api_routes(sink, deps),
                      std::invalid_argument);
}

TEST_CASE("dashboard_api_routes: /api/agents returns the visible-agents JSON for the "
          "authenticated username when both gates pass",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_username = "bob";
    h.visible_agents_json_fn = [](const std::string& username) {
        return json{{"agents", json::array({username + "-agent-1"})}};
    };
    h.wire();

    auto r = h.sink.Get("/api/agents");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(h.last_visible_agents_username == "bob");
    auto j = json::parse(r->body);
    REQUIRE(j["agents"].size() == 1);
    CHECK(j["agents"][0] == "bob-agent-1");
}

// ── GET /api/audit: perm_fn(AuditLog, Read) ────────────────────────────────

TEST_CASE("dashboard_api_routes: /api/audit gates on AuditLog:Read and denies without it",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Get("/api/audit");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "AuditLog");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: /api/audit 503s when audit_store is unset",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // audit_store stays null
    h.wire();

    auto r = h.sink.Get("/api/audit");
    REQUIRE(r);
    CHECK(r->status == 503);
}

// ── POST /api/export/json-to-csv: perm_fn(Response, Read); pure, no store ──

TEST_CASE("dashboard_api_routes: /api/export/json-to-csv gates on Response:Read and denies "
          "without it",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Post("/api/export/json-to-csv", R"([{"name":"widget"}])");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Response");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: /api/export/json-to-csv transforms a JSON array into CSV",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Post("/api/export/json-to-csv", R"([{"name":"widget"},{"name":"gadget"}])");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("Content-Type") == "text/csv; charset=utf-8");
    CHECK(r->body == "name\r\nwidget\r\ngadget\r\n");
}

TEST_CASE("dashboard_api_routes: /api/export/json-to-csv rejects a non-array JSON body with 400",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Post("/api/export/json-to-csv", R"({"not":"an array"})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

// ── POST /api/scope/validate: auth_fn only; pure, no store ─────────────────

TEST_CASE("dashboard_api_routes: /api/scope/validate denies without auth",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_present = false;
    h.wire();

    auto r = h.sink.Post("/api/scope/validate", R"({"expression":"tag:env == \"prod\""})");
    REQUIRE(r);
    CHECK(r->status == 401);
}

TEST_CASE("dashboard_api_routes: /api/scope/validate requires a non-empty expression",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Post("/api/scope/validate", R"({})");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("dashboard_api_routes: /api/scope/validate reports valid:true for a well-formed "
          "expression",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Post("/api/scope/validate", R"({"expression":"tag:env == \"prod\""})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["valid"] == true);
}

TEST_CASE("dashboard_api_routes: /api/scope/validate reports valid:false with an error for a "
          "malformed expression",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Post("/api/scope/validate", R"({"expression":"tag:env =="})");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["valid"] == false);
    CHECK(j.contains("error"));
}

// ── GET /api/analytics/status + /api/analytics/recent: perm_fn(Infra, Read) ─

TEST_CASE("dashboard_api_routes: /api/analytics/status gates on Infrastructure:Read and denies "
          "without it",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Get("/api/analytics/status");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: /api/analytics/status reports enabled:false (200, not 503) when "
          "analytics_store is unset",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // analytics_store stays null
    h.wire();

    auto r = h.sink.Get("/api/analytics/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["enabled"] == false);
    CHECK(j["pending_count"] == 0);
    CHECK(j["total_emitted"] == 0);
}

TEST_CASE("dashboard_api_routes: /api/analytics/recent gates on Infrastructure:Read and denies "
          "without it",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto r = h.sink.Get("/api/analytics/recent");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(h.last_perm_type == "Infrastructure");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("dashboard_api_routes: /api/analytics/recent reports an empty list (200, not 503) when "
          "analytics_store is unset",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // analytics_store stays null
    h.wire();

    auto r = h.sink.Get("/api/analytics/recent");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["events"].empty());
    CHECK(j["count"] == 0);
}

// ── [pg] cases: real RbacStore / AuditStore / AnalyticsEventStore ─────────

namespace {
// RbacStore is Postgres-backed (ADR-0041); pre-migrated template, mirroring
// test_plugin_config_routes.cpp's ROUTES_RBAC pattern. Unique key (not
// shared with any other file's template) since nothing else needs this
// exact single-store setup.
yuzu::test::PgTestTemplate dashapi_rbac_tpl{"dashapiroutesrbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("dashapiroutesrbac template: store failed to migrate");
}};

// AuditStore is Postgres-backed (ADR-0006 Update); pre-migrated template,
// mirroring test_audit_store.cpp's pattern. Unique key for the same reason.
yuzu::test::PgTestTemplate dashapi_audit_tpl{"dashapiroutesaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("dashapiroutesaudit template: store failed to migrate");
}};
} // namespace

TEST_CASE("dashboard_api_routes: /api/me reports the assigned RBAC role when rbac is enabled",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.assign_role({"user", "alice", "PlatformEngineer"}).has_value());

    Harness h;
    h.rbac_store = &rbac;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["rbac_enabled"] == true);
    CHECK(j["rbac_role"] == "PlatformEngineer");
}

TEST_CASE("dashboard_api_routes: /api/me falls back to the legacy-role mapping when rbac is "
          "enabled but the user has no assigned role",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);

    Harness h;
    h.session_role = auth::Role::admin;
    h.rbac_store = &rbac;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    auto j = json::parse(r->body);
    CHECK(j["rbac_enabled"] == true);
    CHECK(j["rbac_role"] == "Administrator");
}

TEST_CASE("dashboard_api_routes: /api/audit queries a real store and reports events, count, and "
          "total",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    AuditEvent e;
    e.principal = "alice";
    e.action = "auth.login";
    e.result = "success";
    REQUIRE(audit.log(e));

    Harness h;
    h.audit_store = &audit;
    h.wire();

    auto r = h.sink.Get("/api/audit");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    REQUIRE(j["events"].size() == 1);
    CHECK(j["events"][0]["principal"] == "alice");
    CHECK(j["events"][0]["action"] == "auth.login");
    CHECK(j["count"] == 1);
    CHECK(j["total"] == 1);
}

TEST_CASE("dashboard_api_routes: /api/audit filters by the principal query param",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    AuditEvent e1;
    e1.principal = "alice";
    e1.action = "auth.login";
    e1.result = "success";
    REQUIRE(audit.log(e1));
    AuditEvent e2;
    e2.principal = "bob";
    e2.action = "auth.login";
    e2.result = "success";
    REQUIRE(audit.log(e2));

    Harness h;
    h.audit_store = &audit;
    h.wire();

    auto r = h.sink.Get("/api/audit?principal=bob");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    REQUIRE(j["events"].size() == 1);
    CHECK(j["events"][0]["principal"] == "bob");
}

TEST_CASE("dashboard_api_routes: /api/audit rejects a non-numeric 'since' with 400 against a "
          "real (open) store",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    Harness h;
    h.audit_store = &audit;
    h.wire();

    auto r = h.sink.Get("/api/audit?since=not-a-number");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("dashboard_api_routes: /api/audit rejects limit < 1 with 400 against a real (open) "
          "store",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    Harness h;
    h.audit_store = &audit;
    h.wire();

    auto r = h.sink.Get("/api/audit?limit=0");
    REQUIRE(r);
    CHECK(r->status == 400);
}

TEST_CASE("dashboard_api_routes: /api/analytics/status reports real pending/total counts",
          "[pg][server][routes][dashboard_api_routes]") {
    yuzu::test::AnalyticsEventStorePg analytics;

    AnalyticsEvent event;
    event.event_type = "agent.registered";
    analytics->emit(event);

    Harness h;
    h.analytics_store = analytics.get();
    h.wire();

    auto r = h.sink.Get("/api/analytics/status");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["enabled"] == true);
    CHECK(j["pending_count"] == 1);
    CHECK(j["total_emitted"] == 1);
}

TEST_CASE("dashboard_api_routes: /api/analytics/recent reports the emitted event",
          "[pg][server][routes][dashboard_api_routes]") {
    yuzu::test::AnalyticsEventStorePg analytics;

    AnalyticsEvent event;
    event.event_type = "agent.registered";
    event.agent_id = "agent-001";
    analytics->emit(event);

    Harness h;
    h.analytics_store = analytics.get();
    h.wire();

    auto r = h.sink.Get("/api/analytics/recent");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    REQUIRE(j["events"].size() == 1);
    CHECK(j["events"][0]["event_type"] == "agent.registered");
    CHECK(j["events"][0]["agent_id"] == "agent-001");
    CHECK(j["count"] == 1);
}
