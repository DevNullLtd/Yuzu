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
#include "test_principal_lock_gate.hpp" // yuzu::test::GrantReadFault (/api/me real-store fault)

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <regex>
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
    std::string session_display_name;
    auth::Role session_role{auth::Role::user};
    std::string session_mcp_tier;
    std::string session_scope_service;
    std::string session_principal_kind{"human"};
    std::string session_auth_source{"local"};
    bool session_elevated{false};

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
            s.display_name = session_display_name;
            s.role = session_role;
            s.mcp_tier = session_mcp_tier;
            s.token_scope_service = session_scope_service;
            s.principal_kind = session_principal_kind;
            s.auth_source = session_auth_source;
            if (session_elevated) {
                s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
                s.elevated_until = std::chrono::system_clock::now() + std::chrono::hours(1);
            }
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

TEST_CASE("dashboard_api_routes: /api/me self-description per persona (#5779, #4208)",
          "[server][routes][dashboard_api_routes]") {
    struct Row {
        auth::Role role;
        bool elevated;
        const char* mcp_tier;
        const char* scope;
        const char* effective;
        bool can_access;
    };
    const Row rows[] = {
        {auth::Role::admin, false, "", "", "admin", true},
        {auth::Role::user, false, "", "", "user", false},
        {auth::Role::user, true, "", "", "admin", true},
        {auth::Role::admin, false, "operator", "", "admin", false},
        {auth::Role::user, false, "", "finance", "user", false},
    };
    for (const auto& row : rows) {
        Harness h;
        h.session_role = row.role;
        h.session_elevated = row.elevated;
        h.session_mcp_tier = row.mcp_tier;
        h.session_scope_service = row.scope;
        h.wire();
        auto r = h.sink.Get("/api/me");
        REQUIRE(r);
        auto j = json::parse(r->body);
        CHECK(j["role"] == auth::role_to_string(row.role));
        CHECK(j["effective_role"] == row.effective);
        CHECK(j["elevated"] == row.elevated);
        CHECK(j.contains("elevated_until") == row.elevated);
        if (row.elevated) {
            REQUIRE(j["elevated_until"].is_string());
            CHECK(std::regex_match(j["elevated_until"].get<std::string>(),
                                   std::regex(R"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)")));
        }
        CHECK(j["can_access_settings"] == row.can_access);
        CHECK(r->get_header_value("Cache-Control") == "no-store, private");
        // perm_fn is never called (the audit-row absence is pinned by the PG
        // decision-table case in test_auth_routes.cpp, which wires a real store).
        CHECK(h.last_perm_type.empty());
    }
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

TEST_CASE("dashboard_api_routes: /api/me for an engine principal omits rbac_role and carries the "
          "new identity keys (the shell JS falls back to `role`)",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // rbac_store stays null: RBAC off
    h.session_username = "engine:indexer";
    h.session_role = auth::Role::user;
    h.session_principal_kind = "engine";
    h.session_auth_source = "engine_token";
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["username"] == "engine:indexer");
    CHECK(j["role"] == "user");
    CHECK(j["principal_kind"] == "engine");
    CHECK(j["auth_source"] == "engine_token");
    CHECK_FALSE(j.contains("rbac_role")); // never a fabricated Viewer
    CHECK(j["rbac_roles"].is_array());
    CHECK(j["rbac_roles_resolved"] == true);
    CHECK(r->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("dashboard_api_routes: /api/me human keeps every legacy key and adds the new ones",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_role = auth::Role::user;
    h.session_mcp_tier = "readonly";
    h.session_scope_service = "finance";
    h.wire();

    auto j = json::parse(h.sink.Get("/api/me")->body);
    for (const char* k : {"username", "display_name", "role", "rbac_enabled", "rbac_role",
                          "effective_role", "elevated", "can_access_settings"})
        CHECK(j.contains(k));
    CHECK(j["principal_kind"] == "human");
    CHECK(j["mcp_tier"] == "readonly");
    CHECK(j["scope_service"] == "finance");
}

TEST_CASE("dashboard_api_routes: /api/me with invalid UTF-8 in the session answers 200 with U+FFFD, "
          "never a throw",
          "[server][routes][dashboard_api_routes]") {
    Harness h;
    h.session_username = std::string("ab\xC3\x28");
    h.session_display_name = std::string("\xFF\xFE");
    h.wire();

    std::unique_ptr<httplib::Response> r;
    REQUIRE_NOTHROW(r = h.sink.Get("/api/me"));
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto j = json::parse(r->body); // the body itself is valid JSON/UTF-8
    CHECK(j["username"].get<std::string>() == "ab\xEF\xBF\xBD(");
    CHECK(j["display_name"].get<std::string>() == "\xEF\xBF\xBD\xEF\xBF\xBD");
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

TEST_CASE("dashboard_api_routes: /api/export/json-to-csv rejects a body nested deeper than 32 "
          "with 400 and still accepts a legitimate nested row",
          "[server][routes][dashboard_api_routes][export]") {
    Harness h;
    h.wire();

    // Deeper than kMcpMaxJsonDepth: dump() of this cell would recurse 40 deep
    // per row; at depth ~100k it kills the process. Must be refused pre-parse.
    std::string deep = R"([{"a":)" + std::string(40, '[') + std::string(40, ']') + "}]";
    auto bad = h.sink.Post("/api/export/json-to-csv", deep);
    REQUIRE(bad);
    CHECK(bad->status == 400);
    CHECK(bad->body.find("request body nests too deeply") != std::string::npos);

    // Depth 3 (array, object, array, array) is a legitimate row.
    auto ok = h.sink.Post("/api/export/json-to-csv", R"([{"a":[[1,2]]}])");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(ok->body == "a\r\n\"[[1,2]]\"\r\n");
}

TEST_CASE("dashboard_api_routes: /api/export/json-to-csv quotes non-string cells without "
          "formula-neutralising them",
          "[server][routes][dashboard_api_routes][export]") {
    Harness h;
    h.wire();

    // A negative number stays a number: neutralize_formula would make it '-5.
    auto num = h.sink.Post("/api/export/json-to-csv", R"([{"n":-5,"f":-1.5,"b":true}])");
    REQUIRE(num);
    CHECK(num->body == "b,f,n\r\ntrue,-1.5,-5\r\n"); // keys sort; -5 untouched

    // A nested object with commas stays in ONE cell (RFC 4180 quoted).
    auto obj = h.sink.Post("/api/export/json-to-csv", R"([{"o":{"a":1,"b":2},"z":"x"}])");
    REQUIRE(obj);
    CHECK(obj->body == "o,z\r\n\"{\"\"a\"\":1,\"\"b\"\":2}\",x\r\n");

    // A free-text string starting with '=' is still neutralised.
    auto str = h.sink.Post("/api/export/json-to-csv", R"([{"s":"=1+1"}])");
    REQUIRE(str);
    CHECK(str->body == "s\r\n'=1+1\r\n");
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
    // #5779: an RBAC role label never opens /settings (require_admin ignores RBAC
    // grants); the link predicate must stay false for a non-admin session.
    CHECK(j["can_access_settings"] == false);
    CHECK(j["effective_role"] == "user");
}

TEST_CASE("dashboard_api_routes: /api/me can_access_settings stays false for an RBAC "
          "Administrator grant on a legacy user session (#5779)",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.assign_role({"user", "alice", "Administrator"}).has_value());

    Harness h;
    h.rbac_store = &rbac;
    h.wire();

    auto r = h.sink.Get("/api/me");
    REQUIRE(r);
    auto j = json::parse(r->body);
    CHECK(j["rbac_role"] == "Administrator");
    CHECK(j["role"] == "user");
    CHECK(j["can_access_settings"] == false);
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

TEST_CASE("dashboard_api_routes: /api/me reads grants under the namespace of the session kind, "
          "not the username prefix",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    // RbacStore refuses a ('user', 'engine:...') row, so the engine grant is the only
    // row that carries this id. A user-namespace read of the same string must not see it.
    REQUIRE(rbac.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(rbac.assign_role({"engine", "engine:shared", "EngineReader"}).has_value());

    SECTION("a human named engine:shared is a user lookup and does not see the engine grant") {
        Harness h;
        h.session_username = "engine:shared";
        h.rbac_store = &rbac;
        h.wire();
        auto j = json::parse(h.sink.Get("/api/me")->body);
        CHECK(j["rbac_role"] == "Viewer"); // legacy fallback for a human with no user grant
        CHECK(j["rbac_roles"].empty());
        CHECK(j["rbac_roles_resolved"] == true);
    }
    SECTION("an engine principal is an engine lookup") {
        Harness h;
        h.session_username = "engine:shared";
        h.session_principal_kind = "engine";
        h.session_auth_source = "engine_token";
        h.rbac_store = &rbac;
        h.wire();
        auto j = json::parse(h.sink.Get("/api/me")->body);
        CHECK(j["rbac_role"] == "EngineReader");
        CHECK(j["rbac_roles"] == json::array({"EngineReader"}));
        CHECK(j["rbac_roles_resolved"] == true);
    }
    SECTION("an engine with no engine grant gets no rbac_role, not Viewer") {
        Harness h;
        h.session_username = "engine:ungranted";
        h.session_principal_kind = "engine";
        h.session_auth_source = "engine_token";
        h.rbac_store = &rbac;
        h.wire();
        auto j = json::parse(h.sink.Get("/api/me")->body);
        CHECK(j["rbac_enabled"] == true);
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK(j["rbac_roles"].empty());
        CHECK(j["rbac_roles_resolved"] == true);
    }
}

TEST_CASE("dashboard_api_routes: /api/me with a REAL store fault (principal_roles unreadable) is a "
          "200 with rbac_roles_resolved:false and no invented role",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.assign_role({"user", "alice", "Operator"}).has_value());

    Harness h;
    h.session_role = auth::Role::admin;
    h.rbac_store = &rbac;
    h.wire();

    // GrantReadFault moves rbac_store.principal_roles aside: the REAL
    // get_principal_roles_checked fails while is_rbac_enabled() (rbac_meta) still answers.
    yuzu::test::GrantReadFault fault(pool);
    fault.arm();
    auto r = h.sink.Get("/api/me");
    fault.repair();
    REQUIRE(r);
    CHECK(r->status == 200);
    auto j = json::parse(r->body);
    CHECK(j["rbac_enabled"] == true);
    CHECK(j["rbac_roles_resolved"] == false);
    CHECK_FALSE(j.contains("rbac_role")); // not even the legacy Administrator label
    CHECK_FALSE(j.contains("rbac_roles"));
    CHECK(j["role"] == "admin");

    // Repaired: the same route resolves the real grant again.
    auto again = json::parse(h.sink.Get("/api/me")->body);
    CHECK(again["rbac_roles_resolved"] == true);
    CHECK(again["rbac_role"] == "Operator");
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

TEST_CASE("dashboard_api_routes: /api/audit bounds limit and offset like its v1/MCP twins",
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
    {
        // One statement seeds 1000 more rows (1001 total) so the cap is observable.
        auto lease = pool.acquire();
        REQUIRE(lease);
        PGresult* ins = PQexec(
            lease.get(),
            "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, action, "
            "result) SELECT g, 'bulk', 'admin', 'bulk.seed', 'success' FROM generate_series(1, "
            "1000) g");
        REQUIRE(PQresultStatus(ins) == PGRES_COMMAND_OK);
        PQclear(ins);
    }

    Harness h;
    h.audit_store = &audit;
    h.wire();

    // An oversized limit is clamped to 1000 before the store: 1001 rows exist,
    // exactly 1000 come back - not an unbounded fetch and not an error.
    auto r = h.sink.Get("/api/audit?limit=2147483647");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(json::parse(r->body)["events"].size() == 1000);
    // offset is capped at kAuditMaxOffset; the cap itself is valid.
    r = h.sink.Get("/api/audit?offset=10001");
    REQUIRE(r);
    CHECK(r->status == 400);
    r = h.sink.Get("/api/audit?offset=10000");
    REQUIRE(r);
    CHECK(r->status == 200);
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

// ── #4644: strict numeric query parameters ──────────────────────────

TEST_CASE("dashboard_api_routes: /api/audit rejects a malformed since/until/limit/offset with "
          "400 instead of reading its numeric prefix",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    Harness h;
    h.audit_store = &audit;
    h.wire();

    for (const char* bad :
         {"since=1e9", "since=junk", "since=100abc", "until=0x10", "until=", "limit=100abc",
          "limit=1e3", "offset=5x", "limit=4294967296", "since=99999999999999999999"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/audit?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(json::parse(r->body)["error"]["message"] == "invalid numeric query parameter");
    }
    auto ok = h.sink.Get("/api/audit?since=0&until=1&limit=10&offset=0");
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("dashboard_api_routes: /api/audit rejects a negative since and until of zero or below "
          "with 400 while since of zero is accepted",
          "[pg][server][routes][dashboard_api_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dashapi_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore audit{pool};
    REQUIRE(audit.is_open());

    Harness h;
    h.audit_store = &audit;
    h.wire();

    // The bounds are presence-tracked: a literal -3600 or 0 used to mean "the whole log".
    for (const char* bad : {"since=-1", "since=-3600", "since=-1&until=5", "since=-5&until=7"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/audit?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(json::parse(r->body)["error"]["message"] == "since must not be negative");
    }
    for (const char* bad : {"until=0", "until=000", "until=-1", "since=5&until=0",
                            "since=0&until=0", "since=0&until=-5"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/audit?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(json::parse(r->body)["error"]["message"] ==
              "until must be a positive epoch second or omitted");
    }
    for (const char* ok : {"since=0", "until=1", "since=0&until=1", "", "since=1700000000"}) {
        INFO(ok);
        auto r = h.sink.Get(std::string("/api/audit?") + ok);
        REQUIRE(r);
        CHECK(r->status == 200);
    }
}

TEST_CASE("dashboard_api_routes: /api/analytics/recent rejects a malformed limit with 400 "
          "instead of silently ignoring it",
          "[server][routes][dashboard_api_routes]") {
    Harness h; // analytics_store stays null: the 400 is decided before the store is touched
    h.wire();

    for (const char* bad : {"limit=abc", "limit=50x", "limit=1e3", "limit=", "limit=4294967296"}) {
        INFO(bad);
        auto r = h.sink.Get(std::string("/api/analytics/recent?") + bad);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(json::parse(r->body)["error"]["message"] == "invalid numeric query parameter");
    }
    // A well-formed value (even a non-positive one, which is clamped) is not an error.
    for (const char* ok : {"limit=10", "limit=0", "limit=-5"}) {
        INFO(ok);
        auto r = h.sink.Get(std::string("/api/analytics/recent?") + ok);
        REQUIRE(r);
        CHECK(r->status == 200);
    }
}
