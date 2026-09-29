/// @file test_app_usage_routes.cpp
/// Tests for `GET /api/v1/forensics/agents/{agent_id}/app-usage` (Wave 7
/// PR7.2) — driven in-process through TestRouteSink (no httplib acceptor,
/// #438). Mirrors test_sle_routes.cpp's single-agent drill coverage: the
/// unwired-gate fail-closed posture, scoped in/out-of-scope, provider
/// nullopt -> 503 A4 (never an empty 200), the per-open behavioural audit
/// (app_usage.agent.view) that FAILS CLOSED (503 + Sec-Audit-Failed), and the
/// success response shape.
///
/// PLUS (adjudication P2) production-composition coverage through the REAL
/// `AuthRoutes::require_scoped_permission` — the shape
/// test_authz_topology_floor.cpp uses — proving the route's scoped gate
/// closure actually composes with the live RBAC engine and the Wave 7 PR7.2
/// `Forensics:Read` topology-floor entry, not just a fake harness predicate.

#include "app_usage_routes.hpp"
#include "test_route_sink.hpp"

#include "auth_routes.hpp"
#include "app_usage_store.hpp" // AgentLastUsedRow
#include "audit_store.hpp"
#include "rbac_store.hpp"
#include "test_rbac_store_pg_helper.hpp" // PG-backed RbacStore (ADR-0041)

#include "pg/pg_pool.hpp"
#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

AgentLastUsedRow row(std::string exe_key) {
    AgentLastUsedRow r;
    r.exe_key = std::move(exe_key);
    r.first_seen = 1000;
    r.last_seen = 2000;
    r.run_count_30d = 3;
    r.total_seconds_30d = 456;
    return r;
}

// ── Route harness — all providers injected, every flag re-read per call ──────
struct AppUsageHarness {
    yuzu::server::test::TestRouteSink sink;
    AppUsageRoutes routes;

    bool allow_scoped_all = false;
    std::vector<std::string> scoped_agents; // in-scope agent ids
    bool degrade_snapshot = false; // the ONE combined rows+collected_at read degrades
    bool audit_should_fail = false;

    std::vector<AgentLastUsedRow> agent_rows;
    std::int64_t collected_at_value = 0;

    std::vector<std::string> audits;     // "action|result"
    std::vector<std::string> audit_full; // "action|result|target_type|target_id"
    std::vector<std::string> scoped_calls; // "type|op|agent_id"

    AppUsageHarness() {
        auto scoped = [this](const httplib::Request&, httplib::Response& res,
                             const std::string& type, const std::string& op,
                             const std::string& agent_id) {
            scoped_calls.push_back(type + "|" + op + "|" + agent_id);
            bool ok = allow_scoped_all;
            for (const auto& a : scoped_agents)
                if (a == agent_id)
                    ok = true;
            if (!ok) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"permission":")" + type + ":" + op +
                                    R"("}})",
                                "application/json");
            }
            return ok;
        };
        auto snapshot_fn = [this](const std::string&) -> std::optional<AppUsageSnapshot> {
            if (degrade_snapshot)
                return std::nullopt;
            AppUsageSnapshot snap;
            snap.rows = agent_rows;
            snap.collected_at = collected_at_value;
            return snap;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid, const std::string&) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            return !audit_should_fail;
        };
        routes.register_routes(sink, scoped, snapshot_fn, audit);
    }

    bool audited(const std::string& tok) const {
        for (const auto& a : audits)
            if (a == tok)
                return true;
        return false;
    }
};

const char* kPath = "/api/v1/forensics/agents/agent-1/app-usage";

} // namespace

// ───────────────────────── unwired scope gate — fail closed ─────────────────

TEST_CASE("app-usage: unwired scope gate -> 503, never legacy-open", "[app_usage_routes]") {
    yuzu::server::test::TestRouteSink sink;
    AppUsageRoutes routes;
    // No scoped_perm_fn supplied — the default-constructed std::function is empty.
    routes.register_routes(sink, /*scoped_perm_fn=*/{}, /*agent_usage_snapshot_fn=*/{});
    auto res = sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(contains(res->body, "scope gate not configured"));
}

// ───────────────────────── scoped gate: in/out of scope ─────────────────────

TEST_CASE("app-usage: demands exactly Forensics:Read via the scoped gate", "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.sink.Get("/api/v1/forensics/agents/agent-77/app-usage");
    REQUIRE(h.scoped_calls.size() == 1);
    CHECK(h.scoped_calls[0] == "Forensics|Read|agent-77");
}

TEST_CASE("app-usage: scoped gate — in-scope 200, out-of-scope 403", "[app_usage_routes]") {
    AppUsageHarness h;
    h.scoped_agents = {"agent-in"};
    h.agent_rows = {row("notepad.exe")};

    auto in = h.sink.Get("/api/v1/forensics/agents/agent-in/app-usage");
    REQUIRE(in);
    CHECK(in->status == 200);
    CHECK(contains(in->body, "notepad.exe"));

    auto out = h.sink.Get("/api/v1/forensics/agents/agent-out/app-usage");
    REQUIRE(out);
    CHECK(out->status == 403);
    CHECK_FALSE(contains(out->body, "notepad.exe")); // no data leaked outside scope
}

TEST_CASE("app-usage: scoped gate runs BEFORE the audit + read (out-of-scope -> no audit)",
          "[app_usage_routes]") {
    AppUsageHarness h; // scoped gate denies everything
    h.agent_rows = {row("notepad.exe")};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audits.empty());
}

// ───────────────────────── provider nullopt / degrade -> 503 A4 ─────────────

TEST_CASE("app-usage: provider nullopt -> 503 A4 envelope, never a silent empty 200",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.degrade_snapshot = true;
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = json::parse(res->body);
    CHECK(j["error"]["code"] == 503);
    // A degrade is audited as a failure so the evidence trail is honest.
    CHECK(h.audited("app_usage.agent.view|failure"));
}

// ───────────────────────── empty result -> 200 with apps: [] ────────────────

TEST_CASE("app-usage: empty result -> 200 with data.apps as an empty array", "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {}; // agent genuinely reported no rows for the retained window
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["agent_id"] == "agent-1");
    CHECK(j["apps"].is_array());
    CHECK(j["apps"].empty());
}

TEST_CASE("app-usage: an empty-snapshot result still carries the real collected_at, "
          "never 0 (#C2)",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    // A legitimate replace-to-empty snapshot (the store's own header banner:
    // "the retained-window projection can genuinely shrink to nothing") — the
    // provider closure mirrors AppUsageStore::collected_at, sourced from
    // usage_state, NOT rows->front() (there is no row to source it from).
    h.agent_rows = {};
    h.collected_at_value = 1751700000;
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["apps"].empty());
    CHECK(j["collected_at"] == 1751700000);
}

// ───────────────────────── success response shape ───────────────────────────

TEST_CASE("app-usage: success shape — data.agent_id, apps[].{exe_key,...}, collected_at",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {row("chrome.exe")};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["agent_id"] == "agent-1");
    REQUIRE(j["apps"].size() == 1);
    CHECK(j["apps"][0]["exe_key"] == "chrome.exe");
    CHECK(j["apps"][0]["first_seen"] == 1000);
    CHECK(j["apps"][0]["last_seen"] == 2000);
    CHECK(j["apps"][0]["run_count_30d"] == 3);
    CHECK(j["apps"][0]["total_seconds_30d"] == 456);
    CHECK(j.contains("collected_at"));
}

// ───────────────────────── per-open behavioural audit ───────────────────────

TEST_CASE("app-usage: per-open behavioural audit is emitted (app_usage.agent.view)",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {row("chrome.exe")};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.audited("app_usage.agent.view|success"));
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "app_usage.agent.view|success|Agent|agent-1")
            target_ok = true;
    CHECK(target_ok);
}

TEST_CASE("app-usage: audit FAILS CLOSED — 503 + Sec-Audit-Failed, data withheld",
          "[app_usage_routes]") {
    AppUsageHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true;
    h.agent_rows = {row("chrome.exe")};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK_FALSE(contains(res->body, "chrome.exe"));
    CHECK_FALSE(contains(res->body, "\"apps\""));
}

// ═══════════════════ Production composition (adjudication P2) ═══════════════
//
// Wires AppUsageRoutes' ScopedPermFn to the REAL
// `AuthRoutes::require_scoped_permission`, the same fixture shape
// test_authz_topology_floor.cpp uses, so this proves the route composes with
// the live RBAC engine and the Wave 7 PR7.2 `Forensics:Read` topology-floor
// entry — not merely a fake harness predicate. See
// test_authz_topology_floor.cpp's "Forensics:Read" TEST_CASE for the
// unscoped (require_permission) twin of this matrix.

namespace {

yuzu::test::PgTestTemplate app_usage_routes_audit_tpl{
    "appusageroutesaudit", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::AuditStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("app_usage_routes audit template: store failed to migrate");
    }};

/// Wires a real PG-backed RbacStore + AuditStore behind AuthRoutes and a real
/// AppUsageRoutes registered against `AuthRoutes::require_scoped_permission`,
/// so each TEST_CASE only mints a cookie session and dispatches through the
/// sink. Mirrors FloorFixture (test_authz_topology_floor.cpp).
struct ProductionFixture {
    yuzu::test::RbacStorePg rbac_bundle;
    RbacStore& rbac_store = *rbac_bundle;
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auth::AuthManager auth_mgr{};
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    yuzu::server::test::TestRouteSink sink;
    AppUsageRoutes routes;

    ProductionFixture() {
        REQUIRE(rbac_store.is_open());
        audit_db.emplace(app_usage_routes_audit_tpl);
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit_store = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit_store->is_open());
        auth_mgr.set_metrics_registry(&metrics);
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac_store,
                                          /*api_token_store=*/nullptr, audit_store.get(),
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

        AppUsageRoutes::ScopedPermFn scoped =
            [this](const httplib::Request& req, httplib::Response& res, const std::string& type,
                  const std::string& op, const std::string& agent_id) {
                return ar->require_scoped_permission(req, res, type, op, agent_id);
            };
        AppUsageRoutes::AgentUsageSnapshotFn snapshot_fn =
            [](const std::string&) -> std::optional<AppUsageSnapshot> {
            return AppUsageSnapshot{};
        };
        // Audit-off (empty AuditFn): this fixture exercises the AUTHZ
        // composition, not the audit tier — SleRoutes'/FloorFixture's
        // precedent of keeping unrelated dimensions out of scope.
        routes.register_routes(sink, scoped, snapshot_fn, /*audit_fn=*/{});
    }

    httplib::Request session_request(const std::string& username, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", role));
        auto token = auth_mgr.create_local_session(username, role, /*mfa_verified=*/true);
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }
};

} // namespace

TEST_CASE("app-usage production composition: RBAC off — ordinary session 403, admin 200",
          "[pg][app_usage_routes]") {
    ProductionFixture fix;

    SECTION("RBAC off: an ordinary user cookie session is denied (Forensics:Read is floored)") {
        auto req = fix.session_request("alice", auth::Role::user);
        auto res = fix.sink.dispatch("GET", kPath, {}, "application/json",
                                     {{"Cookie", req.get_header_value("Cookie")}});
        REQUIRE(res);
        CHECK(res->status == 403);
    }

    SECTION("RBAC off: an admin cookie session is allowed") {
        auto req = fix.session_request("bob", auth::Role::admin);
        auto res = fix.sink.dispatch("GET", kPath, {}, "application/json",
                                     {{"Cookie", req.get_header_value("Cookie")}});
        REQUIRE(res);
        CHECK(res->status == 200);
    }
}

TEST_CASE("app-usage production composition: RBAC on — seeded Administrator grant 200, "
          "no grant 403",
          "[pg][app_usage_routes]") {
    ProductionFixture fix;

    SECTION("RBAC on: a user assigned the seeded Administrator role is allowed") {
        REQUIRE(fix.rbac_store.assign_role({"user", "carol", "Administrator"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("carol", auth::Role::user);
        auto res = fix.sink.dispatch("GET", kPath, {}, "application/json",
                                     {{"Cookie", req.get_header_value("Cookie")}});
        REQUIRE(res);
        CHECK(res->status == 200);
    }

    SECTION("RBAC on: a non-admin with no Forensics grant is denied") {
        fix.rbac_store.set_rbac_enabled(true);
        auto req = fix.session_request("dave", auth::Role::user);
        auto res = fix.sink.dispatch("GET", kPath, {}, "application/json",
                                     {{"Cookie", req.get_header_value("Cookie")}});
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}
