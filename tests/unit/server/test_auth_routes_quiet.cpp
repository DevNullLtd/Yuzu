/**
 * test_auth_routes_quiet.cpp -- coverage for `Quiet::Yes` on
 * `AuthRoutes::require_permission` / `require_tier_policy`: the render-time
 * capability probe. A quiet call must return the SAME verdict, status and
 * body as the loud call, and must write no denial audit row and move no
 * denial counter. The default (`Quiet::No`) stays loud.
 *
 * The engine-principal arm (including its 503 "authorization store
 * unavailable" refusal, reached by wiring AuthRoutes with no RBAC store) and
 * the ceiling-degraded arm are covered below. Not covered: an RBAC store that
 * is wired but whose handle has died mid-run (is_open() false) for a HUMAN
 * session; it takes the same `rbac_enforcement_in_effect` branch the
 * RBAC-on column already exercises.
 */

#include "auth_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "engine_principal_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "service_scope_policy.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate quiet_tpl{"authroutesquiet", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore rbac{pool};
    TagStore tags{pool};
    AuditStore audit{pool};
    if (!rbac.is_open() || !tags.is_open() || !audit.is_open())
        throw std::runtime_error("authroutesquiet template: a store failed to migrate");
}};

struct QuietRig {
    Config cfg{};
    yuzu::MetricsRegistry metrics; // before auth_mgr: it keeps a raw pointer
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    TagStore tags;
    PgPool audit_pool;
    AuditStore audit;
    yuzu::test::ApiTokenStorePg api_tokens;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    explicit QuietRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 2}}, rbac{pool}, tags{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit{audit_pool} {
        REQUIRE(rbac.is_open());
        REQUIRE(audit.is_open());
        auth_mgr.set_metrics_registry(&metrics);
        REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(), &audit,
                                          /*mgmt_group_store=*/nullptr, &tags,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    httplib::Request cookie_request(const std::string& user, auth::Role role, bool elevate = false) {
        REQUIRE(auth_mgr.upsert_user(user, "password1234", role));
        auto token = auth_mgr.create_local_session_for_test(user, role, /*mfa_verified=*/true);
        if (elevate)
            REQUIRE(auth_mgr.elevate_session(token, std::chrono::seconds(300)).has_value());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    httplib::Request token_request(const std::string& scope_service, const std::string& tier) {
        const auto exp = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count() + 3600;
        auto raw = api_tokens->create_token("quiet-test", "minter", exp, scope_service, tier);
        REQUIRE(raw.has_value());
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + *raw);
        req.path = "/api/v1/probe"; // a non-MCP transport: the approval belt applies
        return req;
    }

    std::size_t rows(const std::string& action) {
        auto r = audit.query(AuditQuery{.action = action, .limit = 1000});
        REQUIRE(r.has_value());
        return r->size();
    }
    std::size_t denial_rows() {
        return rows("auth.permission_required") + rows("auth.approval_required");
    }
    double floor_counter(const std::string& perm) {
        return metrics.counter("yuzu_auth_topology_floor_denied_total", {{"permission", perm}})
            .value();
    }
    double default_deny_counter(const std::string& perm) {
        return metrics
            .counter("yuzu_auth_service_scope_default_denied_total",
                     {{"permission", perm}, {"path_class", "default"}})
            .value();
    }
};

struct Verdict {
    bool ok;
    int status;
    nlohmann::json body; // correlation_id removed: it is minted per response
};

Verdict ask(AuthRoutes& ar, const httplib::Request& req, const std::string& type,
            const std::string& op, Quiet q) {
    httplib::Response res;
    const bool ok = ar.require_permission(req, res, type, op, q);
    Verdict v{ok, res.status, nlohmann::json::object()};
    if (!res.body.empty()) {
        v.body = nlohmann::json::parse(res.body);
        if (v.body.contains("error") && v.body["error"].is_object())
            v.body["error"].erase("correlation_id");
        v.body.erase("correlation_id");
    }
    return v;
}

struct Pair {
    const char* type;
    const char* op;
};
constexpr Pair kPairs[] = {{"Infrastructure", "Read"},
                           {"Infrastructure", "Write"},
                           {"AccessReview", "Read"}, // topology-floored
                           {"ApiToken", "Rotate"}};  // legacy self-service exempt

// Runs every pair for one request: quiet first (must not write), then loud
// (must agree, and must write exactly one row when it denies).
void check_equivalent(QuietRig& r, const httplib::Request& req, const std::string& label,
                      AuthRoutes* ar_override = nullptr) {
    AuthRoutes& ar = ar_override ? *ar_override : *r.ar;
    for (const auto& p : kPairs) {
        INFO(label << " " << p.type << ":" << p.op);
        const auto before = r.denial_rows();
        const auto q = ask(ar, req, p.type, p.op, Quiet::Yes);
        CHECK(r.denial_rows() == before); // quiet wrote nothing
        const auto l = ask(ar, req, p.type, p.op, Quiet::No);
        CHECK(q.ok == l.ok);
        CHECK(q.status == l.status);
        CHECK(q.body == l.body);
        CHECK(r.denial_rows() == before + (l.ok ? 0u : 1u)); // loud is unchanged
    }
}

} // namespace

TEST_CASE("Quiet probe: loud and quiet agree for cookie sessions, RBAC off",
          "[pg][authz][quiet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    check_equivalent(r, r.cookie_request("alice", auth::Role::user), "user/rbac-off");
    check_equivalent(r, r.cookie_request("bob", auth::Role::admin), "admin/rbac-off");
    check_equivalent(r, r.cookie_request("carol", auth::Role::user, /*elevate=*/true),
                     "elevated/rbac-off");
}

TEST_CASE("Quiet probe: loud and quiet agree for cookie sessions, RBAC on",
          "[pg][authz][quiet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "dave", "Administrator"}).has_value());
    r.rbac.set_rbac_enabled(true);
    check_equivalent(r, r.cookie_request("dave", auth::Role::user), "granted/rbac-on");
    check_equivalent(r, r.cookie_request("erin", auth::Role::user), "ungranted/rbac-on");
}

TEST_CASE("Quiet probe: loud and quiet agree for MCP-tier tokens",
          "[pg][authz][quiet][mcp]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    for (const char* tier : {"readonly", "operator", "supervised"})
        check_equivalent(r, r.token_request("", tier), std::string("tier/") + tier);
    // The approval-gated pair on a REST path is its own audit action.
    auto req = r.token_request("", "supervised");
    const auto before = r.rows("auth.approval_required");
    CHECK_FALSE(ask(*r.ar, req, "Execution", "Execute", Quiet::Yes).ok);
    CHECK(r.rows("auth.approval_required") == before);
    CHECK_FALSE(ask(*r.ar, req, "Execution", "Execute", Quiet::No).ok);
    CHECK(r.rows("auth.approval_required") == before + 1);
}

TEST_CASE("Quiet probe: a quiet call consumes nothing -- the loud call still denies and audits once",
          "[pg][authz][quiet][mcp]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    auto req = r.token_request("", "supervised");
    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(ask(*r.ar, req, "Execution", "Execute", Quiet::Yes).ok);
    CHECK(r.denial_rows() == 0);
    CHECK_FALSE(ask(*r.ar, req, "Execution", "Execute", Quiet::No).ok);
    CHECK(r.rows("auth.approval_required") == 1);
}

TEST_CASE("Quiet probe: denial counters move only for loud calls",
          "[pg][authz][quiet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};

    SECTION("topology floor") {
        auto req = r.cookie_request("frank", auth::Role::user);
        CHECK_FALSE(ask(*r.ar, req, "AccessReview", "Read", Quiet::Yes).ok);
        CHECK(r.floor_counter("AccessReview:Read") == 0.0);
        CHECK_FALSE(ask(*r.ar, req, "AccessReview", "Read", Quiet::No).ok);
        CHECK(r.floor_counter("AccessReview:Read") == 1.0);
    }

    SECTION("service-scope default-deny") {
        r.rbac.set_rbac_enabled(true);
        REQUIRE(r.rbac.set_permission({"ITServiceOwner", "Response", "Read", "allow"}).has_value());
        auto req = r.token_request("printers", "");
        CHECK_FALSE(ask(*r.ar, req, "Response", "Read", Quiet::Yes).ok);
        CHECK(r.default_deny_counter("Response:Read") == 0.0);
        CHECK(r.rows("auth.permission_required") == 0);
        CHECK_FALSE(ask(*r.ar, req, "Response", "Read", Quiet::No).ok);
        CHECK(r.default_deny_counter("Response:Read") == 1.0);
        CHECK(r.rows("auth.permission_required") == 1);
    }
}

TEST_CASE("Quiet probe: a degraded ceiling read under a populated allow-list is refused quietly",
          "[pg][authz][quiet][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    r.rbac.set_rbac_enabled(true);
    auto req = r.token_request("printers", "");
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE rbac_store.role_permissions CASCADE")};
        REQUIRE(d.ok());
    }
    r.ar->set_service_scope_global_safe_override_for_test(
        std::vector<authz::PermPair>{{"Response", "Read"}});

    const auto quiet = ask(*r.ar, req, "Response", "Read", Quiet::Yes);
    CHECK_FALSE(quiet.ok);
    CHECK(quiet.status == 503); // the refusal is the same retryable outage, just unrecorded
    CHECK(r.rows("auth.permission_required") == 0);
    CHECK(r.metrics.counter("yuzu_server_rbac_read_degrade_total", {{"reason", "query_error"}})
              .value() == 0.0);

    const auto loud = ask(*r.ar, req, "Response", "Read", Quiet::No);
    CHECK_FALSE(loud.ok);
    CHECK(loud.status == 503);
    CHECK(quiet.body == loud.body);
    CHECK(r.rows("auth.permission_required") == 1);
    CHECK(r.metrics.counter("yuzu_server_rbac_read_degrade_total", {{"reason", "query_error"}})
              .value() == 1.0);
}

TEST_CASE("Quiet probe: loud and quiet agree for an engine principal (granted, ungranted, RBAC "
          "off, RBAC store unavailable)",
          "[pg][authz][quiet][engine]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quiet_tpl);
    QuietRig r{db.dsn()};
    PgPool engine_pool{{.conninfo = db.dsn(), .size = 2}};
    EnginePrincipalStore engine_store{engine_pool};
    REQUIRE(engine_store.is_open());
    REQUIRE(engine_store
                .create("Quiet Engine", "alice", "quiet probe coverage", "internal", "admin",
                        "engine:quiet-test")
                .has_value());
    r.api_tokens->set_engine_referent_check(
        [&](const std::string& id) { return engine_store.get_for_auth(id).status; });
    r.ar->set_engine_principal_store(&engine_store);

    const auto exp = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count() + 3600;
    auto raw = r.api_tokens->create_token("quiet-engine", "engine:quiet-test", exp, "", "readonly",
                                          "engine");
    REQUIRE(raw.has_value());
    httplib::Request req;
    req.headers.emplace("Authorization", "Bearer " + *raw);
    req.path = "/api/v1/probe";

    SECTION("RBAC off: denied (engine never reaches the legacy fallback)") {
        check_equivalent(r, req, "engine/rbac-off");
    }
    SECTION("RBAC on, ungranted") {
        r.rbac.set_rbac_enabled(true);
        check_equivalent(r, req, "engine/ungranted");
    }
    SECTION("RBAC on, granted") {
        // A custom role: the seeded Administrator role cannot be assigned to an engine.
        REQUIRE(r.rbac.create_role({.name = "QuietEngineRole", .description = "d"}).has_value());
        REQUIRE(r.rbac.set_permission({"QuietEngineRole", "Infrastructure", "Read", "allow"})
                    .has_value());
        REQUIRE(r.rbac.assign_role({"engine", "engine:quiet-test", "QuietEngineRole"}).has_value());
        r.rbac.set_rbac_enabled(true);
        check_equivalent(r, req, "engine/granted");
        httplib::Response res;
        CHECK(r.ar->require_permission(req, res, "Infrastructure", "Read", Quiet::Yes));
    }
    SECTION("RBAC store unavailable: 503 on both paths") {
        std::shared_mutex mu;
        std::unique_ptr<oidc::OidcProvider> no_oidc;
        AuthRoutes bare(r.cfg, r.auth_mgr, /*rbac_store=*/nullptr, r.api_tokens.get(), &r.audit,
                        nullptr, &r.tags, nullptr, mu, no_oidc);
        bare.set_engine_principal_store(&engine_store);
        const auto q = ask(bare, req, "Infrastructure", "Read", Quiet::Yes);
        CHECK_FALSE(q.ok);
        CHECK(q.status == 503);
        check_equivalent(r, req, "engine/store-unavailable", &bare);
    }
}
