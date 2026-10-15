/**
 * test_rest_engine_principal_roles.cpp — HTTP-level tests for
 * `/api/v1/engine-principals/{id}/roles` (PR 4.2, design doc
 * docs/auth-engine-principals-design.md §4.1).
 *
 * This is the fleet-wide engine role-assignment AUTHORING surface flagged
 * by external review as the largest confirmed HIGH finding on PR #2202:
 * `RbacStore::assign_role(principal_type="engine")` had zero production
 * callers, so the RBAC resolver's engine-resolution branch (the third UNION
 * arm in `collect_roles_locked`) was unreachable. These tests prove the
 * route exists, is gated correctly, and — critically — that the loop the
 * reviewer flagged is now closed end-to-end: assigning a role through this
 * REST route makes `RbacStore::check_permission("engine:<slug>", ...)`
 * return true.
 *
 * Pattern: register RestApiV1 routes against an in-process TestRouteSink
 * (mirrors test_rest_api_tokens.cpp) — no httplib::Server, no acceptor
 * thread, TSan-safe (#438).
 *
 * PG-gated: EnginePrincipalStore AND RbacStore are both born-on-Postgres
 * stores (ADR-0006). Skips when YUZU_TEST_POSTGRES_DSN is unset, fails when
 * set but broken (test_helpers.hpp skip-vs-fail contract).
 */

#include "engine_principal_store.hpp"
#include "rbac_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "pg/pg_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;

namespace {

// ── shared PG-backed EnginePrincipalStore helper (mirrors
// test_engine_principal_integration.cpp's EnginePrincipalStorePg; a distinct
// PgTestTemplate name keeps the registry entries separate). ─────────────────

void setup_engine_principal_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("engine_principal (rest routes) template: store failed to migrate");
}

yuzu::test::PgTestTemplate engine_principal_rest_template{
    "engineprincipal_rest", &setup_engine_principal_store_pg_template};

class EnginePrincipalStorePg {
public:
    EnginePrincipalStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(engine_principal_rest_template);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<EnginePrincipalStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    EnginePrincipalStorePg(const EnginePrincipalStorePg&) = delete;
    EnginePrincipalStorePg& operator=(const EnginePrincipalStorePg&) = delete;

    [[nodiscard]] EnginePrincipalStore* get() const noexcept { return store_.get(); }
    EnginePrincipalStore* operator->() const noexcept { return store_.get(); }

    // RbacStore coexists in this SAME database (own `rbac_store` schema) —
    // RestEngineRolesHarness shares this pool rather than standing up a
    // second PG database per test.
    [[nodiscard]] yuzu::server::pg::PgPool& pool() noexcept { return *pool_; }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<EnginePrincipalStore> store_;
};

struct RestEngineRolesHarness {
    yuzu::server::test::TestRouteSink sink;

    // engine_store declared first: its constructor is where the
    // YUZU_TEST_POSTGRES_DSN SKIP actually fires (mirrors ModelHarness in
    // test_access_review_model.cpp), and rbac_store below is constructed
    // from engine_store's pool, so engine_store must exist first.
    EnginePrincipalStorePg engine_store;
    std::unique_ptr<RbacStore> rbac_store;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};
    bool auth_enabled{true};
    // Default permissive (matches every other test in this file, which
    // exercises the route's own logic, not the RBAC gate). A test that wants
    // to prove the Security:Write gate itself denies a non-admin/engine
    // session sets this to a predicate returning false — mirrors
    // McpTestServer's perm_override_for_test in test_mcp_server.cpp.
    std::function<bool(const std::string&, const std::string&)> perm_override;
    // #2466/#2406: when false, audit_fn returns false (row NOT persisted) exactly
    // as AuditStore::log does on a degraded store, so the route must fail closed.
    bool audit_allow{true};

    struct AuditRecord {
        std::string action;
        std::string result;
        std::string target_id;
        std::string detail;
    };
    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    RestEngineRolesHarness() {
        rbac_store = std::make_unique<RbacStore>(engine_store.pool());
        REQUIRE(rbac_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (!auth_enabled)
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // Permissive by default — see `perm_override` above.
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            if (perm_override && !perm_override(type, op)) {
                res.status = 403;
                return false;
            }
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return audit_allow;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            rbac_store.get(),
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{}, // no MFA gate in this harness (mirrors token tests)
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/engine_store.get());
    }

    auto get_roles(const std::string& slug) {
        return sink.Get("/api/v1/engine-principals/" + slug + "/roles");
    }
    auto assign(const std::string& slug, const std::string& body) {
        return sink.Post("/api/v1/engine-principals/" + slug + "/roles", body);
    }
    auto unassign(const std::string& slug, const std::string& role) {
        return sink.Delete("/api/v1/engine-principals/" + slug + "/roles/" + role);
    }
};

} // namespace

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: assign creates a resolvable "
          "fleet-wide grant (the loop the reviewer flagged)",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store->set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store
               ->create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                        "engine:vuln")
               .has_value());

    // Before assignment: the resolver has nothing to resolve.
    CHECK_FALSE(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));

    auto res = h.assign("vuln", R"({"role":"EngineReader"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"assigned\":true") != std::string::npos);

    // The end-to-end proof: RbacStore::check_permission on "engine:vuln" now
    // resolves true through the resolution-side UNION arm — production
    // route -> RbacStore::assign_role -> collect_roles_locked engine arm.
    CHECK(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "engine_principal.role.assigned");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == "engine:vuln");

    // GET list reflects the new grant.
    auto listed = h.get_roles("vuln");
    REQUIRE(listed);
    CHECK(listed->status == 200);
    CHECK(listed->body.find("EngineReader") != std::string::npos);
    // Field-name contract (ADR-1005 A1 twin parity): the list item key is
    // `role`, matching the assign/unassign response bodies and the MCP
    // list twin — NOT the legacy `role_name`. Lock it so a rename can't
    // silently reintroduce the REST/MCP drift.
    CHECK(listed->body.find("\"role\"") != std::string::npos);
    CHECK(listed->body.find("role_name") == std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/engine-principals/{id}/roles/{role}: unassign removes the grant",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store->set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    REQUIRE(h.assign("vuln", R"({"role":"EngineReader"})")->status == 201);
    REQUIRE(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));

    auto res = h.unassign("vuln", "EngineReader");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"unassigned\":true") != std::string::npos);

    CHECK_FALSE(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));

    bool found_unassign_audit = false;
    for (const auto& e : h.audit_log)
        if (e.action == "engine_principal.role.unassigned" && e.result == "success")
            found_unassign_audit = true;
    CHECK(found_unassign_audit);
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: admin/system role assignment is "
          "rejected 4xx, not 500 (design §4.2 'no admin, ever')",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    SECTION("literal 'admin' role name") {
        auto res = h.assign("vuln", R"({"role":"admin"})");
        REQUIRE(res);
        CHECK(res->status >= 400);
        CHECK(res->status < 500);
    }

    SECTION("the built-in 'Administrator' role") {
        auto res = h.assign("vuln", R"({"role":"Administrator"})");
        REQUIRE(res);
        CHECK(res->status >= 400);
        CHECK(res->status < 500);
    }

    SECTION("a built-in system role outside the literal admin bar (Viewer)") {
        auto res = h.assign("vuln", R"({"role":"Viewer"})");
        REQUIRE(res);
        CHECK(res->status >= 400);
        CHECK(res->status < 500);
    }

    // None of the rejected grants ever landed.
    CHECK(h.rbac_store->get_principal_roles("engine", "engine:vuln").empty());
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: unknown role name rejected 400",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    auto res = h.assign("vuln", R"({"role":"NoSuchRole"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rbac_store->get_principal_roles("engine", "engine:vuln").empty());
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: assigning to a nonexistent engine "
          "principal returns 404",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());

    auto res = h.assign("no-such-principal", R"({"role":"EngineReader"})");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(h.rbac_store->get_principal_roles("engine", "engine:no-such-principal").empty());
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: assigning to a revoked engine "
          "principal returns 404 (terminal, not a transient outage)",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    auto revoked = h.engine_store->revoke("engine:vuln");
    REQUIRE(revoked.has_value());
    REQUIRE(*revoked);

    auto res = h.assign("vuln", R"({"role":"EngineReader"})");
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("REST /api/v1/engine-principals/{id}/roles: unauthenticated session cannot assign "
          "(auth_fn gate runs before the store write)",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    h.auth_enabled = false;

    auto res = h.assign("vuln", R"({"role":"EngineReader"})");
    REQUIRE(res);
    // The route's auth_fn gate (after perm_fn, before the store write) returns
    // std::nullopt and the handler returns without ever calling assign_role —
    // no grant lands, no audit row fires, regardless of the exact status code
    // the (mocked) auth_fn chose to set.
    CHECK(h.rbac_store->get_principal_roles("engine", "engine:vuln").empty());
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: a non-admin/engine session without "
          "Security:Write is denied",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    h.session_user = "bob";
    h.session_role = auth::Role::user;
    h.perm_override = [](const std::string& type, const std::string& op) {
        return !(type == "Security" && op == "Write"); // deny only Security:Write
    };

    auto res = h.assign("vuln", R"({"role":"EngineReader"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.rbac_store->get_principal_roles("engine", "engine:vuln").empty());
    CHECK(h.audit_log.empty()); // the route's own audit never fires — perm_fn gated first
}

TEST_CASE("REST POST /api/v1/engine-principals/{id}/roles: missing role field rejected 400",
          "[pg][rest][engine_principal][rbac]") {
    RestEngineRolesHarness h;
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    auto res = h.assign("vuln", R"({})");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ═══════════════════════════════════════════════════════════════════════════
// #2466/#2406: a role assign/unassign whose audit write drops FAILS CLOSED
// (503 + Sec-Audit-Failed) — never success on an unrecorded grant mutation
// (ADR-1005 "mutations fail closed on audit failure"). The read (GET roles)
// PROCEEDS but sets the header. Driven by RestEngineRolesHarness::audit_allow.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("REST engine-principal roles: assign fails CLOSED (503 + Sec-Audit-Failed) "
          "when its audit write drops",
          "[pg][rest][engine_principal][rbac][audit_failclose]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store->set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    h.audit_allow = false;
    auto res = h.assign("vuln", R"({"role":"EngineReader"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // The grant itself committed before the audit (fail-closed is about the
    // RESPONSE, not a rollback) — the operator reconciles on the 503.
    CHECK(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));
}

TEST_CASE("REST engine-principal roles: unassign fails CLOSED (503 + Sec-Audit-Failed) "
          "when its audit write drops",
          "[pg][rest][engine_principal][rbac][audit_failclose]") {
    RestEngineRolesHarness h;
    REQUIRE(h.rbac_store->create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(
        h.rbac_store->set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());
    REQUIRE(h.assign("vuln", R"({"role":"EngineReader"})")->status == 201);

    // Precondition: the grant is live before the fail-closed unassign.
    REQUIRE(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));

    h.audit_allow = false;
    auto res = h.unassign("vuln", "EngineReader");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // Attribution (qe-SHOULD-2, parity with the assign case): the unassign
    // COMMITTED — the grant is gone — though its audit dropped; the 503 is the
    // audit failure, not a failed mutation.
    CHECK_FALSE(h.rbac_store->check_permission("engine:vuln", "Inventory", "Read"));
}

TEST_CASE("REST engine-principal roles: GET roles (read) PROCEEDS 200 but sets "
          "Sec-Audit-Failed when its audit write drops",
          "[pg][rest][engine_principal][rbac][audit_failclose]") {
    RestEngineRolesHarness h;
    REQUIRE(h.engine_store->create("Vuln Sync", "alice", "j", "internal", "admin", "engine:vuln")
               .has_value());

    h.audit_allow = false;
    auto res = h.get_roles("vuln");
    REQUIRE(res);
    CHECK(res->status == 200); // data still served
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
}
