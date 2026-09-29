/**
 * test_rest_api_t2.cpp -- Integration tests for T2 REST API data flows
 *
 * Tests the store methods as they would be called by the REST handlers,
 * validating the full data round-trip for each new endpoint:
 *   - ExecutionTracker statistics (GET /api/v1/execution-statistics)
 *   - InventoryEval evaluation  (POST /api/v1/inventory/evaluate)
 *   - DeviceTokenStore CRUD     (POST/GET/DELETE /api/v1/device-tokens)
 *   - SoftwareDeploymentStore   (software deployment endpoints)
 *   - LicenseStore              (POST/GET /api/v1/license)
 *   - Cross-store interactions
 */

#include "device_token_store.hpp"
#include "execution_tracker.hpp"
#include "inventory_eval.hpp"
#include "license_store.hpp"
#include "pg/pg_pool.hpp"
#include "software_deployment_store.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

// LicenseStore (ADR-0048), SoftwareDeploymentStore (ADR-0051),
// DeviceTokenStore (ADR-0052), and ExecutionTracker (ADR-0065) are all
// Postgres-backed. Mirrors test_deployment_store.cpp's PgTestTemplate
// declaration.
namespace {
yuzu::test::PgTestTemplate license_store_tpl{
    "licensestore_t2", [](const std::string& dsn) {
        pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        LicenseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("license_store template: store failed to migrate");
    }};

// Pre-migrated template — shares the "swdeploystore" key with
// test_software_deployment_store.cpp's own template (identical setup,
// replay-verified per docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate t2_sw_deploy_tpl{
    "swdeploystore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        SoftwareDeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("software_deployment_store template: failed to migrate");
    }};

// Shares the "devicetokenstore" key with test_device_token_store.cpp's and
// test_rest_api_tokens.cpp's own templates (identical setup, replay-verified
// per docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate t2_device_token_tpl{
    "devicetokenstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        DeviceTokenStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("device_token_store template: store failed to migrate");
    }};
} // namespace

static Execution make_execution(const std::string& definition_id = "def-001",
                                const std::string& scope = "ostype = 'windows'",
                                const std::string& dispatched_by = "admin",
                                int agents_targeted = 1) {
    Execution exec;
    exec.definition_id = definition_id;
    exec.scope_expression = scope;
    exec.dispatched_by = dispatched_by;
    exec.status = "running";
    exec.agents_targeted = agents_targeted;
    return exec;
}

// ============================================================================
// Execution Statistics flow (GET /api/v1/execution-statistics)
// ============================================================================

TEST_CASE("T2 REST: get_fleet_summary with multiple statuses",
          "[pg][rest_api_t2][execution_statistics]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Create executions with various statuses
    auto e1 = make_execution("def-001");
    e1.agents_targeted = 10;
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    auto e2 = make_execution("def-002");
    e2.agents_targeted = 5;
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());

    // Add agent statuses for e1: 7 success, 3 failure.
    // #872 — update_agent_status now chains refresh_counts internally; the
    // explicit refresh_counts() after the loop is duplicate work and
    // encoded the pre-UAT-2026-05-06 "decoupled mutator" contract that no
    // longer holds. Dropping it.
    for (int i = 0; i < 10; ++i) {
        AgentExecStatus as;
        as.agent_id = "agent-" + std::to_string(i);
        as.status = (i < 7) ? "success" : "failure";
        as.dispatched_at = 1000;
        as.completed_at = 1005;
        as.exit_code = (i < 7) ? 0 : 1;
        tracker.update_agent_status(*id1, as);
    }

    // Add agent statuses for e2: all success
    for (int i = 0; i < 5; ++i) {
        AgentExecStatus as;
        as.agent_id = "agent-" + std::to_string(10 + i);
        as.status = "success";
        as.dispatched_at = 2000;
        as.completed_at = 2003;
        as.exit_code = 0;
        tracker.update_agent_status(*id2, as);
    }

    auto summary = tracker.get_fleet_summary();
    CHECK(summary.total_executions >= 2);
    CHECK(summary.active_agents >= 0);
    CHECK(summary.overall_success_rate >= 0.0);
    CHECK(summary.overall_success_rate <= 100.0);
}

TEST_CASE("T2 REST: get_fleet_summary with zero executions returns zeroed fields",
          "[pg][rest_api_t2][execution_statistics]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto summary = tracker.get_fleet_summary();
    CHECK(summary.total_executions == 0);
    CHECK(summary.executions_today == 0);
    CHECK(summary.active_agents == 0);
    CHECK(summary.overall_success_rate == 0.0);
    CHECK(summary.avg_duration_seconds == 0.0);
}

TEST_CASE("T2 REST: get_agent_statistics with pagination (limit=5)",
          "[pg][rest_api_t2][execution_statistics]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Create a single execution targeting 8 agents
    auto exec = make_execution();
    exec.agents_targeted = 8;
    auto id = tracker.create_execution(exec);
    REQUIRE(id.has_value());

    for (int i = 0; i < 8; ++i) {
        AgentExecStatus as;
        as.agent_id = "agent-" + std::to_string(i);
        as.status = (i % 3 == 0) ? "failure" : "success";
        as.dispatched_at = 1000;
        as.completed_at = 1000 + i + 1;
        as.exit_code = (i % 3 == 0) ? 1 : 0;
        tracker.update_agent_status(*id, as);
    }
    // #872 — refresh chained inside update_agent_status; explicit call dropped.

    ExecutionStatsQuery q;
    q.limit = 5;
    auto stats = tracker.get_agent_statistics(q);
    CHECK(stats.size() <= 5);
}

TEST_CASE("T2 REST: get_agent_statistics filters by agent_id",
          "[pg][rest_api_t2][execution_statistics]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    auto id = tracker.create_execution(exec);
    REQUIRE(id.has_value());

    AgentExecStatus s1;
    s1.agent_id = "target-agent";
    s1.status = "success";
    s1.dispatched_at = 1000;
    s1.completed_at = 1005;
    tracker.update_agent_status(*id, s1);

    AgentExecStatus s2;
    s2.agent_id = "other-agent";
    s2.status = "success";
    s2.dispatched_at = 1000;
    s2.completed_at = 1003;
    tracker.update_agent_status(*id, s2);

    ExecutionStatsQuery q;
    q.agent_id = "target-agent";
    auto stats = tracker.get_agent_statistics(q);
    // Should return only the target agent or be filtered
    for (auto& s : stats) {
        CHECK(s.agent_id == "target-agent");
    }
}

TEST_CASE("T2 REST: get_definition_statistics returns per-definition aggregates",
          "[pg][rest_api_t2][execution_statistics]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Two different definitions
    auto e1 = make_execution("def-alpha");
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    auto e2 = make_execution("def-beta");
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());

    // Add statuses and refresh counts to advance execution out of 'pending'
    // #872 — refresh chained inside update_agent_status; explicit calls dropped.
    AgentExecStatus as;
    as.agent_id = "a1";
    as.status = "success";
    as.exit_code = 0;
    as.dispatched_at = 1000;
    as.completed_at = 1010;
    tracker.update_agent_status(*id1, as);
    tracker.update_agent_status(*id2, as);

    auto def_stats = tracker.get_definition_statistics();
    CHECK(def_stats.size() >= 2);

    bool found_alpha = false, found_beta = false;
    for (auto& ds : def_stats) {
        if (ds.definition_id == "def-alpha")
            found_alpha = true;
        if (ds.definition_id == "def-beta")
            found_beta = true;
    }
    CHECK(found_alpha);
    CHECK(found_beta);
}

// ============================================================================
// Inventory Evaluation flow (POST /api/v1/inventory/evaluate)
// ============================================================================

using Records = std::vector<std::pair<std::string, std::string>>;

TEST_CASE("T2 REST: inventory eval with conditions matches correct agents",
          "[rest_api_t2][inventory_eval]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "ram_gb": 16, "cpu_cores": 8})"},
        {"agent-2|hardware", R"({"os": "Linux", "ram_gb": 32, "cpu_cores": 16})"},
        {"agent-3|hardware", R"({"os": "Windows", "ram_gb": 8, "cpu_cores": 4})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "==", "Windows"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 2);
    // Both Windows agents should match
    bool found_1 = false, found_3 = false;
    for (auto& r : results) {
        CHECK(r.match == true);
        CHECK(r.matched_value == "Windows");
        if (r.agent_id == "agent-1")
            found_1 = true;
        if (r.agent_id == "agent-3")
            found_3 = true;
    }
    CHECK(found_1);
    CHECK(found_3);
}

TEST_CASE("T2 REST: inventory eval combine 'any' vs 'all' produces different results",
          "[rest_api_t2][inventory_eval]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "ram_gb": 16})"},
        {"agent-1|software", R"({"browser": "Chrome"})"},
        {"agent-2|hardware", R"({"os": "Linux", "ram_gb": 32})"},
        {"agent-2|software", R"({"browser": "Firefox"})"},
    };

    // Conditions: hardware.os == "Windows" AND software.browser == "Firefox"
    // With "all": no agent has both
    InventoryEvalRequest req_all;
    req_all.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"software", "browser", "==", "Firefox"},
    };
    req_all.combine = "all";
    auto results_all = evaluate_inventory(req_all, records);

    // With "any": both agents match (agent-1 has Windows, agent-2 has Firefox)
    InventoryEvalRequest req_any;
    req_any.conditions = req_all.conditions;
    req_any.combine = "any";
    auto results_any = evaluate_inventory(req_any, records);

    CHECK(results_all.size() != results_any.size());
    CHECK(results_any.size() >= results_all.size());
}

TEST_CASE("T2 REST: inventory eval empty conditions returns all agents",
          "[rest_api_t2][inventory_eval]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows"})"},
        {"agent-2|hardware", R"({"os": "Linux"})"},
        {"agent-3|hardware", R"({"os": "Darwin"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    CHECK(results.size() == 3);
}

TEST_CASE("T2 REST: inventory eval with contains operator", "[rest_api_t2][inventory_eval]") {
    Records records = {
        {"agent-1|software", R"({"packages": "vim,git,curl"})"},
        {"agent-2|software", R"({"packages": "nano,wget"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "packages", "contains", "git"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

// ============================================================================
// Device Token flow (POST/GET/DELETE /api/v1/device-tokens)
// ============================================================================

TEST_CASE("T2 REST: device token create and validate round-trip",
          "[rest_api_t2][device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_device_token_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store(pool);
    REQUIRE(store.is_open());

    auto token_result = store.create_token("test-token", "admin", "device-001", "def-001", 0);
    REQUIRE(token_result.has_value());
    auto raw_token = *token_result;
    CHECK(!raw_token.empty());

    // Token is bound to device-001 — present matching agent_id (#824).
    auto validated = store.validate_token(raw_token, "device-001");
    REQUIRE(validated.has_value());
    CHECK(validated->name == "test-token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->device_id == "device-001");
    CHECK(validated->definition_id == "def-001");
    CHECK(validated->revoked == false);
}

TEST_CASE("T2 REST: device token list shows created tokens",
          "[rest_api_t2][device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_device_token_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store(pool);
    REQUIRE(store.is_open());

    REQUIRE(store.create_token("token-a", "admin", "", "", 0).has_value());
    REQUIRE(store.create_token("token-b", "admin", "", "", 0).has_value());
    REQUIRE(store.create_token("token-c", "user1", "", "", 0).has_value());

    auto all = store.list_tokens();
    REQUIRE(all.has_value());
    CHECK(all->size() == 3);

    auto admin_only = store.list_tokens("admin");
    REQUIRE(admin_only.has_value());
    CHECK(admin_only->size() == 2);
}

TEST_CASE("T2 REST: device token revoke invalidates validation",
          "[rest_api_t2][device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_device_token_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store(pool);
    REQUIRE(store.is_open());

    // Bind to an explicit device — empty device_id tokens are rejected as
    // unbound_legacy after W1.2 R2.
    auto token_result = store.create_token("revoke-me", "admin", "device-RV", "", 0);
    REQUIRE(token_result.has_value());
    auto raw_token = *token_result;

    // Validate before revoke succeeds (presenter matches stored device_id)
    auto pre_revoke = store.validate_token(raw_token, "device-RV");
    REQUIRE(pre_revoke.has_value());

    // Get the token_id from the list so we can revoke by id
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(!tokens->empty());
    auto revoked = store.revoke_token((*tokens)[0].token_id);
    CHECK(revoked.has_value());

    // Validate after revoke should fail
    auto post_revoke = store.validate_token(raw_token, "device-RV");
    REQUIRE(!post_revoke.has_value());
    // W1.3 (#1053): error() now returns RejectedToken — reach for `.error`.
    CHECK(post_revoke.error().error == DeviceTokenValidateError::revoked);
}

TEST_CASE("T2 REST: device token expired token fails validation",
          "[rest_api_t2][device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_device_token_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store(pool);
    REQUIRE(store.is_open());

    // Expires at epoch 1 (long past). Bind to a device so the failure is
    // purely "expired" — unbound_legacy precedes binding_mismatch but follows
    // expired, so a bound expired token still reports expired.
    auto result = store.create_token("expired", "admin", "device-E", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-E");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::expired);
}

// ============================================================================
// Software Deployment flow (software deployment endpoints)
// ============================================================================

TEST_CASE("T2 REST: create package and list packages",
          "[rest_api_t2][software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store(pool);
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.name = "Firefox";
    pkg.version = "125.0";
    pkg.platform = "windows";
    pkg.installer_type = "msi";
    pkg.content_hash = "abc123def456";
    pkg.content_url = "https://example.com/firefox.msi";
    pkg.silent_args = "/qn /norestart";
    pkg.created_by = "admin";

    auto id = store.create_package(pkg);
    REQUIRE(id.has_value());
    CHECK(!id->empty());

    auto packages = store.list_packages();
    REQUIRE(packages.has_value());
    REQUIRE(packages->size() == 1);
    CHECK((*packages)[0].name == "Firefox");
    CHECK((*packages)[0].version == "125.0");
    CHECK((*packages)[0].platform == "windows");
}

TEST_CASE("T2 REST: deployment lifecycle: create, start, status, refresh",
          "[rest_api_t2][software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store(pool);
    REQUIRE(store.is_open());

    // Create package first
    SoftwarePackage pkg;
    pkg.name = "TestApp";
    pkg.version = "1.0.0";
    pkg.platform = "linux";
    pkg.installer_type = "deb";
    pkg.content_hash = "deadbeef";
    pkg.content_url = "https://example.com/testapp.deb";
    pkg.created_by = "admin";

    auto pkg_id = store.create_package(pkg);
    REQUIRE(pkg_id.has_value());

    // Create deployment
    SoftwareDeployment dep;
    dep.package_id = *pkg_id;
    dep.scope_expression = "os = 'linux'";
    dep.created_by = "admin";
    dep.agents_targeted = 3;

    auto dep_id = store.create_deployment(dep);
    REQUIRE(dep_id.has_value());

    // Start deployment
    auto started = store.start_deployment(*dep_id);
    CHECK(started.has_value());

    auto fetched = store.get_deployment(*dep_id);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->status == "deploying");

    // Add agent statuses
    AgentDeploymentStatus s1;
    s1.deployment_id = *dep_id;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.completed_at = 2000;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    AgentDeploymentStatus s2;
    s2.deployment_id = *dep_id;
    s2.agent_id = "agent-2";
    s2.status = "success";
    s2.completed_at = 2001;
    REQUIRE(store.update_agent_status(*dep_id, s2).has_value());

    AgentDeploymentStatus s3;
    s3.deployment_id = *dep_id;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.completed_at = 2002;
    s3.error = "checksum mismatch";
    REQUIRE(store.update_agent_status(*dep_id, s3).has_value());

    // Refresh counts
    REQUIRE(store.refresh_counts(*dep_id).has_value());

    auto summary = store.get_deployment(*dep_id);
    REQUIRE(summary.has_value());
    REQUIRE(summary->has_value());
    CHECK((*summary)->agents_success == 2);
    CHECK((*summary)->agents_failure == 1);
}

TEST_CASE("T2 REST: deployment cancel stops active deployment",
          "[rest_api_t2][software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store(pool);
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.name = "CancelMe";
    pkg.version = "2.0.0";
    pkg.platform = "windows";
    pkg.installer_type = "msi";
    pkg.content_hash = "aabb";
    pkg.content_url = "https://example.com/cancel.msi";
    pkg.created_by = "admin";
    auto pkg_id = store.create_package(pkg);
    REQUIRE(pkg_id.has_value());

    SoftwareDeployment dep;
    dep.package_id = *pkg_id;
    dep.scope_expression = "all";
    dep.created_by = "admin";
    auto dep_id = store.create_deployment(dep);
    REQUIRE(dep_id.has_value());

    REQUIRE(store.start_deployment(*dep_id).has_value());
    auto cancelled = store.cancel_deployment(*dep_id);
    CHECK(cancelled.has_value());

    auto fetched = store.get_deployment(*dep_id);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->status == "cancelled");
}

TEST_CASE("T2 REST: deployment agent statuses are retrievable",
          "[rest_api_t2][software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store(pool);
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.name = "StatusApp";
    pkg.version = "1.0";
    pkg.platform = "darwin";
    pkg.installer_type = "pkg";
    pkg.content_hash = "ccdd";
    pkg.content_url = "https://example.com/status.pkg";
    pkg.created_by = "admin";
    auto pkg_id = store.create_package(pkg);
    REQUIRE(pkg_id.has_value());

    SoftwareDeployment dep;
    dep.package_id = *pkg_id;
    dep.scope_expression = "all";
    dep.created_by = "admin";
    auto dep_id = store.create_deployment(dep);
    REQUIRE(dep_id.has_value());

    REQUIRE(store.start_deployment(*dep_id).has_value());

    AgentDeploymentStatus s1;
    s1.deployment_id = *dep_id;
    s1.agent_id = "mac-1";
    s1.status = "downloading";
    s1.started_at = 3000;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 1);
    CHECK((*statuses)[0].agent_id == "mac-1");
    CHECK((*statuses)[0].status == "downloading");
}

TEST_CASE("T2 REST: active_count reflects running deployments",
          "[rest_api_t2][software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store(pool);
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.name = "ActiveApp";
    pkg.version = "1.0";
    pkg.platform = "linux";
    pkg.installer_type = "rpm";
    pkg.content_hash = "eeff";
    pkg.content_url = "https://example.com/active.rpm";
    pkg.created_by = "admin";
    auto pkg_id = store.create_package(pkg);
    REQUIRE(pkg_id.has_value());

    auto ac0 = store.active_count();
    REQUIRE(ac0.has_value());
    CHECK(*ac0 == 0);

    SoftwareDeployment dep;
    dep.package_id = *pkg_id;
    dep.scope_expression = "all";
    dep.created_by = "admin";
    auto dep_id = store.create_deployment(dep);
    REQUIRE(dep_id.has_value());

    REQUIRE(store.start_deployment(*dep_id).has_value());
    auto ac1 = store.active_count();
    REQUIRE(ac1.has_value());
    CHECK(*ac1 >= 1);
}

// ============================================================================
// License flow (POST/GET /api/v1/license)
// ============================================================================

TEST_CASE("T2 REST: license activate and get active", "[rest_api_t2][license][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "Acme Corp";
    lic.seat_count = 100;
    lic.edition = "enterprise";
    lic.features_json = R"(["sso","mfa","rbac"])";
    lic.status = "active";

    auto result = store.activate_license(lic, "LICENSE-KEY-12345");
    REQUIRE(result.has_value());

    auto active = store.get_active_license();
    REQUIRE(active.has_value());
    REQUIRE(active->has_value());
    CHECK((*active)->organization == "Acme Corp");
    CHECK((*active)->seat_count == 100);
    CHECK((*active)->edition == "enterprise");
}

TEST_CASE("T2 REST: license validate with agent count generates alerts on exceeded",
          "[rest_api_t2][license][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "SmallCo";
    lic.seat_count = 5;
    lic.edition = "professional";
    lic.features_json = "[]";
    lic.status = "active";

    auto result = store.activate_license(lic, "LICENSE-SMALL-001");
    REQUIRE(result.has_value());

    // Validate with more agents than seats
    auto validated = store.validate(10);
    REQUIRE(validated.has_value());

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    // Should have generated at least one alert about exceeded seats
    bool found_exceeded = false;
    for (auto& a : *alerts) {
        if (a.alert_type == "exceeded" || a.alert_type == "seat_limit_warning") {
            found_exceeded = true;
        }
    }
    CHECK(found_exceeded);
}

TEST_CASE("T2 REST: license feature check", "[rest_api_t2][license][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "FeatureCo";
    lic.seat_count = 50;
    lic.edition = "enterprise";
    lic.features_json = R"(["sso","advanced_policies","webhook_delivery"])";
    lic.status = "active";

    REQUIRE(store.activate_license(lic, "LICENSE-FEAT-001").has_value());

    auto sso = store.has_feature("sso");
    REQUIRE(sso.has_value());
    CHECK(*sso == true);
    auto adv = store.has_feature("advanced_policies");
    REQUIRE(adv.has_value());
    CHECK(*adv == true);
    auto none = store.has_feature("nonexistent_feature");
    REQUIRE(none.has_value());
    CHECK(*none == false);
}

TEST_CASE("T2 REST: license alert acknowledge", "[rest_api_t2][license][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "AlertCo";
    lic.seat_count = 2;
    lic.edition = "community";
    lic.features_json = "[]";
    lic.status = "active";

    REQUIRE(store.activate_license(lic, "LICENSE-ALERT-001").has_value());
    REQUIRE(store.validate(100).has_value()); // trigger alerts

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    if (!alerts->empty()) {
        auto ack_result = store.acknowledge_alert((*alerts)[0].id);
        CHECK(ack_result.has_value());

        auto unacked = store.list_alerts(true);
        REQUIRE(unacked.has_value());
        bool found_acked = false;
        for (auto& a : *unacked) {
            if (a.id == (*alerts)[0].id)
                found_acked = true;
        }
        CHECK(found_acked == false);
    }
}

TEST_CASE("T2 REST: license remove", "[rest_api_t2][license][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "RemoveCo";
    lic.seat_count = 10;
    lic.edition = "professional";
    lic.features_json = "[]";
    lic.status = "active";

    auto result = store.activate_license(lic, "LICENSE-REM-001");
    REQUIRE(result.has_value());

    auto removed = store.remove_license(*result);
    CHECK(removed.has_value());

    auto active = store.get_active_license();
    REQUIRE(active.has_value());
    CHECK(!active->has_value());
}

// ============================================================================
// Cross-store interactions
// ============================================================================

TEST_CASE("T2 REST: execution statistics work with concurrent agent updates",
          "[pg][rest_api_t2][cross_store]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Create two executions concurrently
    auto e1 = make_execution("def-cross-1");
    e1.agents_targeted = 3;
    auto id1 = tracker.create_execution(e1);
    REQUIRE(id1.has_value());

    auto e2 = make_execution("def-cross-2");
    e2.agents_targeted = 3;
    auto id2 = tracker.create_execution(e2);
    REQUIRE(id2.has_value());

    // Interleave agent status updates for both
    for (int i = 0; i < 3; ++i) {
        AgentExecStatus s1;
        s1.agent_id = "agent-" + std::to_string(i);
        s1.status = "success";
        s1.dispatched_at = 1000;
        s1.completed_at = 1005;
        tracker.update_agent_status(*id1, s1);

        AgentExecStatus s2;
        s2.agent_id = "agent-" + std::to_string(i);
        s2.status = (i < 2) ? "success" : "failure";
        s2.dispatched_at = 2000;
        s2.completed_at = 2005;
        s2.exit_code = (i < 2) ? 0 : 1;
        tracker.update_agent_status(*id2, s2);
    }
    // #872 — refresh chained inside update_agent_status; explicit calls dropped.

    // Fleet summary should reflect both executions
    auto fleet = tracker.get_fleet_summary();
    CHECK(fleet.total_executions >= 2);

    // Per-definition stats
    ExecutionStatsQuery q;
    q.definition_id = "def-cross-1";
    auto d1_stats = tracker.get_definition_statistics(q);
    bool found = false;
    for (auto& ds : d1_stats) {
        if (ds.definition_id == "def-cross-1") {
            found = true;
            CHECK(ds.total_executions >= 1);
        }
    }
    CHECK(found);
}

TEST_CASE("T2 REST: device tokens and software deployment independent stores",
          "[rest_api_t2][cross_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(token_db, t2_device_token_tpl);
    yuzu::server::pg::PgPool token_pool{{.conninfo = token_db.dsn(), .size = 4}};
    DeviceTokenStore token_store(token_pool);
    REQUIRE(token_store.is_open());

    YUZU_REQUIRE_PG_DB_TPL(db, t2_sw_deploy_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore deploy_store(pool);
    REQUIRE(deploy_store.is_open());

    // Create a device token
    auto token = token_store.create_token("deploy-token", "admin", "device-001", "", 0);
    REQUIRE(token.has_value());

    // Create a package and deployment
    SoftwarePackage pkg;
    pkg.name = "CrossTest";
    pkg.version = "1.0.0";
    pkg.platform = "linux";
    pkg.installer_type = "deb";
    pkg.content_hash = "xyzzy";
    pkg.content_url = "https://example.com/cross.deb";
    pkg.created_by = "admin";
    auto pkg_id = deploy_store.create_package(pkg);
    REQUIRE(pkg_id.has_value());

    SoftwareDeployment dep;
    dep.package_id = *pkg_id;
    dep.scope_expression = "device_id = 'device-001'";
    dep.created_by = "admin";
    auto dep_id = deploy_store.create_deployment(dep);
    REQUIRE(dep_id.has_value());

    // Both stores are functional and independent. Token is bound to
    // device-001 — present matching presenter to pass binding check (#824).
    auto validated = token_store.validate_token(*token, "device-001");
    CHECK(validated.has_value());
    auto deployment = deploy_store.get_deployment(*dep_id);
    REQUIRE(deployment.has_value());
    CHECK(deployment->has_value());
}

TEST_CASE("T2 REST: license store and execution tracker independent operation",
          "[rest_api_t2][cross_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore license_store{pool};
    REQUIRE(license_store.is_open());

    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Activate a license
    License lic;
    lic.organization = "CrossCo";
    lic.seat_count = 50;
    lic.edition = "enterprise";
    lic.features_json = R"(["unlimited_executions"])";
    lic.status = "active";
    auto lic_id = license_store.activate_license(lic, "CROSS-KEY-001");
    REQUIRE(lic_id.has_value());

    // Create an execution
    auto exec = make_execution("cross-def");
    auto exec_id = tracker.create_execution(exec);
    REQUIRE(exec_id.has_value());

    // Both stores maintain their data independently
    auto feat = license_store.has_feature("unlimited_executions");
    REQUIRE(feat.has_value());
    CHECK(*feat == true);
    auto seats = license_store.seat_count();
    REQUIRE(seats.has_value());
    CHECK(*seats == 50);

    auto fetched = tracker.get_execution(*exec_id);
    CHECK(fetched.has_value());
    CHECK(fetched->definition_id == "cross-def");
}
