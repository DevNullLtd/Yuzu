/**
 * test_patch_manager.cpp — Unit tests for PatchManager (Postgres-backed,
 * ADR-0006/0009/0062 migration, schema `patch_manager`).
 *
 * Covers: create/get deployment, DeploymentRequest struct, reboot_delay
 *         clamping, kb_id validation, cancel_deployment, list_deployments.
 *
 * execute_deployment (reboot orchestration: Windows/Linux/unknown-OS,
 * notification-failure-is-non-fatal — 4 cases) was REMOVED along with the
 * code it tested (zero production callers on dev — see ADR-0062 "Deleted:
 * execute_deployment"), not ported.
 */

#include "patch_manager.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <stdexcept>
#include <string>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7). Every
// store-behaviour case clones this instead of re-migrating per test.
yuzu::test::PgTestTemplate patch_mgr_tpl{"patchmgr", [](const std::string& dsn) {
                                            PgPool pool{{.conninfo = dsn, .size = 1}};
                                            PatchManager mgr{pool};
                                            if (!mgr.is_open())
                                                throw std::runtime_error(
                                                    "patch_manager template: store failed to migrate");
                                        }};

} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open PatchManager.
// Expands to statements (includes the SKIP-if-no-DSN guard), so it must
// lead a block. The db/pool must outlive `mgr_var`; declaring all three
// here keeps that order.
#define PATCH_MANAGER(mgr_var)                                                                    \
    YUZU_REQUIRE_PG_DB_TPL(patch_db_fx_, patch_mgr_tpl);                                          \
    PgPool patch_pool_fx_{{.conninfo = patch_db_fx_.dsn(), .size = 4}};                           \
    REQUIRE(patch_pool_fx_.valid());                                                              \
    PatchManager mgr_var{patch_pool_fx_};                                                          \
    REQUIRE(mgr_var.is_open())

// ── Test: create and get deployment ─────────────────────────────────────────

TEST_CASE("PatchManager: create and get deployment", "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    auto result = mgr.deploy_patch("KB1234567", {"agent-1", "agent-2"}, false, "admin");
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto depl = mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->id == *result);
    CHECK(depl->kb_id == "KB1234567");
    CHECK(depl->status == "pending");
    CHECK(depl->total_targets == 2);
    CHECK(depl->created_by == "admin");
    CHECK(depl->reboot_if_needed == false);
    CHECK(depl->created_at > 0);
    CHECK(depl->targets.size() == 2);
}

// ── Test: deploy_patch with DeploymentRequest ───────────────────────────────

TEST_CASE("PatchManager: deploy_patch with DeploymentRequest", "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    DeploymentRequest req;
    req.kb_id = "KB5034441";
    req.agent_ids = {"agent-1"};
    req.reboot_if_needed = true;
    req.created_by = "operator";
    req.reboot_delay_seconds = 600;
    req.reboot_at = 1700000000;

    auto result = mgr.deploy_patch(req);
    REQUIRE(result.has_value());

    auto depl = mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->kb_id == "KB5034441");
    CHECK(depl->reboot_if_needed == true);
    CHECK(depl->reboot_delay_seconds == 600);
    CHECK(depl->reboot_at == 1700000000);
    CHECK(depl->created_by == "operator");
}

// ── Test: reboot_delay_seconds clamped ──────────────────────────────────────

TEST_CASE("PatchManager: reboot_delay_seconds clamped", "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    SECTION("too small is clamped to 60") {
        auto result = mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 10);
        REQUIRE(result.has_value());

        auto depl = mgr.get_deployment(*result);
        REQUIRE(depl.has_value());
        CHECK(depl->reboot_delay_seconds == 60);
    }

    SECTION("too large is clamped to 86400") {
        auto result = mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 100000);
        REQUIRE(result.has_value());

        auto depl = mgr.get_deployment(*result);
        REQUIRE(depl.has_value());
        CHECK(depl->reboot_delay_seconds == 86400);
    }
}

// ── Test: kb_id validation ──────────────────────────────────────────────────

TEST_CASE("PatchManager: kb_id validation", "[patch_manager][pg][validation]") {
    PATCH_MANAGER(mgr);

    SECTION("empty kb_id") {
        auto result = mgr.deploy_patch("", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("invalid prefix") {
        auto result = mgr.deploy_patch("NOTAKB", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("too few digits") {
        auto result = mgr.deploy_patch("KB123", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("valid kb_id succeeds") {
        auto result = mgr.deploy_patch("KB1234567", {"agent-1"}, false, "admin");
        CHECK(result.has_value());
    }
}

// ── Test: cancel_deployment covers rebooting ────────────────────────────────

TEST_CASE("PatchManager: cancel_deployment covers rebooting", "[patch_manager][pg][cancel]") {
    PATCH_MANAGER(mgr);

    auto deploy_result = mgr.deploy_patch("KB1234567", {"agent-1", "agent-2"}, true, "admin");
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    // Manually set agent-1 to "rebooting" status
    mgr.update_target_status(deployment_id, "agent-1", "rebooting");

    auto cancel_result = mgr.cancel_deployment(deployment_id);
    REQUIRE(cancel_result.has_value());

    auto depl = mgr.get_deployment(deployment_id);
    REQUIRE(depl.has_value());
    CHECK(depl->status == "cancelled");

    // Both targets should now be cancelled (rebooting + pending are both in the cancel set).
    // REQUIRE the count first — quality-engineer governance finding: a
    // loop-only assertion with no size check passes vacuously if the
    // target sub-query ever silently returns an empty vector.
    REQUIRE(depl->targets.size() == 2);
    for (const auto& t : depl->targets) {
        CHECK(t.status == "cancelled");
    }
}

// New coverage (governance Gate 8 quality-engineer finding): cancel_deployment's
// two guard branches were only reachable via the happy path above, never
// exercised directly.

TEST_CASE("PatchManager: cancel_deployment rejects an unknown id", "[patch_manager][pg][cancel]") {
    PATCH_MANAGER(mgr);

    auto result = mgr.cancel_deployment("no-such-deployment-id");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == "deployment not found");
}

TEST_CASE("PatchManager: cancel_deployment rejects a double-cancel", "[patch_manager][pg][cancel]") {
    PATCH_MANAGER(mgr);

    auto deploy_result = mgr.deploy_patch("KB1234567", {"agent-1"}, false, "admin");
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    REQUIRE(mgr.cancel_deployment(deployment_id).has_value());

    auto second = mgr.cancel_deployment(deployment_id);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == "deployment already cancelled");
}

// ── Test: list_deployments ──────────────────────────────────────────────────

TEST_CASE("PatchManager: list_deployments", "[patch_manager][pg][query]") {
    PATCH_MANAGER(mgr);

    mgr.deploy_patch("KB1111111", {"agent-1"}, false, "admin");
    mgr.deploy_patch("KB2222222", {"agent-1"}, false, "admin");
    mgr.deploy_patch("KB3333333", {"agent-1"}, false, "admin");

    auto all = mgr.list_deployments(50);
    REQUIRE(all.size() == 3);

    auto limited = mgr.list_deployments(2);
    REQUIRE(limited.size() == 2);
}

// ── Test: deploy_patch de-duplicates caller-supplied agent_ids ─────────────
// New coverage (ADR-0062): the SQLite era silently under-counted a duplicate
// agent_id's target row (unchecked sqlite3_step, total_targets set from the
// raw list size) — this store now de-dupes up front so total_targets always
// matches the actual number of target rows created.

TEST_CASE("PatchManager: deploy_patch de-duplicates agent_ids", "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    auto result = mgr.deploy_patch("KB1234567", {"agent-1", "agent-2", "agent-1"}, false, "admin");
    REQUIRE(result.has_value());

    auto depl = mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->total_targets == 2);
    CHECK(depl->targets.size() == 2);
}

// ── Test: deploy_patch rejects an oversized agent_ids list ─────────────────
// New coverage (governance sre finding, closed 2026-08-30): an unbounded
// agent_ids list would hold the shared pool connection for the duration of
// a near-fleet-wide unnest() batch insert, contributing to pool starvation
// for unrelated stores. deploy_patch now rejects a list over kMaxDeployTargets
// (5000) before touching the database.

TEST_CASE("PatchManager: deploy_patch rejects an oversized agent_ids list",
          "[patch_manager][pg][deploy][validation]") {
    PATCH_MANAGER(mgr);
    yuzu::MetricsRegistry metrics;
    mgr.set_metrics(&metrics);

    std::vector<std::string> agent_ids;
    agent_ids.reserve(5001);
    for (int i = 0; i < 5001; ++i)
        agent_ids.push_back("agent-" + std::to_string(i));

    auto result = mgr.deploy_patch("KB1234567", agent_ids, false, "admin");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("too many target agents") != std::string::npos);
    CHECK(metrics.serialize().find(
              "yuzu_server_patch_manager_writes_total{op=\"deploy_patch\","
              "result=\"rejected_oversized\"} 1") != std::string::npos);
}

// ── Test: record_patches upserts inventory ──────────────────────────────────
// New coverage (ADR-0062): record_patches's batch upsert (unnest()-driven
// INSERT ... ON CONFLICT DO UPDATE, replacing the SQLite-era per-row
// prepared-statement loop) — insert then overwrite the same (agent_id,
// kb_id) pair and confirm the update landed, plus a fleet-summary/
// missing-vs-installed filter sanity check.

TEST_CASE("PatchManager: record_patches upserts and queries", "[patch_manager][pg][inventory]") {
    PATCH_MANAGER(mgr);

    mgr.record_patches("agent-1", {
        {.kb_id = "KB1111111", .title = "Update A", .severity = "Critical",
         .status = "missing", .agent_id = "agent-1", .released_at = 100},
        {.kb_id = "KB2222222", .title = "Update B", .severity = "Important",
         .status = "installed", .agent_id = "agent-1", .released_at = 200},
    });

    auto missing = mgr.get_missing_patches({.agent_id = "agent-1"});
    REQUIRE(missing.size() == 1);
    CHECK(missing[0].kb_id == "KB1111111");
    CHECK(missing[0].severity == "Critical");

    auto installed = mgr.get_installed_patches({.agent_id = "agent-1"});
    REQUIRE(installed.size() == 1);
    CHECK(installed[0].kb_id == "KB2222222");

    // Re-report KB1111111 as installed — ON CONFLICT DO UPDATE must overwrite
    // the row rather than duplicate it.
    mgr.record_patches("agent-1", {
        {.kb_id = "KB1111111", .title = "Update A", .severity = "Critical",
         .status = "installed", .agent_id = "agent-1", .released_at = 100},
    });
    CHECK(mgr.get_missing_patches({.agent_id = "agent-1"}).empty());
    CHECK(mgr.get_installed_patches({.agent_id = "agent-1"}).size() == 2);

    auto summary = mgr.get_fleet_patch_summary(10);
    CHECK(summary.empty()); // nothing missing anymore
}

// New coverage (governance Gate 3 quality-engineer finding): the rewritten
// GROUP BY/ORDER BY/LIMIT query had only ever been exercised by
// `summary.empty()` — this exercises real grouping, descending-count
// ordering, and LIMIT truncation across multiple kb_ids/agents.
TEST_CASE("PatchManager: get_fleet_patch_summary groups, orders, and truncates",
          "[patch_manager][pg][inventory]") {
    PATCH_MANAGER(mgr);

    // KB1111111 missing on 3 agents, KB2222222 on 2, KB3333333 on 1.
    mgr.record_patches("agent-1", {
        {.kb_id = "KB1111111", .status = "missing"},
        {.kb_id = "KB2222222", .status = "missing"},
        {.kb_id = "KB3333333", .status = "missing"},
    });
    mgr.record_patches("agent-2", {
        {.kb_id = "KB1111111", .status = "missing"},
        {.kb_id = "KB2222222", .status = "missing"},
    });
    mgr.record_patches("agent-3", {
        {.kb_id = "KB1111111", .status = "missing"},
    });

    auto summary = mgr.get_fleet_patch_summary(50);
    REQUIRE(summary.size() == 3);
    CHECK(summary[0] == std::pair<std::string, int>{"KB1111111", 3});
    CHECK(summary[1] == std::pair<std::string, int>{"KB2222222", 2});
    CHECK(summary[2] == std::pair<std::string, int>{"KB3333333", 1});

    auto limited = mgr.get_fleet_patch_summary(2);
    REQUIRE(limited.size() == 2);
    CHECK(limited[0].first == "KB1111111");
    CHECK(limited[1].first == "KB2222222");
}

// New coverage (governance Gate 3 quality-engineer finding): deploy_patch's
// same-transaction title-enrichment read was never asserted, either found
// or not-found.
TEST_CASE("PatchManager: deploy_patch enriches title from inventory when present",
          "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    mgr.record_patches("agent-1", {
        {.kb_id = "KB1234567", .title = "Security Update for Widgets", .status = "missing"},
    });

    auto result = mgr.deploy_patch("KB1234567", {"agent-1"}, false, "admin");
    REQUIRE(result.has_value());
    auto depl = mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->title == "Security Update for Widgets");
}

TEST_CASE("PatchManager: deploy_patch leaves title empty when kb_id is not in inventory",
          "[patch_manager][pg][deploy]") {
    PATCH_MANAGER(mgr);

    auto result = mgr.deploy_patch("KB9999999", {"agent-1"}, false, "admin");
    REQUIRE(result.has_value());
    auto depl = mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->title.empty());
}

// Regression test (governance Gate 2, empirically reproduced): a single
// record_patches() call whose `patches` vector repeats a kb_id used to fail
// the WHOLE batch — Postgres refuses to let one INSERT ... ON CONFLICT DO
// UPDATE affect the same conflict target twice ("command cannot affect row
// a second time"), which would otherwise silently stall an agent's entire
// inventory report on any scan carrying a duplicate kb_id. Last occurrence
// in the vector must win (matches the SQLite-era per-row INSERT OR REPLACE
// semantics).
TEST_CASE("PatchManager: record_patches de-duplicates a repeated kb_id in one call",
          "[patch_manager][pg][inventory]") {
    PATCH_MANAGER(mgr);

    mgr.record_patches("agent-1", {
        {.kb_id = "KB1111111", .title = "stale title", .severity = "Low",
         .status = "missing", .agent_id = "agent-1", .released_at = 100},
        {.kb_id = "KB1111111", .title = "current title", .severity = "Critical",
         .status = "installed", .agent_id = "agent-1", .released_at = 100},
    });

    // The whole call must succeed (not silently no-op), and the LAST entry
    // for the duplicated kb_id must be the one that landed.
    CHECK(mgr.get_missing_patches({.agent_id = "agent-1"}).empty());
    auto installed = mgr.get_installed_patches({.agent_id = "agent-1"});
    REQUIRE(installed.size() == 1);
    CHECK(installed[0].title == "current title");
    CHECK(installed[0].severity == "Critical");
}

// gov fjarvis B1 precedent (test_offline_endpoint_store.cpp): a reachable
// database whose schema migration FAILS must leave the store !is_open() —
// which server.cpp wires to startup_failed_ (fail closed, not
// serve-degraded; a posture upgrade from the SQLite era, where construction
// was unconditional/best-effort). Force the failure by pre-seeding a table
// in the store's schema with no schema_meta row: the migration runner's
// schema-drift guard refuses (version 0 but tables exist), so run() returns
// false. deploy_patch/cancel_deployment on the resulting closed store must
// return their existing not-available std::expected error, never crash or
// silently no-op.
TEST_CASE("PatchManager reports !is_open on a migration failure and degrades writes",
          "[patch_manager][pg]") {
    YUZU_REQUIRE_PG_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA patch_manager")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE patch_manager.bogus (x int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    PatchManager mgr{pool};
    CHECK_FALSE(mgr.is_open()); // → server.cpp sets startup_failed_ = true

    auto deploy_result = mgr.deploy_patch("KB1234567", {"agent-1"}, false, "admin");
    REQUIRE_FALSE(deploy_result.has_value());
    CHECK(deploy_result.error() == "patch manager not available");

    CHECK(mgr.get_missing_patches().empty());
    CHECK(mgr.list_deployments().empty());
    CHECK_FALSE(mgr.get_deployment("anything").has_value());
}
