/**
 * test_software_deployment_store.cpp — `SoftwareDeploymentStore` (capability
 * 7.6 — software packaging + fleet deployment catalog).
 *
 * Covers: fail-closed construction (migration drift + unreachable pool),
 * package CRUD (incl. the enforced-FK delete-block), deployment lifecycle
 * (create/start/cancel/rollback, guarded transitions), agent status +
 * refresh_counts + active_count, list filters, and a full end-to-end
 * lifecycle.
 *
 * Born-on-Postgres migrated store (ADR-0012 §1, authoritative/fail-hard).
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but
 * broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases use
 * the pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md
 * step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no gate at
 * all, per the plain-migration-test carve-out documented on that macro.
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite
 * TEST_CASE suite was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) -- no production fleet has ever run a
 * pre-Postgres build. SoftwareDeploymentStore::migrate_from_sqlite() itself
 * was retired (chore/retire-migrate-from-sqlite-batch-b, #3623) -- this
 * store had zero production callers to begin with, so there was no live
 * database to protect either way.
 */

#include "software_deployment_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AgentDeploymentStatus;
using yuzu::server::SoftwareDeployment;
using yuzu::server::SoftwareDeploymentStore;
using yuzu::server::SoftwarePackage;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate sw_deploy_store_tpl{
    "swdeploystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        SoftwareDeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("software_deployment_store template: failed to migrate");
    }};

SoftwarePackage make_package(const std::string& name = "Firefox",
                             const std::string& version = "125.0",
                             const std::string& platform = "windows") {
    SoftwarePackage pkg;
    pkg.name = name;
    pkg.version = version;
    pkg.platform = platform;
    pkg.installer_type = "msi";
    pkg.content_hash = "abc123def456";
    pkg.content_url = "https://content.example.com/firefox-125.msi";
    pkg.silent_args = "/qn /norestart";
    pkg.verify_command = "reg query HKLM\\Software\\Mozilla";
    pkg.rollback_command = "msiexec /x {id} /qn";
    pkg.size_bytes = 85000000;
    pkg.created_by = "admin";
    return pkg;
}

SoftwareDeployment make_deployment(const std::string& package_id,
                                   const std::string& scope = "ostype = 'windows'",
                                   int agents_targeted = 5) {
    SoftwareDeployment dep;
    dep.package_id = package_id;
    dep.scope_expression = scope;
    dep.agents_targeted = agents_targeted;
    dep.created_by = "admin";
    return dep;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore reports !is_open on a migration failure",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA software_deployment_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(
            conn.get(), "CREATE TABLE software_deployment_store.software_packages (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    SoftwareDeploymentStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("SoftwareDeploymentStore reports !is_open on an unreachable pool, and every method "
          "fails closed",
          "[software_deployment]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    SoftwareDeploymentStore store{pool};
    CHECK_FALSE(store.is_open());

    auto create_pkg = store.create_package(make_package());
    CHECK_FALSE(create_pkg.has_value());
    CHECK(create_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto list_pkg = store.list_packages();
    CHECK_FALSE(list_pkg.has_value());
    CHECK(list_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto get_pkg = store.get_package("x");
    CHECK_FALSE(get_pkg.has_value());
    CHECK(get_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto del_pkg = store.delete_package("x");
    CHECK_FALSE(del_pkg.has_value());
    CHECK(del_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto create_dep = store.create_deployment(make_deployment("pkg-x"));
    CHECK_FALSE(create_dep.has_value());
    CHECK(create_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto list_dep = store.list_deployments();
    CHECK_FALSE(list_dep.has_value());
    CHECK(list_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto get_dep = store.get_deployment("x");
    CHECK_FALSE(get_dep.has_value());
    CHECK(get_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto start = store.start_deployment("x");
    CHECK_FALSE(start.has_value());
    CHECK(start.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto cancel = store.cancel_deployment("x");
    CHECK_FALSE(cancel.has_value());
    CHECK(cancel.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto rollback = store.rollback_deployment("x");
    CHECK_FALSE(rollback.has_value());
    CHECK(rollback.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "pending";
    auto upd = store.update_agent_status("x", s);
    CHECK_FALSE(upd.has_value());
    CHECK(upd.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto refresh = store.refresh_counts("x");
    CHECK_FALSE(refresh.has_value());
    CHECK(refresh.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto statuses = store.get_agent_statuses("x");
    CHECK_FALSE(statuses.has_value());
    CHECK(statuses.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto active = store.active_count();
    CHECK_FALSE(active.has_value());
    CHECK(active.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

// ── Package CRUD ─────────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: create package and get", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_package(make_package());
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto pkg = store.get_package(*result);
    REQUIRE(pkg.has_value());
    REQUIRE(pkg->has_value());
    CHECK((*pkg)->id == *result);
    CHECK((*pkg)->name == "Firefox");
    CHECK((*pkg)->version == "125.0");
    CHECK((*pkg)->platform == "windows");
    CHECK((*pkg)->installer_type == "msi");
    CHECK((*pkg)->content_hash == "abc123def456");
    CHECK((*pkg)->silent_args == "/qn /norestart");
    CHECK((*pkg)->size_bytes == 85000000);
    CHECK((*pkg)->created_at > 0);
    CHECK((*pkg)->created_by == "admin");
}

TEST_CASE("SoftwareDeploymentStore: list packages", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_package(make_package("Firefox", "125.0")).has_value());
    REQUIRE(store.create_package(make_package("Chrome", "124.0")).has_value());
    REQUIRE(store.create_package(make_package("VSCode", "1.89")).has_value());

    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->size() == 3);
}

TEST_CASE("SoftwareDeploymentStore: delete package", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto id = store.create_package(make_package());
    REQUIRE(id.has_value());

    CHECK(store.delete_package(*id).has_value());

    auto pkg = store.get_package(*id);
    REQUIRE(pkg.has_value());
    CHECK_FALSE(pkg->has_value());

    auto list = store.list_packages();
    REQUIRE(list.has_value());
    CHECK(list->empty());
}

TEST_CASE("SoftwareDeploymentStore: delete nonexistent package fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.delete_package("nonexistent-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "package not found");
}

// Postgres enforces the software_deployments.package_id FK (the
// pre-migration SQLite store never did) — deleting a package a live
// deployment references must fail, not silently orphan the deployment.
TEST_CASE("SoftwareDeploymentStore: delete package referenced by a deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    REQUIRE(store.create_deployment(make_deployment(*pkg_id)).has_value());

    auto r = store.delete_package(*pkg_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("referenced") != std::string::npos);
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    // The package must survive the rejected delete.
    auto pkg = store.get_package(*pkg_id);
    REQUIRE(pkg.has_value());
    CHECK(pkg->has_value());
}

TEST_CASE("SoftwareDeploymentStore: create package empty name fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg = make_package();
    pkg.name = "";
    auto result = store.create_package(pkg);
    CHECK_FALSE(result.has_value());
    CHECK_FALSE(result.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

// ── Deployment lifecycle ─────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: create deployment has staged status",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "staged");
    CHECK((*dep)->package_id == *pkg_id);
    CHECK((*dep)->agents_targeted == 5);
    CHECK((*dep)->created_at > 0);
    CHECK((*dep)->started_at == 0);
}

TEST_CASE("SoftwareDeploymentStore: create deployment with nonexistent package_id fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_deployment(make_deployment("no-such-package"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "package_id does not exist");
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

TEST_CASE("SoftwareDeploymentStore: start deployment staged to deploying",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    CHECK(store.start_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "deploying");
    CHECK((*dep)->started_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: start non-staged deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    auto r = store.start_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment is not staged");
}

TEST_CASE("SoftwareDeploymentStore: start unknown deployment is not_found",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.start_deployment("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment not found");
}

TEST_CASE("SoftwareDeploymentStore: cancel from staged", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    CHECK(store.cancel_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "cancelled");
    CHECK((*dep)->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: cancel from deploying", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    CHECK(store.cancel_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "cancelled");
}

TEST_CASE("SoftwareDeploymentStore: cancel an already-cancelled deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.cancel_deployment(*dep_id).has_value());

    auto r = store.cancel_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only staged or deploying deployments can be cancelled");
}

TEST_CASE("SoftwareDeploymentStore: rollback deployment", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    CHECK(store.rollback_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "rolled_back");
    CHECK((*dep)->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: rollback staged fails", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    auto r = store.rollback_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only deploying, verifying, or completed deployments can be rolled back");
}

// ── Agent status & refresh counts ───────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: update agent status", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 1000;
    s1.completed_at = 1010;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 1);
    CHECK((*statuses)[0].agent_id == "agent-1");
    CHECK((*statuses)[0].status == "success");
    CHECK((*statuses)[0].started_at == 1000);
    CHECK((*statuses)[0].completed_at == 1010);
}

TEST_CASE("SoftwareDeploymentStore: update agent status rejects an unrecognised status",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "sideways";
    auto r = store.update_agent_status(*dep_id, s);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "invalid status");
}

TEST_CASE("SoftwareDeploymentStore: update agent status on nonexistent deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "pending";
    auto r = store.update_agent_status("no-such-deployment", s);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment_id does not exist");
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

TEST_CASE("SoftwareDeploymentStore: refresh counts", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());
    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    REQUIRE(store.update_agent_status(*dep_id, s2).has_value());
    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "download timeout";
    REQUIRE(store.update_agent_status(*dep_id, s3).has_value());

    REQUIRE(store.refresh_counts(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->agents_success == 2);
    CHECK((*dep)->agents_failure == 1);
}

TEST_CASE("SoftwareDeploymentStore: refresh counts on unknown deployment is not_found",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.refresh_counts("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment not found");
}

TEST_CASE("SoftwareDeploymentStore: get agent statuses returns all agents",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    for (int i = 1; i <= 5; ++i) {
        AgentDeploymentStatus s;
        s.agent_id = "agent-" + std::to_string(i);
        s.status = (i <= 3) ? "success" : "failed";
        REQUIRE(store.update_agent_status(*dep_id, s).has_value());
    }

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    CHECK(statuses->size() == 5);
}

// ── Active count ─────────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: active count", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());
    auto ac0 = store.active_count();
    REQUIRE(ac0.has_value());
    CHECK(*ac0 == 0);

    REQUIRE(store.start_deployment(*dep1).has_value());
    auto ac1 = store.active_count();
    REQUIRE(ac1.has_value());
    CHECK(*ac1 == 1);

    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    REQUIRE(store.start_deployment(*dep2).has_value());
    auto ac2 = store.active_count();
    REQUIRE(ac2.has_value());
    CHECK(*ac2 == 2);

    REQUIRE(store.cancel_deployment(*dep1).has_value());
    auto ac3 = store.active_count();
    REQUIRE(ac3.has_value());
    CHECK(*ac3 == 1);
}

// ── List deployments ─────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: list deployments with status filter",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());
    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    REQUIRE(store.start_deployment(*dep2).has_value());

    auto all = store.list_deployments();
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);

    auto staged = store.list_deployments("staged");
    REQUIRE(staged.has_value());
    CHECK(staged->size() == 1);

    auto deploying = store.list_deployments("deploying");
    REQUIRE(deploying.has_value());
    CHECK(deploying->size() == 1);
}

// ── Full lifecycle ───────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: full lifecycle", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package("Firefox", "125.0", "windows"));
    REQUIRE(pkg_id.has_value());
    auto pkg = store.get_package(*pkg_id);
    REQUIRE(pkg.has_value());
    REQUIRE(pkg->has_value());
    CHECK((*pkg)->name == "Firefox");

    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "ostype = 'windows'", 3));
    REQUIRE(dep_id.has_value());
    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "staged");

    REQUIRE(store.start_deployment(*dep_id).has_value());
    auto ac = store.active_count();
    REQUIRE(ac.has_value());
    CHECK(*ac == 1);

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "deploying");
    CHECK((*dep)->started_at > 0);

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 100;
    s1.completed_at = 110;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    s2.started_at = 100;
    s2.completed_at = 115;
    REQUIRE(store.update_agent_status(*dep_id, s2).has_value());

    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "installer exit code 1603";
    s3.started_at = 100;
    s3.completed_at = 112;
    REQUIRE(store.update_agent_status(*dep_id, s3).has_value());

    REQUIRE(store.refresh_counts(*dep_id).has_value());

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->agents_success == 2);
    CHECK((*dep)->agents_failure == 1);

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    CHECK(statuses->size() == 3);

    bool found_failed = false;
    for (const auto& a : *statuses) {
        if (a.agent_id == "agent-3") {
            CHECK(a.status == "failed");
            CHECK(a.error == "installer exit code 1603");
            found_failed = true;
        }
    }
    CHECK(found_failed);
}

