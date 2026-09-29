/**
 * test_deployment_store.cpp — `DeploymentStore` (operator-initiated ad-hoc
 * deployment jobs: SSH / group-policy / manual agent installs, Issue 7.7).
 *
 * NOT a test for `DeploymentRunStore` (the `/auto` Deploy feature's
 * stage->execute state machine) — same English word, unrelated store; see
 * deployment_store.hpp's file header for the naming trap.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but
 *    unmigratable database) and the unreachable-pool case (mirrors
 *    test_access_review_store.cpp's two fail-closed cases).
 *  - create_job validation (target_host DNS-char/length, os, method).
 *  - list_jobs / get_job: typed reads — a genuine DB error is
 *    distinguishable from "no jobs"/"not found" (ADR-0036 program policy).
 *  - update_status: per-status timestamp stamping (started_at on 'running',
 *    completed_at on 'completed'/'failed'), invalid-status rejection,
 *    not-found rejection.
 *  - cancel_job: only pending/running jobs are cancellable; the guarded
 *    single-UPDATE shape distinguishes not-found from wrong-state.
 *
 * No legacy-SQLite backfill test coverage: the dedicated [backfill] TEST_CASE
 * suite (2026-08-25) was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) — no production fleet has ever run a
 * pre-Postgres build. DeploymentStore::migrate_from_sqlite() itself was
 * retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 *
 * Born-on-... migrated-to-Postgres store (ADR-0012 §1, authoritative/
 * fail-hard). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when set but broken (test_helpers.hpp skip-vs-fail contract).
 * Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test
 * carve-out documented on that macro.
 */

#include "deployment_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::DeploymentJob;
using yuzu::server::DeploymentStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate deployment_store_tpl{
    "deploystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        DeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("deployment_store template: store failed to migrate");
    }};

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DeploymentStore reports !is_open on a migration failure", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA deployment_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE deployment_store.deployment_jobs (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeploymentStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("DeploymentStore reports !is_open on an unreachable pool, and every method fails "
          "closed",
          "[deployment_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    DeploymentStore store{pool};
    CHECK_FALSE(store.is_open());

    // Every failure here is a genuine store-unavailable condition, never a
    // validation/not-found business error — each must carry
    // kDeploymentDbErrorPrefix so discovery_routes.cpp's classifier maps it
    // to 503, not 400/404. Locks the contract create_job/cancel_job's route
    // handlers depend on (gov quality-engineer finding #1): a future error
    // string that drops the prefix would silently regress a genuine outage
    // back to "bad request", with no test to catch it.
    auto create_res = store.create_job("host.example.com", "linux", "manual");
    CHECK_FALSE(create_res.has_value());
    CHECK(create_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto list_res = store.list_jobs();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto get_res = store.get_job("x");
    CHECK_FALSE(get_res.has_value());
    CHECK(get_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto update_res = store.update_status("x", "running");
    CHECK_FALSE(update_res.has_value());
    CHECK(update_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto cancel_res = store.cancel_job("x");
    CHECK_FALSE(cancel_res.has_value());
    CHECK(cancel_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));
}

// ── create_job validation ───────────────────────────────────────────────────

TEST_CASE("create_job validates target_host/os/method before writing", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    SECTION("empty target_host is rejected") {
        auto r = store.create_job("", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a shell-metacharacter host is rejected") {
        auto r = store.create_job("host;rm -rf /", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an over-length host is rejected") {
        auto r = store.create_job(std::string(254, 'a'), "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an SSH-option-injection-shaped leading-dash host is rejected") {
        // gov fjarvis MEDIUM — empirically these passed the char-allowlist
        // before the leading/trailing '-' check existed: real SSH option
        // shapes ("-oProxyCommand=...", "-Jjump.host", "-Ffile") a future
        // ssh-method executor could pass straight to a command line.
        auto r = store.create_job("-Jjump.evil.com", "linux", "ssh");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a trailing-dash host is rejected") {
        auto r = store.create_job("host.example.com-", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an unrecognised os is rejected") {
        auto r = store.create_job("host.example.com", "beos", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an unrecognised method is rejected") {
        auto r = store.create_job("host.example.com", "linux", "telepathy");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a valid job is created as pending") {
        auto r = store.create_job("host.example.com", "linux", "ssh");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->empty());

        auto job = store.get_job(*r);
        REQUIRE(job.has_value());
        REQUIRE(job->has_value());
        CHECK((*job)->target_host == "host.example.com");
        CHECK((*job)->os == "linux");
        CHECK((*job)->method == "ssh");
        CHECK((*job)->status == "pending");
        CHECK((*job)->created_at > 0);
        CHECK((*job)->started_at == 0);
        CHECK((*job)->completed_at == 0);
    }
}

// ── list_jobs / get_job — typed reads ───────────────────────────────────────

TEST_CASE("list_jobs: empty when no job has ever been created", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value()); // a genuine empty result, never unexpected
    CHECK(jobs->empty());
}

TEST_CASE("list_jobs: returns every job newest-first", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto a = store.create_job("a.example.com", "linux", "manual");
    auto b = store.create_job("b.example.com", "windows", "ssh");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    REQUIRE(jobs->size() == 2);
    // created_at DESC, ties possible within the same second — assert set
    // membership rather than a strict order that a fast test run could flake.
    std::vector<std::string> ids;
    for (const auto& j : *jobs)
        ids.push_back(j.id);
    CHECK(std::find(ids.begin(), ids.end(), *a) != ids.end());
    CHECK(std::find(ids.begin(), ids.end(), *b) != ids.end());
}

TEST_CASE("get_job: nullopt for an unknown id, distinct from a store failure",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto job = store.get_job("no-such-id");
    REQUIRE(job.has_value()); // a genuine successful read of zero rows
    CHECK_FALSE(job->has_value());
}

TEST_CASE("list_jobs/get_job report a genuine store failure as unexpected, never a silent "
          "empty/not-found",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE deployment_store.deployment_jobs CASCADE")};
        REQUIRE(d.ok());
    }

    auto jobs = store.list_jobs();
    CHECK_FALSE(jobs.has_value());
    CHECK(jobs.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto job = store.get_job(*created);
    CHECK_FALSE(job.has_value());
    CHECK(job.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));
}

// ── update_status ────────────────────────────────────────────────────────────

TEST_CASE("update_status rejects an unrecognised status", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    auto r = store.update_status(*created, "sideways");
    REQUIRE_FALSE(r.has_value());
}

TEST_CASE("update_status on an unknown id is not_found", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.update_status("no-such-id", "running");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "job not found");
}

TEST_CASE("update_status stamps started_at on a transition to running", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    REQUIRE(store.update_status(*created, "running").has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "running");
    CHECK((*job)->started_at > 0);
    CHECK((*job)->completed_at == 0);
}

TEST_CASE("update_status stamps completed_at and error on a transition to failed",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());

    REQUIRE(store.update_status(*created, "failed", "install script exited 1").has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "failed");
    CHECK((*job)->completed_at > 0);
    CHECK((*job)->error == "install script exited 1");
    CHECK((*job)->started_at > 0); // untouched by the completed/failed branch
}

// ── cancel_job ───────────────────────────────────────────────────────────────

TEST_CASE("cancel_job cancels a pending job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    REQUIRE(store.cancel_job(*created).has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "cancelled");
    CHECK((*job)->error == "cancelled by operator");
    CHECK((*job)->completed_at == 0); // cancel never stamps completed_at
}

TEST_CASE("cancel_job cancels a running job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());

    REQUIRE(store.cancel_job(*created).has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "cancelled");
}

TEST_CASE("cancel_job rejects an already-completed job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());
    REQUIRE(store.update_status(*created, "completed").has_value());

    auto r = store.cancel_job(*created);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only pending or running jobs can be cancelled");

    // Rejected cancel must not have touched the row.
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "completed");
}

TEST_CASE("cancel_job on an unknown id is not_found", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.cancel_job("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "job not found");
}
