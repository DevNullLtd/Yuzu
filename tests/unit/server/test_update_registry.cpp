/**
 * test_update_registry.cpp — Unit tests for the OTA update registry
 * (ADR-0061, Postgres-backed, schema `update_registry`)
 *
 * Covers: UpdateRegistry CRUD, latest_for version selection,
 *         is_eligible rollout logic, binary_path, upsert-replace,
 *         the not-open degrade path, and a migration-failure fail-closed
 *         probe (mirrors OfflineEndpointStore's precedent).
 */

#include "update_registry.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <yuzu/metrics.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace fs = std::filesystem;

namespace {

/// RAII per-test update_dir. Process-salted: a fixed dir name is a cross-JOB
/// shared resource on the shared-identity CI pools — one job's cleanup
/// remove_all would yank the dir out from under another job's live
/// UpdateRegistry (#1883). RAII (vs the old trailing cleanup call) also
/// removes the dir when a REQUIRE fails — with salted never-reused names a
/// leaked dir is pure litter, not self-overwriting. Creation is asserted so
/// a full temp volume can't silently hollow out the tests (gov safe-1/-2).
struct TempUpdateDir {
    yuzu::test::TempDir guard{"yuzu_test_update_registry-"};
    TempUpdateDir() {
        std::error_code ec;
        fs::create_directories(guard.path, ec);
        REQUIRE(fs::exists(guard.path));
    }
    const fs::path& path() const { return guard.path; }
};

/// Helper: build an UpdatePackage with sensible defaults.
UpdatePackage make_pkg(const std::string& platform = "windows", const std::string& arch = "x86_64",
                       const std::string& version = "0.1.0",
                       const std::string& filename = "yuzu-agent-0.1.0-x64-windows.exe") {
    UpdatePackage pkg;
    pkg.platform = platform;
    pkg.arch = arch;
    pkg.version = version;
    pkg.sha256 = "aabbccdd";
    pkg.filename = filename;
    pkg.mandatory = false;
    pkg.rollout_pct = 100;
    pkg.uploaded_at = "2025-01-01T00:00:00Z";
    pkg.file_size = 1024;
    return pkg;
}

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate update_registry_tpl{
    "update_registry", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        UpdateRegistry reg{pool, fs::temp_directory_path()};
        if (!reg.is_open())
            throw std::runtime_error("update_registry template: store failed to migrate");
    }};

} // namespace

// ── Database Lifecycle ──────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: opens and migrates", "[update_registry][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());
}

// ── Upsert & List ───────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: upsert_package + list_packages returns it",
          "[update_registry][pg][upsert]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    auto pkg = make_pkg();
    REQUIRE(reg.upsert_package(pkg));

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 1);
    REQUIRE(packages[0].platform == "windows");
    REQUIRE(packages[0].arch == "x86_64");
    REQUIRE(packages[0].version == "0.1.0");
    REQUIRE(packages[0].filename == "yuzu-agent-0.1.0-x64-windows.exe");
}

// ── latest_for ──────────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: latest_for returns package for matching platform/arch",
          "[update_registry][pg][latest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("linux", "x86_64", "0.1.0", "yuzu-agent-0.1.0-linux")));

    auto result = reg.latest_for("linux", "x86_64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.1.0");
    REQUIRE(result->platform == "linux");
}

TEST_CASE("UpdateRegistry: latest_for returns nullopt for unknown platform",
          "[update_registry][pg][latest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0")));

    auto result = reg.latest_for("freebsd", "x86_64");
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("UpdateRegistry: latest_for returns newest version when multiple exist",
          "[update_registry][pg][latest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0", "agent-0.1.0.exe")));
    REQUIRE(reg.upsert_package(make_pkg("windows", "x86_64", "0.2.0", "agent-0.2.0.exe")));

    auto result = reg.latest_for("windows", "x86_64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.2.0");
}

TEST_CASE("UpdateRegistry: latest_for handles numeric version comparison (0.10.0 > 0.9.0)",
          "[update_registry][pg][latest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("linux", "aarch64", "0.9.0", "agent-0.9.0")));
    REQUIRE(reg.upsert_package(make_pkg("linux", "aarch64", "0.10.0", "agent-0.10.0")));

    auto result = reg.latest_for("linux", "aarch64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.10.0");
}

// ── Remove ──────────────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: remove_package makes latest_for return nullopt",
          "[update_registry][pg][remove]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0")));
    reg.remove_package("windows", "x86_64", "0.1.0");

    auto result = reg.latest_for("windows", "x86_64");
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("UpdateRegistry: remove_package for nonexistent does not crash",
          "[update_registry][pg][remove]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    // Should not throw or crash
    reg.remove_package("darwin", "aarch64", "9.9.9");

    auto packages = reg.list_packages();
    REQUIRE(packages.empty());
}

// ── Rollout Eligibility (pure — no DB) ───────────────────────────────────────

TEST_CASE("UpdateRegistry: is_eligible at 100% always returns true", "[update_registry][rollout]") {
    for (int i = 0; i < 50; ++i) {
        REQUIRE(UpdateRegistry::is_eligible("agent-" + std::to_string(i), 100));
    }
}

TEST_CASE("UpdateRegistry: is_eligible at 0% always returns false", "[update_registry][rollout]") {
    for (int i = 0; i < 50; ++i) {
        REQUIRE_FALSE(UpdateRegistry::is_eligible("agent-" + std::to_string(i), 0));
    }
}

TEST_CASE("UpdateRegistry: is_eligible is deterministic", "[update_registry][rollout]") {
    const std::string agent_id = "test-agent-42";
    bool first_result = UpdateRegistry::is_eligible(agent_id, 50);

    // Same agent_id and rollout_pct should always produce the same result
    for (int i = 0; i < 20; ++i) {
        REQUIRE(UpdateRegistry::is_eligible(agent_id, 50) == first_result);
    }
}

TEST_CASE("UpdateRegistry: is_eligible distributes roughly 50% at rollout_pct=50",
          "[update_registry][rollout]") {
    int eligible_count = 0;
    constexpr int kTotal = 100;

    for (int i = 0; i < kTotal; ++i) {
        if (UpdateRegistry::is_eligible("agent-distribution-" + std::to_string(i), 50)) {
            ++eligible_count;
        }
    }

    // Expect roughly half — allow wide margin (30-70) to avoid flaky tests
    REQUIRE(eligible_count >= 30);
    REQUIRE(eligible_count <= 70);
}

// ── binary_path (pure — no DB) ────────────────────────────────────────────

TEST_CASE("UpdateRegistry: binary_path returns update_dir / filename", "[update_registry][pg][path]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    auto pkg = make_pkg("windows", "x86_64", "0.1.0", "yuzu-agent.exe");
    auto path = reg.binary_path(pkg);
    REQUIRE(path == tmp.path() / "yuzu-agent.exe");
}

// A STORED filename is revalidated at READ time, not only at upload (#3863).
// The upload guard protects new rows; these paths are derived from whatever the
// row already holds, so a row written BEFORE that guard landed, or written
// straight to the database, would otherwise be resolved here and then read from
// (CheckForUpdate serves the sidecar beside it) or unlinked (the delete route)
// outside update_dir_.
//
// The assertion is `.empty()`, not "some path inside update_dir_": joining an
// unsafe name yields update_dir_ ITSELF, and handing that to a remove() is
// worse than handing it nothing. Without this case the read-time guard could be
// deleted and every other test here would stay green.
TEST_CASE("UpdateRegistry: an unsafe stored filename resolves to no path at all",
          "[update_registry][pg][path]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    for (const char* unsafe : {"../escape.exe", "sub/dir.exe", "/abs/path.exe", ""}) {
        INFO("stored filename = '" << unsafe << "'");
        auto pkg = make_pkg("windows", "x86_64", "0.1.0", unsafe);
        CHECK(reg.binary_path(pkg).empty());
        // The sidecar is derived from the binary path, so it must not fall back
        // to a bare ".sig" resolved against the process working directory.
        CHECK(reg.signature_path(pkg).empty());
    }
}

// ── list_packages ───────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: list_packages returns all upserted packages",
          "[update_registry][pg][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    REQUIRE(reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0", "agent-win-0.1.0.exe")));
    REQUIRE(reg.upsert_package(make_pkg("linux", "x86_64", "0.1.0", "agent-linux-0.1.0")));
    REQUIRE(reg.upsert_package(make_pkg("darwin", "aarch64", "0.1.0", "agent-darwin-0.1.0")));

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 3);
}

// ── Upsert Replace ─────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: upsert same platform/arch/version replaces existing",
          "[update_registry][pg][upsert]") {
    YUZU_REQUIRE_PG_DB_TPL(db, update_registry_tpl);
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    UpdateRegistry reg(pool, tmp.path());
    REQUIRE(reg.is_open());

    auto pkg = make_pkg("windows", "x86_64", "0.1.0", "agent-v1.exe");
    pkg.sha256 = "original_hash";
    REQUIRE(reg.upsert_package(pkg));

    // Upsert with same primary key but different fields
    pkg.sha256 = "updated_hash";
    pkg.filename = "agent-v1-rebuilt.exe";
    pkg.file_size = 2048;
    REQUIRE(reg.upsert_package(pkg));

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 1);
    REQUIRE(packages[0].sha256 == "updated_hash");
    REQUIRE(packages[0].filename == "agent-v1-rebuilt.exe");
    REQUIRE(packages[0].file_size == 2048);
}

// ── Not-open degrade path (deliberately NOT typed-error — see the header doc
//    comment's ADR-0036 deny-or-benign rationale) — no live Postgres needed,
//    the malformed conninfo never dials out (mirrors test_pg_pool.cpp's
//    "malformed conninfo" case). ────────────────────────────────────────────

TEST_CASE("UpdateRegistry: a store that fails to open degrades every method to a benign "
          "empty/false/nullopt, never crashes",
          "[update_registry][pg]") {
    TempUpdateDir tmp;
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());

    UpdateRegistry reg(pool, tmp.path());
    REQUIRE_FALSE(reg.is_open());

    CHECK(reg.list_packages().empty());
    CHECK_FALSE(reg.latest_for("windows", "x86_64").has_value());
    // Neither call should throw or crash against a never-opened store, and the
    // write must REPORT that it did not commit — the degrade is the behaviour
    // under test, so asserting the false is stronger than discarding it.
    CHECK_FALSE(reg.upsert_package(make_pkg()));
    reg.remove_package("windows", "x86_64", "0.1.0");
    CHECK(reg.list_packages().empty());
}

// gov sre finding (Gate 8 re-review, adversarial review 2026-08-28), mirrors
// test_instruction_store.cpp's "read and write degrade counters increment on
// a store that failed to open" precedent exactly: a code-read confirmation
// that note_read_degrade/note_write_degrade are called is not the same as
// proof the counters actually move. Same malformed-conninfo store_not_open
// path as the test above, but with a MetricsRegistry wired and inspected.
TEST_CASE("UpdateRegistry: read and write degrade counters increment on a store "
          "that failed to open",
          "[update_registry][pg]") {
    TempUpdateDir tmp;
    PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    REQUIRE_FALSE(broken_pool.valid());
    UpdateRegistry reg(broken_pool, tmp.path());
    REQUIRE_FALSE(reg.is_open());

    yuzu::MetricsRegistry metrics;
    reg.set_metrics(&metrics); // wired after construction — construction's own
                              // failed lease attempt must not touch the counter.

    auto packages = reg.list_packages();
    CHECK(packages.empty());
    CHECK(metrics.counter("yuzu_server_update_registry_read_degrade_total",
                          {{"reason", "store_not_open"}})
              .value() == 1.0);

    CHECK_FALSE(reg.upsert_package(make_pkg()));
    CHECK(metrics.counter("yuzu_server_update_registry_write_degrade_total",
                          {{"reason", "store_not_open"}})
              .value() == 1.0);
}

// gov fjarvis B1 precedent (OfflineEndpointStore): a reachable database whose
// schema migration FAILS must leave the store !is_open() — which server.cpp
// wires to startup_failed_ (fail closed, not serve-degraded). Force the
// failure by pre-seeding a table in the store's schema with no schema_meta
// row: the migration runner's schema-drift guard refuses (version 0 but
// tables exist), so run() returns false.
//
// gov fjarvis C2 (PR #3695 review, 2026-08-28): this is exactly the
// fresh-migrate/"!is_open on a migration failure" case
// YUZU_REQUIRE_PG_MIGRATION_DB's own docstring names as its target — an
// earlier version of this test stayed on plain YUZU_REQUIRE_PG_DB with a
// comment claiming the two macros hand out different databases. They don't:
// YUZU_REQUIRE_PG_MIGRATION_DB is YUZU_REQUIRE_PG_DB plus a Windows skip for
// the #2354 EXEC_BACKEND fresh-DB cost, nothing else.
TEST_CASE("UpdateRegistry reports !is_open on a migration failure", "[update_registry][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    TempUpdateDir tmp;

    // Pre-seed: create the update_registry schema + a conflicting table, but
    // no public.schema_meta row for the store — the drift guard will refuse.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA update_registry")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE update_registry.update_packages (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    UpdateRegistry reg(pool, tmp.path());
    CHECK_FALSE(reg.is_open()); // → server.cpp sets startup_failed_ = true
}

// gov quality-engineer/cpp-safety (adversarial review, 2026-08-28, converged
// independently across 2 reviewers), modelled directly on
// test_api_token_store.cpp's "#2961 round-2" precedent: the migration-failure
// test above exercises PgMigrationRunner's own schema-drift guard (version 0
// but tables exist) — a DIFFERENT failure mode from the post-migration
// projection smoke-read added in this PR's own hardening round. The runner's
// guard can only see a version collision baked into THIS binary's own
// migrations() vector; it cannot see a version already recorded by a
// DIFFERENT binary whose schema doesn't match what THIS binary's runtime
// queries select. Force exactly that: stamp schema_meta at v1 (a lie — no
// real v1 migration ran against this schema) against a table that is
// missing `file_size`, one of the columns list_packages()/latest_for()
// actually select. Disabling the smoke-read would leave this green with
// !is_open() never firing until the first runtime read hit `undefined
// column` instead.
TEST_CASE("UpdateRegistry reports !is_open when schema_meta claims v1 but update_packages "
          "is missing a selected column (post-migration smoke-read guard)",
          "[update_registry][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    TempUpdateDir tmp;

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA update_registry")};
        REQUIRE(schema.ok());

        // v1 DDL copied from migrations() in update_registry.cpp, deliberately
        // missing the file_size column that list_packages()/latest_for()'s
        // SELECT actually projects.
        PgResult table{PQexec(conn.get(),
                              "CREATE TABLE update_registry.update_packages ("
                              "  platform    TEXT    NOT NULL,"
                              "  arch        TEXT    NOT NULL,"
                              "  version     TEXT    NOT NULL,"
                              "  sha256      TEXT    NOT NULL,"
                              "  filename    TEXT    NOT NULL,"
                              "  mandatory   BOOLEAN NOT NULL DEFAULT FALSE,"
                              "  rollout_pct INTEGER NOT NULL DEFAULT 100,"
                              "  uploaded_at TEXT    NOT NULL DEFAULT '',"
                              "  PRIMARY KEY (platform, arch, version))")};
        REQUIRE(table.ok());

        // Stamp schema_meta at v1 — a LIE: no real v1 migration ran against
        // this schema, it's missing file_size. Models a database another
        // binary's runner believed it already migrated (so
        // PgMigrationRunner::run sees nothing pending and returns true),
        // never a real migration run against this exact schema.
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('update_registry', 1, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    UpdateRegistry reg(pool, tmp.path());
    CHECK_FALSE(reg.is_open()); // → smoke-read fails closed, not just the runner's own guard
}
