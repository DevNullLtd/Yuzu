/**
 * test_schedule_engine.cpp — Unit tests for ScheduleEngine (ADR-0065,
 * migration-programme PR 5 commit 1/3: Postgres-backed).
 *
 * Covers: create, query with filters, delete, enable/disable, evaluate_due,
 *         advance_schedule, validation, the not-open degrade path, and a
 *         migration-failure fail-closed path.
 *
 * The pre-migration SQLite v1-row-backfill acceptance test is DROPPED —
 * there is no legacy ladder to migrate against on a fresh Postgres schema
 * (ADR-0009 fresh-start-by-default); `parameter_values` is a column in the
 * store's only DDL version from day one.
 */

#include "test_schedule_engine_pg_helper.hpp"

#include "pg/pg_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::test::ScheduleEnginePg;

// ── Helpers ─────────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static InstructionSchedule make_schedule(const std::string& definition_id,
                                         const std::string& frequency_type,
                                         const std::string& name = "test-schedule") {
    InstructionSchedule sched;
    sched.name = name;
    sched.definition_id = definition_id;
    sched.frequency_type = frequency_type;
    sched.scope_expression = "ostype = 'windows'";
    sched.enabled = true;
    sched.created_by = "admin";
    return sched;
}

/// Sets next_execution_at directly via a second raw connection into the
/// fixture's own database — the PG analogue of the old direct-sqlite3
/// pokes the SQLite-era tests used to force due-ness deterministically.
static void poke_next_execution_at(ScheduleEnginePg& fx, const std::string& id, int64_t value) {
    PgConn conn{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    std::string sql = "UPDATE schedule_engine.schedules SET next_execution_at = " +
                      std::to_string(value) + " WHERE id = '" + id + "'";
    PgResult res{PQexec(conn.get(), sql.c_str())};
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}

// ── Create Schedule ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: create schedule", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-001", "interval", "Hourly Scan");
    sched.interval_minutes = 60;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ScheduleEngine: create with bad frequency_type fails", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-001", "every_full_moon", "Bad Schedule");
    auto result = fx->create_schedule(sched);
    CHECK(!result.has_value());
}

// #3136 blocker: a schedule's parameter_values is the sole record
// ScheduleRunner::dispatch_tracked reads back to re-dispatch on every future
// occurrence — redacting a persisted grant_secret would silently break that
// re-dispatch rather than merely protecting a history row, so creation is
// refused outright instead. See sensitive_instruction_params.hpp.
TEST_CASE("ScheduleEngine: create is refused when parameters carry a one-time credential",
         "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-001", "interval", "Upload Schedule");
    sched.interval_minutes = 60;
    sched.parameter_values = R"({"grant_secret":"deadbeef","path":"/tmp/x"})";
    auto result = fx->create_schedule(sched);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("one-time credential") != std::string::npos);
}

TEST_CASE("ScheduleEngine: create is refused when parameters carry a bare grant_id",
         "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-001", "interval", "Upload Schedule");
    sched.interval_minutes = 60;
    sched.parameter_values = R"({"grant_id":"abc123"})";
    auto result = fx->create_schedule(sched);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("ScheduleEngine: create succeeds when parameters carry no sensitive key",
         "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-001", "interval", "Ordinary Schedule");
    sched.interval_minutes = 60;
    sched.parameter_values = R"({"path":"/tmp/x","max_size_mb":"100"})";
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ScheduleEngine: create schedule with all fields", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    InstructionSchedule sched;
    sched.name = "Weekly Audit";
    sched.definition_id = "def-audit";
    sched.frequency_type = "weekly";
    sched.interval_minutes = 0;
    sched.time_of_day = "09:00";
    sched.day_of_week = 1; // Monday
    sched.scope_expression = "tag = 'production'";
    sched.requires_approval = true;
    sched.enabled = true;
    sched.created_by = "admin";
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());
}

// ── Query Schedules ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: query all schedules", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    fx->create_schedule(make_schedule("def-1", "interval", "One"));
    fx->create_schedule(make_schedule("def-2", "daily", "Two"));
    fx->create_schedule(make_schedule("def-3", "weekly", "Three"));

    auto results = fx->query_schedules();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ScheduleEngine: query by definition_id", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    fx->create_schedule(make_schedule("def-alpha", "daily", "A"));
    fx->create_schedule(make_schedule("def-beta", "daily", "B"));
    fx->create_schedule(make_schedule("def-alpha", "weekly", "C"));

    ScheduleQuery q;
    q.definition_id = "def-alpha";
    auto results = fx->query_schedules(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("ScheduleEngine: query enabled_only", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto r1 = fx->create_schedule(make_schedule("def-1", "daily", "Enabled"));
    auto r2 = fx->create_schedule(make_schedule("def-2", "daily", "Disabled"));
    REQUIRE(r2.has_value());
    fx->set_enabled(*r2, false, "admin");

    ScheduleQuery q;
    q.enabled_only = true;
    auto results = fx->query_schedules(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].name == "Enabled");
}

TEST_CASE("ScheduleEngine: query empty store returns empty", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto results = fx->query_schedules();
    CHECK(results.empty());
}

// #4030 review finding (blocking): query_schedules_checked() queries one row
// PAST the fixed 100-row cap specifically so a fleet of EXACTLY the cap is
// never misreported as truncated by the simpler "returned == limit"
// heuristic (schedule_engine.cpp's own comment on the +1 LIMIT). No
// regression test pinned either side of this boundary before this PR
// (608d3bbee fixed the truncation-signal consumers; the boundary itself was
// untested).
TEST_CASE("ScheduleEngine: query_schedules_checked at exactly the list cap is not "
          "misreported as truncated (#4030 boundary)",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;
    for (int i = 0; i < 100; ++i)
        REQUIRE(fx->create_schedule(make_schedule("def-cap", "interval", "S" + std::to_string(i)))
                    .has_value());

    auto result = fx->query_schedules_checked();
    REQUIRE(result.has_value());
    CHECK(result->schedules.size() == 100);
    CHECK_FALSE(result->truncated);
}

// Sibling of the exact-cap test above: one schedule OVER the cap must come
// back capped at 100 rows WITH result.truncated == true -- the honest
// pagination signal both REST (GET /api/v1/schedules) and MCP
// (list_schedules) surface as result_truncated_by_cap. Before 608d3bbee,
// `total` silently asserted completeness even when the store had actually
// truncated the response.
TEST_CASE("ScheduleEngine: query_schedules_checked truncates and flags a fleet one "
          "over the list cap (#4030 boundary)",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;
    for (int i = 0; i < 101; ++i)
        REQUIRE(fx->create_schedule(make_schedule("def-cap", "interval", "S" + std::to_string(i)))
                    .has_value());

    auto result = fx->query_schedules_checked();
    REQUIRE(result.has_value());
    CHECK(result->schedules.size() == 100);
    CHECK(result->truncated);
}

// ── Delete Schedule ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: delete schedule", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    bool deleted = fx->delete_schedule(*result, "admin");
    REQUIRE(deleted);

    auto results = fx->query_schedules();
    CHECK(results.empty());
}

TEST_CASE("ScheduleEngine: delete nonexistent returns false", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    bool deleted = fx->delete_schedule("nonexistent-id", "admin");
    CHECK(!deleted);
}

// M-01 (#1806): a non-owner must not be able to delete (or probe the
// existence of) another principal's schedule via Schedule:Delete.
TEST_CASE("ScheduleEngine: delete by a non-owner is rejected and the row survives",
          "[schedule_engine][pg][m01]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    bool deleted = fx->delete_schedule(*result, "someone-else");
    CHECK(!deleted);

    auto results = fx->query_schedules();
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == *result);
}

// ── Enable / Disable ───────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: set_enabled disables schedule", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    CHECK(fx->set_enabled(*result, false, "admin"));

    ScheduleQuery q;
    q.enabled_only = true;
    auto enabled = fx->query_schedules(q);
    CHECK(enabled.empty());
}

TEST_CASE("ScheduleEngine: set_enabled re-enables schedule", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    fx->set_enabled(*result, false, "admin");
    fx->set_enabled(*result, true, "admin");

    ScheduleQuery q;
    q.enabled_only = true;
    auto enabled = fx->query_schedules(q);
    REQUIRE(enabled.size() == 1);
}

// M-01 (#1806): a non-owner's set_enabled must be a no-op, not a silent
// fleet-wide arm/disarm of someone else's schedule.
TEST_CASE("ScheduleEngine: set_enabled by a non-owner is rejected and does not change state",
          "[schedule_engine][pg][m01]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    CHECK_FALSE(fx->set_enabled(*result, false, "someone-else"));

    ScheduleQuery q;
    q.enabled_only = true;
    auto enabled = fx->query_schedules(q);
    REQUIRE(enabled.size() == 1); // still enabled — the non-owner's call did nothing
}

// ── evaluate_due ───────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: evaluate_due returns overdue schedule", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-due", "interval", "Overdue");
    sched.interval_minutes = 1;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    poke_next_execution_at(fx, *result, now_epoch() - 60);

    auto due = fx->evaluate_due();
    REQUIRE(due.size() >= 1);

    bool found = false;
    for (const auto& s : due) {
        if (s.id == *result)
            found = true;
    }
    CHECK(found);
}

TEST_CASE("ScheduleEngine: evaluate_due does not return disabled schedule",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-disabled", "interval", "Disabled");
    sched.interval_minutes = 1;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());
    fx->set_enabled(*result, false, "admin");

    poke_next_execution_at(fx, *result, now_epoch() - 60);

    auto due = fx->evaluate_due();
    for (const auto& s : due) {
        CHECK(s.id != *result);
    }
}

TEST_CASE("ScheduleEngine: evaluate_due does not return future schedule",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-future", "interval", "Future");
    sched.interval_minutes = 60;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    poke_next_execution_at(fx, *result, now_epoch() + 7200);

    auto due = fx->evaluate_due();
    for (const auto& s : due) {
        CHECK(s.id != *result);
    }
}

// ── advance_schedule ───────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: advance_schedule updates next_execution_at",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-adv", "interval", "Advancing");
    sched.interval_minutes = 30;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    auto now = now_epoch();
    poke_next_execution_at(fx, *result, now - 60);

    fx->advance_schedule(*result);

    auto all = fx->query_schedules();
    REQUIRE(!all.empty());

    bool found = false;
    for (const auto& s : all) {
        if (s.id == *result) {
            found = true;
            // next_execution_at should have been advanced past now
            CHECK(s.next_execution_at > now - 60);
            // execution_count should be incremented
            CHECK(s.execution_count == 1);
            // last_executed_at should be set
            CHECK(s.last_executed_at > 0);
        }
    }
    REQUIRE(found);
}

TEST_CASE("ScheduleEngine: advance_schedule increments execution_count",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-count", "interval", "Counter");
    sched.interval_minutes = 10;
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    fx->advance_schedule(*result);
    fx->advance_schedule(*result);
    fx->advance_schedule(*result);

    auto all = fx->query_schedules();
    for (const auto& s : all) {
        if (s.id == *result) {
            CHECK(s.execution_count == 3);
        }
    }
}

TEST_CASE("ScheduleEngine: advance_schedule sets last_executed_at", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-last", "daily", "LastExec");
    sched.time_of_day = "14:00";
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    auto before = now_epoch();
    fx->advance_schedule(*result);

    auto all = fx->query_schedules();
    for (const auto& s : all) {
        if (s.id == *result) {
            CHECK(s.last_executed_at >= before);
        }
    }
}

TEST_CASE("ScheduleEngine: advance_schedule 'once' disables re-firing",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-once", "once", "OneShot");
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    fx->advance_schedule(*result);

    auto all = fx->query_schedules();
    bool found = false;
    for (const auto& s : all) {
        if (s.id == *result) {
            found = true;
            CHECK(s.next_execution_at == 0);
        }
    }
    REQUIRE(found);
}

TEST_CASE("ScheduleEngine: advance_schedule on nonexistent id is a silent no-op",
          "[schedule_engine][pg]") {
    ScheduleEnginePg fx;
    fx->advance_schedule("nonexistent-id"); // must not crash
    CHECK(fx->query_schedules().empty());
}

// ── Stop ───────────────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: stop is safe to call", "[schedule_engine][pg]") {
    ScheduleEnginePg fx;
    fx->stop(); // should not crash
    REQUIRE(true);
}

// ── PR1.5a: typed schedule parameters ───────────────────────────────────────

TEST_CASE("ScheduleEngine: a schedule created with no parameters defaults to the canonical "
          "empty object",
          "[schedule_engine][pg][params]") {
    ScheduleEnginePg fx;

    auto result = fx->create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    auto all = fx->query_schedules();
    REQUIRE(all.size() == 1);
    CHECK(all[0].parameter_values == "{}");
}

TEST_CASE("ScheduleEngine: create_schedule stores the canonical (sorted-key) form regardless "
          "of the caller's key order",
          "[schedule_engine][pg][params]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-1", "interval", "Params");
    sched.parameter_values = R"({"zeta":"1","alpha":"2"})";
    auto result = fx->create_schedule(sched);
    REQUIRE(result.has_value());

    auto all = fx->query_schedules();
    REQUIRE(all.size() == 1);
    CHECK(all[0].parameter_values == R"({"alpha":"2","zeta":"1"})");
}

TEST_CASE("ScheduleEngine: create_schedule rejects invalid parameters and creates no row",
          "[schedule_engine][pg][params]") {
    ScheduleEnginePg fx;

    auto sched = make_schedule("def-1", "interval");
    sched.parameter_values = R"({"nested":{"a":1}})"; // non-scalar value
    auto result = fx->create_schedule(sched);
    CHECK_FALSE(result.has_value());
    CHECK(fx->query_schedules().empty());
}

// ── Not-open degrade path + migration-failure fail-closed ──────────────────
// (gov fjarvis B1 precedent, test_patch_manager.cpp): a reachable database
// whose schema migration FAILS must leave the store !is_open() — which
// server.cpp wires to startup_failed_ (fail closed, not serve-degraded; a
// posture upgrade from the SQLite era, where migration failure was
// log-only and no caller ever checked an availability flag). Force the
// failure by pre-seeding a table in the store's schema with no schema_meta
// row: the migration runner's schema-drift guard refuses (version 0 but
// tables exist), so run() returns false. Every method on the resulting
// closed store must degrade to its existing benign empty/no-op/error shape,
// never crash.
TEST_CASE("ScheduleEngine reports !is_open on a migration failure and degrades every method",
          "[schedule_engine][pg]") {
    // governance PR review (2026-08-31, Doomgoose): this is exactly the
    // migration-in-substance shape docs/postgres-store-playbook.md routes to
    // YUZU_REQUIRE_PG_MIGRATION_DB (not plain YUZU_REQUIRE_PG_DB) — the
    // wrong macro re-adds the per-test Windows EXEC_BACKEND DDL cost the
    // migration-macro exists to remove.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA schedule_engine")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE schedule_engine.bogus (x int)")};
        REQUIRE(t.ok());
    }

    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ScheduleEngine engine{pool};
    CHECK_FALSE(engine.is_open()); // → server.cpp sets startup_failed_ = true

    auto result = engine.create_schedule(make_schedule("def-1", "interval"));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == "database not open");

    CHECK(engine.query_schedules().empty());
    CHECK(engine.evaluate_due().empty());
    CHECK_FALSE(engine.delete_schedule("anything", "admin"));
    CHECK_FALSE(engine.set_enabled("anything", true, "admin"));
    engine.advance_schedule("anything"); // must not crash

    // #4030 review finding (blocking): query_schedules_checked() must fail
    // closed (std::unexpected) on the SAME degrade the unchecked
    // query_schedules() above silently collapses to an empty vector --
    // GET /api/v1/schedules and MCP list_schedules both depend on this to
    // tell "genuinely empty" apart from "store degraded" (5686776fe fixed
    // the consumers; no regression test existed for this checked path
    // itself before this PR).
    auto checked = engine.query_schedules_checked();
    REQUIRE_FALSE(checked.has_value());
    CHECK(checked.error().find("schedule engine not open") != std::string::npos);
}
