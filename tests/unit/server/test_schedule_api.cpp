/**
 * test_schedule_api.cpp — the SEVENTH per-family in-process API seam for the
 * presentation/core/engine split (ADR-0031, WS-A4). `LocalScheduleApi`
 * (schedule_api.cpp) is a thin wrap of `ScheduleEngine::query_schedules_
 * checked` — its own behaviour (the store-failure-vs-empty distinction, the
 * `truncated` cap flag) is already covered by `test_schedule_engine.cpp`, so
 * this file proves only the WIRING: that the seam forwards the query
 * unmodified and returns the engine's result unmodified, through the public
 * `ScheduleApi` interface — the class itself (`LocalScheduleApi`) is
 * deliberately private to schedule_api.cpp, so this file uses only
 * `make_local_schedule_api`, matching how a real presentation/MCP caller
 * will use it.
 */

#include "schedule_api_local.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_schedule_engine_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

using yuzu::server::InstructionSchedule;
using yuzu::server::make_local_schedule_api;
using yuzu::server::ScheduleEngine;
using yuzu::server::ScheduleQuery;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::test::ScheduleEnginePg;

TEST_CASE("ScheduleApi::list_schedules: forwards an empty query and returns an honest-empty result",
          "[pg][schedule_api]") {
    ScheduleEnginePg fx;
    auto api = make_local_schedule_api(*fx.get());

    auto result = api->list_schedules(ScheduleQuery{});
    REQUIRE(result.has_value());
    CHECK(result->schedules.empty());
    CHECK_FALSE(result->truncated);
}

TEST_CASE("ScheduleApi::list_schedules: definition_id/enabled_only filters reach the store unmodified",
          "[pg][schedule_api]") {
    ScheduleEnginePg fx;
    auto api = make_local_schedule_api(*fx.get());

    InstructionSchedule matching;
    matching.name = "matching";
    matching.definition_id = "def-a";
    matching.frequency_type = "once";
    matching.enabled = true;
    matching.created_by = "admin";
    REQUIRE(fx->create_schedule(matching).has_value());

    InstructionSchedule other;
    other.name = "other";
    other.definition_id = "def-b";
    other.frequency_type = "once";
    other.enabled = false;
    other.created_by = "admin";
    REQUIRE(fx->create_schedule(other).has_value());

    ScheduleQuery q;
    q.definition_id = "def-a";
    auto result = api->list_schedules(q);
    REQUIRE(result.has_value());
    REQUIRE(result->schedules.size() == 1);
    CHECK(result->schedules[0].name == "matching");

    ScheduleQuery enabled_q;
    enabled_q.enabled_only = true;
    auto enabled_result = api->list_schedules(enabled_q);
    REQUIRE(enabled_result.has_value());
    REQUIRE(enabled_result->schedules.size() == 1);
    CHECK(enabled_result->schedules[0].name == "matching");
}

// Mirrors test_schedule_engine.cpp's "reports !is_open on a migration
// failure" case: a reachable database whose schema migration FAILS leaves
// the engine `!is_open()`. `LocalScheduleApi::list_schedules` is a thin wrap
// of `ScheduleEngine::query_schedules_checked` — this proves the seam
// forwards that AUTHORITATIVE degrade unmodified (not swallowed into a
// false empty result), which is what the fragment/REST v1/MCP degraded-path
// tests all depend on.
TEST_CASE("ScheduleApi::list_schedules: an unopened engine answers the AUTHORITATIVE degrade",
          "[pg][schedule_api]") {
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
    REQUIRE_FALSE(engine.is_open());
    auto api = make_local_schedule_api(engine);

    auto result = api->list_schedules(ScheduleQuery{});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("schedule engine not open") != std::string::npos);
}
