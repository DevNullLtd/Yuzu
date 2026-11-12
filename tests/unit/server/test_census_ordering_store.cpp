/**
 * test_census_ordering_store.cpp : #5690 PR2a-1: the census ordering key, the durable pending
 * evidence, and schema v4 of the guaranteed_state_store.
 *
 * Needs a Postgres database (YUZU_TEST_POSTGRES_DSN); without one every case here SKIPS, so a
 * run with no DSN proves nothing. Cases are grouped by commit of the PR: schema (C1) first.
 */

#include "guaranteed_state_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include "test_events_table_lock.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <future>
#include <algorithm>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

void exec_sql(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

std::string query_scalar(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

// SQLSTATE of a statement expected to fail ("" when it succeeded).
std::string sqlstate_of(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    const char* st = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return st ? st : "";
}

GuaranteedStateRuleRow make_rule(std::string rule_id, std::string name) {
    GuaranteedStateRuleRow r;
    r.rule_id = std::move(rule_id);
    r.name = std::move(name);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "tag:workstations";
    r.created_at = "2026-04-19T12:00:00Z";
    r.updated_at = "2026-04-19T12:00:00Z";
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

// Pre-migrated template (PgTestTemplate in test_helpers.hpp): the behaviour cases below clone a
// database the store already migrated instead of paying a v1..v4 migration per case, and they run
// on Windows, which skips the fresh-DB migration cases (#2354). Same shared key spelling as every
// other GuaranteedStateStore test file.
yuzu::test::PgTestTemplate ordering_tpl{
    "guardianstate", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        GuaranteedStateStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("guardianstate template: store failed to migrate");
    }};

constexpr const char* kSchema = "guaranteed_state_store";

// The version the latest migration stamps. The v4 cases below check v4's objects; the stamp they
// read back is the store's current one.
constexpr const char* kStampedVersion = "5";

std::string schema_version(const std::string& dsn) {
    return query_scalar(dsn, "SELECT version FROM public.schema_meta "
                             "WHERE store = 'guaranteed_state_store'");
}

// Open a store on `dsn` and say whether it opened (the object is discarded).
bool opens(const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 2}};
    GuaranteedStateStore store(pool);
    return store.is_open();
}

// Put a v4 database back to the v3 shape: drop what v4 added and stamp 3.
void downgrade_to_v3(const std::string& dsn) {
    exec_sql(dsn, std::string("DROP INDEX IF EXISTS ") + kSchema + ".idx_gse_pending");
    exec_sql(dsn, std::string("ALTER TABLE ") + kSchema +
                      ".guaranteed_state_events DROP COLUMN ingest_seq, DROP COLUMN proj_key, "
                      "DROP COLUMN proj_key_capped, DROP COLUMN projection_pending");
    exec_sql(dsn, std::string("ALTER TABLE ") + kSchema +
                      ".guardian_agent_rule_status DROP COLUMN key_ns, DROP COLUMN ingest_seq, "
                      "DROP COLUMN ts_hwm, DROP COLUMN seq_hwm, DROP COLUMN hwm_recv_ns, "
                      "DROP COLUMN order_uncertain");
    exec_sql(dsn, "UPDATE public.schema_meta SET version = 3 "
                  "WHERE store = 'guaranteed_state_store'");
}

// The v4 body of the census tripwire function (what a v4 database carries; v5 replaces it).
constexpr const char* kV4TripwireBody =
    "BEGIN IF (NEW.state IS DISTINCT FROM OLD.state OR NEW.updated_at IS DISTINCT FROM "
    "OLD.updated_at) AND NEW.key_ns IS NOT DISTINCT FROM OLD.key_ns AND NEW.ingest_seq IS NOT "
    "DISTINCT FROM OLD.ingest_seq THEN NEW.order_uncertain := true; END IF; RETURN NEW; END";

void replace_tripwire_body(const std::string& dsn, const std::string& body) {
    exec_sql(dsn, std::string("CREATE OR REPLACE FUNCTION ") + kSchema +
                      ".guardian_agent_rule_status_flag_legacy_write() RETURNS trigger "
                      "LANGUAGE plpgsql AS $fn$ " +
                      body + " $fn$");
}

// Put a v5 database back to the v4 shape: drop what v5 added, restore the v4 tripwire body and
// stamp 4.
void downgrade_to_v4(const std::string& dsn) {
    exec_sql(dsn, std::string("DROP TABLE IF EXISTS ") + kSchema + ".guardian_agent_order");
    exec_sql(dsn, std::string("ALTER TABLE ") + kSchema +
                      ".guaranteed_state_events DROP COLUMN boot_epoch, DROP COLUMN emit_seq");
    exec_sql(dsn, std::string("ALTER TABLE ") + kSchema +
                      ".guardian_agent_rule_status DROP COLUMN boot_epoch, DROP COLUMN emit_seq");
    replace_tripwire_body(dsn, kV4TripwireBody);
    exec_sql(dsn, "UPDATE public.schema_meta SET version = 4 "
                  "WHERE store = 'guaranteed_state_store'");
}

} // namespace

// ── C1: schema v4 ────────────────────────────────────────────────────────────

TEST_CASE("census ordering: a fresh database migrates to v4 with every v4 object",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == kStampedVersion);
    CHECK(query_scalar(db.dsn(), "SELECT attidentity FROM pg_attribute WHERE attrelid = "
                                 "'guaranteed_state_store.guaranteed_state_events'::regclass "
                                 "AND attname = 'ingest_seq'") == "a");
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_indexes WHERE schemaname = "
                                 "'guaranteed_state_store' AND indexname IN "
                                 "('idx_gse_ingest_seq', 'idx_gse_pending')") == "2");
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_attribute WHERE attrelid = "
                                 "'guaranteed_state_store.guardian_agent_rule_status'::regclass "
                                 "AND attname IN ('key_ns', 'ingest_seq', 'ts_hwm', 'seq_hwm', "
                                 "'hwm_recv_ns', 'order_uncertain') AND NOT attisdropped") == "6");
}

TEST_CASE("census ordering: a v4 database missing the two later census columns is repaired by a "
          "reset to version 3",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    // The remedy the upgrade guide gives for a development database stamped v4 by an earlier build
    // of this change: the migration replays with IF NOT EXISTS and adds only what is missing.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    const std::string st = std::string(kSchema) + ".guardian_agent_rule_status";
    exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN seq_hwm, DROP COLUMN hwm_recv_ns");
    CHECK_FALSE(opens(db.dsn())); // the boot probe refuses it
    exec_sql(db.dsn(), "UPDATE public.schema_meta SET version = 3 "
                       "WHERE store = 'guaranteed_state_store'");
    CHECK(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == kStampedVersion);
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_attribute WHERE attrelid = '" + st +
                                     "'::regclass AND attname IN ('seq_hwm', 'hwm_recv_ns') AND "
                                     "NOT attisdropped") == "2");
}

TEST_CASE("census ordering: v4 over a v3 database keeps the census and fills ingest_seq once",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    downgrade_to_v3(db.dsn());
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_rules (rule_id, name, yaml_source, created_at, "
                           "updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
    for (int i = 1; i <= 3; ++i) {
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, agent_id, "
                               "event_type, severity, timestamp) VALUES ('e" +
                               std::to_string(i) +
                               "', 'r1', 'a1', 'drift.detected', 'high', "
                               "'2026-04-19T12:00:00Z')");
    }
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at) "
                           "VALUES ('a1', 'r1', 'drifted', '2026-04-19T12:00:00Z')");

    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == kStampedVersion);
    // Pre-v4 events: one distinct sequence value each, no key, never pending.
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(DISTINCT ingest_seq) FROM ") + kSchema +
                                     ".guaranteed_state_events") == "3");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE proj_key IS NOT NULL OR "
                                     "projection_pending") == "0");
    // The census row keeps its verdict; the new columns are NULL / false.
    CHECK(query_scalar(db.dsn(), std::string("SELECT state || '|' || (key_ns IS NULL) || '|' || "
                                             "(ingest_seq IS NULL) || '|' || (ts_hwm IS NULL) "
                                             "|| '|' || order_uncertain FROM ") +
                                     kSchema + ".guardian_agent_rule_status") ==
          "drifted|true|true|true|false");
}

TEST_CASE("census ordering: replaying v4 over a used v4 changes nothing and the sequence continues",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_rules (rule_id, name, yaml_source, created_at, "
                           "updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp) VALUES ('e1', 'r1', 'a1', 'drift.detected', "
                           "'high', 't')");
    const std::string objs =
        "SELECT md5(string_agg(c.oid::text || a.attnum::text || a.attname, ',' ORDER BY "
        "c.oid, a.attnum)) FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND "
        "a.attnum > 0 AND NOT a.attisdropped WHERE c.relnamespace = "
        "'guaranteed_state_store'::regnamespace AND c.relkind IN ('r', 'i')";
    const std::string before = query_scalar(db.dsn(), objs);
    const std::string max_before =
        query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) FROM ") + kSchema +
                                   ".guaranteed_state_events");

    exec_sql(db.dsn(), "UPDATE public.schema_meta SET version = 2 "
                       "WHERE store = 'guaranteed_state_store'");
    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == kStampedVersion);
    CHECK(query_scalar(db.dsn(), objs) == before);
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp) VALUES ('e2', 'r1', 'a1', 'drift.detected', "
                           "'high', 't')");
    CHECK(std::stoll(query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) FROM ") + kSchema +
                                                ".guaranteed_state_events")) >
          std::stoll(max_before));
}

TEST_CASE("census ordering: ingest_seq cannot be supplied by a caller",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_rules (rule_id, name, yaml_source, created_at, "
                           "updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
    // 428C9: cannot insert a non-DEFAULT value into a GENERATED ALWAYS identity column.
    CHECK(sqlstate_of(db.dsn(), std::string("INSERT INTO ") + kSchema +
                                    ".guaranteed_state_events (event_id, rule_id, agent_id, "
                                    "event_type, severity, timestamp, ingest_seq) VALUES "
                                    "('x', 'r1', 'a1', 't', 'high', 't', 5)") == "428C9");
}

TEST_CASE("census ordering: an adopted v4 object not as this version creates it is refused",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    const std::string ev = std::string(kSchema) + ".guaranteed_state_events";
    const std::string st = std::string(kSchema) + ".guardian_agent_rule_status";
    const std::string seq = std::string(kSchema) + ".guaranteed_state_events_ingest_seq_seq";

    std::string expect; // the named defect each section must be refused for

    SECTION("ingest_seq is BY DEFAULT, not ALWAYS") {
        expect = "events.ingest_seq(bigint,not null,identity ALWAYS)";
        exec_sql(db.dsn(),
                 "ALTER TABLE " + ev + " ALTER COLUMN ingest_seq SET GENERATED BY DEFAULT");
    }
    SECTION("idx_gse_pending is not partial") {
        expect = "idx_gse_pending((rule_id,agent_id) WHERE projection_pending)";
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_pending");
        exec_sql(db.dsn(),
                 std::string("CREATE INDEX idx_gse_pending ON ") + ev + " (rule_id, agent_id)");
    }
    SECTION("idx_gse_pending is in the other column order") {
        expect = "idx_gse_pending((rule_id,agent_id) WHERE projection_pending)";
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_pending");
        exec_sql(db.dsn(), std::string("CREATE INDEX idx_gse_pending ON ") + ev +
                               " (agent_id, rule_id) WHERE projection_pending");
    }
    SECTION("the census order_uncertain is nullable") {
        expect = ".order_uncertain";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN order_uncertain DROP NOT NULL");
    }
    SECTION("the census seq_hwm column is missing") {
        expect = ".seq_hwm";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN seq_hwm");
    }
    SECTION("the census hwm_recv_ns column is missing") {
        expect = ".hwm_recv_ns";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN hwm_recv_ns");
    }
    SECTION("the census hwm_recv_ns column is of the wrong type") {
        expect = ".hwm_recv_ns";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN hwm_recv_ns TYPE integer USING 0");
    }
    SECTION("a census key column of the wrong type") {
        expect = ".key_ns";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN key_ns TYPE integer");
    }
    SECTION("proj_key_capped is a generated column, not an ordinary one") {
        expect = ".proj_key_capped";
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " DROP COLUMN proj_key_capped");
        exec_sql(db.dsn(), "ALTER TABLE " + ev +
                               " ADD COLUMN proj_key_capped boolean "
                               "GENERATED ALWAYS AS (false) STORED NOT NULL");
    }
    SECTION("the sequence has a low maximum") {
        expect = "events.ingest_seq sequence(";
        exec_sql(db.dsn(), "ALTER SEQUENCE " + seq + " MAXVALUE 2");
    }
    SECTION("the unique index was replaced by a deferred constraint") {
        expect = "idx_gse_ingest_seq(unique,immediate,valid,on ingest_seq only)";
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_ingest_seq");
        exec_sql(db.dsn(), "ALTER TABLE " + ev +
                               " ADD CONSTRAINT idx_gse_ingest_seq UNIQUE "
                               "(ingest_seq) DEFERRABLE INITIALLY DEFERRED");
    }
    SECTION("the census foreign key was renamed (the 23503 classifier keys on the name)") {
        expect = "census foreign key name guardian_agent_rule_status_rule_fk";
        exec_sql(db.dsn(), "ALTER TABLE " + st +
                               " RENAME CONSTRAINT "
                               "guardian_agent_rule_status_rule_fk TO adopted_fk");
    }
    SECTION("the event primary key was renamed (the 23505 classifier keys on the name)") {
        expect = "events primary key name guaranteed_state_events_pkey";
        exec_sql(db.dsn(), "ALTER TABLE " + ev +
                               " RENAME CONSTRAINT "
                               "guaranteed_state_events_pkey TO adopted_pk");
    }
    SECTION("the legacy-write trigger was dropped") {
        expect = "census trigger guardian_agent_rule_status_flag_legacy";
        exec_sql(db.dsn(), "DROP TRIGGER guardian_agent_rule_status_flag_legacy ON " + st);
    }
    SECTION("the legacy-write trigger is disabled") {
        expect = "census trigger guardian_agent_rule_status_flag_legacy";
        exec_sql(db.dsn(),
                 "ALTER TABLE " + st + " DISABLE TRIGGER guardian_agent_rule_status_flag_legacy");
    }
    SECTION("the sequence was reseeded below the census seq_hwm (the events were reaped)") {
        expect = "is not above the retained maxima";
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_rules (rule_id, name, yaml_source, "
                               "created_at, updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
        exec_sql(db.dsn(), "INSERT INTO " + st +
                               " (agent_id, rule_id, state, updated_at, key_ns, "
                               "ingest_seq, seq_hwm) VALUES ('a1', 'r1', "
                               "'compliant', 't', 1, 1, 500)");
        exec_sql(db.dsn(),
                 "SELECT setval('" + seq +
                     "', 2, false)"); // above ingest_seq (1) and at or below seq_hwm (500)
    }
    SECTION("the sequence was reseeded below the retained maximum") {
        expect = "is not above the retained maxima";
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_rules (rule_id, name, yaml_source, "
                               "created_at, updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
        exec_sql(db.dsn(), "INSERT INTO " + ev +
                               " (event_id, rule_id, agent_id, event_type, "
                               "severity, timestamp) VALUES ('e1', 'r1', 'a1', "
                               "'t', 'high', 't')");
        exec_sql(db.dsn(), "SELECT setval('" + seq + "', 1, false)");
    }

    yuzu::test::LogCapture cap(spdlog::level::err);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    GuaranteedStateStore store(pool);
    cap.stop();
    CHECK_FALSE(store.is_open());
    CHECK(cap.text().find("unsupported schema, refusing to start") != std::string::npos);
    CHECK(cap.text().find("v4: object not as this version creates it") != std::string::npos);
    REQUIRE_FALSE(expect.empty()); // a section that forgets its token would pass vacuously
    CHECK(cap.text().find(expect) != std::string::npos);
}

TEST_CASE("census ordering: a hand-broken object makes the v4 migration refuse and not stamp",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    downgrade_to_v3(db.dsn());
    // An adopted (pre-existing) object with the v4 name but the wrong shape.
    exec_sql(db.dsn(), std::string("CREATE INDEX idx_gse_pending ON ") + kSchema +
                           ".guaranteed_state_events (rule_id)");
    CHECK_FALSE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "3");
}

// A2: schema v5 (the event pair and the per-agent order table)

namespace {

// Opens a store on a v5 database that holds a hand-broken object and returns the boot log.
struct OpenAttempt {
    bool open = false;
    std::string log;
};

OpenAttempt try_open(const std::string& dsn) {
    yuzu::test::LogCapture cap(spdlog::level::err);
    PgPool pool{{.conninfo = dsn, .size = 2}};
    GuaranteedStateStore store(pool);
    cap.stop();
    return {store.is_open(), cap.text()};
}

void insert_rule(const std::string& dsn, const char* rule_id) {
    exec_sql(dsn, std::string("INSERT INTO ") + kSchema +
                      ".guaranteed_state_rules (rule_id, name, yaml_source, created_at, "
                      "updated_at) VALUES ('" +
                      rule_id + "', 'n', 'y', 't', 't')");
}

// "name:type:notnull" for every live column of a v5 table, in column order.
std::string column_shape(const std::string& dsn, const char* table) {
    return query_scalar(
        dsn, std::string("SELECT string_agg(a.attname || ':' || format_type(a.atttypid, NULL) "
                         "|| ':' || a.attnotnull, ',' ORDER BY a.attnum) FROM pg_attribute a "
                         "WHERE a.attrelid = '") +
                 kSchema + "." + table + "'::regclass AND a.attnum > 0 AND NOT a.attisdropped");
}

} // namespace

TEST_CASE("census ordering: a fresh database migrates to v5 with every v5 object",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "5");
    // The four pair columns: bigint, nullable (NULL/NULL is an unpaired event or verdict).
    for (const char* table : {"guaranteed_state_events", "guardian_agent_rule_status"}) {
        CHECK(query_scalar(db.dsn(), std::string("SELECT string_agg(a.attname || ':' || "
                                                 "format_type(a.atttypid, NULL) || ':' || "
                                                 "a.attnotnull || ':' || (d.oid IS NULL), ',' "
                                                 "ORDER BY a.attname) FROM pg_attribute a LEFT "
                                                 "JOIN pg_attrdef d ON d.adrelid = a.attrelid "
                                                 "AND d.adnum = a.attnum WHERE a.attrelid = '") +
                                         kSchema + "." + table +
                                         "'::regclass AND a.attname IN ('boot_epoch', "
                                         "'emit_seq') AND NOT a.attisdropped") ==
              "boot_epoch:bigint:false:true,emit_seq:bigint:false:true");
    }
    // The order table: exactly the full regime machine's columns, in this order.
    CHECK(column_shape(db.dsn(), "guardian_agent_order") ==
          "agent_id:text:true,epoch:bigint:false,emit_seq_hwm:bigint:false,"
          "epoch_recv_ns:bigint:false,retired_epoch:bigint:false,unpaired_recv_ns:bigint:false,"
          "unpaired_events:bigint:true,unpaired_held:bigint:true,pair_regressions:bigint:true,"
          "pair_stragglers:bigint:true,pair_recoveries:bigint:true,pair_duplicates:bigint:true,"
          "retired_events:bigint:true");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM pg_attrdef d JOIN "
                                             "pg_attribute a ON a.attrelid = d.adrelid AND "
                                             "a.attnum = d.adnum WHERE d.adrelid = '") +
                                     kSchema +
                                     ".guardian_agent_order'::regclass AND "
                                     "pg_get_expr(d.adbin, d.adrelid) = '0'") == "7");
    CHECK(
        query_scalar(db.dsn(), std::string("SELECT conname || ':' || contype::text || ':' "
                                           "|| conkey::text FROM pg_constraint WHERE contype = 'p' "
                                           "AND conrelid = '") +
                                   kSchema + ".guardian_agent_order'::regclass") ==
        "guardian_agent_order_pkey:p:{1}");
    // The tripwire function carries the pair test (the shape check pins the same three fragments).
    const std::string def =
        query_scalar(db.dsn(), std::string("SELECT pg_get_functiondef('") + kSchema +
                                   ".guardian_agent_rule_status_flag_legacy_write'::regproc)");
    CHECK(def.find("NEW.boot_epoch IS NOT NULL") != std::string::npos);
    CHECK(def.find("NEW.boot_epoch IS NOT DISTINCT FROM OLD.boot_epoch") != std::string::npos);
    CHECK(def.find("NEW.emit_seq IS NOT DISTINCT FROM OLD.emit_seq") != std::string::npos);
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guardian_agent_order") == "0");
}

TEST_CASE("census ordering: v5 over a v4 database keeps the census with a NULL pair and the "
          "sequence continues",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    downgrade_to_v4(db.dsn());
    insert_rule(db.dsn(), "r1");
    for (int i = 1; i <= 3; ++i) {
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, agent_id, "
                               "event_type, severity, timestamp) VALUES ('e" +
                               std::to_string(i) +
                               "', 'r1', 'a1', 'drift.detected', 'high', "
                               "'2026-04-19T12:00:00Z')");
    }
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at, "
                           "key_ns, ingest_seq, ts_hwm, seq_hwm, hwm_recv_ns) VALUES ('a1', "
                           "'r1', 'drifted', '2026-04-19T12:00:00Z', 11, 3, 11, 3, 12)");
    const std::string max_before =
        query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) FROM ") + kSchema +
                                   ".guaranteed_state_events");

    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "5");
    // The v4 census row is untouched; its pair is NULL (unordered), as is every event's.
    CHECK(query_scalar(db.dsn(), std::string("SELECT state || '|' || key_ns || '|' || ingest_seq "
                                             "|| '|' || (boot_epoch IS NULL) || '|' || "
                                             "(emit_seq IS NULL) || '|' || order_uncertain FROM ") +
                                     kSchema + ".guardian_agent_rule_status") ==
          "drifted|11|3|true|true|false");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE boot_epoch IS NOT NULL OR "
                                     "emit_seq IS NOT NULL") == "0");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guaranteed_state_events") == "3");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guardian_agent_order") == "0");
    // The identity sequence was not reset by the v5 apply.
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp) VALUES ('e4', 'r1', 'a1', 'drift.detected', "
                           "'high', 't')");
    CHECK(std::stoll(query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) FROM ") + kSchema +
                                                ".guaranteed_state_events")) >
          std::stoll(max_before));
}

TEST_CASE("census ordering: replaying v5 over a used v5 changes nothing",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    insert_rule(db.dsn(), "r1");
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, boot_epoch, emit_seq) VALUES ('e1', 'r1', 'a1', "
                           "'drift.detected', 'high', 't', 7, 9)");
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at, "
                           "key_ns, ingest_seq, boot_epoch, emit_seq) VALUES ('a1', 'r1', "
                           "'drifted', 't', 5, 1, 7, 9)");
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_order (agent_id, epoch, emit_seq_hwm, epoch_recv_ns, "
                           "retired_epoch, unpaired_recv_ns, unpaired_events, unpaired_held, "
                           "pair_regressions, pair_stragglers, pair_recoveries, pair_duplicates, "
                           "retired_events) VALUES ('a1', 7, 9, 100, 3, 50, 1, 2, 3, 4, 5, 6, 7)");
    const std::string objs =
        "SELECT md5(string_agg(c.oid::text || a.attnum::text || a.attname || a.attnotnull, ',' "
        "ORDER BY c.oid, a.attnum)) FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
        "AND a.attnum > 0 AND NOT a.attisdropped WHERE c.relnamespace = "
        "'guaranteed_state_store'::regnamespace AND c.relkind IN ('r', 'i')";
    const std::string rows =
        std::string("SELECT (SELECT string_agg(g::text, ';') FROM ") + kSchema +
        ".guardian_agent_order g) || '#' || (SELECT string_agg(e.boot_epoch || '/' || e.emit_seq, "
        "';') FROM " +
        kSchema +
        ".guaranteed_state_events e) || '#' || (SELECT string_agg(c.boot_epoch || '/' || "
        "c.emit_seq || '/' || c.order_uncertain, ';') FROM " +
        kSchema + ".guardian_agent_rule_status c)";
    const std::string fn = std::string("SELECT md5(pg_get_functiondef('") + kSchema +
                           ".guardian_agent_rule_status_flag_legacy_write'::regproc))";
    const std::string objs_before = query_scalar(db.dsn(), objs);
    const std::string rows_before = query_scalar(db.dsn(), rows);
    const std::string fn_before = query_scalar(db.dsn(), fn);
    REQUIRE_FALSE(rows_before.empty());

    // The remedy for a v5-only defect: stamp 4, so the v5 migration text runs again.
    exec_sql(db.dsn(), "UPDATE public.schema_meta SET version = 4 "
                       "WHERE store = 'guaranteed_state_store'");
    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "5");
    CHECK(query_scalar(db.dsn(), objs) == objs_before);
    CHECK(query_scalar(db.dsn(), rows) == rows_before);
    CHECK(query_scalar(db.dsn(), fn) == fn_before);
}

TEST_CASE("census ordering: the v5 tripwire flags a verdict change that leaves a paired row's "
          "pair unchanged and nothing else new",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    insert_rule(db.dsn(), "r1");
    const std::string st = std::string(kSchema) + ".guardian_agent_rule_status";
    auto flagged = [&](const char* agent) {
        return query_scalar(db.dsn(), "SELECT order_uncertain FROM " + st + " WHERE agent_id = '" +
                                          agent + "'");
    };
    exec_sql(db.dsn(), "INSERT INTO " + st +
                           " (agent_id, rule_id, state, updated_at, key_ns, ingest_seq, "
                           "boot_epoch, emit_seq) VALUES ('paired_same', 'r1', 'compliant', 't', "
                           "1, 1, 5, 10), ('paired_moved', 'r1', 'compliant', 't', 1, 1, 5, 10), "
                           "('paired_unkeyed', 'r1', 'compliant', 't', 1, 1, 5, 10)");
    exec_sql(db.dsn(), "INSERT INTO " + st +
                           " (agent_id, rule_id, state, updated_at, key_ns, ingest_seq) VALUES "
                           "('unpaired_moved', 'r1', 'compliant', 't', 1, 1), "
                           "('unpaired_same', 'r1', 'compliant', 't', 1, 1)");
    // The v5 rule: the verdict changed, the ordering tuple moved, the NON-NULL pair did not.
    exec_sql(db.dsn(), "UPDATE " + st +
                           " SET state = 'drifted', key_ns = 2, ingest_seq = 2 "
                           "WHERE agent_id = 'paired_same'");
    CHECK(flagged("paired_same") == "t");
    // The pair moved with the verdict: this version's own upsert, clean.
    exec_sql(db.dsn(), "UPDATE " + st +
                           " SET state = 'drifted', key_ns = 2, ingest_seq = 2, "
                           "boot_epoch = 5, emit_seq = 11 WHERE agent_id = 'paired_moved'");
    CHECK(flagged("paired_moved") == "f");
    // The v4 rule is kept: the ordering tuple did not move.
    exec_sql(db.dsn(), "UPDATE " + st +
                           " SET state = 'drifted', boot_epoch = 5, emit_seq = 11 "
                           "WHERE agent_id = 'paired_unkeyed'");
    CHECK(flagged("paired_unkeyed") == "t");
    // A v4 write to an unpaired row is as clean as under v4.
    exec_sql(db.dsn(), "UPDATE " + st +
                           " SET state = 'drifted', key_ns = 2, ingest_seq = 2 "
                           "WHERE agent_id = 'unpaired_moved'");
    CHECK(flagged("unpaired_moved") == "f");
    exec_sql(db.dsn(), "UPDATE " + st + " SET state = 'drifted' WHERE agent_id = 'unpaired_same'");
    CHECK(flagged("unpaired_same") == "t");
}

TEST_CASE("census ordering: an adopted v5 object not as this version creates it is refused",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    const std::string ev = std::string(kSchema) + ".guaranteed_state_events";
    const std::string st = std::string(kSchema) + ".guardian_agent_rule_status";
    const std::string ord = std::string(kSchema) + ".guardian_agent_order";

    std::string expect; // the named defect each section must be refused for

    SECTION("events.boot_epoch is INTEGER") {
        expect = "guaranteed_state_events.boot_epoch";
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ALTER COLUMN boot_epoch TYPE integer");
    }
    SECTION("events.emit_seq is NOT NULL") {
        expect = "guaranteed_state_events.emit_seq";
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ALTER COLUMN emit_seq SET NOT NULL");
    }
    SECTION("the census boot_epoch has a default") {
        expect = "guardian_agent_rule_status.boot_epoch";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN boot_epoch SET DEFAULT 0");
    }
    SECTION("the census emit_seq column is missing") {
        expect = "guardian_agent_rule_status.emit_seq";
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN emit_seq");
    }
    SECTION("the agent table is missing") {
        expect = "table guardian_agent_order(permanent, ordinary)";
        exec_sql(db.dsn(), "DROP TABLE " + ord);
    }
    SECTION("the agent table is unlogged") {
        expect = "table guardian_agent_order(permanent, ordinary)";
        exec_sql(db.dsn(), "ALTER TABLE " + ord + " SET UNLOGGED");
    }
    SECTION("an agent table column is of the wrong type") {
        expect = "guardian_agent_order.emit_seq_hwm";
        exec_sql(db.dsn(), "ALTER TABLE " + ord + " ALTER COLUMN emit_seq_hwm TYPE integer");
    }
    SECTION("an agent table counter lost its default") {
        expect = "guardian_agent_order.pair_duplicates";
        exec_sql(db.dsn(), "ALTER TABLE " + ord + " ALTER COLUMN pair_duplicates DROP DEFAULT");
    }
    SECTION("an agent table counter is nullable") {
        expect = "guardian_agent_order.retired_events";
        exec_sql(db.dsn(), "ALTER TABLE " + ord + " ALTER COLUMN retired_events DROP NOT NULL");
    }
    SECTION("an agent table column is missing") {
        expect = "guardian_agent_order.pair_stragglers";
        exec_sql(db.dsn(), "ALTER TABLE " + ord + " DROP COLUMN pair_stragglers");
    }
    SECTION("the agent table primary key was renamed") {
        expect = "order table primary key guardian_agent_order_pkey(agent_id)";
        exec_sql(db.dsn(), "ALTER TABLE " + ord +
                               " RENAME CONSTRAINT guardian_agent_order_pkey TO adopted_pk");
    }
    SECTION("the tripwire function body is v4's, without the pair test") {
        expect = "guardian_agent_rule_status_flag_legacy_write(pair test)";
        replace_tripwire_body(db.dsn(), kV4TripwireBody);
    }
    SECTION("the tripwire function tests the epoch but not the sequence") {
        expect = "guardian_agent_rule_status_flag_legacy_write(pair test)";
        replace_tripwire_body(
            db.dsn(),
            "BEGIN IF (NEW.state IS DISTINCT FROM OLD.state) AND ((NEW.key_ns IS NOT DISTINCT "
            "FROM OLD.key_ns) OR (NEW.boot_epoch IS NOT NULL AND NEW.boot_epoch IS NOT DISTINCT "
            "FROM OLD.boot_epoch)) THEN NEW.order_uncertain := true; END IF; RETURN NEW; END");
    }
    SECTION("the tripwire function tests the sequence but not the epoch") {
        expect = "guardian_agent_rule_status_flag_legacy_write(pair test)";
        replace_tripwire_body(
            db.dsn(),
            "BEGIN IF (NEW.state IS DISTINCT FROM OLD.state) AND ((NEW.key_ns IS NOT DISTINCT "
            "FROM OLD.key_ns) OR (NEW.boot_epoch IS NOT NULL AND NEW.emit_seq IS NOT DISTINCT "
            "FROM OLD.emit_seq)) THEN NEW.order_uncertain := true; END IF; RETURN NEW; END");
    }
    SECTION("the tripwire function tests the pair but not that it is non-NULL") {
        expect = "guardian_agent_rule_status_flag_legacy_write(pair test)";
        replace_tripwire_body(
            db.dsn(),
            "BEGIN IF (NEW.state IS DISTINCT FROM OLD.state) AND ((NEW.key_ns IS NOT DISTINCT "
            "FROM OLD.key_ns) OR (NEW.boot_epoch IS NOT DISTINCT FROM OLD.boot_epoch AND "
            "NEW.emit_seq IS NOT DISTINCT FROM OLD.emit_seq)) THEN NEW.order_uncertain := true; "
            "END IF; RETURN NEW; END");
    }

    REQUIRE_FALSE(expect.empty()); // a section that forgets its token would pass vacuously
    const OpenAttempt a = try_open(db.dsn());
    CHECK_FALSE(a.open);
    CHECK(a.log.find("unsupported schema, refusing to start") != std::string::npos);
    CHECK(a.log.find("v5: object not as this version creates it") != std::string::npos);
    CHECK(a.log.find(expect) != std::string::npos);
    // The remedy of a defect only v5 has resets to 4, never to 3.
    CHECK(a.log.find("SET version = 4 WHERE store = 'guaranteed_state_store'") !=
          std::string::npos);
    CHECK(a.log.find("SET version = 3") == std::string::npos);
}

TEST_CASE("census ordering: a defect v4 also has keeps v4's text and its reset to version 3",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_pending");
    SECTION("alone") {}
    SECTION("beside a v5 defect, v4 is reported first") {
        exec_sql(db.dsn(), std::string("DROP TABLE ") + kSchema + ".guardian_agent_order");
    }
    const OpenAttempt a = try_open(db.dsn());
    CHECK_FALSE(a.open);
    CHECK(a.log.find("v4: object not as this version creates it") != std::string::npos);
    CHECK(a.log.find("idx_gse_pending") != std::string::npos);
    CHECK(a.log.find("SET version = 3 WHERE store = 'guaranteed_state_store'") !=
          std::string::npos);
    CHECK(a.log.find("v5: object not as") == std::string::npos);
    CHECK(a.log.find("SET version = 4") == std::string::npos);
}

TEST_CASE("census ordering: a hand-broken object makes the v5 migration refuse and not stamp",
          "[pg][guaranteed_state_store][db][census][ordering][schema][pair]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    downgrade_to_v4(db.dsn());
    const std::string ev = std::string(kSchema) + ".guaranteed_state_events";

    SECTION("an adopted events.boot_epoch of the wrong type") {
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ADD COLUMN boot_epoch integer");
    }
    SECTION("an adopted agent table of the wrong shape") {
        exec_sql(db.dsn(),
                 std::string("CREATE TABLE ") + kSchema + ".guardian_agent_order (agent_id text)");
    }
    SECTION("an adopted agent table with a renamed primary key") {
        exec_sql(db.dsn(), std::string("CREATE TABLE ") + kSchema +
                               ".guardian_agent_order (agent_id text CONSTRAINT adopted_pk "
                               "PRIMARY KEY, epoch bigint, emit_seq_hwm bigint, epoch_recv_ns "
                               "bigint, retired_epoch bigint, unpaired_recv_ns bigint, "
                               "unpaired_events bigint NOT NULL DEFAULT 0, unpaired_held bigint "
                               "NOT NULL DEFAULT 0, pair_regressions bigint NOT NULL DEFAULT 0, "
                               "pair_stragglers bigint NOT NULL DEFAULT 0, pair_recoveries "
                               "bigint NOT NULL DEFAULT 0, pair_duplicates bigint NOT NULL "
                               "DEFAULT 0, retired_events bigint NOT NULL DEFAULT 0)");
    }
    CHECK_FALSE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "4"); // not stamped
    // The migration rolled back as a whole: the half it had applied is gone too.
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_attribute WHERE attrelid = '" + ev +
                                     "'::regclass AND attname = 'emit_seq' AND NOT "
                                     "attisdropped") == "0");
}

// ── C3: the key, the pending evidence, the fold, the upsert and the clear ───────────────────

namespace {

constexpr std::int64_t kBase = 1'700'000'000'000'000'000LL; // a plausible receipt instant, ns
constexpr std::int64_t kCapNs = 300'000'000'000LL;          // the +300 s receipt skew bound

GuaranteedStateEventRow ev(std::string id, std::string rule, std::string agent, std::string type,
                           std::int64_t agent_ns, std::int64_t received_ns = kBase) {
    GuaranteedStateEventRow e;
    e.event_id = std::move(id);
    e.rule_id = std::move(rule);
    e.agent_id = std::move(agent);
    e.event_type = std::move(type);
    e.severity = "high";
    e.guard_type = "registry";
    e.guard_category = "event";
    e.detected_value = "0";
    e.expected_value = "1";
    e.remediation_action = "registry-write";
    e.remediation_success = true;
    e.timestamp = "2026-04-19T12:00:00Z";
    e.agent_ns = agent_ns;
    e.received_ns = received_ns;
    return e;
}

constexpr const char* kCompliant = "guard.compliant";
constexpr const char* kDrifted = "drift.detected";
constexpr const char* kErrored = "guard.unhealthy";

// "state|key_ns|ts_hwm|order_uncertain" with NULL as "-".
std::string census(const std::string& dsn, const std::string& agent, const std::string& rule) {
    return query_scalar(dsn,
                        std::string("SELECT state || '|' || COALESCE(key_ns::text, '-') || '|' "
                                    "|| COALESCE(ts_hwm::text, '-') || '|' || order_uncertain "
                                    "FROM ") +
                            kSchema + ".guardian_agent_rule_status WHERE agent_id = '" + agent +
                            "' AND rule_id = '" + rule + "'");
}

// "boot_epoch/emit_seq" of a census row with NULL as "-" ("-/-" is an unpaired verdict).
std::string census_pair_text(const std::string& dsn, const std::string& agent,
                             const std::string& rule) {
    return query_scalar(dsn, std::string("SELECT COALESCE(boot_epoch::text, '-') || '/' || "
                                         "COALESCE(emit_seq::text, '-') FROM ") +
                                 kSchema + ".guardian_agent_rule_status WHERE agent_id = '" + agent +
                                 "' AND rule_id = '" + rule + "'");
}

// The same for the stored event row (the first-delivery pair, written once).
std::string event_pair_text(const std::string& dsn, const std::string& event_id) {
    return query_scalar(dsn, std::string("SELECT COALESCE(boot_epoch::text, '-') || '/' || "
                                         "COALESCE(emit_seq::text, '-') FROM ") +
                                 kSchema + ".guaranteed_state_events WHERE event_id = '" +
                                 event_id + "'");
}

GuaranteedStateEventRow with_pair(GuaranteedStateEventRow e, std::int64_t epoch,
                                  std::int64_t seq) {
    e.boot_epoch = epoch;
    e.emit_seq = seq;
    return e;
}

std::string pending_count(const std::string& dsn) {
    return query_scalar(dsn, std::string("SELECT count(*) FROM ") + kSchema +
                                 ".guaranteed_state_events WHERE projection_pending");
}

std::string key_str(std::int64_t v) {
    return std::to_string(v);
}

void install_census_fail(const std::string& dsn, const char* when_sql) {
    exec_sql(dsn, std::string("CREATE FUNCTION ") + kSchema +
                      ".yuzu_test_ord_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " +
                      when_sql +
                      " THEN RAISE EXCEPTION 'forced census failure' USING ERRCODE = "
                      "'XX000'; END IF; RETURN NEW; END $$");
    exec_sql(dsn, std::string("CREATE TRIGGER yuzu_test_ord_fail BEFORE INSERT OR UPDATE ON ") +
                      kSchema + ".guardian_agent_rule_status FOR EACH ROW EXECUTE FUNCTION " +
                      kSchema + ".yuzu_test_ord_fail()");
}

void remove_census_fail(const std::string& dsn) {
    exec_sql(dsn, std::string("DROP TRIGGER yuzu_test_ord_fail ON ") + kSchema +
                      ".guardian_agent_rule_status");
}

// Holds the census lock barrier at its first hit so a test can park one writer right after it took
// the pair's pending rows. `release()` is idempotent.
struct BarrierHold {
    std::promise<void> reached_p;
    std::promise<void> release_p;
    std::future<void> reached_f = reached_p.get_future();
    std::shared_future<void> release_f = release_p.get_future().share();
    std::atomic<int> calls{0};
    std::atomic<bool> released{false};
    void hit() {
        if (calls.fetch_add(1) == 0) {
            reached_p.set_value();
            release_f.wait();
        }
    }
    void release() {
        if (!released.exchange(true))
            release_p.set_value();
    }
};

// Owns the writer threads of a concurrency test. RULE: every local a thread touches (result slots,
// flags, strings) is declared BEFORE the owner so it outlives the join. On scope exit (including a
// failed REQUIRE) it releases the barrier, joins every thread, and only then clears the store's
// barrier, so a failure is a red test and never std::terminate on a joinable thread or a barrier
// pointing at dead locals.
class WriterThreads {
public:
    WriterThreads(GuaranteedStateStore& store, BarrierHold* hold) : store_(store), hold_(hold) {}
    WriterThreads(const WriterThreads&) = delete;
    WriterThreads& operator=(const WriterThreads&) = delete;
    ~WriterThreads() { join_all(); }
    template <class F> void start(F&& f) { threads_.emplace_back(std::forward<F>(f)); }
    void join_all() {
        if (hold_ != nullptr)
            hold_->release();
        for (auto& t : threads_)
            if (t.joinable())
                t.join();
        threads_.clear();
        store_.set_census_lock_barrier_for_test({});
    }

private:
    GuaranteedStateStore& store_;
    BarrierHold* hold_;
    std::vector<std::thread> threads_;
};

// Poll until `n` backends in this database wait on a lock of `wait_event` (any lock when empty).
// This observes that a writer really parked, which a fixed sleep cannot.
bool wait_for_lock_waiters(const std::string& dsn, int n, const std::string& wait_event = {}) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    const std::string sql =
        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND "
        "wait_event_type = 'Lock'" +
        (wait_event.empty() ? std::string{} : " AND wait_event = '" + wait_event + "'");
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::stoi(query_scalar(dsn, sql)) >= n)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

} // namespace

TEST_CASE(
    "census ordering: the later key wins whatever the arrival order and says when it is unsure",
    "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    SECTION("in order: the newer verdict replaces the older, no doubt") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("out of order: the older key arrives last, is refused, and the row is flagged") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
        CHECK(store.event_count() == 2); // the refused event is still audited
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("the same key: the later INSERT-allocated sequence wins") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        // Arrival order is all that separates them, and it is not emission order: flagged.
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 100) + "|" + key_str(kBase + 100) + "|true");
    }
    SECTION("the same key and the same verdict: nothing to doubt") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 100) + "|" + key_str(kBase + 100) + "|false");
    }
    SECTION("a same-key flag clears on the next key strictly above the mark") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        REQUIRE(census(db.dsn(), "a", "r1").ends_with("|true"));
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kErrored, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");
    }
    SECTION("a same-key pair with an unusable key is already flagged by the key, not by the tie") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, 0)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, 0)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1").ends_with("|true"));
    }
    SECTION(
        "an arrival that is newer in sequence but older in key leaves the verdict and flags it") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kErrored, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
    }
    SECTION("a clean in-order event after a flag keeps it until a key strictly above the mark") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted); // flagged
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kErrored, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted); // same key as the mark: still unsure
        CHECK(census(db.dsn(), "a", "r1").ends_with("|true"));
        REQUIRE(
            store.insert_event_classified(ev("e4", "r1", "a", kCompliant, kBase + 400)).outcome ==
            EventInsertOutcome::Inserted); // strictly above: clears
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 400) + "|" + key_str(kBase + 400) + "|false");
    }
}

TEST_CASE("census ordering: the derived key is the agent stamp bounded by receipt plus 300 s",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto key_of = [&](const char* id) {
        return query_scalar(db.dsn(),
                            std::string("SELECT proj_key || '|' || proj_key_capped FROM ") +
                                kSchema + ".guaranteed_state_events WHERE event_id = '" + id + "'");
    };

    SECTION("a stamp inside the bound is the key and is not capped") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase - 5)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(key_of("e1") == key_str(kBase - 5) + "|false");
        CHECK(census(db.dsn(), "a", "r1").ends_with("|false"));
    }
    SECTION("a stamp past receipt plus 300 s is capped to it and the verdict is flagged") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000 * kCapNs))
                    .outcome == EventInsertOutcome::Inserted);
        CHECK(key_of("e1") == key_str(kBase + kCapNs) + "|true");
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + kCapNs) + "|" + key_str(kBase + kCapNs) + "|true");
    }
    SECTION("an absent stamp is key 0, flagged, with no high-water mark") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, 0)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(key_of("e1") == "0|false");
        CHECK(census(db.dsn(), "a", "r1") == "drifted|0|-|true");
    }
    SECTION("a zero receipt means the store's own clock") {
        // kBase is in the past of the store's clock, so it is uncapped; with a receipt of 0 taken
        // literally the bound would be 300 s and the key would be capped to 300000000000.
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase, 0)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(key_of("e1") == key_str(kBase) + "|false");
    }
}

TEST_CASE("census ordering: events with no census meaning or no ids never carry pending evidence",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    install_census_fail(db.dsn(), "true"); // any census write would fail and leave evidence

    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", "guard.armed", kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("e2", "", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted); // a direct store caller: ingest refuses these earlier
    REQUIRE(store.insert_event_classified(ev("e3", "r1", "", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(store.census_proj_failures_total() == 0);
}

TEST_CASE(
    "census ordering: a failed projection leaves pending evidence and a redelivery repairs it",
    "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);

    install_census_fail(db.dsn(), "NEW.state = 'drifted'");
    const auto e2 = ev("e2", "r1", "a", kDrifted, kBase + 200);
    REQUIRE(store.insert_event_classified(e2).outcome == EventInsertOutcome::Inserted);
    CHECK(store.census_proj_failures_total() == 1);
    CHECK(pending_count(db.dsn()) == "1");
    CHECK(census(db.dsn(), "a", "r1").starts_with("compliant|"));
    remove_census_fail(db.dsn());

    CHECK(store.insert_event_classified(e2).outcome == EventInsertOutcome::Redelivered);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");

    // A second redelivery of the now-retired event changes nothing.
    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guardian_agent_rule_status SET state = 'errored'");
    CHECK(store.insert_event_classified(e2).outcome == EventInsertOutcome::Redelivered);
    CHECK(census(db.dsn(), "a", "r1").starts_with("errored|"));
}

TEST_CASE("census ordering: a transaction aborted before commit is refused and stores nothing",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const std::string events =
        std::string("SELECT count(*) FROM ") + kSchema + ".guaranteed_state_events";
    // Aborts the open transaction right before the health check, as a failed DEX savepoint
    // release would; without the check COMMIT of an aborted transaction reports success.
    const auto abort_txn = [](void* conn) {
        const pg::PgResult aborted{PQexec(static_cast<PGconn*>(conn), "SELECT 1/0")};
    };

    SECTION("a plain census-bearing event") {
        store.set_pre_commit_hook_for_test(abort_txn);
        const auto r = store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase));
        CHECK(r.outcome == EventInsertOutcome::Error);
        CHECK(r.error.find("transaction aborted before commit") != std::string::npos);
        store.set_pre_commit_hook_for_test(nullptr);
        CHECK(query_scalar(db.dsn(), events) == "0");
        CHECK(census(db.dsn(), "a", "r1").empty());
    }
    SECTION("a reserved-rule observation, which carries no census meaning") {
        store.set_pre_commit_hook_for_test(abort_txn);
        auto obs = ev("__observation__-1-0", "__observation__", "a", "process.crashed", kBase);
        obs.guard_category = "";
        const auto r = store.insert_event_classified(obs);
        CHECK(r.outcome == EventInsertOutcome::Error);
        CHECK(r.error.find("transaction aborted before commit") != std::string::npos);
        store.set_pre_commit_hook_for_test(nullptr);
        CHECK(query_scalar(db.dsn(), events) == "0");
    }
    SECTION("the repair of a redelivered pending event") {
        install_census_fail(db.dsn(), "NEW.state = 'drifted'");
        const auto e1 = ev("e1", "r1", "a", kDrifted, kBase + 100);
        REQUIRE(store.insert_event_classified(e1).outcome == EventInsertOutcome::Inserted);
        REQUIRE(pending_count(db.dsn()) == "1");
        remove_census_fail(db.dsn());

        store.set_pre_commit_hook_for_test(abort_txn);
        const auto r = store.insert_event_classified(e1);
        CHECK(r.outcome == EventInsertOutcome::Error);
        CHECK(r.error.find("transaction aborted before the repair commit") != std::string::npos);
        store.set_pre_commit_hook_for_test(nullptr);
        CHECK(pending_count(db.dsn()) == "1"); // nothing was retired by the refused repair
        CHECK(census(db.dsn(), "a", "r1").empty());

        // A later redelivery with a healthy transaction still repairs it.
        CHECK(store.insert_event_classified(e1).outcome == EventInsertOutcome::Redelivered);
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("a batch") {
        store.set_pre_commit_hook_for_test(abort_txn);
        const auto n = store.insert_events(
            {ev("b1", "r1", "a", kDrifted, kBase), ev("b2", "r1", "a", kCompliant, kBase + 1)});
        REQUIRE_FALSE(n.has_value());
        CHECK(n.error().find("transaction aborted before commit") != std::string::npos);
        store.set_pre_commit_hook_for_test(nullptr);
        CHECK(query_scalar(db.dsn(), events) == "0");
    }
}

TEST_CASE("census ordering: two failed projections then a repair keep the disagreement",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    // Astra SQL pass Q2: H (key 120, seq lower) and L (key 110, seq higher) both fail and stay
    // pending; repairing H folds L, applies H and retires both. Delivered one at a time the same
    // two events leave the row flagged, so the repair must too.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);

    install_census_fail(db.dsn(), "true");
    const auto h = ev("eH", "r1", "a", kCompliant, kBase + 120);
    const auto l = ev("eL", "r1", "a", kDrifted, kBase + 110);
    REQUIRE(store.insert_event_classified(h).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(l).outcome == EventInsertOutcome::Inserted);
    CHECK(pending_count(db.dsn()) == "2");
    remove_census_fail(db.dsn());

    CHECK(store.insert_event_classified(h).outcome == EventInsertOutcome::Redelivered);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 120) + "|" + key_str(kBase + 120) + "|true");
}

TEST_CASE("census ordering: a rule that is gone rejects the census write and keeps the event",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    // No rule row: the census foreign key refuses the write (23503). The event is audit evidence
    // and stays, but it must not stay pending: there is nothing to project it onto.
    REQUIRE(store.insert_event_classified(ev("e1", "ghost", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(store.event_count() == 1);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "ghost").empty());
    CHECK(store.census_proj_failures_total() == 0); // a rejection is not a fault
}

TEST_CASE("census ordering: the batch path orders by key and rolls back on a failed projection",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto n = store.insert_events(
        {ev("b1", "r1", "a", kDrifted, kBase + 200), ev("b2", "r1", "a", kCompliant, kBase + 100)});
    REQUIRE(n.has_value());
    CHECK(*n == 2);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");

    // The batch path records no pending evidence, so a failed projection aborts the whole batch:
    // neither event is stored and the census row is unchanged.
    install_census_fail(db.dsn(), "true");
    const auto events_before = store.event_count();
    REQUIRE(events_before == 2); // a degraded read returns 0; the comparison below must not be vacuous
    const auto m = store.insert_events(
        {ev("b3", "r1", "a", kErrored, kBase + 300), ev("b4", "r1", "a", kDrifted, kBase + 400)});
    REQUIRE_FALSE(m.has_value());
    CHECK(m.error().find("batch rolled back") != std::string::npos);
    CHECK(store.event_count() == events_before);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
}

TEST_CASE("census ordering: a sequence collision is an operational error and never a redelivery",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    // Reseed the sequence at an already used value (an operator reset gone wrong).
    exec_sql(db.dsn(), std::string("SELECT setval('") + kSchema +
                           ".guaranteed_state_events_ingest_seq_seq', 1, false)");

    const auto r = store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 1));
    CHECK(r.outcome == EventInsertOutcome::Error);
    CHECK(r.error.find("ingest sequence collision") != std::string::npos);
    CHECK(store.events_ingest_errors_total() == 1);
    CHECK(store.event_count() == 1);
}

TEST_CASE("census ordering: two repairs of one pair lock in one order and never deadlock",
          "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    // Two pending events of one pair. Writer A repairs the LATER one and is held right after the
    // pair-lock statement; writer B repairs the EARLIER one and must PARK on the first row A holds
    // (observed through pg_stat_activity) instead of closing a lock cycle (40P01). Once A has
    // retired both rows B finds its own evidence gone.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);

    install_census_fail(db.dsn(), "true");
    const auto first = ev("p1", "r1", "a", kDrifted, kBase + 200);
    const auto second = ev("p2", "r1", "a", kCompliant, kBase + 300);
    REQUIRE(store.insert_event_classified(first).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(second).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    REQUIRE(pending_count(db.dsn()) == "2");
    const auto failures_before = store.census_proj_failures_total();

    // Every local a writer thread touches is declared BEFORE `writers`, so on unwinding the owner
    // joins the threads before those locals are destroyed.
    EventInsertResult a_res;
    EventInsertResult b_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] { a_res = store.insert_event_classified(second); });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    writers.start([&] { b_res = store.insert_event_classified(first); });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1)); // B is parked on A's row lock
    writers.join_all();

    CHECK(a_res.outcome == EventInsertOutcome::Redelivered);
    CHECK(b_res.outcome == EventInsertOutcome::Redelivered);
    CHECK(store.census_proj_failures_total() == failures_before); // no 40P01 became a Failed
    CHECK(pending_count(db.dsn()) == "0");
    // p2 outranks p1 in both key and arrival order, so there is nothing to doubt.
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|false");
}

// ── C4: rule delete, the reaper exemption and the pending gauge ──────────────────────────────

TEST_CASE("census ordering: the pending gauge counts stored evidence and reports an error instead "
          "of zero",
          "[pg][guaranteed_state_store][db][census][ordering][gauge]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    CHECK(store.pending_projection_count_checked().value() == 0);

    install_census_fail(db.dsn(), "true");
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("e2", "r1", "b", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(store.pending_projection_count_checked().value() == 2);
    remove_census_fail(db.dsn());
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Redelivered);
    CHECK(store.pending_projection_count_checked().value() == 1);

    PgPool dead{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    yuzu::MetricsRegistry metrics;
    GuaranteedStateStore closed(dead);
    closed.set_metrics(&metrics);
    CHECK_FALSE(closed.pending_projection_count_checked().has_value());
    // A failed read is counted as a read degrade; only the reason depends on how the pool fails.
    // It is attributed to its own source, not to the DEX family.
    double census = 0;
    double dex = 0;
    for (const char* reason : {"store_not_open", "pool_acquire_timeout", "query_error"}) {
        census += metrics
                      .counter("yuzu_server_guardian_read_degrade_total",
                               {{"reason", reason}, {"source", "guardian_census"}})
                      .value();
        dex += metrics
                   .counter("yuzu_server_guardian_read_degrade_total",
                            {{"reason", reason}, {"source", "guardian_state"}})
                   .value();
    }
    CHECK(census >= 1);
    CHECK(dex == 0);
}

TEST_CASE("census ordering: the reaper keeps an expired event that still carries pending evidence",
          "[pg][guaranteed_state_store][db][census][ordering][reaper]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    store.reap_expired(); // consume the bootstrap decline on an empty table

    for (int i = 0; i < 3; ++i)
        REQUIRE(store
                    .insert_event_classified(
                        ev("fresh-" + std::to_string(i), "r1", "f", kDrifted, kBase))
                    .outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("stale-ok", "r1", "s", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    REQUIRE(
        store.insert_event_classified(ev("stale-pending", "r1", "p", kDrifted, kBase)).outcome ==
        EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guaranteed_state_events SET ttl_expires_at = 1 "
                           "WHERE event_id LIKE 'stale-%'");

    store.reap_expired();
    CHECK(store.events_reaped_total() == 1); // only the one with nothing pending
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'stale-pending'") ==
          "1");

    // Once a redelivery retires the evidence, the next pass reaps it.
    REQUIRE(
        store.insert_event_classified(ev("stale-pending", "r1", "p", kDrifted, kBase)).outcome ==
        EventInsertOutcome::Redelivered);
    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guaranteed_state_events SET ttl_expires_at = 1 "
                           "WHERE event_id = 'stale-pending'");
    store.reap_expired();
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'stale-pending'") ==
          "0");
}

TEST_CASE("census ordering: delete_rule retires the rule's pending evidence and removes the rule",
          "[pg][guaranteed_state_store][db][census][ordering][delete]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));
    install_census_fail(db.dsn(), "true");
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("e2", "r2", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    REQUIRE(pending_count(db.dsn()) == "2");

    REQUIRE(store.delete_rule("r1").has_value());
    CHECK(pending_count(db.dsn()) == "1"); // r1's evidence retired, r2's untouched
    CHECK(store.event_count() == 2);       // the audit rows stay
    CHECK_FALSE(store.get_rule("r1").value().has_value());

    // A missing rule is "not found" and undoes the retire it would have done.
    exec_sql(db.dsn(), std::string("DELETE FROM ") + kSchema +
                           ".guaranteed_state_rules WHERE rule_id = 'r2'");
    REQUIRE(pending_count(db.dsn()) == "1");
    const auto gone = store.delete_rule("r2");
    REQUIRE_FALSE(gone.has_value());
    CHECK(gone.error().starts_with("not found"));
    CHECK(pending_count(db.dsn()) == "1");
}

TEST_CASE(
    "census ordering: delete_rule waits on a repair that holds the pair's rows without a deadlock",
    "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    const auto p = ev("p1", "r1", "a", kDrifted, kBase + 200);
    REQUIRE(store.insert_event_classified(p).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    const auto failures_before = store.census_proj_failures_total();

    EventInsertResult repair_res;
    std::expected<void, std::string> del_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] { repair_res = store.insert_event_classified(p); });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    writers.start([&] { del_res = store.delete_rule("r1"); });
    // The delete must PARK on the pending row the repair holds (it waits in its pending-rows
    // statements; a run with delete_rule not touching them at all would not wait and fail here).
    // This observes parking and completion without a deadlock. It does not pin the ORDER BY
    // ingest_seq FOR UPDATE shape of the lock statement: the retire UPDATE parks on the same row
    // without it, so the ordering claim rests on the statement's EXPLAIN (LockRows over Sort).
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1));
    writers.join_all();

    CHECK(repair_res.outcome == EventInsertOutcome::Redelivered);
    CHECK(del_res.has_value());
    CHECK(store.census_proj_failures_total() == failures_before); // no 40P01
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(*) FROM ") + kSchema +
                                     ".guardian_agent_rule_status") == "0"); // the delete cascaded
}

// ── Governance fix round: UP-1, UP-2, the write cost, the counters, the scope and the gaps ───

TEST_CASE("census ordering: a pending event that disagrees with a verdict inserted concurrently "
          "keeps the row flagged",
          "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    // The UP-1 schedule (found in review, reproduced on Postgres 18). New pair, no census row.
    //   X (key 100, seq 1) is held inside its event INSERT,
    //   W (key 200, seq 2) projects first and holds an UNCOMMITTED census INSERT,
    //   P (key 150, seq 3) is a committed pending event that arrives after W's pair lock,
    //   X then takes its pair lock (seen = [P]), its fold finds no visible row, and its upsert
    //   waits on W. Without the second fold, X retires P against W's row with the row unflagged.
    // Delivered one at a time the three events leave the row flagged, so it must stay flagged here.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    exec_sql(db.dsn(), std::string("CREATE FUNCTION ") + kSchema +
                           ".yuzu_test_hold_x() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                           "IF NEW.event_id = 'ux' THEN PERFORM pg_advisory_lock(91001); "
                           "PERFORM pg_advisory_unlock(91001); END IF; RETURN NEW; END $$");
    exec_sql(db.dsn(), std::string("CREATE TRIGGER yuzu_test_hold_x BEFORE INSERT ON ") + kSchema +
                           ".guaranteed_state_events FOR EACH ROW EXECUTE FUNCTION " + kSchema +
                           ".yuzu_test_hold_x()");
    exec_sql(db.dsn(), std::string("CREATE FUNCTION ") + kSchema +
                           ".yuzu_test_hold_w() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                           "PERFORM pg_advisory_lock(91002); PERFORM pg_advisory_unlock(91002); "
                           "RETURN NEW; END $$");
    exec_sql(db.dsn(), std::string("CREATE TRIGGER yuzu_test_hold_w AFTER INSERT ON ") + kSchema +
                           ".guardian_agent_rule_status FOR EACH ROW EXECUTE FUNCTION " + kSchema +
                           ".yuzu_test_hold_w()");

    // Declaration order is the safety argument: the result slots first (the threads write them),
    // then the owner, then the lock holder, so on a failure the holder (and its advisory locks) is
    // destroyed first, the parked writers finish, and only then are they joined.
    EventInsertResult x_res;
    EventInsertResult w_res;
    WriterThreads writers(store, nullptr);
    pg::PgConn holder{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        pg::PgResult r{
            PQexec(holder.get(), "SELECT pg_advisory_lock(91001), pg_advisory_lock(91002)")};
        REQUIRE(r.ok());
    }
    const auto unlock = [&](const char* key) {
        pg::PgResult r{
            PQexec(holder.get(), (std::string("SELECT pg_advisory_unlock(") + key + ")").c_str())};
        REQUIRE(r.ok());
    };

    writers.start([&] {
        x_res = store.insert_event_classified(ev("ux", "r1", "a", kCompliant, kBase + 100));
    });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1, "advisory")); // X holds seq 1, parked in its INSERT
    writers.start(
        [&] { w_res = store.insert_event_classified(ev("uw", "r1", "a", kDrifted, kBase + 200)); });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 2, "advisory")); // W's census INSERT is uncommitted
    // P: committed pending, seq 3, key 150 (its projection "failed" earlier).
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, proj_key, projection_pending) VALUES ('up', 'r1', "
                           "'a', 'guard.compliant', 'high', 't', " +
                           key_str(kBase + 150) + ", true)");
    unlock("91001"); // X proceeds: its pair lock sees P, its fold sees no visible census row
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1, "transactionid")); // X's upsert waits on W
    unlock("91002"); // W commits, X's upsert lands in the UPDATE arm
    writers.join_all();

    CHECK(x_res.outcome == EventInsertOutcome::Inserted);
    CHECK(w_res.outcome == EventInsertOutcome::Inserted);
    CHECK(query_scalar(db.dsn(), std::string("SELECT ingest_seq FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'ux'") == "1");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
    CHECK(pending_count(db.dsn()) ==
          "0"); // P was retired, with the disagreement recorded on the row
}

TEST_CASE("census ordering: two concurrent first deliveries to one pair match the serial result",
          "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    // With no pending rows nothing but the census row serialises two first deliveries of one pair.
    // Whatever the interleaving, the winner is the greater (key, ingest_seq) and the row is flagged
    // exactly when the later arrival (higher ingest_seq) has the lower or the same key.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const std::vector<std::pair<std::int64_t, std::int64_t>> keys = {
        {100, 200}, {200, 100}, {150, 150}, {100, 300},
        {300, 100}, {250, 251}, {251, 250}, {500, 500}};
    for (std::size_t i = 0; i < 40; ++i) {
        const std::string agent = "c" + std::to_string(i);
        const auto [ka, kb] = keys[i % keys.size()];
        std::atomic<bool> go{false};
        WriterThreads writers(store, nullptr);
        const auto run = [&](const char* id, const char* type, std::int64_t k) {
            writers.start([&store, &go, agent, id = std::string(id), type = std::string(type), k] {
                while (!go.load())
                    std::this_thread::yield();
                store.insert_event_classified(ev(id, "r1", agent, type, kBase + k));
            });
        };
        run((agent + "a").c_str(), kDrifted, ka);
        run((agent + "b").c_str(), kCompliant, kb);
        go = true;
        writers.join_all();

        const auto seq_of = [&](const std::string& id) {
            return std::stoll(query_scalar(
                db.dsn(), std::string("SELECT ingest_seq FROM ") + kSchema +
                              ".guaranteed_state_events WHERE event_id = '" + id + "'"));
        };
        const std::int64_t sa = seq_of(agent + "a");
        const std::int64_t sb = seq_of(agent + "b");
        const bool a_wins = std::make_pair(ka, sa) > std::make_pair(kb, sb);
        const std::int64_t win_key = a_wins ? ka : kb;
        const bool later_is_a = sa > sb;
        const std::int64_t later_key = later_is_a ? ka : kb;
        const std::int64_t earlier_key = later_is_a ? kb : ka;
        // Different verdicts with the same key are flagged too (arrival order is not emission
        // order).
        const bool expect_flag = later_key <= earlier_key;
        INFO("pair " << i << " ka=" << ka << " kb=" << kb << " sa=" << sa << " sb=" << sb);
        CHECK(census(db.dsn(), agent, "r1") ==
              std::string(a_wins ? "drifted" : "compliant") + "|" + key_str(kBase + win_key) + "|" +
                  key_str(kBase + std::max(ka, kb)) + "|" + (expect_flag ? "true" : "false"));
    }
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(store.census_proj_failures_total() == 0); // no 40P01 surfaced as a stale row
}

TEST_CASE(
    "census ordering: a state change that did not come from this version's upsert flags the row",
    "[pg][guaranteed_state_store][db][census][ordering][k]") {
    // UP-2: an earlier build's census write changes state/updated_at and leaves the ordering tuple
    // alone. The trigger flags it; this version's own writes are not flagged by it.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1").ends_with("|false")); // this version's own update: no flag

    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guardian_agent_rule_status SET state = 'compliant', updated_at = "
                           "'2026-01-01T00:00:00Z'"); // what the previous build's upsert does
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
}

TEST_CASE(
    "census ordering: the happy path writes the event once and a failure records the evidence",
    "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    // A tuple that was never updated keeps the first slot of its page; an UPDATE (the old
    // insert-pending-then-clear shape) moves it to a new tuple version.
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(query_scalar(db.dsn(), std::string("SELECT ctid::text FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'e1'") == "(0,1)");
    CHECK(pending_count(db.dsn()) == "0");

    install_census_fail(db.dsn(), "true");
    REQUIRE(store.insert_event_classified(ev("e2", "r1", "b", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(pending_count(db.dsn()) == "1"); // recorded by the failure, in the same transaction
}

TEST_CASE("census ordering: every projection outcome is counted by source",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto count = [&](const char* source, const char* outcome) {
        return metrics
            .counter("yuzu_server_guardian_census_projection_total",
                     {{"source", source}, {"outcome", outcome}})
            .value();
    };
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted); // dominated, flagged
    REQUIRE(store.insert_event_classified(ev("e3", "ghost", "a", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted); // rule gone
    CHECK(count("first_delivery", "applied") == 1);
    CHECK(count("first_delivery", "refused_flagged") == 1);
    CHECK(count("first_delivery", "rejected") == 1);

    install_census_fail(db.dsn(), "true");
    const auto f = ev("e4", "r1", "b", kDrifted, kBase);
    REQUIRE(store.insert_event_classified(f).outcome == EventInsertOutcome::Inserted);
    CHECK(count("first_delivery", "failed") == 1);
    remove_census_fail(db.dsn());
    REQUIRE(store.insert_event_classified(f).outcome == EventInsertOutcome::Redelivered);
    CHECK(count("repair", "applied") == 1);
}

TEST_CASE("census ordering: a repair projects from the stored inputs and keeps a higher-key "
          "pending row pending",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    const auto high = ev("h", "r1", "a", kDrifted, kBase + 150);  // seq 2, key 150
    const auto low = ev("l", "r1", "a", kCompliant, kBase + 110); // seq 3, key 110
    REQUIRE(store.insert_event_classified(high).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(low).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());

    // The redelivery carries a different stamp and receipt: the STORED inputs decide.
    auto redelivered = low;
    redelivered.agent_ns = 0;
    redelivered.received_ns = 1;
    CHECK(store.insert_event_classified(redelivered).outcome == EventInsertOutcome::Redelivered);
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 110) + "|" + key_str(kBase + 150) + "|true");
    // The higher-key pending row outranks the verdict just applied: it must stay pending.
    CHECK(query_scalar(db.dsn(), std::string("SELECT projection_pending FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'h'") == "t");
    CHECK(query_scalar(db.dsn(), std::string("SELECT projection_pending FROM ") + kSchema +
                                     ".guaranteed_state_events WHERE event_id = 'l'") == "f");
}

TEST_CASE("census ordering: a recovery repair that lowers the key leaves a higher-key pending peer "
          "pending",
          "[pg][guaranteed_state_store][db][census][ordering][stale][k]") {
    // Ruled (architect, 2026-11-04): a repair retires only the evidence the verdict it applied
    // dominates, and recovery lowers the key. The peer S sits between the repaired event I and the
    // mark, so it stays pending: retiring it would drop the only record that its verdict was never
    // applied. Redelivering S later then orders by key again, still flagged.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    const auto s_ev = ev("s", "r1", "a", kErrored, kBase + 700);   // seq 2, key 700: below the mark
    const auto i_ev = ev("i", "r1", "a", kCompliant, kBase + 500); // seq 3, key 500: lower still
    REQUIRE(store.insert_event_classified(s_ev).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(i_ev).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    CHECK(pending_count(db.dsn()) == "2");
    // Age the mark past the hour so recovery lets the later arrival apply by arrival.
    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns - "
                           "3700000000000 WHERE agent_id = 'a' AND rule_id = 'r1'");

    auto redelivered = i_ev;
    redelivered.agent_ns = 0;
    redelivered.received_ns = 1;
    REQUIRE(store.insert_event_classified(redelivered).outcome == EventInsertOutcome::Redelivered);
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    const auto pending_of = [&](const char* id) {
        return query_scalar(db.dsn(), std::string("SELECT projection_pending FROM ") + kSchema +
                                          ".guaranteed_state_events WHERE event_id = '" + id + "'");
    };
    CHECK(pending_of("i") == "f");
    CHECK(pending_of("s") == "t");

    // S's own redelivery orders by key above the recovered verdict and stays flagged.
    auto s_again = s_ev;
    s_again.agent_ns = 0;
    s_again.received_ns = 1;
    REQUIRE(store.insert_event_classified(s_again).outcome == EventInsertOutcome::Redelivered);
    CHECK(census(db.dsn(), "a", "r1") ==
          "errored|" + key_str(kBase + 700) + "|" + key_str(kBase + 1000) + "|true");
    CHECK(pending_of("s") == "f");
}

TEST_CASE("census ordering: two failed projections with no census row at all keep the disagreement",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    // The INSERT arm of the upsert: no row exists, H (key 150, seq 2) and L (key 110, seq 3) are
    // both pending. Repairing L inserts its verdict and must see that H outranks it.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    install_census_fail(db.dsn(), "true");
    const auto h = ev("h", "r1", "a", kDrifted, kBase + 150);
    const auto l = ev("l", "r1", "a", kCompliant, kBase + 110);
    REQUIRE(store.insert_event_classified(h).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(l).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    REQUIRE(store.insert_event_classified(l).outcome == EventInsertOutcome::Redelivered);
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 110) + "|" + key_str(kBase + 150) + "|true");
}

TEST_CASE("census ordering: a pre-v4 row is superseded unflagged and a key-0 row keeps its flag",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    // A row written before v4: verdict and text timestamp only, no key, no sequence.
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at) "
                           "VALUES ('old', 'r1', 'drifted', '2026-01-01T00:00:00Z')");
    REQUIRE(store.insert_event_classified(ev("n1", "r1", "old", kCompliant, kBase + 5)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "old", "r1") == "compliant|" + key_str(kBase + 5) + "|" +
                                               key_str(kBase + 5) +
                                               "|false"); // not flagged for being pre-v4

    // A row written from an unusable key stays flagged when a keyed event replaces it.
    REQUIRE(store.insert_event_classified(ev("z1", "r1", "zero", kDrifted, 0)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("z2", "r1", "zero", kCompliant, kBase + 9)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "zero", "r1") ==
          "compliant|" + key_str(kBase + 9) + "|" + key_str(kBase + 9) + "|true");
}

TEST_CASE("census ordering: the uncertain-rule count honours the caller's scope",
          "[pg][guaranteed_state_store][db][census][ordering][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));
    REQUIRE(store.create_rule(make_rule("r3", "guard-three")));
    // r1 / agent A: flagged (an older verdict arrived later). r3 / agent C: clean.
    REQUIRE(store.insert_event_classified(ev("a1", "r1", "A", kCompliant, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("a2", "r1", "A", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("c1", "r3", "C", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    // r2 / agent B: a row exists and a later verdict failed to project (pending).
    REQUIRE(store.insert_event_classified(ev("b1", "r2", "B", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "NEW.state = 'drifted'");
    REQUIRE(store.insert_event_classified(ev("b2", "r2", "B", kDrifted, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    REQUIRE(pending_count(db.dsn()) == "1");

    using Scope = std::optional<std::vector<std::string>>;
    CHECK(store.uncertain_rule_count(Scope{}).value() == 2);      // unfiltered: r1 and r2
    CHECK(store.uncertain_rule_count(Scope{{"A"}}).value() == 1); // flagged branch
    CHECK(store.uncertain_rule_count(Scope{{"B"}}).value() == 1); // pending branch
    CHECK(store.uncertain_rule_count(Scope{{"C"}}).value() == 0); // clean agent
    CHECK(store.uncertain_rule_count(Scope{{"A", "B"}}).value() == 2);
    CHECK(store.uncertain_rule_count(Scope{{"nobody"}}).value() == 0); // out of scope
    CHECK(store.uncertain_rule_count(Scope{std::vector<std::string>{}}).value() ==
          0); // engaged-empty

    // An engaged-empty scope is answered without a query, so it holds on a store that is down.
    PgPool dead{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    GuaranteedStateStore closed(dead);
    CHECK(closed.uncertain_rule_count(Scope{std::vector<std::string>{}}).value() == 0);
    CHECK_FALSE(closed.uncertain_rule_count(Scope{}).has_value());
}

TEST_CASE("census ordering: a stale high-water mark stops freezing the verdict after an hour "
          "(#5690 UP-11)",
          "[pg][guaranteed_state_store][db][census][ordering][stale]") {
    // An agent clock that steps backwards stamps every later event below the mark. Within the hour
    // after the mark last rose the verdict is held and flagged; after it, arrival order governs
    // (still flagged) until a key passes the mark.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto age_mark = [&](const char* by) {
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns - " + by +
                               " WHERE agent_id = 'a' AND rule_id = 'r1'");
    };
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);

    SECTION("inside the hour a lower key is refused and the verdict is held") {
        age_mark("3500000000000"); // 58 min 20 s: well inside the hour
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("past the hour a lower key applies by arrival, stays flagged, and keeps the mark") {
        age_mark("3700000000000"); // 61 min 40 s: well past the hour
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
        // The next event in the new clock frame also applies, still flagged.
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kErrored, kBase + 600)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 600) + "|" + key_str(kBase + 1000) + "|true");
        // A key strictly above the mark ends the doubt.
        REQUIRE(
            store.insert_event_classified(ev("e4", "r1", "a", kCompliant, kBase + 2000)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 2000) + "|" + key_str(kBase + 2000) + "|false");
    }
    SECTION("an unusable key never recovers, however old the mark") {
        age_mark("7200000000000");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, 0)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("a row with no recorded mark time never recovers") {
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = NULL");
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("the mark time moves only when the mark rises") {
        const std::string before =
            query_scalar(db.dsn(), std::string("SELECT hwm_recv_ns FROM ") + kSchema +
                                       ".guardian_agent_rule_status WHERE agent_id = 'a'");
        REQUIRE_FALSE(before.empty());
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted); // refused: the mark does not rise
        CHECK(query_scalar(db.dsn(), std::string("SELECT hwm_recv_ns FROM ") + kSchema +
                                         ".guardian_agent_rule_status WHERE agent_id = 'a'") ==
              before);
    }
}

// "ingest_seq|seq_hwm|max event ingest_seq" of a pair, so a test can see the three move together.
std::string census_internals(const std::string& dsn, const std::string& agent,
                             const std::string& rule) {
    return query_scalar(
        dsn,
        std::string("SELECT c.ingest_seq || '|' || c.seq_hwm || '|' || (SELECT max(ingest_seq) "
                    "FROM ") +
            kSchema +
            ".guaranteed_state_events e WHERE e.agent_id = c.agent_id AND "
            "e.rule_id = c.rule_id) FROM " +
            kSchema + ".guardian_agent_rule_status c WHERE c.agent_id = '" + agent +
            "' AND c.rule_id = '" + rule + "'");
}

// True when `hwm_recv_ns` is within a minute of the database clock (and so was not taken from an
// agent stamp, which these tests set years in the past).
std::string hwm_recv_is_db_now(const std::string& dsn, const std::string& agent) {
    return query_scalar(
        dsn, std::string("SELECT (hwm_recv_ns BETWEEN "
                         "(floor(extract(epoch FROM clock_timestamp()) * 1000000000))::bigint - "
                         "60000000000 AND "
                         "(floor(extract(epoch FROM clock_timestamp()) * 1000000000))::bigint + "
                         "1000000000)::text FROM ") +
                 kSchema + ".guardian_agent_rule_status WHERE agent_id = '" + agent + "'");
}

TEST_CASE("census ordering: a pending event that shares a key with a different verdict is flagged "
          "(#5690 UP-3)",
          "[pg][guaranteed_state_store][db][census][ordering][tie]") {
    // Found in review (nine reviewers): a PENDING event with the same key as a
    // later, different verdict was retired as dominated with the row left clean. A pending event's
    // verdict is not stored beside its key, so any same-key pending peer flags (an over-flag for a
    // peer with the same verdict is accepted: pending events are rare).
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    SECTION("no census row yet: the insert arm flags the pair") {
        install_census_fail(db.dsn(), "NEW.state = 'drifted'");
        REQUIRE(store.insert_event_classified(ev("d1", "r1", "a", kDrifted, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted); // pending, no census row
        remove_census_fail(db.dsn());
        REQUIRE(pending_count(db.dsn()) == "1");
        REQUIRE(
            store.insert_event_classified(ev("d2", "r1", "a", kCompliant, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("no census row yet and the same verdict: flagged too (documented over-flag)") {
        install_census_fail(db.dsn(), "NEW.state = 'drifted'");
        REQUIRE(store.insert_event_classified(ev("d1", "r1", "a", kDrifted, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        remove_census_fail(db.dsn());
        REQUIRE(store.insert_event_classified(ev("d2", "r1", "a", kDrifted, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1").ends_with("|true"));
    }
    SECTION("a pending event with a different key does not flag the pair") {
        install_census_fail(db.dsn(), "NEW.state = 'drifted'");
        REQUIRE(store.insert_event_classified(ev("d1", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        remove_census_fail(db.dsn());
        REQUIRE(
            store.insert_event_classified(ev("d2", "r1", "a", kCompliant, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|false");
    }
    SECTION("a row already at the key and an older pending peer at the same key: the apply flags") {
        // The row holds (key, seq 1). A pending peer at the same key with a LOWER sequence than the
        // row can only exist when it became pending after the row's own projection read the pair,
        // so it is written directly. A later event then sees it.
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted);
        REQUIRE(census(db.dsn(), "a", "r1").ends_with("|false"));
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, "
                               "agent_id, event_type, severity, timestamp, ingest_seq, proj_key, "
                               "projection_pending) OVERRIDING SYSTEM VALUE VALUES ('p0', 'r1', "
                               "'a', 'drift.detected', "
                               "'high', 't', 0, " +
                               key_str(kBase + 300) + ", true)");
        REQUIRE(pending_count(db.dsn()) == "1");
        // The same verdict at the same key: nothing separates the new event from the row but the
        // pending peer, which shares the winning key.
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("an older pending peer at a LOWER key than the winner is irrelevant") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                               "severity, timestamp, ingest_seq, proj_key, projection_pending) "
                               "OVERRIDING SYSTEM VALUE VALUES ('p0', 'r1', 'a', 'drift.detected', "
                               "'high', 't', 0, " +
                               key_str(kBase + 200) + ", true)");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kErrored, kBase + 400)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 400) + "|" + key_str(kBase + 400) + "|false");
    }
}

TEST_CASE("census ordering: only the fold flags a pending same-key peer that a lower-key "
          "lower-sequence arrival sees",
          "[pg][guaranteed_state_store][db][census][ordering][tie]") {
    // The schedule where the fold's same-key term is the ONLY thing that flags the row (found in
    // review): Q (errored, key 300) projects and commits first; P (drifted, the same key, a LOWER
    // sequence) became pending meanwhile; Z (key 100, a sequence BELOW Q's) then projects. Z
    // neither applies nor flags in the upsert (key and sequence both below the row), and the clear
    // would retire P as dominated. Sequences are placed by hand (setval and a hand-written pending
    // row), because three concurrent ingests cannot be ordered otherwise.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const std::string seq = std::string(kSchema) + ".guaranteed_state_events_ingest_seq_seq";

    exec_sql(db.dsn(), "SELECT setval('" + seq + "', 10, false)");
    REQUIRE(store.insert_event_classified(ev("q", "r1", "a", kErrored, kBase + 300)).outcome ==
            EventInsertOutcome::Inserted); // seq 10, unflagged
    REQUIRE(census(db.dsn(), "a", "r1") ==
            "errored|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|false");
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, ingest_seq, proj_key, projection_pending) "
                           "OVERRIDING SYSTEM VALUE VALUES ('p', 'r1', 'a', 'drift.detected', "
                           "'high', 't', 3, " +
                           key_str(kBase + 300) + ", true)");
    exec_sql(db.dsn(), "SELECT setval('" + seq + "', 5, false)");
    REQUIRE(store.insert_event_classified(ev("z", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted); // seq 5: below Q's, above P's
    CHECK(census(db.dsn(), "a", "r1") ==
          "errored|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
    CHECK(pending_count(db.dsn()) == "0");
}

TEST_CASE("census ordering: a lower-sequence arrival with the same key and a different verdict is "
          "flagged",
          "[pg][guaranteed_state_store][db][census][ordering][tie][lockorder]") {
    // The non-apply branch and the WHERE disjunct for a tie, reached deterministically: W1 (the
    // lower sequence) parks after its pair lock, W2 (same key, other verdict) applies, W1 resumes.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    EventInsertResult w1_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] {
        w1_res = store.insert_event_classified(ev("w1", "r1", "a", kDrifted, kBase + 500));
    });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(store.insert_event_classified(ev("w2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 500) + "|false");
    writers.join_all();

    CHECK(w1_res.outcome == EventInsertOutcome::Inserted);
    // W1 arrived first, so the later arrival's verdict stays; the doubt is recorded.
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 500) + "|true");
    CHECK(census_internals(db.dsn(), "a", "r1") ==
          query_scalar(db.dsn(),
                       std::string("SELECT max(ingest_seq) || '|' || max(ingest_seq) || '|' "
                                   "|| max(ingest_seq) FROM ") +
                           kSchema + ".guaranteed_state_events"));
}

TEST_CASE("census ordering: recovery needs a later arrival than the applied verdict",
          "[pg][guaranteed_state_store][db][census][ordering][stale][lockorder]") {
    // R's `EXCLUDED.ingest_seq > c.ingest_seq`: after a quiet hour W2 (the later arrival) recovers
    // the verdict; W1 (the earlier arrival, processed afterwards) must be refused, not applied.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
    exec_sql(db.dsn(),
             std::string("UPDATE ") + kSchema +
                 ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns - 7200000000000");

    EventInsertResult w1_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] {
        w1_res = store.insert_event_classified(ev("w1", "r1", "a", kCompliant, kBase + 500));
    });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(store.insert_event_classified(ev("w2", "r1", "a", kErrored, kBase + 600)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "errored|" + key_str(kBase + 600) + "|" + key_str(kBase + 1000) + "|true");
    writers.join_all();

    CHECK(w1_res.outcome == EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "errored|" + key_str(kBase + 600) + "|" + key_str(kBase + 1000) + "|true");
}

TEST_CASE("census ordering: the mark's time is the database clock and is set when the mark rises",
          "[pg][guaranteed_state_store][db][census][ordering][stale]") {
    // Note: the test server and the database share a host clock, so these cases cannot tell a
    // replica's clock from the database's; the clock authority is established by the SQL (the stamp
    // is `statement_timestamp()` in the statement text), and these cases pin that the stamp is a
    // current time and not an agent stamp or an event receipt.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto backdate = [&] {
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = 1000");
    };

    SECTION("the insert arm stamps the database time, not the agent stamp or the event receipt") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("the update arm stamps it when the mark rises") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        backdate();
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("the fold stamps it when a seen event raises the mark") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
        install_census_fail(db.dsn(), "NEW.state = 'errored'");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kErrored, kBase + 400)).outcome ==
                EventInsertOutcome::Inserted); // pending, outranks the row
        remove_census_fail(db.dsn());
        backdate();
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted); // sees e2: the fold raises the mark to its key
        CHECK(census(db.dsn(), "a", "r1").find("|" + key_str(kBase + 400) + "|") !=
              std::string::npos);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("a recorded time four minutes ahead is inside the slack: the verdict is still held") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "240000000000");
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("a recorded time six minutes ahead is past the five-minute slack: it counts as stale") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "360000000000");
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("a recorded time ten minutes ahead is past the slack: it counts as stale") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "600000000000");
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION(
        "a recorded time in the database's future counts as stale, never as an indefinite hold") {
        REQUIRE(
            store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
            EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "10800000000000"); // three hours ahead
        REQUIRE(
            store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
            EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    }
}

TEST_CASE(
    "census ordering: a refused later arrival is remembered when an earlier one applies afterwards",
    "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    // Three overlapping first deliveries to one new pair (#5690 UP-13).
    //   W1 key 200 (seq 1), W0 key 300 (seq 2), W2 key 100 (seq 3).
    // They are processed in the order W1, W2, W0: W2 (the latest arrival) is refused and flagged
    // against W1's row, then W0 applies with a key above the high-water mark. Delivered in arrival
    // order the same events leave the row flagged, because W2 arrived after the winner with a lower
    // key; the key high-water mark alone forgets that, so the row also tracks the highest arrival
    // sequence processed.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    REQUIRE(store.insert_event_classified(ev("w1", "r1", "a", kCompliant, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted); // seq 1, applied

    EventInsertResult w0_res; // before the owner: the thread writes it
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] {
        w0_res = store.insert_event_classified(ev("w0", "r1", "a", kDrifted, kBase + 300));
    });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    // W0 (seq 2) is parked right after its pair lock. W2 (seq 3) now runs to completion: refused.
    REQUIRE(store.insert_event_classified(ev("w2", "r1", "a", kErrored, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
    writers.join_all(); // W0 applies

    CHECK(w0_res.outcome == EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
    CHECK(pending_count(db.dsn()) == "0");
}

TEST_CASE(
    "census ordering: a repair of a rejected event retires its evidence in the outer transaction",
    "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    install_census_fail(db.dsn(), "true");
    const auto p = ev("p", "r1", "a", kDrifted, kBase);
    REQUIRE(store.insert_event_classified(p).outcome == EventInsertOutcome::Inserted);
    remove_census_fail(db.dsn());
    REQUIRE(pending_count(db.dsn()) == "1");
    // The rule disappears out from under the pending event (the F-13 class), so the repair's census
    // write meets the foreign key (23503) and the event's evidence is retired, not left to repeat.
    exec_sql(db.dsn(), std::string("DELETE FROM ") + kSchema +
                           ".guaranteed_state_rules WHERE rule_id = 'r1'");
    CHECK(store.insert_event_classified(p).outcome == EventInsertOutcome::Redelivered);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(metrics
              .counter("yuzu_server_guardian_census_projection_total",
                       {{"source", "repair"}, {"outcome", "rejected"}})
              .value() == 1);
    CHECK(store.event_count() == 1); // the audit row stays
}

TEST_CASE(
    "census ordering: a seen event retired by a flagged apply is still remembered by a later apply",
    "[pg][guaranteed_state_store][db][census][ordering][lockorder]") {
    // A randomised-schedule finding: W1 (key 250, seq 1) is held inside its INSERT; W2
    // (key 300, seq 2) takes its pair lock and parks; a pending event E (key 100, seq 3) is stored.
    // W1 then sees E, applies flagged and retires E (E is dominated); W2 applies with a key above
    // the high-water mark. Delivered in arrival order E arrives last with the lowest key, so the
    // row must stay flagged: the retired event's arrival sequence is kept in `seq_hwm`.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    exec_sql(db.dsn(), std::string("CREATE FUNCTION ") + kSchema +
                           ".yuzu_test_hold_x() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                           "IF NEW.event_id = 'w1' THEN PERFORM pg_advisory_lock(91011); "
                           "PERFORM pg_advisory_unlock(91011); END IF; RETURN NEW; END $$");
    exec_sql(db.dsn(), std::string("CREATE TRIGGER yuzu_test_hold_x BEFORE INSERT ON ") + kSchema +
                           ".guaranteed_state_events FOR EACH ROW EXECUTE FUNCTION " + kSchema +
                           ".yuzu_test_hold_x()");

    EventInsertResult w1_res;
    EventInsertResult w2_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    pg::PgConn holder{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        pg::PgResult r{PQexec(holder.get(), "SELECT pg_advisory_lock(91011)")};
        REQUIRE(r.ok());
    }
    writers.start([&] {
        w1_res = store.insert_event_classified(ev("w1", "r1", "a", kCompliant, kBase + 250));
    });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1, "advisory")); // W1 holds seq 1, parked in its INSERT
    writers.start([&] {
        w2_res = store.insert_event_classified(ev("w2", "r1", "a", kDrifted, kBase + 300));
    });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) ==
            std::future_status::ready); // W2: seq 2, parked
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, proj_key, projection_pending) VALUES ('we', 'r1', "
                           "'a', 'guard.unhealthy', 'high', 't', " +
                           key_str(kBase + 100) + ", true)");
    {
        pg::PgResult r{PQexec(holder.get(), "SELECT pg_advisory_unlock(91011)")};
        REQUIRE(r.ok());
    }
    // W1 now runs to completion against E; poll until its census row exists, then release W2.
    for (int i = 0; i < 400 && census(db.dsn(), "a", "r1").empty(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    REQUIRE_FALSE(census(db.dsn(), "a", "r1").empty());
    writers.join_all();

    CHECK(w1_res.outcome == EventInsertOutcome::Inserted);
    CHECK(w2_res.outcome == EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
    CHECK(pending_count(db.dsn()) == "0");
}

TEST_CASE("census ordering: iso8601_to_ns reports an instant past int64 nanoseconds as unparsed",
          "[census][ordering][helper]") {
    // 2262-04-11T23:47:16Z is the last whole second whose nanosecond count fits in int64.
    CHECK(yuzu::test::iso8601_to_ns("1970-01-01T00:00:01Z") == 1'000'000'000LL);
    CHECK(yuzu::test::iso8601_to_ns("2262-04-11T23:47:16Z") == 9'223'372'036'000'000'000LL);
    CHECK(yuzu::test::iso8601_to_ns("2262-04-11T23:47:17Z") == 0);
    CHECK(yuzu::test::iso8601_to_ns("9999-12-31T23:59:59Z") == 0);
}

// ── #7217: unrepresented pending evidence for one device ─────────────────────

namespace {

// A retained, pending event with NO census row: written raw so nothing projects it. The event id
// carries a suffix so one pair can hold several of them.
void raw_pending(const std::string& dsn, const std::string& agent, const std::string& rule,
                 const std::string& suffix = "") {
    exec_sql(dsn, std::string("INSERT INTO ") + kSchema +
                      ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                      "severity, timestamp, proj_key, projection_pending) VALUES ('up-" +
                      agent + "-" + rule + suffix + "', '" + rule + "', '" + agent +
                      "', 'guard.compliant', 'high', 't', 100, true)");
}

void raw_census(const std::string& dsn, const std::string& agent, const std::string& rule) {
    exec_sql(dsn, std::string("INSERT INTO ") + kSchema +
                      ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at) "
                      "VALUES ('" + agent + "', '" + rule + "', 'compliant', 't')");
}

using PendingScope = std::optional<std::vector<std::string>>;

} // namespace

TEST_CASE("census ordering: unrepresented pending lists pairs with pending evidence and no census row",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));
    REQUIRE(store.create_rule(make_rule("r3", "guard-three")));

    SECTION("a pending-only pair is returned") {
        raw_pending(db.dsn(), "A", "r1");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"r1"});
    }

    SECTION("a pair that has a census row is excluded even with a pending event") {
        raw_pending(db.dsn(), "A", "r1");
        raw_pending(db.dsn(), "A", "r2");
        raw_census(db.dsn(), "A", "r1");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"r2"});
    }

    SECTION("a non-pending event is not evidence") {
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, agent_id, "
                               "event_type, severity, timestamp, proj_key, projection_pending) "
                               "VALUES ('np', 'r1', 'A', 'guard.compliant', 'high', 't', 100, "
                               "false)");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 0);
        CHECK(s->rule_ids.empty());
    }

    SECTION("the rule filter keeps only the listed rules") {
        raw_pending(db.dsn(), "A", "r1");
        raw_pending(db.dsn(), "A", "r2");
        raw_pending(db.dsn(), "A", "r3");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{{"r1", "r3"}});
        REQUIRE(s.has_value());
        CHECK(s->count == 2);
        CHECK(s->rule_ids == std::vector<std::string>{"r1", "r3"});
        const auto none = store.unrepresented_pending_for_agent("A", PendingScope{{"nope"}});
        REQUIRE(none.has_value());
        CHECK(none->count == 0);
        CHECK(none->rule_ids.empty());
    }

    SECTION("another agent's pending evidence is not counted") {
        raw_pending(db.dsn(), "B", "r1");
        raw_pending(db.dsn(), "A", "r2");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"r2"});
    }

    SECTION("duplicate pending events of one pair count once") {
        raw_pending(db.dsn(), "A", "r1", "-1");
        raw_pending(db.dsn(), "A", "r1", "-2");
        raw_pending(db.dsn(), "A", "r1", "-3");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"r1"});
    }

    SECTION("a pending event whose rule has no rule row is still counted (no live-rule join)") {
        raw_pending(db.dsn(), "A", "ghost");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"ghost"});
        const auto f = store.unrepresented_pending_for_agent("A", PendingScope{{"ghost"}});
        REQUIRE(f.has_value());
        CHECK(f->count == 1);
    }
}

TEST_CASE("census ordering: unrepresented pending caps the id list but never the count",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    // 57 distinct pairs, two events each for the first ones so duplicates cannot inflate the count.
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, proj_key, projection_pending) "
                           "SELECT 'cap-' || g || '-' || d, 'rule-' || lpad(g::text, 3, '0'), "
                           "'A', 'guard.compliant', 'high', 't', 100, true "
                           "FROM generate_series(1, 57) g, generate_series(1, 2) d");
    const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
    REQUIRE(s.has_value());
    CHECK(s->count == 57);
    REQUIRE(s->rule_ids.size() == kUnrepresentedPendingIdCap);
    CHECK(std::is_sorted(s->rule_ids.begin(), s->rule_ids.end()));
    CHECK(std::adjacent_find(s->rule_ids.begin(), s->rule_ids.end()) == s->rule_ids.end());
    CHECK(s->rule_ids.front() == "rule-001");
    CHECK(s->rule_ids.back() == "rule-050");

    // The filtered form caps the same way and still reports the exact count.
    std::vector<std::string> all;
    for (int i = 1; i <= 57; ++i) {
        all.emplace_back(std::format("rule-{:03}", i));
    }
    const auto f = store.unrepresented_pending_for_agent("A", PendingScope{all});
    REQUIRE(f.has_value());
    CHECK(f->count == 57);
    CHECK(f->rule_ids.size() == kUnrepresentedPendingIdCap);
}

namespace {

constexpr const char* kDegradeCounter = "yuzu_server_guardian_read_degrade_total";
constexpr const char* kSourceDevice = "guardian_census_device";
constexpr const char* kSourceGauge = "guardian_census";

double degrade_count(yuzu::MetricsRegistry& metrics, const char* source, const char* reason) {
    return metrics.counter(kDegradeCounter, {{"reason", reason}, {"source", source}}).value();
}

// Sum over the reasons the per-device read can report, for one source.
double degrade_total(yuzu::MetricsRegistry& metrics, const char* source) {
    double total = 0;
    for (const char* reason : {"store_not_open", "pool_acquire_timeout", "query_error", "statement_timeout"})
        total += degrade_count(metrics, source, reason);
    return total;
}

// After any fault arm the pool holds no lease and the store still serves a read AND a write.
// `tag` keeps the rule id of the write distinct per call.
void expect_pool_and_store_intact(PgPool& pool, GuaranteedStateStore& store, const std::string& dsn,
                                  const std::string& tag) {
    CHECK(pool.in_use() == 0);
    raw_pending(dsn, "intact-" + tag, "r-" + tag);
    const auto read = store.unrepresented_pending_for_agent("intact-" + tag, PendingScope{});
    REQUIRE(read.has_value());
    CHECK(read->count == 1);
    CHECK(read->rule_ids == std::vector<std::string>{"r-" + tag});
    CHECK(store.create_rule(make_rule("w-" + tag, "intact-write-" + tag)).has_value());
    CHECK(pool.in_use() == 0);
}

// Pending event whose agent and rule travel as bind parameters, so a hostile id is stored as is.
void raw_pending_param(const std::string& dsn, const std::string& agent, const std::string& rule) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r = pg::exec_params(
        conn.get(),
        (std::string("INSERT INTO ") + kSchema +
         ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, severity, timestamp, "
         "proj_key, projection_pending) VALUES ('hp-' || $2::text || '-' || $1::text, $2::text, $1::text, 'guard.compliant', "
         "'high', 't', 100, true)")
            .c_str(),
        std::vector<std::string>{agent, rule});
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

} // namespace

TEST_CASE("census ordering: unrepresented pending fails hard and never reads as zero",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    SECTION("a store that is not open") {
        yuzu::MetricsRegistry metrics;
        PgPool dead{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
        GuaranteedStateStore closed(dead);
        closed.set_metrics(&metrics);
        REQUIRE_FALSE(closed.is_open());
        const auto a = closed.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE_FALSE(a.has_value());
        CHECK(a.error().kind == UnrepresentedPendingFault::kUnavailable);
        CHECK_FALSE(a.error().message.empty());
        const auto b = closed.unrepresented_pending_for_agent("A", PendingScope{{"r1"}});
        REQUIRE_FALSE(b.has_value());
        CHECK(b.error().kind == UnrepresentedPendingFault::kUnavailable);
        // An engaged-empty filter is answered without touching the store, so it holds on a store that
        // is down, and it is not counted as a degrade.
        const auto e = closed.unrepresented_pending_for_agent("A", PendingScope{std::vector<std::string>{}});
        REQUIRE(e.has_value());
        CHECK(e->count == 0);
        CHECK(e->rule_ids.empty());
        CHECK(degrade_count(metrics, kSourceDevice, "store_not_open") == 2);
        CHECK(degrade_total(metrics, kSourceDevice) == 2);
        // The gauge read's source is untouched by the per-device read.
        CHECK(degrade_total(metrics, kSourceGauge) == 0);
    }

    SECTION("the fault seam fails only this read and recovers when cleared") {
        YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
        // Declared before the store that owns the seam: the lambda holds its own reference.
        yuzu::MetricsRegistry metrics;
        const auto calls = std::make_shared<std::atomic<int>>(0);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        GuaranteedStateStore store(pool);
        store.set_metrics(&metrics);
        REQUIRE(store.is_open());
        raw_pending(db.dsn(), "A", "r1");
        store.set_unrepresented_pending_fault_for_test([calls] {
            calls->fetch_add(1);
            return true;
        });
        const auto first = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE_FALSE(first.has_value());
        CHECK(first.error().kind == UnrepresentedPendingFault::kUnavailable);
        CHECK(calls->load() == 1);
        CHECK_FALSE(store.unrepresented_pending_for_agent("A", PendingScope{{"r1"}}).has_value());
        CHECK(calls->load() == 2);
        // Counted once per failed read, on the per-device source and as query_error.
        CHECK(degrade_count(metrics, kSourceDevice, "query_error") == 2);
        CHECK(degrade_total(metrics, kSourceDevice) == 2);
        CHECK(degrade_total(metrics, kSourceGauge) == 0);
        // Another read on the same store is unaffected, and does not move the per-device source.
        CHECK(store.pending_projection_count_checked().has_value());
        CHECK(degrade_total(metrics, kSourceDevice) == 2);
        // The engaged-empty short-circuit never reaches the seam.
        const auto e = store.unrepresented_pending_for_agent("A", PendingScope{std::vector<std::string>{}});
        REQUIRE(e.has_value());
        CHECK(e->count == 0);
        CHECK(calls->load() == 2);
        // The injected fault leaked nothing: no lease is out.
        CHECK(pool.in_use() == 0);

        store.set_unrepresented_pending_fault_for_test({});
        const auto ok = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(ok.has_value());
        CHECK(ok->count == 1);
        CHECK(calls->load() == 2);
        expect_pool_and_store_intact(pool, store, db.dsn(), "seam");
    }

    SECTION("a pool that cannot lease in time is a pool_acquire_timeout and leaves no lease behind") {
        YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
        yuzu::MetricsRegistry metrics;
        PgPool pool{{.conninfo = db.dsn(), .size = 1}};
        GuaranteedStateStore store(pool);
        store.set_metrics(&metrics);
        REQUIRE(store.is_open());
        {
            // The saboteur holds the pool's only connection for the whole read.
            auto held = pool.try_acquire_for(std::chrono::seconds(5));
            REQUIRE(static_cast<bool>(held));
            const auto r = store.unrepresented_pending_for_agent("A", PendingScope{});
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().kind == UnrepresentedPendingFault::kUnavailable);
            CHECK(degrade_count(metrics, kSourceDevice, "pool_acquire_timeout") == 1);
            CHECK(degrade_total(metrics, kSourceDevice) == 1);
            CHECK(pool.in_use() == 1); // the saboteur's, not the read's
        }
        expect_pool_and_store_intact(pool, store, db.dsn(), "pool");
    }
}

TEST_CASE("census ordering: unrepresented pending reports a statement timeout as its own fault",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    yuzu::MetricsRegistry metrics;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    store.set_metrics(&metrics);
    REQUIRE(store.is_open());
    raw_pending(db.dsn(), "A", "r1");
    store.set_unrepresented_pending_timeout_ms_for_test(50);

    const bool filtered = GENERATE(false, true);
    CAPTURE(filtered);
    const PendingScope scope = filtered ? PendingScope{{"r1"}} : PendingScope{};
    const double before = degrade_count(metrics, kSourceDevice, "statement_timeout");
    {
        // The read blocks behind the lock until its 50 ms statement timeout cancels it (57014).
        yuzu::test::EventsTableLock lock(db.dsn());
        const auto r = store.unrepresented_pending_for_agent("A", scope);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == UnrepresentedPendingFault::kStatementTimeout);
        CHECK_FALSE(r.error().message.empty());
        CHECK(degrade_count(metrics, kSourceDevice, "statement_timeout") == before + 1);
        // Counted as a timeout and NOT also as a generic query error, on the per-device source only.
        CHECK(degrade_count(metrics, kSourceDevice, "query_error") == 0);
        CHECK(degrade_total(metrics, kSourceGauge) == 0);
        // The failed transaction was rolled back and its connection returned.
        CHECK(pool.in_use() == 0);
    }
    // Lock released: restore the production budget, then the same store answers the same read and
    // a follow-up read and write succeed.
    store.set_unrepresented_pending_timeout_ms_for_test(5000);
    const auto ok = store.unrepresented_pending_for_agent("A", scope);
    REQUIRE(ok.has_value());
    CHECK(ok->count == 1);
    CHECK(ok->rule_ids == std::vector<std::string>{"r1"});
    expect_pool_and_store_intact(pool, store, db.dsn(), filtered ? "to-f" : "to-u");
}

TEST_CASE("census ordering: unrepresented pending orders ids by byte value and keeps the byte-order cap",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    SECTION("mixed case and punctuation sort as bytes, whatever the cluster locale") {
        for (const char* id : {"g-a", "g_a", "gA", "g-b", "g.b", "G-c"})
            raw_pending_param(db.dsn(), "A", id);
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 6);
        // 'G' < 'g'; after "g": '-' (0x2d) < '.' (0x2e) < 'A' (0x41) < '_' (0x5f).
        CHECK(s->rule_ids == std::vector<std::string>{"G-c", "g-a", "g-b", "g.b", "gA", "g_a"});
    }

    SECTION("the cap keeps the first ids in byte order") {
        // 50 lowercase ids and one uppercase id: byte order puts the uppercase one first, so the
        // last lowercase id is the one the cap drops. A locale collation would keep it instead.
        for (int i = 1; i <= 50; ++i)
            raw_pending_param(db.dsn(), "A", std::format("m-{:03}", i));
        raw_pending_param(db.dsn(), "A", "Z-last");
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 51);
        REQUIRE(s->rule_ids.size() == kUnrepresentedPendingIdCap);
        CHECK(s->rule_ids.front() == "Z-last");
        CHECK(s->rule_ids.back() == "m-049");
        CHECK(std::is_sorted(s->rule_ids.begin(), s->rule_ids.end()));
    }
}

TEST_CASE("census ordering: unrepresented pending carries hostile and empty ids through the filter",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    // Quotes, backslash, braces, commas, whitespace, a newline, SQL and array-literal look-alikes,
    // a NULL look-alike and multi-byte UTF-8: agent-reported ids are not validated at ingest.
    const std::vector<std::string> hostile{
        "a'b",         "a\"b",    "a\\b",   "a,b",         "{a}",      "a b",
        "a\nb",        "x'; DROP TABLE t; --", "{\"k\":1}", "NULL",   "\xC3\xBC-\xE6\x97\xA5\xE6\x9C\xAC",
        "\\\"",        "'",       "\"",     "\\"};
    for (const std::string& id : hostile)
        raw_pending_param(db.dsn(), "A", id);
    std::vector<std::string> expected = hostile;
    std::sort(expected.begin(), expected.end()); // std::string compares bytes, like COLLATE "C"
    expected.erase(std::unique(expected.begin(), expected.end()), expected.end());

    SECTION("unfiltered: every id comes back verbatim, byte-sorted") {
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == static_cast<std::int64_t>(expected.size()));
        CHECK(s->rule_ids == expected);
    }

    SECTION("filtered by the same ids: the array literal round-trips every byte") {
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{hostile});
        REQUIRE(s.has_value());
        CHECK(s->count == static_cast<std::int64_t>(expected.size()));
        CHECK(s->rule_ids == expected);
    }

    SECTION("one hostile filter id selects only itself") {
        const auto s = store.unrepresented_pending_for_agent("A", PendingScope{{"a'b"}});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"a'b"});
        const auto none = store.unrepresented_pending_for_agent("A", PendingScope{{"a'"}});
        REQUIRE(none.has_value());
        CHECK(none->count == 0);
    }

    SECTION("an agent id with SQL metacharacters is bound, not interpolated") {
        raw_pending_param(db.dsn(), "ev'il\"A", "r1");
        const auto s = store.unrepresented_pending_for_agent("ev'il\"A", PendingScope{});
        REQUIRE(s.has_value());
        CHECK(s->count == 1);
        CHECK(s->rule_ids == std::vector<std::string>{"r1"});
    }
}

TEST_CASE("census ordering: an empty-string rule id is an id, not a wildcard",
          "[pg][guaranteed_state_store][db][census][ordering][unrepresented]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    raw_pending_param(db.dsn(), "A", "r1");

    // The only pending pair is r1, so a filter holding just "" matches nothing (and is not the
    // engaged-empty short-circuit, which would also say zero but without reading).
    const auto only_empty = store.unrepresented_pending_for_agent("A", PendingScope{{""}});
    REQUIRE(only_empty.has_value());
    CHECK(only_empty->count == 0);
    CHECK(only_empty->rule_ids.empty());

    // An empty element next to a real one does not widen the filter or drop the real one.
    const auto mixed = store.unrepresented_pending_for_agent("A", PendingScope{{"", "r1"}});
    REQUIRE(mixed.has_value());
    CHECK(mixed->count == 1);
    CHECK(mixed->rule_ids == std::vector<std::string>{"r1"});

    // A pending pair whose rule id really is the empty string is found by a filter that names it.
    raw_pending_param(db.dsn(), "A", "");
    const auto both = store.unrepresented_pending_for_agent("A", PendingScope{{""}});
    REQUIRE(both.has_value());
    CHECK(both->count == 1);
    CHECK(both->rule_ids == std::vector<std::string>{""});
    const auto all = store.unrepresented_pending_for_agent("A", PendingScope{});
    REQUIRE(all.has_value());
    CHECK(all->count == 2);
    CHECK(all->rule_ids == std::vector<std::string>{"", "r1"});
}

// -- #5675: GuaranteedStateStore::delete_agent (decommission erasure) -------------------------

namespace {

// How many census rows the store reports for one agent (a degraded read fails the test).
std::size_t census_rows_for(const GuaranteedStateStore& store, const std::string& agent) {
    const auto rows = store.agent_rule_statuses_for_agent(agent);
    REQUIRE(rows.has_value());
    return rows->size();
}

// Count of stored events (pending or not) for one agent, read raw.
std::string events_for(const std::string& dsn, const std::string& agent) {
    return query_scalar(dsn, std::string("SELECT count(*) FROM ") + kSchema +
                                 ".guaranteed_state_events WHERE agent_id = '" + agent + "'");
}

std::string pending_for(const std::string& dsn, const std::string& agent) {
    return query_scalar(dsn, std::string("SELECT count(*) FROM ") + kSchema +
                                 ".guaranteed_state_events WHERE projection_pending AND "
                                 "agent_id = '" +
                                 agent + "'");
}

// A pending (failed projection) event for `agent` through the real ingest path: every census write
// fails while it is inserted, so the event is stored with projection_pending set.
void insert_pending_event(GuaranteedStateStore& store, const std::string& dsn,
                          const std::string& event_id, const std::string& rule,
                          const std::string& agent, std::int64_t agent_ns) {
    install_census_fail(dsn, "true");
    REQUIRE(store.insert_event_classified(ev(event_id, rule, agent, kDrifted, agent_ns)).outcome ==
            EventInsertOutcome::Inserted);
    remove_census_fail(dsn);
    // remove_census_fail drops only the trigger; drop the function too so a case can seed pending
    // events for more than one agent.
    exec_sql(dsn, std::string("DROP FUNCTION ") + kSchema + ".yuzu_test_ord_fail()");
}

} // namespace

TEST_CASE("census ordering: delete_agent refuses an empty id without leasing a connection",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    // Hold the pool's only connection: a delete_agent that reached the pool would wait out its
    // 4 s lease budget, so a prompt false proves it returned before leasing.
    auto lease = pool.try_acquire_for(std::chrono::seconds(2));
    REQUIRE(lease);

    yuzu::test::LogCapture cap(spdlog::level::warn);
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_FALSE(store.delete_agent(""));
    const auto took = std::chrono::steady_clock::now() - t0;
    cap.stop();
    CHECK(took < std::chrono::seconds(1));
    CHECK(cap.text().find("empty agent_id") != std::string::npos);
}

TEST_CASE("census ordering: delete_agent on a store that never opened returns false",
          "[guaranteed_state_store][census][ordering][delete_agent]") {
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nope connect_timeout=1", .size = 1}};
    GuaranteedStateStore store(pool);
    REQUIRE_FALSE(store.is_open());
    CHECK_FALSE(store.delete_agent("A"));
}

TEST_CASE("census ordering: delete_agent removes one agent's census rows and leaves the others",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));
    REQUIRE(store.insert_event_classified(ev("a1", "r1", "A", kErrored, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("a2", "r2", "A", kErrored, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("b1", "r1", "B", kCompliant, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(census_rows_for(store, "A") == 2);
    REQUIRE(census_rows_for(store, "B") == 1);
    const auto before = store.errored_rule_count(std::nullopt);
    REQUIRE(before.has_value());
    REQUIRE(*before == 2);

    REQUIRE(store.delete_agent("A"));

    // Re-read the table: an outcome-only check would pass an empty-bodied method.
    CHECK(census_rows_for(store, "A") == 0);
    CHECK(census_rows_for(store, "B") == 1);
    CHECK(census(db.dsn(), "B", "r1") ==
          "compliant|" + key_str(kBase) + "|" + key_str(kBase) + "|false");
    const auto after = store.errored_rule_count(std::nullopt);
    REQUIRE(after.has_value());
    CHECK(*after == 0);
    // The event log is not erased (D1): A's two events are still stored.
    CHECK(events_for(db.dsn(), "A") == "2");
}

TEST_CASE("census ordering: delete_agent retires the agent's pending evidence and keeps the events",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    insert_pending_event(store, db.dsn(), "pa", "r1", "A", kBase);
    insert_pending_event(store, db.dsn(), "pb", "r1", "B", kBase);
    REQUIRE(pending_count(db.dsn()) == "2");
    const auto un_a = store.unrepresented_pending_for_agent("A", PendingScope{});
    REQUIRE(un_a.has_value());
    REQUIRE(un_a->count == 1);

    REQUIRE(store.delete_agent("A"));

    const auto gauge = store.pending_projection_count_checked();
    REQUIRE(gauge.has_value());
    CHECK(*gauge == 1); // only B's evidence is still pending
    const auto un_a_after = store.unrepresented_pending_for_agent("A", PendingScope{});
    REQUIRE(un_a_after.has_value());
    CHECK(un_a_after->count == 0);
    const auto un_b = store.unrepresented_pending_for_agent("B", PendingScope{});
    REQUIRE(un_b.has_value());
    CHECK(un_b->count == 1); // the bystander is untouched
    // The retired event row still exists; only its pending flag is cleared.
    CHECK(events_for(db.dsn(), "A") == "1");
    CHECK(pending_for(db.dsn(), "A") == "0");
    CHECK(pending_for(db.dsn(), "B") == "1");
}

TEST_CASE("census ordering: delete_agent is idempotent",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("a1", "r1", "A", kErrored, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.delete_agent("A"));
    CHECK(store.delete_agent("A")); // nothing left to erase is still success
    CHECK(store.delete_agent("never-seen"));
    CHECK(census_rows_for(store, "A") == 0);
}

TEST_CASE("census ordering: a re-registered agent inherits nothing from its decommissioned self",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    // The dead device: a census row, then a pending event whose key sits ahead of the receipt
    // instant (inside the 300 s bound), the shape a stepped-back clock leaves behind.
    REQUIRE(store.insert_event_classified(ev("old1", "r1", "A", kCompliant, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    insert_pending_event(store, db.dsn(), "old2", "r1", "A", kBase + 200'000'000'000LL);
    REQUIRE(pending_for(db.dsn(), "A") == "1");

    REQUIRE(store.delete_agent("A"));

    // The same agent_id registers again and reports a verdict with a lower key than the dead
    // pending event. With the dead evidence still pending, the first projection would fold its key
    // into the new row's high-water mark and flag the row; retired, nothing carries over.
    REQUIRE(store.insert_event_classified(ev("new1", "r1", "A", kCompliant, kBase + 10)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "A", "r1") ==
          "compliant|" + key_str(kBase + 10) + "|" + key_str(kBase + 10) + "|false");
    CHECK(pending_for(db.dsn(), "A") == "0");
}

TEST_CASE("census ordering: delete_agent and a projection holding the pair's rows never deadlock",
          "[pg][guaranteed_state_store][db][census][ordering][lockorder][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "A", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    const auto p = ev("p1", "r1", "A", kDrifted, kBase + 200);
    insert_pending_event(store, db.dsn(), "p1", "r1", "A", kBase + 200);
    const auto failures_before = store.census_proj_failures_total();

    SECTION("a repair parked on the pair's pending rows, then delete_agent") {
        EventInsertResult repair_res;
        bool deleted = false;
        BarrierHold hold;
        store.set_census_lock_barrier_for_test([&] { hold.hit(); });
        WriterThreads writers(store, &hold);
        writers.start([&] { repair_res = store.insert_event_classified(p); });
        REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        writers.start([&] { deleted = store.delete_agent("A"); });
        // delete_agent must PARK on the pending row the repair holds.
        REQUIRE(wait_for_lock_waiters(db.dsn(), 1));
        writers.join_all();

        CHECK(repair_res.outcome == EventInsertOutcome::Redelivered);
        CHECK(deleted);
        CHECK(store.census_proj_failures_total() == failures_before); // no 40P01
        CHECK(pending_for(db.dsn(), "A") == "0");
        CHECK(census_rows_for(store, "A") == 0); // the delete ran over the repair's committed row
    }

    SECTION("delete_agent parked behind a raw row lock, then a new event for the same pair") {
        EventInsertResult ingest_res;
        bool deleted = false;
        WriterThreads writers(store, nullptr);
        // Declared after the owner: destroyed first, so the held lock is released before the
        // owner joins the parked writers on a failed REQUIRE.
        pg::PgConn holder{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
        {
            pg::PgResult b{PQexec(holder.get(), "BEGIN")};
            REQUIRE(b.ok());
            pg::PgResult l{
                PQexec(holder.get(), (std::string("SELECT event_id FROM ") + kSchema +
                                      ".guaranteed_state_events WHERE agent_id = 'A' AND "
                                      "projection_pending ORDER BY ingest_seq FOR UPDATE")
                                         .c_str())};
            REQUIRE(l.ok());
        }
        writers.start([&] { deleted = store.delete_agent("A"); });
        REQUIRE(wait_for_lock_waiters(db.dsn(), 1));
        writers.start([&] {
            ingest_res =
                store.insert_event_classified(ev("n1", "r1", "A", kCompliant, kBase + 300));
        });
        REQUIRE(wait_for_lock_waiters(db.dsn(), 2));
        {
            pg::PgResult c{PQexec(holder.get(), "COMMIT")};
            REQUIRE(c.ok());
        }
        writers.join_all();

        CHECK(deleted);
        CHECK(ingest_res.outcome == EventInsertOutcome::Inserted);
        CHECK(store.census_proj_failures_total() == failures_before); // no 40P01
        CHECK(pending_for(db.dsn(), "A") == "0");
        // Either order is legal: the delete ran last (no row) or the in-flight event re-created it.
        const auto rows = store.agent_rule_statuses_for_agent("A");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() <= 1);
        if (!rows->empty())
            CHECK((*rows)[0].state == "compliant");
    }
}

TEST_CASE("census ordering: a failed census delete rolls the pending retire back with it",
          "[pg][guaranteed_state_store][db][census][ordering][delete_agent]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "A", kCompliant, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    insert_pending_event(store, db.dsn(), "p1", "r1", "A", kBase + 50);
    exec_sql(db.dsn(), std::string("CREATE FUNCTION ") + kSchema +
                           ".yuzu_test_del_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                           "RAISE EXCEPTION 'forced census delete failure' USING ERRCODE = "
                           "'XX000'; END $$");
    exec_sql(db.dsn(), std::string("CREATE TRIGGER yuzu_test_del_fail BEFORE DELETE ON ") +
                           kSchema + ".guardian_agent_rule_status FOR EACH ROW EXECUTE FUNCTION " +
                           kSchema + ".yuzu_test_del_fail()");

    CHECK_FALSE(store.delete_agent("A"));
    // One unit: the retire UPDATE that preceded the failed DELETE is undone.
    CHECK(pending_for(db.dsn(), "A") == "1");
    CHECK(census_rows_for(store, "A") == 1);

    exec_sql(db.dsn(), std::string("DROP TRIGGER yuzu_test_del_fail ON ") + kSchema +
                           ".guardian_agent_rule_status");
    CHECK(store.delete_agent("A")); // the re-issue completes the erasure
    CHECK(pending_for(db.dsn(), "A") == "0");
    CHECK(census_rows_for(store, "A") == 0);
}

// ---- A4a (#5690, UP-14 server PR A): the emit-order pair is stored, never compared. The v4
// predicate (key K, ingest_seq, order_uncertain, ts_hwm/seq_hwm) decides every verdict exactly as
// before; these cases pin only where the pair lands.

TEST_CASE("census ordering: a paired apply stores the pair on the event and on the census row",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    SECTION("the insert arm and the update arm both take the applied event's pair") {
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e1", "r1", "a", kCompliant, kBase + 100), 5, 10))
                    .outcome == EventInsertOutcome::Inserted);
        CHECK(event_pair_text(db.dsn(), "e1") == "5/10");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e2", "r1", "a", kDrifted, kBase + 200), 5, 11))
                    .outcome == EventInsertOutcome::Inserted);
        CHECK(event_pair_text(db.dsn(), "e2") == "5/11");
        CHECK(event_pair_text(db.dsn(), "e1") == "5/10"); // written once, never updated
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/11");
        // The verdict is the v4 verdict: the pair changed nothing about it.
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");
    }
    SECTION("an unpaired event stores NULL/NULL on both tables") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(event_pair_text(db.dsn(), "e1") == "-/-");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "-/-");
    }
    SECTION("an applied unpaired verdict clears the pair of the paired verdict it replaces") {
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e1", "r1", "a", kCompliant, kBase + 100), 5, 10))
                    .outcome == EventInsertOutcome::Inserted);
        REQUIRE(census_pair_text(db.dsn(), "a", "r1") == "5/10");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "-/-");
        CHECK(event_pair_text(db.dsn(), "e1") == "5/10");
        CHECK(event_pair_text(db.dsn(), "e2") == "-/-");
    }
    SECTION("a paired verdict replaces an unpaired one") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e2", "r1", "a", kDrifted, kBase + 200), 7, 3))
                    .outcome == EventInsertOutcome::Inserted);
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "7/3");
    }
}

TEST_CASE("census ordering: a refused event's pair is never written to the census row",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    SECTION("an older key with a higher pair is refused by the v4 rule and keeps the row's pair") {
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e1", "r1", "a", kDrifted, kBase + 200), 5, 10))
                    .outcome == EventInsertOutcome::Inserted);
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e2", "r1", "a", kCompliant, kBase + 100), 6, 99))
                    .outcome == EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
        CHECK(event_pair_text(db.dsn(), "e2") == "6/99"); // the event keeps its own pair
    }
    SECTION("a refused unpaired event does not clear the row's pair") {
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e1", "r1", "a", kDrifted, kBase + 200), 5, 10))
                    .outcome == EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1").ends_with("|true"));
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
    }
}

TEST_CASE("census ordering: a repair projects the pair stored with the event, never the redelivery's",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    install_census_fail(db.dsn(), "NEW.state = 'drifted'");
    const auto e1 = with_pair(ev("e1", "r1", "a", kDrifted, kBase + 100), 5, 10);
    REQUIRE(store.insert_event_classified(e1).outcome == EventInsertOutcome::Inserted);
    REQUIRE(pending_count(db.dsn()) == "1");
    REQUIRE(census(db.dsn(), "a", "r1").empty()); // the forced failure left no census row
    CHECK(event_pair_text(db.dsn(), "e1") == "5/10"); // the pair is stored before the projection
    remove_census_fail(db.dsn());

    auto redelivered = e1;
    SECTION("a 0/0 replay repairs from the stored pair") {
        redelivered.boot_epoch.reset();
        redelivered.emit_seq.reset();
    }
    SECTION("a replay carrying a different pair still repairs from the stored pair") {
        redelivered.boot_epoch = 9;
        redelivered.emit_seq = 99;
    }
    CHECK(store.insert_event_classified(redelivered).outcome == EventInsertOutcome::Redelivered);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 100) + "|" + key_str(kBase + 100) + "|false");
    CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
    CHECK(event_pair_text(db.dsn(), "e1") == "5/10"); // the replay did not rewrite the event
}

TEST_CASE("census ordering: the batch path stores the pair on both tables",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));
    const auto n = store.insert_events(
        {with_pair(ev("b1", "r1", "a", kDrifted, kBase + 200), 4, 20),
         with_pair(ev("b2", "r1", "a", kCompliant, kBase + 100), 4, 21), // refused by key
         ev("b3", "r2", "a", kCompliant, kBase + 100)});                 // unpaired
    REQUIRE(n.has_value());
    CHECK(*n == 3);
    CHECK(event_pair_text(db.dsn(), "b1") == "4/20");
    CHECK(event_pair_text(db.dsn(), "b2") == "4/21");
    CHECK(event_pair_text(db.dsn(), "b3") == "-/-");
    CHECK(census_pair_text(db.dsn(), "a", "r1") == "4/20"); // b2 was refused, its pair not written
    CHECK(census_pair_text(db.dsn(), "a", "r2") == "-/-");
}

TEST_CASE("census ordering: a direct caller cannot store a half or out-of-range pair",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    constexpr std::int64_t k2p62 = std::int64_t{1} << 62;

    const auto stored_unpaired = [&](const std::string& id, GuaranteedStateEventRow e) {
        REQUIRE(store.insert_event_classified(e).outcome == EventInsertOutcome::Inserted);
        CHECK(event_pair_text(db.dsn(), id) == "-/-");
    };
    auto half = ev("h1", "r1", "a", kCompliant, kBase + 100);
    half.boot_epoch = 5;
    stored_unpaired("h1", half);
    auto other_half = ev("h2", "r1", "a", kCompliant, kBase + 110);
    other_half.emit_seq = 5;
    stored_unpaired("h2", other_half);
    stored_unpaired("h3", with_pair(ev("h3", "r1", "a", kCompliant, kBase + 120), k2p62, 1));
    stored_unpaired("h4", with_pair(ev("h4", "r1", "a", kCompliant, kBase + 130), 1, k2p62));
    stored_unpaired("h5", with_pair(ev("h5", "r1", "a", kCompliant, kBase + 140), 0, 7));
    stored_unpaired("h6", with_pair(ev("h6", "r1", "a", kCompliant, kBase + 150), -1, 7));
    CHECK(census_pair_text(db.dsn(), "a", "r1") == "-/-");

    // The edges of the accepted range are stored as given.
    REQUIRE(store
                .insert_event_classified(
                    with_pair(ev("ok", "r1", "a", kDrifted, kBase + 200), 1, k2p62 - 1))
                .outcome == EventInsertOutcome::Inserted);
    CHECK(event_pair_text(db.dsn(), "ok") == "1/" + std::to_string(k2p62 - 1));
    CHECK(census_pair_text(db.dsn(), "a", "r1") == "1/" + std::to_string(k2p62 - 1));
}

TEST_CASE("census ordering: a redelivery never compares or rewrites the pair",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    // Plan 4.1 (a), (b), (d): the pair is neither selected nor compared by the duplicate check.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto e1 = with_pair(ev("e1", "r1", "a", kCompliant, kBase + 100), 5, 10);
    REQUIRE(store.insert_event_classified(e1).outcome == EventInsertOutcome::Inserted);

    SECTION("(a) a 0/0 replay of a stored paired event is a Redelivery that changes nothing") {
        auto replay = e1;
        replay.boot_epoch.reset();
        replay.emit_seq.reset();
        const auto dropped = store.events_dropped_total();
        const auto redelivered = store.events_redelivered_total();
        CHECK(store.insert_event_classified(replay).outcome == EventInsertOutcome::Redelivered);
        CHECK(store.events_dropped_total() == dropped);
        CHECK(store.events_redelivered_total() == redelivered + 1);
        CHECK(store.event_count() == 1);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 100) + "|" + key_str(kBase + 100) + "|false");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
        CHECK(event_pair_text(db.dsn(), "e1") == "5/10");
    }
    SECTION("(b) a replay after a newer verdict applied leaves the newer verdict and pair") {
        REQUIRE(store
                    .insert_event_classified(
                        with_pair(ev("e2", "r1", "a", kDrifted, kBase + 200), 5, 11))
                    .outcome == EventInsertOutcome::Inserted);
        auto replay = e1;
        replay.boot_epoch.reset();
        replay.emit_seq.reset();
        CHECK(store.insert_event_classified(replay).outcome == EventInsertOutcome::Redelivered);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/11");
    }
    SECTION("(d) a replay whose pair differs is a Redelivery, never a Conflict") {
        const auto dropped = store.events_dropped_total();
        CHECK(store.insert_event_classified(with_pair(e1, 9, 99)).outcome ==
              EventInsertOutcome::Redelivered);
        CHECK(store.events_dropped_total() == dropped);
        CHECK(event_pair_text(db.dsn(), "e1") == "5/10");
        CHECK(census_pair_text(db.dsn(), "a", "r1") == "5/10");
    }
}

TEST_CASE("census ordering: an applied event whose pair equals the row's pair is flagged (F8)",
          "[pg][guaranteed_state_store][db][census][ordering][pair]") {
    // Two processes of one agent under one boot epoch can send the same pair. PR A has no
    // comparator, so the v4 rule applies the later key. v5's extended legacy-write trigger flags
    // a state change that leaves a NON-NULL pair unchanged, where v4 leaves the row clean. This is
    // a change of the FLAG, never of the VERDICT: the verdict, key and marks below are v4's.
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.create_rule(make_rule("r2", "guard-two")));

    // Control: the same two verdicts unpaired are clean (the v4 result).
    REQUIRE(store.insert_event_classified(ev("c1", "r2", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("c2", "r2", "a", kDrifted, kBase + 200)).outcome ==
            EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r2") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");

    // Control: a pair that MOVES with the verdict is clean.
    REQUIRE(store
                .insert_event_classified(
                    with_pair(ev("m1", "r1", "a", kCompliant, kBase + 100), 5, 10))
                .outcome == EventInsertOutcome::Inserted);
    REQUIRE(store
                .insert_event_classified(
                    with_pair(ev("m2", "r1", "a", kDrifted, kBase + 200), 5, 11))
                .outcome == EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|false");

    // The F8 shape: the later key applies (v4 verdict) with the SAME pair as the row.
    REQUIRE(store
                .insert_event_classified(
                    with_pair(ev("f1", "r1", "b", kCompliant, kBase + 100), 5, 10))
                .outcome == EventInsertOutcome::Inserted);
    REQUIRE(store
                .insert_event_classified(
                    with_pair(ev("f2", "r1", "b", kDrifted, kBase + 200), 5, 10))
                .outcome == EventInsertOutcome::Inserted);
    CHECK(census(db.dsn(), "b", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
    CHECK(census_pair_text(db.dsn(), "b", "r1") == "5/10");
}
