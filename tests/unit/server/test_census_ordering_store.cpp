/**
 * test_census_ordering_store.cpp — #5690 PR2a-1: the census ordering key, the durable pending
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

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>
#include <utility>

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

constexpr const char* kSchema = "guaranteed_state_store";

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
                      "DROP COLUMN ts_hwm, DROP COLUMN order_uncertain");
    exec_sql(dsn, "UPDATE public.schema_meta SET version = 3 "
                  "WHERE store = 'guaranteed_state_store'");
}

} // namespace

// ── C1: schema v4 ────────────────────────────────────────────────────────────

TEST_CASE("census ordering: a fresh database migrates to v4 with every v4 object",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "4");
    CHECK(query_scalar(db.dsn(), "SELECT attidentity FROM pg_attribute WHERE attrelid = "
                                 "'guaranteed_state_store.guaranteed_state_events'::regclass "
                                 "AND attname = 'ingest_seq'") == "a");
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_indexes WHERE schemaname = "
                                 "'guaranteed_state_store' AND indexname IN "
                                 "('idx_gse_ingest_seq', 'idx_gse_pending')") == "2");
    CHECK(query_scalar(db.dsn(), "SELECT count(*) FROM pg_attribute WHERE attrelid = "
                                 "'guaranteed_state_store.guardian_agent_rule_status'::regclass "
                                 "AND attname IN ('key_ns', 'ingest_seq', 'ts_hwm', "
                                 "'order_uncertain') AND NOT attisdropped") == "4");
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
                               std::to_string(i) + "', 'r1', 'a1', 'drift.detected', 'high', "
                               "'2026-04-19T12:00:00Z')");
    }
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guardian_agent_rule_status (agent_id, rule_id, state, updated_at) "
                           "VALUES ('a1', 'r1', 'drifted', '2026-04-19T12:00:00Z')");

    REQUIRE(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "4");
    // Pre-v4 events: one distinct sequence value each, no key, never pending.
    CHECK(query_scalar(db.dsn(), std::string("SELECT count(DISTINCT ingest_seq) FROM ") +
                                     kSchema + ".guaranteed_state_events") == "3");
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
    CHECK(schema_version(db.dsn()) == "4");
    CHECK(query_scalar(db.dsn(), objs) == before);
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp) VALUES ('e2', 'r1', 'a1', 'drift.detected', "
                           "'high', 't')");
    CHECK(std::stoll(query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) FROM ") +
                                                kSchema + ".guaranteed_state_events")) >
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

    SECTION("ingest_seq is BY DEFAULT, not ALWAYS") {
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ALTER COLUMN ingest_seq SET GENERATED BY DEFAULT");
    }
    SECTION("idx_gse_pending is not partial") {
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_pending");
        exec_sql(db.dsn(), std::string("CREATE INDEX idx_gse_pending ON ") + ev +
                               " (rule_id, agent_id)");
    }
    SECTION("idx_gse_pending is in the other column order") {
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_pending");
        exec_sql(db.dsn(), std::string("CREATE INDEX idx_gse_pending ON ") + ev +
                               " (agent_id, rule_id) WHERE projection_pending");
    }
    SECTION("the census order_uncertain is nullable") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN order_uncertain DROP NOT NULL");
    }
    SECTION("a census key column of the wrong type") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN key_ns TYPE integer");
    }
    SECTION("proj_key_capped is a generated column, not an ordinary one") {
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " DROP COLUMN proj_key_capped");
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ADD COLUMN proj_key_capped boolean "
                                                "GENERATED ALWAYS AS (false) STORED NOT NULL");
    }
    SECTION("the sequence has a low maximum") {
        exec_sql(db.dsn(), "ALTER SEQUENCE " + seq + " MAXVALUE 2");
    }
    SECTION("the unique index was replaced by a deferred constraint") {
        exec_sql(db.dsn(), std::string("DROP INDEX ") + kSchema + ".idx_gse_ingest_seq");
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " ADD CONSTRAINT idx_gse_ingest_seq UNIQUE "
                                                "(ingest_seq) DEFERRABLE INITIALLY DEFERRED");
    }
    SECTION("the census foreign key was renamed (the 23503 classifier keys on the name)") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " RENAME CONSTRAINT "
                                                "guardian_agent_rule_status_rule_fk TO adopted_fk");
    }
    SECTION("the event primary key was renamed (the 23505 classifier keys on the name)") {
        exec_sql(db.dsn(), "ALTER TABLE " + ev + " RENAME CONSTRAINT "
                                                "guaranteed_state_events_pkey TO adopted_pk");
    }
    SECTION("the sequence was reseeded below the retained maximum") {
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_rules (rule_id, name, yaml_source, "
                               "created_at, updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
        exec_sql(db.dsn(), "INSERT INTO " + ev + " (event_id, rule_id, agent_id, event_type, "
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
    CHECK(cap.text().find("v4") != std::string::npos);
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
