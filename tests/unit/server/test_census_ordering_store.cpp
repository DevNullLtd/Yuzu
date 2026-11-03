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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <string>
#include <thread>
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
    return query_scalar(dsn, std::string("SELECT state || '|' || COALESCE(key_ns::text, '-') || '|' "
                                         "|| COALESCE(ts_hwm::text, '-') || '|' || order_uncertain "
                                         "FROM ") +
                                 kSchema + ".guardian_agent_rule_status WHERE agent_id = '" + agent +
                                 "' AND rule_id = '" + rule + "'");
}

std::string pending_count(const std::string& dsn) {
    return query_scalar(dsn, std::string("SELECT count(*) FROM ") + kSchema +
                                 ".guaranteed_state_events WHERE projection_pending");
}

std::string key_str(std::int64_t v) { return std::to_string(v); }

void install_census_fail(const std::string& dsn, const char* when_sql) {
    exec_sql(dsn, std::string("CREATE FUNCTION ") + kSchema +
                      ".yuzu_test_ord_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " +
                      when_sql + " THEN RAISE EXCEPTION 'forced census failure' USING ERRCODE = "
                                 "'XX000'; END IF; RETURN NEW; END $$");
    exec_sql(dsn, std::string("CREATE TRIGGER yuzu_test_ord_fail BEFORE INSERT OR UPDATE ON ") +
                      kSchema + ".guardian_agent_rule_status FOR EACH ROW EXECUTE FUNCTION " +
                      kSchema + ".yuzu_test_ord_fail()");
}

void remove_census_fail(const std::string& dsn) {
    exec_sql(dsn, std::string("DROP TRIGGER yuzu_test_ord_fail ON ") + kSchema +
                      ".guardian_agent_rule_status");
}

} // namespace

TEST_CASE("census ordering: the later key wins whatever the arrival order, and says when it is unsure",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));

    SECTION("in order: the newer verdict replaces the older, no doubt") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
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
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");
        CHECK(store.event_count() == 2); // the refused event is still audited
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("the same key: the later INSERT-allocated sequence wins") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 100) + "|" + key_str(kBase + 100) + "|false");
    }
    SECTION("an arrival that is newer in sequence but older in key leaves the verdict and flags it") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
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
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted); // flagged
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kErrored, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted); // same key as the mark: still unsure
        CHECK(census(db.dsn(), "a", "r1").ends_with("|true"));
        REQUIRE(store.insert_event_classified(ev("e4", "r1", "a", kCompliant, kBase + 400)).outcome ==
                EventInsertOutcome::Inserted); // strictly above: clears
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 400) + "|" + key_str(kBase + 400) + "|false");
    }
}

TEST_CASE("census ordering: the derived key is the agent stamp bounded by receipt plus 300 s",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto key_of = [&](const char* id) {
        return query_scalar(db.dsn(), std::string("SELECT proj_key || '|' || proj_key_capped FROM ") +
                                          kSchema + ".guaranteed_state_events WHERE event_id = '" +
                                          id + "'");
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
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, 1, 0)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(key_of("e1") == "1|false");
    }
}

TEST_CASE("census ordering: events with no census meaning, or no ids, never carry pending evidence",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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

TEST_CASE("census ordering: a failed projection leaves pending evidence and a redelivery repairs it",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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

TEST_CASE("census ordering: two failed projections, then a repair: the disagreement is not lost",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    // Astra SQL pass Q2: H (key 120, seq lower) and L (key 110, seq higher) both fail and stay
    // pending; repairing H folds L, applies H and retires both. Delivered one at a time the same
    // two events leave the row flagged, so the repair must too.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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

TEST_CASE("census ordering: the batch path orders by key and stores no pending evidence",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    const auto n = store.insert_events({ev("b1", "r1", "a", kDrifted, kBase + 200),
                                        ev("b2", "r1", "a", kCompliant, kBase + 100)});
    REQUIRE(n.has_value());
    CHECK(*n == 2);
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(census(db.dsn(), "a", "r1") ==
          "drifted|" + key_str(kBase + 200) + "|" + key_str(kBase + 200) + "|true");

    // A batch projection failure leaves no durable repair evidence (documented limit).
    install_census_fail(db.dsn(), "true");
    const auto m = store.insert_events({ev("b3", "r1", "a", kErrored, kBase + 300)});
    REQUIRE(m.has_value());
    CHECK(pending_count(db.dsn()) == "0");
}

TEST_CASE("census ordering: a sequence collision is an operational error, never a redelivery",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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
    // pair-lock statement; writer B repairs the EARLIER one. Both statements take the pending rows
    // in ingest_seq order, so B waits on the first row A holds instead of closing a lock cycle
    // (40P01), and once A has retired both rows B finds its own evidence gone.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
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

    std::promise<void> reached;
    std::promise<void> release;
    auto reached_f = reached.get_future();
    auto release_f = release.get_future().share();
    std::atomic<int> calls{0};
    store.set_census_lock_barrier_for_test([&] {
        if (calls.fetch_add(1) == 0) {
            reached.set_value();
            release_f.wait();
        }
    });

    EventInsertResult a_res;
    EventInsertResult b_res;
    std::thread a([&] { a_res = store.insert_event_classified(second); });
    REQUIRE(reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    std::thread b([&] { b_res = store.insert_event_classified(first); });
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // B is parked on A's row lock
    release.set_value();
    a.join();
    b.join();
    store.set_census_lock_barrier_for_test({});

    CHECK(a_res.outcome == EventInsertOutcome::Redelivered);
    CHECK(b_res.outcome == EventInsertOutcome::Redelivered);
    CHECK(store.census_proj_failures_total() == failures_before); // no 40P01 became a Failed
    CHECK(pending_count(db.dsn()) == "0");
    // p2 outranks p1 in both key and arrival order, so there is nothing to doubt.
    CHECK(census(db.dsn(), "a", "r1") ==
          "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|false");
}
