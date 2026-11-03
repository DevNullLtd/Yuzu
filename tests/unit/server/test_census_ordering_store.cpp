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

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <algorithm>
#include <initializer_list>
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
yuzu::test::PgTestTemplate ordering_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

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
                      "DROP COLUMN ts_hwm, DROP COLUMN seq_hwm, DROP COLUMN hwm_recv_ns, "
                      "DROP COLUMN order_uncertain");
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
                                 "AND attname IN ('key_ns', 'ingest_seq', 'ts_hwm', 'seq_hwm', "
                                 "'hwm_recv_ns', 'order_uncertain') AND NOT attisdropped") == "6");
}

TEST_CASE("census ordering: a v4 database missing the two later census columns is repaired by a reset to version 3",
          "[pg][guaranteed_state_store][db][census][ordering][schema]") {
    // The remedy the upgrade guide gives for a development database stamped v4 by an earlier build of
    // this change: the migration replays with IF NOT EXISTS and adds only what is missing.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    REQUIRE(opens(db.dsn()));
    const std::string st = std::string(kSchema) + ".guardian_agent_rule_status";
    exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN seq_hwm, DROP COLUMN hwm_recv_ns");
    CHECK_FALSE(opens(db.dsn())); // the boot probe refuses it
    exec_sql(db.dsn(), "UPDATE public.schema_meta SET version = 3 "
                       "WHERE store = 'guaranteed_state_store'");
    CHECK(opens(db.dsn()));
    CHECK(schema_version(db.dsn()) == "4");
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
    SECTION("the census seq_hwm column is missing") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN seq_hwm");
    }
    SECTION("the census hwm_recv_ns column is missing") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DROP COLUMN hwm_recv_ns");
    }
    SECTION("the census hwm_recv_ns column is of the wrong type") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " ALTER COLUMN hwm_recv_ns TYPE integer USING 0");
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
    SECTION("the legacy-write trigger was dropped") {
        exec_sql(db.dsn(), "DROP TRIGGER guardian_agent_rule_status_flag_legacy ON " + st);
    }
    SECTION("the legacy-write trigger is disabled") {
        exec_sql(db.dsn(), "ALTER TABLE " + st + " DISABLE TRIGGER guardian_agent_rule_status_flag_legacy");
    }
    SECTION("the sequence was reseeded below the census seq_hwm (the events were reaped)") {
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_rules (rule_id, name, yaml_source, "
                               "created_at, updated_at) VALUES ('r1', 'n1', 'y', 't', 't')");
        exec_sql(db.dsn(), "INSERT INTO " + st + " (agent_id, rule_id, state, updated_at, key_ns, "
                                                "ingest_seq, seq_hwm) VALUES ('a1', 'r1', "
                                                "'compliant', 't', 1, 1, 500)");
        exec_sql(db.dsn(), "SELECT setval('" + seq + "', 2, false)"); // above ingest_seq (1) and at or below seq_hwm (500)
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
    CHECK(cap.text().find("v4: object not as this version creates it") != std::string::npos);
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
// flags, strings) is declared BEFORE the owner so it outlives the join. On scope exit (including a failed REQUIRE) it
// releases the barrier, joins every thread, and only then clears the store's barrier, so a failure
// is a red test and never std::terminate on a joinable thread or a barrier pointing at dead locals.
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

TEST_CASE("census ordering: the later key wins whatever the arrival order and says when it is unsure",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
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
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 100)).outcome ==
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
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
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

TEST_CASE("census ordering: a failed projection leaves pending evidence and a redelivery repairs it",
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

TEST_CASE("census ordering: the batch path orders by key and stores no pending evidence",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
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

TEST_CASE("census ordering: the pending gauge counts stored evidence and reports an error instead of zero",
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
    GuaranteedStateStore closed(dead);
    CHECK_FALSE(closed.pending_projection_count_checked().has_value());
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
        REQUIRE(store.insert_event_classified(ev("fresh-" + std::to_string(i), "r1", "f", kDrifted,
                                                  kBase)).outcome == EventInsertOutcome::Inserted);
    REQUIRE(store.insert_event_classified(ev("stale-ok", "r1", "s", kDrifted, kBase)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    REQUIRE(store.insert_event_classified(ev("stale-pending", "r1", "p", kDrifted, kBase)).outcome ==
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
    REQUIRE(store.insert_event_classified(ev("stale-pending", "r1", "p", kDrifted, kBase)).outcome ==
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

TEST_CASE("census ordering: delete_rule waits on a repair that holds the pair's rows without a deadlock",
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

TEST_CASE("census ordering: a pending event that disagrees with a verdict inserted concurrently keeps the row flagged",
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
    exec_sql(db.dsn(),
             std::string("CREATE FUNCTION ") + kSchema +
                 ".yuzu_test_hold_x() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                 "IF NEW.event_id = 'ux' THEN PERFORM pg_advisory_lock(91001); "
                 "PERFORM pg_advisory_unlock(91001); END IF; RETURN NEW; END $$");
    exec_sql(db.dsn(), std::string("CREATE TRIGGER yuzu_test_hold_x BEFORE INSERT ON ") + kSchema +
                           ".guaranteed_state_events FOR EACH ROW EXECUTE FUNCTION " + kSchema +
                           ".yuzu_test_hold_x()");
    exec_sql(db.dsn(),
             std::string("CREATE FUNCTION ") + kSchema +
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
        pg::PgResult r{PQexec(holder.get(), "SELECT pg_advisory_lock(91001), pg_advisory_lock(91002)")};
        REQUIRE(r.ok());
    }
    const auto unlock = [&](const char* key) {
        pg::PgResult r{PQexec(holder.get(), (std::string("SELECT pg_advisory_unlock(") + key + ")").c_str())};
        REQUIRE(r.ok());
    };

    writers.start([&] { x_res = store.insert_event_classified(ev("ux", "r1", "a", kCompliant, kBase + 100)); });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1, "advisory")); // X holds seq 1, parked in its INSERT
    writers.start([&] { w_res = store.insert_event_classified(ev("uw", "r1", "a", kDrifted, kBase + 200)); });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 2, "advisory")); // W's census INSERT is uncommitted
    // P: committed pending, seq 3, key 150 (its projection "failed" earlier).
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, proj_key, projection_pending) VALUES ('up', 'r1', "
                           "'a', 'guard.compliant', 'high', 't', " + key_str(kBase + 150) + ", true)");
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
    CHECK(pending_count(db.dsn()) == "0"); // P was retired, with the disagreement recorded on the row
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
        {100, 200}, {200, 100}, {150, 150}, {100, 300}, {300, 100}, {250, 251}, {251, 250}, {500, 500}};
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
            return std::stoll(query_scalar(db.dsn(), std::string("SELECT ingest_seq FROM ") + kSchema +
                                                         ".guaranteed_state_events WHERE event_id = '" +
                                                         id + "'"));
        };
        const std::int64_t sa = seq_of(agent + "a");
        const std::int64_t sb = seq_of(agent + "b");
        const bool a_wins = std::make_pair(ka, sa) > std::make_pair(kb, sb);
        const std::int64_t win_key = a_wins ? ka : kb;
        const bool later_is_a = sa > sb;
        const std::int64_t later_key = later_is_a ? ka : kb;
        const std::int64_t earlier_key = later_is_a ? kb : ka;
        // Different verdicts with the same key are flagged too (arrival order is not emission order).
        const bool expect_flag = later_key <= earlier_key;
        INFO("pair " << i << " ka=" << ka << " kb=" << kb << " sa=" << sa << " sb=" << sb);
        CHECK(census(db.dsn(), agent, "r1") ==
              std::string(a_wins ? "drifted" : "compliant") + "|" + key_str(kBase + win_key) + "|" +
                  key_str(kBase + std::max(ka, kb)) + "|" + (expect_flag ? "true" : "false"));
    }
    CHECK(pending_count(db.dsn()) == "0");
    CHECK(store.census_proj_failures_total() == 0); // no 40P01 surfaced as a stale row
}

TEST_CASE("census ordering: a state change that did not come from this version's upsert flags the row",
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

TEST_CASE("census ordering: the happy path writes the event once and a failure records the evidence",
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

TEST_CASE("census ordering: a repair projects from the stored inputs and keeps a lower-key pending row pending",
          "[pg][guaranteed_state_store][db][census][ordering][k]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ordering_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    REQUIRE(store.insert_event_classified(ev("e0", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted);
    install_census_fail(db.dsn(), "true");
    const auto high = ev("h", "r1", "a", kDrifted, kBase + 150);     // seq 2, key 150
    const auto low = ev("l", "r1", "a", kCompliant, kBase + 110);    // seq 3, key 110
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
    CHECK(census(db.dsn(), "old", "r1") ==
          "compliant|" + key_str(kBase + 5) + "|" + key_str(kBase + 5) + "|false"); // not flagged for being pre-v4

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
    CHECK(store.uncertain_rule_count(Scope{}).value() == 2);                      // unfiltered: r1 and r2
    CHECK(store.uncertain_rule_count(Scope{{"A"}}).value() == 1);                 // flagged branch
    CHECK(store.uncertain_rule_count(Scope{{"B"}}).value() == 1);                 // pending branch
    CHECK(store.uncertain_rule_count(Scope{{"C"}}).value() == 0);                 // clean agent
    CHECK(store.uncertain_rule_count(Scope{{"A", "B"}}).value() == 2);
    CHECK(store.uncertain_rule_count(Scope{{"nobody"}}).value() == 0);            // out of scope
    CHECK(store.uncertain_rule_count(Scope{std::vector<std::string>{}}).value() == 0); // engaged-empty

    // An engaged-empty scope is answered without a query, so it holds on a store that is down.
    PgPool dead{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    GuaranteedStateStore closed(dead);
    CHECK(closed.uncertain_rule_count(Scope{std::vector<std::string>{}}).value() == 0);
    CHECK_FALSE(closed.uncertain_rule_count(Scope{}).has_value());
}

TEST_CASE("census ordering: a stale high-water mark stops freezing the verdict after an hour (#5690 UP-11)",
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
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("past the hour a lower key applies by arrival, stays flagged, and keeps the mark") {
        age_mark("3700000000000"); // 61 min 40 s: well past the hour
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
        // The next event in the new clock frame also applies, still flagged.
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kErrored, kBase + 600)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 600) + "|" + key_str(kBase + 1000) + "|true");
        // A key strictly above the mark ends the doubt.
        REQUIRE(store.insert_event_classified(ev("e4", "r1", "a", kCompliant, kBase + 2000)).outcome ==
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
    SECTION("a row with no recorded receipt never recovers") {
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = NULL");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("the receipt time moves only when the mark rises") {
        const std::string before = query_scalar(
            db.dsn(), std::string("SELECT hwm_recv_ns FROM ") + kSchema +
                          ".guardian_agent_rule_status WHERE agent_id = 'a'");
        REQUIRE_FALSE(before.empty());
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted); // refused: the mark does not rise
        CHECK(query_scalar(db.dsn(), std::string("SELECT hwm_recv_ns FROM ") + kSchema +
                                         ".guardian_agent_rule_status WHERE agent_id = 'a'") == before);
    }
}

// "ingest_seq|seq_hwm|max event ingest_seq" of a pair, so a test can see the three move together.
std::string census_internals(const std::string& dsn, const std::string& agent,
                             const std::string& rule) {
    return query_scalar(
        dsn, std::string("SELECT c.ingest_seq || '|' || c.seq_hwm || '|' || (SELECT max(ingest_seq) "
                         "FROM ") +
                 kSchema + ".guaranteed_state_events e WHERE e.agent_id = c.agent_id AND "
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

TEST_CASE("census ordering: a pending event that shares a key with a different verdict is flagged (#5690 UP-3)",
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
        REQUIRE(store.insert_event_classified(ev("d2", "r1", "a", kCompliant, kBase + 300)).outcome ==
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
        REQUIRE(store.insert_event_classified(ev("d2", "r1", "a", kCompliant, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|false");
    }
    SECTION("a row already at the key and an older pending peer at the same key: the apply flags") {
        // The row holds (key, seq 1). A pending peer at the same key with a LOWER sequence than the
        // row can only exist when it became pending after the row's own projection read the pair,
        // so it is written directly. A later event then sees it.
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        REQUIRE(census(db.dsn(), "a", "r1").ends_with("|false"));
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, "
                               "agent_id, event_type, severity, timestamp, ingest_seq, proj_key, "
                               "projection_pending) OVERRIDING SYSTEM VALUE VALUES ('p0', 'r1', 'a', 'drift.detected', "
                               "'high', 't', 0, " + key_str(kBase + 300) + ", true)");
        REQUIRE(pending_count(db.dsn()) == "1");
        // The same verdict at the same key: nothing separates the new event from the row but the
        // pending peer, which shares the winning key.
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
        CHECK(pending_count(db.dsn()) == "0");
    }
    SECTION("an older pending peer at a LOWER key than the winner is irrelevant") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 300)).outcome ==
                EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                               ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                               "severity, timestamp, ingest_seq, proj_key, projection_pending) "
                               "OVERRIDING SYSTEM VALUE VALUES ('p0', 'r1', 'a', 'drift.detected', "
                               "'high', 't', 0, " + key_str(kBase + 200) + ", true)");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kErrored, kBase + 400)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "errored|" + key_str(kBase + 400) + "|" + key_str(kBase + 400) + "|false");
    }
}

TEST_CASE("census ordering: only the fold flags a pending same-key peer that a lower-key lower-sequence arrival sees",
          "[pg][guaranteed_state_store][db][census][ordering][tie]") {
    // The schedule where the fold's same-key term is the ONLY thing that flags the row (found in review): Q (errored, key 300) projects and commits first; P (drifted, the
    // same key, a LOWER sequence) became pending meanwhile; Z (key 100, a sequence BELOW Q's)
    // then projects. Z neither applies nor flags in the upsert (key and sequence both below the row),
    // and the clear would retire P as dominated. Sequences are placed by hand (setval and a
    // hand-written pending row), because three concurrent ingests cannot be ordered otherwise.
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
                           "'high', 't', 3, " + key_str(kBase + 300) + ", true)");
    exec_sql(db.dsn(), "SELECT setval('" + seq + "', 5, false)");
    REQUIRE(store.insert_event_classified(ev("z", "r1", "a", kCompliant, kBase + 100)).outcome ==
            EventInsertOutcome::Inserted); // seq 5: below Q's, above P's
    CHECK(census(db.dsn(), "a", "r1") ==
          "errored|" + key_str(kBase + 300) + "|" + key_str(kBase + 300) + "|true");
    CHECK(pending_count(db.dsn()) == "0");
}

TEST_CASE("census ordering: a lower-sequence arrival with the same key and a different verdict is flagged",
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
    writers.start([&] { w1_res = store.insert_event_classified(ev("w1", "r1", "a", kDrifted, kBase + 500)); });
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
          query_scalar(db.dsn(), std::string("SELECT max(ingest_seq) || '|' || max(ingest_seq) || '|' "
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
    exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                           ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns - 7200000000000");

    EventInsertResult w1_res;
    BarrierHold hold;
    store.set_census_lock_barrier_for_test([&] { hold.hit(); });
    WriterThreads writers(store, &hold);
    writers.start([&] { w1_res = store.insert_event_classified(ev("w1", "r1", "a", kCompliant, kBase + 500)); });
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
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("the update arm stamps it when the mark rises") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        backdate();
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("the fold stamps it when a seen event raises the mark") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kCompliant, kBase + 100)).outcome ==
                EventInsertOutcome::Inserted);
        install_census_fail(db.dsn(), "NEW.state = 'errored'");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kErrored, kBase + 400)).outcome ==
                EventInsertOutcome::Inserted); // pending, outranks the row
        remove_census_fail(db.dsn());
        backdate();
        REQUIRE(store.insert_event_classified(ev("e3", "r1", "a", kDrifted, kBase + 200)).outcome ==
                EventInsertOutcome::Inserted); // sees e2: the fold raises the mark to its key
        CHECK(census(db.dsn(), "a", "r1").find("|" + key_str(kBase + 400) + "|") != std::string::npos);
        CHECK(hwm_recv_is_db_now(db.dsn(), "a") == "true");
    }
    SECTION("a recorded time four minutes ahead is inside the slack: the verdict is still held") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
                EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "240000000000");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "drifted|" + key_str(kBase + 1000) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("a recorded time ten minutes ahead is past the slack: it counts as stale") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
                EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "600000000000");
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    }
    SECTION("a recorded time in the database's future counts as stale, never as an indefinite hold") {
        REQUIRE(store.insert_event_classified(ev("e1", "r1", "a", kDrifted, kBase + 1000)).outcome ==
                EventInsertOutcome::Inserted);
        exec_sql(db.dsn(), std::string("UPDATE ") + kSchema +
                               ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns + "
                               "10800000000000"); // three hours ahead
        REQUIRE(store.insert_event_classified(ev("e2", "r1", "a", kCompliant, kBase + 500)).outcome ==
                EventInsertOutcome::Inserted);
        CHECK(census(db.dsn(), "a", "r1") ==
              "compliant|" + key_str(kBase + 500) + "|" + key_str(kBase + 1000) + "|true");
    }
}

TEST_CASE("census ordering: a refused later arrival is remembered when an earlier one applies afterwards",
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
    writers.start([&] { w0_res = store.insert_event_classified(ev("w0", "r1", "a", kDrifted, kBase + 300)); });
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

TEST_CASE("census ordering: a repair of a rejected event retires its evidence in the outer transaction",
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
    CHECK(metrics.counter("yuzu_server_guardian_census_projection_total",
                          {{"source", "repair"}, {"outcome", "rejected"}}).value() == 1);
    CHECK(store.event_count() == 1); // the audit row stays
}

TEST_CASE("census ordering: a seen event retired by a flagged apply is still remembered by a later apply",
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
    exec_sql(db.dsn(),
             std::string("CREATE FUNCTION ") + kSchema +
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
    writers.start([&] { w1_res = store.insert_event_classified(ev("w1", "r1", "a", kCompliant, kBase + 250)); });
    REQUIRE(wait_for_lock_waiters(db.dsn(), 1, "advisory")); // W1 holds seq 1, parked in its INSERT
    writers.start([&] { w2_res = store.insert_event_classified(ev("w2", "r1", "a", kDrifted, kBase + 300)); });
    REQUIRE(hold.reached_f.wait_for(std::chrono::seconds(10)) == std::future_status::ready); // W2: seq 2, parked
    exec_sql(db.dsn(), std::string("INSERT INTO ") + kSchema +
                           ".guaranteed_state_events (event_id, rule_id, agent_id, event_type, "
                           "severity, timestamp, proj_key, projection_pending) VALUES ('we', 'r1', "
                           "'a', 'guard.unhealthy', 'high', 't', " + key_str(kBase + 100) + ", true)");
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
