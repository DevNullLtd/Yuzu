/**
 * test_software_lifecycle_store.cpp - SoftwareLifecycleStore (born-on-Postgres, schema
 * `software_lifecycle_store`): migration, source-scoped idempotent rule replacement, distinct
 * declared facts with the newest last_seen, authoritative reads (a degrade is never an empty
 * answer), the 500-lookup bound, the declared-read row cap and exact-pair selection, the
 * replace_rules rollback and advisory-lock serialisation, and agreement between evaluate_batch and
 * the pure evaluator.
 */

#include "software_lifecycle_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_catalogue_model.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using Kind = SoftwareLifecycleStore::Error::Kind;

namespace {

yuzu::test::PgTestTemplate lifecycle_tpl{"lifecyclestore", [](const std::string& dsn) {
                                             PgPool pool{{.conninfo = dsn, .size = 1}};
                                             SoftwareLifecycleStore store{pool};
                                             if (!store.is_open())
                                                 throw std::runtime_error(
                                                     "lifecycle template: store failed to migrate");
                                         }};

constexpr std::int64_t kNow = 10'000'000;
constexpr const char* kToday = "2026-11-14";
const std::string kKey = "product:postgresql:postgresql";

LifecycleRule rule(LifecycleSource src, std::string key, std::string prefix, LifecycleEvent ev,
                   std::string date, std::string ref = "ref") {
    return LifecycleRule{std::move(key), std::move(prefix), ev, std::move(date), src,
                         std::move(ref), 0};
}

DeclaredFact fact(std::string version, LifecycleEvent ev, std::string date, std::int64_t seen,
                  std::string key = kKey) {
    return DeclaredFact{std::move(key), std::move(version), ev, std::move(date), seen};
}

// Direct SQL against the clone for the shapes the store API cannot produce.
std::string scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQerrorMessage(conn.get()));
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

} // namespace

#define LIFECYCLE_STORE(store_var)                                                                 \
    YUZU_REQUIRE_PG_DB_TPL(lifecycle_db_fx_, lifecycle_tpl);                                       \
    PgPool lifecycle_pool_fx_{{.conninfo = lifecycle_db_fx_.dsn(), .size = 2}};                    \
    REQUIRE(lifecycle_pool_fx_.valid());                                                           \
    SoftwareLifecycleStore store_var{lifecycle_pool_fx_};                                          \
    REQUIRE(store_var.is_open())

TEST_CASE("SoftwareLifecycleStore: migration creates both tables and is a no-op twice",
          "[pg][store][lifecycle][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    SoftwareLifecycleStore store{pool};
    REQUIRE(store.is_open());
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM information_schema.tables WHERE table_schema = "
                           "'software_lifecycle_store'") == "2");
    CHECK(scalar(db.dsn(), "SELECT version FROM public.schema_meta WHERE store = "
                           "'software_lifecycle_store'") == "1");
    SoftwareLifecycleStore again{pool};
    CHECK(again.is_open());
}

TEST_CASE("SoftwareLifecycleStore: replace_rules is idempotent and replaces only its own source",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    const auto shipped = std::vector<LifecycleRule>{
        rule(LifecycleSource::shipped, kKey, "16", LifecycleEvent::end_of_life, "2028-11-09", "s16"),
        rule(LifecycleSource::shipped, kKey, "15", LifecycleEvent::end_of_life, "2027-11-11", "s15")};
    const auto external = std::vector<LifecycleRule>{
        rule(LifecycleSource::external, kKey, "16", LifecycleEvent::end_of_life, "2029-01-01", "x16")};

    REQUIRE(store.replace_rules(LifecycleSource::shipped, shipped).value() == 2);
    REQUIRE(store.replace_rules(LifecycleSource::external, external).value() == 1);
    // Idempotent: the same load again changes nothing.
    REQUIRE(store.replace_rules(LifecycleSource::shipped, shipped).value() == 2);
    auto rules = store.rules_for({kKey});
    REQUIRE(rules.has_value());
    CHECK(rules->size() == 3);

    SECTION("a smaller shipped set drops the removed rows and leaves external alone") {
        REQUIRE(store.replace_rules(LifecycleSource::shipped, {shipped[0]}).value() == 1);
        rules = store.rules_for({kKey});
        REQUIRE(rules.has_value());
        REQUIRE(rules->size() == 2);
        std::size_t n_ext = 0;
        for (const auto& r : *rules)
            n_ext += r.source == LifecycleSource::external;
        CHECK(n_ext == 1);
    }
    SECTION("an empty set clears the source") {
        REQUIRE(store.replace_rules(LifecycleSource::shipped, {}).value() == 0);
        rules = store.rules_for({kKey});
        REQUIRE(rules.has_value());
        REQUIRE(rules->size() == 1);
        CHECK((*rules)[0].source == LifecycleSource::external);
    }
    SECTION("rows round-trip: date, event, prefix, reference and database-clock loaded_at") {
        const auto got = store.rules_for({kKey});
        REQUIRE(got.has_value());
        const auto it = std::find_if(got->begin(), got->end(), [](const LifecycleRule& r) {
            return r.source == LifecycleSource::shipped && r.version_prefix == "16";
        });
        REQUIRE(it != got->end());
        CHECK(it->date == "2028-11-09");
        CHECK(it->event == LifecycleEvent::end_of_life);
        CHECK(it->source_ref == "s16");
        CHECK(it->loaded_at > 1'700'000'000);
    }
    SECTION("a bad rule set is refused and changes nothing") {
        auto bad = shipped;
        bad.push_back(rule(LifecycleSource::shipped, kKey, "14", LifecycleEvent::end_of_life,
                           "2026-02-30"));
        CHECK_FALSE(store.replace_rules(LifecycleSource::shipped, bad).has_value());
        auto dup = shipped;
        dup.push_back(shipped[0]);
        CHECK_FALSE(store.replace_rules(LifecycleSource::shipped, dup).has_value());
        CHECK_FALSE(store.replace_rules(LifecycleSource::shipped, external).has_value()); // wrong source
        CHECK_FALSE(store.replace_rules(LifecycleSource::declared, {}).has_value());
        CHECK(store.rules_for({kKey})->size() == 3);
    }
}

TEST_CASE("SoftwareLifecycleStore: upsert_declared dedups to distinct facts and keeps the newest last_seen",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    REQUIRE(store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2027-01-01", 100),
                                   fact("16", LifecycleEvent::end_of_life, "2027-01-01", 300),
                                   fact("16", LifecycleEvent::end_of_support, "2026-06-01", 100)}));
    // A later, older report of the same fact never moves last_seen back.
    REQUIRE(store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2027-01-01", 200)}));
    const auto got = store.declared_for({{kKey, "16"}});
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2);
    for (const auto& f : *got)
        if (f.event == LifecycleEvent::end_of_life)
            CHECK(f.last_seen == 300);
        else
            CHECK(f.last_seen == 100);
    CHECK(scalar(lifecycle_db_fx_.dsn(),
                 "SELECT count(*) FROM software_lifecycle_store.lifecycle_declared") == "2");

    SECTION("an invalid fact refuses the whole batch") {
        CHECK_FALSE(store.upsert_declared(
            {fact("17", LifecycleEvent::end_of_life, "2028-01-01", 1),
             fact("17", LifecycleEvent::end_of_life, "not-a-date", 1)}));
        CHECK(store.declared_for({{kKey, "17"}})->empty());
    }
    SECTION("a negative last_seen or an empty version is refused") {
        CHECK_FALSE(
            store.upsert_declared({fact("17", LifecycleEvent::end_of_life, "2028-01-01", -1)}));
        CHECK_FALSE(store.upsert_declared({fact("", LifecycleEvent::end_of_life, "2028-01-01", 1)}));
        CHECK(scalar(lifecycle_db_fx_.dsn(),
                     "SELECT count(*) FROM software_lifecycle_store.lifecycle_declared") == "2");
    }
    SECTION("an empty batch is a successful no-op") { CHECK(store.upsert_declared({})); }
}

TEST_CASE("SoftwareLifecycleStore: a corrected date keeps both rows, each with its own last_seen",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    REQUIRE(store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2026-08-01", 1000)}));
    REQUIRE(store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2026-12-01", 9'900'000)}));
    const auto got = store.declared_for({{kKey, "16"}});
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2); // the store keeps both; the evaluator supersedes
    // The old date is stale at kNow and the corrected one is current: the corrected date wins.
    const auto ev = store.evaluate_batch({{kKey, "16"}}, kToday, kNow);
    REQUIRE(ev.has_value());
    REQUIRE(ev->size() == 1);
    CHECK((*ev)[0].end_of_life->date == "2026-12-01");
    CHECK_FALSE((*ev)[0].conflict);
    CHECK((*ev)[0].status == LifecycleStatus::current);
}

TEST_CASE("SoftwareLifecycleStore: reads are empty VALUES on no rows and nullopt on a degrade",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    SECTION("no rows is an empty value, not a degrade") {
        const auto rules = store.rules_for({"product:no:such"});
        REQUIRE(rules.has_value());
        CHECK(rules->empty());
        const auto declared = store.declared_for({{"product:no:such", "1"}});
        REQUIRE(declared.has_value());
        CHECK(declared->empty());
        CHECK(store.rules_for({})->empty());
        CHECK(store.declared_for({})->empty());
    }
    SECTION("a backend failure (schema dropped) degrades reads - never a silent empty") {
        exec_sql(lifecycle_db_fx_.dsn(), "DROP SCHEMA software_lifecycle_store CASCADE");
        CHECK_FALSE(store.rules_for({kKey}).has_value());
        CHECK_FALSE(store.declared_for({{kKey, "16"}}).has_value());
        CHECK_FALSE(store.evaluate_batch({{kKey, "16"}}, kToday, kNow).has_value());
        CHECK_FALSE(
            store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2027-01-01", 1)}));
        CHECK(metrics
                  .counter("yuzu_server_software_lifecycle_store_read_degrade_total",
                           {{"reason", "query_error"}})
                  .value() >= 3.0);
        CHECK(metrics
                  .counter("yuzu_server_software_lifecycle_store_write_degrade_total",
                           {{"reason", "query_error"}})
                  .value() == 1.0);
    }
    SECTION("a held pool is a degrade, never an empty answer") {
        store.set_acquire_timeout_for_test(std::chrono::milliseconds{50});
        auto lease1 = lifecycle_pool_fx_.acquire();
        auto lease2 = lifecycle_pool_fx_.acquire();
        REQUIRE(lease1);
        REQUIRE(lease2);
        CHECK_FALSE(store.rules_for({kKey}).has_value());
        CHECK_FALSE(store.declared_for({{kKey, "16"}}).has_value());
        CHECK_FALSE(
            store.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2027-01-01", 1)}));
        CHECK(metrics
                  .counter("yuzu_server_software_lifecycle_store_read_degrade_total",
                           {{"reason", "pool_acquire_timeout"}})
                  .value() == 2.0);
        CHECK(metrics
                  .counter("yuzu_server_software_lifecycle_store_write_degrade_total",
                           {{"reason", "pool_acquire_timeout"}})
                  .value() == 1.0);
    }
    SECTION("a row the closed event set refuses is a degrade, never a silent skip") {
        // Drop the CHECKs so the tables can hold a row the store's own writes never produce.
        exec_sql(lifecycle_db_fx_.dsn(), "ALTER TABLE software_lifecycle_store.lifecycle_rule "
                                         "DROP CONSTRAINT lifecycle_rule_event_check");
        exec_sql(lifecycle_db_fx_.dsn(), "ALTER TABLE software_lifecycle_store.lifecycle_declared "
                                         "DROP CONSTRAINT lifecycle_declared_event_check");
        exec_sql(lifecycle_db_fx_.dsn(),
                 "INSERT INTO software_lifecycle_store.lifecycle_rule (product_key, version_prefix, "
                 "event, event_date, source, source_ref, loaded_at) VALUES "
                 "('product:corrupt', '', 'not_an_event', DATE '2030-01-01', 'shipped', 'r', 1)");
        exec_sql(lifecycle_db_fx_.dsn(),
                 "INSERT INTO software_lifecycle_store.lifecycle_declared (product_key, version, "
                 "event, event_date, last_seen) VALUES "
                 "('product:corrupt', '1', 'not_an_event', DATE '2030-01-01', 1)");
        CHECK_FALSE(store.rules_for({"product:corrupt"}).has_value());
        CHECK_FALSE(store.declared_for({{"product:corrupt", "1"}}).has_value());
        CHECK(metrics
                  .counter("yuzu_server_software_lifecycle_store_read_degrade_total",
                           {{"reason", "corrupt_row"}})
                  .value() == 2.0);
    }
}

TEST_CASE("SoftwareLifecycleStore: a store whose schema drifted does not open and degrades every call",
          "[pg][store][lifecycle][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    {
        SoftwareLifecycleStore fresh{pool};
        REQUIRE(fresh.is_open());
    }
    yuzu::MetricsRegistry metrics;
    // schema_meta says v1 is applied, so the runner skips it; the projection check catches the
    // drift.
    exec_sql(db.dsn(), "ALTER TABLE software_lifecycle_store.lifecycle_rule "
                       "RENAME COLUMN source_ref TO source_ref_gone");
    SoftwareLifecycleStore closed{pool};
    REQUIRE_FALSE(closed.is_open());
    closed.set_metrics(&metrics);
    CHECK_FALSE(closed.rules_for({kKey}).has_value());
    CHECK_FALSE(closed.declared_for({{kKey, "16"}}).has_value());
    const auto ev = closed.evaluate_batch({{kKey, "16"}}, kToday, kNow);
    REQUIRE_FALSE(ev.has_value());
    CHECK(ev.error().kind == Kind::Unavailable);
    CHECK_FALSE(closed.replace_rules(LifecycleSource::shipped, {}).has_value());
    CHECK_FALSE(closed.upsert_declared({fact("16", LifecycleEvent::end_of_life, "2027-01-01", 1)}));
    CHECK(metrics
              .counter("yuzu_server_software_lifecycle_store_read_degrade_total",
                       {{"reason", "store_not_open"}})
              .value() >= 3.0);
    CHECK(metrics
              .counter("yuzu_server_software_lifecycle_store_write_degrade_total",
                       {{"reason", "store_not_open"}})
              .value() >= 1.0);
}

TEST_CASE("SoftwareLifecycleStore: declared_for selects exact (key, version) pairs, never a cross product",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    const std::string a = kKey;
    const std::string b = "product:other:thing";
    REQUIRE(store.upsert_declared({fact("1", LifecycleEvent::end_of_life, "2027-01-01", 100, a),
                                   fact("2", LifecycleEvent::end_of_life, "2028-01-01", 100, b)}));
    // Each key is stored under the other's version only: a read by key alone, or by the two
    // lists as a cross product, would return both rows.
    const auto crossed = store.declared_for({{a, "2"}, {b, "1"}});
    REQUIRE(crossed.has_value());
    CHECK(crossed->empty());
    const auto exact = store.declared_for({{a, "1"}, {b, "2"}});
    REQUIRE(exact.has_value());
    CHECK(exact->size() == 2);
}

TEST_CASE("SoftwareLifecycleStore: a declared read over the row cap is a degrade, never a truncated answer",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    const auto row_cap = [&] {
        return metrics
            .counter("yuzu_server_software_lifecycle_store_read_degrade_total",
                     {{"reason", "row_cap"}})
            .value();
    };
    // 20,001 distinct dates for one (key, version, event): one row past the 20,000 cap, in one
    // statement.
    exec_sql(lifecycle_db_fx_.dsn(),
             "INSERT INTO software_lifecycle_store.lifecycle_declared (product_key, version, event, "
             "event_date, last_seen) SELECT '" +
                 kKey + "', '16', 'end_of_life', DATE '2000-01-01' + g, 1 "
                        "FROM generate_series(0, 20000) g");
    REQUIRE(scalar(lifecycle_db_fx_.dsn(),
                   "SELECT count(*) FROM software_lifecycle_store.lifecycle_declared") == "20001");

    CHECK_FALSE(store.declared_for({{kKey, "16"}}).has_value());
    CHECK(row_cap() == 1.0);
    const auto ev = store.evaluate_batch({{kKey, "16"}}, kToday, kNow);
    REQUIRE_FALSE(ev.has_value());
    CHECK(ev.error().kind == Kind::Unavailable);
    CHECK(row_cap() == 2.0); // evaluate_batch reads declared facts once

    // Exactly at the cap is an answer.
    exec_sql(lifecycle_db_fx_.dsn(), "DELETE FROM software_lifecycle_store.lifecycle_declared "
                                     "WHERE event_date = DATE '2000-01-01'");
    const auto at_cap = store.declared_for({{kKey, "16"}});
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->size() == 20000);
    CHECK(row_cap() == 2.0);
}

TEST_CASE("SoftwareLifecycleStore: a failed replace_rules rolls back and leaves the stored rows alone",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    const auto two = std::vector<LifecycleRule>{
        rule(LifecycleSource::shipped, kKey, "16", LifecycleEvent::end_of_life, "2028-11-09",
             "s16"),
        rule(LifecycleSource::shipped, kKey, "15", LifecycleEvent::end_of_life, "2027-11-11",
             "s15")};
    REQUIRE(store.replace_rules(LifecycleSource::shipped, two).value() == 2);

    // A constraint only this test adds: the DELETE succeeds, then the INSERT is refused, so the
    // two stored rows survive only if the whole transaction rolled back.
    exec_sql(lifecycle_db_fx_.dsn(),
             "ALTER TABLE software_lifecycle_store.lifecycle_rule ADD CONSTRAINT test_refuse_key "
             "CHECK (product_key <> 'product:refused')");
    const auto refused = store.replace_rules(
        LifecycleSource::shipped,
        {rule(LifecycleSource::shipped, "product:refused", "", LifecycleEvent::end_of_life,
              "2030-01-01")});
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("SQLSTATE 23514") != std::string::npos);
    const auto after = store.rules_for({kKey, "product:refused"});
    REQUIRE(after.has_value());
    CHECK(after->size() == 2);
    CHECK(metrics
              .counter("yuzu_server_software_lifecycle_store_write_degrade_total",
                       {{"reason", "txn_failed"}})
              .value() == 1.0);
}

TEST_CASE("SoftwareLifecycleStore: replace_rules serialises on its advisory lock and fails within lock_timeout",
          "[pg][store][lifecycle]") {
    YUZU_REQUIRE_PG_DB_TPL(db, lifecycle_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1, .lock_timeout_ms = 300}};
    REQUIRE(pool.valid());
    SoftwareLifecycleStore store{pool};
    REQUIRE(store.is_open());
    const auto one = std::vector<LifecycleRule>{
        rule(LifecycleSource::shipped, kKey, "16", LifecycleEvent::end_of_life, "2028-11-09",
             "s16")};
    auto two = one;
    two.push_back(rule(LifecycleSource::shipped, kKey, "15", LifecycleEvent::end_of_life,
                       "2027-11-11", "s15"));
    REQUIRE(store.replace_rules(LifecycleSource::shipped, one).value() == 1);

    // Another transaction holds the replacement lock, as a second replica starting at the same
    // moment would. Removing the pg_advisory_xact_lock statement from replace_rules makes the
    // blocked call below succeed, so this case fails.
    PgConn holder{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    REQUIRE(PgResult{PQexec(holder.get(), "BEGIN")}.status() == PGRES_COMMAND_OK);
    REQUIRE(PgResult{PQexec(holder.get(), "SELECT pg_advisory_xact_lock(hashtextextended("
                                          "'software_lifecycle_rules', 0))")}
                .status() == PGRES_TUPLES_OK);
    const auto blocked = store.replace_rules(LifecycleSource::shipped, two);
    REQUIRE_FALSE(blocked.has_value());
    CHECK(store.rules_for({kKey})->size() == 1); // unchanged; the pool's one connection is reusable

    // Released, the same call lands on the same connection.
    REQUIRE(PgResult{PQexec(holder.get(), "COMMIT")}.status() == PGRES_COMMAND_OK);
    REQUIRE(store.replace_rules(LifecycleSource::shipped, two).value() == 2);
    CHECK(store.rules_for({kKey})->size() == 2);
}

TEST_CASE("SoftwareLifecycleStore: evaluate_batch refuses more than 500 lookups",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    std::vector<LifecycleLookup> lookups;
    for (std::size_t i = 0; i < kLifecycleBatchMax; ++i)
        lookups.push_back({"product:k" + std::to_string(i), "1"});
    const auto at_cap = store.evaluate_batch(lookups, kToday, kNow);
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->size() == kLifecycleBatchMax);
    lookups.push_back({"product:one-too-many", "1"});
    const auto over = store.evaluate_batch(lookups, kToday, kNow);
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().kind == Kind::TooMany);

    SECTION("a malformed date or lookup is refused before any read") {
        CHECK(store.evaluate_batch({{kKey, "1"}}, "2026-13-01", kNow).error().kind ==
              Kind::InvalidInput);
        CHECK(store.evaluate_batch({{"", "1"}}, kToday, kNow).error().kind == Kind::InvalidInput);
    }
    SECTION("an empty batch is an empty answer") {
        const auto none = store.evaluate_batch({}, kToday, kNow);
        REQUIRE(none.has_value());
        CHECK(none->empty());
    }
}

TEST_CASE("SoftwareLifecycleStore: evaluate_batch equals the pure evaluator on the same inputs",
          "[pg][store][lifecycle]") {
    LIFECYCLE_STORE(store);
    const std::string other = "os:ubuntu";
    REQUIRE(store.replace_rules(
        LifecycleSource::shipped,
        {rule(LifecycleSource::shipped, kKey, "", LifecycleEvent::end_of_life, "2030-01-01", "all"),
         rule(LifecycleSource::shipped, kKey, "14", LifecycleEvent::end_of_life, "2026-11-12", "pg14"),
         rule(LifecycleSource::shipped, other, "22.04", LifecycleEvent::end_of_support, "2027-06-01",
              "u22")}));
    REQUIRE(store.replace_rules(
        LifecycleSource::external,
        {rule(LifecycleSource::external, kKey, "14", LifecycleEvent::end_of_life, "2027-01-01", "x14")}));
    REQUIRE(store.upsert_declared({fact("14.2", LifecycleEvent::end_of_life, "2026-09-01", kNow - 5),
                                   fact("16.1", LifecycleEvent::end_of_life, "2026-01-01",
                                        kNow - 200'000)}));

    const std::vector<LifecycleLookup> lookups{{kKey, "14.2"}, {kKey, "14.9"}, {kKey, "16.1"},
                                               {other, "22.04"}, {other, "99.1"}, {"product:none", "1"}};
    const auto batch = store.evaluate_batch(lookups, kToday, kNow);
    REQUIRE(batch.has_value());
    REQUIRE(batch->size() == lookups.size());

    // The same rows through the pure function, one lookup at a time.
    const auto rules = store.rules_for({kKey, other, "product:none"});
    const auto declared = store.declared_for(lookups);
    REQUIRE(rules.has_value());
    REQUIRE(declared.has_value());
    for (std::size_t i = 0; i < lookups.size(); ++i) {
        CAPTURE(i, lookups[i].product_key, lookups[i].version);
        CHECK((*batch)[i] == evaluate_lifecycle(lookups[i].product_key, lookups[i].version, *rules,
                                                *declared, kToday, kNow,
                                                software_catalogue::kStaleWindowSecs));
    }
    // Spot checks that the comparison is not vacuous.
    CHECK((*batch)[0].end_of_life->source == LifecycleSource::declared); // current declared wins
    CHECK((*batch)[1].end_of_life->source == LifecycleSource::external); // 14.9: external beats shipped
    CHECK((*batch)[1].conflict);
    CHECK((*batch)[2].end_of_life->source == LifecycleSource::shipped);  // 16.1: stale fact loses
    CHECK((*batch)[3].state == LifecycleState::supported);
    CHECK((*batch)[4].state == LifecycleState::unknown);
    CHECK((*batch)[5].state == LifecycleState::unknown);
}
