// test_pg_retention_guard.cpp — WS-10 (#2508): the shared clock-guarded,
// single-writer, capped retention DELETE (pg/pg_retention_guard.{hpp,cpp}). This
// binds the parts the three prune stores rely on: advisory-lock serialization
// (a lost race SKIPS), the part-6 bootstrap Decline/Proceed policies, the classify
// declines reachable by manipulating the durable anchor (prev_unusable / big_step
// / would_wipe), the unconditional cap, and durable anchor persistence.

#include "pg/pg_retention_guard.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using yuzu::server::pg::ClockGuardedPruneSpec;
using yuzu::server::pg::MissingAnchorPolicy;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::run_clock_guarded_prune;
using namespace std::chrono_literals;

namespace {

// A scratch store: a `t` table with a ms timestamp column + a retention_meta.
void setup_schema(PgPool& pool) {
    // Multi-statement DDL — PQexec (not exec_params/PQexecParams, which runs a
    // single command). PQexec returns the LAST command's result.
    REQUIRE(pool.with_txn_for(2000ms, [](PGconn* c) {
        PgResult r{PQexec(
            c,
            "CREATE SCHEMA IF NOT EXISTS rg_test;"
            "CREATE TABLE IF NOT EXISTS rg_test.t (id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS rg_test.retention_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "TRUNCATE rg_test.t; DELETE FROM rg_test.retention_meta;")};
        return r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK;
    }));
}

std::int64_t db_now_ms(PgPool& pool) {
    // Production reads the shared PostgreSQL clock. A host-clock anchor can
    // be a few milliseconds ahead of a remote/VM database and correctly trip
    // BadState, obscuring the cap/lock/wipe behavior the fixture intends to test.
    std::int64_t value = 0;
    REQUIRE(pool.with_txn_for(2000ms, [&](PGconn* c) {
        PgResult r = yuzu::server::pg::exec_params(
            c, "SELECT (EXTRACT(EPOCH FROM now())*1000)::bigint",
            std::vector<std::string>{});
        if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1 ||
            PQgetisnull(r.get(), 0, 0))
            return false;
        value = std::stoll(PQgetvalue(r.get(), 0, 0));
        return true;
    }));
    return value;
}

// Seed `n` rows all stamped `age_ms` in the past (so a small window expires them).
void seed(PgPool& pool, int n, std::int64_t age_ms) {
    const std::int64_t ts = db_now_ms(pool) - age_ms;
    REQUIRE(pool.with_txn_for(2000ms, [&](PGconn* c) {
        for (int i = 0; i < n; ++i)
            if (yuzu::server::pg::exec_params(c, "INSERT INTO rg_test.t (ts) VALUES ($1::bigint)",
                                              std::vector<std::string>{std::to_string(ts)})
                    .status() != PGRES_COMMAND_OK)
                return false;
        return true;
    }));
}

std::int64_t count_rows(PgPool& pool) {
    std::int64_t n = -1;
    pool.with_txn_for(2000ms, [&](PGconn* c) {
        PgResult r = yuzu::server::pg::exec_params(c, "SELECT COUNT(*) FROM rg_test.t",
                                                   std::vector<std::string>{});
        if (r.status() != PGRES_TUPLES_OK)
            return false;
        n = std::stoll(PQgetvalue(r.get(), 0, 0));
        return true;
    });
    return n;
}

// Directly set a retention_meta value (to inject a poisoned/old anchor, or the
// settled marker, so the classify declines become reachable in a unit test).
void set_meta(PgPool& pool, const std::string& key, const std::string& value) {
    REQUIRE(pool.with_txn_for(2000ms, [&](PGconn* c) {
        return yuzu::server::pg::exec_params(
                   c,
                   "INSERT INTO rg_test.retention_meta (key,value) VALUES ($1,$2) "
                   "ON CONFLICT (key) DO UPDATE SET value=excluded.value",
                   std::vector<std::string>{key, value})
                   .status() == PGRES_COMMAND_OK;
    }));
}

ClockGuardedPruneSpec spec(std::int64_t window_ms, std::int64_t cap, MissingAnchorPolicy policy,
                           std::int64_t cutoff_align = 0) {
    return ClockGuardedPruneSpec{
        .store_label = "rg_test",
        .target_table = "rg_test.t",
        .ts_column = "ts",
        .now_expr = "(EXTRACT(EPOCH FROM now())*1000)::bigint",
        .meta_table = "rg_test.retention_meta",
        .anchor_key = "t_last_pass_now",
        .settled_key = "t_bootstrap_settled",
        .facts_key = "t_last_anomaly_facts",
        .advisory_lock_key = "hashtext('rg_test:t_prune')",
        .retention_window = window_ms,
        .big_step_floor = 86'400'000,       // 24h
        .implausibility_bound = 86'400'000, // ts is never future
        .min_plausible_reading = 946'684'800'000, // year 2000 in ms
        .cap_per_pass = cap,
        .missing_anchor = policy,
        .cutoff_align = cutoff_align,
    };
}

} // namespace

TEST_CASE("retention guard: bootstrap DECLINES once, then proceeds", "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 5, 3'600'000); // 5 expired (1h old)
    seed(pool, 1, 0);         // 1 recent — so this is NOT would_wipe (isolates the bootstrap decline)

    auto s = spec(/*window*/ 60'000, /*cap*/ 100, MissingAnchorPolicy::Decline);
    auto r1 = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK(r1.deleted == 0);       // part-6 Decline: no anchor + data → decline
    CHECK(r1.declined);
    CHECK(count_rows(pool) == 6); // nothing deleted yet
    auto r2 = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(r2.declined);
    CHECK(r2.deleted == 5);       // now proceeds; the recent row survives
    CHECK(count_rows(pool) == 1);
}

TEST_CASE("retention guard: PROCEED policy deletes on the first pass",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 3, 3'600'000); // 3 expired
    seed(pool, 1, 0);         // 1 recent — not would_wipe

    auto s = spec(60'000, 100, MissingAnchorPolicy::Proceed);
    auto r = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(r.declined); // Proceed never sets no_anchor → proceeds on the first pass
    CHECK(r.deleted == 3);
    CHECK(count_rows(pool) == 1);
}

TEST_CASE("retention guard: a held advisory lock makes the pass SKIP",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    // Set the store up so that, ABSENT the lock, this pass would DELETE (not decline):
    // 4 expired + 1 recent (→ not would_wipe), past bootstrap, with a fresh plausible
    // anchor (→ no Step). The ONLY reason nothing happens is the held lock.
    seed(pool, 4, 3'600'000);
    seed(pool, 1, 0);
    set_meta(pool, "t_bootstrap_settled", "1");
    set_meta(pool, "t_last_pass_now", std::to_string(db_now_ms(pool)));

    // Hold the SAME advisory-lock key (session-scoped) on an independent backend.
    PgConn holder{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    PgResult lk{PQexec(holder.get(), "SELECT pg_advisory_lock(hashtext('rg_test:t_prune'))")};
    REQUIRE(lk.status() == PGRES_TUPLES_OK);

    auto r = run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);
    CHECK(r.skipped_lock);
    CHECK(r.deleted == 0);
    CHECK(count_rows(pool) == 5); // untouched — the holder wins the tick
    // Own the PGresult: a bare PQexec() here leaked it, which LeakSanitizer fails the
    // nightly ASan leg on (3,288 bytes, test_pg_retention_guard.cpp).
    PgResult unlock{PQexec(holder.get(), "SELECT pg_advisory_unlock(hashtext('rg_test:t_prune'))")};
    CHECK(unlock.status() == PGRES_TUPLES_OK);
}

TEST_CASE("retention guard: an unusable persisted anchor DECLINES (BadState)",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 2, 3'600'000);
    set_meta(pool, "t_bootstrap_settled", "1");
    set_meta(pool, "t_last_pass_now", "123"); // below min_plausible_reading → prev_unusable

    auto r = run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);
    CHECK(r.anomaly == yuzu::server::audit_retention::Anomaly::BadState);
    CHECK(r.declined);
    CHECK(count_rows(pool) == 2); // declined — nothing deleted
}

TEST_CASE("retention guard: an ahead-of-now anchor DECLINES (BadState, part 3)",
          "[pg][store][retention-guard]") {
    // Part 3 (docs/clock-guarded-retention.md): "Ahead-of-now, negative, or
    // unparseable is an anomaly, never a quiet reset." A persisted anchor in the
    // FUTURE by LESS than the big_step floor must still decline — big_step (part 7)
    // cannot catch it, so only the ahead-of-now sanitiser can. Mirrors the
    // reference AuditStore's `*prev > pg_now` carrier.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 2, 3'600'000); // expired
    seed(pool, 1, 0);         // recent → NOT would_wipe (isolates the ahead-of-now clause)
    set_meta(pool, "t_bootstrap_settled", "1");
    // 1h in the FUTURE: ahead-of-now, but well under the 24h big_step floor.
    set_meta(pool, "t_last_pass_now", std::to_string(db_now_ms(pool) + 3'600'000));

    auto r = run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);
    CHECK(r.anomaly == yuzu::server::audit_retention::Anomaly::BadState);
    CHECK(r.declined);
    CHECK(count_rows(pool) == 3); // declined — nothing deleted (no silent proceed)
}

TEST_CASE("retention guard: a large clock step DECLINES (Step)", "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 2, 3'600'000);
    set_meta(pool, "t_bootstrap_settled", "1");
    // A plausible anchor 10 days in the past — |now - anchor| >> the 24h floor.
    set_meta(pool, "t_last_pass_now", std::to_string(db_now_ms(pool) - 10LL * 86'400'000));

    auto r = run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);
    CHECK(r.anomaly == yuzu::server::audit_retention::Anomaly::Step);
    CHECK(r.declined);
    CHECK(count_rows(pool) == 2);
}

TEST_CASE("retention guard: an all-expired table DECLINES once (Wipe), then drains",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 3, 3'600'000); // every row is older than the window → would_wipe
    set_meta(pool, "t_bootstrap_settled", "1");
    set_meta(pool, "t_last_pass_now", std::to_string(db_now_ms(pool))); // fresh, plausible → no Step

    auto s = spec(60'000, 100, MissingAnchorPolicy::Decline);
    auto r1 = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK(r1.anomaly == yuzu::server::audit_retention::Anomaly::Wipe);
    CHECK(r1.declined);
    CHECK(count_rows(pool) == 3); // first all-expired pass declines
    // An identical repeat is suppressed and drains (part 4).
    auto r2 = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(r2.declined);
    CHECK(r2.deleted == 3);
}

TEST_CASE("retention guard: caps deletes per pass, unconditionally",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    // 10 expired + 1 recent (so it is NOT would_wipe → no decline, straight to cap).
    seed(pool, 10, 3'600'000);
    seed(pool, 1, 0);
    set_meta(pool, "t_bootstrap_settled", "1");
    set_meta(pool, "t_last_pass_now", std::to_string(db_now_ms(pool)));

    auto s = spec(/*window*/ 60'000, /*cap*/ 4, MissingAnchorPolicy::Decline);
    auto r = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(r.declined);
    CHECK(r.deleted == 4);         // exactly the cap
    CHECK(count_rows(pool) == 7);  // 11 - 4
}

TEST_CASE("retention guard: a pass persists the anchor (survives restart)",
          "[pg][store][retention-guard]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    seed(pool, 1, 3'600'000);
    run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);

    // The anchor is a durable retention_meta row (not a process-local value), so a
    // fresh pool (a "restart") reads it back.
    PgPool pool2{{.conninfo = db.dsn(), .size = 2}};
    std::string anchor;
    pool2.with_txn_for(2000ms, [&](PGconn* c) {
        PgResult r = yuzu::server::pg::exec_params(
            c, "SELECT value FROM rg_test.retention_meta WHERE key='t_last_pass_now'",
            std::vector<std::string>{});
        if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
            return false;
        anchor = PQgetvalue(r.get(), 0, 0);
        return true;
    });
    CHECK_FALSE(anchor.empty());
    CHECK(std::stoll(anchor) > 946'684'800'000); // a plausible present-day ms epoch
}

TEST_CASE("Retention cutoff preserves boundary rows and raw anchors across midnight",
          "[pg][store][retention-guard][contract-pg-retention-cutoff]") {
    // ClockGuardedPruneSpec::cutoff_align applies to the cutoff only. Fixed SQL
    // readings exercise the real prune before and after midnight, without a
    // wall-clock race or a near-midnight blind spot in the anchor assertion.
    // This tests the helper's clock handling, not consumers' now_expr wiring.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    setup_schema(pool);

    // Independent connection observes committed state, including a positive
    // before-state. Explicit IDs and timestamp values are the oracle; we do not
    // copy production cutoff arithmetic into the expected-row calculation.
    PgConn observer{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(observer.get()) == CONNECTION_OK);
    PgResult inserted{PQexec(observer.get(),
        "INSERT INTO rg_test.t (id, ts) VALUES "
        "(1, 1727827199999)," // one ms before the first floored cutoff
        "(2, 1727827200000)," // exactly at the first floored cutoff
        "(3, 1727827200001)," // inside the bucket, before the raw cutoff
        "(4, 1727913600000)," // exactly at the next day's floored cutoff
        "(5, 1728086399999)")}; // recent survivor prevents would-wipe
    REQUIRE(inserted.status() == PGRES_COMMAND_OK);
    REQUIRE(std::string{PQcmdTuples(inserted.get())} == "5");

    using Rows = std::vector<std::string>;
    const auto read_rows = [&] {
        PgResult rows{PQexec(observer.get(), "SELECT id, ts FROM rg_test.t ORDER BY id")};
        REQUIRE(rows.status() == PGRES_TUPLES_OK);
        REQUIRE(PQnfields(rows.get()) == 2);
        Rows result;
        for (int i = 0; i < PQntuples(rows.get()); ++i) {
            REQUIRE_FALSE(PQgetisnull(rows.get(), i, 0));
            REQUIRE_FALSE(PQgetisnull(rows.get(), i, 1));
            result.push_back(std::string{PQgetvalue(rows.get(), i, 0)} + ":" +
                             PQgetvalue(rows.get(), i, 1));
        }
        return result;
    };
    const auto read_anchor = [&] {
        PgResult anchor{PQexec(observer.get(),
            "SELECT value FROM rg_test.retention_meta WHERE key='t_last_pass_now'")};
        REQUIRE(anchor.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(anchor.get()) == 1);
        REQUIRE_FALSE(PQgetisnull(anchor.get(), 0, 0));
        return std::string{PQgetvalue(anchor.get(), 0, 0)};
    };
    REQUIRE(read_rows() == Rows{"1:1727827199999", "2:1727827200000", "3:1727827200001",
                               "4:1727913600000", "5:1728086399999"});

    constexpr std::int64_t kDayMs = 86'400'000;
    auto s = spec(2 * kDayMs, 100, MissingAnchorPolicy::Proceed, kDayMs);
    s.now_expr = "1728086399999::bigint"; // one ms before midnight
    const auto first = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(first.error);
    CHECK_FALSE(first.declined);
    CHECK_FALSE(first.skipped_lock);
    CHECK(first.anomaly == yuzu::server::audit_retention::Anomaly::None);
    CHECK(first.deleted == 1);
    CHECK(read_rows() == Rows{"2:1727827200000", "3:1727827200001",
                             "4:1727913600000", "5:1728086399999"});
    CHECK(read_anchor() == "1728086399999");

    s.now_expr = "1728086400001::bigint"; // two ms later, across midnight
    const auto second = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(second.error);
    CHECK_FALSE(second.declined);
    CHECK_FALSE(second.skipped_lock);
    CHECK(second.anomaly == yuzu::server::audit_retention::Anomaly::None);
    CHECK(second.deleted == 2);
    CHECK(read_rows() == Rows{"4:1727913600000", "5:1728086399999"});
    CHECK(read_anchor() == "1728086400001");
}

TEST_CASE("retention guard: a failed txn reports error and deletes nothing",
          "[pg][store][retention-guard]") {
    // Gate on PG being ENABLED (keeps this in the [pg] suite), but the failure path
    // needs no live schema: a parseable-but-unreachable conninfo makes every
    // connection attempt fail, so with_txn_for returns false and the helper must
    // surface error=true / deleted=0 (its documented best-effort contract) rather
    // than throw or silently "succeed" with nothing done.
    YUZU_REQUIRE_PG_DB(db);
    (void)db;
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nobody connect_timeout=1",
                .size = 1}};
    REQUIRE(bad.valid()); // the conninfo PARSES — the failure is at connect time
    auto r = run_clock_guarded_prune(bad, spec(60'000, 100, MissingAnchorPolicy::Decline), 1000ms);
    CHECK(r.error);
    CHECK(r.deleted == 0);
    CHECK_FALSE(r.declined);
    CHECK_FALSE(r.skipped_lock);
}
