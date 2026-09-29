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

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Seed `n` rows all stamped `age_ms` in the past (so a small window expires them).
void seed(PgPool& pool, int n, std::int64_t age_ms) {
    const std::int64_t ts = now_ms() - age_ms;
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
    set_meta(pool, "t_last_pass_now", std::to_string(now_ms()));

    // Hold the SAME advisory-lock key (session-scoped) on an independent backend.
    PgConn holder{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    PgResult lk{PQexec(holder.get(), "SELECT pg_advisory_lock(hashtext('rg_test:t_prune'))")};
    REQUIRE(lk.status() == PGRES_TUPLES_OK);

    auto r = run_clock_guarded_prune(pool, spec(60'000, 100, MissingAnchorPolicy::Decline), 2000ms);
    CHECK(r.skipped_lock);
    CHECK(r.deleted == 0);
    CHECK(count_rows(pool) == 5); // untouched — the holder wins the tick
    PQexec(holder.get(), "SELECT pg_advisory_unlock(hashtext('rg_test:t_prune'))");
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
    set_meta(pool, "t_last_pass_now", std::to_string(now_ms() + 3'600'000));

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
    set_meta(pool, "t_last_pass_now", std::to_string(now_ms() - 10LL * 86'400'000));

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
    set_meta(pool, "t_last_pass_now", std::to_string(now_ms())); // fresh, plausible → no Step

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
    set_meta(pool, "t_last_pass_now", std::to_string(now_ms()));

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

TEST_CASE("retention guard: cutoff_align floors the cutoff but leaves the anchor RAW (WS-10 C1)",
          "[pg][store][retention-guard]") {
    // cutoff_align must day-align the CUTOFF only — the persisted anchor stays the
    // RAW reading, or two adjacent-bucket passes read one full bucket apart and
    // false-fire Step every boundary crossing. (a) a row exactly at the floored
    // cutoff survives (cutoff floored); (b) the stored anchor is near raw now, NOT
    // floored to the day bucket.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    setup_schema(pool);
    const std::int64_t day = 86'400'000; // ms/day (the align unit)
    seed(pool, 1, 3 * day); // ~3 days old → well before the 2-day floored cutoff → deleted
    seed(pool, 1, 0);       // recent survivor (avoids would_wipe)
    const std::int64_t before = now_ms();

    // Proceed policy → no bootstrap decline; a fresh raw anchor is stamped this pass.
    auto s = spec(/*window*/ 2 * day, /*cap*/ 100, MissingAnchorPolicy::Proceed, /*cutoff_align*/ day);
    auto r = run_clock_guarded_prune(pool, s, 2000ms);
    CHECK_FALSE(r.declined);
    CHECK(r.deleted == 1);        // the ~3-day-old row (cutoff floored to ~2 days)
    CHECK(count_rows(pool) == 1); // the recent survivor

    // The persisted anchor is the RAW reading (≈ now), NOT floored to the day
    // bucket (a floored anchor would be up to ~24h < now → fails this bound, except
    // within 60s of UTC midnight where the distinction — and the bug — vanish).
    std::string anchor;
    pool.with_txn_for(2000ms, [&](PGconn* c) {
        PgResult a = yuzu::server::pg::exec_params(
            c, "SELECT value FROM rg_test.retention_meta WHERE key='t_last_pass_now'",
            std::vector<std::string>{});
        if (a.status() != PGRES_TUPLES_OK || PQntuples(a.get()) != 1)
            return false;
        anchor = PQgetvalue(a.get(), 0, 0);
        return true;
    });
    REQUIRE_FALSE(anchor.empty());
    CHECK(std::stoll(anchor) >= before - 60'000); // raw, not day-floored
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
