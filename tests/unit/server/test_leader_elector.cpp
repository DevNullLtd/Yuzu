// test_leader_elector.cpp — WS-3 slice 3.1 (ADR-2002 §3/§6/§10): the fenced
// LeaderElector primitive. These [pg] tests take real Postgres backends and
// prove the four properties the fencing model rests on:
//   1. schema migrates on a fresh DB;
//   2. a single acquirer becomes leader and mints an epoch;
//   3. a second elector is REFUSED while the first holds (mutual exclusion via
//      the session advisory lock);
//   4. the epoch is strictly monotonic across a handover, and the
//      `epoch_fence_sql()` predicate, embedded in a claim's WRITE statement,
//      fences a stale ex-leader's epoch atomically (fail-closed).
// The primitive is not wired into any loop yet (slice 3.2), so nothing here
// exercises runtime dispatch — this binds the coordination primitive alone.

#include "leader_elector.hpp"
#include "leader_gate.hpp"

#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <thread>

using yuzu::server::background_job_class;
using yuzu::server::LeaderElector;
using yuzu::server::kServerBackgroundLeaderLock;
using yuzu::server::leader_gate_permits;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

LeaderElector::Config cfg(const std::string& dsn, std::string holder) {
    return LeaderElector::Config{.dsn = dsn, .holder_id = std::move(holder)};
}

// Store-behaviour cases clone this pre-migrated template rather than migrating a
// fresh database each time (docs/testing/unit-test-conventions.md — per-test
// migration DDL is tied to a documented 2026-07-12 Windows CI timeout). The
// setup runs the LeaderElector migration ONCE on the template; it does not
// acquire, so the cloned leader_state is empty. The "migrates schema" and
// fail-closed-construction cases deliberately stay off the template (they must
// exercise migration-from-empty, or never touch a database at all).
yuzu::test::PgTestTemplate leader_elector_tpl{
    "leaderelector", [](const std::string& dsn) {
        LeaderElector migrator{LeaderElector::Config{.dsn = dsn, .holder_id = "template"}};
        if (!migrator.is_open())
            throw std::runtime_error("leader_elector template: store failed to migrate");
    }};

// Evaluate an SQL boolean expression; true iff it evaluates to 't' (a NULL,
// e.g. a fence over a missing leader row, reads as false — fail-closed).
bool eval_bool(PGconn* conn, const std::string& expr) {
    PgResult r{PQexec(conn, ("SELECT " + expr).c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetisnull(r.get(), 0, 0) == 0 && PQgetvalue(r.get(), 0, 0)[0] == 't';
}

// Run a claim-shaped guarded INSERT (INSERT ... SELECT ... WHERE <fence>) into a
// per-session temp table; returns the number of rows the fence admitted. This
// is the atomic same-statement fence the predicate exists for.
int guarded_insert(PGconn* conn, const std::string& fence) {
    PgResult r{PQexec(conn, ("INSERT INTO claim_probe(n) SELECT 1 WHERE " + fence).c_str())};
    REQUIRE(r.status() == PGRES_COMMAND_OK);
    return std::atoi(PQcmdTuples(r.get()));
}

} // namespace

TEST_CASE("LeaderElector migrates schema and starts non-leader", "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB(db);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    CHECK(e.is_open());
    CHECK_FALSE(e.is_leader());
    CHECK_FALSE(e.epoch().has_value());
}

TEST_CASE("LeaderElector acquires leadership and mints an epoch", "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    REQUIRE(e.try_acquire());
    CHECK(e.is_leader());
    REQUIRE(e.epoch().has_value());
    CHECK(*e.epoch() >= 1);
    // Re-acquire while already leader keeps the same epoch (liveness re-check).
    const auto first = *e.epoch();
    REQUIRE(e.try_acquire());
    CHECK(*e.epoch() == first);
}

TEST_CASE("LeaderElector refuses a second elector while the first holds",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.is_open());
    REQUIRE(b.is_open());

    REQUIRE(a.try_acquire());
    CHECK(a.is_leader());

    // b cannot lead while a holds the session advisory lock.
    CHECK_FALSE(b.try_acquire());
    CHECK_FALSE(b.is_leader());
    CHECK_FALSE(b.epoch().has_value());
}

TEST_CASE("LeaderElector epoch is strictly monotonic across handover",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.try_acquire());
    const auto e1 = *a.epoch();

    a.resign();
    CHECK_FALSE(a.is_leader());
    CHECK_FALSE(a.epoch().has_value());

    REQUIRE(b.try_acquire());
    const auto e2 = *b.epoch();
    CHECK(e2 > e1); // a strictly higher epoch than the resigned leader

    // a re-acquiring after b resigns mints a still-higher epoch.
    b.resign();
    REQUIRE(a.try_acquire());
    CHECK(*a.epoch() > e2);
}

TEST_CASE("epoch_fence_sql predicate fences a stale ex-leader epoch (fail-closed)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    const std::string lock_name = kServerBackgroundLeaderLock;
    auto claim = connect(db.dsn()); // an ordinary (non-owning) connection, like a claim conn

    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.try_acquire());
    const auto e_a = *a.epoch();

    // The current leader's epoch passes; a lower (stale) epoch fails.
    CHECK(eval_bool(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_a)));
    CHECK_FALSE(eval_bool(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_a - 1)));

    // Handover: a resigns, b takes over with a higher epoch. a's old epoch is
    // now stale and must be rejected — the paused-ex-leader guarantee.
    a.resign();
    REQUIRE(b.try_acquire());
    const auto e_b = *b.epoch();
    REQUIRE(e_b > e_a);
    CHECK_FALSE(eval_bool(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_a)));
    CHECK(eval_bool(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_b)));
}

TEST_CASE("epoch_fence_sql guards a claim WRITE atomically",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    const std::string lock_name = kServerBackgroundLeaderLock;
    auto claim = connect(db.dsn());
    PgResult tmp{PQexec(claim.get(), "CREATE TEMP TABLE claim_probe(n int)")};
    REQUIRE(tmp.status() == PGRES_COMMAND_OK);

    LeaderElector a(cfg(db.dsn(), "holder-a"));
    REQUIRE(a.try_acquire());
    const auto e_a = *a.epoch();

    // A guarded INSERT commits only when the epoch matches — the fence is part
    // of the write, so a stale epoch admits zero rows.
    CHECK(guarded_insert(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_a)) == 1);
    CHECK(guarded_insert(claim.get(), LeaderElector::epoch_fence_sql(lock_name, e_a - 1)) == 0);
}

TEST_CASE("epoch_fence_sql fails closed with no leader row and on an invalid name",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    // Construct an elector only to run the migration (creates leader_state), but
    // never acquire — so the table exists with no row.
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    auto claim = connect(db.dsn());
    // No row → inner SELECT is NULL → predicate is NULL → false.
    CHECK_FALSE(eval_bool(claim.get(), LeaderElector::epoch_fence_sql(kServerBackgroundLeaderLock, 1)));
    // Invalid name → constant-false predicate, never admits a claim.
    CHECK(LeaderElector::epoch_fence_sql("Bad Name!", 1) == "(1=0)");
    CHECK_FALSE(eval_bool(claim.get(), LeaderElector::epoch_fence_sql("Bad Name!", 1)));
}

TEST_CASE("LeaderElector follower recovers after its backend is terminated (F1)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(a.is_open());
    REQUIRE(b.is_open());
    // b leads; a is an OPEN FOLLOWER (epoch_ == nullopt) — the exact F1 case.
    // The already-leader liveness branch is SKIPPED for a, so a's recovery can
    // only come from the try-lock-query-failure reconnect the F1 fix added.
    // (The earlier version of this test made `a` the leader and thus exercised
    // the already-healing leader path — it would have passed without the fix.)
    REQUIRE(b.try_acquire());
    REQUIRE_FALSE(a.try_acquire()); // a is a live follower, refused by b's lock

    // Kill every backend on this per-case ephemeral database except the killer's
    // — drops a's and b's dedicated connections and frees b's advisory lock.
    auto killer = connect(db.dsn());
    PgResult k{PQexec(killer.get(),
                      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                      "WHERE datname = current_database() AND pid <> pg_backend_pid()")};
    REQUIRE(k.status() == PGRES_TUPLES_OK);

    // a, a follower on a now-dead connection, must heal: the F1 fix reconnects on
    // the failed try-lock query so a later call can lead once b's lock is freed.
    // Pre-fix this looped forever returning false on the dead PGconn.
    bool led = false;
    for (int i = 0; i < 20 && !led; ++i) {
        led = a.try_acquire();
        if (!led)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    CHECK(led);
    CHECK(a.is_leader());
    CHECK(a.epoch().has_value());
}

TEST_CASE("LeaderElector heartbeat tracks leadership", "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    CHECK_FALSE(a.heartbeat()); // not leader yet
    REQUIRE(a.try_acquire());
    CHECK(a.heartbeat()); // leader, connection live
    a.resign();
    CHECK_FALSE(a.heartbeat()); // resigned
}

TEST_CASE("LeaderElector heartbeat drops leadership after its backend is terminated (#4013)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector a(cfg(db.dsn(), "holder-a"));
    REQUIRE(a.try_acquire());
    REQUIRE(a.is_leader());

    // Kill a's dedicated backend out from under it (leaving the killer alone).
    auto killer = connect(db.dsn());
    PgResult k{PQexec(killer.get(),
                      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                      "WHERE datname = current_database() AND pid <> pg_backend_pid()")};
    REQUIRE(k.status() == PGRES_TUPLES_OK);

    // pg_terminate_backend signals ASYNCHRONOUSLY — the victim session may still
    // answer one more SELECT 1 before it tears down, so poll heartbeat() to false
    // with a deadline rather than asserting the very first call fails (adversarial
    // review K4). The first false drops leadership + reconnects; epoch_ is then
    // nullopt so every subsequent heartbeat() stays false.
    bool dropped = false;
    for (int i = 0; i < 40 && !dropped; ++i) {
        if (!a.heartbeat())
            dropped = true;
        else
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    CHECK(dropped);
    CHECK_FALSE(a.is_leader());
    CHECK_FALSE(a.epoch().has_value());

    // And it heals: a later acquire re-leads on the reconnected backend once the
    // dead session's advisory lock is gone.
    bool led = false;
    for (int i = 0; i < 40 && !led; ++i) {
        led = a.try_acquire();
        if (!led)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    CHECK(led);
    CHECK(a.is_leader());
    CHECK(a.epoch().has_value());
}

TEST_CASE("LeaderElector releases the advisory lock when epoch minting fails (#4013)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    // Break epoch minting: drop the sequence the acquire's nextval() needs. The
    // session try-lock still SUCCEEDS, then the epoch INSERT fails — exactly the
    // path that must RELEASE the lock rather than leak it (acquired-but-unrecorded).
    auto admin = connect(db.dsn());
    PgResult d{PQexec(admin.get(), "DROP SEQUENCE leader_elector.leader_epoch_seq")};
    REQUIRE(d.status() == PGRES_COMMAND_OK);

    LeaderElector a(cfg(db.dsn(), "holder-a"));
    REQUIRE(a.is_open());
    CHECK_FALSE(a.try_acquire()); // took the lock, failed to mint the epoch
    CHECK_FALSE(a.is_leader());
    CHECK_FALSE(a.epoch().has_value());

    // Prove the lock did NOT leak: restore the sequence, and a SECOND elector can
    // now acquire — only possible if a released the session advisory lock.
    PgResult c{PQexec(admin.get(), "CREATE SEQUENCE leader_elector.leader_epoch_seq AS bigint")};
    REQUIRE(c.status() == PGRES_COMMAND_OK);
    LeaderElector b(cfg(db.dsn(), "holder-b"));
    REQUIRE(b.is_open());
    CHECK(b.try_acquire());
    CHECK(b.is_leader());
}

TEST_CASE("leader_gate_permits gates a FencedLeaderOnly pass on live leadership",
          "[pg][store][leader-elector][leader-gate]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    // Before acquiring: a FencedLeaderOnly pass is DENIED; a ReplicaSafe pass (the
    // WS-2a event poll) runs regardless.
    CHECK_FALSE(leader_gate_permits<background_job_class("schedule_runner.tick")>(&e));
    CHECK(leader_gate_permits<background_job_class("execution_tracker.poll_event_outbox_once")>(&e));
    // After acquiring leadership: the FencedLeaderOnly pass is now PERMITTED.
    REQUIRE(e.try_acquire());
    CHECK(leader_gate_permits<background_job_class("schedule_runner.tick")>(&e));
    // Resign: denied again — the gate tracks live leadership.
    e.resign();
    CHECK_FALSE(leader_gate_permits<background_job_class("schedule_runner.tick")>(&e));
}

TEST_CASE("LeaderElector lock-free reads run concurrently with the election writer (TSan)",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector e(cfg(db.dsn(), "holder-a"));
    REQUIRE(e.is_open());
    // Exercise the lock-free is_leader()/epoch() reader path (the worker-tick path)
    // concurrently with the acquire/resign writer path (the election loop). The
    // real value is under TSan (nightly): the release/acquire publish of live_epoch_
    // must be race-free. Functionally we assert only liveness (no deadlock, the
    // reader ran) and a QUIESCENT final consistency — is_leader() iff epoch(), read
    // with NO writer running. We deliberately do NOT assert that consistency WHILE
    // the writer runs: is_leader() and epoch() are two separate atomic loads, so
    // they may legitimately straddle a concurrent acquire/resign, which is not a bug.
    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> reads{0};
    std::thread reader([&] {
        while (!stop.load(std::memory_order_acquire)) {
            (void)e.is_leader();
            (void)e.epoch();
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });
    for (int i = 0; i < 50; ++i) {
        (void)e.try_acquire();
        e.resign();
    }
    stop.store(true, std::memory_order_release);
    reader.join();
    CHECK(reads.load() > 0);                        // the reader actually ran
    CHECK(e.is_leader() == e.epoch().has_value());  // quiescent: internally consistent
    CHECK_FALSE(e.is_leader());                     // the last write was resign()
}

TEST_CASE("LeaderElector distinct lock names hold independent locks",
          "[pg][store][leader-elector]") {
    YUZU_REQUIRE_PG_DB_TPL(db, leader_elector_tpl);
    LeaderElector alpha(LeaderElector::Config{.dsn = db.dsn(), .holder_id = "h", .lock_name = "alpha"});
    LeaderElector beta(LeaderElector::Config{.dsn = db.dsn(), .holder_id = "h", .lock_name = "beta"});
    REQUIRE(alpha.is_open());
    REQUIRE(beta.is_open());
    // Different names derive different advisory keys, so both lead at once —
    // proving make_lock_key does not collapse names to one lock.
    CHECK(alpha.try_acquire());
    CHECK(beta.try_acquire());
    CHECK(alpha.is_leader());
    CHECK(beta.is_leader());
}

// Fail-closed construction — invalid config never opens and never leads. These
// need no database: the constructor returns before any PQconnectdb, so they
// assert the early-return paths (invalid lock_name, empty dsn, empty holder_id)
// leave the elector permanently non-open. Tagged [pg][store] to sit with the
// sibling cases in the same shard; they never skip.
TEST_CASE("LeaderElector fails closed on an invalid lock_name",
          "[pg][store][leader-elector]") {
    LeaderElector e(LeaderElector::Config{
        .dsn = "postgresql://ignored", .holder_id = "holder-a", .lock_name = "Bad Name!"});
    CHECK_FALSE(e.is_open());
    CHECK_FALSE(e.try_acquire());
    CHECK_FALSE(e.is_leader());
}

TEST_CASE("LeaderElector fails closed on an empty dsn (no libpq-default fallback)",
          "[pg][store][leader-elector]") {
    LeaderElector e(LeaderElector::Config{.dsn = "", .holder_id = "holder-a"});
    CHECK_FALSE(e.is_open());
    CHECK_FALSE(e.try_acquire());
}

TEST_CASE("LeaderElector fails closed on an empty holder_id",
          "[pg][store][leader-elector]") {
    LeaderElector e(LeaderElector::Config{.dsn = "postgresql://ignored", .holder_id = ""});
    CHECK_FALSE(e.is_open());
    CHECK_FALSE(e.try_acquire());
}
