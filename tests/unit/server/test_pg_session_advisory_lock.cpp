// test_pg_session_advisory_lock.cpp — pg/pg_session_advisory_lock.hpp:
// `PgAdvisoryLockKey`'s SQL generation, and `PgSessionAdvisoryLockGuard`'s
// aborted-transaction recovery path (#2964 round 3 review finding 3).
//
// The finding this file exists to pin: a PRIOR revision of this guard's
// destructor, on a live-connection unlock-QUERY failure, went straight to
// `SELECT pg_terminate_backend(pg_backend_pid())` and claimed that was
// "correct by construction". Measured against live Postgres:
// `pg_terminate_backend(pg_backend_pid())` is ALSO an ordinary SQL
// statement, so it fails IDENTICALLY to the `pg_advisory_unlock` it was
// meant to backstop when the connection is in an ABORTED transaction — the
// lock stayed granted, the connection reported `CONNECTION_OK`, and
// `PgPool::release()` would have recycled it. The fix rolls back the aborted
// transaction (the one statement Postgres accepts in that state) and
// retries the SAME targeted unlock once before falling back to termination.
// The [pg] test below reproduces the aborted-transaction case directly and
// asserts BOTH that the lock is actually released (a second connection can
// re-acquire it) AND that the guard's own connection was NOT terminated
// (recovery succeeded without needing the last-resort kill).

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_raii.hpp"
#include "pg/pg_session_advisory_lock.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <string>
#include <thread>

using yuzu::server::pg::PgAdvisoryLockKey;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::PgSessionAdvisoryLockGuard;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

// Bounded poll for a backend pid to vanish from `pg_stat_activity`, as seen
// from `observer` — `pg_terminate_backend` is asynchronous from the caller's
// point of view (it requests termination, it does not wait for it), so
// asserting on the very next statement would be racy. 100 x 50ms = 5s
// budget, generous for a local/CI Postgres to actually tear a backend down.
bool wait_for_pid_gone(PGconn* observer, std::int64_t pid) {
    const std::string check_sql = "SELECT 1 FROM pg_stat_activity WHERE pid = " +
                                  std::to_string(pid);
    for (int attempt = 0; attempt < 100; ++attempt) {
        PgResult check{PQexec(observer, check_sql.c_str())};
        REQUIRE(check.status() == PGRES_TUPLES_OK);
        if (PQntuples(check.get()) == 0)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

} // namespace

TEST_CASE("PgAdvisoryLockKey::single generates matching try-lock/unlock SQL from ONE key "
          "expression",
          "[server][pg-session-advisory-lock]") {
    const auto key = PgAdvisoryLockKey::single("hashtextextended('some:key', 0)");
    CHECK(key.try_lock_sql() ==
          "SELECT pg_try_advisory_lock(hashtextextended('some:key', 0))");
    CHECK(key.unlock_sql() == "SELECT pg_advisory_unlock(hashtextextended('some:key', 0))");
}

TEST_CASE("PgAdvisoryLockKey::pair generates matching two-argument try-lock/unlock SQL from ONE "
          "key expression pair",
          "[server][pg-session-advisory-lock]") {
    const auto key = PgAdvisoryLockKey::pair("2037545589", "hashtext('secrets_kek_op')");
    CHECK(key.try_lock_sql() ==
          "SELECT pg_try_advisory_lock(2037545589, hashtext('secrets_kek_op'))");
    CHECK(key.unlock_sql() ==
          "SELECT pg_advisory_unlock(2037545589, hashtext('secrets_kek_op'))");
}

TEST_CASE("PgSessionAdvisoryLockGuard: an unlock attempted on an ABORTED transaction rolls "
          "back and retries — the lock is actually released and the connection is NOT "
          "terminated (#2964 round 3 review finding 3)",
          "[pg][server][pg-session-advisory-lock]") {
    YUZU_REQUIRE_PG_DB(db);

    const auto key = PgAdvisoryLockKey::single(
        "hashtextextended('test:pg_session_advisory_lock:aborted-txn', 0)");

    auto holder = connect(db.dsn());

    // Take the lock, then poison the connection's transaction state exactly
    // the way the guard's destructor must recover from: BEGIN, then a
    // statement that errors, leaving the transaction ABORTED (every ordinary
    // statement other than ROLLBACK now fails at the query level).
    {
        const std::string try_lock_sql = key.try_lock_sql();
        PgResult lock_res{PQexec(holder.get(), try_lock_sql.c_str())};
        REQUIRE(lock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(lock_res.get()) == 1);
        REQUIRE(std::string(PQgetvalue(lock_res.get(), 0, 0)) == "t");
    }
    {
        PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
    }
    {
        // Division by zero is a query-level ERROR that aborts the
        // transaction without killing the connection.
        PgResult poison{PQexec(holder.get(), "SELECT 1/0")};
        REQUIRE(poison.status() != PGRES_TUPLES_OK);
        REQUIRE(poison.status() != PGRES_COMMAND_OK);
    }
    REQUIRE(PQtransactionStatus(holder.get()) == PQTRANS_INERROR);

    // Destroy the guard NOW, while the connection is still in the aborted
    // state — this is the exact moment the release protocol must recover
    // from.
    {
        PgSessionAdvisoryLockGuard guard{holder.get(), key, "test aborted-txn lock"};
        (void)guard;
    }

    // THE ASSERTION THIS TEST EXISTS FOR, part 1: recovery worked without
    // needing to terminate the backend — reverting the rollback+retry fix
    // (falling straight to `pg_terminate_backend`) makes this fail, because
    // that statement ALSO fails on an aborted transaction and the
    // connection would report CONNECTION_BAD or the terminate signal would
    // land on a connection libpq itself then marks bad.
    CHECK(PQstatus(holder.get()) == CONNECTION_OK);
    // The rollback leaves the connection able to run ordinary statements
    // again — proves this is a genuinely recovered, reusable connection, not
    // merely one whose PQstatus() hasn't caught up yet.
    {
        PgResult probe{PQexec(holder.get(), "SELECT 1")};
        CHECK(probe.status() == PGRES_TUPLES_OK);
    }

    // THE ASSERTION THIS TEST EXISTS FOR, part 2: the lock was ACTUALLY
    // released — a second, independent connection can acquire it
    // immediately. Reverting the fix (leaving the lock silently held because
    // the unlock query failed and was never retried) makes this fail: the
    // try-lock below would return `false`.
    auto observer = connect(db.dsn());
    const std::string observer_try_lock_sql = key.try_lock_sql();
    PgResult observer_res{PQexec(observer.get(), observer_try_lock_sql.c_str())};
    REQUIRE(observer_res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(observer_res.get()) == 1);
    CHECK(std::string(PQgetvalue(observer_res.get(), 0, 0)) == "t");

    // Clean up the observer's own hold so this test leaves nothing behind.
    const std::string unlock_sql = key.unlock_sql();
    PgResult cleanup{PQexec(observer.get(), unlock_sql.c_str())};
    (void)cleanup;
}

TEST_CASE("PgSessionAdvisoryLockGuard: an unlock-QUERY failure on an otherwise-IDLE "
          "connection falls straight to the terminate-backend fallback — the branch neither "
          "existing test in this file exercises",
          "[pg][server][pg-session-advisory-lock]") {
    YUZU_REQUIRE_PG_DB(db);

    // `unlock_sql()` built from THIS key is `SELECT pg_advisory_unlock(1/0)` —
    // a division-by-zero ERROR every time it runs, on a connection that is
    // otherwise perfectly IDLE (never inside a transaction at all), so the
    // aborted-transaction recovery branch does not apply (`PQtransactionStatus`
    // reads `PQTRANS_IDLE`, never `PQTRANS_INERROR`) and the destructor has
    // nothing left but the terminate-backend fallback.
    const auto key = PgAdvisoryLockKey::single("1/0");

    auto holder = connect(db.dsn());
    std::int64_t holder_pid = 0;
    {
        PgResult pid_res{PQexec(holder.get(), "SELECT pg_backend_pid()")};
        REQUIRE(pid_res.status() == PGRES_TUPLES_OK);
        holder_pid = std::stoll(PQgetvalue(pid_res.get(), 0, 0));
    }
    REQUIRE(PQtransactionStatus(holder.get()) == PQTRANS_IDLE);

    {
        PgSessionAdvisoryLockGuard guard{holder.get(), key, "test terminate-fallback"};
        (void)guard;
    }

    // THE ASSERTION THIS TEST EXISTS FOR: the terminate fallback actually
    // ran and actually reached PostgreSQL — the holder's own backend pid is
    // gone from `pg_stat_activity`. A destructor that silently swallowed the
    // unlock failure without ever attempting the terminate call (e.g. an
    // early return before that statement) would leave this backend alive
    // indefinitely and this check would time out failing.
    auto observer = connect(db.dsn());
    CHECK(wait_for_pid_gone(observer.get(), holder_pid));
}

TEST_CASE("PgSessionAdvisoryLockGuard: a connection already dead when the destructor runs "
          "takes the dead-connection early return and completes cleanly, without hanging or "
          "throwing",
          "[pg][server][pg-session-advisory-lock]") {
    YUZU_REQUIRE_PG_DB(db);

    const auto key = PgAdvisoryLockKey::single(
        "hashtextextended('test:pg_session_advisory_lock:dead-connection', 0)");

    auto holder = connect(db.dsn());
    std::int64_t holder_pid = 0;
    {
        PgResult pid_res{PQexec(holder.get(), "SELECT pg_backend_pid()")};
        REQUIRE(pid_res.status() == PGRES_TUPLES_OK);
        holder_pid = std::stoll(PQgetvalue(pid_res.get(), 0, 0));
    }
    {
        const std::string try_lock_sql = key.try_lock_sql();
        PgResult lock_res{PQexec(holder.get(), try_lock_sql.c_str())};
        REQUIRE(lock_res.status() == PGRES_TUPLES_OK);
        REQUIRE(std::string(PQgetvalue(lock_res.get(), 0, 0)) == "t");
    }

    // Kill the holder's backend from a SEPARATE connection, and wait for the
    // kill to actually land BEFORE the guard's destructor ever runs — unlike
    // the terminate-fallback test above, where the DESTRUCTOR itself is what
    // kills the backend, this test's session (and the lock it held) must
    // already be gone when the destructor starts.
    {
        auto killer = connect(db.dsn());
        const std::string kill_sql =
            "SELECT pg_terminate_backend(" + std::to_string(holder_pid) + ")";
        PgResult kill{PQexec(killer.get(), kill_sql.c_str())};
        REQUIRE(kill.status() == PGRES_TUPLES_OK);
        REQUIRE(wait_for_pid_gone(killer.get(), holder_pid));
    }

    // THE ASSERTION THIS TEST EXISTS FOR: the destructor returns cleanly —
    // no throw, no hang — when the connection is already dead, via the
    // dead-connection early-return branch rather than the terminate
    // fallback. `PQstatus(holder.get())` does NOT update purely from the
    // server-side kill above (libpq only notices on its own next I/O
    // attempt), so this genuinely exercises the destructor's own detection
    // (its first `PQexec` unlock attempt, which fails against the closed
    // socket) rather than a pre-known-dead `PQstatus` short-circuit.
    { PgSessionAdvisoryLockGuard guard{holder.get(), key, "test dead-connection"}; (void)guard; }
    // Reaching here at all is the assertion — a hang or an uncaught
    // exception escaping the destructor would fail this test by
    // timeout/crash rather than by a false CHECK.
    SUCCEED("destructor completed without throwing on an already-dead connection");
}
