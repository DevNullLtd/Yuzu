// Contract tests for the pg_raii.hpp RAII owners (#1320 PR 1, ADR-0008).
//
// The move-only static_asserts run on every platform with no database; the
// behavioral cases (rollback-unless-commit, double-commit) need a live
// Postgres and follow the skip-vs-fail contract in test_helpers.hpp.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::PgTxn;

// ── Move-only contract (compile-time, no database) ─────────────────────────

static_assert(!std::is_copy_constructible_v<PgConn>);
static_assert(!std::is_copy_assignable_v<PgConn>);
static_assert(std::is_nothrow_move_constructible_v<PgConn>);
static_assert(std::is_nothrow_move_assignable_v<PgConn>);

static_assert(!std::is_copy_constructible_v<PgResult>);
static_assert(!std::is_copy_assignable_v<PgResult>);
static_assert(std::is_nothrow_move_constructible_v<PgResult>);
static_assert(std::is_nothrow_move_assignable_v<PgResult>);

static_assert(!std::is_copy_constructible_v<PgTxn>);
static_assert(!std::is_copy_assignable_v<PgTxn>);
static_assert(std::is_nothrow_move_constructible_v<PgTxn>);
static_assert(std::is_nothrow_move_assignable_v<PgTxn>);

namespace {

/// Open a connection to the fixture database and create a scratch table.
PgConn connect_with_table(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res{PQexec(conn.get(), "CREATE TABLE t (id INT PRIMARY KEY)")};
    REQUIRE(res.ok());
    return conn;
}

int count_rows(PGconn* conn) {
    PgResult res{PQexec(conn, "SELECT count(*) FROM t")};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    REQUIRE(PQnfields(res.get()) == 1);
    return std::atoi(PQgetvalue(res.get(), 0, 0));
}

void begin(PGconn* conn) {
    PgResult res{PQexec(conn, "BEGIN")};
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}

void insert_row(PGconn* conn, int id) {
    const std::string sql = "INSERT INTO t (id) VALUES (" + std::to_string(id) + ")";
    PgResult res{PQexec(conn, sql.c_str())};
    REQUIRE(res.status() == PGRES_COMMAND_OK);
}

} // namespace

TEST_CASE("PgConn/PgResult basics", "[pg][raii][pg-smoke]") {
    SECTION("default-constructed owners are empty and safe to destroy") {
        PgConn conn;
        PgResult res;
        CHECK_FALSE(static_cast<bool>(conn));
        CHECK_FALSE(static_cast<bool>(res));
        res.reset(); // idempotent on empty
        conn.reset();
    }

    SECTION("moved-from owner is empty; target owns") {
        YUZU_REQUIRE_PG_DB(db);
        PgConn a{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
        PGconn* raw = a.get();
        PgConn b{std::move(a)};
        CHECK_FALSE(static_cast<bool>(a));
        CHECK(b.get() == raw);

        PgResult r1{PQexec(b.get(), "SELECT 1")};
        REQUIRE(r1.status() == PGRES_TUPLES_OK);
        PgResult r2{std::move(r1)};
        CHECK_FALSE(static_cast<bool>(r1));
        CHECK(r2.status() == PGRES_TUPLES_OK);

        // Move-assignment over an owned value releases the old one (only
        // observable as "does not crash/leak" — ASan covers the leak half).
        r2 = PgResult{PQexec(b.get(), "SELECT 2")};
        CHECK(r2.status() == PGRES_TUPLES_OK);
    }

    SECTION("release() hands off ownership") {
        YUZU_REQUIRE_PG_DB(db);
        PgConn a{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(a.get()) == CONNECTION_OK);
        PGconn* raw = a.release();
        CHECK_FALSE(static_cast<bool>(a));
        REQUIRE(raw != nullptr);
        PQfinish(raw); // we took the obligation
    }
}

TEST_CASE("PgTxn rollback-unless-commit", "[pg][raii][pg-smoke]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn conn = connect_with_table(db.dsn());

    SECTION("destruction without commit rolls back") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
        } // no commit — must roll back
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 0);
    }

    SECTION("commit persists and disarms the rollback") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
            CHECK(txn.commit());
        }
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 1);
    }

    SECTION("double commit is a no-op returning true") {
        begin(conn.get());
        PgTxn txn{conn.get()};
        insert_row(conn.get(), 2);
        CHECK(txn.commit());
        CHECK(txn.commit()); // second call: no-op, still true
        CHECK(count_rows(conn.get()) == 1);
    }

    SECTION("exception unwind between BEGIN and commit rolls back") {
        auto throwing_op = [&] {
            begin(conn.get());
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 3);
            throw std::runtime_error("boom");
        };
        CHECK_THROWS(throwing_op());
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 0);
    }

    SECTION("an aborted transaction is rolled back by commit(), which returns false") {
        begin(conn.get());
        PgTxn txn{conn.get()};
        // Poison the transaction: a failed statement puts it in
        // PQTRANS_INERROR, after which COMMIT reports rollback.
        PgResult bad{PQexec(conn.get(), "SELECT no_such_column FROM t")};
        CHECK(bad.status() == PGRES_FATAL_ERROR);
        // Postgres turns COMMIT on an aborted txn into ROLLBACK but still
        // answers PGRES_COMMAND_OK, so commit() checks the transaction state
        // first, rolls back and returns false (see the aborted-transaction case
        // below). The invariant here: the connection comes back idle and
        // nothing persisted.
        CHECK_FALSE(txn.commit());
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 0);
    }

    SECTION("moved-from txn is disarmed; target carries the obligation") {
        begin(conn.get());
        {
            PgTxn a{conn.get()};
            insert_row(conn.get(), 4);
            PgTxn b{std::move(a)};
            // Both guards leave scope here (b first, then a). Only b is
            // armed — a was disarmed by the move — so exactly one ROLLBACK
            // is issued.
        }
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 0); // b rolled back exactly once
    }
}

// Dave's review of #7376, item 3: PgTxn::commit() must not report success for a transaction a
// refused or failed statement aborted. COMMIT in PQTRANS_INERROR completes as ROLLBACK yet
// answers PGRES_COMMAND_OK, so commit() checks the transaction state first.
TEST_CASE("PgTxn commit() and an aborted transaction", "[pg][raii][pg-smoke]") {
    YUZU_REQUIRE_PG_DB(db);
    PgConn conn = connect_with_table(db.dsn());

    SECTION("a NUL refusal the callback ignored: commit() is false and nothing persists") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
            const std::vector<std::optional<std::string>> params{std::string("a\0b", 3)};
            PgResult refused = yuzu::server::pg::exec_params(
                conn.get(), "INSERT INTO t (id) VALUES (length($1))", params);
            CHECK(refused.status() == PGRES_FATAL_ERROR); // the callback "ignores" this result
            CHECK_FALSE(txn.commit());
            CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE); // rolled back by commit()
            CHECK_FALSE(txn.commit()); // stays false; no second COMMIT on a reused connection
        }
        CHECK(count_rows(conn.get()) == 0); // the earlier insert did not persist either
    }

    SECTION("a failed statement recovered with ROLLBACK TO SAVEPOINT still commits") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
            PgResult sp{PQexec(conn.get(), "SAVEPOINT s1")};
            REQUIRE(sp.status() == PGRES_COMMAND_OK);
            PgResult bad{PQexec(conn.get(), "INSERT INTO t (id) VALUES (1)")}; // duplicate key
            CHECK(bad.status() == PGRES_FATAL_ERROR);
            PgResult back{PQexec(conn.get(), "ROLLBACK TO SAVEPOINT s1")};
            REQUIRE(back.status() == PGRES_COMMAND_OK);
            insert_row(conn.get(), 2);
            CHECK(txn.commit());
        }
        CHECK(count_rows(conn.get()) == 2);
    }

    SECTION("after a refused commit the guard is disarmed: a transaction started later survives") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
            PgResult bad{PQexec(conn.get(), "SELECT no_such_column FROM t")};
            CHECK(bad.status() == PGRES_FATAL_ERROR);
            CHECK_FALSE(txn.commit()); // rolled back here; the guard must not roll back again
            // The caller starts and commits its own transaction on the same connection while the
            // guard is still in scope. A destructor that still rolled back would not touch it
            // (it runs after COMMIT), so open a second one that is still open at destruction.
            begin(conn.get());
            insert_row(conn.get(), 2);
        } // ~PgTxn runs with the caller's second transaction open: it must NOT roll it back
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_INTRANS);
        PgResult commit2{PQexec(conn.get(), "COMMIT")};
        CHECK(commit2.status() == PGRES_COMMAND_OK);
        CHECK(count_rows(conn.get()) == 1); // the second transaction's row, not the first's
    }

    SECTION("a guard moved after its refused commit stays disarmed") {
        begin(conn.get());
        {
            PgTxn first{conn.get()};
            insert_row(conn.get(), 1);
            PgResult bad{PQexec(conn.get(), "SELECT no_such_column FROM t")};
            CHECK(bad.status() == PGRES_FATAL_ERROR);
            CHECK_FALSE(first.commit());
            PgTxn second{std::move(first)};
            CHECK_FALSE(second.commit()); // the flag travelled with the move
            begin(conn.get());
            insert_row(conn.get(), 2);
        } // both guards leave scope with the caller's transaction open
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_INTRANS);
        PgResult commit2{PQexec(conn.get(), "COMMIT")};
        CHECK(commit2.status() == PGRES_COMMAND_OK);
        CHECK(count_rows(conn.get()) == 1);
    }

    SECTION("plain success is unchanged") {
        begin(conn.get());
        {
            PgTxn txn{conn.get()};
            insert_row(conn.get(), 1);
            CHECK(txn.commit());
            CHECK(txn.commit());
        }
        CHECK(PQtransactionStatus(conn.get()) == PQTRANS_IDLE);
        CHECK(count_rows(conn.get()) == 1);
    }
}
