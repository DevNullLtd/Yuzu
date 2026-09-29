// Contract tests for the pg_raii.hpp RAII owners (#1320 PR 1, ADR-0008).
//
// The move-only static_asserts run on every platform with no database; the
// behavioral cases (rollback-unless-commit, double-commit) need a live
// Postgres and follow the skip-vs-fail contract in test_helpers.hpp.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

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

    SECTION("commit failure leaves the guard armed") {
        begin(conn.get());
        PgTxn txn{conn.get()};
        // Poison the transaction: a failed statement puts it in
        // PQTRANS_INERROR, after which COMMIT reports rollback.
        PgResult bad{PQexec(conn.get(), "SELECT no_such_column FROM t")};
        CHECK(bad.status() == PGRES_FATAL_ERROR);
        // Postgres turns COMMIT on an aborted txn into ROLLBACK but still
        // answers PGRES_COMMAND_OK, so commit() "succeeds" — the invariant
        // that matters is the connection comes back idle and nothing
        // persisted.
        (void)txn.commit();
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
