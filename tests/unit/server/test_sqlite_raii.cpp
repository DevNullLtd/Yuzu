/**
 * test_sqlite_raii.cpp -- Unit tests for the SQLite RAII owners (#2360)
 *
 * These owners exist to make a store's CONSTRUCTOR exception-safe: a throw after
 * the connection is open but before the constructor completes means `~Store`
 * never runs, so a raw `sqlite3*` member leaks the connection and its WAL/SHM
 * files. Member destruction DOES run during that unwind, which is why the handle
 * belongs in an owner.
 *
 * That property was previously asserted only by construction -- no test could
 * reach it, because making `spdlog` throw needs a fault-injecting allocator.
 * These tests close it from the other side: instead of trying to make the store
 * throw, they throw through a scope holding the OWNER and assert the connection
 * was actually released.
 *
 * THE OBSERVABLE. A WAL-mode database has `-wal` and `-shm` sidecar files while
 * a connection is open; SQLite deletes them when the LAST connection closes
 * cleanly. A leaked connection therefore leaves them on disk. Verified against
 * the shipped SQLite (3.52) before these tests were written, including the
 * negative case: with an outstanding statement, plain `sqlite3_close` returns
 * SQLITE_BUSY and does NOT close, and the sidecars persist even after the
 * statement is finalized, because nothing retries the close.
 */

#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <filesystem>
#include <stdexcept>
#include <string>

using namespace yuzu::server;

namespace {

// True while a connection to this WAL database is still open.
bool wal_sidecar_present(const std::filesystem::path& db) {
    return std::filesystem::exists(db.string() + "-wal");
}

// Open a WAL database through the owner and put one table in it, so the WAL
// sidecar exists and the close has something to check.
void open_wal(SqliteDb& db, const std::filesystem::path& path) {
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    sqlite3_exec(db.get(), "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    REQUIRE(sqlite3_exec(db.get(), "CREATE TABLE t(x); INSERT INTO t VALUES(1);", nullptr, nullptr,
                         nullptr) == SQLITE_OK);
}

} // namespace

TEST_CASE("SqliteDb: releases the connection when an exception unwinds its scope",
          "[sqlite_raii][db]") {
    // The constructor-escape property, tested directly. A store holding this as
    // its FIRST member gets the same guarantee during constructor unwind, which
    // is the case that cannot be reached from a test.
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-unwind-"}};

    bool threw = false;
    try {
        SqliteDb db;
        open_wal(db, tmp.path);
        REQUIRE(wal_sidecar_present(tmp.path)); // open: sidecar exists
        throw std::runtime_error("simulating a throw between open and constructor completion");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    REQUIRE(threw);
    CHECK_FALSE(wal_sidecar_present(tmp.path)); // released during unwind
}

TEST_CASE("SqliteDb: an outstanding statement does not defeat close", "[sqlite_raii][db]") {
    // THE close_v2 REGRESSION TEST. `sqlite3_close` returns SQLITE_BUSY and does
    // NOT close while a statement is live; an owner that discards that result and
    // nulls its handle has leaked the connection while reporting success -- the
    // exact leak this class exists to prevent. `close_v2` instead defers the
    // close until the last statement finalizes.
    //
    // Swapping close_v2 back to close reddens the final assertion.
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-busy-"}};

    SqliteStmt stmt;
    {
        SqliteDb db;
        open_wal(db, tmp.path);
        REQUIRE(sqlite3_prepare_v2(db.get(), "SELECT x FROM t", -1, stmt.addr(), nullptr) ==
                SQLITE_OK);
        REQUIRE(wal_sidecar_present(tmp.path));
        db.close(); // while `stmt` is still live
        // Deferred, not done: the statement still holds the connection open.
        CHECK(wal_sidecar_present(tmp.path));
    }
    stmt.reset(); // last reference goes away -> the deferred close completes
    CHECK_FALSE(wal_sidecar_present(tmp.path));
}

TEST_CASE("SqliteDb: close is idempotent and the destructor after it is a no-op",
          "[sqlite_raii][db]") {
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-idem-"}};
    {
        SqliteDb db;
        open_wal(db, tmp.path);
        db.close();
        CHECK_FALSE(static_cast<bool>(db));
        db.close(); // second close must not double-close
        CHECK(db.get() == nullptr);
    } // destructor runs on an already-closed owner
    CHECK_FALSE(wal_sidecar_present(tmp.path));
}

TEST_CASE("SqliteDb: reopening through a live owner does not leak the old connection",
          "[sqlite_raii][db]") {
    // `addr()` releases first. Without that, a second open through the same owner
    // overwrites a live handle and the first connection is unreachable forever.
    yuzu::test::TempDbFile first{std::string_view{"sqliteraii-reopen-a-"}};
    yuzu::test::TempDbFile second{std::string_view{"sqliteraii-reopen-b-"}};
    {
        SqliteDb db;
        open_wal(db, first.path);
        REQUIRE(wal_sidecar_present(first.path));
        open_wal(db, second.path); // reuse the same owner
        CHECK_FALSE(wal_sidecar_present(first.path)); // the first was released
        CHECK(wal_sidecar_present(second.path));
    }
    CHECK_FALSE(wal_sidecar_present(second.path));
}

TEST_CASE("SqliteStmt: re-preparing through one owner finalizes the first statement",
          "[sqlite_raii][stmt]") {
    // The contract `SqliteStmt::addr()` shares with the other two owners, and the
    // only behaviour the last commit changed. It needs its own test for a reason
    // that is easy to get wrong: LSan does NOT catch this leak. SQLite keeps
    // unfinalized statements reachable from the connection, so a leaked statement
    // is not "lost" memory -- it is a live object pinning the connection, which
    // with `close_v2` means the connection zombies until process exit.
    //
    // `sqlite3_next_stmt` walks the connection's live statement list, so it is a
    // direct, deterministic observable for exactly this. Removing the `reset()`
    // from `addr()` leaves the first statement on that list and reddens the final
    // assertion.
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-stmt-"}};
    SqliteDb db;
    open_wal(db, tmp.path);

    SqliteStmt stmt;
    REQUIRE(sqlite3_prepare_v2(db.get(), "SELECT x FROM t", -1, stmt.addr(), nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_next_stmt(db.get(), nullptr) != nullptr); // one live statement

    // Re-prepare through the SAME owner.
    REQUIRE(sqlite3_prepare_v2(db.get(), "SELECT count(*) FROM t", -1, stmt.addr(), nullptr) ==
            SQLITE_OK);

    // Exactly ONE live statement, not two: the first was finalized by addr().
    sqlite3_stmt* first = sqlite3_next_stmt(db.get(), nullptr);
    REQUIRE(first != nullptr);
    CHECK(sqlite3_next_stmt(db.get(), first) == nullptr);

    stmt.reset();
    CHECK(sqlite3_next_stmt(db.get(), nullptr) == nullptr); // owner released it
}

TEST_CASE("SqliteDb: move transfers ownership exactly once", "[sqlite_raii][db]") {
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-move-"}};
    {
        SqliteDb a;
        open_wal(a, tmp.path);
        SqliteDb b{std::move(a)};
        CHECK_FALSE(static_cast<bool>(a)); // source disengaged: no double close
        CHECK(static_cast<bool>(b));
        CHECK(wal_sidecar_present(tmp.path));
    }
    CHECK_FALSE(wal_sidecar_present(tmp.path));
}

TEST_CASE("SqliteErrMsg: frees on unwind and never returns null", "[sqlite_raii][errmsg]") {
    yuzu::test::TempDbFile tmp{std::string_view{"sqliteraii-errmsg-"}};
    SqliteDb db;
    REQUIRE(sqlite3_open(tmp.path.string().c_str(), db.addr()) == SQLITE_OK);

    SECTION("a failing exec populates the message and it survives to the log site") {
        SqliteErrMsg err;
        const int rc = sqlite3_exec(db.get(), "THIS IS NOT SQL", nullptr, nullptr, err.addr());
        CHECK(rc != SQLITE_OK);
        CHECK(std::string{err.c_str()}.find("syntax error") != std::string::npos);
    }

    SECTION("an untouched message reads as a usable string, not a null deref") {
        // SQLite leaves the out-param alone on success, and does not set it on
        // every failure path either. Callers format `c_str()` directly.
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(db.get(), "SELECT 1", nullptr, nullptr, err.addr()) == SQLITE_OK);
        CHECK(std::string{err.c_str()} == "unknown error");
    }

    SECTION("reuse through addr() releases the previous message") {
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(db.get(), "BAD ONE", nullptr, nullptr, err.addr()) != SQLITE_OK);
        REQUIRE(std::string{err.c_str()} != "unknown error");
        // Second use of the same owner: the first message must not leak. ASan/LSan
        // is the actual detector here; this pins the calling pattern.
        REQUIRE(sqlite3_exec(db.get(), "ALSO BAD", nullptr, nullptr, err.addr()) != SQLITE_OK);
        CHECK(std::string{err.c_str()} != "unknown error");
    }
}
