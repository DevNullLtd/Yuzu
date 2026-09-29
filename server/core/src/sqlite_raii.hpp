#pragma once

/// @file sqlite_raii.hpp
/// RAII owners for the SQLite resources whose manual cleanup is easy to leak on
/// an early return or -- the case that motivated this header -- an exception
/// thrown where no destructor would otherwise run: between `BEGIN` and `COMMIT`,
/// or inside a store's CONSTRUCTOR, where a throw means `~Store` never runs at
/// all. Governance treats manual resource cleanup not wrapped in an owner as
/// BLOCKING.
///
/// Four owners: `SqliteStmt` (prepared statement), `SqliteTxn` (transaction),
/// `SqliteErrMsg` (an `sqlite3_exec` error string), and `SqliteDb` (the
/// connection itself). Used by the server stores generally -- `audit_store`,
/// `baseline_store`, `guaranteed_state_store`, `nvd_db`, `rbac_store`,
/// `response_store`, `tag_store`.
///
/// SHARED CONTRACT for the three owners exposing `addr()`: it RELEASES whatever
/// is currently held before handing out the address, so re-preparing or
/// re-opening through one owner cannot leak. Do not add a fourth `addr()` that
/// behaves differently.
///
/// Reuse note: `response_store` also caches *persistent* prepared statements as
/// raw members (a different ownership model, untouched by these owners); these
/// are for the per-operation prepare/step/finalize pattern.

#include <sqlite3.h>

namespace yuzu::server {

/// RAII finalizer for a prepared statement. `sqlite3_finalize` runs on scope
/// exit — including exception unwind — so no early-return/error/throw path
/// between prepare and finalize can leak the statement. Move-only.
class SqliteStmt {
public:
    SqliteStmt() = default;
    explicit SqliteStmt(sqlite3_stmt* s) noexcept : s_(s) {}
    ~SqliteStmt() { reset(); }

    SqliteStmt(const SqliteStmt&) = delete;
    SqliteStmt& operator=(const SqliteStmt&) = delete;
    SqliteStmt(SqliteStmt&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
    SqliteStmt& operator=(SqliteStmt&& o) noexcept {
        if (this != &o) {
            reset();
            s_ = o.s_;
            o.s_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_prepare_v2(db, sql, -1, stmt.addr(), nullptr)`.
    /// Finalizes any statement already held, so re-preparing through one owner
    /// is safe. All three owners in this header share that contract - without it
    /// a second prepare would leak the first statement, and because `SqliteDb`
    /// closes with `close_v2`, a leaked statement also pins the connection as a
    /// zombie until process exit.
    [[nodiscard]] sqlite3_stmt** addr() noexcept {
        reset();
        return &s_;
    }
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return s_; }
    explicit operator bool() const noexcept { return s_ != nullptr; }

    /// Finalize early (e.g. before COMMIT). Idempotent.
    void reset() noexcept {
        if (s_) {
            sqlite3_finalize(s_);
            s_ = nullptr;
        }
    }

private:
    sqlite3_stmt* s_{nullptr};
};

/// RAII transaction guard. The CALLER issues `BEGIN` (so it can choose
/// `BEGIN`/`BEGIN IMMEDIATE` and map the begin-failure error itself) and then
/// constructs the guard. On scope exit the guard issues `ROLLBACK` unless
/// `commit()` has succeeded — so any early return OR exception between `BEGIN`
/// and a successful `commit()` leaves the connection rolled back, never wedged in
/// an open transaction.
///
/// Ordering: declare the guard BEFORE any `SqliteStmt` used in the transaction
/// (or finalize the statements first). C++ destroys locals in reverse order, so
/// the statements then finalize before the rollback runs — SQLite wants live
/// statements finalized/reset before `ROLLBACK`.
class SqliteTxn {
public:
    explicit SqliteTxn(sqlite3* db) noexcept : db_(db) {}
    ~SqliteTxn() {
        if (db_ && !committed_)
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }

    SqliteTxn(const SqliteTxn&) = delete;
    SqliteTxn& operator=(const SqliteTxn&) = delete;

    /// Run `COMMIT`; on success disarm the rollback. On failure the guard stays
    /// armed and the destructor rolls back. Returns the `sqlite3_exec` code.
    [[nodiscard]] int commit() noexcept {
        const int rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
        if (rc == SQLITE_OK)
            committed_ = true;
        return rc;
    }

private:
    sqlite3* db_{nullptr};
    bool committed_{false};
};

/// RAII owner for a `char*` message allocated by SQLite (the `errmsg` out-param
/// of `sqlite3_exec`). `sqlite3_free` runs on scope exit, so a throw between the
/// `exec` and the free -- an fmt or `bad_alloc` throw from the log call that
/// formats the message being the realistic one -- cannot leak it. Move-only.
class SqliteErrMsg {
public:
    SqliteErrMsg() = default;
    ~SqliteErrMsg() { reset(); }

    SqliteErrMsg(const SqliteErrMsg&) = delete;
    SqliteErrMsg& operator=(const SqliteErrMsg&) = delete;
    SqliteErrMsg(SqliteErrMsg&& o) noexcept : m_(o.m_) { o.m_ = nullptr; }
    SqliteErrMsg& operator=(SqliteErrMsg&& o) noexcept {
        if (this != &o) {
            reset();
            m_ = o.m_;
            o.m_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_exec(db, sql, nullptr, nullptr, msg.addr())`.
    [[nodiscard]] char** addr() noexcept {
        reset(); // reusing a live owner would otherwise leak the old message
        return &m_;
    }

    /// Never null. SQLite leaves the out-param untouched on success and does not
    /// set it on every failure path either, so callers get a usable string
    /// without each writing its own ternary at the log site.
    [[nodiscard]] const char* c_str() const noexcept { return m_ ? m_ : "unknown error"; }

    void reset() noexcept {
        if (m_) {
            sqlite3_free(m_);
            m_ = nullptr;
        }
    }

private:
    char* m_{nullptr};
};

/// RAII owner for the connection itself. `sqlite3_close_v2` runs on scope exit,
/// which is what makes a store's CONSTRUCTOR exception-safe: a throw after the
/// handle is open but before the constructor completes means `~Store` never
/// runs, so a raw `sqlite3*` member leaks the connection and its WAL/SHM files.
/// Holding the handle in a member owner instead moves the close into member
/// destruction, which DOES run during constructor unwind. Move-only.
///
/// `close()` is exposed for stores that deliberately close early and then treat
/// a null handle as "degraded, fail every operation" (a failed migration, for
/// example); it is idempotent, so the destructor after an explicit close is a
/// no-op rather than a double close.
class SqliteDb {
public:
    SqliteDb() = default;
    explicit SqliteDb(sqlite3* db) noexcept : db_(db) {}
    ~SqliteDb() { close(); }

    SqliteDb(const SqliteDb&) = delete;
    SqliteDb& operator=(const SqliteDb&) = delete;
    SqliteDb(SqliteDb&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }
    SqliteDb& operator=(SqliteDb&& o) noexcept {
        if (this != &o) {
            close();
            db_ = o.db_;
            o.db_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_open_v2(path, db.addr(), flags, nullptr)`. SQLite
    /// may allocate the handle even when the open FAILS, which is exactly why it
    /// wants an owner from the first call rather than after the error check.
    [[nodiscard]] sqlite3** addr() noexcept {
        close(); // re-opening through a live owner would otherwise leak it
        return &db_;
    }
    [[nodiscard]] sqlite3* get() const noexcept { return db_; }
    explicit operator bool() const noexcept { return db_ != nullptr; }

    /// close_v2, NOT close. `sqlite3_close` returns SQLITE_BUSY and does NOT
    /// close when any statement is still outstanding -- so nulling the member
    /// after it would leak the connection and its WAL/SHM files while this owner
    /// reported success, which is precisely the leak this class exists to stop.
    /// close_v2 marks the connection zombie and closes it when the last
    /// statement finalizes. `audit_store` no longer has any raw statement owner,
    /// but any future one -- or any other store adopting `SqliteDb` -- would
    /// reintroduce the exposure, which is why the owner does not rely on callers
    /// getting it right.
    void close() noexcept {
        if (db_) {
            sqlite3_close_v2(db_);
            db_ = nullptr;
        }
    }

private:
    sqlite3* db_{nullptr};
};

} // namespace yuzu::server
