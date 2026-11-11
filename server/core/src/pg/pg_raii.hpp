#pragma once

/// @file pg_raii.hpp
/// RAII owners for the three libpq resources whose manual cleanup is easy to
/// leak on an early return or an exception — the direct Postgres port of
/// `server/core/src/sqlite_raii.hpp` mandated by ADR-0008 and the F1
/// conditions ledger on #1320 (the F0 canary's manual PQfinish/PQclear
/// cleanup was a one-time exception that does not carry forward).
///
/// CLAUDE.md governance treats manual resource cleanup not wrapped in a RAII
/// owner as BLOCKING; these are the owners all `server/core/src/pg/`
/// substrate code and every future Postgres-backed store use.

#include <libpq-fe.h>

namespace yuzu::server::pg {

/// RAII owner for a `PGresult*`. `PQclear` runs on scope exit — including
/// exception unwind — so no early-return/error/throw path between exec and
/// clear can leak the result. Move-only.
class PgResult {
public:
    PgResult() = default;
    explicit PgResult(PGresult* r) noexcept : r_(r) {}
    ~PgResult() { reset(); }

    PgResult(const PgResult&) = delete;
    PgResult& operator=(const PgResult&) = delete;
    PgResult(PgResult&& o) noexcept : r_(o.r_) { o.r_ = nullptr; }
    PgResult& operator=(PgResult&& o) noexcept {
        if (this != &o) {
            reset();
            r_ = o.r_;
            o.r_ = nullptr;
        }
        return *this;
    }

    PGresult* get() const noexcept { return r_; }
    explicit operator bool() const noexcept { return r_ != nullptr; }

    /// `PQresultStatus` on the owned result; `PGRES_FATAL_ERROR` when empty
    /// (libpq itself maps a null result to fatal in `PQresultStatus`).
    ExecStatusType status() const noexcept { return PQresultStatus(r_); }

    /// True when the result is a successfully completed command or query.
    bool ok() const noexcept {
        const auto s = status();
        return s == PGRES_COMMAND_OK || s == PGRES_TUPLES_OK;
    }

    /// Clear early. Idempotent.
    void reset() noexcept {
        if (r_) {
            PQclear(r_);
            r_ = nullptr;
        }
    }

private:
    PGresult* r_{nullptr};
};

/// RAII owner for a `PGconn*`. `PQfinish` runs on scope exit. Move-only.
///
/// Construction does not connect — adopt the result of `PQconnectdb` /
/// `PQconnectdbParams` (libpq returns a non-null handle even on failure, so
/// the owner also guarantees the failed-connection handle is finished):
///
///     PgConn conn{PQconnectdb(dsn)};
///     if (PQstatus(conn.get()) != CONNECTION_OK) { ... }
class PgConn {
public:
    PgConn() = default;
    explicit PgConn(PGconn* c) noexcept : c_(c) {}
    ~PgConn() { reset(); }

    PgConn(const PgConn&) = delete;
    PgConn& operator=(const PgConn&) = delete;
    PgConn(PgConn&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    PgConn& operator=(PgConn&& o) noexcept {
        if (this != &o) {
            reset();
            c_ = o.c_;
            o.c_ = nullptr;
        }
        return *this;
    }

    PGconn* get() const noexcept { return c_; }
    explicit operator bool() const noexcept { return c_ != nullptr; }

    /// Release ownership without finishing (e.g. handing the connection to a
    /// pool that takes over the lifetime).
    PGconn* release() noexcept {
        PGconn* c = c_;
        c_ = nullptr;
        return c;
    }

    /// Finish early. Idempotent.
    void reset() noexcept {
        if (c_) {
            PQfinish(c_);
            c_ = nullptr;
        }
    }

private:
    PGconn* c_{nullptr};
};

/// RAII transaction guard — direct port of `SqliteTxn`. The CALLER issues
/// `BEGIN` (so it can choose `BEGIN`/`BEGIN ISOLATION LEVEL ...` and map the
/// begin-failure error itself) and then constructs the guard. On scope exit
/// the guard issues `ROLLBACK` unless `commit()` has succeeded — so any early
/// return OR exception between `BEGIN` and a successful `commit()` leaves the
/// connection rolled back, never wedged in an open transaction.
///
/// Move-only (unlike `SqliteTxn`, which predates the need): moving transfers
/// the rollback obligation; the moved-from guard is disarmed. Two further
/// deliberate divergences from `SqliteTxn`: `commit()` returns `bool`, not
/// the C-API return code, and a second `commit()` after success is a no-op
/// returning true (SqliteTxn would re-issue COMMIT and surface the error).
///
/// The guard borrows the connection — it must not outlive the `PgConn` /
/// pool lease that owns it. Operational note: the destructor's ROLLBACK is
/// a server round-trip with no client-side timeout; on a half-open
/// connection it blocks until TCP gives up. If that ever bites, set a
/// statement_timeout on the pool's connections (PR-3 consideration), not
/// here.
class PgTxn {
public:
    explicit PgTxn(PGconn* conn) noexcept : conn_(conn) {}
    ~PgTxn() {
        if (conn_ && !committed_ && !rolled_back_)
            PgResult rollback{PQexec(conn_, "ROLLBACK")};
    }

    PgTxn(const PgTxn&) = delete;
    PgTxn& operator=(const PgTxn&) = delete;
    PgTxn(PgTxn&& o) noexcept
        : conn_(o.conn_), committed_(o.committed_), rolled_back_(o.rolled_back_) {
        o.conn_ = nullptr;
    }
    PgTxn& operator=(PgTxn&& o) noexcept {
        if (this != &o) {
            if (conn_ && !committed_ && !rolled_back_)
                PgResult rollback{PQexec(conn_, "ROLLBACK")};
            conn_ = o.conn_;
            committed_ = o.committed_;
            rolled_back_ = o.rolled_back_;
            o.conn_ = nullptr;
        }
        return *this;
    }

    /// Run `COMMIT`; on success disarm the rollback. If the COMMIT itself
    /// fails the guard stays armed and the destructor rolls back. Calling
    /// again after a successful commit is a no-op returning true.
    ///
    /// An ABORTED transaction (a prior statement failed, including a bound
    /// parameter `exec_params` refused for a NUL byte) is rolled back here and
    /// commit() returns false: Postgres would complete `COMMIT` as a rollback
    /// and still answer `PGRES_COMMAND_OK`, which used to read as success for
    /// work that did not persist. The rollback is issued at once and, once it
    /// takes effect, the guard is disarmed: the connection is idle when
    /// commit() returns and the destructor cannot roll back a transaction the
    /// caller started later. (If the ROLLBACK itself did not take effect the
    /// guard stays armed and the destructor retries it.)
    /// A failed statement the caller recovered from with `ROLLBACK TO
    /// SAVEPOINT` leaves the transaction usable and still commits. A
    /// transaction that is already idle (the caller ended it) takes the
    /// previous path.
    bool commit() noexcept {
        if (!conn_)
            return false;
        if (committed_)
            return true;
        if (rolled_back_)
            return false;
        if (PQtransactionStatus(conn_) == PQTRANS_INERROR) {
            PgResult rollback{PQexec(conn_, "ROLLBACK")};
            // Disarm the destructor once the transaction has ended (or the connection is
            // gone). If the ROLLBACK did not take effect the connection is still aborted,
            // no later transaction can have started on it, and the destructor retries.
            rolled_back_ = PQtransactionStatus(conn_) != PQTRANS_INERROR;
            return false;
        }
        PgResult res{PQexec(conn_, "COMMIT")};
        if (res.status() == PGRES_COMMAND_OK)
            committed_ = true;
        return committed_;
    }

private:
    PGconn* conn_{nullptr};
    bool committed_{false};
    bool rolled_back_{false}; // commit() rolled back an aborted transaction and the ROLLBACK took effect
};

} // namespace yuzu::server::pg
