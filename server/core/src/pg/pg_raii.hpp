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
#include <yuzu/log_token.hpp> // log_key_token: query-phase detail

#include <string>
#include <string_view>

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

/// Distinct causes callers and tests name (the #4943 reserve-slots discriminator among them).
inline constexpr const char* kConnectNoFreeSlots =
    "no free connection slots (max_connections or reserved slots exhausted)";
inline constexpr const char* kConnectNoWritableHost =
    "no writable host (read-only session or hot standby)";
inline constexpr const char* kConnectFailureGeneric =
    "connection failed (details withheld; check host, port and credentials)";

/// Map libpq's connect-failure text to a FIXED, credential-free cause (F56, CWE-532). The raw
/// `PQerrorMessage` of a failed connect quotes the host, port and dbname libpq parsed out of the
/// DSN, and a URI DSN whose password holds an unescaped '/' or '@' parses cleanly with part of
/// the password landing in one of those fields -- so the raw text must never reach a log line or
/// `last_error()`. The text is inspected only to pick one of these constants; nothing from it is
/// ever copied out. Substring matching on libpq's stable phrases; anything unrecognised falls to
/// the generic cause. ASCII, one line.
[[nodiscard]] inline const char* connect_failure_cause(std::string_view err) noexcept {
    const auto has = [&](std::string_view needle) { return err.find(needle) != std::string_view::npos; };
    // ORDER MATTERS: libpq quotes caller-chosen names (a database or role called "SSL_prod" or
    // "No such file or directory"), so the specific, structural phrases come first and the
    // does-not-exist test comes before the loose ones. A missing sslrootcert says "does not
    // exist" too, so the TLS phrases precede it.
    if (has("password authentication failed") || has("authentication failed") ||
        has("no password supplied") || has("password retrieved from file"))
        return "authentication failed (credentials rejected or missing)";
    if (has("no pg_hba.conf entry"))
        return "refused by server access rules (no matching pg_hba.conf entry)";
    if (has("SSL error") || has("SSL SYSCALL") || has("SSL connection") ||
        has("SSL is not enabled") || has("does not support SSL") || has("root certificate file") ||
        has("certificate verify failed") || has("sslmode"))
        return "TLS negotiation or certificate verification failed";
    if (has("\" does not exist"))
        return "database or role does not exist";
    // #4943/#4944 discriminator: a probe refused at max_connections because the free slots are
    // the superuser/pg_use_reserved_connections reserve.
    if (has("remaining connection slots") || has("too many clients"))
        return kConnectNoFreeSlots;
    // target_session_attrs=read-write refused every host: nothing writable behind the DSN.
    if (has("session is read-only") || has("hot standby") || has("target_session_attrs") ||
        has("server is in hot standby mode") || has("read-only transaction"))
        return kConnectNoWritableHost;
    if (has("could not translate host name") || has("Name or service not known") ||
        has("Temporary failure in name resolution"))
        return "host name could not be resolved";
    if (has("timeout expired") || has("timed out"))
        return "connection timed out";
    if (has("Connection refused") || has("No such file or directory") ||
        has("Is the server running"))
        return "server not reachable (connection refused or no such socket)";
    if (has("starting up") || has("shutting down"))
        return "server not accepting connections (starting up or shutting down)";
    if (has("out of memory"))
        return "out of memory";
    return kConnectFailureGeneric;
}

/// Query-phase failure detail (the connection existed): the connect classifier does NOT apply -- a
/// dropped connection or "SSL SYSCALL error: EOF detected" during a failover is not a certificate
/// problem -- and these messages do not quote the DSN. Returns `step` plus the FIRST line of libpq's
/// text, folded with log_key_token and capped at kQueryDetailMaxBytes, so on-call still reads "server
/// closed the connection unexpectedly". NOT for connect-phase text: that quotes the DSN and must go
/// through connect_failure_cause.
inline constexpr std::size_t kQueryDetailMaxBytes = 120;
[[nodiscard]] inline std::string query_failure_detail(std::string_view step, std::string_view raw) {
    raw = raw.substr(0, raw.find_first_of("\r\n"));
    if (raw.size() > kQueryDetailMaxBytes) {
        // Cut on a code-point boundary: back up over continuation bytes so no lead byte dangles.
        std::size_t cut = kQueryDetailMaxBytes;
        while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0) == 0x80)
            --cut;
        raw = raw.substr(0, cut);
    }
    const std::string safe = ::yuzu::log_key_token(raw);
    return safe.empty() ? std::string(step) : std::string(step) + ": " + safe;
}

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
