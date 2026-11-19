#pragma once

/// @file pg_background_build.hpp
/// Reusable steps for building a derived structure over a LARGE existing table in the BACKGROUND,
/// without holding up boot, readiness or ingest. Every step runs on ONE leased connection in
/// AUTOCOMMIT (never inside a pool transaction; `CREATE INDEX CONCURRENTLY` cannot).
///
/// THE CONTRACT A STORE FOLLOWS (first user: the certificate inventory's DN dictionary; PR 2a-4
/// registers its own index with the same helpers):
///   1. Migrations create only the EMPTY structure (cheap on any table size). Nothing in a migration
///      or at boot builds, backfills or scans the big table.
///   2. A FencedLeaderOnly background pass (`leader_gate_permits`, registered in
///      `background_jobs.hpp`) runs the steps in order: indexes, then the reconcile, then it records
///      completion (a marker the store's readiness check reads). A pass is re-entrant and idempotent.
///   3. Indexes come from ONE `IndexSpec` (name + definition): the helper generates the SQL from it
///      and stamps the spec text onto the index as its COMMENT. A same-name index whose stamped spec
///      DIFFERS (or is INVALID) is dropped CONCURRENTLY and rebuilt - `IF NOT EXISTS` alone would
///      keep a stale one for ever. A valid, matching index is a no-op.
///   4. The reconcile runs at EVERY process start before the structure is reported ready, so a
///      rollback to a binary that did not maintain the structure, followed by a re-upgrade, can never
///      read as ready with missing entries. Readiness is "a reconcile STARTED AFTER this process
///      started completed" (database clock on both sides).
///   5. Until ready, the feature that needs the structure is REFUSED, never answered from a partial
///      structure. A wait that is EXPECTED (a restart) is a RETRYABLE refusal with a hint; only a
///      genuinely failed or absent structure is non-retryable.
///   6. Readiness/gauges: the caller pre-seeds its gauges (present-as-0) at BOOT and sets them from
///      the store's readiness accessor; the helpers report each step's outcome through a
///      `StepObserver` (step, result) so the caller can count `..._runs_total{step,result}`.
///   7. CANCELLATION. Batches are bounded by the pool's timeouts and by `should_stop` between
///      batches. The two unbounded statements (`CREATE INDEX CONCURRENTLY` waits for every older
///      transaction in the database; `DROP INDEX CONCURRENTLY` likewise) are interruptible: before
///      each one the caller's `BuildCancel` is armed with the connection's `PGcancel`, and
///      `BuildCancel::cancel()` (called from stop(), another thread) issues `PQcancel`, which libpq
///      documents as thread-safe and which works on every platform and on libpq 16 (no PG17
///      `PQcancelCreate`). No socket is polled here (so there is no select/FD_SET/poll code and no
///      winsock include); the worker is blocked in `PQexec` and returns with SQLSTATE 57014. The
///      result is then typed `stopped`, NEVER detected by matching an error string.
///   8. SESSION STATE. The index build lifts `statement_timeout` and `lock_timeout` for the SESSION
///      (a transaction-local SET is impossible outside a transaction). The RAII `UnboundedSession`
///      RESETs them on every exit; if the RESET itself fails on a live connection (a cancel landing
///      during it) the backend is TERMINATED so the pool discards the connection instead of handing
///      timeouts of 0 to the next borrower. This needs SESSION AFFINITY: a transaction-mode pooler in
///      front of Postgres is UNSUPPORTED for this step (ADR-2002's list of constraints that preclude
///      one).
///   9. Every statement may be cancelled (57014, an administrator's `pg_cancel_backend`, a shutdown):
///      that is a failed ATTEMPT with the real error logged and recorded, retried at the next cycle;
///      it never throws and never leaves the structure marked ready.
///
/// All identifiers passed in are the caller's compile-time constants (validated here); values are
/// bound parameters.

#include "pg_raii.hpp"

#include <libpq-fe.h>

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {

struct BuildResult {
    bool ok{false};
    bool stopped{false};   ///< a requested stop interrupted it: not a fault, not recorded as failed
    std::string sqlstate;  ///< "" when none (e.g. a connection loss)
    std::string error;     ///< the real database error, for the log and the operator
    bool cancelled{false}; ///< SQLSTATE 57014 (statement_timeout / pg_cancel_backend / PQcancel)
};

/// Observes each step's outcome: step is the caller's label (`index`, `reconcile`, `prune`, ...),
/// result one of `ok`, `failed`, `cancelled`, `stopped`, `skipped`.
using StepObserver = std::function<void(std::string_view step, std::string_view result)>;

/// Lets another thread interrupt the one statement currently running on an armed connection.
/// Owns the PGcancel (freed by its deleter on every path, including destruction while armed).
class BuildCancel {
public:
    /// RAII arm: disarms (and frees the PGcancel) on every exit path. `armed()` is false when a stop
    /// was already requested - decided under the same mutex `cancel()` takes, so a stop landing
    /// between the caller's own check and this arm is never lost; the caller must not run the
    /// statement then.
    class ScopedArm {
    public:
        ScopedArm(BuildCancel& owner, PGconn* conn) : owner_(owner), armed_(owner.arm(conn)) {}
        ~ScopedArm() {
            if (armed_)
                owner_.disarm();
        }
        ScopedArm(const ScopedArm&) = delete;
        ScopedArm& operator=(const ScopedArm&) = delete;
        [[nodiscard]] bool armed() const noexcept { return armed_; }

    private:
        BuildCancel& owner_;
        bool armed_;
    };

    /// Request a stop: sets the stop flag and, if armed, PQcancel()s the running statement. Safe to
    /// call from any thread at any time; a call with nothing armed only sets the flag. Residual: a
    /// cancel landing in the microseconds between a successful arm and the statement reaching the
    /// server hits an idle backend and is ignored; callers that need certainty call it again -
    /// ServerImpl::stop() re-cancels about every 500 ms until the maintenance thread has finished.
    void cancel();
    [[nodiscard]] bool stop_requested() const noexcept { return stop_.load(std::memory_order_acquire); }
    /// Clear a stop that was requested for ONE run (lost leadership) so the next run can start. NEVER
    /// call it for a shutdown stop: the server's stop() keeps re-cancelling until the thread is done.
    void reset_stop() {
        std::lock_guard<std::mutex> lk(mu_);
        stop_.store(false, std::memory_order_release);
    }

private:
    struct CancelDeleter {
        void operator()(PGcancel* p) const noexcept { PQfreeCancel(p); }
    };
    [[nodiscard]] bool arm(PGconn* conn);
    void disarm();

    std::mutex mu_;
    std::unique_ptr<PGcancel, CancelDeleter> cancel_;
    std::atomic<bool> stop_{false};
};

/// Session-level `statement_timeout = 0`, `lock_timeout = 0` for the guard's lifetime; RESET on
/// destruction (every exit path); a failed RESET terminates the backend (see contract point 8).
class UnboundedSession {
public:
    explicit UnboundedSession(PGconn* conn) noexcept;
    ~UnboundedSession();
    UnboundedSession(const UnboundedSession&) = delete;
    UnboundedSession& operator=(const UnboundedSession&) = delete;
    [[nodiscard]] bool armed() const noexcept { return armed_; }
    /// TEST SEAM (production never sets it): 1 = behave as if the RESET failed; 2 = as if the RESET
    /// failed AND the post-reset verification failed (forces the terminate path).
    static inline std::atomic<int> force_reset_failure_for_test{0};

private:
    PGconn* conn_;
    bool armed_{false};
};

/// ONE source of truth for an index: the name, the table, the access method and key columns, and an
/// optional partial predicate. `sql()` generates the statement, `spec_text()` the stamp.
struct IndexSpec {
    std::string schema;
    std::string name;
    std::string table;
    std::string method{"btree"};
    std::string columns;   ///< e.g. "issuer_dn" or "dn public.gin_trgm_ops"
    std::string predicate; ///< optional, without "WHERE"
    [[nodiscard]] std::string spec_text() const;
    [[nodiscard]] std::string sql() const;
};

/// Build the index from its spec if absent, INVALID, or stamped with a different spec (those are
/// dropped CONCURRENTLY first). Idempotent: a valid matching index is a no-op.
[[nodiscard]] BuildResult ensure_index_concurrently(PGconn* conn, const IndexSpec& spec,
                                                    BuildCancel* cancel = nullptr);

/// True when the named index exists AND is valid and ready (a failed concurrent build leaves an
/// invalid one). Catalog read only.
[[nodiscard]] bool index_is_valid(PGconn* conn, const std::string& schema,
                                  const std::string& index_name);

/// One reconcile: `fetch(cursor, batch)` fills `batch` with the next keys after `cursor` (empty =
/// done) and advances `cursor`; `apply(batch)` records them. Both return a failed BuildResult after
/// filling the error. `should_stop` is polled between batches (shutdown, lost leadership).
struct BatchedReconcile {
    std::function<BuildResult(std::string& cursor, std::vector<std::string>& batch)> fetch;
    std::function<BuildResult(const std::vector<std::string>& batch)> apply;
};
[[nodiscard]] BuildResult run_batched_reconcile(const BatchedReconcile& step,
                                                const std::function<bool()>& should_stop,
                                                std::size_t* batches_run = nullptr);

/// Fill a BuildResult from a failed PGresult (SQLSTATE, message, cancelled flag).
[[nodiscard]] BuildResult result_from_failure(PGconn* conn, const PgResult& r);

} // namespace yuzu::server::pg
