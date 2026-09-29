#include "pg_pool.hpp"

#include "pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdlib>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::pg {

namespace {

/// Scan a parsed conninfo for an explicitly-set keyword. `PQconninfoParse`
/// returns entries for every known keyword; only those with a non-null `val`
/// were actually present in the string (or inherited from the environment —
/// close enough: an operator setting PGCONNECT_TIMEOUT wins too, which is the
/// right precedence).
bool conninfo_sets(PQconninfoOption* opts, const char* keyword) {
    for (PQconninfoOption* o = opts; o && o->keyword; ++o) {
        if (std::string_view(o->keyword) == keyword)
            return o->val != nullptr && o->val[0] != '\0';
    }
    return false;
}

} // namespace

PgPool::PgPool(Options opts)
    : conninfo_(std::move(opts.conninfo)), size_(opts.size > 0 ? opts.size : 1),
      connect_timeout_s_(opts.connect_timeout_s), statement_timeout_ms_(opts.statement_timeout_ms),
      lock_timeout_ms_(opts.lock_timeout_ms), keepalives_idle_s_(opts.keepalives_idle_s),
      tcp_user_timeout_ms_(opts.tcp_user_timeout_ms),
      saturated_fast_fail_(opts.saturated_fast_fail), observer_(std::move(opts.observer)),
      backoff_base_(opts.connect_backoff_base),
      backoff_cap_(opts.connect_backoff_cap) {
    // Parse up front so a malformed conninfo is caught here, once, with a
    // sanitized error — NOT at first acquire with libpq's parse error, which
    // quotes the offending token (potentially a credential).
    char* errmsg = nullptr;
    PQconninfoOption* parsed = PQconninfoParse(conninfo_.c_str(), &errmsg);
    if (!parsed) {
        // errmsg deliberately NOT propagated: it echoes conninfo fragments.
        set_error("invalid connection string (details withheld — conninfo "
                  "fragments are never echoed)");
        spdlog::error("PgPool: connection string failed to parse; refusing all acquires");
        if (errmsg)
            PQfreemem(errmsg);
        return;
    }
    // PQconninfoParse does NOT consult the environment, so honour an
    // operator's PGCONNECT_TIMEOUT explicitly — it should win over the
    // pool's injected default, same as a conninfo-level setting.
    const char* env_timeout = std::getenv("PGCONNECT_TIMEOUT");
    conninfo_has_timeout_ = conninfo_sets(parsed, "connect_timeout") ||
                            (env_timeout != nullptr && env_timeout[0] != '\0');
    // The pool injects statement/lock timeouts via the `options` keyword and
    // keepalives via `keepalives*`; never clobber an operator who set their
    // own (conninfo wins). PGOPTIONS is the env analogue of `options`.
    const char* env_options = std::getenv("PGOPTIONS");
    conninfo_has_options_ = conninfo_sets(parsed, "options") ||
                            (env_options != nullptr && env_options[0] != '\0');
    conninfo_has_keepalives_ = conninfo_sets(parsed, "keepalives");
    // No dedicated PG* env var exists for tcp_user_timeout (unlike
    // connect_timeout/options above) — conninfo is the only source to check.
    conninfo_has_tcp_user_timeout_ = conninfo_sets(parsed, "tcp_user_timeout");
    PQconninfoFree(parsed);
    valid_ = true;
}

PgPool::~PgPool() {
    std::unique_lock lk{mu_};
    shutdown_ = true;
    cv_.notify_all();
    // Wait for every lease to come home, every in-flight connect to
    // resolve, AND every blocked acquirer to leave its wait — destroying
    // mu_/cv_ while a woken waiter is still reacquiring the mutex inside
    // cv_.wait would be UB (Gate 3 cpp-B1). release() closes connections
    // instead of pooling them once shutdown_ is set; waiters observe
    // shutdown_, decrement waiters_, notify, and return empty leases.
    // Calling acquire() for the FIRST time after the destructor returns
    // is a caller lifetime bug, same as any destroyed object.
    cv_.wait(lk, [this] { return leased_ == 0 && connecting_ == 0 && waiters_ == 0; });
    while (!idle_.empty()) {
        PQfinish(idle_.front());
        idle_.pop_front();
        --open_;
    }
}

PgPool::Lease PgPool::acquire() {
    return acquire_internal(nullptr);
}

PgPool::Lease PgPool::try_acquire_for(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    return acquire_internal(&deadline);
}

PgPool::Lease PgPool::acquire_internal(const std::chrono::steady_clock::time_point* deadline) {
    const auto t0 = std::chrono::steady_clock::now();
    // Report wall time spent waiting for a checkout — including the zero-wait
    // idle-hit fast path. Always invoked AFTER `lk` is released (the histogram
    // has its own mutex; calling under mu_ would needlessly widen the
    // critical section and the Observer contract forbids re-entry anyway).
    const auto observe_wait = [&] {
        if (observer_.on_acquire_wait_seconds) {
            const auto secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            observer_.on_acquire_wait_seconds(secs);
        }
    };

    std::unique_lock lk{mu_};
    if (!valid_)
        return {};

    // Fast-fail-on-saturation (#2146 gov sre finding
    // up-2146-a2r1-httplib-worker-cascade): checked ONCE, here, before the
    // wait loop below -- `idle_.empty() && open_ + connecting_ >= size_` is
    // exactly the condition the loop already requires before it will ever
    // reach its `cv_.wait_until` branch, so this is equivalent to clamping
    // the wait at that branch, without duplicating the branch's own
    // bookkeeping. If a BOUNDED acquire (`deadline != nullptr`) observes the
    // pool already in that state, the caller's own timeout is very unlikely
    // to be honoured by an actual release in time -- clamp the wait to
    // `saturated_fast_fail_` instead, so the calling thread (often an
    // httplib worker for a REST route, but any caller of a bounded acquire
    // backed by this pool) is freed almost immediately rather than pinned
    // for the full timeout. Measured from `t0` (taken
    // before the lock, above) rather than "now" here, so time already spent
    // waiting on `mu_` counts against the budget too -- the caller's thread
    // has been unavailable to its own caller since `t0`. Unbounded
    // `acquire()` (`deadline == nullptr`) and a bounded acquire that is NOT
    // already saturated at entry are both unaffected. See
    // Options::saturated_fast_fail's doc comment for why its default is
    // 500ms rather than a smaller "near-zero" value -- several existing
    // callers already pick a deliberately short timeout for reasons
    // unrelated to this finding, and 500ms is chosen to sit AT OR ABOVE every
    // one of them (a few tie at exactly 500ms; see the doc comment for the
    // full survey).
    std::chrono::steady_clock::time_point fast_fail_deadline;
    if (deadline && idle_.empty() && open_ + connecting_ >= size_) {
        fast_fail_deadline = std::min(*deadline, t0 + saturated_fast_fail_);
        deadline = &fast_fail_deadline;
    }

    for (;;) {
        if (shutdown_) {
            last_error_ = "pool is shutting down";
            // The destructor may be waiting on waiters_ == 0; make sure it
            // re-evaluates after we leave (we may have just decremented).
            cv_.notify_all();
            return {};
        }
        if (!idle_.empty()) {
            PGconn* c = idle_.front();
            idle_.pop_front();
            ++leased_;
            // Take ownership in the RAII Lease BEFORE the observer can run: if
            // observe_wait() throws, `lease` destructs and returns `c` to the
            // pool (decrementing leased_) instead of leaking it and wedging the
            // destructor's leased_==0 wait (gov fjarvis S1). The Observer
            // contract is SHOULD-NOT-throw, but that is weaker than noexcept.
            Lease lease{this, c};
            lk.unlock();
            observe_wait();
            return lease;
        }
        // Deadline gate: never START a connect (or another wait) past the
        // caller's deadline. An idle connection at/past the deadline is
        // still taken above — that costs nothing.
        if (deadline && std::chrono::steady_clock::now() >= *deadline) {
            // Deliberately not "exhausted": the deadline can also expire
            // before a connect was ever attempted (Gate 8 LOW).
            last_error_ = "acquire timed out before a connection was available";
            lk.unlock();
            if (observer_.on_acquire_timeout)
                observer_.on_acquire_timeout();
            return {};
        }
        // Connect-failure breaker (#1368): with no idle connection available
        // and a failed connect still inside its suppression window, fail fast
        // rather than launch another connect into a down database. The idle
        // check above runs first, so a recovered connection is always served.
        if (std::chrono::steady_clock::now() < connect_blocked_until_) {
            last_error_ = "connect backoff active after repeated connection failures";
            return {};
        }
        if (open_ + connecting_ < size_) {
            ++connecting_;
            lk.unlock();
            PGconn* c = nullptr;
            try {
                c = connect_one(); // slow; deliberately outside the lock
            } catch (...) {
                // bad_alloc from error-string building: restore the
                // reserved capacity or the destructor waits forever on
                // connecting_ == 0 (Gate 3 cpp-S1).
                lk.lock();
                --connecting_;
                cv_.notify_all();
                throw;
            }
            lk.lock();
            --connecting_;
            if (!c) {
                // Arm the breaker so the next acquirers fail fast instead of
                // each launching another connect storm, then free the
                // reserved capacity and wake a waiter to retry-or-fail.
                arm_connect_backoff_locked();
                cv_.notify_all();
                return {};
            }
            if (shutdown_) {
                PQfinish(c);
                cv_.notify_all();
                last_error_ = "pool is shutting down";
                return {};
            }
            // A live connection proves the database is reachable: clear the
            // breaker so recovery is immediate.
            connect_failures_ = 0;
            connect_blocked_until_ = {};
            ++open_;
            ++leased_;
            // RAII owner before the (SHOULD-not-throw) observer — see the
            // idle-hit path above (gov fjarvis S1).
            Lease lease{this, c};
            lk.unlock();
            observe_wait();
            return lease;
        }
        // waiters_ keeps the destructor from tearing the pool down while we
        // are still inside the wait (it spins on waiters_ == 0).
        ++waiters_;
        if (deadline)
            cv_.wait_until(lk, *deadline);
        else
            cv_.wait(lk);
        --waiters_;
    }
}

void PgPool::arm_connect_backoff_locked() {
    ++connect_failures_;
    // base × 2^(failures-1), capped, then ±25% jitter. Shift is bounded by
    // the cap so a long outage can't overflow.
    const long long base = backoff_base_.count() > 0 ? backoff_base_.count() : 1;
    const long long cap = std::max<long long>(backoff_cap_.count(), base);
    long long window = base;
    for (std::size_t i = 1; i < connect_failures_ && window < cap; ++i)
        window = std::min(cap, window * 2);
    window = std::min(window, cap);
    // Jitter in [75%, 100%] of the window — decorrelates a fleet of acquirers
    // that all failed at once.
    std::uniform_int_distribution<long long> jitter(window * 3 / 4, window);
    const long long ms = jitter(jitter_rng_);
    connect_blocked_until_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
}

PGconn* PgPool::connect_one() {
    // Expand the caller's conninfo through the `dbname` keyword
    // (expand_dbname=1) and append the pool's effective defaults only where
    // the conninfo (or the matching env var) didn't set one — operator
    // settings always win:
    //  - connect_timeout: libpq has no client-side timeout, so a black-holed
    //    host would otherwise wedge the acquiring thread;
    //  - keepalives/keepalives_idle: surface a silently reaped connection as a
    //    failed statement rather than an indefinite hang;
    //  - tcp_user_timeout: bounds how long UNACKED data may sit on a
    //    genuinely dark network path, independent of the keepalive cycle
    //    (see the Options doc comment for why this differs from keepalives);
    //  - options (-c statement_timeout / -c lock_timeout): bound a wedged
    //    query and the migration-runner advisory-lock wait server-side.
    // All locals below must outlive the PQconnectdbParams call (they do — the
    // call happens before this function returns).
    const std::string timeout = std::to_string(connect_timeout_s_);
    const std::string keepalives_idle = std::to_string(keepalives_idle_s_);
    const std::string tcp_user_timeout = std::to_string(tcp_user_timeout_ms_);
    std::string options;
    if (!conninfo_has_options_) {
        if (statement_timeout_ms_ > 0)
            options += "-c statement_timeout=" + std::to_string(statement_timeout_ms_);
        if (lock_timeout_ms_ > 0) {
            if (!options.empty())
                options += " ";
            options += "-c lock_timeout=" + std::to_string(lock_timeout_ms_);
        }
    }

    std::vector<const char*> keys;
    std::vector<const char*> vals;
    keys.push_back("dbname");
    vals.push_back(conninfo_.c_str());
    if (!conninfo_has_timeout_) {
        keys.push_back("connect_timeout");
        vals.push_back(timeout.c_str());
    }
    if (!conninfo_has_keepalives_ && keepalives_idle_s_ > 0) {
        keys.push_back("keepalives");
        vals.push_back("1");
        keys.push_back("keepalives_idle");
        vals.push_back(keepalives_idle.c_str());
    }
    if (!conninfo_has_tcp_user_timeout_ && tcp_user_timeout_ms_ > 0) {
        keys.push_back("tcp_user_timeout");
        vals.push_back(tcp_user_timeout.c_str());
    }
    if (!conninfo_has_options_ && !options.empty()) {
        keys.push_back("options");
        vals.push_back(options.c_str());
    }
    keys.push_back(nullptr);
    vals.push_back(nullptr);

    PgConn conn{PQconnectdbParams(keys.data(), vals.data(), /*expand_dbname=*/1)};
    if (PQstatus(conn.get()) != CONNECTION_OK) {
        // Safe to surface: connect errors from a *well-formed* conninfo name
        // host/port and the failure cause, never credentials. The malformed
        // case never reaches here (rejected at construction).
        std::string err = conn ? PQerrorMessage(conn.get()) : "out of memory";
        spdlog::warn("PgPool: connection attempt failed: {}", err);
        set_error(std::move(err));
        // Observer runs here: connect_one is always called WITHOUT mu_ held.
        if (observer_.on_connect_failure)
            observer_.on_connect_failure();
        return nullptr;
    }
    return conn.release();
}

void PgPool::release(PGconn* conn) noexcept {
    bool healthy = PQstatus(conn) == CONNECTION_OK;
    if (healthy && PQtransactionStatus(conn) != PQTRANS_IDLE) {
        // The caller leaked an open/failed transaction into the pool. Roll it
        // back defensively; if the connection still isn't idle, discard it.
        PgResult rollback{PQexec(conn, "ROLLBACK")};
        healthy = PQstatus(conn) == CONNECTION_OK && PQtransactionStatus(conn) == PQTRANS_IDLE;
        if (healthy)
            spdlog::warn("PgPool: connection returned mid-transaction; rolled back");
    }

    bool discarded_unhealthy = false;
    {
        std::lock_guard lk{mu_};
        --leased_;
        if (shutdown_ || !healthy) {
            PQfinish(conn);
            --open_;
            // A discard during shutdown is routine teardown, not a health
            // signal; only count connections dropped because they came back
            // broken.
            discarded_unhealthy = !healthy;
        } else {
            try {
                idle_.push_back(conn);
            } catch (...) {
                // release() is noexcept; a bad_alloc from the deque must not
                // terminate — drop the connection instead (capacity frees up
                // for a fresh connect).
                PQfinish(conn);
                --open_;
            }
        }
        cv_.notify_all();
    }
    // Observer runs after the lock is released; release() is noexcept, so a
    // throwing hook must not propagate.
    if (discarded_unhealthy && observer_.on_unhealthy_discard) {
        try {
            observer_.on_unhealthy_discard();
        } catch (...) {
        }
    }
}

bool PgPool::with_txn(const std::function<bool(PGconn*)>& fn) {
    return run_in_txn(acquire(), fn);
}

bool PgPool::with_txn_for(std::chrono::milliseconds timeout,
                          const std::function<bool(PGconn*)>& fn) {
    return run_in_txn(try_acquire_for(timeout), fn);
}

bool PgPool::with_txn_on(Lease lease, const std::function<bool(PGconn*)>& fn) {
    return run_in_txn(std::move(lease), fn);
}

bool PgPool::run_in_txn(Lease lease, const std::function<bool(PGconn*)>& fn) {
    if (!lease)
        return false;

    PgResult begin{PQexec(lease.get(), "BEGIN")};
    if (begin.status() != PGRES_COMMAND_OK) {
        spdlog::error("PgPool: BEGIN failed: {}", PQerrorMessage(lease.get()));
        return false;
    }
    // Declared after `lease` so unwind order is txn-rollback first, then the
    // lease returns the (now idle) connection.
    PgTxn txn{lease.get()};
    if (!fn(lease.get()))
        return false; // txn dtor rolls back
    // Refuse to "commit" an aborted transaction: COMMIT in PQTRANS_INERROR
    // completes as ROLLBACK yet reports PGRES_COMMAND_OK, so a callback
    // that swallowed a statement failure and returned true would otherwise
    // get `true` back with nothing persisted (UP-3). Enforce here instead
    // of trusting every store author to check.
    if (PQtransactionStatus(lease.get()) != PQTRANS_INTRANS) {
        spdlog::error("PgPool: with_txn callback returned true on an aborted/idle "
                      "transaction — rolling back");
        return false; // txn dtor rolls back
    }
    return txn.commit();
}

std::string PgPool::last_error() const {
    std::lock_guard lk{mu_};
    return last_error_;
}

std::size_t PgPool::in_use() const {
    std::lock_guard lk{mu_};
    return leased_;
}

std::size_t PgPool::open() const {
    std::lock_guard lk{mu_};
    return open_;
}

std::size_t PgPool::waiters() const {
    std::lock_guard lk{mu_};
    return waiters_;
}

bool PgPool::connect_breaker_open() const {
    std::lock_guard lk{mu_};
    return std::chrono::steady_clock::now() < connect_blocked_until_;
}

void PgPool::set_error(std::string msg) {
    std::lock_guard lk{mu_};
    last_error_ = std::move(msg);
}

} // namespace yuzu::server::pg
