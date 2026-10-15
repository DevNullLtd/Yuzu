#pragma once

/// @file pg_pool.hpp
/// Bounded, thread-safe pool of libpq connections — the one shared
/// `PgPool` every Postgres-backed server store receives in place of the
/// per-store `sqlite3*` handle (ADR-0008 "Connection model"). Generalizes
/// `InstructionDbPool` from one shared handle to a checkout-per-operation,
/// pin-per-transaction set, exploiting Postgres's real concurrency (the
/// per-store `shared_mutex` serialization goes away) while bounding backend
/// processes.
///
/// Usage:
///     PgPool pool{{.conninfo = dsn, .size = 16}};
///     if (!pool.valid()) { ... }            // conninfo failed to parse
///     {
///         auto lease = pool.acquire();      // blocks; empty on shutdown or
///         if (!lease) { ... }               // connection failure
///         PgResult r{PQexec(lease.get(), "SELECT 1")};
///     }                                      // lease returns the conn
///
/// Error surfaces never echo raw DSN fragments: a malformed conninfo is
/// reported as a fixed string (libpq's parse error quotes tokens, which can
/// include credentials — F1 conditions ledger #3 on #1320). Connect errors
/// from a well-formed conninfo pass through `PQerrorMessage`, which names
/// host/port but never the password.
///
/// TLS note for DSN wiring (F1 ledger #4): on Windows libpq verifies
/// `sslmode=verify-ca/verify-full` against `%APPDATA%\postgresql\root.crt`
/// (or the DSN's `sslrootcert=`), NOT the Windows certificate store that
/// `cert_store.cpp` handles — provision the root there when a TLS DSN ships.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <random>
#include <string>

#include <libpq-fe.h>

namespace yuzu::server::pg {

class PgPool {
public:
    /// Optional observability hooks (#1368). Every callback is invoked
    /// WITHOUT the pool's internal lock held, so an implementation may do
    /// real work — but it MUST NOT re-enter the pool (acquire/with_txn/
    /// destroy), which risks self-deadlock, and SHOULD NOT throw
    /// (`on_unhealthy_discard` fires from a noexcept context, where a throw
    /// is swallowed). The server wires these to its Prometheus registry; the
    /// default — every hook empty — is a zero-overhead no-op. Connection
    /// in_use/open/size are polled gauges via the accessors below, not hooks.
    struct Observer {
        /// A fresh connection attempt failed (feeds a connect-failure counter).
        std::function<void()> on_connect_failure;
        /// `try_acquire_for` gave up at its deadline (acquire-timeout counter).
        std::function<void()> on_acquire_timeout;
        /// A returned connection was discarded as unhealthy (discard counter).
        std::function<void()> on_unhealthy_discard;
        /// Wall time a successful `acquire`/`try_acquire_for` spent waiting,
        /// in seconds (the acquire-wait histogram — the leading saturation
        /// indicator). Observed on every successful checkout, including the
        /// zero-wait idle-hit fast path.
        std::function<void(double)> on_acquire_wait_seconds;
    };

    struct Options {
        /// Connection string — keyword/value or URI form, as accepted by
        /// `PQconnectdb`.
        std::string conninfo;
        /// Maximum simultaneously open connections (= max Postgres backend
        /// processes this pool can consume). Connections are opened lazily
        /// on demand and never reaped, so the steady-state backend count
        /// equals the historical peak concurrency, not `size`. 0 is
        /// clamped to 1.
        std::size_t size = 16;
        /// Applied to every connection attempt unless the conninfo already
        /// carries its own `connect_timeout`. libpq has NO client-side
        /// timeout by default — without this a black-holed host wedges the
        /// acquiring thread indefinitely.
        int connect_timeout_s = 10;
        /// Server-side per-statement timeout (ms), injected as a startup GUC
        /// (`-c statement_timeout=`) via the `options` keyword unless the
        /// conninfo sets its own `options`. Bounds a wedged query — including
        /// the `PgTxn`-dtor ROLLBACK on a half-open connection. 0 disables
        /// (libpq default = no timeout). (#1368 UP-2/4)
        int statement_timeout_ms = 30000;
        /// Server-side lock-acquisition timeout (ms), injected the same way.
        /// Bounds the migration-runner advisory-lock wait so a wedged
        /// lock-holder fails the boot closed instead of hanging forever — the
        /// runner inherits this from its pooled lease. 0 disables. (#1368 CH-10)
        int lock_timeout_ms = 10000;
        /// TCP keepalive idle (s), injected as `keepalives=1 keepalives_idle=`
        /// unless the conninfo sets `keepalives`. Surfaces a silently-dropped
        /// connection (NAT/firewall reap) as a failed statement instead of an
        /// indefinite hang. 0 leaves libpq defaults.
        int keepalives_idle_s = 30;
        /// TCP_USER_TIMEOUT (ms, libpq 12+ — a no-op where the platform lacks
        /// the socket option, e.g. macOS). Linux support is confirmed against
        /// this project's vendored libpq (`fe-connect.c` sets `TCP_USER_TIMEOUT`
        /// under `__linux__`). **Windows is unconfirmed, not confirmed
        /// unsupported** — Gate 3 review (#2703) produced disagreeing reads
        /// of libpq's own Windows conditional compilation and neither could be
        /// fully settled from available evidence; treat it as a documented
        /// open question rather than an established fact either way until
        /// someone verifies against a live Windows build. Injected as
        /// `tcp_user_timeout=`
        /// unless the conninfo sets its own. Distinct from keepalives_idle
        /// above: keepalives only start probing once the connection goes
        /// IDLE (no traffic either direction) and, with `keepalives_interval`/
        /// `keepalives_count` left at OS defaults, total detection can run to
        /// several minutes; this bounds how long UNACKNOWLEDGED data (e.g. a
        /// query already sent, awaiting a reply that a dead network path will
        /// never deliver) may sit before the OS gives up, independent of any
        /// keepalive cycle. Does NOT race statement_timeout on a live
        /// connection — TCP ACKs happen at the transport layer regardless of
        /// how long the server takes to produce a response, so this only
        /// fires on a genuinely dark path, never on an alive-but-slow query.
        /// 0 leaves libpq defaults (unbounded).
        int tcp_user_timeout_ms = 10000;
        /// Connect-failure circuit breaker (#1368 cheap-idle): after a failed
        /// connect, suppress further connect attempts for an
        /// exponentially-growing window (`base × 2^(failures-1)`, capped, with
        /// ±25% jitter) so a down database is not hammered by `size`
        /// simultaneous `connect_timeout_s` connects on every retry. During
        /// the window `acquire()` fails fast with an empty lease; a returned
        /// healthy idle connection is still served immediately (recovery is
        /// not blocked). A successful connect resets the breaker.
        std::chrono::milliseconds connect_backoff_base{200};
        std::chrono::milliseconds connect_backoff_cap{5000};
        /// Fast-fail-on-saturation ceiling for a bounded acquire (#2146 gov
        /// sre finding `up-2146-a2r1-httplib-worker-cascade`). Checked ONCE,
        /// at entry, inside `try_acquire_for`/`with_txn_for` (never the
        /// unbounded `acquire()`/`with_txn()`): if the pool is ALREADY
        /// saturated at that instant (no idle connection, no spare capacity
        /// to open a new one -- exactly the condition under which the
        /// acquire loop would otherwise block a caller), the wait is clamped
        /// to `min(caller's own timeout, this value)`, so a caller that
        /// arrives after saturation gets its degrade response back quickly
        /// rather than pinning its thread (often an httplib worker for a
        /// REST route, but any caller of a bounded acquire) for the full
        /// timeout waiting on a connection that is very unlikely to free up
        /// in time anyway. A caller that arrives BEFORE
        /// saturation is unaffected -- this never shortens a wait that would
        /// otherwise have succeeded quickly.
        ///
        /// Default 500ms, not a smaller "near-zero" value, DELIBERATELY:
        /// this is a SHARED chokepoint every bounded acquire in the codebase
        /// goes through, and several callers already pick a short timeout on
        /// purpose for reasons unrelated to this finding -- most notably
        /// `auth_db.cpp`'s `#2396` login-resilience retry
        /// (`kAcquireRetryTimeout{150}`), whose own doc comment explains it
        /// is sized to be >= its retry backoff SPECIFICALLY so a retry has
        /// time to catch a just-freed connection, after a prior review
        /// (Gate 4 UP-3) rejected a narrower window for causing false
        /// `StoreBusy` under mere contention. 500ms sits AT OR ABOVE every
        /// deliberately-short acquire/retry timeout already in this codebase
        /// at the time of writing (audited: the largest is
        /// `kCreateAcquireTimeout`/`kIngestAcquireTimeout`/gateway_route_
        /// store's `kWriteTimeout`, all exactly 500ms -- a tie, not a gap) so
        /// this fix only compresses the LONG budgets the finding is actually
        /// about, never an already-tuned short one. Those long budgets span a
        /// wider range than the `kReadTimeout`/`kWriteTimeout` shorthand
        /// above suggests: several stores' own `with_txn_for`/`try_acquire_
        /// for` call sites reach `AuditStore::kReapTimeout{8000}` (the
        /// retention reaper), `LicenseStore::kValidateTimeout{10000}`,
        /// `AppPerfRollup::kRollAcquireTimeout{5000}`, and
        /// `AnalyticsEventStore::kDrainClaimTimeout{5000}` -- up to a 20x
        /// compression at the extreme, not merely 3-8x (#2146 A2-R1 Gate 8
        /// round 4, architect). This clamp is a SHARED chokepoint with no
        /// read/write distinction: it applies identically to security- and
        /// audit-critical WRITE paths sharing this pool (RbacStore, AuditStore,
        /// QuarantineStore, SessionStore, EnginePrincipalStore among them, all
        /// with `kWriteTimeout` well above 500ms) -- a deliberate, uniform
        /// chokepoint-level policy rather than a read-only-scoped one, reviewed
        /// and accepted in Gate 8 round 4 on the basis that a failed
        /// `with_txn_for` already means "transaction never began" either way
        /// (no partial-mutation risk is introduced), the only change being the
        /// RATE of that pre-existing failure mode under sustained saturation.
        /// It mirrors `kContainmentReadSlotWait` (server.cpp)'s own reasoning
        /// for the same number: a healthy store's read is milliseconds, so
        /// 500ms is unobservable there, while a stalled one is rejected
        /// quickly instead of pinning a worker.
        std::chrono::milliseconds saturated_fast_fail{500};
        /// Observability hooks; see Observer. All optional.
        Observer observer;
    };

    /// Parses (but does not connect) the conninfo. A parse failure leaves the
    /// pool constructed-but-invalid: `valid()` is false and every `acquire`
    /// returns an empty lease.
    explicit PgPool(Options opts);

    /// Blocks until every outstanding lease has been returned and every
    /// thread blocked in `acquire()` has been woken (they receive empty
    /// leases), then closes all connections. Two caller obligations:
    ///  - a thread that holds a lease MUST NOT destroy the pool — the
    ///    destructor waits for that very lease and self-deadlocks;
    ///  - entering `acquire()` for the first time after the destructor has
    ///    returned is a use-after-destroy like any other.
    ~PgPool();

    PgPool(const PgPool&) = delete;
    PgPool& operator=(const PgPool&) = delete;
    PgPool(PgPool&&) = delete;
    PgPool& operator=(PgPool&&) = delete;

    /// RAII checkout. Returns the connection to the pool on destruction; a
    /// connection that is no longer healthy (or stuck in a transaction the
    /// caller failed to close — the pool rolls it back defensively) is
    /// discarded instead, freeing capacity for a fresh one.
    class Lease {
    public:
        Lease() = default;
        ~Lease() { reset(); }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& o) noexcept : pool_(o.pool_), conn_(o.conn_) {
            o.pool_ = nullptr;
            o.conn_ = nullptr;
        }
        Lease& operator=(Lease&& o) noexcept {
            if (this != &o) {
                reset();
                pool_ = o.pool_;
                conn_ = o.conn_;
                o.pool_ = nullptr;
                o.conn_ = nullptr;
            }
            return *this;
        }

        PGconn* get() const noexcept { return conn_; }
        explicit operator bool() const noexcept { return conn_ != nullptr; }

        /// Return the connection early. Idempotent.
        void reset() noexcept {
            if (pool_ && conn_)
                pool_->release(conn_);
            pool_ = nullptr;
            conn_ = nullptr;
        }

    private:
        friend class PgPool;
        Lease(PgPool* pool, PGconn* conn) noexcept : pool_(pool), conn_(conn) {}

        PgPool* pool_{nullptr};
        PGconn* conn_{nullptr};
    };

    /// Block until a connection is available. Empty lease when the pool is
    /// invalid, shutting down, or a fresh connection attempt failed (the
    /// failure reason is in `last_error()`).
    [[nodiscard]] Lease acquire();

    /// The `connect_timeout` (seconds) this pool adds to a new connection when
    /// the conninfo and PGCONNECT_TIMEOUT set none. The /readyz probe applies the
    /// same default so it gives up on a host exactly when the pool does (HA WS-8).
    [[nodiscard]] int connect_timeout_s() const noexcept { return connect_timeout_s_; }

    /// As `acquire()`, but gives up after `timeout` when the pool is
    /// exhausted and nothing is released in time. Bound caveat: a fresh
    /// connection attempt is only STARTED before the deadline, but once
    /// started it runs to completion -- worst case is roughly
    /// `timeout + connect_timeout_s`.
    ///
    /// Fast-fail-on-saturation (Options::saturated_fast_fail): when the pool
    /// is ALREADY saturated at the moment this is called, the effective wait
    /// is `min(timeout, saturated_fast_fail)`, not the full `timeout` --
    /// see the option's doc comment. A caller depending on the full
    /// `timeout` being honoured under saturation (there should be none --
    /// that is the failure mode this exists to close) needs to know this.
    [[nodiscard]] Lease try_acquire_for(std::chrono::milliseconds timeout);

    /// Pin one connection for a transaction: BEGIN, run `fn`, COMMIT when it
    /// returns true, ROLLBACK when it returns false or throws (the exception
    /// propagates). Returns false on acquire/BEGIN/COMMIT failure or when
    /// `fn` returned false.
    ///
    /// Store-contract notes (PR-3 consumers):
    ///  - Reserve with_txn for multi-statement atomic units. A
    ///    single-statement operation (e.g. the heartbeat
    ///    `INSERT ... ON CONFLICT ... RETURNING`) should run on a plain
    ///    `acquire()` lease under autocommit — with_txn would triple its
    ///    round-trips (BEGIN/COMMIT).
    ///  - Nesting with_txn (calling it from inside `fn`) acquires a SECOND
    ///    connection: it deadlocks a size-1 pool and is rarely what you
    ///    want — restructure instead.
    ///  - A connection severed while idle (NAT/firewall reap) surfaces as a
    ///    failed first statement; the pool discards it on release. Stores
    ///    should treat one connection-level retry as routine.
    bool with_txn(const std::function<bool(PGconn*)>& fn);

    /// As `with_txn`, but the connection is acquired with a bounded deadline
    /// (`try_acquire_for`) instead of the blocking `acquire()`. Returns false if
    /// no connection is available within `timeout`. Hot-path transactional
    /// writes (e.g. the inventory full-payload replace) MUST use this so a
    /// saturated pool — e.g. a fleet-wide need_full storm — cannot block a gRPC
    /// worker indefinitely (ADR-0012 bounded-acquire discipline; gov UP-3).
    /// Inherits `try_acquire_for`'s fast-fail-on-saturation clamp
    /// (Options::saturated_fast_fail) since it acquires through that call.
    bool with_txn_for(std::chrono::milliseconds timeout,
                      const std::function<bool(PGconn*)>& fn);

    /// As `with_txn`/`with_txn_for`, but the caller supplies an ALREADY-ACQUIRED lease
    /// instead of this call doing its own acquire. Exists so a caller can tell apart "the
    /// connection was never acquired, nothing ambiguous" from "a connection was held and the
    /// transaction itself reported failure" — the two `with_txn*` overloads collapse both into
    /// one `false`, which is fine for callers that only need to know success/failure, but is
    /// NOT safe for a caller whose failure-handling includes a DESTRUCTIVE step (e.g. undoing
    /// prior side effects): a lost COMMIT response after Postgres actually committed reports
    /// `false` here exactly like a genuine rollback does, and destructive failure-handling built
    /// on the WRONG assumption ("false always means nothing landed") can delete data that is
    /// actually there (gov Gate 5 CHAOS-1, #3481 — `ProductPackStore::install`'s compensating
    /// rollback is the first consumer: acquire via `try_acquire_for` first, and only treat a
    /// subsequent `with_txn_on` failure as "safe to compensate" after CONFIRMING via
    /// `pg_xact_status()` (see `ProductPackStore::check_transaction_outcome`) — NOT via a
    /// fresh row-existence read, which CHAOS-1b (gov Gate 8) found is itself unreliable: the
    /// client-observed connection failure that triggers this check is not ordered relative to
    /// the backend's own commit progress, so row-absence can mean "aborted" OR "not yet
    /// committed" — the exact ambiguity this whole mechanism exists to resolve).
    ///
    /// Gov Gate 8 review (architect): unlike `with_txn_for`, the bounded-acquire discipline
    /// (ADR-0012 §2a) is NOT baked into this call — it depends entirely on the CALLER acquiring
    /// via `try_acquire_for` immediately beforehand, with nothing in between. Three rules for
    /// any new caller: (1) acquire the lease via `try_acquire_for`, never the blocking
    /// `acquire()` — this call has no timeout of its own to fall back on; (2) do NOTHING between
    /// the acquire and this call — no I/O, no other store call, nothing that could block or run
    /// its own transaction on the same lease first (a nested `BEGIN` on a connection already
    /// mid-transaction only WARNs and silently continues the EXISTING transaction — this call's
    /// COMMIT would then sweep in whatever was left uncommitted); (3) never reuse `lease` after
    /// passing it here — it is consumed by value and MUST be a connection this call alone owns
    /// for its lifetime.
    bool with_txn_on(Lease lease, const std::function<bool(PGconn*)>& fn);

    /// False when the conninfo failed to parse at construction.
    [[nodiscard]] bool valid() const noexcept { return valid_; }

    /// Last acquire/connect failure, sanitized (never raw DSN fragments).
    [[nodiscard]] std::string last_error() const;

    /// Configured capacity.
    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    /// Connections currently leased out (PR-3 Prometheus gauge feed).
    [[nodiscard]] std::size_t in_use() const;

    /// Connections currently open (leased + idle).
    [[nodiscard]] std::size_t open() const;

    /// Threads currently blocked in acquire() waiting for a lease — the
    /// saturation depth that fills the gap between "all leased" and a /readyz
    /// flip (gov sre).
    [[nodiscard]] std::size_t waiters() const;

    /// True while the connect-failure breaker is suppressing new connects.
    /// A cheap, NON-lease-consuming health signal for readiness probes: armed
    /// ⇒ the database is unreachable (recent connect failures). Pool
    /// saturation alone — all leases out but no connect failures — does NOT
    /// arm the breaker, so this never false-trips under load, which a
    /// lease-consuming probe would (gov UP-2).
    [[nodiscard]] bool connect_breaker_open() const;

private:
    // Shared BEGIN/run/COMMIT-or-ROLLBACK body for with_txn / with_txn_for, so
    // the PQTRANS_INERROR commit-guard lives in exactly one place.
    bool run_in_txn(Lease lease, const std::function<bool(PGconn*)>& fn);
    void release(PGconn* conn) noexcept;
    Lease acquire_internal(const std::chrono::steady_clock::time_point* deadline);
    /// Connect with the pool's effective parameters. Called WITHOUT the lock
    /// held (connects can take seconds). Returns nullptr on failure and
    /// stores the reason via `set_error`.
    PGconn* connect_one();
    void set_error(std::string msg);
    /// Arm the connect-failure breaker after a failed connect. Caller holds
    /// `mu_`; grows the suppression window exponentially with ±jitter.
    void arm_connect_backoff_locked();

    std::string conninfo_;
    std::size_t size_{16};
    int connect_timeout_s_{10};
    int statement_timeout_ms_{30000};
    int lock_timeout_ms_{10000};
    int keepalives_idle_s_{30};
    int tcp_user_timeout_ms_{10000};
    bool valid_{false};
    bool conninfo_has_timeout_{false};
    bool conninfo_has_options_{false};
    bool conninfo_has_keepalives_{false};
    bool conninfo_has_tcp_user_timeout_{false};
    std::chrono::milliseconds saturated_fast_fail_{500};
    Observer observer_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<PGconn*> idle_;
    std::size_t open_{0};       ///< established connections (leased + idle)
    std::size_t leased_{0};     ///< checked out right now
    std::size_t connecting_{0}; ///< reserved capacity, connect in flight
    std::size_t waiters_{0};    ///< threads blocked inside acquire's wait
    bool shutdown_{false};
    std::string last_error_;

    // Connect-failure circuit breaker (guarded by mu_). connect_blocked_until_
    // is the steady-clock instant before which no new connect is attempted.
    std::chrono::milliseconds backoff_base_{200};
    std::chrono::milliseconds backoff_cap_{5000};
    std::size_t connect_failures_{0};
    std::chrono::steady_clock::time_point connect_blocked_until_{};
    /// Backoff jitter only (not crypto). Seeded from random_device so a fleet
    /// of instances started together decorrelate their reconnect jitter — a
    /// fixed seed gives every instance the identical sequence (gov fjarvis L1).
    std::minstd_rand jitter_rng_{std::random_device{}()};
};

} // namespace yuzu::server::pg
