#pragma once

/// @file pg_session_advisory_lock.hpp
/// Generic exception-safe RAII release for a SESSION-scoped Postgres
/// advisory lock — lifted out of `kek_op_lock.hpp`'s `KekOpLockGuard` (#2395,
/// governance-hardened) so a second store that needs a session-scoped lock
/// does not hand-roll its own release protocol.
///
/// THE MECHANISM (what every consumer needs to know): a session advisory
/// lock is released by an explicit `pg_advisory_unlock` call — an ORDINARY
/// SQL statement, so it fails at the QUERY level on a connection whose
/// transaction is currently ABORTED, rather than actually releasing the
/// lock. Left there, the lock survives whatever ROLLBACK eventually
/// happens, the connection itself stays `CONNECTION_OK`, and
/// `PgPool::release()` recycles it: that method checks both `PQstatus` AND
/// `PQtransactionStatus` and issues its own defensive `ROLLBACK` when the
/// latter reads non-idle (`pg_pool.cpp`), so it does clear an ABORTED
/// transaction on the way back into the pool — but that rollback runs
/// AFTER this guard's own destructor has already tried and failed to
/// unlock, and it does not retry the unlock itself, so a lock still held at
/// that point outlives the rollback and is handed back to the pool anyway.
/// Session advisory locks are re-entrant per backend, so the wedge is
/// asymmetric: whichever request next draws the poisoned connection
/// succeeds while every other connection is denied indefinitely.
///
/// THE RECOVERY PROTOCOL this guard's destructor runs on an unlock-query
/// failure: (1) if the connection is already dead, nothing leaked — the
/// session, and every lock it held, is gone with it. (2) If the connection
/// is alive and its transaction is ABORTED (the ordinary case above),
/// ROLLBACK (the one statement Postgres accepts in that state) and retry
/// the SAME targeted unlock once — this recovers the ordinary case
/// genuinely, not merely best-effort. (3) Only if that does not apply, or
/// does not work, does it fall back to terminating this backend
/// (`pg_terminate_backend(pg_backend_pid())`) as a LAST resort — itself an
/// ordinary SQL statement with no special exemption from the same failure
/// mode, so this is best-effort, not a hard guarantee, for whatever is left
/// after (1) and (2) do not apply.
///
/// HISTORY (condensed; see #2964 PR history for the full account): an
/// earlier revision hand-rolled its own release with a false claim that
/// `pg_advisory_unlock_all()` was a working "fallback" (it fails
/// identically to the targeted unlock in the aborted-transaction case);
/// a later revision fixed that but then fell straight to
/// `pg_terminate_backend` on any live-connection failure with an
/// overclaimed "correct by construction" comment — also false, since that
/// terminate call fails the same way on an aborted transaction. THIS
/// revision is the first to actually recover the aborted-transaction case
/// (step (2) above) rather than merely documenting around it. The T12
/// rotation-sweep call site (`api_token_store.cpp`) is additionally safe
/// against this specific failure mode by an UNRELATED, unpinned mechanism —
/// its unlock guard is declared before the `pg::PgTxn` covering its
/// classification transaction, so reverse-destruction-order means
/// `~PgTxn`'s own ROLLBACK always runs first — but that is a property of
/// THAT call site's declaration order, not of this guard, and a THIRD
/// consumer must not assume it gets that property for free.

#include <string>
#include <utility>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

// STL -> third-party -> project (docs/cpp-conventions.md) — this project
// header sits last (#2964 round 3 review finding 6: an earlier revision had
// this inverted).
#include "pg_raii.hpp"

namespace yuzu::server::pg {

/// A SESSION advisory lock's KEY, as the Postgres SQL expression(s) that
/// compute it — generates matching try-lock/unlock SQL from ONE definition
/// (#2964 round 3 review finding 3), so a call site can never hand-write a
/// try-lock and an unlock statement that reference different keys. Before
/// this existed, each of the two consumers (`KekOpLockGuard`,
/// `api_token_store.cpp`'s rotation-sweep lock) hand-wrote its own matched
/// pair of SQL string constants; a drift between them unlocks a key this
/// session never locked, Postgres returns `false` (a legitimate result for
/// "not held"), and the guard's destructor treats that as released — a
/// SILENT leak of the key actually held, indistinguishable from the benign
/// release-if-held case.
///
/// Two forms, matching the two this codebase's session locks use today:
///   * `single(key_sql)` — one bigint key expression, e.g.
///     `"hashtextextended('api_token_store:rotation_sweep', 0)"`.
///   * `pair(classid_sql, objid_sql)` — two int32 key expressions, e.g.
///     `"2037545589"` and `"hashtext('secrets_kek_op')"`.
///
/// Each argument is a full SQL EXPRESSION, not a literal value — every
/// existing call site's key is (at least in part) computed by Postgres
/// itself (`hashtext`/`hashtextextended`), never reproduced in C++, so this
/// stores the expression text rather than a resolved integer.
class PgAdvisoryLockKey {
public:
    [[nodiscard]] static PgAdvisoryLockKey single(std::string key_sql) {
        return PgAdvisoryLockKey(std::move(key_sql), std::string(), /*is_pair=*/false);
    }
    [[nodiscard]] static PgAdvisoryLockKey pair(std::string classid_sql, std::string objid_sql) {
        return PgAdvisoryLockKey(std::move(classid_sql), std::move(objid_sql), /*is_pair=*/true);
    }

    [[nodiscard]] std::string try_lock_sql() const {
        return is_pair_ ? "SELECT pg_try_advisory_lock(" + first_ + ", " + second_ + ")"
                        : "SELECT pg_try_advisory_lock(" + first_ + ")";
    }
    [[nodiscard]] std::string unlock_sql() const {
        return is_pair_ ? "SELECT pg_advisory_unlock(" + first_ + ", " + second_ + ")"
                        : "SELECT pg_advisory_unlock(" + first_ + ")";
    }

private:
    // Private, taking the discriminator explicitly rather than inferring it
    // from `second.empty()` — a `pair()` caller could (however implausibly)
    // hand a key expression that happens to be an empty string, and that
    // must still generate the two-argument form. Only the two named
    // factories above construct this type.
    PgAdvisoryLockKey(std::string first, std::string second, bool is_pair)
        : first_(std::move(first)), second_(std::move(second)), is_pair_(is_pair) {}

    std::string first_;
    std::string second_;
    bool is_pair_;
};

/// Construct only after the caller has confirmed the lock was actually
/// granted (e.g. a `pg_try_advisory_lock`/`pg_advisory_lock` call that
/// returned true) — OR, defensively, when the caller could not tell whether
/// it was granted (a failed try-lock probe) and wants to release-if-held
/// rather than risk leaving a silently-granted lock on the connection. In
/// the latter case, releasing a lock this session never held is a harmless
/// no-op (Postgres reports `false`, which this guard treats the same as
/// "released" — see the destructor).
///
/// Declare this guard AFTER the pool `Lease`/connection in the same scope so
/// it destructs (releases) BEFORE the lease returns the connection to the
/// pool — a session-scoped advisory lock outlives the statement/transaction
/// that took it, so releasing it here is not optional cleanup, it is the
/// only way to unlock at all.
class PgSessionAdvisoryLockGuard {
public:
    /// `key` — the SAME `PgAdvisoryLockKey` the caller used to build its
    /// try-lock statement (`key.try_lock_sql()`); this guard derives its own
    /// unlock statement from it (`key.unlock_sql()`) so the two can never
    /// reference different keys (#2964 round 3 review finding 3). `label` is
    /// a short, human-readable name for this lock (e.g. `"KEK op"`,
    /// `"api_token_store rotation sweep"`) used to prefix every log line this
    /// guard emits, so a caller can tell which lock family is misbehaving
    /// without inspecting the SQL string.
    ///
    /// Deliberately NOT `noexcept` (#2964 round 3 review, item 6):
    /// `key.unlock_sql()` builds a fresh, heap-allocated string on every
    /// call (it concatenates the key expression text — never a static
    /// literal, since every existing key is at least partly computed by
    /// Postgres itself), so this mem-initializer can throw `bad_alloc`. A
    /// `noexcept` here would turn that into `std::terminate` instead of an
    /// ordinary propagating exception; the two call sites already tolerate a
    /// throwing constructor (neither constructs this guard in a context that
    /// requires `noexcept`).
    PgSessionAdvisoryLockGuard(PGconn* conn, const PgAdvisoryLockKey& key, std::string label)
        : conn_(conn), unlock_sql_(key.unlock_sql()), label_(std::move(label)) {}

    ~PgSessionAdvisoryLockGuard() {
        // Implicitly noexcept: a throwing log sink here would std::terminate
        // on the exact path that already signals trouble. Everything below
        // is wrapped.
        try {
            pg::PgResult res{PQexec(conn_, unlock_sql_.c_str())};
            // A successfully-executed unlock query (`res.ok()`, i.e. the
            // QUERY ran, regardless of the boolean value it returned) is
            // never itself the wedge case this guard exists to prevent — a
            // `false` return means "this session did not hold the lock",
            // which is a legitimate benign outcome for the defensive
            // release-if-held case above, not a fault. The actual failure
            // mode reproduced against live Postgres is the query ITSELF
            // failing (aborted-transaction), which `res.ok()` catches.
            if (res.ok())
                return;

            // The unlock QUERY failed. Two very different worlds:
            //
            //  - Connection already dead => the SESSION is gone, and a
            //    session-scoped advisory lock dies with its session. Nothing
            //    leaked; the pool discards the connection on release.
            //  - Connection still HEALTHY => the lock is genuinely still
            //    held (or unknowable — an aborted transaction blocks every
            //    ordinary statement, including the unlock itself), and
            //    `PgPool::release` would hand this connection back to the
            //    pool possibly still holding it. Session advisory locks are
            //    re-entrant per backend, so the wedge is worse than it
            //    looks: whichever request next draws THIS connection
            //    succeeds while every other connection is denied
            //    indefinitely.
            if (PQstatus(conn_) != CONNECTION_OK) {
                spdlog::warn("{}: advisory-lock release failed on an already-dead connection — "
                             "the session (and its locks) are gone; nothing leaked",
                             label_);
                return;
            }

            // Before assuming the lock is unrecoverably wedged, try to
            // actually RECOVER it. The ordinary cause of a live-connection
            // unlock failure is an ABORTED transaction — every statement
            // other than ROLLBACK (or COMMIT, which behaves the same way
            // here) fails identically in that state, INCLUDING the
            // `pg_terminate_backend` call this falls to below. Roll back,
            // then retry the SAME targeted unlock once — measured against
            // live Postgres to take a leak from 1 to 0.
            //
            // Deliberately `== PQTRANS_INERROR`, not `!= PQTRANS_IDLE`: the
            // wider test also matches `PQTRANS_INTRANS` — a HEALTHY
            // uncommitted transaction, not an aborted one — and would roll
            // it back on this guard's say-so, discarding whatever work it
            // held. Unreachable at both of today's call sites (neither
            // constructs this guard mid a live, uncommitted transaction),
            // but a future third consumer must not inherit that assumption
            // silently — narrowed here rather than left to the caller to
            // notice.
            //
            // What narrowing does NOT do, stated because the paragraph above
            // could be read as promising it: an INTRANS connection whose
            // unlock failed still loses its transaction. It falls through to
            // the terminate below, which kills the backend and rolls the
            // transaction back with it. The difference is not that the work
            // survives — it is that the caller finds out, because the
            // connection is marked bad and discarded rather than silently
            // rolled back and handed to the next borrower.
            if (PQtransactionStatus(conn_) == PQTRANS_INERROR) {
                pg::PgResult rollback{PQexec(conn_, "ROLLBACK")};
                if (rollback.ok()) {
                    pg::PgResult retry{PQexec(conn_, unlock_sql_.c_str())};
                    if (retry.ok()) {
                        spdlog::warn("{}: advisory-lock release failed on an aborted "
                                     "transaction — rolled back and the retried unlock "
                                     "succeeded; nothing leaked",
                                     label_);
                        return;
                    }
                }
            }

            // Recovery did not apply (the connection was not in an aborted
            // transaction to begin with) or did not work. Genuinely
            // best-effort from here: terminate our own backend, which
            // releases every session lock it holds and marks the connection
            // bad so `PgPool::release` discards it instead of recycling a
            // poisoned one. This is NOT a guarantee — the terminate
            // statement is itself an ordinary SQL statement and can fail the
            // same way the unlock did if the connection is broken for some
            // other reason — but killing one pooled connection on a
            // best-effort basis is still strictly better than doing nothing.
            //
            // The terminate call runs BEFORE the log line below, never
            // after: this whole destructor is wrapped in `try`/`catch(...)`
            // specifically so a throw here cannot propagate out of a
            // destructor, and a throwing log sink is exactly such a throw —
            // logging first would let that same `catch(...)` silently skip
            // the terminate call, leaving the backend alive and the lock
            // still held, with the guard that exists to make this
            // destructor safe being what disabled its own last-resort
            // release. `err_detail` is captured before the terminate call
            // runs, since `PQerrorMessage` reflects the connection's most
            // recent result and would otherwise report the terminate
            // statement's own outcome instead of the unlock failure this
            // message is about.
            const std::string err_detail = PQerrorMessage(conn_);
            pg::PgResult kill{PQexec(conn_, "SELECT pg_terminate_backend(pg_backend_pid())")};
            (void)kill; // best-effort; the connection is discarded either way
            spdlog::critical("{}: could not release the advisory lock on a live connection: {} "
                             "— terminated this backend on a best-effort basis to try to "
                             "guarantee the lock is released",
                             label_, err_detail);
        } catch (...) {
            // Nothing safe left to do during unwind.
        }
    }

    PgSessionAdvisoryLockGuard(const PgSessionAdvisoryLockGuard&) = delete;
    PgSessionAdvisoryLockGuard& operator=(const PgSessionAdvisoryLockGuard&) = delete;
    PgSessionAdvisoryLockGuard(PgSessionAdvisoryLockGuard&&) = delete;
    PgSessionAdvisoryLockGuard& operator=(PgSessionAdvisoryLockGuard&&) = delete;

private:
    PGconn* conn_;
    std::string unlock_sql_;
    std::string label_;
};

} // namespace yuzu::server::pg
