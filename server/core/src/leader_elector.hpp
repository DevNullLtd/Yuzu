#pragma once

/// @file leader_elector.hpp
/// WS-3 (ADR-2002 §3/§6/§10): a FENCED, Postgres-backed leader elector — the
/// coordination primitive that lets exactly one core replica run the singleton
/// background loops (schedule tick, policy remediation, reconcilers) once a
/// second replica is enabled. This file is the PRIMITIVE only (slice 3.1); no
/// loop gates on it yet, so building this changes no runtime behaviour.
///
/// THE FENCING MODEL (read before touching this — it is the whole point).
/// A Postgres *session* advisory lock gives mutual exclusion only while its
/// owning connection lives; it says NOTHING about a *paused* former leader
/// resuming work after the lock silently moved to a new backend (network blip,
/// primary failover). So leadership is NOT proven by "I hold the lock" — it is
/// proven by a **monotonically-increasing epoch**:
///
///   * On each successful acquire, the elector mints a fresh epoch from a
///     Postgres SEQUENCE (`leader_epoch_seq`) and records it as
///     `leader_state.current_leader_epoch` — done ON the lock-owning
///     connection, so mutual exclusion guarantees only the true holder writes
///     it, and each new leader's epoch is strictly greater than any prior one.
///   * Every LEADER-DRIVEN side-effecting claim (the slice-3.3 command outbox,
///     on an ORDINARY pooled connection) embeds the `epoch_fence_sql()` predicate
///     (`current_leader_epoch == expected_epoch`) INTO its claim's WRITE
///     statement, so the epoch is verified ATOMICALLY with the side effect. A
///     stale ex-leader's cached epoch is < the current one, so the guarded write
///     admits zero rows even in the window before it notices its lock dropped.
///     THIS is the correctness guarantee. There is deliberately NO standalone
///     boolean fence read: a check-then-act read (`if (current) { claim(); }`)
///     races a handover between the read and the claim commit.
///
/// `is_leader()` gates only WHETHER TO ATTEMPT work; the `epoch_fence_sql()`
/// predicate embedded in the claim's write is what makes a stale leader's write
/// fail. A boolean "I am leader" cached and trusted OUTSIDE the lock connection
/// is PROHIBITED (ADR-2002 §6) — it is exactly the paused-ex-leader hazard the
/// epoch closes.
///
/// TWO DISPATCH PLANES (ADR-2002 Decision 1, plan §1a). The epoch fence gates
/// LEADER-DRIVEN BACKGROUND dispatch ONLY. Operator-triggered SYNCHRONOUS
/// dispatch (e.g. `PolicyEvaluator::remediate`/`evaluate_now`, REST handlers)
/// runs on whichever active-active replica received the request — frequently a
/// non-leader — and MUST NOT be epoch-fenced or it regresses the active-active
/// operator plane. Those paths are arbitrated by their own per-occurrence
/// durable CAS, never by this epoch. Do not embed `epoch_fence_sql()` on an
/// operator-synchronous path.
///
/// CONNECTION OWNERSHIP (ADR-2002 §10). The elector owns ONE dedicated,
/// never-recycled, lifetime-owned libpq connection — NOT a `pg_pool`
/// checkout-per-op lease (a recycled connection would drop the session lock).
/// A transaction-mode pooler must not front it (it breaks backend affinity for
/// session advisory locks). HAProxy-to-primary (WS-7) preserves affinity and is
/// compatible. `epoch_fence_sql()` is a pure string builder (no connection); the
/// SQL it returns is the one part of the fence that executes on a CALLER's
/// pooled connection, inside the caller's own claim statement.

#include "pg/pg_migration_runner.hpp"
#include "pg/pg_raii.hpp"
#include "pg/pg_session_advisory_lock.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The single coordination store/schema this primitive owns. Also the Postgres
/// schema name (see `pg::PgMigrationRunner::valid_store_name`).
inline constexpr const char* kLeaderElectorStore = "leader_elector";

/// The one leadership key slice 3.1 ships (plan OQ1: a single "server
/// background leader"; per-family leadership is deliberately NOT built).
inline constexpr const char* kServerBackgroundLeaderLock = "server_background_leader";

class LeaderElector {
public:
    struct Config {
        std::string dsn;       ///< DSN for the dedicated coordination connection.
        std::string holder_id; ///< This process's identity (e.g. a boot-time random hex).
        /// The logical leadership key. Validated to `[a-z][a-z0-9_]{0,47}`;
        /// an invalid value leaves the elector permanently non-open (fail-closed).
        std::string lock_name = kServerBackgroundLeaderLock;
    };

    explicit LeaderElector(Config cfg);
    ~LeaderElector();
    LeaderElector(const LeaderElector&) = delete;
    LeaderElector& operator=(const LeaderElector&) = delete;

    /// True iff the dedicated connection is live and the schema migrated. A
    /// non-open elector never becomes leader (every `try_acquire` returns false).
    [[nodiscard]] bool is_open() const;

    /// Attempt to acquire leadership on the owned connection. On a fresh
    /// acquisition, mints a new epoch and records it in `leader_state`; caches
    /// it. If already leader, re-verifies liveness (a cheap heartbeat) and keeps
    /// the existing epoch. Returns true iff this process now leads.
    [[nodiscard]] bool try_acquire();

    /// True iff we currently believe we hold the lock (last liveness check OK).
    /// NEVER the sole basis for a side effect — see the fencing model above.
    ///
    /// LOCK-FREE (slice 3.2, #4013): reads a published atomic, NOT `mu_`. The
    /// election loop (the sole writer) holds `mu_` across its blocking libpq
    /// probe; if this reader also took `mu_`, a half-open backend would stall
    /// every worker tick asking "may I run?" for the OS TCP timeout. The loop
    /// publishes leadership through the atomic so a stalled probe can never block
    /// a reader. A momentarily-stale `true` here is acceptable BY DESIGN — this is
    /// the attempt gate, and the epoch fence in a leader-driven claim's WRITE
    /// (slice 3.3's command outbox) is the correctness guarantee that rejects a
    /// stale ex-leader. Operator-synchronous claims (slice 3.4's remediation) are
    /// arbitrated by their own plain guarded CAS, never this epoch (see below).
    [[nodiscard]] bool is_leader() const;

    /// The epoch stamped at our last successful acquire; `nullopt` if not leader.
    /// LOCK-FREE, same published-atomic channel and rationale as `is_leader()`.
    [[nodiscard]] std::optional<std::int64_t> epoch() const;

    /// Liveness heartbeat on the owned connection. On failure, drops leadership
    /// (so a later `try_acquire` re-acquires with a strictly higher epoch) and
    /// reconnects the dedicated connection best-effort. Returns `is_leader()`
    /// after the check. This is an AVAILABILITY mechanism (libpq does not surface
    /// a silently-dropped backend on an idle connection) — NOT the correctness
    /// guarantee, which is the epoch predicate in the claim txn.
    bool heartbeat();

    /// Voluntarily release leadership (unlock + clear the cached epoch). Safe to
    /// call when not leader. Leaves the connection open.
    void resign();

    /// THE FENCE, as an SQL boolean expression to EMBED in a side-effecting
    /// claim's WRITE statement (its `WHERE`/guard). Returns SQL of the form:
    ///   ((SELECT current_leader_epoch FROM leader_elector.leader_state
    ///       WHERE lock_key = '<lock_name>') = <epoch>)
    ///
    /// WHY A PREDICATE, NOT A BOOLEAN READ. ADR-2002 §3 requires the epoch check
    /// to run "in the SAME TRANSACTION as the claim" — and, more strongly, it
    /// must be indivisible from the claim's WRITE. A standalone boolean read
    /// (`if (is_current) { claim(); }`) is a check-then-act race: a successor can
    /// advance the epoch in the window between the read returning true and the
    /// claim committing, so a stale ex-leader commits anyway. This primitive
    /// therefore deliberately ships NO standalone boolean fence. The claim site
    /// (slice 3.3) MUST compose this fragment into the writing statement, e.g.
    ///   UPDATE claims SET ... WHERE claim_id = $1 AND <epoch_fence_sql(...)>
    /// so the epoch is verified atomically with the write; a row count of zero
    /// then means "fenced out", and a paused ex-leader cannot commit.
    ///
    /// Use ONLY on leader-driven background claims, never on an operator-
    /// synchronous path (see the two-dispatch-planes note above).
    ///
    /// ISOLATION CONTRACT (the claim-side wiring, slice 3.3, MUST honour this —
    /// embedding the predicate is necessary but NOT sufficient on its own). The
    /// predicate is a scalar subquery over `leader_state`, so it reads under the
    /// claim statement's TRANSACTION SNAPSHOT. Run the guarded write in a
    /// READ COMMITTED transaction, or as the FIRST data statement of its
    /// transaction — never after an earlier statement in a REPEATABLE READ /
    /// SERIALIZABLE transaction, whose snapshot was taken before a concurrent
    /// handover committed. A snapshot predating the handover reads the
    /// pre-handover epoch and would ADMIT a stale ex-leader's claim even though
    /// the check is in the same statement as the write. The primitive cannot
    /// enforce the caller's isolation level, so the claim site owns this. (A
    /// residual in-flight window — the handover committing after this statement's
    /// snapshot is taken — is narrow and is bounded by §6 effectively-once; if a
    /// claim requires strict exclusion it must add `FOR KEY SHARE` on the fence
    /// row or stamp the epoch into the claim row under a constraint.)
    ///
    /// SAFE TO INLINE: `lock_name` is validated to `[a-z][a-z0-9_]{0,47}` and
    /// `epoch` is an integer, so both are rendered as SQL literals — this lets
    /// the caller splice the fragment into a larger statement without colliding
    /// with its own `$N` placeholders. FAIL-CLOSED: an invalid `lock_name`
    /// returns the constant-false predicate `(1=0)`, which fences everything out
    /// rather than admitting a claim.
    [[nodiscard]] static std::string epoch_fence_sql(const std::string& lock_name,
                                                     std::int64_t epoch);

    /// The schema migrations for this store (version 1: `leader_epoch_seq` +
    /// `leader_state`). Exposed for tests and for the migration ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    bool connect_locked();          ///< (Re)establish the dedicated connection + run migrations.
    void drop_leadership_locked();  ///< Release the lock guard and clear the cached epoch.

    Config cfg_;
    bool name_valid_ = false;                 ///< cfg_.lock_name passed validation.
    pg::PgAdvisoryLockKey lock_key_;          ///< Derived from cfg_.lock_name.

    mutable std::mutex mu_;
    pg::PgConn conn_;                          ///< Dedicated, never-recycled (declared BEFORE the guard).
    std::optional<pg::PgSessionAdvisoryLockGuard> lock_guard_; ///< Held only while leader.
    std::optional<std::int64_t> epoch_;        ///< Epoch of the current leadership, if any (writer state, under mu_).
    bool open_ = false;

    /// Lock-free publish channel for `is_leader()`/`epoch()` (slice 3.2, #4013):
    /// `0` = not leader; `>= 1` = leader at that epoch (minted epochs start at 1,
    /// so `0` is an unambiguous sentinel). The election loop stores this under
    /// `mu_` whenever `epoch_` changes (acquire → the minted epoch; drop → 0),
    /// release-ordered; readers load it with acquire and never touch `mu_`, so a
    /// libpq probe stalled under `mu_` cannot block a worker tick's leadership
    /// read. `epoch_` above stays the writer's authoritative state under `mu_`.
    std::atomic<std::int64_t> live_epoch_{0};
};

} // namespace yuzu::server
