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

#include <array>
#include <atomic>
#include <cstddef>
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

/// WS-11 (#4014): the CLOSED sets of causes the elector counts, with their
/// exported label values. These arrays are the single source of truth for the
/// `cause` label of `yuzu_server_leader_acquire_failures_total` /
/// `yuzu_server_leader_lost_total` (`leader_metrics.hpp` seeds and publishes
/// from them), so a count site, the exporter and the docs cannot drift.
///
/// An acquire FAILURE is an infrastructure fault. The normal follower outcome
/// -- another replica holds the advisory lock (try-lock answered 'f') -- is
/// DELIBERATELY not a failure and has no cause here.
enum class AcquireFailure : std::size_t {
    Connect = 0,     ///< No usable dedicated connection (open failed / fail-closed config).
    LockQuery,       ///< The try-lock QUERY itself failed (transport error, not 't'/'f').
    LockGuard,       ///< Lock granted but the release guard could not be constructed.
    EpochRecord,     ///< Lock granted but the epoch could not be minted/recorded/parsed.
};
inline constexpr std::size_t kAcquireFailureCount = 4;
inline constexpr std::array<const char*, kAcquireFailureCount> kAcquireFailureLabels = {
    "connect", "lock_query", "lock_guard", "epoch_record"};

/// Why leadership that WAS held was dropped. A failed heartbeat always drops
/// leadership, so `LivenessFailed` is also the heartbeat-failure count.
enum class LeadershipLoss : std::size_t {
    LivenessFailed = 0, ///< The heartbeat / already-leader `SELECT 1` failed.
    Resigned,           ///< Voluntary `resign()` while leading.
};
inline constexpr std::size_t kLeadershipLossCount = 2;
inline constexpr std::array<const char*, kLeadershipLossCount> kLeadershipLossLabels = {
    "liveness_failed", "resigned"};

// A hand-written count and a hand-written label list can drift apart: a brace
// list shorter than its std::array leaves the tail slots nullptr, which would
// become `std::string(nullptr)` when the exporter builds the `cause` label at
// boot. Tie the counts to the last enumerator and require every label present.
namespace leader_label_detail {
template <std::size_t N>
constexpr bool all_labels_present(const std::array<const char*, N>& labels) {
    for (const char* label : labels)
        if (label == nullptr || label[0] == '\0')
            return false;
    return true;
}
} // namespace leader_label_detail
static_assert(static_cast<std::size_t>(AcquireFailure::EpochRecord) + 1 == kAcquireFailureCount,
              "kAcquireFailureCount must equal the number of AcquireFailure enumerators");
static_assert(static_cast<std::size_t>(LeadershipLoss::Resigned) + 1 == kLeadershipLossCount,
              "kLeadershipLossCount must equal the number of LeadershipLoss enumerators");
static_assert(leader_label_detail::all_labels_present(kAcquireFailureLabels),
              "every AcquireFailure needs a non-empty exported label");
static_assert(leader_label_detail::all_labels_present(kLeadershipLossLabels),
              "every LeadershipLoss needs a non-empty exported label");

class LeaderElector {
public:
    /// A point-in-time copy of the elector's observability state (WS-11, #4014).
    /// Plain values: a consumer holds no reference to the elector, so it cannot
    /// reach a `mu_`-taking accessor (`is_open()`) from a scrape path.
    struct Stats {
        bool leader = false;
        std::int64_t epoch = 0;         ///< Epoch this process leads at; 0 when not leading.
        std::uint64_t acquired = 0;     ///< Leadership acquisitions by this process.
        std::array<std::uint64_t, kAcquireFailureCount> acquire_failed{}; ///< By AcquireFailure.
        std::array<std::uint64_t, kLeadershipLossCount> lost{};           ///< By LeadershipLoss.
        /// `steady_clock` nanoseconds (since its epoch) of the last query the
        /// dedicated connection answered successfully; 0 = never.
        std::int64_t last_ok_steady_ns = 0;
    };

    /// Monotonic "now" in the units and clock of `Stats::last_ok_steady_ns` (never
    /// 0: 0 is that field's "never answered" sentinel). The ONE place the elector
    /// stamps and a scrape-time age computation read the clock, so they cannot
    /// disagree on the clock or the unit.
    [[nodiscard]] static std::int64_t steady_now_ns() noexcept;

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

    /// WS-11 (#4014): a lock-free snapshot of the observability counters and the
    /// leadership belief. NEVER takes `mu_` (the election loop holds it across
    /// blocking libpq calls; a /metrics scrape must not be able to stall behind
    /// one -- the same rule as `is_leader()`/`epoch()`), so it is safe to call
    /// from a scrape handler. Counters are relaxed atomics: each value is
    /// individually exact, the set is not a single atomic cut (fine for
    /// monotonic counters read by `increase()`).
    ///
    /// `is_leader` here is the replica's BELIEF (the attempt gate), not proof of
    /// leadership: correctness is the epoch fence in a leader-driven claim's
    /// write. `last_ok_steady_ns` is what makes a stale belief visible -- it stops
    /// advancing when the dedicated connection stops answering.
    [[nodiscard]] Stats stats() const noexcept;

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
    /// claim requires strict exclusion it must add `FOR SHARE` on the fence
    /// row (`FOR KEY SHARE` would NOT block the elector's non-key epoch update) or stamp
    /// the epoch into the claim row under a constraint.)
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
    /// Release the lock guard and clear the cached epoch. With a `cause`, counts a
    /// leadership LOSS -- but only if leadership was actually held (`epoch_` set),
    /// so a drop on a follower or in an aborted acquire can never inflate it.
    void drop_leadership_locked(std::optional<LeadershipLoss> cause = std::nullopt);
    void note_ok_locked() noexcept;  ///< Stamp "the connection just answered a query".

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

    // WS-11 (#4014) observability counters. Written only under `mu_` (plain
    // fetch_add, no new locking), read lock-free by `stats()`.
    std::atomic<std::uint64_t> acquired_{0};
    std::array<std::atomic<std::uint64_t>, kAcquireFailureCount> acquire_failed_{};
    std::array<std::atomic<std::uint64_t>, kLeadershipLossCount> lost_{};
    std::atomic<std::int64_t> last_ok_steady_ns_{0}; ///< 0 = never answered.
};

} // namespace yuzu::server
