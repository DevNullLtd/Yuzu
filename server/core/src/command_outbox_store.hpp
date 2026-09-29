#pragma once

/// @file command_outbox_store.hpp
/// WS-3 slice 3.3 (ADR-2002 §6): the durable **transactional command outbox**
/// behind leader-driven background dispatch. A side-effecting background producer
/// commits a `pending` outbound-command row; a leader-gated delivery loop drives
/// `pending → sent`; a crash between the commit and the wire send re-drives from
/// `pending`. The receiver (the agent) dedups on `command_id` (WS-0, durable), so
/// an at-least-once re-drive is **effectively-once**, never exactly-once — a
/// duplicate wire send is absorbed at the endpoint.
///
/// TWO PRODUCER SHAPES — do not conflate them (arch-F2):
///   * `claim_and_enqueue_on(conn, ...)` commits the `pending` row in the SAME
///     transaction as the producer's own state transition (true
///     claim-before-side-effect atomicity) — for a future producer whose state
///     ALSO lives in Postgres and can share a txn.
///   * `claim_and_enqueue(...)` autocommits on its own bounded lease. The FIRST
///     consumer, `ScheduleRunner`, uses THIS: its state transition
///     (`ScheduleEngine::advance_schedule`) is a SEPARATE write, so cross-txn
///     atomicity is impossible. Correctness there rests entirely on the
///     `occurrence_id` PRIMARY KEY being idempotent — a crash-before-advance
///     re-fire recomputes the identical key and reads `AlreadyEnqueued`, so no
///     second occurrence is produced (see `schedule_runner.hpp`). Do NOT assume
///     enqueue and the producer's transition are atomic for that consumer.
///
/// THE TWO STRUCTURAL GUARANTEES (read before touching the SQL — they are the
/// whole point of this store, and an adversarial review of the plan made both
/// load-bearing):
///
///  1. **The occurrence key is a PRIMARY KEY (a UNIQUE constraint).** It — not
///     the epoch fence, not `FOR KEY SHARE` — is the PRIMARY guard against a
///     duplicate occurrence. Two racing leaders (a paused ex-leader that has
///     not yet noticed its lock moved, and the new leader) that both compute
///     the SAME `occurrence_id` for the same logical occurrence will each
///     attempt the enqueue; the second `INSERT ... ON CONFLICT DO NOTHING`
///     commits zero rows. The producer reads that as `AlreadyEnqueued` — an
///     idempotent success, NOT a failure — because the occurrence is durably
///     present exactly once. This closes the residual in-flight epoch-race
///     window (a handover committing after the guarded statement's snapshot)
///     that the epoch fence alone cannot: with the unique key the loser simply
///     no-ops instead of double-inserting.
///
///  2. **The epoch fence is the defense-in-depth ATTEMPT gate.** Every claim
///     (`claim_and_enqueue`, `mark_sent`, `mark_failed`, `reschedule`) embeds
///     `LeaderElector::epoch_fence_sql(lock_name, epoch)` INTO its writing
///     statement, so the leader epoch is verified ATOMICALLY with the write
///     (never a check-then-act boolean read — see the primitive's header). A
///     stale ex-leader's cached epoch is below the current one, so its guarded
///     write admits zero rows. On the single-replica deployment the sole
///     replica is always the leader, so the fence never rejects anything and
///     this store behaves as a plain durable queue.
///
/// ISOLATION CONTRACT (`leader_elector.hpp`, `epoch_fence_sql` doc). The fence
/// is a scalar subquery over `leader_elector.leader_state`, read under the
/// writing statement's transaction snapshot. Every method here runs its
/// guarded write as the FIRST data statement of its transaction (a single
/// autocommit statement, or the first statement inside a `with_txn`), never
/// after an earlier statement in a REPEATABLE READ / SERIALIZABLE transaction
/// whose snapshot predates a concurrent handover. Because guarantee (1) makes
/// the unique key the primary guard, `FOR KEY SHARE` on the fence row is NOT
/// required for the first consumer (`ScheduleRunner`); the fence is belt to the
/// unique key's braces.
///
/// TWO DISPATCH PLANES (ADR-2002 Decision 1). This store is for LEADER-DRIVEN
/// BACKGROUND dispatch ONLY. An operator-triggered SYNCHRONOUS dispatch runs on
/// whichever active-active replica received the request (frequently a
/// non-leader) and is arbitrated by its own per-occurrence durable CAS — it
/// MUST NOT enqueue here with an epoch fence, or it regresses the active-active
/// operator plane.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard. The outbox IS the source
/// of truth for what background dispatch is owed; `list_pending` feeds a
/// dispatch decision, so a degraded read returns a TYPE-DISTINGUISHABLE
/// `unexpected(db_error)`, never a silently-empty vector that reads as "nothing
/// owed" (which would silently drop every scheduled fire).
///
/// This store is a DUMB durable queue: it owns the idempotency key, the epoch
/// fence, the state machine, and the pending index — NOT the encoding of
/// `parameters` / `agent_ids` / `scope_expr`, which are opaque producer-owned
/// strings the delivery consumer round-trips verbatim. Born-on-Postgres
/// (ADR-0009 fresh-start): no legacy SQLite file, no backfill.

// Real header, not a forward-declare — pulls libpq's `PGconn` (needed by
// `claim_and_enqueue_on`) and `pg::PgMigration`, exactly as `leader_elector.hpp`
// does; the same rationale as `pg_migration_runner.hpp`'s own include note.
#include "pg/pg_migration_runner.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Outcome of an epoch-fenced idempotent enqueue.
enum class OutboxEnqueueOutcome {
    Enqueued,        ///< This call committed the `pending` row.
    AlreadyEnqueued, ///< The occurrence was already present (idempotency race
                     ///< won by another attempt/leader) — an idempotent SUCCESS,
                     ///< the producer should advance its own state as if it had
                     ///< enqueued. NEVER a failure.
    FencedOut,       ///< The epoch fence rejected this write (a stale ex-leader).
                     ///< The occurrence is NOT present; the true leader owns it.
    Degraded,        ///< Store not open / lease timeout / query error — the
                     ///< producer MUST fail closed (not advance), so a retry
                     ///< re-attempts the enqueue.
};

/// Typed read failure (ADR-0036 type-distinguishable authoritative read).
enum class CommandOutboxError {
    store_unavailable, ///< not open / pool exhausted — the store cannot answer
    db_error,          ///< a query against an open store failed
};

/// A producer's request to enqueue one outbound command occurrence. All string
/// fields except the keys are opaque to this store (producer/consumer encoding).
struct OutboxEnqueueRequest {
    std::string occurrence_id;  ///< STABLE per-occurrence idempotency key (PK). The
                                ///< producer must derive it deterministically from the
                                ///< occurrence (e.g. schedule_id + occurrence anchor) so
                                ///< two racing leaders compute the identical value.
    std::string command_id;     ///< STABLE wire command id the agent dedups on (WS-0).
    std::string source;         ///< Producing subsystem, e.g. "schedule_runner".
    std::string plugin;
    std::string action;
    std::string scope_expr;     ///< Targeting scope expression (opaque).
    std::string agent_ids;      ///< Explicit target id list, producer-encoded (opaque).
    std::string parameters;     ///< Dispatch parameters, producer-serialized (opaque).
    std::string execution_id;   ///< Executions-ladder correlation id.
    std::string principal;      ///< Arming principal identity — the delivery consumer
                                ///< RE-RESOLVES the caller/authority from this at send
                                ///< time (never a serialized DispatchCaller — that would
                                ///< re-create the #1398 provenance-forgery hazard).
    std::string approval_id;    ///< Non-empty iff this occurrence cleared an approval gate at
                                ///< enqueue time. The delivery consumer stamps
                                ///< `DispatchCaller::approval_provenance = Ticket` from it, so a
                                ///< re-authorized AlwaysApproval/AdminOrApproval action still
                                ///< passes the #1398 ExecuteGate at send time (the approval that
                                ///< admitted it already happened; the caller's *authority* is
                                ///< re-checked fresh, the *approval provenance* is carried).
};

/// A pending occurrence handed to the leader-gated delivery loop.
struct OutboxCommand {
    std::string occurrence_id;
    std::string command_id;
    std::string source;
    std::string plugin;
    std::string action;
    std::string scope_expr;
    std::string agent_ids;
    std::string parameters;
    std::string execution_id;
    std::string principal;
    std::string approval_id; ///< see OutboxEnqueueRequest::approval_id
    int attempts{0};
};

class CommandOutboxStore {
public:
    /// Borrows the shared pool; runs the `command_outbox_store` schema migration
    /// on a pinned construction lease. `is_open()` is false if the lease was
    /// empty or the migration failed (a fatal startup error at the wiring site,
    /// per the PG store playbook §6). Born-on-Postgres: no `migrate_from_sqlite`.
    explicit CommandOutboxStore(pg::PgPool& pool);

    CommandOutboxStore(const CommandOutboxStore&) = delete;
    CommandOutboxStore& operator=(const CommandOutboxStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for degrade counters (set-before-traffic).
    void set_metrics(yuzu::MetricsRegistry* metrics) noexcept { metrics_ = metrics; }

    /// Enqueue one occurrence on a CALLER-SUPPLIED connection, so the `pending`
    /// row commits in the SAME transaction as the producer's own state
    /// transition (claim-before-side-effect). `conn` must be inside an open
    /// transaction owned by the caller (e.g. a `PgPool::with_txn` body), and the
    /// guarded INSERT must be the FIRST data statement of that transaction (see
    /// the isolation contract in the file header). The epoch fence
    /// (`leader_lock_name` + `leader_epoch`) is embedded into the INSERT. This
    /// call does NOT commit — the caller's transaction owns commit/rollback, so
    /// the enqueue and the transition are atomic.
    ///
    /// Returns `Enqueued` / `AlreadyEnqueued` / `FencedOut` (see the enum). A
    /// query error returns `Degraded` and the caller must roll back and fail
    /// closed.
    [[nodiscard]] OutboxEnqueueOutcome claim_and_enqueue_on(PGconn* conn,
                                                            const OutboxEnqueueRequest& req,
                                                            const std::string& leader_lock_name,
                                                            std::int64_t leader_epoch);

    /// Convenience wrapper: enqueue on the store's own bounded, autocommitted
    /// lease (one statement, so atomic on its own). For a producer whose state
    /// transition is already durable, or for tests. Same fence + idempotency
    /// semantics as `claim_and_enqueue_on`.
    [[nodiscard]] OutboxEnqueueOutcome claim_and_enqueue(const OutboxEnqueueRequest& req,
                                                         const std::string& leader_lock_name,
                                                         std::int64_t leader_epoch);

    /// The pending occurrences due for delivery (`state='pending'` and
    /// `next_attempt_at <= now()`), oldest first, capped at `limit`. AUTHORITATIVE:
    /// a degraded read is `unexpected(db_error)`, never an empty vector (which the
    /// delivery loop would read as "nothing owed" and silently drop every
    /// scheduled fire). Not epoch-fenced — it is a read; the fence gates the
    /// subsequent state-changing claim.
    [[nodiscard]] std::expected<std::vector<OutboxCommand>, CommandOutboxError>
    list_pending(int limit = 100) const;

    /// The number of `pending` occurrences (the delivery backlog), for the
    /// `yuzu_server_command_outbox_pending` observability gauge (sre-F2/WS-11): a
    /// stuck delivery loop (leadership never acquired, degraded gate) shows flat
    /// event counters, so a backlog gauge is the only signal that scheduled
    /// dispatch has silently stopped. `nullopt` on a degraded read (the caller
    /// leaves the gauge unchanged rather than publishing a false 0). Cheap — a
    /// count over the partial `outbox_ready_idx`.
    [[nodiscard]] std::optional<std::int64_t> count_pending() const;

    /// Epoch-fenced `pending → sent`. Records that the occurrence was delivered
    /// so the delivery loop stops re-driving it. A stale ex-leader's mark is
    /// fenced out (0 rows) and the row stays `pending` for the true leader to
    /// re-drive — harmless, because the receiver deduped the duplicate wire send
    /// on `command_id`. `true` = transitioned, `false` = not (already terminal,
    /// fenced out, or no such row); `unexpected` = store degraded.
    [[nodiscard]] std::expected<bool, CommandOutboxError>
    mark_sent(const std::string& occurrence_id, const std::string& leader_lock_name,
              std::int64_t leader_epoch);

    /// Epoch-fenced `pending → failed` — a PERMANENT failure (e.g. the arming
    /// principal's authority was revoked between enqueue and delivery, so the
    /// re-resolved caller is denied). Terminal; not re-driven. Same return
    /// contract as `mark_sent`.
    [[nodiscard]] std::expected<bool, CommandOutboxError>
    mark_failed(const std::string& occurrence_id, const std::string& leader_lock_name,
                std::int64_t leader_epoch, const std::string& reason);

    /// Epoch-fenced transient retry: keep the occurrence `pending`, bump
    /// `attempts`, and push `next_attempt_at` out by `delay` (so a transient
    /// delivery failure — a degraded dispatch chokepoint — backs off instead of
    /// hot-looping). Same return contract as `mark_sent`.
    [[nodiscard]] std::expected<bool, CommandOutboxError>
    reschedule(const std::string& occurrence_id, const std::string& leader_lock_name,
               std::int64_t leader_epoch, std::chrono::seconds delay);

    /// The schema migrations for this store (version 1). Exposed for tests and
    /// the migration ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    /// Shared implementation of the fenced state transition used by
    /// `mark_sent` / `mark_failed` / `reschedule`.
    [[nodiscard]] std::expected<bool, CommandOutboxError>
    fenced_transition(const char* sql, const std::vector<std::string>& params,
                      const char* op_label);

    void count_degrade(const char* op, const char* reason) const;

    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
