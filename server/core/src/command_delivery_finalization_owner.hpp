#pragma once

/// @file command_delivery_finalization_owner.hpp
/// #4982 round 5: the ADR-0012 §3 cross-store query owner for the two places a
/// genuine dispatch's DELIVERY needs to reach across the `command_outbox_store`
/// / `execution_tracker` schema boundary. Follows the same shape
/// `rbac_admin_authority_owner.hpp` established (a dedicated owner that takes
/// ONE pool lease and issues schema-qualified SQL spanning the schemas
/// directly, so the two per-store classes on either side of the boundary stay
/// single-schema owners per the ADR):
///
///  * `mark_sent_with_target` — a WRITE. The atomic `pending → sent` outbox
///    transition PLUS the execution's real `agents_targeted` count, in ONE
///    transaction (#4982 round 3's fix). `CommandOutboxStore::
///    mark_sent_with_target` (command_outbox_store.cpp) is a thin delegating
///    forward to this — mirrors `RbacStore::unassign_role`'s own delegation to
///    `RbacAdminAuthorityOwner::unassign_role` exactly: construct an instance
///    per call (`CommandDeliveryFinalizationOwner{pool_}.mark_sent_with_target(...)`),
///    never cache one, and translate the typed outcome back into the store's
///    own `std::expected<bool, CommandOutboxError>` + `count_degrade` metrics
///    call. The SQL, the fencing, the rollback-on-either-failure behavior and
///    the error handling are UNCHANGED from round 3 — only WHERE the code
///    lives moved.
///
///  * `kPendingOutboxNotExistsClause` — the READ counterpart (round 5; both
///    round-4 adversarial reviewers flagged `ExecutionTracker::
///    reap_stuck_running_executions`'s own hand-written `NOT EXISTS (SELECT 1
///    FROM command_outbox_store.outbox ...)` clause as the SAME class of
///    violation — a per-store class directly querying another schema). This
///    one does NOT take the shape of an owner-executed query, and that is a
///    deliberate departure from `RbacAdminAuthorityOwner`'s pattern (every
///    RBAC method there runs its OWN `pool_.with_txn_for`/lease): the
///    predicate is a correlated subquery embedded, three times, inside
///    `reap_stuck_running_executions`'s own single transaction — most load-
///    bearingly inside the FINAL atomic `UPDATE ... WHERE ... RETURNING id`
///    that round 2/3 built specifically so the cancel's full candidate
///    predicate (including this outbox check) is evaluated AS PART OF the
///    state transition itself — same connection, same transaction, same
///    advisory lock, not a separately-leased read whose answer could go
///    stale before the write commits. (Not a shared MVCC snapshot: each
///    Postgres READ COMMITTED statement gets its own; see
///    execution_tracker.cpp's own comment on the atomic cancel UPDATE for
///    the narrow residual this leaves for a NOT EXISTS subquery, as opposed
///    to the UPDATE's own locked target row.) Answering this predicate on a
///    SEPARATELY-acquired
///    owner lease (the way the RBAC owner's own `regime_authority` answers
///    its point-in-time question on its OWN lock-free lease) would reopen
///    exactly the TOCTOU that atomic recheck exists to close — a row
///    could flip to outbox-pending between the owner's read and
///    `ExecutionTracker`'s own UPDATE committing. So instead of an
///    owner-executed method, this is a single shared, schema-qualified SQL
///    FRAGMENT: the one place that spells out what "still owned by the
///    delivery loop" means for a `command_outbox_store.outbox` row. Every
///    consumer — today, `ExecutionTracker::reap_stuck_running_executions`'s
///    three occurrences of this exact clause — references this ONE symbol
///    instead of hand-writing the cross-schema literal, so the three copies
///    that previously had to stay byte-identical by hand now cannot drift.
///    `ExecutionTracker` still issues the SQL on its own connection (it must,
///    for the atomicity guarantee above), but the SCHEMA-QUALIFIED KNOWLEDGE
///    of what the predicate means is owned here, not duplicated in
///    `execution_tracker.cpp`. No `CommandDeliveryFinalizationOwner` instance
///    is needed to use it — it is a `static constexpr` string, not a query.
///
/// Only `CommandOutboxStore` constructs an instance of this class (the write
/// path); `ExecutionTracker` never does — it references the static string
/// member directly. Mirrors `RbacAdminAuthorityOwner`'s own "only RbacStore
/// constructs it" restriction, at this class's own, simpler reason (there is
/// no local-cache-generation-apply step here to protect; the restriction is
/// kept anyway so construction stays a single, auditable call site rather
/// than an incidental convenience any future caller could reach for).

#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class CommandOutboxStore;

class CommandDeliveryFinalizationOwner {
public:
    /// Outcome of `mark_sent_with_target`. Deliberately mirrors the local
    /// variables `CommandOutboxStore::mark_sent_with_target` used to compute
    /// inline before this move — `CommandOutboxStore` translates this 1:1 into
    /// its own `std::expected<bool, CommandOutboxError>` + `count_degrade`
    /// call, exactly reproducing the pre-move behavior.
    struct MarkSentWithTargetOutcome {
        /// False iff the whole transaction (both writes) failed to commit —
        /// either write's query erroring, or the commit itself failing. A
        /// business outcome of "not ours" (fenced out / already terminal) is
        /// NOT a failure: it is `committed=true, matched=false`, same as
        /// `mark_sent`'s own "0 rows" contract.
        bool committed{false};
        /// True iff THIS call's sent-transition actually fired AND (when it
        /// did) the target-count write also committed with it. Meaningless
        /// when `committed` is false.
        bool matched{false};
        /// True iff a query inside the transaction returned an error status
        /// (vs. `committed=false` with no query-level error, e.g. a lease
        /// timeout surfacing as a `with_txn_for` failure the lambda never
        /// observes). Preserves the exact `db_error` vs `commit_failed`
        /// degrade-reason distinction `CommandOutboxStore::count_degrade`
        /// reported before this move.
        bool db_error{false};
    };

    CommandDeliveryFinalizationOwner(const CommandDeliveryFinalizationOwner&) = delete;
    CommandDeliveryFinalizationOwner& operator=(const CommandDeliveryFinalizationOwner&) = delete;

    /// See this file's header banner and `command_outbox_store.hpp`'s
    /// `CommandOutboxStore::mark_sent_with_target` doc comment (the public
    /// behavioral contract callers see) for the full rationale. Byte-identical
    /// SQL/fencing/rollback/error-handling to the round-3 implementation this
    /// replaces — only its location moved, per ADR-0012 §3.
    [[nodiscard]] MarkSentWithTargetOutcome
    mark_sent_with_target(const std::string& occurrence_id, const std::string& leader_lock_name,
                          std::int64_t leader_epoch, const std::string& execution_id,
                          int agents_targeted) const;

    /// THE cross-schema predicate: true (from the embedding caller's own
    /// transaction/connection) iff `executions.id` (the correlated column —
    /// callers embed this literally in a `WHERE ... AND
    /// <kPendingOutboxNotExistsClause>` over `execution_tracker.executions`,
    /// never rename that alias) does NOT have a `state='pending'` row in
    /// `command_outbox_store.outbox` — i.e. TRUE means the delivery loop no
    /// longer owns this occurrence (it was already finalized, sent or
    /// failed, one way or the other); FALSE means it is still pending and
    /// the delivery loop still owns it. #4982 round 6 (Kimi K4): read the
    /// SQL, not this paragraph's shape, if in doubt — it is a literal
    /// `NOT EXISTS (...)`, so the predicate is true precisely when no such
    /// row exists. See this file's header banner for why this is a shared
    /// TEXT fragment rather than an owner-executed method: the caller's own
    /// transaction, not a separately-leased read, must evaluate it. Never
    /// build this fragment by hand at a new call site — reference this
    /// symbol.
    static constexpr std::string_view kPendingOutboxNotExistsClause =
        "NOT EXISTS (SELECT 1 FROM command_outbox_store.outbox "
        "            WHERE execution_id = executions.id AND state = 'pending')";

private:
    friend class CommandOutboxStore;
    explicit CommandDeliveryFinalizationOwner(pg::PgPool& pool) : pool_(pool) {}

    pg::PgPool& pool_;
};

} // namespace yuzu::server
