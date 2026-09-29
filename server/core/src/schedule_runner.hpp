#pragma once

#include "command_outbox_store.hpp" // WS-3 3.3: OutboxEnqueueRequest / OutboxEnqueueOutcome

/// @file schedule_runner.hpp
/// Drives the recurring-instruction schedules that were previously dead.
///
/// `ScheduleEngine` persists schedules and computes due-ness
/// (`evaluate_due`) and the post-fire advance (`advance_schedule`), but
/// nothing ever called either in production (#1191) — schedules were
/// created, listed and never fired. This component closes that gap.
///
/// Model (WS-3 3.3, ADR-2002 §6): a background thread in ServerImpl `tick()`s
/// on a cadence (the policy_eval_thread_ / preflight_runner_thread_ pattern).
/// Each tick pulls the due schedules and, for each fire, creates a tracked
/// execution row (the create-before-dispatch contract from the
/// executions-history ladder, UP2-4) and COMMITS A DURABLE `pending` OUTBOX
/// OCCURRENCE — it no longer dispatches to agents inline. The leader-gated
/// `CommandOutboxDelivery` loop performs the actual wire send. This is
/// claim-before-side-effect: a crash between the enqueue and the send re-drives
/// from `pending`, and the occurrence's stable id keeps it effectively-once. A
/// fire-time crash before advance re-fires next tick, but the occurrence key
/// (`schedule_id:next_execution_at`) is idempotent (`AlreadyEnqueued`), so the
/// re-fire produces no second occurrence. Scheduled runs still appear in the
/// Executions history exactly like manual runs (the exec row is created here).
///
/// Approval posture — a scheduled fire NEVER bypasses the approval gate the
/// interactive execute path enforces. A fire requires approval when the
/// schedule's own `requires_approval` flag is set OR the definition's
/// `approval_mode` is anything but "auto" (there is no operator session on
/// this path, so "role-gated" fails closed to require-approval, matching the
/// interactive path's unknown-mode posture). An approval-gated occurrence:
///   * submits ONE approval ticket (deduped against an extant pending
///     ticket for the same definition/creator/scope) and leaves the
///     schedule due — it re-checks each tick,
///   * fires within a tick of the ticket being APPROVED. One-approval ==
///     one-run is enforced by the occurrence anchor: firing advances the
///     schedule, and only tickets submitted strictly AFTER the last advance
///     count for the next occurrence, so a spent ticket can never re-fire,
///   * skips the occurrence and advances when the ticket is REJECTED —
///     the next occurrence submits a fresh ticket.
///
/// Advance discipline: every non-approval outcome advances the schedule
/// (fire-and-advance — a missed/failed occurrence is recorded and skipped,
/// never retried into a backlog). Only a pending approval holds a schedule
/// at its due time.
///
/// Arming re-check (D7, PLAN-003) — a schedule can sit dormant for months
/// between occurrences, long enough for the authority it was armed under to
/// have changed (a role revoked, a definition re-pointed). `fire()` re-
/// verifies the arming principal via `Deps::arming_check` BEFORE branching
/// on approval, so the check covers the direct-dispatch arm exactly as much
/// as the approval-gated arm. It is an ADDITIONAL gate in front of the
/// approval-ticket flow (ApprovalManager / fire_with_approval, M-02/#1806),
/// not a second copy of it — a denial here means fire_with_approval never
/// runs at all for that occurrence.

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry; // yuzu/metrics.hpp — observability counters (optional)
}

namespace yuzu::server {

// Forward declarations — full types are included in the .cpp.
class ScheduleEngine;
class InstructionStore;
class ExecutionTracker;
class ApprovalManager;
class AuditStore;
struct InstructionSchedule;

class ScheduleRunner {
public:
    /// WS-3 3.3 — commit ONE durable `pending` outbox occurrence for a fire,
    /// replacing the former inline dispatch. server.cpp binds this to a lambda
    /// that mints the occurrence's stable `command_id`, reads the current leader
    /// epoch, and calls `CommandOutboxStore::claim_and_enqueue` — so this file
    /// stays free of the store/elector concrete types and its tests can inject a
    /// fake. The delivery loop (`CommandOutboxDelivery`) performs the actual send
    /// and re-authorization; this runner only DECIDES a fire and durably records
    /// it. REQUIRED: an unwired `enqueue_fn` means a fire cannot be durably
    /// queued, so `enqueue_occurrence` fails closed (the schedule stays due and
    /// retries) rather than silently dropping the occurrence.
    using EnqueueFn =
        std::function<yuzu::server::OutboxEnqueueOutcome(const yuzu::server::OutboxEnqueueRequest&)>;

    /// Re-verify the arming principal's current authority to fire ONE
    /// plugin.action (D7, peer finding PLAN-003). Checked in `fire()`
    /// BEFORE the approval/direct branch, so it covers both the
    /// `approval_mode == "auto"` direct-dispatch arm AND the approval-gated
    /// arm — a check reachable only from inside `fire_with_approval` would
    /// leave every auto schedule dispatching under stale authority. This
    /// package owns only the fail-closed seam and its tests: an UNSET
    /// callback denies every fire. p14 wires the real RBAC/arming lookup.
    using ArmingCheckFn = std::function<bool(const std::string& principal,
                                             const std::string& plugin,
                                             const std::string& action)>;

    struct Deps {
        ScheduleEngine* schedule_engine{nullptr};       // required
        InstructionStore* instruction_store{nullptr};   // required
        ExecutionTracker* execution_tracker{nullptr};   // optional (fires untracked)
        ApprovalManager* approval_manager{nullptr};     // optional (see fire())
        AuditStore* audit_store{nullptr};               // optional forensic sink
        yuzu::MetricsRegistry* metrics{nullptr};        // optional observability sink
        EnqueueFn enqueue_fn;                            // required (WS-3 3.3) — see doc comment
        ArmingCheckFn arming_check;                      // fail-closed when unset — see above
        // #3495: lets a shutdown request stop tick() from firing further due
        // schedules once stop_requested_ flips — checked once per schedule,
        // before fire() runs, so a schedule already firing still completes
        // cleanly (this only stops the NEXT one from starting). Ports the
        // same field QuarantineContainmentReconciler::Deps already carries
        // (governance Gate 5, #3425). Unset (default) = never stop, matching
        // every existing production/test Deps that predates this field.
        std::function<bool()> should_stop;
    };

    explicit ScheduleRunner(Deps deps);

    /// One scheduler cycle: fire every due schedule. Safe to call from a
    /// single background thread; individual fire failures are contained
    /// (logged + counted) so one bad schedule cannot starve the rest.
    void tick();

private:
    // Fire one due schedule: approval gate, tracked dispatch, advance.
    void fire(const InstructionSchedule& s);

    // The approval-gated arm of fire(). Returns true when the occurrence is
    // settled (fired, skipped-rejected, or submit failed) and the schedule
    // was advanced; false when it stays due waiting on a pending ticket.
    bool fire_with_approval(const InstructionSchedule& s, const std::string& plugin,
                            const std::string& action);

    // Create the tracked execution row and commit ONE durable pending outbox
    // occurrence, shared by the direct and approved arms (WS-3 3.3). Returns
    // true iff the occurrence is durably queued (Enqueued or the idempotent
    // AlreadyEnqueued) and the caller should advance the schedule; false on a
    // degraded/fenced-out enqueue (the schedule stays due and retries — the
    // stable occurrence key keeps the retry idempotent). Does NOT dispatch to
    // agents — the delivery loop does that.
    bool enqueue_occurrence(const InstructionSchedule& s, const std::string& plugin,
                            const std::string& action, const std::string& approval_id);

    void audit(const InstructionSchedule& s, const std::string& action,
               const std::string& result, const std::string& detail);
    void count(const char* name);

    Deps d_;
};

} // namespace yuzu::server
