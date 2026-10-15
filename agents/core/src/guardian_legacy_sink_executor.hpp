#pragma once

/**
 * guardian_legacy_sink_executor.hpp - a bounded, FIFO, gap-accounting, detached
 * sender for the legacy IGuard producers' event sink (#4783, delivery plan
 * `.claude/plans/4783-legacy-guard-sink-blocking-PLAN-v2.md` §3.1).
 *
 * WHY: FileGuard/RegistryGuard/ServiceGuard/SystemdServiceGuard each call
 * GuardianEngine::emit_guard_event(). BEFORE this class existed, emit_guard_event()
 * called the injected EventSink directly, which meant emit_guardian_event()'s
 * synchronous gRPC Write() ran on the SAME thread that runs the guard's own
 * detection loop. A stalled-but-not-dead stream (no deadline on subscribe_ctx_)
 * wedged that thread indefinitely: the guard stopped detecting, and if the wedge
 * happened to land inside GuardianEngine::stop()'s mtx_-held guard join, teardown
 * itself wedged. This class decouples the producer from the send: emit_guard_event()
 * (guardian_engine.cpp) now enqueues onto this executor via offer() instead of
 * calling the sink synchronously, and is unconditionally live in production
 * (constructed in GuardianEngine's ctor, independent of prefer_spark_) - mirroring
 * guardian_outbox_send_executor.hpp / guardian_io_executor.hpp's detached-worker
 * shape (spawn_detached, the armed-under-lock AliveTicket idiom,
 * GuardianDetachedWorkerRole, firewalled stall/recovery logging) - but is NOT
 * single-flight like those two: producers commit their decider state (last_compliant
 * etc.) BEFORE calling the sink and GuardSink returns void, so a refused/dropped
 * event here is a PERMANENT edge loss no later offer() repairs on its own. That is
 * why this class, unlike its siblings, keeps a bounded FIFO queue (not a 1-deep
 * slot) plus a sticky, per-rule integrity-gap ledger - see the loss table below.
 *
 * QUEUE POLICY - pure FIFO, never coalesced/replaced/reordered. Every admitted
 * event is delivered in admission order or counted as lost; two events for the
 * SAME rule_id never collapse into one slot (drift.detected, drift.remediated,
 * remediation.failed, guard.compliant, guard.unhealthy are all distinct census
 * signals - the server orders same-second events by ARRIVAL order, so reordering
 * is a correctness bug, not just a cardinality change). Bounded by BOTH
 * `max_events` and `max_bytes` (Event::ByteSizeLong(), computed once at offer()).
 *
 * LOSS ACCOUNTING AND THE STICKY INTEGRITY GAP. Every event this executor admitted
 * or was offered but the server will not receive is a *loss* except the two
 * shutdown/pre-network classes:
 *
 *   source                                      | counter(s)                    | gap?
 *   RefusedCapacity (count or bytes)             | backpressure_drops+events_lost | yes
 *   RefusedAdmission (allocation failure)        | admission_failures+events_lost | yes
 *   sink returned WriteFailed                    | send_failures+events_lost      | yes
 *   sink threw                                   | send_exceptions+events_lost    | yes
 *   sink returned LinkDown (no stream yet)       | dropped_link_down              | NO (D4b)
 *   discarded_at_stop (backlog cleared at stop()) | discarded_at_stop             | no
 *
 * A gap is `gaps[rule_id]` (guard_type/rule_name copied from the lost event so a
 * repair can be synthesized without touching the guard), sticky until CLEARED by
 * a strictly-newer confirmed-Sent delivery for that rule_id - see "SEQ-GUARDED
 * CLEARING" below (#4783 follow-up review; a REPAIR report offer()'d with
 * is_gap_repair=true is one way to close it, but so is an ordinary real event
 * whose admission-time seq postdates the loss it is closing). If the gap ledger
 * itself cannot be updated (allocation failure), record_gap_locked() degrades
 * gap_ledger_degraded=true and counts gap_ledger_faults instead of throwing -
 * surfaced as its own loss signal, never silently swallowed. Gap *repair
 * synthesis and dispatch* (building a guard.unhealthy event and calling kick()'s
 * heartbeat-driven repair loop) is GuardianEngine::legacy_sink_kick()'s job
 * (commit 4 of the delivery plan) - this class only maintains the ledger and
 * exposes it via gapped_rules_needing_repair().
 *
 * SEQ-GUARDED CLEARING (#4783 follow-up review - a correctness defect found in
 * the ORIGINAL commit-4 design, where ANY offer()'d is_gap_repair=true send that
 * came back Sent erased the gap unconditionally). Every offer() - admitted OR
 * refused alike - is assigned a strictly increasing `seq` (State::next_seq) at
 * admission time; every lost event's gap advances `GapRecord::lost_seq` to the
 * max seq of any loss recorded against it. A delivery (real OR repair) clears
 * the gap ONLY if its own seq is STRICTLY NEWER than `lost_seq` - i.e. it is
 * provably a report of state at-or-after the most recent loss, not a stale
 * in-flight item that merely happened to finish afterwards. This closes two
 * failure classes the naive "clear on any Sent" rule permits: (1) an
 * already-in-flight OLDER send completing Sent after a NEWER loss for the same
 * rule must not erase evidence of that newer loss; (2) a REPAIR queued before a
 * newer loss occurred must not silently confirm the OLD state as current. Case
 * (2) needs a second mechanism because nothing re-validates a queued repair
 * between the moment it is queued and the moment it reaches the front of the
 * FIFO - see DEQUEUE-TIME SUPERSESSION below, which is what actually closes it;
 * the seq check alone only stops a superseded repair's Sent from erasing the
 * gap after the fact, it does not stop the repair from being SENT at all.
 *
 * `GapRecord::repair_seq` (0 = no repair outstanding) records the seq of the
 * repair CURRENTLY queued for that rule, if any - the successor to a plain
 * `repair_in_flight` bool, needed because a repair can be superseded (a newer
 * loss opens/advances the gap while the old repair is still queued) and the
 * executor must be able to tell "this specific queued repair is still the
 * live one" from "a newer repair (or nothing) has since taken its place".
 *
 * DEQUEUE-TIME SUPERSESSION. Immediately after a repair item is popped off the
 * FIFO - BEFORE its send() is invoked - the worker re-checks the rule's CURRENT
 * gap state: if the gap no longer exists, or `repair_seq` no longer names THIS
 * item's own seq (a newer repair superseded it, or - the third case, see the
 * worker loop's own comment - the repair was queued after the gap had already
 * been re-cleared by a fresh real event, so it was never stamped with a live
 * repair_seq at all), the repair is SKIPPED - never sent - and counted in
 * `repairs_suppressed`. This is the piece that actually closes the reported
 * symptom (a stale synthetic repair overwriting a newer real verdict on the
 * server via its own `updated_at >=` upsert guard): checking supersession only
 * at kick/fire time is not enough, because the supersession can happen AFTER
 * the repair is already queued and BEFORE it reaches the front.
 *
 * ADMISSION-TIME EPISODE BINDING (adversarial-review finding, 2026-09-24 - a
 * residual gap in SEQ-GUARDED CLEARING that DEQUEUE-TIME SUPERSESSION alone
 * does not close). The caller (GuardianEngine::legacy_sink_kick()) captures a
 * GapRecord snapshot via gapped_rules_needing_repair() and only builds+offers
 * the repair event afterwards - an unbounded window in which the SAME rule's
 * gap can be cleared-and-reopened (or simply accrue a further loss) before
 * offer()'s is_gap_repair branch ever runs. The original code stamped
 * `repair_seq` on whatever gap was live for `rule_id` at admission time with no
 * check that it was still the SAME loss episode the caller captured - so a
 * stale repair could bind itself to a brand-new gap, and because its own
 * admission `seq` necessarily postdates that gap's `lost_seq` (offer() always
 * runs after the episode it is racing against), SEQ-GUARDED CLEARING's
 * `it.seq > lost_seq` check passed trivially on a later Sent and erased
 * evidence of a loss the repair never actually observed. `offer()` now takes
 * an optional `expected_gap_lost_seq`; when present, the admission stamp only
 * fires if it still equals the CURRENT `GapRecord::lost_seq` (monotonic, so
 * `==` is exact - a mismatch can only mean the episode moved on, never that it
 * fell behind). On a mismatch, `repair_seq` is deliberately left untouched
 * rather than stamped-then-unstamped: DEQUEUE-TIME SUPERSESSION above already
 * suppresses any item whose seq isn't the rule's live `repair_seq`, so an
 * unstamped stale repair is caught by that existing machinery for free, with
 * no new suppression counter needed. `std::nullopt` (the default, used by
 * every direct test call that does not care about this refinement) preserves
 * the original unconditional-stamp behavior - only GuardianEngine::
 * legacy_sink_kick(), the one production caller, supplies a real value.
 *
 * CORRECTNESS PROPERTIES (each was a specific defect class found in design
 * review of the delivery plan - see the class's own test file for the regression
 * each property guards):
 *  1. FIFO only - never coalesce/replace/reorder; every offered event is
 *     delivered exactly once or counted as lost.
 *  2. Bounded by both max_events and max_bytes; a refusal always counts and
 *     records a gap, never a silent drop.
 *  3. Launch retry works from a stranded state: launch eligibility (queue
 *     non-empty, no worker running, not stopping) is evaluated on EVERY offer()
 *     outcome (Queued or Refused alike) AND inside kick() - so a failed
 *     spawn_detached is recoverable both by the next offer() of ANY key and by
 *     kick() alone with zero new offers.
 *  4. offer() never throws to its caller (a guard's own detection thread calls
 *     this - an escaping exception ends that guard's detection permanently, see
 *     guard_file.cpp's outer catch). The whole body is one try/catch; any
 *     exception rolls back to a state as if nothing happened, counts
 *     admission_failures+events_lost, records a best-effort gap, and returns
 *     RefusedAdmission.
 *  5. No self-deadlock on ticket destruction: ~AliveTicket locks state_->mu, so
 *     the LAST live reference to an armed ticket is never dropped while this
 *     thread already holds that mutex. On launch-rollback, the ticket captured
 *     BY VALUE into the (failed) worker closure is destroyed synchronously
 *     inside spawn_detached's own stack frame (unlocked); THIS function's own
 *     copy - kept alive deliberately, not moved into the closure - is dropped
 *     only after the rollback's lock_guard has already released the lock.
 *  6. A quiet, fully-stalled queue (no new offers, one send that never returns)
 *     is still eventually observed as a stall: kick() re-checks the in-flight
 *     stall condition on every call, independent of any offer() - production
 *     wires it to the engine's heartbeat tick (commit 4), not guard activity.
 *  7. stop() never blocks and never touches an in-flight send: it only flips
 *     `stopping`, discards the (counted) backlog, and returns. A send already
 *     admitted as in-flight before stop() is allowed to complete after stop()
 *     returns - a defined, tested outcome (active_worker_count() reflects it
 *     until the worker retires), not a race bug. stop() also does NOT prevent an
 *     OS thread from being *created* after `stopping` is already true (admission
 *     committed -> stop() -> spawn_detached is a real interleaving) - safe
 *     because the worker checks `stopping` under the lock before any dequeue, so
 *     it retires immediately without touching the (already-cleared) backlog.
 *  8. No claimed upper bound on transient active_worker_count() beyond "reaches
 *     0 at rest" - retiring workers may overlap successors arbitrarily; do not
 *     add a comment claiming a small fixed ceiling.
 *
 * WORKER FAULT BOUNDARY: the worker loop wraps its ENTIRE iteration body (not
 * just the send() call) in try/catch(...) - a whole-iteration boundary, counted
 * as worker_faults, with the loop continuing on the next iteration. The stall
 * check runs BEFORE `in_flight` is cleared (do NOT copy
 * guardian_outbox_send_executor.hpp's check_stall_locked() verbatim here - it
 * early-returns on `!in_flight`, which would suppress exactly the check this
 * class needs at that point). If the throw hit AFTER an item was already
 * popped off the FIFO but BEFORE account_outcome_locked() ran for it (an
 * allocation failure between the pop and the send - the identifying fields are
 * captured immediately after the pop for exactly this reason), the catch ALSO
 * records a best-effort gap for that item (send_exceptions/events_lost +
 * record_gap_locked, same chokepoint offer()'s own loss sites use) so it is
 * never silently dropped uncounted - correctness property 1 holds even here.
 *
 * ORPHAN-EXIT CONTRACT: identical to the sibling executors - a worker wedged in
 * a blocking Write() cannot be joined or force-cancelled. active_worker_count()
 * IS summed into GuardianEngine::active_io_workers() (guardian_engine.cpp) as
 * the fourth term, after spark_reader_'s state-read executor, spark_runtime_'s
 * arm/disarm executor, and spark_drain_worker_'s outbox-send executor, so a
 * detached send survives teardown observably, not silently.
 *
 * WIRED: this class is constructed unconditionally in GuardianEngine's
 * constructor and is the live legacy IGuard sink path in production, independent
 * of prefer_spark_ - see guardian_engine.cpp's emit_guard_event() (enqueues via
 * offer()) and legacy_sink_kick() (drives kick() and gap repair from the agent
 * heartbeat, agent.cpp).
 */

#include "guardian_detached_worker_role.hpp" // GuardianDetachedWorkerRole
#include "guardian_io_executor.hpp"          // io_detail::spawn_detached

#include "guaranteed_state.pb.h" // yuzu::guardian::v1::GuaranteedStateEvent

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <spdlog/spdlog.h> // firewalled stall/recovery logging, matching the sibling executors

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <new> // std::bad_alloc (test-fault-injection throws below)
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Outcome of one delivery attempt, reported by the injected send function.
enum class LegacySendOutcome : std::uint8_t { Sent, LinkDown, WriteFailed };

/**
 * Known limitations (accepted, #4783 D1d / Gate 4 UP-3+UP-4). Two are a
 * confirmed, deliberately-NOT-fixed trade-off; read them together with
 * snapshot()/restore() below, which close a DIFFERENT gap (process-restart
 * survival of the loss/gap BOOKKEEPING itself, never of any lost event's own
 * payload - this class stays a loss-visibility marker, not a durable spool):
 *
 *  - UP-4 (accepted trade-off). An interior compliance transition (e.g.
 *    `drift.detected`) can be silently and permanently lost if it is refused
 *    at capacity while the rule's BRACKETING events (the state before and
 *    the state after) both succeed - the gap self-clears on the later
 *    successful event (SEQ-GUARDED CLEARING above) with no repair ever
 *    firing, so the server's audit HISTORY shows continuous compliance
 *    through a window that was, for a time, a real violation - even though
 *    CURRENT state is accurate. The loss is never SILENT, though: it is
 *    counted (`events_lost`, restart-durable via snapshot()/restore()),
 *    attributed in the agent log by rule_id at the moment of loss (see
 *    LossLogHook / the per-loss spdlog::warn/info call in offer()/
 *    account_outcome_locked), and fleet-visible
 *    (`yuzu_fleet_guardian_legacy_sink_events_lost`). Fully closing this
 *    needs a durable spool of the lost event's own content, which D1d
 *    explicitly declined as out of scope - tracked as a separate follow-up
 *    issue, #4888.
 *
 *  - UP-3 (fixed here, restart semantics). snapshot()/restore() make the gap
 *    ledger and loss counters survive an agent restart mid-outage - without
 *    this, a restarted agent's fresh-boot state (everything zeroed) fed the
 *    next heartbeat's fleet-gauge sweep identically to a genuine repair, so
 *    an operator could not tell "fixed" from "agent bounced, evidence lost"
 *    by reading `yuzu_fleet_guardian_legacy_sink_gap_rules` alone. Two
 *    restart outcomes: if the link comes back up before the rule's next real
 *    transition, that transition's own arm-time verdict clears the restored
 *    gap LEGITIMATELY via the ordinary SEQ-GUARDED CLEARING path - restore()
 *    resets a restored gap's `lost_seq` to 0, so ANY subsequent delivery for
 *    that rule (seq >= 1) clears it; if the link is still down, the gap
 *    stays open and legacy_sink_kick()'s repair loop resumes once reachable,
 *    stamping the repair with the gap's ORIGINAL pre-restart `last_lost`
 *    (preserved byte-for-byte by restore(), never reset to the restart
 *    time).
 *
 *  - A narrower residual (accepted, not worth its own follow-up). stop()'s
 *    final snapshot()+persist (GuardianEngine::stop()) runs immediately
 *    after legacy_sink_executor_->stop() returns, but correctness property 7
 *    above still lets an already-in-flight send complete AFTER stop()
 *    returns. If that send comes back WriteFailed, the gap it opens exists
 *    in memory but postdates the final persisted snapshot, so it is not
 *    itself restart-durable - the same orphan-exit window
 *    active_worker_count()/GuardianEngine::active_io_workers() already cover
 *    for shutdown-OBSERVABILITY purposes, just not separately covered here.
 */
class YUZU_EXPORT GuardianLegacySinkExecutor {
public:
    using Event = ::yuzu::guardian::v1::GuaranteedStateEvent;
    using SendFn = std::function<LegacySendOutcome(const Event&)>;

    /// TEST-ONLY observation seam for the per-loss attribution log (#4783 Gate 4
    /// UP-4 de-escalation, part 1) - see log_loss()'s call sites in offer()/
    /// account_outcome_locked and set_loss_log_hook_for_test() below.
    /// spdlog::level::off is never delivered here (log_loss() returns before
    /// invoking the hook in that case) - the hook only ever fires alongside a
    /// real spdlog::warn/info call. `kind` is always a static string literal
    /// ("RefusedCapacity"/"RefusedAdmission"/"WriteFailed"/"SendException"), so
    /// the `const char*` outlives every call.
    using LossLogHook = std::function<void(const std::string& rule_id, const char* kind,
                                           const std::string& event_type,
                                           spdlog::level::level_enum level)>;

    struct Config {
        std::size_t max_events{4096};
        std::size_t max_bytes{4u << 20};
        std::chrono::milliseconds stall_threshold{5'000};
    };

    /// Admission outcome of offer(). Never describes the eventual SEND outcome -
    /// that is asynchronous and observed later via stats()/gapped_rules_needing_repair().
    enum class OfferOutcome { Queued, RefusedCapacity, RefusedAdmission, RefusedStopping };

    /// A sticky per-rule integrity gap - see the class doc comment's loss table
    /// and its SEQ-GUARDED CLEARING / DEQUEUE-TIME SUPERSESSION sections.
    /// guard_type/rule_name are copied from the LOST event so a repair report can
    /// be synthesized without going back to the guard (guard.hpp has no query API
    /// for "give me your last known state"). `lost_seq` is the max admission-time
    /// seq of any loss recorded against this rule - the floor a delivery's own
    /// seq must strictly exceed to be allowed to clear the gap. `repair_seq` (0 =
    /// none outstanding) is the seq of the repair CURRENTLY queued for this rule,
    /// if any - checked again at DEQUEUE time (worker_loop) to catch the case
    /// where the gap was superseded (a newer loss, or a newer repair, or the gap
    /// being cleared outright by a fresh real delivery) after this repair was
    /// already sitting in the FIFO.
    struct GapRecord {
        std::string guard_type;
        std::string rule_name;
        std::uint64_t lost{0};
        std::chrono::system_clock::time_point first_lost{};
        std::chrono::system_clock::time_point last_lost{};
        std::uint64_t lost_seq{0};
        std::uint64_t repair_seq{0};
        /// #4783 Gate 4 UP-2: the kick_epoch (State::kick_epoch) at the moment a
        /// repair was last QUEUED for this rule (offer()'s is_gap_repair branch) -
        /// 0 if no repair has ever been queued. gapped_rules_needing_repair()'s
        /// rotation sort reads this as its PRIMARY key (least-recently-attempted
        /// first) so a stable set of >kMaxGapRepairsPerKick eligible gaps cycles
        /// through every entry instead of starving whichever ones happen to sort
        /// first. Deliberately NOT reset when a queued repair later fails
        /// (WriteFailed/threw, which resets `repair_seq` back to 0) - keeping the
        /// stale value sends a chronically-failing rule to the back of the
        /// rotation too, so it cannot starve the rules behind it either.
        std::uint64_t last_attempt_kick{0};
    };

    /// A restart-durable projection of one GapRecord (#4783 Gate 4 UP-3) - see
    /// snapshot()/restore() below. Deliberately narrower than GapRecord: no
    /// `lost_seq`/`repair_seq`/`last_attempt_kick` - those are IN-PROCESS
    /// sequencing tied to this executor's own `next_seq`/`kick_epoch` counters,
    /// which restart at 0 in a fresh process, so restore() always seeds them
    /// fresh (0) rather than replaying stale sequence state from a prior
    /// process (see restore()'s own doc comment for why that makes a restored
    /// gap immediately eligible for repair). Timestamps are epoch-milliseconds
    /// (not `time_point`, which is not a stable on-disk representation across
    /// a process/library-version boundary).
    struct GapSnapshotEntry {
        std::string rule_id;
        std::string guard_type;
        std::string rule_name;
        std::uint64_t lost{0};
        std::int64_t first_lost_ms{0};
        std::int64_t last_lost_ms{0};
    };

    struct Stats {
        std::uint64_t events_lost{0};
        std::uint64_t backpressure_drops{0};
        std::uint64_t admission_failures{0};
        std::uint64_t send_failures{0};
        std::uint64_t send_exceptions{0};
        std::uint64_t worker_faults{0};
        std::uint64_t dropped_link_down{0};
        std::uint64_t discarded_at_stop{0};
        std::uint64_t stalls{0};
        std::uint64_t launch_failures{0};
        /// record_gap_locked()'s own allocation-failure degrade path (see the
        /// class doc comment). #4783 Gate 6 sre finding, 2026-09-24: also
        /// bumped by read_legacy_sink_loss_record() (guardian_engine.cpp) for
        /// each empty-rule_id entry it skips on restore - a second, rarer
        /// source of the same "the gap ledger's own bookkeeping degraded"
        /// signal, folded into this field rather than a new one so it stays
        /// fleet-durable across the field's existing JSON persistence, not
        /// just a one-line log an operator has to be watching for at the
        /// exact restart moment.
        std::uint64_t gap_ledger_faults{0};
        std::size_t gap_rules{0};
        /// #4783 follow-up: queued repairs skipped at dequeue time because they
        /// were superseded before reaching the front - see the class doc
        /// comment's DEQUEUE-TIME SUPERSESSION section. Never sent, never counted
        /// as a loss (the gap they would have repaired was either already closed
        /// by something newer, or has since advanced past them).
        std::uint64_t repairs_suppressed{0};
    };

    /// A restart-durable snapshot of this executor's loss counters + open-gap
    /// ledger (#4783 Gate 4 UP-3/UP-4) - see snapshot()/restore() below and
    /// GuardianEngine's own KV-persistence wiring (guardian_engine.cpp's
    /// legacy_sink_kick()/start_local()/stop()). Deliberately does NOT capture
    /// any queued Item/Event payload, in-flight send state, or in-process
    /// sequencing (next_seq/kick_epoch) - see this class's own "Known
    /// limitations" doc comment above: this is a loss-VISIBILITY marker, never
    /// a durable spool.
    struct Snapshot {
        Stats counters;
        std::vector<GapSnapshotEntry> gaps;
        /// The executor-internal change generation this snapshot was taken at
        /// (State::change_gen) - a caller compares this against the generation
        /// it last successfully persisted to decide whether a fresh write is
        /// worth doing at all (see legacy_sink_kick()'s own gate). Not itself
        /// meaningful across a restart (a fresh process's executor starts back
        /// at 0) - purely a same-process "has anything changed since I last
        /// wrote" token.
        std::uint64_t change_gen{0};
    };

    /// Test-only fault injection for the admission path (offer()). `ThrowOnTicket`
    /// fires at the earliest allocation (the AliveTicket, before the lock and
    /// before any State mutation - the UNARMED rollback, nothing to undo);
    /// `ThrowOnNode` fires at the list-node allocation itself (the LAST throwing
    /// step inside the locked admission block, per the class doc comment - the
    /// only State mutation ahead of it is the harmless next_seq bump, #4783
    /// follow-up). `ThrowOnGapLedger` fires inside
    /// record_gap_locked()'s own map mutation, from EITHER call site (offer()'s
    /// admission-refusal path or the worker's post-send accounting) - it is
    /// caught internally and degrades gap_ledger_degraded rather than escaping,
    /// so this exercises that degradation path specifically, not offer()'s own
    /// RefusedAdmission path.
    enum class AdmissionFaultForTest { None, ThrowOnNode, ThrowOnTicket, ThrowOnGapLedger };

    /// Test-only fault injection for the launch path (spawn_detached).
    /// `SpawnRefused` mirrors the OS refusing to create the thread;
    /// `Throw` mirrors a std::bad_alloc anywhere in the guarded launch region.
    enum class LaunchFaultForTest { None, SpawnRefused, Throw };

    /// Test-only fault injection for worker_loop's post-pop item-identity
    /// capture (#4783 Gate 3 cpp-safety/cpp-expert/security-guardian finding,
    /// 2026-09-24 - three independent reviewers converged on the same defect).
    /// `ThrowDuringCapture` fires AFTER popped_rule_id is captured but BEFORE
    /// the remaining fields (guard_type/rule_name/event_type/seq) - mirroring
    /// the realistic worst case (an allocation failure partway through the
    /// four capture copies, not on the very first one) and proving the outer
    /// catch(...) still accounts the loss using whatever was captured before
    /// the throw, rather than silently dropping it.
    /// `ThrowOnFirstCapture` (#4783 Gate 4 unhappy-path finding, same date)
    /// fires BEFORE popped_rule_id is captured at all - the one case where
    /// the outer catch has NO rule_id to work with. Proves the empty-rule_id
    /// guard on the catch's record_gap_locked() call: the loss is still
    /// counted globally, but no "phantom" empty-rule_id GapRecord is created.
    enum class WorkerFaultForTest { None, ThrowDuringCapture, ThrowOnFirstCapture };

    GuardianLegacySinkExecutor() : GuardianLegacySinkExecutor(Config{}) {}
    explicit GuardianLegacySinkExecutor(Config cfg) : state_(std::make_shared<State>()) {
        state_->max_events = cfg.max_events;
        state_->max_bytes = cfg.max_bytes;
        state_->stall_threshold = cfg.stall_threshold;
    }
    GuardianLegacySinkExecutor(const GuardianLegacySinkExecutor&) = delete;
    GuardianLegacySinkExecutor& operator=(const GuardianLegacySinkExecutor&) = delete;

    /// Enqueue `ev` for delivery via `send`, which runs on a DETACHED worker,
    /// never on the caller's thread. Never blocks on network I/O; never throws
    /// (correctness property 4) - every exception anywhere in this function maps
    /// to RefusedAdmission. `is_gap_repair` marks this offer as a synthesized
    /// repair report for an existing gap (see the class doc comment); it is the
    /// caller's (GuardianEngine::legacy_sink_kick(), guardian_engine.cpp) job to
    /// build that event, not this class's. `expected_gap_lost_seq` (only
    /// meaningful when `is_gap_repair` is true) is the `GapRecord::lost_seq` the
    /// caller captured when it selected this repair (gapped_rules_needing_repair())
    /// - see the class doc comment's ADMISSION-TIME EPISODE BINDING section.
    /// `std::nullopt` preserves the pre-existing unconditional-stamp behavior.
    [[nodiscard]] OfferOutcome offer(Event ev, SendFn send, bool is_gap_repair = false,
                                     std::optional<std::uint64_t> expected_gap_lost_seq =
                                         std::nullopt) noexcept {
        // Declared here (not inside the try) so the catch block below can still
        // use whatever was successfully computed before an exception hit -
        // correctness property 4's "record a best-effort gap" clause.
        std::string rule_id;
        std::string guard_type;
        std::string rule_name;
        // #4783 Gate 4 UP-4: extracted early alongside rule_id/guard_type/
        // rule_name (not read off `ev` later) for the SAME reason those three
        // are - by the time either loss site below could want it, `ev` may
        // already have been moved-from (the success branch moves it into the
        // queued Item; protobuf's move leaves the source cleared, not merely
        // unspecified), and the catch(...) branch may run after a throw whose
        // exact point relative to that move is not fixed.
        std::string event_type;
        // #4783 Gate 4 UP-4: the per-loss log decision + the test-hook copy for
        // it, computed under the SAME lock acquisition as the loss itself
        // (record_gap_locked/State::loss_log_hook_for_test) so this costs no
        // extra lock beyond what offer() already takes - the actual spdlog
        // call happens AFTER the lock releases, at the very end of this
        // function, matching the existing log_send_stall/log_send_recovery
        // pattern (logging must never happen while state_->mu is held).
        auto loss_log_level = spdlog::level::off;
        const char* loss_log_kind = nullptr;
        LossLogHook loss_log_hook;
        try {
            // (1) Compute the byte size and copy the identifying fields BEFORE
            // the lock - these allocate, and the strong-guarantee rollback below
            // relies on none of them having touched State yet.
            const std::size_t bytes = ev.ByteSizeLong();
            rule_id = ev.rule_id();
            guard_type = ev.guard_type();
            rule_name = ev.rule_name();
            event_type = ev.event_type();

            // (2) The unarmed ticket, BEFORE the lock (allocates; #3966 idiom -
            // see guardian_outbox_send_executor.hpp's AliveTicket doc comment).
            if (admission_fault_for_test() == AdmissionFaultForTest::ThrowOnTicket)
                throw std::bad_alloc{};
            auto ticket = std::make_shared<AliveTicket>(state_);

            OfferOutcome outcome = OfferOutcome::Queued;
            bool need_spawn = false;
            {
                std::unique_lock<std::mutex> lk{state_->mu};
                // (2.5) Every offer that reaches the lock - admitted OR refused
                // alike - is assigned its own strictly increasing seq HERE, before
                // the outcome is even decided (#4783 follow-up: SEQ-GUARDED
                // CLEARING, see the class doc comment). This is a State mutation
                // ahead of the (3) list-node allocation below, so ThrowOnNode's
                // rollback is no longer "nothing above this point mutated State" -
                // consuming a seq on a rolled-back attempt is harmless (numbering
                // gaps are unobservable; only relative order matters), so this
                // deliberately stays ahead of the throwing step rather than being
                // pushed below it.
                const std::uint64_t seq = ++state_->next_seq;
                if (state_->stopping) {
                    // Not a "loss" counter by design - see the class doc comment's
                    // loss table (discarded_at_stop is deliberately not events_lost).
                    // Still consumes a seq above (harmless - see the comment there).
                    ++state_->counters.discarded_at_stop;
                    outcome = OfferOutcome::RefusedStopping;
                } else if (state_->queue.size() >= state_->max_events ||
                           state_->bytes + bytes > state_->max_bytes) {
                    // #4783 Gate 4 UP-4: copy the test hook FIRST, before any
                    // counters/ledger mutation below - a std::function copy can
                    // allocate and throw, and this branch has no throwing-step-
                    // is-last discipline of its own the way the success branch's
                    // ThrowOnNode does; if it threw AFTER the increments/
                    // record_gap_locked below, the outer catch(...) would record
                    // a SECOND, spurious RefusedAdmission loss for the same
                    // event on top of this branch's already-recorded
                    // RefusedCapacity one.
                    loss_log_hook = state_->loss_log_hook_for_test;
                    ++state_->counters.backpressure_drops;
                    ++state_->counters.events_lost;
                    loss_log_level = record_gap_locked(*state_, rule_id, guard_type, rule_name, seq);
                    loss_log_kind = "RefusedCapacity";
                    outcome = OfferOutcome::RefusedCapacity;
                } else {
                    // (3) The list-node allocation - the LAST throwing step; on
                    // throw, nothing above this point mutated State EXCEPT the seq
                    // counter bump above, which is deliberately harmless to lose
                    // track of on rollback (see the comment on that bump).
                    if (admission_fault_for_test() == AdmissionFaultForTest::ThrowOnNode)
                        throw std::bad_alloc{};
                    state_->queue.push_back(Item{std::move(ev), std::move(send), rule_id, bytes,
                                                 is_gap_repair, seq});
                    state_->bytes += bytes;
                    if (is_gap_repair) {
                        if (auto gi = state_->gaps.find(rule_id); gi != state_->gaps.end()) {
                            // ADMISSION-TIME EPISODE BINDING (class doc comment):
                            // only bind this repair to the gap - and so only make
                            // it eligible to clear on a later Sent - if it still
                            // describes the SAME loss episode the caller captured.
                            // A mismatch means the episode moved on (a further
                            // loss, or a clear-and-reopen) since selection; leave
                            // repair_seq untouched so DEQUEUE-TIME SUPERSESSION
                            // (worker_loop) suppresses this now-stale item before
                            // its send() ever runs, instead of letting it bind to
                            // - and later wrongly clear - a gap it never observed.
                            if (!expected_gap_lost_seq.has_value() ||
                                gi->second.lost_seq == *expected_gap_lost_seq) {
                                gi->second.repair_seq = seq;
                                // #4783 Gate 4 UP-2: stamp the CURRENT kick round
                                // as this rule's last repair attempt - see
                                // GapRecord's own doc comment and
                                // gapped_rules_needing_repair()'s rotation sort.
                                // Read now, under this same lock, so it reflects
                                // whichever kick() call most recently bumped it
                                // (or 0 if this offer is racing ahead of the first
                                // kick() - harmless, it just sorts to the front
                                // once).
                                gi->second.last_attempt_kick = state_->kick_epoch;
                            }
                        }
                    }
                }

                // (4) Regardless of outcome (Queued or any Refused* above),
                // evaluate launch eligibility in this SAME locked block -
                // correctness property 3: a stranded queue (worker_running still
                // false after an earlier failed launch) is retried by ANY
                // subsequent offer(), not only a fresh key.
                if (!state_->queue.empty() && !state_->worker_running && !state_->stopping) {
                    state_->worker_running = true;
                    ticket->arm();
                    need_spawn = true;
                }
            }
            // (5) Unlock, then spawn outside the lock.
            if (need_spawn)
                attempt_launch(std::move(ticket));
            // (6) Log OUTSIDE the lock, same as (5)'s spawn - #4783 Gate 4 UP-4.
            // A no-op unless the capacity-refusal branch above actually ran.
            log_loss(rule_id, loss_log_kind, event_type, loss_log_level, loss_log_hook);
            return outcome;
        } catch (...) {
            auto catch_loss_log_level = spdlog::level::off;
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                // The throw may have hit before the locked block above ever ran
                // (the pre-lock ticket allocation), OR inside it - ThrowOnNode
                // throws AFTER the locked block's own seq bump (deliberately, see
                // that block's own comment), and the capacity-refusal branch's
                // loss_log_hook std::function copy can also throw there. Either
                // way this catch's own seq comes from the SAME state_->next_seq
                // counter, under this lock, so ordering stays consistent with the
                // main path regardless of which branch actually assigns it - a
                // throw inside the locked block just means TWO seqs get consumed
                // for this one offer() call (harmless, see the seq-bump comment
                // above: numbering gaps are unobservable, only relative order
                // matters), not that this catch's own bump double-counts anything.
                const std::uint64_t seq = ++state_->next_seq;
                ++state_->counters.admission_failures;
                ++state_->counters.events_lost;
                // #4783 Gate 4 unhappy-path finding, 2026-09-24: only open a
                // per-rule gap when rule_id was actually captured - see
                // worker_loop's identical guard (its own doc comment has the
                // full rationale: an empty-rule_id GapRecord is a "phantom" no
                // real rule can ever repair, and - because
                // read_legacy_sink_loss_record() rejects the WHOLE restart
                // snapshot on any single empty-rule_id entry - persisting one
                // can silently discard every OTHER rule's legitimate open-gap
                // state on the next restart. The loss is still counted
                // globally (events_lost/admission_failures above) either way.
                // This is the pre-existing sibling of the worker_loop finding,
                // not introduced by this range - fixed here for the same
                // reason, once found.
                if (!rule_id.empty()) {
                    catch_loss_log_level = record_gap_locked(*state_, rule_id, guard_type, rule_name, seq);
                    loss_log_hook = state_->loss_log_hook_for_test;
                }
            } catch (...) {
            }
            // #4783 Gate 4 UP-4: logged OUTSIDE the lock_guard above, same
            // rationale as the main path's own (6).
            log_loss(rule_id, "RefusedAdmission", event_type, catch_loss_log_level, loss_log_hook);
            return OfferOutcome::RefusedAdmission;
        }
    }

    /// Re-evaluate launch eligibility and observe an in-flight stall, entirely
    /// independent of offer() (correctness properties 3 and 6). Production wires
    /// this to the agent heartbeat tick via GuardianEngine::legacy_sink_kick()
    /// (agent.cpp), independent of prefer_spark_, so a stranded queue or a
    /// quiet-but-stalled send is noticed within one heartbeat interval even with
    /// zero new guard activity. Never throws; a failure here is best-effort and
    /// simply retried on the next call.
    void kick() noexcept {
        std::shared_ptr<AliveTicket> ticket;
        bool need_spawn = false;
        bool log_stall = false;
        std::string stalled_rule_id;
        try {
            std::unique_lock<std::mutex> lk{state_->mu};
            // #4783 Gate 4 UP-2: bump the kick round FIRST, before any other
            // kick() logic - gapped_rules_needing_repair() (called by the
            // production caller, GuardianEngine::legacy_sink_kick(), immediately
            // after this returns) reads the now-current kick_epoch to stamp any
            // repair it queues via offer(). This is a separate lock acquisition
            // from that later call, but since nothing else can run kick() or
            // offer() concurrently against the SAME rule in a way that matters
            // here, bumping it up front is what makes it "current" for the
            // selection that follows.
            ++state_->kick_epoch;
            if (!state_->queue.empty() && !state_->worker_running && !state_->stopping) {
                ticket = std::make_shared<AliveTicket>(state_);
                state_->worker_running = true;
                ticket->arm();
                need_spawn = true;
            }
            // Stall observation is orthogonal to the launch decision above - a
            // wedged send and a stranded (worker-not-running) queue are
            // independent conditions and either or both can be true here.
            if (state_->in_flight && !state_->stall_logged &&
                (std::chrono::steady_clock::now() - state_->send_started_at >=
                 state_->stall_threshold)) {
                ++state_->counters.stalls;
                state_->stall_logged = true;
                log_stall = true;
                stalled_rule_id = state_->in_flight_rule_id;
            }
        } catch (...) {
            return;
        }
        if (log_stall)
            log_send_stall(stalled_rule_id);
        if (need_spawn)
            attempt_launch(std::move(ticket));
    }

    /// Prohibits new admissions; discards the (counted) backlog; never blocks;
    /// never touches an in-flight send (correctness property 7). Idempotent.
    void stop() noexcept {
        try {
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->stopping = true;
            state_->counters.discarded_at_stop += state_->queue.size();
            state_->queue.clear();
            state_->bytes = 0;
        } catch (...) {
        }
    }

    /// PHYSICAL alive worker count (payload not yet destroyed) - 0 at rest, no
    /// claimed transient ceiling (correctness property 8). Summed into
    /// GuardianEngine::active_io_workers()'s orphan-exit sum (guardian_engine.cpp).
    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->worker_count);
    }

    [[nodiscard]] bool has_in_flight_send() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->in_flight;
    }

    [[nodiscard]] Stats stats() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        Stats s = state_->counters;
        s.gap_rules = state_->gaps.size();
        return s;
    }

    /// Up to `max` gaps ELIGIBLE for a new repair attempt right now - i.e. with
    /// `repair_seq == 0` (NOT already mid-repair; #4783 Gate 4 UP-2 - a gap with
    /// one outstanding is excluded from consideration here rather than counted
    /// against `max` and then skipped by the caller, which is what let an
    /// already-saturated kick offer fewer than `max` NEW repairs). Selection
    /// among the eligible set is a least-recently-attempted round-robin: sorted
    /// by (last_attempt_kick ascending, first_lost ascending, rule_id ascending -
    /// the rule_id tie-break makes selection fully deterministic, independent of
    /// unordered_map iteration order) and the first `max` are returned.
    ///
    /// GUARANTEE: every open gap not already mid-repair receives a repair attempt
    /// within ceil(n_eligible / kMaxGapRepairsPerKick) kicks, where n_eligible is
    /// the number of gaps with repair_seq == 0 at a given kick. Each kick selects
    /// the `max` least-recently-attempted eligible gaps, and offer()'s
    /// is_gap_repair branch stamps every queued repair's last_attempt_kick to the
    /// CURRENT kick round - so a gap selected this kick sorts to the BACK of the
    /// rotation for every following kick until every other still-eligible gap has
    /// had an equal-or-more-recent turn, guaranteeing it resurfaces within
    /// ceil(n_eligible / max) kicks of its last attempt. Because the rule_id
    /// tie-break makes the ordering deterministic rather than dependent on
    /// unordered_map iteration order, this holds even for a perfectly stable set
    /// of gaps - the failure mode this fixes was exactly that stability: a fixed
    /// subset returned (and only ever offered) by every kick, forever.
    [[nodiscard]] std::vector<std::pair<std::string, GapRecord>>
    gapped_rules_needing_repair(std::size_t max) const {
        std::lock_guard<std::mutex> lk{state_->mu};
        // Pointers into the map's own nodes - stable under this lock, so this
        // avoids copying every eligible GapRecord just to sort and then discard
        // most of them.
        std::vector<const std::pair<const std::string, GapRecord>*> eligible;
        eligible.reserve(state_->gaps.size());
        for (const auto& kv : state_->gaps) {
            if (kv.second.repair_seq == 0)
                eligible.push_back(&kv);
        }
        const std::size_t take = std::min(max, eligible.size());
        std::partial_sort(eligible.begin(), eligible.begin() + take, eligible.end(),
                          [](const auto* a, const auto* b) {
                              return std::tie(a->second.last_attempt_kick, a->second.first_lost,
                                              a->first) <
                                     std::tie(b->second.last_attempt_kick, b->second.first_lost,
                                              b->first);
                          });
        std::vector<std::pair<std::string, GapRecord>> out;
        out.reserve(take);
        for (std::size_t i = 0; i < take; ++i)
            out.emplace_back(eligible[i]->first, eligible[i]->second);
        return out;
    }

    /// A restart-durable snapshot of the current counters + open-gap ledger
    /// (#4783 Gate 4 UP-3/UP-4) - see the class's own "Known limitations" doc
    /// comment and GuardianEngine::legacy_sink_kick()/stop() for how a caller
    /// persists this to KvStore. Read-only: takes state_->mu, copies, releases -
    /// does not mutate anything (in particular does NOT reset change_gen; that
    /// only ever moves forward via a loss/clear, see record_gap_locked and
    /// account_outcome_locked's Sent-clears-gap branch).
    [[nodiscard]] Snapshot snapshot() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        Snapshot snap;
        snap.counters = state_->counters;
        snap.counters.gap_rules = state_->gaps.size(); // same read-time denormalization as stats()
        snap.gaps.reserve(state_->gaps.size());
        for (const auto& [rule_id, g] : state_->gaps) {
            GapSnapshotEntry e;
            e.rule_id = rule_id;
            e.guard_type = g.guard_type;
            e.rule_name = g.rule_name;
            e.lost = g.lost;
            e.first_lost_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  g.first_lost.time_since_epoch())
                                  .count();
            e.last_lost_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 g.last_lost.time_since_epoch())
                                 .count();
            snap.gaps.push_back(std::move(e));
        }
        snap.change_gen = state_->change_gen;
        return snap;
    }

    /// Seed this executor's counters + open-gap ledger from a PRIOR process's
    /// snapshot() (#4783 Gate 4 UP-3) - the restart-durability half of the
    /// fix; see the class's own "Known limitations" doc comment for the full
    /// restart-semantics contract this establishes.
    ///
    /// PRECONDITION (caller's responsibility, not enforced here): MUST be
    /// called before this executor's first offer()/kick() - i.e. on the
    /// single-threaded agent boot path, before any guard thread or the
    /// heartbeat thread can reach this executor. GuardianEngine::start_local()
    /// satisfies this by calling restore() (under its own mtx_, itself only
    /// ever called before guards are (re-)armed) strictly before the rule
    /// re-arm loop that could otherwise let a freshly-armed guard's detection
    /// thread call offer() concurrently with this seeding. Calling this after
    /// concurrent activity has begun is a data race on state_->gaps/counters
    /// (this function does not itself take any lock ordering precaution beyond
    /// its own state_->mu acquisition, which does not help if a concurrent
    /// offer()/kick() interleaves a partially-seeded ledger into its own
    /// decisions).
    ///
    /// `seed_counters` seeds state_->counters directly - this is what makes
    /// `events_lost` (and every other counter) MONOTONIC across a restart: the
    /// new process's counters start from the persisted value, not 0, and
    /// increment from there. `gaps` reconstructs one GapRecord per entry, with
    /// FRESH in-process sequencing (`lost_seq`/`repair_seq`/`last_attempt_kick`
    /// all reset to 0 - these are NEW post-restart sequence numbers tied to
    /// this process's own next_seq/kick_epoch counters, which also both start
    /// at 0) but the ORIGINAL `first_lost`/`last_lost` timestamps preserved -
    /// a restored gap is therefore immediately ELIGIBLE for repair
    /// (repair_seq==0) and clears on the very next delivery for that rule
    /// (lost_seq==0 is strictly less than any real seq, which starts at 1).
    /// Never throws (fully firewalled) - a restore that fails partway through
    /// leaves whatever was already seeded in place rather than crashing agent
    /// boot; the caller degrades to "start with an empty ledger" on any read
    /// failure BEFORE ever calling this, so a throw here would only be a
    /// secondary allocation failure on an already-parsed, well-formed record.
    void restore(Stats seed_counters, std::vector<GapSnapshotEntry> gaps) noexcept {
        try {
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->counters = seed_counters;
            // gap_rules is a read-time denormalization (see stats()/snapshot()),
            // never stored authoritatively in state_->counters - zero it back
            // out so a stale seeded value is never mistaken for one.
            state_->counters.gap_rules = 0;
            for (auto& e : gaps) {
                GapRecord g;
                g.guard_type = e.guard_type;
                g.rule_name = e.rule_name;
                g.lost = e.lost;
                g.first_lost =
                    std::chrono::system_clock::time_point{std::chrono::milliseconds{e.first_lost_ms}};
                g.last_lost =
                    std::chrono::system_clock::time_point{std::chrono::milliseconds{e.last_lost_ms}};
                g.lost_seq = 0;
                g.repair_seq = 0;
                g.last_attempt_kick = 0;
                state_->gaps.emplace(std::move(e.rule_id), std::move(g));
            }
        } catch (...) {
        }
    }

    // ---- test seams -------------------------------------------------------

    /// EVERY current gap, unfiltered by eligibility and unsorted - unlike
    /// gapped_rules_needing_repair() (production selection: eligible-only,
    /// rotation-sorted, capped), this is a raw snapshot for inspecting a gap's
    /// state (e.g. `repair_seq` while a repair is still mid-flight, which makes
    /// it ineligible and therefore invisible to gapped_rules_needing_repair()).
    [[nodiscard]] std::vector<std::pair<std::string, GapRecord>> all_gaps_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        std::vector<std::pair<std::string, GapRecord>> out;
        out.reserve(state_->gaps.size());
        for (const auto& kv : state_->gaps)
            out.emplace_back(kv.first, kv.second);
        return out;
    }

    [[nodiscard]] std::size_t pending_count_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->queue.size();
    }
    [[nodiscard]] std::size_t pending_bytes_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->bytes;
    }

    /// True once the queue is empty AND nothing is in flight - NOT physical
    /// worker retirement (a worker that just observed an empty queue is still
    /// counted in active_worker_count() until its trampoline destroys the
    /// payload). Use wait_workers_retired_for_test() to wait for that instead.
    [[nodiscard]] bool wait_idle_for_test(std::chrono::milliseconds timeout) const {
        return poll_for_test(timeout, [&] {
            std::lock_guard<std::mutex> lk{state_->mu};
            return state_->queue.empty() && !state_->in_flight;
        });
    }

    /// True once active_worker_count() reaches 0 - physical retirement.
    [[nodiscard]] bool wait_workers_retired_for_test(std::chrono::milliseconds timeout) const {
        return poll_for_test(timeout, [&] { return active_worker_count() == 0; });
    }

    /// Fires on the calling thread, with state_->mu NOT held, right before the
    /// actual spawn attempt inside attempt_launch() - i.e. after a caller
    /// (offer() or kick()) has already committed worker_running=true and armed
    /// its ticket under the lock, and released it. A test can synchronously
    /// offer() a SECOND event from inside this hook: that second offer() sees
    /// worker_running already true, so it enqueues without attempting its own
    /// launch - deterministically reproducing "B offered while A's launch is
    /// still outstanding" via call ordering, matching the same idiom
    /// guardian_outbox_send_executor.hpp uses for its own launch-race tests.
    /// This seam is not in the delivery plan's §3.1 code sketch verbatim; it is
    /// this file's minimal addition to make that specific interleaving
    /// deterministic in a test rather than relying on real thread scheduling.
    void set_pre_launch_race_hook_for_test(std::function<void()> hook) {
        pre_launch_race_hook_for_test_ = std::move(hook);
    }

    void set_launch_fault_for_test(LaunchFaultForTest f) {
        launch_fault_for_test_.store(f, std::memory_order_relaxed);
    }
    void set_admission_fault_for_test(AdmissionFaultForTest f) {
        state_->admission_fault_for_test.store(f, std::memory_order_relaxed);
    }
    void set_worker_fault_for_test(WorkerFaultForTest f) {
        state_->worker_fault_for_test.store(f, std::memory_order_relaxed);
    }

    /// TEST-ONLY (#4783 Gate 4 UP-4 de-escalation): observe the per-loss
    /// attribution log without depending on spdlog's own default-logger state,
    /// which is unreliable across a shared-library boundary (see
    /// test_log_capture.hpp's own doc comment and test_guardian_arm_ack.cpp's
    /// LogCapture removal - this class is compiled into libyuzu_agent_core AND
    /// directly into any test TU that includes this header, so which image's
    /// spdlog state a given call observes is not guaranteed). Guarded by
    /// state_->mu like every other State field - set this BEFORE any
    /// offer()/kick() that could race a concurrent read of it.
    void set_loss_log_hook_for_test(LossLogHook hook) {
        std::lock_guard<std::mutex> lk{state_->mu};
        state_->loss_log_hook_for_test = std::move(hook);
    }

private:
    struct Item {
        Event ev;
        SendFn send;
        std::string rule_id;
        std::size_t bytes{0};
        bool gap_repair{false};
        /// #4783 follow-up: this item's own admission-time seq (State::next_seq at
        /// the moment offer() admitted it) - see the class doc comment's
        /// SEQ-GUARDED CLEARING section.
        std::uint64_t seq{0};
    };

    struct State {
        std::mutex mu;
        std::condition_variable cv;
        std::list<Item> queue;
        std::size_t bytes{0};
        bool worker_running{false};
        bool in_flight{false};
        bool stopping{false};
        int worker_count{0};
        std::string in_flight_rule_id;
        std::chrono::steady_clock::time_point send_started_at{};
        bool stall_logged{false};
        std::unordered_map<std::string, GapRecord> gaps;
        bool gap_ledger_degraded{false};
        Stats counters{};
        std::chrono::milliseconds stall_threshold{5'000}; // copied from Config at construction
        std::size_t max_events{4096};                     // copied from Config at construction
        std::size_t max_bytes{4u << 20};                  // copied from Config at construction
        std::atomic<AdmissionFaultForTest> admission_fault_for_test{AdmissionFaultForTest::None};
        /// #4783 Gate 3 finding, 2026-09-24: worker_loop's post-pop capture fault
        /// seam - see WorkerFaultForTest's own doc comment. Lives on State (not
        /// the executor instance, unlike launch_fault_for_test_) because
        /// worker_loop is a static function that only ever sees a
        /// shared_ptr<State>, never `this`.
        std::atomic<WorkerFaultForTest> worker_fault_for_test{WorkerFaultForTest::None};
        /// #4783 follow-up: the executor-wide admission sequence counter - every
        /// offer() call that reaches the lock (admitted or refused alike) gets the
        /// next value. See the class doc comment's SEQ-GUARDED CLEARING section.
        std::uint64_t next_seq{0};
        /// #4783 Gate 4 UP-2: bumped once per kick() call (the first statement in
        /// its locked block, before any other kick() logic) - the "round number"
        /// stamped onto GapRecord::last_attempt_kick when a repair is queued for a
        /// rule, so gapped_rules_needing_repair()'s rotation sort can tell which
        /// gaps were attempted longest ago.
        std::uint64_t kick_epoch{0};
        /// #4783 Gate 4 UP-3: bumped by record_gap_locked() (every loss) and by
        /// account_outcome_locked()'s Sent-clears-gap branch (every gap erase) -
        /// see snapshot()'s own doc comment. A caller (GuardianEngine) compares
        /// this against the generation it last persisted to decide whether a
        /// fresh restart-durable write is worth doing. Deliberately NOT bumped
        /// by every Stats field (e.g. `stalls`/`worker_faults`/
        /// `repairs_suppressed`) - only loss/clear events, which is what
        /// `events_lost`/the open-gap ledger (the UP-3/UP-4 restart-durability
        /// target) actually depend on.
        std::uint64_t change_gen{0};
        /// #4783 Gate 4 UP-4: process-lifetime, per-rule loss count for the
        /// per-loss attribution log's rate limit - see log_loss()'s call sites.
        /// Deliberately SEPARATE from GapRecord::lost: GapRecord (and its
        /// `lost` field) is ERASED when a gap clears (SEQ-GUARDED CLEARING), but
        /// the rate limit must never reset just because a rule's gap happened
        /// to close in between two losses - a chronically-flapping rule must
        /// still only warn once per process, not once per open-gap episode.
        /// Never erased; bounded in practice by the number of distinct rule_ids
        /// this agent has ever had rules for (the same unbounded-by-rule_id
        /// growth shape `gaps` itself has while open).
        std::unordered_map<std::string, std::uint64_t> loss_log_counts;
        /// TEST-ONLY (see set_loss_log_hook_for_test) - guarded by mu like every
        /// other State field; empty = no-op.
        LossLogHook loss_log_hook_for_test;
    };

    /// RAII orphan-exit marker (#3966 idiom - see
    /// guardian_outbox_send_executor.hpp's AliveTicket doc comment for the full
    /// rationale). Unarmed by default; arm() is called by offer()/kick() as the
    /// LAST statement of the SAME locked block that sets worker_running=true, so
    /// admission and the physical count commit atomically under one lock
    /// acquisition. A ticket destroyed before/without arm() is a no-op.
    struct AliveTicket {
        explicit AliveTicket(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~AliveTicket() {
            if (!armed)
                return;
            std::lock_guard<std::mutex> lk{state->mu};
            if (state->worker_count > 0)
                --state->worker_count;
        }
        /// CALLER MUST HOLD state->mu.
        void arm() noexcept {
            ++state->worker_count;
            armed = true;
        }
        AliveTicket(const AliveTicket&) = delete;
        AliveTicket& operator=(const AliveTicket&) = delete;
        std::shared_ptr<State> state;
        bool armed{false};
    };

    [[nodiscard]] AdmissionFaultForTest admission_fault_for_test() const {
        return state_->admission_fault_for_test.load(std::memory_order_relaxed);
    }

    template <class Pred>
    static bool poll_for_test(std::chrono::milliseconds timeout, Pred&& pred) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return pred();
    }

    /// #4783 Gate 4 UP-4: the per-loss attribution log's rate limit - see
    /// State::loss_log_counts' own doc comment and record_gap_locked below.
    static constexpr std::uint64_t kLossLogRateLimit = 100;

    /// Called with state_->mu HELD, from EITHER offer() (an admission refusal)
    /// or the worker (post-send accounting) - a single chokepoint so
    /// AdmissionFaultForTest::ThrowOnGapLedger exercises the same degrade path
    /// regardless of caller. Never propagates: an allocation failure while
    /// recording the gap itself degrades gap_ledger_degraded/gap_ledger_faults
    /// rather than escaping into either caller's own noexcept contract. `seq` is
    /// the LOST event's own admission-time seq - folded into `lost_seq` as
    /// `max(existing, seq)` (#4783 follow-up: SEQ-GUARDED CLEARING).
    ///
    /// Returns the per-loss attribution log DECISION for the caller to act on
    /// AFTER releasing state_->mu (#4783 Gate 4 UP-4 - see log_loss() and this
    /// function's own two call sites in offer()/account_outcome_locked):
    /// spdlog::level::off means "do not log", ::warn means "first loss this
    /// process has recorded for this rule_id", ::info means "the
    /// kLossLogRateLimit-th loss since then".
    static spdlog::level::level_enum record_gap_locked(State& st, const std::string& rule_id,
                                                       const std::string& guard_type,
                                                       const std::string& rule_name,
                                                       std::uint64_t seq) {
        // #4783 Gate 4 UP-3: bumped FIRST, unconditionally - a plain ++ on a
        // uint64_t cannot throw, so this still advances even if the gap-ledger
        // mutation below degrades (AdmissionFaultForTest::ThrowOnGapLedger).
        // The caller (GuardianEngine::legacy_sink_kick()) compares this against
        // the generation it last persisted to decide whether events_lost (which
        // the caller already bumped, just before calling this) is worth a
        // fresh restart-durable write - that counter changed regardless of
        // whether the gap ledger itself could be updated.
        ++st.change_gen;
        auto log_level = spdlog::level::off;
        try {
            if (st.admission_fault_for_test.load(std::memory_order_relaxed) ==
                AdmissionFaultForTest::ThrowOnGapLedger)
                throw std::bad_alloc{};
            const auto now = std::chrono::system_clock::now();
            auto it = st.gaps.find(rule_id);
            if (it == st.gaps.end()) {
                GapRecord g;
                g.guard_type = guard_type;
                g.rule_name = rule_name;
                g.lost = 1;
                g.first_lost = now;
                g.last_lost = now;
                g.lost_seq = seq;
                st.gaps.emplace(rule_id, std::move(g)); // the one throwing step
            } else {
                ++it->second.lost;
                it->second.last_lost = now;
                it->second.lost_seq = std::max(it->second.lost_seq, seq);
            }
            // #4783 Gate 4 UP-4: a process-lifetime, per-rule loss count - see
            // State::loss_log_counts' own doc comment for why this is separate
            // from GapRecord::lost (which resets on every gap clear). warn on
            // this rule_id's very first loss this process has ever recorded,
            // then info every kLossLogRateLimit-th loss thereafter, so a
            // chronically-lossy rule cannot flood the log but is never silent.
            const std::uint64_t total = ++st.loss_log_counts[rule_id];
            if (total == 1)
                log_level = spdlog::level::warn;
            else if (total % kLossLogRateLimit == 0)
                log_level = spdlog::level::info;
        } catch (...) {
            st.gap_ledger_degraded = true;
            ++st.counters.gap_ledger_faults;
        }
        return log_level;
    }

    /// Called with state_->mu HELD, on the worker thread, after one send
    /// attempt completes (normally or by throwing). Applies the loss-accounting
    /// table from the class doc comment. `rule_id`/`guard_type`/`rule_name` are
    /// read from `it` (untouched by the worker loop up to this call); `it.seq` is
    /// this item's own admission-time seq, needed both to advance a freshly
    /// recorded loss's `lost_seq` and to decide (Sent case) whether this specific
    /// delivery is allowed to clear an existing gap (#4783 follow-up:
    /// SEQ-GUARDED CLEARING - see the class doc comment).
    ///
    /// Returns the per-loss attribution log decision (#4783 Gate 4 UP-4), same
    /// contract as record_gap_locked's own return - spdlog::level::off for
    /// every non-loss outcome (Sent, LinkDown) below.
    static spdlog::level::level_enum account_outcome_locked(State& st, const Item& it,
                                                             LegacySendOutcome r, bool threw) {
        if (threw) {
            ++st.counters.send_exceptions;
            ++st.counters.events_lost;
            const auto level =
                record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name(), it.seq);
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0;
            }
            return level;
        }
        switch (r) {
        case LegacySendOutcome::Sent:
            // A delivery (real OR repair) clears the gap only if it is STRICTLY
            // NEWER than the most recent loss recorded against this rule - an
            // in-flight item whose seq predates a subsequent loss must not erase
            // evidence of that loss (#4783 follow-up). Otherwise, if this WAS a
            // repair, it completed but was superseded: reset repair_seq (not an
            // erase) so the next kick requeues a fresh repair with current eyes -
            // in practice DEQUEUE-TIME SUPERSESSION (worker_loop) means a
            // superseded repair is normally never sent at all, so this branch is
            // mainly reached by a repair that raced ahead of a loss recorded
            // AFTER it was already dequeued and sending.
            if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end()) {
                if (it.seq > gi->second.lost_seq) {
                    st.gaps.erase(gi); // confirmed delivered, strictly newer than any known loss
                    // #4783 Gate 4 UP-3: a gap CLEAR is the other half of
                    // change_gen's contract (record_gap_locked bumps it on every
                    // LOSS) - a caller comparing generations must see this too,
                    // or a resolved gap would never get persisted away.
                    ++st.change_gen;
                } else if (it.gap_repair) {
                    gi->second.repair_seq = 0;
                }
            }
            break;
        case LegacySendOutcome::WriteFailed: {
            ++st.counters.send_failures;
            ++st.counters.events_lost;
            const auto level =
                record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name(), it.seq);
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0; // retry on the next kick
            }
            return level;
        }
        case LegacySendOutcome::LinkDown:
            ++st.counters.dropped_link_down; // NOT a gap - D4b, today's documented
                                             // pre-network/A3 drop semantics
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0;
            }
            break;
        }
        return spdlog::level::off;
    }

    static void log_send_stall(const std::string& rule_id) {
        try {
            spdlog::warn("Guardian legacy sink send stalled past its threshold "
                         "(rule_id {}); the queue continues, this send stays running "
                         "detached.",
                         rule_id);
        } catch (...) {
        }
    }
    static void log_send_recovery(const std::string& rule_id) {
        try {
            spdlog::info("Guardian legacy sink send (rule_id {}) completed after "
                         "having stalled past its threshold.",
                         rule_id);
        } catch (...) {
        }
    }

    /// #4783 Gate 4 UP-4 de-escalation, part 1 (per-loss attribution log). MUST
    /// be called with state_->mu NOT held, same posture as log_send_stall/
    /// log_send_recovery above - every call site computes `level` (and, if a
    /// test hook is armed, `hook`) under the lock via record_gap_locked/
    /// account_outcome_locked's return value, then calls this AFTER releasing
    /// it. A no-op (does not log, does not invoke `hook`) when
    /// `level == spdlog::level::off` - the common case, every offer()/send
    /// outcome that was not itself a loss. `kind` is always one of the four
    /// static string literals named at this class's loss sites
    /// ("RefusedCapacity"/"RefusedAdmission"/"WriteFailed"/"SendException").
    static void log_loss(const std::string& rule_id, const char* kind,
                         const std::string& event_type, spdlog::level::level_enum level,
                         const LossLogHook& hook) {
        if (level == spdlog::level::off)
            return;
        try {
            if (level == spdlog::level::warn) {
                spdlog::warn("Guardian legacy sink lost an event (rule_id {}, loss_kind {}, "
                             "event_type {}) - first loss recorded for this rule this "
                             "process; see legacy_sink_events_lost/legacy_sink_gap_rules for "
                             "the running totals.",
                             rule_id, kind, event_type);
            } else {
                spdlog::info("Guardian legacy sink lost another event (rule_id {}, loss_kind "
                            "{}, event_type {}) - rate-limited: logged every {}th loss "
                            "recorded for this rule this process.",
                            rule_id, kind, event_type, kLossLogRateLimit);
            }
        } catch (...) {
        }
        if (hook) {
            try {
                hook(rule_id, kind, event_type, level);
            } catch (...) {
            }
        }
    }

    /// The detached worker body. Captures `st` and `ticket` only - never `this`
    /// (this class can be destroyed while a worker is still alive; the orphan-exit
    /// contract is what makes that safe, see the class doc comment).
    static void worker_loop(std::shared_ptr<State> st,
                            std::shared_ptr<AliveTicket> ticket) noexcept {
        const GuardianDetachedWorkerRole role; // first statement
        for (;;) {
            // #4783 adversarial-review finding, 2026-09-24 (non-blocking, folded
            // in): identifying fields for whatever item this iteration pops,
            // captured EARLY (right after the pop, before any later step that
            // can throw - concretely, the in_flight_rule_id copy-assignment
            // below) so the outer catch(...) can still record a best-effort gap
            // for a popped-but-never-accounted item, mirroring offer()'s own
            // early-extraction discipline. `have_unaccounted_item` is true only
            // in the narrow window between the pop and account_outcome_locked()
            // actually running - without this, a throw in that window silently
            // dropped the item with no loss/gap accounting at all, violating
            // this class's own correctness property 1 ("every offered event is
            // delivered exactly once or counted as lost").
            std::string popped_rule_id, popped_guard_type, popped_rule_name, popped_event_type;
            std::uint64_t popped_seq = 0;
            bool have_unaccounted_item = false;
            // Whole-iteration fault boundary: wraps the ENTIRE body, not just the
            // send() call below (which has its own inner try/catch to convert a
            // throw into a counted, accounted outcome rather than an abandoned
            // iteration). Anything else that throws here (e.g. a lock failure) is
            // counted as worker_faults and the loop simply continues.
            try {
                std::unique_lock<std::mutex> lk{st->mu};
                if (st->stopping || st->queue.empty()) {
                    st->worker_running = false;
                    lk.unlock();
                    st->cv.notify_all();
                    break;
                }
                Item it = std::move(st->queue.front());
                st->queue.pop_front();
                st->bytes -= it.bytes;

                // #4783 Gate 3 cpp-safety finding, 2026-09-24: have_unaccounted_item
                // is set FIRST, before any of the capture copies below - each of
                // those four std::string copy-assignments is itself an allocation,
                // hence throw-capable. Setting the flag only AFTER them would
                // reproduce, inside this very fix, the exact defect class it exists
                // to close: an allocation failure during the capture itself would
                // reach the outer catch(...) with the flag still false, and the
                // popped item would be dropped uncounted again. If the very first
                // copy below throws, popped_rule_id (etc.) stay at their
                // default-constructed empty value - the catch's send_exceptions/
                // events_lost counters still increment correctly (the bar
                // correctness property 1 sets), and record_gap_locked() degrades to
                // gap_ledger_faults on an empty rule_id no worse than it already
                // does for any other malformed input; misattribution to an empty
                // rule_id is a lesser, accepted defect next to dropping the loss
                // entirely.
                have_unaccounted_item = true;
                // Test-only: WorkerFaultForTest::ThrowOnFirstCapture fires HERE,
                // before ANY capture - the one case where the catch below has
                // no rule_id to work with, proving its empty-rule_id guard.
                if (st->worker_fault_for_test.load(std::memory_order_relaxed) ==
                    WorkerFaultForTest::ThrowOnFirstCapture)
                    throw std::bad_alloc{};
                // Capture NOW - see this loop's own comment above.
                popped_rule_id = it.rule_id;
                // Test-only: WorkerFaultForTest::ThrowDuringCapture fires HERE,
                // after popped_rule_id but before the remaining fields - the
                // realistic worst case, proving the catch below still accounts
                // the loss (using the rule_id already captured) rather than
                // dropping it.
                if (st->worker_fault_for_test.load(std::memory_order_relaxed) ==
                    WorkerFaultForTest::ThrowDuringCapture)
                    throw std::bad_alloc{};
                popped_guard_type = it.ev.guard_type();
                popped_rule_name = it.ev.rule_name();
                popped_event_type = it.ev.event_type();
                popped_seq = it.seq;

                if (it.gap_repair) {
                    // #4783 follow-up: DEQUEUE-TIME SUPERSESSION - re-validate
                    // THIS repair's seq against the rule's CURRENT gap state,
                    // immediately after popping and BEFORE its send() ever runs
                    // (never after - the whole point is to catch a supersession
                    // that happened while this item sat queued, which checking
                    // only at kick/fire time cannot). Three cases collapse into
                    // the same check: (1) a newer loss advanced lost_seq and this
                    // rule's repair_seq now belongs to a DIFFERENT (later)
                    // repair - only one repair_seq is ever live per rule, offer()
                    // overwrites it rather than appending; (2) a newer repair for
                    // the same rule superseded this one the same way; (3) the gap
                    // was already cleared outright by a fresh real delivery (see
                    // account_outcome_locked's Sent case) either before this
                    // repair was ever stamped as the live repair_seq, or after.
                    // In every case the gap no longer needs THIS item's report -
                    // skip it, never invoke its send(), never account it as any
                    // kind of loss (it was never a real report to begin with).
                    const auto gi = st->gaps.find(it.rule_id);
                    if (gi == st->gaps.end() || gi->second.repair_seq != it.seq) {
                        ++st->counters.repairs_suppressed;
                        have_unaccounted_item = false; // never a real report - not a loss
                        lk.unlock();
                        continue;
                    }
                }

                st->in_flight = true;
                st->in_flight_rule_id = it.rule_id;
                st->send_started_at = std::chrono::steady_clock::now();
                st->stall_logged = false;
                lk.unlock();

                LegacySendOutcome r = LegacySendOutcome::WriteFailed;
                bool threw = false;
                try {
                    r = it.send(it.ev);
                } catch (...) {
                    threw = true;
                }

                lk.lock();
                // Stall check BEFORE clearing in_flight - do NOT copy
                // guardian_outbox_send_executor.hpp's check_stall_locked()
                // verbatim, it early-returns on !in_flight, which would suppress
                // this exact check (see the class doc comment).
                const bool stalled = !st->stall_logged &&
                    (std::chrono::steady_clock::now() - st->send_started_at >=
                     st->stall_threshold);
                if (stalled) {
                    ++st->counters.stalls;
                    st->stall_logged = true;
                }
                const bool recovered = st->stall_logged;
                const auto loss_level = account_outcome_locked(*st, it, r, threw);
                // Accounted for now (whatever loss_level came back - Sent/
                // LinkDown are legitimately spdlog::level::off, not a residual
                // loss) - see this loop's own comment above.
                have_unaccounted_item = false;
                // #4783 Gate 4 UP-4: the test-hook copy, same "under the SAME
                // lock this call already holds, no extra acquisition" posture
                // as offer()'s own two loss sites - only bothers copying it
                // when there is actually something to log.
                LossLogHook loss_hook;
                if (loss_level != spdlog::level::off)
                    loss_hook = st->loss_log_hook_for_test;
                st->in_flight = false;
                lk.unlock();

                if (stalled)
                    log_send_stall(it.rule_id);
                if (recovered)
                    log_send_recovery(it.rule_id);
                // #4783 Gate 4 UP-4: logged OUTSIDE the lock, same as the stall/
                // recovery logs above. `threw` (SendException) and WriteFailed
                // are the only two outcomes account_outcome_locked returns a
                // non-off level for (Sent/LinkDown never lose an event).
                if (loss_level != spdlog::level::off) {
                    const char* kind = threw ? "SendException" : "WriteFailed";
                    log_loss(it.rule_id, kind, it.ev.event_type(), loss_level, loss_hook);
                }
                // `it` (and its SendFn copy) destructs here, before `ticket`.
            } catch (...) {
                auto catch_loss_log_level = spdlog::level::off;
                LossLogHook catch_loss_hook;
                try {
                    std::lock_guard<std::mutex> lk{st->mu};
                    ++st->counters.worker_faults;
                    st->in_flight = false;
                    if (have_unaccounted_item) {
                        // #4783 adversarial-review finding, 2026-09-24: this
                        // item was popped off the FIFO but the throw hit before
                        // account_outcome_locked() ever ran - without this, it
                        // would be silently dropped with no loss/gap accounting
                        // at all (correctness property 1's "exactly once or
                        // counted as lost" is a false statement without it).
                        // Same chokepoint offer()'s own loss sites use.
                        ++st->counters.send_exceptions;
                        ++st->counters.events_lost;
                        // #4783 Gate 4 unhappy-path finding, 2026-09-24: only
                        // open a per-rule gap when popped_rule_id was actually
                        // captured. have_unaccounted_item is set before the
                        // capture copies (see this loop's own comment above)
                        // specifically so a throw can hit DURING them - and if
                        // the throw hits on popped_rule_id's OWN copy (the
                        // first one), popped_rule_id is still its
                        // default-constructed "". record_gap_locked("", ...)
                        // would open a "phantom" gap no real rule can ever
                        // repair (guardian_engine.cpp rejects empty-rule_id
                        // rules at load, so nothing will ever offer a matching
                        // repair for it) - it would enter the normal repair
                        // rotation, get persisted to the restart-durable
                        // snapshot, and because
                        // read_legacy_sink_loss_record() rejects the WHOLE
                        // record as Malformed on any single empty-rule_id
                        // entry, silently discard every OTHER rule's
                        // legitimate open-gap state on the next restart - a
                        // rare local fault amplified into full ledger loss.
                        // The loss is still counted globally
                        // (send_exceptions/events_lost above) either way; this
                        // only withholds per-rule tracking that cannot be
                        // meaningfully attributed with no rule_id to attribute
                        // it to.
                        if (!popped_rule_id.empty()) {
                            catch_loss_log_level = record_gap_locked(
                                *st, popped_rule_id, popped_guard_type, popped_rule_name, popped_seq);
                            if (catch_loss_log_level != spdlog::level::off)
                                catch_loss_hook = st->loss_log_hook_for_test;
                        }
                    }
                } catch (...) {
                }
                // #4783 Gate 4 UP-4: logged OUTSIDE the lock, same rationale as
                // every other loss site in this class.
                if (catch_loss_log_level != spdlog::level::off)
                    log_loss(popped_rule_id, "SendException", popped_event_type,
                             catch_loss_log_level, catch_loss_hook);
            }
        }
        // `role`, then `ticket`, destruct after the loop - the ticket's
        // destructor is the physical retirement point (correctness property 8).
    }

    /// Called from offer()/kick() with state_->mu NOT held. `ticket` is already
    /// ARMED (worker_running was already set to true, under the same locked
    /// block that decided to call this). On a failed launch (spawn_detached
    /// returned false, or threw before/while building the worker closure), rolls
    /// worker_running back to false and counts launch_failures; the queued
    /// backlog is left untouched, so the NEXT offer() of any key or the next
    /// kick() retries (correctness property 3). Never throws.
    ///
    /// `ticket` is captured BY VALUE (copy, not move) into the worker closure -
    /// deliberately, so THIS function keeps its own live reference. On a failed
    /// spawn, the worker closure (and its copy) is destroyed synchronously
    /// inside spawn_detached's own stack frame, UNLOCKED; this function's own
    /// copy is the one that survives to be dropped AFTER the rollback lock_guard
    /// below has already released the lock - never destroying the last live
    /// reference to an armed ticket while this thread holds state_->mu
    /// (correctness property 5).
    void attempt_launch(std::shared_ptr<AliveTicket> ticket) noexcept {
        if (pre_launch_race_hook_for_test_)
            pre_launch_race_hook_for_test_();
        bool launched = false;
        try {
            if (launch_fault_for_test_.load(std::memory_order_relaxed) ==
                LaunchFaultForTest::Throw)
                throw std::bad_alloc{};
            auto st = state_;
            auto worker = [st, ticket]() mutable noexcept { worker_loop(st, std::move(ticket)); };
            launched = (launch_fault_for_test_.load(std::memory_order_relaxed) ==
                        LaunchFaultForTest::SpawnRefused)
                           ? false
                           : io_detail::spawn_detached(std::move(worker));
        } catch (...) {
            launched = false;
        }
        if (!launched) {
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                state_->worker_running = false;
                ++state_->counters.launch_failures;
            } catch (...) {
            }
            // `ticket` (this function's own reference) goes out of scope here,
            // AFTER the lock above has already been released.
        }
    }

    std::shared_ptr<State> state_;
    std::function<void()> pre_launch_race_hook_for_test_; ///< test seam; null = no-op
    std::atomic<LaunchFaultForTest> launch_fault_for_test_{LaunchFaultForTest::None};
};

} // namespace yuzu::agent
