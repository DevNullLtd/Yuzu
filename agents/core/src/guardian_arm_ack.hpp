#pragma once

/**
 * guardian_arm_ack.hpp - rung 9c PR-2 ack bookkeeping (Unit 5: built and
 * tested standalone; Unit 6: wired into the live apply_rules()/heartbeat path).
 * See docs/spark-stage2-guardian-consumer-design.md §R5.3.
 *
 * #5459 (option D): the former K-bound waiver is DELETED. A generation is
 * acknowledged only when the application is genuinely done (can_advance()); an
 * outstanding wedge holds it, honestly, for as long as the arm is hung, so the
 * server's full_sync re-push keeps retrying. The waiver's predicate moved from the
 * ACK gate (can_advance()) to the RETRY gate (decide_retry()): an identical retry
 * whose only unresolved items are outstanding wedges (or wedges with a compensating
 * teardown outstanding, or a wedge whose late success was just adopted and awaits the
 * next tick's recovery scan) is Suppressed instead of paying a full teardown + re-arm.
 *
 * GuardianArmAckLedger tracks ONE outstanding "application" - the set of rules
 * a single apply_rules() push accepted for spark arming
 * (GuardianEngine::ReconcileOutcome::Accepted) - so a heartbeat-bounded drain
 * (§R5.3) can tell whether a generation may advance, and a same-generation
 * full_sync retry can be told apart from a genuinely new or changed push
 * (§R5.3's own duplicate-retry language: "A same-generation re-push ... is a
 * no-op while every outstanding episode for that generation is still
 * genuinely pending ... and only triggers a full re-apply once something has
 * actually failed, expired, or the push's content has changed underneath
 * it"). Most Accepted receipts genuinely have not yet resolved when added -
 * but a re-observed Wedged receipt (rung 9c PR-5c, #4221 up-2) is already
 * terminal the moment it is registered; the ledger does not distinguish the
 * two cases, it just drains whatever each receipt's own status reports.
 *
 * Built and independently tested here in Unit 5; wired into the live path by
 * Unit 6 - reconcile_rule_locked() now calls GuardianSparkRuntime::attach_rule
 * (NonWaiting{}, ...), so ReconcileOutcome::Accepted is genuinely produced in
 * production (see that enum's own doc comment in guardian_engine.hpp).
 * apply_rules() begins/feeds an application, journal_maintenance_tick() drains
 * it every heartbeat, and the generation-hold gate reads can_advance() instead
 * of assuming pending_arms == 0.
 *
 * Deliberately conservative: a receipt that resolves to anything other than
 * Committed holds its application's generation until a genuine recovery (a late
 * success the runtime adopts) or a fresh successful application replaces it,
 * exactly like the pre-PR-2 synchronous behavior. There is no escape hatch: rung
 * 9c PR-5e's K-bound waiver (acknowledge a Wedged-only failure set after K
 * identical re-applies) was removed by #5459 because acknowledging a still-hung
 * arm made the server stop re-pushing, stranding the rule if the arm later failed.
 * §R5.2's ClaimEnd split (queue-wait expiry vs. dispatched timeout vs. genuine
 * refusal) is now used only by decide_retry(), to tell an outstanding wedge (retry
 * Suppressed) from a genuine failure (retry Reapplied) - see decide_retry().
 *
 * One current application, never a history (Astra opine review: "New
 * application: stale receipts cannot acknowledge it"). begin_application()
 * unconditionally replaces whatever was there. A receipt from a superseded
 * application resolving later touches nothing - it is simply no longer in
 * any ledger's pending set. This is safe by construction, not by explicit
 * cancellation: an ArmReceipt is an OBSERVATION handle (its own doc comment)
 * and its KeyClaim is owned entirely by the runtime's own claims_ registry
 * either way - dropping the ledger's copy neither withdraws the rule nor
 * abandons the operation.
 */

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <yuzu/plugin.h>

#include "guardian_arm_heartbeat.hpp" // GuardianArmStats (rung 9c PR-3)
#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::ArmReceipt (nested type - needs the complete class)

namespace yuzu::guardian::v1 {
class GuaranteedStatePush;
} // namespace yuzu::guardian::v1

namespace yuzu::agent {

/// Per-heartbeat-tick bound for GuardianArmAckLedger::drain_locked() (rung 9c PR-2
/// Unit 6), matching guardian_journal_format.hpp's kJournalPersistMaxRecordsPerTick
/// in spirit (bound the one heartbeat-thread caller, never the one-shot callers -
/// there are none for this ledger yet, but the same principle applies if one is
/// ever added). Generous relative to a realistic push size since each entry costs
/// one brief, allocation-free registry_mu_ check, not KV I/O.
inline constexpr std::size_t kAckDrainMaxPerTick = 1024;

/// #5459 (option D): the safety valve on retry suppression. decide_retry() may
/// Suppress an identical retry on account of an outstanding wedge (or a wedge with a
/// compensating teardown outstanding) at most this many times per application, then
/// returns Reapply. A DECISION-count bound, not wall-clock: decide_retry() has one
/// production caller (apply_rules(), driven by the server's push cadence), so at the
/// 30 s heartbeat this is about 330 s (275 s at 25 s spacing). A forced Reapply
/// re-arms every rule in the push (and so reintroduces the #4045 baseline-recapture
/// exposure for Spark-captured, unpersisted baselines) but does NOT unstick the wedged
/// claim - an identical re-observation returns the existing claim. It bounds the
/// dependence on the suppress classification; it is NOT a recovery guarantee against
/// a classifier that misidentifies a dead claim. Reset only by begin_application()
/// and retire().
inline constexpr std::size_t kWedgeSuppressMaxDecisions = 10;

/// Content identity for a push: a rule_id, its enabled flag, enforcement_mode,
/// version, and its spark/assertion/remediation GuardianSpecBlocks (type +
/// params, each params map canonicalized by sorted key - proto's own
/// map<string,string> wire serialization is NOT deterministic, so hashing
/// SerializeAsString() directly would make two byte-identical pushes hash
/// differently depending on hash-map iteration order alone), plus the push's
/// own full_sync flag. Deliberately does NOT read yaml_source: that field is
/// the verbatim, human-authoritative form the agent "never parses" (see the
/// proto's own comment) - the agent's arming behavior is driven entirely by
/// the structured blocks, so a yaml_source-only edit that leaves every
/// structured block unchanged must not be treated as a content change here.
/// Two pushes with identical content (by this definition) hash identically
/// regardless of process, restart, or map iteration order.
YUZU_EXPORT std::string guardian_push_content_id(const yuzu::guardian::v1::GuaranteedStatePush& push);

/// Human-readable rendering of a ReceiptStatus, for drain_locked()'s own async-
/// failure warn line (the only place a non-Committed resolution is logged - see
/// that call site's own comment). Exported (unlike an internal helper) so a
/// direct unit test can assert the full mapping without LogCapture - governance
/// follow-up (Gate 4, happy-path + unhappy-path, 2026-09-16): the LogCapture-
/// based assertions this function's naming previously relied on were removed
/// (cross-image hazard, see resolved_statuses_for_test()'s own doc comment)
/// without anything replacing their incidental coverage of this mapping.
/// Exhaustive switch, no `default` (its own definition's comment has the full
/// rationale) - a missing case is a build WARNING, not a silent "Unknown".
YUZU_EXPORT const char* receipt_status_name(GuardianSparkRuntime::ReceiptStatus status);

class YUZU_EXPORT GuardianArmAckLedger {
public:
    GuardianArmAckLedger();
    ~GuardianArmAckLedger();

    GuardianArmAckLedger(const GuardianArmAckLedger&) = delete;
    GuardianArmAckLedger& operator=(const GuardianArmAckLedger&) = delete;

    /// Starts tracking a new application, discarding whatever the previous one
    /// still had pending (see the file header: no history, no carry-over).
    /// `content_id` is a caller-computed identity over the push's actual rule
    /// contents plus its full_sync flag (a generation number alone is not
    /// content identity - two different pushes can share one; see the design
    /// doc's own "unordered-map-dependent protobuf byte string alone is
    /// insufficient" warning about naive serialization of a rule's
    /// map<string,string> spark params). `applied` is the count the caller's
    /// own apply_rules() already computed for this push - stashed so a
    /// Suppress decision (decide_retry(), below) can hand it straight back
    /// without recomputing anything. Known limit of the delta-push case (a partial push
    /// that omits an unresolved rule drops that rule's retry obligation, because this
    /// replaces the open application wholesale): design doc R5.3 known limits, flip-gate
    /// AC-11.
    void begin_application(std::uint64_t generation, std::string content_id, bool full_sync,
                           std::size_t applied);

    /// Add one rule's accepted arm to the current application - USUALLY still
    /// unresolved, but a re-observed Wedged receipt (rung 9c PR-5c, #4221
    /// up-2) is already terminal at this call; drain_locked() resolves it on
    /// its very next tick either way. Caller's responsibility: only ever
    /// called for a rule_id reconcile_rule_locked mapped to
    /// ReconcileOutcome::Accepted, for the application currently open (i.e.
    /// after begin_application() for this push - never across a push
    /// boundary, and never with no current application). A no-op (logged, not
    /// asserted - this is bookkeeping, not a safety property) if called with
    /// no current application.
    void add_pending(std::string rule_id, GuardianSparkRuntime::ArmReceipt receipt);

    /// Mark the current application as having hit one of apply_rules()'s
    /// existing generation-hold failures (the kv sweep failure, a del_keys
    /// undercount, a full_sync teardown throw, a put_rule_locked failure) -
    /// these are orthogonal to any single rule's own arm outcome, so they
    /// cannot be expressed as a receipt. A no-op if there is no current
    /// application.
    /// noexcept: GuardianEngine::note_boot_rearm_failure_locked() (noexcept) calls this, so it
    /// must never throw (the body is a pointer test and a bool store).
    void latch_failure() noexcept;

    /// Expected to be called with the caller's own engine lock held, matching
    /// journal_maintenance_tick()'s own posture - this call does not take any
    /// lock of its own beyond what `runtime`'s public API already takes
    /// internally (registry_mu_, briefly, allocation-free). Sweeps
    /// runtime.expire_overdue_claims() first (rung 9c PR-2 Unit 2's own
    /// deferred "later by Unit 5's tick"), then resolves up to `max_per_tick`
    /// of the current application's still-pending receipts via
    /// runtime.receipt_status(). A no-op (returns 0) if there is no current
    /// application. Returns the number of receipts resolved THIS call (tests
    /// / diagnostics only - bounded draining is otherwise silent).
    ///
    /// The bound is on how many receipts RESOLVE this call, not how many are
    /// examined - every still-pending receipt is checked every call (one
    /// brief, allocation-free receipt_status() each; unlike the lifecycle
    /// journal's own bounded drain, there is no KV I/O here to bound, and
    /// std::map has no resume cursor to page through anyway), so a large
    /// pending set costs a scan, never a stall. This is also why
    /// decide_retry() re-checks `runtime` directly rather than trusting
    /// resolved_failed alone: a receipt beyond this call's max_per_tick cap
    /// can still be sitting in `pending`, already resolved, uncounted.
    ///
    /// `failed_out`, if non-null, is INCREMENTED (never reset) by the number of
    /// receipts THIS call resolved to non-Committed - governance finding UP-3
    /// (Gate 4, unhappy-path): an async arm failure used to update only this
    /// ledger's own internal `resolved_failed` and a local log line, never the
    /// cumulative `arm_failures_` counter a synchronous refusal already did
    /// (that counter has no production reader today, so it is not fleet-visible;
    /// tracked by #4062). The caller (GuardianEngine::journal_maintenance_tick()) folds
    /// this into `arm_failures_` itself - the ledger has no engine pointer of its
    /// own and must not gain one.
    std::size_t drain_locked(GuardianSparkRuntime& runtime, std::size_t max_per_tick,
                             std::size_t* failed_out = nullptr);

    /// True iff there IS a current application, it has nothing left pending,
    /// nothing latched, and nothing resolved to a (still-counted) failure. #5459
    /// (option D): there is NO wedge escape any more - an outstanding wedge, a
    /// compensation-pending wedge, and every ordinary failure all hold the
    /// generation until a genuine recovery decrements resolved_failed (the runtime
    /// adopted a late success) or a fresh successful application replaces this one.
    /// False, not vacuously true, when there is no current application at all
    /// (nothing to advance FOR is not the same question as "may advance").
    ///
    /// A current application with an EMPTY pending map because add_pending()
    /// was simply never called (every rule this push resolved synchronously -
    /// Armed or Inert, nothing Accepted) trivially returns true here, matching
    /// today's pending_arms == 0 behavior exactly - this is the common case,
    /// not a gap. The design doc's own "Zero-accepted push ... does NOT
    /// advance vacuously" warning is about a DIFFERENT thing: a rule refused
    /// AT ADMISSION (ReconcileOutcome::Failed), which is counted by
    /// apply_rules()'s own pre-existing reconcile_failures gate and never
    /// reaches this ledger as a receipt at all. What THIS ledger must never
    /// do vacuously is call an application done when a receipt it WAS given
    /// resolved to anything other than Committed - that is resolved_failed,
    /// checked above, independent of whether pending is empty.
    bool can_advance() const;

    /// The `applied` count stashed at begin_application() time (or updated by
    /// set_applied(), below). Valid only when there is a current application;
    /// 0 otherwise.
    std::size_t applied_count() const;

    /// TEST-ONLY: the current application's still-pending receipt count (0 if there
    /// is no current application). Lets a test settle on "every accepted arm from
    /// the last push has resolved" without a production accessor of its own -
    /// GuardianEngine::ack_pending_count_for_test() forwards to this. No production
    /// caller.
    std::size_t pending_count_for_test() const;

    /// TEST-ONLY: the current application's retained outstanding-wedge count
    /// (eligible or compensation-pending; 0 if there is no current application) -
    /// see Application::failed_receipts and
    /// drain_locked()'s own arm-recovery scan (rung 9c PR-5d, concern 2). Lets a
    /// test settle on "the recovery scan has cleared every rule it is going to"
    /// without a production accessor. No production caller.
    std::size_t failed_receipt_count_for_test() const;

    /// TEST-ONLY: every non-Committed ReceiptStatus this application's receipts
    /// have resolved to via drain_locked() - i.e. the same failure-group values
    /// receipt_status_name() would render into the log line this accessor
    /// replaces (Committed receipts increment resolved_armed instead and are
    /// never pushed here). In drain order (std::map key order within one
    /// drain_locked() call, call order across several - NOT the chronological
    /// order the underlying claims actually resolved in at runtime); empty if
    /// there is no current application. Plain object state, not captured log
    /// text - a captured-log
    /// assertion is unreliable here because drain_locked()'s own logging call is
    /// compiled into libyuzu_agent_core, a SEPARATE shared library from the test
    /// binary on macOS: the default-logger swap test_log_capture.hpp performs
    /// happens in the test binary's own image and does not reach spdlog calls
    /// made from the library's image there (see that header's own doc comment -
    /// the same class of hazard already forced #2238's LogCapture use out of
    /// this codebase once, tracked unfixed for a second instance as #3355; this
    /// accessor exists so a third never needs LogCapture at all). No production
    /// caller.
    std::vector<GuardianSparkRuntime::ReceiptStatus> resolved_statuses_for_test() const;

    /// rung 9c PR-3: a re-statable snapshot of the current application's pending
    /// and resolved-failed counts (see guardian_arm_heartbeat.hpp's
    /// GuardianArmStats for the full field-by-field semantics). nullopt when there
    /// is no current application (governance fix, adversarial review: the settled
    /// KICKOFF-v2 Decision-1 interface signature, and the CALLER - GuardianEngine::
    /// arm_stats() - still layers its OWN prefer_spark_/stopped_/spark_availability_
    /// dormancy gate on top; this ledger still has no notion of prefer_spark_ and
    /// must not gain one, it only reports whether IT has an application). A LIVE,
    /// EMPTY application (begin_application() called, add_pending() never - every
    /// accepted rule resolved synchronously) is a real, present {0, 0} - the common
    /// case, not the same as no application at all. Production caller:
    /// GuardianEngine::arm_stats(), called under mtx_ like every other
    /// engine-owned accessor.
    [[nodiscard]] std::optional<GuardianArmStats> arm_stats() const;

    /// rung 9c PR-2 Unit 6: apply_rules() calls begin_application() BEFORE its
    /// per-rule loop (so reconcile_rule_locked's add_pending() calls during
    /// that loop land in the right application) but does not know the real
    /// applied count until the loop finishes - this updates it afterward, so
    /// a later same-generation Suppress decision hands back the true count
    /// rather than begin_application()'s placeholder. A no-op if there is no
    /// current application.
    void set_applied(std::size_t applied);

    /// The generation the current application is FOR (0 if there is none) -
    /// what journal_maintenance_tick() compares against policy_generation_
    /// before advancing it once can_advance() is true.
    std::uint64_t pending_generation() const;

    enum class RetryDecision { Suppress, Reapply };

    /// Whether an incoming push matching (generation, content_id, full_sync)
    /// against the CURRENT application is a genuine same-generation retry
    /// that can be skipped (Suppress), or must be treated as new work
    /// (Reapply). Reapply when there is no current application; when generation,
    /// content_id or full_sync differ; when either content_id is not a real 64-hex
    /// SHA-256 digest (a sentinel is never trusted as a match, even against an
    /// identical sentinel); when the application latched a failure; when any
    /// counted failure has no retained outstanding-wedge receipt (a genuine
    /// non-wedge failure, drained or not); and when nothing is outstanding at all
    /// (an application with no pending receipts and no outstanding wedge - this
    /// preserves the failed-generation-persist retry, sec-1/arch-1: Suppressing with
    /// nothing in flight swallowed the one thing apply_rules()'s tail gate still
    /// needed to do on a repeat push).
    ///
    /// #5459 (option D): OUTSTANDING WORK no longer forces Reapply. Every counted failure
    /// is re-read from `runtime` NOW through the ONE combined accessor
    /// receipt_recovery_status() (never trusted from the retained map, never assembled from
    /// two calls) and is outstanding when it is WedgeEligible (the arm is still hung),
    /// CompensationPending (the late result returned, a compensating teardown is
    /// outstanding) or Recovered (the late success was ADOPTED after the last drain, so the
    /// rule just armed and the next drain's recovery scan has yet to clear its
    /// resolved_failed; tearing it down now would undo the recovery). Only Blocking (the
    /// claim ended without recovery) forces Reapply. Every pending receipt must be
    /// Pending/Committed or a live outstanding wedge not yet drained. If so the retry is
    /// Suppressed up to kWedgeSuppressMaxDecisions times per application (a Recovered
    /// entry spends the budget like any other Suppress), then Reapply. When a wedged claim
    /// pops WITHOUT recovery (a late failure, a finished compensation) the live check stops
    /// holding and the next push is a Reapply, so the rule re-arms. Suppression NEVER
    /// acknowledges anything: the generation stays held (can_advance() has no wedge
    /// escape); a Recovered entry is acknowledged only by the next tick's recovery scan
    /// clearing resolved_failed.
    ///
    /// Not const: the Suppress-on-wedge branch increments
    /// Application::wedge_suppress_count. `runtime` is read via
    /// receipt_recovery_status() (retained failures) and receipt_status_wedge_aware()
    /// (pending receipts), each taking its own brief registry_mu_ internally. Call it under
    /// the same engine lock as drain_locked(). Calling it after drain_locked() is not
    /// required for correctness: every read of `runtime` is live, so a count a
    /// drain has not caught up with yet is always resolved by the live re-read (the one
    /// production caller, GuardianEngine::apply_rules(), does not drain first).
    ///
    /// `runtime` is consulted directly, not just `resolved_failed`, because
    /// drain_locked() is BOUNDED: a receipt past one tick's max_per_tick cap
    /// can sit in `pending` long after it actually resolved (to Failed or
    /// anything else), and Suppress must mean "every pending receipt is
    /// still genuinely Pending or an outstanding wedge" - not merely
    /// "drain_locked hasn't gotten to it yet".
    [[nodiscard]] RetryDecision decide_retry(std::uint64_t generation,
                                             const std::string& content_id, bool full_sync,
                                             const GuardianSparkRuntime& runtime);

    /// Stop-time: drop the current application without resolving it further.
    /// Its receipts' claims remain the runtime's own problem exactly as
    /// §R5.5 already describes (in-flight workers finish on their own
    /// schedule after stop() returns; a late-arriving success is disarmed
    /// rather than left live) - dropping the ledger's observation handles
    /// changes none of that. Idempotent.
    void retire();

private:
    struct Application {
        std::uint64_t generation{0};
        std::string content_id;
        bool full_sync{false};
        std::size_t applied{0};
        bool latched_failure{false};
        std::size_t resolved_armed{0};
        std::size_t resolved_failed{0};
        std::map<std::string, GuardianSparkRuntime::ArmReceipt> pending;
        std::vector<GuardianSparkRuntime::ReceiptStatus> resolved_statuses_for_test;
        /// rung 9c PR-5d (concern 2, arm-recovery): rule_id -> the receipt drain_
        /// locked() resolved to Wedged, retained (NOT the other failure statuses -
        /// nothing else can spontaneously become committed later) so a LATER
        /// drain_locked() call can notice via GuardianSparkRuntime::
        /// receipt_recovery_status() (rung 9c PR-5e's atomic accessor - see below)
        /// that the runtime has since adopted it (rung 9c PR-5d's own concern 1)
        /// and clear its contribution to resolved_failed -
        /// scoped to THIS application's own bookkeeping only: begin_application()/
        /// retire() replace `current_` wholesale (see the file header), so a
        /// receipt whose application was superseded before recovering is simply
        /// gone, same as every other per-application field here. This is NOT the
        /// durable, cross-application "last known outcome for every currently-
        /// desired rule" gauge - deliberately unbuilt (rung 9c PR-5e, #4221's own
        /// "Explicit narrowing": docs/spark-stage2-guardian-consumer-design.md's
        /// R5.3 stamp), not a silent drop.
        ///
        /// #5459 (option D): membership means "currently an OUTSTANDING wedge" -
        /// either still hung (Eligible) or with a compensating teardown outstanding
        /// (CompensationPending); an adopted late success (Recovered) is also outstanding
        /// work until the recovery scan erases it - and is re-validated every drain tick
        /// against GuardianSparkRuntime::receipt_recovery_status(). An entry that has since
        /// settled to Blocking (a Dispatching-window race corrected to a genuine
        /// Failed/Stopped/AdmissionRejected outcome, or the claim was popped from its
        /// key's FIFO by a real completion nobody adopted) is dropped from this map
        /// WITHOUT decrementing resolved_failed: it is still a genuine, counted
        /// failure, just no longer an outstanding wedge. So
        /// `resolved_failed == failed_receipts.size()` means "every counted failure
        /// has a retained retry-deferral candidate", a NECESSARY condition for
        /// decide_retry()'s wedge Suppress - never sufficient (each entry is
        /// re-read live) and never an acknowledgment gate.
        std::map<std::string, GuardianSparkRuntime::ArmReceipt> failed_receipts;
        /// #5459 (option D): how many times decide_retry() has returned Suppress on
        /// account of an outstanding wedge for THIS application. Bounded by
        /// kWedgeSuppressMaxDecisions (the safety valve); incremented only on that
        /// branch; reset only by begin_application()/retire() (this struct is
        /// replaced wholesale), never by a drain or a sibling's recovery.
        std::size_t wedge_suppress_count{0};
    };
    std::unique_ptr<Application> current_;
};

} // namespace yuzu::agent
