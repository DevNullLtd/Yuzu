#pragma once

/**
 * guardian_arm_ack.hpp - rung 9c PR-2 ack bookkeeping (Unit 5: built and
 * tested standalone; Unit 6: wired into the live apply_rules()/heartbeat path).
 * See docs/spark-stage2-guardian-consumer-design.md §R5.3.
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
 * Deliberately conservative and pre-K-bound at rung 9c PR-2's own original
 * scope: a receipt that resolves to anything other than Committed held its
 * application's generation FOREVER, exactly like the pre-PR-2 synchronous
 * behavior - no wedge marking, no K-bound retry-then-waive. §R5.2's ClaimEnd
 * preserved the finer split a later rung 9c PR needed to implement that
 * (queue-wait expiry vs. dispatched timeout vs. genuine refusal); this
 * ledger did not need it and did not re-derive it here.
 *
 * As implemented (rung 9c PR-5e, #4221, K-bound closeout, decision 1): that
 * FOREVER hold now has exactly one carve-out, scoped narrowly to the Wedged
 * subset ClaimEnd's split makes expressible - see can_advance()'s own doc
 * comment and Application::reapply_count/failed_receipts for the mechanism.
 * A CongestionExpired/Withdrawn/Stopped/plain-Failed receipt, or a latched
 * application-level failure, still holds the generation forever exactly as
 * this paragraph originally described - K is a Wedged-only escape hatch, not
 * a change to that conservative default.
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

/// rung 9c PR-5e (#4221, K-bound closeout, decision 1): the number of
/// identically-re-applied generations (§R5.3's own "three identical same-generation
/// re-applies") a Wedged-only failure set may be waived after. A single shared
/// saturating counter per application-sequence - NOT per-rule credit (a rule that only
/// wedges on the 2nd re-apply can still ride the sequence's existing count to waiver on
/// the 3rd; see Application::reapply_count's own doc comment) - matching the master
/// plan's recorded decision and R5.3's literal phrasing exactly.
inline constexpr std::size_t kReapplyWaiverThreshold = 3;

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
    /// without recomputing anything.
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
    void latch_failure();

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
    /// durable fleet-visible `arm_failures_` counter a synchronous refusal
    /// already did. The caller (GuardianEngine::journal_maintenance_tick()) folds
    /// this into `arm_failures_` itself - the ledger has no engine pointer of its
    /// own and must not gain one.
    std::size_t drain_locked(GuardianSparkRuntime& runtime, std::size_t max_per_tick,
                             std::size_t* failed_out = nullptr);

    /// True iff there IS a current application, it has nothing left pending,
    /// nothing latched, and either nothing resolved to a failure OR (rung 9c
    /// PR-5e, #4221, K-bound closeout, decision 1) every resolved failure is a
    /// still-genuinely-outstanding Wedged episode (Application::failed_receipts,
    /// kept pruned to exactly that set every drain tick - see its own doc
    /// comment) AND this application-sequence has been identically re-applied
    /// at least kReapplyWaiverThreshold times (Application::reapply_count). A
    /// non-Wedged failure (CongestionExpired/Withdrawn/Stopped/plain Failed, or
    /// a Wedged entry whose eligibility has since settled to false) NEVER
    /// waives, no matter how high reapply_count climbs - K is scoped to the
    /// Wedged-only subset, never a generation-wide liveness bound (R5.3's own
    /// framing). False, not vacuously true, when there is no current
    /// application at all (nothing to advance FOR is not the same question as
    /// "may advance").
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

    /// TEST-ONLY: the current application's retained-Wedged-failure count (0 if
    /// there is no current application) - see Application::failed_receipts and
    /// drain_locked()'s own arm-recovery scan (rung 9c PR-5d, concern 2). Lets a
    /// test settle on "the recovery scan has cleared every rule it is going to"
    /// without a production accessor. No production caller.
    std::size_t failed_receipt_count_for_test() const;

    /// TEST-ONLY: the current application's reapply_count (0 if there is no current
    /// application) - rung 9c PR-5e (#4221, K-bound closeout, decision 1). No
    /// production caller; can_advance() reads Application::reapply_count directly.
    std::size_t reapply_count_for_test() const;

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
    /// (Reapply) - a different generation, changed content under the same
    /// generation number, or an application that has already seen a failure
    /// (latched or a resolved receipt). Reapply when there is no current
    /// application at all - nothing to suppress against - AND, critically
    /// (Gate 8 doc-currency fix; see the .cpp's own longer comment and
    /// docs/spark-stage2-guardian-consumer-design.md's R5.3 correction),
    /// whenever `pending` is EMPTY: this dedup exists only to protect a
    /// claim that is genuinely still in flight, and Suppressing with nothing
    /// in flight is what let a failed persist_generation_locked() write go
    /// unretried forever (sec-1/arch-1). A content_id that is not a real
    /// 64-hex-char SHA-256 digest (a sentinel, never a real hash) is also
    /// never trusted as a match, even against an identical sentinel from a
    /// different push. Never mutates
    /// state (a query only - `runtime` is read via receipt_status(), which
    /// takes its own brief registry_mu_ internally); call this AFTER
    /// drain_locked() so a receipt that resolved this tick is reflected.
    ///
    /// `runtime` is consulted directly, not just `resolved_failed`, because
    /// drain_locked() is BOUNDED: a receipt past one tick's max_per_tick cap
    /// can sit in `pending` long after it actually resolved (to Failed or
    /// anything else), and Suppress must mean "every pending receipt is
    /// still genuinely Pending" - not merely "drain_locked hasn't gotten to
    /// it yet". This scan is what makes that true without drain_locked
    /// itself needing an unbounded pass first.
    RetryDecision decide_retry(std::uint64_t generation, const std::string& content_id,
                               bool full_sync, const GuardianSparkRuntime& runtime) const;

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
        /// rung 9c PR-5e (#4221, K-bound closeout): also re-validated every drain
        /// tick against GuardianSparkRuntime::receipt_recovery_status() (see that
        /// accessor's own doc comment) - an entry whose eligibility has since
        /// settled to false (a Dispatching-window race corrected to a genuine
        /// Failed/Stopped/AdmissionRejected outcome, or the claim was popped from
        /// its key's FIFO by a real completion) is dropped from this map WITHOUT
        /// decrementing resolved_failed: it is still a genuine, counted failure,
        /// just no longer part of the Wedged-only subset K may waive. This keeps
        /// `resolved_failed == failed_receipts.size()` a SAFE K-waiver predicate -
        /// membership here means "currently, genuinely, still-outstanding Wedged",
        /// never a stale or since-corrected classification.
        std::map<std::string, GuardianSparkRuntime::ArmReceipt> failed_receipts;
        /// rung 9c PR-5e (#4221, K-bound closeout, decision 1): a saturating count
        /// (capped at kReapplyWaiverThreshold) of how many times THIS EXACT
        /// application identity - (generation, content_id, full_sync), the same
        /// comparison decide_retry() already uses - has been established in a row
        /// via begin_application(). A single shared counter per application-
        /// SEQUENCE, not per-rule credit: a rule that only wedges on the 2nd
        /// identical reapply can still ride the sequence's existing count to
        /// waiver on the 3rd (the master plan's own recorded decision 1). Carried
        /// forward by begin_application() ONLY on an exact identity match against
        /// the OUTGOING application; reset to 0 on any distinct generation,
        /// content_id, full_sync, an invalid (non-SHA-256) digest on either side,
        /// or when there was no prior application at all. can_advance() is the
        /// sole production reader.
        std::size_t reapply_count{0};
    };
    std::unique_ptr<Application> current_;
};

} // namespace yuzu::agent
