#pragma once

/**
 * guardian_engine.hpp — Agent-side engine for the Yuzu Guardian (Guaranteed
 * State) policy loop. See docs/yuzu-guardian-design-v1.1.md.
 *
 * The engine accepts push_rules / get_status commands over the `__guard__`
 * dispatch hook, persists rule state into the agent's KvStore under the
 * reserved namespace "__guardian__", and arms one on-box IGuard per enabled
 * rule (File / Registry / Windows-Service / systemd). ADR-0021 rung 7 wires an
 * alternate SparkEngine-backed detection path (GuardianSparkRuntime,
 * guardian_spark_runtime.hpp) alongside the legacy IGuard path; a per-rule
 * reconcile op selects exactly one, never both.
 *
 * Two-phase startup (design §4 — pre-login activation):
 *   start_local()        — open persistent state, load cached rules;
 *                          safe to call before the Register RPC.
 *   sync_with_server()   — mark the engine network-connected; a future PR
 *                          will drain the buffered-event queue here.
 */

#include <yuzu/plugin.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <yuzu/agent/guard.hpp>  // IGuard, GuardDrift (guard abstraction)
#include <yuzu/agent/spark.hpp> // SparkType (for the classify() capability set)

namespace yuzu::agent {
class KvStore;
}

namespace yuzu::guardian::v1 {
class GuaranteedStatePush;
class GuaranteedStateRule;
class GuaranteedStateStatus;
class GuaranteedStateEvent;
} // namespace yuzu::guardian::v1

namespace yuzu::agent::v1 {
class CommandRequest;
} // namespace yuzu::agent::v1

// Forward-declared rather than #include-d: these live under agents/core/src/
// (agent-internal implementation headers), and no header under
// agents/core/include/yuzu/agent/ has ever crossed that boundary - this stays
// consistent. Only used here as std::function<SendResult(const OutboxEntry&)> /
// std::function<LegacySendOutcome(const GuaranteedStateEvent&)> (EventSink, #4783)
// parameter types, which do not need complete types to declare (only to call) -
// an enum class with a fixed underlying type is itself a complete type once
// forward-declared this way, so LegacySendOutcome can appear by value in EventSink.
namespace yuzu::agent {
class SparkEngine;
class GuardianSparkRuntime;
class GuardianArmAckLedger;
class ConvergenceScheduler;
class GuardianOutboxDrainWorker;
class GuardianLifecycleJournal;
struct GuardianJournalStats;
struct GuardianJournalAgeStats;
struct GuardianArmStats;
class GuardianStateReader;
class GuardianSparkEngineBackend;
class GuardianLegacySinkExecutor;
struct OutboxEntry;
enum class SendResult;
enum class LegacySendOutcome : std::uint8_t;
} // namespace yuzu::agent

namespace yuzu::agent {

// Whether GuardianEngine::WorkerHostileMutex actually ENFORCES (aborts) rather than
// compiling away. Defined here, not in the .cpp, so a test can skip instead of hanging on a
// build where the guard is absent: without it a violating worker deadlocks, which to a test
// harness is indistinguishable from a hang.
#if defined(__has_feature)
#  if __has_feature(thread_sanitizer) || __has_feature(address_sanitizer)
#    define YUZU_WORKER_MUTEX_GUARD 1
#  endif
#endif
#if !defined(NDEBUG) || defined(__SANITIZE_THREAD__) || defined(__SANITIZE_ADDRESS__) || \
    defined(YUZU_FORCE_WORKER_MUTEX_GUARD)
#  define YUZU_WORKER_MUTEX_GUARD 1
#endif

/// True iff taking GuardianEngine::mtx_ on a thread stop() joins, or on a detached
/// GuardianIoExecutor worker (rung 9c R5.1), aborts the process.
[[nodiscard]] constexpr bool worker_mutex_guard_enabled() noexcept {
#ifdef YUZU_WORKER_MUTEX_GUARD
    return true;
#else
    return false;
#endif
}

/// Result of dispatching a `__guard__` command. The caller (agent.cpp)
/// converts this into a CommandResponse on the bidi stream.
struct GuardianDispatchResult {
    int exit_code{0};                 ///< 0 = success, non-zero = failure
    std::string output;               ///< payload — serialized proto on success, error detail otherwise
    std::string content_type;         ///< "proto" for SerializeAsString output, "text" otherwise
};

/// Engine lifecycle and dispatch surface. PR 2 scope: persist rules,
/// answer status queries, ignore everything else. Thread-safe — the
/// internal mutex serialises apply_rules / dispatch / get_status.
class YUZU_EXPORT GuardianEngine {
public:
    /// The immutable, set-once outcome of wire_spark_engine() - never a
    /// mutable runtime toggle (rung 7: Sol's rev-1 review explicitly rejected
    /// a test-only mutable setter for the spark-vs-legacy decision; this is a
    /// constructor-time parameter instead, see `prefer_spark` below).
    ///   Unwired       - wire_spark_engine() has not yet run (the member-
    ///                   initializer default). A programming fault if
    ///                   reconcile ever observes it with prefer_spark true -
    ///                   NEVER silently falls back to legacy.
    ///   SparkDisabled - --spark-disable: a deliberate kill-switch. Legacy is
    ///                   the CORRECT, expected path here, not a fallback.
    ///   SparkFailed   - spark_engine_ failed to boot, OR this engine's own
    ///                   wiring sequence failed after that (consumer
    ///                   registration, scheduler start). NEVER falls back to
    ///                   legacy - a failure must be visible (errored via
    ///                   get_status()'s existing fail-closed behaviour), not
    ///                   silently absorbed (the mutual-exclusion invariant).
    ///   Available     - the spark path is wired and could run: spark_runtime_ is
    ///                   live and the reconcile op classifies per-rule from here.
    ///                   The convergence scheduler + drain worker are CONSTRUCTED
    ///                   but STARTED only when prefer_spark_ is set (rung 7.7b) -
    ///                   at prefer_spark_=false nothing places on spark, so their
    ///                   threads would be pure overhead; see wire_spark_engine().
    enum class SparkAvailability { Unwired, SparkDisabled, SparkFailed, Available };

    /// The KvStore pointer may be null at construction (e.g. KV open
    /// failed). All subsequent methods degrade to soft failures with
    /// error strings rather than crashing — matches the agent's
    /// existing "KV unavailable is a warning, not a fatal" posture.
    ///
    /// `prefer_spark`: whether the reconcile op ATTEMPTS the spark path at
    /// all when wire_spark_engine() later reports Available. IMMUTABLE for
    /// this object's lifetime (a constructor parameter, not a setter) - rung
    /// 7 ships with every production agent.cpp call site passing the literal
    /// `false` (legacy stays the observable default); rung 12's "default
    /// flip" changes that one literal. Tests pass `true` to exercise the
    /// spark path.
    GuardianEngine(KvStore* kv, std::string agent_id, bool prefer_spark = false);
    ~GuardianEngine();

    GuardianEngine(const GuardianEngine&) = delete;
    GuardianEngine& operator=(const GuardianEngine&) = delete;

    /// Phase 1 startup (pre-network). Loads cached rules from KvStore
    /// into the in-memory count cache so get_status() is cheap.
    ///
    /// #4783 Gate 4 UP-3/UP-4: also restores legacy_sink_executor_'s loss
    /// ledger (counters + open-gap snapshots) from a prior process, if one was
    /// persisted (see legacy_sink_kick()/stop()) - STRICTLY BEFORE the rule
    /// re-arm loop below, so a restored gap is already visible before the
    /// first guard thread (or the first post-boot legacy_sink_kick()) can
    /// reach the executor. An absent/malformed/schema-mismatched record
    /// self-heals (logged, skipped, boot proceeds) - same posture as a
    /// corrupt/absent #4021 baseline record.
    std::expected<void, std::string> start_local();

    /// Phase 2 startup (post-Register). No-op in PR 2 — PR 4 uses this
    /// to drain a buffered-events queue over the command stream.
    void sync_with_server();

    /// Periodic durable-journal maintenance, driven by the agent heartbeat (item 7 PR-Ag).
    /// SINGLE-PHASE since C0 (#2298 gate 1): under mtx_, retry any persist a prior write left
    /// pending - this is what makes a failed write self-heal with NO new push/reconnect (Sol
    /// BLOCKER-4). Retention prune + replay paging (the old off-mtx_ phase 2) moved to the
    /// drain worker so neither can stall the heartbeat on a contended KvStore.
    /// prefer_spark_-gated; a no-op after stop(). Safe to call every heartbeat.
    void journal_maintenance_tick();

    /// #4783 commit 4: legacy-sink loss VISIBILITY, driven by the agent heartbeat
    /// alongside journal_maintenance_tick() above but DELIBERATELY NOT sharing its
    /// gate — journal_maintenance_tick() no-ops when `!prefer_spark_` (it drives
    /// spark-only maintenance passes), whereas legacy_sink_executor_ is the LIVE
    /// production path regardless of the flip (prefer_spark_ defaults false; see
    /// the Spark row in routed-concerns.md), so its own loss-repair path MUST run
    /// unconditionally. Not gated behind mtx_ either: (1) legacy_sink_executor_->
    /// kick() relaunches a stranded worker and observes a quiet-queue stall, using
    /// only the executor's own internal lock; (2) gap repair — for up to
    /// kMaxGapRepairsPerKick sticky integrity gaps (gapped_rules_needing_repair())
    /// not already mid-repair (GapRecord::repair_seq != 0), synthesizes a
    /// guard.unhealthy report (kLegacySinkDeliveryGapDetail, a fixed short
    /// constant) via emit_guard_event(..., is_gap_repair=true, gap.last_lost) —
    /// which itself takes only sink_mtx_, then the executor's own lock, exactly
    /// like a real guard's own emission, EXCEPT this call also passes the gap's
    /// `last_lost` as the event's timestamp override (#4783 follow-up review,
    /// part (c) — never the kick's own wall-clock `now`; a real verdict delivered
    /// between two losses is legitimately older than the SECOND loss and should
    /// still be overwritten by a repair covering that second loss, which stamping
    /// with `now` instead of `last_lost` would otherwise let a stale repair do to
    /// a NEWER, already-delivered real verdict, via the server's own
    /// `updated_at >=` upsert guard — belt-and-braces alongside the executor's own
    /// seq-guarded clearing and dequeue-time supersession check, see
    /// guardian_legacy_sink_executor.hpp's class doc comment). The server's
    /// census goes fail-closed (errored) for a gapped rule until either the
    /// repair is confirmed delivered or the rule's next real verdict clears it
    /// (same-or-newer timestamp `>=` ordering — D11's "first verdict clears"
    /// semantics, docs/spark-legacy-delta-registry.md); locally, the executor's
    /// own gap ledger can ALSO be cleared by that same next real verdict, before
    /// any repair for it is ever dispatched — see
    /// guardian_legacy_sink_executor.hpp's SEQ-GUARDED CLEARING section. noexcept:
    /// runs on the bare heartbeat thread (agent.cpp), same posture as
    /// journal_maintenance_tick()'s own firewalling.
    ///
    /// #4783 Gate 4 UP-3/UP-4: AFTER the repair-dispatch loop above (own
    /// try/catch), also persists legacy_sink_executor_'s loss ledger
    /// (counters + open-gap snapshots - GuardianLegacySinkExecutor::Snapshot)
    /// to KvStore whenever its change_gen has moved since the last successful
    /// write (legacy_sink_last_persisted_gen_) — a small, restart-durable
    /// marker, NOT a durable spool of the lost events themselves (see
    /// guardian_legacy_sink_executor.hpp's "Known limitations" doc comment).
    /// This is what keeps `yuzu_fleet_guardian_legacy_sink_gap_rules` from
    /// reading as "resolved" after a mid-outage agent restart the same way a
    /// genuine repair would (UP-3), and keeps `events_lost` monotonic across
    /// one (UP-4's restart-durability half - see start_local()/stop() below
    /// for the read/final-write sides of this same mechanism).
    ///
    /// #4783 Gate 8 re-review: the snapshot/decide/persist/record-gen
    /// sequence below runs under legacy_sink_persist_mu_ (own doc comment
    /// near that member) for its ENTIRE span, not just the KV write - stop()'s
    /// own final persist (see stop()'s doc comment) takes the same lock for
    /// its own entire span, so the two call sites can never interleave a
    /// stale snapshot from one against a fresher write from the other. See
    /// that member's doc comment for the lost-update race this closes.
    void legacy_sink_kick() noexcept;

    /// Ask for a prompt durable-journal replay into the send window (item 7 PR-Ag). Since C0
    /// (#2298 gate 1) this KICKS the drain worker rather than paging inline: it takes mtx_
    /// briefly, then notifies. The reconnect thread therefore never touches the KvStore.
    /// prefer_spark_-gated; a no-op after stop() and before the worker is wired.
    /// Called from the reconnect hook, after set_event_sink.
    void page_journal();

    /// A snapshot of the durable-journal integrity + activity counters (item 7 PR-Ag §8),
    /// assembled from the runtime (staging) + the journal component. The agent heartbeat
    /// emits these SPARSELY (only non-zero) via emit_guardian_journal_heartbeat_tags. All
    /// zero when prefer_spark is off / the journal is quiescent.
    [[nodiscard]] GuardianJournalStats journal_stats() const;

    /// The journal AGE gauges (flip item 6 + #2364 step-1), emitted via
    /// emit_guardian_journal_age_tags. Returns nullopt while the ages are meaningless:
    /// prefer_spark off (spark dormant - the counters-are-zero trick does NOT extend to
    /// ages, where 0 is a real reading, so dormancy must be an ABSENCE), no drain worker,
    /// or a worker that has not completed start() (stamps still 0). This gate is inside the
    /// engine because prefer_spark_ is deliberately not exposed; the heartbeat just forwards
    /// whatever this returns.
    [[nodiscard]] std::optional<GuardianJournalAgeStats> journal_age_stats() const;

    /// rung 9c PR-3: a re-statable snapshot of the ack ledger's CURRENT
    /// application (yuzu.guardian_arm_pending / yuzu.guardian_arm_failed - see
    /// guardian_arm_heartbeat.hpp's GuardianArmStats for the field semantics and
    /// emit_guardian_arm_heartbeat_tags for the emission posture). Returns nullopt
    /// while the signal is dormant: `prefer_spark_` false, the engine stopped, Spark
    /// itself unavailable (Unwired/SparkFailed/SparkDisabled), or the ledger has no
    /// current application yet.
    ///
    /// ALL FOUR conditions are LOAD-BEARING, not belt-and-braces (Check A,
    /// ~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md Decision 1;
    /// governance fix, adversarial review CODEX-1/K1 - the original shipped gate
    /// checked only `prefer_spark_`, silently emitting a false-present-healthy
    /// {0,0} pair whenever Spark was stopped or unavailable while prefer_spark_
    /// stayed true, which is the READIEST state at cutover for exactly this to
    /// matter): unlike journal_age_stats() above, whose dormancy the drain-worker's
    /// own zero-timestamp check would eventually catch even without the flag,
    /// ack_ledger_->arm_stats() alone cannot tell "spark dormant" from "spark live,
    /// currently clean" - GuardianEngine::apply_rules() calls
    /// GuardianArmAckLedger::begin_application() UNCONDITIONALLY on every push,
    /// regardless of prefer_spark_, so a legacy (non-spark) agent has a live,
    /// empty Application (pending={}, resolved_failed=0) exactly like a spark
    /// agent with nothing currently pending or failed - the ledger's own
    /// arm_stats() now separately returns nullopt only when there is genuinely NO
    /// current application (see guardian_arm_ack.hpp), which is a DIFFERENT
    /// absence reason than any of the three engine-level ones above and must stay
    /// additive to them, not a substitute. Reading `prefer_spark_` alone as
    /// sufficient - or `current_ != nullptr` as sufficient - would each make some
    /// reachable agent state emit arm_pending=0/arm_failed=0 - read by a fleet
    /// consumer as "spark arming, healthy" - when nothing is actually being
    /// observed. This four-way check is what prevents that in every reachable
    /// state, not just the one that happens to be live in every released agent
    /// today.
    [[nodiscard]] std::optional<GuardianArmStats> arm_stats() const;

    /// rung 9c PR-3 (Decision 3, Option B): the arm/disarm executor's cumulative
    /// physical-ceiling refusal count (R5.1's CeilingExhausted;
    /// GuardianSparkRuntime::io_ceiling_rejections()), surfaced as
    /// yuzu.guardian_io_arm_disarm_rejected_ceiling. A plain monitor-only
    /// counter, zero when dormant or simply never hit - unlike arm_stats() above
    /// this needs no prefer_spark_ dormancy gate: a zero count is equally
    /// truthful whether spark is dormant or has just never hit the ceiling, so
    /// there is no "always-present empty state" trap to gate around here. Zero
    /// when prefer_spark is off / no runtime, matching
    /// outbox_backpressure_drops()'s own shape.
    [[nodiscard]] std::uint64_t io_ceiling_rejections() const;

    /// Count of repeat-Unknown convergence re-evals whose guard.unhealthy was
    /// edge-suppressed (M1). Surfaced sparsely on the heartbeat as
    /// `yuzu.guardian_unhealthy_suppressed` so a rule stuck errored is observable
    /// without flooding the health stream. Zero when prefer_spark is off / no runtime.
    [[nodiscard]] std::uint64_t unhealthy_suppressed() const;
    /// F5 (M1 item a): repeat-Unknown convergence re-evals whose guard.unhealthy WAS
    /// re-emitted as a minutes-cadence refresh (errored_refresh_ms), sibling to
    /// unhealthy_suppressed() above. Surfaced as `yuzu.guardian_unhealthy_refreshed`.
    /// Zero when prefer_spark is off / no runtime.
    [[nodiscard]] std::uint64_t unhealthy_refreshed() const;
    /// F5 (M1 item b): rule_ids demoted off the 5s convergence priority lane to their
    /// normal type-lane cadence. Surfaced as `yuzu.guardian_priority_demoted`. Zero
    /// when prefer_spark is off / no runtime.
    [[nodiscard]] std::uint64_t priority_demoted() const;
    /// #2993: compliance/health entries rejected at the MAIN outbox's capacity (distinct
    /// from journal_stats().lifecycle_backpressure_drops, a different log's own
    /// counter). Surfaced as `yuzu.guardian_outbox_backpressure_drops`. Zero when
    /// prefer_spark is off / no runtime.
    [[nodiscard]] std::uint64_t outbox_backpressure_drops() const;

    /// #4783 commit 4: cumulative count of legacy-sink events this engine could not
    /// deliver (RefusedCapacity/RefusedAdmission/WriteFailed/a throwing send — see
    /// guardian_legacy_sink_executor.hpp's own loss-table doc comment; LinkDown and
    /// discarded_at_stop are DELIBERATELY excluded, same doc). Never gated on
    /// prefer_spark_ — legacy_sink_executor_ is always live. Surfaced as
    /// `yuzu.guardian_legacy_sink_events_lost` (heartbeat, sparse: 0 omits the tag).
    /// Production accessor — unlike legacy_sink_executor_for_test() above, this is
    /// the one production code (agent.cpp's heartbeat) actually calls.
    [[nodiscard]] std::uint64_t legacy_sink_events_lost() const;

    /// #4783 commit 4: CURRENT count of rules with an open sticky integrity gap -
    /// a rule's gap shrinks back to 0 as soon as EITHER its repair report is
    /// confirmed Sent (and not itself since superseded), OR the rule's own next
    /// real verdict is delivered with a strictly-newer admission-time seq than
    /// the loss it covers, whichever happens first (#4783 follow-up: SEQ-GUARDED
    /// CLEARING — see guardian_legacy_sink_executor.hpp's class doc comment and
    /// legacy_sink_kick() above). Surfaced as `yuzu.guardian_legacy_sink_gap_rules`
    /// (sparse). Production accessor, same rationale as legacy_sink_events_lost()
    /// above.
    [[nodiscard]] std::uint64_t legacy_sink_gap_rules() const;

    /// #4783 governance follow-up: cumulative count of emit_guard_event() calls that
    /// bailed because no sink was wired yet (see legacy_sink_dropped_unwired_'s own
    /// doc comment near its declaration below - the pre-network-arm A3 drop, a
    /// routine window on every agent boot before agent.cpp's post-Subscribe
    /// set_event_sink call). Surfaced as `yuzu.guardian_legacy_sink_dropped_unwired`
    /// (sparse). Production accessor, same rationale as legacy_sink_events_lost()
    /// above.
    [[nodiscard]] std::uint64_t legacy_sink_dropped_unwired() const;

    /// Idempotent shutdown. After stop() returns, dispatch() will
    /// return a transient-failure result rather than touching KV.
    ///
    /// #4783 Gate 4 UP-3/UP-4: also takes one final, UNCONDITIONAL (not
    /// change_gen-gated, unlike legacy_sink_kick()'s own persist) snapshot of
    /// legacy_sink_executor_'s loss ledger and writes it to KvStore - a
    /// bounded, synchronous write, same reasoning as the pre-existing
    /// lifecycle-journal final flush right after it in the .cpp. Covers the
    /// case where the agent shuts down before its next heartbeat ever runs
    /// (an open gap with zero prior legacy_sink_kick() calls still needs to
    /// survive the restart it is about to undergo).
    void stop();

    /// Sink for outbound Guardian events (drift, etc.). Wired by agent.cpp once
    /// the Subscribe stream is open and BEFORE any push arrives, so a guard started
    /// by apply_rules captures a live sink. The sink writes a
    /// CommandResponse{plugin:"__guard__", action:"event", payload:<event>} on the
    /// stream and reports the delivery outcome (#4783: Sent / LinkDown / WriteFailed)
    /// so a failed Write() is countable instead of silently swallowed. Guards capture
    /// a copy at start, so this is set-once-then-read. Called ONLY from
    /// legacy_sink_executor_'s own detached worker, never from a guard's own thread
    /// or from emit_guard_event() directly - see guardian_legacy_sink_executor.hpp.
    using EventSink =
        std::function<LegacySendOutcome(const yuzu::guardian::v1::GuaranteedStateEvent&)>;
    void set_event_sink(EventSink sink);

    /// Replace (full_sync=true) or merge (full_sync=false) the active
    /// rule set with the contents of `push`. Persists each rule as a
    /// JSON blob under key "rule:<rule_id>". Returns the number of
    /// rules applied on success, or an error detail string.
    std::expected<std::size_t, std::string>
    apply_rules(const yuzu::guardian::v1::GuaranteedStatePush& push);

    /// Build a GuaranteedStateStatus reflecting currently cached rules.
    /// All rules report status="errored" in PR 2 because no guards are
    /// running yet — we cannot prove compliance without an evaluator, so
    /// be honest about it. The real status machine (compliant/drifted/
    /// errored per-rule) arrives with PR 3; dashboard presentation of the
    /// PR 2 state is also a PR 3 concern.
    yuzu::guardian::v1::GuaranteedStateStatus get_status() const;

    /// Entry point for `cmd.plugin() == "__guard__"`. Parses the
    /// action + params and returns a DispatchResult ready to be
    /// serialised into a CommandResponse by the caller.
    GuardianDispatchResult dispatch(const yuzu::agent::v1::CommandRequest& cmd);

    /// Number of rules currently persisted. Informational only.
    std::size_t rule_count() const;

    /// Number of guards CURRENTLY ARMED via the LEGACY IGuard path (may be <
    /// rule_count(): a disabled rule, an unsupported/off-platform spark type,
    /// or a failed start all persist the rule without arming a guard).
    /// Informational + the test seam for the enabled()/disable/re-enable/
    /// same-id-replace contract (rung 6) and the rung-7 mutual-exclusion
    /// invariant (a rule_id is never counted here AND in
    /// spark_armed_rule_count() at once).
    std::size_t armed_guard_count() const;

    /// Number of rules CURRENTLY ARMED via the SPARK path (0 if spark was
    /// never wired). The rung-7 counterpart to armed_guard_count() - the
    /// mutual-exclusion test seam.
    std::size_t spark_armed_rule_count() const;

    /// Per-SparkType count of rules CURRENTLY classified RulePlacement::Unsupported -
    /// enforced by neither armed_guard_count() nor spark_armed_rule_count() (F7,
    /// #2298 rung 2). A CURRENT gauge, not a cumulative counter: aggregates the live
    /// unsupported_rules_ map fresh on every call, so it can legally decrease (e.g. a
    /// mechanism becoming available, or the rule being disabled/removed). Backs the
    /// mech_unsupported_total heartbeat tag.
    [[nodiscard]] std::map<SparkType, std::uint64_t> unsupported_counts_by_type() const;

    /// Current policy generation — monotonically increasing; bumped on
    /// every successful apply_rules call. Persisted across restarts.
    std::uint64_t policy_generation() const;

    /// Cumulative count of reconcile (arm) ATTEMPTS that threw and were firewalled in
    /// apply_rules — a rule that persisted but did not arm. This counts attempts, NOT
    /// distinct rules: one persistently-failing rule increments it once per push (so it
    /// is a rate signal / "a gap is open", not "how many rules are gapped"). A nonzero
    /// value means an enforcement gap is (or was) open on this endpoint; surfaced via the
    /// heartbeat by item 9 so a persistent gap stays fleet-visible even after the
    /// generation later advances past it (rung 7.7b PR-1 item 3 / Sol B1). Lock-free.
    [[nodiscard]] std::uint64_t arm_failure_count() const noexcept {
        return arm_failures_.load(std::memory_order_relaxed);
    }

    /// KV namespace used for all Guardian persistent state. Exposed for
    /// tests — do not read from this namespace in production code.
    static std::string_view kv_namespace();

    /// #4783 Gate 4 UP-3/UP-4: the single fixed KvStore key (under
    /// kv_namespace()) the legacy-sink loss ledger (counters + open-gap
    /// snapshots) persists under — see legacy_sink_kick()/start_local()/
    /// stop() in guardian_engine.cpp. Exposed for tests — same "do not read
    /// from this namespace in production code" rule as kv_namespace() above;
    /// lets a test write a deliberately malformed/absent record directly
    /// (the self-heal / boot-degrade regression) without needing a second
    /// GuardianEngine instance to have produced one first.
    static std::string_view legacy_sink_loss_ledger_key_for_test();

    /// Wire the spark detection path, once, before start_local() (agent.cpp,
    /// rung 7.7): builds the reader, the SparkEngine backend adapter, the
    /// runtime, registers the SparkEngine consumer, and constructs the
    /// convergence scheduler and the outbox drain worker - starting their
    /// threads only when prefer_spark_ is set (rung 7.7b); at prefer_spark_=false
    /// they are created but idle (nothing places on spark). An all-or-nothing
    /// transaction (ANY step failing after `engine` is confirmed non-null rolls
    /// every partial construction back and reports SparkFailed; see the .cpp for
    /// the exact rollback sequence). `engine` is a BORROWED pointer, safe
    /// only because of the agent.cpp member-declaration-order guarantee that
    /// spark_engine_ outlives this GuardianEngine's teardown (spark_engine_ is
    /// declared BEFORE guardian_ in agent.cpp; members destroy in reverse
    /// declaration order, so guardian_ - declared later - is destroyed first).
    /// `spark_disabled_by_config` disambiguates a null `engine` meaning
    /// --spark-disable from one meaning spark_engine_ failed to boot -
    /// agent.cpp already knows which case it is; this method must not guess.
    /// `send` is the wire-serializing callback the drain worker uses; a fake
    /// suffices for tests that only need wiring/reconcile behaviour, not real
    /// delivery. Idempotent-once: a second call is a no-op (logs and returns)
    /// once spark_availability() is anything other than Unwired.
    void wire_spark_engine(SparkEngine* engine, bool spark_disabled_by_config,
                           std::function<SendResult(const OutboxEntry&)> send);

    /// The current, immutable-after-set outcome of wire_spark_engine().
    [[nodiscard]] SparkAvailability spark_availability() const;

    /// Constructor-time spark preference (F7). No lock needed: prefer_spark_ is const,
    /// set once in the ctor initializer list before this object is ever shared across
    /// threads - unlike spark_availability_, which IS written later by
    /// wire_spark_engine() and needs mtx_ for the cross-thread happens-before edge.
    /// Exposed for yuzu.guardian_backend (guardian_backend_from_state()): Available
    /// alone does not mean the backend IS spark, since prefer_spark_ defaults false.
    [[nodiscard]] bool prefer_spark() const noexcept { return prefer_spark_; }

    /// TEST-ONLY: the durable-journal component, for fault injection (see
    /// GuardianLifecycleJournal::inject_write_failures_for_test). Null until
    /// wire_spark_engine runs. No production caller.
    [[nodiscard]] GuardianLifecycleJournal* lifecycle_journal_for_test() {
        return lifecycle_journal_.get();
    }

    /// TEST-ONLY: the spark runtime, for fault injection (e.g.
    /// GuardianSparkRuntime::set_detach_fault_for_test - rung 9c PR-2 Unit 6's own
    /// "full_sync teardown throws" regression net). Null until wire_spark_engine
    /// runs. No production caller.
    [[nodiscard]] GuardianSparkRuntime* spark_runtime_for_test() {
        return spark_runtime_.get();
    }

    /// TEST-ONLY: the current application's still-pending accepted-arm count (see
    /// GuardianArmAckLedger::pending_count_for_test) - lets a test settle on "every
    /// arm the last apply_rules() push accepted has resolved" without reaching into
    /// the ledger directly. Defined out-of-line (guardian_engine.cpp): GuardianArmAckLedger
    /// is only forward-declared here. Takes mtx_ (matches every other _for_test
    /// accessor that reads engine-owned state). No production caller.
    [[nodiscard]] std::size_t ack_pending_count_for_test() const;

    /// TEST-ONLY: the spark drain worker / convergence scheduler, for started-state
    /// introspection (#2238, fixes BLOCKING-2b). wire_spark_engine() constructs both
    /// unconditionally but starts them only under prefer_spark_ — journal_age_stats()
    /// short-circuits on !prefer_spark_ BEFORE its stamp check, so that accessor alone
    /// does not discriminate "constructed but never started" from "prefer_spark_
    /// false"; reverting the start gate (always-start) fails no other test. Read-only
    /// introspection — categorically outside the mutable-decision-setter class rev-1
    /// review rejected (see SparkAvailability above). Null until wire_spark_engine
    /// runs. No production caller.
    [[nodiscard]] GuardianOutboxDrainWorker* drain_worker_for_test() {
        return spark_drain_worker_.get();
    }
    [[nodiscard]] ConvergenceScheduler* convergence_scheduler_for_test() {
        return spark_scheduler_.get();
    }

    /// TEST-ONLY: override the drain worker's periodic backstop and maintenance cadences.
    /// MUST be called BEFORE wire_spark_engine(), which is what constructs the worker.
    ///
    /// Exists so a test can prove a journal page happened because of the reconnect KICK and
    /// not because the backstop fired anyway: with the production 5 s bound the worker's
    /// timer is already running during fixture setup, so any "it paged within 1 s" assertion
    /// can pass for the wrong reason (#2298 governance quality-engineer BLOCKING-1).
    /// 0 leaves the corresponding default in place. No production caller.
    void set_drain_worker_timing_for_test(std::uint64_t periodic_bound_ms,
                                          std::chrono::milliseconds page_interval = {},
                                          std::chrono::milliseconds prune_interval = {}) {
        test_periodic_bound_ms_ = periodic_bound_ms;
        test_page_interval_ = page_interval;
        test_prune_interval_ = prune_interval;
    }

    /// TEST-ONLY: shrink the bounded wait `GuardianSparkRuntime::attach_rule()`/
    /// `submit_disarm_off_lock()` place on their own backend arm/disarm claim
    /// (`GuardianSparkRuntime::Config::backend_op_deadline`, production default 5s) —
    /// a test can drive a deterministic "backend parked" scenario without a real
    /// multi-second wait. MUST be called BEFORE wire_spark_engine(), which is what
    /// constructs the runtime (the same ordering constraint as
    /// set_drain_worker_timing_for_test above); a call afterward is silently inert.
    /// `GuardianSparkRuntime::Config` is not usable here directly — this header only
    /// forward-declares GuardianSparkRuntime (ABI boundary), so only the one field
    /// tests actually need is threaded through; unset means "keep the production
    /// default". No production caller.
    void set_spark_backend_op_deadline_for_test(std::chrono::milliseconds deadline) {
        test_spark_backend_op_deadline_ = deadline;
    }

    /// Spread this agent's journal-maintenance phase and its forced pages over their
    /// intervals (C0 flip-checklist item 12). MUST be called BEFORE wire_spark_engine(),
    /// which is what constructs the worker.
    ///
    /// OFF by default and turned on EXPLICITLY by the production wiring in agent.cpp. The
    /// alternative - inferring it from whether a test-timing override was installed - is
    /// wrong: several tests drive a live worker without overriding timing at all, and the
    /// production-boot-order regression in particular depends on the worker running
    /// immediately, so an inferred jitter would turn a real race assertion into a hollow
    /// pass rather than a failure (Sol review).
    void set_maintenance_jitter(bool on) { maintenance_jitter_ = on; }

    /// TEST-ONLY: if set, invoked inside start_local()'s re-arm walk once per cached
    /// enabled rule, immediately BEFORE reconcile_rule_locked() — so a throw from the
    /// hook simulates the failure class the surrounding catch exists for (a legacy
    /// guard's std::thread ctor throwing std::system_error under thread/handle
    /// exhaustion), aimed at exactly one rule by rule_id. Deliberately NOT fired from
    /// inside reconcile_rule_locked() itself, which would also fire on the apply_rules
    /// path this seam is not meant to touch.
    ///
    /// This is fault INJECTION into an existing degrade handler, not the mutable
    /// spark-vs-legacy DECISION setter rev-1 review rejected (see SparkAvailability
    /// above) — same class of seam as SparkEngine::set_arm_fault_hook_for_test (#2270).
    ///
    /// CONTRACT: fires with mtx_ HELD (start_local() holds it for the whole re-arm
    /// walk) — throw or observe only; re-entering the engine from the hook
    /// self-deadlocks. This is a genuine same-thread std::mutex relock (undefined
    /// behavior in practice: a silent hang, not the loud WorkerHostileMutex abort —
    /// that guard only fires for the worker threads stop() joins, and the calling
    /// thread here is never one of those). Arming a hook (non-null) MUST happen
    /// BEFORE start_local() runs (set-then-use; asserted) — clearing it (nullptr),
    /// typically during teardown after start_local() already ran, is always fine.
    /// No production caller.
    void set_rearm_fault_hook_for_test(std::function<void(const std::string& rule_id)> hook) {
        assert((!hook || !started_) &&
               "set_rearm_fault_hook_for_test: arming a hook must happen before start_local()");
        rearm_fault_hook_for_test_ = std::move(hook);
    }

    /// TEST-ONLY (#4783 Gate 8 re-review): arms legacy_sink_persist_race_hook_for_test_ -
    /// see that member's own doc comment for the exact firing point and its
    /// same-thread-relock CONTRACT. Set-then-use: arm this on the thread that
    /// will construct/own the kicker thread, strictly before starting it, so
    /// the write establishing the std::function is visible to the thread that
    /// will read it (std::thread's own launch is itself a synchronizes-with
    /// edge - no additional synchronization needed for the ARMING itself).
    /// No production caller.
    void set_legacy_sink_persist_race_hook_for_test(std::function<void()> hook) {
        legacy_sink_persist_race_hook_for_test_ = std::move(hook);
    }

    /// TEST-ONLY: the exact message logged for the most recent start_local() re-arm
    /// degrade (empty if none occurred this run). Recorded directly at the point of
    /// emission rather than observed via spdlog - a test binary's process-wide
    /// spdlog::set_default_logger() swap is not guaranteed to be visible to spdlog::
    /// calls made inside this class's own translation unit across every supported
    /// toolchain (confirmed on a macOS dylib build: the swap in the test image never
    /// reached this catch's spdlog::error call, silently emptying the capture -
    /// same cross-image-state class as the #501 abseil hash-seed split
    /// guardian_dispatch_push_bytes_for_test works around). Plain object-member
    /// state has no such hazard: it lives in the GuardianEngine instance regardless
    /// of which image the writing method's code was compiled into. Locked (like
    /// rule_count()/spark_armed_rule_count()) and returned BY VALUE, not by
    /// reference - a reference into mtx_-protected state would keep aliasing it
    /// after the lock_guard released, defeating the point of taking the lock. No
    /// production caller.
    [[nodiscard]] std::string last_rearm_degrade_message_for_test() const;

    /// TEST-ONLY (#4685): the outcome of the most recent Unsupported-branch classification
    /// log reconcile_rule_locked emitted, plus a count of how many times that log has
    /// genuinely fired (edge-triggered — that branch logs only on a change, never on a
    /// retained/re-observed classification, see unsupported_rules_'s own doc comment).
    /// Recorded directly at the point of emission, not observed via spdlog - same
    /// cross-image hazard and the same object-member fix as
    /// last_rearm_degrade_message_for_test above. `level` distinguishes the two
    /// Unsupported causes #4685 asks the log to tell apart: Warn for a mechanism that IS
    /// registered but refused to bind at start() (boot-inert - never emitted for a merely
    /// runtime-degraded episode, which stays armable and never reaches this branch at
    /// all), Info for a spark type with no mechanism registered on this host at all (the
    /// routine cross-platform gap). `level == None` (the default) means no Unsupported
    /// classification has logged yet this run. Locked, returned by value - same rationale
    /// as the sibling accessors above. No production caller.
    enum class UnsupportedLogLevel { None, Info, Warn };
    struct UnsupportedLogRecord {
        UnsupportedLogLevel level{UnsupportedLogLevel::None};
        std::string rule_id;
        SparkType type{};
        std::uint64_t edge_count{0}; ///< how many genuine (logged) Unsupported edges so far
    };
    [[nodiscard]] UnsupportedLogRecord last_unsupported_log_for_test() const;

    /// #4021: the `expected_hash` a file-hash-equals rule's most recent legacy arm
    /// attempt ended up with — empty if never armed as file-hash-equals, the
    /// authored value if `expected_hash` was set, or a SEEDED persisted baseline
    /// if one existed for this rule_id/target. This is what
    /// start_guard_for_rule_locked built INTO `FileGuard::Config` before calling
    /// `start()` — set regardless of whether `start()` itself actually arms
    /// (FileGuard is Windows-only for the MVP; off Windows this is the only
    /// observable proof the seed-lookup ran and produced the right value, since no
    /// FileGuard object survives to observe otherwise). Locked, returned by value
    /// — same rationale as last_rearm_degrade_message_for_test above. No
    /// production caller.
    [[nodiscard]] std::string last_file_expected_hash_for_test() const;

    /// Gate 3 quality-engineer follow-up (#4021): `last_file_expected_hash_for_test`
    /// only proves the SEED lookup ran — it says nothing about whether the
    /// CAPTURE callback (`FileGuard::Config::on_baseline`) was actually attached,
    /// since a seeded (non-empty `expected_hash`) rule never re-enters the
    /// capture branch at all. Set unconditionally, right after the assignment,
    /// on every file-hash-equals arm attempt — true regardless of seeding, so a
    /// test can assert the wiring itself happened (deleting the assignment
    /// would otherwise leave every Linux test green, since no real FileGuard
    /// runs off Windows to observe the callback firing). Locked, returned by
    /// value — same rationale as the sibling accessors above. No production
    /// caller.
    [[nodiscard]] bool last_file_on_baseline_wired_for_test() const;

    /// Live bounded-I/O worker count on the spark reader (0 if never wired) -
    /// the F3 orphan-exit obligation's plumbing (rung 7.6 is the enforcement).
    [[nodiscard]] std::size_t active_io_workers() const;

    /// TEST-ONLY (#4783): direct access to the legacy-sink executor itself, for its
    /// own test seams (pending_count_for_test/pending_bytes_for_test/stats()/
    /// active_worker_count()/etc - see guardian_legacy_sink_executor.hpp). No
    /// production caller; production code funnels through emit_guard_event()/stop()/
    /// active_io_workers() only, never this accessor. A test using this must
    /// `#include "guardian_legacy_sink_executor.hpp"` itself for the complete type -
    /// this header only forward-declares it.
    [[nodiscard]] GuardianLegacySinkExecutor& legacy_sink_executor_for_test() const;

    /// TEST-ONLY (#4783): true once the legacy-sink executor's queue is IDLE (empty
    /// && nothing in flight) within `timeout` - see
    /// GuardianLegacySinkExecutor::wait_idle_for_test's own doc comment for why this
    /// is NOT the same as physical worker retirement (retire_legacy_sink_workers_for_test
    /// below is that seam). Use this to make a delivery assertion deterministic
    /// instead of racing the detached worker.
    [[nodiscard]] bool flush_legacy_sink_for_test(std::chrono::milliseconds timeout) const;

    /// TEST-ONLY (#4783): true once every legacy-sink executor worker has PHYSICALLY
    /// retired (active_worker_count()==0) within `timeout`. Call this - not just
    /// flush_legacy_sink_for_test above - before any fixture/capture a sink's SendFn
    /// still references destructs (plan hygiene rule 6): a worker can remain
    /// momentarily alive even after the queue reports idle.
    [[nodiscard]] bool retire_legacy_sink_workers_for_test(std::chrono::milliseconds timeout) const;

    /// TEST-ONLY (#4783 commit 4): replaces legacy_sink_executor_ with a freshly
    /// constructed instance whose Config::max_events is `max_events` — lets a test
    /// force a deterministic RefusedCapacity (and the sticky gap it records)
    /// without pushing thousands of events. GuardianLegacySinkExecutor::Config is
    /// not usable as a parameter type here directly (this header only
    /// forward-declares GuardianLegacySinkExecutor, the same ABI-boundary reason
    /// set_spark_backend_op_deadline_for_test above threads only the one field
    /// tests need instead of the runtime's own Config type) — so, like that seam,
    /// only the single field a test needs is threaded through. MUST be called
    /// BEFORE start_local() (asserted, same pre-start_local() convention as
    /// set_rearm_fault_hook_for_test above): the fresh executor replaces one that
    /// may otherwise already have live queued/in-flight state once guards can run.
    /// No production caller.
    void set_legacy_sink_max_events_for_test(std::size_t max_events);

private:
    KvStore* kv_;
    std::string agent_id_;

    /// A std::mutex that ABORTS if locked on any thread GuardianEngine::stop() joins.
    ///
    /// GuardianEngine::stop() holds mtx_ across its whole body AND joins BOTH the
    /// ConvergenceScheduler lanes and the drain worker inside it, so any mtx_ acquisition
    /// from any of them is a lock-vs-join deadlock -
    /// a hung agent shutdown, fleet-wide. Everything the worker runs (journal prune/page,
    /// and the INJECTED send, which is an arbitrary std::function supplied by agent.cpp)
    /// must therefore stay off this lock. That was previously a review-only invariant
    /// recorded in comments; here it fails loudly instead (#2298 governance A2).
    /// BasicLockable, so every `std::lock_guard lock(mtx_)` site is unchanged by CTAD.
    ///
    /// Holds NO reference to the worker: it asks a thread-local role marker
    /// (on_guardian_joined_thread()) instead. A pointer to the worker would have to
    /// be read here BEFORE mu_ is held - an unsynchronised cross-thread read - and wiring
    /// rollback can destroy the worker while another thread holds that pointer, which made
    /// the safety device itself a use-after-free (#2298 Sol review).
    ///
    /// Aborts rather than asserts: `assert` is a no-op under NDEBUG, so a release build
    /// with sanitizers would have logged the violation and then walked into the deadlock.
    ///
    /// Second role, rung 9c R5.1 (guardian_detached_worker_role.hpp): a DETACHED
    /// GuardianIoExecutor worker - either dispatch form, including the consumer-injected
    /// on_abandoned/on_complete callback it runs after the backend call - is a different
    /// hazard class (lock-vs-lifetime, not lock-vs-join: it can never be joined and may
    /// outlive stop() or the F3 orphan grace) with the same remedy. The tripwire consults
    /// both markers and names the role that fired.
    class WorkerHostileMutex {
    public:
        void lock() {
            abort_if_worker_thread();
            mu_.lock();
        }
        bool try_lock() {
            abort_if_worker_thread();
            return mu_.try_lock();
        }
        void unlock() { mu_.unlock(); }

    private:
        static void abort_if_worker_thread() noexcept;
        std::mutex mu_;
    };

    mutable WorkerHostileMutex mtx_;
    bool started_{false};
    bool stopped_{false};
    std::uint64_t policy_generation_{0};
    std::size_t rule_count_{0};
    std::atomic<std::uint64_t> arm_failures_{0}; ///< reconcile-throw count (item 3 / Sol B1)

    bool put_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);
    void refresh_count_locked();
    /// Persists `gen` to the policy-generation KV key. Returns kv_->set()'s own
    /// success bool (false if kv_ is null) - callers publish policy_generation_
    /// ONLY after a true return, never before, so a failed (or throwing - kv_->set()
    /// is not noexcept) write leaves policy_generation_ at its prior value and the
    /// caller's own advance condition (gen > policy_generation_) is still true next
    /// time it is checked, retrying naturally with no separate bookkeeping needed
    /// (coordinator finding, rung 9c PR-2 Unit 6 gate: the old void-returning form
    /// let a failed or throwing persist strand policy_generation_ already advanced
    /// with nothing durable behind it - a silent, permanent stop to server re-push).
    [[nodiscard]] bool persist_generation_locked(std::uint64_t gen);
    /// Flush the runtime's staged lifecycle records to the durable journal (item 7
    /// PR-Ag). mtx_ held; snapshot → persist → erase-persisted-prefix, circuit-broken
    /// on the first write failure. prefer_spark_-gated (inert when spark is not the
    /// active backend). Fired via a terminate-safe guard on every apply_rules /
    /// start_local exit.
    ///
    /// `max_batches` / `max_records` bound ONE call; pass `kJournalPersistUnbounded`
    /// for either to disable it. NEITHER is defaulted, so every caller states its
    /// intent and a future cadence caller cannot silently inherit unbounded behaviour.
    /// Only the heartbeat's retry-persist passes real bounds - it is the sole cadence
    /// caller, and the one that must not sit under mtx_ for an unbounded number of
    /// slow-but-successful KvStore writes. Every one-shot caller (boot re-arm,
    /// apply_rules, and both shutdown flushes) passes unbounded because each has to
    /// drain what it was given.
    void persist_lifecycle_journal_locked(std::size_t max_batches, std::size_t max_records);

    /// Step 4: arm (or re-arm) the on-box guard for a rule. Reads the rule's
    /// spark type to pick the guard: file-change to FileGuard,
    /// service-status-change to ServiceGuard (Windows) or SystemdServiceGuard
    /// (Linux), registry-change to RegistryGuard (Windows). An unknown or
    /// off-platform type is a no-op. Called under mtx_. Returns true iff a guard
    /// was actually started (false for an unsupported type, an off-platform
    /// mechanism, or a failed start) so callers count armed guards accurately.
    bool start_guard_for_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);
    void stop_all_guards_locked();

    /// Retire any legacy guard armed for rule_id, if one exists. Idempotent
    /// for a rule with none. This is start_guard_for_rule_locked's own
    /// rung-6 hoisted find-stop-erase block, factored out so
    /// reconcile_rule_locked (rung 7) can call it directly on the
    /// disabled/invalid/spark-armed paths without duplicating it.
    void withdraw_legacy_guard_locked(const std::string& rule_id);

    /// reconcile_rule_locked's outcome. Armed: the rule ended up armed via either
    /// backend. Failed: the rule was ELIGIBLE to arm and a genuine arm ATTEMPT did
    /// not succeed (currently: a spark attach_rule() error - a synchronous refusal,
    /// a #2233 item 3 bounded-wait timeout, or a same-key busy rejection). Inert:
    /// every other false-shaped outcome - disabled, an authoring/validation fault,
    /// agent-wide SparkFailed/Unwired, Unsupported (a routine cross-platform gap,
    /// NOT an error - pinned by "an all-unsupported push still advances
    /// policy_generation" in test_guardian_engine_spark_reconcile.cpp), or a
    /// legacy-path arm that did not start. Failed is deliberately narrower than
    /// "returned false": apply_rules' policy_generation hold-on-failure gate must
    /// count a genuine per-push arm failure (else a timed-out rule's push is
    /// silently treated as fully applied and the server never retries it) without
    /// also holding generation on routine/expected inert outcomes (#2233 item 3).
    ///
    /// Accepted (rung 9c PR-2): the rule was eligible and a spark arm attempt was
    /// ACCEPTED — dispatched to the backend, OR queued behind an in-flight/retained
    /// claim already occupying its key (R5.2's per-key claim/queue model: a queued
    /// sibling is accepted without triggering its own backend submission) — but has
    /// not yet resolved, as opposed to Armed (resolved, successfully). Named after
    /// docs/spark-stage2-guardian-consumer-design.md §R5.3's own vocabulary
    /// ("'Accepted' means reconcile_rule_locked() returned Accepted specifically —
    /// the async-arm outcome, as opposed to Armed").
    ///
    /// Exception (rung 9c PR-5c, #4221 up-2): a same-rule_id/same-spec retry that
    /// RE-OBSERVES an already-Wedged head is also Accepted, but its receipt is
    /// ALREADY TERMINAL at registration time — no async resolution is pending for
    /// it. The generation-hold gate still treats it like any other Accepted episode
    /// (ack_ledger_->can_advance() reads the receipt's actual status), so it simply
    /// resolves on the ledger's very next drain instead of waiting on anything new.
    ///
    /// Production status as of this comment (rung 9c PR-2 Unit 6): PRODUCED -
    /// reconcile_rule_locked() calls GuardianSparkRuntime::attach_rule(NonWaiting{},
    /// ...), so a rule whose arm is genuinely still in flight resolves to Accepted
    /// here instead of waiting (bounded) for it. apply_rules' generation-hold gate
    /// (ack_ledger_->can_advance()) treats it exactly like an unresolved episode
    /// (holds the generation), never like Failed (it is not a failure) or like
    /// Armed (it is not yet resolved) - the receipt itself is registered with
    /// ack_ledger_ (guardian_arm_ack.hpp), which the heartbeat's
    /// journal_maintenance_tick() drains and, once every accepted episode this
    /// generation resolves, advances policy_generation_ from.
    enum class ReconcileOutcome { Armed, Accepted, Failed, Inert };

    /// THE reconcile op (rung 7): the SOLE per-rule arm/disarm decision point,
    /// replacing the direct start_guard_for_rule_locked call apply_rules and
    /// start_local's A2 re-arm loop used to make. Decides spark vs legacy per
    /// rule (see the SparkAvailability doc above for the exact state matrix)
    /// and guarantees the mutual-exclusion invariant: a rule is armed in
    /// AT MOST ONE of guards_ / spark_runtime_, and an arm failure on
    /// whichever path was attempted is errored, NEVER a silent fallback to
    /// the other. Called under mtx_. See ReconcileOutcome for what each value
    /// means and why Failed is narrower than "not Armed".
    ReconcileOutcome reconcile_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);

    /// Unwind a partially-completed wire_spark_engine() attempt, in the
    /// reverse order construction attempted the steps (each step is
    /// independently null-safe, so this is correct regardless of exactly how
    /// far wiring got before it threw). `registered` + `consumer_id` capture
    /// whether register_consumer() itself succeeded before the failure, so
    /// this can unregister a leaked consumer registration. Always ends by
    /// setting spark_availability_ to SparkFailed. Called under mtx_, only
    /// from wire_spark_engine() itself.
    void rollback_spark_wiring_locked(SparkEngine* engine, bool registered,
                                      std::uint64_t consumer_id);

    /// Build a GuaranteedStateEvent from a guard's drift report and ENQUEUE it on
    /// legacy_sink_executor_ for delivery on a detached worker (#4783) - the
    /// hand-off itself (offer()) never blocks on network I/O and never throws;
    /// everything BEFORE that hand-off (the event_id string build, the
    /// health-detail JSON encode, the EventSink copy) keeps whatever throw surface
    /// it already had - this function is not newly noexcept overall, only the
    /// final hand-off is. Called from guard worker threads, so it takes ONLY
    /// sink_mtx_ (never mtx_): guards may fire during apply_rules / stop which
    /// hold mtx_, and taking mtx_ here would deadlock the stop-join.
    ///
    /// `is_gap_repair` (#4783 commit 4): threaded straight through to offer()'s own
    /// parameter of the same name — set ONLY by legacy_sink_kick() when building a
    /// synthesized guard.unhealthy report for a sticky integrity gap; every real
    /// guard callsite (and the guardian_emit_drift_for_test friend helper) uses the
    /// default. This flag is what lets the executor stamp GapRecord::repair_seq /
    /// clear the gap on a strictly-newer Sent without the executor having to
    /// reconstruct "is this drift report actually a repair" from the event's own
    /// content (see guardian_legacy_sink_executor.hpp's SEQ-GUARDED CLEARING).
    ///
    /// `timestamp_override` (#4783 follow-up review, part (c)): when present,
    /// stamps the built event's `timestamp` field from THIS time point instead of
    /// `std::chrono::system_clock::now()` — `event_id` still mints from `now_ms`
    /// regardless, only the wire `timestamp` field changes. ONLY
    /// legacy_sink_kick() ever passes this, with the gap's `last_lost` (never
    /// `first_lost` — a real verdict delivered between two losses is legitimately
    /// older than the SECOND loss and should still be overwritten by a repair
    /// covering that second loss); every real guard callsite leaves it at
    /// nullopt and keeps stamping `now`. This is belt-and-braces alongside the
    /// executor's own seq-guarded clearing and dequeue-time supersession check —
    /// it lets the server's existing `updated_at >=` upsert guard independently
    /// reject a stale repair, even if it somehow still reached the wire.
    ///
    /// `expected_gap_lost_seq` (adversarial-review finding, 2026-09-24): threaded
    /// straight through to offer()'s own parameter of the same name — see
    /// guardian_legacy_sink_executor.hpp's ADMISSION-TIME EPISODE BINDING
    /// section. ONLY legacy_sink_kick() ever passes this, with the
    /// `GapRecord::lost_seq` it captured from the SAME gapped_rules_needing_repair()
    /// call that produced `drift`/`timestamp_override` — every real guard
    /// callsite leaves it at nullopt.
    void emit_guard_event(const GuardDrift& drift, bool is_gap_repair = false,
                          std::optional<std::chrono::system_clock::time_point>
                              timestamp_override = std::nullopt,
                          std::optional<std::uint64_t> expected_gap_lost_seq = std::nullopt);

    // Test seam: drift emission is otherwise reachable only through an armed
    // guard, and guards are Windows-only / no-op elsewhere — so the event_id
    // shape (the #1307 agent_id fold) has no cross-platform test path without
    // this. The helper drives emit_guard_event() with a synthetic GuardDrift;
    // a sink installed via set_event_sink() captures the resulting event.
    friend YUZU_EXPORT void guardian_emit_drift_for_test(GuardianEngine& engine,
                                                         const GuardDrift& drift);

    // event_sink_ is guarded by its own mutex (not mtx_) so a guard worker can
    // deliver an event without contending with — or deadlocking against — the
    // engine's rule-management path. The dedicated lock makes the A2 pre-network
    // arm (guards started by start_local before the sink is wired) race-free.
    mutable std::mutex sink_mtx_;
    EventSink event_sink_;
    std::atomic<std::uint64_t> event_seq_{0};
    /// #4783: count of emit_guard_event() calls that bailed because no sink was wired
    /// yet (event_sink_ null - the pre-network-arm A3 drop, unchanged semantics).
    /// Previously a silent, uncounted return; now countable so "the sink was never
    /// wired" is distinguishable from "wired and delivered". Governance follow-up:
    /// now wired to a production consumer too - legacy_sink_dropped_unwired() above
    /// reads it (no lock needed, plain atomic), and agent.cpp's heartbeat surfaces it
    /// fleet-wide as yuzu_fleet_guardian_legacy_sink_dropped_unwired.
    std::atomic<std::uint64_t> legacy_sink_dropped_unwired_{0};
    /// #4783 Gate 8 re-review: serializes the ENTIRE snapshot/decide/persist/
    /// record-gen sequence in both legacy_sink_kick() and stop()'s final
    /// persist (see each method's own doc comment) against each other. Fixes
    /// a lost-update race: legacy_sink_kick() runs off mtx_ on the agent's
    /// heartbeat thread (by design - it must never contend with a guard
    /// thread's own reporting or an apply_rules reconcile), while stop() holds
    /// mtx_ but that guards nothing here - and agent.cpp's own shutdown
    /// ScopeExit calls guardian_->stop() BEFORE joining the heartbeat thread
    /// (quiesce_run_workers() - a late in-flight heartbeat tick can still call
    /// legacy_sink_kick() while stop() is already running). Before this lock
    /// existed, a CAS on legacy_sink_last_persisted_gen_ alone was NOT
    /// sufficient: kick() could take a snapshot at generation G1, decide to
    /// write, then be preempted while stop() runs entirely - taking its own
    /// later snapshot at G2, writing G2 to KV, and recording G2 - after which
    /// kick() resumes and unconditionally writes its STALE G1 snapshot,
    /// physically overwriting the newer KV record with older, less-complete
    /// data (the two writes are each individually mutex-serialized inside
    /// KvStore::set(), but nothing fenced kick()'s call to that function
    /// against running after stop()'s on the OS scheduler's own timing).
    /// Taking the snapshot itself under this lock (not just gating the write)
    /// is what closes it: whichever call acquires the lock second always
    /// takes a FRESH snapshot that already reflects everything the first call
    /// did, so the second write can never regress the first.
    ///
    /// Deliberately NOT mtx_ - reusing that would block a guard thread's own
    /// reporting or an apply_rules reconcile on a KvStore write, exactly the
    /// hazard legacy_sink_kick() exists to stay off of (see that method's own
    /// doc comment); this lock is taken ONLY around the orchestration
    /// (snapshot + persist + record-gen), never around anything guard-thread-
    /// reachable.
    ///
    /// Lock order: mtx_ -> legacy_sink_persist_mu_ -> {executor's own
    /// internal `mu`, KvStore's own mutex}. stop() enters at the first level
    /// (it holds mtx_ for its ENTIRE body, including this persist block - see
    /// stop()'s own doc comment); legacy_sink_kick() enters at the second
    /// level directly, never taking mtx_ at all. What keeps this acyclic:
    /// nothing acquires legacy_sink_persist_mu_ while already holding the
    /// executor's `mu` or KvStore's own mutex (both are taken NESTED inside
    /// it, by snapshot()/persist_legacy_sink_loss_ledger() respectively,
    /// never the reverse), and nothing acquires mtx_ while already holding
    /// legacy_sink_persist_mu_.
    std::mutex legacy_sink_persist_mu_;
    /// #4783 Gate 4 UP-3/UP-4: the change_gen (GuardianLegacySinkExecutor::
    /// Snapshot::change_gen) of the loss ledger this engine last successfully
    /// persisted to KvStore - see legacy_sink_kick()'s own doc comment for the
    /// gate this guards. A PLAIN uint64_t, not atomic: every read and write of
    /// this field happens under legacy_sink_persist_mu_ above (both call
    /// sites), which is what actually serializes the two threads that can
    /// touch it - the atomic this used to be only protected the field itself,
    /// never the read-modify-decide-write sequence around it (see
    /// legacy_sink_persist_mu_'s own doc comment for the race that left open).
    /// Default 0 matches a freshly-constructed (or freshly-restore()'d -
    /// restore() never touches change_gen) executor's own change_gen default,
    /// so the first post-boot kick()/stop() does not treat "nothing changed
    /// since restore()" as something worth a redundant write.
    std::uint64_t legacy_sink_last_persisted_gen_{0};
    /// TEST-ONLY (#4783 Gate 8 re-review): if set, invoked from
    /// legacy_sink_kick()'s persist block AFTER it has taken its snapshot and
    /// decided a write is needed, but BEFORE it actually calls
    /// persist_legacy_sink_loss_ledger() - reproducing the exact window the
    /// lost-update race occupied. CONTRACT: fires with legacy_sink_persist_mu_
    /// HELD on the calling thread - observe/park only; calling back into
    /// legacy_sink_kick() or stop() from the hook (directly, or via a
    /// same-thread call) self-deadlocks (a genuine same-thread std::mutex
    /// relock - same posture as set_rearm_fault_hook_for_test's CONTRACT
    /// above). The regression test below instead runs stop() on a SECOND
    /// thread, which the lock legitimately blocks until the hook releases -
    /// see test_guardian_engine_legacy_sink.cpp for the full orchestration.
    /// Set-then-use (arm before starting the kicker thread that will observe
    /// it); null = no-op, the production default. No production caller.
    std::function<void()> legacy_sink_persist_race_hook_for_test_;
    /// Journal persist / final-flush exceptions swallowed to keep the bare heartbeat thread +
    /// the (noexcept) destructor path from std::terminate (item 7 PR-Ag, review B4). Since C0
    /// (#2298) prune/page throws are counted on the drain worker instead; journal_stats() sums
    /// both into the single operator-facing guardian_journal_maint_exceptions tag.
    std::atomic<std::uint64_t> journal_maint_exceptions_{0};
    /// TEST-ONLY drain-worker timing overrides (see set_drain_worker_timing_for_test);
    /// 0 / zero-duration means "keep the production default".
    std::uint64_t test_periodic_bound_ms_{0};
    std::chrono::milliseconds test_page_interval_{0};
    std::chrono::milliseconds test_prune_interval_{0};
    /// TEST-ONLY (see set_spark_backend_op_deadline_for_test); nullopt = production default.
    std::optional<std::chrono::milliseconds> test_spark_backend_op_deadline_;
    /// Maintenance phase/forced-page jitter (see set_maintenance_jitter). OFF unless the
    /// production wiring turns it on, so every test's cadence stays deterministic.
    bool maintenance_jitter_{false};
    /// TEST-ONLY re-arm fault injector (see set_rearm_fault_hook_for_test); null = no-op.
    std::function<void(const std::string&)> rearm_fault_hook_for_test_;
    /// TEST-ONLY (see last_rearm_degrade_message_for_test); empty = no degrade this run.
    std::string last_rearm_degrade_message_for_test_;
    /// TEST-ONLY (see last_unsupported_log_for_test); default level None = never logged.
    UnsupportedLogRecord last_unsupported_log_for_test_;
    /// TEST-ONLY (see last_file_expected_hash_for_test); empty = no file-hash-equals
    /// arm attempt has run yet.
    std::string last_file_expected_hash_for_test_;
    /// TEST-ONLY (see last_file_on_baseline_wired_for_test); false = no
    /// file-hash-equals arm attempt has run yet.
    bool last_file_on_baseline_wired_for_test_{false};

    /// #4783: the detached, bounded, FIFO, gap-accounting sender legacy guard
    /// producers' events are enqueued on (emit_guard_event() -> offer()). Constructed
    /// UNCONDITIONALLY in the constructor (always live, regardless of prefer_spark_ -
    /// the legacy IGuard path is the one this executor exists for). Declared BEFORE
    /// guards_ deliberately: a guard's own worker thread may still call
    /// emit_guard_event() -> offer() during its OWN stop() (stop_all_guards_locked()
    /// joins guards_ one at a time, and an in-flight report on guard N+1 can still be
    /// racing that join while guard N's teardown is offer()-ing its own final event),
    /// so this executor must outlive every guards_ entry - reverse-declaration-order
    /// destruction means a member declared here is destroyed AFTER guards_.
    std::unique_ptr<GuardianLegacySinkExecutor> legacy_sink_executor_;
    std::unordered_map<std::string, std::unique_ptr<IGuard>> guards_;

    /// rule_id -> SparkType for every rule CURRENTLY classified RulePlacement::Unsupported
    /// (F7, #2298 rung 2): a known spark type with no mechanism registered on this host,
    /// enforced by NEITHER backend. Maintained by reconcile_rule_locked (mtx_ held): every
    /// outcome that is NOT Unsupported explicitly erases its own rule_id there; only the
    /// Unsupported branch inserts/updates. Deliberately not an erase-at-function-entry +
    /// reinsert pattern - that shape loses data if reconcile_rule_locked throws between the
    /// erase and the (much later) reinsert point (apply_rules's per-rule try/catch means it
    /// really can throw), and independently makes every retained-unsupported rule look
    /// newly-unsupported on a full_sync pass, spamming the edge-triggered log. Backs
    /// unsupported_counts_by_type(). Cleared (by rule_id sweep, not blanket) at the end of a
    /// full_sync apply_rules pass, and blanket-cleared in stop().
    std::unordered_map<std::string, SparkType> unsupported_rules_;

    // --- Spark detection path (rung 7) - all guarded by mtx_ except where noted ---
    const bool prefer_spark_; ///< IMMUTABLE for object lifetime; set only at construction
    SparkAvailability spark_availability_{SparkAvailability::Unwired};
    SparkEngine* spark_engine_{nullptr}; ///< BORROWED - see wire_spark_engine's doc
    std::shared_ptr<GuardianStateReader> spark_reader_;
    std::shared_ptr<GuardianSparkEngineBackend> spark_backend_;
    std::shared_ptr<GuardianSparkRuntime> spark_runtime_;
    /// rung 9c PR-2 Unit 5/6 (§R5.3 ack bookkeeping): the current push's accepted-
    /// but-unresolved arm episodes. Constructed unconditionally in the constructor
    /// (no backend dependency, unlike spark_runtime_) - engine-owned, never null.
    /// apply_rules() begins/feeds it; journal_maintenance_tick() drains it and
    /// advances policy_generation_ once it can_advance(); stop() retires it.
    std::unique_ptr<GuardianArmAckLedger> ack_ledger_;
    /// rung 9c PR-2 Unit 6: a throw from ack_ledger_->drain_locked() or the
    /// generation-advance it gates, caught on the bare heartbeat thread exactly
    /// like journal_maint_exceptions_ below (same B4a firewall posture).
    std::atomic<std::uint64_t> ack_maint_exceptions_{0};
    /// Durable lifecycle-audit journal (item 7 PR-Ag). Engine-owned (NOT the runtime: the runtime
    /// must borrow no KvStore); borrows kv_ (the agent owns it and destroys it AFTER the engine).
    /// Constructed in wire_spark_engine; persist calls are prefer_spark_-gated.
    ///
    /// SHARED with the drain worker, which uses it for both the send-wrap's mark_batch_sent
    /// and its prune/page maintenance pass. A shared_ptr rather than a unique_ptr + raw
    /// borrow because that borrow made correctness depend on this member being declared
    /// before spark_drain_worker_ - an ordering nothing would catch if changed
    /// (#2298 governance A4). The declaration order below is still the tidy one, but it is
    /// no longer load-bearing.
    std::shared_ptr<GuardianLifecycleJournal> lifecycle_journal_;
    std::unique_ptr<ConvergenceScheduler> spark_scheduler_;
    std::unique_ptr<GuardianOutboxDrainWorker> spark_drain_worker_;
};

/// Test-support helper: builds a __guard__ `CommandRequest` inside the
/// agent-core DLL, populates `parameters["push"]` with the supplied bytes,
/// and dispatches it through `engine.dispatch()`. Intended ONLY for unit
/// tests — production code paths in `agent.cpp` already own the full
/// CommandRequest lifecycle inside the DLL.
///
/// Why this helper exists (#501, load-bearing):
///
///   On Windows MSVC debug, abseil's `MixingHashState::Seed()` returns
///   `reinterpret_cast<uintptr_t>(&MixingHashState::kSeed)`. `kSeed` lives
///   in the static library `absl_hash.lib`, which is linked once into the
///   test EXE and once into `yuzu_agent_core.dll` (yuzu_proto is a static
///   lib that pulls in absl transitively, and it's linked into both
///   targets). Each image therefore has its own copy of `kSeed` at a
///   different virtual address. That address is the hash seed for every
///   protobuf `Map<K,V>` operation (see `google::protobuf::internal::Hash`
///   in `map.h` — it calls `absl::HashOf(k, salt)` which mixes in `Seed()`).
///
///   Result: if the test EXE populates a `Map<string,string>` via `insert()`,
///   the bucket index is computed using EXE-side `Seed()`. When the DLL
///   then calls `.find()` on the same map, the bucket index is computed
///   using DLL-side `Seed()` — a different value — so `find()` returns
///   `end()` even though the key is present. With two buckets (`kMinTableSize
///   = 16 / sizeof(void*) = 2` on 64-bit), this fails ~50% of the time on
///   average, deterministically for any specific key/seed combination.
///
///   Production doesn't hit this because the gRPC Subscribe stream parses
///   `CommandRequest` bytes inside `yuzu_agent_core.dll` (see `agent.cpp`
///   Subscribe loop), so population and lookup both use the DLL's seed.
///
///   Release builds happen to pass because aggressive inlining + `/OPT:ICF`
///   can fold the seed accesses; debug builds with `/INCREMENTAL` keep the
///   split. The fix is to keep the map population inside the DLL by using
///   this helper instead of hand-constructing a `CommandRequest` in test
///   code. See `.claude/agents/build-ci.md` for the broader #375 context
///   and `docs/yuzu-guardian-design-v1.1.md` §10 for the Guardian test
///   strategy.
YUZU_EXPORT GuardianDispatchResult
guardian_dispatch_push_bytes_for_test(GuardianEngine& engine,
                                      std::string_view push_param_bytes);

/// Test-support helper: emit a synthetic GuardDrift through the engine's
/// private emit_guard_event() so the resulting GuaranteedStateEvent can be
/// captured by a sink installed via set_event_sink(). Intended ONLY for unit
/// tests — production drift originates inside Windows-only guard workers. Used
/// by the #1307 regression test to assert the event_id embeds the agent_id.
YUZU_EXPORT void guardian_emit_drift_for_test(GuardianEngine& engine,
                                              const GuardDrift& drift);

/// Test-support helpers (#4021 adversarial-review K1/C2-1 regression net): reach
/// the persist-side overwrite guard and the seed-side lookup directly, since the
/// real call site (`FileGuard::Config::on_baseline`) fires only from a running
/// Windows-only guard worker thread — not exercisable end-to-end on this
/// platform's tests. Both are thin forwarders into guardian_engine.cpp's
/// anonymous-namespace `guardian_persist_baseline`/`guardian_seed_baseline`
/// (internal linkage) — not friends, no GuardianEngine state involved. No
/// production caller.
YUZU_EXPORT void guardian_persist_baseline_for_test(KvStore& kv, const std::string& rule_id,
                                                    const std::string& fingerprint,
                                                    const std::string& hash);
YUZU_EXPORT std::optional<std::string>
guardian_seed_baseline_for_test(KvStore& kv, const std::string& rule_id,
                                const std::string& fingerprint);

} // namespace yuzu::agent
