#pragma once

/**
 * guardian_spark_runtime.hpp - the shared, lifetime-safe core of the Guardian
 * spark consumer (ADR-0021 Stage 2 rung 3). Design:
 * docs/spark-stage2-guardian-consumer-design.md.
 *
 * This is the object the SparkEngine queued handler captures - and ONLY this. A
 * queued handler that blocks past the shutdown budget is DETACHED and may run
 * after GuardianEngine and the SparkEngine are gone (spark_engine.hpp capture-
 * lifetime contract). So the handler captures a shared_ptr<GuardianSparkRuntime>
 * that owns everything it touches (registry, per-key state, readers, outbox); it
 * never captures GuardianEngine, the SparkEngine, or the server sink by raw
 * reference. Emits go to the in-memory outbox, never straight to a sink, so a
 * detached late handler is memory-safe: it mutates only runtime-owned state.
 *
 * Concurrency model (Sol's rev-2 shape; the orchestration review BLOCKED the
 * naive version):
 *   - ONE evaluate_key(key, reason) for initial / event / convergence. Events are
 *     invalidation HINTS: evaluate_key always re-reads live state via the
 *     StateReader, never trusts a queued payload (prevents a stale queued value
 *     committing backward).
 *   - Per-key eval mutex held across read+commit, so read order == commit order
 *     for a key and the freshest read commits last (no backward compliance).
 *   - registry mutex guards the index / rule generations / per-key maps + the
 *     stopping flag; held only for brief, IO-free snapshot and commit sections.
 *   - #2233 item 3 / rung 9c R5.2: File/Registry/Service arm/disarm runs OFF
 *     registry_mu_ (GuardianIoExecutor). Each spark_key has at most one claim
 *     entry (claims_): a FIFO whose head is the operation in flight (an arm
 *     dispatched via the non-waiting submit(), or a disarm driven through the
 *     bounded run()) and whose tail is the siblings waiting behind it. A same-key
 *     attach during that window QUEUES behind the head rather than failing fast
 *     or double-arming; the arm's completion callback (a detached executor
 *     worker) commits the head and every live sibling against the one new
 *     subscription, or fails them all together. A disarm claim is retained at the
 *     head until it executes (admission refusals keep it, they never drop it), so
 *     "a key's disarm completes before its own rearm dispatches" holds by
 *     construction. In PR-1 attach_rule() still WAITS (bounded) for its own claim's
 *     outcome so GuardianEngine's synchronous contract is unchanged; PR-2 removes
 *     that wait.
 *   - Monotonic per-rule generations: a rule update installs a NEW
 *     RuleGeneration (never mutates one in place), so an in-flight eval on the
 *     old generation finishes harmlessly and its commit is rejected by a
 *     generation/active recheck.
 *   - Tri-state Unknown (guardian_rule_eval.hpp) leaves decider state untouched
 *     and routes a health event; a Known read commits a compliance verdict.
 *
 * LOCK ORDER (total, never inverted): drain_mu_  ->  per-key eval_mu  ->
 * registry_mu_  ->  outbox_mu_. Registry mutations take registry_mu_ -> outbox_mu_.
 * The drain (item 4) takes drain_mu_ (single-drainer), then CYCLES outbox_mu_ per
 * entry - copy the head, RELEASE outbox_mu_, run the injected send off-lock, re-acquire,
 * pop-if-unchanged - so a slow send never holds outbox_mu_. The send fn MAY take runtime
 * locks (e.g. outbox_size()) since outbox_mu_ is released across it, but it must NOT
 * re-enter drain() (drain_mu_ is non-recursive).
 *
 * last_eval_timings_mu_ (#4606 criterion-10) is a LEAF: taken standalone, briefly, at the
 * very end of evaluate_key() (after eval_lk and registry_mu_ have both already released)
 * and in last_eval_timings_for_test(); never held while taking any lock above.
 *
 * Rung 3 builds this against FAKE seams (IStateReader, ISparkBackend). The real
 * platform readers are rung 5; the convergence scheduler that also drives
 * evaluate_key is rung 4; the unified reconcile op (merge / full-sync / kill-
 * switch / mutual-exclusion) and the agent wiring are rung 7.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/spark.hpp> // SparkSpec, SparkEvent, SparkType, ServiceRunState

#include "guardian_io_executor.hpp" // GuardianIoExecutor, IoClass (#2233 item 3)
#include "guardian_journal_format.hpp" // JournalRecord + caps (item 7 PR-Ag)
#include "guardian_outbox.hpp"
#include "guardian_rule_eval.hpp"
#include "guardian_spark_timing.hpp" // #4606 criterion-10: EvalTrigger, EvalTimingRecord

#include <algorithm> // (std::min) in drop_oldest_pending_for_test
#include <atomic>
#include <cassert> // UP-6 (#4221): reclassify_dispatching_race_locked()'s debug guard
#include <new> // std::bad_alloc (detach_fault_here_for_test)
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <utility>  // std::exchange (CompensationPermit/RetainedGuard move ops)
#include <vector>

namespace yuzu::agent {

class SparkKeyRuleIndex; // spark_key_rule_index.hpp (fwd - kept out of this header's include set)

/// Why an evaluation is running. Initial and Convergence come from the runtime /
/// scheduler; Event comes from a SparkEvent hint. The verdict path is identical
/// (always a live re-read); the reason only tunes pending-initial bookkeeping.
enum class EvalReason { Initial, Event, Convergence };

/// What the file reader must resolve for a key. One watcher serves rules with
/// different caps, so the reader hashes ONCE at the largest admitting cap and the
/// evaluator projects oversize per-rule. hash_cap == 0 means no rule on the key
/// hashes (file-exists only) - skip hashing.
struct FileReadPlan {
    std::uint64_t hash_cap{0}; ///< max max_bytes over the key's file-hash rules; 0 = no hash needed
};

/// What the registry reader must resolve for a key. Rules under ONE (hive,key)
/// spark_key may watch DIFFERENT values, so the reader reads each requested value
/// (memoised per value_name) and returns a per-value map; the evaluator selects
/// its rule's value_name. Reading one snapshot and fanning it to all rules would
/// be wrong for a multi-value key.
struct RegistryReadPlan {
    std::vector<std::string> value_names; ///< distinct values to read under the key
};

/// The registry reader's result: a per-value_name read plus the measured latency
/// (registry is the one type that records detection_latency_us for parity). A key
/// that could not be opened fills every requested value_name with Unknown.
struct RegistryRead {
    std::unordered_map<std::string, ReadResult<RegistrySnapshot>> values;
    std::uint64_t latency_us{0};
};

/// The runtime's view of live endpoint state. Rung 5 supplies the platform
/// readers (file handle-scoped #807, registry RegOpenKeyExW, service SCM/sd-bus);
/// tests supply fakes.
///
/// CONTRACT for implementers (rung 5):
///   - A method returns Unknown (ReadResult.known == false) when it cannot
///     determine the value - never a fabricated absent/stopped.
///   - MUST be thread-safe: the convergence lanes and the consumer handler call it
///     concurrently for different keys (each call gets its own params/plan).
///   - MUST be bounded / cancellable: a read participates in shutdown (a lane join
///     and the consumer detach both wait on an in-flight read), so a platform call
///     that can block indefinitely (SCM, sd-bus, a filesystem stall) must carry a
///     timeout and degrade to Unknown rather than hang agent shutdown.
///   - MUST implement request_stop(): begin_stop() calls it (outside the runtime's
///     lock) so an in-flight / future read wakes and degrades to Unknown instead of
///     blocking a lane join or the consumer detach.
class IStateReader {
public:
    virtual ~IStateReader() = default;
    virtual ReadResult<FileSnapshot> read_file(const FileSparkParams& p, const FileReadPlan& plan) = 0;
    virtual RegistryRead read_registry(const RegistrySparkParams& p, const RegistryReadPlan& plan) = 0;
    virtual ReadResult<ServiceRunState> read_service(const ServiceSparkParams& p) = 0;
    /// Wake any waiting read and reject new ones so shutdown does not hang. Does NOT
    /// cancel a detached OS call already in a kernel syscall (that cannot be
    /// cancelled or joined); it decouples the waiter, which degrades to Unknown.
    /// MUST be idempotent and MUST NOT throw - the `noexcept` is load-bearing since
    /// begin_stop() runs from ~GuardianSparkRuntime(), where an escaping exception
    /// would std::terminate (the implementer must contain any exception itself, not
    /// merely avoid causing one). MUST NOT block on I/O or an unbounded wait; a
    /// short lock-protected critical section over in-memory state (no syscalls) is
    /// acceptable and is what GuardianStateReader does - this is not a wait-free /
    /// hard-realtime guarantee.
    virtual void request_stop() noexcept = 0;
};

/// The runtime's view of the spark backend: arm a watcher for a spec (returns the
/// per-key SubscriptionId) and disarm it. The production adapter binds the
/// runtime's ConsumerId to SparkEngine::arm/disarm (rung 7); tests fake it.
/// Uses a plain uint64 SubscriptionId so this header need not include
/// spark_engine.hpp.
class ISparkBackend {
public:
    virtual ~ISparkBackend() = default;
    virtual std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) = 0;
    virtual void disarm(std::uint64_t subscription) = 0;

    /// #2818 poll backstop: cheap, lock-only, no I/O (see SubscriptionHealth's own doc
    /// comment, spark.hpp). Non-pure so no pre-existing implementation (production or
    /// test fake) is forced to change — a double not exercising #2818 simply reports
    /// every subscription Healthy, which is the correct "not modeling this" default.
    /// ANY NEW PRODUCTION `ISparkBackend` MUST override this: an unoverridden default
    /// makes `revalidate_subscriptions()`'s poll backstop silently inert (fails open)
    /// for that backend, rather than failing loudly (governance Gate 2 finding, PR-2d)
    /// — `GuardianSparkEngineBackend` (guardian_spark_backend.hpp), the only production
    /// implementation today, does override it correctly.
    virtual SubscriptionHealth subscription_health(std::uint64_t /*subscription*/) {
        return SubscriptionHealth::Healthy;
    }
};

/// Injected monotonic clock (steady). Tests supply a deterministic source; the
/// default is steady_clock::now.
using RuntimeClock = std::function<std::chrono::steady_clock::time_point()>;

/// rung 9c PR-5b hardening (#4221, Gate 3 cpp-safety adjudication, this governance
/// run): move-only RAII permit for one slot in an atomic<int>-backed capacity pool.
/// Replaces a plain bool-guarded manual acquire/release pairing that cpp-safety's
/// RAII-floor adjudication declined to exempt - the proposer's "the resource crosses
/// a stack boundary, so RAII can't span it" reasoning was correctly rejected: the
/// permit doesn't need to live on a stack frame, only on the long-lived KeyClaim
/// object that already outlives both the acquiring call and the async release.
/// Engaging (constructing with a non-null slot pointer) is done under registry_mu_
/// by the one true acquire site (GuardianSparkRuntime::try_reserve_compensation_
/// locked()), paired atomically with the admission check that found capacity - but
/// the RELEASE side is deliberately NOT lock-dependent: the slot is std::atomic<int>
/// specifically so this guard's destructor is safe to run on ANY thread, without
/// registry_mu_ held, which is what makes it a genuine structural backstop against a
/// future call path that forgets an explicit release (the exact class of gap
/// cpp-safety's adjudication identified in the pre-refactor manual pairing). Never
/// copyable - a slot has exactly one owner; moving transfers ownership without
/// touching the counter.
///
/// Lifetime precondition (Gate 8 re-review, this governance run, security-guardian):
/// the pointer this permit holds is into GuardianSparkRuntime's own member storage
/// (compensation_reserved_count_), so an engaged permit must never outlive the
/// runtime it came from. This holds today because every async path that can hold a
/// claim with an engaged permit (on_arm_complete, finalize_arm_compensation) is
/// reached via a self = shared_from_this() capture, keeping the runtime alive until
/// the same critical section that releases the permit - a precondition the old
/// plain-bool field did not have (it read/wrote a value, not a pointer). A future
/// caller that engages a permit without going through the runtime's own
/// shared_from_this()-captured callback path would need to establish this same
/// guarantee itself.
class CompensationPermit {
public:
    CompensationPermit() = default;
    explicit CompensationPermit(std::atomic<int>* slot) noexcept : slot_(slot) {}
    CompensationPermit(const CompensationPermit&) = delete;
    CompensationPermit& operator=(const CompensationPermit&) = delete;
    CompensationPermit(CompensationPermit&& other) noexcept
        : slot_(std::exchange(other.slot_, nullptr)) {}
    CompensationPermit& operator=(CompensationPermit&& other) noexcept {
        if (this != &other) {
            reset();
            slot_ = std::exchange(other.slot_, nullptr);
        }
        return *this;
    }
    ~CompensationPermit() { reset(); }
    /// Idempotent: a no-op if already released or never engaged.
    void reset() noexcept {
        if (slot_) {
            slot_->fetch_sub(1, std::memory_order_relaxed);
            slot_ = nullptr;
        }
    }

private:
    std::atomic<int>* slot_{nullptr};
};

/// rung 9c PR-5b hardening (#4221, same cpp-safety adjudication as CompensationPermit
/// above): move-only RAII guard for the disarm_retained_ live-lifecycle count (see
/// GuardianSparkRuntime::disarm_retained()'s own doc comment). The target counter is
/// already std::atomic<std::uint64_t>, so - same reasoning as CompensationPermit -
/// the destructor is unconditionally safe to run off-lock, giving a structural
/// backstop against a future terminal-removal path that forgets to release it.
class RetainedGuard {
public:
    RetainedGuard() = default;
    explicit RetainedGuard(std::atomic<std::uint64_t>* counter) noexcept : counter_(counter) {}
    RetainedGuard(const RetainedGuard&) = delete;
    RetainedGuard& operator=(const RetainedGuard&) = delete;
    RetainedGuard(RetainedGuard&& other) noexcept
        : counter_(std::exchange(other.counter_, nullptr)) {}
    RetainedGuard& operator=(RetainedGuard&& other) noexcept {
        if (this != &other) {
            reset();
            counter_ = std::exchange(other.counter_, nullptr);
        }
        return *this;
    }
    ~RetainedGuard() { reset(); }
    /// Idempotent: a no-op if already released or never engaged.
    void reset() noexcept {
        if (counter_) {
            counter_->fetch_sub(1, std::memory_order_relaxed);
            counter_ = nullptr;
        }
    }

private:
    std::atomic<std::uint64_t>* counter_{nullptr};
};

class YUZU_EXPORT GuardianSparkRuntime : public std::enable_shared_from_this<GuardianSparkRuntime> {
public:
    /// A recovery emits a PAIR of entries (guard.healthy + the verdict) that
    /// enqueue_all lands atomically, so the outbox must always hold at least two -
    /// a smaller cap would reject every recovery forever (permanent health-recovery
    /// loss). The constructor floors the configured capacity at this.
    static constexpr std::size_t kMinOutboxCapacity = 2;

    struct Config {
        std::size_t outbox_capacity{4096};
        /// #2233 item 3: bound on the wall-clock a caller (GuardianEngine::apply_rules
        /// / start_local / stop, all still holding their own mtx_ throughout) waits
        /// for one backend arm/disarm. Matches GuardianStateReader's Registry/Service
        /// state-read deadline (guardian_state_reader.hpp) - generous for local
        /// TP_WAIT setup and SCM admission, well under what a dead UNC path or a
        /// wedged SCM/sd-bus can hold a mechanism's own lock for. A logical deadline
        /// only: it cannot cancel the OS call itself (RegOpenKeyExW,
        /// WaitForThreadpoolWaitCallbacks, an SCM query, or a File probe already
        /// inside SparkEngine's per-type lock) - it bounds how long THIS caller waits
        /// for it, not the call's own lifetime (io_executor_'s orphan-exit contract,
        /// wired through GuardianEngine::active_io_workers(), covers the rest).
        /// Configurable (unlike a compile-time constant) so a test can shrink it for
        /// fast, deterministic timeout coverage without a real multi-second sleep.
        std::chrono::milliseconds backend_op_deadline{5000};
        /// M1 item (a): minutes-cadence backstop re-emission of guard.unhealthy for a
        /// rule still stuck Unknown, so a lost/coalesced edge cannot leave the server's
        /// errored view stale forever (edge-only emission made the edge the SOLE source
        /// of truth). 0 disables refresh (edge-only, pre-F5 behaviour). Effective
        /// granularity floors at the owning convergence lane's sweep cadence (file:
        /// ~600s) since a refresh can only fire on a committed re-evaluation.
        std::uint64_t errored_refresh_ms{300'000};
        /// M1 item (b): consecutive Convergence-reason Unknown READS (committed or
        /// outbox-rejected - #2992) after which a still-pending-initial rule is
        /// demoted off the 5s priority lane to its normal type-lane cadence (the read
        /// flood, not the wire flood - errored_refresh_ms above already bounds the
        /// wire side). 0 disables the sweep-count demotion arm.
        std::uint64_t pending_demote_sweeps{12};
        /// Elapsed-time companion to pending_demote_sweeps: demote once this much time
        /// has passed since the rule first went pending, even if convergence sweeps
        /// were sparse (Event-driven eval alone never advances the sweep counter).
        /// Checked on every Unknown pass regardless of reason or enqueue outcome
        /// (#2992). 0 disables the elapsed-time demotion arm.
        std::uint64_t pending_demote_ms{120'000};
    };

    /// The runtime OWNS the reader and backend (shared_ptr): a queued handler that
    /// is detached at shutdown may run past GuardianEngine, so keeping the captured
    /// runtime alive must transitively keep everything the handler touches alive -
    /// a borrowed reader reference would UAF the moment the agent destroyed it under
    /// a detached mid-read. The clock callable must likewise be self-contained (the
    /// default captures nothing); a clock that borrows agent state reintroduces the
    /// same hazard.
    ///
    /// PRECONDITION (cpp-safety, adversarial review): every instance MUST be owned
    /// by a `shared_ptr<GuardianSparkRuntime>` for its ENTIRE lifetime (construct
    /// via `std::make_shared` - as `GuardianEngine::wire_spark_engine()` and every
    /// test fixture already do). `attach_rule()`'s claim path calls
    /// `shared_from_this()` (in `dispatch_arm_off_lock`, building the `submit()`
    /// completion callback) to keep the runtime alive on a detached
    /// `GuardianIoExecutor` worker; calling it on an instance with no owning
    /// `shared_ptr` throws `std::bad_weak_ptr` AFTER the claim is already queued and
    /// holds its `index_` mapping. That throw is caught in `dispatch_arm_off_lock`,
    /// which fails the claim (and every arm queued behind it) with "arm worker launch
    /// failed" and erases the entry - it does not permanently block the key. Not
    /// reachable today regardless (verified: every construction site uses
    /// `make_shared`), but this is a real precondition of the class now, not just of
    /// `enable_shared_from_this` abstractly.
    GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                         std::shared_ptr<ISparkBackend> backend);
    GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                         std::shared_ptr<ISparkBackend> backend, Config cfg,
                         RuntimeClock clock = RuntimeClock{});
    ~GuardianSparkRuntime();
    GuardianSparkRuntime(const GuardianSparkRuntime&) = delete;
    GuardianSparkRuntime& operator=(const GuardianSparkRuntime&) = delete;

    /// Build the SparkEngine queued handler for `rt`. It captures the shared_ptr
    /// (detach-safe) and routes each event to on_event. Static so the capture is
    /// unambiguously the shared_ptr and nothing else.
    static std::function<void(const SparkEvent&)> make_handler(std::shared_ptr<GuardianSparkRuntime> rt);

    /// Attach a rule: index it under spark_key(spec), arm the watcher on the
    /// key's 0->1 edge, and mark it pending its initial eval. Replaces any prior
    /// mapping for the same rule_id (a fresh generation + fresh eval state - the
    /// reconcile op at rung 7 is what preserves state across an identical
    /// re-push). Returns the new generation on success; an error string if the
    /// backend refused to arm, or this caller's bounded wait (cfg_.backend_op_deadline)
    /// ended first (the rule is left errored, NOT silently legacy - mutual
    /// exclusion; a timeout retries on the next push like any other arm failure).
    /// #2233 item 3 / rung 9c R5.2: for File/Registry/Service the actual backend call
    /// runs OFF registry_mu_ on a detached io_executor_ worker (submit()), and the
    /// commit runs in that worker's completion callback - every OTHER rule's
    /// attach/detach and evaluate_key proceed while this one's arm is pending, and a
    /// second attach on the SAME key QUEUES behind the in-flight claim (see KeyClaim)
    /// and commits against the same subscription when it lands, never a redundant
    /// backend arm and never a fail-fast. Interval/Startup/Disk stay synchronous/
    /// inline (never blocking OS watches).
    std::expected<std::uint64_t, std::string> attach_rule(std::string rule_id, SparkSpec spec,
                                                          RuleAssertion assertion,
                                                          bool emit_compliant_edge);

    /// Detach a rule: drop it from the index, disarm the watcher on the key's ->0
    /// edge, mark its generation inactive, and purge its buffered outbox entries.
    /// Idempotent for an unknown rule.
    void detach_rule(const std::string& rule_id);

    /// Detach EVERY currently-attached rule (mirrors GuardianEngine's legacy
    /// stop_all_guards_locked()). For the reconcile op's full_sync branch: a
    /// full sync replaces the active set, so any spark-attached rule the new
    /// push omits must be withdrawn too, not just the ones the per-rule loop
    /// revisits. Equivalent to calling detach_rule() for every attached rule_id,
    /// but atomic under one registry_mu_ acquisition.
    void detach_all();

    /// The queued-handler body: resolve `ev.key` to its rules and run one
    /// evaluate_key(Event) pass. Safe to call on a detached thread post-shutdown
    /// (it observes the stopping flag and commits nothing).
    void on_event(const SparkEvent& ev);

    /// Evaluate every active rule on `key` against a single live re-read. The sole
    /// eval path for all reasons. Serialised per key; commits a verdict to the
    /// outbox (or a health event on Unknown). No-op if stopping or the key is gone.
    /// `trigger` (#4606 criterion-10): the T_mechanism/T_handler context this pass was
    /// invoked with, when it was invoked from on_event() for a real Fired SparkEvent;
    /// absent for a Convergence-reason (or other no-event) pass. Purely diagnostic —
    /// never consulted by any eval/dispatch/commit decision.
    void evaluate_key(const std::string& key, EvalReason reason,
                       std::optional<EvalTrigger> trigger = std::nullopt);

    /// #2818 poll backstop: scan every armed key and query the backend's
    /// subscription_health() for it, cheaply (no I/O). A Dead subscription is
    /// reported "errored" exactly like a delivered Lost notification would have -
    /// this is the delivery-guarantee backstop for TWO ways a genuine Lost
    /// notification can fail to land, not an independent detection path:
    ///   (1) a full Queued consumer channel silently drops it (queued_dropped_total);
    ///   (2) a dedup-race window (governance Gate 4 unhappy-path UP-4): a sibling
    ///       queues onto a key whose first arm is still in flight off-lock (rung 9c
    ///       R5.2 made this reachable for direct concurrent callers; the window is
    ///       the same size as before: backend call returned -> the completion
    ///       callback re-acquires registry_mu_ and writes keys_[key]); if that arm
    ///       delivers Lost BEFORE the commit writes keys_[key],
    ///       on_subscription_lost's staleness guard sees no keys_ entry yet, treats
    ///       the notification as stale, and discards it - the commit that follows
    ///       then persists a subscription that is already dead, with its one Lost
    ///       already consumed, for the head and every sibling alike. This sweep is
    ///       what actually recovers that case, bounded by its own cadence rather
    ///       than instant.
    /// Intended to be driven off GuardianConvergenceScheduler's existing ~5s priority
    /// lane - no new thread. Scoped to Dead only: a missed Faulted/Recovered toggle is
    /// health-reporting-only (no enforcement break, no keys_ mutation), lower
    /// severity, and not backstopped here.
    void revalidate_subscriptions();

    /// Drain buffered emits through `send`. `send(const OutboxEntry&) -> SendResult`.
    /// Drains the Lifecycle audit log FIRST, then (only if it fully cleared) the
    /// compliance/health outbox - distinct structures internally (see
    /// GuardianLifecycleLog) but one send callback suffices since `send` can switch on
    /// OutboxEntry::domain. Holds drain_mu_ (single-drainer) and CYCLES outbox_mu_ per
    /// entry - the send runs with outbox_mu_ RELEASED (item 4), so a slow send never
    /// blocks enqueuers/heartbeat. The drain trigger (sink publication + reconnect +
    /// live wake-on-enqueue) is wired at rung 7; this is the mechanism. Returns the
    /// number SENT (not removed - a coalesced head counts as sent but is not popped).
    ///
    /// `limits` bounds ONE pass. Bounding exists because the caller's thread may carry
    /// OTHER periodic work (C0 #2298: the drain worker also runs journal retention).
    /// Unbounded, a slow stream drains the whole window - up to 4096 lifecycle entries -
    /// head-of-line blocking that work; on a slow link that starves retention until the
    /// journal hits its write ceiling and DROPS audit records. A caller that bounds a pass
    /// should re-drain immediately while `truncated` comes back true.
    struct DrainLimits {
        /// 0 = unbounded (the historical behaviour).
        std::size_t max_entries{0};
        /// Wall-clock cap on one pass, checked between sends. 0 = unbounded. A COUNT bound
        /// alone is not a safety bound: one slow-but-succeeding send makes an N-entry pass
        /// arbitrarily long, and the caller may be holding up a join (#2298 Sol review).
        std::chrono::milliseconds max_wall{0};
        /// Checked BEFORE every send. Lets a caller stop starting new sends the moment
        /// shutdown is requested rather than at the end of a whole bounded pass. The
        /// in-flight send is not interruptible; no further one begins.
        std::function<bool()> should_stop{};
        /// Fraction reserved for the compliance/health outbox so a busy lifecycle log cannot
        /// consume the entire pass. Applies to BOTH dimensions: the entry count and (gated on
        /// `max_wall > 0`, not on `max_entries`) the wall clock. The guarantee is that
        /// compliance gets an opportunity to START - not a slice of time, since an in-flight
        /// send cannot be interrupted. Unused lifecycle allowance rolls
        /// over, so this costs nothing when lifecycle is quiet. Load-bearing: draining
        /// lifecycle first with a SHARED budget silently recreated the detection blackout
        /// that Gate 4 UP-3 removed - compliance simply never ran (#2298 Sol review).
        std::size_t compliance_reserve_num{1};
        std::size_t compliance_reserve_den{2};
    };
    struct DrainOutcome {
        std::size_t sent{0};
        /// A limit cut the pass short (count, wall-clock, or should_stop) and entries may
        /// remain. The caller should re-drain without waiting rather than sleep.
        bool truncated{false};
    };
    /// Free slots in the lifecycle send window, sampled without a lock held by the caller.
    /// Used by the replay path as a pure OPTIMISATION - to avoid building entries for a batch
    /// that plainly cannot fit. It is NOT the authority on whether a batch was blocked: that
    /// comes back from try_page_batch's PageOutcome, decided under outbox_mu_, because this
    /// value can be stale by the time the attempt happens (#2345).
    [[nodiscard]] std::size_t lifecycle_headroom() const;
    /// Snapshot of the event_ids currently in the lifecycle send window, taken ONCE per replay
    /// pass. Lets the replay path size a candidate by its NET-NEW records rather than its raw
    /// entry count without taking outbox_mu_ per candidate. Same status as lifecycle_headroom():
    /// an optimisation, stale the moment it returns, never the authority - try_page_batch's
    /// PageOutcome decides under the lock (#2345 Gate 8 QE).
    [[nodiscard]] std::unordered_set<std::string> lifecycle_event_ids() const;

    std::size_t drain(const std::function<SendResult(const OutboxEntry&)>& send);
    DrainOutcome drain_bounded(const std::function<SendResult(const OutboxEntry&)>& send,
                               const DrainLimits& limits);

    // --- Durable lifecycle journal - staging seam (item 7 PR-Ag) ------------
    // Staging lives HERE (co-located with lifecycle_log_ under outbox_mu_) because
    // DISARM must stage inside detach_rule_locked. The KvStore-backed
    // persist/page/retention live in an engine-owned GuardianLifecycleJournal that
    // drives these via the narrow API below. The runtime NEVER touches a KvStore:
    // it is the detach-survival object and must OWN everything it touches (file
    // header), so the durable seam stays in the engine.

    /// A FIFO copy of the currently-staged (built + validated, not-yet-persisted)
    /// records. Immutable view; the caller serialises + writes them, then calls
    /// erase_persisted_prefix() for the count it durably wrote.
    /// A staging snapshot and the overflow-drop count observed WITH it, under one lock. The
    /// pair travels together because erase_persisted_prefix needs both to identify the prefix
    /// it wrote rather than trust an index a concurrent overflow drop can shift; returning
    /// them as one value is what stops a caller taking the snapshot and forgetting the count,
    /// which is the mistake that produced the bug in the first place.
    struct PendingSnapshot {
        std::vector<std::shared_ptr<const JournalRecord>> records;
        std::uint64_t drops_at_snapshot{0};
    };
    [[nodiscard]] PendingSnapshot snapshot_pending() const;

    /// Drop the oldest `n` staged records (those a persist just durably wrote).
    /// Clamped to the current size.
    /// TEST-ONLY: perform `n` overflow drop-oldest steps exactly as stage_pending_locked does
    /// at kMaxPendingJournalRecords (erase the front, count it). Reaching the real 4096-record
    /// ceiling from a test would need 4096 arms, which is why the interleaving that this
    /// models - a front-drop landing between snapshot_pending() and erase_persisted_prefix() -
    /// had no coverage. No production caller.
    void drop_oldest_pending_for_test(std::size_t n) {
        std::lock_guard<std::mutex> ob{outbox_mu_};
        // (std::min), not std::min: MSVC's min() macro would clobber it in a windows.h TU.
        n = (std::min)(n, pending_journal_.size());
        pending_journal_.erase(pending_journal_.begin(),
                               pending_journal_.begin() + static_cast<std::ptrdiff_t>(n));
        journal_stage_dropped_.fetch_add(n, std::memory_order_relaxed);
    }

    /// `drops_at_snapshot` is journal_stage_dropped() as read WITH the snapshot. It is what
    /// makes the erase identify the prefix rather than trust an index that a concurrent
    /// overflow drop can shift underneath it.
    void erase_persisted_prefix(std::size_t n, std::uint64_t drops_at_snapshot);

    /// Outcome of a page attempt, decided UNDER outbox_mu_ so it reflects the window as it
    /// actually was. A bare count could not distinguish "the window had no room for this
    /// batch" from "every entry was already a member" - opposite situations, and the caller
    /// needs the first to know a backlog is waiting (#2345 Gate 3).
    struct PageOutcome {
        std::size_t added{0};          ///< entries newly enqueued
        bool blocked_for_headroom{false}; ///< the batch did not fit, atomically observed
        std::size_t required{0};       ///< entries the batch needed when blocked
    };
    /// Page a REPLAYED batch into the send window: iff the window has >= batch-size headroom,
    /// enqueue each entry NOT already present (window-scan membership, no allocating set).
    /// Paged entries enter lifecycle_log_ ONLY (they are already durable - never
    /// pending_journal_). Does NOT wake the drain; the caller drives sending.
    ///
    /// Reports WHY nothing was added via PageOutcome above: a bare count could not separate
    /// "no room for this batch" from "every entry already a member", and the caller needs the
    /// first to know a backlog is waiting (#2345).
    [[nodiscard]] PageOutcome try_page_batch(std::vector<OutboxEntry> entries);

    /// Back-fill provenance onto the LIVE window entries of a just-persisted batch (review M3),
    /// so a live send writes its sent-label rather than the batch later ageing out counted
    /// evicted_without_send_evidence. Called from the engine persist boundary; takes outbox_mu_.
    /// `event_ids` are the batch's records in order; `last_event_id` is its last-in-batch record.
    void backfill_batch_provenance(const std::string& batch_key,
                                   const std::vector<std::string>& event_ids,
                                   const std::string& last_event_id);

    /// Current staged-record depth (gauge). Takes outbox_mu_.
    [[nodiscard]] std::size_t pending_journal_depth() const;

    // Staging integrity counters (design §2 loss table). Lock-free.
    [[nodiscard]] std::uint64_t journal_stage_dropped() const noexcept {
        return journal_stage_dropped_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_stage_failures() const noexcept {
        return journal_stage_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_field_rejected() const noexcept {
        return journal_field_rejected_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_clock_rejected() const noexcept {
        return journal_clock_rejected_.load(std::memory_order_relaxed);
    }
    /// Repeat Unknown evaluations whose guard.unhealthy was edge-suppressed (M1): a rule
    /// stuck errored is re-evaluated every convergence tick to catch recovery, but only the
    /// first Unknown of an episode emits a health event. Non-zero means at least one rule is
    /// persistently errored - the count is the number of ticks NOT flooded onto the wire.
    [[nodiscard]] std::uint64_t unhealthy_suppressed() const noexcept {
        return unhealthy_suppressed_.load(std::memory_order_relaxed);
    }
    /// M1 item (a): guard.unhealthy re-emissions for a rule still stuck Unknown, sent
    /// at errored_refresh_ms cadence so a lost/coalesced edge cannot leave the
    /// server's errored view stale forever. Distinct from unhealthy_suppressed() -
    /// this counts entries actually PUT ON THE WIRE (the refresh channel), the other
    /// counts ticks that were NOT (still bounded by errored_refresh_ms in between).
    [[nodiscard]] std::uint64_t unhealthy_refreshed() const noexcept {
        return unhealthy_refreshed_.load(std::memory_order_relaxed);
    }
    /// M1 item (b): rule_ids demoted off the 5s convergence priority lane to their
    /// normal type-lane cadence after pending_demote_sweeps consecutive Convergence-
    /// reason Unknown reads (committed or outbox-rejected - #2992) or pending_demote_ms
    /// elapsed, whichever first. A counted metric, not a silent behavior change
    /// (Option-A: every loss/suppression/resource-shedding channel is observable).
    [[nodiscard]] std::uint64_t priority_demoted() const noexcept {
        return priority_demoted_.load(std::memory_order_relaxed);
    }
    /// #2233 item 3 / rung 9c R5.2: attach_rule callers whose bounded wait
    /// (cfg_.backend_op_deadline) on their own claim ended before it resolved -
    /// whether the claim was still queued behind a sibling (queue-wait expiry) or
    /// already dispatched (the caller abandons it; the completion callback finishes
    /// it and disarms a late success) - PLUS submit_disarm_off_lock calls that hit
    /// the same deadline waiting on a backend disarm (detach_rule/detach_all/the
    /// prior-generation paths and the drain's own compensating disarm) - one shared
    /// counter for both directions, not just arm. Lock-free. Does NOT distinguish
    /// this from executor admission rejections (AlreadyRunning, CapacityExhausted,
    /// CeilingExhausted) at this surface - tracked separately, see #3813.
    [[nodiscard]] std::uint64_t backend_op_timeouts() const noexcept {
        return backend_op_timeouts_.load(std::memory_order_relaxed);
    }
    /// rung 9c R5.2: attach_rule calls that QUEUED behind an in-flight or retained
    /// same-key claim instead of dispatching a redundant backend arm (the shape that
    /// replaced #2233 item 3's fail-fast "busy" rejection). Unreachable via
    /// GuardianEngine's mtx_-serialised production callers until PR-2's cutover;
    /// exercised by direct concurrent callers of this class (tests). Lock-free.
    [[nodiscard]] std::uint64_t backend_op_queued() const noexcept {
        return backend_op_queued_.load(std::memory_order_relaxed);
    }
    /// rung 9c R5.2: disarm claims the executor refused at admission (capacity, key,
    /// ceiling, launch) and that were RETAINED at the head of their key entry rather
    /// than dropped (the #3415 gap, now counted); each is re-driven by the next
    /// same-key event.
    ///
    /// up-5 (#4221, rung 9c PR-5b): the number CURRENTLY retained - i.e. awaiting a
    /// redrive and not yet finally resolved. Was a monotonic, cumulative-since-boot
    /// event counter before this PR (correction recorded on issue #4221's own
    /// comment thread: a monotonic counter cannot answer "is anything stuck right
    /// now"); now a real lifecycle count, decremented on this same claim's own
    /// successful completion or any other terminal removal (Stopped-drop,
    /// DeadSubscription shortcut) - see mark_retained_locked()/clear_retained_
    /// locked(). A repeated refusal on the SAME already-retained claim
    /// (KeyClaim::retained_guard's own engaged check in mark_retained_locked())
    /// never inflates this past 1 for that claim. Lock-free read.
    [[nodiscard]] std::uint64_t disarm_retained() const noexcept {
        return disarm_retained_.load(std::memory_order_relaxed);
    }
    /// rung 9c R5.2: queued (never dispatched) claims dropped by begin_stop(), plus
    /// disarm claims the executor refused with Stopped. Lock-free.
    [[nodiscard]] std::uint64_t claims_dropped_at_stop() const noexcept {
        return claims_dropped_at_stop_.load(std::memory_order_relaxed);
    }
    /// up-3 (#4221): an arm was refused admission because its compensating-disarm
    /// reservation pool was exhausted (compensation_reserved_count_ at capacity for
    /// its IoClass) - the arm never dispatched, no backend call ran. Lock-free.
    [[nodiscard]] std::uint64_t compensation_reservation_refused() const noexcept {
        return compensation_reservation_refused_.load(std::memory_order_relaxed);
    }
    /// up-3 (#4221): a claim's compensation-observation deadline (KeyClaim::
    /// compensation_deadline, from cfg_.backend_op_deadline) was observed elapsed by
    /// expire_overdue_claims()'s maintenance pass, counted once per claim
    /// (compensation_deadline_observed latches). Observation-only in 5b - see the
    /// KeyClaim field's own doc comment; does not release anything. Lock-free.
    [[nodiscard]] std::uint64_t compensation_deadline_elapsed() const noexcept {
        return compensation_deadline_elapsed_.load(std::memory_order_relaxed);
    }
    /// up-2 (#4221, rung 9c PR-5c): a genuinely new claimant (different rule_id)
    /// was refused immediately against a Wedged key's head. Lock-free.
    [[nodiscard]] std::uint64_t wedged_refusals() const noexcept {
        return wedged_refusals_.load(std::memory_order_relaxed);
    }
    /// up-2 (#4221, rung 9c PR-5c): an identical (rule_id, spec) retry re-observed
    /// a Wedged key's existing head receipt instead of queuing a new claim.
    /// Lock-free.
    [[nodiscard]] std::uint64_t wedged_reobservations() const noexcept {
        return wedged_reobservations_.load(std::memory_order_relaxed);
    }
    /// Governance Gate 8 fix (rung 9c PR-5d /governance run): a wedged claim's
    /// late arm success was refused adoption because `rules_` already held an
    /// entry for its rule_id - NOT necessarily a bug. Reachable via entirely
    /// ordinary desired-state churn, no fault injection needed: rule R wedges on
    /// key A; R is redeployed to key B (commits normally, `rules_[R]` now live on
    /// B); R is redeployed BACK to key A while the ORIGINAL key-A arm is still
    /// in flight - `is_retained_wedge()` never consults `rg->active`, so the
    /// still-outstanding claim is genuinely re-observed and its adoption
    /// candidacy restored; when that original arm eventually completes, this
    /// counter increments and the stale success is safely disarmed instead of
    /// being adopted over the live key-B generation. A sustained, climbing rate
    /// is worth investigating (a rule redeploying faster than its own arm calls
    /// resolve), but a nonzero count alone is NOT itself evidence of a bug -
    /// unlike wedged_refusals_/wedged_reobservations_ above, whose triggers are
    /// narrower. Lock-free.
    [[nodiscard]] std::uint64_t wedge_adopt_stale_refused() const noexcept {
        return wedge_adopt_stale_refused_.load(std::memory_order_relaxed);
    }
    /// rung 9c R5.2: completion-callback drains whose OWN bookkeeping threw (not a
    /// commit throw, which is delivered to the waiter) - the firewall published a
    /// terminal outcome on every claim and dropped the entry. Lock-free.
    [[nodiscard]] std::uint64_t claim_drain_failures() const noexcept {
        return claim_drain_failures_.load(std::memory_order_relaxed);
    }
    /// Test seam: claims currently queued on `key` (0 when the key has no entry).
    [[nodiscard]] std::size_t claim_queue_depth_for_test(const std::string& key) const;
    /// Test seam (R5.7): {detach_epoch_, gen_counter_} snapshot, registry_mu_
    /// held internally. Lets a test assert the fence invariant directly -
    /// detach_all() bumps the epoch by exactly one, and every attach after it
    /// returns an incarnation strictly greater than the floor it reported -
    /// without needing log capture.
    [[nodiscard]] std::pair<std::uint64_t, std::uint64_t> application_fence_for_test() const;
    struct ArmReceipt;
    /// #4508: read-only claims_ walk; W1 requires at most one candidate per rule.
    [[nodiscard]] std::size_t wedge_candidate_count_for_test(const std::string& rule_id) const;
    /// Requires both FIFO-front identity membership and is_wedge_candidate_locked.
    /// Reuses only is_wedge_k_eligible_locked's membership shape, not its Dispatched
    /// gate: is_retained_wedge (defined in the .cpp) also accepts Dispatching.
    /// A refused, popped claim can retain every candidate field under a different
    /// committed generation (CH-4); receipt history alone cannot prove membership.
    /// False after adoption or pop even though receipt_status stays Wedged.
    [[nodiscard]] bool receipt_wedge_candidate_for_test(const ArmReceipt& receipt) const;
    /// Committed generation's active bit, or nullopt if absent (CH-3 W0 pin).
    [[nodiscard]] std::optional<bool> rule_active_for_test(const std::string& rule_id) const;
    /// #3816 / rung 9c R5.2: an arm's completion callback found a live subscription
    /// nobody was left to adopt - the head's caller had already timed out and no
    /// queued sibling was still waiting - so it disarmed it (a bounded run() on the
    /// same worker; a direct call on any non-timeout executor failure). The runtime's own
    /// late-SUCCESS-specific view (#3813's distinction kept at the source). Lock-free.
    [[nodiscard]] std::uint64_t backend_op_late_arms() const noexcept {
        return backend_op_late_arms_.load(std::memory_order_relaxed);
    }
    /// Live backend I/O workers for #2233 item 3's bounded arm/disarm executor - a
    /// second source GuardianEngine::active_io_workers() must sum alongside the
    /// state reader's own count for the process orphan-exit contract to stay
    /// accurate (hard_exit.hpp / guardian_io_executor.hpp).
    [[nodiscard]] std::size_t active_backend_op_workers() const {
        return io_executor_.active_worker_count();
    }

    /// Test seam (#3848): the bounded arm/disarm executor's own per-class counters,
    /// which this class otherwise never surfaces anywhere.
    ///
    /// WHY A TEST NEEDS THEM. backend_op_timeouts() counts ONLY IoFailure::Timeout. An
    /// arm or disarm the executor refuses outright - AlreadyRunning (the (class, key)
    /// single-flight ticket is still held) or CapacityExhausted (the per-class quota is
    /// full) - is counted NOWHERE at this surface (rung 9c R5.2: a refused DISARM is
    /// now retained + counted by disarm_retained(), but the executor-side breakdown
    /// still is not). A concurrency test that reconciles
    /// "every id armed" against "every id disarmed" therefore cannot distinguish a
    /// genuinely leaked subscription from a disarm the executor simply declined to run:
    /// both present as a surplus. Reading rejected_key/rejected_capacity and requiring
    /// them ZERO is what turns that reconciliation from "the lane partition made a
    /// collision unlikely" into an actual proof.
    ///
    /// TEST-ONLY ON PURPOSE, and the production gap is real and SEPARATE: the runtime
    /// still has no egress for these counters; a refused disarm is retained rather than
    /// dropped since rung 9c PR-1 (disarm_retained()), but the per-cause breakdown is
    /// still invisible to an operator. Tracked as #3415
    /// (docs/spark-legacy-delta-registry.md) - do NOT read this accessor as having
    /// closed it.
    [[nodiscard]] GuardianIoExecutor::Stats io_executor_stats_for_test() const {
        return io_executor_.stats();
    }
    /// Test seam (rung 9c R5.2): make the executor refuse the next launch(es) with
    /// LaunchFailed, so a disarm claim's retained-after-admission-refusal path can be
    /// exercised deterministically (the runtime's own executor is not injectable).
    /// Sticky until reset, like GuardianIoExecutor::set_fail_launch_for_test.
    void set_io_executor_fail_launch_for_test(bool v) { io_executor_.set_fail_launch_for_test(v); }
    /// R5.2 drain seam (adversarial-review fix round, C1/K1'): invoked on the
    /// on_arm_complete worker in the ONE gap where a key's outcome is decided but its
    /// claims are still unpublished - between step (1)'s unlock and the compensating
    /// disarm - which exists ONLY when a compensating disarm is owed. An ADOPTED commit
    /// publishes and pops inside step (1) itself and never reaches the hook; a test
    /// asserting "the hook did not fire" on a plain successful attach pins that. Set
    /// before triggering the drain; copied under registry_mu_ at the drain's start.
    void set_drain_gap_hook_for_test(std::function<void()> hook);
    /// rung 9c PR-5c (#4221) test seam: fires exactly once, at the very top of
    /// dispatch_arm_off_lock(), before that function takes registry_mu_ at all - a
    /// hook body is free to call expire_overdue_claims() or anything else needing
    /// that lock without deadlocking. This is the window a caller-side timeout
    /// needs to land in, racing either the reservation check or the executor
    /// submission further down in that function, to reproduce the
    /// Dispatching-window race deterministically. Set before triggering the
    /// dispatch; consumed (moved out, resetting to empty) under registry_mu_.
    void set_dispatch_entry_hook_for_test(std::function<void()> hook);
    /// R5.2 drain fault seam (C2/K5): consumed once by the next on_arm_complete.
    /// 1 = std::bad_alloc before the fifo snapshot (after `compensating` took ownership
    /// of a successful arm); 2 = a throw right after the first commit adopted the
    /// subscription (before its verdict is staged); 3 = a throw inside the publish
    /// after the verdicts were written into the claims but before the pop (governance
    /// pass-3 ch-1 seam: exercises step (3)'s catch and the terminal-head pop); 4 = a
    /// throw before the compensating-disarm continuation's allocation, i.e. while `sub`
    /// is captured in a local but before `built`/`cont` exist (adversarial review C1,
    /// PR #4318 fjarvis: proves the direct-disarm-and-fall-through recovery, not a
    /// std::terminate, is what happens here); 5 = a throw AFTER that allocation
    /// succeeded but while copying `key` into it, i.e. `built` is alive but `cont`
    /// is STILL null (Gate 8 re-review, cpp-safety + security-guardian, PR #4318: an
    /// earlier fix shape assigned `cont` before the key copy was known to succeed,
    /// so a throw here left `cont` non-null with an empty `key`, which made the
    /// continuation branch below run on top of an already-issued direct disarm AND
    /// made finalize_arm_compensation()'s claims_.find("") miss the real key,
    /// permanently wedging it - `cont` is now assigned only as the LAST statement
    /// of the try, so points 4 and 5 both leave it null identically). 0 = off.
    void set_drain_fault_point_for_test(int point) noexcept;
    /// R5.2 detach fault seam (adversarial re-review r2 C1): consumed once by the next
    /// detach_rule_locked that builds a DISARM claim - throws std::bad_alloc at the
    /// claim allocation, i.e. before the durable index_/rules_/keys_ mutation.
    void set_detach_fault_for_test(bool on) noexcept;
    /// R5.2 index-release fault seam (adversarial re-review r2 C2): consumed once by
    /// the next release_claim_index_locked - throws std::bad_alloc where
    /// index_->remove_rule's own key-copy allocation would, BEFORE the mapping or the
    /// claim's index_held flag is touched.
    void set_index_remove_fault_for_test(bool on) noexcept;
    /// R5.2 detach post-mutation fault seam (adversarial re-review r3 C4): consumed
    /// once by the next detach_rule_locked. 1 = std::bad_alloc where the lifecycle-kind
    /// string copy allocates (now BEFORE the durable mutation: the detach fails cleanly
    /// with the rule intact); 2 = std::bad_alloc where outbox_.drop_rule's Key
    /// allocation would (AFTER the mutation: contained and counted, the queued disarm
    /// is still handed to the caller). 0 = off.
    void set_detach_post_fault_point_for_test(int point) noexcept;
    /// R5.2 (r3 C4): a post-mutation, non-durable step of detach_rule_locked
    /// (outbox_.drop_rule) threw and was contained; the teardown and the queued disarm
    /// completed regardless. Expected 0. Lock-free.
    [[nodiscard]] std::uint64_t detach_post_commit_failures() const noexcept {
        return detach_post_commit_failures_.load(std::memory_order_relaxed);
    }
    /// R5.2: detach_rule_locked found itself unable to hand the subscription to a
    /// disarm claim (a throw inside index_->remove_rule after the claim was pushed,
    /// or the cannot-happen prediction mismatch) and took the counted rollback / last
    /// resort. Expected 0. Lock-free.
    /// Disarm claims completed WITHOUT a backend call because on_subscription_lost had
    /// already proven their subscription id dead (governance pass-3 cs-1): the claim a
    /// dead key's last detach queues is popped in the same critical section, so no
    /// undriven claim for a dead id lingers at the key's head and the next same-key
    /// attach arms without first redriving a no-op disarm.
    [[nodiscard]] std::uint64_t dead_subscription_disarms_skipped() const noexcept {
        return dead_subscription_disarms_skipped_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t detach_claim_failures() const noexcept {
        return detach_claim_failures_.load(std::memory_order_relaxed);
    }
    /// R5.2 (adversarial re-review r3 C2/C3): a claim's index release threw inside
    /// index_->remove_rule (its key-copy allocation) and was CONTAINED instead of
    /// crossing a noexcept boundary (the drain, a refill's admission-failure cleanup,
    /// begin_stop from the destructor); the claim keeps its index ownership for the
    /// next release to retry. Expected 0. Lock-free.
    [[nodiscard]] std::uint64_t claim_index_release_failures() const noexcept {
        return claim_index_release_failures_.load(std::memory_order_relaxed);
    }
    /// rung 9c PR-5a (#4221 cs-103): detach_rule_locked's last-on-key branch sweeps
    /// claims_[key] before constructing a new Disarm claim, on the belief (see the
    /// reachability note at that call site) that nothing survives the sweep. This
    /// counts every time that belief was WRONG - i.e. every time the debug-only
    /// assert() next to this counter's increment site would have fired in a debug
    /// build. Expected 0; unlike a bare assert() (compiled out under NDEBUG in a
    /// release build), this counter and its accompanying log line survive into
    /// release, matching this file's own established precedent at
    /// dispatch_arm_off_lock's "not an Arm claim" guard for a should-never-happen
    /// branch. A nonzero value here means the reachability note's call-graph
    /// argument was incomplete somewhere - re-open the investigation rather than
    /// assume it is safe to ignore.
    [[nodiscard]] std::uint64_t detach_sweep_left_residue() const noexcept {
        return detach_sweep_left_residue_.load(std::memory_order_relaxed);
    }

    /// Phase 1 of shutdown: set the stopping flag and mark every generation
    /// inactive under the registry lock, so no in-flight or late eval commits.
    /// Does NOT join threads (the SparkEngine consumer join is phase 2, owned by
    /// the caller at rung 7). Idempotent. #2233 item 3: also stops io_executor_,
    /// waking any attach_rule/detach_rule currently parked in a bounded backend
    /// wait immediately rather than making it ride out the full deadline. rung 9c
    /// R5.2: drops every QUEUED (never dispatched) claim with "stopping" (counted,
    /// claims_dropped_at_stop()) and wakes their waiters; a dispatched claim is left
    /// for its completion callback, which disarms a late success (R5.5).
    void begin_stop();

    // --- Telemetry / introspection (rung 3: enough to test; rung 8 adds the
    // spark_unsupported heartbeat gauge). All take the registry lock. ---
    [[nodiscard]] std::size_t armed_key_count() const;
    [[nodiscard]] std::size_t rule_count() const;
    [[nodiscard]] std::size_t outbox_size() const;
    [[nodiscard]] std::uint64_t outbox_backpressure_drops() const;
    /// rung 9c PR-3 (Decision 3, Option B): THIS instance's io_executor_ - summed
    /// across IO classes - CeilingExhausted (R5.1's physical alive-worker ceiling)
    /// refusal count. Deliberately narrow: NOT a general Counters/Stats egress -
    /// #3415 (docs/spark-legacy-delta-registry.md row D10) is the broader, still-
    /// open gap this accessor does not close (see io_executor_stats_for_test()'s
    /// own doc comment on that gap); this is one signal Dave ruled to ship now
    /// (~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md Decision 3), not
    /// the start of #3415's general counter wiring. Only THIS runtime's arm/disarm
    /// executor instance is reachable here - the state reader owns a separate
    /// GuardianIoExecutor instance with no egress of its own yet, and per D10 its
    /// run()-only usage means it structurally cannot hit CeilingExhausted anyway.
    [[nodiscard]] std::uint64_t io_ceiling_rejections() const;
    /// rule_ids still awaiting a first Known eval on `key` (the pending-initial
    /// dirty-set the convergence priority lane services). Includes DEMOTED rule_ids -
    /// this reflects "never Known", not priority-lane membership; use
    /// keys_with_pending_initial() to see which keys the priority lane still sweeps.
    [[nodiscard]] std::vector<std::string> pending_initial(const std::string& key) const;
    /// Test seam: rule_ids on `key` that have been demoted off the priority lane
    /// (M1 item (b)). A subset of pending_initial(key).
    [[nodiscard]] std::vector<std::string> pending_demoted_for_test(const std::string& key) const;
    /// #4606 criterion-10: the EvalTimingRecord batch staged by the most recent
    /// evaluate_key() call that REACHED the emission step, for direct unit-test inspection
    /// (field order / two-entry / accepted=false cases) without depending on log capture.
    /// A call that returns early (stopping runtime, withdrawn key, nothing planned, a
    /// non-event type) leaves the previous batch in place, and concurrent calls are
    /// last-writer-wins (the batch is assigned after the log I/O, so a slow older pass can
    /// overwrite a newer one), so only assert on it after a call you know reached emission
    /// and that nothing else is evaluating. Test-only.
    [[nodiscard]] std::vector<EvalTimingRecord> last_eval_timings_for_test() const;
    /// Test seam (#4606): make the timing staging in evaluate_key() throw as if an allocation
    /// failed when it is about to stage the record at index `k` OF THE PASS (0 = the first
    /// record, 1 = the second, ...; -1 = off, the default). ONE-SHOT: it disarms itself when
    /// it fires, so a later rule in the same pass stages normally. Proves the bookkeeping is
    /// best-effort: the real enqueue still happens, and only the failing rule's timing is
    /// dropped (records staged for earlier rules in the same pass survive).
    void fail_timing_stage_at_for_test(int k) noexcept {
        fail_timing_stage_at_for_test_.store(k, std::memory_order_relaxed);
    }
    /// Test seam (#4606): make the NEXT evaluate_key() timing `reserve()` throw as if it could
    /// not allocate. One-shot. Proves the reserve guard: the pass still enqueues and wakes.
    void fail_next_timing_reserve_for_test() noexcept {
        fail_timing_reserve_for_test_.store(true, std::memory_order_relaxed);
    }
    [[nodiscard]] bool stopping() const;

    /// A live status snapshot for one currently-attached rule, reflecting the
    /// LAST COMMITTED eval outcome (not a fresh re-read - matching every other
    /// introspection method here). `in_unknown` true means the last committed
    /// read was Unknown (the rule is errored, not compliant/drifted).
    /// `last_compliant` is nullopt until the first Known verdict ever commits.
    struct RuleStatusSnapshot {
        bool in_unknown{false};
        std::optional<bool> last_compliant;
    };
    /// nullopt if rule_id is not attached here (unknown to the runtime - e.g.
    /// legacy-armed, invalid, or never pushed; the reconcile op / GuardianEngine
    /// owns the wider status picture across both backends, rung 7.5).
    [[nodiscard]] std::optional<RuleStatusSnapshot> status_for_rule(const std::string& rule_id) const;

    // --- Convergence-scheduler seam (rung 4) ---
    /// Armed spark_keys whose spec is `type` - the lane a convergence thread
    /// sweeps on its own cadence (so a slow file hash never blocks a service
    /// reconcile).
    [[nodiscard]] std::vector<std::string> keys_for_type(SparkType type) const;
    /// Armed keys that still carry at least one NON-DEMOTED pending-initial rule (the
    /// priority lane's work-list). M1 item (b): a key whose every pending rule has been
    /// demoted (pending_demote_sweeps / pending_demote_ms) is excluded here - it still
    /// converges at its normal type-lane cadence via keys_for_type(), just no longer at
    /// the 5s priority cadence. A key with a MIX of demoted and non-demoted pending
    /// rules is still returned (the read cost is per-key, so the non-demoted sibling
    /// already pays it).
    [[nodiscard]] std::vector<std::string> keys_with_pending_initial() const;
    /// Install a waker the runtime invokes (OUTSIDE its lock) whenever a rule is
    /// newly attached with a pending initial eval, so the scheduler can service
    /// it immediately rather than waiting a full cadence. Pass {} to clear (the
    /// scheduler clears it before it tears down).
    void set_pending_initial_waker(std::function<void()> waker);
    /// Test seam: a copy of the currently-installed waker, to exercise the
    /// copied-waker-outlives-scheduler lifetime path.
    [[nodiscard]] std::function<void()> pending_initial_waker_for_test() const;

    // --- Live-drain seam (rung 7, F6) ---
    /// Install a waker the runtime invokes (OUTSIDE its lock, same lifetime-
    /// safety shape as set_pending_initial_waker) whenever ANY outbox mutation
    /// happens - a compliance/health commit in evaluate_key's commit section, OR
    /// a Lifecycle armed/disarmed enqueue in attach_rule/detach_rule. Called
    /// unconditionally after any such mutation (not gated on "was this truly a
    /// new key vs a coalesce" - a coalesced-in-place update is still fresh data
    /// waiting to be sent, and an extra CV wake is harmless, whereas under-
    /// waking risks steady-state staleness with no bounded recovery). Lets
    /// GuardianEngine's drain worker (rung 7.5) wake immediately instead of
    /// waiting for the next reconnect or periodic tick. Pass {} to clear.
    void set_outbox_enqueue_waker(std::function<void()> waker);
    /// Test seam: a copy of the currently-installed waker.
    [[nodiscard]] std::function<void()> outbox_enqueue_waker_for_test() const;
    /// Count of Lifecycle audit entries rejected for capacity (arm/disarm still
    /// succeeds regardless - the audit trail never blocks a real detection-
    /// capability change - but a drop here must be loudly observable, never
    /// silent). Takes only the outbox lock.
    [[nodiscard]] std::uint64_t lifecycle_backpressure_drops() const;
    /// #2233 item 7 test seam: how many times enqueue_lifecycle_locked's log-once
    /// branch actually fired an spdlog::warn (the FIRST capacity drop, arm or disarm
    /// side combined) - distinct from lifecycle_backpressure_drops() above, which
    /// counts every drop, logged or not. LogCapture (tests/unit/test_log_capture.hpp)
    /// is documented unreliable for code compiled into this shared library, so this
    /// object-state seam is the direct way to prove the log-once logic engaged,
    /// mirroring GuardianEngine::last_rearm_degrade_message_for_test's own precedent
    /// for the same class of gap. Lock-free.
    [[nodiscard]] std::uint64_t lifecycle_backpressure_log_fires_for_test() const noexcept {
        return lifecycle_backpressure_log_fires_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of drain sends that THREW (caught in drain(); the head is
    /// retained and that log's drain stops). A nonzero value means an entry could not be
    /// serialized/sent (e.g. a permanently-failing entry jamming the head, not just a
    /// stream-down Retain) - surfaced via the heartbeat by item 9. Lock-free.
    [[nodiscard]] std::uint64_t send_exception_count() const noexcept {
        return send_exceptions_.load(std::memory_order_relaxed);
    }

    /// Install the source of THIS agent's id, folded into every event_id so the
    /// server's global `event_id` PRIMARY KEY (drops on UNIQUE conflict, #1307)
    /// does not treat two agents drifting on the same rule - or the same agent
    /// after a restart - as duplicate events. A provider (not a fixed string) so the
    /// call site controls how current the value is; default is empty until wired.
    /// Wired by `GuardianEngine::wire_spark_engine()` (#2237) to a copy of the
    /// engine's own `agent_id_` - the same source and lifetime the legacy path
    /// already uses for its event_ids, set once at construction, not gated on a
    /// later Register completing.
    ///
    /// The provider MUST be self-contained (process-lifetime-safe captures), like
    /// the clock, and callable from ANY thread: since rung 9c R5.2 the arm commit -
    /// and so the "armed" lifecycle enqueue that calls this provider - runs on a
    /// detached io_executor_ worker, not only on the engine's mtx_-serialised
    /// callers. It must also never take GuardianEngine::mtx_ (that worker wears the
    /// GuardianDetachedWorkerRole marker and would abort). A by-value capture of an
    /// already-immutable string (the wired production provider) is safe; a provider
    /// that captures a pointer/reference back into its owner is not.
    void set_agent_id_provider(std::function<std::string()> provider);

private:
    /// Per-rule generation: an immutable assertion/spec-edge + monotonic
    /// generation + the mutable eval state. Held by shared_ptr so an in-flight
    /// eval keeps it alive across the registry-lock release; a rule update
    /// installs a NEW one rather than mutating fields, so eval() (which mutates
    /// `eval`) races nothing.
    struct RuleGeneration {
        std::uint64_t generation{0};
        bool active{true};            ///< registry_mu_-guarded; uncommitted wedge desire or committed rule state
        bool emit_compliant_edge{true};
        RuleAssertion assertion;
        RuleEvalState eval;           ///< mutated only under the key's eval_mu (single serialisation domain)
    };

    /// M1 item (b) bookkeeping for one rule_id still awaiting its first Known eval.
    /// registry_mu_-guarded (same as the map it lives in). `demoted` does NOT remove
    /// the entry from pending_initial - membership there still means "never produced a
    /// Known verdict" (pinned by existing tests); it only excludes the key from
    /// keys_with_pending_initial()'s priority-lane worklist. A demoted rule keeps
    /// converging (and keeps re-arming errored_refresh_ms) at its normal type-lane
    /// cadence, which is what makes 6b the staleness backstop for 6c.
    /// commit_new_generation_locked() reseeds this fresh (first_seen=attach_now,
    /// unknown_sweeps=0, demoted=false) on EVERY generation commit for a rule_id, not
    /// only on first attach - a same-rule_id content-plane push mid-demotion-episode
    /// restarts the demotion clock rather than carrying prior progress forward.
    struct PendingState {
        std::chrono::steady_clock::time_point first_seen{};
        std::uint64_t unknown_sweeps{0}; ///< Convergence-reason Unknown reads since first_seen
                                         ///< (committed or outbox-rejected - #2992)
        bool demoted{false};
    };

    /// Per-spark_key shared-watcher state. One armed watcher per key (the engine
    /// dedups); SubscriptionId is PER-KEY. `eval_mu` serialises a whole
    /// evaluate_key pass (read + fan-out + commit) for this key. Heap-stable
    /// (shared_ptr) because it holds a mutex.
    struct PerKey {
        SparkSpec spec;
        std::uint64_t subscription{0};
        std::mutex eval_mu;
        /// rule_ids awaiting a first Known eval (registry_mu_-guarded). A demoted
        /// entry stays a MEMBER (see PendingState::demoted) - reads are per-KEY, so a
        /// demoted rule sharing this key with a fresh non-demoted sibling still gets
        /// priority-lane-cadence reads via that sibling; only when every entry on a
        /// key is demoted does the key itself leave the priority worklist.
        std::map<std::string, PendingState> pending_initial;
    };

    /// rung 9c R5.2: the per-key claim/queue state machine (replaces #2233 item 3's
    /// single-slot `arming_keys_` busy marker). One KeyClaim is one operation a
    /// caller wants on a spark_key: an ARM (a rule attaching, holding everything
    /// commit_new_generation_locked needs) or a DISARM (a subscription
    /// detach_rule_locked has already withdrawn from keys_/rules_/index_ and still
    /// owes the backend call for). Claims live in claims_[key].fifo; the FRONT is
    /// the operation in flight (or a retained disarm awaiting redrive), everything
    /// behind it waits. Held by shared_ptr: a waiter keeps its handle across CV
    /// waits while other claims are erased around it, and the executor callback
    /// keeps the head alive past the caller. Rollback/erase match on POINTER
    /// identity - strictly stronger than #3831's (rule_id, generation) match, since a
    /// same-rule_id retry is a different object by construction.
    ///
    /// Structural fact the invariants lean on: a disarm claim is only ever created
    /// on a key with no keys_ entry left (detach_rule_locked erases it in the same
    /// critical section), and an arm claim never writes keys_ until it commits, so a
    /// fifo is always `[optional Disarm head] + [Arm claims...]` - "arm queued behind
    /// a disarm" is the real rearm-after-teardown shape, "disarm behind an arm" is
    /// unreachable. Asserted in debug; the code handles the general push regardless.
    ///
    /// Index ownership: an Arm claim that is neither withdrawn nor abandoned holds
    /// exactly one index_ (key, rule_id) mapping (`index_held`), added when it is
    /// queued (index_->add is the 0->1 detector and detach_rule_locked finds claimed
    /// rules through key_for_rule) and released by whichever code marks it withdrawn,
    /// abandoned, failed, or committed (commit passes ownership to the normal
    /// rules_/keys_ state). Every index_->remove_rule for a claim is guarded by that
    /// flag because remove_rule() removes the CURRENT mapping with no generation
    /// check (spark_key_rule_index.hpp) - a stale claim must never remove a
    /// replacement's mapping.
    ///
    /// `end` is a PR-5 plug point: a FACT about how the claim ended, recorded so the
    /// fault-wiring rung (wedge marking / K-bound / arm_failed reason) has something to
    /// classify. PR-1 carries NO classification logic on it; the only reads are the
    /// bookkeeping guards (a `Committed` claim is a rules_ entry, never "pending":
    /// detach_rule_locked's Case-0 skip, and the drain's publish fill-in).
    enum class ClaimKind { Arm, Disarm };
    enum class ClaimDispatch { Queued, Dispatching, Dispatched };
    enum class ClaimEnd {
        None, Committed, BackendRefused, WorkerThrew, AdmissionRejected, Withdrawn,
        WaiterTimedOutQueued, WaiterTimedOutDispatched, Stopped, CommitThrew, DisarmDone,
        DeadSubscription ///< Disarm: its subscription id was already reported dead (Lost);
                         ///< completed without a backend call (governance pass-3 cs-1)
    };
    struct KeyClaim {
        ClaimKind kind{ClaimKind::Arm};
        ClaimDispatch dispatch{ClaimDispatch::Queued};
        std::string key;
        IoClass io_class{};
        bool withdrawn{false};        ///< Arm: its rule was detached while claimed (Case 0 generalised)
        bool waiter_abandoned{false}; ///< the PR-1 synchronous waiter gave up (deadline / stop)
        bool index_held{false};       ///< Arm: owns index_'s (key, rule_id) mapping (see above)
        std::uint32_t admission_rejections{0}; ///< Disarm: retained-after-refusal count
        /// Written exactly once, under registry_mu_, when the claim reaches a terminal
        /// state; what the waiter returns. A disarm's retained-after-refusal return to
        /// its caller is NOT an outcome (the claim is still live).
        std::optional<std::expected<std::uint64_t, std::string>> outcome;
        std::exception_ptr commit_exception; ///< a commit throw, rethrown on the waiter's thread
        ClaimEnd end{ClaimEnd::None};
        // Arm payload (built off-lock in attach_rule, exactly as before).
        std::string rule_id;
        std::uint64_t generation{0};
        SparkSpec spec;
        std::shared_ptr<RuleGeneration> rg;
        std::string rule_name;
        const char* guard_type{""};
        std::chrono::steady_clock::time_point attach_now{};
        /// rung 9c PR-2 Unit 2 (Astra opine review Blocker 2 / coordinator ruling
        /// 2026-09-12): real monotonic deadline for THIS claim's own arm attempt, set
        /// once in attach_core() at the same instant the blocking wrapper's own
        /// wait_for_claim() deadline has always approximated - std::chrono::
        /// steady_clock::now(), never the injected evaluation clock_() ("Record real
        /// monotonic deadlines in the claim. Do not reuse the injected evaluation
        /// clock."). Meaningful for Arm claims only - since Unit 3, a Disarm claim
        /// has no caller-side deadline at all: submit_disarm_off_lock's submit()
        /// call has none (guardian_io_executor.hpp: "there is no waiter to time
        /// out"), so there is nothing for this field to bound. Consulted by
        /// expire_overdue_claims() so a
        /// non-waiting caller's claim still times out with nobody blocked in
        /// wait_for_claim() to notice - the existing timeout-fails-attempt behavior,
        /// just relocated out of a waiter, not removed.
        std::chrono::steady_clock::time_point deadline{};
        // Disarm payload.
        std::uint64_t subscription{0};

        // up-3/up-4 (#4221, rung 9c PR-5b): Arm-claim-only compensation bookkeeping.
        // `compensation_permit`, when engaged, is this claim's held slot in the
        // compensating-disarm reservation pool (rung 9c PR-5b hardening, this
        // governance run: an RAII CompensationPermit - see that class's own doc
        // comment - replacing a plain bool the pre-hardening cpp-safety RAII-floor
        // adjudication declined to exempt). Engaged the instant
        // dispatch_arm_off_lock() reserves this claim's slot, BEFORE the arm is
        // ever submitted - see compensation_reserved_count_'s header comment.
        // `compensation_finished` defaults true (nothing to track yet);
        // dispatch_arm_off_lock() never touches it, on_arm_complete() sets it false
        // the instant a live subscription becomes compensation-owed (entering the
        // `if (compensating)` branch) and back to true - in the SAME critical
        // section that pops/publishes the claim - once the compensating disarm has
        // genuinely finished (or turned out never to be needed).
        // expire_overdue_claims()'s terminal-recovery pass (up-4) reads it to know a
        // terminal/stranded head is safe to reap: never touch one whose compensation
        // is not yet finished. `compensation_deadline` is set ONCE, when
        // compensation first becomes owed, from cfg_.backend_op_deadline - never
        // reset on a fallback retry. `compensation_deadline_observed` is a
        // once-only latch: in 5b, an elapsed deadline only increments
        // compensation_deadline_elapsed_ (see the class-level comment there) - it
        // does not, and must not, release the reservation, the subscription, the
        // FIFO head, or worker accounting; a blocked OS call cannot be
        // force-cancelled.
        std::optional<CompensationPermit> compensation_permit;
        bool compensation_finished{true};
        std::chrono::steady_clock::time_point compensation_deadline{};
        bool compensation_deadline_observed{false};

        // up-5 (#4221, rung 9c PR-5b): Disarm-claim-only. Engaged from this claim's
        // FIRST retention (an admission refusal or worker throw) until it is either
        // finally removed (success, Stopped-drop, DeadSubscription shortcut) or
        // successfully redriven to completion - see disarm_retained()'s own doc
        // comment on GuardianSparkRuntime for the full lifecycle contract. A
        // repeated refusal on the SAME already-retained claim must never engage a
        // second RetainedGuard (mark_retained_locked()'s own idempotency check on
        // this member is what makes that safe). RAII (rung 9c PR-5b hardening, this
        // governance run) replacing a plain bool for the same cpp-safety-adjudicated
        // reason as compensation_permit above.
        std::optional<RetainedGuard> retained_guard;
    };
    struct KeyClaimQueue {
        std::deque<std::shared_ptr<KeyClaim>> fifo; ///< front() = the current claim
    };

    /// rung 9c PR-2, Unit 1 (shared attach core): attach_rule()'s outcome BEFORE any
    /// wait. Armed/Failed mean already resolved - the caller need not wait further.
    /// Pending means the claim returned alongside it is this call's own live claim,
    /// already enqueued in claims_ and (if selected) already dispatched off-lock; the
    /// public, blocking attach_rule() waits on it via wait_for_claim(). Vocabulary
    /// matches docs/spark-stage2-guardian-consumer-design.md §R5.3 (Armed / Accepted
    /// / Failed) - Pending, not a fourth outcome word, names the same "not yet
    /// resolved" concept from the runtime's own side, where a future non-waiting
    /// entry point (not yet added) would report it as Accepted.
    ///
    /// rung 9c PR-5c (#4221 up-2): Reobserved means this call created NO new claim
    /// at all - it is an identical (rule_id, spec) retry onto a key whose head is
    /// already Wedged, and the claim returned alongside it is that EXISTING,
    /// already-owned head, handed back purely for observation. Like Pending, the
    /// caller need not wait further in the sense that nothing further will ever
    /// resolve differently by waiting - the head's own eventual resolution is
    /// already in motion independently of this call.
    enum class AttachCoreState { Armed, Pending, Failed, Reobserved };
    struct AttachCoreResult {
        AttachCoreState state{AttachCoreState::Failed};
        std::uint64_t generation{0};      ///< valid iff state == Armed
        std::string error;                ///< valid iff state == Failed
        /// rung 9c PR-5c round 2 (#4221, UP-1 residual): valid iff state == Failed.
        /// True iff THIS return happened BEFORE detach_rule_locked(rule_id) ran
        /// anywhere in this call - i.e. rule_id's prior committed/claimed state (if
        /// it had any) is untouched, exactly as it was when this call started.
        /// False means detach_rule_locked(rule_id) already ran earlier in this same
        /// call (and, on the inline-type backend-failure path, this attempt's own
        /// newly-created state was also fully rolled back) - rule_id has nothing
        /// left either way, so a caller's defensive cleanup afterward is a genuine
        /// no-op. A caller MUST skip that defensive cleanup when this is true:
        /// rule_id's real, still-live arm would otherwise be torn down one call
        /// later by cleanup that assumes (the now-stale premise) "attach_rule
        /// leaves nothing on failure" - see attach_rule(NonWaiting, ...)'s ArmError
        /// and GuardianEngine::reconcile_rule_locked()'s own comment.
        bool prior_state_preserved{false};
        /// valid iff state == Pending OR Reobserved. An OBSERVATION handle only
        /// (rung 9c PR-2, Astra opine review 2026-09-12): destroying it must never
        /// withdraw the rule or abandon its operation - ownership of cancellation
        /// stays in claims_ and the callback's own capture, exactly as it does
        /// today for attach_rule's local `arm_claim`. For Reobserved specifically,
        /// this call OWNS NOTHING NEW - the claim is the pre-existing head's own
        /// object, already owned by whatever attach originally created it.
        std::shared_ptr<KeyClaim> claim;
    };

public:
    /// rung 9c PR-2 Unit 2 (Astra opine review, Blocker 3): tag selecting the
    /// non-waiting attach_rule() overload below - a distinct type, not an easily
    /// missed boolean, so a call site cannot silently pick the wrong overload.
    struct NonWaiting {};

    /// An OBSERVATION handle onto a claim the non-waiting attach_rule() overload
    /// returned as Accepted (Astra opine review, Blocker 1: "The receipt should be
    /// an observation handle. Destroying it must neither withdraw the rule nor
    /// abandon its operation."). Wraps the SAME shared_ptr<KeyClaim> the blocking
    /// attach_rule() would have waited on - no separate allocation, and ownership of
    /// cancellation/commit stays entirely in claims_ and the completion callback's
    /// own capture, exactly as it does today for attach_rule's local `arm_claim`.
    struct ArmReceipt {
        std::shared_ptr<KeyClaim> claim;
    };

    /// Authoritative, allocation-free status of an ArmReceipt's claim (Astra opine
    /// review: "An asynchronous receipt needs an allocation-free authoritative
    /// status, with diagnostic strings optional. An erased claim with no string
    /// must not look pending forever."). receipt_status() derives this from
    /// KeyClaim::end ALONE, not from `outcome`/`commit_exception` - `end` is a
    /// nothrow enum write on every terminal path, set even when the accompanying
    /// `outcome` string failed to allocate (see begin_stop's queued-claim drop and
    /// publish_locked's own fill-in, both of which write `end` unconditionally),
    /// which is exactly the case that must not read back as stuck Pending.
    /// rung 9c PR-5c (#4221): `Expired` split into `CongestionExpired` (timed out
    /// merely queued behind another claim - never reached dispatch, ordinary
    /// backpressure) and `Wedged` (timed out while dispatching/dispatched - the
    /// state up-2's immediate-refusal/re-observation logic keys off). "Wedged" is a
    /// SLIGHT overclaim for this name: `Dispatching` doesn't prove the backend call
    /// actually started, and compensation can remain outstanding even after an arm
    /// eventually returns - read it as "an overdue retained dispatch episode," not
    /// a guarantee the backend is literally hung.
    enum class ReceiptStatus {
        Pending, Committed, Failed, CongestionExpired, Wedged, Withdrawn, Stopped
    };

    /// R5.7 (docs/spark-stage2-guardian-consumer-design.md): which path reached
    /// commit_new_generation_locked(). A closed set - the T2 log line tags every
    /// commit with it so the #3990 diagnostic can tell a real backend arm() from
    /// a shared-watcher join or a wedge late-success adoption. Adding a sixth
    /// caller means adding a value here (enforced by review + -Wswitch, not by
    /// the build - werror=false repo-wide).
    enum class CommitPath {
        InlineArm,       ///< attach_core: inline type, synchronous backend_->arm() just returned
        InlineShared,    ///< attach_core: joins an already-committed watcher, no backend call
        CallbackArm,     ///< on_arm_complete: first SURVIVING live claim adopts the
                         ///< subscription and creates the PerKey (a withdrawn head is skipped)
        CallbackShared,  ///< on_arm_complete: a later live claim joins that watcher
        CallbackAdopt,   ///< on_arm_complete: a retained wedge's late success adopted (PR-5d)
    };

    /// registry_mu_ taken internally (short critical section, allocation-free). A
    /// default-constructed (empty) receipt reports Failed - there is nothing to
    /// observe.
    ReceiptStatus receipt_status(const ArmReceipt& receipt) const;
    /// Convenience: receipt_status(receipt) != ReceiptStatus::Pending.
    bool is_terminal(const ArmReceipt& receipt) const;

    /// rung 9c PR-5e (#4221, K-bound closeout - adversarial-review-class finding,
    /// cpp-safety): `status` exactly as receipt_status() would report, and
    /// `wedge_eligible` (meaningful ONLY when `status == Wedged`, false otherwise)
    /// exactly as receipt_wedge_k_eligible() would report - both computed under
    /// ONE registry_mu_ acquisition. A caller needing BOTH facts about the same
    /// receipt must use this, never receipt_status() followed by a separate call
    /// to receipt_wedge_k_eligible() - the two-call sequence has the identical
    /// TOCTOU shape the adversarial review found and fixed in
    /// GuardianArmAckLedger::drain_locked()'s recovery-scan loop
    /// (receipt_recovery_status()'s own doc comment), just reachable from
    /// drain_locked()'s PRIMARY per-pending loop instead: a claim read as Wedged
    /// by call 1 can be genuinely adopted-and-popped by on_arm_complete() in the
    /// gap before call 2, which then (correctly, as of that later instant) reports
    /// not-eligible - but the caller has already committed to treating the
    /// receipt as a failure based on call 1's stale snapshot, permanently losing
    /// the genuine success for this specific application (self-heals only on the
    /// NEXT identical retry, via decide_retry()'s forced Reapply once
    /// resolved_failed>0 - not truly unbounded, but a real, avoidable gap).
    struct WedgeAwareStatus {
        ReceiptStatus status{ReceiptStatus::Failed};
        bool wedge_eligible{false};
    };
    [[nodiscard]] WedgeAwareStatus receipt_status_wedge_aware(const ArmReceipt& receipt) const;
    /// rung 9c PR-5d (concern 2, arm-recovery): true iff `receipt`'s own claim has
    /// been ADOPTED - i.e. rules_ currently carries a live generation for that
    /// claim's rule_id AND it is EXACTLY this claim's own (rule_id, generation)
    /// incarnation, not a newer or older one that happens to share the rule_id.
    /// `end`/`receipt_status()` never change on adoption (the sticky-Wedged
    /// receipt stays Wedged - a per-episode historical fact, docs/spark-stage2-
    /// guardian-consumer-design.md R5.3), so this is a SEPARATE signal for
    /// noticing a late-success recovery on a claim still held as a retained
    /// failure. rung 9c PR-5e (#4221, K-bound closeout - governance Gate 4/
    /// consistency-auditor finding): `GuardianArmAckLedger::drain_locked()`'s
    /// recovery-scan loop, this accessor's own original motivating caller, now
    /// calls the atomic `receipt_recovery_status()` below instead (this standalone
    /// accessor's own two-call combination with `receipt_wedge_k_eligible()` has a
    /// TOCTOU `receipt_recovery_status()`'s own doc comment explains) - this
    /// accessor stays live standalone API, currently with no production caller.
    /// False for a default-constructed / empty receipt (nothing to recover) and
    /// false for any receipt whose claim was never adopted. registry_mu_ taken
    /// internally.
    [[nodiscard]] bool receipt_recovered(const ArmReceipt& receipt) const;

    /// rung 9c PR-5e (#4221, K-bound closeout): true iff `receipt`'s own claim is a
    /// CURRENTLY, GENUINELY outstanding Wedged episode - the narrow subset of "sticky
    /// Wedged" (see receipt_status()'s own doc comment) that K-bound may waive.
    /// `end == ClaimEnd::WaiterTimedOutDispatched` alone is NOT sufficient - `end` is
    /// sticky (never un-Wedges) but the underlying episode is NOT: (1) a caller-side
    /// timeout can stamp WaiterTimedOutDispatched while the claim is still mid-dispatch
    /// (abandon_claim_locked()'s Dispatching branch), racing dispatch_arm_off_lock()'s
    /// own re-lock, which - on a synchronous admission refusal - corrects the REAL
    /// outcome via reclassify_dispatching_race_locked() but ONLY while `dispatch` is
    /// still Dispatching; `dispatch` itself never reaches Dispatched on that corrected
    /// path (dispatch_arm_off_lock only ever writes Dispatched on a successful
    /// submission, see its own body) - so requiring `dispatch == Dispatched` here
    /// excludes exactly that unsettled/corrected window, never the genuinely-launched-
    /// and-still-outstanding case (a claim that IS submitted reaches Dispatched
    /// immediately, well before any real backend deadline, and simply stays there for
    /// as long as the backend call genuinely runs). (2) A LATER real backend outcome
    /// (a synchronous refusal on the worker, or any other on_arm_complete() resolution)
    /// leaves `end` stuck at Wedged by design (the sticky-Wedged receipt is a fact
    /// about the ORIGINAL episode, not a live status - R5.3 "Three separate
    /// transitions, never collapsed") but POPS the claim from its key's FIFO the
    /// instant that resolution is published - so requiring `claim` to still be
    /// `claims_[claim->key]`'s FIFO FRONT is the "still-claimed" test
    /// docs/spark-legacy-delta-registry.md's own K-bound row names: once popped, this
    /// reads false forever for that claim, regardless of what `end` still says. Both
    /// checks together, evaluated atomically under registry_mu_ (the same lock every
    /// FIFO pop and every reclassify_dispatching_race_locked() call already holds), are
    /// race-free: an external reader (GuardianArmAckLedger::drain_locked()) can only
    /// ever observe the state strictly before or strictly after either transition, never
    /// in between. False for a default-constructed / empty receipt, an unclaimed key, or
    /// a key whose front is a different claim entirely. Never mutates state (a query
    /// only, matching receipt_recovered()'s own contract) - registry_mu_ taken
    /// internally.
    [[nodiscard]] bool receipt_wedge_k_eligible(const ArmReceipt& receipt) const;

    /// rung 9c PR-5e (#4221, K-bound closeout - adversarial review finding, Kimi K3 +
    /// Codex Sol independently converging): the ATOMIC combination of
    /// receipt_recovered() and receipt_wedge_k_eligible(), for a caller that needs
    /// BOTH questions answered about the exact same instant. Calling the two
    /// standalone accessors sequentially (each takes and releases registry_mu_
    /// independently) is NOT equivalent to this - a genuine adoption can land in the
    /// gap between them: the first call correctly observes "not yet recovered", the
    /// adoption's on_arm_complete() pops the claim in the window, and the second call
    /// then observes "not eligible either" (no longer FIFO-front) - so a caller
    /// combining the two booleans with `if (recovered) ... else if (!eligible) ...`
    /// can misclassify a genuine, just-landed recovery as "no longer eligible",
    /// dropping it without recording the recovery (GuardianArmAckLedger::
    /// drain_locked()'s own recovery-scan loop is exactly this caller - see its own
    /// comment on why it uses this accessor instead of the two standalone ones).
    /// `Recovered` takes priority over `WedgeEligible` when both could apply (they
    /// cannot in practice - an adopted claim's rule generation match and an
    /// unadopted claim's FIFO-front position are mutually exclusive states of the
    /// SAME claim - but the priority is stated for clarity, not because the case is
    /// reachable). `Blocking` covers every other case: an empty receipt, a claim
    /// neither recovered nor currently wedge-eligible (settled to a genuine
    /// refusal/rejection/withdrawal, or already popped by a resolution nobody
    /// adopted). registry_mu_ taken ONCE, internally; never mutates state.
    enum class RecoveryStatus { Recovered, WedgeEligible, Blocking };
    [[nodiscard]] RecoveryStatus receipt_recovery_status(const ArmReceipt& receipt) const;

    enum class ArmOutcomeKind { Armed, Accepted };
    /// The non-waiting attach_rule() overload's success result. Never encodes
    /// Accepted as a special generation number or makes it implicitly convertible
    /// to a successful one (Astra opine review, Blocker 3) - callers must check
    /// `kind` explicitly before reading `generation`.
    struct ArmOutcome {
        ArmOutcomeKind kind{ArmOutcomeKind::Armed};
        std::uint64_t generation{0}; ///< valid iff kind == Armed
        ArmReceipt receipt;          ///< valid iff kind == Accepted
    };

    /// rung 9c PR-5c round 2 (#4221, UP-1 residual): the non-waiting attach_rule()
    /// overload's failure result. `message` is the same diagnostic text the
    /// blocking overload returns as a bare std::string. `prior_state_preserved`
    /// carries attach_core()'s own AttachCoreResult::prior_state_preserved bit
    /// straight through (see its doc comment for the full contract) - true means
    /// rule_id's prior live state, if it had any, was left completely untouched by
    /// this failure. GuardianEngine::reconcile_rule_locked(), the production
    /// caller, MUST check this bit before running its own defensive
    /// spark_runtime_->detach_rule(rule_id) cleanup: skip that call when this is
    /// true, or a real, still-live arm on a DIFFERENT key gets torn down one call
    /// later - reproducing the exact defect this bit exists to prevent.
    struct ArmError {
        std::string message;
        bool prior_state_preserved{false};
    };

    /// Non-waiting counterpart to attach_rule() above: shares the identical
    /// preparation/dispatch/commit/cleanup path (attach_core(), the same
    /// claim_rollback pattern and #3831 shape - see the blocking overload's own doc
    /// comment) but never calls wait_for_claim(). On Armed/Failed this behaves
    /// exactly like the blocking overload, including the case where completion races
    /// ahead of this call and the claim is observed already-terminal before return
    /// (Astra opine review: "A claim observed committed before return can also
    /// return Armed"). On an unresolved claim it hands ownership to claims_/the
    /// completion callback - never marking it waiter_abandoned, since Accepted means
    /// the operation is still wanted, not abandoned - and returns Accepted(receipt)
    /// immediately, without waiting.
    ///
    /// Exception (rung 9c PR-5c, #4221 up-2): AttachCoreState::Reobserved also
    /// returns Accepted, but for a pre-existing, already-Wedged head this call did
    /// NOT create and does not own - see attach_core()'s own doc comment for that
    /// branch. That receipt is already terminal; nothing further resolves it.
    ///
    /// GuardianEngine::reconcile_rule_locked() is the production caller as of Unit 6.
    /// Failure is reported as ArmError (rung 9c PR-5c round 2, #4221), not a bare
    /// std::string, specifically so that caller can distinguish a refusal that
    /// preserved rule_id's prior state from one that already tore it down - see
    /// ArmError's own doc comment.
    std::expected<ArmOutcome, ArmError> attach_rule(NonWaiting, std::string rule_id,
                                                     SparkSpec spec, RuleAssertion assertion,
                                                     bool emit_compliant_edge);

    /// rung 9c PR-2 Unit 2 (Astra opine review Blocker 2 / coordinator ruling
    /// 2026-09-12): registry-locked expiry transition, callable directly - nobody is
    /// blocked in wait_for_claim() to notice a non-waiting claim's own deadline (see
    /// KeyClaim::deadline) elapse. Does exactly what wait_for_claim's own timeout
    /// branch has always done for the blocking caller - abandon_claim_locked() every
    /// live Arm claim whose deadline has passed - so today's timeout-fails-attempt
    /// behavior is preserved, just relocated out of a waiter, not removed. A Disarm
    /// claim is never a target: since Unit 3, submit_disarm_off_lock() dispatches
    /// disarms through submit() too, which has no deadline concept at all - see
    /// redrive_retained_disarms() for the disarm-side maintenance pass instead.
    /// Idempotent: a claim already terminal or already waiter_abandoned is
    /// skipped. GuardianArmAckLedger::drain_locked() (Unit 5/6) is the production
    /// caller, from GuardianEngine::journal_maintenance_tick()'s own heartbeat
    /// cadence; exposed standalone here so a test can drive it directly. Returns
    /// the number of claims this call expired.
    ///
    /// up-4 (#4221, rung 9c PR-5b): in the SAME acquisition, also runs
    /// reap_stranded_claims_locked() - a SEPARATE terminal-recovery pass over every
    /// key's FIFO front for two residue shapes this function's own overdue-live-
    /// claim scan above deliberately excludes (a Dispatched terminal head; a
    /// Queued, withdrawn/abandoned head with no outcome yet - see that function's
    /// own doc comment for why each is reachable and what reaps it) and to observe
    /// (count-only) any elapsed compensation_deadline. Any claim newly dispatchable
    /// as a result is dispatched off-lock after this function's own lock releases,
    /// exactly like every other refill site in this file. This return value's
    /// meaning is unchanged - it still counts only THIS function's own overdue-
    /// live-claim expiries, not the terminal-recovery pass's reaps.
    std::size_t expire_overdue_claims();

    /// rung 9c PR-2 Unit 3 (Astra opine review Blocker 4): bounded, on-demand
    /// maintenance pass for retained disarms - one attempted re-submission per
    /// currently-Queued Disarm head across every key, no sleeps/recursion/waiting
    /// for quota. Without this, a disarm retained after an admission refusal (or
    /// dropped by a caller-side throw between detach_rule_locked() and
    /// submit_disarm_off_lock()) sits inert until a FUTURE same-key attach happens
    /// to redrive it - which may never come for a key nothing re-attaches to. A
    /// future heartbeat tick (Unit 5) is its production caller; exposed standalone
    /// here so a test can drive it directly. Returns the number of claims this call
    /// attempted to redrive (a redrive can itself be refused again; that retained
    /// claim is picked up again on the next call).
    std::size_t redrive_retained_disarms();

private:
    /// The shared body of attach_rule(), before any wait: derive the claim/inline/
    /// shared-watcher decision, retire any prior generation, and (claim path only)
    /// dispatch off-lock. `key` is precomputed by the caller (spark_key(spec)) since
    /// the caller's own claim_rollback guard captures it before this call, and before
    /// `spec` is moved in here. `arm_claim` is a REFERENCE to the caller's own local:
    /// this function writes it (a noexcept pointer write, exactly at the point the
    /// claim is enqueued) rather than returning the claim only inside the result, so
    /// that a throw AFTER the enqueue but before this function returns still leaves
    /// the caller's own claim_rollback (armed over that same local, per #3831) able
    /// to find and abandon it - returning the claim solely via AttachCoreResult would
    /// leave the caller's rollback guard looking at a still-null slot on exactly that
    /// throw path, recreating #3831 one level up. The caller (attach_rule()) alone
    /// owns claim_rollback's scope and commit point.
    AttachCoreResult attach_core(const std::string& key, std::string rule_id, SparkSpec spec,
                                 RuleAssertion assertion, bool emit_compliant_edge,
                                 std::shared_ptr<KeyClaim>& arm_claim);

    /// rung 9c PR-5c round 2 governance fold (#4221): the retained-wedge
    /// classification - a claim kind==Arm, dispatch in {Dispatching, Dispatched},
    /// waiter_abandoned, and end==WaiterTimedOutDispatched - used to be duplicated
    /// verbatim across attach_core()'s hoisted UP-1 pre-check and its original,
    /// now-largely-superseded post-detach check (kept as defense-in-depth, not
    /// removed). A future edit to one copy without the other could silently
    /// reintroduce a UP-1-class bug, so both now read this one definition. Pure
    /// read of `head`'s own fields - registry_mu_ held is the caller's
    /// responsibility (both current call sites already hold it), not this
    /// function's, since it never touches shared state itself.
    [[nodiscard]] static bool is_retained_wedge(const KeyClaim& head) noexcept;

    /// rung 9c PR-5e (#4221, K-bound closeout): the pure ClaimEnd->ReceiptStatus
    /// mapping receipt_status() applies - factored out so
    /// receipt_status_wedge_aware() can compute the SAME mapping under its own
    /// single registry_mu_ acquisition without duplicating the switch (and
    /// therefore without the two ever silently drifting apart). No lock of its
    /// own - a pure function of the enum value the caller already holds under
    /// registry_mu_.
    [[nodiscard]] static ReceiptStatus classify_claim_end(ClaimEnd end) noexcept;

    /// rung 9c PR-5e (#4221, K-bound closeout - cpp-expert governance finding):
    /// the K-eligibility predicate (`end == WaiterTimedOutDispatched && dispatch
    /// == Dispatched && still its key's FIFO front`) - factored out so
    /// receipt_wedge_k_eligible(), receipt_recovery_status() and
    /// receipt_status_wedge_aware() all read ONE definition instead of three
    /// independently-maintained copies (the drift risk classify_claim_end() was
    /// already extracted to prevent for the ClaimEnd->ReceiptStatus mapping,
    /// applied here to the eligibility predicate too). registry_mu_ held by the
    /// CALLER - every call site already holds it - not this function's own
    /// responsibility, since it never touches shared state itself beyond the
    /// read-only `claims_` lookup a caller already has the right to make.
    [[nodiscard]] bool is_wedge_k_eligible_locked(const std::shared_ptr<KeyClaim>& claim) const noexcept;

    /// registry_mu_ held. Exact generation ownership, including unpublished commits.
    [[nodiscard]] bool generation_committed_locked(const KeyClaim& claim) const noexcept;
    /// registry_mu_ held. W0 excludes rg shared with a committed generation.
    [[nodiscard]] bool is_wedge_candidate_locked(const KeyClaim& claim) const noexcept;
    /// registry_mu_ held. nullopt selects all rules; except preserves one claim.
    /// Allocation-free walks over claims_, never over receipt-held history.
    void deactivate_wedge_candidates_locked(std::optional<std::string_view> rule_id,
                                            const KeyClaim* except) noexcept;
    [[nodiscard]] bool wedge_candidate_exists_locked(std::optional<std::string_view> rule_id,
                                                     const KeyClaim* except) const noexcept;
    /// registry_mu_ held; caller has already swept wedge candidates for rule_id.
    [[nodiscard]] std::shared_ptr<KeyClaim> withdraw_rule_after_wedge_sweep_locked(
        const std::string& rule_id, std::string_view lifecycle_kind);
    /// Called under registry_mu_ (from WedgeWithdrawalPostcondition's destructor,
    /// which still holds it) - touches no `this` state itself, so it needs no
    /// `_locked` suffix of its own despite running under the caller's lock.
    /// spdlog::critical, try/catch-guarded - never throws, never masks the real
    /// failure. Out-of-line so this header stays spdlog-free.
    void log_wedge_withdrawal_postcondition_violation(
        std::optional<std::string_view> rule_id) const noexcept;
    /// #4508: postcondition tripwire for instance-5's shape (a #4508 predecessor
    /// commit's own final fix: an early return or a reordered edit skipping the
    /// sweep). Only the final assert()/abort is debug-only - it, alone, compiles
    /// out under NDEBUG, though this repo leaves b_ndebug unset so it is live in
    /// every buildtype this repo actually configures today. The scan that decides
    /// whether to fire, and the breadcrumb logged immediately before it does, are
    /// NOT conditional on NDEBUG and always run. NOT a release-build structural
    /// guarantee even where the abort IS live: deleting this guard or calling
    /// withdraw_rule_after_wedge_sweep_locked directly bypasses it silently.
    /// Construct FIRST (before the sweep, before any withdrawal work) so its
    /// destructor - which runs LAST, per reverse construction order - observes
    /// every exit path (normal return, Case 0's early return, an unwind), still
    /// under registry_mu_. Copy disabled: the guard is stack-scoped RAII, never
    /// meant to be duplicated or outlive the call it guards (matches this file's
    /// own CompensationPermit/RetainedGuard convention for a scope-owned guard).
    struct WedgeWithdrawalPostcondition {
        const GuardianSparkRuntime& runtime;
        std::optional<std::string_view> rule_id;
        WedgeWithdrawalPostcondition(const GuardianSparkRuntime& rt,
                                     std::optional<std::string_view> rid) noexcept
            : runtime(rt), rule_id(rid) {}
        WedgeWithdrawalPostcondition(const WedgeWithdrawalPostcondition&) = delete;
        WedgeWithdrawalPostcondition& operator=(const WedgeWithdrawalPostcondition&) = delete;
        ~WedgeWithdrawalPostcondition() noexcept {
            // sg-1 (governance Gate 6, sre): unlike #3388's routine-input-gap ruling
            // (aa081485f) against a bare abort, this IS the right invariant to abort
            // on - a survived candidate means real state corruption, not a modeled
            // gap with a safe fallback. But a bare assert leaves no breadcrumb before
            // the process dies, so log first (this file's own detach_sweep_left_
            // residue_ precedent, :2668-2706) via an out-of-line .cpp helper (keeps
            // spdlog out of this header, matching every other log call in this file).
            const bool survived = runtime.wedge_candidate_exists_locked(rule_id, nullptr);
            if (survived)
                runtime.log_wedge_withdrawal_postcondition_violation(rule_id);
            assert(!survived);
        }
    };

    // Helpers (all assume the documented lock discipline; see the .cpp).
    /// registry_mu_ held. Returns backend work still owed (a watcher disarm on the
    /// rule's key ->0 edge) for the CALLER to submit off-lock once it unlocks - see
    /// the class comment above and attach_rule/detach_rule/detach_all's own docs.
    /// `lifecycle_kind` names the audit entry ("disarmed" | "errored" -
    /// guardian_outbox.hpp's documented vocabulary): #2818's on_subscription_lost
    /// passes "errored" - the rule wasn't withdrawn, its enforcement broke - every
    /// other call site keeps the default. std::string_view per this file's own
    /// convention for a non-owning string ref (cpp-conventions.md) - both current
    /// callers pass string literals, but the type itself doesn't privilege that.
    std::shared_ptr<KeyClaim> detach_rule_locked(const std::string& rule_id,
                                                 std::string_view lifecycle_kind = "disarmed");
    /// #2818: `key`'s watch died entirely (SparkEventKind::Lost, or revalidate_
    /// subscriptions() finding it Dead). Staleness-guarded on `subscription_id`
    /// against keys_[key]->subscription: a fresh re-arm superseding this key between
    /// the detection and this call means there is nothing to do. Detaches every rule
    /// on the key as "errored". `detail` is the mechanism's failure text (from
    /// SparkEvent::detail on the push path) or a synthetic reason (the poll backstop) -
    /// logged only (journal-only, not on the wire - enterprise-readiness Gate 6: a
    /// wire-payload extension is deliberately deferred, see spark-flip-gate.md).
    void on_subscription_lost(const std::string& key, std::uint64_t subscription_id,
                               const std::string& detail);
    /// #2818: `key`'s watch toggled health WITHOUT being torn down (B1 Faulted/
    /// Recovered) - same staleness guard, but does NOT touch keys_/rules_/index_,
    /// since the key is still armed. Surfaces a Health-domain outbox entry per active
    /// rule on the key.
    void on_subscription_faulted(const std::string& key, std::uint64_t subscription_id,
                                  bool faulted, const std::string& detail);
    /// Dispatch a DISARM claim that detach_rule_locked already queued at the head of
    /// its key entry, through io_executor_.submit() (rung 9c PR-2 Unit 3: genuinely
    /// non-blocking, replacing the earlier bounded run() - see on_disarm_complete()
    /// for the actual pop/refill, which now happens in that completion callback, not
    /// here). This function only handles SYNCHRONOUS admission: an executor
    /// ADMISSION refusal (capacity, key, ceiling, launch, or a throw building the
    /// call) does NOT drop the claim - it is RETAINED at the head, counted
    /// (disarm_retained_), and re-driven by the next same-key event (an attach on
    /// the key, which then queues its own arm behind it) or by
    /// redrive_retained_disarms(); only Stopped drops it, counted, via
    /// fail_all_claims_locked. No-op if the claim is no longer the Queued head
    /// (another caller, or a prior retry, is already driving it, or it already
    /// completed). Never called with either runtime lock held.
    void submit_disarm_off_lock(const std::shared_ptr<KeyClaim>& claim);
    /// The submit() completion callback for a DISARM claim, on the detached worker
    /// (rung 9c PR-2 Unit 3): pop it and dispatch the next head ("refill" - an arm
    /// queued behind it) on a real completion; on a worker throw, retain it exactly
    /// like a synchronous admission refusal (Astra opine review Blocker 4: "Record
    /// actual worker failure; retain for bounded retry rather than pretend
    /// admission failed"), just logged distinctly. Only WorkerThrew is reachable
    /// here - submit() has no deadline (so no Timeout), and every other refusal is
    /// synchronous, handled in submit_disarm_off_lock above before a worker ever
    /// launches. Unlike on_arm_complete there is no commit and no compensation to
    /// run - a disarm's only "verdict" is done-or-retry.
    void on_disarm_complete(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                            IoResult<int>&& r) noexcept;
    /// registry_mu_ held. If `key`'s fifo has a Queued head, flip it to Dispatching and
    /// return it for the caller to dispatch off-lock; else nullptr.
    std::shared_ptr<KeyClaim> try_dispatch_head_locked(const std::string& key);
    /// Pop every TERMINAL, never-dispatched claim at the front of `entry` (a Queued
    /// claim that already carries an outcome or a commit exception: a withdrawn or
    /// release-failed tombstone), retrying its index release. Governance pass-3
    /// sg-3/ar-4/cs-5: such a tombstone must never be re-dispatched as an arm, never
    /// re-committed by the live sweep, and never sit ahead of a Disarm claim. Called
    /// by try_dispatch_head_locked (refill) and detach_rule_locked (before it queues a
    /// Disarm). noexcept by construction (iterator erases + a noexcept release).
    void sweep_terminal_queued_locked(KeyClaimQueue& entry) noexcept;
    /// up-4 (#4221, rung 9c PR-5b): registry_mu_ held. Write a claim's fallback
    /// outcome exactly as publish_arm_verdicts_locked's own fill-in loop would have,
    /// had a double-fault not interrupted it before reaching this claim: an already-
    /// committed rule (rules_ carries its generation) is honestly reported Armed;
    /// anything else fails plainly ("arm drain failed"). A no-op if `c` already
    /// carries an outcome or commit_exception. Shared by that fill-in loop's own
    /// call sites are NOT yet routed through this (kept separate deliberately, to
    /// avoid touching that already-hardened, already-tested code this late) - this
    /// exists for reap_stranded_claims_locked() below, which needs the identical
    /// synthesis for a claim publish_arm_verdicts_locked never got the chance to
    /// finish deciding.
    /// NOT noexcept (fixed, this governance run - Gate 2/3 cpp-expert/cpp-safety/
    /// security-guardian independently found the same defect: this body's
    /// allocating `std::unexpected(std::string{...})` line CAN throw, and a throw
    /// escaping a noexcept function calls std::terminate() at the boundary itself,
    /// never reaching a caller's catch - the previous `noexcept` plus this
    /// function's own comment claiming the caller's try/catch "contains" it were
    /// both wrong; reap_stranded_claims_locked()'s existing try/catch around its
    /// call to this now genuinely does what it always claimed to, matching the
    /// non-noexcept sibling line in publish_arm_verdicts_locked's own fill-in loop
    /// this function mirrors).
    void synthesize_fallback_outcome_locked(KeyClaim& c);
    /// up-4 (#4221): registry_mu_ held. Reaps ONE residue shape neither
    /// sweep_terminal_queued_locked (Queued-only, requires an outcome already
    /// present), expire_overdue_claims's own overdue-live-claim pass (skips any
    /// claim with an outcome/commit_exception/waiter_abandoned already set), nor
    /// redrive_retained_disarms (Disarm claims only) ever reaches: a Queued,
    /// withdrawn-or-waiter_abandoned head with NO outcome yet - a CONFIRMED real
    /// defect (Fable review): on_arm_complete's and finalize_arm_compensation's own
    /// deep-catch recovery hands a claim back to Queued, forever, when a double-
    /// fault interrupts its own fill-in verdict; reachable via a genuine
    /// std::bad_alloc, not a test-only seam. Left alone, a future same-key attach
    /// would spuriously re-arm an already-resolved spec; a key nothing ever
    /// revisits stays wedged.
    ///
    /// Deliberately does NOT also reap a Dispatched, terminal (outcome/
    /// commit_exception already written) head - the kickoff's own literal ask, kept
    /// out after this PR's own implementation measured it as UNSAFE: a Dispatched
    /// head's outcome can be written EARLY by abandon_claim_locked (a caller-
    /// deadline timeout) while the underlying async arm() call is still genuinely
    /// running - compensation_finished defaults true and does not distinguish that
    /// case from a genuinely stuck Dispatched head, and reaping it there ripped a
    /// still-pending claim out from under its own not-yet-run completion callback
    /// (regression measured directly against "expire_overdue_claims(): abandons a
    /// non-waiting claim's own overdue arm ... the compensating disarm still runs
    /// once the late success arrives"). Neither Astra's nor Fable's review could
    /// construct a real reproduction of the Dispatched case either - see the PLAN
    /// doc's own note on this; a future PR should only add it back with a genuinely
    /// safe "the completion callback has actually run" signal, not outcome-
    /// presence alone.
    /// Never touches a head whose compensation_finished is still false (its own
    /// compensating disarm is genuinely still outstanding). Also, as its own
    /// maintenance pass, observes (once, via compensation_deadline_observed) any
    /// STILL-outstanding compensation whose compensation_deadline has elapsed,
    /// counting it (compensation_deadline_elapsed_) without touching anything else
    /// about that claim - up-3's own deadline-semantics contract. Returns the number
    /// of claims actually reaped. `refills` collects any newly-dispatchable head
    /// (an arm queued behind a reaped entry) for the caller to dispatch off-lock.
    std::size_t reap_stranded_claims_locked(std::vector<std::pair<std::string, std::shared_ptr<KeyClaim>>>& refills);
    /// Off-lock. Dispatch an ARM claim (already the Dispatching head) through
    /// io_executor_.submit(); on a synchronous admission refusal (or a throw building
    /// the call) fail the head and every arm queued behind it with today's strings.
    void dispatch_arm_off_lock(const std::string& key, const std::shared_ptr<KeyClaim>& claim);
    /// A staged, not-yet-published outcome for one claim - what on_arm_complete's own
    /// staging decides, before publish_arm_verdicts_locked() writes it into the claim.
    /// (Named ArmVerdict, not Verdict: was a local struct inside on_arm_complete's
    /// body; rung 9c PR-2 Unit 4 promotes it to a member type so ArmCompensation
    /// below can carry a batch of them across the async compensating-disarm gap.)
    struct ArmVerdict {
        std::optional<std::expected<std::uint64_t, std::string>> outcome;
        std::exception_ptr ex;
        ClaimEnd end{ClaimEnd::None};
    };
    /// rung 9c PR-2 Unit 4 (Astra opine review, "Compensating disarm is a separate,
    /// harder case"): everything on_arm_complete's deferred (compensation-owed) path
    /// needs to finish the job once the compensating disarm - now genuinely async
    /// (submit(), not a bounded run()) - actually completes. Built BEFORE
    /// `compensating` is relinquished ("Prepare continuation storage before
    /// relinquishing existing subscription ownership"), so the only fallible step
    /// between owning the live subscription and handing off responsibility for it is
    /// the submit() call itself - the exact same shape dispatch_arm_off_lock's own
    /// submit() call already tolerates.
    struct ArmCompensation {
        std::string key;
        std::shared_ptr<KeyClaim> claim; ///< the head; identity-checked like everywhere else
        std::uint64_t sub{0};            ///< the unadopted subscription owed a disarm
        std::vector<std::shared_ptr<KeyClaim>> finished;
        std::vector<std::pair<std::shared_ptr<KeyClaim>, ArmVerdict>> verdicts;
        std::function<void()> waker;
        std::function<void()> outbox_waker;
        bool firewalled{false};
    };
    /// registry_mu_ held. Shared publish body for on_arm_complete's own immediate
    /// path (nothing to disarm) and finalize_arm_compensation()'s deferred path
    /// (rung 9c PR-2 Unit 4 - previously a local lambda inside on_arm_complete,
    /// extracted so both paths run the identical logic instead of duplicating it).
    /// PUBLISH `verdicts` onto the matching claims in `finished`, pop the finished
    /// prefix from `key`'s fifo, and on `firewall` sweep a never-finished head too.
    /// `refill` is an OUT param: an arm queued behind the finished prefix, for the
    /// caller to dispatch off-lock once unlocked. Returns true once this call has
    /// done everything it is going to do (including the "entry already vanished"
    /// no-op case, mirroring a lambda's own captured "published" bool) - false ONLY
    /// if this function itself throws before reaching either return.
    bool publish_arm_verdicts_locked(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                                     const std::vector<std::shared_ptr<KeyClaim>>& finished,
                                     std::vector<std::pair<std::shared_ptr<KeyClaim>, ArmVerdict>>& verdicts,
                                     bool firewall, std::shared_ptr<KeyClaim>& refill);
    /// Best-effort direct disarm call, off-lock, on whichever (already detached)
    /// worker calls it - the shared fallback for a compensating disarm that either
    /// could not be admitted via submit() (Stopped included - Astra opine review:
    /// "Stopped cannot silently discard a subscription that the late arm just
    /// produced") or whose admitted attempt itself threw on the worker. A disarm
    /// exception here is best-effort teardown failure only, not proof an OS
    /// resource is still live - contained and logged, never retried again beyond
    /// this one attempt (mirrors the pre-Unit-4 run_compensating_disarm's own single
    /// direct-fallback attempt).
    void direct_disarm_fallback(const std::string& key, std::uint64_t sub) noexcept;
    /// The submit() completion callback for an arm's compensating disarm (rung 9c
    /// PR-2 Unit 4), OR called directly and synchronously, off-lock, by
    /// on_arm_complete itself when submit() refuses admission for it (there is no
    /// worker to call back in that case, so the caller finishes the job itself,
    /// here, right away - no async gap). Finishes what on_arm_complete's own
    /// deferred path could not: publish (via publish_arm_verdicts_locked), pop,
    /// notify, fire wakers, dispatch a refill. Carries the SAME double-fault
    /// recovery on_arm_complete's own fallback path always has (a throw publishing
    /// hands the head back to Queued so the next same-key event re-drives it,
    /// rather than wedging the key until restart).
    void finalize_arm_compensation(std::shared_ptr<ArmCompensation> cont) noexcept;
    /// The submit() completion callback for an ARM claim, on the detached worker:
    /// the moved post-wait commit (rung 9c R5.2, commit-in-callback). Commits the
    /// head and every live sibling against the one subscription, or fails them all;
    /// if a compensating disarm is owed, ownership of finishing the job (publish,
    /// pop, notify, wake, refill) transfers to finalize_arm_compensation() (rung 9c
    /// PR-2 Unit 4) - genuinely async now (submit(), not a bounded run()), so this
    /// function returns as soon as that hand-off is made, rather than waiting for
    /// the compensating disarm itself. When nothing is owed a disarm, this function
    /// finishes the job itself, immediately, exactly as before. Firewalled: an
    /// exception in its own staging still eventually publishes a terminal outcome on
    /// every claim and drops the entry (claim_drain_failures_), whichever path reaches
    /// that publish.
    void on_arm_complete(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                         IoResult<std::expected<std::uint64_t, std::string>>&& r) noexcept;
    /// The drain_fault_point_for_test_ seam on_arm_complete's own staging (and, since
    /// rung 9c PR-2 Unit 4, publish_arm_verdicts_locked() when reached from
    /// finalize_arm_compensation()) consult: 1 = bad_alloc before the fifo snapshot
    /// (the window C2 found), 2 = a throw right after the first commit adopted the
    /// subscription, 3 = a throw after the verdicts are staged and before the pop
    /// (governance pass-3 sg-3/ar-4/cs-5: the terminal-tombstone sweep), 4/5 = a throw
    /// while building the ArmCompensation continuation itself - 4 before the
    /// allocation, 5 after it but before the `key` copy completes (adversarial review
    /// C1, PR #4318 fjarvis: the unguarded-allocation window under a live, un-disarmed
    /// subscription; Gate 8 re-review, cpp-safety + security-guardian: split into two
    /// points because the fix must leave `cont` null on EITHER fallible step, not just
    /// the first one - see `on_arm_complete`'s own comment at the try). Consumed once
    /// (compare_exchange against 0); a no-op if `point` is not currently armed.
    void fault_here_for_test(int point);
    /// registry_mu_ held. Publish `reason` on every claim in `key`'s fifo, release their
    /// index entries, and erase the entry. Reached from on_arm_complete() (noexcept):
    /// every allocating step is contained per claim (r3 C2).
    void fail_all_claims_locked(const std::string& key, const std::string& reason, ClaimEnd end);
    /// registry_mu_ held. Release the claim's index_ mapping iff it still owns one.
    /// Never throws (r3 C2/C3): a throw inside index_->remove_rule is counted
    /// (claim_index_release_failures_) and reported as false, with index_held left
    /// true so the next release retries.
    /// Callers may ignore the result: retry is implicit in the retained ownership.
    bool release_claim_index_locked(KeyClaim& claim) noexcept;
    /// registry_mu_ held. The waiter gave up on `claim` (deadline or stop): a Queued
    /// claim is erased outright, a dispatched one is marked waiter_abandoned for its
    /// completion to finish. Returns the string outcome for the caller.
    std::string abandon_claim_locked(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                                     bool stopping);
    /// Block (registry_mu_ taken inside) until `claim` has an outcome, a commit
    /// exception (rethrown here), or `deadline` / stop; on the latter two the claim is
    /// abandoned per abandon_claim_locked. The PR-1 synchronous contract only.
    std::expected<std::uint64_t, std::string>
    wait_for_claim(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                   std::chrono::steady_clock::time_point deadline);
    /// registry_mu_ held. The commit body shared by all three of attach_rule's
    /// success branches (inline-type, existing-shared-watcher, bounded-arm
    /// post-wait) - installs the new generation, marks it pending-initial, copies
    /// the wakers, and enqueues the "armed" audit entry, in that order (the waker
    /// copies precede the audit enqueue so a throwing copy rolls back with no
    /// phantom "armed" entry - see attach_rule's own doc). `pk` must already be the
    /// key's live PerKey (freshly created or the existing shared one); `rg` is
    /// consumed. `waker`/`outbox_waker` are OUT params the caller fires after
    /// unlocking.
    void commit_new_generation_locked(const std::string& rule_id, std::uint64_t gen,
                                      const char* guard_type, const std::string& rule_name,
                                      const std::shared_ptr<PerKey>& pk,
                                      std::shared_ptr<RuleGeneration> rg,
                                      std::chrono::steady_clock::time_point attach_now,
                                      std::function<void()>& waker,
                                      std::function<void()>& outbox_waker,
                                      CommitPath via);
    EvalOutcome eval_rule(const SparkSpec& spec, const RuleAssertion& a, RuleEvalState& state,
                          std::chrono::steady_clock::time_point now, bool edge,
                          const ReadResult<FileSnapshot>* file,
                          const RegistryRead* reg,
                          const ReadResult<ServiceRunState>* svc);
    /// The outbox entries an outcome requires (0, 1, or 2): a recovery emits
    /// guard.healthy AND the verdict, which enqueue_all lands atomically. `refresh`
    /// (M1 item (a)) mints a health(false) for a NON-edge Unhealthy outcome - the
    /// caller has already decided errored_refresh_ms elapsed; build_entries does not
    /// re-check the clock. Mutually exclusive with out.unhealthy_edge in practice (the
    /// caller only sets refresh when the edge did not already cover this tick), but
    /// both are read independently so a future caller mistake fails loudly rather than
    /// silently double-emitting. Called under registry_mu_ (make_event_id needs it).
    std::vector<OutboxEntry> build_entries(const RuleGeneration& gen, const EvalOutcome& out,
                                           const std::string& agent_id, bool refresh);
    /// Mint a wire event_id: `<agent_id>-<nonce>-<rule_id>-<wall_ms>-<seq>`
    /// (registry_mu_ held). agent_id (snapshotted at pass start) distinguishes
    /// agents, the boot nonce distinguishes restarts, wall_ms + seq distinguish
    /// observations - closing the collision the server's event_id PK would drop on.
    std::string make_event_id(const std::string& rule_id, std::int64_t wall_ms,
                              const std::string& agent_id);
    /// Build + buffer a Lifecycle("armed"|"disarmed") entry for `rule_id` into
    /// lifecycle_log_ (registry_mu_ held - make_event_id needs it) and return
    /// whether it was accepted (false => capacity; caller counts/logs, never
    /// rolls back the arm/disarm itself). Calls agent_id_fn_ directly under the lock
    /// (no separate pass-in): its callers are attach_rule's inline paths,
    /// detach_rule_locked, and - since rung 9c R5.2 - on_arm_complete on a detached
    /// executor worker, which is why set_agent_id_provider requires a provider that
    /// is callable from any thread and never takes GuardianEngine::mtx_. None of the
    /// call sites is a blocking-I/O site.
    bool enqueue_lifecycle_locked(const std::string& rule_id, std::uint64_t generation,
                                  const std::string& kind, const std::string& guard_type,
                                  const std::string& rule_name);
    /// Build + validate a durable JournalRecord (may throw bad_alloc on the string
    /// copies - the caller decides whether that propagates). Returns nullptr if the
    /// record is not journalable, counting the reason (field vs clock rejection).
    std::shared_ptr<JournalRecord> build_journal_record(
        const std::string& rule_id, std::uint64_t generation, const std::string& event_id,
        std::int64_t enqueued_ns, const std::string& kind, const std::string& guard_type,
        const std::string& rule_name);
    /// Append a record to the bounded pending_journal_ reserve (outbox_mu_ held).
    /// NOEXCEPT: the reserve is fixed at construction so push_back never reallocates;
    /// overflow drops the oldest and counts journal_stage_dropped. A null record is a
    /// no-op (it was rejected at build).
    void stage_pending_locked(std::shared_ptr<JournalRecord> record) noexcept;

    std::shared_ptr<IStateReader> reader_;   ///< OWNED: outlives any detached handler
    std::shared_ptr<ISparkBackend> backend_; ///< OWNED
    RuntimeClock clock_;
    /// Immutable post-construction (set once in the ctor init list, never reassigned):
    /// read from evaluate_key's registry_mu_-held commit section without a separate
    /// lock. Only errored_refresh_ms / pending_demote_sweeps / pending_demote_ms are
    /// consulted post-construction; outbox_capacity was already consumed to size
    /// outbox_/lifecycle_log_ and is kept here only so the whole Config need not be
    /// re-threaded piecemeal.
    const Config cfg_;
    std::uint64_t gen_counter_{0};   ///< registry_mu_-guarded monotonic generation source
    /// registry_mu_-guarded; +1 as the FIRST statement of detach_all()'s locked
    /// block (R5.7 fence, docs/spark-stage2-guardian-consumer-design.md). Names
    /// which full_sync APPLICATION a commit belongs to - the #3990 diagnostic's
    /// T2 measurement rejects any commit whose logged epoch doesn't match the
    /// application currently being measured, closing a real gap an Astra
    /// adversarial review found in an earlier timestamp-only design (a prior
    /// application's ordinary in-flight callback could otherwise land between
    /// the new full_sync's own teardown-start and detach_all() and be
    /// miscounted as belonging to the new one).
    std::uint64_t detach_epoch_{0};
    std::uint64_t event_seq_{0};     ///< registry_mu_-guarded event_id source
    std::string boot_nonce_;         ///< random, fixed at construction; disambiguates event_ids across
                                     ///< process restarts (wall_ms + seq alone are not restart-unique)

    mutable std::mutex registry_mu_;
    bool stopping_{false};
    std::function<void()> pending_initial_waker_; ///< registry_mu_-guarded; called outside the lock
    /// registry_mu_-guarded (same pattern as pending_initial_waker_ above, NOT
    /// outbox_mu_ - every call site that needs to copy+invoke it already holds
    /// registry_mu_: evaluate_key's commit section, attach_rule, detach_rule[_locked]).
    /// Called outside BOTH locks after any outbox_/lifecycle_log_ mutation.
    std::function<void()> outbox_enqueue_waker_;
    std::function<std::string()> agent_id_fn_;    ///< registry_mu_-guarded; wired by GuardianEngine::wire_spark_engine (#2237)
    std::unique_ptr<SparkKeyRuleIndex> index_;                          // key <-> rule fan-out + refcount
    std::unordered_map<std::string, std::shared_ptr<RuleGeneration>> rules_; // rule_id -> generation
    std::unordered_map<std::string, std::shared_ptr<PerKey>> keys_;          // spark_key -> per-key
    /// rung 9c R5.2: per-spark_key claim entries (registry_mu_-guarded, same as
    /// keys_/index_/rules_ above). See KeyClaim's doc; empty in steady state, an entry
    /// exists only while a key has an arm or disarm in flight, queued, or retained.
    /// #4508: claims_ is ALSO the sole source of pending wedge adoption candidacy:
    /// is_retained_wedge(c) && c.rg && c.rg->active && !generation_committed_locked(c).
    /// Receipt history (end / waiter_abandoned) is independent of candidacy.
    /// Commitment is identified by rules_' generation, not a second adopted bit;
    /// non-adopted completion ends candidacy when the claim leaves claims_.
    /// W0: candidacy writers never mutate a generation owned by rules_, including
    /// adoption's shared rg during the commit-to-publication exception window.
    /// W1: at most one candidate per rule_id, the last attached or re-observed.
    /// Three writer sites preserve these invariants under registry_mu_:
    /// - withdrawal sweeps all matching candidates before ordinary teardown;
    /// - re-observation sweeps other candidates before restoring its own desire;
    /// - abandonment yields to an existing candidate (the fresher desire).
    /// Each walk is allocation-free and noexcept, with no cached locator to drift.
    /// detach_rule_locked guards then sweeps before Case 0 can return or throw.
    /// detach_all guards and sweeps once globally, then uses the pre-swept helper
    /// for both withdrawal loops. Its debug postcondition runs on unwind too.
    /// A receipt can outlive its claim's FIFO membership, so test accessors must
    /// check that membership separately from the candidate predicate.
    std::unordered_map<std::string, KeyClaimQueue> claims_;

    /// ONE runtime-wide CV (paired with registry_mu_) for every claim waiter: per-key
    /// CVs have an entry-lifetime problem (erased while a waiter references them),
    /// and production has at most one waiter at a time (GuardianEngine's mtx_); the
    /// spurious-wakeup cost lands only on direct concurrent callers (tests). Waiters
    /// always use the predicate form and act on the claim's own outcome fields, never
    /// on the wait's timeout status.
    std::condition_variable claim_cv_;
    /// #2233 item 3: bounded off-lock executor for File/Registry/Service arm/disarm
    /// (Interval/Startup/Disk stay inline/synchronous under registry_mu_ - they are
    /// not backed by a blocking OS watch, matching GuardianIoExecutor's own
    /// kIoClassCount==3 scope). A DEDICATED instance, never shared with the state
    /// reader's own executor: a hung Registry arm and a hung Registry state read are
    /// independent failures and must not share a capacity budget or a single-flight
    /// key namespace with each other.
    GuardianIoExecutor io_executor_;

    // up-3 (#4221, rung 9c PR-5b): a runtime-side reservation pool for the
    // compensating-disarm fallback (direct_disarm_fallback()'s 3 entrances),
    // deliberately NOT routed through io_executor_'s own submit()/run() admission.
    // io_executor_ has no compensation-priority IoClass and rejects EVERY submission
    // unconditionally once Stopped (guardian_io_executor.hpp: admit_locked checks
    // state_->stopping first, no per-class exemption) - routing the fallback through
    // it would silently break R5.5's "Stopped cannot discard a subscription the late
    // arm just produced" requirement. This pool lives here instead, reserved per
    // claim BEFORE its arm is ever dispatched (dispatch_arm_off_lock, while no
    // subscription exists yet), so a claim that later needs compensation always has
    // its slot - including after begin_stop(), since this pool is independent of
    // io_executor_'s Stopped gate entirely.
    //
    // Sized 1:1 with io_executor_'s own per-class quota. io_executor_ is ALWAYS
    // default-constructed here (GuardianIoExecutor() -> GuardianIoExecutor(Config{}):
    // no constructor of this class threads a custom Config into it), so reading
    // GuardianIoExecutor::Config{}'s default member initializers directly is exact,
    // not an approximation - no accessor needed on GuardianIoExecutor, no risk of
    // drift from whatever it is actually configured with. Worst case, every class
    // simultaneously saturated: sum(reservations) + sum(quotas) ==
    // kMaxAliveIoWorkers exactly (10 + 10 == 20) - the compensation population can
    // never itself become the thing that drives alive-worker count past the existing
    // ceiling.
    static constexpr int kFileCompensationReservation = GuardianIoExecutor::Config{}.file_quota;
    static constexpr int kRegistryCompensationReservation =
        GuardianIoExecutor::Config{}.registry_quota;
    static constexpr int kServiceCompensationReservation =
        GuardianIoExecutor::Config{}.service_quota;
    static_assert(kFileCompensationReservation + kRegistryCompensationReservation +
                      kServiceCompensationReservation + GuardianIoExecutor::kMaxProcessIoWorkers ==
                  GuardianIoExecutor::kMaxAliveIoWorkers,
                  "up-3's compensation reservation must sum 1:1 with io_executor_'s own "
                  "per-class quotas - see the comment above");
    [[nodiscard]] static constexpr int compensation_capacity_for(IoClass c) noexcept {
        switch (c) {
        case IoClass::File:     return kFileCompensationReservation;
        case IoClass::Registry: return kRegistryCompensationReservation;
        case IoClass::Service:  return kServiceCompensationReservation;
        }
        return 0;
    }
    /// registry_mu_ held (both to serialize the capacity check itself and to keep it
    /// atomic with the claim-identity recheck dispatch_arm_off_lock pairs it with).
    /// Returns an engaged CompensationPermit iff capacity was available;
    /// std::nullopt on refusal (nothing reserved, nothing to release). rung 9c
    /// PR-5b hardening (this governance run, cpp-safety RAII-floor adjudication):
    /// the returned permit's destructor/reset() is lock-independent-safe (see that
    /// class's own doc comment) - release it via KeyClaim::compensation_permit's
    /// own reset(), or release_compensation_locked() below, never by touching
    /// compensation_reserved_count_ directly.
    [[nodiscard]] std::optional<CompensationPermit> try_reserve_compensation_locked(IoClass c) noexcept {
        const auto idx = io_class_index(c);
        if (compensation_reserved_count_[idx].load(std::memory_order_relaxed) >= compensation_capacity_for(c))
            return std::nullopt;
        compensation_reserved_count_[idx].fetch_add(1, std::memory_order_relaxed);
        return CompensationPermit{&compensation_reserved_count_[idx]};
    }
    /// Gate 8 re-review (this governance run, unhappy-path UP-8): registry_mu_ IS
    /// required here, and the scope of the earlier "lock not required" claim was
    /// too broad - correct it precisely. What's actually lock-independent is ONLY
    /// the atomic decrement inside CompensationPermit::reset() (see that class's
    /// own doc comment). Accessing `claim.compensation_permit` itself - the
    /// std::optional wrapper on KeyClaim - has no synchronization of its own, so a
    /// caller reading/writing it concurrently with another registry_mu_-holding
    /// caller of the SAME claim is a data race regardless of the target atomic's
    /// own thread-safety. Every real call site already takes registry_mu_ for
    /// locality with the rest of this claim's bookkeeping - that requirement is
    /// not merely a style choice. Idempotent: a no-op if `claim` does not
    /// currently hold a reservation (already released, or never took one - a
    /// Disarm claim, or an Arm claim that never reached dispatch_arm_off_lock).
    /// Always call this (or KeyClaim::compensation_permit.reset() directly, still
    /// under registry_mu_) rather than touching compensation_reserved_count_
    /// directly, so double-release and leaks are both structurally impossible.
    void release_compensation_locked(KeyClaim& claim) noexcept {
        claim.compensation_permit.reset();
    }
    /// up-5 (#4221, rung 9c PR-5b): registry_mu_ held. First retention of `claim`
    /// (an admission refusal or worker throw) - idempotent: a claim already marked
    /// retained does not engage a second RetainedGuard (and so does not increment
    /// disarm_retained_ a second time) on a repeated refusal. Callers keep their
    /// own `++claim->admission_rejections` (unconditional attempt history,
    /// unchanged shape) - this touches ONLY the lifecycle count. Disarm claims
    /// only, but harmless (a no-op guard) if ever called on anything else.
    void mark_retained_locked(KeyClaim& claim) noexcept {
        if (claim.retained_guard)
            return;
        disarm_retained_.fetch_add(1, std::memory_order_relaxed);
        claim.retained_guard.emplace(&disarm_retained_);
    }
    /// Gate 8 re-review (this governance run, unhappy-path UP-8): registry_mu_ IS
    /// required here, same correction as release_compensation_locked() above -
    /// only RetainedGuard's own atomic decrement is lock-independent; the
    /// `claim.retained_guard` optional wrapper itself is not synchronized and every
    /// real call site already takes registry_mu_ for that reason, not merely for
    /// locality. Idempotent: a no-op if `claim` is not currently counted as
    /// retained. Call at EVERY terminal removal of a Disarm claim (successful
    /// completion, Stopped-drop, DeadSubscription shortcut) - never decrement
    /// disarm_retained_ directly.
    void clear_retained_locked(KeyClaim& claim) noexcept {
        claim.retained_guard.reset();
    }
    /// rung 9c PR-5c (#4221, the Dispatching-window race): abandon_claim_locked()
    /// can tag a claim WaiterTimedOutDispatched while its admission outcome is
    /// still genuinely unresolved (a caller timeout racing dispatch_arm_off_lock's
    /// own re-lock after building the executor submission). If admission then
    /// resolves via fail_all_claims_locked(), that function's own per-claim guard
    /// (`if (c->end == ClaimEnd::None) c->end = end;`) cannot overwrite the stale
    /// value - the claim would report Wedged for what was really an ordinary
    /// AdmissionRejected/Stopped outcome. Call this immediately before
    /// fail_all_claims_locked() at both call sites the race can reach
    /// (dispatch_arm_off_lock()'s reservation-exhaustion branch and its submission-
    /// failure branch) - and only there: force-reclassifies this ONE claim's own
    /// already-set `end` to the real outcome. Every other caller/claim's guard is
    /// deliberately left untouched; this is not a relaxation of
    /// fail_all_claims_locked()'s own contract, which stays conservative for
    /// everything else in this file.
    ///
    /// UP-6 (#4221, rung 9c PR-5c follow-up governance): this correction is
    /// verified safe today only because a Disarm claim structurally can never
    /// carry WaiterTimedOutDispatched - no caller ever waits on a disarm with a
    /// deadline, so abandon_claim_locked()'s `stopping ? Stopped :
    /// WaiterTimedOutDispatched` branch is reachable only for an Arm claim's
    /// waiter. That is not centrally enforced anywhere, so assert it here rather
    /// than trust it silently: both current call sites already sit past
    /// dispatch_arm_off_lock()'s own entry guard (a non-Arm claim returns before
    /// reaching either call), so this is defense-in-depth - a future third or
    /// fourth caller, or a change that gives Disarm claims their own deadline,
    /// fails loudly here in a debug build instead of silently reintroducing the
    /// Dispatching-window race this function exists to close.
    void reclassify_dispatching_race_locked(KeyClaim& claim, ClaimEnd real_end) noexcept {
        assert(claim.kind == ClaimKind::Arm);
        if (claim.dispatch == ClaimDispatch::Dispatching &&
            claim.end == ClaimEnd::WaiterTimedOutDispatched) {
            claim.end = real_end;
        }
    }
    /// rung 9c PR-5b hardening (this governance run): std::atomic<int> elements
    /// (was a plain std::array<int, kIoClassCount>) specifically so a
    /// CompensationPermit's destructor can release a slot safely regardless of
    /// which thread or lock state is active when its owning KeyClaim is finally
    /// destroyed - see CompensationPermit's own doc comment. ENGAGING a slot
    /// (try_reserve_compensation_locked) still requires registry_mu_, to keep the
    /// capacity check atomic with the claim-identity recheck it's paired with.
    std::array<std::atomic<int>, kIoClassCount> compensation_reserved_count_{};
    /// up-3: #4221's own criterion text ("the fallback is deadline-bounded and
    /// counted, and a ceiling hit is surfaced") - reservation-exhaustion refusals and
    /// compensation-deadline elapses, counted separately from every pre-existing
    /// counter. Fleet-visible egress is out of scope here; rides #3415's already-open
    /// counter-egress scope like every other internal-only counter in this file.
    std::atomic<std::uint64_t> compensation_reservation_refused_{0};
    std::atomic<std::uint64_t> compensation_deadline_elapsed_{0};
    /// up-2 (#4221, rung 9c PR-5c): a genuinely new claimant refused immediately
    /// against a Wedged key, vs. an identical (rule_id, spec) retry that
    /// re-observed the existing wedged head's receipt instead of queuing a new
    /// claim. Same "internal-only, rides #3415" scope as the pair above.
    std::atomic<std::uint64_t> wedged_refusals_{0};
    std::atomic<std::uint64_t> wedged_reobservations_{0};
    /// Governance Gate 8 fix (rung 9c PR-5d /governance run): see
    /// wedge_adopt_stale_refused()'s own doc comment - same "internal-only,
    /// rides #3415" scope as the pair above.
    std::atomic<std::uint64_t> wedge_adopt_stale_refused_{0};

    std::atomic<std::uint64_t> backend_op_timeouts_{0};   ///< arm/disarm calls that hit cfg_.backend_op_deadline
    std::atomic<std::uint64_t> backend_op_queued_{0};     ///< R5.2: attach_rule queued behind a same-key claim
    std::atomic<std::uint64_t> backend_op_late_arms_{0};  ///< #3816/R5.2: late-succeeding arm disarmed by the drain
    std::atomic<std::uint64_t> disarm_retained_{0};       ///< R5.2: disarm claims retained after an admission refusal
    std::atomic<std::uint64_t> claims_dropped_at_stop_{0}; ///< R5.2: queued claims dropped by begin_stop / Stopped
    std::atomic<std::uint64_t> claim_drain_failures_{0};  ///< R5.2: on_arm_complete firewall fired
    std::atomic<std::uint64_t> detach_claim_failures_{0}; ///< R5.2: detach_rule_locked rollback / last resort fired
    std::atomic<std::uint64_t> dead_subscription_disarms_skipped_{0}; ///< cs-1: Disarm claims completed for an id already reported dead
    std::atomic<std::uint64_t> claim_index_release_failures_{0}; ///< r3 C2/C3: contained remove_rule throw
    std::atomic<std::uint64_t> detach_sweep_left_residue_{0}; ///< PR-5a #4221 cs-103: last-on-key sweep left the fifo non-empty (should never happen)
    std::function<void()> drain_gap_hook_for_test_; ///< registry_mu_-guarded; see the setter
    std::function<void()> dispatch_entry_hook_for_test_; ///< registry_mu_-guarded; see the setter
    std::atomic<int> drain_fault_point_for_test_{0};  ///< see the setter
    std::atomic<bool> detach_fault_for_test_{false};  ///< see the setter
    std::atomic<bool> index_remove_fault_for_test_{false}; ///< see the setter
    std::atomic<std::uint64_t> detach_post_commit_failures_{0}; ///< r3 C4: contained drop_rule throw
    std::atomic<int> detach_post_fault_point_for_test_{0}; ///< see the setter
    /// Seam body for set_detach_post_fault_point_for_test; consumed once at `point`.
    void detach_post_fault_here_for_test(int point) {
        int expected = point;
        if (detach_post_fault_point_for_test_.compare_exchange_strong(expected, 0))
            throw std::bad_alloc{};
    }
    /// Seam body for set_index_remove_fault_for_test; consumed once.
    void index_remove_fault_here_for_test() {
        if (index_remove_fault_for_test_.exchange(false))
            throw std::bad_alloc{};
    }
    /// Seam body for set_detach_fault_for_test; consumed once.
    void detach_fault_here_for_test() {
        if (detach_fault_for_test_.exchange(false))
            throw std::bad_alloc{};
    }

    mutable std::mutex outbox_mu_;
    GuardianOutbox outbox_;
    GuardianLifecycleLog lifecycle_log_; ///< capacity set in the ctor init list (see the .cpp)
    /// Durable-journal staging: built + validated records awaiting persist. Bounded
    /// (kMaxPendingJournalRecords), reserved ONCE in the ctor, drop-oldest on overflow.
    /// outbox_mu_-guarded (co-located with lifecycle_log_). Mutated by the engine's
    /// mtx_-serialised paths (reconcile stage + persist) AND, since rung 9c R5.2, by
    /// on_arm_complete's "armed" staging on a detached executor worker - never by the
    /// send drain. The lock, not the calling thread, is what serialises it.
    std::vector<std::shared_ptr<JournalRecord>> pending_journal_;
    std::atomic<std::uint64_t> journal_stage_dropped_{0};  ///< overflow drop-oldest (disk-full backpressure)
    std::atomic<std::uint64_t> journal_stage_failures_{0}; ///< disarm record un-buildable post-teardown
    std::atomic<std::uint64_t> journal_field_rejected_{0}; ///< NUL/oversized/non-UTF-8 field kept out
    std::atomic<std::uint64_t> journal_clock_rejected_{0}; ///< skewed clock (secs<=0) kept out (rev-4.1 #2)
    /// #2233 item 7: incremented each time enqueue_lifecycle_locked's log-once branch
    /// actually calls spdlog::warn (see lifecycle_backpressure_log_fires_for_test()).
    std::atomic<std::uint64_t> lifecycle_backpressure_log_fires_{0};
    // Serialises drain() calls WITHOUT blocking enqueuers (they take outbox_mu_, not
    // this): drain() releases outbox_mu_ across each send, so two concurrent drainers
    // could otherwise both peek+send the same head. drain_once() is public, so this is
    // load-bearing, not just belt-and-braces (item 4). NOTE: a send callback must never
    // re-enter drain() (it would self-deadlock on this mutex); none does.
    std::mutex drain_mu_;
    std::atomic<std::uint64_t> send_exceptions_{0}; ///< drain sends that threw (item 4 hardening)
    std::atomic<std::uint64_t> unhealthy_suppressed_{0}; ///< repeat Unknown evals whose guard.unhealthy
                                                         ///< was edge-suppressed (rule stuck errored;
                                                         ///< NOT re-minted every ~5s convergence tick). M1.
    std::atomic<std::uint64_t> unhealthy_refreshed_{0};  ///< M1 item (a): guard.unhealthy re-emitted at
                                                         ///< errored_refresh_ms cadence for a rule still
                                                         ///< stuck Unknown. Lock-free, mutated (like
                                                         ///< unhealthy_suppressed_) from evaluate_key's
                                                         ///< registry_mu_-held commit section.
    std::atomic<std::uint64_t> priority_demoted_{0};     ///< M1 item (b): rule_ids demoted off the 5s
                                                         ///< priority lane (pending_demote_sweeps /
                                                         ///< pending_demote_ms). Lock-free, same call site.

    /// #4606 criterion-10: the most recent evaluate_key() call's staged EvalTimingRecord
    /// batch, for last_eval_timings_for_test(). A LEAF lock, never held while taking any
    /// other lock this class defines (registry_mu_, outbox_mu_, drain_mu_, a PerKey's
    /// eval_mu) — needed because eval_mu is PER-KEY (sibling keys evaluate concurrently),
    /// so writing this cross-key member under only the calling pass's eval_mu would race.
    mutable std::mutex last_eval_timings_mu_;
    std::vector<EvalTimingRecord> last_eval_timings_;
    std::atomic<int> fail_timing_stage_at_for_test_{-1}; ///< test seam, see fail_timing_stage_at_for_test()
    std::atomic<bool> fail_timing_reserve_for_test_{false}; ///< test seam, see fail_next_timing_reserve_for_test()
};

/// R5.7 (docs/spark-stage2-guardian-consumer-design.md): human-readable rendering
/// of a GuardianSparkRuntime::CommitPath, for the T2 log line
/// commit_new_generation_locked() emits. Declared here (not in
/// guardian_arm_ack.hpp, which already includes this header) so
/// guardian_spark_runtime.cpp names its own enum without a reverse include.
/// Exported so the mapping stays directly unit-testable, mirroring
/// receipt_status_name()'s own convention (guardian_arm_ack.hpp).
YUZU_EXPORT const char* commit_path_name(GuardianSparkRuntime::CommitPath path);

} // namespace yuzu::agent
