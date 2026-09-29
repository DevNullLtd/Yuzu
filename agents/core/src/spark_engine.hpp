#pragma once

/**
 * spark_engine.hpp — SparkEngine, the agent's single detection layer
 * (ADR-0021 Decisions 1 + 3; campaign plan Stage 1).
 *
 * Watchers are multiplexed by MECHANISM, never by rule: this PR ships the
 * timer wheel (one thread servicing every interval, startup, and poll-class
 * spark); the file-notification thread, the event-handle wait pool (TP_WAIT,
 * #1907), and the multiplexed service pump land in the follow-up PRs. Arming
 * is deduped across consumers: two subscriptions to an equal SparkSpec share
 * one watcher entry and one per-spark state (N consumers, 1 watcher).
 *
 * Delivery tiers (contract in spark.hpp):
 *   - Queued  — each registered consumer owns a bounded queue + dispatch
 *               thread. Watchers enqueue without ever blocking: when a queue
 *               is full the OLDEST event is dropped and counted
 *               (queued_dropped_total), so a stuck consumer can neither stall
 *               a watcher nor starve a sibling consumer. Queued handlers may
 *               block, dispatch plugins, do network I/O.
 *   - Inline  — runs synchronously on the PRODUCING watcher thread: the wheel
 *               for timer sparks, OR the mechanism's own thread (the file
 *               IOCP worker, a registry TP_WAIT pool thread) for event-driven
 *               sparks. Core-internal (never reachable from the plugin ABI);
 *               enforce-class only. Every inline call is timed — the duration
 *               counters (inline_us_*, inline_over_*) are the ADR §3 watchdog
 *               that feeds the Stage-11 resource gate. SLO is µs-MEDIAN,
 *               rare-ms tolerated (owner decision 2026-07-06).
 *
 * Lifecycle: construct → register consumers / arm sparks (any order) →
 * start() → … → stop(). Single-shot: the engine does not restart after
 * stop(). stop() drops + counts undelivered queued events and quiesces the
 * watcher + consumer threads. It is prompt FOR WELL-BEHAVED HANDLERS: a queued
 * handler that blocks past kConsumerJoinBudgetMs is detached + counted, not
 * joined, so a hung handler can never hang shutdown (governance UP-1 / #1311).
 *
 * Threading contract for callers: arm/disarm/register/stats are safe from any
 * thread, and from inside a handler WHILE THE ENGINE IS ALIVE. THREE exceptions:
 *   (1) unregister_consumer quiesces that consumer's thread — never call it
 *       from the consumer's own handler (self-join).
 *   (2) An INLINE handler on an EVENT-DRIVEN spark runs on the mechanism's own
 *       thread. Calling disarm() for that SAME registry spark from inside its
 *       inline handler can self-deadlock in the current TP_WAIT teardown (the
 *       callback waits on its own wait object). Queued handlers, and inline
 *       handlers disarming a DIFFERENT spark, are safe. The registry mechanism
 *       must defer teardown before an inline registry consumer is wired
 *       (Stage 2) — governance F3.
 *   (3) A QUEUED handler that may BLOCK must not call back into the engine
 *       (arm/disarm/stats). It can be DETACHED at shutdown (see above), and the
 *       engine — reached via the captured `this` such a call would use — may be
 *       destroyed by the time the blocked handler resumes → use-after-free
 *       (governance UP2-1). "Safe from inside a handler" holds only for the
 *       non-blocking, engine-outlives-the-call case; a blockable handler must
 *       treat the engine as possibly-gone once it has blocked.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT
#include <yuzu/agent/spark.hpp>

#include "spark_mechanism.hpp" // ISparkMechanism, register_mechanism
#include "spark_types.hpp"     // DiskReaderFn, SparkFireDecision

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace yuzu::agent {

/// Point-in-time counters, surfaced via heartbeat status_tags by the agent
/// wiring (the agent has no /metrics — the dex/guardian convention).
struct SparkEngineStats {
    std::uint64_t armed_sparks{0};       ///< deduped watcher entries
    std::uint64_t armed_faulted{0};      ///< armed sparks a mechanism reported deaf (B1 health)
    std::uint64_t subscriptions{0};      ///< live subscriptions across all armed sparks
    std::uint64_t consumers{0};          ///< registered queued consumers
    /// Watcher UNITS while running: the wheel + one per registered event-driven
    /// mechanism. NOT an OS thread count — a mechanism may run a small pool (the
    /// registry TP_WAIT pool is 2–4 threads). Named `_units` deliberately so a
    /// resource-gate cross-check doesn't mistake it for `ps -T` (governance S1).
    std::uint64_t watcher_units{0};
    std::uint64_t watch_faults_total{0}; ///< mechanism fault reports (post-arm deaf edges), monotonic
    /// Mechanism unwatch() calls that THREW during the ARM-RACE teardown (#2270).
    /// SCOPE IS IN THE NAME ON PURPOSE: this covers teardown_arm_race ONLY. disarm()
    /// has its own counter below. unregister_consumer() is NOT a peer of these two —
    /// its unwatch() still propagates UNCONTAINED, and the consequence is worse than
    /// an uncounted orphaned watch: escaping a void function there permanently
    /// strands the consumer's dispatch thread (#2814). A zero across both counters
    /// below does NOT mean "no orphaned watches fleet-wide", and does not speak to
    /// #2814 at all. Every other counter in this struct is scope-complete; these two
    /// are not, and an alert built on either must say so.
    /// Non-zero means an OS watch outlived its armed_ entry. Reclamation is
    /// mechanism-dependent, not simply OS-dependent: a File watch (Windows-only
    /// mechanism) is never reclaimed short of a process restart; a Service watch
    /// (Linux or Windows) is reclaimed the next time stop() runs; a Registry watch
    /// (Windows-only mechanism) cannot fail this way at all — its unwatch()
    /// allocates nothing (see teardown_arm_race for the per-mechanism detail).
    /// macOS is out of scope for all of the above: every mechanism factory returns
    /// nullptr there (`spark_mechanism.hpp`), so `mech` is always null and this
    /// counter is structurally unreachable on that platform.
    /// Monotonic. Surfaced as the sparse heartbeat tag `yuzu.spark_arm_race_unwatch_failures`;
    /// the fleet rollup, metrics.md row and alert rule are deferred to the
    /// prefer_spark flip alongside `retiring`/`retiring_cap` (spark_fleet_tags.hpp).
    ///
    /// #2833 — WHEN THAT TAG IS UNREACHABLE, which is exactly when it would matter most.
    /// Increments that happen during SHUTDOWN never reach the wire: the agent's heartbeat
    /// composer emits NOTHING once stop_requested_ is set (agent.cpp:2582 / :3311). The
    /// two shutdown paths' spark-stop and heartbeat-join calls (:1086 / :3345 vs :3125 /
    /// :3774) run on different threads and aren't ordered relative to each other, but
    /// that isn't load-bearing here — the engine's own gate says the same thing
    /// independently: emit_spark_heartbeat_tags() takes the ABSENT posture on !running, and stop() has
    /// already cleared running_. So a shutdown-window increment is JOURNAL-ONLY: its sole
    /// egress is the spdlog::error at the increment site.
    ///
    /// OPERATOR CONSEQUENCE: a zero reading for this tag during a shutdown is NOT evidence
    /// that nothing was orphaned. Accepted, not fixed — adding an egress here would be
    /// inert, because the gate that suppresses it is the agent's and is deliberate
    /// (STOPPED is not FAILED: a cleanly-stopping agent must not page on-call). Pinned by
    /// "#2833 — a shutdown-window unwatch failure is counted but has NO heartbeat egress"
    /// in test_spark_mechanism.cpp.
    std::uint64_t arm_race_unwatch_failures_total{0};
    /// Mechanism unwatch() calls that THREW during an ordinary disarm() teardown (#2270).
    /// The counterpart of the counter above, scoped the same way on purpose: that one
    /// covers teardown_arm_race, this one covers disarm(). Neither covers
    /// unregister_consumer() (#2814, worse in kind — see above), so a zero across
    /// BOTH is still not "no orphaned watches fleet-wide". Same per-mechanism
    /// reclamation bound as its counterpart — and the same #2833 shutdown-window
    /// unreachability, stated in full at that counter: an increment during shutdown is
    /// journal-only, so a zero reading then is not evidence nothing was orphaned.
    std::uint64_t disarm_unwatch_failures_total{0};
    std::uint64_t consumer_threads_detached{0}; ///< handlers that blocked past the shutdown budget
    /// stop() calls whose BOUNDED wait for the in-flight mechanism-teardown lease
    /// expired, so stop() proceeded to tear the mechanisms down with a caller still
    /// inside the post-mu_ window (#2815). Monotonic.
    ///
    /// JOURNAL-ONLY BY CONSTRUCTION, and deliberately absent from
    /// emit_spark_heartbeat_tags(): this counter can only ever increment INSIDE stop(),
    /// which runs after running_ = false, and the heartbeat gate at agent.cpp:2582 emits
    /// nothing once shutdown has been requested. A heartbeat tag for it would be
    /// unreachable on every path that can set it — the same shape as the two
    /// unwatch-failure counters' shutdown-window increments (#2833). Its egress is the
    /// spdlog::warn at the expiry site, plus this field for tests.
    ///
    /// Non-zero does NOT mean a use-after-free happened: ~SparkEngine's wait is
    /// UNBOUNDED and is what actually closes that. It means the late unwatch may have
    /// reached an already-stopped mechanism (benign — every real mechanism fails a
    /// post-stop unwatch closed) and that some caller outstayed the budget.
    std::uint64_t teardown_join_timeouts_total{0};
    std::uint64_t events_total{0};       ///< spark fires (post-dedup, pre-fan-out)
    std::uint64_t queued_delivered_total{0};
    std::uint64_t queued_dropped_total{0}; ///< bounded-queue overflow + shutdown drops
    std::uint64_t consumer_errors_total{0}; ///< queued handlers that threw
    // Inline-tier watchdog (ADR §3): duration accounting for every inline call.
    std::uint64_t inline_calls_total{0};
    std::uint64_t inline_errors_total{0}; ///< inline handlers that threw (contract breach)
    std::uint64_t inline_us_total{0};
    std::uint64_t inline_us_max{0};
    std::uint64_t inline_over_100us_total{0}; ///< tail counter (p-high proxy)
    std::uint64_t inline_over_10ms_total{0};  ///< scheduler-quantum-class outliers
    // Summed across every registered mechanism's stats() (#1979); see
    // SparkMechanismStats for per-field meaning. The per-mechanism-type breakdown
    // (which sum() folds away) is available via stats_by_type() (#2011 rung 1).
    std::uint64_t mech_retiring{0};
    std::uint64_t mech_retiring_cap{0}; ///< summed teardown-backpressure ceiling — the
                                        ///< context that makes mech_retiring readable
                                        ///< (a bare retiring count has no scale)
    std::uint64_t mech_watch_rejected_total{0};
    std::uint64_t mech_quarantined_total{0};
    std::uint64_t mech_slow_op_total{0};
    /// #2818: Lost notifications actually DELIVERED (i.e. the drop_key_locked call site
    /// found >=1 live subscriber to notify before erasing the key). Distinct from
    /// watch_faults_total/armed_faulted, which already cover the Faulted/Recovered edge
    /// at the key level — this counts the previously-invisible hard-kill case
    /// specifically. Monotonic.
    std::uint64_t subscription_lost_total{0};
};

class YUZU_EXPORT SparkEngine {
public:
    using ConsumerId = std::uint64_t;
    using SubscriptionId = std::uint64_t;
    using QueuedHandler = std::function<void(const SparkEvent&)>;
    /// Stage 2 narrows this to (event, enforce-capability) — no dispatcher, no
    /// plugin-host handle, so a plugin call from an inline handler is a
    /// compile error (ADR §3 "enforced, not conventional").
    using InlineHandler = std::function<void(const SparkEvent&)>;

    static constexpr std::size_t kDefaultQueueCap = 1024;
    /// Cadence floor for interval/poll sparks (the TriggerEngine 30 s minimum).
    static constexpr std::uint64_t kMinCadenceMs = 30'000;
    /// A disk spark's FIRST poll runs within this of start — early, but
    /// timer-driven, never at-arm (the dex_win_poll macOS lesson).
    static constexpr std::uint64_t kFirstDiskPollCapMs = 60'000;
    /// Per-consumer shutdown budget: a dispatch thread still inside a handler
    /// past this on stop()/unregister is detached, not joined (governance UP-1).
    static constexpr std::uint64_t kConsumerJoinBudgetMs = 2'000;

    SparkEngine();
    ~SparkEngine();
    SparkEngine(const SparkEngine&) = delete;
    SparkEngine& operator=(const SparkEngine&) = delete;

    /// Register the watch mechanism for an event-driven spark type (File /
    /// Registry / Service). MUST be called before start(). Production wires the
    /// platform factories (make_file_mechanism / make_registry_mechanism);
    /// tests wire a fake. With NO mechanism registered for a type, arm() of
    /// that type is rejected — preserving the spark.hpp invariant "Armed means
    /// a watcher is running". Rejects a null mechanism, a timer-driven type
    /// (interval/startup/disk are the wheel's), a duplicate registration, and
    /// any call after start().
    [[nodiscard]] std::expected<void, std::string>
    register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism);

    /// Register a queued consumer. Its dispatch thread starts immediately;
    /// events flow once the engine starts and the consumer arms sparks.
    /// CAPTURE-LIFETIME CONTRACT (governance UP2-1): because a hung handler is
    /// DETACHED at shutdown (see unregister_consumer / stop()), its dispatch
    /// thread may still be executing `handler(ev)` after this engine — and its
    /// caller — return. Anything the handler CAPTURES (a plugin host, a network
    /// client, a Reflex context) must therefore be process-lifetime-stable, or
    /// its owner must outlive a possibly-detached dispatch. Capturing a
    /// stack/short-lived object by reference into a queued handler is a
    /// use-after-free waiting for a slow-handler shutdown.
    [[nodiscard]] std::expected<ConsumerId, std::string>
    register_consumer(std::string name, QueuedHandler handler,
                      std::size_t queue_cap = kDefaultQueueCap);

    /// Drop a consumer: disarms its subscriptions, then BOUNDED-joins its
    /// dispatch thread (kConsumerJoinBudgetMs). A handler still running past the
    /// budget (queued handlers may block on I/O) is DETACHED and counted
    /// (consumer_threads_detached) rather than hanging the caller — the detached
    /// thread touches only its own refcounted state, never the engine, so it is
    /// memory-safe. Never call from inside the consumer's own handler (self-join).
    void unregister_consumer(ConsumerId id);

    /// Arm a spark for queued delivery to `consumer`. Dedup: an equal spec
    /// already armed (by anyone) adds a subscription to the existing watcher.
    /// Rejects a malformed spec or an event-driven type with no registered
    /// mechanism (armed == a watcher is running).
    [[nodiscard]] std::expected<SubscriptionId, std::string> arm(ConsumerId consumer,
                                                                 SparkSpec spec);

    /// Arm a spark for INLINE delivery (see tier contract above). Core-internal.
    [[nodiscard]] std::expected<SubscriptionId, std::string> arm_inline(SparkSpec spec,
                                                                        InlineHandler handler);

    /// Remove one subscription; the watcher itself disarms when its last
    /// subscription goes. Unknown ids are ignored (idempotent).
    /// NOT noexcept, and the surviving sources are exactly what
    /// GuardianSparkRuntime::detach_rule_locked needs to know: the two lock_guard
    /// acquisitions can raise std::system_error. Everything else on the path is
    /// contained as of #2270 — the allocations, the log, and the mechanism unwatch.
    /// (`mech_ops_mu_by_type_.at()` cannot throw: it is populated in lockstep with
    /// mechanisms_ and frozen after start().)
    void disarm(SubscriptionId id);

    /// Start the mechanism threads. Interval/poll deadlines are (re)based on
    /// the start instant; startup sparks fire immediately. Single-shot. On a
    /// failure (#2050), an internal rollback guard tears the partial startup
    /// back down and the original exception propagates — the engine is left
    /// TERMINALLY stopped (mirrors stop()'s own sticky-stop invariant), never
    /// restartable, not restored to a pre-start state.
    void start();

    /// Stop watchers (wheel + mechanisms), then consumer dispatch threads.
    /// PROMPT FOR WELL-BEHAVED HANDLERS ONLY: a queued handler that blocks past
    /// kConsumerJoinBudgetMs is DETACHED + counted rather than joined, so a hung
    /// handler can never hang agent shutdown (governance UP-1 / #1311 class).
    /// Undelivered queued events are dropped + counted.
    ///
    /// IDEMPOTENT **AND** CONCURRENCY-SAFE: serialised against start(),
    /// register_mechanism() and any other stop() by `lifecycle_mu_`, which is held
    /// for the WHOLE operation. A second caller therefore BLOCKS until the first
    /// has fully torn down — it does not early-return past an in-flight teardown.
    /// That completion barrier is load-bearing: ~SparkEngine calls stop(), and
    /// Agent::stop() is reachable concurrently from the Windows SCM control thread
    /// (service_win.cpp handler_ex). Without it, the destructor could outrun an
    /// in-flight stop() and run ~std::thread on a still-joinable wheel thread
    /// (std::terminate) while the other thread was mid-`m->stop()` on mechanisms_
    /// being destroyed (use-after-free) — governance Gate-3 B3 / Gate-4 UP-1.
    ///
    /// noexcept: ~SparkEngine calls this, and NOTHING may terminate the agent for
    /// an observe-only subsystem. The body swallows teardown exceptions.
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;

    [[nodiscard]] SparkEngineStats stats() const;

    /// #2818: cheap, lock-only (mu_), no I/O — safe to call from any context, including
    /// a periodic backstop sweep (GuardianSparkRuntime::revalidate_subscriptions). See
    /// SubscriptionHealth's own doc comment for why this needs no incarnation counter.
    [[nodiscard]] SubscriptionHealth subscription_health(SubscriptionId id) const;

    /// Pull query for the establishment signal (rung 9c PR-6 item 1) — see
    /// spark.hpp's SubscriptionEstablishment doc comment for the field
    /// semantics. nullopt for an unknown/dead subscription id, mirroring
    /// subscription_health()'s Dead case (same sub_keys_/armed_ lookup).
    /// Cheap, lock-only (mu_), no I/O.
    ///
    /// `coverage` is overlaid to None while the type's mechanism reports itself
    /// inert - either reason, boot-inert OR runtime-degraded (whatever it last
    /// reported); `established_at` is never touched. The result is a conservative
    /// snapshot, not a coherent one: inert is an atomic read beside the mu_-guarded
    /// cache, so it can disagree with a newer report.
    ///
    /// R4: after stop(), this returns the LAST-KNOWN values (stop() never
    /// erases armed_ — the same precedent subscription_health() already sets,
    /// and emit_spark_heartbeat_tags()'s ABSENT posture on !running takes the
    /// same "consumer gates on liveness" shape). A caller that cares whether
    /// the engine is still live checks is_running() itself; this query does
    /// not do it for them.
    [[nodiscard]] std::optional<SubscriptionEstablishment>
    subscription_establishment(SubscriptionId id) const;

    /// Per-mechanism-type snapshot of the mechanism-owned counters (#2011 rung 1).
    /// Keyed by the registered SparkType — the KEY that stats() sums away — so the
    /// agent can export a per-type (file / registry / service) heartbeat breakdown
    /// instead of a single blended sum. Only registered (event-driven, platform-
    /// supported) mechanisms appear, so the key set doubles as the agent's spark
    /// capability. Same point-in-time skew caveat as SparkMechanismStats (each field
    /// is an independent atomic; not a coherent cross-field snapshot).
    [[nodiscard]] std::map<SparkType, SparkMechanismStats> stats_by_type() const;

    /// Test seam: substitute the platform disk reader. Set BEFORE start().
    void set_disk_reader_for_test(DiskReaderFn reader);
    /// Test seam: lower the interval/poll cadence floor so tests run in ms.
    /// Set BEFORE any arm().
    void set_cadence_floor_for_test(std::uint64_t floor_ms);
    /// Test seam: shrink the per-consumer shutdown budget so the detach-a-hung-
    /// handler path (UP-1) is exercised in ms, not kConsumerJoinBudgetMs.
    void set_consumer_join_budget_for_test(std::uint64_t ms);
    /// Test seam: if set, invoked once inside register_consumer() right after
    /// its dispatch thread starts but before the consumers_ insert — lets a
    /// test deterministically force stop() into the exact
    /// register_consumer()/stop() race window instead of relying on a
    /// timing-dependent multi-threaded stress loop (governance Tr3kkR finding,
    /// PR #1927 review). Same set-then-use contract as the other test seams
    /// above: set before the register_consumer() call under test, no
    /// concurrent-access support.
    void set_register_race_hook_for_test(std::function<void()> hook);
    /// Test seam: if set, invoked once inside arm_impl() after the mechanism
    /// watch (if any) succeeds and before the post-insert consumer re-check —
    /// lets a test deterministically force unregister_consumer() into the M1
    /// ghost-subscription race window (#1994) instead of a timing-dependent
    /// stress loop. Same set-then-use contract as the other race-hook seams.
    void set_arm_race_hook_for_test(std::function<void()> hook);
    /// Test seam (#2270): if set, invoked once inside arm() AFTER the consumer
    /// pre-check releases consumers_mu_ and BEFORE arm_impl() runs — no locks
    /// held. This is the only deterministic reach into the FIRST half of the M1
    /// window: set_arm_race_hook_for_test fires after the insert, so a hook that
    /// unregisters from there has unregister_consumer() perform the teardown
    /// itself and arm_impl's own teardown degenerates to a no-op. Unregistering
    /// from HERE leaves nothing for the scan to find, so the teardown's real-work
    /// branch (including the OS unwatch) runs. Same set-then-use contract.
    void set_arm_precheck_race_hook_for_test(std::function<void()> hook);
    /// Test seam: if set, invoked inside disarm(), unregister_consumer() AND
    /// teardown_arm_race() (#2270 added the third site, and the M2 case in
    /// test_spark_mechanism.cpp depends on it) — after mu_ is released and before the
    /// staleness-rechecked mechanism unwatch() call. Lets a test deterministically
    /// force a concurrent equal-spec re-arm into the M2 late-unwatch race window
    /// (#1994). Same set-then-use contract. No locks are held when it fires.
    void set_disarm_race_hook_for_test(std::function<void()> hook);
    /// Test seam (#2270): if set, invoked at each labelled allocation point inside
    /// arm_impl() AND inside start()'s pre-start replay (kArmFaultPhaseWatchErrorBuild
    /// fires from both — named, not numbered, so a future renumber cannot strand this —
    /// watch_guarded is shared by the two arm paths, and a replay case depends on it).
    /// A test throws from the phase it wants to simulate an allocation failure at,
    /// which is the only way to exercise the strong-guarantee path deterministically —
    /// a real std::bad_alloc cannot be aimed at one statement. Same set-then-use
    /// contract as the other seams.
    void set_arm_fault_hook_for_test(std::function<void(int phase)> hook);
    /// Test seam (rung 9c PR-6 item 1, E13): if set, invoked exactly once inside
    /// start(), after every mechanism's start() has returned (and the
    /// establishment sink has been installed on each) but BEFORE the pre-start
    /// replay loop runs. No locks held. Lets a test land a disarm+re-arm of a
    /// pre-start subscription INSIDE this exact window, deterministically
    /// reproducing the race the replay's incarnation gate (not a bare
    /// armed_.contains() check) exists to close — the replay must skip a key
    /// whose incarnation has moved on, not merely a key that is still present.
    /// Same set-then-use contract as the other test seams: set before start().
    void set_on_start_hook_for_test(std::function<void()> hook);
    /// Test seam (#2050): if set, invoked at each labelled phase inside start()'s
    /// in-mu_ startup sequence (Replay collection, mechanism-pointer collection,
    /// wheel-thread spawn). None of these three sites is reachable through a
    /// mechanism fake — they run before/around the per-mechanism loop — so this is
    /// the only way to deterministically exercise start()'s rollback guard for them.
    /// CONTRACT: fires with the non-recursive mu_ HELD (all three phases run inside
    /// start()'s `{ lock_guard lk(mu_); ... }` block) — throw or observe only;
    /// re-entering the engine self-deadlocks. Same set-then-use contract as the
    /// other test seams: set before start().
    void set_start_fault_hook_for_test(std::function<void(int phase)> hook);
    /// Reached immediately before the Replay-collection loop iterates armed_.
    static constexpr int kStartFaultPhaseReplayCollection = 1;
    /// Reached immediately before the mechanism-pointer collection loop.
    static constexpr int kStartFaultPhaseMechCollection = 2;
    /// Reached immediately before wheel_thread_ is constructed.
    static constexpr int kStartFaultPhaseWheelSpawn = 3;
    /// Reached after arm_impl's armed_ entry is committed and before the sub_keys_
    /// node is allocated: a throw here must leave armed_/sub_keys_ exactly as on
    /// entry (the in-lock layer).
    /// CONTRACT: fires with the non-recursive mu_ HELD. Throw or observe only —
    /// re-entering the engine from this phase self-deadlocks.
    static constexpr int kArmFaultPhaseBeforeSubKeys = 1;
    /// Reached inside watch_guarded()'s catch arms, before the watch error is
    /// completed from its pre-sized buffer. Pins CONTAINMENT, not rollback: a throw
    /// here must not escape watch_guarded (it would escape arm_impl past a committed
    /// subscription — the #2270 ghost — and escape the void start() on the replay
    /// path). DEFENCE IN DEPTH, not a live-path guard: completion is BoundedMsg::finish,
    /// which is noexcept by construction, so no production statement at this point can
    /// throw today. The seam pins that property portably, on the platforms where the
    /// Linux-only allocation counter in the tests cannot run.
    /// CONTRACT: fires with this spark type's mech_ops_mu_by_type_ entry HELD. Throw or
    /// observe only — re-entering the engine self-deadlocks on that non-recursive mutex.
    ///
    /// ORDINAL 3, NOT 2, DELIBERATELY. Ordinal 2 was `kArmFaultPhaseAfterCommit` until
    /// 6c1d6942 deleted it with the post-commit rollback. Round 4 first reintroduced 2
    /// under this new meaning, which meant a pre-round-4 test or ledger row citing
    /// "phase 2" resolved to something else entirely — and ledger rows in both #2270
    /// fragments do cite it (CA8-1 owns the count; a count quoted here would decay with
    /// every appended row, which governance.d/README.md forbids). Renumbered to 3 so
    /// retired ordinals stay retired
    /// (Gate 8 — CA8-1, doc8-2). Retired so far: 2. Add the next phase as 4, and
    /// document its lock contract as both live phases do.
    static constexpr int kArmFaultPhaseWatchErrorBuild = 3;

private:
    struct Subscriber {
        SubscriptionId id{0};
        SparkTier tier{SparkTier::Queued};
        ConsumerId consumer{0};  ///< Queued only
        InlineHandler inline_fn; ///< Inline only
        /// Startup sparks only: this subscriber has not yet received its
        /// one-shot. A late subscriber re-schedules the spark, but the fire is
        /// delivered ONLY to still-pending subscribers — an earlier subscriber
        /// never sees "startup" twice.
        bool startup_pending{true};
    };

    /// One deduped armed spark: the spec, its wheel schedule, its per-spark
    /// state, and every subscription fanned out from it.
    struct Armed {
        SparkSpec spec;
        std::uint64_t cadence_ms{0}; ///< floored interval/poll cadence
        std::uint64_t seq{0};
        std::chrono::steady_clock::time_point next_due{};
        bool scheduled{false};    ///< on the wheel (false once a one-shot fired)
        bool disk_latched{false}; ///< Disk sparks: poll-and-latch state
        /// A mechanism reported this event-driven spark's watch deaf after a
        /// successful arm (B1). Health-only: surfaced in stats, never blocks
        /// firing. Cleared when the mechanism reports recovery.
        bool faulted{false};
        std::vector<Subscriber> subs;
        /// Identity token (rung 9c PR-6 item 1), minted from the SAME shared
        /// next_id_ counter as ConsumerId/SubscriptionId, ONLY on a fresh key
        /// (never on a dedup arm, which shares the existing key's token). Lets
        /// a mechanism's asynchronous establishment report be checked against
        /// "is this still the CURRENT watch for this key" before it is trusted
        /// (H1) — see report_established().
        SparkIncarnation incarnation{kNoSparkIncarnation};
        /// When this key's CURRENT incarnation was minted (H14: even a
        /// pre-start arm gets this at arm time, not at start()).
        std::chrono::steady_clock::time_point armed_at{};
        /// First time a mechanism reported Notification coverage for the
        /// CURRENT incarnation — first-wins, never re-stamped by a later
        /// recovery (spark.hpp's SubscriptionEstablishment doc comment).
        std::optional<std::chrono::steady_clock::time_point> established_at;
        /// The mechanism's most recently reported tri-state coverage for this
        /// key — unlike established_at, this DOES track the current state
        /// (can drop back to None or Poll and this field follows it).
        SparkCoverage coverage{SparkCoverage::None};
    };

    // #2270 tripwires. arm_impl's publishing tail runs AFTER its first shared-state
    // commit, so it must not throw: it move-assigns an Armed into the map entry and
    // moves a Subscriber into already-reserved vector capacity. Both are nothrow
    // today (every member bottoms out in std::string / std::vector / std::function /
    // trivial types). Adding a throwing-move member to either struct would silently
    // reopen the ghost-entry hole this ordering closes, so it fails to COMPILE here
    // instead — the same tripwire idiom as kMaxProcessIoWorkers in
    // guardian_io_executor.hpp.
    static_assert(std::is_nothrow_move_constructible_v<Subscriber>,
                  "arm_impl publishes a Subscriber into reserved capacity after its "
                  "first commit; a throwing move would leave a ghost armed_ entry (#2270)");
    static_assert(std::is_nothrow_move_assignable_v<Armed>,
                  "arm_impl move-assigns Armed into the committed map entry; a throwing "
                  "move would leave a ghost armed_ entry (#2270)");
    // Move-ASSIGNMENT, which the two asserts above do NOT cover: teardown_arm_race runs
    // std::erase_if(subs, ...) in the post-commit window, where nothing may throw, and
    // erase_if move-assigns Subscribers. is_nothrow_move_assignable_v<Armed> does not
    // reach it transitively — vector's move-assign is nothrow for std::allocator
    // regardless of T. NOT standard-guaranteed: [func.wrap.func.con] declares
    // std::function's move-assignment with no exception specification, and P0771R1
    // strengthened only the move CONSTRUCTOR. All three implementations strengthen it
    // anyway, MEASURED in governance round 4: libstdc++ 15 = true, and MSVC
    // (cl.exe /std:c++latest on the DGRHP rig) = true; libc++ declares it _NOEXCEPT.
    // If a future platform disagrees this fails to COMPILE, loudly and immediately,
    // which is the tripwire working — far better than a silent throw past the commit.
    static_assert(std::is_nothrow_move_assignable_v<Subscriber>,
                  "teardown_arm_race erase_if move-assigns Subscribers after the commit; "
                  "a throwing move-assign would strand a live subscription (#2270)");

    /// Delivery counters touched by consumer dispatch threads. Heap-owned via a
    /// shared_ptr the threads capture, so a DETACHED consumer thread (a handler
    /// that blocked past the shutdown budget, UP-1) can keep writing them safely
    /// after the engine is destroyed — the thread never dereferences the engine.
    struct DeliveryCounters {
        std::atomic<std::uint64_t> delivered{0};
        std::atomic<std::uint64_t> dropped{0};
        std::atomic<std::uint64_t> errors{0};
    };

    struct Consumer {
        std::string name;
        QueuedHandler handler;
        std::size_t cap{kDefaultQueueCap};
        std::mutex mu;
        std::condition_variable cv;
        std::deque<SparkEvent> queue;
        bool stopping{false};
        /// Bounded-shutdown signal: the dispatch thread sets `finished` + notifies
        /// `done_cv` on clean exit, so stop()/unregister can wait_for the budget
        /// then join-or-detach. A hung handler never sets it → we detach (UP-1).
        std::mutex done_mu;
        std::condition_variable done_cv;
        bool finished{false};
        std::thread thread;
    };

    std::expected<SubscriptionId, std::string> arm_impl(SparkSpec spec, Subscriber sub);
    /// Drop one spark key and every subscription fanned out from it. Caller holds
    /// mu_ and owns any OS-watch teardown. Used by arm_impl's failed-WATCH teardown
    /// — see the definition for why a failed watch drops the whole key rather than
    /// one sub. The consumer-race path does NOT use it: losing that race invalidates
    /// one subscription, not the key, so it goes through teardown_arm_race().
    /// (The post-commit rollback this doc used to name was deleted in 6c1d6942.)
    /// Allocates nothing — map/node erases and string compares only.
    void drop_key_locked(const std::string& key);
    /// Undo ONE subscription after arm_impl loses the M1 consumer race. This
    /// declaration states the interface contract; the DEFINITION owns implementation
    /// claims — allocation posture, and the exact count/enumeration of differences
    /// from disarm() — so this comment does not restate either. Both drifted out of
    /// sync when restated here before, each caught by fjarvis's adversarial review
    /// of the PR then open: a completeness claim with no number attached ("differ
    /// only in that this one takes key/type from the caller"), found reviewing PR
    /// #2863; and an "allocating nothing" claim, made false by the log calls this
    /// function contains, found reviewing PR #2868. Do not reintroduce either at
    /// THIS declaration — see the definition for both. The caller owns `key`/`type`/
    /// `event_driven`, so nothing has to be copied or recomputed for THOSE
    /// specifically. A specialization of disarm() — lockstep siblings, NOT exact
    /// duplicates. It is NOT redundant with disarm():
    /// routing arm_impl's M1 teardown through disarm() would remove ONE subscription
    /// via a whole-key-capable path and reintroduce a lookup on values the caller
    /// already holds. Keep the two in lockstep.
    /// NOT noexcept: mutex acquisition can raise std::system_error (the residual
    /// stated in arm_impl); turning that into std::terminate would be worse.
    void teardown_arm_race(SubscriptionId id, const std::string& key, SparkType type,
                           bool event_driven);
    /// Validate + normalise (cadence flooring). Returns the effective cadence
    /// (0 for the event-driven and startup types, which have no wheel cadence).
    std::expected<std::uint64_t, std::string> validate_and_floor(const SparkSpec& spec) const;
    [[nodiscard]] std::chrono::steady_clock::time_point
    initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                std::chrono::steady_clock::time_point now) const;
    /// File / Registry / Service: serviced by a mechanism, never the wheel.
    [[nodiscard]] static bool is_event_driven(SparkType type) noexcept;
    /// The mechanism fire entry point: fan one event-driven fire out to every
    /// subscriber of `key`. Looks the key up + snapshots subs under mu_, then
    /// releases mu_ before delivering (an inline consumer that re-arms takes
    /// mu_ — delivering under it would deadlock). A key disarmed mid-flight is
    /// simply skipped. Distinct from the wheel's commit path, which also owns
    /// reschedule + per-subscriber startup semantics.
    void emit_event(const std::string& key, SparkData data);
    /// Mechanism health entry point (B1): a mechanism reports that a watch it had
    /// armed went deaf (faulted=true) or recovered (faulted=false). Folds the
    /// edge into Armed::faulted + the fault counter under mu_. Never blocks
    /// firing — health only. Called with the engine lock released.
    void report_fault(const std::string& key, bool faulted, std::string_view reason);
    /// Establishment-signal entry point (rung 9c PR-6 item 1): a mechanism
    /// reports a coverage transition for `key`. mu_ ONLY — allocation-free, no
    /// deliver() (this is a pull-query field, not a delivered event). Identity
    /// check first (drops a report whose incarnation no longer names the
    /// key's CURRENT watch — H1), then an UNCONDITIONAL coverage assignment
    /// (the cache always reflects the mechanism's last-reported value), then
    /// first-wins established_at stamping (set only once per incarnation, only
    /// on a Notification transition). Called with the engine lock released,
    /// like report_fault().
    void report_established(const std::string& key, SparkIncarnation incarnation,
                            std::chrono::steady_clock::time_point at, SparkCoverage coverage);
    /// #2050: stop()'s teardown body, factored out so start()'s own rollback guard can
    /// drive the identical teardown on a startup failure. REQUIRES lifecycle_mu_
    /// ALREADY HELD by the caller — stop() holds it via its own `life` lock_guard;
    /// start()'s rollback guard runs while start()'s `life` lock_guard is still live
    /// (the guard is declared after `life` and destructs before it unwinds — see
    /// start()'s definition for why that ordering is deadlock-load-bearing, not
    /// cosmetic). Never call this without lifecycle_mu_ held, and never re-enter it on
    /// the same thread — lifecycle_mu_ is non-recursive.
    ///
    /// MAY THROW, exactly as stop()'s body always could (joins, map ops, spdlog can
    /// all raise). Each of the two callers contains that itself: stop()'s own outer
    /// `noexcept try { } catch (...) { }` (unchanged by this refactor), and the
    /// rollback guard's own inline try/catch (a destructor must never let an
    /// exception escape mid-unwind).
    ///
    /// Mechanism teardown is per-iteration-isolated: one mechanism's stop() throwing
    /// does not skip the rest, and `teardown_complete_` is set ONLY when every phase
    /// — including every mechanism this pass — completed without throwing, so a
    /// partial pass is retried (idempotently) by the next caller instead of being
    /// latched away as done.
    void teardown_locked();
    void wheel_loop();
    void deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs);
    /// Signal one consumer to stop (set stopping + notify). Non-blocking.
    static void signal_stop(const std::shared_ptr<Consumer>& consumer);
    /// Wait for one already-signalled consumer to finish until `deadline`, then
    /// join it; detach + count if it is still inside a handler at the deadline
    /// (UP-1). Caller holds NO lock.
    void await_consumer(const std::shared_ptr<Consumer>& consumer,
                        std::chrono::steady_clock::time_point deadline);
    /// signal_stop + await_consumer against a fresh per-consumer budget (the
    /// single-consumer path, unregister_consumer). Idempotent per consumer.
    void quiesce_consumer(const std::shared_ptr<Consumer>& consumer);
    /// Static (captures no `this`): a detached consumer thread must reference only
    /// the two shared_ptrs it was handed, so it stays memory-safe after the engine
    /// dies (UP-1).
    static void consumer_loop(std::shared_ptr<Consumer> consumer,
                              std::shared_ptr<DeliveryCounters> counters);

    /// LIFECYCLE lock — serialises register_mechanism() / start() / stop() against
    /// each other, held for the WHOLE of each. Distinct from `mu_` (which guards
    /// per-operation state and is taken by the wheel and the hot arm/disarm paths):
    /// a lifecycle op must not hold `mu_` while joining threads, but it MUST exclude
    /// its siblings end-to-end.
    ///
    /// Two invariants ride on it:
    ///   1. stop()'s teardown_complete_ early-out is a genuine COMPLETION barrier —
    ///      the loser waits here for the winner to finish, so ~SparkEngine can never
    ///      outrun an in-flight stop() (Gate-3 B3).
    ///   2. stop() may iterate `mechanisms_` without `mu_` — no register_mechanism()
    ///      can be concurrently mutating the map, even during the boot window where
    ///      Agent::stop() is reachable from the Windows SCM control thread while the
    ///      main thread is still registering (Gate-4 UP-1).
    ///
    /// LOCK ORDER: lifecycle_mu_ → mu_. Never the reverse. The wheel and the
    /// arm/disarm paths take only mu_, so they cannot deadlock against a lifecycle op.
    std::mutex lifecycle_mu_;

    // armed sparks + subscription index + wheel state, all under mu_.
    mutable std::mutex mu_;
    /// Serializes every mechanism watch()/unwatch() call PER MECHANISM TYPE
    /// (#1994 M2; per-type granularity #2011). Without this, a disarm()'s
    /// pending unwatch(key) and a concurrent re-arm's watch(key) for an equal
    /// spec can interleave out of order — the late unwatch tears down the fresh
    /// watch while armed_ still shows the key armed. Each call site re-checks
    /// armed_'s current state for the key WHILE HOLDING this lock, immediately
    /// before issuing the mechanism call, so the mechanism call always reflects
    /// the freshest armed_ state. Correctness needs only same-KEY ordering, and
    /// a key encodes its SparkType (spark_key) — so a lock per mechanism type is
    /// sufficient: two keys that could collide always share a type.
    /// Lock order: mech_ops_mu_by_type_[type] → mu_, NEVER reversed; mechanism
    /// worker threads (wheel/IOCP/TP_WAIT callbacks) call emit()/fault() with
    /// their own internal lock released and never touch these locks, so there is
    /// no cycle. REQUIRES (Stage-2 trap, enforced by convention): a mechanism
    /// must deliver emit()/fault() ASYNCHRONOUSLY — off the watch()/unwatch()
    /// call stack, from its own thread. A mechanism that fired emit()
    /// synchronously from inside watch(), reaching an inline consumer that
    /// re-arms, would re-enter arm_impl → the same type's lock and self-deadlock
    /// this non-recursive lock. All shipped mechanisms emit from worker threads,
    /// so this holds today; a future mechanism author must preserve it
    /// (cpp-safety Gate 3). Coarsened to per-TYPE (not per-key): arm/disarm are
    /// rare control-plane operations, so a mechanism call briefly blocking
    /// another same-type key's arm/disarm is an acceptable trade for not needing
    /// per-key generation tokens.
    /// RESOLVED cross-mechanism coupling (#2011): a slow watch() on one
    /// mechanism no longer blocks a concurrent arm/disarm on a DIFFERENT
    /// mechanism (e.g. File no longer blocks Registry/Service) — the HARD GATE
    /// closed before Stage 2 wires the second live mechanism under load.
    /// SAME-TYPE stall (#2012/#3840, the walk-off-mu_ restructure), per
    /// mechanism: a slow watch() stalls its OWN type's arm/disarm queue for as
    /// long as the mechanism lets it. REGISTRY is bounded since PR-B1
    /// (spark_registry.cpp): watch() reserves under the mechanism's own lock,
    /// runs the probe on a detached F3-counted worker, waits at most
    /// kRegCallerWaitBudget (50 ms - PR-B's chosen initial policy value, not a
    /// measured bound; the measured inputs in docs/spark-rebuild-baselines/
    /// stage2-watch-establish-latency.md sit at 82 us / 1264 us p99) and
    /// otherwise publishes the probe to its sweeper; unwatch() hands the
    /// blocking callback drain to a detached worker and returns in
    /// microseconds - which also closes the #4181 same-type reentrant deadlock
    /// (this lock held across that drain while the drained callback's Inline
    /// consumer needed it). Cost: a consumed Target-mode Registry notification is now TWO
    /// emit submissions (the immediate fire, then a synthetic fire when the
    /// asynchronous re-arm commits) - a queued consumer's per-consumer,
    /// drop-oldest queue (deliver()) can therefore be pushed by a noisy key's
    /// synthetic fire into evicting a quiet key's only fire, a detection-
    /// latency/fairness cost, and nothing here dedups on the wire (Guardian's
    /// decide_emit re-emits Drift past debounce_ms regardless). LANDED for FILE
    /// (PR-B2, #2012): watch()'s discovery/ancestor-walk probe now runs on a
    /// detached F3-counted worker, bounded on the control path by
    /// kFileCallerWaitBudget, with the same reservation-before-publication
    /// shape as Registry above - a hung probe on a dead UNC path no longer
    /// holds File's lock for the OS network timeout. LANDED for SERVICE, Windows
    /// half only (PR-B3, #2012/#3840): its queue-push watch()/unwatch() were
    /// already O(1); OpenServiceW establishment now runs on a bounded,
    /// F3-counted probe lane instead of head-of-line on its worker. The Linux
    /// sd-bus mechanism has no head-of-line OS call in watch()/unwatch() at
    /// all (a queue push only), so PR-B3 did not need a Linux half.
    /// Populated in register_mechanism() under mu_, in lockstep with
    /// mechanisms_, and — like mechanisms_ — never erased thereafter, so a
    /// std::mutex& obtained via .at(type) is safe to hold across the blocking
    /// mechanism call for the same structural-stability reason a raw mechanism
    /// pointer is (see mechanisms_ below). The map is moreover FROZEN after
    /// start(): register_mechanism() is rejected once running_ (all under mu_),
    /// while every .at() read site runs only when running_ — so the lock-free
    /// .at() tree-walks are strictly disjoint in time from the sole mutator
    /// across the start() mu_ barrier, never a concurrent read/write race (that
    /// frozen-after-start fact, not node-stability alone, is what makes the
    /// unsynchronized .at() reads sound).
    mutable std::map<SparkType, std::mutex> mech_ops_mu_by_type_;
    std::condition_variable wheel_cv_;
    std::map<std::string, Armed> armed_; ///< by spark_key
    std::map<SubscriptionId, std::string> sub_keys_;
    bool running_{false};
    /// Atomic (not just mu_-guarded, though every write and most reads still
    /// hold mu_ too): register_consumer() must re-check this under
    /// consumers_mu_ — a DIFFERENT mutex — to close the race where stop() lands
    /// between its stopped_ check and its consumers_ insert (governance Tr3kkR
    /// finding, PR #1927 review). Atomic gives that cross-mutex read a defined
    /// value without relying on a same-thread mu_-then-consumers_mu_ publish
    /// argument that a future refactor could silently break.
    std::atomic<bool> stopped_{false};
    /// Set ONLY once stop()'s teardown has actually run to completion. Distinct from
    /// stopped_, which latches "accept no new work" BEFORE the teardown (whose joins,
    /// map ops and logging can all throw). stop()'s early-out tests THIS, so a teardown
    /// that threw part-way is retried by the next caller — normally ~SparkEngine —
    /// instead of being latched away as "already stopped" and leaving a joinable wheel
    /// thread for the destructor to terminate on (Gate-8 security-guardian).
    bool teardown_complete_{false}; ///< guarded by mu_
    std::thread wheel_thread_;
    std::uint64_t next_id_{1}; ///< shared consumer/subscription id counter

    /// Event-driven watch mechanisms by type. Registered before start(),
    /// structurally stable thereafter (entries never added/removed until
    /// destruction), so a raw pointer captured under mu_ stays valid for any
    /// operation. Mechanism methods (start/watch/unwatch/stop) are ALWAYS
    /// invoked with mu_ released — they may block on OS handle setup.
    std::map<SparkType, std::unique_ptr<ISparkMechanism>> mechanisms_;

    mutable std::mutex consumers_mu_;
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers_;

    DiskReaderFn disk_reader_; ///< test seam; null = read_disk_level (set before start; the
                               ///< wheel snapshots it once at thread start — set-then-start)
    std::atomic<std::uint64_t> cadence_floor_ms_{kMinCadenceMs}; ///< atomic: read at arm, set by test seam
    std::atomic<std::uint64_t> consumer_join_budget_ms_{kConsumerJoinBudgetMs}; ///< test seam
    std::function<void()> register_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::function<void()> arm_race_hook_for_test_;      ///< test seam; null = no-op (set-then-use)
    std::function<void()> arm_precheck_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::function<void(int)> arm_fault_hook_for_test_;  ///< test seam; null = no-op (set-then-use)
    std::function<void()> disarm_race_hook_for_test_;   ///< test seam; null = no-op (set-then-use)
    std::function<void()> on_start_hook_for_test_;      ///< test seam (E13); null = no-op (set-then-use)
    std::function<void(int)> start_fault_hook_for_test_; ///< test seam (#2050); null = no-op (set-then-use)

    // Delivery counters touched by consumer dispatch threads live in a shared
    // block so a detached thread can write them after ~SparkEngine (UP-1). The
    // producer-side drop-oldest path (deliver, on watcher threads joined before
    // destruction) writes the same block via this handle.
    std::shared_ptr<DeliveryCounters> delivery_{std::make_shared<DeliveryCounters>()};
    std::atomic<std::uint64_t> consumer_threads_detached_{0};
    std::atomic<std::uint64_t> watch_faults_{0}; ///< monotonic mechanism fault-report count
    std::atomic<std::uint64_t> arm_race_unwatch_failures_{0}; ///< monotonic; teardown_arm_race ONLY (#2270)
    std::atomic<std::uint64_t> disarm_unwatch_failures_{0};   ///< monotonic; disarm() ONLY (#2270)
    std::atomic<std::uint64_t> teardown_join_timeouts_{0};    ///< monotonic; stop()'s lease wait expired (#2815)
    std::atomic<std::uint64_t> subscription_lost_{0}; ///< monotonic; #2818 Lost notifications delivered

    /// #2815 TEARDOWN LEASE. Callers currently inside one of the FOUR windows that
    /// resolve a raw `ISparkMechanism*` (and this engine's mech_ops_mu_by_type_ entry)
    /// under mu_, RELEASE mu_, and then call into the mechanism: disarm(),
    /// teardown_arm_race(), unregister_consumer(), and the live arm path in arm_impl().
    /// Armed as the last statement of the SAME mu_ block that resolves the mechanism,
    /// released when the enclosing function returns (an RAII lease in spark_engine.cpp).
    ///
    /// stop() waits on it BOUNDED before stopping the mechanisms; ~SparkEngine waits on
    /// it UNBOUNDED before any member is destroyed. The unbounded one is the actual
    /// safety mechanism: without it, ~SparkEngine frees mech_ops_mu_by_type_ out from
    /// under a caller parked in that window (use-after-free). The bounded one is an
    /// API-contract nicety, and stop() must never become a place shutdown can hang.
    ///
    /// NO NEW CALLER CAN ARM A LEASE BEHIND stop() on three of the four doors: disarm(),
    /// teardown_arm_race() and arm_impl() gate their own entry on running_/stopped_
    /// under mu_ BEFORE they resolve a mechanism, so once stop()'s early locked block
    /// has flipped both flags a later caller resolves nothing and arms nothing. (Door 3
    /// is the exception to THIS claim only — its unwatch()-gating is uniform across all
    /// four doors; see below.)
    /// unregister_consumer() (door 3) gates ENTRY differently — on whether `id` is
    /// still present in consumers_, which stop() doesn't empty until its OWN later
    /// step 3 (the consumers.swap) — so a call landing in that window still arms a
    /// lease (governance Gate 8 cpp-expert finding, correcting an earlier draft of
    /// this paragraph that overstated door 3's residual risk: it does NOT still call
    /// unwatch() on a mechanism stop() may be concurrently tearing down). The actual
    /// unwatch() call is gated by the SAME running_ check as the other three doors —
    /// it sits on the to_unwatch collection inside this window, not on the lease —
    /// so once stop() flips running_ false, a racing unregister_consumer() collects
    /// nothing and its post-mu_ unwatch loop runs zero times. What's genuinely
    /// different about door 3 is narrower: the lease itself is armed
    /// UNCONDITIONALLY (see unregister_consumer()'s own comment), because this
    /// function's tail — quiesce_consumer() — touches consumer_join_budget_ms_/
    /// consumer_threads_detached_ regardless of whether any mechanism call happened.
    /// So a post-flip caller can still arm a lease with an empty unwatch loop
    /// (harmless, slightly conservative over-counting), never a live unwatch()
    /// racing a concurrently-stopping mechanism. What's not true is that the ENTRY
    /// GATE on the LEASE is uniform across all four doors — it is uniform on the
    /// mechanism-unwatch path.
    ///
    /// A PLAIN ATOMIC, POLLED — a simplicity choice, not a forced one (governance
    /// Gate 3 cpp-expert review: worth recording precisely, since the original
    /// wording here overclaimed that a condition_variable was ruled out entirely).
    /// The lease is released from an RAII DESTRUCTOR on the door caller's thread. A
    /// destructor that itself LOCKED a mutex would std::terminate on the
    /// std::system_error std::mutex::lock is permitted to raise, in a subsystem whose
    /// whole design premise is that an observe-only component may never take the
    /// agent down (see stop()'s noexcept rationale) — that part is a real, load-
    /// bearing constraint. But `condition_variable::notify_all()` itself takes no
    /// lock and is noexcept, so a hybrid (atomic fetch_sub, then a lock-free
    /// notify_all, with this same poll retained only as a much-longer-interval
    /// lost-wakeup backstop) was a real option that was not implemented, not one
    /// that couldn't be. fetch_sub cannot throw, so the count is always correct
    /// either way; the waiters absorb the cost as a 1 ms sleep-poll, which is paid
    /// only at shutdown and only while a caller is genuinely in flight — judged not
    /// worth the added complexity for a dormant subsystem's teardown path. Ordering:
    /// the releasing fetch_sub and the waiters' acquiring load give the waiter
    /// happens-before over everything the door caller did.
    std::atomic<std::uint64_t> inflight_teardowns_{0};

    // Counters updated outside mu_ (delivery paths) — atomics.
    std::atomic<std::uint64_t> events_total_{0};
    std::atomic<std::uint64_t> inline_calls_{0};
    std::atomic<std::uint64_t> inline_errors_{0};
    std::atomic<std::uint64_t> inline_us_total_{0};
    std::atomic<std::uint64_t> inline_us_max_{0};
    std::atomic<std::uint64_t> inline_over_100us_{0};
    std::atomic<std::uint64_t> inline_over_10ms_{0};
};

} // namespace yuzu::agent
