#pragma once

/**
 * guardian_outbox_drain_worker.hpp - the live-drain worker for
 * GuardianSparkRuntime's outbox + Lifecycle audit log (ADR-0021 Stage 2 rung
 * 7, F6).
 *
 * Mirrors ConvergenceScheduler's proven CV-wake + shared-Signal lifetime shape
 * (twice-Sol-reviewed, TSan-clean): the waker installed on the runtime
 * captures ONLY a shared_ptr<Signal>, never `this`, so a copy invoked after
 * this worker is destroyed touches a still-alive Signal (a harmless no-op),
 * never a destroyed mutex/cv.
 *
 * WHY (F6): the approved outbox contract drains at sink-publication + every
 * reconnect. A healthy connection can stay up indefinitely, so that alone has
 * no bounded staleness for an event produced while already connected. This
 * worker adds a THIRD trigger: wake immediately whenever the runtime enqueues
 * anything (compliance/health/lifecycle), with a periodic bound as a backstop
 * in case a wake is ever missed.
 *
 * OWNERSHIP: GuardianEngine owns this as a member alongside the
 * GuardianSparkRuntime it references - constructed after, stopped/joined
 * before (see GuardianEngine::stop()'s documented shutdown order), so the
 * reference stays valid for this worker's entire lifetime, the same
 * relationship ConvergenceScheduler already has to the runtime.
 *
 * `send` MAY capture GuardianEngine/AgentImpl state (e.g. `this`) directly -
 * BUT (#2233 item 4, revised) the actual call to `send` no longer necessarily
 * runs ON this worker's thread, and is no longer necessarily joined by stop():
 * drain_bounded() routes it through GuardianOutboxSendExecutor
 * (guardian_outbox_send_executor.hpp), which detaches the call so a stalled
 * sink cannot wedge this worker's own maintenance/cadence. A detached send can
 * therefore outlive stop()'s join, exactly like the SparkEngine-queued-consumer
 * handler this paragraph used to contrast against - `send`'s capture is safe
 * ONLY because active_send_workers() (below) is summed into
 * GuardianEngine::active_io_workers(), the orphan-exit contract's sole source
 * of truth: main.cpp/service_win.cpp refuse normal C++ teardown of the very
 * object `send` captures while that count is nonzero, hard_exit()ing instead
 * after a bounded grace. A source left out of that sum would silently
 * reinstate the use-after-free this paragraph used to rule out by construction.
 *
 * WITH ONE ABSOLUTE EXCEPTION: whatever runs ON THIS WORKER'S OWN THREAD - the
 * loop() body and journal maintenance, see the central constraint below - must
 * never take GuardianEngine::mtx_. `send` (the injected std::function from
 * agent.cpp) is deliberately EXCLUDED from that set as of #2233 item 4: it now
 * runs on GuardianOutboxSendExecutor's detached worker (guardian_outbox_send_
 * executor.hpp), never on this thread, so it can no longer produce the
 * lock-vs-join deadlock this exception used to warn about - that is precisely
 * the property tests/unit/test_guardian_outbox_drain_worker.cpp's role-marker
 * test now checks (on_guardian_joined_thread() reads FALSE inside `send`).
 * `send` taking mtx_ is still pointless (nothing on that thread needs it) and
 * still worth avoiding, but it is no longer the CATASTROPHIC exposure this
 * paragraph originally named - see guardian_outbox_send_executor.hpp for what
 * IS still load-bearing about `send`'s capture (the orphan-exit contract).
 * GuardianEngine aborts on an mtx_ acquisition on the WORKER thread itself in
 * debug/sanitizer builds via the thread-local marker in
 * guardian_joined_thread_role.hpp, so a violation there crashes loudly rather
 * than hanging a fleet.
 *
 * JOURNAL MAINTENANCE (C0, #2298 gate 1): this worker also runs the durable
 * lifecycle journal's retention prune + replay paging, which used to run inline
 * on the heartbeat thread (journal_maintenance_tick phase 2) and the reconnect /
 * run-loop thread (page_journal). Both are KvStore-bound and can block on its
 * 5 s busy timeout, so a large or contended journal stalled a latency-sensitive
 * thread; here the same work is already-async and co-located with the KvStore I/O
 * the drain path does anyway (mark_batch_sent per sent batch).
 *
 * THE CENTRAL CONSTRAINT: maintenance must NEVER take the GuardianEngine mtx_.
 * GuardianEngine::stop() holds mtx_ across its whole body AND joins this worker
 * inside it, so an mtx_ acquisition on this thread is a lock-vs-join deadlock.
 * That is why the journal arrives as a pre-resolved shared_ptr captured at
 * construction rather than being re-read off the engine under its lock - the same
 * shape as the enqueue-waker capturing only a shared Signal, never `this`.
 * Shutdown is coordinated purely by atomics: the journal's own stopping_ gate
 * (set FIRST in engine::stop()) plus this worker's stopping flag.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_outbox.hpp"              // OutboxEntry, SendResult
#include "guardian_outbox_send_executor.hpp" // GuardianOutboxSendExecutor
#include "guardian_spark_runtime.hpp"        // GuardianSparkRuntime

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <thread>

namespace yuzu::agent {

class GuardianLifecycleJournal;

/// Journal REPLAY-PAGE cadence. Load-bearing (#2298 governance f-1/A1): a paging pass scans
/// the whole batch-key namespace, and JournalPagingBucket charges a token only when a batch
/// pages NET-NEW work. So when the send window already holds every candidate - the normal
/// state while the link is down and the backlog is retained - the bucket never throttles and
/// every wake rescans. Since the drain worker wakes on EVERY outbox enqueue, "page on every
/// wake" is scan cost driven by the event rate. 30 s restores exactly the pre-C0 rate (one
/// page per heartbeat tick); the reconnect kick still forces an immediate page, so replay
/// promptness is unaffected.
///
/// The per-pass cost is much lower since #2299 - the scan reads keys and value lengths, and
/// values are read only for the candidates actually considered - but the cadence still bounds
/// the SCAN, which no amount of lazy parsing removes.
inline constexpr std::chrono::milliseconds kGuardianJournalPageInterval{30'000};

/// Retention-prune cadence. TIME-based for the same reason, and additionally because the
/// heartbeat's old "every 4th tick" rule was only safe while a tick WAS a fixed 30 s.
/// ~2 min preserves that effective cadence (4 x 30 s) without depending on a tick count.
inline constexpr std::chrono::milliseconds kGuardianJournalPruneInterval{120'000};

/// Entries shipped per drain pass before the worker re-checks its other work. Unbounded, a
/// slow stream drains the whole 4096-entry window - at 20 ms/send that is ~82 s of
/// head-of-line blocking - which post-C0 would starve journal retention until the write
/// ceiling DROPS audit records (#2298 governance f-3). The worker re-drains immediately on
/// hitting this bound, so steady-state throughput is unchanged.
inline constexpr std::size_t kGuardianDrainBudget = 512;

/// Minimum gap between refill-driven forced pages. The refill re-arm exists so a reconnect
/// backlog moves without waiting out the page cadence, but each forced page is a full journal
/// scan, so it needs a floor. TIME rather than a cycle count: a counter reset on a
/// condition-variable wait is no bound at all, because that wait returns immediately whenever
/// an enqueue already moved the generation (#2345 Gate 4 UP-1).
inline constexpr std::chrono::milliseconds kGuardianMinRefillInterval{1'000};

/// How far a RECONNECT-forced page may be deferred when jitter is on (item 12). Small on
/// purpose: the kick exists for promptness, and replay volume is bucket-paced anyway, so a
/// few seconds of fleet spread costs nothing an operator would notice while turning a
/// simultaneous fleet-wide journal scan into a smear.
inline constexpr std::chrono::milliseconds kGuardianForcedPageJitterMax{5'000};

/// A uniform offset in [0, upper). Free function so the distribution itself is unit-testable
/// without a running worker. `upper <= 0` yields 0 (a zero interval means "no cadence").
[[nodiscard]] YUZU_EXPORT std::chrono::milliseconds
guardian_jitter_offset(std::mt19937& rng, std::chrono::milliseconds upper);

/// Wall-clock companion to kGuardianDrainBudget. 512 entries bounds the COUNT but not the
/// TIME: at a pathological seconds-per-send it is still minutes, and the worker may be
/// holding up GuardianEngine::stop()'s join for all of it.
inline constexpr std::chrono::milliseconds kGuardianDrainMaxWall{2'000};

/// Per-attempt bound on how long the worker thread waits for a detached send to finish
/// before treating it as still-in-flight and retaining the head (#2233 item 4,
/// guardian_outbox_send_executor.hpp). Small relative to kGuardianDrainMaxWall so a
/// stalled sink costs the worker at most this much per tick, not the send's actual
/// duration - the detached worker keeps running past this deadline; only the CALLER
/// stops waiting on it.
inline constexpr std::chrono::milliseconds kGuardianSendOfferWait{200};

/// Internal re-check bound (#3953 item 3): when a send is known in flight on either
/// lane (GuardianOutboxSendExecutor::has_in_flight_send()), loop()'s own wait is
/// clamped to at most this, instead of riding out the full periodic bound. Closes the
/// throughput cliff a send finishing between kGuardianSendOfferWait and the periodic
/// bound used to hit: detection latency after completion is now bounded by roughly
/// kGuardianSendOfferWait + this, not by kDefaultPeriodicBoundMs (5s in production).
/// Deliberately NOT a wake source (no sig_->gen bump, no notify_all) - it only shortens
/// how long the loop's OWN wait blocks, so it cannot perturb any test whose timing
/// depends on nothing else waking the loop (see the R4 test's own comment).
inline constexpr std::chrono::milliseconds kGuardianSendRecheckInterval{200};

/// Journal-maintenance knobs for GuardianOutboxDrainWorker. A struct rather than more
/// positional parameters so the two same-typed intervals cannot be transposed at a call
/// site, and so a test can name only what it overrides:
/// `{.journal = j, .prune_interval = 0ms}`.
///
/// Namespace-scope, not nested: a default argument cannot require a nested class's default
/// member initializers before the enclosing class is complete.
struct GuardianMaintenanceConfig {
    /// SHARED, may be null (no maintenance runs). A shared_ptr rather than a raw borrow so
    /// the worker's dependency on the journal is expressed in the type system: previously
    /// correctness rested on GuardianEngine declaring the journal before the worker, an
    /// unenforceable ordering nothing would have caught if reordered (#2298 governance A4).
    /// One allocation, and the whole class of failure goes away.
    std::shared_ptr<GuardianLifecycleJournal> journal{};
    std::chrono::milliseconds page_interval{kGuardianJournalPageInterval};
    std::chrono::milliseconds prune_interval{kGuardianJournalPruneInterval};
    std::size_t drain_budget{kGuardianDrainBudget};
    /// Wall-clock cap on one drain pass. A COUNT bound is not a safety bound - one
    /// slow-but-succeeding send makes an N-entry pass arbitrarily long while
    /// GuardianEngine::stop() waits on our join (#2298 Sol review).
    std::chrono::milliseconds drain_max_wall{kGuardianDrainMaxWall};
    /// Spread this agent's maintenance phase over its interval (C0 flip-checklist item 12).
    /// Every agent boots its worker at its own start, so nothing correlates the CADENCE
    /// across a fleet - but the FORCED passes do correlate: a gateway bounce or a restored
    /// snapshot hands every agent a boot/reconnect page in the same second, each a full
    /// journal scan and a token burst. Jitter is aimed at that burst.
    ///
    /// Default OFF and enabled explicitly by production wiring. Inferring it from whatever
    /// else a caller configured would be worse than useless in tests: several drive a live
    /// worker without overriding any timing, including the production-boot-order regression
    /// that depends on the worker running IMMEDIATELY - a hollow pass is the failure mode
    /// there, not a red one.
    bool jitter{false};
};

/// Which maintenance passes to run this cycle. The CALLER owns cadence - the worker loop
/// keeps its timers as locals, so the worker holds no cross-thread timer state and
/// maintenance_once() is a pure function of its argument.
struct GuardianMaintenanceOps {
    /// Re-offer batches that already carry a durable sent-label. TRUE only on a FORCED page
    /// (boot replay, reconnect kick) - the events after which an in-flight send may have been
    /// lost. False on the cadence pass, so steady state does not re-deliver what the server
    /// already has (#2345 round 8).
    bool replay_sent{false};
    bool prune{false};
    bool page{false};
};

/// Outcome of one maintenance pass. Deliberately NOT JournalPageStats: keeping the journal
/// a forward declaration here holds the dependency direction to worker -> journal without
/// dragging the audit component into this header.
struct GuardianMaintenanceResult {
    bool page_attempted{false};   ///< a paging pass was requested and ran
    std::size_t records_paged{0}; ///< net-new records placed in the send window
    /// The pass had a candidate it could not place for lack of room FOR THAT BATCH (not
    /// necessarily a full window - headroom 255 blocks a 256-entry batch). Only
    /// this - never "records_paged == 0" - justifies re-attempting outside the cadence
    /// (#2298 Gate 4 UP-2).
    bool headroom_blocked{false};
    /// Smallest blocked batch's requirement; see JournalPageStats.
    std::size_t min_blocked_headroom{0};
    /// The pass did nothing because the paging rate-limiter had no token; see
    /// JournalPageStats::deferred_no_token. A forced page must be re-armed on this.
    bool deferred_no_token{false};
    /// Candidates skipped because they already carry a durable sent-label - per-pass and
    /// diagnostic. No cumulative counter and no heartbeat tag, so do not cite it as
    /// fleet-visible evidence (#2345 Gate 8).
    std::size_t skipped_already_sent{0};
    /// The sent-label scan failed and the pass fell back to re-offering everything.
    bool sent_scan_failed{false};
    /// THE page-side gate signal (#2452 Gate 7): the pass placed records or positively verified a
    /// clean idle backlog (JournalPageStats::progress_or_verified_idle). False on EVERY no-work
    /// exit - deferred, sent-scan/candidate/value read failure, boot-prune barrier, headroom-
    /// blocked, quarantine-only, null-kv, a stopping_ bail - so the drain worker's page success
    /// stamp advances iff this is true (mirrors the prune side gating on prune_progress_or_verified).
    bool progress_or_verified_idle{false};
    /// A prune pass was requested and ran (mirrors page_attempted for the retention side).
    bool prune_attempted{false};
    /// THE prune-side gate signal (JournalPruneStats::progress_or_verified, #2452 Gate 8): retention
    /// was applied or verified idle. False on every no-work prune exit - scan failure, delete
    /// failure, and any stop before the delete - so the prune success stamp advances only on this
    /// (the prune-side mirror of progress_or_verified_idle; closes UP-7 delete-fail + UP8-3
    /// stop-abort that gating on read_ok alone left open).
    bool prune_progress_or_verified{false};
};

class YUZU_EXPORT GuardianOutboxDrainWorker {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    /// Backstop poll cadence when no enqueue-wake ever arrives. Matches the
    /// convergence scheduler's priority-lane cadence philosophy (fleet-kind,
    /// still bounds staleness in the pathological case).
    static constexpr std::uint64_t kDefaultPeriodicBoundMs = 5'000;

    GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                              std::uint64_t periodic_bound_ms = kDefaultPeriodicBoundMs,
                              GuardianMaintenanceConfig maintenance = GuardianMaintenanceConfig{});
    ~GuardianOutboxDrainWorker();
    GuardianOutboxDrainWorker(const GuardianOutboxDrainWorker&) = delete;
    GuardianOutboxDrainWorker& operator=(const GuardianOutboxDrainWorker&) = delete;

    /// Install the enqueue waker on `rt` and start the worker thread.
    /// Single-shot (a second call is a no-op).
    void start();
    /// Clear the waker, wake the worker, and join. Idempotent; never blocks a
    /// full periodic bound (the CV wake is immediate).
    void stop();

    /// Wake the worker NOW, and force the next cycle to page regardless of the page
    /// cadence. Used by the reconnect hook so a freshly-connected stream gets its
    /// journal replay promptly (C0 #2298: the reconnect thread kicks, it no longer pages
    /// inline). The force is what keeps kDefaultPageInterval from delaying reconnect
    /// replay. A no-op after stop(). Safe before start(): both the bumped generation and
    /// the force flag are observed by the loop's first cycle.
    void notify();

    /// TEST-ONLY deterministic seam: run ONE drain pass synchronously on the caller's thread,
    /// UNBOUNDED. It has NO production caller by design - the loop body uses the bounded
    /// private drain_bounded(). Deliberately retained rather than deleted because several
    /// tests rely on a synchronous drain, but note it bypasses every limit the worker applies
    /// in production (count, wall clock, stop predicate), so it must not become a shortcut for
    /// production code (#2345 / Sol). Does NOT firewall
    /// exceptions - the worker thread's loop() does (so a test can still observe a
    /// throw, but a bad_alloc on the bare worker thread never terminates the agent).
    void drain_once();

    /// TEST-ONLY: pin the jitter source so offsets are reproducible. Intended before
    /// start(), but it takes sig_->mu regardless: the RNG is worker-thread state guarded by
    /// that mutex, and a doc comment is not a synchronization primitive - a later caller
    /// would otherwise race the loop's own draws and trip TSan rather than fail visibly.
    void seed_jitter_rng_for_test(std::uint32_t seed) {
        std::lock_guard<std::mutex> lk{sig_->mu};
        jitter_rng_.seed(seed);
    }

    /// TEST-ONLY: the steady-clock ms before which a pending forced page will not be
    /// consumed (0 = none). Reading it is how a test observes a DEFERRED force without
    /// asserting a wall-clock upper bound.
    [[nodiscard]] std::int64_t force_page_not_before_ms_for_test() {
        std::lock_guard<std::mutex> lk{sig_->mu};
        return force_page_not_before_ms_;
    }

    /// TEST-ONLY: arm a ONE-SHOT throw in loop()'s own tail - the un-firewalled arithmetic and
    /// the refill re-arm's rt_.lifecycle_headroom() call (std::mutex::lock can throw
    /// std::system_error), which sit OUTSIDE every inner firewall. Nothing in production can
    /// make that tail throw, so the thread lambda's top-level catch and its
    /// journal_maint_exceptions_ increment are otherwise unexercised (flip item 13). The seam
    /// fires exactly once and kills this one-shot worker, so it is a boolean, not a countdown -
    /// a second cycle can never consume a second throw. Relaxed atomic, written before start()
    /// (thread creation is the happens-before edge), read only on the worker thread; no lock,
    /// no mtx_ contact. No production caller.
    void inject_loop_tail_throw_for_test() noexcept {
        inject_loop_tail_throw_.store(true, std::memory_order_relaxed);
    }

    /// Deterministic test seam (also the worker thread's own loop body): run the
    /// maintenance passes named by `ops` synchronously on the caller's thread. Holds no
    /// timer state of its own, so unlike a cadence-owning variant it is safe to call
    /// from any thread. A no-op with no journal. Does NOT firewall exceptions - loop()
    /// does.
    GuardianMaintenanceResult maintenance_once(GuardianMaintenanceOps ops);

    /// Cumulative count of drain passes that threw and were firewalled by loop().
    /// A nonzero value means the drain path hit an exception (bad_alloc under memory
    /// pressure); surfaced via the heartbeat by item 9. Lock-free.
    [[nodiscard]] std::uint64_t drain_exception_count() const noexcept {
        return drain_exceptions_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of journal-maintenance passes that threw and were firewalled
    /// by loop(). Surfaces as `yuzu.guardian_journal_maint_exceptions` alongside the
    /// heartbeat's retry-persist - that tag is JOURNAL work only. Delivery throws are
    /// counted separately (drain_exception_count) and emitted as
    /// `yuzu.guardian_drain_exceptions`: a retention failure and a delivery failure need
    /// different operator responses, so they are deliberately not one number. Lock-free.
    [[nodiscard]] std::uint64_t journal_maint_exception_count() const noexcept {
        return journal_maint_exceptions_.load(std::memory_order_relaxed);
    }

    /// steady_clock ms of the last PAGE maintenance pass that made REPLAY PROGRESS or positively
    /// established there was none, seeded non-zero at start() (flip item 6 / item 14). 0 means
    /// start() has not run - the reader treats that as "no worker", not as an age. The cadence
    /// locals in loop() advance even when a pass throws (deliberate min-GAP pacing); this stamp
    /// advances only on a pass that did not throw, was not stop-aborted, AND either PLACED records
    /// (records_paged > 0 - demonstrable progress, so a stray same-pass read failure does not make
    /// it stale) or cleanly established there was nothing to page (not deferred_no_token, not
    /// sent_scan_failed, and not read_failed - the candidate scan, a candidate value read, or the
    /// boot-prune barrier's scan failing). So a dead thread, a permanently-throwing pass, a
    /// permanently token-starved worker, or one whose reads permanently fail (INCLUDING a
    /// journal-read failure from boot that keeps the boot-prune barrier from latching) all read as
    /// an ever-growing age on the heartbeat. This CLOSES the former UP-4/UP-11 blind spot (#2452):
    /// a deferred or read-failed pass used to stamp "fresh" here while zero replay happened, so the
    /// gauge is now a replay-progress-or-verified-idle signal, not merely a loop-liveness one. Read
    /// failures also keep their own counter (page_read_failures), except the boot-barrier case
    /// which is counted on prune_failures. Lock-free.
    [[nodiscard]] std::uint64_t last_page_success_steady_ms() const noexcept {
        return last_page_success_steady_ms_.load(std::memory_order_relaxed);
    }
    /// PRUNE sibling of last_page_success_steady_ms() - separate because the two passes run
    /// on different cadences (30 s page / 120 s prune) and stall independently. Advances only on a
    /// prune that genuinely RAN retention: it did not throw, a stop did not abort it, and it applied
    /// the delete OR verified nothing was eligible (JournalPruneStats::progress_or_verified, the
    /// prune-side mirror of the page stamp's positive flag). A prune whose scan fails, whose DELETE
    /// fails, or that a stop aborts before the delete returns without throwing, so gating on "did
    /// not throw" (or on scan-only read_ok) would read a stalled retention loop as fresh (#2452
    /// Gate 8, closing UP-7 delete-fail + UP8-3 stop-abort). A forward-clock-jump wipe still advances
    /// it (the delete DID succeed - the L5 clock-guard #2360/#2361 owns that, not this gauge).
    [[nodiscard]] std::uint64_t last_prune_success_steady_ms() const noexcept {
        return last_prune_success_steady_ms_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: whether start() actually ran (spawning the thread) — the observable for
    /// GuardianEngine::wire_spark_engine's prefer_spark_ start gate (#2238), which otherwise
    /// has none. Reads started_ under sig_->mu. No production caller.
    [[nodiscard]] bool started_for_test() const {
        std::lock_guard<std::mutex> lk{sig_->mu};
        return started_;
    }

    /// For GuardianEngine::active_io_workers() (#2233 item 4) - the orphan-exit
    /// contract's sole source of truth (hard_exit.hpp). MUST be summed in there
    /// alongside the state-reader and arm/disarm executors; see
    /// guardian_outbox_send_executor.hpp's header comment.
    [[nodiscard]] std::size_t active_send_workers() const {
        return lifecycle_send_exec_.active_worker_count() + compliance_send_exec_.active_worker_count();
    }

    /// #3953 item 1: fleet sum of both lanes' reclaimed-orphan thrown-exception counts.
    [[nodiscard]] std::uint64_t send_orphan_exception_count() const {
        return lifecycle_send_exec_.orphan_exception_count() + compliance_send_exec_.orphan_exception_count();
    }

    /// #3953 item 2: fleet sum of both lanes' send-stall counts.
    [[nodiscard]] std::uint64_t send_stall_count() const {
        return lifecycle_send_exec_.send_stall_count() + compliance_send_exec_.send_stall_count();
    }

    /// Test-only forwarder to the private wrapped_send() (#3953 item 6) - lets a test
    /// drive a single send attempt directly, on the test's own thread, without
    /// start()ing the worker thread. No production caller.
    [[nodiscard]] SendResult wrapped_send_for_test(const OutboxEntry& entry) {
        return wrapped_send(entry);
    }

    /// Test-only synchronization seam - see the call site in stop() for what race it
    /// exists to make deterministic (#3953 item 6). Production callers never set this.
    void set_stop_race_hook_for_test(std::function<void()> hook) {
        stop_race_hook_for_test_ = std::move(hook);
    }

    /// Test-only synchronization seam - see the call site in stop() (between the two
    /// lane executors' own stop() calls) for the tolerated admission window it pins
    /// (governance Gate 4 unhappy-path UP-4). Fire-once by construction (moved out and
    /// invoked, see stop()) - both lane stop() calls are unconditional, not gated on
    /// first_stop, so a second/idempotent stop() call must not re-fire this against an
    /// already-stopped lane. Production callers never set this.
    void set_between_lane_stops_hook_for_test(std::function<void()> hook) {
        between_lane_stops_hook_for_test_ = std::move(hook);
    }

private:
    void loop();
    /// The SendFn actually threaded through rt_.drain_bounded(): bounces each send
    /// through a per-LANE GuardianOutboxSendExecutor so the worker thread never blocks
    /// on the real, injected `send_` for longer than kGuardianSendOfferWait (#2233
    /// item 4). TWO executors, not one: drain_bounded() calls this once for
    /// lifecycle_log_ and once for outbox_ (compliance+health) per pass
    /// (guardian_spark_runtime.cpp), and a SHARED single-flight slot across both lanes
    /// would let a slow-but-succeeding lifecycle send silently starve compliance
    /// delivery every pass - the compliance send would never even be INVOKED, hitting
    /// the mismatch-orphan branch instead (governance Gate 4 unhappy-path finding
    /// UP-1, derived BLOCKING: I5(b) unavailability on a path shared with an audit/
    /// detection operation). This reintroduces the fairness the existing
    /// guaranteed_attempts/compliance-reserve machinery in drain_bounded() already
    /// protects, WITHOUT that machinery ever seeing it happen, since Retain here never
    /// reaches drain_log_unlocked's own "did we actually try" accounting. Routed by
    /// OutboxEntry::domain: Lifecycle is the only domain in lifecycle_log_
    /// (guardian_outbox.hpp); Compliance/Health share outbox_ and therefore share the
    /// second lane, matching drain_bounded()'s own two-call structure exactly. The two
    /// lanes' detached sends CAN contend on agent.cpp's stream_write_mu_ if both are
    /// in flight at once - that is the SAME pre-existing, already-disclaimed
    /// contention this whole class's header names ("NOT a fix for stream_write_mu_
    /// contention"), now on two detached threads instead of one; it never touches the
    /// worker's own thread. The same two-executor split also makes a same-pass
    /// cross-lane WIRE ORDERING residual reachable (#3953 item 5 / #3972) - see
    /// GuardianSparkRuntime::drain_bounded()'s own note for the mechanism.
    [[nodiscard]] SendResult wrapped_send(const OutboxEntry& entry) {
        // Enumerator-exhaustive, no `default` (#3953 item 4): a new OutboxDomain value
        // added without updating this routing is at least a silent fall-through into
        // `compliance_send_exec_` (the pre-switch default), never something crash-safe
        // to ignore. On GCC/Clang this also warns via -Wswitch (part of warning_level=3,
        // meson.build) - but this repo builds with werror=false project-wide, so that
        // warning does not fail CI, and MSVC's equivalent (C4062) is off at this
        // project's current warning level (no /w14062 or /Wall set anywhere) - governance
        // Gate 3 cpp-expert finding: do not assume uniform compiler protection here.
        GuardianOutboxSendExecutor* exec = &compliance_send_exec_;
        switch (entry.domain) {
        case OutboxDomain::Lifecycle:
            exec = &lifecycle_send_exec_;
            break;
        case OutboxDomain::Compliance:
        case OutboxDomain::Health:
            break;
        }
        return exec->offer(entry, send_, kGuardianSendOfferWait).value_or(SendResult::Retain);
    }
    /// True once stop() has been requested. Lock-free and noexcept BY DESIGN: this is
    /// the one check loop() makes outside a try, and taking a mutex here would let
    /// std::system_error escape the bare worker thread and terminate the agent (the
    /// #2037 class of defect).
    [[nodiscard]] bool stop_requested() const noexcept {
        return sig_->stopping.load(std::memory_order_acquire);
    }
    /// One drain pass under the configured count / wall-clock / stop-predicate limits.
    /// `truncated` means entries remain and the loop should re-drain WITHOUT waiting.
    [[nodiscard]] GuardianSparkRuntime::DrainOutcome drain_bounded();

    /// Heap sync state shared by the worker thread AND the waker (a
    /// std::function copied into the runtime) - see the class doc for why a
    /// copy invoked after this worker is destroyed is still safe.
    struct Signal {
        std::mutex mu;
        std::condition_variable cv;
        /// Write-once-true. ATOMIC so stop_requested() needs no lock (see above); still
        /// STORED under `mu` so a waiter inside wait_for cannot miss the transition.
        std::atomic<bool> stopping{false};
        std::uint64_t gen{0}; ///< bumped by the waker; the loop waits on a change
    };

    GuardianSparkRuntime& rt_;
    SendFn send_;
    /// Detaches the actual send call from this worker's own thread (#2233 item 4).
    /// TWO instances, one per drain lane - see wrapped_send()'s doc comment for why a
    /// single shared slot silently starves one lane behind the other. See
    /// guardian_outbox_send_executor.hpp for the per-instance contract.
    GuardianOutboxSendExecutor lifecycle_send_exec_;
    GuardianOutboxSendExecutor compliance_send_exec_;
    std::uint64_t periodic_bound_ms_;
    GuardianMaintenanceConfig maint_;
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::thread thread_;
    std::function<void()> stop_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::function<void()> between_lane_stops_hook_for_test_; ///< test seam; null = no-op, fire-once
    std::atomic<std::uint64_t> drain_exceptions_{0}; ///< firewalled drain-pass throws (item 4 hardening)
    std::atomic<std::uint64_t> journal_maint_exceptions_{0}; ///< firewalled maintenance-pass throws (C0)
    /// Success stamps for the staleness gauges (item 6). Seeded at start() (clamped >= 1 so
    /// 0 stays the unambiguous "never started" sentinel even right after boot, where
    /// steady_clock's epoch-relative reading can itself be ~0), stored at the loop's
    /// maintenance call sites only when the firewalled pass did not throw.
    std::atomic<std::uint64_t> last_page_success_steady_ms_{0};
    std::atomic<std::uint64_t> last_prune_success_steady_ms_{0};
    /// Set by notify(), cleared by the loop: force ONE page irrespective of cadence.
    /// Seeded TRUE so the first cycle replays the journal at boot without waiting out
    /// kDefaultPageInterval.
    std::atomic<bool> force_page_{true};
    /// TEST-ONLY one-shot: make loop()'s tail throw once (item 13). Consumed by exchange, so it
    /// arms a single throw. Default false = inert in production (one relaxed load per cycle).
    std::atomic<bool> inject_loop_tail_throw_{false};
    /// Earliest steady-clock ms at which a pending forced page may be consumed (item 12).
    /// 0 = no deferral. Written under sig_->mu (by notify() and the loop) so the loop can
    /// derive its wait deadline from it without a second synchronisation point.
    std::int64_t force_page_not_before_ms_{0};
    /// Per-agent jitter source. Touched only under sig_->mu, or on the worker thread before
    /// start() publishes it.
    std::mt19937 jitter_rng_;
};


} // namespace yuzu::agent
