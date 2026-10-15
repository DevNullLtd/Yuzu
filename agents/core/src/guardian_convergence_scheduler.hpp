#pragma once

/**
 * guardian_convergence_scheduler.hpp - the Guardian spark consumer's convergence
 * driver (ADR-0021 Stage 2 rung 4). Design:
 * docs/spark-stage2-guardian-consumer-design.md.
 *
 * Spark events are the fast path, but they are lossy hints (the queued consumer
 * can drop under a storm, and some initial state never produces an event). So a
 * dropped sole event for a key would leave its drift undetected forever. This
 * scheduler is the backstop: it periodically re-drives GuardianSparkRuntime::
 * evaluate_key(Convergence) for every armed key from CURRENT state, independent
 * of edges, so compliance always re-converges within a bounded age.
 *
 * Shape (Sol's rev-2 note "one convergence thread reintroduces head-of-line
 * blocking"): ONE scheduler owning ONE thread PER TYPE-LANE (file / registry /
 * service) plus a priority lane, so a slow file hash never blocks a fast service
 * reconcile. Lanes carry different cadences (service / registry ~60s, file
 * ~5-15min) with per-lane jitter (fleet-kindness: no synchronised convergence
 * herd). The priority lane services keys that still owe an initial eval; it is
 * CV-woken the moment a rule is attached (set_pending_initial_waker) so a fresh
 * rule learns its compliance promptly instead of waiting a full cadence.
 *
 * M1 item (b), decided entirely runtime-side (this scheduler's sweep is unchanged):
 * a rule that stays Unknown across pending_demote_sweeps convergence passes (or
 * pending_demote_ms elapsed) is DEMOTED off this lane's worklist
 * (keys_with_pending_initial() excludes it) to its normal type lane above - the
 * read flood a stuck-Unknown rule would otherwise cause on THIS 5s lane forever.
 * It keeps converging at the slower cadence (still catches recovery); the
 * runtime's minutes-cadence errored_refresh_ms backstops the resulting slower
 * wire staleness.
 *
 * Every wait is CV-interruptible: stop() wakes all lanes at once rather than
 * blocking a multi-minute sleep on shutdown. Lanes hard-join (they are Guardian-
 * owned, never detached like the SparkEngine consumer); a sweep observes the
 * runtime's stopping flag and commits nothing, so a join waits only for the
 * current bounded read, not a whole cadence, plus the synchronous #4606 T_detect log
 * write that a sweep now performs after its read (guardian_spark_timing.hpp). (A truly
 * hung reader is the
 * blocked-reader shutdown bound the runtime documents; the agent hard-exit is the
 * final backstop.)
 *
 * DEFERRED to rung 5 (where the real readers exist and there is a read cost to
 * meter): size+mtime skip before re-hash, forced periodic full hash, and the
 * file-lane byte token bucket. Against rung 4's fake instant reader there is
 * nothing to budget, so wiring them here would be untested theatre; they live at
 * the file StateReader / runtime boundary.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/spark.hpp> // SparkType

#include "guardian_spark_runtime.hpp"

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <functional>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace yuzu::agent {

class YUZU_EXPORT ConvergenceScheduler {
public:
    struct Config {
        std::uint64_t service_cadence_ms{kGuardianServiceLaneCadenceMs};
        std::uint64_t registry_cadence_ms{kGuardianRegistryLaneCadenceMs};
        std::uint64_t file_cadence_ms{kGuardianFileLaneCadenceMs}; ///< ~10 min (the 5-15 min band)
        std::uint64_t priority_poll_ms{5'000};  ///< pending-initial backstop poll (also CV-woken)
        std::uint32_t jitter_pct{kGuardianLaneJitterPct}; ///< +/- this % of the cadence, per lane
        std::uint64_t rng_seed{0x5eed};          ///< deterministic jitter source (per-lane offset)
    };

    explicit ConvergenceScheduler(GuardianSparkRuntime& rt);
    ConvergenceScheduler(GuardianSparkRuntime& rt, Config cfg);
    ~ConvergenceScheduler();
    ConvergenceScheduler(const ConvergenceScheduler&) = delete;
    ConvergenceScheduler& operator=(const ConvergenceScheduler&) = delete;

    /// Launch the lane threads and install the pending-initial waker. Single-shot.
    void start();
    /// Clear the waker, wake every lane, and join. Idempotent; never blocks a full
    /// cadence.
    void stop();

    /// Deterministic test seams (also the lane threads' bodies): run ONE sweep
    /// synchronously on the caller's thread.
    void sweep_lane(SparkType type);
    void sweep_pending_initial();
    /// #2818 poll backstop: pass-through to GuardianSparkRuntime::revalidate_
    /// subscriptions() (also what priority_loop's own tick calls). Public and
    /// synchronous for the same reason as the two above - a test drives one pass
    /// deterministically rather than waiting on the ~5s priority lane's own cadence.
    void revalidate_subscriptions();
    /// up-5 (#4221, rung 9c PR-5b): pass-through to GuardianSparkRuntime::
    /// redrive_retained_disarms() (also what priority_loop's own elapsed-time-gated
    /// tick calls, see priority_loop's own doc comment). Public and synchronous,
    /// same reason as revalidate_subscriptions() above - deterministic single-pass
    /// test coverage independent of the lane's own time-gate.
    void redrive_retained_disarms();
    /// Deterministic test seam (also lane_loop's own wait-duration source, #3531):
    /// apply cfg_'s jitter_pct to base_ms using the given RNG. Single-sourced with
    /// guardian_spark_bridge.hpp's debounce-default computation via
    /// guardian_jitter_span_ms (spark.hpp) - not just the same input constants, the
    /// same arithmetic, so the two can't silently desync.
    [[nodiscard]] std::chrono::milliseconds jittered(std::uint64_t base_ms, std::mt19937& rng) const;

private:
    /// Heap sync state shared by the lane threads AND the pending-initial waker. The
    /// waker (a std::function copied into the runtime) captures shared_ptr<Signal>,
    /// NOT `this`, so a copy invoked after this scheduler is destroyed - e.g. an
    /// attach_rule that copied the waker just before stop() then ran it after the
    /// dtor - touches a still-alive Signal (a harmless no-op: `stopping` is set and no
    /// thread is waiting), never a destroyed mutex/CV. Clearing a std::function slot
    /// alone would not revoke that already-taken copy.
    struct Signal {
        std::mutex mu;
        std::condition_variable cv;
        bool stopping{false};
        std::uint64_t priority_gen{0}; ///< bumped by the waker; the priority lane waits on a change
    };

    void lane_loop(SparkType type, std::uint64_t cadence_ms, std::uint64_t rng_offset);
    void priority_loop();
    /// Run `fn` (one lane sweep) with a catch-all firewall, counting and logging the first
    /// throw. These are BARE threads with no top-level handler, so an escaping bad_alloc
    /// terminates the whole agent daemon - the #2037 class of defect the drain worker was
    /// firewalled against and these lanes, identically exposed, were not (#2298 Gate 4).
    void firewalled_sweep(const std::function<void()>& fn);

    GuardianSparkRuntime& rt_;
    Config cfg_;
    /// Firewalled lane-sweep throws. Lock-free; mirrors the drain worker's counter.
    std::atomic<std::uint64_t> sweep_exceptions_{0};

public:
    /// Cumulative convergence-sweep passes that threw and were firewalled. A counter nobody
    /// can read is not observability: this surfaces as its OWN `yuzu.guardian_sweep_exceptions`
    /// tag via GuardianEngine::journal_stats(). Deliberately not folded into
    /// `yuzu.guardian_journal_maint_exceptions` - a sweep failure means drift DETECTION is
    /// degraded, a journal failure means the AUDIT TRAIL is at risk, and an operator needs to
    /// tell those apart. Lock-free.
    [[nodiscard]] std::uint64_t sweep_exception_count() const noexcept {
        return sweep_exceptions_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: whether start() actually ran (spawning the lane threads) — the
    /// observable for GuardianEngine::wire_spark_engine's prefer_spark_ start gate
    /// (#2238), which otherwise has none. Reads started_ under sig_->mu. No production
    /// caller.
    [[nodiscard]] bool started_for_test() const {
        std::lock_guard<std::mutex> lk{sig_->mu};
        return started_;
    }

private:
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::vector<std::thread> threads_;
    /// up-5 (#4221): priority_loop-thread-only (never touched from any other
    /// thread, so no lock needed) - the next time redrive_retained_disarms() is
    /// allowed to run. Advanced by cfg_.priority_poll_ms after every ATTEMPTED
    /// sweep (including one that throws), never a catch-up burst, so a burst of
    /// priority wake-ups (e.g. several attaches in quick succession bumping
    /// priority_gen) cannot drive redundant full claims_ scans. Default-constructed
    /// (steady_clock's epoch, always in the past) so the very first tick always
    /// redrives once.
    std::chrono::steady_clock::time_point next_redrive_{};
};

} // namespace yuzu::agent
