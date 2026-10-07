#pragma once

/**
 * guardian_baseline_persister.hpp -- the ENGINE-owned durable side of Spark's baseline-on-arm
 * capture (#4045, the Spark half of the #4021 baseline store).
 *
 * WHY A SEPARATE OBJECT: GuardianSparkRuntime is the detach-survival object and NEVER touches a
 * KvStore (guardian_spark_runtime.hpp, file header): a queued SparkEngine handler can run after
 * GuardianEngine is gone. So the runtime only STAGES the capture edge (a rule_id -> {path, hash}
 * map under its registry_mu_, no I/O) and this class, owned by the engine and borrowing its
 * `kv_`, drains that staging into the #4021 `baseline:<rule_id>` record through the existing
 * guardian_persist_baseline overwrite guard. Same shape as GuardianLifecycleJournal.
 *
 * SNAPSHOT AND ERASE BY IDENTITY: a pass COPIES the staged captures (snapshot), writes them in
 * order, and then erases from staging only the ones whose write returned Written or Refused,
 * and only if the entry is still identical (rule_id, path, hash); a newer capture or a
 * retarget for the same rule_id stays staged. Nothing is ever "out" of staging, so a throw
 * anywhere in a pass cannot lose a capture: a Failed tuple simply stays staged for the next
 * pass, and the persist-before-seed handoff in attach_core keeps seeing it until it is durable.
 *
 * BOUNDED PASSES: a pass stops at the FIRST Failed write and leaves the rest staged untried.
 * Under a sustained SQLite BUSY each failing write costs one busy timeout (5 s), so a pass, and
 * therefore every wait on persist_mu_ below, is bounded by about ONE busy timeout instead of
 * one per staged capture. A failed pass is counted ONCE. The worker path additionally backs
 * off (Trigger::Worker): after a failed pass it does not try again for 5 s, doubling to 60 s,
 * reset by any pass that has no failure, so a flapping rule's enqueue wakes cannot drive a
 * retry storm. apply_rules and stop() (Trigger::Forced) attempt regardless of the backoff, but
 * are bounded by the first-failure abort.
 *
 * OWNERSHIP: `kv_` is BORROWED and may be null (nothing is then persisted and nothing is
 * erased, so a staged capture is not lost to a missing store; each pass that finds one staged
 * counts it in no_store_pending() and the first logs once). The KvStore outlives the engine
 * (agent.cpp declares kv_store_ before guardian_), the same proof guard_file.hpp relies on.
 * That branch is unreachable in production today: both arm paths dereference `*kv_` for the
 * seed read before anything can be staged. The runtime is passed per call and never retained;
 * only its drop counter is shared (below).
 *
 * LOCKING: `persist_mu_` is a LEAF that serialises concurrent drainers' write loops (worker
 * vs apply_rules vs stop). The engine ALSO holds it (hold_seed_fence()) across a
 * baseline-on-arm rule's whole seed step (the KV seed read through attach_rule). That fence is
 * REQUIRED, not an optimisation: an entry leaves staging after its write (write W, then erase
 * E), so without the fence a worker pass could run entirely between the engine's KV seed read
 * (empty, before W) and attach_core's staged read (empty, after E), and the replacement would
 * capture drifted content as its live baseline. With it, no worker pass overlaps the seed
 * read through the attach: at the KV read every capture is durable or still staged, and
 * attach_core reads staging next. Because passes are first-failure bounded and the worker
 * backs off, at most ONE pass is ever pending behind the fence (about one busy timeout, not
 * one per staged capture). Order: engine mtx_ -> persist_mu_ -> registry_mu_ (snapshot/erase/
 * attach) and persist_mu_ -> KvStore::mu_; the worker takes persist_mu_ -> registry_mu_ and
 * never mtx_ (WorkerHostileMutex). persist_mu_ is never taken under any runtime lock.
 *
 * HEARTBEAT: failure_signals() is lock-free over atomics (no mtx_), so the heartbeat thread
 * cannot be blocked by a long apply_rules. The engine reads this object through an atomic
 * pointer published at wire time; the object lives until the engine's destructor, which runs
 * after the heartbeat thread is gone and after the drain worker is joined (agent.cpp declares
 * kv_store_ before guardian_). The runtime's drop counter is held by shared_ptr, so it stays
 * valid regardless of runtime teardown order.
 *
 * CALLERS of persist_staged (exactly three, and NEVER only from a connection-gated thread, or
 * a pre-network boot re-arm would lose its capture on a crash): GuardianEngine::apply_rules
 * under mtx_ before any teardown or re-arm (so the common case is already durable when the
 * seed is read), GuardianEngine::stop() after the worker join, and the drain worker's loop.
 * Not journal_maintenance_tick: it runs only on a live connection. The drain is NOT what
 * orders an in-flight evaluation's capture against a replacement's seed (one can stage after
 * any drain); the fence above and attach_core's staged read do.
 *
 * LATENCY: persistence is wake-driven. A capture's compliant-edge enqueue normally wakes the
 * worker, which persists it ahead of its outbox drain (typically within milliseconds), but a
 * capture that produced no enqueue waits for the next wake or the 5 s worker backstop, and
 * after a failed pass the worker waits out its backoff. apply_rules and stop() drain
 * regardless. There is no latency bound while the KV write keeps failing.
 *
 * FAILURE POSTURE: a failed write (kv->set false or a throw) is DELIBERATE fail-OPEN: the rule
 * keeps running on its in-memory baseline, but never silent: the tuple stays staged for the
 * next pass, persist_failures() counts it, the error is logged, and the heartbeat carries it.
 * A refusal by the #4021 overwrite guard is not a failure (first capture wins): it is erased
 * from staging, counted separately in persist_refusals() (NOT in failure_signals()), and the
 * guard's own warning is logged. Remaining loss channels (all counted in failure_signals()):
 * an allocation failure while staging, a retarget that replaced a still-unpersisted capture,
 * a capture staged with no store, and a throw firewalled around a pass.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

class YUZU_EXPORT GuardianBaselinePersister {
public:
    using Clock = std::chrono::steady_clock;

    /// Who is draining. Forced (apply_rules, stop) ignores the retry backoff; Worker honours it.
    enum class Trigger { Forced, Worker };

    /// `kv` is BORROWED (may be null) and must outlive this object. `staging_drops` is the
    /// runtime's drop counter (GuardianSparkRuntime::staged_baseline_drops_source()); it is
    /// folded into failure_signals() and may be null (nothing to fold).
    explicit GuardianBaselinePersister(
        KvStore* kv, std::shared_ptr<const std::atomic<std::uint64_t>> staging_drops = {}) noexcept
        : kv_(kv), staging_drops_(std::move(staging_drops)) {}
    GuardianBaselinePersister(const GuardianBaselinePersister&) = delete;
    GuardianBaselinePersister& operator=(const GuardianBaselinePersister&) = delete;

    struct Outcome {
        std::size_t written{0};
        std::size_t refused{0};
        std::size_t failed{0};        ///< 0 or 1: a pass stops at its first failure
        bool backoff_deferred{false}; ///< a Worker pass skipped because a retry is not yet due
    };

    /// Snapshot the runtime's staged captures, persist them in order until the first failure,
    /// erase the persisted ones from staging by identity. Thread-safe (serialised on
    /// persist_mu_); callable from an mtx_ holder or the joined drain worker. A per-tuple
    /// exception counts as Failed; a throw out of snapshot/erase itself (allocation or lock)
    /// propagates to the caller's firewall, and loses nothing (see the class comment).
    Outcome persist_staged(GuardianSparkRuntime& rt, Trigger trigger = Trigger::Forced);

    /// Cumulative count of failed persist attempts: one per failed PASS (a pass stops at its
    /// first failure), so a tuple that keeps failing adds one per attempt.
    [[nodiscard]] std::uint64_t persist_failures() const noexcept {
        return persist_failures_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of passes that found a capture staged but had no store to write it to
    /// (kv_ null). The capture stays staged; never silent.
    [[nodiscard]] std::uint64_t no_store_pending() const noexcept {
        return no_store_pending_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of captures the #4021 overwrite guard refused to write because a
    /// same-target record already existed (first capture wins). NOT a failure and NOT part of
    /// failure_signals(): it is the guard working. It is the one signal that the live rule's
    /// baseline may differ from the durable record (a seed read failed at arm while a record
    /// existed): until the next re-arm re-seeds, the rule is judged against the re-captured
    /// content, not the record.
    [[nodiscard]] std::uint64_t persist_refusals() const noexcept {
        return persist_refusals_.load(std::memory_order_relaxed);
    }

    /// A pass threw out of snapshot/erase (allocation, lock) and a caller's firewall caught it.
    /// Both firewalls (GuardianEngine::persist_staged_baselines_locked and the drain worker's
    /// loop) call this. Nothing was lost (see the class comment); the count is the signal.
    void note_firewalled_exception() noexcept {
        firewalled_exceptions_.fetch_add(1, std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t firewalled_exceptions() const noexcept {
        return firewalled_exceptions_.load(std::memory_order_relaxed);
    }

    /// The heartbeat aggregate (`yuzu.guardian_baseline_persist_failures`): failed persist
    /// passes + captures dropped from staging + passes that found a capture and no store +
    /// firewalled throws. Cumulative since boot, so a flat non-zero value does not by itself
    /// say whether anything is still failing. Lock-free (atomics only): safe from the
    /// heartbeat thread while apply_rules holds the engine mtx_.
    [[nodiscard]] std::uint64_t failure_signals() const noexcept {
        return persist_failures() + no_store_pending() + firewalled_exceptions() +
               (staging_drops_ ? staging_drops_->load(std::memory_order_relaxed) : 0);
    }

    /// The persist-before-seed fence: hold persist_mu_ for the lifetime of the returned lock.
    /// Blocks until any in-flight persist_staged pass has finished (about one busy timeout at
    /// worst, see the class comment), and keeps the next one out. REQUIRED for correctness:
    /// see LOCKING above. Caller: GuardianEngine::reconcile_rule_locked (mtx_ held), around a
    /// baseline-on-arm rule's seed read and attach. Must never be taken under a runtime lock.
    [[nodiscard]] std::unique_lock<std::mutex> hold_seed_fence() {
        return std::unique_lock<std::mutex>{persist_mu_};
    }

    /// TEST-ONLY: how many times the one-time "no store" error was logged (0 or 1). Read off
    /// the object because the agent core is a separate image from the test binary, so a
    /// captured spdlog logger would not see it. No production caller.
    [[nodiscard]] std::uint32_t no_store_logs_for_test() const noexcept {
        return no_store_logs_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: true iff persist_mu_ is currently held. Probes with try_lock, so it must be
    /// called from a thread that does NOT itself hold the fence. No production caller.
    [[nodiscard]] bool seed_fence_held_for_test() {
        std::unique_lock<std::mutex> lk{persist_mu_, std::try_to_lock};
        return !lk.owns_lock();
    }

    /// TEST-ONLY: how many persist_staged calls are BLOCKED right now because persist_mu_ was
    /// held when they tried it (try_lock failed first). Lets a test observe "this pass is
    /// waiting on the seed fence" without a sleep. No production caller.
    [[nodiscard]] std::uint32_t lock_waiters_for_test() const noexcept {
        return lock_waiters_.load(std::memory_order_relaxed);
    }
    /// TEST-ONLY: replace the backoff clock (default steady_clock::now). Set before any pass
    /// runs; not synchronised. No production caller.
    void set_clock_for_test(std::function<Clock::time_point()> clock) { clock_ = std::move(clock); }
    /// TEST-ONLY: replace the backoff bounds (default 5 s initial, 60 s max). Same contract.
    void set_backoff_for_test(Clock::duration initial, Clock::duration max) noexcept {
        backoff_initial_ = initial;
        backoff_max_ = max;
    }
    /// TEST-ONLY: the current retry-backoff width (zero = no failed pass outstanding).
    [[nodiscard]] Clock::duration backoff_for_test() {
        std::lock_guard<std::mutex> lk{persist_mu_};
        return backoff_;
    }
    /// TEST-ONLY: runs inside a pass, with persist_mu_ held, right after the snapshot is taken
    /// and before the first write: the deterministic stand-in for "a worker pass is mid-flight".
    /// Must not re-enter the persister. Set before use (not synchronised). No production caller.
    void set_post_snapshot_hook_for_test(std::function<void()> hook) {
        post_snapshot_hook_ = std::move(hook);
    }

private:
    [[nodiscard]] Clock::time_point now() const { return clock_ ? clock_() : Clock::now(); }

    KvStore* kv_;
    const std::shared_ptr<const std::atomic<std::uint64_t>> staging_drops_; ///< runtime drops
    std::mutex persist_mu_; ///< LEAF, see LOCKING above
    std::atomic<std::uint64_t> persist_failures_{0};
    std::atomic<std::uint64_t> no_store_pending_{0};
    std::atomic<std::uint64_t> persist_refusals_{0};
    std::atomic<std::uint64_t> firewalled_exceptions_{0};
    std::atomic<std::uint32_t> no_store_logs_{0}; ///< 0 -> 1 latches the one-time "no store" log
    std::atomic<std::uint32_t> lock_waiters_{0};  ///< TEST-ONLY observation, see its accessor
    /// Retry backoff (Worker passes only). `next_attempt_rep_` is the steady_clock rep before
    /// which a Worker pass is skipped (0 = none); read lock-free, written under persist_mu_.
    std::atomic<Clock::rep> next_attempt_rep_{0};
    Clock::duration backoff_{}; ///< persist_mu_-guarded
    Clock::duration backoff_initial_{std::chrono::seconds{5}};
    Clock::duration backoff_max_{std::chrono::seconds{60}};
    std::function<Clock::time_point()> clock_;
    std::function<void()> post_snapshot_hook_;
};

} // namespace yuzu::agent
