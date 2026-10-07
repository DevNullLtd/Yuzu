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
 * BOUNDED PASSES: every pass runs under a BUDGET (kBaselinePassBudget, kBaselineStopBudget
 * below): at most `max_tuples` writes, at most `max_failures` failed writes and at most
 * `max_wall` of wall clock between tuples; whatever it did not attempt stays staged. A pass is
 * therefore bounded by its wall budget plus ONE in-flight write, NOT by "one busy timeout": the
 * wall is checked between tuples, so the last write may start just before it expires and run
 * as long as the store takes (one KvStore busy timeout, 5 s, when the store is BUSY). The
 * failure budget lets a few per-key faults sit at the head without blocking the tail, and a
 * ROTATING START CURSOR (the last attempted rule_id, kept across passes) makes the next pass
 * begin after it, so a tuple that fails every time cannot starve the ones sorted behind it. A
 * pass that ends because it ran out of tuples or wall with NO failure is not a failure: it does
 * not back off and reports `budget_exhausted` so the worker runs again at once. A pass with a
 * failure is counted ONCE (however many of its writes failed) and the worker path backs off
 * (Trigger::Worker): after a failed pass it does not try again for 5 s, doubling to 60 s,
 * reset by any pass that has no failure, so a flapping rule's enqueue wakes cannot drive a
 * retry storm. apply_rules (Trigger::Forced) attempts regardless of the backoff. stop()
 * (Trigger::Stop) attempts regardless too, but with the tighter stop budget, and SKIPS its pass
 * when the immediately preceding pass failed SLOWLY (at least the stop wall budget) without
 * persisting anything: a BUSY store burns a busy timeout per write, which stop()'s shared
 * shutdown deadline cannot afford to repeat, whereas a fast failure costs nothing to retry.
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
 * attach_core reads staging next. Because passes are budgeted (above) and the worker backs
 * off, at most ONE pass is ever pending behind the fence: its wall budget plus one in-flight
 * write, however many captures are staged. Order: engine mtx_ -> persist_mu_ -> registry_mu_
 * (snapshot/erase/attach) and persist_mu_ -> KvStore::mu_; the worker takes persist_mu_ ->
 * registry_mu_ and never mtx_ (WorkerHostileMutex). persist_mu_ is never taken under any
 * runtime lock.
 *
 * HEARTBEAT: failure_signals() takes no lock (atomics only, no mtx_), so reading THIS tag
 * cannot be blocked by a long apply_rules. That is a property of this accessor only: the same
 * heartbeat tick also calls GuardianEngine getters that do take mtx_ (policy_generation(),
 * journal_stats(), ...), so the tick as a whole can still wait. The engine reads this object through an atomic
 * pointer published at wire time; the object lives until the engine's destructor, which runs
 * after the heartbeat thread is gone and after the drain worker is joined (agent.cpp declares
 * kv_store_ before guardian_). The runtime's drop counter is held by shared_ptr, so it stays
 * valid regardless of runtime teardown order.
 *
 * CALLERS of persist_staged (exactly three, and NEVER only from a connection-gated thread, or
 * a pre-network boot re-arm would lose its capture on a crash): GuardianEngine::apply_rules
 * under mtx_ before any teardown or re-arm (so the common case is already durable when the
 * seed is read; Trigger::Forced), GuardianEngine::stop() after the worker join
 * (Trigger::Stop), and the drain worker's loop (Trigger::Worker). A budget-exhausted
 * apply_rules or stop() pass leaves the rest staged: attach_core still inherits it for a
 * re-armed rule and the worker persists it on its next cycle (an apply_rules leftover waits
 * for the worker's next wake or its 5 s backstop; a stop() leftover is lost to this process,
 * and the engine logs that the flush was incomplete).
 * Not journal_maintenance_tick: it runs only on a live connection. The drain is NOT what
 * orders an in-flight evaluation's capture against a replacement's seed (one can stage after
 * any drain); the fence above and attach_core's staged read do.
 *
 * LATENCY: persistence is wake-driven. A capture's compliant-edge enqueue normally wakes the
 * worker, which persists it ahead of its outbox drain (typically within milliseconds), but a
 * capture that produced no enqueue waits for the next wake or the 5 s worker backstop, and
 * after a failed pass the worker waits out its backoff. A worker pass that ran out of budget
 * with captures still staged re-runs the worker's cycle immediately. apply_rules and stop()
 * drain regardless of the backoff. There is no latency bound while the KV write keeps failing.
 *
 * FAILURE POSTURE: a failed write (kv->set false or a throw) is DELIBERATE fail-OPEN: the rule
 * keeps running on its in-memory baseline, but never silent: the tuple stays staged for the
 * next pass, persist_failures() counts the failed pass, the error is logged, and the heartbeat
 * carries it. A refusal by the #4021 overwrite guard is not a failure (first capture wins): it
 * is erased from staging, counted separately in persist_refusals() (NOT in failure_signals()),
 * and the guard's own warning is logged. Other channels counted in failure_signals(): an
 * allocation failure while staging (the runtime then does not commit that capture's baseline,
 * so the rule re-captures at its next evaluation), a retarget that replaced a still-unpersisted
 * capture (that capture is lost), a capture staged with no store, and a throw firewalled
 * around a pass.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

/// The bound on ONE persist pass (see BOUNDED PASSES). A pass always attempts at least one
/// tuple, then stops as soon as any limit is reached; the rest stays staged.
struct GuardianBaselinePassBudget {
    std::size_t max_tuples;             ///< writes attempted (Written, Refused or Failed)
    std::size_t max_failures;           ///< failed writes before the pass gives up
    std::chrono::milliseconds max_wall; ///< wall clock, checked BETWEEN tuples
};

/// Worker and apply_rules passes.
///  - 64 tuples: a healthy write measured ~2 ms (Gate 8), so a full pass holds persist_mu_ for
///    about 0.13 s; a larger rule set simply drains over several back-to-back passes.
///  - 3 failures: tolerates a couple of per-key faults at the head of the order; a GLOBAL fault
///    (BUSY, full disk, read-only) still ends after one write, because its 5 s busy timeout
///    alone exceeds the wall budget.
///  - 2000 ms: apply_rules already pays one synchronous KV write per rule under mtx_
///    (put_rule_locked), so a pass capped at 2 s of wall adds a stall of the same order, not an
///    unbounded one.
inline constexpr GuardianBaselinePassBudget kBaselinePassBudget{64, 3,
                                                                std::chrono::milliseconds{2000}};

/// stop()'s final flush. stop() shares ONE 20 s ShutdownDeadlineGuard with the joined worker
/// pass, the legacy-sink loss-ledger write and the journal flush, each of which can spend a
/// 5 s busy timeout, so this pass gets ONE failure and 1 s of wall (the same 64-tuple bound),
/// and is skipped outright after a slow failed pass (see BOUNDED PASSES).
inline constexpr GuardianBaselinePassBudget kBaselineStopBudget{64, 1,
                                                                std::chrono::milliseconds{1000}};

class YUZU_EXPORT GuardianBaselinePersister {
public:
    using Clock = std::chrono::steady_clock;

    /// Who is draining. Worker honours the retry backoff; Forced (apply_rules) and Stop ignore
    /// it. Stop also runs under the tighter kBaselineStopBudget and skips its pass after a
    /// stalled one. persist_staged takes the trigger with no default: a caller must say which.
    enum class Trigger { Forced, Worker, Stop };

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
        std::size_t failed{0};        ///< failed WRITES this pass (0..max_failures); the pass
                                      ///< counts once in persist_failures() however many
        bool backoff_deferred{false}; ///< a Worker pass skipped because a retry is not yet due
        /// The pass stopped on its tuple or wall limit with captures still staged and NO
        /// failure: not a failure (no backoff), and the worker should run again at once.
        bool budget_exhausted{false};
        /// A Stop pass skipped because the preceding pass failed slowly, persisting nothing.
        bool skipped_after_stall{false};
    };

    /// Snapshot the runtime's staged captures, persist them in rotation order under the
    /// trigger's budget, erase the persisted ones from staging by identity. Thread-safe
    /// (serialised on persist_mu_); callable from an mtx_ holder or the joined drain worker.
    /// A per-tuple exception counts as Failed; a throw out of snapshot/erase itself
    /// (allocation or lock) propagates to the caller's firewall, widens the worker backoff,
    /// and loses nothing (see the class comment). `should_stop`, if set, is polled before each
    /// tuple: the drain worker passes its stop flag so a pass in flight when stop() joins it
    /// ends after at most one more write.
    Outcome persist_staged(GuardianSparkRuntime& rt, Trigger trigger,
                           const std::function<bool()>& should_stop = {});

    /// Cumulative count of FAILED PASSES: one per pass that had a failed write, however many
    /// tuples of it failed, so a tuple that keeps failing adds one per attempt-pass.
    [[nodiscard]] std::uint64_t persist_failures() const noexcept {
        return persist_failures_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of passes that found a capture staged but had no store to write it to
    /// (kv_ null). The capture stays staged; never silent.
    [[nodiscard]] std::uint64_t no_store_pending() const noexcept {
        return no_store_pending_.load(std::memory_order_relaxed);
    }

    /// DIAGNOSTIC accessor (no production consumer: the heartbeat does not carry it; the
    /// guard's own warning log is the operator signal). Cumulative count of captures the #4021
    /// overwrite guard refused to write because a same-target record already existed (first
    /// capture wins). NOT a failure and NOT part of failure_signals(): it is the guard working.
    /// It is an UPPER BOUND on "the live baseline differs from the durable record" and has two
    /// causes: (1) a seed read failed at arm while a record existed, so until the next re-arm
    /// re-seeds the rule is judged against the re-captured content, not the record (the record
    /// is intact); (2) a benign duplicate: an erase threw after a successful write, so the next
    /// pass re-wrote the same capture and the guard refused it (live baseline == record).
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
    /// Blocks until any in-flight persist_staged pass has finished (its wall budget plus one
    /// in-flight write at worst, see the class comment), and keeps the next one out. REQUIRED
    /// for correctness:
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
    /// TEST-ONLY: replace the backoff bounds (default 5 s initial, 60 s max). Safe against a
    /// live worker (it takes persist_mu_, which a failing pass holds while it reads them).
    void set_backoff_for_test(Clock::duration initial, Clock::duration max) {
        std::lock_guard<std::mutex> lk{persist_mu_};
        backoff_initial_ = initial;
        backoff_max_ = max;
    }
    /// TEST-ONLY: replace the pass budgets (defaults kBaselinePassBudget / kBaselineStopBudget).
    /// Safe against a live worker (it takes persist_mu_, which a pass holds while it reads them).
    void set_budgets_for_test(GuardianBaselinePassBudget pass, GuardianBaselinePassBudget stop) {
        std::lock_guard<std::mutex> lk{persist_mu_}; // passes read the budgets under this lock
        pass_budget_ = pass;
        stop_budget_ = stop;
    }
    /// TEST-ONLY: runs after EACH tuple's write attempt (inside the pass, persist_mu_ held), so
    /// a test can advance an injected clock per write instead of sleeping. Same contract.
    void set_post_write_hook_for_test(std::function<void()> hook) {
        post_write_hook_ = std::move(hook);
    }
    /// TEST-ONLY: Worker passes skipped by the retry backoff (before or after taking the lock).
    [[nodiscard]] std::uint64_t backoff_deferrals_for_test() const noexcept {
        return backoff_deferrals_.load(std::memory_order_relaxed);
    }
    /// TEST-ONLY: INFO lines emitted for a persisted capture (the log has no cross-image capture).
    [[nodiscard]] std::uint64_t info_logs_for_test() const noexcept {
        return info_logs_.load(std::memory_order_relaxed);
    }
    /// The exact INFO line logged for a persisted capture. Pure and static so a test can pin its
    /// content (rule id through log_id_token only: no path, no hash) without capturing spdlog.
    [[nodiscard]] static std::string persisted_log_line(const std::string& rule_id);
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
    std::atomic<std::uint64_t> backoff_deferrals_{0}; ///< TEST-ONLY, see its accessor
    std::atomic<std::uint64_t> info_logs_{0};         ///< TEST-ONLY, see its accessor
    /// Retry backoff (Worker passes only). `next_attempt_rep_` is the steady_clock rep before
    /// which a Worker pass is skipped (0 = none); read lock-free, written under persist_mu_.
    std::atomic<Clock::rep> next_attempt_rep_{0};
    Clock::duration backoff_{}; ///< persist_mu_-guarded
    Clock::duration backoff_initial_{std::chrono::seconds{5}};
    Clock::duration backoff_max_{std::chrono::seconds{60}};
    /// Widen the retry backoff after a failed pass (persist_mu_ held).
    void note_failed_pass();
    GuardianBaselinePassBudget pass_budget_{kBaselinePassBudget};
    GuardianBaselinePassBudget stop_budget_{kBaselineStopBudget};
    /// Rotating start cursor: the rule_id of the last tuple a pass attempted (persist_mu_-guarded).
    /// The next pass begins at the first staged rule_id AFTER it, wrapping.
    std::string cursor_;
    /// The preceding pass failed slowly and persisted nothing (persist_mu_-guarded): a Stop pass
    /// skips.
    bool stalled_{false};
    std::function<Clock::time_point()> clock_;
    std::function<void()> post_snapshot_hook_;
    std::function<void()> post_write_hook_;
};

} // namespace yuzu::agent
