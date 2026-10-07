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
 * pass that attempted nothing (its stop predicate or a waiter beat its first tuple) changes no
 * bookkeeping at all: not the cursor, not the backoff, not the stall. A pass that ends because
 * it ran out of tuples or wall with NO failure is not a failure: it does not back off and
 * reports `budget_exhausted` so the worker runs again at once. A pass with a failure is counted
 * ONCE (however many of its writes failed) and the worker path backs off (Trigger::Worker):
 * after a failed pass it does not try again for 5 s, doubling to 60 s, reset by any pass that
 * has no failure, so a flapping rule's enqueue wakes cannot drive a retry storm. The backoff is
 * pass-wide, so one tuple that fails every time pins the worker at the 60 s cap: captures
 * staged after that wait up to about 65 s (the cap plus the worker's 5 s backstop) for their
 * write, while apply_rules and stop() are not delayed by it. apply_rules (Trigger::Forced)
 * attempts regardless of the backoff. stop() (Trigger::Stop) attempts regardless too, with the
 * stop budget (no tuple cap: its 1 s wall and its single failure already bound it, and a cap
 * would abandon a healthy store's remaining captures), and SKIPS its pass iff a failed write
 * that took at least the stop wall budget ENDED at or after begin_stop(), i.e. a stall that
 * spent this stop's shared shutdown deadline (a BUSY store burns a busy timeout per write).
 * A stall that ended before stop began spent none of it and says nothing about the store now,
 * so it is not a reason to skip; a fast failure (a dropped table, a read-only file) costs
 * nothing to retry and never counts as a stall.
 *
 * YIELDING: apply_rules takes the seed fence once per baseline-on-arm rule, so a worker pass
 * that kept the lock for its whole budget would make each of those fences wait. A Worker pass
 * therefore (1) defers outright, without taking the lock, while an apply_rules is in flight
 * (ApplyScope), and (2) stops after its current tuple when a fence taker or a Forced/Stop pass
 * is waiting for the lock. Either is Outcome::yielded: not a failure, no backoff, leftovers
 * stay staged (attach_core inherits them for a re-armed rule), and the worker re-checks within
 * kGuardianSendRecheckInterval instead of waiting for a wake. What remains: a fence can still
 * wait for the one write already in flight (a slow store: one write), and apply_rules' own
 * Forced pass is a normal budgeted pass, so it is bounded by its wall budget plus one write.
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
 * attach_core reads staging next. Because passes are budgeted and a Worker pass yields
 * (YIELDING above), the pass a fence waits behind is one in-flight write for a Worker pass and
 * at most the wall budget plus one write for a Forced one, however many captures are staged. Order: engine mtx_ -> persist_mu_ -> registry_mu_
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
 * apply_rules pass leaves the rest staged: attach_core still inherits it for a re-armed rule
 * and the worker persists it on its next cycle (an apply_rules leftover waits for the worker's
 * re-check or its next wake or 5 s backstop). A stop() pass that ends on its wall budget with
 * captures left, on its single failure, or by skipping leaves them lost to this process, and
 * the engine logs that the flush was incomplete.
 * Not journal_maintenance_tick: it runs only on a live connection. The drain is NOT what
 * orders an in-flight evaluation's capture against a replacement's seed (one can stage after
 * any drain); the fence above and attach_core's staged read do.
 *
 * LATENCY: persistence is wake-driven. A capture's compliant-edge enqueue normally wakes the
 * worker, which persists it ahead of its outbox drain (typically within milliseconds), but a
 * capture that produced no enqueue waits for the next wake or the 5 s worker backstop, and
 * after a failed pass the worker waits out its backoff. A worker pass that ran out of budget
 * with captures still staged re-runs the worker's cycle immediately; one that yielded re-checks
 * within 200 ms. apply_rules and stop() drain regardless of the backoff. There is no latency
 * bound while the KV write keeps failing, and one tuple that fails every time keeps the worker
 * at its 60 s backoff cap (see BOUNDED PASSES).
 *
 * FAILURE POSTURE: a failed write (kv->set false or a throw) is DELIBERATE fail-OPEN: the rule
 * keeps running on its in-memory baseline, but never silent: the tuple stays staged for the
 * next pass, persist_failures() counts the failed pass, the error is logged, and the heartbeat
 * carries it. A refusal by the #4021 overwrite guard is not a failure (first capture wins): it
 * is erased from staging, counted separately in persist_refusals() (NOT in failure_signals()),
 * and the guard's own warning is logged. Other channels counted in failure_signals(): each
 * failed attempt to stage a capture (an allocation failure: the runtime keeps the baseline
 * live and retries staging at the generation's later evaluations, so the rule keeps detecting
 * drift against the original capture meanwhile), a retarget that replaced a still-unpersisted
 * capture (that capture is lost), a capture staged with no store, and a throw firewalled
 * around a pass.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <string>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

/// The bound on ONE persist pass (see BOUNDED PASSES). A pass that gets to run attempts at
/// least one tuple (unless its stop predicate or a waiter beats the first), then stops as soon
/// as any limit is reached; the rest stays staged.
struct GuardianBaselinePassBudget {
    std::size_t max_tuples;             ///< writes attempted (Written, Refused or Failed)
    std::size_t max_failures;           ///< failed writes before the pass gives up
    std::chrono::milliseconds max_wall; ///< wall clock, checked BETWEEN tuples
};

/// Worker and apply_rules passes.
///  - 64 tuples: a healthy write is on the order of a millisecond (WAL, synchronous=FULL), so a
///    full pass holds persist_mu_ for well under a second; a larger rule set simply drains over
///    several back-to-back passes.
///  - 3 failures: tolerates a couple of per-key faults at the head of the order. A BUSY store
///    ends a pass after one write, because its 5 s busy timeout alone exceeds the wall budget;
///    a fast global fault (full disk, read-only file) ends it after three cheap failures.
///  - 2000 ms: apply_rules already pays one synchronous KV write per rule under mtx_
///    (put_rule_locked), so a pass capped at 2 s of wall adds a stall of the same order, not an
///    unbounded one.
inline constexpr GuardianBaselinePassBudget kBaselinePassBudget{64, 3,
                                                                std::chrono::milliseconds{2000}};

/// stop()'s final flush. stop() shares ONE 20 s deadline (agent.cpp's kShutdownDeadlineGrace)
/// with the worker join, the legacy-sink loss-ledger write and two journal flushes, each of
/// which can spend a 5 s busy timeout (GuardianEngine::stop() lists the worst case), so this
/// pass gets ONE failure and 1 s of wall between tuples, and is skipped when a slow failure
/// during this stop already spent the deadline (see BOUNDED PASSES). It has NO tuple cap: a
/// healthy store persists every staged capture in a few milliseconds, and a cap would silently
/// abandon the rest.
inline constexpr GuardianBaselinePassBudget kBaselineStopBudget{
    (std::numeric_limits<std::size_t>::max)(), 1, std::chrono::milliseconds{1000}};

class YUZU_EXPORT GuardianBaselinePersister {
public:
    using Clock = std::chrono::steady_clock;

    /// Who is draining. Worker honours the retry backoff and yields (see YIELDING); Forced
    /// (apply_rules) and Stop ignore the backoff. Stop also runs under the tighter
    /// kBaselineStopBudget and skips its pass after a stall during this stop (begin_stop()).
    /// persist_staged takes the trigger with no default: a caller must say which.
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
        /// A Stop pass skipped because a pass during this stop failed slowly (see begin_stop()).
        bool skipped_after_stall{false};
        /// A Worker pass that ended early, or never started, to let a waiter or an in-flight
        /// apply_rules go first (see YIELDING): not a failure, no backoff, nothing lost. The
        /// worker re-checks soon rather than at once.
        bool yielded{false};
    };

    /// Held by GuardianEngine::apply_rules for its whole duration (mtx_ held): Worker passes
    /// then defer (Outcome::yielded) instead of competing for the seed fence once per rule.
    /// Counted, so nested or concurrent scopes compose. Null-safe (no persister, no-op).
    class ApplyScope {
    public:
        explicit ApplyScope(GuardianBaselinePersister* p) noexcept : p_(p) {
            if (p_)
                p_->apply_active_.fetch_add(1, std::memory_order_relaxed);
        }
        ~ApplyScope() {
            if (p_)
                p_->apply_active_.fetch_sub(1, std::memory_order_relaxed);
        }
        ApplyScope(const ApplyScope&) = delete;
        ApplyScope& operator=(const ApplyScope&) = delete;

    private:
        GuardianBaselinePersister* p_;
    };

    /// GuardianEngine::stop() calls this FIRST, before it joins the drain worker. Only the
    /// FIRST call counts (a second stop() from the destructor must not move the mark). A Stop
    /// pass skips only a stall observed at or after this mark: a stall that ended before stop
    /// began has spent none of stop()'s shared shutdown deadline and says nothing about the
    /// store now. A Stop pass with no begin_stop() never skips. Lock-free.
    void begin_stop() noexcept;

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
        std::unique_lock<std::mutex> lk{persist_mu_, std::try_to_lock};
        if (!lk.owns_lock()) {
            WaiterGuard waiter{*this, /*priority=*/true}; // a Worker pass in flight yields to us
            lk.lock();
        }
        return lk;
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
    /// TEST-ONLY: Worker passes that yielded (Outcome::yielded), at any point.
    [[nodiscard]] std::uint64_t yields_for_test() const noexcept {
        return yields_.load(std::memory_order_relaxed);
    }
    /// TEST-ONLY: ApplyScopes currently alive.
    [[nodiscard]] std::uint32_t apply_active_for_test() const noexcept {
        return apply_active_.load(std::memory_order_relaxed);
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
    /// Non-Worker callers (Forced/Stop passes, the seed fence) blocked on persist_mu_ right now:
    /// a Worker pass yields to them between tuples.
    std::atomic<std::uint32_t> priority_waiters_{0};
    std::atomic<std::uint32_t> apply_active_{0};  ///< live ApplyScopes: Worker passes defer
    std::atomic<std::uint64_t> yields_{0};        ///< TEST-ONLY, see yields_for_test()
    /// Counts one blocked lock acquisition on lock_waiters_ (and on priority_waiters_ for a
    /// non-Worker caller); RAII so a throwing lock() cannot leave either count inflated.
    struct WaiterGuard {
        GuardianBaselinePersister& p;
        bool priority;
        WaiterGuard(GuardianBaselinePersister& persister, bool prio) noexcept
            : p(persister), priority(prio) {
            p.lock_waiters_.fetch_add(1, std::memory_order_relaxed);
            if (priority)
                p.priority_waiters_.fetch_add(1, std::memory_order_relaxed);
        }
        ~WaiterGuard() {
            p.lock_waiters_.fetch_sub(1, std::memory_order_relaxed);
            if (priority)
                p.priority_waiters_.fetch_sub(1, std::memory_order_relaxed);
        }
        WaiterGuard(const WaiterGuard&) = delete;
        WaiterGuard& operator=(const WaiterGuard&) = delete;
    };
    /// begin_stop()'s mark (steady_clock rep, 0 = no stop begun): see begin_stop().
    std::atomic<Clock::rep> stop_began_rep_{0};
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
    /// The last pass that attempted anything saw a failed write that took at least the stop
    /// wall budget (a BUSY store burns a busy timeout per write), and `stalled_at_` is when it
    /// ended (steady_clock rep). persist_mu_-guarded. A Stop pass skips iff stalled_at_ is at or
    /// after begin_stop()'s mark.
    bool stalled_{false};
    Clock::rep stalled_at_{0};
    std::function<Clock::time_point()> clock_;
    std::function<void()> post_snapshot_hook_;
    std::function<void()> post_write_hook_;
};

} // namespace yuzu::agent
