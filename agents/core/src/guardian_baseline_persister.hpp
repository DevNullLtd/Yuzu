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
 * OWNERSHIP: `kv_` is BORROWED and may be null (nothing is then persisted and nothing is
 * taken, so a staged capture is not lost to a missing store; each drain that finds one staged
 * counts it in no_store_pending() and the first logs once). The KvStore outlives the engine
 * (agent.cpp declares kv_store_ before guardian_), the same proof guard_file.hpp relies on.
 * The runtime is passed per call and never retained.
 *
 * LOCKING: `persist_mu_` is a LEAF. It is held across take -> persist loop -> restage so an
 * engine drain WAITS for an in-flight worker batch. The engine ALSO holds it (hold_seed_fence())
 * across a baseline-on-arm rule's whole seed step (the KV seed read through attach_rule), so
 * the worker cannot have a capture taken-but-not-yet-written while the seed is read: at the
 * seed read every capture is either durable in the KV or still staged for attach_core's
 * under-registry_mu_ read (see GuardianSparkRuntime::attach_core). Order: engine mtx_ ->
 * persist_mu_ -> registry_mu_ (take/restage/attach) and persist_mu_ -> KvStore::mu_; the worker
 * takes persist_mu_ -> registry_mu_ and never mtx_. persist_mu_ is never taken under any
 * runtime lock.
 *
 * CALLERS of persist_staged (exactly three, and NEVER only from a connection-gated thread, or
 * a pre-network boot re-arm would lose its capture on a crash): GuardianEngine::apply_rules
 * under mtx_ before any teardown or re-arm (so the common case is already durable when the
 * seed is read), GuardianEngine::stop() after the worker join, and the drain worker's loop.
 * Not journal_maintenance_tick: it runs only on a live connection. The drain is NOT what
 * orders an in-flight evaluation's capture against a replacement's seed (one can stage after
 * any drain); the fence above and attach_core's staged read do.
 *
 * FAILURE POSTURE: a failed write (kv->set false or a throw) is DELIBERATE fail-OPEN, the rule
 * keeps running on its in-memory baseline, but never silent: the tuple is restaged for the
 * next drain, persist_failures() counts it, and the heartbeat carries it. A refusal by the
 * #4021 overwrite guard is not a failure: first capture wins.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

class YUZU_EXPORT GuardianBaselinePersister {
public:
    /// `kv` is BORROWED (may be null) and must outlive this object.
    explicit GuardianBaselinePersister(KvStore* kv) noexcept : kv_(kv) {}
    GuardianBaselinePersister(const GuardianBaselinePersister&) = delete;
    GuardianBaselinePersister& operator=(const GuardianBaselinePersister&) = delete;

    struct Outcome {
        std::size_t written{0};
        std::size_t refused{0};
        std::size_t failed{0};
    };

    /// Take the runtime's staged captures, persist each, restage the failures.
    /// Thread-safe (serialised on persist_mu_); callable from an mtx_ holder or the joined
    /// drain worker. Per-tuple exceptions count as Failed; a throw out of take/restage
    /// itself (allocation) propagates to the caller's firewall.
    Outcome persist_staged(GuardianSparkRuntime& rt);

    /// Cumulative count of failed persist attempts (a tuple retried N times counts N).
    [[nodiscard]] std::uint64_t persist_failures() const noexcept {
        return persist_failures_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of drains that found a capture staged but had no store to write it to
    /// (kv_ null). The capture stays staged (bounded by the runtime's cap); never silent.
    [[nodiscard]] std::uint64_t no_store_pending() const noexcept {
        return no_store_pending_.load(std::memory_order_relaxed);
    }

    /// The persist-before-seed fence: hold persist_mu_ for the lifetime of the returned lock.
    /// Blocks until any in-flight persist_staged batch has finished, and keeps the next one out.
    /// Caller: GuardianEngine::reconcile_rule_locked (mtx_ held), around a baseline-on-arm
    /// rule's seed read and attach. Must never be taken under a runtime lock.
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

private:
    KvStore* kv_;
    std::mutex persist_mu_; ///< LEAF, see LOCKING above
    std::atomic<std::uint64_t> persist_failures_{0};
    std::atomic<std::uint64_t> no_store_pending_{0};
    std::atomic<std::uint32_t> no_store_logs_{0}; ///< 0 -> 1 latches the one-time "no store" log
};

} // namespace yuzu::agent
