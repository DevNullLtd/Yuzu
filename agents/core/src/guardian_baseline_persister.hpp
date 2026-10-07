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
 * taken, so a staged capture is not lost to a missing store). The KvStore outlives the engine
 * (agent.cpp declares kv_store_ before guardian_), the same proof guard_file.hpp relies on.
 * The runtime is passed per call and never retained.
 *
 * LOCKING: `persist_mu_` is a LEAF. It is held across take -> persist loop -> restage so an
 * engine drain WAITS for an in-flight worker batch (an apply_rules re-arm can never seed while
 * a batch is mid-write). Order: engine mtx_ -> persist_mu_ -> registry_mu_ (take/restage) and
 * persist_mu_ -> KvStore::mu_; the worker takes persist_mu_ -> registry_mu_ and never mtx_.
 * persist_mu_ is never taken under any runtime lock.
 *
 * CALLERS (exactly three, and NEVER only from a connection-gated thread, or a pre-network
 * boot re-arm would lose its capture on a crash): GuardianEngine::apply_rules under mtx_
 * BEFORE any teardown or re-arm (the seed read of the new generation must observe the prior
 * generation's capture), GuardianEngine::stop() after the worker join, and the drain worker's
 * loop. Not journal_maintenance_tick: it runs only on a live connection.
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

private:
    KvStore* kv_;
    std::mutex persist_mu_; ///< LEAF, see LOCKING above
    std::atomic<std::uint64_t> persist_failures_{0};
};

} // namespace yuzu::agent
