#pragma once

/**
 * guardian_baseline_persister.hpp -- the ENGINE-owned durable side of Spark's baseline-on-arm
 * capture (#4045, the Spark half of the #4021 baseline store).
 *
 * #4045 RED-COMMIT STUB: signatures only, no behaviour. The real class (borrowed KvStore*,
 * persist_mu_ leaf mutex, take -> persist -> restage) lands with the engine change.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

class GuardianBaselinePersister {
public:
    explicit GuardianBaselinePersister(KvStore* kv) noexcept : kv_(kv) {}
    struct Outcome {
        std::size_t written{0};
        std::size_t refused{0};
        std::size_t failed{0};
    };
    Outcome persist_staged(GuardianSparkRuntime&) { return {}; }
    [[nodiscard]] std::uint64_t persist_failures() const noexcept {
        return persist_failures_.load(std::memory_order_relaxed);
    }

private:
    KvStore* kv_;
    std::atomic<std::uint64_t> persist_failures_{0};
};

} // namespace yuzu::agent
