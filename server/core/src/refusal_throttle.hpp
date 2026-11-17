#pragma once

/// @file refusal_throttle.hpp
/// Per-target rate limit for the warn log and audit row a declined webhook/offload delivery writes
/// (outbound_destination_guard.hpp): a stored row aimed at a refused address would otherwise write
/// one of each for EVERY fleet event. Header-light so the store headers can hold one as a member.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace yuzu::server {

/// At most one warn log and one audit row per target per window for a refused or unresolved
/// destination: a stored row aimed at a refused address would otherwise write a log line and an
/// audit row for EVERY fleet event. The counter and the delivery-log row are not throttled.
/// Bounded: the table is cleared when it reaches `kMaxTracked` targets.
class RefusalThrottle {
public:
    explicit RefusalThrottle(std::chrono::seconds window = std::chrono::seconds(300)) : window_(window) {}
    [[nodiscard]] bool admit(std::int64_t target_id,
                             std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) {
        std::lock_guard lock(mu_);
        if (last_.size() >= kMaxTracked)
            last_.clear();
        const auto it = last_.find(target_id);
        if (it != last_.end() && now - it->second < window_)
            return false;
        last_[target_id] = now;
        return true;
    }

private:
    static constexpr std::size_t kMaxTracked = 4096;
    std::chrono::seconds window_;
    std::mutex mu_;
    std::unordered_map<std::int64_t, std::chrono::steady_clock::time_point> last_;
};

} // namespace yuzu::server
