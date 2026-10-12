#pragma once

/// @file refusal_log_throttle.hpp
/// Bounds how often one repeated refusal reaches the log at warn level (#4966).
///
/// An IdP that is refused a SCIM deprovision with a 409 commonly retries it on its next sync
/// cycle, and a 409 does not prove it ever stops, so an unthrottled warn line per attempt is a
/// log flood driven by an external party. The caller still writes its audit row and bumps its
/// counter on EVERY refusal (the evidence is never throttled); only the human-readable log line
/// is demoted. Header-only and clock-injectable so the policy is unit-testable without sleeping.

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

class RefusalLogThrottle {
public:
    using Clock = std::chrono::steady_clock;

    explicit RefusalLogThrottle(std::chrono::seconds interval = std::chrono::seconds(60),
                                std::size_t max_keys = 1024)
        : interval_(interval), max_keys_(max_keys) {}

    /// True when the caller should log `key` at warn level now (the first sighting, or the first
    /// one at least `interval` after the last warn for that key); false when it should demote the
    /// line to debug. Memory is bounded by `max_keys`: when the table is full, entries older than
    /// the interval are evicted first, and if none is evictable the key is not tracked and is
    /// demoted (never an unbounded map, never a missed audit row).
    [[nodiscard]] bool should_warn(const std::string& key, Clock::time_point now = Clock::now()) {
        std::lock_guard lock(mu_);
        if (auto it = last_warn_.find(key); it != last_warn_.end()) {
            if (now - it->second < interval_)
                return false;
            it->second = now;
            return true;
        }
        if (last_warn_.size() >= max_keys_) {
            for (auto it = last_warn_.begin(); it != last_warn_.end();) {
                if (now - it->second >= interval_)
                    it = last_warn_.erase(it);
                else
                    ++it;
            }
            if (last_warn_.size() >= max_keys_)
                return false;
        }
        last_warn_.emplace(key, now);
        return true;
    }

private:
    std::chrono::seconds interval_;
    std::size_t max_keys_;
    std::mutex mu_;
    std::unordered_map<std::string, Clock::time_point> last_warn_;
};

} // namespace yuzu::server
