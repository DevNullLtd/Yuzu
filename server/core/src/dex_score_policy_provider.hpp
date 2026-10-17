#pragma once

/**
 * @file dex_score_policy_provider.hpp
 * Read-through cache of the score policy in force, over an injected store read
 * and an injected millisecond clock.
 *
 * Every server instance reads the same stored document through its own
 * provider, so a change reaches all of them within kDexPolicyRefreshMs without
 * any process-local push. The provider owns the failure direction:
 *   - a good read (including "nothing stored", which is the shipped defaults)
 *     is cached for kDexPolicyRefreshMs;
 *   - a stored document that fails to parse or validate is still a GOOD read:
 *     the policy in force is the shipped defaults with `fault` set;
 *   - a failed read serves the last good policy while it is no older than
 *     kDexPolicyStaleCapMs, and past that returns an error, so the caller
 *     degrades instead of scoring under a guess;
 *   - a failed read before any good read is an error at once.
 *
 * No clock or store is touched except through the injected functions, so the
 * behaviour is testable without sleeping.
 */

#include "dex_read_model.hpp"
#include "dex_score_policy_json.hpp"

#include <spdlog/spdlog.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

/// How long a good read is served before the store is read again.
inline constexpr std::int64_t kDexPolicyRefreshMs = 5000;
/// How long the last good policy is served while the store cannot be read.
inline constexpr std::int64_t kDexPolicyStaleCapMs = 60000;

class DexScorePolicyProvider {
public:
    /// The stored document text: nullopt = nothing stored, error = unreadable.
    using ReadFn = std::function<std::expected<std::optional<std::string>, std::string>()>;
    /// Monotonic milliseconds.
    using ClockFn = std::function<std::int64_t()>;

    DexScorePolicyProvider(ReadFn read, ClockFn clock)
        : read_(std::move(read)), clock_(std::move(clock)) {}

    DexScorePolicyProvider(const DexScorePolicyProvider&) = delete;
    DexScorePolicyProvider& operator=(const DexScorePolicyProvider&) = delete;

    /// The policy in force, from cache while fresh. See the file banner for the
    /// failure direction.
    [[nodiscard]] std::expected<DexPolicyInForce, std::string> current() {
        // ponytail: one mutex across a single-row store read that is bounded
        // by the store's own acquire timeout; a snapshot-outside-the-lock
        // refresh if the Apps read ever queues on it.
        std::lock_guard lk(mu_);
        const std::int64_t now = clock_();
        if (have_ && now - last_ok_ms_ < kDexPolicyRefreshMs)
            return cached_;
        return read_locked(now);
    }

private:
    std::expected<DexPolicyInForce, std::string> read_locked(std::int64_t now) {
        auto r = read_();
        if (r) {
            cached_ = dex_policy_in_force_from_stored(*r);
            if (!cached_.fault.empty() && cached_.fault != logged_fault_)
                spdlog::warn("DEX score policy refused, shipped defaults in force: {}",
                             cached_.fault);
            logged_fault_ = cached_.fault;
            last_ok_ms_ = now;
            have_ = true;
            outage_logged_ = false;
            return cached_;
        }
        if (have_ && now - last_ok_ms_ <= kDexPolicyStaleCapMs) {
            if (!outage_logged_)
                spdlog::warn("DEX score policy store unreadable, serving the last good policy: {}",
                             r.error());
            outage_logged_ = true;
            return cached_;
        }
        return std::unexpected("score policy unreadable: " + r.error());
    }

    ReadFn read_;
    ClockFn clock_;

    std::mutex mu_;
    bool have_{false};
    bool outage_logged_{false};
    std::int64_t last_ok_ms_{0};
    DexPolicyInForce cached_;
    std::string logged_fault_;
};

} // namespace yuzu::server
