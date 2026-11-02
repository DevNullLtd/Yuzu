#pragma once

/**
 * echo_hour_dedup.hpp -- "first time this hour" membership set
 *
 * One primitive shared by the tcp closing-socket rule and the module-load rule: a row
 * whose key was already stored this hour is dropped. The set is bounded (20,000 keys by
 * default) and cleared when the hour changes, so a restart or an overflow costs at most
 * one extra row per key, never a missed first sighting.
 *
 * The hour follows the timestamps in BOTH directions: any change of hour clears the set. A
 * single timestamp far in the future therefore costs one repeated row per key when the clock
 * comes back, instead of pinning the set at the future hour and silently dropping every real
 * row after it.
 *
 * Pure and copyable on purpose. Callers filter against a COPY and assign it back only
 * after the rows are committed, so a rolled-back tick re-derives the same rows instead
 * of finding its keys already consumed.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>

namespace yuzu::echo {

class HourlySeenSet {
public:
    static constexpr std::size_t kDefaultCap = 20000;

    explicit HourlySeenSet(std::size_t cap = kDefaultCap) : cap_(cap) {}

    /// True when `key` has not been seen in the hour containing `ts_unix` (and records it);
    /// false when it was. A different hour, earlier or later, clears the set first and becomes
    /// the current hour, so a timestamp that straddles an hour boundary (or one outlier) costs
    /// a repeated row, never a lost first row. Admitting a NEW key into a full set clears the
    /// set and counts one overflow, with the same worst case.
    [[nodiscard]] bool first_this_hour(int64_t ts_unix, std::string key) {
        const int64_t hour = hour_of(ts_unix);
        if (hour != hour_) {
            keys_.clear();
            hour_ = hour;
        }
        if (keys_.contains(key))
            return false;
        if (keys_.size() >= cap_) {
            keys_.clear();
            ++overflows_;
        }
        keys_.insert(std::move(key));
        return true;
    }

    /// Times the cap forced a clear. Monotonic for the life of the process.
    [[nodiscard]] uint64_t overflows() const noexcept { return overflows_; }

private:
    // Floor division, so a negative (pre-1970, dead-RTC) timestamp still lands in a stable hour.
    static int64_t hour_of(int64_t ts) noexcept {
        const int64_t q = ts / 3600;
        return (ts % 3600 < 0) ? q - 1 : q;
    }

    std::size_t cap_;
    int64_t hour_{INT64_MIN};
    uint64_t overflows_{0};
    std::unordered_set<std::string> keys_;
};

} // namespace yuzu::echo
