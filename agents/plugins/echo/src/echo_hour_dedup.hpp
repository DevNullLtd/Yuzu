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
 * Pure and copyable. A tick filters IN PLACE inside a batch: begin_batch() starts recording the
 * keys admitted from then on, commit_batch() keeps them, rollback_batch() erases them so a
 * rolled-back tick re-derives the same rows instead of finding its keys already consumed. The
 * undo costs one erase per admitted key, not a copy of the whole set (up to 20,000 strings) on
 * every tick. An hour change or overflow clear inside a batch is not undone: that costs at most
 * one repeated row per key, the same worst case the clear already has. A batch left open (an
 * exception between begin and commit) is rolled back by the next begin_batch(); BatchScope
 * below makes that the destructor's job so no tick can leave one open.
 *
 * A key admitted OUTSIDE a batch (the nstat drain filters before its insert) is given back with
 * release() when the row it admitted is dropped unstored, so the next sighting in the hour is
 * stored instead of being read as a repeat.
 */

#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::echo {

/// The closing-socket rule's key, shared by the poll leg (compute_network_events) and the
/// macOS nstat leg (nstat_dedupe_closing_opens) so the two cannot drift apart: a socket first
/// seen already closing is one row per process, remote address and remote port per hour.
[[nodiscard]] inline std::string tcp_closing_key(std::string_view process_name,
                                                 std::string_view remote_addr, int remote_port) {
    return std::format("{}\x1f{}\x1f{}", process_name, remote_addr, remote_port);
}

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
        if (batch_open_)
            admitted_.push_back(key);
        keys_.insert(std::move(key));
        return true;
    }

    /// Start recording admitted keys. An earlier batch that was never committed is rolled back
    /// first, so an exception between begin and commit cannot leave its keys consumed.
    void begin_batch() {
        rollback_batch();
        batch_open_ = true;
    }
    /// The rows were stored: keep the keys admitted since begin_batch().
    void commit_batch() noexcept {
        admitted_.clear();
        batch_open_ = false;
    }
    /// The rows were not stored: erase the keys admitted since begin_batch().
    void rollback_batch() noexcept {
        for (const auto& k : admitted_)
            keys_.erase(k);
        admitted_.clear();
        batch_open_ = false;
    }
    /// The row `key` admitted was dropped without being stored: forget the key so the next
    /// sighting this hour is stored. A key from an earlier hour is already gone (no-op).
    void release(const std::string& key) noexcept { keys_.erase(key); }
    /// Keys admitted in the open batch (what a rollback would erase).
    [[nodiscard]] std::size_t batch_admitted() const noexcept { return admitted_.size(); }
    [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }

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
    std::vector<std::string> admitted_;
    bool batch_open_{false};
};

/// One tick's batch on a HourlySeenSet: begins on construction and, unless commit() was called,
/// rolls back on destruction, so an exception (or an early return) between the filter and the
/// insert can never leave the admitted keys consumed or the batch open for the next tick to
/// inherit. commit() and rollback() are idempotent and end the scope's responsibility.
class BatchScope {
public:
    explicit BatchScope(HourlySeenSet& set) : set_(&set) { set_->begin_batch(); }
    ~BatchScope() { rollback(); }
    BatchScope(const BatchScope&) = delete;
    BatchScope& operator=(const BatchScope&) = delete;

    void commit() noexcept {
        if (set_)
            set_->commit_batch();
        set_ = nullptr;
    }
    void rollback() noexcept {
        if (set_)
            set_->rollback_batch();
        set_ = nullptr;
    }

private:
    HourlySeenSet* set_;
};

} // namespace yuzu::echo
