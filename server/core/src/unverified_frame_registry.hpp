#pragma once

/// Remembers, per (command id, agent id), that a non-terminal response frame arrived whose
/// provenance could not be resolved. Such a frame is stored under the unverified label, which the
/// result-set fill never reads, and it reaches no tracker row (it carries no execution id), so
/// without this record a later verified terminal frame would make the agent read as having fully
/// answered. The terminal frame's ingest consumes the entry and reports the agent's answer as not
/// fully stored (`response_dropped`).
///
/// Bounded: at most `capacity` entries and `max_age_s` seconds per entry. An entry older than the
/// age bound is dropped silently (the result-set fill runs within minutes of a dispatch, so an
/// older entry no longer changes any fill); reaching the capacity evicts the oldest entry, which
/// the caller counts. Lives in process memory only: a restart, or a terminal frame served by
/// another replica, loses the record (docs/executions-history-ladder.md, "Response frames the
/// response store did not keep"). Mutex-guarded, no thread; the clock is the caller's.

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace yuzu::server {

class UnverifiedFrameRegistry {
public:
    static constexpr std::size_t kDefaultCapacity = 4096;
    static constexpr int64_t kDefaultMaxAgeSeconds = 3600;

    explicit UnverifiedFrameRegistry(std::size_t capacity = kDefaultCapacity,
                                     int64_t max_age_s = kDefaultMaxAgeSeconds)
        : capacity_(capacity == 0 ? 1 : capacity), max_age_s_(max_age_s) {}

    /// Record an unverified non-terminal frame seen at `now_s`. A key already present keeps its
    /// first-seen time. Returns how many entries were evicted to stay within the capacity (0 or 1);
    /// the caller counts them, since each is a lost signal.
    [[nodiscard]] std::size_t note(const std::string& command_id, const std::string& agent_id,
                                   int64_t now_s) {
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        Key key{command_id, agent_id};
        if (by_key_.contains(key))
            return 0;
        const uint64_t seq = next_seq_++;
        by_age_.emplace(seq, key);
        by_key_.emplace(std::move(key), Entry{now_s, seq});
        std::size_t evicted = 0;
        while (by_key_.size() > capacity_) {
            auto oldest = by_age_.begin();
            by_key_.erase(oldest->second);
            by_age_.erase(oldest);
            ++evicted;
        }
        return evicted;
    }

    /// True when an unexpired entry for the key exists. The entry is erased either way, so each
    /// record is reported to at most one terminal frame.
    [[nodiscard]] bool consume(const std::string& command_id, const std::string& agent_id,
                               int64_t now_s) {
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        auto it = by_key_.find(Key{command_id, agent_id});
        if (it == by_key_.end())
            return false;
        by_age_.erase(it->second.seq);
        by_key_.erase(it);
        return true;
    }

    [[nodiscard]] std::size_t size() const {
        std::lock_guard lock(mu_);
        return by_key_.size();
    }

private:
    using Key = std::pair<std::string, std::string>;
    struct Entry {
        int64_t seen_s{0};
        uint64_t seq{0};
    };

    // Entries are inserted in sequence order with a caller clock that only moves forward in
    // practice; a clock step back only delays expiry (never drops a fresh entry early).
    void expire_locked(int64_t now_s) {
        while (!by_age_.empty()) {
            auto oldest = by_age_.begin();
            auto it = by_key_.find(oldest->second);
            if (it != by_key_.end() && now_s - it->second.seen_s < max_age_s_)
                break;
            if (it != by_key_.end())
                by_key_.erase(it);
            by_age_.erase(oldest);
        }
    }

    const std::size_t capacity_;
    const int64_t max_age_s_;
    mutable std::mutex mu_;
    std::map<Key, Entry> by_key_;
    std::map<uint64_t, Key> by_age_; // insertion order: oldest first
    uint64_t next_seq_{0};
};

} // namespace yuzu::server
