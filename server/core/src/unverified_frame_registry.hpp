#pragma once

/// Remembers, per (command id, agent id), that a non-terminal response frame arrived whose
/// provenance lookup FAILED (`ProvenanceOutcome::kLookupDegraded`). Such a frame is stored under
/// the unverified label, which the result-set fill never reads, and it reaches no tracker row (it
/// carries no execution id), so without this record a later verified terminal frame would make the
/// agent read as having fully answered. The terminal frame's ingest checks the record (`contains`,
/// which does not erase) and reports the agent's answer as not fully stored (`response_dropped`);
/// the record is erased (`forget`) only once a tracker row has recorded that flag, so a terminal
/// frame that could not be recorded leaves it for a replayed terminal frame. A frame with no
/// record at all (forged, reaped or never issued id) is not noted: it can never reach a tracker
/// row, so recording it would protect nothing.
///
/// Bounded, and FAILS CLOSED whenever it cannot keep a record (it over-reports an answer as not
/// fully stored rather than lose one):
/// - at most `per_agent_capacity` entries per agent: a new entry past it evicts THAT agent's own
///   oldest entry, never another agent's;
/// - at most `capacity` entries in all: past it the oldest entry is evicted;
/// - an evicted entry's COMMAND id is remembered (at most `command_capacity` of them, refreshed on
///   each eviction), and `contains` is true for every agent of a remembered command;
/// - a command id over `kMaxCommandIdBytes` cannot be remembered at all, and a full command set
///   cannot take another: either one sets a global latch for `max_age_s` seconds during which
///   `contains` is true for every pair;
/// - an agent id over `kMaxAgentIdBytes` (longer than any enrolled agent id) is not kept as a
///   pair; its command is remembered instead.
/// Every entry, remembered command and latch is dropped `max_age_s` seconds after it was set (the
/// result-set fill runs within minutes of a dispatch, so an older one no longer changes any fill).
/// Lives in process memory only: a restart, or a terminal frame served by another replica, loses
/// the record (docs/executions-history-ladder.md, "Response frames the response store did not
/// keep"). Mutex-guarded, no thread; the clock is the caller's.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>

namespace yuzu::server {

class UnverifiedFrameRegistry {
public:
    static constexpr std::size_t kDefaultCapacity = 4096;
    static constexpr std::size_t kDefaultPerAgentCapacity = 64;
    static constexpr std::size_t kDefaultCommandCapacity = 1024;
    static constexpr int64_t kDefaultMaxAgeSeconds = 3600;
    /// No server-minted command id is this long (plugin name, `-`, 16 or 32 hex characters).
    static constexpr std::size_t kMaxCommandIdBytes = 128;
    /// auth::kMaxAgentIdLength: no enrolled agent id is longer.
    static constexpr std::size_t kMaxAgentIdBytes = 256;

    struct NoteResult {
        std::size_t evicted{0}; ///< entries evicted to stay within a capacity (each fails closed)
        bool skipped{false};    ///< the pair could not be kept as an entry (fails closed)
        bool latched{false};    ///< this call set the global latch (it was not already set)
    };

    explicit UnverifiedFrameRegistry(std::size_t capacity = kDefaultCapacity,
                                     int64_t max_age_s = kDefaultMaxAgeSeconds,
                                     std::size_t per_agent_capacity = kDefaultPerAgentCapacity,
                                     std::size_t command_capacity = kDefaultCommandCapacity)
        : capacity_(std::max<std::size_t>(capacity, 1)), max_age_s_(max_age_s),
          per_agent_capacity_(std::max<std::size_t>(per_agent_capacity, 1)),
          command_capacity_(std::max<std::size_t>(command_capacity, 1)) {}

    /// Record a non-terminal frame whose provenance lookup failed, seen at `now_s`. A pair already
    /// present keeps its first-seen time.
    [[nodiscard]] NoteResult note(const std::string& command_id, const std::string& agent_id,
                                  int64_t now_s) {
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        NoteResult out;
        if (command_id.size() > kMaxCommandIdBytes) {
            out.skipped = true;
            out.latched = latch_locked(now_s);
            return out;
        }
        if (agent_id.size() > kMaxAgentIdBytes) {
            out.skipped = true;
            out.latched = remember_command_locked(command_id, now_s);
            return out;
        }
        Key key{command_id, agent_id};
        if (by_key_.contains(key))
            return out;
        auto& own = by_agent_[agent_id];
        if (own.size() >= per_agent_capacity_) {
            const uint64_t oldest = *own.begin(); // this agent's own oldest entry
            out.latched |= evict_locked(by_key_.find(by_age_.at(oldest)), now_s);
            ++out.evicted;
        }
        const uint64_t seq = next_seq_++;
        by_age_.emplace(seq, key);
        by_agent_[agent_id].insert(seq); // re-looked-up: evict_locked may have erased the set
        by_key_.emplace(std::move(key), Entry{now_s, seq});
        while (by_key_.size() > capacity_) {
            out.latched |= evict_locked(by_key_.find(by_age_.begin()->second), now_s);
            ++out.evicted;
        }
        return out;
    }

    /// True when the pair must be reported as not fully stored: an unexpired entry for it, its
    /// command remembered after an eviction, or the global latch set. Erases nothing.
    [[nodiscard]] bool contains(const std::string& command_id, const std::string& agent_id,
                                int64_t now_s) {
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        return now_s < latched_until_s_ || commands_.contains(command_id) ||
               by_key_.contains(Key{command_id, agent_id});
    }

    /// Erase the pair's entry (once its flag is recorded). A remembered command and the latch stay
    /// until they expire: they stand for other pairs too.
    void forget(const std::string& command_id, const std::string& agent_id) {
        std::lock_guard lock(mu_);
        auto it = by_key_.find(Key{command_id, agent_id});
        if (it != by_key_.end())
            erase_locked(it);
    }

    /// Pairs held (remembered commands and the latch are not counted).
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
    struct Remembered {
        int64_t at_s{0};
        uint64_t seq{0};
    };

    void erase_locked(std::map<Key, Entry>::iterator it) {
        const uint64_t seq = it->second.seq;
        auto own = by_agent_.find(it->first.second);
        if (own != by_agent_.end()) {
            own->second.erase(seq);
            if (own->second.empty())
                by_agent_.erase(own);
        }
        by_age_.erase(seq);
        by_key_.erase(it);
    }

    /// Evicts one entry and remembers its command. True when that set the latch.
    bool evict_locked(std::map<Key, Entry>::iterator it, int64_t now_s) {
        const std::string command_id = it->first.first;
        erase_locked(it);
        return remember_command_locked(command_id, now_s);
    }

    /// Remembers (or refreshes) a command whose pair could not be kept. True when that set the
    /// latch (the command set was full).
    bool remember_command_locked(const std::string& command_id, int64_t now_s) {
        if (auto it = commands_.find(command_id); it != commands_.end()) {
            commands_by_age_.erase(it->second.seq);
            commands_.erase(it);
        }
        const uint64_t seq = next_seq_++;
        commands_by_age_.emplace(seq, command_id);
        commands_.emplace(command_id, Remembered{now_s, seq});
        bool latched = false;
        while (commands_.size() > command_capacity_) {
            auto oldest = commands_by_age_.begin();
            commands_.erase(oldest->second);
            commands_by_age_.erase(oldest);
            latched |= latch_locked(now_s);
        }
        return latched;
    }

    /// Sets the global latch until `now_s + max_age_s`. True when it was not already set.
    bool latch_locked(int64_t now_s) {
        const bool was_set = now_s < latched_until_s_;
        latched_until_s_ = std::max(latched_until_s_, now_s + max_age_s_);
        return !was_set;
    }

    // Entries are inserted in sequence order with a caller clock that only moves forward in
    // practice; a clock step back only delays expiry (never drops a fresh entry early).
    void expire_locked(int64_t now_s) {
        while (!by_age_.empty()) {
            auto it = by_key_.find(by_age_.begin()->second);
            if (it == by_key_.end()) { // not reachable: the two maps change together
                by_age_.erase(by_age_.begin());
                continue;
            }
            if (now_s - it->second.seen_s < max_age_s_)
                break;
            erase_locked(it);
        }
        while (!commands_by_age_.empty()) {
            auto oldest = commands_by_age_.begin();
            auto it = commands_.find(oldest->second);
            if (it != commands_.end() && now_s - it->second.at_s < max_age_s_)
                break;
            if (it != commands_.end())
                commands_.erase(it);
            commands_by_age_.erase(oldest);
        }
    }

    const std::size_t capacity_;
    const int64_t max_age_s_;
    const std::size_t per_agent_capacity_;
    const std::size_t command_capacity_;
    mutable std::mutex mu_;
    std::map<Key, Entry> by_key_;
    std::map<uint64_t, Key> by_age_;                       // insertion order: oldest first
    std::map<std::string, std::set<uint64_t>> by_agent_;   // each agent's entries, oldest first
    std::map<std::string, Remembered> commands_;           // commands of evicted or skipped pairs
    std::map<uint64_t, std::string> commands_by_age_;      // oldest first
    int64_t latched_until_s_{0};
    uint64_t next_seq_{0};
};

} // namespace yuzu::server
