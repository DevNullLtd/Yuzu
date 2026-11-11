#pragma once

/// Remembers, per (command id, agent id), that an answer of that agent may be missing from the
/// response store although its terminal frame can still be recorded: a non-terminal frame whose
/// provenance lookup FAILED (`ProvenanceOutcome::kLookupDegraded`), stored under the unverified
/// label the result-set fill never reads and reaching no tracker row, or a frame the store did not
/// keep whose tracker row could not be written either. Without this record a later verified
/// terminal frame would make the agent read as having fully answered. The terminal frame's ingest
/// checks the record (`contains`, which does not erase) and reports the agent's answer as not fully
/// stored (`response_dropped`); the record is erased (`forget`) only once a tracker row has recorded
/// that flag, so a terminal frame that could not be recorded leaves it for a replayed terminal
/// frame. A frame for an id the server never issued is not noted: it can never reach a tracker row,
/// so recording it would protect nothing. Entries for frames that never reach the tracker (for
/// example workflow-step ids and `polchk-`, `bundle-`, `preflight-` and `deployment-` ids) are never
/// forgotten; they age out after `max_age_s`.
///
/// Ids are kept as fixed-width 64-bit digests (in-process only, never persisted or compared across
/// processes), so memory per entry does not depend on what an agent sends. Two ids with the same
/// digest read as one, which only over-reports, with one exception: forgetting a pair also erases a
/// different pair whose two digests both match, which needs two ids the server issued to the same
/// agent within `max_age_s` to share a 64-bit digest.
///
/// Bounded, and FAILS CLOSED whenever it cannot keep a record (it over-reports an answer as not
/// fully stored rather than lose one):
/// - at most `per_agent_capacity` entries per agent: a new entry past it evicts THAT agent's own
///   oldest entry and sets a marker for that agent (at most `marker_capacity` markers, refreshed on
///   each eviction), and `contains` is true for every pair of a marked agent. A flooding agent
///   therefore affects only its own answers;
/// - at most `capacity` entries in all: past it the oldest entry is evicted and its COMMAND is
///   remembered (at most `command_capacity` of them, refreshed on each eviction), and `contains`
///   is true for every agent of a remembered command;
/// - a full marker set or a full command set cannot take another: either one sets a global latch
///   for `max_age_s` seconds during which `contains` is true for every pair. Only these two cases
///   affect agents other than the one that sent the frames.
/// Every entry, marker, remembered command and latch is dropped `max_age_s` seconds after it was set
/// (the result-set fill runs within minutes of a dispatch, so an older one no longer changes any
/// fill). Lives in process memory only: a restart, or a terminal frame served by another replica,
/// loses the record (docs/executions-history-ladder.md, "Response frames the response store did not
/// keep"). Mutex-guarded, no thread; the clock is the caller's.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string_view>
#include <utility>

namespace yuzu::server {

class UnverifiedFrameRegistry {
public:
    static constexpr std::size_t kDefaultCapacity = 4096;
    static constexpr std::size_t kDefaultPerAgentCapacity = 64;
    static constexpr std::size_t kDefaultCommandCapacity = 1024;
    static constexpr std::size_t kDefaultMarkerCapacity = 1024;
    static constexpr int64_t kDefaultMaxAgeSeconds = 3600;

    /// The id digest. Tests may inject one to force collisions.
    using Digest = uint64_t (*)(std::string_view);
    static uint64_t default_digest(std::string_view id) noexcept {
        return static_cast<uint64_t>(std::hash<std::string_view>{}(id));
    }

    struct NoteResult {
        std::size_t evicted{0}; ///< entries evicted to stay within a capacity (each fails closed)
        bool marked{false};     ///< this call set a marker for the agent (it was not already set)
        bool latched{false};    ///< this call set the global latch (it was not already set)
    };

    explicit UnverifiedFrameRegistry(std::size_t capacity = kDefaultCapacity,
                                     int64_t max_age_s = kDefaultMaxAgeSeconds,
                                     std::size_t per_agent_capacity = kDefaultPerAgentCapacity,
                                     std::size_t command_capacity = kDefaultCommandCapacity,
                                     std::size_t marker_capacity = kDefaultMarkerCapacity,
                                     Digest digest = &default_digest)
        : capacity_(std::max<std::size_t>(capacity, 1)), max_age_s_(max_age_s),
          per_agent_capacity_(std::max<std::size_t>(per_agent_capacity, 1)),
          command_capacity_(std::max<std::size_t>(command_capacity, 1)),
          marker_capacity_(std::max<std::size_t>(marker_capacity, 1)), digest_(digest) {}

    /// Record a pair whose answer may be missing, seen at `now_s`. A pair already present keeps its
    /// first-seen time.
    [[nodiscard]] NoteResult note(std::string_view command_id, std::string_view agent_id,
                                  int64_t now_s) {
        const Key key{digest_(command_id), digest_(agent_id)};
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        NoteResult out;
        if (by_key_.contains(key))
            return out;
        if (auto own = by_agent_.find(key.second);
            own != by_agent_.end() && own->second.size() >= per_agent_capacity_) {
            // Evict this agent's own oldest entry; the agent's marker, set first so a failed
            // allocation loses nothing, stands for it.
            const auto oldest = by_key_.find(by_age_.at(*own->second.begin()));
            const bool was_marked = markers_.contains(key.second);
            if (markers_.remember(key.second, now_s, next_seq_++, marker_capacity_))
                out.latched |= latch_locked(now_s);
            out.marked = !was_marked;
            erase_locked(oldest);
            ++out.evicted;
        }
        // Insert into all three indexes or none (an allocation failure leaves no orphan).
        const uint64_t seq = next_seq_++;
        const auto entry = by_key_.emplace(key, Entry{now_s, seq}).first;
        try {
            by_age_.emplace(seq, key);
            by_agent_[key.second].insert(seq);
        } catch (...) {
            by_age_.erase(seq);
            if (auto own = by_agent_.find(key.second); own != by_agent_.end()) {
                own->second.erase(seq);
                if (own->second.empty())
                    by_agent_.erase(own);
            }
            by_key_.erase(entry);
            throw;
        }
        while (by_key_.size() > capacity_) {
            const auto oldest = by_key_.find(by_age_.begin()->second);
            if (commands_.remember(oldest->first.first, now_s, next_seq_++, command_capacity_))
                out.latched |= latch_locked(now_s);
            erase_locked(oldest); // after its command is remembered: nothing is lost on a throw
            ++out.evicted;
        }
        return out;
    }

    /// True when the pair must be reported as not fully stored: an unexpired entry for it, its
    /// agent marked, its command remembered after an eviction, or the global latch set. Erases
    /// nothing.
    [[nodiscard]] bool contains(std::string_view command_id, std::string_view agent_id,
                                int64_t now_s) {
        const Key key{digest_(command_id), digest_(agent_id)};
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        return now_s < latched_until_s_ || markers_.contains(key.second) ||
               commands_.contains(key.first) || by_key_.contains(key);
    }

    /// Erase the pair's entry (once its flag is recorded). A marker, a remembered command and the
    /// latch stay until they expire: they stand for other pairs too.
    void forget(std::string_view command_id, std::string_view agent_id) {
        const Key key{digest_(command_id), digest_(agent_id)};
        std::lock_guard lock(mu_);
        if (auto it = by_key_.find(key); it != by_key_.end())
            erase_locked(it);
    }

    /// Pairs held (markers, remembered commands and the latch are not counted).
    [[nodiscard]] std::size_t size() const {
        std::lock_guard lock(mu_);
        return by_key_.size();
    }

private:
    using Key = std::pair<uint64_t, uint64_t>; // (command digest, agent digest)
    struct Entry {
        int64_t seen_s{0};
        uint64_t seq{0};
    };

    /// Digests kept for `max_age_s` after they were last set, oldest dropped past a capacity.
    class AgedSet {
    public:
        bool contains(uint64_t id) const { return items_.contains(id); }

        /// Sets (or refreshes) `id`. True when the set was full and dropped its oldest member.
        bool remember(uint64_t id, int64_t now_s, uint64_t seq, std::size_t capacity) {
            if (auto it = items_.find(id); it != items_.end()) {
                by_age_.erase(it->second.seq);
                items_.erase(it);
            }
            const auto item = items_.emplace(id, Item{now_s, seq}).first;
            try {
                by_age_.emplace(seq, id);
            } catch (...) {
                items_.erase(item);
                throw;
            }
            bool dropped = false;
            while (items_.size() > capacity) {
                const auto oldest = by_age_.begin();
                items_.erase(oldest->second);
                by_age_.erase(oldest);
                dropped = true;
            }
            return dropped;
        }

        void expire(int64_t now_s, int64_t max_age_s) {
            while (!by_age_.empty()) {
                const auto oldest = by_age_.begin();
                if (now_s - items_.at(oldest->second).at_s < max_age_s)
                    break;
                items_.erase(oldest->second);
                by_age_.erase(oldest);
            }
        }

    private:
        struct Item {
            int64_t at_s{0};
            uint64_t seq{0};
        };
        std::map<uint64_t, Item> items_;
        std::map<uint64_t, uint64_t> by_age_; // seq -> id, oldest first
    };

    void erase_locked(std::map<Key, Entry>::iterator it) {
        const uint64_t seq = it->second.seq;
        if (auto own = by_agent_.find(it->first.second); own != by_agent_.end()) {
            own->second.erase(seq);
            if (own->second.empty())
                by_agent_.erase(own);
        }
        by_age_.erase(seq);
        by_key_.erase(it);
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
            const auto it = by_key_.find(by_age_.begin()->second);
            if (it == by_key_.end()) { // not reachable: the indexes change together
                by_age_.erase(by_age_.begin());
                continue;
            }
            if (now_s - it->second.seen_s < max_age_s_)
                break;
            erase_locked(it);
        }
        markers_.expire(now_s, max_age_s_);
        commands_.expire(now_s, max_age_s_);
    }

    const std::size_t capacity_;
    const int64_t max_age_s_;
    const std::size_t per_agent_capacity_;
    const std::size_t command_capacity_;
    const std::size_t marker_capacity_;
    const Digest digest_;
    mutable std::mutex mu_;
    std::map<Key, Entry> by_key_;
    std::map<uint64_t, Key> by_age_;                    // insertion order: oldest first
    std::map<uint64_t, std::set<uint64_t>> by_agent_;   // each agent's entries, oldest first
    AgedSet markers_;  // agents that lost an entry to their own cap
    AgedSet commands_; // commands of entries evicted by the global cap
    int64_t latched_until_s_{0};
    uint64_t next_seq_{0};
};

} // namespace yuzu::server
