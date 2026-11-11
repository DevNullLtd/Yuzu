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
/// Keys (in process only, never persisted or compared across processes): the EXACT agent id, and a
/// 64-bit digest of the command id salted with a random per-process value. Entries, the per-agent
/// index and the agent markers all compare agent ids byte for byte, so nothing one agent sends can
/// read, erase or mark another agent's entry. Agent ids are at most `kMaxAgentIdBytes` (Register
/// refuses a longer one, `auth::kMaxAgentIdLength`), which bounds what an entry or marker holds; a
/// longer id is never stored: noting one sets the global latch (fail closed). Two command ids with
/// the same digest read as one command: within one agent's own pairs forgetting one also erases the
/// other, and a remembered command also covers the other; neither reaches another agent's entry.
/// The salt keeps such a collision from being computed ahead of time; the digest is not a
/// cryptographic MAC.
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
/// A failed allocation loses no record (a marker or command is set before the entry it stands for
/// is erased, and a refresh re-keys in place without allocating), but can leave more than
/// `capacity` entries (one per failed `note`) until the next successful `note` evicts back to it.
/// Memory is bounded, about 4 MiB worst case at the default caps with every agent id at the
/// 256-byte bound (an estimate from allocation sizes measured on one platform, not a guarantee).
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
#include <random>
#include <set>
#include <string>
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
    /// The longest agent id kept (equal to `auth::kMaxAgentIdLength`, asserted where both are
    /// visible).
    static constexpr std::size_t kMaxAgentIdBytes = 256;

    /// The command-id digest, given the per-process salt. Tests may inject one to force collisions.
    using CommandDigest = uint64_t (*)(uint64_t salt, std::string_view command_id);
    /// FNV-1a over the id, started from the salt.
    static uint64_t default_command_digest(uint64_t salt, std::string_view id) noexcept {
        uint64_t h = salt ^ 0xcbf29ce484222325ULL;
        for (const unsigned char c : id) {
            h ^= c;
            h *= 0x100000001b3ULL;
        }
        return h;
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
                                     CommandDigest command_digest = &default_command_digest)
        : capacity_(std::max<std::size_t>(capacity, 1)), max_age_s_(max_age_s),
          per_agent_capacity_(std::max<std::size_t>(per_agent_capacity, 1)),
          command_capacity_(std::max<std::size_t>(command_capacity, 1)),
          marker_capacity_(std::max<std::size_t>(marker_capacity, 1)),
          command_digest_(command_digest), salt_(random_salt()) {}

    /// Record a pair whose answer may be missing, seen at `now_s`. A pair already present keeps its
    /// first-seen time.
    [[nodiscard]] NoteResult note(std::string_view command_id, std::string_view agent_id,
                                  int64_t now_s) {
        const KeyView view{command_digest_(salt_, command_id), agent_id};
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        NoteResult out;
        if (agent_id.size() > kMaxAgentIdBytes) {
            // Not reachable (Register refuses such an id); never stored, so fail closed for all.
            out.latched = latch_locked(now_s);
            return out;
        }
        if (by_key_.contains(view))
            return out;
        if (auto own = by_agent_.find(agent_id);
            own != by_agent_.end() && own->second.size() >= per_agent_capacity_) {
            // Evict this agent's own oldest entry; the agent's marker, set first so a failed
            // allocation loses nothing, stands for it.
            const auto oldest = by_age_.at(*own->second.begin());
            const bool was_marked = markers_.contains(agent_id);
            if (markers_.remember(std::string(agent_id), now_s, next_seq_++, marker_capacity_))
                out.latched |= latch_locked(now_s);
            out.marked = !was_marked;
            erase_locked(oldest);
            ++out.evicted;
        }
        // Insert into all three indexes or none (an allocation failure leaves no orphan).
        const uint64_t seq = next_seq_++;
        const auto entry =
            by_key_.emplace(Key{view.first, std::string(agent_id)}, Entry{now_s, seq}).first;
        try {
            by_age_.emplace(seq, entry);
            by_agent_[entry->first.second].insert(seq);
        } catch (...) {
            by_age_.erase(seq);
            if (auto own = by_agent_.find(agent_id); own != by_agent_.end()) {
                own->second.erase(seq);
                if (own->second.empty())
                    by_agent_.erase(own);
            }
            by_key_.erase(entry);
            throw;
        }
        while (by_key_.size() > capacity_) {
            const auto oldest = by_age_.begin()->second;
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
        const KeyView view{command_digest_(salt_, command_id), agent_id};
        std::lock_guard lock(mu_);
        expire_locked(now_s);
        return now_s < latched_until_s_ || markers_.contains(agent_id) ||
               commands_.contains(view.first) || by_key_.contains(view);
    }

    /// Erase the pair's entry (once its flag is recorded). A marker, a remembered command and the
    /// latch stay until they expire: they stand for other pairs too.
    void forget(std::string_view command_id, std::string_view agent_id) {
        const KeyView view{command_digest_(salt_, command_id), agent_id};
        std::lock_guard lock(mu_);
        if (auto it = by_key_.find(view); it != by_key_.end())
            erase_locked(it);
    }

    /// Pairs held (markers, remembered commands and the latch are not counted).
    [[nodiscard]] std::size_t size() const {
        std::lock_guard lock(mu_);
        return by_key_.size();
    }

private:
    using Key = std::pair<uint64_t, std::string>;          // (salted command digest, agent id)
    using KeyView = std::pair<uint64_t, std::string_view>; // the same, for a lookup
    /// Orders `Key` and `KeyView` alike, so a lookup never copies the agent id.
    struct KeyLess {
        using is_transparent = void;
        template <class A, class B> bool operator()(const A& a, const B& b) const {
            return a.first != b.first ? a.first < b.first
                                      : std::string_view(a.second) < std::string_view(b.second);
        }
    };
    struct Entry {
        int64_t seen_s{0};
        uint64_t seq{0};
    };
    using Entries = std::map<Key, Entry, KeyLess>;

    static uint64_t random_salt() noexcept {
        try {
            std::random_device rd;
            return (static_cast<uint64_t>(rd()) << 32) ^ rd();
        } catch (...) {
            return 0; // the exact agent key, not the salt, keeps agents apart
        }
    }

    /// Ids kept for `max_age_s` after they were last set, oldest dropped past a capacity.
    template <class Id> class AgedSet {
    public:
        template <class K> bool contains(const K& id) const { return items_.contains(id); }

        /// Sets (or refreshes) `id`. True when the set was full and dropped its oldest member.
        bool remember(Id id, int64_t now_s, uint64_t seq, std::size_t capacity) {
            if (auto it = items_.find(id); it != items_.end()) {
                // Refresh in place: re-keying the age node allocates nothing, so it cannot throw.
                auto node = by_age_.extract(it->second.seq);
                node.key() = seq;
                by_age_.insert(std::move(node));
                it->second = Item{now_s, seq};
                return false;
            }
            const auto item = items_.emplace(std::move(id), Item{now_s, seq}).first;
            try {
                by_age_.emplace(seq, item);
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
                if (now_s - oldest->second->second.at_s < max_age_s)
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
        using Items = std::map<Id, Item, std::less<>>;
        Items items_;
        std::map<uint64_t, typename Items::iterator> by_age_; // seq -> item, oldest first
    };

    void erase_locked(Entries::iterator it) {
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
            const auto it = by_age_.begin()->second;
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
    const CommandDigest command_digest_;
    const uint64_t salt_;
    mutable std::mutex mu_;
    Entries by_key_;
    std::map<uint64_t, Entries::iterator> by_age_;                    // insertion order: oldest first
    std::map<std::string, std::set<uint64_t>, std::less<>> by_agent_; // each agent's entries, oldest first
    AgedSet<std::string> markers_; // agents that lost an entry to their own cap
    AgedSet<uint64_t> commands_;   // commands of entries evicted by the global cap
    int64_t latched_until_s_{0};
    uint64_t next_seq_{0};
};

} // namespace yuzu::server
