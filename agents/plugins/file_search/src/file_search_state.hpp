/**
 * file_search_state.hpp -- the in-memory state of the on-demand file search: which volumes an abandoned
 * worker is still blocked in, and how many times one cursor has stalled. Pure: STL only; nothing durable
 * lives here, nothing is serialised and no clock is read.
 *
 * THE AGENT KEEPS NO STATE ACROSS A RESTART. An agent restart forgets both tables: a volume that is still
 * dead costs the next slice one more timeout and one more abandoned worker, and a stall count starts at
 * zero again (bounded by the slice maximum). That is the whole recovery story, and no write-ahead marker,
 * boot id or stored record exists to make it better.
 *
 * STALLED VOLUME. A slice that times out leaves its worker thread blocked in one volume. The pool thread
 * records {volume key, the worker's own done flag}; a volume reads stalled while any recorded worker for it
 * has not set its flag. When the worker returns it sets only that flag, the next slice drops the entry and
 * the volume is searched again. At most kMaxAbandoned workers are recorded: with that many still blocked
 * every search answers busy until one returns.
 *
 * BLOCKED VOLUME QUERIES. The Windows shell asks the system about a volume inside a bounded call, and a call
 * that times out leaves its thread blocked. BlockedQueries records it (the same {key, done flag} record,
 * keyed by the volume's spelling because the query is made before the volume's identity is known) so the
 * shell does not ask again while it is blocked: one blocked query per volume spelling at most, and another
 * volume is unaffected. No cap of its own: one entry per real spelling is the bound.
 *
 * STALL COUNT. record_slice (file_search_governor.hpp) counts consecutive non-advancing attempts on ONE
 * cursor. The count is held here, per lineage (the cursor's query hash, sequence and generation), so the
 * agent is the holder and a caller needs no counter. The map is bounded; the oldest lineage is evicted,
 * and an evicted or never-seen lineage starts at zero. Only a COUNT is kept: a terminal verdict (stalled or
 * unstable) is delivered once, on the slice that reached it, and is not stored, so a later search of the
 * same query, which reaches the same lineage, never inherits a dead search's verdict. `unstable` is
 * re-derived from the cursor's generation on every slice, so forgetting it loses nothing.
 *
 * THREADS. Nothing here is synchronised: a SearchState is touched only by the pool thread that holds the
 * process-wide slot (file_search_driver.hpp), never by a worker.
 */
#pragma once

#include <file_search_cursor.hpp>
#include <file_search_governor.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::file_search {

namespace fsr = yuzu::shared::file_search;

/// Workers still blocked in a volume that the agent remembers.
inline constexpr std::size_t kMaxAbandoned = 2;
/// Cursors whose stall count is remembered.
inline constexpr std::size_t kMaxLineages = 32;

using DoneFlag = std::shared_ptr<std::atomic<bool>>;

[[nodiscard]] inline DoneFlag make_done_flag() { return std::make_shared<std::atomic<bool>>(false); }

struct Abandoned {
    std::string volume; // the volume key (Unit::key in file_search_volumes.hpp); a blocked query's volume spelling
    DoneFlag done;      // set by the abandoned worker, and only by it, when it returns
};

/// Volume queries that timed out and have not returned, one per volume spelling. Touched only by the pool
/// thread that holds the slice slot; a blocked query thread sets only its own done flag.
class BlockedQueries {
public:
    /// True while a query for `volume` has not returned. Forgets every one that has.
    [[nodiscard]] bool blocked(const std::string& volume) {
        std::erase_if(entries_, [](const Abandoned& a) { return a.done->load(std::memory_order_acquire); });
        return std::ranges::any_of(entries_, [&](const Abandoned& a) { return a.volume == volume; });
    }

    /// Records a query left blocked in `volume`; nothing when it has already returned or when one is already
    /// recorded for that volume.
    void add(std::string volume, DoneFlag done) {
        if (!done || done->load(std::memory_order_acquire) || blocked(volume))
            return;
        entries_.push_back({std::move(volume), std::move(done)});
    }

private:
    std::vector<Abandoned> entries_;
};

/// The cursor a slice resumed from: what its stall count belongs to.
struct Lineage {
    fsr::QueryHash query{};
    std::uint64_t sequence{0};
    std::uint32_t generation{0};
    bool operator==(const Lineage&) const = default;
};

class SearchState {
public:
    /// Forgets every abandoned worker that has returned.
    void drop_finished() {
        std::erase_if(abandoned_, [](const Abandoned& a) { return a.done->load(std::memory_order_acquire); });
    }

    [[nodiscard]] std::size_t abandoned_count() const noexcept { return abandoned_.size(); }
    [[nodiscard]] bool abandoned_full() const noexcept { return abandoned_.size() >= kMaxAbandoned; }
    [[nodiscard]] const std::vector<Abandoned>& abandoned() const noexcept { return abandoned_; }

    /// Records a worker left blocked in `volume`. false when the list is full (the caller answers busy
    /// before it can get here: a slice never starts with the list full).
    bool add_abandoned(std::string volume, DoneFlag done) {
        if (abandoned_full() || !done)
            return false;
        abandoned_.push_back({std::move(volume), std::move(done)});
        return true;
    }

    /// True while a recorded worker for `volume` has not returned.
    [[nodiscard]] bool is_stalled(const std::string& volume) const {
        for (const auto& a : abandoned_)
            if (a.volume == volume && !a.done->load(std::memory_order_acquire))
                return true;
        return false;
    }

    /// The governor state remembered for `lineage`; zero when there is none.
    [[nodiscard]] fsr::GovernorState carried(const Lineage& lineage) const {
        for (const auto& l : lineages_)
            if (l.first == lineage)
                return l.second;
        return {};
    }

    /// Remembers `state` for `lineage` as the newest entry, evicting the oldest past kMaxLineages. Only a
    /// healthy state with a stall count is kept: a state with no stall forgets the lineage, and so does a
    /// terminal one (stalled or unstable), which the slice that reached it has already delivered.
    void store(const Lineage& lineage, const fsr::GovernorState& state) {
        std::erase_if(lineages_, [&](const auto& l) { return l.first == lineage; });
        if (state.consecutive_stalls == 0 || state.health != fsr::Health::ok)
            return;
        if (lineages_.size() >= kMaxLineages)
            lineages_.erase(lineages_.begin());
        lineages_.emplace_back(lineage, state);
    }

    [[nodiscard]] std::size_t lineage_count() const noexcept { return lineages_.size(); }

private:
    std::vector<Abandoned> abandoned_;
    std::vector<std::pair<Lineage, fsr::GovernorState>> lineages_; // oldest first
};

} // namespace yuzu::file_search
