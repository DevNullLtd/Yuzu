#pragma once

/**
 * win_bounded_run.hpp -- the shell the agent-core Windows reads (win_*.cpp) put around
 * detail::bounded_single_flight, and the one page loop their Net* enumerations share. Internal to
 * agent-core. Portable, with no Windows type, so both are tested on every OS.
 */

#include <yuzu/agent/bounded_single_flight.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent::win::detail {

/// A slot that is never destroyed, so an abandoned worker's release never touches a destroyed
/// mutex. For a namespace-scope reference, one per read.
inline SingleFlightSlot& new_slot() {
    return *new SingleFlightSlot;
}

/// One bounded read through `slot`, waiting inside `deadline` for a healthy read already in
/// flight. Returns what `fn` returned, or a default Result if it did not complete; Result::status
/// says which. `what` names the read in the log.
template <typename Result, typename Fn>
Result run_bounded_read(SingleFlightSlot& slot, std::chrono::milliseconds deadline,
                        std::string_view what, Fn fn) {
    auto flight = ::yuzu::agent::detail::bounded_single_flight(
        slot, deadline, SlotWait::within_deadline, std::move(fn));
    Result out = flight.value ? std::move(*flight.value) : Result{};
    out.status = flight.status;
    switch (flight.status) {
    case BoundedStatus::Completed:
        break;
    case BoundedStatus::TimedOut:
        spdlog::warn("{}: no answer (deadline {} ms)", what, deadline.count());
        break;
    case BoundedStatus::Busy:
    case BoundedStatus::Abandoned:
    case BoundedStatus::Rejected:
        spdlog::debug("{}: no answer ({})", what, bounded_cause(flight.status));
        break;
    }
    return out;
}

/// What one call of a paged Net* enumeration (NetSessionEnum, NetUserEnum,
/// NetLocalGroupGetMembers) answered.
template <typename T> struct NetPage {
    std::uint32_t status = 0;    ///< the call's NET_API_STATUS
    std::uint32_t raw_count = 0; ///< entries the call read, including any not copied to `entries`
    std::vector<T> entries;
};

/// Every page of one enumeration.
template <typename T> struct Drained {
    std::uint32_t nerr = 0;   ///< status of a failed call, else 0; never 234 (ERROR_MORE_DATA)
    bool truncated = false;   ///< cut: the entry past the cap, or a more-data page that fills it
    bool no_progress = false; ///< the pages stopped advancing, or reached kMaxNetPages
    std::vector<T> items;
};

/// Far more pages than a real result set needs.
inline constexpr unsigned kMaxNetPages = 4096;

/// Calls `next_page()`, which returns a NetPage<T>, until a page answers status 0. The drain ends
/// early, keeping the entries already taken, at a failed page (nerr), at the entry past the cap,
/// or a more-data page that fills it (truncated; the cap is `max_entries`), and at an
/// ERROR_MORE_DATA page that read nothing or is the kMaxNetPages-th (no_progress), so a provider
/// that always has more cannot spin an abandoned worker for ever.
template <typename T, typename PageFn>
Drained<T> drain_net_pages(std::size_t max_entries, PageFn next_page) {
    constexpr std::uint32_t kMoreData = 234; // ERROR_MORE_DATA
    Drained<T> out;
    for (unsigned pages = 1;; ++pages) {
        NetPage<T> page = next_page();
        if (page.status != 0 && page.status != kMoreData) {
            out.nerr = page.status;
            return out;
        }
        for (T& entry : page.entries) {
            if (out.items.size() >= max_entries) {
                out.truncated = true;
                return out;
            }
            out.items.push_back(std::move(entry));
        }
        if (page.status == 0)
            return out;
        if (out.items.size() >= max_entries) { // full, and more to come: no further call
            out.truncated = true;
            return out;
        }
        if (page.raw_count == 0 || pages >= kMaxNetPages) {
            out.no_progress = true;
            return out;
        }
    }
}

} // namespace yuzu::agent::win::detail
