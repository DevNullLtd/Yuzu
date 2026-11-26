#pragma once

/**
 * win_bounded_run.hpp -- the shell the agent-core Windows reads (win_*.cpp) put around
 * detail::bounded_single_flight. Internal to agent-core.
 */

#include <yuzu/agent/bounded_single_flight.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <string_view>
#include <utility>

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

} // namespace yuzu::agent::win::detail
