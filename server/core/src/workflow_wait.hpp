#pragma once

/// @file workflow_wait.hpp
/// The interruptible wait behind a workflow run's retry delay (#2146). A retry delay used to be a
/// bare `sleep_for`, which a shutting-down server could not cut short: a run asleep in a 30 s
/// delay held its HTTP worker, and the drain, for the whole delay. This is a sliced poll (the
/// pattern of the server's background loops): the wake predicate is asked before the first slice
/// and after every slice, so a stop that flips while the run sleeps is seen within one
/// `kInterruptibleWaitSlice`, whatever the total.
///
/// Pure and header-only: no store, no lock, no thread of its own. The clock is injected, so the
/// tests run it on a fake clock whose `sleep_for` advances virtual time.

#include <algorithm>
#include <chrono>
#include <thread>

namespace yuzu::server {

/// The longest the wait sleeps without asking the predicate again.
inline constexpr std::chrono::milliseconds kInterruptibleWaitSlice{250};

enum class WaitResult {
    kElapsed, ///< the whole duration passed and the predicate never said wake
    kWoken,   ///< the predicate said wake (at once, or after some slices)
};

/// The production clock: the steady clock and a real sleep.
struct SteadyWaitClock {
    using duration = std::chrono::steady_clock::duration;
    using time_point = std::chrono::steady_clock::time_point;
    [[nodiscard]] time_point now() const { return std::chrono::steady_clock::now(); }
    void sleep_for(duration d) const { std::this_thread::sleep_for(d); }
};

/// Wait up to `total`, sleeping in slices of at most `slice`, and return `kWoken` as soon as
/// `wake()` is true. `wake` is asked at least once, even for a zero or negative `total`, and
/// always before the first sleep, so a stop that is already set costs no sleep at all. `Clock`
/// supplies `duration`, `time_point`, `now()` and `sleep_for(duration)`.
template <class Wake, class Clock = SteadyWaitClock>
[[nodiscard]] WaitResult
interruptible_wait(typename Clock::duration total, Wake&& wake, Clock clock = Clock{},
                   typename Clock::duration slice = kInterruptibleWaitSlice) {
    const auto end = clock.now() + total;
    for (;;) {
        if (wake())
            return WaitResult::kWoken;
        const auto left = end - clock.now();
        if (left <= typename Clock::duration(0))
            return WaitResult::kElapsed;
        clock.sleep_for(std::min(left, slice));
    }
}

} // namespace yuzu::server
