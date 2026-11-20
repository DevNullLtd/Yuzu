#pragma once

/// @file interruptible_wait.hpp
/// `sleep_interruptible`: a long sleep in slices of at most one second that checks a stop predicate
/// between slices, so a command's stagger or delay (up to 600 s) can never hold a command-pool worker
/// past a reconnect or a stop (the pool destructor joins every worker, and an uninterruptible sleep
/// made that join wait the whole delay). Pure apart from the injected sleep.

#include <algorithm>
#include <chrono>
#include <thread>
#include <utility>

namespace yuzu::agent {

inline constexpr std::chrono::milliseconds kWaitSlice{1000};

/// Sleeps `total` in slices of at most `kWaitSlice`; `stop()` is checked BEFORE every slice. Returns
/// true when the whole duration elapsed, false when `stop()` interrupted it. `sleep_for(duration)` is
/// injectable so a test can count slices without real time.
template <typename StopFn, typename SleepFn>
[[nodiscard]] bool sleep_interruptible(std::chrono::milliseconds total, StopFn&& stop, SleepFn&& sleep_for) {
    auto left = total;
    while (left.count() > 0) {
        if (stop())
            return false;
        const auto slice = std::min(left, kWaitSlice);
        sleep_for(slice);
        left -= slice;
    }
    return !stop();
}

template <typename StopFn>
[[nodiscard]] bool sleep_interruptible(std::chrono::milliseconds total, StopFn&& stop) {
    return sleep_interruptible(total, std::forward<StopFn>(stop),
                               [](std::chrono::milliseconds d) { std::this_thread::sleep_for(d); });
}

} // namespace yuzu::agent
