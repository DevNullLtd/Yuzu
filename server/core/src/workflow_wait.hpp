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
#include <cstdint>
#include <optional>
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

/// The longest retry delay `bounded_retry_delay` returns. Far past anything a workflow stores
/// (create clamps to one hour) and far short of overflowing `clock.now() + delay`.
inline constexpr std::chrono::hours kMaxRetryDelay{24};

/// A retry delay of `seconds` as a steady-clock duration, bounded to `[0, time_left]` when the run
/// has a deadline. The stored value is a column (create clamps it to 0..3600, but the engine does
/// not rely on that): a negative one is no delay, one past `kMaxRetryDelay` saturates there (so
/// `now() + delay` cannot overflow), and the lower bound is taken BEFORE the clamp so
/// `std::clamp`'s `lo <= hi` precondition can never be violated (a negative delay would otherwise
/// invert the bounds). `time_left` may itself be negative (the deadline has passed): the delay is
/// then zero.
[[nodiscard]] inline std::chrono::steady_clock::duration
bounded_retry_delay(std::int64_t seconds,
                    std::optional<std::chrono::steady_clock::duration> time_left) {
    using D = std::chrono::steady_clock::duration;
    constexpr auto kMaxSeconds = std::chrono::duration_cast<std::chrono::seconds>(kMaxRetryDelay).count();
    const std::int64_t floored = std::max<std::int64_t>(seconds, 0);
    D delay = floored >= kMaxSeconds ? D(kMaxRetryDelay) : D(std::chrono::seconds(floored));
    if (time_left)
        delay = std::clamp(*time_left, D::zero(), delay);
    return delay;
}

/// The back-off between two empty lease acquires of a persistent write: the first sleep is the
/// minimum and the sleep doubles up to the maximum.
inline constexpr std::chrono::milliseconds kAcquireBackoffMin{50};
inline constexpr std::chrono::milliseconds kAcquireBackoffMax{250};

/// Keep asking `try_acquire` for a lease until one arrives or `total` is spent, sleeping a back-off
/// slice (50 to 250 ms) after every EMPTY answer. Without the sleep the loop spins: the pool's
/// connect-failure breaker answers an empty lease at once for as long as it is armed, so the
/// retry used to hammer the pool lock a recovering connect needs. `try_acquire(ms)` takes the
/// time left (at least one millisecond) and returns a lease that converts to `true` when it holds
/// one. It runs at least once, whatever `total`.
///
/// SHUTDOWN. The wait is deliberately not cut short by a stop: the write it serves must still
/// get its chance during shutdown. But once `stopping()` is true the deadline is pulled in to
/// `stop_cap` after the moment the stop was first seen. The cap is best-effort: it is only
/// consulted between tries, and a `try_acquire` already in flight (a pool connect can run up to
/// its connect timeout, 10 s) is not interruptible, nor is the first try, which runs whatever the
/// cap. Shutdown stays bounded by the web server's own bound, then the process exits hard.
/// `stopping` is asked after every empty answer.
///
/// Pure and header-only like `interruptible_wait`: the clock is injected.
template <class TryAcquire, class Stopping, class Clock = SteadyWaitClock>
[[nodiscard]] auto acquire_within(typename Clock::duration total, TryAcquire&& try_acquire,
                                  Stopping&& stopping, typename Clock::duration stop_cap,
                                  Clock clock = Clock{}) {
    auto end = clock.now() + total;
    std::optional<typename Clock::time_point> stop_seen;
    typename Clock::duration backoff = kAcquireBackoffMin;
    for (;;) {
        const auto slice = std::max(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - clock.now()),
            std::chrono::milliseconds(1));
        auto lease = try_acquire(slice);
        if (lease)
            return lease;
        if (!stop_seen && stopping()) {
            stop_seen = clock.now();
            end = std::min(end, *stop_seen + stop_cap);
        }
        const auto left = end - clock.now();
        if (left <= typename Clock::duration(0))
            return lease; // empty
        clock.sleep_for(std::min(left, backoff));
        backoff = std::min<typename Clock::duration>(backoff * 2, kAcquireBackoffMax);
    }
}

} // namespace yuzu::server
