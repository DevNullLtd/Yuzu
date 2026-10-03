#pragma once

/**
 * wall_clock_step.hpp -- in-process detection of a FORWARD wall-clock step by
 * comparing CONSECUTIVE (wall, monotonic) samples. Portable: std only; the
 * one impure function is sample_clocks().
 *
 * Why consecutive samples, not a comparison against the startup sample: a
 * startup-relative check misses a backward step that is later restored (the
 * restoration looks like a plain return to the startup baseline) and never
 * recovers from a permanent forward correction. Comparing consecutive samples
 * sees the restoration itself as a forward step, and a detected step
 * quarantines the caller for `quarantine_s` of MONOTONIC time -- long enough
 * that every object created before the step has a real age beyond the
 * caller's staleness threshold, so work resumes by itself without a restart.
 *
 * Only forward steps are acted on: a backward step merely makes entries look
 * fresher (age shrinks), which can delay a cleanup but never trigger one early.
 * Nothing is persisted; the first sample a caller takes has no predecessor and
 * is accepted as-is by construction (the caller seeds `ClockStepGuard::last`).
 *
 * Suspend/resume: where the monotonic clock excludes sleep (Linux
 * CLOCK_MONOTONIC, Darwin mach_absolute_time) a resume reads as a forward step
 * and costs one quarantine of delayed work -- fail-safe, never an early
 * deletion. On Windows std::steady_clock is QueryPerformanceCounter, which
 * counts time asleep, so a resume is not read as a step.
 */

#include <chrono>
#include <cstdint>
#include <limits>

namespace yuzu::shared {

struct ClockSample {
    std::int64_t wall_s;   ///< seconds since the system_clock epoch
    std::int64_t steady_s; ///< seconds on the monotonic clock (arbitrary epoch)
};

[[nodiscard]] inline ClockSample sample_clocks() {
    using namespace std::chrono;
    return {duration_cast<seconds>(system_clock::now().time_since_epoch()).count(),
            duration_cast<seconds>(steady_clock::now().time_since_epoch()).count()};
}

/// True when the wall clock advanced more than `tolerance_s` faster than the
/// monotonic clock between `prev` and `now`. Strictly greater: equality is no step.
[[nodiscard]] constexpr bool stepped_forward(const ClockSample& prev, const ClockSample& now,
                                             std::int64_t tolerance_s) noexcept {
    return (now.wall_s - prev.wall_s) - (now.steady_s - prev.steady_s) > tolerance_s;
}

struct ClockStepGuard {
    ClockSample last{0, 0};
    std::int64_t quarantine_until_steady_s = (std::numeric_limits<std::int64_t>::min)();
};

/// Records `now` as the new `last` sample; returns true while the caller must
/// skip (a forward step was seen within the past `quarantine_s` of monotonic time).
[[nodiscard]] constexpr bool observe_and_should_skip(ClockStepGuard& g, const ClockSample& now,
                                                     std::int64_t tolerance_s,
                                                     std::int64_t quarantine_s) noexcept {
    if (stepped_forward(g.last, now, tolerance_s))
        g.quarantine_until_steady_s = now.steady_s + quarantine_s;
    g.last = now;
    return now.steady_s < g.quarantine_until_steady_s;
}

} // namespace yuzu::shared
