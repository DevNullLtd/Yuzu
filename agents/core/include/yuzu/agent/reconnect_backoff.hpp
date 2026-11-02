#pragma once

/**
 * reconnect_backoff.hpp -- the agent's reconnect delay, as a pure function of its
 * own previous delay.
 *
 * No I/O, no clock, no platform dependency. The random source is INJECTED, so the
 * schedule is unit-testable without waiting or seeding anything.
 *
 * Decorrelated jitter (owner decision on #5990, 2026-10-17; Marc Brooker, "Exponential
 * Backoff And Jitter", AWS Architecture Blog, 2015):
 *
 *     delay = min( cap , random_between( base , previous_delay * 3 ) )
 *
 * with base 1 s, cap 300 s, and previous_delay set back to base after a successful
 * Register. The first retry is therefore 1 to 3 s.
 *
 * Why this exists (HA WS-13, #291, #5990): the delay used to be a fixed 2, 4, 8 ... 256 s
 * ladder, so every agent that lost the same gateway node or server came back at the same
 * instants, wave after wave. Each delay now depends on the agent's OWN previous delay
 * and a random draw, not on the retry number, so agents that start together drift apart.
 *
 * Behaviour a reader should know:
 *   - The FIRST retry is whole seconds in 1..3, so a cohort that lost a stream together
 *     still lands in three one-second buckets (about a third each). The spread widens with
 *     every retry; this scheme does not remove the first wave, it breaks it into three.
 *   - The delay is never below base (1 s), so a misbehaving random source cannot make the
 *     reconnect loop spin, and never above cap (300 s) nor three times the previous delay.
 *   - The MEAN delay grows about 1.5x per retry (the old ladder doubled), but a typical
 *     single agent's delay grows much more slowly, so in a long outage an agent retries
 *     about twice as often as the old ladder did. Simulated, 30 minutes down: a mean of
 *     about 28 attempts against 13 for the old ladder, and a steady-state mean delay of
 *     about 135 s against 256 s. That is the cost of the faster recovery and the
 *     better spread; it is the owner's choice on #5990.
 *   - When previous_delay * 3 exceeds the cap, a draw above the cap becomes the cap
 *     itself, so the cap carries extra probability mass (this is the formula as decided).
 *
 * NOT covered here, deliberately: the heartbeat-driven forced re-registration cooldown
 * (`forced_rereg_streak_`, #1894). It is a separate damper keyed on NOT_FOUND /
 * UNAUTHENTICATED heartbeats and is unchanged.
 */

#include <algorithm>
#include <array>
#include <cstdint>

namespace yuzu::agent {

/// Smallest reconnect delay and the value `previous_delay` returns to after a success.
inline constexpr int kReconnectBaseSecs = 1;

/// Upper bound of a single reconnect delay, in seconds.
inline constexpr int kMaxReconnectDelaySecs = 300;

/// A delay is drawn from [base, previous_delay * this].
inline constexpr int kReconnectGrowthFactor = 3;

/// Decorrelated-jitter reconnect delay. Owns the one piece of state the scheme needs: the
/// previous delay. Single-threaded by design (the agent's reconnect loop is on one thread).
class ReconnectBackoff {
public:
    /// The delay most recently returned by next(), or the base after reset().
    constexpr int previous() const noexcept { return previous_; }

    /// Registration succeeded: the next failure starts again from the base.
    constexpr void reset() noexcept { previous_ = kReconnectBaseSecs; }

    /// The delay to wait before the next attempt, in seconds, and the new `previous_delay`.
    ///
    /// `uniform_in(lo, hi)` must return an integer in [lo, hi] (inclusive). Whatever it
    /// returns is clamped back into that window, so a faulty source can neither spin the
    /// loop (below base) nor exceed three times the previous delay.
    template <class UniformIn>
    int next(UniformIn&& uniform_in) {
        const int hi = previous_ * kReconnectGrowthFactor;
        const int pick = std::clamp(static_cast<int>(uniform_in(kReconnectBaseSecs, hi)),
                                    kReconnectBaseSecs, hi);
        previous_ = std::min(pick, kMaxReconnectDelaySecs);
        return previous_;
    }

private:
    int previous_ = kReconnectBaseSecs;
};

/// Words that seed the agent's reconnect random engine, and whether they are the degraded
/// kind.
struct ReconnectSeed {
    std::array<std::uint32_t, 4> words{};
    bool degraded = false; ///< true when `entropy` failed and `fallback` supplied the words
};

/// Builds the seed words. `entropy()` is the OS source (it may THROW, as
/// std::random_device does when no entropy source can be opened); if it does, every word
/// comes from `fallback()` instead and `degraded` is set, so a failed entropy source costs
/// the agent seed quality (a weak seed is fine for jitter, which is not a secret) and never
/// a std::terminate on a path that has no handler. `fallback` must not throw and should
/// return a different value per call and per process (clocks, a thread id, a counter), never
/// a constant, or agents cloned from one image would share a sequence.
template <class Entropy, class Fallback>
ReconnectSeed reconnect_seed(Entropy&& entropy, Fallback&& fallback) {
    ReconnectSeed seed;
    try {
        for (auto& w : seed.words)
            w = static_cast<std::uint32_t>(entropy());
    } catch (...) {
        seed.degraded = true;
        for (auto& w : seed.words)
            w = static_cast<std::uint32_t>(fallback());
    }
    return seed;
}

} // namespace yuzu::agent
