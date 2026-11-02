#pragma once

/**
 * reconnect_backoff.hpp -- the agent's reconnect delay, as a pure function.
 *
 * No I/O, no clock, no platform dependency. The random source is INJECTED, so
 * the schedule is unit-testable without waiting or seeding anything.
 *
 * Why this is jittered (HA WS-13, #291): when a gateway node dies, every agent it
 * held loses its Subscribe stream in the same instant. A deterministic 2, 4, 8 ...
 * ladder sends all of them back at exactly the same moments, so the surviving nodes
 * (and the server behind them) take the failed node's whole share (about 1/N of the
 * fleet) as synchronised waves. Spreading each delay over a window removes the waves.
 *
 * The window is centred on the old ladder value up to the 128 s step, so the MEAN delay
 * is unchanged there:
 *
 *     ladder(n) = min(2^n, 256)               n = reconnect_count, capped at 8
 *     delay(n)  = uniform[ ladder/2 , ladder * 3/2 ], at least 1 s, at most 300 s
 *
 * That makes the first retry 1 to 3 s (was exactly 2 s), the second 2 to 6 s, and so
 * on. The delay is never below 1 s, so a misbehaving random source cannot make the
 * reconnect loop spin. At the top step (n >= 8) the 300 s ceiling truncates the window to
 * 128 to 300 s: its mean is 214 s where the old ladder held a fixed 256 s, so the
 * average is NOT unchanged there and the window is not symmetric.
 *
 * Delays are whole seconds, so the first retry lands in three one-second buckets (about
 * a third of the agents that lost a stream together in each). Later retries spread wider.
 * Only a lost-stream retry is covered: a process restart starts again at count 0 with
 * no wait.
 *
 * Note for readers of the old code: its `kMaxReconnectDelaySecs = 300` never bound,
 * because `1 << 8` is 256 and the exponent was capped at 8. 300 s is now the real
 * upper bound of the jittered window.
 *
 * NOT covered here, deliberately: the heartbeat-driven forced re-registration
 * cooldown (`forced_rereg_streak_`, #1894). It is a separate damper keyed on
 * NOT_FOUND / UNAUTHENTICATED heartbeats and is unchanged.
 */

#include <algorithm>
#include <array>
#include <cstdint>

namespace yuzu::agent {

/// Upper bound of a single reconnect delay, in seconds.
inline constexpr int kMaxReconnectDelaySecs = 300;

/// The exponent cap of the ladder (2^8 = 256 s).
inline constexpr int kReconnectLadderMaxExponent = 8;

/// The un-jittered ladder: 2^n seconds, n capped at kReconnectLadderMaxExponent.
/// Returns 0 for `reconnect_count <= 0` (the first connection attempt does not wait).
constexpr int reconnect_ladder_secs(int reconnect_count) noexcept {
    if (reconnect_count <= 0)
        return 0;
    const int n = std::min(reconnect_count, kReconnectLadderMaxExponent);
    return std::min(1 << n, kMaxReconnectDelaySecs);
}

/// The jittered delay to wait before reconnect attempt `reconnect_count`, in seconds.
///
/// `uniform_in(lo, hi)` must return an integer in [lo, hi] (inclusive). Whatever it
/// returns is clamped back into the window, so a faulty source can neither stall the
/// agent beyond the window nor spin the loop.
///
/// Returns 0 for `reconnect_count <= 0`.
template <class UniformIn>
int reconnect_delay_secs(int reconnect_count, UniformIn&& uniform_in) {
    const int ladder = reconnect_ladder_secs(reconnect_count);
    if (ladder == 0)
        return 0;
    const int lo = std::max(1, ladder / 2);
    const int hi = std::min(ladder + ladder / 2, kMaxReconnectDelaySecs);
    return std::clamp(static_cast<int>(uniform_in(lo, hi)), lo, hi);
}

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
/// return a different value per call and per process (clocks, addresses, a counter), never
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
