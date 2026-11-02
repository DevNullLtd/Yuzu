/**
 * test_reconnect_backoff.cpp — the agent's jittered reconnect delay
 * (reconnect_backoff.hpp, HA WS-13 / #291).
 *
 * The random source is injected, so every case here is deterministic and none
 * waits on a clock. The agent's reconnect LOOP is not exercised end to end here
 * (it needs a live Register path); what is pinned is the schedule it asks for.
 */
#include <yuzu/agent/reconnect_backoff.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <functional>
#include <random>
#include <set>
#include <utility>

using namespace yuzu::agent;

namespace {

/// Records the window it was asked for and returns a fixed pick.
struct FixedSource {
    int pick;
    mutable int calls = 0;
    mutable int last_lo = -1;
    mutable int last_hi = -1;
    int operator()(int lo, int hi) const {
        ++calls;
        last_lo = lo;
        last_hi = hi;
        return pick;
    }
};

std::pair<int, int> window_for(int reconnect_count) {
    FixedSource src{0};
    (void)reconnect_delay_secs(reconnect_count, std::ref(src));
    return {src.last_lo, src.last_hi};
}

} // namespace

static_assert(reconnect_ladder_secs(0) == 0);
static_assert(reconnect_ladder_secs(1) == 2);
static_assert(reconnect_ladder_secs(8) == 256);

TEST_CASE("reconnect_ladder_secs is the 2^n ladder, capped, and zero before the first retry",
          "[agent][reconnect_backoff]") {
    CHECK(reconnect_ladder_secs(-3) == 0);
    CHECK(reconnect_ladder_secs(0) == 0);
    CHECK(reconnect_ladder_secs(1) == 2);
    CHECK(reconnect_ladder_secs(2) == 4);
    CHECK(reconnect_ladder_secs(3) == 8);
    CHECK(reconnect_ladder_secs(7) == 128);
    CHECK(reconnect_ladder_secs(8) == 256);
    // The exponent stops at 8, so the ladder never reaches the 300 s ceiling and a
    // huge count cannot overflow the shift.
    CHECK(reconnect_ladder_secs(9) == 256);
    CHECK(reconnect_ladder_secs(1000) == 256);
    CHECK(reconnect_ladder_secs(INT32_MAX) == 256);
}

TEST_CASE("the first connection attempt does not wait and does not consume randomness",
          "[agent][reconnect_backoff]") {
    FixedSource src{99};
    CHECK(reconnect_delay_secs(0, std::ref(src)) == 0);
    CHECK(reconnect_delay_secs(-1, std::ref(src)) == 0);
    CHECK(src.calls == 0);
}

TEST_CASE("the jitter window is centred on the old ladder: [ladder/2, ladder*3/2], 1 s to 300 s",
          "[agent][reconnect_backoff]") {
    // The first retry used to be exactly 2 s. It is now anywhere in 1..3 s.
    CHECK(window_for(1) == std::pair{1, 3});
    CHECK(window_for(2) == std::pair{2, 6});
    CHECK(window_for(3) == std::pair{4, 12});
    CHECK(window_for(4) == std::pair{8, 24});
    CHECK(window_for(7) == std::pair{64, 192});
    // The top of the ladder: 256 * 3/2 = 384 is clamped to the 300 s ceiling.
    CHECK(window_for(8) == std::pair{128, 300});
    CHECK(window_for(9) == std::pair{128, 300});
    CHECK(window_for(INT32_MAX) == std::pair{128, 300});
}

TEST_CASE("every window is at least 1 s and never above the 300 s ceiling",
          "[agent][reconnect_backoff]") {
    for (int n = 1; n <= 64; ++n) {
        const auto [lo, hi] = window_for(n);
        CAPTURE(n, lo, hi);
        CHECK(lo >= 1);
        CHECK(lo <= hi);
        CHECK(hi <= kMaxReconnectDelaySecs);
    }
}

TEST_CASE("a faulty random source is clamped into the window (no spin, no stall)",
          "[agent][reconnect_backoff]") {
    // Zero or negative would make the reconnect loop spin; huge would stall the agent.
    for (int n : {1, 2, 5, 8, 20}) {
        const auto [lo, hi] = window_for(n);
        CAPTURE(n, lo, hi);
        CHECK(reconnect_delay_secs(n, FixedSource{0}) == lo);
        CHECK(reconnect_delay_secs(n, FixedSource{-100}) == lo);
        CHECK(reconnect_delay_secs(n, FixedSource{INT32_MIN}) == lo);
        CHECK(reconnect_delay_secs(n, FixedSource{1'000'000}) == hi);
        CHECK(reconnect_delay_secs(n, FixedSource{INT32_MAX}) == hi);
    }
}

TEST_CASE("the delay actually spreads: a deterministic ladder would fail this",
          "[agent][reconnect_backoff]") {
    // The regression this guards is the one the change exists to remove: every agent
    // that lost its stream at the same instant choosing the same delay.
    std::mt19937 rng{12345};
    const auto uniform = [&rng](int lo, int hi) {
        return std::uniform_int_distribution<int>{lo, hi}(rng);
    };

    std::set<int> first_retry;
    for (int i = 0; i < 2000; ++i)
        first_retry.insert(reconnect_delay_secs(1, uniform));
    CHECK(first_retry == std::set<int>{1, 2, 3});

    std::set<int> third_retry;
    for (int i = 0; i < 2000; ++i)
        third_retry.insert(reconnect_delay_secs(3, uniform));
    CHECK(third_retry.size() >= 8); // [4, 12] holds nine values

    std::set<int> top;
    for (int i = 0; i < 4000; ++i)
        top.insert(reconnect_delay_secs(8, uniform));
    CHECK(top.size() >= 100); // [128, 300]
}

TEST_CASE("the mean schedule is unchanged below the ceiling (only the spread is new)",
          "[agent][reconnect_backoff]") {
    std::mt19937 rng{777};
    const auto uniform = [&rng](int lo, int hi) {
        return std::uniform_int_distribution<int>{lo, hi}(rng);
    };
    // For n <= 7 the window never meets the 300 s clamp, and its midpoint is exactly the
    // old ladder value, so a fleet's average retry timing is what it was.
    for (int n = 1; n <= 7; ++n) {
        constexpr int kSamples = 20000;
        double sum = 0;
        for (int i = 0; i < kSamples; ++i)
            sum += reconnect_delay_secs(n, uniform);
        const double mean = sum / kSamples;
        const double ladder = reconnect_ladder_secs(n);
        CAPTURE(n, mean, ladder);
        CHECK(mean > ladder * 0.97);
        CHECK(mean < ladder * 1.03);
    }
}
