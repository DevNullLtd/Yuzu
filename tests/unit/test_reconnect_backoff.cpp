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

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <random>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

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

TEST_CASE("simulated fleet: no one-second bucket holds more than a bounded share of retries",
          "[agent][reconnect_backoff]") {
    // The #5990 acceptance shape: 10,000 agents lose their stream at t=0 and every retry
    // fails, so each agent's retry times are the running sum of its delays. The old fixed
    // ladder put ALL 10,000 in one bucket in every round. The source is a plain
    // `lo + engine() % range` on mt19937 (whose raw output is fixed by the standard), not
    // std::uniform_int_distribution, whose output differs between standard libraries.
    //
    // The FIRST round is deliberately bounded loosely: delays are whole seconds in [1,3],
    // so a third of the fleet lands in each of three buckets. This design does not claim to
    // remove the first wave, only to break it into three and to widen it every round.
    constexpr int kAgents = 10'000;
    constexpr int kRounds = 8;
    // Observed with this engine and seed: 3342 2016 1144 608 321 177 92 72. Bounds leave
    // headroom for sampling noise only; the old ladder would read 10000 in every round.
    constexpr int kBound[kRounds] = {3500, 2200, 1300, 700, 400, 250, 150, 120};

    std::mt19937 engine{20261102u};
    const auto uniform = [&engine](int lo, int hi) {
        return lo + static_cast<int>(engine() % static_cast<std::uint32_t>(hi - lo + 1));
    };

    std::vector<int> when(kAgents, 0);
    std::set<int> round_eight_buckets;
    for (int round = 1; round <= kRounds; ++round) {
        std::vector<int> bucket;
        for (int& t : when)
            t += reconnect_delay_secs(round, uniform);
        // Absolute retry second -> agents retrying in it.
        std::vector<int> sorted(when);
        std::sort(sorted.begin(), sorted.end());
        int peak = 0;
        for (std::size_t i = 0; i < sorted.size();) {
            std::size_t j = i;
            while (j < sorted.size() && sorted[j] == sorted[i])
                ++j;
            peak = std::max(peak, static_cast<int>(j - i));
            if (round == kRounds)
                round_eight_buckets.insert(sorted[i]);
            i = j;
        }
        CAPTURE(round, peak);
        CHECK(peak <= kBound[round - 1]);
    }
    // By the last round the fleet is spread over hundreds of distinct seconds.
    CHECK(round_eight_buckets.size() >= 200);
}

TEST_CASE("reconnect_seed: a working entropy source supplies the words and is not degraded",
          "[agent][reconnect_backoff]") {
    int next = 100;
    int fallback_calls = 0;
    const auto seed = reconnect_seed([&next] { return static_cast<unsigned>(next++); },
                                     [&fallback_calls] {
                                         ++fallback_calls;
                                         return 0u;
                                     });
    CHECK_FALSE(seed.degraded);
    CHECK(fallback_calls == 0);
    CHECK(seed.words == std::array<std::uint32_t, 4>{100, 101, 102, 103});
}

TEST_CASE("reconnect_seed: an entropy source that throws degrades to the fallback, never throws",
          "[agent][reconnect_backoff]") {
    // std::random_device throws when no entropy source can be opened. run() has no handler
    // on this path, so an escape would be a std::terminate at agent boot.
    int fallback_calls = 0;
    const auto throwing = []() -> unsigned { throw std::runtime_error{"random_device"}; };
    const auto counting = [&fallback_calls] {
        return 7u + static_cast<unsigned>(fallback_calls++);
    };

    ReconnectSeed seed;
    REQUIRE_NOTHROW(seed = reconnect_seed(throwing, counting));
    CHECK(seed.degraded);
    CHECK(fallback_calls == 4);
    CHECK(seed.words == std::array<std::uint32_t, 4>{7, 8, 9, 10});
}

TEST_CASE("reconnect_seed: a throw part-way through discards the partial words",
          "[agent][reconnect_backoff]") {
    int calls = 0;
    const auto flaky = [&calls]() -> unsigned {
        if (++calls == 3)
            throw std::runtime_error{"entropy went away"};
        return 5u;
    };
    const auto seed = reconnect_seed(flaky, [] { return 9u; });
    CHECK(seed.degraded);
    // All four words come from the fallback; none is a mix of the two sources.
    CHECK(seed.words == std::array<std::uint32_t, 4>{9, 9, 9, 9});
}
