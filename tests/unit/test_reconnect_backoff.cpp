/**
 * test_reconnect_backoff.cpp -- the agent's decorrelated-jitter reconnect delay
 * (reconnect_backoff.hpp, #5990 / HA WS-13 / #291).
 *
 * The random source is injected, so every case here is deterministic and none
 * waits on a clock. The agent's reconnect LOOP is not exercised end to end here
 * (it needs a live Register path); what is pinned is the schedule it asks for.
 */
#include <yuzu/agent/reconnect_backoff.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
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

/// Always picks the top of the window (the fastest possible growth).
struct TopSource {
    mutable int last_hi = -1;
    int operator()(int, int hi) const {
        last_hi = hi;
        return hi;
    }
};

/// `lo + engine() % range` on mt19937, whose raw output is fixed by the standard (unlike
/// std::uniform_int_distribution, whose output differs between standard libraries), so the
/// simulation numbers below are reproducible everywhere.
struct EngineSource {
    std::mt19937& engine;
    int operator()(int lo, int hi) const {
        return lo + static_cast<int>(engine() % static_cast<std::uint32_t>(hi - lo + 1));
    }
};

} // namespace

static_assert(kReconnectBaseSecs == 1);
static_assert(kMaxReconnectDelaySecs == 300);
static_assert(ReconnectBackoff{}.previous() == 1);

TEST_CASE("a new backoff starts at the base, and the first retry is drawn from 1..3 s",
          "[agent][reconnect_backoff]") {
    ReconnectBackoff b;
    CHECK(b.previous() == 1);
    FixedSource src{0};
    (void)b.next(src);
    CHECK(src.last_lo == 1);
    CHECK(src.last_hi == 3);
}

TEST_CASE("each window is [base, 3 x the previous delay]; the delay is capped at 300 s",
          "[agent][reconnect_backoff]") {
    // Always picking the top of the window is the fastest the delay can grow:
    // 3, 9, 27, 81, 243, then the cap. The window itself keeps widening (3 x 300 = 900),
    // so a draw above the cap becomes the cap.
    ReconnectBackoff b;
    TopSource src;
    const int expected[] = {3, 9, 27, 81, 243, 300, 300, 300};
    const int expected_hi[] = {3, 9, 27, 81, 243, 729, 900, 900};
    for (int i = 0; i < 8; ++i) {
        CAPTURE(i);
        CHECK(b.next(src) == expected[i]);
        CHECK(src.last_hi == expected_hi[i]);
        CHECK(b.previous() == expected[i]);
    }
}

TEST_CASE("a faulty random source is clamped into the window (no spin, no stall)",
          "[agent][reconnect_backoff]") {
    // Below the base would make the reconnect loop spin; above the window would break the
    // 3 x previous bound.
    for (int pick : {0, -1, -100, INT_MIN}) {
        ReconnectBackoff b;
        CAPTURE(pick);
        CHECK(b.next(FixedSource{pick}) == kReconnectBaseSecs);
        CHECK(b.previous() == kReconnectBaseSecs);
    }
    for (int pick : {1'000'000, INT_MAX}) {
        ReconnectBackoff b;
        CAPTURE(pick);
        CHECK(b.next(FixedSource{pick}) == 3);   // 3 x base
        CHECK(b.next(FixedSource{pick}) == 9);   // 3 x 3
    }
    // At the cap a huge pick is the cap, not 900.
    ReconnectBackoff b;
    for (int i = 0; i < 10; ++i)
        (void)b.next(FixedSource{INT_MAX});
    CHECK(b.previous() == kMaxReconnectDelaySecs);
}

TEST_CASE("after a successful Register the next failure starts again from the base",
          "[agent][reconnect_backoff]") {
    ReconnectBackoff b;
    TopSource top;
    for (int i = 0; i < 5; ++i)
        (void)b.next(top);
    REQUIRE(b.previous() == 243);

    b.reset();
    CHECK(b.previous() == kReconnectBaseSecs);
    FixedSource src{0};
    (void)b.next(src);
    CHECK(src.last_hi == 3);

    // Without a reset the delay keeps growing: the enrolled-but-no-cert retry relies on this.
    ReconnectBackoff c;
    (void)c.next(top);
    (void)c.next(top);
    CHECK(c.previous() == 9);
}

TEST_CASE("every delay is in [base, cap] and never more than 3 x the previous (200,000 draws)",
          "[agent][reconnect_backoff]") {
    std::mt19937 engine{424242u};
    EngineSource src{engine};
    ReconnectBackoff b;
    int previous = kReconnectBaseSecs;
    int longest = 0;
    for (int i = 0; i < 200'000; ++i) {
        const int d = b.next(src);
        if (d < kReconnectBaseSecs || d > kMaxReconnectDelaySecs || d > 3 * previous) {
            CAPTURE(i, d, previous);
            FAIL("delay out of bounds");
        }
        longest = std::max(longest, d);
        previous = d;
    }
    // The cap is reached, so the bound above was not vacuous.
    CHECK(longest == kMaxReconnectDelaySecs);
}

TEST_CASE("the delay actually spreads: a deterministic ladder would fail this",
          "[agent][reconnect_backoff]") {
    std::mt19937 engine{12345u};
    EngineSource src{engine};

    std::set<int> first;
    for (int i = 0; i < 2000; ++i) {
        ReconnectBackoff b;
        first.insert(b.next(src));
    }
    CHECK(first == std::set<int>{1, 2, 3});

    // From a previous delay of 27 the window is 1..81: the draws cover most of it.
    std::set<int> from_ten;
    for (int i = 0; i < 4000; ++i) {
        ReconnectBackoff b;
        (void)b.next(FixedSource{3});  // previous = 3
        (void)b.next(FixedSource{9});  // previous = 9
        (void)b.next(FixedSource{27}); // previous = 27
        from_ten.insert(b.next(src));  // window 1..81
    }
    CHECK(from_ten.size() >= 70);
}

TEST_CASE("simulated fleet: no one-second bucket holds more than a bounded share of retries",
          "[agent][reconnect_backoff]") {
    // The #5990 simulation: 10,000 agents lose their stream at t=0 and every retry fails,
    // so each agent's retry times are the running sum of its own delays. The old fixed
    // ladder put ALL 10,000 in one bucket in every round.
    //
    // The FIRST round is deliberately bounded loosely: delays are whole seconds in 1..3,
    // so a third of the fleet lands in each of three buckets. This scheme does not remove
    // the first wave, only breaks it into three and widens the spread every round.
    constexpr int kAgents = 10'000;
    constexpr int kRounds = 8;
    // Observed with this engine and seed (see the commit message); the bounds leave headroom
    // for sampling noise only.
    constexpr int kBound[kRounds] = {3500, 2300, 1300, 700, 480, 340, 260, 200};

    std::mt19937 engine{20261102u};
    EngineSource src{engine};
    std::vector<ReconnectBackoff> agents(kAgents);
    std::vector<int> when(kAgents, 0);
    std::set<int> last_round_buckets;
    for (int round = 1; round <= kRounds; ++round) {
        for (int i = 0; i < kAgents; ++i)
            when[static_cast<std::size_t>(i)] += agents[static_cast<std::size_t>(i)].next(src);
        std::vector<int> sorted(when);
        std::sort(sorted.begin(), sorted.end());
        int peak = 0;
        for (std::size_t i = 0; i < sorted.size();) {
            std::size_t j = i;
            while (j < sorted.size() && sorted[j] == sorted[i])
                ++j;
            peak = std::max(peak, static_cast<int>(j - i));
            if (round == kRounds)
                last_round_buckets.insert(sorted[i]);
            i = j;
        }
        CAPTURE(round, peak);
        CHECK(peak <= kBound[round - 1]);
    }
    // By the last round the fleet is spread over hundreds of distinct seconds (751 or more
    // in every seed tried).
    CHECK(last_round_buckets.size() >= 600);
}

TEST_CASE("a long outage costs about twice the retries of the old ladder (the documented trade)",
          "[agent][reconnect_backoff]") {
    // The decision on #5990 trades load for recovery speed: in a sustained outage an agent
    // retries more often than the old 2, 4 ... 256 s ladder did. The figures in the
    // documentation come from this simulation, so a change to the formula that moves them
    // fails here and the documentation has to be revisited.
    constexpr int kAgents = 3000;
    constexpr int kHorizonSecs = 1800;
    std::mt19937 engine{777u};
    EngineSource src{engine};
    long total = 0;
    for (int a = 0; a < kAgents; ++a) {
        ReconnectBackoff b;
        int t = 0;
        int attempts = 0;
        for (;;) {
            t += b.next(src);
            if (t > kHorizonSecs)
                break;
            ++attempts;
        }
        total += attempts;
    }
    const double mean = static_cast<double>(total) / kAgents;

    int old_attempts = 0;
    for (int t = 0, n = 1;; ++n) {
        t += std::min(1 << std::min(n, 8), 300);
        if (t > kHorizonSecs)
            break;
        ++old_attempts;
    }
    CAPTURE(mean, old_attempts);
    CHECK(old_attempts == 13);
    CHECK(mean > 24.0);
    CHECK(mean < 33.0);
}

TEST_CASE("reconnect_seed: a working entropy source supplies the words and is not degraded",
          "[agent][reconnect_backoff]") {
    int next = 100;
    int entropy_calls = 0;
    int fallback_calls = 0;
    const auto seed = reconnect_seed([&next, &entropy_calls] {
                                         ++entropy_calls;
                                         return static_cast<unsigned>(next++);
                                     },
                                     [&fallback_calls] {
                                         ++fallback_calls;
                                         return 0u;
                                     });
    CHECK_FALSE(seed.degraded);
    CHECK(fallback_calls == 0);
    CHECK(entropy_calls == 4);
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
