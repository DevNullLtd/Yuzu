/**
 * test_file_search_governor.cpp -- unit tests for agents/shared/file_search_governor.hpp: the
 * duty-cycle pacer and the stall/restart bookkeeping. Time and sleep are injected through a fake
 * clock whose sleep advances it; nothing here touches a real clock, thread or filesystem.
 */
#include <catch2/catch_test_macros.hpp>

#include <file_search_governor.hpp>

#include <chrono>
#include <vector>

namespace fs = yuzu::shared::file_search;
using std::chrono::milliseconds;

namespace {
struct FakeClock {
    fs::Clock::time_point t{fs::Clock::time_point{} + std::chrono::hours{1}};
    std::vector<milliseconds> sleeps;
    fs::GovernorEnv env() {
        return {[this] { return t; },
                [this](milliseconds d) {
                    sleeps.push_back(d);
                    t += d;
                }};
    }
    void work(milliseconds d) { t += d; }
};
} // namespace

TEST_CASE("governor: limits validation", "[file_search][governor]") {
    fs::GovernorLimits l;
    CHECK(fs::valid(l));
    l.duty_percent = 0;
    CHECK_FALSE(fs::valid(l));
    l.duty_percent = 101;
    CHECK_FALSE(fs::valid(l));
    l.duty_percent = 100;
    CHECK(fs::valid(l));
    l = {};
    l.slice = milliseconds{0};
    CHECK_FALSE(fs::valid(l));
    l = {};
    l.work_quantum = milliseconds{0};
    CHECK_FALSE(fs::valid(l));
}

TEST_CASE("governor: deadline is construction time plus slice", "[file_search][governor]") {
    FakeClock c;
    const auto start = c.t;
    fs::SliceGovernor g({}, c.env());
    CHECK(g.deadline() == start + milliseconds{10'000});
}

TEST_CASE("governor: 50 percent duty over a slice of per-entry work", "[file_search][governor]") {
    FakeClock c;
    const auto start = c.t;
    const fs::GovernorLimits l;
    fs::SliceGovernor g(l, c.env());

    // One 1 ms entry at a time, pace() per entry, no listing boundary anywhere.
    constexpr milliseconds entry{1};
    milliseconds work_total{0}, since_sleep{0}, max_stretch{0};
    std::size_t seen_sleeps = 0;
    while (c.t < g.deadline()) {
        c.work(entry);
        work_total += entry;
        since_sleep += entry;
        g.pace();
        CHECK(c.t <= g.deadline());
        if (c.sleeps.size() != seen_sleeps) {
            seen_sleeps = c.sleeps.size();
            if (since_sleep > max_stretch)
                max_stretch = since_sleep;
            since_sleep = milliseconds{0};
        }
    }
    CHECK(work_total <= l.slice / 2 + l.work_quantum);
    CHECK(max_stretch <= l.work_quantum + entry);
    CHECK(c.t - start <= l.slice);
    milliseconds sum{0};
    for (auto d : c.sleeps)
        sum += d;
    CHECK(sum > milliseconds{0});
}

TEST_CASE("governor: never sleeps at 100 percent duty", "[file_search][governor]") {
    FakeClock c;
    fs::GovernorLimits l;
    l.duty_percent = 100;
    fs::SliceGovernor g(l, c.env());
    for (int i = 0; i < 200; ++i) {
        c.work(milliseconds{10});
        g.pace();
    }
    CHECK(c.sleeps.empty());
}

TEST_CASE("governor: a zero duty is paced as the gentlest setting, never divided by",
          "[file_search][governor]") {
    FakeClock c;
    fs::GovernorLimits l;
    l.duty_percent = 0; // valid() refuses it; the pacer must still be total
    fs::SliceGovernor g(l, c.env());
    c.work(milliseconds{50});
    g.pace();
    REQUIRE(c.sleeps.size() == 1);
    CHECK(c.sleeps[0] == milliseconds{5'000}); // 50 ms of work at 1 %
}

TEST_CASE("governor: never sleeps at or past the deadline", "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g({}, c.env());
    c.work(milliseconds{10'000});
    g.pace();
    c.work(milliseconds{500});
    g.pace();
    CHECK(c.sleeps.empty());
}

TEST_CASE("governor: never sleeps before one quantum of work", "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g({}, c.env());
    c.work(milliseconds{49});
    g.pace();
    CHECK(c.sleeps.empty());
    c.work(milliseconds{1});
    g.pace();
    REQUIRE(c.sleeps.size() == 1);
    CHECK(c.sleeps[0] == milliseconds{50});
}

TEST_CASE("governor: the sleep is clamped short of the deadline", "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g({}, c.env());
    c.work(milliseconds{9'980}); // 20 ms left; an unclamped sleep would be 9980 ms
    g.pace();
    REQUIRE(c.sleeps.size() == 1);
    CHECK(c.t < g.deadline());
}

TEST_CASE("governor: record_slice stalls after max_stalls non-advancing slices",
          "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    s = fs::record_slice(s, l, false, false);
    s = fs::record_slice(s, l, false, false);
    CHECK(s.health == fs::Health::ok);
    s = fs::record_slice(s, l, false, false);
    CHECK(s.health == fs::Health::stalled);
    CHECK(s.consecutive_stalls == 3);
}

TEST_CASE("governor: an advancing slice resets the stall count", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    s = fs::record_slice(s, l, false, false);
    s = fs::record_slice(s, l, false, false);
    s = fs::record_slice(s, l, true, false);
    CHECK(s.consecutive_stalls == 0);
    s = fs::record_slice(s, l, false, false);
    s = fs::record_slice(s, l, false, false);
    CHECK(s.health == fs::Health::ok);
}

TEST_CASE("governor: a restarted slice is not a stall", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    s = fs::record_slice(s, l, false, false);
    s = fs::record_slice(s, l, false, true);
    CHECK(s.restarts == 1);
    CHECK(s.consecutive_stalls == 1); // unchanged by the restart, advanced or not
    s = fs::record_slice(s, l, true, true);
    CHECK(s.consecutive_stalls == 1);
    CHECK(s.restarts == 2);
}

TEST_CASE("governor: max_restarts gives unstable and health is sticky", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    for (unsigned i = 0; i < l.max_restarts; ++i)
        s = fs::record_slice(s, l, true, true);
    CHECK(s.health == fs::Health::unstable);
    s = fs::record_slice(s, l, true, false);
    CHECK(s.health == fs::Health::unstable);

    fs::GovernorState t;
    for (unsigned i = 0; i < l.max_stalls; ++i)
        t = fs::record_slice(t, l, false, false);
    REQUIRE(t.health == fs::Health::stalled);
    t = fs::record_slice(t, l, true, false);
    CHECK(t.health == fs::Health::stalled);
}
