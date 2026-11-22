/**
 * test_file_search_governor.cpp -- unit tests for agents/shared/file_search_governor.hpp: the
 * duty-cycle pacer with its adaptive listing back-off and the stall/restart bookkeeping. Time and
 * sleep are injected through a fake clock whose sleep advances it; nothing here touches a real clock,
 * thread or filesystem.
 *
 * MUTATION NOTES (each case FAILS if the named rule is removed):
 *  - back-off: a note_listing that never lengthens the pause, a doubling with no cap, a back-off not
 *    bounded by half of the remaining room, or one that never relaxes fails the back-off cases.
 *  - golden: any change to the healthy-disk arithmetic fails the golden case and the original pacing cases.
 *  - overflow: an unclamped span or limit fails the extreme-duration case.
 */
#include <catch2/catch_test_macros.hpp>

#include <file_search_governor.hpp>

#include <algorithm>
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
    l = {};
    l.work_quantum = l.slice + milliseconds{1}; // a quantum longer than the slice never paces
    CHECK_FALSE(fs::valid(l));
    l.work_quantum = l.slice;
    l.max_backoff_pause = l.slice; // a back-off cap below one quantum is refused (checked below)
    CHECK(fs::valid(l));
    l = {};
    l.slice = fs::kMaxSlice;
    CHECK(fs::valid(l));
    l.slice += milliseconds{1}; // the bound is far below the slice that overflows the deadline sum
    CHECK_FALSE(fs::valid(l));
}

TEST_CASE("governor: a zero max_stalls or max_restarts is refused, not read as one",
          "[file_search][governor]") {
    fs::GovernorLimits l;
    l.max_stalls = 0;
    CHECK_FALSE(fs::valid(l));
    l.max_stalls = 1;
    CHECK(fs::valid(l));
    l = {};
    l.max_restarts = 0;
    CHECK_FALSE(fs::valid(l));
    l.max_restarts = 1;
    CHECK(fs::valid(l));
}

TEST_CASE("governor: the default limits are the ruled slice, entry and row budgets",
          "[file_search][governor]") {
    const fs::GovernorLimits l;
    CHECK(l.slice == milliseconds{10'000});
    CHECK(l.max_entries == 400'000);
    CHECK(l.max_rows == 1'000);
    CHECK(l.max_stalls == 3);
    CHECK(l.max_restarts == 3);
    CHECK(l.slow_list_floor == milliseconds{20}); // the back-off defaults are reasoned, not measured
    CHECK(l.slow_list_ratio == 4);
    CHECK(l.slow_list_hard == milliseconds{250});
    CHECK(l.max_backoff_pause == milliseconds{1'000});
    CHECK(fs::valid(l));
}

TEST_CASE("governor: deadline is construction time plus slice", "[file_search][governor]") {
    FakeClock c;
    const auto start = c.t;
    fs::SliceGovernor g({}, c.env());
    CHECK(g.deadline() == start + milliseconds{10'000});
    fs::GovernorLimits l; // valid() refuses both; an unvalidated slice is clamped, never overflowed
    l.slice = milliseconds::max();
    CHECK(fs::SliceGovernor(l, c.env()).deadline() == start + std::chrono::hours{1});
    l.slice = milliseconds{-1};
    CHECK(fs::SliceGovernor(l, c.env()).deadline() == start);
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
    c.work(milliseconds{200}); // the nap follows the work measured since the last sleep ENDED
    g.pace();
    CHECK(c.sleeps.back() == milliseconds{200});
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
    s = fs::record_slice(s, l, false, false, 0);
    s = fs::record_failed_slice(s, l, 0); // no result (threw, timed out, refused): a stall too
    CHECK(s.health == fs::Health::ok);
    s = fs::record_slice(s, l, false, false, 0);
    CHECK(s.health == fs::Health::stalled);
    CHECK(s.consecutive_stalls == 3);
}

TEST_CASE("governor: an advancing slice resets the stall count", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    s = fs::record_slice(s, l, false, false, 0);
    s = fs::record_slice(s, l, false, false, 0);
    s = fs::record_slice(s, l, true, false, 0);
    CHECK(s.consecutive_stalls == 0);
    s = fs::record_slice(s, l, false, false, 0);
    s = fs::record_slice(s, l, false, false, 0);
    CHECK(s.health == fs::Health::ok);
}

TEST_CASE("governor: a restarted slice is not a stall", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    s = fs::record_slice(s, l, false, false, 0);
    s = fs::record_slice(s, l, false, true, 0);
    CHECK(s.restarts == 1);
    CHECK(s.consecutive_stalls == 1); // unchanged by the restart, advanced or not
    s = fs::record_slice(s, l, true, true, 0); // replayed after a lost response: counted once
    CHECK(s.consecutive_stalls == 1);
    CHECK(s.restarts == 1);
    s = fs::record_slice(s, l, true, true, 1); // the next cursor's restart is the second
    CHECK(s.restarts == 2);
}

TEST_CASE("governor: max_restarts gives unstable and health is sticky", "[file_search][governor]") {
    const fs::GovernorLimits l;
    fs::GovernorState s;
    for (unsigned i = 0; i < l.max_restarts; ++i)
        s = fs::record_slice(s, l, true, true, i);
    CHECK(s.health == fs::Health::unstable);
    for (unsigned i = 0; i < l.max_stalls; ++i) // later stalls keep the first terminal state
        s = fs::record_slice(s, l, false, false, l.max_restarts);
    CHECK(s.health == fs::Health::unstable);

    fs::GovernorState t;
    for (unsigned i = 0; i < l.max_stalls; ++i)
        t = fs::record_slice(t, l, false, false, 0);
    REQUIRE(t.health == fs::Health::stalled);
    t = fs::record_slice(t, l, true, false, l.max_restarts); // nor does a spent restart budget
    CHECK(t.health == fs::Health::stalled);
    // The verdict follows from the cursor alone: a caller that kept no state reaches it too.
    CHECK(fs::record_slice({}, l, true, true, l.max_restarts - 1).health == fs::Health::unstable);
    CHECK(fs::record_slice({}, l, true, false, l.max_restarts).health == fs::Health::unstable);
    CHECK(fs::record_failed_slice({}, l, l.max_restarts).health == fs::Health::unstable);
    CHECK(fs::record_slice({}, l, true, true, 0xFFFFFFFFu).restarts == 4294967296ull); // 64-bit sum
    fs::GovernorLimits zero;
    zero.max_restarts = 0; // acts as 1: unstable at the first restart, not before it
    CHECK(fs::record_slice({}, zero, true, false, 0).health == fs::Health::ok);
    CHECK(fs::record_slice({}, zero, true, true, 0).health == fs::Health::unstable);
}

// ---- the adaptive listing back-off ----

namespace {
// One listing as the driver reports it: the listing's own time passes, then it is noted, then the next
// pace() call (the next entry or listing) takes the nap.
void listing(FakeClock& c, fs::SliceGovernor& g, milliseconds took) {
    c.work(took);
    g.note_listing(took);
    g.pace();
}

fs::GovernorLimits backoff_only() {
    fs::GovernorLimits l;
    l.duty_percent = 100; // no duty nap: every sleep is the back-off alone
    return l;
}
} // namespace

TEST_CASE("governor: each back-off limit is validated", "[file_search][governor]") {
    fs::GovernorLimits l;
    l.slow_list_floor = milliseconds{0};
    CHECK_FALSE(fs::valid(l));
    l = {};
    l.slow_list_floor = milliseconds{-5};
    CHECK_FALSE(fs::valid(l));
    l = {};
    l.slow_list_hard = l.slow_list_floor - milliseconds{1}; // hard below the floor never fires alone
    CHECK_FALSE(fs::valid(l));
    l.slow_list_hard = l.slow_list_floor;
    CHECK(fs::valid(l));
    l = {};
    l.slow_list_hard = l.slice; // at the slice is the largest accepted
    CHECK(fs::valid(l));
    l.slow_list_hard = l.slice + milliseconds{1};
    CHECK_FALSE(fs::valid(l));
    l = {};
    l.slow_list_ratio = 1;
    CHECK_FALSE(fs::valid(l));
    l.slow_list_ratio = 2;
    CHECK(fs::valid(l));
    l.slow_list_ratio = 64;
    CHECK(fs::valid(l));
    l.slow_list_ratio = 65;
    CHECK_FALSE(fs::valid(l));
    l = {};
    l.max_backoff_pause = l.work_quantum - milliseconds{1}; // below one quantum
    CHECK_FALSE(fs::valid(l));
    l.max_backoff_pause = l.work_quantum;
    CHECK(fs::valid(l));
    l.max_backoff_pause = l.slice;
    CHECK(fs::valid(l));
    l.max_backoff_pause = l.slice + milliseconds{1};
    CHECK_FALSE(fs::valid(l));
}

TEST_CASE("governor: the pause grows under a slow sequence and relaxes after recovery",
          "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g(backoff_only(), c.env());
    // Seven listings at the hard bound: the back-off starts at one quantum, doubles, and stops at the cap.
    for (int i = 0; i < 7; ++i)
        listing(c, g, milliseconds{300});
    CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{50}, milliseconds{100}, milliseconds{200},
                                                milliseconds{400}, milliseconds{800}, milliseconds{1'000},
                                                milliseconds{1'000}});
    // Fast listings halve it each time, and one below a quantum is dropped.
    c.sleeps.clear();
    for (int i = 0; i < 6; ++i) {
        c.work(milliseconds{60}); // other work: enough for pace() to nap
        g.note_listing(milliseconds{1});
        g.pace();
    }
    CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{500}, milliseconds{250}, milliseconds{125},
                                                milliseconds{62}});
}

TEST_CASE("governor: the back-off adds to the duty nap and never replaces it", "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g({}, c.env()); // 50 % duty
    c.work(milliseconds{300});
    g.note_listing(milliseconds{300}); // at or over the hard bound: slow
    g.pace();
    REQUIRE(c.sleeps.size() == 1);
    CHECK(c.sleeps[0] == milliseconds{350}); // 300 ms of work at 50 % duty, plus one quantum of back-off
}

TEST_CASE("governor: the pause never exceeds the cap, the deadline or half of the room left",
          "[file_search][governor]") {
    SECTION("the cap, over a whole slice of slow listings") {
        FakeClock c;
        fs::GovernorLimits l = backoff_only();
        l.slice = milliseconds{20'000};
        l.max_backoff_pause = milliseconds{400};
        fs::SliceGovernor g(l, c.env());
        // Each round fits before the deadline, so the back-off is the only thing that could pass it.
        while (c.t + milliseconds{300} < g.deadline()) {
            const auto before = c.t;
            listing(c, g, milliseconds{300});
            CHECK(c.t < g.deadline());
            CHECK(c.t - before <= milliseconds{300} + l.max_backoff_pause);
        }
        REQUIRE_FALSE(c.sleeps.empty());
        for (const auto d : c.sleeps)
            CHECK(d <= l.max_backoff_pause);
        CHECK(*std::max_element(c.sleeps.begin(), c.sleeps.end()) == l.max_backoff_pause); // it did reach the cap
    }
    SECTION("the back-off alone takes at most half of the room, so a slice that would progress still does") {
        FakeClock c;
        fs::GovernorLimits l = backoff_only();
        l.slice = milliseconds{400};
        fs::SliceGovernor g(l, c.env());
        c.work(milliseconds{300}); // 100 ms left, 99 ms of room
        g.note_listing(milliseconds{300});
        g.pace();
        REQUIRE(c.sleeps.size() == 1);
        CHECK(c.sleeps[0] == milliseconds{49}); // half of the room: the back-off of 50 ms is cut
        CHECK(c.t < g.deadline());
        CHECK(g.deadline() - c.t == milliseconds{51});
    }
    SECTION("with the duty nap, the total still stops short of the deadline") {
        FakeClock c;
        fs::GovernorLimits l; // 50 % duty
        l.slice = milliseconds{1'000};
        l.max_backoff_pause = milliseconds{1'000};
        fs::SliceGovernor g(l, c.env());
        c.work(milliseconds{300});
        g.note_listing(milliseconds{300});
        g.pace();
        // room 699, duty nap 300: back-off min(50, (699 - 300) / 2) = 50
        REQUIRE(c.sleeps.size() == 1);
        CHECK(c.sleeps[0] == milliseconds{350});
        c.work(milliseconds{200});
        g.note_listing(milliseconds{300}); // backoff doubles to 100
        g.pace();
        // t is 850 ms in, room 149 ms: the duty nap 200 is clamped to the room, nothing is added
        REQUIRE(c.sleeps.size() == 2);
        CHECK(c.sleeps[1] == milliseconds{149});
        CHECK(c.t < g.deadline());
    }
}

TEST_CASE("governor: a healthy disk paces exactly as the duty cycle always has", "[file_search][governor]") {
    // Every listing here is over slow_list_floor, within slow_list_ratio of the fastest so far and under
    // slow_list_hard, so none is slow by the rule. That is what a healthy disk means: no listing is slow.
    const std::vector<milliseconds> took = {milliseconds{30}, milliseconds{40}, milliseconds{25},
                                            milliseconds{35}, milliseconds{45}, milliseconds{28},
                                            milliseconds{40}, milliseconds{33}, milliseconds{41},
                                            milliseconds{26}};
    FakeClock with_note, without;
    fs::SliceGovernor a({}, with_note.env());
    fs::SliceGovernor b({}, without.env());
    for (const auto d : took) {
        a.pace();
        with_note.work(d);
        a.note_listing(d);
        b.pace();
        without.work(d);
    }
    a.pace();
    b.pace();
    // The expected naps, worked by hand at 50 % duty (nap = work since the last sleep ended): 30 and
    // 40 ms are under one quantum; 70 ms of work naps 70; 25 + 35 = 60 naps 60; 45 + 28 = 73 naps 73;
    // 40 + 33 = 73 naps 73; 41 + 26 = 67 naps 67 at the final pace().
    const std::vector<milliseconds> expected = {milliseconds{70}, milliseconds{60}, milliseconds{73},
                                                milliseconds{73}, milliseconds{67}};
    CHECK(without.sleeps == expected);
    CHECK(with_note.sleeps == expected);
}

TEST_CASE("governor: zero samples and one sample", "[file_search][governor]") {
    SECTION("no sample: the plain duty cycle") {
        FakeClock c;
        fs::SliceGovernor g({}, c.env());
        c.work(milliseconds{200});
        g.pace();
        CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{200}});
    }
    SECTION("one sample under the hard bound has no baseline to be slower than") {
        FakeClock c;
        fs::SliceGovernor g({}, c.env());
        c.work(milliseconds{249});
        g.note_listing(milliseconds{249});
        g.pace();
        CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{249}});
    }
    SECTION("one sample at the hard bound is slow on its own") {
        FakeClock c;
        fs::SliceGovernor g({}, c.env());
        c.work(milliseconds{250});
        g.note_listing(milliseconds{250});
        g.pace();
        CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{300}});
    }
    SECTION("the second sample is judged against the first") {
        FakeClock c;
        fs::SliceGovernor g(backoff_only(), c.env());
        g.note_listing(milliseconds{5});
        g.note_listing(milliseconds{19}); // below the floor, however many times the fastest
        c.work(milliseconds{60});
        g.pace();
        CHECK(c.sleeps.empty());
        g.note_listing(milliseconds{20}); // at the floor and exactly four times the fastest (5 ms): slow
        c.work(milliseconds{60});
        g.pace();
        CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{50}});
    }
}

TEST_CASE("governor: evenly slow listings under the hard bound stop counting once the ring holds only them",
          "[file_search][governor]") {
    FakeClock c;
    fs::SliceGovernor g(backoff_only(), c.env());
    for (std::size_t i = 0; i < fs::kLatencyRing; ++i)
        g.note_listing(milliseconds{5}); // the healthy baseline: none of these is slow
    // The disk turns evenly slow. Each 100 ms listing is four times the fastest sample still in the ring
    // until the last 5 ms sample is overwritten (the eighth), then the new baseline is 100 ms.
    for (std::size_t i = 0; i < fs::kLatencyRing; ++i)
        listing(c, g, milliseconds{100});
    CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{50}, milliseconds{100}, milliseconds{200},
                                                milliseconds{400}, milliseconds{800}, milliseconds{1'000},
                                                milliseconds{1'000}, milliseconds{1'000}});
    c.sleeps.clear();
    listing(c, g, milliseconds{100}); // the ring now holds only 100 ms listings: not slower than itself
    listing(c, g, milliseconds{100});
    CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{500}, milliseconds{250}});
}

TEST_CASE("governor: extreme and negative spans are clamped, never overflowed", "[file_search][governor]") {
    SECTION("the longest span is slow, and the pause stays capped") {
        FakeClock c;
        fs::GovernorLimits l = backoff_only();
        l.slow_list_ratio = 64;
        fs::SliceGovernor g(l, c.env());
        g.note_listing(fs::Clock::duration::max());
        g.note_listing(fs::Clock::duration::max()); // a baseline of the longest span times 64: no overflow
        c.work(milliseconds{60});
        g.pace();
        CHECK(c.sleeps == std::vector<milliseconds>{milliseconds{100}}); // two slow notes: 50, then 100
    }
    SECTION("a negative span (a clock that stepped back) reads as zero") {
        FakeClock c;
        fs::SliceGovernor g(backoff_only(), c.env());
        g.note_listing(fs::Clock::duration::min());
        g.note_listing(-std::chrono::hours{5});
        c.work(milliseconds{60});
        g.pace();
        CHECK(c.sleeps.empty());
    }
    SECTION("unvalidated limits are clamped too") {
        FakeClock c;
        fs::GovernorLimits l = backoff_only();
        l.slow_list_hard = milliseconds::max();
        l.slow_list_floor = milliseconds::max();
        l.max_backoff_pause = milliseconds::max();
        l.slow_list_ratio = 0xFFFFFFFFu;
        fs::SliceGovernor g(l, c.env());
        for (int i = 0; i < 4; ++i)
            g.note_listing(fs::Clock::duration::max());
        c.work(milliseconds{60});
        g.pace(); // clamped to the slice, whatever the limits said: four slow notes give 400 ms
        REQUIRE(c.sleeps.size() == 1);
        CHECK(c.sleeps[0] == milliseconds{400});
        CHECK(c.t < g.deadline());
    }
}
