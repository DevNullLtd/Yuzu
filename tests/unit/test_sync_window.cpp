// Pure tests for sync_window.hpp's next_window_fire and for the scheduler's overdue
// catch-up. No real clock, file, process or network: the zone is a fake with a DST
// transition table (America/Los_Angeles 2026 rules: spring-forward 2026-03-08
// 02:00 PST = 10:00Z, fall-back 2026-11-01 02:00 PDT = 09:00Z), injected as a LocalClock.

#include "sync_scheduler.hpp"
#include "sync_window.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::agent;

namespace {

constexpr std::int64_t kHour = 3600;
constexpr std::int64_t kDay = 24 * kHour;

namespace chr = std::chrono;

// Broken-down time <-> seconds-since-epoch read as if UTC. Linear in tm_mday, so an
// out-of-range day normalises the way mktime does (day 32 of a 31-day month = the 1st).
std::int64_t civil_seconds(const std::tm& l) {
    const chr::year_month_day first{chr::year{l.tm_year + 1900},
                                    chr::month{static_cast<unsigned>(l.tm_mon + 1)}, chr::day{1}};
    const chr::sys_days d = chr::sys_days{first} + chr::days{l.tm_mday - 1};
    return d.time_since_epoch().count() * kDay + l.tm_hour * kHour + l.tm_min * 60 + l.tm_sec;
}

std::tm civil_tm(std::int64_t secs) {
    const chr::sys_seconds tp{chr::seconds{secs}};
    const chr::sys_days d = chr::floor<chr::days>(tp);
    const chr::year_month_day ymd{d};
    const chr::hh_mm_ss<chr::seconds> hms{tp - d};
    std::tm l{};
    l.tm_year = static_cast<int>(ymd.year()) - 1900;
    l.tm_mon = static_cast<int>(static_cast<unsigned>(ymd.month())) - 1;
    l.tm_mday = static_cast<int>(static_cast<unsigned>(ymd.day()));
    l.tm_hour = static_cast<int>(hms.hours().count());
    l.tm_min = static_cast<int>(hms.minutes().count());
    l.tm_sec = static_cast<int>(hms.seconds().count());
    return l;
}

std::int64_t utc(int y, int m, int d, int hh, int mm) {
    std::tm l{};
    l.tm_year = y - 1900;
    l.tm_mon = m - 1;
    l.tm_mday = d;
    l.tm_hour = hh;
    l.tm_min = mm;
    return civil_seconds(l);
}

struct FakeZone {
    std::int64_t std_off; // seconds east of UTC outside DST
    std::int64_t dst_off;
    std::int64_t dst_begin; // UTC instant DST starts
    std::int64_t dst_end;   // UTC instant DST ends

    std::int64_t offset_at(std::int64_t t) const {
        return (t >= dst_begin && t < dst_end) ? dst_off : std_off;
    }

    LocalClock clock() const {
        const FakeZone z = *this;
        LocalClock lc;
        lc.to_local = [z](std::int64_t t) { return civil_tm(t + z.offset_at(t)); };
        lc.from_local = [z](const std::tm& l) {
            const std::int64_t local = civil_seconds(l);
            const std::int64_t as_dst = local - z.dst_off;
            const std::int64_t as_std = local - z.std_off;
            const bool dst_ok = z.offset_at(as_dst) == z.dst_off;
            const bool std_ok = z.offset_at(as_std) == z.std_off;
            if (dst_ok && std_ok) // fall-back overlap: the earlier instant, always
                return std::min(as_dst, as_std);
            if (dst_ok)
                return as_dst;
            if (std_ok)
                return as_std;
            return as_std; // spring-forward gap: resolves forward, as mktime does
        };
        return lc;
    }
};

const FakeZone kUtc{0, 0, 0, 0};
const FakeZone kPacificFixed{-8 * kHour, -8 * kHour, 0, 0};
const FakeZone kPacific{-8 * kHour, -7 * kHour, utc(2026, 3, 8, 10, 0), utc(2026, 11, 1, 9, 0)};

constexpr SyncWindow kNight{60, 300}; // 01:00-05:00 local
constexpr std::int64_t kSpan = (300 - 60) * 60;

// Minutes after local midnight of `t` in `clock`'s zone.
int local_minutes(const LocalClock& clock, std::int64_t t) {
    const std::tm l = clock.to_local(t);
    return l.tm_hour * 60 + l.tm_min;
}

bool in_window(const LocalClock& clock, std::int64_t t, SyncWindow w = kNight) {
    const int m = local_minutes(clock, t);
    return m >= w.start_min && m < w.end_min;
}

} // namespace

TEST_CASE("next_window_fire: placement lands inside the window for fixed offsets",
          "[sync][window]") {
    for (const FakeZone* z : {&kUtc, &kPacificFixed}) {
        const LocalClock clock = z->clock();
        for (std::uint64_t h = 0; h < 20000; h += 331) {
            const std::int64_t now = utc(2026, 6, 10, 12, 0);
            const std::int64_t fire = next_window_fire(now, kNight, h, clock);
            INFO("hash=" << h);
            CHECK(fire > now);
            CHECK(fire <= now + 2 * kDay);
            CHECK(in_window(clock, fire));
        }
    }
}

TEST_CASE("next_window_fire: stable per agent, spread across agents", "[sync][window]") {
    const LocalClock clock = kPacificFixed.clock();
    const std::int64_t now = utc(2026, 6, 10, 12, 0);
    CHECK(next_window_fire(now, kNight, 1234, clock) == next_window_fire(now, kNight, 1234, clock));
    // The same agent a day later sits at the same local time.
    const std::int64_t f1 = next_window_fire(now, kNight, 1234, clock);
    const std::int64_t f2 = next_window_fire(f1, kNight, 1234, clock);
    CHECK(f2 - f1 == kDay);
    // Different hashes give different instants (an offset of kSpan/2 apart is 2 h).
    const std::int64_t a = next_window_fire(now, kNight, 100, clock);
    const std::int64_t b = next_window_fire(now, kNight, 100 + kSpan / 2, clock);
    CHECK(b - a == kSpan / 2);
}

TEST_CASE("next_window_fire: a candidate already passed today moves to tomorrow",
          "[sync][window]") {
    const LocalClock clock = kUtc.clock();
    const std::uint64_t h = 3600; // 01:00 + 1 h = 02:00 local
    SECTION("before the slot: today") {
        CHECK(next_window_fire(utc(2026, 6, 10, 1, 30), kNight, h, clock) == utc(2026, 6, 10, 2, 0));
    }
    SECTION("exactly at the slot: strictly after now, so tomorrow") {
        CHECK(next_window_fire(utc(2026, 6, 10, 2, 0), kNight, h, clock) == utc(2026, 6, 11, 2, 0));
    }
    SECTION("after the slot: tomorrow, across a month end") {
        CHECK(next_window_fire(utc(2026, 6, 30, 3, 0), kNight, h, clock) == utc(2026, 7, 1, 2, 0));
    }
}

TEST_CASE("next_window_fire: spring-forward gap resolves forward and stays in the window",
          "[sync][window]") {
    const LocalClock clock = kPacific.clock();
    // Local 02:00-03:00 on 2026-03-08 does not exist. now = the previous noon local.
    const std::int64_t now = utc(2026, 3, 7, 20, 0);
    SECTION("a slot inside the gap lands at 03:30 local, not before the gap") {
        const std::uint64_t h = 5400; // 01:00 + 1.5 h = 02:30 local (nonexistent)
        const std::int64_t fire = next_window_fire(now, kNight, h, clock);
        const std::tm l = clock.to_local(fire);
        CHECK(l.tm_mday == 8);
        CHECK(l.tm_hour == 3);
        CHECK(l.tm_min == 30);
    }
    SECTION("every slot of the window lands inside it on the gap day") {
        for (std::uint64_t h = 0; h < static_cast<std::uint64_t>(kSpan); h += 97) {
            const std::int64_t fire = next_window_fire(now, kNight, h, clock);
            INFO("hash=" << h);
            CHECK(fire > now);
            CHECK(in_window(clock, fire));
        }
    }
}

TEST_CASE("next_window_fire: fall-back overlap picks one deterministic instant",
          "[sync][window]") {
    const LocalClock clock = kPacific.clock();
    // Local 01:00-02:00 on 2026-11-01 happens twice. now = the previous noon local.
    const std::int64_t now = utc(2026, 10, 31, 19, 0);
    const std::uint64_t h = 1800; // 01:30 local, ambiguous
    const std::int64_t fire = next_window_fire(now, kNight, h, clock);
    CHECK(fire == next_window_fire(now, kNight, h, clock));
    CHECK(fire == utc(2026, 11, 1, 8, 30)); // the first (PDT) 01:30
    for (std::uint64_t k = 0; k < static_cast<std::uint64_t>(kSpan); k += 97) {
        const std::int64_t f = next_window_fire(now, kNight, k, clock);
        INFO("hash=" << k);
        CHECK(in_window(clock, f));
    }
}

TEST_CASE("next_window_fire: an unconvertible local time falls back to a day later, never the past",
          "[sync][window]") {
    LocalClock broken = kUtc.clock();
    broken.from_local = [](const std::tm&) -> std::int64_t { return -1; };
    const std::int64_t now = utc(2026, 6, 10, 12, 0);
    CHECK(next_window_fire(now, kNight, 7, broken) == now + kDay);
    CHECK(next_window_fire(now, SyncWindow{300, 60}, 7, kUtc.clock()) == now + kDay); // empty span
}

TEST_CASE("next_window_fire: the real C-library clock lands inside the window",
          "[sync][window]") {
    // Smoke test of the production conversions only: it asserts the result lies inside the
    // window as the SAME clock reads it back, so it holds in whatever zone the host has
    // (TZ unset, UTC, a DST zone) and pins nothing about which zone that is. The DST edges
    // are pinned on the fake zone above.
    const LocalClock clock = system_local_clock();
    const std::int64_t now = 1'781'000'000; // a fixed instant, not the wall clock
    for (std::uint64_t h : {0ULL, 5400ULL, 14399ULL}) {
        const std::int64_t fire = next_window_fire(now, kNight, h, clock);
        CHECK(fire > now);
        CHECK(fire <= now + 2 * kDay);
        CHECK(in_window(clock, fire));
    }
}

namespace {

// A scheduler over an in-memory KV holding one source whose collect() is counted.
struct CatchUpRig {
    std::map<std::string, std::string> kv;
    int collects{0};
    SyncScheduler sched;

    explicit CatchUpRig(std::map<std::string, std::string> seed)
        : kv(std::move(seed)),
          sched(
              "agent-catchup", [this](const std::string& k) {
                  auto it = kv.find(k);
                  return it == kv.end() ? std::string{} : it->second;
              },
              [this](const std::string& k, const std::string& v) { kv[k] = v; },
              [](const std::vector<std::pair<std::string, std::string>>&,
                 const std::vector<std::pair<std::string, std::string>>&)
                  -> std::optional<std::vector<std::string>> { return std::vector<std::string>{}; }) {
        SyncSource src;
        src.name = "s";
        src.interval = std::chrono::seconds{86400};
        src.collect = [this]() -> std::optional<std::pair<std::string, std::string>> {
            ++collects;
            return std::make_pair(std::string("blob"), std::string("hash"));
        };
        sched.add_source(src);
    }

    std::int64_t next_fire() const { return std::stoll(kv.at("sync.s.next_fire")); }
};

std::map<std::string, std::string> persisted(std::int64_t next_fire) {
    return {{"sync.s.next_fire", std::to_string(next_fire)}, {"sync.s.last_hash", "old"}};
}

} // namespace

TEST_CASE("catch-up: an overdue persisted next_fire is re-armed within 30 min, stably",
          "[sync][window][catchup]") {
    const std::int64_t now = 5'000'000;
    CatchUpRig a(persisted(now - 86400));
    a.sched.tick(now);
    CHECK(a.collects == 0); // not at once
    const std::int64_t armed = a.next_fire();
    CHECK(armed >= now);
    CHECK(armed < now + SyncScheduler::kCatchUpWindow.count());

    CatchUpRig b(persisted(now - 3 * 86400)); // same agent and source, longer outage
    b.sched.tick(now);
    CHECK(b.next_fire() == armed); // stable offset

    a.sched.tick(armed + 1); // and it does fire once the spread offset passes
    CHECK(a.collects == 1);
}

TEST_CASE("catch-up: a next_fire less than one tick late is left alone", "[sync][window][catchup]") {
    const std::int64_t now = 5'000'000;
    const std::int64_t late = SyncScheduler::kMaxTickSeconds.count();
    SECTION("exactly one clamped sleep late: fires") {
        CatchUpRig r(persisted(now - late));
        r.sched.tick(now);
        CHECK(r.collects == 1);
    }
    SECTION("just over one clamped sleep late: re-armed") {
        CatchUpRig r(persisted(now - late - 1));
        r.sched.tick(now);
        CHECK(r.collects == 0);
    }
}
