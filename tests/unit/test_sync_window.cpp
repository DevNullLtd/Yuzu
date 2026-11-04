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
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::agent;

namespace {

constexpr std::int64_t kHour = 3600;
constexpr std::int64_t kDay = 24 * kHour;

// Days since 1970-01-01 for a proleptic Gregorian civil date; linear in `d`, so an
// out-of-range day normalises the way mktime does (day 32 of a 31-day month = the 1st).
std::int64_t days_from_civil(std::int64_t y, std::int64_t m, std::int64_t d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t yoe = y - era * 400;
    const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

void civil_from_days(std::int64_t z, int& y, int& m, int& d) {
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const std::int64_t doe = z - era * 146097;
    const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    d = static_cast<int>(doy - (153 * mp + 2) / 5 + 1);
    m = static_cast<int>(mp < 10 ? mp + 3 : mp - 9);
    y = static_cast<int>(yoe + era * 400 + (m <= 2));
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
        LocalClock c;
        c.to_local = [z](std::int64_t t) {
            const std::int64_t local = t + z.offset_at(t);
            std::int64_t days = local / kDay;
            std::int64_t rem = local % kDay;
            if (rem < 0) {
                rem += kDay;
                --days;
            }
            LocalTm l;
            civil_from_days(days, l.year, l.month, l.day);
            l.hour = static_cast<int>(rem / kHour);
            l.minute = static_cast<int>(rem % kHour / 60);
            l.second = static_cast<int>(rem % 60);
            return l;
        };
        c.from_local = [z](const LocalTm& l) {
            const std::int64_t local = days_from_civil(l.year, l.month, l.day) * kDay +
                                       l.hour * kHour + l.minute * 60 + l.second;
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
        return c;
    }
};

std::int64_t utc(int y, int m, int d, int hh, int mm) {
    return days_from_civil(y, m, d) * kDay + hh * kHour + mm * 60;
}

const FakeZone kUtc{0, 0, 0, 0};
const FakeZone kPacificFixed{-8 * kHour, -8 * kHour, 0, 0};
const FakeZone kPacific{-8 * kHour, -7 * kHour, utc(2026, 3, 8, 10, 0), utc(2026, 11, 1, 9, 0)};

constexpr SyncWindow kNight{60, 300}; // 01:00-05:00 local
constexpr std::int64_t kSpan = (300 - 60) * 60;

// Minutes after local midnight of `t` in `clock`'s zone.
int local_minutes(const LocalClock& clock, std::int64_t t) {
    const LocalTm l = clock.to_local(t);
    return l.hour * 60 + l.minute;
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
        const LocalTm l = clock.to_local(fire);
        CHECK(l.day == 8);
        CHECK(l.hour == 3);
        CHECK(l.minute == 30);
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
    broken.from_local = [](const LocalTm&) -> std::int64_t { return -1; };
    const std::int64_t now = utc(2026, 6, 10, 12, 0);
    CHECK(next_window_fire(now, kNight, 7, broken) == now + kDay);
    CHECK(next_window_fire(now, SyncWindow{300, 60}, 7, kUtc.clock()) == now + kDay); // empty span
}

TEST_CASE("next_window_fire: the real C-library clock lands inside the window",
          "[sync][window]") {
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
