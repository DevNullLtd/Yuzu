/**
 * test_software_sync_pacing.cpp — the pure admission and pacing rule behind the on-demand sync
 * (software_sync_pacing.hpp): how fast one run may ask the fleet to report, how long its spread
 * is, when it has to wait and when it cannot be spread at all. Table-driven over a plain vector of
 * active runs; no clock, no state, no Runner.
 */

#include "software_sync_pacing.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

namespace ss = yuzu::server::software_sync;
using Kind = ss::Admission::Kind;

namespace {

constexpr std::int64_t kNow = 1'700'000'000;

double sum_rates(const std::vector<ss::ActiveRun>& runs, std::int64_t now) {
    double total = 0.0;
    for (const auto& r : runs)
        if (r.ends_at > now)
            total += r.rate;
    return total;
}

} // namespace

TEST_CASE("sync pacing: an empty ledger admits at half the budget; the spread is ceil(targets / rate)",
          "[server][software_sync][pacing]") {
    CHECK(ss::kFleetPacingBudgetPerSec == 50.0);
    CHECK(ss::kMaxRunShare == 0.5);
    struct Row {
        std::size_t targets;
        double rate;
        std::int64_t delay;
    };
    const Row rows[] = {
        {100, 25.0, 4},    // exact multiple
        {101, 25.0, 5},    // one over: the spread rounds UP, never down
        {26, 25.0, 2},     // one past the rate
        {2500, 25.0, 100}, //
        {1'000'000, 25.0, 40'000},
    };
    for (const Row& r : rows) {
        INFO("targets=" << r.targets);
        const auto a = ss::admit({}, r.targets, kNow);
        REQUIRE(a.kind == Kind::Admit);
        CHECK(a.rate == r.rate);
        CHECK(a.delay_max_s == r.delay);
        CHECK(a.ends_at == kNow + r.delay);
    }
}

TEST_CASE("sync pacing: targets within the rate give delay 0 and a one second ledger entry",
          "[server][software_sync][pacing]") {
    for (const std::size_t targets : {std::size_t{1}, std::size_t{10}, std::size_t{25}}) {
        INFO("targets=" << targets);
        const auto a = ss::admit({}, targets, kNow);
        REQUIRE(a.kind == Kind::Admit);
        CHECK(a.delay_max_s == 0);
        CHECK(a.rate == static_cast<double>(targets)); // it reserves what it uses, no more
        CHECK(a.ends_at == kNow + 1);
    }
}

TEST_CASE("sync pacing: the admitted rates never sum past the budget across a sequence of runs",
          "[server][software_sync][pacing][security]") {
    // Three shapes of demand: always huge (halves every time), mixed, and many tiny ones.
    const std::vector<std::vector<std::size_t>> demands = {
        std::vector<std::size_t>(40, 100'000),
        {100'000, 3, 50, 7, 400, 1, 1, 90, 12'000, 2, 2, 2, 600, 5},
        std::vector<std::size_t>(200, 1),
    };
    for (const auto& demand : demands) {
        std::vector<ss::ActiveRun> ledger;
        std::size_t admitted = 0;
        std::size_t busy = 0;
        for (const std::size_t targets : demand) {
            const auto a = ss::admit(ledger, targets, kNow);
            if (a.kind == Kind::Admit) {
                ledger.push_back({a.rate, a.ends_at});
                ++admitted;
            } else {
                ++busy;
            }
            REQUIRE(sum_rates(ledger, kNow) <= ss::kFleetPacingBudgetPerSec);
        }
        CHECK(admitted > 0);
        CHECK(busy > 0); // every table runs the budget dry, and the rule says so rather than overrun
    }
}

TEST_CASE("sync pacing: three runs started from an empty ledger take 25, 12.5 and 6.25 per second",
          "[server][software_sync][pacing]") {
    std::vector<ss::ActiveRun> ledger;
    for (const double want : {25.0, 12.5, 6.25}) {
        const auto a = ss::admit(ledger, 10'000, kNow);
        REQUIRE(a.kind == Kind::Admit);
        CHECK(a.rate == want);
        ledger.push_back({a.rate, a.ends_at});
    }
    CHECK(sum_rates(ledger, kNow) == 43.75);
}

TEST_CASE("sync pacing: a free share below the minimum rate is Busy; the retry is the earliest end",
          "[server][software_sync][pacing]") {
    // 49 of 50 in use: free 1, half of it 0.5 < kMinRunRate.
    {
        const std::vector<ss::ActiveRun> ledger = {{49.0, kNow + 30}};
        const auto a = ss::admit(ledger, 10, kNow);
        CHECK(a.kind == Kind::Busy);
        CHECK(a.retry_after_s == 30);
        CHECK(a.rate == 0.0);
    }
    // The earliest of several, not the first listed or the last.
    {
        const std::vector<ss::ActiveRun> ledger = {{20.0, kNow + 90}, {20.0, kNow + 12}, {9.5, kNow + 40}};
        const auto a = ss::admit(ledger, 10, kNow);
        CHECK(a.kind == Kind::Busy);
        CHECK(a.retry_after_s == 12);
    }
    // The boundary: free 2 leaves a share of exactly kMinRunRate, which is enough.
    {
        const std::vector<ss::ActiveRun> ledger = {{48.0, kNow + 30}};
        const auto a = ss::admit(ledger, 10, kNow);
        REQUIRE(a.kind == Kind::Admit);
        CHECK(a.rate == ss::kMinRunRate);
        CHECK(a.delay_max_s == 10);
    }
}

TEST_CASE("sync pacing: a run that has ended frees its rate", "[server][software_sync][pacing]") {
    const std::vector<ss::ActiveRun> ledger = {{49.0, kNow + 30}};
    CHECK(ss::admit(ledger, 10, kNow).kind == Kind::Busy);
    CHECK(ss::admit(ledger, 10, kNow + 29).kind == Kind::Busy);
    // ends_at is the first second the rate is free again.
    const auto at_end = ss::admit(ledger, 100, kNow + 30);
    REQUIRE(at_end.kind == Kind::Admit);
    CHECK(at_end.rate == 25.0);
    const auto after = ss::admit(ledger, 100, kNow + 31);
    REQUIRE(after.kind == Kind::Admit);
    CHECK(after.rate == 25.0);
}

TEST_CASE("sync pacing: a run that cannot be spread inside 86,400 s is TooLarge",
          "[server][software_sync][pacing]") {
    CHECK(ss::kMaxSpreadSecs == 86'400);
    // 25 per second for 86,400 s is 2,160,000 devices: that fits exactly, one more does not.
    const auto fits = ss::admit({}, 2'160'000, kNow);
    REQUIRE(fits.kind == Kind::Admit);
    CHECK(fits.delay_max_s == ss::kMaxSpreadSecs);
    const auto over = ss::admit({}, 2'160'001, kNow);
    CHECK(over.kind == Kind::TooLarge);
    CHECK(over.delay_max_s == 0);
    CHECK(over.rate == 0.0);
    // The same run is TooLarge sooner when other runs already hold part of the budget.
    const std::vector<ss::ActiveRun> busy = {{25.0, kNow + 600}};
    CHECK(ss::admit(busy, 1'080'001, kNow).kind == Kind::TooLarge); // free share 12.5 per second
    CHECK(ss::admit(busy, 1'080'000, kNow).kind == Kind::Admit);
}

TEST_CASE("sync pacing: a clock that steps backwards never yields a negative delay or retry",
          "[server][software_sync][pacing]") {
    // The ledger was written at kNow; the clock is now an hour earlier. Entries stay active.
    const std::int64_t earlier = kNow - 3600;
    {
        const std::vector<ss::ActiveRun> ledger = {{25.0, kNow + 4}};
        const auto a = ss::admit(ledger, 100, earlier);
        REQUIRE(a.kind == Kind::Admit);
        CHECK(a.rate == 12.5);
        CHECK(a.delay_max_s >= 0);
        CHECK(a.ends_at > earlier);
    }
    {
        const std::vector<ss::ActiveRun> ledger = {{49.0, kNow + 4}};
        const auto a = ss::admit(ledger, 100, earlier);
        REQUIRE(a.kind == Kind::Busy);
        CHECK(a.retry_after_s >= 1);
        CHECK(a.retry_after_s <= ss::kMaxSpreadSecs); // bounded, whatever the step
    }
    {
        // A ledger entry the clock has long passed with a far-future "now" stays free.
        const std::vector<ss::ActiveRun> ledger = {{49.0, kNow + 4}};
        CHECK(ss::admit(ledger, 100, kNow + 10'000'000).kind == Kind::Admit);
    }
}
