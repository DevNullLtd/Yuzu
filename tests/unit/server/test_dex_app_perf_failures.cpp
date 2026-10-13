/**
 * test_dex_app_perf_failures.cpp -- the PURE per-version crash and hang join of the
 * fleet app-perf report: the canonical-version comparator, the two-cohort floor
 * rules, the rate and rate-ratio wiring, the 20-version cap, and the shared
 * versions[] serializer. No store, no PG, no I/O.
 *
 * Hand-computed anchors (plain double bisection on the exact Poisson and
 * binomial CDFs, independent of dex_stats.hpp, 2026-10-12):
 *   12 events over 15 devices        -> rate 0.8,  95% [0.4133717, 1.3974390]
 *   5 events over 12 devices         -> rate 5/12
 *   12/15 against 5/12 as a ratio    -> 1.92,      95% [0.6296367, 6.9567849]
 */
#include "dex_app_perf_pure.hpp"
#include "dex_window.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

using Catch::Approx;
using namespace yuzu::server;

namespace {

constexpr double kInf = std::numeric_limits<double>::infinity();

AppPerfTrendPoint point(const std::string& version, std::int64_t day, std::int64_t devices = 20) {
    AppPerfTrendPoint p;
    p.version = version;
    p.day = day;
    p.device_count = devices;
    p.cpu_mean = 1.0;
    return p;
}

// Per-type device counts default to "every affected device did this and is exposed";
// a case about a cohort or remainder states them. -1 selects the default.
AppPerfVersionFailureRow fail_row(const std::string& version, std::optional<std::int64_t> exposure,
                                  std::int64_t crashes, std::int64_t hangs, std::int64_t affected,
                                  std::int64_t exp_crashes, std::int64_t exp_hangs,
                                  std::int64_t crash_dev = -1, std::int64_t hang_dev = -1,
                                  std::int64_t exp_crash_dev = -1, std::int64_t exp_hang_dev = -1) {
    AppPerfVersionFailureRow r;
    r.version = version;
    r.exposure_devices = exposure;
    r.crashes = crashes;
    r.hangs = hangs;
    r.affected_devices = affected;
    r.exposed_crashes = exp_crashes;
    r.exposed_hangs = exp_hangs;
    r.crash_devices = crash_dev >= 0 ? crash_dev : (crashes > 0 ? affected : 0);
    r.hang_devices = hang_dev >= 0 ? hang_dev : (hangs > 0 ? affected : 0);
    r.exposed_crash_devices = exp_crash_dev >= 0 ? exp_crash_dev : r.crash_devices;
    r.exposed_hang_devices = exp_hang_dev >= 0 ? exp_hang_dev : r.hang_devices;
    return r;
}

const AppPerfVersionRow* row_of(const AppPerfFleetReport& rep, const std::string& version) {
    for (const auto& r : rep.versions)
        if (r.perf.version == version)
            return &r;
    return nullptr;
}

// Two versions of trend points: 1.0.0.0 on day 100, 2.0.0.0 on days 100 and 101;
// each case supplies its own failure rows.
std::vector<AppPerfTrendPoint> two_version_points() {
    return {point("1.0.0.0", 100), point("2.0.0.0", 100), point("2.0.0.0", 101)};
}

} // namespace

TEST_CASE("app_perf_canon_version_less orders numerically group by group", "[dex][app_perf]") {
    CHECK(app_perf_canon_version_less("9.9.9.9", "10.0.0.0")); // lexical order would say otherwise
    CHECK_FALSE(app_perf_canon_version_less("10.0.0.0", "9.9.9.9"));
    CHECK(app_perf_canon_version_less("1.2.3.4", "1.2.3.5"));
    CHECK(app_perf_canon_version_less("1.2.9.0", "1.10.0.0"));
    CHECK_FALSE(app_perf_canon_version_less("1.2.3.4", "1.2.3.4"));
    // A shorter form pads with zeros.
    CHECK_FALSE(app_perf_canon_version_less("1.2", "1.2.0.0"));
    CHECK_FALSE(app_perf_canon_version_less("1.2.0.0", "1.2"));
    CHECK(app_perf_canon_version_less("1.2", "1.2.0.1"));
    // The unknown bucket is below everything and equal only to itself.
    CHECK(app_perf_canon_version_less("", "0.0.0.0"));
    CHECK_FALSE(app_perf_canon_version_less("0.0.0.0", ""));
    CHECK_FALSE(app_perf_canon_version_less("", ""));
}

TEST_CASE("version join: the rate counts exposed events and the breadth counts every event",
          "[dex][app_perf]") {
    // 2.0.0.0: 20 fleet events over 14 devices (breadth) but only 12 of them (10 crashes
    // + 2 hangs) on the 15 exposed devices. 1.0.0.0: 8 fleet events, 5 on its 12 exposed
    // devices (4 crashes + 1 hang).
    const std::vector<AppPerfVersionFailureRow> fails{
        fail_row("1.0.0.0", 12, 7, 1, 5, 4, 1),
        fail_row("2.0.0.0", 15, 17, 3, 14, 10, 2, 14, 14, 4, 4), // remainder 10: shown
    };
    const auto rep = app_perf_version_failure_join(two_version_points(), fails, 30);
    REQUIRE(rep.versions.size() == 2);
    CHECK(rep.failure_window_days == 30);
    CHECK(rep.stat_failures == 0);
    CHECK_FALSE(rep.versions_truncated);

    const auto& v2 = rep.versions[0];
    REQUIRE(v2.perf.version == "2.0.0.0");
    CHECK(v2.perf.day_count == 2);
    CHECK(v2.affected_devices == 14);
    CHECK_FALSE(v2.below_floor);
    CHECK(v2.crashes == 17);
    CHECK(v2.hangs == 3);
    CHECK(v2.exposure_devices == 15);
    CHECK_FALSE(v2.exposure_below_floor);
    CHECK(v2.exposed_crashes == 10);
    CHECK(v2.exposed_hangs == 2);
    REQUIRE(v2.failure_rate);
    // 12 exposed events / 15 devices, NOT the 20 fleet events (which would read 1.33).
    CHECK(v2.failure_rate->estimate == Approx(0.8));
    CHECK(v2.failure_rate->lower == Approx(0.4133717).epsilon(1e-3));
    CHECK(v2.failure_rate->upper == Approx(1.3974390).epsilon(1e-3));
    CHECK_FALSE(v2.failure_rate->reliable); // 12 < 20 events
    const auto oracle = dex_rate(12, 15.0);
    REQUIRE(oracle);
    CHECK(v2.failure_rate->estimate == oracle->estimate);
    CHECK(v2.failure_rate->lower == oracle->lower);
    CHECK(v2.failure_rate->upper == oracle->upper);

    CHECK(v2.previous_version == "1.0.0.0");
    REQUIRE(v2.failure_rate_ratio);
    CHECK(v2.failure_rate_ratio->estimate == Approx(1.92));
    CHECK(v2.failure_rate_ratio->lower == Approx(0.6296367).epsilon(1e-3));
    CHECK(v2.failure_rate_ratio->upper == Approx(6.9567849).epsilon(1e-3));
    const auto ratio_oracle = dex_rate_ratio(12, 15.0, 5, 12.0);
    REQUIRE(ratio_oracle);
    CHECK(v2.failure_rate_ratio->lower == ratio_oracle->lower);
    CHECK(v2.failure_rate_ratio->upper == ratio_oracle->upper);

    const auto& v1 = rep.versions[1];
    REQUIRE(v1.perf.version == "1.0.0.0");
    CHECK(v1.previous_version.empty());
    CHECK_FALSE(v1.failure_rate_ratio);
    REQUIRE(v1.failure_rate);
    CHECK(v1.failure_rate->estimate == Approx(5.0 / 12.0));
}

TEST_CASE("version join: the breadth and exposure cohorts are floored independently",
          "[dex][app_perf]") {
    SECTION("a crash cohort under the floor withholds the crashes, not the hangs") {
        // 9 devices crashed (9 events); 12 hung (20 events); 12 affected in all.
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 12, 9, 20, 12, 3, 5, 9, 12)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.below_floor);
        CHECK(r.affected_devices == 12);
        CHECK_FALSE(r.crashes);
        CHECK(r.hangs == 20);
        // The exposure cohort is above the floor on its own devices.
        CHECK(r.exposed_crashes == 3);
        REQUIRE(r.failure_rate);
    }
    SECTION("nine hang-once devices beside one repeat crasher withhold both totals") {
        // affected 10 passes the union floor, but crashes=3 would be one device and
        // hangs=9 is nine: each type is judged on its own devices.
        for (const auto exposure : {std::optional<std::int64_t>{12}, std::optional<std::int64_t>{}}) {
            const auto rep = app_perf_version_failure_join(
                {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", exposure, 3, 9, 10, 0, 0, 1, 9)}, 30);
            const auto& r = rep.versions.at(0);
            CHECK(r.below_floor);
            CHECK(r.affected_devices == 10);
            CHECK_FALSE(r.crashes);
            CHECK_FALSE(r.hangs);
        }
    }
    SECTION("a hang cohort at the floor is shown while the crash cohort is withheld") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 12, 3, 10, 11, 0, 0, 1, 10)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.below_floor); // one omitted total is enough
        CHECK_FALSE(r.crashes);
        CHECK(r.hangs == 10);
    }
    SECTION("a hang cohort under the floor withholds the hangs and raises below_floor alone") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 12, 20, 3, 12, 0, 0, 12, 3)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.below_floor);
        CHECK(r.crashes == 20);
        CHECK_FALSE(r.hangs);
    }
    SECTION("a cohort below the floor is withheld whether exposure is unknown or itself under the floor") {
        for (const auto exposure : {std::optional<std::int64_t>{}, std::optional<std::int64_t>{9}}) {
            const auto rep = app_perf_version_failure_join(
                {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", exposure, 9, 0, 9, 0, 0)}, 30);
            CHECK(rep.versions.at(0).below_floor);
            CHECK_FALSE(rep.versions.at(0).crashes);
        }
    }
    SECTION("cohorts exactly at the floor are shown, and an empty type is shown as zero") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)},
            {fail_row("1.0.0.0", 12, 4, 6, kDexCohortFloor, 4, 6, kDexCohortFloor, kDexCohortFloor)},
            30);
        const auto& r = rep.versions.at(0);
        CHECK_FALSE(r.below_floor);
        CHECK(r.crashes == 4);
        CHECK(r.hangs == 6);
        const auto none = app_perf_version_failure_join(
            {point("1.0.0.0", 100)},
            {fail_row("1.0.0.0", 12, 0, 6, kDexCohortFloor, 0, 6, 0, kDexCohortFloor)}, 30);
        CHECK_FALSE(none.versions.at(0).below_floor);
        CHECK(none.versions.at(0).crashes == 0);
        CHECK(none.versions.at(0).hangs == 6);
        const auto crash_only = app_perf_version_failure_join(
            {point("1.0.0.0", 100)},
            {fail_row("1.0.0.0", 12, 10, 0, kDexCohortFloor, 10, 0, kDexCohortFloor, 0)}, 30);
        CHECK_FALSE(crash_only.versions.at(0).below_floor);
        CHECK(crash_only.versions.at(0).crashes == 10);
        CHECK(crash_only.versions.at(0).hangs == 0);
    }
    SECTION("a remainder of 1 to 9 unexposed devices of a type withholds that total") {
        // 20 devices of each type, `rem` of them outside the exposure cohort: showing
        // the total beside its exposed part would let a reader subtract those events.
        for (const std::int64_t rem : {1, 5, 9}) {
            CAPTURE(rem);
            const auto rep = app_perf_version_failure_join(
                {point("1.0.0.0", 100)},
                {fail_row("1.0.0.0", 15, 30, 4, 20, 10, 2, 20, 20, 20 - rem, 20 - rem)}, 30);
            const auto& r = rep.versions.at(0);
            CHECK(r.below_floor);
            CHECK(r.affected_devices == 20);
            CHECK_FALSE(r.crashes);
            CHECK_FALSE(r.hangs);
            // The exposure cohort stands on its own devices, so its figures stay.
            CHECK(r.exposed_crashes == 10);
            CHECK(r.exposed_hangs == 2);
            REQUIRE(r.failure_rate);
            CHECK(rep.stat_failures == 0);
        }
    }
    SECTION("the remainder is judged per type, not on the union") {
        // 15 of 20 crashing devices are exposed (remainder 5); all 20 hanging devices are.
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)},
            {fail_row("1.0.0.0", 15, 30, 4, 20, 10, 2, 20, 20, 15, 20)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.below_floor);
        CHECK_FALSE(r.crashes);
        CHECK(r.hangs == 4);
    }
    SECTION("an empty remainder or one at the floor shows the totals") {
        for (const std::int64_t rem : {0, 10, 11}) {
            CAPTURE(rem);
            const auto rep = app_perf_version_failure_join(
                {point("1.0.0.0", 100)},
                {fail_row("1.0.0.0", 15, 30, 4, 20, 10, 2, 20, 20, 20 - rem, 20 - rem)}, 30);
            const auto& r = rep.versions.at(0);
            CHECK_FALSE(r.below_floor);
            CHECK(r.crashes == 30);
            CHECK(r.hangs == 4);
            CHECK(r.exposed_crashes == 10);
            REQUIRE(r.failure_rate);
        }
    }
    SECTION("the remainder is not read off figures that are withheld") {
        // Exposure under the floor: nothing exposed is shown to subtract from.
        const auto under = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 9, 30, 4, 20, 10, 2, 20, 20, 15, 15)}, 30);
        CHECK_FALSE(under.versions.at(0).below_floor);
        CHECK(under.versions.at(0).crashes == 30);
        CHECK_FALSE(under.versions.at(0).exposed_crashes);
        // Exposure unknown: same.
        const auto unknown = app_perf_version_failure_join(
            {point("1.0.0.0", 100)},
            {fail_row("1.0.0.0", std::nullopt, 30, 4, 20, 0, 0, 20, 20, 0, 0)}, 30);
        CHECK_FALSE(unknown.versions.at(0).below_floor);
        CHECK(unknown.versions.at(0).crashes == 30);
    }
    SECTION("exposure under the floor withholds the exposed figures, rate and ratio") {
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 12, 7, 1, 5, 4, 1), fail_row("2.0.0.0", 9, 17, 3, 15, 10, 2)}, 30);
        const auto& v2 = rep.versions.at(0);
        CHECK(v2.exposure_devices == 9); // the device count is carried
        CHECK(v2.exposure_below_floor);
        CHECK_FALSE(v2.exposed_crashes);
        CHECK_FALSE(v2.exposed_hangs);
        CHECK_FALSE(v2.failure_rate);
        CHECK_FALSE(v2.failure_rate_ratio);
        CHECK(v2.crashes == 17); // breadth stays
        CHECK(v2.previous_version == "1.0.0.0"); // the neighbour is still named
        // The above-floor neighbour has no previous of its own and keeps its rate.
        REQUIRE(rep.versions[1].failure_rate);
        CHECK(rep.stat_failures == 0);
    }
    SECTION("the neighbour of an under-floor row withholds its ratio as well") {
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 9, 7, 1, 12, 4, 1), fail_row("2.0.0.0", 15, 17, 3, 15, 10, 2)}, 30);
        const auto& v2 = rep.versions.at(0);
        CHECK_FALSE(v2.exposure_below_floor);
        REQUIRE(v2.failure_rate);
        CHECK_FALSE(v2.failure_rate_ratio); // previous arm is under the floor
        CHECK(rep.stat_failures == 0);
    }
}

TEST_CASE("version join: unknown exposure is null and never zero", "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join(
        two_version_points(),
        {fail_row("1.0.0.0", 12, 7, 1, 5, 0, 0), fail_row("2.0.0.0", std::nullopt, 17, 3, 15, 0, 0)},
        30);
    const auto& v2 = rep.versions.at(0);
    CHECK_FALSE(v2.exposure_devices);
    CHECK_FALSE(v2.exposure_below_floor);
    CHECK_FALSE(v2.exposed_crashes);
    CHECK_FALSE(v2.exposed_hangs);
    CHECK_FALSE(v2.failure_rate);
    CHECK_FALSE(v2.failure_rate_ratio);
    CHECK(v2.crashes == 17); // breadth, governed by its own floor only
    CHECK(v2.hangs == 3);
    CHECK(rep.stat_failures == 0);
}

TEST_CASE("version join: no failure row at all reads as zero failures", "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join({point("1.0.0.0", 100)}, {}, 30);
    const auto& r = rep.versions.at(0);
    CHECK(r.affected_devices == 0);
    CHECK_FALSE(r.below_floor);
    CHECK(r.crashes == 0);
    CHECK(r.hangs == 0);
    CHECK_FALSE(r.exposure_devices);
}

TEST_CASE("version join: the unknown version is kept but never chains", "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join(
        {point("", 100), point("1.0.0.0", 100), point("2.0.0.0", 100)},
        {fail_row("", 15, 3, 0, 3, 3, 0), fail_row("1.0.0.0", 15, 3, 0, 3, 3, 0),
         fail_row("2.0.0.0", 15, 3, 0, 3, 3, 0)},
        30);
    REQUIRE(rep.versions.size() == 3);
    CHECK(rep.versions[0].perf.version == "2.0.0.0");
    CHECK(rep.versions[1].perf.version == "1.0.0.0");
    CHECK(rep.versions[2].perf.version.empty());
    CHECK(rep.versions[1].previous_version.empty()); // the oldest known version has none
    CHECK_FALSE(rep.versions[1].failure_rate_ratio);
    CHECK(rep.versions[2].previous_version.empty());
    CHECK_FALSE(rep.versions[2].failure_rate_ratio);
    CHECK(rep.versions[0].previous_version == "1.0.0.0");
}

TEST_CASE("version join: a previous version with no exposed events gives an unbounded ratio",
          "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join(
        two_version_points(),
        {fail_row("1.0.0.0", 15, 2, 0, 2, 0, 0), fail_row("2.0.0.0", 12, 5, 0, 5, 5, 0)}, 30);
    const auto& v2 = rep.versions.at(0);
    REQUIRE(v2.failure_rate_ratio);
    CHECK(std::isinf(v2.failure_rate_ratio->estimate));
    CHECK(std::isinf(v2.failure_rate_ratio->upper));
    CHECK_FALSE(v2.failure_rate_ratio->reliable);
    // Lower bound by hand: 5 of 5 conditional events -> p = 0.025^(1/5); odds p/(1-p);
    // scaled by exposure_prev / exposure_cur = 15 / 12.
    const double p = std::pow(0.025, 0.2);
    CHECK(v2.failure_rate_ratio->lower == Approx(p / (1.0 - p) * 15.0 / 12.0).epsilon(1e-6));
    CHECK(rep.stat_failures == 0);
}

TEST_CASE("version join: a corrupt count the join cannot pre-screen is counted", "[dex][app_perf]") {
    // A negative store count is outside every documented precondition, so the
    // statistic comes back empty with the cohort above the floor: that is a
    // computation failure, not a refusal, and the consumer duty is to count it.
    SECTION("a rate that returns nothing") {
        const auto rep = app_perf_version_failure_join(
            {point("2.0.0.0", 100)}, {fail_row("2.0.0.0", 15, 0, 0, 0, -1, 0)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK_FALSE(r.exposure_below_floor);
        CHECK_FALSE(r.failure_rate);
        CHECK(rep.stat_failures == 1);
    }
    SECTION("a ratio that returns nothing") {
        // The corrupt newer row fails its own rate and the ratio against 1.0.0.0.
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 15, 1, 0, 1, 1, 0), fail_row("2.0.0.0", 15, 0, 0, 0, -1, 0)}, 30);
        CHECK_FALSE(rep.versions.at(0).failure_rate);
        CHECK_FALSE(rep.versions.at(0).failure_rate_ratio);
        CHECK(rep.versions.at(1).failure_rate);
        CHECK(rep.stat_failures == 2);
    }
}

TEST_CASE("version join: documented refusals are not counted as failures", "[dex][app_perf]") {
    SECTION("both arms zero events") {
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 15, 1, 0, 1, 0, 0), fail_row("2.0.0.0", 15, 1, 0, 1, 0, 0)}, 30);
        const auto& v2 = rep.versions.at(0);
        CHECK_FALSE(v2.failure_rate_ratio);
        REQUIRE(v2.failure_rate); // a zero rate is still a rate: 0 events over 15 devices
        CHECK(v2.failure_rate->estimate == 0.0);
        CHECK(rep.stat_failures == 0);
    }
    SECTION("an arm past the ratio's accuracy limit") {
        const std::int64_t over = kDexRateRatioMaxEvents + 1;
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 15, 1, 0, 1, 1, 0), fail_row("2.0.0.0", 15, over, 0, 15, over, 0)},
            30);
        CHECK_FALSE(rep.versions.at(0).failure_rate_ratio);
        CHECK(rep.versions.at(0).failure_rate); // dex_rate has no such ceiling
        CHECK(rep.stat_failures == 0);
    }
}

TEST_CASE("version join: 21 versions keep the 20 newest and say so", "[dex][app_perf]") {
    std::vector<AppPerfTrendPoint> pts;
    for (int i = 1; i <= 21; ++i)
        pts.push_back(point(std::to_string(i) + ".0.0.0", 100)); // inserted oldest first
    const auto rep = app_perf_version_failure_join(std::move(pts), {}, 30);
    REQUIRE(rep.versions.size() == kAppPerfVersionJoinCap);
    CHECK(rep.versions_truncated);
    CHECK(rep.versions.front().perf.version == "21.0.0.0");
    CHECK(rep.versions.back().perf.version == "2.0.0.0"); // 1.0.0.0, the oldest, dropped
    CHECK(rep.versions.back().previous_version.empty());  // the 20th row has no previous
    CHECK(row_of(rep, "1.0.0.0") == nullptr);
    CHECK(rep.versions[18].previous_version == "2.0.0.0");
}

TEST_CASE("newest versions: the one selection the join and the failure read share",
          "[dex][app_perf]") {
    std::vector<AppPerfTrendPoint> pts;
    for (int i = 1; i <= 21; ++i)
        pts.push_back(point(std::to_string(i) + ".0.0.0", 100)); // inserted oldest first
    pts.push_back(point("21.0.0.0", 101));                       // a repeat never duplicates
    const auto sel = app_perf_newest_versions(pts);
    const auto& keep = sel.versions;
    REQUIRE(keep.size() == kAppPerfVersionJoinCap);
    CHECK(sel.truncated);
    CHECK(keep.front() == "21.0.0.0");
    CHECK(keep.back() == "2.0.0.0");
    CHECK(std::find(keep.begin(), keep.end(), "1.0.0.0") == keep.end());

    // The join emits exactly these rows, in this order.
    const auto rep = app_perf_version_failure_join(pts, {}, 30);
    REQUIRE(rep.versions.size() == keep.size());
    for (std::size_t i = 0; i < keep.size(); ++i)
        CHECK(rep.versions[i].perf.version == keep[i]);
    CHECK(rep.versions_truncated == sel.truncated);
}

TEST_CASE("newest versions: exactly 20 distinct versions are not truncated", "[dex][app_perf]") {
    std::vector<AppPerfTrendPoint> pts;
    for (int i = 1; i <= 20; ++i)
        pts.push_back(point(std::to_string(i) + ".0.0.0", 100));
    const auto sel = app_perf_newest_versions(pts);
    CHECK(sel.versions.size() == 20);
    CHECK_FALSE(sel.truncated);
}

TEST_CASE("version join: exactly 20 versions are not truncated", "[dex][app_perf]") {
    std::vector<AppPerfTrendPoint> pts;
    for (int i = 1; i <= 20; ++i)
        pts.push_back(point(std::to_string(i) + ".0.0.0", 100));
    const auto rep = app_perf_version_failure_join(std::move(pts), {}, 30);
    CHECK(rep.versions.size() == 20);
    CHECK_FALSE(rep.versions_truncated);
}

TEST_CASE("version join: unsorted and repeated points still group and order", "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join(
        {point("2.0.0.0", 101), point("1.0.0.0", 100), point("2.0.0.0", 100),
         point("10.0.0.0", 100), point("1.0.0.0", 101)},
        {}, 30);
    REQUIRE(rep.versions.size() == 3);
    CHECK(rep.versions[0].perf.version == "10.0.0.0"); // numeric, not lexical
    CHECK(rep.versions[1].perf.version == "2.0.0.0");
    CHECK(rep.versions[2].perf.version == "1.0.0.0");
    CHECK(rep.versions[1].perf.day_count == 2);
    CHECK(rep.points.size() == 5); // the points pass through unchanged
}

TEST_CASE("versions json: a fixed report serialises to the exact string", "[dex][app_perf]") {
    AppPerfFleetReport rep;
    rep.failure_window_days = 30;

    AppPerfVersionRow a;
    a.perf.version = "2.0.0.0";
    a.perf.latest_day = 20000;
    a.perf.day_count = 3;
    a.perf.device_count = 15;
    a.affected_devices = 7;
    a.below_floor = true; // crashes omitted, hangs shown
    a.hangs = 3;
    a.exposure_devices = 15;
    a.exposed_crashes = 5;
    a.exposed_hangs = 2;
    a.failure_rate = DexInterval{0.5, 0.25, 1.5, false};
    a.previous_version = "1.0.0.0";
    a.failure_rate_ratio = DexInterval{kInf, 2.5, kInf, false};
    rep.versions.push_back(a);

    AppPerfVersionRow b;
    b.perf.version = "1.0.0.0";
    b.perf.latest_day = 19999;
    b.perf.day_count = 1;
    b.perf.device_count = 4;
    b.perf.suppressed = true;
    b.crashes = 0;
    b.hangs = 0;
    rep.versions.push_back(b);

    AppPerfVersionRow c;
    c.perf.version = "0.9.0.0";
    c.perf.latest_day = 19998;
    c.perf.day_count = 1;
    c.perf.device_count = 11;
    c.affected_devices = 11;
    c.below_floor = true; // hangs omitted, crashes shown
    c.crashes = 20;
    rep.versions.push_back(c);

    const std::string expected =
        R"([{"affected_devices":7,"below_floor":true,"day_count":3,"device_count":15,)"
        R"("exposed_crashes":5,"exposed_hangs":2,"exposure_below_floor":false,)"
        R"("exposure_devices":15,"failure_rate":{"estimate":0.5,"lower":0.25,"reliable":false,)"
        R"("upper":1.5},"failure_rate_ratio":{"estimate":null,"lower":2.5,"reliable":false,)"
        R"("unbounded":true,"upper":null},"hangs":3,"latest_day":20000,"previous_version":"1.0.0.0",)"
        R"("suppressed":false,"version":"2.0.0.0"},)"
        R"({"affected_devices":0,"below_floor":false,"crashes":0,"day_count":1,"device_count":4,)"
        R"("exposed_crashes":null,"exposed_hangs":null,"exposure_below_floor":false,)"
        R"("exposure_devices":null,"failure_rate":null,"failure_rate_ratio":null,"hangs":0,)"
        R"("latest_day":19999,"previous_version":null,"suppressed":true,"version":"1.0.0.0"},)"
        R"({"affected_devices":11,"below_floor":true,"crashes":20,"day_count":1,"device_count":11,)"
        R"("exposed_crashes":null,"exposed_hangs":null,"exposure_below_floor":false,)"
        R"("exposure_devices":null,"failure_rate":null,"failure_rate_ratio":null,)"
        R"("latest_day":19998,"previous_version":null,"suppressed":false,"version":"0.9.0.0"}])";
    CHECK(dex_app_perf_versions_json(rep) == expected);
}

TEST_CASE("versions json: a small rate is never rounded to two decimals", "[dex][app_perf]") {
    AppPerfFleetReport rep;
    AppPerfVersionRow r;
    r.perf.version = "1.0.0.0";
    r.exposure_devices = 15;
    r.failure_rate = DexInterval{0.004, 0.0015, 0.0123456789, false};
    rep.versions.push_back(r);
    const std::string out = dex_app_perf_versions_json(rep);
    CHECK(out.find(R"("estimate":0.004,)") != std::string::npos);
    CHECK(out.find(R"("lower":0.0015,)") != std::string::npos);
    CHECK(out.find("0.0123456789") != std::string::npos);
    CHECK(out.find("0.00,") == std::string::npos);
}

TEST_CASE("versions json: an empty report is an empty array", "[dex][app_perf]") {
    CHECK(dex_app_perf_versions_json(AppPerfFleetReport{}) == "[]");
}

TEST_CASE("day window: whole UTC days ending at the current midnight", "[dex][app_perf]") {
    // 2023-11-15T00:00:00Z is 1'700'006'400; a mid-day instant still floors to it.
    constexpr std::int64_t kMidnight = 1'700'006'400;
    const auto w7 = dex_day_window(kMidnight + 12'345, 7);
    CHECK(w7.end_day == kMidnight);
    CHECK(w7.since_day == 1'699'401'600);
    CHECK(w7.since_iso == "2023-11-08T00:00:00Z");
    const auto w30 = dex_day_window(kMidnight, 30);
    CHECK(w30.end_day == kMidnight);
    CHECK(w30.since_day == 1'697'414'400);
    CHECK(w30.since_iso == "2023-10-16T00:00:00Z");
}
