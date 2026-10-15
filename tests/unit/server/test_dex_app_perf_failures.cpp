/**
 * test_dex_app_perf_failures.cpp -- the PURE per-version crash and hang join of the
 * fleet app-perf report: the canonical-version comparator, the no-device-floor
 * publication rule, the rate and rate-ratio wiring, the 20-version cap, and the
 * shared versions[] serializer. No store, no PG, no I/O.
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

AppPerfVersionFailureRow fail_row(const std::string& version, std::optional<std::int64_t> exposure,
                                  std::int64_t crashes, std::int64_t hangs, std::int64_t affected,
                                  std::int64_t exp_crashes, std::int64_t exp_hangs) {
    AppPerfVersionFailureRow r;
    r.version = version;
    r.exposure_devices = exposure;
    r.crashes = crashes;
    r.hangs = hangs;
    r.affected_devices = affected;
    r.exposed_crashes = exp_crashes;
    r.exposed_hangs = exp_hangs;
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
        fail_row("2.0.0.0", 15, 17, 3, 14, 10, 2),
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
    CHECK(v2.crashes == 17);
    CHECK(v2.hangs == 3);
    CHECK(v2.exposure_devices == 15);
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
    const auto ratio_oracle = dex_rate_ratio(12, 15.0, 5, 12.0, 1.0);
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

TEST_CASE("version join: figures are published at any device count", "[dex][app_perf]") {
    // Maintainer ruling 2026-10-14: the join carries no device floor, so a cohort of
    // one device publishes every figure exactly as a large one does.
    SECTION("one device publishes its counts, exposed figures and rate") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 1, 1, 0, 1, 1, 0)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.affected_devices == 1);
        CHECK(r.crashes == 1);
        CHECK(r.hangs == 0);
        CHECK(r.exposure_devices == 1);
        CHECK(r.exposed_crashes == 1);
        CHECK(r.exposed_hangs == 0);
        REQUIRE(r.failure_rate);
        CHECK(r.failure_rate->estimate == 1.0);
        const auto oracle = dex_rate(1, 1.0);
        REQUIRE(oracle);
        CHECK(r.failure_rate->lower == oracle->lower);
        CHECK(r.failure_rate->upper == oracle->upper);
        CHECK(rep.stat_failures == 0);
    }
    SECTION("nine devices likewise, hangs included") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 9, 9, 3, 9, 9, 3)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.crashes == 9);
        CHECK(r.hangs == 3);
        CHECK(r.exposed_crashes == 9);
        CHECK(r.exposed_hangs == 3);
        REQUIRE(r.failure_rate);
        CHECK(r.failure_rate->estimate == Approx(12.0 / 9.0));
        CHECK(rep.stat_failures == 0);
    }
    SECTION("a one-device version against a nine-device version publishes a ratio") {
        // 2.0.0.0: 2 exposed events over 1 device; 1.0.0.0: 6 over 9. The join
        // states its minimum exposure of 1 explicitly; the default guard is 1 too
        // since the cohort floor became one device.
        const auto rep = app_perf_version_failure_join(
            two_version_points(),
            {fail_row("1.0.0.0", 9, 5, 1, 6, 5, 1), fail_row("2.0.0.0", 1, 2, 0, 1, 2, 0)}, 30);
        const auto& v2 = rep.versions.at(0);
        REQUIRE(v2.failure_rate_ratio);
        CHECK(dex_rate_ratio(2, 1.0, 6, 9.0)); // the default guard admits one device-unit
        const auto oracle = dex_rate_ratio(2, 1.0, 6, 9.0, 1.0);
        REQUIRE(oracle);
        CHECK(v2.failure_rate_ratio->estimate == oracle->estimate);
        CHECK(v2.failure_rate_ratio->lower == oracle->lower);
        CHECK(v2.failure_rate_ratio->upper == oracle->upper);
        CHECK(v2.failure_rate_ratio->estimate == Approx(2.0 / (6.0 / 9.0)));
        CHECK(rep.stat_failures == 0);
    }
    SECTION("a total and its exposed part are both shown whatever the remainder") {
        // 30 crashes, 29 on exposed devices: one event outside the exposure cohort.
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 15, 30, 4, 20, 29, 4)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.crashes == 30);
        CHECK(r.exposed_crashes == 29);
        CHECK(r.hangs == 4);
        CHECK(r.exposed_hangs == 4);
        REQUIRE(r.failure_rate);
    }
    SECTION("a zero exposure publishes zero exposed counts and a null rate, not a failure") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", 0, 3, 1, 3, 0, 0)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.exposure_devices == 0);
        CHECK(r.exposed_crashes == 0);
        CHECK(r.exposed_hangs == 0);
        CHECK_FALSE(r.failure_rate); // never a divide by zero, never a healthy zero
        CHECK(r.crashes == 3);
        CHECK(r.hangs == 1);
        CHECK(rep.stat_failures == 0);
    }
    SECTION("a zero-exposure arm leaves the ratio null and uncounted") {
        for (const auto zero_newer : {true, false}) {
            CAPTURE(zero_newer);
            const auto rep = app_perf_version_failure_join(
                two_version_points(),
                {fail_row("1.0.0.0", zero_newer ? 9 : 0, 5, 1, 6, 5, 1),
                 fail_row("2.0.0.0", zero_newer ? 0 : 9, 2, 0, 1, 2, 0)},
                30);
            CHECK_FALSE(rep.versions.at(0).failure_rate_ratio);
            CHECK(rep.versions.at(0).previous_version == "1.0.0.0");
            CHECK(rep.stat_failures == 0);
        }
    }
    SECTION("unknown exposure keeps the breadth counts and nulls the rest") {
        const auto rep = app_perf_version_failure_join(
            {point("1.0.0.0", 100)}, {fail_row("1.0.0.0", std::nullopt, 2, 0, 2, 0, 0)}, 30);
        const auto& r = rep.versions.at(0);
        CHECK(r.crashes == 2);
        CHECK(r.affected_devices == 2);
        CHECK_FALSE(r.exposure_devices);
        CHECK_FALSE(r.exposed_crashes);
        CHECK_FALSE(r.exposed_hangs);
        CHECK_FALSE(r.failure_rate);
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
    CHECK_FALSE(v2.exposed_crashes);
    CHECK_FALSE(v2.exposed_hangs);
    CHECK_FALSE(v2.failure_rate);
    CHECK_FALSE(v2.failure_rate_ratio);
    CHECK(v2.crashes == 17); // breadth is present whatever the exposure
    CHECK(v2.hangs == 3);
    CHECK(rep.stat_failures == 0);
}

TEST_CASE("version join: no failure row at all reads as zero failures", "[dex][app_perf]") {
    const auto rep = app_perf_version_failure_join({point("1.0.0.0", 100)}, {}, 30);
    const auto& r = rep.versions.at(0);
    CHECK(r.affected_devices == 0);
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
    // statistic comes back empty with a positive exposure: that is a computation
    // failure, not a refusal, and the consumer duty is to count it.
    SECTION("a rate that returns nothing") {
        const auto rep = app_perf_version_failure_join(
            {point("2.0.0.0", 100)}, {fail_row("2.0.0.0", 15, 0, 0, 0, -1, 0)}, 30);
        const auto& r = rep.versions.at(0);
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
    a.crashes = 4;
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
    rep.versions.push_back(b);

    AppPerfVersionRow c;
    c.perf.version = "0.9.0.0";
    c.perf.latest_day = 19998;
    c.perf.day_count = 1;
    c.perf.device_count = 11;
    c.affected_devices = 1;
    c.crashes = 20;
    c.exposure_devices = 0;
    c.exposed_crashes = 0;
    c.exposed_hangs = 0;
    rep.versions.push_back(c);

    const std::string expected =
        R"([{"affected_devices":7,"crashes":4,"day_count":3,"device_count":15,)"
        R"("exposed_crashes":5,"exposed_hangs":2,)"
        R"("exposure_devices":15,"failure_rate":{"estimate":0.5,"lower":0.25,"reliable":false,)"
        R"("upper":1.5},"failure_rate_ratio":{"estimate":null,"lower":2.5,"reliable":false,)"
        R"("unbounded":true,"upper":null},"hangs":3,"latest_day":20000,"previous_version":"1.0.0.0",)"
        R"("suppressed":false,"version":"2.0.0.0"},)"
        R"({"affected_devices":0,"crashes":0,"day_count":1,"device_count":4,)"
        R"("exposed_crashes":null,"exposed_hangs":null,)"
        R"("exposure_devices":null,"failure_rate":null,"failure_rate_ratio":null,"hangs":0,)"
        R"("latest_day":19999,"previous_version":null,"suppressed":true,"version":"1.0.0.0"},)"
        R"({"affected_devices":1,"crashes":20,"day_count":1,"device_count":11,)"
        R"("exposed_crashes":0,"exposed_hangs":0,)"
        R"("exposure_devices":0,"failure_rate":null,"failure_rate_ratio":null,"hangs":0,)"
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
