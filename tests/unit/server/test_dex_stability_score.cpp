/**
 * test_dex_stability_score.cpp — the pure application/version stability score
 * (dex_stability_score.hpp). Known-answer cases; no store, no process, no I/O.
 */
#include "dex_stability_score.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <limits>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Approx;

namespace {
constexpr std::int64_t kFloor = 10;

StabilityInputs mk(std::int64_t n, std::int64_t a, std::int64_t crash, std::int64_t hang = 0,
                   std::optional<RateRatioInterval> rr = std::nullopt) {
    StabilityInputs i;
    i.reporting_devices = n;
    i.devices_affected = a;
    i.crash_events = crash;
    i.hang_events = hang;
    i.rate_ratio = rr;
    return i;
}

void require_scored(const StabilityScore& r, double score, StabilityBand band) {
    REQUIRE(r.score.has_value());
    REQUIRE(r.band.has_value());
    CHECK(*r.score == Approx(score).margin(0.01));
    CHECK(*r.band == band);
    CHECK(std::string(r.withheld).empty());
    REQUIRE(r.deductions.size() == 4);
    double sum = 0.0;
    for (const auto& d : r.deductions)
        sum += d.points;
    CHECK(100.0 - sum == Approx(*r.score).margin(1e-9));
}

void require_withheld(const StabilityScore& r, const char* why) {
    CHECK_FALSE(r.score.has_value());
    CHECK_FALSE(r.band.has_value());
    CHECK(std::string(r.withheld) == why);
    CHECK(r.deductions.empty());
}
} // namespace

TEST_CASE("stability: failing on every device", "[dex][stability]") {
    auto r = compute_stability_score(mk(1000, 1000, 5000, 5000), kFloor);
    require_scored(r, 12.0, StabilityBand::Poor);
    CHECK(r.deductions[0].points == Approx(60.0));
    CHECK(r.deductions[1].points == Approx(20.0));
    CHECK(r.deductions[2].points == Approx(8.0));
    CHECK_FALSE(r.deductions[3].assessed);

    auto crashes_only = compute_stability_score(mk(1000, 1000, 5000, 0), kFloor);
    require_scored(crashes_only, 20.0, StabilityBand::Poor);
    CHECK(crashes_only.deductions[2].points == Approx(0.0));
}

TEST_CASE("stability: one crash-looping device", "[dex][stability]") {
    auto r = compute_stability_score(mk(10000, 1, 5), kFloor);
    require_scored(r, 99.99, StabilityBand::Excellent);
    CHECK(std::string(r.deductions[0].name) == "breadth");
    CHECK(r.deductions[0].points >= r.deductions[1].points);
}

TEST_CASE("stability: per-device capping is the caller's job", "[dex][stability]") {
    require_scored(compute_stability_score(mk(1000, 300, 304), kFloor), 80.78,
                   StabilityBand::Good);
    require_withheld(compute_stability_score(mk(1000, 300, 100299), kFloor), "inconsistent");
}

TEST_CASE("stability: cross-field consistency", "[dex][stability]") {
    require_withheld(compute_stability_score(mk(1000, 0, 100000), kFloor), "inconsistent");
    require_withheld(compute_stability_score(mk(1000, 10, 3, 2), kFloor), "inconsistent");
    require_withheld(compute_stability_score(mk(1000, 10, 51), kFloor), "inconsistent");
    CHECK(compute_stability_score(mk(1000, 10, 50, 50), kFloor).score.has_value());
    require_scored(compute_stability_score(mk(10, 0, 0), kFloor), 100.0,
                   StabilityBand::Excellent);
}

TEST_CASE("stability: rare, widespread-mild and half-fleet cases", "[dex][stability]") {
    require_scored(compute_stability_score(mk(1000, 20, 25, 5), kFloor), 98.7,
                   StabilityBand::Excellent);
    require_scored(compute_stability_score(mk(1000, 300, 300), kFloor), 80.8, StabilityBand::Good);
    require_scored(compute_stability_score(mk(1000, 500, 2500), kFloor), 60.0, StabilityBand::Fair);
}

TEST_CASE("stability: withheld ladder", "[dex][stability]") {
    require_withheld(compute_stability_score(mk(0, -4, 99), kFloor), "no_population");
    require_withheld(compute_stability_score(mk(9, 1, 1), kFloor), "below_floor");
    CHECK(compute_stability_score(mk(10, 1, 1), kFloor).score.has_value());
    require_withheld(compute_stability_score(mk(1000, 1001, 1001), kFloor), "inconsistent");
    require_withheld(compute_stability_score(mk(1000, 0, -1), kFloor), "inconsistent");
    require_withheld(compute_stability_score(mk(5, 6, 6), kFloor), "inconsistent");
}

TEST_CASE("stability: weight contract", "[dex][stability]") {
    CHECK(stability_weights_valid(kStabilityWeights));
    const double nan = std::numeric_limits<double>::quiet_NaN();
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {nan, 20, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {60, -1, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(0, 0, 0), kFloor, {nan, 20, 8, 12}),
                     "no_population");

    auto over = compute_stability_score(mk(1000, 1000, 5000), kFloor, {200, 20, 8, 12});
    REQUIRE(over.score.has_value());
    CHECK(*over.score == 0.0);
    CHECK(*over.band == StabilityBand::Poor);
    CHECK(over.deductions[0].points == Approx(200.0));
    CHECK(over.deductions[1].points == Approx(20.0));
}

TEST_CASE("stability: hangs weigh less than crashes", "[dex][stability]") {
    auto c = compute_stability_score(mk(1000, 100, 300, 0), kFloor);
    auto h = compute_stability_score(mk(1000, 100, 0, 300), kFloor);
    REQUIRE(c.score);
    REQUIRE(h.score);
    CHECK(h.deductions[2].points / c.deductions[1].points == Approx(8.0 / 20.0));
}

TEST_CASE("stability: regression term", "[dex][stability]") {
    auto reg = [](std::optional<RateRatioInterval> rr) {
        return compute_stability_score(mk(1000, 100, 300, 0, rr), kFloor);
    };
    auto none = reg(std::nullopt);
    CHECK_FALSE(none.deductions[3].assessed);
    CHECK(none.deductions[3].points == 0.0);

    for (auto rr : {RateRatioInterval{0.8, 1.3}, RateRatioInterval{0.3, 0.7}}) {
        auto r = reg(rr);
        CHECK(r.deductions[3].assessed);
        CHECK(r.deductions[3].points == 0.0);
        require_scored(r, 92.8, StabilityBand::Excellent);
    }
    auto f = reg(RateRatioInterval{2.0, 4.5});
    CHECK(f.deductions[3].points == Approx(6.0));
    require_scored(f, 86.8, StabilityBand::Good);
    CHECK(reg(RateRatioInterval{3.0, 9.0}).deductions[3].points == Approx(12.0));

    const double nan = std::numeric_limits<double>::quiet_NaN();
    for (auto rr : {RateRatioInterval{5.0, 2.0}, RateRatioInterval{nan, 2.0},
                    RateRatioInterval{-1.0, 2.0}}) {
        auto r = reg(rr);
        CHECK_FALSE(r.deductions[3].assessed);
        CHECK(r.deductions[3].points == 0.0);
    }
    // Full regression alone never reaches the bottom band.
    require_scored(compute_stability_score(mk(1000, 0, 0, 0, RateRatioInterval{3.0, 9.0}), kFloor),
                   88.0, StabilityBand::Good);
}

TEST_CASE("stability: decomposition and constants", "[dex][stability]") {
    auto r = compute_stability_score(mk(1000, 100, 300, 20, RateRatioInterval{2.0, 4.5}), kFloor);
    REQUIRE(r.deductions.size() == 4);
    CHECK(std::string(r.deductions[0].name) == "breadth");
    CHECK(std::string(r.deductions[1].name) == "crashes");
    CHECK(std::string(r.deductions[2].name) == "hangs");
    CHECK(std::string(r.deductions[3].name) == "regression");
    CHECK(std::string(stability_band_label(StabilityBand::Excellent)) == "excellent");
    CHECK(std::string(stability_band_label(StabilityBand::Good)) == "good");
    CHECK(std::string(stability_band_label(StabilityBand::Fair)) == "fair");
    CHECK(std::string(stability_band_label(StabilityBand::Poor)) == "poor");
}

TEST_CASE("stability: band edges", "[dex][stability]") {
    CHECK(stability_band(90.0) == StabilityBand::Excellent);
    CHECK(stability_band(89.99) == StabilityBand::Good);
    CHECK(stability_band(75.0) == StabilityBand::Good);
    CHECK(stability_band(74.99) == StabilityBand::Fair);
    CHECK(stability_band(60.0) == StabilityBand::Fair);
    CHECK(stability_band(59.99) == StabilityBand::Poor);
}

TEST_CASE("stability: rank flip under perturbed weights", "[dex][stability]") {
    const StabilityInputs x = mk(1000, 300, 300);
    const StabilityInputs y = mk(1000, 200, 1000);
    const StabilityWeights pert{10, 70, 8, 12};

    auto f = stability_rank_flip({x, y}, kFloor, pert);
    REQUIRE(f.has_value());
    CHECK(f->first == 0);
    CHECK(f->second == 1);

    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, kStabilityWeights).has_value());
    CHECK_FALSE(stability_rank_flip({x, x}, kFloor, pert).has_value());

    const StabilityInputs tiny = mk(5, 1, 1);
    auto g = stability_rank_flip({tiny, x, y}, kFloor, pert);
    REQUIRE(g.has_value());
    CHECK(g->first == 1);
    CHECK(g->second == 2);

    const double nan = std::numeric_limits<double>::quiet_NaN();
    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, {nan, 70, 8, 12}).has_value());
}
