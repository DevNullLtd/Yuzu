/**
 * test_dex_stability_score.cpp — the pure application/version stability score
 * (dex_stability_score.hpp). Known-answer cases; no store, no process, no I/O.
 */
#include "dex_perf_model.hpp" // kDexCohortFloor
#include "dex_stability_score.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Approx;

namespace {
using Rr = StabilityRateRatioInterval;
constexpr std::int64_t kFloor = kDexCohortFloor;
constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
constexpr double kInf = std::numeric_limits<double>::infinity();

// mk(N reporting, A affected, capped crashes, capped hangs, rate-ratio interval)
StabilityInputs mk(std::int64_t n, std::int64_t a, std::int64_t crash, std::int64_t hang = 0,
                   std::optional<Rr> rr = std::nullopt) {
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
    CHECK(*r.score == Approx(score).epsilon(0).margin(0.01));
    CHECK(*r.band == band);
    CHECK(std::string(r.withheld).empty());
    REQUIRE(r.deductions.size() == 4);
    double sum = 0.0;
    for (const auto& d : r.deductions)
        sum += d.points;
    CHECK_THAT(*r.score, Catch::Matchers::WithinAbs(100.0 - sum, 1e-12));
}

void require_withheld(const StabilityScore& r, const char* why) {
    CHECK_FALSE(r.score.has_value());
    CHECK_FALSE(r.band.has_value());
    CHECK(std::string(r.withheld) == why);
    CHECK(r.deductions.empty());
}

// The floor is a mandatory argument. A concept (not std::is_invocable) so a
// regression is a red case, not a broken translation unit. The flip probe
// passes weights where the floor belongs: it is well-formed only if `floor`
// stops being the argument right after the apps (removed, or moved behind the
// defaulted tail).
template <class In>
concept ScoreWithoutFloor = requires(const In& i) { compute_stability_score(i); };
template <class V>
concept FlipWithoutFloor =
    requires(const V& v, const StabilityWeights& w) { stability_rank_flip(v, w); };
// The one-argument form: well-formed only if floor, perturbed and base are all
// defaulted, which the two-argument probe above cannot see.
template <class V>
concept FlipWithOnlyApps = requires(const V& v) { stability_rank_flip(v); };
} // namespace

TEST_CASE("stability: failing on every device", "[dex][stability]") {
    auto r = compute_stability_score(mk(1000, 1000, 5000, 5000), kFloor);
    require_scored(r, 12.0, StabilityBand::Poor);
    CHECK(r.deductions[0].points == Approx(60.0));
    CHECK(r.deductions[1].points == Approx(20.0));
    CHECK(r.deductions[2].points == Approx(8.0));
    CHECK(r.deductions[0].assessed);
    CHECK(r.deductions[1].assessed);
    CHECK(r.deductions[2].assessed);
    CHECK_FALSE(r.deductions[3].assessed);

    auto crashes_only = compute_stability_score(mk(1000, 1000, 5000, 0), kFloor);
    require_scored(crashes_only, 20.0, StabilityBand::Poor);
    CHECK(crashes_only.deductions[2].points == Approx(0.0));
}

TEST_CASE("stability: one crash-looping device", "[dex][stability]") {
    auto r = compute_stability_score(mk(10000, 1, 5), kFloor);
    require_scored(r, 99.99, StabilityBand::Excellent);
    CHECK_THAT(*r.score, Catch::Matchers::WithinAbs(99.992, 1e-9));
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
    require_withheld(compute_stability_score(mk(1000, 10, 0, 51), kFloor), "inconsistent");
    // Only the hang < 0 guard catches this one.
    require_withheld(compute_stability_score(mk(1000, 1, 5, -1), kFloor), "inconsistent");
    // Only the crash < 0 guard catches this one.
    require_withheld(compute_stability_score(mk(1000, 1, -1, 5), kFloor), "inconsistent");
    // The affected < 0 guard is the only thing that withholds this one; without
    // it A * cap overflows (signed overflow under UBSan).
    require_withheld(
        compute_stability_score(mk(1000, (std::numeric_limits<std::int64_t>::min)(), 0), kFloor),
        "inconsistent");
    CHECK(compute_stability_score(mk(1000, 10, 50, 50), kFloor).score.has_value());
    require_scored(compute_stability_score(mk(10, 0, 0), kFloor), 100.0,
                   StabilityBand::Excellent);
}

TEST_CASE("stability: int64 extremes", "[dex][stability]") {
    const auto big = (std::numeric_limits<std::int64_t>::max)();
    auto r = compute_stability_score(mk(big, big, big, 0), kFloor);
    require_scored(r, 36.0, StabilityBand::Poor);
    CHECK(r.deductions[0].points == Approx(60.0));
    CHECK(r.deductions[1].points == Approx(4.0));
}

TEST_CASE("stability: cap check at the int64 overflow boundary", "[dex][stability]") {
    const std::int64_t m = (std::numeric_limits<std::int64_t>::max)();
    const std::int64_t a = m / 5; // largest A whose A * cap is representable
    CHECK(compute_stability_score(mk(m, a, a * 5), kFloor).score.has_value());
    CHECK(compute_stability_score(mk(m, a, 0, a * 5), kFloor).score.has_value());
    CHECK(std::string(compute_stability_score(mk(m, a, a * 5 + 1), kFloor).withheld) ==
          "inconsistent");
    CHECK(std::string(compute_stability_score(mk(m, a, 0, a * 5 + 1), kFloor).withheld) ==
          "inconsistent");
    // A * cap would overflow: every representable count is within the cap.
    CHECK(compute_stability_score(mk(m, a + 1, m), kFloor).score.has_value());
    CHECK(compute_stability_score(mk(m, a + 1, 0, m), kFloor).score.has_value());
}

TEST_CASE("stability: rare widespread-mild and half-fleet cases", "[dex][stability]") {
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

TEST_CASE("stability: the floor argument is mandatory and honoured", "[dex][stability]") {
    CHECK_FALSE(ScoreWithoutFloor<StabilityInputs>);
    CHECK_FALSE(FlipWithoutFloor<std::vector<StabilityInputs>>);
    CHECK_FALSE(FlipWithOnlyApps<std::vector<StabilityInputs>>);
    require_withheld(compute_stability_score(mk(50, 1, 1), 100), "below_floor");
    CHECK(compute_stability_score(mk(50, 1, 1), 50).score.has_value());
    CHECK(compute_stability_score(mk(5, 1, 1), 5).score.has_value());
    CHECK(compute_stability_score(mk(5, 1, 1), 0).score.has_value());
    require_withheld(compute_stability_score(mk(5, 1, 1), 6), "below_floor");
}

TEST_CASE("stability: weight contract", "[dex][stability]") {
    CHECK(stability_weights_valid(kStabilityWeights));
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {kNaN, 20, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {60, 20, kNaN, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {60, 20, 8, -1}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {kInf, 20, 8, 12}),
                     "invalid_weights");
    // invalid_weights outranks inconsistent and below_floor.
    require_withheld(compute_stability_score(mk(1000, 1001, 1001), kFloor, {kNaN, 20, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(5, 1, 1), kFloor, {kNaN, 20, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(1000, 1, 1), kFloor, {60, -1, 8, 12}),
                     "invalid_weights");
    require_withheld(compute_stability_score(mk(0, 0, 0), kFloor, {kNaN, 20, 8, 12}),
                     "no_population");

    const struct {
        const char* name;
        double StabilityWeights::*slot;
    } slots[] = {{"breadth", &StabilityWeights::breadth},
                 {"crashes", &StabilityWeights::crashes},
                 {"hangs", &StabilityWeights::hangs},
                 {"regression", &StabilityWeights::regression}};
    for (const auto& [name, slot] : slots) {
        for (double bad : {kNaN, kInf, -kInf, -1.0}) {
            INFO(name << " = " << bad);
            StabilityWeights bw = kStabilityWeights;
            bw.*slot = bad;
            CHECK_FALSE(stability_weights_valid(bw));
        }
        INFO(name << " = 0");
        StabilityWeights zw = kStabilityWeights;
        zw.*slot = 0.0;
        CHECK(stability_weights_valid(zw));
    }
    CHECK(stability_weights_valid({0, 0, 0, 0}));
    // Zero weights score every cohort 100: the precondition of the rank-flip tie guard.
    CHECK(compute_stability_score(mk(1000, 300, 300), kFloor, {0, 0, 0, 0}).score == 100.0);

    auto over = compute_stability_score(mk(1000, 1000, 5000), kFloor, {200, 20, 8, 12});
    REQUIRE(over.score.has_value());
    REQUIRE(over.deductions.size() == 4);
    CHECK(*over.score == 0.0);
    CHECK(*over.band == StabilityBand::Poor);
    CHECK(over.deductions[0].points == Approx(200.0));
    CHECK(over.deductions[1].points == Approx(20.0));
}

TEST_CASE("stability: near-maximum finite weights give finite rows at ordinary cohort size",
          "[dex][stability]") {
    auto r = compute_stability_score(mk(1000, 1000, 5000, 5000), kFloor, {1e308, 1e308, 1e308, 0});
    REQUIRE(r.score.has_value());
    REQUIRE(r.deductions.size() == 4);
    CHECK(*r.score == 0.0);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(std::isfinite(r.deductions[i].points));
        CHECK(r.deductions[i].points == Approx(1e308));
    }
}

TEST_CASE("stability: hangs weigh less than crashes", "[dex][stability]") {
    auto c = compute_stability_score(mk(1000, 100, 300, 0), kFloor);
    auto h = compute_stability_score(mk(1000, 100, 0, 300), kFloor);
    REQUIRE(c.score);
    REQUIRE(h.score);
    REQUIRE(c.deductions.size() == 4);
    REQUIRE(h.deductions.size() == 4);
    CHECK(h.deductions[2].points / c.deductions[1].points == Approx(8.0 / 20.0));
}

TEST_CASE("stability: regression term", "[dex][stability]") {
    auto reg = [](std::optional<Rr> rr) {
        auto r = compute_stability_score(mk(1000, 100, 300, 0, rr), kFloor);
        REQUIRE(r.deductions.size() == 4);
        return r;
    };
    auto none = reg(std::nullopt);
    CHECK_FALSE(none.deductions[3].assessed);
    CHECK(none.deductions[3].points == 0.0);

    // Assessed at 0 points: improving, containing 1, or an open (+inf) upper bound.
    for (auto rr : {Rr{0.8, 1.3}, Rr{0.3, 0.7},
                    Rr{0.8, kInf}}) {
        INFO(rr.lower << " " << rr.upper);
        auto r = reg(rr);
        CHECK(r.deductions[3].assessed);
        CHECK(r.deductions[3].points == 0.0);
        require_scored(r, 92.8, StabilityBand::Excellent);
    }
    auto f = reg(Rr{2.0, 4.5});
    CHECK(f.deductions[3].points == Approx(6.0));
    require_scored(f, 86.8, StabilityBand::Good);
    CHECK(reg(Rr{3.0, 9.0}).deductions[3].points == Approx(12.0));
    // The regression weight is read from the weights, not fixed at 12:
    // 100 - (6.0 + 1.2 + 0 + 6 * clamp((3 - 1) / 2)) = 86.8.
    auto custom = compute_stability_score(mk(1000, 100, 300, 0, Rr{3.0, 9.0}), kFloor,
                                          StabilityWeights{60, 20, 8, 6});
    REQUIRE(custom.deductions.size() == 4);
    CHECK(custom.deductions[3].points == Approx(6.0));
    require_scored(custom, 86.8, StabilityBand::Good);
    // A previous version with no events gives an open upper bound; lower alone
    // counts. The statistics sibling labels such an interval unreliable, and it
    // is still assessed: the label is for display, never suppression.
    CHECK(reg(Rr{3.0, kInf}).deductions[3].points == Approx(12.0));

    for (auto rr : {Rr{5.0, 2.0}, Rr{kNaN, 2.0},
                    Rr{-1.0, 2.0}, Rr{0.8, kNaN},
                    Rr{0.8, -kInf}, Rr{kInf, kInf}}) {
        INFO(rr.lower << " " << rr.upper);
        auto r = reg(rr);
        CHECK_FALSE(r.deductions[3].assessed);
        CHECK(r.deductions[3].points == 0.0);
    }
    // Clamp and boundary values.
    CHECK(reg(Rr{10.0, 20.0}).deductions[3].points == Approx(12.0));
    CHECK(reg(Rr{1e9, 2e9}).deductions[3].points == Approx(12.0));
    CHECK(reg(Rr{0.0, 1.0}).deductions[3].assessed);
    CHECK(reg(Rr{0.0, 1.0}).deductions[3].points == 0.0);
    CHECK(reg(Rr{1.5, 1.5}).deductions[3].assessed);
    CHECK(reg(Rr{1.5, 1.5}).deductions[3].points == Approx(3.0));
    // Full regression alone never reaches the bottom band.
    require_scored(compute_stability_score(
                       mk(1000, 0, 0, 0, Rr{3.0, 9.0}), kFloor),
                   88.0, StabilityBand::Good);
}

TEST_CASE("stability: decomposition and labels", "[dex][stability]") {
    auto r = compute_stability_score(
        mk(1000, 100, 300, 20, Rr{2.0, 4.5}), kFloor);
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

TEST_CASE("stability: display score rounds half away from zero at one decimal",
          "[dex][stability]") {
    CHECK(stability_display_score(59.999999999999993) == 60.0);
    CHECK(stability_display_score(74.96) == 75.0);
    CHECK(stability_display_score(74.94) == 74.9);
    CHECK(stability_display_score(0.0) == 0.0);
    CHECK(stability_display_score(100.0) == 100.0);
    // Exact ties: 84.25 and 84.45 times 10 are exactly 842.5 and 844.5 in double
    // arithmetic, so half-away goes up on both; round-half-even would give 84.2
    // and 84.4.
    CHECK(stability_display_score(84.25) == 84.3);
    CHECK(stability_display_score(84.45) == 84.5);
    // A cohort that really scores 84.25: 100 - 60 * 32/160 - 20 * 150/800
    // = 100 - 12 - 3.75. The products land on 12.0 and 3.75 exactly (32/160 is
    // not representable, its product with 60 still rounds to 12.0), so the
    // score is exactly 84.25.
    auto tie = compute_stability_score(mk(160, 32, 150, 0), kFloor);
    REQUIRE(tie.score.has_value());
    CHECK(*tie.score == 84.25);
    CHECK(stability_display_score(*tie.score) == 84.3);
}

TEST_CASE("stability: band edges are banded on the displayed score", "[dex][stability]") {
    CHECK(stability_band(90.0) == StabilityBand::Excellent);
    CHECK(stability_band(89.96) == StabilityBand::Excellent);
    CHECK(stability_band(89.94) == StabilityBand::Good);
    CHECK(stability_band(89.9) == StabilityBand::Good);
    CHECK(stability_band(75.0) == StabilityBand::Good);
    CHECK(stability_band(74.96) == StabilityBand::Good);
    CHECK(stability_band(74.94) == StabilityBand::Fair);
    CHECK(stability_band(60.0) == StabilityBand::Fair);
    CHECK(stability_band(59.96) == StabilityBand::Fair);
    CHECK(stability_band(59.94) == StabilityBand::Poor);
}

TEST_CASE("stability: scores that display at an edge band at that edge", "[dex][stability]") {
    // Exact score 60, computed as 59.999999999999993.
    auto exact = compute_stability_score(mk(12, 6, 26, 10), kFloor);
    REQUIRE(exact.score.has_value());
    REQUIRE(exact.band.has_value());
    CHECK(*exact.score < 60.0);
    CHECK(*exact.band == StabilityBand::Fair);

    // Score 74.96 displays 75.0 and bands good.
    auto shown = compute_stability_score(mk(10, 3, 12, 14), kFloor);
    REQUIRE(shown.score.has_value());
    REQUIRE(shown.band.has_value());
    CHECK(*shown.score == Approx(74.96).epsilon(0).margin(1e-9));
    CHECK(stability_display_score(*shown.score) == 75.0);
    CHECK(*shown.band == StabilityBand::Good);
}

TEST_CASE("stability: exact-edge cohorts band at the edge and one more crash bands lower",
          "[dex][stability]") {
    // Integer identity for a score of exactly e:
    //   5N(100 - e) = 300A + 20 crash + 8 hang
    // so the cohort is built from integers and the expectation needs no reference
    // implementation of the code under test.
    const struct {
        std::int64_t edge;
        StabilityBand at;
        StabilityBand below;
    } edges[] = {{90, StabilityBand::Excellent, StabilityBand::Good},
                 {75, StabilityBand::Good, StabilityBand::Fair},
                 {60, StabilityBand::Fair, StabilityBand::Poor}};
    int cohorts = 0;
    for (std::int64_t n = 10; n <= 60; ++n) {
        for (std::int64_t a = 0; a <= n; ++a) {
            for (std::int64_t crash = 0; crash <= 5 * a; ++crash) {
                for (const auto& e : edges) {
                    const std::int64_t rest = 5 * n * (100 - e.edge) - 300 * a - 20 * crash;
                    if (rest < 0 || rest % 8 != 0)
                        continue;
                    const std::int64_t hang = rest / 8;
                    if (hang > 5 * a || crash + hang < a)
                        continue;
                    INFO("N=" << n << " A=" << a << " crash=" << crash << " hang=" << hang
                              << " edge=" << e.edge);
                    auto r = compute_stability_score(mk(n, a, crash, hang), kFloor);
                    REQUIRE(r.band.has_value());
                    CHECK(*r.band == e.at);
                    ++cohorts;
                    if (crash + 1 <= 5 * a) {
                        // 4/N > 0.05 for N <= 60: the step always crosses a display boundary.
                        auto lower = compute_stability_score(mk(n, a, crash + 1, hang), kFloor);
                        REQUIRE(lower.band.has_value());
                        CHECK(*lower.band == e.below);
                    }
                }
            }
        }
    }
    CHECK(cohorts > 0);
}

TEST_CASE("stability: rank flip under perturbed weights", "[dex][stability]") {
    const StabilityInputs x = mk(1000, 300, 300);
    const StabilityInputs y = mk(1000, 200, 1000);
    const StabilityWeights pert{10, 70, 8, 12};

    auto f = stability_rank_flip({x, y}, kFloor, pert);
    REQUIRE(f.has_value());
    CHECK(f->first == 0);
    CHECK(f->second == 1);

    // Custom base: x outranks y under pert, so the default weights reverse it.
    auto h = stability_rank_flip({x, y}, kFloor, kStabilityWeights, pert);
    REQUIRE(h.has_value());
    CHECK(h->first == 0);
    CHECK(h->second == 1);

    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, kStabilityWeights).has_value());
    CHECK_FALSE(stability_rank_flip({x, x}, kFloor, pert).has_value());

    // One-sided ties: all-zero weights score every app 100. The strictly
    // higher-scoring app comes first so a deleted tie guard would report a flip.
    CHECK_FALSE(stability_rank_flip({y, x}, kFloor, {0, 0, 0, 0}).has_value());
    CHECK_FALSE(stability_rank_flip({y, x}, kFloor, kStabilityWeights, {0, 0, 0, 0}).has_value());

    const StabilityInputs tiny = mk(5, 1, 1);
    auto g = stability_rank_flip({tiny, x, y}, kFloor, pert);
    REQUIRE(g.has_value());
    CHECK(g->first == 1);
    CHECK(g->second == 2);

    // The floor argument is used: a 5-device app is comparable only at floor 5.
    const StabilityInputs small = mk(5, 1, 5);
    auto s5 = stability_rank_flip({small, x, y}, 5, pert);
    REQUIRE(s5.has_value());
    CHECK(s5->first == 0);
    CHECK(s5->second == 1);
    auto sf = stability_rank_flip({small, x, y}, kFloor, pert);
    REQUIRE(sf.has_value());
    CHECK(sf->first == 1);
    CHECK(sf->second == 2);

    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, {kNaN, 70, 8, 12}).has_value());

    // "Lowest i, then lowest j" among several reversing pairs. Five comparable
    // apps at N = 1000 with no hangs. With base weights (60, 20, 8, 12) and
    // `pert` (10, 70, 8, 12) the score is 100 - 0.06 A - 0.004 crash (base) and
    // 100 - 0.01 A - 0.014 crash (pert); displayed at one decimal:
    //   app 0  A=400 crash= 640   base 73.44 -> 73.4   pert 87.04 -> 87.0
    //   app 1  A=200 crash= 440   base 86.24 -> 86.2   pert 91.84 -> 91.8
    //   app 2  A=220 crash= 380   base 85.28 -> 85.3   pert 92.48 -> 92.5
    //   app 3  A=260 crash=1060   base 80.16 -> 80.2   pert 82.56 -> 82.6
    //   app 4  A=280 crash=1340   base 77.84 -> 77.8   pert 78.44 -> 78.4
    // Exactly three pairs reverse: (0,3), (0,4) and (1,2). The first has the
    // lowest i and, among the two with i = 0, the lowest j; (1,2) has a higher i
    // but a lower j than both, so last-found, j-outer and highest-j orders each
    // return a different pair.
    const std::vector<StabilityInputs> five{mk(1000, 400, 640), mk(1000, 200, 440),
                                            mk(1000, 220, 380), mk(1000, 260, 1060),
                                            mk(1000, 280, 1340)};
    auto lex = stability_rank_flip(five, kFloor, pert);
    REQUIRE(lex.has_value());
    CHECK(lex->first == 0);
    CHECK(lex->second == 3);
}

TEST_CASE("stability: rank flip ties are equal at the display precision", "[dex][stability]") {
    // Both score 84.96 in real arithmetic (85.0 displayed); the doubles differ by
    // about 1e-14, which must not read as an order.
    const StabilityInputs px = mk(10, 2, 4, 9);
    const StabilityInputs py = mk(10, 2, 6, 4);
    for (double hang_weight : {0.0, 20.0}) {
        INFO("hang weight " << hang_weight);
        const StabilityWeights other{60, 20, hang_weight, 12};
        CHECK_FALSE(stability_rank_flip({px, py}, kFloor, other).has_value());
        CHECK_FALSE(stability_rank_flip({py, px}, kFloor, other).has_value());
        CHECK_FALSE(stability_rank_flip({px, py}, kFloor, kStabilityWeights, other).has_value());
        CHECK_FALSE(stability_rank_flip({py, px}, kFloor, kStabilityWeights, other).has_value());
    }
    // A real gap still flips, so the tie rule cannot over-reach.
    auto f = stability_rank_flip({mk(1000, 300, 300), mk(1000, 200, 1000)}, kFloor,
                                 StabilityWeights{10, 70, 8, 12});
    CHECK(f.has_value());
    // The narrowest real gap: one display step. Displayed scores, base then
    // perturbed (weights {10, 70, 8, 12}):
    //   app 0 (A=110, crash=110)  93.0 -> 97.4   (100 - 6.6 - 0.44, 100 - 1.1 - 1.54)
    //   app 1 (A=100, crash=220)  93.1 -> 95.9   (100 - 6.0 - 0.88, 100 - 1.0 - 3.08)
    // 93.0 < 93.1 flips to 97.4 > 95.9, so a tie widened past one step misses it.
    auto narrow = stability_rank_flip({mk(1000, 110, 110), mk(1000, 100, 220)}, kFloor,
                                      StabilityWeights{10, 70, 8, 12});
    REQUIRE(narrow.has_value());
    CHECK(narrow->first == 0);
    CHECK(narrow->second == 1);
}
