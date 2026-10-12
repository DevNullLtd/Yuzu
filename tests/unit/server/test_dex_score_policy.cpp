/**
 * test_dex_score_policy.cpp — the pure DEX score policy, its validator and the
 * resolver (dex_score_policy.hpp). Known-answer cases; no store, no process,
 * no I/O.
 */
#include "dex_perf_model.hpp" // kDexCohortFloor
#include "dex_score_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {
using Rr = StabilityRateRatioInterval;
constexpr std::int64_t kFloor = kDexCohortFloor;
constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
constexpr double kInf = std::numeric_limits<double>::infinity();

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

DexScorePolicy defaults() {
    return dex_default_score_policy();
}

DexScoreOverride ov(std::string image) {
    DexScoreOverride o;
    o.image = std::move(image);
    return o;
}

// The expected fault, always at the global index unless an index is given.
void require_fault(const DexScorePolicy& p, DexPolicyFault f,
                   std::size_t idx = kDexPolicyGlobalIndex) {
    const auto r = dex_score_policy_fault(p);
    REQUIRE(r.has_value());
    CHECK(dex_policy_fault_label(r->fault) == std::string(dex_policy_fault_label(f)));
    CHECK(r->override_index == idx);
}

DexScorePolicy with_edges(double ex, double good, double fair) {
    auto p = defaults();
    p.tiers.edges = {ex, good, fair};
    return p;
}

StabilityBand hand_band(double score, const StabilityBandEdges& e) {
    const double shown = stability_display_score(score);
    if (shown >= e.excellent)
        return StabilityBand::Excellent;
    if (shown >= e.good)
        return StabilityBand::Good;
    if (shown >= e.fair)
        return StabilityBand::Fair;
    return StabilityBand::Poor;
}
} // namespace

TEST_CASE("policy: the default validates and reproduces the stability score bit-for-bit",
          "[dex][policy]") {
    const auto& d = dex_default_score_policy();
    CHECK_FALSE(dex_score_policy_fault(d).has_value());

    const auto eff = resolve_dex_score_policy(d, "anything");
    CHECK(eff.profile == DexPolicyProfile::Default);
    CHECK(eff.weights.breadth == kStabilityWeights.breadth);
    CHECK(eff.weights.crashes == kStabilityWeights.crashes);
    CHECK(eff.weights.hangs == kStabilityWeights.hangs);
    CHECK(eff.weights.regression == kStabilityWeights.regression);
    CHECK(eff.tiers.edges.excellent == 90.0);
    CHECK(eff.tiers.edges.good == 75.0);
    CHECK(eff.tiers.edges.fair == 60.0);
    CHECK(eff.tiers.names[0] == "excellent");
    CHECK(eff.tiers.names[1] == "good");
    CHECK(eff.tiers.names[2] == "fair");
    CHECK(eff.tiers.names[3] == "poor");
    for (auto b : {StabilityBand::Excellent, StabilityBand::Good, StabilityBand::Fair,
                   StabilityBand::Poor})
        CHECK(dex_tier_name(eff.tiers, b) == stability_band_label(b));

    const std::vector<StabilityInputs> cases = {
        mk(12, 6, 26, 10),
        mk(10, 3, 12, 14),
        mk(1000, 300, 300),
        mk(1000, 1, 5, 5), // one crash-looping device
        mk(1000, 300, 300, 0, Rr{2.0, 5.0}),
        mk(1000, 300, 300, 0, Rr{3.0, 9.0}),
        mk(1000, 300, 300, 0, Rr{2.0, kInf}),
        mk(5, 1, 1),  // below the floor
        mk(10, 11, 0) // inconsistent
    };
    for (const auto& in : cases) {
        const auto a = compute_stability_score(in, kFloor);
        const auto b = compute_stability_score(in, kFloor, eff.weights, eff.tiers.edges);
        CHECK(a.score == b.score);
        CHECK(a.band == b.band);
        CHECK(std::string(a.withheld) == b.withheld);
        REQUIRE(a.deductions.size() == b.deductions.size());
        for (std::size_t i = 0; i < a.deductions.size(); ++i) {
            CHECK(std::string(a.deductions[i].name) == b.deductions[i].name);
            CHECK(a.deductions[i].points == b.deductions[i].points);
            CHECK(a.deductions[i].assessed == b.deductions[i].assessed);
        }
    }
}

TEST_CASE("policy: random valid edges keep score, displayed value and band in agreement",
          "[dex][policy]") {
    // Cohorts built from integers: every consistent (N, A, crash, hang) shape.
    std::vector<StabilityInputs> cohorts;
    for (std::int64_t n = 10; n <= 30; ++n)
        for (std::int64_t a = 0; a <= n; ++a)
            for (const std::int64_t c : {std::int64_t{0}, a, 5 * a})
                for (const std::int64_t h : {std::int64_t{0}, a, 5 * a})
                    if (c + h >= a)
                        cohorts.push_back(mk(n, a, c, h));
    REQUIRE(!cohorts.empty());

    std::mt19937 rng(20261012);
    const auto draw = [&](int lo, int hi) {
        return std::uniform_int_distribution<int>(lo, hi)(rng);
    };
    std::vector<StabilityBandEdges> sets;
    sets.push_back({90.0, 75.0, 60.0}); // the default is one of the draws
    for (int i = 0; i < 199; ++i) {
        const int fair = draw(1, 979);
        const int good = draw(fair + 10, 989);
        const int excellent = draw(good + 10, 999);
        sets.push_back({excellent / 10.0, good / 10.0, fair / 10.0});
    }

    for (const auto& e : sets) {
        auto p = defaults();
        p.tiers.edges = e;
        INFO("edges " << e.excellent << " / " << e.good << " / " << e.fair);
        REQUIRE_FALSE(dex_score_policy_fault(p).has_value());
        for (const auto& in : cohorts) {
            const auto r = compute_stability_score(in, kFloor, kStabilityWeights, e);
            if (!r.score)
                continue;
            REQUIRE(r.band.has_value());
            CHECK(*r.band == stability_band(*r.score, e));
            CHECK(*r.band == hand_band(*r.score, e));
        }
        for (int i = 0; i <= 10000; ++i) {
            const double s = i / 100.0;
            REQUIRE(stability_band(s, e) == hand_band(s, e));
        }
    }
}

TEST_CASE("policy: every invalid shape is refused whole with its typed fault and index",
          "[dex][policy]") {
    SECTION("edges out of range, in every slot") {
        for (const double bad : {0.0, 100.0, -1.0, kNaN, kInf, -kInf}) {
            INFO("edge " << bad);
            require_fault(with_edges(bad, 75.0, 60.0), DexPolicyFault::EdgeOutOfRange);
            require_fault(with_edges(90.0, bad, 60.0), DexPolicyFault::EdgeOutOfRange);
            require_fault(with_edges(90.0, 75.0, bad), DexPolicyFault::EdgeOutOfRange);
        }
    }
    SECTION("overlapping-invalid edges pin the check order") {
        require_fault(with_edges(100.04, 75.0, 60.0), DexPolicyFault::EdgeOutOfRange);
        require_fault(with_edges(1e308, 75.0, 60.0), DexPolicyFault::EdgeOutOfRange);
        require_fault(with_edges(90.0, 75.04, 60.0), DexPolicyFault::EdgeNotDisplayExact);
    }
    SECTION("edges not strictly descending, gap below the minimum") {
        require_fault(with_edges(90.0, 90.0, 60.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(90.0, 95.0, 60.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(90.0, 75.0, 80.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(75.0, 74.1, 60.0), DexPolicyFault::EdgeGapBelowMinimum);
    }
    SECTION("names") {
        const std::string excluded[] = {"<", ">", "&", "\"", "\x7F", "\t", "\xC3\x89", "a\nb"};
        for (const auto& bad : excluded) {
            INFO("name byte sequence of length " << bad.size());
            auto p = defaults();
            p.tiers.names[2] = "x" + bad;
            require_fault(p, DexPolicyFault::NameInvalid);
        }
        for (const auto& bad : {std::string(), std::string(25, 'a'), std::string("<b>x")}) {
            auto p = defaults();
            p.tiers.names[0] = bad;
            require_fault(p, DexPolicyFault::NameInvalid);
        }
    }
    SECTION("weights") {
        for (const double bad : {-1.0, kNaN, kInf}) {
            auto p = defaults();
            p.weights.hangs = bad;
            require_fault(p, DexPolicyFault::WeightInvalid);
        }
        auto p = defaults();
        p.weights = {60.0, 20.0, 8.0, 12.5};
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum);
    }
    SECTION("override keys and count") {
        auto p = defaults();
        p.overrides = {ov("")};
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 0);
        p.overrides = {ov("ok.exe"), ov("Excel.exe")};
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 1);
        p.overrides = {ov("excel.exe"), ov("excel.exe")};
        require_fault(p, DexPolicyFault::OverrideKeyDuplicate, 1);
        p.overrides.clear();
        for (int i = 0; i < 201; ++i)
            p.overrides.push_back(ov("app" + std::to_string(i)));
        require_fault(p, DexPolicyFault::TooManyOverrides);
    }
    SECTION("an override is checked against its effective policy") {
        auto p = defaults();
        auto edge = ov("a.exe");
        p.overrides.push_back(ov("clean.exe"));
        edge.good = 95.0; // above the inherited excellent edge of 90
        p.overrides.push_back(edge);
        require_fault(p, DexPolicyFault::EdgesNotDescending, 1);

        p = defaults();
        auto w = ov("b.exe");
        w.breadth = 70.0; // 70 + 20 + 8 + 12 = 110
        p.overrides.push_back(w);
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum, 0);

        p = defaults();
        auto n = ov("c.exe");
        n.names[1] = "<b>";
        p.overrides.push_back(n);
        require_fault(p, DexPolicyFault::NameInvalid, 0);
    }
    SECTION("fault labels are non-empty and distinct") {
        std::set<std::string> seen;
        for (auto f : {DexPolicyFault::EdgeOutOfRange, DexPolicyFault::EdgeNotDisplayExact,
                       DexPolicyFault::EdgesNotDescending, DexPolicyFault::EdgeGapBelowMinimum,
                       DexPolicyFault::NameInvalid, DexPolicyFault::WeightInvalid,
                       DexPolicyFault::WeightSumAboveMaximum, DexPolicyFault::OverrideKeyInvalid,
                       DexPolicyFault::OverrideKeyDuplicate, DexPolicyFault::TooManyOverrides}) {
            const std::string l = dex_policy_fault_label(f);
            CHECK_FALSE(l.empty());
            seen.insert(l);
        }
        CHECK(seen.size() == 10);
    }
}

TEST_CASE("policy: the acceptance boundaries validate", "[dex][policy]") {
    auto p = defaults();
    p.tiers.names[0] = std::string(24, 'a');
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    p = defaults();
    p.weights = {25.0, 25.0, 25.0, 25.0};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    // A gap of exactly 10 tenths (1.0 point).
    CHECK_FALSE(dex_score_policy_fault(with_edges(76.0, 75.0, 74.0)).has_value());

    p = defaults();
    for (int i = 0; i < 200; ++i)
        p.overrides.push_back(ov("app" + std::to_string(i)));
    CHECK_FALSE(dex_score_policy_fault(p).has_value());
    p.overrides.push_back(ov("app200"));
    require_fault(p, DexPolicyFault::TooManyOverrides);
}

TEST_CASE("policy: an override inherits unspecified fields and the resolver matches the "
          "lowercased image",
          "[dex][policy]") {
    auto p = defaults();
    auto o = ov("excel.exe");
    o.names[0] = "Great";
    o.breadth = 50.0;
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    const auto eff = resolve_dex_score_policy(p, "Excel.EXE");
    CHECK(eff.profile == DexPolicyProfile::Override);
    CHECK(eff.tiers.names[0] == "Great");
    CHECK(eff.tiers.names[1] == "good");
    CHECK(eff.tiers.names[2] == "fair");
    CHECK(eff.tiers.names[3] == "poor");
    CHECK(eff.tiers.edges.excellent == 90.0);
    CHECK(eff.tiers.edges.good == 75.0);
    CHECK(eff.tiers.edges.fair == 60.0);
    CHECK(eff.weights.breadth == 50.0);
    CHECK(eff.weights.crashes == 20.0);
    CHECK(eff.weights.hangs == 8.0);
    CHECK(eff.weights.regression == 12.0);
    CHECK(dex_tier_name(eff.tiers, StabilityBand::Excellent) == "Great");
    CHECK(dex_tier_name(eff.tiers, StabilityBand::Poor) == "poor");

    const auto other = resolve_dex_score_policy(p, "outlook.exe");
    CHECK(other.profile == DexPolicyProfile::Default);
    CHECK(other.tiers.names[0] == "excellent");
    CHECK(other.weights.breadth == 60.0);

    CHECK(std::string(dex_policy_profile_label(DexPolicyProfile::Default)) == "default");
    CHECK(std::string(dex_policy_profile_label(DexPolicyProfile::Override)) == "override");
}

TEST_CASE("policy: the resolver's lowercase is ASCII-only and byte-exact", "[dex][policy]") {
    auto p = defaults();
    p.overrides.push_back(ov("\xC3\x89.exe")); // non-ASCII bytes are not folded
    p.overrides.push_back(ov("excel.exe"));
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    CHECK(resolve_dex_score_policy(p, "\xC3\x89.exe").profile == DexPolicyProfile::Override);
    CHECK(resolve_dex_score_policy(p, "\xC3\x89.EXE").profile == DexPolicyProfile::Override);
    CHECK(resolve_dex_score_policy(p, "\xC3\xA9.exe").profile == DexPolicyProfile::Default);
    // The validator and the resolver share one lowercase: a key it accepts is
    // the key a mixed-case query reaches.
    CHECK(resolve_dex_score_policy(p, "Excel.EXE").profile == DexPolicyProfile::Override);
    // An uppercase non-ASCII-adjacent key is still refused as not lowercase.
    auto bad = defaults();
    bad.overrides.push_back(ov("\xC3\x89.Exe"));
    require_fault(bad, DexPolicyFault::OverrideKeyInvalid, 0);
}

TEST_CASE("policy: the rank-flip helper accepts the effective weights", "[dex][policy]") {
    const StabilityInputs x = mk(1000, 300, 300);
    const StabilityInputs y = mk(1000, 200, 1000);

    auto p = defaults();
    auto o = ov("app.exe");
    o.breadth = 10.0;
    o.crashes = 70.0;
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    const auto base = resolve_dex_score_policy(p, "other.exe");
    const auto eff = resolve_dex_score_policy(p, "app.exe");

    const auto f = stability_rank_flip({x, y}, kFloor, eff.weights, base.weights);
    REQUIRE(f.has_value());
    CHECK(f->first == 0);
    CHECK(f->second == 1);
    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, base.weights, base.weights).has_value());
}
