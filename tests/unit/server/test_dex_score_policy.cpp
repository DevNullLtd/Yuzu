/**
 * test_dex_score_policy.cpp — the pure DEX score policy, its validator and the
 * resolver (dex_score_policy.hpp). Known-answer cases; no store, no process,
 * no I/O.
 */
#include "dex_perf_model.hpp" // kDexCohortFloor
#include "dex_score_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cfloat>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>
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
    CHECK(r->fault == f);
    CHECK(dex_policy_fault_label(r->fault) == std::string(dex_policy_fault_label(f)));
    CHECK(r->override_index == idx);
}

DexScorePolicy with_edges(double ex, double good, double fair) {
    auto p = defaults();
    p.tiers.edges = {ex, good, fair};
    return p;
}

// A known answer through the policy path: the resolved default policy scores
// `in` exactly as the stability score's own tests record.
void require_default_answer(const StabilityInputs& in, double shown, StabilityBand band) {
    const auto eff = resolve_dex_score_policy(dex_default_score_policy(), "any.exe");
    const auto r = dex_score_under_policy(in, kFloor, eff);
    REQUIRE(r.score.has_value());
    REQUIRE(r.band.has_value());
    CHECK(stability_display_score(*r.score) == shown);
    CHECK(*r.band == band);
}

// dex_tier_name returns a reference into its argument: a temporary
// (resolve_dex_score_policy(p, img).tiers) would leave it dangling after the
// full expression. Compile-time lock, not a runtime witness.
template <class T>
concept TierNameOfTemporary = requires { dex_tier_name(T{}, StabilityBand::Poor); };
static_assert(!TierNameOfTemporary<DexTierPolicy>,
              "dex_tier_name must not accept a temporary: the returned reference would dangle");
// A const rvalue (std::move of a const object) must be refused as well.
template <class T>
concept TierNameOfConstTemporary =
    requires(const T t) { dex_tier_name(std::move(t), StabilityBand::Poor); };
static_assert(!TierNameOfConstTemporary<DexTierPolicy>,
              "dex_tier_name must not accept a const temporary: the reference would dangle");
// Positive control: the same probe shape compiles for an lvalue, so the two
// locks above fail for the temporary and not because the probe is malformed.
static_assert(requires(const DexTierPolicy& t) { dex_tier_name(t, StabilityBand::Poor); });

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
    CHECK(d.model == kStabilityModel);
    CHECK(d.interval_confidence == kDexStatsConfidence);
    CHECK(eff.model == kStabilityModel);
    CHECK(eff.interval_confidence == kDexStatsConfidence);
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
        mk(5, 1, 1),  // a five-device population (scored: the floor is one device)
        mk(10, 11, 0) // inconsistent
    };
    // Values, not only plumbing: the stability score's known answers.
    {
        const auto exact = dex_score_under_policy(mk(10, 0, 0), kFloor, eff);
        REQUIRE(exact.score.has_value());
        CHECK(*exact.score == 100.0);
    }
    require_default_answer(mk(10, 0, 0), 100.0, StabilityBand::Excellent);
    require_default_answer(mk(1000, 300, 300), 80.8, StabilityBand::Good);
    require_default_answer(mk(1000, 500, 2500), 60.0, StabilityBand::Fair);
    require_default_answer(mk(12, 6, 26, 10), 60.0, StabilityBand::Fair); // raw 59.999999999999993
    for (const auto& in : cases) {
        const auto a = compute_stability_score(in, kFloor);
        const auto b = dex_score_under_policy(in, kFloor, eff);
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

TEST_CASE("policy: random valid edges keep score and displayed value and band in agreement",
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
    // mt19937's output is fully specified; uniform_int_distribution's mapping is not.
    const auto draw = [&](int lo, int hi) {
        return lo + static_cast<int>(rng() % static_cast<unsigned>(hi - lo + 1));
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
        std::size_t mismatches = 0;
        std::string first;
        for (const auto& in : cohorts) {
            const auto r = compute_stability_score(in, kFloor, kStabilityWeights, e);
            // Every cohort has N >= the floor and is consistent, so a validated
            // policy's edges are never refused: a withheld result is a mismatch.
            if (!r.score || !r.band || *r.band != stability_band(*r.score, e) ||
                *r.band != hand_band(*r.score, e)) {
                if (mismatches++ == 0)
                    first = "n=" + std::to_string(in.reporting_devices) +
                            " a=" + std::to_string(in.devices_affected) +
                            " crash=" + std::to_string(in.crash_events) +
                            " hang=" + std::to_string(in.hang_events);
            }
        }
        INFO("first mismatching cohort " << first);
        REQUIRE(mismatches == 0);
        // Only scores within one display tick of an edge (and the range ends)
        // can disagree under a moved comparison or a dropped display rounding;
        // probe that neighbourhood at the 0.01 resolution of the score grid.
        std::vector<double> probes = {0.0, 100.0};
        for (const double edge : {e.excellent, e.good, e.fair}) {
            const auto c = std::llround(edge * 100.0);
            for (auto i = c - 10; i <= c + 10; ++i)
                probes.push_back(static_cast<double>(i) / 100.0);
        }
        for (const double s : probes) {
            INFO("score " << s);
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
    SECTION("finite and in range but not display exact, and a non-finite override field") {
        // 5e-324 is positive and finite, yet rounds to 0.0 at one decimal.
        require_fault(with_edges(90.0, 75.0, 5e-324), DexPolicyFault::EdgeNotDisplayExact);
        auto p = defaults();
        auto o = ov("nan.exe");
        o.good = kNaN;
        p.overrides = {ov("clean.exe"), o};
        require_fault(p, DexPolicyFault::EdgeOutOfRange, 1);
    }
    SECTION("overlapping-invalid edges pin the check order") {
        require_fault(with_edges(100.04, 75.0, 60.0), DexPolicyFault::EdgeOutOfRange);
        require_fault(with_edges(1e308, 75.0, 60.0), DexPolicyFault::EdgeOutOfRange);
        require_fault(with_edges(90.0, 75.04, 60.0), DexPolicyFault::EdgeNotDisplayExact);
    }
    SECTION("an edge one ulp off an exact decimal is not display exact") {
        require_fault(with_edges(std::nextafter(75.0, 76.0), 60.0, 40.0),
                      DexPolicyFault::EdgeNotDisplayExact);
        require_fault(with_edges(std::nextafter(90.0, 0.0), 60.0, 40.0),
                      DexPolicyFault::EdgeNotDisplayExact);
    }
    SECTION("overlapping-invalid policies pin the whole-document order") {
        // Global edges before global weights.
        auto p = with_edges(0.0, 75.0, 60.0);
        p.weights.hangs = -1.0;
        require_fault(p, DexPolicyFault::EdgeOutOfRange);

        // Global weights before the override count.
        p = defaults();
        p.weights.hangs = -1.0;
        for (int i = 0; i < 201; ++i)
            p.overrides.push_back(ov("app" + std::to_string(i)));
        require_fault(p, DexPolicyFault::WeightInvalid);

        // The override count before any per-override check.
        p = defaults();
        for (int i = 0; i < 201; ++i)
            p.overrides.push_back(ov("app" + std::to_string(i)));
        p.overrides[0] = ov("");
        require_fault(p, DexPolicyFault::TooManyOverrides);

        // Within an override: key before the effective policy, duplicate
        // before the effective policy.
        auto conflict = ov("Excel.exe");
        conflict.good = 95.0; // above the inherited excellent edge of 90
        p = defaults();
        p.overrides = {conflict};
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 0);

        conflict.image = "a.exe";
        p.overrides = {ov("a.exe"), conflict};
        require_fault(p, DexPolicyFault::OverrideKeyDuplicate, 1);

        // Per override in index order: an earlier effective fault wins over a
        // later key fault.
        p.overrides = {conflict, ov("Excel.exe")};
        require_fault(p, DexPolicyFault::EdgesNotDescending, 0);

        // Edges in turn: the first edge's display-exactness is reported before
        // the second edge's range.
        require_fault(with_edges(75.04, 100.0, 60.0), DexPolicyFault::EdgeNotDisplayExact);

        // A global fault wins over any override fault.
        p = with_edges(0.0, 75.0, 60.0);
        p.overrides = {conflict};
        require_fault(p, DexPolicyFault::EdgeOutOfRange);

        // Within the effective policy of one override: tiers before weights.
        auto both = ov("both.exe");
        both.good = 95.0;    // above the inherited excellent edge
        both.breadth = 70.0; // 70 + 20 + 8 + 12 = 110
        p = defaults();
        p.overrides = {both};
        require_fault(p, DexPolicyFault::EdgesNotDescending, 0);

        // Names before weights: a bad name wins over a bad weight, globally
        // and within one override's effective policy.
        p = defaults();
        p.tiers.names[0] = "";
        p.weights.hangs = -1.0;
        require_fault(p, DexPolicyFault::NameInvalid);
        auto named = ov("named.exe");
        named.names[0] = "";
        named.breadth = 70.0; // effective weights sum past 100
        p = defaults();
        p.overrides = {named};
        require_fault(p, DexPolicyFault::NameInvalid, 0);

        // Within the tiers: every edge fault before any name fault.
        const std::pair<StabilityBandEdges, DexPolicyFault> edge_then_name[] = {
            {{0.0, 75.0, 60.0}, DexPolicyFault::EdgeOutOfRange},
            {{75.04, 75.0, 60.0}, DexPolicyFault::EdgeNotDisplayExact},
            {{90.0, 90.0, 60.0}, DexPolicyFault::EdgesNotDescending},
            {{75.0, 74.1, 60.0}, DexPolicyFault::EdgeGapBelowMinimum}};
        for (const auto& [e, f] : edge_then_name) {
            p = with_edges(e.excellent, e.good, e.fair);
            p.tiers.names[0] = "";
            require_fault(p, f);
        }
    }
    SECTION("edges not strictly descending, gap below the minimum") {
        require_fault(with_edges(90.0, 90.0, 60.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(90.0, 95.0, 60.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(90.0, 75.0, 80.0), DexPolicyFault::EdgesNotDescending);
        require_fault(with_edges(75.0, 74.1, 60.0), DexPolicyFault::EdgeGapBelowMinimum);
    }
    SECTION("names") {
        const std::string excluded[] = {"<",  ">",    "&",
                                        "\"", "\x7F", "\t",
                                        "\x1F", std::string("\0", 1), "\xC3\x89",
                                        "a\nb"};
        for (const auto& bad : excluded) {
            INFO("name byte sequence of length " << bad.size());
            // Every one of the four slots is checked, the last included.
            for (std::size_t slot = 0; slot < 4; ++slot) {
                auto p = defaults();
                p.tiers.names[slot] = "x" + bad;
                require_fault(p, DexPolicyFault::NameInvalid);
            }
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
        // Just over 100 in decimal, and a sum over by 1e-11, ten times the
        // tolerance: both still refused.
        p.weights = {99.38, 0.33, 0.26, 0.04};
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum);
        p.weights = {100.0, 0.0, 0.0, 1e-11};
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum);
        // Over by 2e-12: two tolerances, refused (a 5e-12 slack would accept it).
        p.weights = {100.0, 2e-12, 0.0, 0.0};
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum);
        // Each weight finite, the sum overflows to +inf.
        p.weights = {DBL_MAX, DBL_MAX, 0.0, 0.0};
        require_fault(p, DexPolicyFault::WeightSumAboveMaximum);
    }
    SECTION("negative zero weights, global and override") {
        for (double StabilityWeights::*slot :
             {&StabilityWeights::breadth, &StabilityWeights::crashes, &StabilityWeights::hangs,
              &StabilityWeights::regression}) {
            auto p = defaults();
            p.weights.*slot = -0.0;
            require_fault(p, DexPolicyFault::WeightInvalid);
        }
        auto p = defaults();
        auto o = ov("z.exe");
        o.crashes = -0.0;
        p.overrides = {ov("clean.exe"), o};
        require_fault(p, DexPolicyFault::WeightInvalid, 1);
    }
    SECTION("override keys and count") {
        auto p = defaults();
        p.overrides = {ov("")};
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 0);
        p.overrides = {ov("ok.exe"), ov("Excel.exe")};
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 1);
        p.overrides = {ov("ok.exe"), ov("Z.exe")}; // the fold's last letter
        require_fault(p, DexPolicyFault::OverrideKeyInvalid, 1);
        p.overrides = {ov("excel.exe"), ov("excel.exe")};
        require_fault(p, DexPolicyFault::OverrideKeyDuplicate, 1);
        // Non-adjacent duplicates are found: first and last of six, and the
        // 4th and 200th of a full set.
        p.overrides.clear();
        for (const char* k : {"k0", "k1", "k2", "k3", "k4", "k0"})
            p.overrides.push_back(ov(k));
        require_fault(p, DexPolicyFault::OverrideKeyDuplicate, 5);
        p.overrides.clear();
        for (int i = 0; i < 200; ++i)
            p.overrides.push_back(ov("app" + std::to_string(i)));
        p.overrides[199].image = "app3";
        require_fault(p, DexPolicyFault::OverrideKeyDuplicate, 199);
        // A key is refused for an embedded NUL, a control byte, a newline, DEL,
        // any non-ASCII byte (lower or upper case) or more than 260 bytes.
        const std::string bad_keys[] = {std::string("a\0b", 3), std::string("a\0", 2), "a\nb",
                                        "a\x1F", "a\x7F", "\xC3\xA9.exe", "\xC3\x89.exe",
                                        std::string(261, 'a')};
        for (const auto& k : bad_keys) {
            INFO("key of " << k.size() << " bytes");
            p = defaults();
            p.overrides = {ov("ok.exe"), ov(k)};
            require_fault(p, DexPolicyFault::OverrideKeyInvalid, 1);
        }
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

        // An override valid on its own (90/80/60) conflicts after a later global
        // edge change (78/75/60 is itself valid): refused at the override's index.
        p = defaults();
        auto late = ov("d.exe");
        late.good = 80.0;
        p.overrides = {ov("clean.exe"), late};
        REQUIRE_FALSE(dex_score_policy_fault(p).has_value());
        p.tiers.edges.excellent = 78.0;
        require_fault(p, DexPolicyFault::EdgesNotDescending, 1);
    }
    SECTION("fault labels are the closed wire tokens") {
        const std::pair<DexPolicyFault, const char*> labels[] = {
            {DexPolicyFault::EdgeOutOfRange, "edge_out_of_range"},
            {DexPolicyFault::EdgeNotDisplayExact, "edge_not_display_exact"},
            {DexPolicyFault::EdgesNotDescending, "edges_not_descending"},
            {DexPolicyFault::EdgeGapBelowMinimum, "edge_gap_below_minimum"},
            {DexPolicyFault::NameInvalid, "name_invalid"},
            {DexPolicyFault::WeightInvalid, "weight_invalid"},
            {DexPolicyFault::WeightSumAboveMaximum, "weight_sum_above_maximum"},
            {DexPolicyFault::OverrideKeyInvalid, "override_key_invalid"},
            {DexPolicyFault::OverrideKeyDuplicate, "override_key_duplicate"},
            {DexPolicyFault::TooManyOverrides, "too_many_overrides"},
        };
        for (const auto& row : labels)
            CHECK(std::string(dex_policy_fault_label(row.first)) == row.second);
    }
}

TEST_CASE("policy: the acceptance boundaries validate", "[dex][policy]") {
    auto p = defaults();
    p.tiers.names[0] = std::string(24, 'a');
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    p = defaults();
    p.weights = {25.0, 25.0, 25.0, 25.0};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    // Sums to exactly 100 in decimal, reads 100.00000000000001 as doubles.
    p.weights = {99.37, 0.33, 0.26, 0.04};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    // A gap of exactly 10 tenths (1.0 point).
    CHECK_FALSE(dex_score_policy_fault(with_edges(76.0, 75.0, 74.0)).has_value());

    // Sums to exactly 100 in decimal on a cent grid, reads 2.8e-14 over as doubles.
    p.weights = {34.06, 33.27, 0.4, 32.27};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());
    // All-zero weights are a valid choice (every application then scores 100).
    p.weights = {0.0, 0.0, 0.0, 0.0};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    // Printable ASCII ends: space (0x20) and tilde (0x7E) are valid name bytes.
    p = defaults();
    p.tiers.names = {" ", "~", "a b", "~ ~"};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

    // Keys: exactly 260 bytes, a space and '<' (printable, not escaped here).
    p = defaults();
    p.overrides = {ov(std::string(260, 'a')), ov("a b.exe"), ov("<x>")};
    CHECK_FALSE(dex_score_policy_fault(p).has_value());

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

    // An override that sets every field: each one is read back from the
    // resolver, and the resolved edges and weights drive a real score.
    auto full = ov("full.exe");
    full.excellent = 95.0;
    full.good = 85.0;
    full.fair = 70.0;
    full.names = {"A", "B", "C", "D"};
    full.breadth = 50.0;
    full.crashes = 30.0;
    full.hangs = 10.0;
    full.regression = 10.0;
    p.overrides.push_back(full);
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    const auto all = resolve_dex_score_policy(p, "Full.EXE");
    CHECK(all.profile == DexPolicyProfile::Override);
    CHECK(all.tiers.edges.excellent == 95.0);
    CHECK(all.tiers.edges.good == 85.0);
    CHECK(all.tiers.edges.fair == 70.0);
    CHECK(all.tiers.names[0] == "A");
    CHECK(all.tiers.names[1] == "B");
    CHECK(all.tiers.names[2] == "C");
    CHECK(all.tiers.names[3] == "D");
    CHECK(all.weights.breadth == 50.0);
    CHECK(all.weights.crashes == 30.0);
    CHECK(all.weights.hangs == 10.0);
    CHECK(all.weights.regression == 10.0);
    // 100 - 50 * 0.3 - 30 * 300 / 5000 = 83.2: good under the defaults, fair
    // under the resolved edges (85 > 83.2 >= 70).
    const auto scored = dex_score_under_policy(mk(1000, 300, 300), kFloor, all);
    REQUIRE(scored.score.has_value());
    REQUIRE(scored.band.has_value());
    CHECK(stability_display_score(*scored.score) == 83.2);
    CHECK(*scored.band == StabilityBand::Fair);
    CHECK(dex_tier_name(all.tiers, *scored.band) == "C");

    const auto other = resolve_dex_score_policy(p, "outlook.exe");
    CHECK(other.profile == DexPolicyProfile::Default);
    CHECK(other.tiers.names[0] == "excellent");
    CHECK(other.weights.breadth == 60.0);

    CHECK(std::string(dex_policy_profile_label(DexPolicyProfile::Default)) == "default");
    CHECK(std::string(dex_policy_profile_label(DexPolicyProfile::Override)) == "override");
}

TEST_CASE("policy: overrides and unmatched applications inherit a customised global",
          "[dex][policy]") {
    // Every field differs from the compile-time default, so inheriting from the
    // global is distinguishable from starting over from the defaults.
    auto p = defaults();
    p.tiers.edges = {95.0, 80.0, 65.0};
    p.tiers.names = {"A", "B", "C", "D"};
    p.weights = {50.0, 25.0, 10.0, 10.0};
    auto o = ov("partial.exe");
    o.names[0] = "Top";
    o.breadth = 40.0;
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    // Each override is validated against the customised global, not the
    // shipped defaults: both partial overrides below are valid merged onto
    // 90/75/60 and 60/20/8/12, and invalid merged onto this global.
    {
        auto q = p;
        auto edge = ov("edge.exe");
        edge.excellent = 78.0; // below the inherited good edge of 80
        q.overrides = {edge};
        require_fault(q, DexPolicyFault::EdgesNotDescending, 0);

        auto weight = ov("weight.exe");
        weight.breadth = 60.0; // 60 + 25 + 10 + 10 = 105
        q.overrides = {weight};
        require_fault(q, DexPolicyFault::WeightSumAboveMaximum, 0);
    }

    // The override sets two fields and inherits the other nine.
    const auto ovr = resolve_dex_score_policy(p, "Partial.EXE");
    CHECK(ovr.profile == DexPolicyProfile::Override);
    CHECK(ovr.tiers.edges.excellent == 95.0);
    CHECK(ovr.tiers.edges.good == 80.0);
    CHECK(ovr.tiers.edges.fair == 65.0);
    CHECK(ovr.tiers.names[0] == "Top");
    CHECK(ovr.tiers.names[1] == "B");
    CHECK(ovr.tiers.names[2] == "C");
    CHECK(ovr.tiers.names[3] == "D");
    CHECK(ovr.weights.breadth == 40.0);
    CHECK(ovr.weights.crashes == 25.0);
    CHECK(ovr.weights.hangs == 10.0);
    CHECK(ovr.weights.regression == 10.0);

    // An application with no override gets the whole customised global.
    const auto glob = resolve_dex_score_policy(p, "other.exe");
    CHECK(glob.profile == DexPolicyProfile::Default);
    CHECK(glob.tiers.edges.excellent == 95.0);
    CHECK(glob.tiers.edges.good == 80.0);
    CHECK(glob.tiers.edges.fair == 65.0);
    CHECK(glob.tiers.names[0] == "A");
    CHECK(glob.tiers.names[1] == "B");
    CHECK(glob.tiers.names[2] == "C");
    CHECK(glob.tiers.names[3] == "D");
    CHECK(glob.weights.breadth == 50.0);
    CHECK(glob.weights.crashes == 25.0);
    CHECK(glob.weights.hangs == 10.0);
    CHECK(glob.weights.regression == 10.0);

    // The inherited edges and weights drive a real score: 100 - 50 * 0.4 -
    // 25 * 400 / 5000 = 78.0 is good under the shipped edges, fair under 95/80/65.
    const auto scored = dex_score_under_policy(mk(1000, 400, 400), kFloor, glob);
    REQUIRE(scored.score.has_value());
    REQUIRE(scored.band.has_value());
    CHECK(stability_display_score(*scored.score) == 78.0);
    CHECK(*scored.band == StabilityBand::Fair);
    CHECK(dex_tier_name(glob.tiers, *scored.band) == "C");
}

TEST_CASE("policy: the resolver matches the exact ASCII-lowercased key and nothing nearby",
          "[dex][policy]") {
    auto p = defaults();
    p.overrides.push_back(ov("excel.exe"));
    p.overrides.push_back(ov("ab"));
    p.overrides.push_back(ov("@.exe")); // the bytes around 'A'..'Z' are not folded
    p.overrides.push_back(ov("[x"));
    p.overrides.push_back(ov("`"));
    p.overrides.push_back(ov("{"));
    p.overrides.push_back(ov("zebra.exe")); // the fold reaches 'Z'
    p.overrides.push_back(ov(std::string(260, 'k'))); // the longest valid key
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    const auto is_override = [&](std::string_view q) {
        return resolve_dex_score_policy(p, q).profile == DexPolicyProfile::Override;
    };
    CHECK(is_override("excel.exe"));
    CHECK(is_override("Excel.EXE"));
    CHECK(is_override("AB"));
    CHECK(is_override("@.exe"));
    CHECK(is_override("[x"));
    CHECK(is_override("`"));
    CHECK(is_override("{"));
    CHECK(is_override("ZEBRA.EXE"));
    CHECK(is_override(std::string(260, 'K')));
    // Near misses resolve to the global policy: longer, shorter, prefixed,
    // empty, and a query whose NUL-terminated prefix equals a key.
    CHECK_FALSE(is_override("excel.exe2"));
    CHECK_FALSE(is_override("xexcel.exe"));
    CHECK_FALSE(is_override("excel"));
    CHECK_FALSE(is_override(""));
    CHECK_FALSE(is_override(std::string(261, 'K'))); // longer than any valid key
    CHECK_FALSE(is_override(std::string_view("excel.exe\0x", 11)));
    CHECK_FALSE(is_override(std::string_view("excel.exe\0", 10)));
    // The fold is ASCII-only: non-ASCII bytes are neither folded nor masked into
    // ASCII, so they never reach a key (a valid key has no byte >= 0x80), and the
    // resolver returns the uncorrupted global policy.
    CHECK_FALSE(is_override("\xC3\x89.exe"));
    CHECK_FALSE(is_override("\xE1\xE2"));
    CHECK_FALSE(is_override("\xC1\xC2"));
    const auto other = resolve_dex_score_policy(p, "\xC3\x89.exe");
    CHECK(other.profile == DexPolicyProfile::Default);
    CHECK(other.tiers.names[0] == "excellent");
    CHECK(other.weights.breadth == 60.0);
}

TEST_CASE("policy: the scorer's structural edge check is looser than the validator on purpose",
          "[dex][policy]") {
    // The validator refuses edges the scorer still bands; the consumer's
    // validate-on-load duty is what keeps those from reaching the scorer.
    const auto in = mk(1000, 100, 500); // scores 92.0
    const auto band_under = [&](const DexScorePolicy& p) {
        const auto r = dex_score_under_policy(in, kFloor, resolve_dex_score_policy(p, "x.exe"));
        REQUIRE(r.band.has_value());
        return *r.band;
    };
    const auto valid = with_edges(99.9, 1.2, 0.1);
    CHECK_FALSE(dex_score_policy_fault(valid).has_value());
    CHECK(band_under(valid) == StabilityBand::Good);

    const auto not_exact = with_edges(99.99, 99.98, 99.97);
    require_fault(not_exact, DexPolicyFault::EdgeNotDisplayExact);
    CHECK(band_under(not_exact) == StabilityBand::Poor);

    const auto too_close = with_edges(99.9, 0.2, 0.1);
    require_fault(too_close, DexPolicyFault::EdgeGapBelowMinimum);
    CHECK(band_under(too_close) == StabilityBand::Good);
}

TEST_CASE("policy: the rank-flip helper accepts the global weights", "[dex][policy]") {
    const StabilityInputs x = mk(1000, 300, 300);
    const StabilityInputs y = mk(1000, 200, 1000);

    // Both sides are global policies: ranking never takes an override's weights.
    auto p = defaults();
    auto q = defaults();
    q.weights = {10.0, 70.0, 8.0, 12.0};
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());
    REQUIRE_FALSE(dex_score_policy_fault(q).has_value());

    const auto base = resolve_dex_score_policy(p, "");
    const auto perturbed = resolve_dex_score_policy(q, "");
    CHECK(base.profile == DexPolicyProfile::Default);
    CHECK(perturbed.profile == DexPolicyProfile::Default);

    const auto f = stability_rank_flip({x, y}, kFloor, perturbed.weights, base.weights);
    REQUIRE(f.has_value());
    CHECK(f->first == 0);
    CHECK(f->second == 1);
    CHECK_FALSE(stability_rank_flip({x, y}, kFloor, base.weights, base.weights).has_value());
}

// -- AP-2.17 model parameters --------------------------------------------------

namespace {
DexScorePolicy with_model(std::int64_t cap, double full, double start) {
    auto p = defaults();
    p.model = StabilityModel{cap, full, start};
    return p;
}
} // namespace

TEST_CASE("policy: the validator refuses each model parameter outside its range",
          "[dex][policy]") {
    for (const std::int64_t cap : {std::int64_t{0}, std::int64_t{1001}, std::int64_t{-1}})
        require_fault(with_model(cap, 3.0, 1.0), DexPolicyFault::EventCapOutOfRange);
    require_fault(with_model(5, 3.0, 0.9), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, 1000.5, 1.0), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, 3.0, kNaN), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, kNaN, 1.0), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, kInf, 1.0), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, 0.5, 1.0), DexPolicyFault::RegressionRatioOutOfRange);
    require_fault(with_model(5, 2.0, 2.0), DexPolicyFault::RegressionRatiosNotAscending);
    require_fault(with_model(5, 1.5, 2.0), DexPolicyFault::RegressionRatiosNotAscending);
    for (const double c : {0.4, 1.0, kNaN, kInf, 0.9995}) {
        auto p = defaults();
        p.interval_confidence = c;
        require_fault(p, DexPolicyFault::IntervalConfidenceOutOfRange);
    }
    // The first failing parameter wins: cap, then the ratios' range, then their order.
    require_fault(with_model(0, 0.5, 2.0), DexPolicyFault::EventCapOutOfRange);
    require_fault(with_model(5, 1.5, 0.5), DexPolicyFault::RegressionRatioOutOfRange);
    // The model is checked after weights and before the override count and confidence.
    {
        auto p = with_model(0, 3.0, 1.0);
        p.weights.breadth = -1.0;
        require_fault(p, DexPolicyFault::WeightInvalid);
    }
    {
        auto p = with_model(0, 3.0, 1.0);
        p.interval_confidence = 2.0;
        for (std::size_t i = 0; i < kDexPolicyMaxOverrides + 1; ++i)
            p.overrides.push_back(ov("app" + std::to_string(i) + ".exe"));
        require_fault(p, DexPolicyFault::EventCapOutOfRange);
        p.model = kStabilityModel;
        require_fault(p, DexPolicyFault::IntervalConfidenceOutOfRange);
        p.interval_confidence = kDexStatsConfidence;
        require_fault(p, DexPolicyFault::TooManyOverrides);
    }
}

TEST_CASE("policy: the model's acceptance boundaries validate", "[dex][policy]") {
    CHECK_FALSE(dex_score_policy_fault(with_model(1, 3.0, 1.0)).has_value());
    CHECK_FALSE(dex_score_policy_fault(with_model(1000, 3.0, 1.0)).has_value());
    CHECK_FALSE(dex_score_policy_fault(with_model(5, 1000.0, 1.0)).has_value());
    CHECK_FALSE(dex_score_policy_fault(with_model(5, 1000.0, 999.0)).has_value());
    for (const double c : {0.5, 0.999}) {
        auto p = defaults();
        p.interval_confidence = c;
        CHECK_FALSE(dex_score_policy_fault(p).has_value());
    }
}

TEST_CASE("policy: model_fault agrees with stability_model_valid over the boundary values",
          "[dex][policy]") {
    // The same cap, start and full values the scorer's validity test lists.
    const std::int64_t caps[] = {-1, 0, 1, 5, 1000, 1001};
    const double ratios[] = {0.5, 1.0, 2.0, 2.5, 3.0, 999.0, 1000.0, 1000.5, kNaN, kInf};
    for (const auto cap : caps)
        for (const double start : ratios)
            for (const double full : ratios) {
                const StabilityModel m{cap, full, start};
                INFO("cap " << cap << " start " << start << " full " << full);
                CHECK(dex_score_policy_detail::model_fault(m).has_value() !=
                      stability_model_valid(m));
            }
}

TEST_CASE("policy: an override's model is checked against the inherited values at its index",
          "[dex][policy]") {
    auto p = with_model(5, 3.0, 1.5);
    auto lowered = ov("app.exe");
    lowered.regression_full_ratio = 1.2; // below the inherited start of 1.5
    p.overrides = {ov("other.exe"), lowered};
    require_fault(p, DexPolicyFault::RegressionRatiosNotAscending, 1);
    // A start raised past the inherited full ratio is the same refusal.
    auto q = defaults();
    auto raised = ov("app.exe");
    raised.regression_start_ratio = 3.5;
    q.overrides = {raised};
    require_fault(q, DexPolicyFault::RegressionRatiosNotAscending, 0);
    // Both set, ascending: valid even though neither alone would be.
    raised.regression_full_ratio = 6.0;
    q.overrides = {raised};
    CHECK_FALSE(dex_score_policy_fault(q).has_value());
    // An out-of-range override value is reported at the override.
    auto cap = ov("app.exe");
    cap.per_device_event_cap = 0;
    q.overrides = {ov("x.exe"), cap};
    require_fault(q, DexPolicyFault::EventCapOutOfRange, 1);
    cap.per_device_event_cap = 1000;
    q.overrides = {cap};
    CHECK_FALSE(dex_score_policy_fault(q).has_value());
}

TEST_CASE("policy: the resolver merges the model per field", "[dex][policy]") {
    auto p = with_model(6, 4.0, 1.5);
    p.interval_confidence = 0.9;
    auto capped = ov("capme.exe");
    capped.per_device_event_cap = 3;
    auto ratios = ov("ratios.exe");
    ratios.regression_start_ratio = 2.0;
    ratios.regression_full_ratio = 5.0;
    p.overrides = {capped, ratios};
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());

    const auto c = resolve_dex_score_policy(p, "CapMe.EXE");
    CHECK(c.profile == DexPolicyProfile::Override);
    CHECK(c.model == (StabilityModel{3, 4.0, 1.5})); // only the cap is the override's
    const auto r = resolve_dex_score_policy(p, "ratios.exe");
    CHECK(r.profile == DexPolicyProfile::Override);
    CHECK(r.model == (StabilityModel{6, 5.0, 2.0}));
    const auto other = resolve_dex_score_policy(p, "unmatched.exe");
    CHECK(other.profile == DexPolicyProfile::Default);
    CHECK(other.model == (StabilityModel{6, 4.0, 1.5}));
    // The confidence level is the global one everywhere.
    for (const auto* e : {&c, &r, &other})
        CHECK(e->interval_confidence == 0.9);

    // Setting only the cap inherits the shipped ratios: {3, 3.0, 1.0}.
    auto q = defaults();
    q.overrides = {capped};
    CHECK(resolve_dex_score_policy(q, "capme.exe").model == (StabilityModel{3, 3.0, 1.0}));
}

TEST_CASE("policy: dex_score_under_policy scores under the effective model", "[dex][policy]") {
    auto p = defaults();
    auto capped = ov("capme.exe");
    capped.per_device_event_cap = 10;
    capped.regression_full_ratio = 2.0;
    p.overrides = {capped};
    REQUIRE_FALSE(dex_score_policy_fault(p).has_value());
    const auto eff = resolve_dex_score_policy(p, "capme.exe");
    // 7 capped crashes on one device: inconsistent at the default cap, scored at 10.
    const auto in = mk(10, 1, 7, 0, Rr{2.0, 4.0});
    CHECK(std::string(dex_score_under_policy(in, kFloor, resolve_dex_score_policy(p, "x.exe"))
                          .withheld) == "inconsistent");
    const auto scored = dex_score_under_policy(in, kFloor, eff);
    REQUIRE(scored.score.has_value());
    CHECK(scored.deductions[3].points == 12.0); // full weight at the override's ratio of 2
    const auto direct = compute_stability_score(in, kFloor, eff.weights, eff.tiers.edges, eff.model);
    CHECK(*scored.score == *direct.score);
}
