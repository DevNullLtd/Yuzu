/**
 * test_dex_stats.cpp -- known-answer and self-consistency tests for the pure
 * DEX statistics core (dex_stats.hpp). No store, no I/O, no process.
 *
 * Invariants pinned here:
 *  - The pinned normal quantile matches the declared 95 percent level.
 *  - dex_stats_detail::log_gamma agrees with std::lgamma (single-threaded oracle only;
 *    the header itself must never call it).
 *  - The incomplete gamma / beta kernels satisfy their closed-form identities
 *    and their bisection quantiles round-trip.
 *  - Intervals match published tables (Newcombe 1998 Table I for Wilson;
 *    Garwood 1936 limits for the exact Poisson interval) AND an independent
 *    high-precision computation (Python Decimal bisection on the exact
 *    Poisson / binomial CDF, 60 to 90 digits, stated per case, 2026-10-07).
 *  - The exact Poisson kernels and the large-count approximations agree at the
 *    switch, rate ratios stay exact (Clopper-Pearson) up to their own limit and
 *    return nothing beyond it, and nothing returns a statistic after a
 *    convergence failure or overflow.
 *  - Absent-not-zero: invalid input and unrepresentable results are nullopt;
 *    below the cohort floor only the device count and the flag survive.
 */
#include "dex_stats.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cfloat>
#include <cmath>
#include <cstdint>
#include <limits>

using namespace yuzu::server;
using Catch::Approx;

namespace {

constexpr std::int64_t kI64Max = std::numeric_limits<std::int64_t>::max();
constexpr double kInf = std::numeric_limits<double>::infinity();

// Absolute match to the 8-decimal reference values below.
Approx near8(double expected) {
    return Approx(expected).margin(5e-8).epsilon(0.0);
}

// Poisson pmf at i for mean lam, via the lgamma oracle (single-threaded test).
double pmf(double i, double lam) {
    return std::exp(-lam + i * std::log(lam) - std::lgamma(i + 1.0));
}

// P(X <= k) for X ~ Poisson(lam): sum downward from k until negligible.
double cdf_le(double k, double lam) {
    double term = pmf(k, lam);
    double sum = 0.0;
    for (double i = k; i >= 0.0 && term > 1e-30 * (sum + 1e-300); i -= 1.0) {
        sum += term;
        term *= i / lam;
    }
    return sum;
}

// P(X >= k) for X ~ Poisson(lam): sum upward from k until negligible.
double sf_ge(double k, double lam) {
    double term = pmf(k, lam);
    double sum = 0.0;
    for (double i = k; term > 1e-30 * (sum + 1e-300); i += 1.0) {
        sum += term;
        term *= lam / (i + 1.0);
    }
    return sum;
}

} // namespace

TEST_CASE("DexStats: constants lock the pinned z to the declared level", "[dex][stats]") {
    CHECK(0.5 * std::erfc(-kDexStatsZ / std::sqrt(2.0)) ==
          Approx(1.0 - (1.0 - kDexStatsConfidence) / 2.0).epsilon(1e-12));
}

TEST_CASE("DexStats: log_gamma matches the lgamma oracle", "[dex][stats]") {
    for (double n : {1.0, 2.0, 3.0, 7.0, 14.0, 15.0, 16.0, 100.0, 1000.0, 1e6}) {
        const double want = std::lgamma(n);
        CHECK(dex_stats_detail::log_gamma(n) == Approx(want).epsilon(1e-13).margin(1e-14));
    }
}

TEST_CASE("DexStats: incomplete gamma and beta identities and quantile round trips",
          "[dex][stats]") {
    for (double x : {0.1, 1.0, 5.0})
        CHECK(dex_stats_detail::regularized_gamma_p(1.0, x) ==
              Approx(1.0 - std::exp(-x)).epsilon(1e-12));
    for (double x : {0.2, 0.5, 0.9})
        CHECK(dex_stats_detail::regularized_beta(x, 1.0, 1.0) == Approx(x).epsilon(1e-12));
    CHECK(dex_stats_detail::regularized_beta(0.3, 2.5, 4.0) ==
          Approx(1.0 - dex_stats_detail::regularized_beta(0.7, 4.0, 2.5)).epsilon(1e-12));
    for (double p : {0.025, 0.5, 0.975}) {
        const double gx = dex_stats_detail::gamma_quantile(7.0, p);
        CHECK(dex_stats_detail::regularized_gamma_p(7.0, gx) == Approx(p).epsilon(1e-10));
        const double bx = dex_stats_detail::beta_quantile(3.0, 9.0, p);
        CHECK(dex_stats_detail::regularized_beta(bx, 3.0, 9.0) == Approx(p).epsilon(1e-10));
    }
}

TEST_CASE("DexStats: exact and large-count Poisson bounds agree at the switch", "[dex][stats]") {
    const auto ex = dex_stats_detail::poisson_bounds_exact(1e6);
    const auto lg = dex_stats_detail::poisson_bounds_large(1e6);
    // Measured about 1.5e-11 relative at the switch.
    CHECK(ex.lower == Approx(lg.lower).epsilon(1e-10));
    CHECK(ex.upper == Approx(lg.upper).epsilon(1e-10));

    // Continuity: one more event moves each bound by about one event.
    const auto at = dex_rate(kDexStatsExactMaxEvents, 1.0);
    const auto past = dex_rate(kDexStatsExactMaxEvents + 1, 1.0);
    REQUIRE(at);
    REQUIRE(past);
    CHECK(past->lower - at->lower == Approx(1.0).margin(0.01));
    CHECK(past->upper - at->upper == Approx(1.0).margin(0.01));

    // Dispatch boundary, with literal counts so a moved cutoff cannot move the
    // inputs with it: exact kernels up to one million events, the approximation
    // past it. The tolerance absorbs rounding differences between the inlined and
    // direct evaluations; a moved cutoff differs by about 1.5e-11 relative.
    CHECK(kDexStatsExactMaxEvents == 1'000'000);
    const auto on_cut = dex_rate(1'000'000, 1.0);
    const auto over_cut = dex_rate(1'000'001, 1.0);
    REQUIRE(on_cut);
    REQUIRE(over_cut);
    CHECK(on_cut->lower == Approx(ex.lower).epsilon(1e-14));
    CHECK(on_cut->upper == Approx(ex.upper).epsilon(1e-14));
    const auto lg_over = dex_stats_detail::poisson_bounds_large(1e6 + 1.0);
    CHECK(over_cut->lower == Approx(lg_over.lower).epsilon(1e-14));
    CHECK(over_cut->upper == Approx(lg_over.upper).epsilon(1e-14));
}

TEST_CASE("DexStats: a convergence failure is NaN never a number", "[dex][stats]") {
    // A cap of one iteration cannot converge for these arguments.
    CHECK(std::isnan(dex_stats_detail::regularized_gamma_p(5.0, 3.0, 1)));
    CHECK(std::isnan(dex_stats_detail::regularized_gamma_p(5.0, 30.0, 1)));
    CHECK(std::isnan(dex_stats_detail::regularized_beta(0.4, 20.0, 30.0, 1)));
    CHECK(std::isnan(dex_stats_detail::gamma_quantile(5.0, 0.5, 1)));
    CHECK(std::isnan(dex_stats_detail::beta_quantile(20.0, 30.0, 0.5, 1)));
}

TEST_CASE("DexStats: dex_proportion Wilson known answers", "[dex][stats]") {
    // Newcombe (1998) Statistics in Medicine 17:857-872 Table I method 3
    // (4 d.p. there); 6 d.p. here from a Decimal evaluation of the closed form.
    struct V { std::int64_t x, n; double lo, hi; };
    for (const V& v : {V{81, 263, 0.255289, 0.366210}, V{15, 148, 0.062386, 0.160487},
                       V{0, 20, 0.0, 0.161125}, V{1, 29, 0.006113, 0.171755}}) {
        const auto p = dex_proportion(v.x, v.n);
        REQUIRE(p);
        CHECK(p->estimate == Approx(static_cast<double>(v.x) / static_cast<double>(v.n)));
        CHECK(p->lower == Approx(v.lo).margin(5e-7).epsilon(0.0));
        CHECK(p->upper == Approx(v.hi).margin(5e-7).epsilon(0.0));
    }
}

TEST_CASE("DexStats: dex_proportion edges validity and flag", "[dex][stats]") {
    const auto zero = dex_proportion(0, 20);
    const auto full = dex_proportion(20, 20);
    REQUIRE(zero);
    REQUIRE(full);
    CHECK(zero->lower == 0.0);
    CHECK(full->upper == 1.0);
    CHECK_FALSE(dex_proportion(5, 0));
    CHECK_FALSE(dex_proportion(-1, 10));
    CHECK_FALSE(dex_proportion(11, 10));
    CHECK_FALSE(dex_proportion(0, -4));
    const auto under = dex_proportion(19, 100);
    const auto atmin = dex_proportion(20, 100);
    REQUIRE(under);
    REQUIRE(atmin);
    CHECK_FALSE(under->reliable);
    CHECK(atmin->reliable);

    const auto all = dex_proportion(kI64Max, kI64Max);
    REQUIRE(all);
    CHECK(all->estimate == 1.0);
    CHECK(all->upper == 1.0);
    const auto none = dex_proportion(0, kI64Max);
    REQUIRE(none);
    CHECK(none->lower == 0.0);

    // At this many trials the estimate rounds to 1 while Wilson's upper bound
    // falls a ulp short; the interval must still contain its estimate.
    const auto edge = dex_proportion(20'000'000'000'000'000 - 1, 20'000'000'000'000'000);
    REQUIRE(edge);
    CHECK(edge->lower <= edge->estimate);
    CHECK(edge->estimate <= edge->upper);
}

TEST_CASE("DexStats: rule of three", "[dex][stats]") {
    const auto n20 = dex_rule_of_three(20);
    const auto n400 = dex_rule_of_three(400);
    const auto n1 = dex_rule_of_three(1);
    const auto n2 = dex_rule_of_three(2);
    REQUIRE(n20);
    REQUIRE(n400);
    REQUIRE(n1);
    REQUIRE(n2);
    CHECK(*n20 == Approx(0.15));
    CHECK(*n400 == Approx(0.0075));
    CHECK(*n1 == 1.0);
    CHECK(*n2 == 1.0);
    CHECK_FALSE(dex_rule_of_three(0));
    CHECK_FALSE(dex_rule_of_three(-5));
    for (double n : {20.0, 400.0, 10000.0}) {
        const double exact = 1.0 - std::pow(0.05, 1.0 / n);
        const auto r = dex_rule_of_three(static_cast<std::int64_t>(n));
        REQUIRE(r);
        CHECK(*r >= exact);
        CHECK(*r <= 1.08 * exact);
    }
}

TEST_CASE("DexStats: dex_rate Garwood known answers", "[dex][stats]") {
    // Garwood (1936) limits as tabulated in standard epidemiology texts
    // (k = 0 upper is -ln(0.025) = 3.6889); 8 d.p. from exact: Python Decimal
    // bisection on the Poisson CDF sum, 60 digits, 2026-10-07.
    struct V { std::int64_t k; double lo, hi; };
    for (const V& v : {V{0, 0.0, 3.68887945}, V{1, 0.02531781, 5.57164339},
                       V{5, 1.62348639, 11.66833208}, V{10, 4.79538870, 18.39035604},
                       V{100, 81.36399125, 121.62679379}}) {
        const auto r = dex_rate(v.k, 1.0);
        REQUIRE(r);
        CHECK(r->estimate == Approx(static_cast<double>(v.k)));
        CHECK(r->lower == near8(v.lo));
        CHECK(r->upper == near8(v.hi));
    }
    const auto none = dex_rate(0, 1.0);
    REQUIRE(none);
    CHECK(none->lower == 0.0);
}

TEST_CASE("DexStats: dex_rate scaling validity overflow and flag", "[dex][stats]") {
    const auto one = dex_rate(5, 1.0);
    const auto many = dex_rate(5, 250.0);
    REQUIRE(one);
    REQUIRE(many);
    CHECK(many->estimate == Approx(one->estimate / 250.0));
    CHECK(many->lower == Approx(one->lower / 250.0));
    CHECK(many->upper == Approx(one->upper / 250.0));

    CHECK_FALSE(dex_rate(-1, 1.0));
    CHECK_FALSE(dex_rate(1, 0.0));
    CHECK_FALSE(dex_rate(1, std::numeric_limits<double>::quiet_NaN()));
    CHECK_FALSE(dex_rate(1, -kInf));
    CHECK_FALSE(dex_rate(1, kInf));
    // Not representable: never infinity.
    CHECK_FALSE(dex_rate(1, std::numeric_limits<double>::denorm_min()));

    const auto big = dex_rate(kI64Max, 1.0);
    REQUIRE(big);
    CHECK(std::isfinite(big->upper));
    CHECK(big->lower < big->estimate);
    CHECK(big->estimate < big->upper);

    const auto under = dex_rate(19, 1.0);
    const auto atmin = dex_rate(20, 1.0);
    REQUIRE(under);
    REQUIRE(atmin);
    CHECK_FALSE(under->reliable);
    CHECK(atmin->reliable);
}

TEST_CASE("DexStats: dex_rate bounds satisfy the Poisson tail definition", "[dex][stats]") {
    // Independent of any table: the upper bound leaves alpha/2 in the lower
    // tail P(X <= k) and the lower bound leaves alpha/2 in P(X >= k). The
    // tolerance is 1e-7, not tighter: the oracle's pmf uses std::lgamma, which
    // at k = 1e6 (lgamma about 1.3e7) is only accurate to about 1e-9 absolute, a
    // few 1e-9 relative in the pmf after exp, so a tighter bound would test the
    // oracle rather than the kernel.
    for (std::int64_t k : {3, 100000, 1000000}) {
        const auto r = dex_rate(k, 1.0);
        REQUIRE(r);
        const double kd = static_cast<double>(k);
        CHECK(cdf_le(kd, r->upper) == Approx(0.025).epsilon(1e-7));
        CHECK(sf_ge(kd, r->lower) == Approx(0.025).epsilon(1e-7));
    }
}

TEST_CASE("DexStats: dex_rate_ratio known answers", "[dex][stats]") {
    // exact conditional (Clopper-Pearson) bounds mapped onto the ratio: Python
    // Decimal bisection on the binomial CDF, 60 digits, 2026-10-07.
    const auto r = dex_rate_ratio(11, 800.0, 21, 3011.0);
    REQUIRE(r);
    CHECK(r->estimate == near8(1.97148810));
    CHECK(r->lower == near8(0.85842640));
    CHECK(r->upper == near8(4.27726594));
    CHECK_FALSE(r->reliable);

    const auto eq = dex_rate_ratio(25, 1000.0, 25, 1000.0);
    REQUIRE(eq);
    CHECK(eq->estimate == near8(1.0));
    CHECK(eq->lower == near8(0.55104408));
    CHECK(eq->upper == near8(1.81473686));
    CHECK(eq->reliable);
}

TEST_CASE("DexStats: dex_rate_ratio arm swap is the reciprocal", "[dex][stats]") {
    const auto ab = dex_rate_ratio(11, 800.0, 21, 3011.0);
    const auto ba = dex_rate_ratio(21, 3011.0, 11, 800.0);
    REQUIRE(ab);
    REQUIRE(ba);
    CHECK(ba->estimate == Approx(1.0 / ab->estimate).epsilon(1e-9));
    CHECK(ba->lower == Approx(1.0 / ab->upper).epsilon(1e-9));
    CHECK(ba->upper == Approx(1.0 / ab->lower).epsilon(1e-9));
}

TEST_CASE("DexStats: dex_rate_ratio zero arms", "[dex][stats]") {
    const auto no_b = dex_rate_ratio(8, 500.0, 0, 500.0);
    REQUIRE(no_b);
    CHECK(no_b->estimate == kInf);
    CHECK(no_b->upper == kInf);
    CHECK(no_b->lower == near8(1.70697059));

    const auto no_a = dex_rate_ratio(0, 500.0, 12, 500.0);
    REQUIRE(no_a);
    CHECK(no_a->estimate == 0.0);
    CHECK(no_a->lower == 0.0);
    CHECK(no_a->upper == near8(0.35989382));

    CHECK_FALSE(dex_rate_ratio(0, 500.0, 0, 500.0));
}

TEST_CASE("DexStats: dex_rate_ratio guards and overflow", "[dex][stats]") {
    CHECK_FALSE(dex_rate_ratio(5, kDexRateRatioMinExposure - 0.5, 5, 100.0));
    CHECK_FALSE(dex_rate_ratio(5, 100.0, 5, kDexRateRatioMinExposure - 0.5));
    CHECK(dex_rate_ratio(5, kDexRateRatioMinExposure, 5, kDexRateRatioMinExposure));
    CHECK_FALSE(dex_rate_ratio(5, kInf, 5, 100.0));
    CHECK_FALSE(dex_rate_ratio(5, 100.0, 5, std::numeric_limits<double>::quiet_NaN()));
    CHECK_FALSE(dex_rate_ratio(-1, 100.0, 5, 100.0));
    CHECK_FALSE(dex_rate_ratio(5, 100.0, -1, 100.0));
    // The ratio itself overflows: distinct from the intentional zero-arm infinity.
    CHECK_FALSE(dex_rate_ratio(30, 10.0, 1, DBL_MAX));
}

TEST_CASE("DexStats: dex_rate_ratio one large arm matches the exact bounds", "[dex][stats]") {
    // Exact conditional (Clopper-Pearson) bounds on the odds a / b, equal
    // exposures so the scale is 1. Vectors: Python Decimal (90 digits) bisection
    // on the exact binomial CDF, 2026-10-07 (script not committed). A small arm
    // makes the tail a short sum: P(X <= a) = 1 - P(Y <= b - 1) with Y = n - X,
    // and P(X >= a) = 1 - P(X <= a - 1); for b = 1 or a = 1 the bounds have the
    // closed forms p_U = 0.975^(1/n) and p_L = 1 - 0.975^(1/n). A Wilson
    // stand-in is 86 percent low on the first row and 600 percent high on the
    // second, which is what these rows pin. The 1e9-arm tolerance of 2e-5
    // is the header banner's libm-dependent envelope, not this platform's
    // rounding; the 984,119,250 row sits at the worst point measured on one libm
    // (its want is the closed form, Decimal at 90 digits).
    struct V {
        std::int64_t a, b;
        bool upper;
        double want, tol;
    };
    for (const V& v : {V{1'000'001, 1, true, 39497968.70098762, 1e-7},
                       V{1, 1'000'001, false, 2.5317757669269599e-8, 1e-7},
                       V{1'000'000'000, 1, true, 39497890244.205102, 2e-5},
                       V{984'119'250, 1, true, 38870634124.328757, 2e-5},
                       V{1, 1'000'000'000, false, 2.5317807959292563e-11, 2e-5},
                       V{20, 1'000'000'000, false, 1.2216519531752164e-8, 2e-5}}) {
        const auto r = dex_rate_ratio(v.a, 100.0, v.b, 100.0);
        REQUIRE(r);
        CHECK(r->estimate == Approx(static_cast<double>(v.a) / static_cast<double>(v.b)));
        CHECK((v.upper ? r->upper : r->lower) == Approx(v.want).epsilon(v.tol));
        CHECK(r->lower < r->estimate);
        CHECK(r->estimate < r->upper);
    }
}

TEST_CASE("DexStats: dex_rate_ratio balanced arms above a million events", "[dex][stats]") {
    // 2,000,000 against 2,000,000 events, equal exposures. Decimal (70 digits)
    // bisection on the binomial tail summed only over the terms within 30
    // sigma of the mode (omitted mass < 1e-100), 2026-10-07; script not
    // committed. Odds, so the bounds are 1 / upper and 1 / lower of each other.
    const auto r = dex_rate_ratio(2'000'000, 100.0, 2'000'000, 100.0);
    REQUIRE(r);
    CHECK(r->estimate == 1.0);
    CHECK(r->lower == Approx(0.99804145643536860).epsilon(1e-7));
    CHECK(r->upper == Approx(1.0019623869850322).epsilon(1e-7));
    CHECK(r->reliable);
}

TEST_CASE("DexStats: dex_rate_ratio domain limit", "[dex][stats]") {
    CHECK(kDexRateRatioMaxEvents == 1'000'000'000);

    // Both arms at the limit still produce a statistic that brackets 1.
    const auto edge = dex_rate_ratio(kDexRateRatioMaxEvents, 100.0, kDexRateRatioMaxEvents, 100.0);
    REQUIRE(edge);
    CHECK(edge->estimate == 1.0);
    CHECK(edge->lower < 1.0);
    CHECK(edge->upper > 1.0);

    // One event past it in either arm, or int64 extremes: no statistic.
    CHECK_FALSE(dex_rate_ratio(kDexRateRatioMaxEvents + 1, 100.0, 1, 100.0));
    CHECK_FALSE(dex_rate_ratio(1, 100.0, kDexRateRatioMaxEvents + 1, 100.0));
    CHECK_FALSE(dex_rate_ratio(kI64Max, 10.0, kI64Max, 10.0));

    // Reliable only when both arms reach the threshold.
    const auto both = dex_rate_ratio(20, 100.0, 20, 100.0);
    const auto a_short = dex_rate_ratio(19, 100.0, 20, 100.0);
    const auto b_short = dex_rate_ratio(20, 100.0, 19, 100.0);
    REQUIRE(both);
    REQUIRE(a_short);
    REQUIRE(b_short);
    CHECK(both->reliable);
    CHECK_FALSE(a_short->reliable);
    CHECK_FALSE(b_short->reliable);
}

TEST_CASE("DexStats: floored helpers report the device count and the reason", "[dex][stats]") {
    const auto below = dex_floored_proportion(3, kDexCohortFloor - 1);
    CHECK(below.devices == kDexCohortFloor - 1);
    CHECK(below.below_floor);
    CHECK_FALSE(below.stats);

    const auto at = dex_floored_proportion(3, kDexCohortFloor);
    const auto at_want = dex_proportion(3, kDexCohortFloor);
    REQUIRE(at.stats);
    REQUIRE(at_want);
    CHECK(at.devices == kDexCohortFloor);
    CHECK_FALSE(at.below_floor);
    CHECK(at.stats->lower == at_want->lower);
    CHECK(at.stats->upper == at_want->upper);

    // Invalid pair AT the floor: not a small cohort, so below_floor stays false.
    const auto bad = dex_floored_proportion(99, kDexCohortFloor);
    CHECK(bad.devices == kDexCohortFloor);
    CHECK_FALSE(bad.below_floor);
    CHECK_FALSE(bad.stats);

    const auto rbelow = dex_floored_rate(3, 40.0, kDexCohortFloor - 1);
    CHECK(rbelow.devices == kDexCohortFloor - 1);
    CHECK(rbelow.below_floor);
    CHECK_FALSE(rbelow.stats);

    const auto rat = dex_floored_rate(3, 40.0, kDexCohortFloor);
    const auto rat_want = dex_rate(3, 40.0);
    REQUIRE(rat.stats);
    REQUIRE(rat_want);
    CHECK_FALSE(rat.below_floor);
    CHECK(rat.stats->upper == rat_want->upper);

    const auto rbad = dex_floored_rate(3, 0.0, kDexCohortFloor);
    CHECK(rbad.devices == kDexCohortFloor);
    CHECK_FALSE(rbad.below_floor);
    CHECK_FALSE(rbad.stats);
}

TEST_CASE("DexStats: dex_proportion exact edges do not rest on rounding luck", "[dex][stats]") {
    // One trial, Wilson closed forms with z2 = kDexStatsZ^2 = 3.84145882069412523:
    // 0/1 -> [0, z2 / (1 + z2)] and 1/1 -> [1 / (1 + z2), 1]. Python Decimal,
    // 70 digits, 2026-10-07.
    const auto none = dex_proportion(0, 1);
    const auto all = dex_proportion(1, 1);
    REQUIRE(none);
    REQUIRE(all);
    CHECK(none->lower == 0.0);
    CHECK(none->upper == near8(0.79345068562276258));
    CHECK(all->lower == near8(0.20654931437723742));
    CHECK(all->upper == 1.0);
    // The formula alone is not exact at the edges for every n and every compiler
    // (unclamped it gives a lower bound of a few 1e-17 at 0/7 and 0/14, the last
    // digits moving with the floating-point contraction setting, and
    // 0.99999999999999989 as the upper bound at 10/10 or 25/25), yet both edges
    // are exactly 0 and 1. The range is wide enough to catch the rounding on any
    // contraction setting.
    for (std::int64_t n = 1; n <= 40; ++n) {
        const auto lo = dex_proportion(0, n);
        const auto hi = dex_proportion(n, n);
        REQUIRE(lo);
        REQUIRE(hi);
        CHECK(lo->lower == 0.0);
        CHECK(hi->upper == 1.0);
    }
}

TEST_CASE("DexStats: a bound that alone overflows is refused", "[dex][stats]") {
    // dex_rate: the rate stays finite but the upper bound does not. 0 /
    // denorm_min is 0 while -ln(0.025) / denorm_min is infinite; 1 / 2.5e-308 =
    // 4e307 is finite while 5.5716434 / 2.5e-308 = 2.2e308 exceeds DBL_MAX.
    CHECK_FALSE(dex_rate(0, std::numeric_limits<double>::denorm_min()));
    CHECK_FALSE(dex_rate(1, 2.5e-308));
    // A finite negative exposure is invalid, not just -infinity.
    CHECK_FALSE(dex_rate(5, -1.0));

    // dex_rate_ratio; Python Decimal, 70 digits, 2026-10-07. scale = exposure_b /
    // exposure_a. Upper overflows while the ratio (0.02 * DBL_MAX) stays finite:
    // odds(0.975^(1/3)) * DBL_MAX / 100 = 2.12e308.
    CHECK_FALSE(dex_rate_ratio(2, 100.0, 1, DBL_MAX));
    // Zero denominator arm: ratio and upper are +infinity by design, so the lower
    // bound is the only finiteness guard: odds(0.025^(1/10000)) * DBL_MAX / 100 =
    // 4.87e309.
    CHECK_FALSE(dex_rate_ratio(10000, 100.0, 0, DBL_MAX));
    // Zero numerator arm: ratio 0 and lower 0 are finite; odds(0.975) * DBL_MAX /
    // 10 = 7.01e308.
    CHECK_FALSE(dex_rate_ratio(0, 10.0, 1, DBL_MAX));

    // A negative count next to a zero arm: the explicit guard is the only refusal.
    CHECK_FALSE(dex_rate_ratio(0, 100.0, -1, 100.0));
    CHECK_FALSE(dex_rate_ratio(-1, 100.0, 0, 100.0));
}

TEST_CASE("DexStats: the rate-ratio exposure guard is the cohort floor per arm", "[dex][stats]") {
    constexpr double floor_d = static_cast<double>(kDexCohortFloor);
    CHECK(kDexRateRatioMinExposure == floor_d);
    // Exactly on the guard passes, one ulp under fails, each arm tested with the
    // other far above.
    CHECK(dex_rate_ratio(5, floor_d, 5, 1000.0));
    CHECK(dex_rate_ratio(5, 1000.0, 5, floor_d));
    CHECK_FALSE(dex_rate_ratio(5, std::nextafter(floor_d, 0.0), 5, 1000.0));
    CHECK_FALSE(dex_rate_ratio(5, 1000.0, 5, std::nextafter(floor_d, 0.0)));
}

TEST_CASE("DexStats: floored helpers clear the floor on devices alone and refuse negatives",
          "[dex][stats]") {
    // One above the floor and far above it, valid pairs: the statistic is present.
    for (const std::int64_t devices : {kDexCohortFloor + 1, std::int64_t{1000}}) {
        const auto p = dex_floored_proportion(3, devices);
        const auto p_want = dex_proportion(3, devices);
        REQUIRE(p.stats);
        REQUIRE(p_want);
        CHECK(p.devices == devices);
        CHECK_FALSE(p.below_floor);
        CHECK(p.stats->lower == p_want->lower);
        const auto r = dex_floored_rate(3, 40.0, devices);
        const auto r_want = dex_rate(3, 40.0);
        REQUIRE(r.stats);
        REQUIRE(r_want);
        CHECK_FALSE(r.below_floor);
        CHECK(r.stats->upper == r_want->upper);
    }
    // The floor is on devices, never exposure: an exposure under the floor value
    // still yields a rate once devices clear it (3 events / 2.5 = 1.2).
    const auto thin = dex_floored_rate(3, 2.5, kDexCohortFloor);
    REQUIRE(thin.stats);
    CHECK(thin.stats->estimate == Approx(1.2));
    // Invalid pair below the floor: the device count and the reason, nothing else.
    const auto bad_p = dex_floored_proportion(99, kDexCohortFloor - 1);
    CHECK(bad_p.devices == kDexCohortFloor - 1);
    CHECK(bad_p.below_floor);
    CHECK_FALSE(bad_p.stats);
    const auto bad_r = dex_floored_rate(-1, 40.0, kDexCohortFloor - 1);
    CHECK(bad_r.below_floor);
    CHECK_FALSE(bad_r.stats);

    // An empty cohort is below the floor, not a failure.
    const auto empty_p = dex_floored_proportion(0, 0);
    CHECK(empty_p.devices == 0);
    CHECK(empty_p.below_floor);
    CHECK_FALSE(empty_p.stats);
    const auto empty_r = dex_floored_rate(0, 40.0, 0);
    CHECK(empty_r.devices == 0);
    CHECK(empty_r.below_floor);
    CHECK_FALSE(empty_r.stats);

    // A negative device count must not reach the statistic (dex_rate(3, 40.0) is
    // valid) and must not read as "too few devices".
    for (const std::int64_t devices :
         {std::int64_t{-1}, std::numeric_limits<std::int64_t>::min()}) {
        const auto p = dex_floored_proportion(3, devices);
        CHECK(p.devices == devices);
        CHECK_FALSE(p.below_floor);
        CHECK_FALSE(p.stats);
        const auto r = dex_floored_rate(3, 40.0, devices);
        CHECK(r.devices == devices);
        CHECK_FALSE(r.below_floor);
        CHECK_FALSE(r.stats);
    }
}

TEST_CASE("DexStats: a quantile does not number past a failed bracket evaluation", "[dex][stats]") {
    // With a cap of one iteration P(1, 1) cannot converge but the larger brackets
    // P(1, 2), P(1, 4) and the bisection points past 2 do (a = 1 makes the first
    // continued-fraction coefficient zero); the quantile must still be NaN.
    CHECK(std::isnan(dex_stats_detail::gamma_quantile(1.0, 0.975, 1)));
}

TEST_CASE("DexStats: dex_rate_ratio converges at a slow large-arm pair", "[dex][stats]") {
    // 33,837 against 1e9 needs about 21,000 beta iterations in one continued-
    // fraction evaluation with fused multiply-add (about 200 without; 25,631
    // against 999,996,012 needs about 25,600), so a cap lowered below that
    // silently turns a valid input into nullopt. Exact conditional bounds on the
    // odds, equal exposures: Python Decimal (70 digits) bisection on the
    // binomial CDF over N = 1,000,033,837 trials, 2026-10-07; the swapped
    // orientation is the reciprocal of the other bound. The 2e-5 is the header's
    // envelope, not this platform's rounding.
    const auto r = dex_rate_ratio(33'837, 100.0, 1'000'000'000, 100.0);
    REQUIRE(r);
    CHECK(r->lower == Approx(3.3477409884938568e-5).epsilon(2e-5));
    CHECK(r->upper == Approx(3.4199489907041657e-5).epsilon(2e-5));
    const auto s = dex_rate_ratio(1'000'000'000, 100.0, 33'837, 100.0);
    REQUIRE(s);
    CHECK(s->lower == Approx(29240.202199451534).epsilon(2e-5));
    CHECK(s->upper == Approx(29870.889158898113).epsilon(2e-5));
}
