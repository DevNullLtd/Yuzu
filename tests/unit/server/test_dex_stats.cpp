/**
 * test_dex_stats.cpp -- known-answer and self-consistency tests for the pure
 * DEX statistics core (dex_stats.hpp). No store, no I/O, no process.
 *
 * Invariants pinned here:
 *  - The pinned normal quantile matches the declared 95 percent level.
 *  - detail::log_gamma agrees with std::lgamma (single-threaded oracle only;
 *    the header itself must never call it).
 *  - The incomplete gamma / beta kernels satisfy their closed-form identities
 *    and their bisection quantiles round-trip.
 *  - Intervals match published tables (Newcombe 1998 Table I for Wilson;
 *    Garwood 1936 limits for the exact Poisson interval) AND an independent
 *    high-precision computation (Python Decimal bisection on the exact
 *    Poisson / binomial CDF, 60 digits, 2026-10-07).
 *  - The exact kernels and the large-count closed forms agree at the switch
 *    and nothing returns a statistic after a convergence failure or overflow.
 *  - Absent-not-zero: invalid input and unrepresentable results are nullopt;
 *    below the cohort floor only counts survive.
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
    CHECK(kDexStatsConfidence == 0.95);
    CHECK(0.5 * std::erfc(-kDexStatsZ / std::sqrt(2.0)) == Approx(0.975).epsilon(1e-12));
    CHECK(kDexStatsExactMaxEvents == 1000000);
}

TEST_CASE("DexStats: log_gamma matches the lgamma oracle", "[dex][stats]") {
    for (double n : {1.0, 2.0, 3.0, 7.0, 14.0, 15.0, 16.0, 100.0, 1000.0, 1e6}) {
        const double want = std::lgamma(n);
        CHECK(detail::log_gamma(n) == Approx(want).epsilon(1e-13).margin(1e-14));
    }
    double fact = 1.0;
    for (int n = 1; n <= 10; ++n) {
        fact *= n;
        CHECK(detail::log_gamma(n + 1.0) == Approx(std::log(fact)).epsilon(1e-13).margin(1e-14));
    }
    CHECK(std::fabs(detail::log_gamma(1.0)) < 1e-15);
    CHECK(std::fabs(detail::log_gamma(2.0)) < 1e-15);
}

TEST_CASE("DexStats: incomplete gamma and beta identities and quantile round trips",
          "[dex][stats]") {
    for (double x : {0.1, 1.0, 5.0})
        CHECK(detail::regularized_gamma_p(1.0, x) == Approx(1.0 - std::exp(-x)).epsilon(1e-12));
    for (double x : {0.2, 0.5, 0.9})
        CHECK(detail::regularized_beta(x, 1.0, 1.0) == Approx(x).epsilon(1e-12));
    CHECK(detail::regularized_beta(0.3, 2.5, 4.0) ==
          Approx(1.0 - detail::regularized_beta(0.7, 4.0, 2.5)).epsilon(1e-12));
    for (double p : {0.025, 0.5, 0.975}) {
        const double gx = detail::gamma_quantile(7.0, p);
        CHECK(detail::regularized_gamma_p(7.0, gx) == Approx(p).epsilon(1e-10));
        const double bx = detail::beta_quantile(3.0, 9.0, p);
        CHECK(detail::regularized_beta(bx, 3.0, 9.0) == Approx(p).epsilon(1e-10));
    }
}

TEST_CASE("DexStats: exact and large-count Poisson bounds agree at the switch", "[dex][stats]") {
    const auto ex = detail::poisson_bounds_exact(1e6);
    const auto lg = detail::poisson_bounds_large(1e6);
    CHECK(ex.lower == Approx(lg.lower).epsilon(1e-9));
    CHECK(ex.upper == Approx(lg.upper).epsilon(1e-9));

    // Continuity: one more event moves each bound by about one event.
    const auto at = dex_rate(kDexStatsExactMaxEvents, 1.0);
    const auto past = dex_rate(kDexStatsExactMaxEvents + 1, 1.0);
    REQUIRE(at);
    REQUIRE(past);
    CHECK(past->lower - at->lower == Approx(1.0).margin(0.01));
    CHECK(past->upper - at->upper == Approx(1.0).margin(0.01));
}

TEST_CASE("DexStats: a convergence failure is NaN never a number", "[dex][stats]") {
    // A cap of one iteration cannot converge for these arguments.
    CHECK(std::isnan(detail::regularized_gamma_p(5.0, 3.0, 1)));
    CHECK(std::isnan(detail::regularized_gamma_p(5.0, 30.0, 1)));
    CHECK(std::isnan(detail::regularized_beta(0.4, 20.0, 30.0, 1)));
    CHECK(std::isnan(detail::gamma_quantile(5.0, 0.5, 1)));
    CHECK(std::isnan(detail::beta_quantile(20.0, 30.0, 0.5, 1)));

    // The asymptotic branch never sees a kernel failure.
    const auto r = dex_rate(1'000'000'000, 1.0);
    REQUIRE(r);
    CHECK(std::isfinite(r->lower));
    CHECK(r->lower < r->rate);
    CHECK(r->rate < r->upper);
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
    CHECK(dex_proportion(0, 20)->lower == 0.0);
    CHECK(dex_proportion(20, 20)->upper == 1.0);
    CHECK_FALSE(dex_proportion(5, 0));
    CHECK_FALSE(dex_proportion(-1, 10));
    CHECK_FALSE(dex_proportion(11, 10));
    CHECK_FALSE(dex_proportion(0, -4));
    CHECK_FALSE(dex_proportion(19, 100)->reliable);
    CHECK(dex_proportion(20, 100)->reliable);

    const auto all = dex_proportion(kI64Max, kI64Max);
    REQUIRE(all);
    CHECK(all->estimate == 1.0);
    CHECK(all->upper == 1.0);
    const auto none = dex_proportion(0, kI64Max);
    REQUIRE(none);
    CHECK(none->lower == 0.0);
}

TEST_CASE("DexStats: rule of three", "[dex][stats]") {
    CHECK(*dex_rule_of_three(20) == Approx(0.15));
    CHECK(*dex_rule_of_three(400) == Approx(0.0075));
    CHECK(*dex_rule_of_three(1) == 1.0);
    CHECK(*dex_rule_of_three(2) == 1.0);
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
        CHECK(r->rate == Approx(static_cast<double>(v.k)));
        CHECK(r->lower == near8(v.lo));
        CHECK(r->upper == near8(v.hi));
    }
    CHECK(dex_rate(0, 1.0)->lower == 0.0);
}

TEST_CASE("DexStats: dex_rate scaling validity overflow and flag", "[dex][stats]") {
    const auto one = dex_rate(5, 1.0);
    const auto many = dex_rate(5, 250.0);
    REQUIRE(one);
    REQUIRE(many);
    CHECK(many->rate == Approx(one->rate / 250.0));
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
    CHECK(big->lower < big->rate);
    CHECK(big->rate < big->upper);

    CHECK_FALSE(dex_rate(19, 1.0)->reliable);
    CHECK(dex_rate(20, 1.0)->reliable);
}

TEST_CASE("DexStats: dex_rate bounds satisfy the Poisson tail definition", "[dex][stats]") {
    // Independent of any table: the upper bound leaves alpha/2 in the lower
    // tail P(X <= k) and the lower bound leaves alpha/2 in P(X >= k).
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
    CHECK(r->ratio == near8(1.97148810));
    CHECK(r->lower == near8(0.85842640));
    CHECK(r->upper == near8(4.27726594));
    CHECK_FALSE(r->reliable);

    const auto eq = dex_rate_ratio(25, 1000.0, 25, 1000.0);
    REQUIRE(eq);
    CHECK(eq->ratio == near8(1.0));
    CHECK(eq->lower == near8(0.55104408));
    CHECK(eq->upper == near8(1.81473686));
    CHECK(eq->reliable);
}

TEST_CASE("DexStats: dex_rate_ratio arm swap is the reciprocal", "[dex][stats]") {
    const auto ab = dex_rate_ratio(11, 800.0, 21, 3011.0);
    const auto ba = dex_rate_ratio(21, 3011.0, 11, 800.0);
    REQUIRE(ab);
    REQUIRE(ba);
    CHECK(ba->ratio == Approx(1.0 / ab->ratio).epsilon(1e-9));
    CHECK(ba->lower == Approx(1.0 / ab->upper).epsilon(1e-9));
    CHECK(ba->upper == Approx(1.0 / ab->lower).epsilon(1e-9));
}

TEST_CASE("DexStats: dex_rate_ratio zero arms", "[dex][stats]") {
    const auto no_b = dex_rate_ratio(8, 500.0, 0, 500.0);
    REQUIRE(no_b);
    CHECK(no_b->ratio == kInf);
    CHECK(no_b->upper == kInf);
    CHECK(no_b->lower == near8(1.70697059));

    const auto no_a = dex_rate_ratio(0, 500.0, 12, 500.0);
    REQUIRE(no_a);
    CHECK(no_a->ratio == 0.0);
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

TEST_CASE("DexStats: dex_rate_ratio large-count branch", "[dex][stats]") {
    const auto r = dex_rate_ratio(2'000'000, 100.0, 2'000'000, 100.0);
    REQUIRE(r);
    CHECK(r->ratio == 1.0);
    CHECK(std::isfinite(r->lower));
    CHECK(std::isfinite(r->upper));
    CHECK(r->lower < 1.0);
    CHECK(r->upper > 1.0);

    // No int64 sum: both arms at the maximum.
    const auto m = dex_rate_ratio(kI64Max, 10.0, kI64Max, 10.0);
    REQUIRE(m);
    CHECK(m->ratio == 1.0);

    // Reliable only when both arms reach the threshold.
    CHECK(dex_rate_ratio(20, 100.0, 20, 100.0)->reliable);
    CHECK_FALSE(dex_rate_ratio(19, 100.0, 20, 100.0)->reliable);
    CHECK_FALSE(dex_rate_ratio(20, 100.0, 19, 100.0)->reliable);
}

TEST_CASE("DexStats: floored helpers carry counts and withhold stats", "[dex][stats]") {
    const auto below = dex_floored_proportion(3, kDexCohortFloor - 1);
    CHECK(below.events == 3);
    CHECK(below.devices == kDexCohortFloor - 1);
    CHECK_FALSE(below.stats);

    const auto at = dex_floored_proportion(3, kDexCohortFloor);
    REQUIRE(at.stats);
    CHECK(at.stats->lower == dex_proportion(3, kDexCohortFloor)->lower);
    CHECK(at.stats->upper == dex_proportion(3, kDexCohortFloor)->upper);

    const auto bad = dex_floored_proportion(99, kDexCohortFloor);
    CHECK(bad.events == 99);
    CHECK(bad.devices == kDexCohortFloor);
    CHECK_FALSE(bad.stats);

    const auto rbelow = dex_floored_rate(3, 40.0, kDexCohortFloor - 1);
    CHECK(rbelow.events == 3);
    CHECK(rbelow.devices == kDexCohortFloor - 1);
    CHECK_FALSE(rbelow.stats);

    const auto rat = dex_floored_rate(3, 40.0, kDexCohortFloor);
    REQUIRE(rat.stats);
    CHECK(rat.stats->upper == dex_rate(3, 40.0)->upper);

    const auto rbad = dex_floored_rate(3, 0.0, kDexCohortFloor);
    CHECK(rbad.events == 3);
    CHECK_FALSE(rbad.stats);
}
