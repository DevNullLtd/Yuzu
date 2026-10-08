/**
 * dex_stats.hpp -- the one home for the statistics the DEX application views
 * print, so every number is derived once and tested once.
 *
 * What is here (intervals are two-sided at kDexStatsConfidence = 95 percent,
 * except the one-sided rule of three):
 *   - dex_proportion      Wilson score interval for events / trials
 *   - dex_rule_of_three   plain-language upper bound when zero events were seen
 *   - dex_rate            exact (Garwood) Poisson interval for events / exposure
 *   - dex_rate_ratio      rate A / rate B with the exact conditional (binomial,
 *                         Clopper-Pearson) interval and a minimum-exposure guard
 *   - dex_floored_*       the same, but only a COUNT is returned below the
 *                         cohort floor (kDexCohortFloor devices)
 *
 * Honesty rules:
 *   - std::optional carries ONE meaning: "no statistic can be stated for these
 *     inputs" -- the input is invalid, the result is not representable as a
 *     finite double, or (rate ratios only) an arm lies outside the accuracy
 *     domain; dex_rate has no such ceiling (Wilson-Hilferty to INT64_MAX). It is
 *     never zero. (The single documented infinity is a rate ratio whose
 *     denominator arm saw no events.)
 *   - A reliability flag is a label, never suppression: a statistic on fewer
 *     than kDexStatsReliableMinEvents (20) numerator events -- the NCHS
 *     small-count convention -- is still printed, marked indicative.
 *   - Below the cohort floor a count is honest and a rate singles people out,
 *     so the floored helpers always carry the counts and withhold only the
 *     statistics.
 *
 * Numerical contract:
 *   - Rates: events up to kDexStatsExactMaxEvents use the exact kernels
 *     (regularised incomplete gamma inverted by bisection). Above it the
 *     Wilson-Hilferty chi-square quantile gives the bounds, within 1e-10
 *     relative of the exact ones at the switch (measured 1.6e-11, pinned by test).
 *   - Rate ratios: the exact conditional (Clopper-Pearson) bounds, from the
 *     regularised incomplete beta, for every arm up to kDexRateRatioMaxEvents,
 *     evaluated in double to within 2e-5 relative of the exact rational bounds.
 *     That envelope is libm-dependent: on one libm the worst measured was 1.1e-5,
 *     at an arm of 1 against about 9.8e8; it is under 4e-6 for arms of 2 or more
 *     and about 1e-9 at 1e6 against 1. Above that limit no ratio is produced.
 *   - A kernel that cannot converge inside kDexStatsMaxIterations returns NaN,
 *     quantiles propagate it, and every public function that computes a bound
 *     ends with a finiteness check: a statistic is never returned after a
 *     convergence failure or an overflow.
 *
 * Thread-safe and store-free: pure functions, no statics, and no C library
 * log-gamma (it writes the global signgam on glibc and Darwin). Header-only.
 */
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>

#include "dex_perf_model.hpp" // kDexCohortFloor

namespace yuzu::server {

/// Two-sided confidence level of every interval in this header (the one-sided
/// rule of three excepted).
inline constexpr double kDexStatsConfidence = 0.95;

/// Normal quantile for kDexStatsConfidence, pinned rather than computed (no
/// inverse-normal code); the unit test locks the pair together.
inline constexpr double kDexStatsZ = 1.959963984540054;

/// A rate or proportion on fewer numerator events than this is flagged
/// unreliable (NCHS small-count convention). For a Poisson count the relative
/// standard error is 1/sqrt(k), so k >= 20 keeps it at or under 22.4 percent.
inline constexpr std::int64_t kDexStatsReliableMinEvents = 20;

/// Both arms of a rate ratio need at least this much exposure (the caller's
/// unit, device-days for the views) or no ratio is produced.
inline constexpr double kDexRateRatioMinExposure = static_cast<double>(kDexCohortFloor);

/// Largest event count dex_rate serves with the exact Poisson kernels. They need
/// about 7.4 * sqrt(k) iterations (7413 at one million); above it dex_rate uses
/// closed-form bounds. Rate ratios have their own limit, kDexRateRatioMaxEvents.
inline constexpr std::int64_t kDexStatsExactMaxEvents = 1'000'000;

/// Largest arm dex_rate_ratio accepts. Beyond it the conditional proportion sits
/// within 1e-16 * a / b of 0 or 1, so the odds lose double precision for any
/// method (measured 1.2e-5 relative at 1e10, 3e-4 at 1e12), and the beta
/// fraction no longer converges inside the iteration cap: no ratio is produced
/// rather than an inaccurate one.
inline constexpr std::int64_t kDexRateRatioMaxEvents = 1'000'000'000;

/// Iteration cap of the series / continued fractions: 2.2x the worst case
/// measured over both exact domains (gamma 7,413 at one million events; beta
/// about 23,200 near 29,500 against 1e9). Hitting it is a convergence failure
/// (NaN), never a result.
inline constexpr int kDexStatsMaxIterations = 50000;

namespace dex_stats_detail {

/// Keeps a Lentz continued-fraction term away from zero.
inline constexpr double kTiny = 1e-300;
/// Relative convergence tolerance of the series and continued fractions.
inline constexpr double kEps = 1e-15;
/// Two-sided alpha of every interval here.
inline constexpr double kAlpha = 1.0 - kDexStatsConfidence;
/// Cap on the halvings of a bisection (it normally stops sooner, when `mid`
/// reaches an end point).
inline constexpr int kBisections = 200;
/// Doublings of the gamma bracket: hi = max(a, 1) * 2^64 exceeds any quantile
/// the exact domain can reach.
inline constexpr int kDoublings = 64;
inline constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
/// log(sqrt(2 * pi)), the constant term of the Stirling series.
inline constexpr double kHalfLog2Pi = 0.91893853320467274178;

[[nodiscard]] inline double floor_tiny(double v) {
    return std::fabs(v) < kTiny ? kTiny : v;
}

/// log(Gamma(n)) for n >= 1 (Stirling series after shifting to n >= 15,
/// ~1e-15 relative). Replaces the C library log-gamma, which is not thread-safe;
/// every argument in this header is an integer >= 1.
inline double log_gamma(double n) {
    double shift = 0.0;
    while (n < 15.0) {
        shift += std::log(n);
        n += 1.0;
    }
    const double n2 = n * n;
    const double n3 = n * n2;
    const double n5 = n3 * n2;
    const double series = 1.0 / (12.0 * n) - 1.0 / (360.0 * n3) + 1.0 / (1260.0 * n5) -
                          1.0 / (1680.0 * n5 * n2) + 1.0 / (1188.0 * n5 * n2 * n2);
    return (n - 0.5) * std::log(n) - n + kHalfLog2Pi + series - shift;
}

/// Regularised lower incomplete gamma P(a, x), a >= 1. NaN if the series or
/// continued fraction does not converge within max_iter.
inline double regularized_gamma_p(double a, double x, int max_iter = kDexStatsMaxIterations) {
    if (x <= 0.0)
        return 0.0;
    const double prefactor = std::exp(-x + a * std::log(x) - log_gamma(a));
    if (x < a + 1.0) {
        double ap = a;
        double term = 1.0 / a;
        double sum = term;
        for (int i = 0; i < max_iter; ++i) {
            ap += 1.0;
            term *= x / ap;
            sum += term;
            if (std::fabs(term) < std::fabs(sum) * kEps)
                return (std::min)(1.0, sum * prefactor);
        }
        return kNaN;
    }
    // Continued fraction for Q(a, x): modified Lentz (Lentz 1976), the gcf form
    // of Numerical Recipes.
    double b = x + 1.0 - a;
    double c = 1.0 / kTiny;
    double d = 1.0 / b;
    double h = d;
    for (int i = 1; i <= max_iter; ++i) {
        const double an = -static_cast<double>(i) * (static_cast<double>(i) - a);
        b += 2.0;
        d = an * d + b;
        d = floor_tiny(d);
        c = b + an / c;
        c = floor_tiny(c);
        d = 1.0 / d;
        const double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < kEps)
            return (std::max)(0.0, 1.0 - prefactor * h);
    }
    return kNaN;
}

/// Continued fraction of the incomplete beta: modified Lentz (Lentz 1976) in the
/// Numerical Recipes betacf form, whence qab / qap / qam (a + b, a + 1, a - 1),
/// aa (the even / odd coefficient) and bt. NaN on cap.
inline double beta_fraction(double x, double a, double b, int max_iter) {
    const double qab = a + b;
    const double qap = a + 1.0;
    const double qam = a - 1.0;
    double c = 1.0;
    double d = 1.0 - qab * x / qap;
    d = floor_tiny(d);
    d = 1.0 / d;
    double h = d;
    for (int m = 1; m <= max_iter; ++m) {
        const double dm = static_cast<double>(m);
        const double m2 = 2.0 * dm;
        double aa = dm * (b - dm) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        d = floor_tiny(d);
        c = 1.0 + aa / c;
        c = floor_tiny(c);
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + dm) * (qab + dm) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        d = floor_tiny(d);
        c = 1.0 + aa / c;
        c = floor_tiny(c);
        d = 1.0 / d;
        const double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < kEps)
            return h;
    }
    return kNaN;
}

/// Regularised incomplete beta I_x(a, b), a and b >= 1. NaN on non-convergence.
inline double regularized_beta(double x, double a, double b,
                               int max_iter = kDexStatsMaxIterations) {
    if (x <= 0.0)
        return 0.0;
    if (x >= 1.0)
        return 1.0;
    const double bt = std::exp(log_gamma(a + b) - log_gamma(a) - log_gamma(b) +
                               a * std::log(x) + b * std::log1p(-x));
    if (x > (a + 1.0) / (a + b + 2.0)) {
        const double f = beta_fraction(1.0 - x, b, a, max_iter);
        // std::max / std::min would swallow a NaN, so test it first.
        return std::isnan(f) ? f : (std::max)(0.0, 1.0 - bt * f / b);
    }
    const double f = beta_fraction(x, a, b, max_iter);
    return std::isnan(f) ? f : (std::min)(1.0, bt * f / a);
}

/// x with P(a, x) = p, by bisection (monotone, iteration cap kBisections: bounded
/// cost). NaN if any evaluation fails to converge.
inline double gamma_quantile(double a, double p, int max_iter = kDexStatsMaxIterations) {
    if (p <= 0.0)
        return 0.0;
    double lo = 0.0;
    double hi = (std::max)(a, 1.0);
    for (int i = 0;; ++i) {
        if (i > kDoublings)
            return kNaN;
        const double v = regularized_gamma_p(a, hi, max_iter);
        if (std::isnan(v))
            return kNaN;
        if (v >= p)
            break;
        lo = hi;
        hi *= 2.0;
    }
    for (int i = 0; i < kBisections; ++i) {
        const double mid = 0.5 * (lo + hi);
        if (mid <= lo || mid >= hi)
            break;
        const double v = regularized_gamma_p(a, mid, max_iter);
        if (std::isnan(v))
            return kNaN;
        (v < p ? lo : hi) = mid;
    }
    return 0.5 * (lo + hi);
}

/// x in [0, 1] with I_x(a, b) = p, by bisection; NaN on any convergence failure.
inline double beta_quantile(double a, double b, double p, int max_iter = kDexStatsMaxIterations) {
    if (p <= 0.0)
        return 0.0;
    if (p >= 1.0)
        return 1.0;
    double lo = 0.0;
    double hi = 1.0;
    for (int i = 0; i < kBisections; ++i) {
        const double mid = 0.5 * (lo + hi);
        if (mid <= lo || mid >= hi)
            break;
        const double v = regularized_beta(mid, a, b, max_iter);
        if (std::isnan(v))
            return kNaN;
        (v < p ? lo : hi) = mid;
    }
    return 0.5 * (lo + hi);
}

struct Bounds {
    double lower;
    double upper;
};

/// Exact (Garwood) Poisson bounds on the mean for k observed events. They equal
/// chi2(alpha/2; 2k) / 2 and chi2(1 - alpha/2; 2k + 2) / 2.
inline Bounds poisson_bounds_exact(double k) {
    return {k == 0.0 ? 0.0 : gamma_quantile(k, kAlpha / 2.0),
            gamma_quantile(k + 1.0, 1.0 - kAlpha / 2.0)};
}

/// Wilson-Hilferty approximation of the same bounds: chi2_p(nu) ~
/// nu * (1 - 2 / (9 nu) + z_p * sqrt(2 / (9 nu)))^3. Used only above
/// kDexStatsExactMaxEvents, where it is within 1e-10 relative of the exact
/// bounds (measured 1.6e-11 at the switch).
inline Bounds poisson_bounds_large(double k) {
    const auto chi2_half = [](double nu, double z) {
        const double t = 2.0 / (9.0 * nu);
        const double u = 1.0 - t + z * std::sqrt(t);
        return 0.5 * nu * u * u * u;
    };
    return {chi2_half(2.0 * k, -kDexStatsZ), chi2_half(2.0 * k + 2.0, kDexStatsZ)};
}

/// Wilson score bounds for proportion p over n trials (p in [0, 1], n > 0).
inline Bounds wilson_bounds(double p, double n) {
    const double z2 = kDexStatsZ * kDexStatsZ;
    const double denom = 1.0 + z2 / n;
    const double centre = (p + z2 / (2.0 * n)) / denom;
    const double half = kDexStatsZ / denom * std::sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n));
    return {(std::max)(0.0, centre - half), (std::min)(1.0, centre + half)};
}

} // namespace dex_stats_detail

/// A point estimate with its 95 percent interval, shared by every statistic
/// here; see each function for what `estimate` and `reliable` mean.
struct DexInterval {
    double estimate;
    double lower;
    double upper;
    bool reliable;
};

/// events / trials with a Wilson interval; `estimate` is the proportion and
/// `reliable` is events >= kDexStatsReliableMinEvents, judged on the numerator
/// the caller counts (crashes, say), never its complement. nullopt iff
/// trials <= 0, events < 0 or events > trials. events == 0 gives lower exactly
/// 0 and events == trials gives upper exactly 1.
[[nodiscard]] inline std::optional<DexInterval> dex_proportion(std::int64_t events,
                                                                 std::int64_t trials) {
    if (trials <= 0 || events < 0 || events > trials)
        return std::nullopt;
    const double n = static_cast<double>(trials);
    const double p = static_cast<double>(events) / n;
    auto b = dex_stats_detail::wilson_bounds(p, n);
    if (events == 0)
        b.lower = 0.0;
    if (events == trials)
        b.upper = 1.0;
    // Rounding at huge n can leave the interval a ulp or so off its own estimate.
    b.lower = (std::min)(b.lower, p);
    b.upper = (std::max)(b.upper, p);
    if (!std::isfinite(p) || !std::isfinite(b.lower) || !std::isfinite(b.upper))
        return std::nullopt;
    return DexInterval{p, b.lower, b.upper, events >= kDexStatsReliableMinEvents};
}

/// One-sided 95 percent upper bound on the event probability when zero events
/// were seen in `trials` (Hanley and Lippman-Hand 1983): min(1, 3 / trials).
/// The exact binomial bound is 1 - 0.05^(1/n) (n = 20: 0.1391); -ln(0.05) / n is
/// its Poisson-limit form (0.1498); 3 / n rounds that up (0.15) and is >= the
/// exact bound for every n >= 1, within 8 percent at n = 20 and 0.52 percent at
/// n = 400. The clamp covers n < 3. It complements dex_proportion(0, n), the
/// two-sided interval; this is the plain-language bound for a zero count.
/// nullopt iff trials <= 0.
[[nodiscard]] inline std::optional<double> dex_rule_of_three(std::int64_t trials) {
    if (trials <= 0)
        return std::nullopt;
    return (std::min)(1.0, 3.0 / static_cast<double>(trials));
}

/// events over `exposure` (the caller's unit, device-days for the views) with
/// the exact Poisson interval; `estimate` is events per unit of that exposure
/// and `reliable` is events >= kDexStatsReliableMinEvents. nullopt iff events < 0
/// or exposure is non-finite or <= 0, or the rate overflows a double (never
/// infinity).
[[nodiscard]] inline std::optional<DexInterval> dex_rate(std::int64_t events, double exposure) {
    if (events < 0 || !std::isfinite(exposure) || exposure <= 0.0)
        return std::nullopt;
    const double k = static_cast<double>(events);
    const auto lam = events <= kDexStatsExactMaxEvents
                         ? dex_stats_detail::poisson_bounds_exact(k)
                         : dex_stats_detail::poisson_bounds_large(k);
    const double rate = k / exposure;
    const double lower = lam.lower / exposure;
    const double upper = lam.upper / exposure;
    if (!std::isfinite(rate) || !std::isfinite(lower) || !std::isfinite(upper))
        return std::nullopt;
    return DexInterval{rate, lower, upper, events >= kDexStatsReliableMinEvents};
}

/// (events_a / exposure_a) / (events_b / exposure_b); `estimate` is that ratio
/// and `reliable` needs BOTH arms >= kDexStatsReliableMinEvents events. Given the
/// total, events_a is binomial, so the interval is the exact conditional
/// (Clopper-Pearson) interval mapped onto the ratio; accuracy and the per-arm
/// limit are in the file banner.
/// nullopt iff a count is negative or above kDexRateRatioMaxEvents (a policy
/// refusal at the edge of the accuracy domain, not an invalid count; dex_rate has
/// no such ceiling), an exposure is non-finite or below kDexRateRatioMinExposure,
/// both counts are zero (no conditional distribution), or a result is not
/// representable. events_b == 0
/// with events_a > 0 gives ratio and upper of +infinity (the data are valid; the
/// lower bound is finite). A reliable == false ratio is printed as indicative,
/// never hidden. The exposure guard is on exposure, not devices, and there is no
/// floored ratio helper: a surface applies the device floor to each arm before
/// calling.
[[nodiscard]] inline std::optional<DexInterval>
dex_rate_ratio(std::int64_t events_a, double exposure_a, std::int64_t events_b, double exposure_b) {
    constexpr double kInf = std::numeric_limits<double>::infinity();
    if (events_a < 0 || events_b < 0 || events_a > kDexRateRatioMaxEvents ||
        events_b > kDexRateRatioMaxEvents)
        return std::nullopt;
    if (!std::isfinite(exposure_a) || !std::isfinite(exposure_b) ||
        exposure_a < kDexRateRatioMinExposure || exposure_b < kDexRateRatioMinExposure)
        return std::nullopt;
    if (events_a == 0 && events_b == 0)
        return std::nullopt;
    constexpr double kAlpha = dex_stats_detail::kAlpha;
    const double a = static_cast<double>(events_a);
    const double b = static_cast<double>(events_b);
    const double p_lo =
        events_a == 0 ? 0.0 : dex_stats_detail::beta_quantile(a, b + 1.0, kAlpha / 2.0);
    const double p_hi =
        events_b == 0 ? 1.0 : dex_stats_detail::beta_quantile(a + 1.0, b, 1.0 - kAlpha / 2.0);
    const double scale = exposure_b / exposure_a;
    const double ratio = events_b == 0 ? kInf : (a / exposure_a) / (b / exposure_b);
    const double lower = p_lo / (1.0 - p_lo) * scale;
    const double upper = p_hi >= 1.0 ? kInf : p_hi / (1.0 - p_hi) * scale;
    const bool ok =
        std::isfinite(lower) && (events_b == 0 || (std::isfinite(ratio) && std::isfinite(upper)));
    if (!ok)
        return std::nullopt;
    return DexInterval{ratio, lower, upper,
                       events_a >= kDexStatsReliableMinEvents &&
                           events_b >= kDexStatsReliableMinEvents};
}

/// A statistic that is withheld below the cohort floor; the counts are always
/// carried.
struct DexFloored {
    std::int64_t events;
    std::int64_t devices;
    std::optional<DexInterval> stats;
};

/// The floor is on the DEVICE population (the same floor every DEX surface
/// uses), not on exposure: below kDexCohortFloor devices a count is honest and
/// a proportion singles people out, so only the count is returned.
[[nodiscard]] inline DexFloored dex_floored_proportion(std::int64_t events,
                                                       std::int64_t devices) {
    return {events, devices,
            devices < kDexCohortFloor ? std::nullopt : dex_proportion(events, devices)};
}

/// As dex_floored_proportion: the floor is on devices, not exposure.
[[nodiscard]] inline DexFloored dex_floored_rate(std::int64_t events, double exposure,
                                                 std::int64_t devices) {
    return {events, devices,
            devices < kDexCohortFloor ? std::nullopt : dex_rate(events, exposure)};
}

} // namespace yuzu::server
