/**
 * dex_stats.hpp -- the one home for the statistics the DEX application views
 * print, so every number is derived once and tested once.
 *
 * What is here (all two-sided at kDexStatsConfidence = 95 percent):
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
 *     inputs" -- the input is invalid, or the result is not representable as a
 *     finite double. It is never zero. (The single documented infinity is a
 *     rate ratio whose denominator arm saw no events.)
 *   - A reliability flag is a label, never suppression: a rate on few events is
 *     still printed, marked indicative.
 *   - Below the cohort floor a count is honest and a rate singles people out,
 *     so the floored helpers always carry the counts and withhold only the
 *     statistics.
 *
 * Numerical contract:
 *   - Counts up to kDexStatsExactMaxEvents use the exact kernels (regularised
 *     incomplete gamma / beta inverted by bisection). Above it the Poisson
 *     bounds use the Wilson-Hilferty chi-square quantile and the conditional
 *     binomial bounds use the Wilson interval; both agree with the exact bounds
 *     to better than 1e-5 relative at the switch.
 *   - A kernel that cannot converge inside kDexStatsMaxIterations returns NaN,
 *     quantiles propagate it, and every public function ends with a finiteness
 *     check: a statistic is never returned after a convergence failure or an
 *     overflow.
 *
 * Thread-safe and store-free: pure functions, no statics, and no C library
 * log-gamma (it writes the global signgam on glibc and Darwin). Header-only.
 */
#pragma once

#include "dex_perf_model.hpp" // kDexCohortFloor

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>

namespace yuzu::server {

/// Two-sided confidence level of every interval in this header.
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

/// Largest event count served by the exact kernels. They need about
/// 7.4 * sqrt(k) iterations (7413 at one million); above this the closed forms
/// are used instead.
inline constexpr std::int64_t kDexStatsExactMaxEvents = 1'000'000;

/// Iteration cap of the series / continued fractions: 2.7x the measured worst
/// case inside the exact domain. Hitting it is a convergence failure (NaN),
/// never a result.
inline constexpr int kDexStatsMaxIterations = 20000;

namespace detail {

inline constexpr double kTiny = 1e-300;
inline constexpr double kEps = 1e-15;
inline constexpr int kBisections = 200;

/// log(Gamma(n)) for n >= 1 (Stirling series after shifting to n >= 15,
/// ~1e-15 relative). Replaces the C library log-gamma, which is not thread-safe; every
/// argument in this header is an integer >= 1.
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
    return (n - 0.5) * std::log(n) - n + 0.5 * std::log(2.0 * 3.14159265358979323846) + series -
           shift;
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
                return std::min(1.0, sum * prefactor);
        }
        return std::numeric_limits<double>::quiet_NaN();
    }
    // Continued fraction for Q(a, x), modified Lentz.
    double b = x + 1.0 - a;
    double c = 1.0 / kTiny;
    double d = 1.0 / b;
    double h = d;
    for (int i = 1; i <= max_iter; ++i) {
        const double an = -static_cast<double>(i) * (static_cast<double>(i) - a);
        b += 2.0;
        d = an * d + b;
        if (std::fabs(d) < kTiny)
            d = kTiny;
        c = b + an / c;
        if (std::fabs(c) < kTiny)
            c = kTiny;
        d = 1.0 / d;
        const double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < kEps)
            return std::max(0.0, 1.0 - prefactor * h);
    }
    return std::numeric_limits<double>::quiet_NaN();
}

/// Continued fraction of the incomplete beta (modified Lentz); NaN on cap.
inline double beta_fraction(double x, double a, double b, int max_iter) {
    const double qab = a + b;
    const double qap = a + 1.0;
    const double qam = a - 1.0;
    double c = 1.0;
    double d = 1.0 - qab * x / qap;
    if (std::fabs(d) < kTiny)
        d = kTiny;
    d = 1.0 / d;
    double h = d;
    for (int m = 1; m <= max_iter; ++m) {
        const double dm = static_cast<double>(m);
        const double m2 = 2.0 * dm;
        double aa = dm * (b - dm) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if (std::fabs(d) < kTiny)
            d = kTiny;
        c = 1.0 + aa / c;
        if (std::fabs(c) < kTiny)
            c = kTiny;
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + dm) * (qab + dm) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if (std::fabs(d) < kTiny)
            d = kTiny;
        c = 1.0 + aa / c;
        if (std::fabs(c) < kTiny)
            c = kTiny;
        d = 1.0 / d;
        const double del = d * c;
        h *= del;
        if (std::fabs(del - 1.0) < kEps)
            return h;
    }
    return std::numeric_limits<double>::quiet_NaN();
}

/// Regularised incomplete beta I_x(a, b), a and b >= 1. NaN on non-convergence.
inline double regularized_beta(double x, double a, double b, int max_iter = kDexStatsMaxIterations) {
    if (x <= 0.0)
        return 0.0;
    if (x >= 1.0)
        return 1.0;
    const double bt = std::exp(log_gamma(a + b) - log_gamma(a) - log_gamma(b) + a * std::log(x) +
                               b * std::log1p(-x));
    if (x > (a + 1.0) / (a + b + 2.0)) {
        const double f = beta_fraction(1.0 - x, b, a, max_iter);
        // std::max / std::min would swallow a NaN, so test it first.
        return std::isnan(f) ? f : std::max(0.0, 1.0 - bt * f / b);
    }
    const double f = beta_fraction(x, a, b, max_iter);
    return std::isnan(f) ? f : std::min(1.0, bt * f / a);
}

/// x with P(a, x) = p, by bisection (monotone, fixed iteration count: bounded
/// and deterministic cost). NaN if any evaluation fails to converge.
inline double gamma_quantile(double a, double p, int max_iter = kDexStatsMaxIterations) {
    constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
    if (p <= 0.0)
        return 0.0;
    double lo = 0.0;
    double hi = std::max(a, 1.0);
    for (int i = 0;; ++i) {
        const double v = regularized_gamma_p(a, hi, max_iter);
        if (std::isnan(v) || i > 64)
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
            return std::numeric_limits<double>::quiet_NaN();
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
    constexpr double alpha = 1.0 - kDexStatsConfidence;
    return {k == 0.0 ? 0.0 : gamma_quantile(k, alpha / 2.0),
            gamma_quantile(k + 1.0, 1.0 - alpha / 2.0)};
}

/// Wilson-Hilferty approximation of the same bounds: chi2_p(nu) ~
/// nu * (1 - 2 / (9 nu) + z_p * sqrt(2 / (9 nu)))^3. Used only above
/// kDexStatsExactMaxEvents, where it is within 1.6e-11 relative of the exact
/// bounds.
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
    const double half =
        kDexStatsZ / denom * std::sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n));
    return {std::max(0.0, centre - half), std::min(1.0, centre + half)};
}

} // namespace detail

/// A proportion with its 95 percent Wilson interval.
struct DexProportion {
    double estimate;
    double lower;
    double upper;
    bool reliable; ///< numerator events >= kDexStatsReliableMinEvents
};

/// events / trials with a Wilson interval. nullopt iff trials <= 0, events < 0
/// or events > trials. events == 0 gives lower exactly 0 and events == trials
/// gives upper exactly 1. `reliable` is about the numerator the caller counts
/// (for example crashes), not its complement.
[[nodiscard]] inline std::optional<DexProportion> dex_proportion(std::int64_t events,
                                                                 std::int64_t trials) {
    if (trials <= 0 || events < 0 || events > trials)
        return std::nullopt;
    const double n = static_cast<double>(trials);
    const double p = static_cast<double>(events) / n;
    auto b = detail::wilson_bounds(p, n);
    if (events == 0)
        b.lower = 0.0;
    if (events == trials)
        b.upper = 1.0;
    if (!std::isfinite(p) || !std::isfinite(b.lower) || !std::isfinite(b.upper))
        return std::nullopt;
    return DexProportion{p, b.lower, b.upper, events >= kDexStatsReliableMinEvents};
}

/// One-sided 95 percent upper bound on the event probability when zero events
/// were seen in `trials` (Hanley and Lippman-Hand 1983): min(1, 3 / trials).
/// The exact binomial bound is 1 - 0.05^(1/n) (n = 20: 0.1391); -ln(0.05) / n is
/// its Poisson-limit form (0.1498); 3 / n rounds that up (0.15) and is >= the
/// exact bound for every n >= 1, within 8 percent at n = 20 and 0.5 percent at
/// n = 400. The clamp covers n < 3. It complements dex_proportion(0, n), the
/// two-sided interval; this is the plain-language bound for a zero count.
/// nullopt iff trials <= 0.
[[nodiscard]] inline std::optional<double> dex_rule_of_three(std::int64_t trials) {
    if (trials <= 0)
        return std::nullopt;
    return std::min(1.0, 3.0 / static_cast<double>(trials));
}

/// A rate (events per unit of exposure) with its exact Poisson interval.
struct DexRate {
    double rate;
    double lower;
    double upper;
    bool reliable; ///< events >= kDexStatsReliableMinEvents
};

/// events over `exposure` (the caller's unit, device-days for the views); the
/// result is per unit of that exposure. nullopt iff events < 0 or exposure is
/// non-finite or <= 0, or the rate overflows a double (never infinity).
[[nodiscard]] inline std::optional<DexRate> dex_rate(std::int64_t events, double exposure) {
    if (events < 0 || !std::isfinite(exposure) || exposure <= 0.0)
        return std::nullopt;
    const double k = static_cast<double>(events);
    const auto lam = events <= kDexStatsExactMaxEvents ? detail::poisson_bounds_exact(k)
                                                       : detail::poisson_bounds_large(k);
    const double rate = k / exposure;
    const double lower = lam.lower / exposure;
    const double upper = lam.upper / exposure;
    if (!std::isfinite(rate) || !std::isfinite(lower) || !std::isfinite(upper))
        return std::nullopt;
    return DexRate{rate, lower, upper, events >= kDexStatsReliableMinEvents};
}

/// Rate A over rate B with an interval on the ratio.
struct DexRateRatio {
    double ratio;
    double lower;
    double upper;
    bool reliable; ///< both arms >= kDexStatsReliableMinEvents events
};

/// (events_a / exposure_a) / (events_b / exposure_b). Given the total, events_a
/// is binomial, so the interval is the exact conditional (Clopper-Pearson)
/// interval mapped onto the ratio; above kDexStatsExactMaxEvents in either arm
/// the Wilson interval stands in (within 2e-6 relative at 1e6 balanced events).
/// nullopt iff a count is negative, an exposure is non-finite or below
/// kDexRateRatioMinExposure, both counts are zero (no conditional distribution),
/// or a result is not representable. events_b == 0 with events_a > 0 gives
/// ratio and upper of +infinity (the data are valid; the lower bound is finite).
/// A reliable == false ratio is printed as indicative, never hidden.
[[nodiscard]] inline std::optional<DexRateRatio>
dex_rate_ratio(std::int64_t events_a, double exposure_a, std::int64_t events_b, double exposure_b) {
    constexpr double kInf = std::numeric_limits<double>::infinity();
    if (events_a < 0 || events_b < 0)
        return std::nullopt;
    if (!std::isfinite(exposure_a) || !std::isfinite(exposure_b) ||
        exposure_a < kDexRateRatioMinExposure || exposure_b < kDexRateRatioMinExposure)
        return std::nullopt;
    if (events_a == 0 && events_b == 0)
        return std::nullopt;
    constexpr double alpha = 1.0 - kDexStatsConfidence;
    const double a = static_cast<double>(events_a);
    const double b = static_cast<double>(events_b);
    const double n = a + b;
    double p_lo = 0.0;
    double p_hi = 1.0;
    if (events_a <= kDexStatsExactMaxEvents && events_b <= kDexStatsExactMaxEvents) {
        if (events_a != 0)
            p_lo = detail::beta_quantile(a, n - a + 1.0, alpha / 2.0);
        if (events_b != 0)
            p_hi = detail::beta_quantile(a + 1.0, n - a, 1.0 - alpha / 2.0);
    } else {
        const auto w = detail::wilson_bounds(a / n, n);
        if (events_a != 0)
            p_lo = w.lower;
        if (events_b != 0)
            p_hi = w.upper;
    }
    const double scale = exposure_b / exposure_a;
    const double ratio = events_b == 0 ? kInf : (a / exposure_a) / (b / exposure_b);
    const double lower = p_lo / (1.0 - p_lo) * scale;
    const double upper = p_hi >= 1.0 ? kInf : p_hi / (1.0 - p_hi) * scale;
    const bool ok = std::isfinite(lower) && (events_b == 0 || (std::isfinite(ratio) && std::isfinite(upper)));
    if (!ok || std::isnan(ratio) || std::isnan(upper))
        return std::nullopt;
    return DexRateRatio{ratio, lower, upper,
                        events_a >= kDexStatsReliableMinEvents &&
                            events_b >= kDexStatsReliableMinEvents};
}

/// A proportion that is withheld below the cohort floor; the counts are always
/// carried.
struct DexFlooredProportion {
    std::int64_t events;
    std::int64_t devices;
    std::optional<DexProportion> stats;
};

/// The floor is on the DEVICE population (the same floor every DEX surface
/// uses), not on exposure: below kDexCohortFloor devices a count is honest and
/// a proportion singles people out, so only the count is returned.
[[nodiscard]] inline DexFlooredProportion dex_floored_proportion(std::int64_t events,
                                                                 std::int64_t devices) {
    return {events, devices,
            devices < kDexCohortFloor ? std::nullopt : dex_proportion(events, devices)};
}

/// A rate that is withheld below the cohort floor; the counts are always
/// carried.
struct DexFlooredRate {
    std::int64_t events;
    std::int64_t devices;
    std::optional<DexRate> stats;
};

/// As dex_floored_proportion: the floor is on devices, not exposure.
[[nodiscard]] inline DexFlooredRate dex_floored_rate(std::int64_t events, double exposure,
                                                     std::int64_t devices) {
    return {events, devices,
            devices < kDexCohortFloor ? std::nullopt : dex_rate(events, exposure)};
}

} // namespace yuzu::server
