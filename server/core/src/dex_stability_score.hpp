#pragma once

/**
 * @file dex_stability_score.hpp
 * Pure stability score for an application, or for one version of it.
 *
 * Header-only, includes nothing from the tree, no I/O, no clock. Nothing acts
 * on the score: it is a transparent number for people to read, and every
 * score carries the deductions that produced it.
 *
 * Score = clamp(100 - sum of deductions, 0, 100). Four deductions, each with
 * its RAW points (before the clamp). A scored result carries them in this
 * order; a withheld result carries none:
 *
 *   breadth     60 * A / N                       share of devices affected
 *   crashes     20 * crash_events / (N * cap)    crash intensity, fleet-normalised
 *   hangs        8 * hang_events  / (N * cap)    hangs weigh less than crashes
 *   regression  12 * clamp((lower - 1) / (3 - 1), 0, 1)
 *
 * - Breadth comes first: how many devices are hit matters more than how often
 *   one device is hit. Intensity is capped per device at 5 events, so one
 *   crash-looping device cannot outweigh a widespread problem. The value
 *   mirrors the function-local kCap in dex_read_model.cpp; the scope differs:
 *   the device score caps per signal family (summed over its signals), this
 *   module caps crashes and hangs separately (up to 10 events per device).
 * - The per-device cap is the CALLER's job: crash_events and hang_events must
 *   be sums of min(events_d, kStabilityPerDeviceEventCap) over devices. A sum
 *   above A * cap proves the cap was skipped, and is withheld as
 *   "inconsistent" rather than clamped (an aggregate clamp is not per-device
 *   capping). The check is necessary, not sufficient: an uncapped feed that
 *   stays under A * cap scores silently.
 * - Regression is assessed only when a usable rate-ratio interval against the
 *   previous version is supplied. It uses the interval's LOWER bound, so only
 *   a regression the data supports counts. An interval containing 1 or lying
 *   below 1 scores 0 points: an improving version earns no credit. Regression
 *   takes its full weight at a 3x lower-bound rate ratio
 *   (kStabilityRegressionFullRatio); 2x takes half. An interval is usable when
 *   lower is finite and >= 0 and lower <= upper. Upper may be +infinity (the
 *   previous version had no events): only lower is read, upper serves the
 *   ordering check. An unusable interval leaves regression unassessed at 0
 *   points. The caller passes nullopt (never a default
 *   StabilityRateRatioInterval{0, 0}, which is a valid interval scoring 0)
 *   when the interval is unreliable or either arm is below the cohort floor;
 *   `floor` here covers N only.
 * - Bands: excellent >= 90, good >= 75, fair >= 60, else poor. This is the
 *   fleet health-score band (build_dex_health_model, dex_read_model.cpp); the
 *   per-device buckets there (great / fair / poor at 90 / 75) are a different
 *   scale.
 * - Display and banding. The returned `score` is UNROUNDED. The display
 *   precision is one decimal (kStabilityScoreScale) and the rounding rule is
 *   stability_display_score(): round half away from zero at one decimal on
 *   the computed double (an IEEE multiply by 10, then std::round; it can differ
 *   from printf of the raw double on near-ties). Consumers display
 *   stability_display_score(*score) formatted at one decimal, never printf of
 *   the raw double. The band is the band of that DISPLAYED value, so a page
 *   never shows "60.0 poor" or "75.0 fair", and the edges 90 / 75 / 60 apply to
 *   the displayed value. Rank-flip ties use the same displayed value. A score
 *   whose exact value is a half-step (x.x5) may display either neighbouring
 *   tenth, because the computed double lands on either side of the tie; band
 *   and display always agree with each other, and two such apps can display
 *   one tenth apart.
 * - `floor` is the reporting-device minimum: fewer devices withholds the score
 *   as below_floor rather than showing a noisy number. Callers pass
 *   kDexCohortFloor literally; the module enforces whatever floor it is
 *   handed. `reporting_devices` is the distinct devices that reported THIS
 *   application/version in the window, never fleet size.
 * - Missing or contradictory population data is withheld (score and band
 *   empty, `withheld` names why), never shown as 0 or 100. A missing or
 *   unusable rate_ratio is NOT withheld: the result is scored with an
 *   unassessed regression row at 0 points, which reads identical to a clean
 *   one, so consumers must carry `assessed`.
 * - "inconsistent" covers: a negative count; A > N; crash or hang above
 *   A * cap; crash + hang below A (every affected device has an event).
 * - Score, band and the four deductions are present together exactly when
 *   `withheld` is empty. No withheld result carries N, A or any count, for
 *   every reason. A page that shows a device count may do so for below_floor
 *   only (a count under the floor identifies nobody) and never for
 *   inconsistent, invalid_weights or no_population, which are fault states.
 * - The string vocabulary is closed and wire-stable: withheld reasons
 *   (no_population, invalid_weights, inconsistent, below_floor), deduction
 *   names (breadth, crashes, hangs, regression) and band labels (excellent,
 *   good, fair, poor). Renaming one is a contract break. `name` and
 *   `withheld` are always string literals (static storage), never owned,
 *   never freed.
 * - Identity: 100 - sum(points) equals score, to within a few ulp in floating
 *   point, while the weights sum to at most 100 (each term then lies in [0, 1]
 *   of its weight). Consumers re-derive the display via
 *   stability_display_score(*score), never by re-summing rows. Custom weights
 *   summing above 100 can push the TOTAL past 100, which clamps the score to 0;
 *   the rows keep raw points.
 *
 * The constants are uncalibrated against real fleet data; recalibration is a
 * constant edit.
 */

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace yuzu::server {

/// Defaults are the declared weights (sum 100); the numbers live here once.
struct StabilityWeights {
    double breadth{60.0};
    double crashes{20.0};
    double hangs{8.0};
    double regression{12.0};
};

inline constexpr StabilityWeights kStabilityWeights{};
static_assert(kStabilityWeights.breadth + kStabilityWeights.crashes + kStabilityWeights.hangs +
                      kStabilityWeights.regression ==
                  100.0,
              "default weights must sum to 100");

inline constexpr std::int64_t kStabilityPerDeviceEventCap = 5;
inline constexpr double kStabilityRegressionFullRatio = 3.0;
inline constexpr double kStabilityBandExcellent = 90.0;
inline constexpr double kStabilityBandGood = 75.0;
inline constexpr double kStabilityBandFair = 60.0;
/// Display resolution: scores are shown at one decimal (10 steps per point).
inline constexpr double kStabilityScoreScale = 10.0;

/// Weights must be finite and non-negative; no sum constraint.
[[nodiscard]] inline bool stability_weights_valid(const StabilityWeights& w) {
    return std::isfinite(w.breadth) && std::isfinite(w.crashes) && std::isfinite(w.hangs) &&
           std::isfinite(w.regression) && w.breadth >= 0.0 && w.crashes >= 0.0 && w.hangs >= 0.0 &&
           w.regression >= 0.0;
}

/// The score as displayed: rounded half away from zero at one decimal.
[[nodiscard]] inline double stability_display_score(double s) {
    return std::round(s * kStabilityScoreScale) / kStabilityScoreScale;
}

enum class StabilityBand { Excellent, Good, Fair, Poor };

/// Band of the DISPLAYED score (see stability_display_score).
[[nodiscard]] inline StabilityBand stability_band(double score) {
    const double shown = stability_display_score(score);
    if (shown >= kStabilityBandExcellent)
        return StabilityBand::Excellent;
    if (shown >= kStabilityBandGood)
        return StabilityBand::Good;
    if (shown >= kStabilityBandFair)
        return StabilityBand::Fair;
    return StabilityBand::Poor;
}

[[nodiscard]] inline const char* stability_band_label(StabilityBand b) {
    switch (b) {
    case StabilityBand::Excellent:
        return "excellent";
    case StabilityBand::Good:
        return "good";
    case StabilityBand::Fair:
        return "fair";
    case StabilityBand::Poor:
        return "poor";
    }
    return "poor";
}

/// Interval around (this version's failure rate / previous version's failure rate).
struct StabilityRateRatioInterval {
    double lower{0.0};
    double upper{0.0};
};

struct StabilityInputs {
    /// N: distinct devices that reported THIS application/version in the window.
    std::int64_t reporting_devices{0};
    std::int64_t devices_affected{0}; ///< A: distinct devices with >= 1 crash or hang
    /// Per-device-capped sums: sum over devices of min(events_d, kStabilityPerDeviceEventCap).
    /// The caller owns the capping; a sum above A * cap is withheld as inconsistent.
    std::int64_t crash_events{0};
    std::int64_t hang_events{0};
    /// Absent when exposure is unknown or there is no previous version.
    std::optional<StabilityRateRatioInterval> rate_ratio;
};

/// Raw points deducted (before the score clamp). `assessed` is false when the
/// deduction had no usable input; its points are then 0. `name` is a string literal.
struct StabilityDeduction {
    const char* name{""};
    double points{0.0};
    bool assessed{true};
};

struct StabilityScore {
    std::optional<double> score; ///< unrounded; display via stability_display_score
    std::optional<StabilityBand> band;
    const char* withheld{""}; ///< empty when scored; otherwise a string literal
    std::vector<StabilityDeduction> deductions;
};

namespace stability_detail {
[[nodiscard]] inline StabilityScore withheld_result(const char* why) {
    StabilityScore r;
    r.withheld = why;
    return r;
}
} // namespace stability_detail

/// Withheld reasons, checked in this order: no_population, invalid_weights,
/// inconsistent, below_floor.
[[nodiscard]] inline StabilityScore
compute_stability_score(const StabilityInputs& in, std::int64_t floor,
                        const StabilityWeights& w = kStabilityWeights) {
    const std::int64_t reporting = in.reporting_devices;
    const std::int64_t affected = in.devices_affected;
    const std::int64_t crash = in.crash_events;
    const std::int64_t hang = in.hang_events;

    if (reporting <= 0)
        return stability_detail::withheld_result("no_population");
    if (!stability_weights_valid(w))
        return stability_detail::withheld_result("invalid_weights");
    // Overflow-safe: above INT64_MAX / cap every representable count is under
    // A * cap, so skipping the multiply is exact. After the non-negative checks
    // A - crash cannot overflow.
    const bool cap_checkable =
        affected <= (std::numeric_limits<std::int64_t>::max)() / kStabilityPerDeviceEventCap;
    if (affected < 0 || crash < 0 || hang < 0 || affected > reporting ||
        (cap_checkable && (crash > affected * kStabilityPerDeviceEventCap ||
                           hang > affected * kStabilityPerDeviceEventCap)) ||
        affected - crash > hang)
        return stability_detail::withheld_result("inconsistent");
    if (reporting < floor)
        return stability_detail::withheld_result("below_floor");

    const double n = static_cast<double>(reporting);
    const double a = static_cast<double>(affected);
    const double cap = static_cast<double>(kStabilityPerDeviceEventCap);

    StabilityScore r;
    r.deductions.reserve(4);
    r.deductions.push_back({"breadth", w.breadth * (a / n), true});
    r.deductions.push_back({"crashes", w.crashes * (static_cast<double>(crash) / (n * cap)), true});
    r.deductions.push_back({"hangs", w.hangs * (static_cast<double>(hang) / (n * cap)), true});

    StabilityDeduction reg{"regression", 0.0, false};
    if (in.rate_ratio) {
        const double lo = in.rate_ratio->lower;
        const double hi = in.rate_ratio->upper;
        // NaN upper fails lo <= hi; -inf fails it because lo >= 0; +inf is valid.
        if (std::isfinite(lo) && lo >= 0.0 && lo <= hi) {
            reg.assessed = true;
            reg.points = w.regression *
                         std::clamp((lo - 1.0) / (kStabilityRegressionFullRatio - 1.0), 0.0, 1.0);
        }
    }
    r.deductions.push_back(reg);

    double total = 0.0;
    for (const auto& d : r.deductions)
        total += d.points;
    const double s = std::clamp(100.0 - total, 0.0, 100.0);
    r.score = s;
    r.band = stability_band(s);
    return r;
}

struct StabilityRankFlip {
    std::size_t first;
    std::size_t second;
};

/// First pair of applications whose strict order under `base` is strictly
/// reversed under `perturbed`; "first" is the lowest i, then the lowest j.
/// Order is compared on the DISPLAYED scores (stability_display_score), so a
/// tie is "equal at the display precision" and a flip is a reversal a reader
/// can see on a page. Apps withheld under either weight set are ignored.
///
/// nullopt means "no reversal found among comparable apps" and NEVER "ranking
/// stable": it is also the answer for an invalid base or perturbed set, fewer
/// than two comparable apps, and weight sets that saturate every app to 0 or
/// 100. Callers that must tell these apart check stability_weights_valid() and
/// the comparable count first.
///
/// Cost: an O(n^2) pair scan, measured at -O2 on arm64 with no flip: 0.9 ms
/// at n = 1,000, 48 ms at 10,000, 907 ms at 50,000. The caller bounds n before
/// the call (n <= 100 expected, 1,000 a hard ceiling; reject rather than
/// truncate). A sort-and-adjacent scan would not preserve the lowest-(i, j)
/// order.
[[nodiscard]] inline std::optional<StabilityRankFlip>
stability_rank_flip(const std::vector<StabilityInputs>& apps, std::int64_t floor,
                    const StabilityWeights& perturbed,
                    const StabilityWeights& base = kStabilityWeights) {
    const auto shown = [&](const StabilityInputs& app,
                           const StabilityWeights& w) -> std::optional<double> {
        const auto s = compute_stability_score(app, floor, w).score;
        if (!s)
            return std::nullopt;
        return stability_display_score(*s);
    };
    std::vector<std::optional<double>> b, p;
    b.reserve(apps.size());
    p.reserve(apps.size());
    for (const auto& app : apps) {
        b.push_back(shown(app, base));
        p.push_back(shown(app, perturbed));
    }
    for (std::size_t i = 0; i < apps.size(); ++i) {
        if (!b[i] || !p[i])
            continue;
        for (std::size_t j = i + 1; j < apps.size(); ++j) {
            if (!b[j] || !p[j] || *b[i] == *b[j] || *p[i] == *p[j])
                continue;
            if ((*b[i] > *b[j]) != (*p[i] > *p[j]))
                return StabilityRankFlip{i, j};
        }
    }
    return std::nullopt;
}

} // namespace yuzu::server
