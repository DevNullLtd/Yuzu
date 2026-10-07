#pragma once

/**
 * @file dex_stability_score.hpp
 * Pure stability score for an application, or for one version of it.
 *
 * Header-only, includes nothing from the tree, no I/O, no clock. Nothing acts
 * on the score: it is a transparent number for people to read, and every
 * score carries the deductions that produced it.
 *
 * Score = clamp(100 - sum of deductions, 0, 100). Four deductions, always
 * returned in this order, each with its RAW points (before the clamp):
 *
 *   breadth     60 * A / N                       share of devices affected
 *   crashes     20 * crash_events / (N * cap)    crash intensity, fleet-normalised
 *   hangs        8 * hang_events  / (N * cap)    hangs weigh less than crashes
 *   regression  12 * clamp((lower - 1) / (3 - 1), 0, 1)
 *
 * - Breadth comes first: how many devices are hit matters more than how often
 *   one device is hit. Intensity is capped per device (cap = 5 events, the
 *   same "full severity at 5" the device score uses in dex_read_model.cpp),
 *   so one crash-looping device cannot outweigh a widespread problem.
 * - The per-device cap is the CALLER's job: crash_events and hang_events must
 *   be sums of min(events_d, kPerDeviceEventCap) over devices. A sum above
 *   A * cap proves the cap was skipped, and is withheld as "inconsistent"
 *   rather than clamped (an aggregate clamp is not per-device capping).
 * - Regression is assessed only when a rate-ratio interval against the
 *   previous version is supplied. It uses the interval's LOWER bound, so only
 *   a regression the data supports counts. An interval containing 1 or lying
 *   below 1 scores 0 points: an improving version earns no credit. Regression
 *   takes its full weight at a 3x lower-bound rate ratio (kRegressionFullRatio);
 *   2x takes half.
 * - Bands: excellent >= 90, good >= 75, fair >= 60, else poor. These are the
 *   same edges and labels as the device health band, so one vocabulary serves
 *   both pages.
 * - `floor` is the reporting-device minimum (callers pass kDexCohortFloor):
 *   fewer devices withholds the score as below_floor rather than showing a
 *   noisy number.
 * - Missing or contradictory data is withheld (score and band empty, `withheld`
 *   names why), never shown as 0 or 100.
 * - With the default weights (sum 100) every term lies in [0, 1] of its
 *   weight, so 100 - sum(points) == score. Custom weights whose raw sum
 *   exceeds 100 clamp the score to 0; the rows still report raw points.
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

struct StabilityWeights {
    double breadth;
    double crashes;
    double hangs;
    double regression;
};

inline constexpr StabilityWeights kStabilityWeights{60.0, 20.0, 8.0, 12.0};
static_assert(kStabilityWeights.breadth + kStabilityWeights.crashes + kStabilityWeights.hangs +
                      kStabilityWeights.regression ==
                  100.0,
              "default weights must sum to 100");

// Mirrors dex_read_model.cpp's function-local kCap (the same "full severity at
// 5"); the two are kept in step by hand.
inline constexpr std::int64_t kPerDeviceEventCap = 5;
inline constexpr double kRegressionFullRatio = 3.0;
inline constexpr double kBandExcellent = 90.0;
inline constexpr double kBandGood = 75.0;
inline constexpr double kBandFair = 60.0;

/// Weights must be finite and non-negative; no sum constraint.
[[nodiscard]] inline bool stability_weights_valid(const StabilityWeights& w) {
    return std::isfinite(w.breadth) && std::isfinite(w.crashes) && std::isfinite(w.hangs) &&
           std::isfinite(w.regression) && w.breadth >= 0.0 && w.crashes >= 0.0 && w.hangs >= 0.0 &&
           w.regression >= 0.0;
}

enum class StabilityBand { Excellent, Good, Fair, Poor };

[[nodiscard]] inline StabilityBand stability_band(double score) {
    if (score >= kBandExcellent)
        return StabilityBand::Excellent;
    if (score >= kBandGood)
        return StabilityBand::Good;
    if (score >= kBandFair)
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
struct RateRatioInterval {
    double lower{0.0};
    double upper{0.0};
};

struct StabilityInputs {
    std::int64_t reporting_devices{0}; ///< N
    std::int64_t devices_affected{0};  ///< A: distinct devices with >= 1 crash or hang
    /// Per-device-capped sums: sum over devices of min(events_d, kPerDeviceEventCap).
    /// The caller owns the capping; a sum above A * cap is withheld as inconsistent.
    std::int64_t crash_events{0};
    std::int64_t hang_events{0};
    /// Absent when exposure is unknown or there is no previous version.
    std::optional<RateRatioInterval> rate_ratio;
};

/// Raw points deducted (before the score clamp). `assessed` is false when the
/// deduction had no usable input; its points are then 0.
struct StabilityDeduction {
    const char* name{""};
    double points{0.0};
    bool assessed{true};
};

struct StabilityScore {
    std::optional<double> score;
    std::optional<StabilityBand> band;
    const char* withheld{""}; ///< empty when scored
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
    const std::int64_t N = in.reporting_devices;
    const std::int64_t A = in.devices_affected;
    const std::int64_t crash = in.crash_events;
    const std::int64_t hang = in.hang_events;

    if (N <= 0)
        return stability_detail::withheld_result("no_population");
    if (!stability_weights_valid(w))
        return stability_detail::withheld_result("invalid_weights");
    // Overflow-safe: above INT64_MAX / cap every representable count is under
    // A * cap, so skipping the multiply is exact. After the non-negative checks
    // A - crash cannot overflow.
    const bool cap_checkable = A <= (std::numeric_limits<std::int64_t>::max)() / kPerDeviceEventCap;
    if (A < 0 || crash < 0 || hang < 0 || A > N ||
        (cap_checkable && (crash > A * kPerDeviceEventCap || hang > A * kPerDeviceEventCap)) ||
        A - crash > hang || (A == 0 && (crash > 0 || hang > 0)))
        return stability_detail::withheld_result("inconsistent");
    if (N < floor)
        return stability_detail::withheld_result("below_floor");

    const double n = static_cast<double>(N);
    const double a = static_cast<double>(A);
    const double cap = static_cast<double>(kPerDeviceEventCap);

    StabilityScore r;
    r.deductions.push_back({"breadth", w.breadth * (a / n), true});
    r.deductions.push_back({"crashes", w.crashes * (static_cast<double>(crash) / (n * cap)), true});
    r.deductions.push_back({"hangs", w.hangs * (static_cast<double>(hang) / (n * cap)), true});

    StabilityDeduction reg{"regression", 0.0, false};
    if (in.rate_ratio) {
        const double lo = in.rate_ratio->lower;
        const double hi = in.rate_ratio->upper;
        if (std::isfinite(lo) && std::isfinite(hi) && lo >= 0.0 && lo <= hi) {
            reg.assessed = true;
            reg.points =
                w.regression * std::clamp((lo - 1.0) / (kRegressionFullRatio - 1.0), 0.0, 1.0);
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

struct RankFlip {
    std::size_t first;
    std::size_t second;
};

/// First pair of applications whose strict order under `base` is strictly
/// reversed under `perturbed`; nullopt when none is found. Apps withheld under
/// either weight set are ignored. An invalid weight set withholds every app, so
/// the result is nullopt: callers that must tell "stable" from "nothing
/// comparable" check stability_weights_valid() first.
// ponytail: O(n^2) pair scan over a page of applications; sort-and-adjacent if n ever exceeds a few thousand
[[nodiscard]] inline std::optional<RankFlip>
stability_rank_flip(const std::vector<StabilityInputs>& apps, std::int64_t floor,
                    const StabilityWeights& perturbed,
                    const StabilityWeights& base = kStabilityWeights) {
    std::vector<std::optional<double>> b, p;
    b.reserve(apps.size());
    p.reserve(apps.size());
    for (const auto& app : apps) {
        b.push_back(compute_stability_score(app, floor, base).score);
        p.push_back(compute_stability_score(app, floor, perturbed).score);
    }
    for (std::size_t i = 0; i < apps.size(); ++i) {
        if (!b[i] || !p[i])
            continue;
        for (std::size_t j = i + 1; j < apps.size(); ++j) {
            if (!b[j] || !p[j] || *b[i] == *b[j] || *p[i] == *p[j])
                continue;
            if ((*b[i] > *b[j]) != (*p[i] > *p[j]))
                return RankFlip{i, j};
        }
    }
    return std::nullopt;
}

} // namespace yuzu::server
