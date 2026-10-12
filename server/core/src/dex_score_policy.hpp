#pragma once

/**
 * @file dex_score_policy.hpp
 * Pure, validated score policy for the application stability score, and the
 * resolver that returns the effective policy for one application.
 *
 * Header-only, includes only the standard library and dex_stability_score.hpp,
 * no I/O, no clock, no JSON. A customer's risk appetite is data: the three
 * lower band edges, the four tier display names and the four deduction
 * weights, globally and per application.
 *
 * Customisable: band edges, tier display names, deduction weights, and
 * per-application overrides of any of them. NOT customisable: the cohort
 * floor, the statistics, and the wire tokens (band labels, deduction names,
 * withheld reasons), which stay the closed vocabulary of dex_stability_score.hpp.
 * A display name is for people; a consumer keys on stability_band_label. The
 * withheld reason invalid_edges is the scorer's own refusal of a stored policy
 * that reached it without passing this validator.
 *
 * Overrides are keyed by the exact ASCII-lowercased image name, apply to every
 * version of that application, replace only the fields they set and inherit
 * the rest. There are no globs, tags or groups.
 *
 * Validation (dex_score_policy_fault) refuses the whole policy with a typed
 * fault and the index of the offending override (kDexPolicyGlobalIndex for the
 * global policy). Checks run in this fixed order, the first failure wins:
 *   1. global edges, each in turn: finite and 0 < e < 100 (EdgeOutOfRange),
 *      then exact at one decimal (EdgeNotDisplayExact), so a 100.04 or 1e308
 *      never reaches the rounding helper; then strictly descending in integer
 *      tenths (EdgesNotDescending) with a gap of at least 1.0 point
 *      (EdgeGapBelowMinimum). Poor's edge is fixed at 0.
 *   2. global names: 1 to 24 bytes, printable ASCII 0x20-0x7E, none of < > & "
 *      (NameInvalid).
 *   3. global weights: finite, non-negative and not negative zero
 *      (WeightInvalid), sum at most 100 plus kDexPolicyWeightSumTolerance
 *      (1e-12, the binary representation error of decimal weights, so
 *      {99.37, 0.33, 0.26, 0.04} validates) so the decomposition identity
 *      holds (WeightSumAboveMaximum). All-zero weights are valid and score
 *      every application 100.
 *   4. at most 200 overrides (TooManyOverrides).
 *   5. per override i: key 1 to kDexPolicyMaxKeyBytes (260) bytes of printable
 *      ASCII 0x20-0x7E and byte-identical to its ASCII lowercase
 *      (OverrideKeyInvalid); key not equal to an earlier key
 *      (OverrideKeyDuplicate); then the EFFECTIVE tiers and weights (the
 *      override merged onto the global policy) pass the same edge, name and
 *      weight checks, reported at index i. A partial edge that conflicts with
 *      an inherited one is therefore refused, reported at that override's
 *      index, including when the conflict comes from a later change to a global
 *      edge; the writer then edits either the override or the global.
 * Names and keys are printable ASCII in this cut; widening to UTF-8 later
 * relaxes the validator and never invalidates a stored document. Lowercasing is
 * the ASCII-only fold (A-Z to a-z, no locale); a writer folds keys the same
 * way before validating.
 * Round-to-nearest floating-point mode is assumed: display exactness and the
 * weight-sum tolerance are specified under it only; another mode may accept or
 * refuse different doubles.
 *
 * Resolver precondition: the policy passed dex_score_policy_fault. The
 * resolver never re-validates. Profile "default" means no per-application
 * override applied: the global policy, which may itself be customised. It does
 * not mean the shipped default (dex_default_score_policy).
 *
 * CONSUMER RULES
 *  - A writer validates before any write, stores only a document that
 *    validated whole, refuses with dex_policy_fault_label and the override
 *    index (kDexPolicyGlobalIndex means the global policy and is not an index
 *    to print), audits each change under its own audit verb, and hands the
 *    resolver only validated documents. Mapping a stored document to
 *    DexScorePolicy and back is the writer's job; this header has no parse or
 *    serialise.
 *  - A reader validates on load. On any fault it serves
 *    dex_default_score_policy() observably: the fault token and index are
 *    logged, a counter is keyed by the fault token (never by override index),
 *    and the fallback is surfaced apart from the profile label, which would
 *    read "default".
 *  - A reader scores with dex_score_under_policy(in, kDexCohortFloor, eff),
 *    the one spelling that keeps weights and edges from one effective policy
 *    together, and never re-bands; shows dex_tier_name beside the unchanged
 *    wire token stability_band_label; and serialises
 *    dex_policy_profile_label(eff.profile). Names are display text: this
 *    validator is not an escaper, every sink escapes.
 *  - A ranking check calls
 *    stability_rank_flip(apps, floor, perturbed.weights, current.weights),
 *    where both are the global policy's weights (the current and the proposed
 *    ones): ranking compares every application under that ONE weight set, and
 *    per-application overrides never enter a ranking.
 *  - The display, count and vocabulary rules in dex_stability_score.hpp's
 *    banner apply unchanged.
 */

#include "dex_stability_score.hpp"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace yuzu::server {

inline constexpr std::size_t kDexPolicyMaxOverrides = 200;
inline constexpr std::int64_t kDexPolicyMinTierGapTenths = 10;
inline constexpr std::size_t kDexPolicyMaxNameBytes = 24;
/// Upper bound on an override key. A Windows image name never exceeds MAX_PATH.
inline constexpr std::size_t kDexPolicyMaxKeyBytes = 260;
inline constexpr double kDexPolicyWeightSumMax = 100.0;
/// Absolute slack on the weight-sum check. A decimal such as 99.37 is not a
/// double: each of the four weights (each at most 100) is off by at most half
/// an ulp of 100 (2^-47, 7.1e-15) and each of the three additions rounds by at
/// most the same, so a decimal set totalling exactly 100 reads at most
/// 100 + 7 * 2^-47 (5e-14, 3.5 ulp) under round-to-nearest; {99.37, 0.33,
/// 0.26, 0.04} reads 100.00000000000001. 1e-12 is about 70 ulp, twenty times
/// that bound, and below any difference a decimal with fewer than twelve places
/// can express, so a set over 100 by 0.01 or more is still refused. It is
/// absolute because the sum is pinned at 100, and a larger slack would stretch
/// the decomposition identity (100 - sum(points) == score) by as much; the
/// score clamps at 0, so this overshoot is absorbed there.
inline constexpr double kDexPolicyWeightSumTolerance = 1e-12;
/// override_index of a fault in the global policy.
inline constexpr std::size_t kDexPolicyGlobalIndex = (std::numeric_limits<std::size_t>::max)();

/// Edges and display names of the four tiers; names are indexed by
/// static_cast<std::size_t>(StabilityBand).
struct DexTierPolicy {
    StabilityBandEdges edges;
    // The wire tokens, spelled once (stability_band_label).
    std::array<std::string, 4> names{
        stability_band_label(StabilityBand::Excellent), stability_band_label(StabilityBand::Good),
        stability_band_label(StabilityBand::Fair), stability_band_label(StabilityBand::Poor)};
};

// dex_tier_name indexes names[] by the StabilityBand value, and DexScoreOverride
// and apply_override mirror the edge and weight fields one by one: a new band
// or a new weight must be added to those places too, so these fail the build
// until it is.
static_assert(static_cast<std::size_t>(StabilityBand::Excellent) == 0 &&
                  static_cast<std::size_t>(StabilityBand::Good) == 1 &&
                  static_cast<std::size_t>(StabilityBand::Fair) == 2 &&
                  static_cast<std::size_t>(StabilityBand::Poor) == 3 &&
                  static_cast<std::size_t>(StabilityBand::Poor) + 1 ==
                      std::tuple_size_v<decltype(DexTierPolicy::names)>,
              "names[] is indexed by StabilityBand; extend DexScoreOverride and apply_override");
static_assert(sizeof(StabilityWeights) == 4 * sizeof(double),
              "a new weight must be mirrored in DexScoreOverride and apply_override");
static_assert(sizeof(StabilityBandEdges) == 3 * sizeof(double),
              "a new edge must be mirrored in DexScoreOverride and apply_override");

/// Every field optional: an unset field inherits the global policy.
struct DexScoreOverride {
    std::string image; ///< exact lowercased image name
    std::optional<double> excellent, good, fair;
    std::array<std::optional<std::string>, 4> names;
    std::optional<double> breadth, crashes, hangs, regression;
};

struct DexScorePolicy {
    DexTierPolicy tiers;
    StabilityWeights weights{kStabilityWeights};
    std::vector<DexScoreOverride> overrides;
};

/// The shipped default: the stability score's own constants and wire tokens.
[[nodiscard]] inline const DexScorePolicy& dex_default_score_policy() {
    static const DexScorePolicy p;
    return p;
}

enum class DexPolicyFault {
    EdgeOutOfRange,
    EdgeNotDisplayExact,
    EdgesNotDescending,
    EdgeGapBelowMinimum,
    NameInvalid,
    WeightInvalid,
    WeightSumAboveMaximum,
    OverrideKeyInvalid,
    OverrideKeyDuplicate,
    TooManyOverrides,
};

/// Closed snake_case tokens.
[[nodiscard]] inline const char* dex_policy_fault_label(DexPolicyFault f) {
    switch (f) {
    case DexPolicyFault::EdgeOutOfRange:
        return "edge_out_of_range";
    case DexPolicyFault::EdgeNotDisplayExact:
        return "edge_not_display_exact";
    case DexPolicyFault::EdgesNotDescending:
        return "edges_not_descending";
    case DexPolicyFault::EdgeGapBelowMinimum:
        return "edge_gap_below_minimum";
    case DexPolicyFault::NameInvalid:
        return "name_invalid";
    case DexPolicyFault::WeightInvalid:
        return "weight_invalid";
    case DexPolicyFault::WeightSumAboveMaximum:
        return "weight_sum_above_maximum";
    case DexPolicyFault::OverrideKeyInvalid:
        return "override_key_invalid";
    case DexPolicyFault::OverrideKeyDuplicate:
        return "override_key_duplicate";
    case DexPolicyFault::TooManyOverrides:
        return "too_many_overrides";
    }
    return "weight_invalid";
}

struct DexPolicyRejection {
    DexPolicyFault fault;
    std::size_t override_index; ///< kDexPolicyGlobalIndex for the global policy
};

namespace dex_score_policy_detail {

/// ASCII-only, locale-independent; bytes >= 0x80 are preserved. Shared by the
/// validator and the resolver so the two cannot disagree on a key.
[[nodiscard]] inline std::string ascii_lower(std::string_view s) {
    std::string r(s);
    for (auto& c : r)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    return r;
}

struct Merged {
    DexTierPolicy tiers;
    StabilityWeights weights;
};

[[nodiscard]] inline Merged apply_override(const DexScorePolicy& p, const DexScoreOverride& o) {
    Merged m{p.tiers, p.weights};
    if (o.excellent)
        m.tiers.edges.excellent = *o.excellent;
    if (o.good)
        m.tiers.edges.good = *o.good;
    if (o.fair)
        m.tiers.edges.fair = *o.fair;
    for (std::size_t i = 0; i < m.tiers.names.size(); ++i)
        if (o.names[i])
            m.tiers.names[i] = *o.names[i];
    if (o.breadth)
        m.weights.breadth = *o.breadth;
    if (o.crashes)
        m.weights.crashes = *o.crashes;
    if (o.hangs)
        m.weights.hangs = *o.hangs;
    if (o.regression)
        m.weights.regression = *o.regression;
    return m;
}

[[nodiscard]] inline std::optional<DexPolicyFault> edge_fault(double e) {
    if (!std::isfinite(e) || !(e > 0.0) || !(e < 100.0))
        return DexPolicyFault::EdgeOutOfRange;
    if (stability_display_score(e) != e)
        return DexPolicyFault::EdgeNotDisplayExact;
    return std::nullopt;
}

/// Every byte in 0x20-0x7E (so no NUL, control byte, DEL or byte >= 0x80).
[[nodiscard]] inline bool printable_ascii(const std::string& s) {
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c > 0x7E)
            return false;
    }
    return true;
}

[[nodiscard]] inline bool name_valid(const std::string& n) {
    if (n.empty() || n.size() > kDexPolicyMaxNameBytes || !printable_ascii(n))
        return false;
    for (const char c : n)
        if (c == '<' || c == '>' || c == '&' || c == '"')
            return false;
    return true;
}

/// 1 to kDexPolicyMaxKeyBytes bytes of printable ASCII, already lowercased.
[[nodiscard]] inline bool key_valid(const std::string& k) {
    return !k.empty() && k.size() <= kDexPolicyMaxKeyBytes && printable_ascii(k) &&
           ascii_lower(k) == k;
}

[[nodiscard]] inline std::optional<DexPolicyFault> tier_fault(const DexTierPolicy& t) {
    const double edges[3] = {t.edges.excellent, t.edges.good, t.edges.fair};
    for (const double e : edges)
        if (const auto f = edge_fault(e))
            return f;
    std::int64_t tenths[3];
    for (int i = 0; i < 3; ++i)
        tenths[i] = std::llround(edges[i] * kStabilityScoreScale);
    for (int i = 0; i < 2; ++i) {
        const std::int64_t gap = tenths[i] - tenths[i + 1];
        if (gap <= 0)
            return DexPolicyFault::EdgesNotDescending;
        if (gap < kDexPolicyMinTierGapTenths)
            return DexPolicyFault::EdgeGapBelowMinimum;
    }
    for (const auto& n : t.names)
        if (!name_valid(n))
            return DexPolicyFault::NameInvalid;
    return std::nullopt;
}

[[nodiscard]] inline std::optional<DexPolicyFault> weight_fault(const StabilityWeights& w) {
    // The scorer's check lets -0.0 through (-0.0 >= 0.0); here it would emit a
    // "-0" deduction, so it is refused. A negative nonzero fails the first test.
    if (!stability_weights_valid(w) || std::signbit(w.breadth) || std::signbit(w.crashes) ||
        std::signbit(w.hangs) || std::signbit(w.regression))
        return DexPolicyFault::WeightInvalid;
    if (w.breadth + w.crashes + w.hangs + w.regression >
        kDexPolicyWeightSumMax + kDexPolicyWeightSumTolerance)
        return DexPolicyFault::WeightSumAboveMaximum;
    return std::nullopt;
}

} // namespace dex_score_policy_detail

/// nullopt means the policy is valid; nothing else is a success sentinel.
[[nodiscard]] inline std::optional<DexPolicyRejection>
dex_score_policy_fault(const DexScorePolicy& p) {
    if (const auto f = dex_score_policy_detail::tier_fault(p.tiers))
        return DexPolicyRejection{*f, kDexPolicyGlobalIndex};
    if (const auto f = dex_score_policy_detail::weight_fault(p.weights))
        return DexPolicyRejection{*f, kDexPolicyGlobalIndex};
    if (p.overrides.size() > kDexPolicyMaxOverrides)
        return DexPolicyRejection{DexPolicyFault::TooManyOverrides, kDexPolicyGlobalIndex};
    for (std::size_t i = 0; i < p.overrides.size(); ++i) {
        const auto& o = p.overrides[i];
        if (!dex_score_policy_detail::key_valid(o.image))
            return DexPolicyRejection{DexPolicyFault::OverrideKeyInvalid, i};
        for (std::size_t j = 0; j < i; ++j)
            if (p.overrides[j].image == o.image)
                return DexPolicyRejection{DexPolicyFault::OverrideKeyDuplicate, i};
        const auto m = dex_score_policy_detail::apply_override(p, o);
        if (const auto f = dex_score_policy_detail::tier_fault(m.tiers))
            return DexPolicyRejection{*f, i};
        if (const auto f = dex_score_policy_detail::weight_fault(m.weights))
            return DexPolicyRejection{*f, i};
    }
    return std::nullopt;
}

enum class DexPolicyProfile { Default, Override };

[[nodiscard]] inline const char* dex_policy_profile_label(DexPolicyProfile p) {
    return p == DexPolicyProfile::Override ? "override" : "default";
}

struct DexEffectivePolicy {
    DexTierPolicy tiers;
    StabilityWeights weights;
    DexPolicyProfile profile{DexPolicyProfile::Default};
};

/// Effective policy for `image` (matched after ASCII lowercasing). Requires a
/// policy that passed dex_score_policy_fault.
[[nodiscard]] inline DexEffectivePolicy resolve_dex_score_policy(const DexScorePolicy& p,
                                                                 std::string_view image) {
    // No valid key is longer (key_valid), so a longer query cannot match: skip the fold.
    if (image.size() > kDexPolicyMaxKeyBytes)
        return {p.tiers, p.weights, DexPolicyProfile::Default};
    const std::string key = dex_score_policy_detail::ascii_lower(image);
    // Known ceiling: linear scan over <=200 overrides, per-application lookups
    // on a page of a few hundred apps; upgrade to a map if a profile ever shows it.
    for (const auto& o : p.overrides) {
        if (o.image == key) {
            auto m = dex_score_policy_detail::apply_override(p, o);
            return {std::move(m.tiers), m.weights, DexPolicyProfile::Override};
        }
    }
    return {p.tiers, p.weights, DexPolicyProfile::Default};
}

/// The reference points into `t`: bind it only while `t` lives.
[[nodiscard]] inline const std::string& dex_tier_name(const DexTierPolicy& t, StabilityBand b) {
    return t.names[static_cast<std::size_t>(b)];
}
/// A temporary (resolve_dex_score_policy(p, img).tiers), const or not, would
/// leave the reference dangling after the full expression, as would a reference
/// bound to a temporary's .names[i].
const std::string& dex_tier_name(DexTierPolicy&&, StabilityBand) = delete;
const std::string& dex_tier_name(const DexTierPolicy&&, StabilityBand) = delete;

/// Scores under ONE effective policy: its weights and its edges together. The
/// one spelling a consumer uses; compute_stability_score's defaulted edges
/// would otherwise let a caller drop them or take them from another policy.
/// It does not re-validate: `eff` must come from a policy that passed
/// dex_score_policy_fault. The scorer's own refusals (invalid_edges,
/// invalid_weights) are structural only and do not stand in for that check.
[[nodiscard]] inline StabilityScore dex_score_under_policy(const StabilityInputs& in,
                                                           std::int64_t floor,
                                                           const DexEffectivePolicy& eff) {
    return compute_stability_score(in, floor, eff.weights, eff.tiers.edges);
}

} // namespace yuzu::server
