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
 * A display name is for people; a consumer keys on stability_band_label.
 *
 * Overrides are keyed by the exact lowercased image name, apply to every
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
 *   3. global weights: finite and non-negative (WeightInvalid), sum at most
 *      100 so the decomposition identity holds (WeightSumAboveMaximum).
 *   4. at most 200 overrides (TooManyOverrides).
 *   5. per override i: key non-empty and byte-identical to its ASCII lowercase
 *      (OverrideKeyInvalid); key not equal to an earlier key
 *      (OverrideKeyDuplicate); then the EFFECTIVE tiers and weights (the
 *      override merged onto the global policy) pass the same edge, name and
 *      weight checks, reported at index i. A partial edge that conflicts with
 *      an inherited one is therefore refused.
 * Names are ASCII-only in this cut; widening to UTF-8 later relaxes the
 * validator and never invalidates a stored document.
 *
 * Resolver precondition: the policy passed dex_score_policy_fault. The
 * resolver never re-validates.
 *
 * CONSUMER DUTIES
 *  - A writer validates before any write, stores only a document that
 *    validated whole, refuses with dex_policy_fault_label and the override
 *    index, and hands the resolver only validated documents. Mapping a stored
 *    document to DexScorePolicy and back is the writer's job; this header has
 *    no parse or serialise.
 *  - A reader scores with
 *    compute_stability_score(in, kDexCohortFloor, eff.weights, eff.edges) and
 *    never re-bands; shows dex_tier_name beside the unchanged wire token
 *    stability_band_label; serialises dex_policy_profile_label(eff.profile);
 *    and passes eff.weights to stability_rank_flip. The consumer duties in
 *    dex_stability_score.hpp apply unchanged.
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
#include <utility>
#include <vector>

namespace yuzu::server {

inline constexpr std::size_t kDexPolicyMaxOverrides = 200;
inline constexpr std::int64_t kDexPolicyMinTierGapTenths = 10;
inline constexpr std::size_t kDexPolicyMaxNameBytes = 24;
inline constexpr double kDexPolicyWeightSumMax = 100.0;
/// override_index of a fault in the global policy.
inline constexpr std::size_t kDexPolicyGlobalIndex = (std::numeric_limits<std::size_t>::max)();

/// Edges and display names of the four tiers; names are indexed by
/// static_cast<std::size_t>(StabilityBand).
struct DexTierPolicy {
    StabilityBandEdges edges;
    std::array<std::string, 4> names{"excellent", "good", "fair", "poor"};
};

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

namespace detail {

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

[[nodiscard]] inline bool name_valid(const std::string& n) {
    if (n.empty() || n.size() > kDexPolicyMaxNameBytes)
        return false;
    for (const char ch : n) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c > 0x7E || c == '<' || c == '>' || c == '&' || c == '"')
            return false;
    }
    return true;
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
    if (!stability_weights_valid(w))
        return DexPolicyFault::WeightInvalid;
    if (w.breadth + w.crashes + w.hangs + w.regression > kDexPolicyWeightSumMax)
        return DexPolicyFault::WeightSumAboveMaximum;
    return std::nullopt;
}

} // namespace detail

/// nullopt means the policy is valid; nothing else is a success sentinel.
[[nodiscard]] inline std::optional<DexPolicyRejection>
dex_score_policy_fault(const DexScorePolicy& p) {
    if (const auto f = detail::tier_fault(p.tiers))
        return DexPolicyRejection{*f, kDexPolicyGlobalIndex};
    if (const auto f = detail::weight_fault(p.weights))
        return DexPolicyRejection{*f, kDexPolicyGlobalIndex};
    if (p.overrides.size() > kDexPolicyMaxOverrides)
        return DexPolicyRejection{DexPolicyFault::TooManyOverrides, kDexPolicyGlobalIndex};
    for (std::size_t i = 0; i < p.overrides.size(); ++i) {
        const auto& o = p.overrides[i];
        if (o.image.empty() || detail::ascii_lower(o.image) != o.image)
            return DexPolicyRejection{DexPolicyFault::OverrideKeyInvalid, i};
        for (std::size_t j = 0; j < i; ++j)
            if (p.overrides[j].image == o.image)
                return DexPolicyRejection{DexPolicyFault::OverrideKeyDuplicate, i};
        const auto m = detail::apply_override(p, o);
        if (const auto f = detail::tier_fault(m.tiers))
            return DexPolicyRejection{*f, i};
        if (const auto f = detail::weight_fault(m.weights))
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
    const std::string key = detail::ascii_lower(image);
    // Known ceiling: linear scan over <=200 overrides, per-application lookups
    // on a page of a few hundred apps; upgrade to a map if a profile ever shows it.
    for (const auto& o : p.overrides) {
        if (o.image == key) {
            auto m = detail::apply_override(p, o);
            return {std::move(m.tiers), m.weights, DexPolicyProfile::Override};
        }
    }
    return {p.tiers, p.weights, DexPolicyProfile::Default};
}

[[nodiscard]] inline const std::string& dex_tier_name(const DexTierPolicy& t, StabilityBand b) {
    return t.names[static_cast<std::size_t>(b)];
}

} // namespace yuzu::server
