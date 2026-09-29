#pragma once

/// @file product_normalize.hpp
/// Pure product-normalisation library for the SLE catalog matcher (ADR-0024
/// Decision 6): deterministic title/vendor normalisation, the canonical
/// `norm_key` that becomes the `products.norm_key` UNIQUE value, the strictly
/// ordered match tiers (`exact_norm` → `title_vendor` → `token_set` → `birth`
/// — no fuzzy/Levenshtein matching, every decision reproducible in unit
/// tests), and the server-side effective-licence-state derivation (ADR-0024
/// Decision 7 lapse rule over the closed §3.2 vocabularies).
///
/// This library has no store, database, or network dependencies — it is pure
/// string/arithmetic logic so the matcher and the compliance evaluator can be
/// exercised entirely in unit tests.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Days-to-expiry threshold below which a licence counts as "expiring soon"
/// on posture rollups and KPI tiles.
inline constexpr int kExpiryWarnDays = 30;

/// Escalation buckets (days to expiry/renewal) for the deduplicated
/// `software_license.expiring` machinery (ADR-0024 Decision 8): an alert
/// fires only on a worsening bucket transition or on persistence past the
/// re-arm window.
inline constexpr std::array<int, 4> kExpiryAlertBuckets{30, 14, 7, 1};

/// Re-arm window for a persisting alert condition: 7 days, in seconds.
inline constexpr std::int64_t kRearmSecs = 7 * 24 * 3600;

/// Result of `normalize_title`: the normalised title with version,
/// architecture, and edition tokens removed, plus the first edition token
/// extracted (empty when the raw title carries none). The matcher operates on
/// the stripped `title`; `edition` feeds the `products.edition` column and
/// the `norm_key` suffix.
struct NormalizedTitle {
    std::string title;
    std::string edition;
};

/// Normalise a raw product title deterministically:
///   - ASCII letters are lowercased; non-ASCII bytes pass through untouched
///     (no Unicode case folding — determinism over cleverness),
///   - whitespace runs collapse to single spaces,
///   - standalone version-ish tokens are stripped ("2019", "16.0.1", "v2.1" —
///     an optional leading 'v' then digits/dots only; embedded digits as in
///     "7-zip" are kept),
///   - architecture tokens are stripped (x64, x86, x86_64, amd64, arm64,
///     ia64, i386, i686, 32-bit/64-bit, 32bit/64bit — wrapping punctuation
///     such as "(64-bit)" is tolerated),
///   - edition tokens (professional, pro, enterprise, standard, community,
///     ultimate, home, education, datacenter, express) are removed from the
///     title; the FIRST one encountered is returned verbatim (lowercased) as
///     `edition`, later ones are dropped.
/// Total over arbitrary bytes; never throws.
NormalizedTitle normalize_title(std::string_view raw);

/// Normalise a raw vendor/publisher name deterministically: ASCII lowercase,
/// commas/semicolons trimmed from token edges, legal-suffix tokens stripped
/// (inc, inc., incorporated, corp, corp., corporation, ltd, ltd., llc, gmbh,
/// s.a., co., company, technologies, software, systems, foundation),
/// whitespace collapsed, then a tiny built-in alias table (Microsoft, Adobe,
/// Oracle, JetBrains, VMware forms) maps well-known variants onto one
/// canonical vendor. Total over arbitrary bytes; never throws.
std::string normalize_vendor(std::string_view raw);

/// Deterministic canonical product key — the `products.norm_key` UNIQUE
/// value. Shape (documented, load-bearing):
///
///   <normalize_vendor(vendor)>:<normalize_title(title).title>
///   <normalize_vendor(vendor)>:<normalize_title(title).title>:<edition>
///
/// The `:<edition>` suffix is present only when `normalize_title` extracted
/// an edition — editions are distinct licensable SKUs (SQL Server Standard
/// vs Enterprise), so they mint distinct product rows; the `title_vendor`
/// match tier below still relates them across editions.
std::string norm_key(std::string_view title, std::string_view vendor);

/// Strictly ordered deterministic match tiers (ADR-0024 Decision 6). Lower
/// enumerators are stronger matches; the matcher returns the first tier that
/// yields a candidate.
enum class MatchTier {
    exact_norm,   ///< computed norm_key equals a candidate key (confidence 1.0)
    title_vendor, ///< normalised title AND vendor equal a candidate's (0.9)
    token_set,    ///< same vendor; one title's token multiset ⊆ the other's (0.8)
    birth,        ///< no candidate matched — mint a new product row
};

/// Tier confidence recorded on `product_aliases.confidence`: 1.0 / 0.9 / 0.8
/// for the three match tiers; 0.0 for `birth` (a birth is not a match).
double match_confidence(MatchTier tier);

/// An existing catalog row offered to the matcher: its persisted norm_key
/// plus its normalised title and vendor (as stored on the products row).
struct ProductCandidate {
    std::string norm_key;
    std::string title;
    std::string vendor;
};

/// Matcher verdict: the winning tier, the matched candidate's norm_key
/// (empty for `birth`), and the tier confidence.
struct MatchResult {
    MatchTier tier = MatchTier::birth;
    std::string norm_key;
    double confidence = 0.0;
};

/// Match a raw (title, vendor) against a candidate set of existing catalog
/// rows. Tiers are evaluated strictly in order; within a tier, ties break to
/// the lexicographically smallest candidate norm_key, so the same input set
/// always yields the same result regardless of candidate order. No
/// fuzzy/Levenshtein matching (ADR-0024 Decision 6). An empty normalised
/// title never matches by token_set (an empty token multiset would be a
/// subset of everything).
MatchResult match_product(std::string_view raw_title, std::string_view raw_vendor,
                          const std::vector<ProductCandidate>& candidates);

/// Derive the effective licence state against server-now (ADR-0024
/// Decision 7): a device that stopped syncing before its licence lapsed must
/// still show `expired`. Total, unknown-preserving function over arbitrary
/// strings — never throws.
///
///   - a `state` outside the closed §3.2 vocabulary → "unknown",
///   - "unknown" stays "unknown" (never fabricated into a verdict),
///   - "expired" / "unlicensed" pass through unchanged,
///   - any remaining state with `expiry_at_epoch > 0` whose expiry has
///     passed (`expiry_at_epoch <= now_epoch`) → "expired" — this covers
///     subscription_active, trial, and grace past expiry,
///   - otherwise the agent-reported state passes through (a `licensed` or
///     `perpetual` row with expiry 0 never lapses).
///
/// `license_type` is part of the derivation contract for future
/// type-specific refinements; the v1 rule is driven by state + expiry alone.
std::string effective_license_state(std::string_view state, std::string_view license_type,
                                    std::int64_t expiry_at_epoch, std::int64_t now_epoch);

/// Lapse rule (roadmap §3.2): a licence is lapsed when its EFFECTIVE state is
/// `expired` or `unlicensed`.
bool is_lapsed(std::string_view effective_state);

} // namespace yuzu::server
