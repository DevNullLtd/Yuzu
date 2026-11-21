#include "product_normalize.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

namespace yuzu::server {

namespace {

/// ASCII-only lowercase; non-ASCII bytes pass through untouched.
std::string ascii_lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : ch;
    }
    return out;
}

bool is_space(char ch) {
    const unsigned char c = static_cast<unsigned char>(ch);
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/// Split on whitespace runs; empty tokens never appear in the result.
std::vector<std::string> split_tokens(std::string_view s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_space(s[i]))
            ++i;
        std::size_t start = i;
        while (i < s.size() && !is_space(s[i]))
            ++i;
        if (i > start)
            out.emplace_back(s.substr(start, i - start));
    }
    return out;
}

std::string join_tokens(const std::vector<std::string>& tokens) {
    std::string out;
    for (const auto& t : tokens) {
        if (!out.empty())
            out += ' ';
        out += t;
    }
    return out;
}

/// Trim wrapping punctuation from a token for CLASSIFICATION only — the
/// emitted token is never rewritten. Tolerates "(64-bit)", "[x64]", "2019,".
std::string_view trim_wrapping(std::string_view t) {
    constexpr std::string_view kWrap = "()[]{},;";
    while (!t.empty() && kWrap.find(t.front()) != std::string_view::npos)
        t.remove_prefix(1);
    while (!t.empty() && kWrap.find(t.back()) != std::string_view::npos)
        t.remove_suffix(1);
    return t;
}

/// Version-ish token: an optional leading 'v', then digits and dots only,
/// at least one digit, no leading/trailing dot ("2019", "16.0.1", "v2.1").
bool is_version_token(std::string_view t) {
    if (!t.empty() && t.front() == 'v')
        t.remove_prefix(1);
    if (t.empty() || t.front() == '.' || t.back() == '.')
        return false;
    bool digit = false;
    for (char c : t) {
        if (c >= '0' && c <= '9')
            digit = true;
        else if (c != '.')
            return false;
    }
    return digit;
}

bool is_arch_token(std::string_view t) {
    static constexpr std::array<std::string_view, 12> kArch = {
        "x64",    "x86",    "x86_64", "amd64", "arm64", "ia64",
        "i386",   "i686",   "32-bit", "64-bit", "32bit", "64bit",
    };
    return std::find(kArch.begin(), kArch.end(), t) != kArch.end();
}

bool is_edition_token(std::string_view t) {
    static constexpr std::array<std::string_view, 10> kEdition = {
        "professional", "pro",  "enterprise", "standard",   "community",
        "ultimate",     "home", "education",  "datacenter", "express",
    };
    return std::find(kEdition.begin(), kEdition.end(), t) != kEdition.end();
}

/// Legal-suffix tokens dropped from vendor names (compared after trimming
/// commas/semicolons off token edges; the dotted forms keep their dots).
bool is_legal_suffix_token(std::string_view t) {
    static constexpr std::array<std::string_view, 18> kSuffix = {
        "inc",  "inc.",  "incorporated", "corp",         "corp.",   "corporation",
        "ltd",  "ltd.",  "llc",          "l.l.c.",       "gmbh",    "s.a.",
        "co.",  "company", "technologies", "software",   "systems", "foundation",
    };
    return std::find(kSuffix.begin(), kSuffix.end(), t) != kSuffix.end();
}

/// Well-known vendor forms that token stripping alone cannot reduce to one
/// canonical name. Consulted both before and after suffix stripping; keys
/// are exact lowercased whitespace-collapsed strings. Deliberately tiny —
/// curation belongs in `product_aliases`, not here. Returns empty on no hit.
std::string_view vendor_alias(std::string_view v) {
    static constexpr std::array<std::pair<std::string_view, std::string_view>, 6> kAlias = {{
        {"microsoft corporation", "microsoft"},
        {"adobe systems", "adobe"},
        {"adobe systems incorporated", "adobe"},
        {"oracle america", "oracle"},
        {"jetbrains s.r.o.", "jetbrains"},
        {"vmware by broadcom", "vmware"},
    }};
    for (const auto& [from, to] : kAlias) {
        if (v == from)
            return to;
    }
    return {};
}

/// Trim commas/semicolons off token edges ("America," → "america").
std::string trim_vendor_token(std::string_view t) {
    while (!t.empty() && (t.front() == ',' || t.front() == ';'))
        t.remove_prefix(1);
    while (!t.empty() && (t.back() == ',' || t.back() == ';'))
        t.remove_suffix(1);
    return std::string{t};
}

/// Multiset-subset test over sorted token vectors: every element of `sub`
/// (with multiplicity) appears in `super`.
bool multiset_subset(const std::vector<std::string>& sub, const std::vector<std::string>& super) {
    return std::includes(super.begin(), super.end(), sub.begin(), sub.end());
}

} // namespace

NormalizedTitle normalize_title(std::string_view raw) {
    NormalizedTitle out;
    std::vector<std::string> kept;
    // True when the previous classified token was an arch or edition word: the word "edition"
    // right after one is the tail of "(x64 edition)" / "Pro Edition", not a title word.
    bool after_arch_or_edition = false;
    const auto take_version = [&out](std::string_view v) {
        if (out.version.empty())
            out.version = std::string{v.front() == 'v' ? v.substr(1) : v};
    };
    for (auto& token : split_tokens(ascii_lower(raw))) {
        std::string_view t = trim_wrapping(token);
        if (t.empty())
            continue;
        const bool was_after = std::exchange(after_arch_or_edition, false);
        if (t == "-") // a bare separator ("Redistributable (x64) - 14.38") names nothing
            continue;
        // "name@version" (a Homebrew formula): the tail is the version and the name is then
        // classified like any other token, so the result stays idempotent under re-normalising.
        if (const std::size_t at = t.find('@'); at != std::string_view::npos && at > 0 &&
                                                 t.find('@', at + 1) == std::string_view::npos &&
                                                 is_version_token(t.substr(at + 1))) {
            take_version(t.substr(at + 1));
            token = std::string{t.substr(0, at)};
            t = trim_wrapping(token);
        }
        if (is_arch_token(t)) {
            after_arch_or_edition = true;
            continue;
        }
        if (was_after && t == "edition")
            continue;
        if (is_version_token(t)) {
            take_version(t);
            continue;
        }
        // An edition word is an edition only after a title word: a title that is an edition
        // word ("Home") or starts with one ("Pro Display Calibrator") keeps it as a title word.
        if (is_edition_token(t)) {
            after_arch_or_edition = true;
            if (!kept.empty()) {
                if (out.edition.empty())
                    out.edition = std::string{t};
                continue;
            }
        }
        kept.push_back(std::move(token));
    }
    out.title = join_tokens(kept);
    return out;
}

std::string normalize_edition(std::string_view raw) {
    std::string edition;
    for (const auto& token : split_tokens(ascii_lower(raw))) {
        const std::string_view t = trim_wrapping(token);
        if (t.empty() || is_arch_token(t) || is_version_token(t))
            continue;
        if (!is_edition_token(t))
            return {};
        if (edition.empty())
            edition = std::string{t};
    }
    return edition;
}

std::string normalize_vendor(std::string_view raw) {
    // FIRST, on the raw bytes: once ascii_lower/tokenising has run, a `via:` label could alias
    // a real vendor.
    if (raw.starts_with(kOriginLabelPrefix))
        return {};
    std::vector<std::string> tokens;
    for (const auto& token : split_tokens(ascii_lower(raw))) {
        std::string t = trim_vendor_token(token);
        if (!t.empty())
            tokens.push_back(std::move(t));
    }
    const std::string collapsed = join_tokens(tokens);
    if (const std::string_view hit = vendor_alias(collapsed); !hit.empty())
        return std::string{hit};

    // Only the TRAILING run of suffix words is a legal form ("Python Software Foundation"); a
    // suffix word earlier in the name is part of it ("macOS Software Signing", "Software AG"),
    // and the last remaining token is never stripped, so a vendor never reduces to nothing.
    while (tokens.size() > 1 && is_legal_suffix_token(tokens.back()))
        tokens.pop_back();
    const std::string stripped = join_tokens(tokens);
    if (const std::string_view hit = vendor_alias(stripped); !hit.empty())
        return std::string{hit};
    return stripped;
}

std::string make_norm_key(std::string_view norm_vendor, std::string_view norm_title,
                          std::string_view edition) {
    std::string key{norm_vendor};
    key += ':';
    key += norm_title;
    if (!edition.empty()) {
        key += ':';
        key += edition;
    }
    return key;
}

std::string norm_key(std::string_view title, std::string_view vendor) {
    const NormalizedTitle nt = normalize_title(title);
    return make_norm_key(normalize_vendor(vendor), nt.title, nt.edition);
}

double match_confidence(MatchTier tier) {
    switch (tier) {
    case MatchTier::exact_norm:
        return 1.0;
    case MatchTier::title_vendor:
        return 0.9;
    case MatchTier::token_set:
        return 0.8;
    case MatchTier::birth:
        break;
    }
    return 0.0;
}

MatchResult match_product(std::string_view raw_title, std::string_view raw_vendor,
                          const std::vector<ProductCandidate>& candidates) {
    const NormalizedTitle nt = normalize_title(raw_title);
    const std::string nv = normalize_vendor(raw_vendor);
    const std::string key = norm_key(raw_title, raw_vendor);

    std::vector<std::string> tokens = split_tokens(nt.title);
    std::sort(tokens.begin(), tokens.end());

    // Within each tier, keep the lexicographically smallest candidate
    // norm_key so the verdict is independent of candidate order.
    const auto pick = [&](auto&& matches, MatchTier tier) -> MatchResult {
        const std::string* best = nullptr;
        for (const auto& c : candidates) {
            if (!matches(c))
                continue;
            if (best == nullptr || c.norm_key < *best)
                best = &c.norm_key;
        }
        if (best == nullptr)
            return {};
        return {tier, *best, match_confidence(tier)};
    };

    if (auto r = pick([&](const ProductCandidate& c) { return c.norm_key == key; },
                      MatchTier::exact_norm);
        r.tier != MatchTier::birth)
        return r;

    if (auto r = pick([&](const ProductCandidate& c) { return c.title == nt.title && c.vendor == nv; },
                      MatchTier::title_vendor);
        r.tier != MatchTier::birth)
        return r;

    if (!tokens.empty()) {
        auto r = pick(
            [&](const ProductCandidate& c) {
                if (c.vendor != nv)
                    return false;
                std::vector<std::string> ct = split_tokens(c.title);
                if (ct.empty())
                    return false;
                std::sort(ct.begin(), ct.end());
                return multiset_subset(ct, tokens) || multiset_subset(tokens, ct);
            },
            MatchTier::token_set);
        if (r.tier != MatchTier::birth)
            return r;
    }

    return {};
}

std::string effective_license_state(std::string_view state, std::string_view /*license_type*/,
                                    std::int64_t expiry_at_epoch, std::int64_t now_epoch) {
    static constexpr std::array<std::string_view, 7> kStates = {
        "licensed", "subscription_active", "trial", "grace", "expired", "unlicensed", "unknown",
    };
    if (std::find(kStates.begin(), kStates.end(), state) == kStates.end())
        return "unknown";
    if (state == "unknown" || state == "expired" || state == "unlicensed")
        return std::string{state};
    if (expiry_at_epoch > 0 && expiry_at_epoch <= now_epoch)
        return "expired";
    return std::string{state};
}

bool is_lapsed(std::string_view effective_state) {
    return effective_state == "expired" || effective_state == "unlicensed";
}

} // namespace yuzu::server
