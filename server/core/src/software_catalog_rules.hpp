#pragma once

/// @file software_catalog_rules.hpp
/// Pure decision core for the Software catalogue rollup (M.9 PR-1): the grain mask,
/// the OS-family table, the catalogue's own TRANSITIVE version order, the
/// streaming fleet-newest fold, search hygiene and the refresh/search bounds. No libpq,
/// no clock, no I/O — the store (`software_inventory_store.cpp`) owns every statement and
/// feeds this header plain values, so the unit suite never touches a database for any of it.
///
/// Version order: `catalog_version_compare` is the catalogue's own transitive order, not the
/// NVD comparator (rationale at its definition below).

#include <algorithm>
#include <array>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::software_catalog {

// ── Grain mask ───────────────────────────────────────────────────────────────

/// `catalog_rollup.grain` = PG's GROUPING(kind, ecosystem, source): bit 2 kind, bit 1
/// ecosystem, bit 0 source; a SET bit means that dimension is aggregated away (not fixed).
/// 7 = title total (no filter), 0 = one exact (kind, ecosystem, source) combination.
inline constexpr int kGrainTitle = 7;
inline constexpr int kGrainEcosystem = 5; ///< ecosystem fixed, kind and source aggregated

[[nodiscard]] constexpr int grain_mask(std::string_view kind, std::string_view ecosystem,
                                       std::string_view source) noexcept {
    return (kind.empty() ? 4 : 0) | (ecosystem.empty() ? 2 : 0) | (source.empty() ? 1 : 0);
}

// ── OS family (single source of truth for the Installs-by-OS KPI) ───────────

struct EcosystemFamily {
    std::string_view ecosystem;
    std::string_view family; ///< windows | macos | linux; any other ecosystem is "other"
};

inline constexpr std::array<EcosystemFamily, 9> kEcosystemFamilies{{
    {"windows", "windows"},
    {"optional_feature", "windows"},
    {"macos", "macos"},
    {"macos_pkgutil", "macos"},
    {"brew", "macos"},
    {"rpm", "linux"},
    {"deb", "linux"},
    {"apk", "linux"},
    {"pacman", "linux"},
}};

/// SQL `CASE` over the `ecosystem` column generated from kEcosystemFamilies, so the SQL has
/// one source of truth. Every literal comes from the constexpr table (never input).
[[nodiscard]] inline std::string os_family_case_sql() {
    std::string sql = "CASE ecosystem";
    for (const auto& e : kEcosystemFamilies) {
        sql += " WHEN '";
        sql += e.ecosystem;
        sql += "' THEN '";
        sql += e.family;
        sql += '\'';
    }
    sql += " ELSE 'other' END";
    return sql;
}

// ── Version order ────────────────────────────────────────────────────────────

namespace detail {

struct VToken {
    bool numeric{false};
    std::string text; // numeric: digits as written; alpha: lower-cased
};

[[nodiscard]] inline bool is_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}
[[nodiscard]] inline bool is_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/// Tokenise on any non-alphanumeric byte and on digit<->alpha transitions (the NVD
/// tokenizer's rules, restated: that one is file-private). A leading "N:" epoch is dropped
/// so an rpm epoch cannot outrank another ecosystem's spelling of the same version.
[[nodiscard]] inline std::vector<VToken> tokenize(std::string_view v) {
    std::size_t i = 0;
    std::size_t d = 0;
    while (d < v.size() && is_digit(v[d]))
        ++d;
    if (d > 0 && d < v.size() && v[d] == ':')
        i = d + 1;
    std::vector<VToken> out;
    while (i < v.size()) {
        const char c = v[i];
        if (!is_digit(c) && !is_alpha(c)) {
            ++i;
            continue;
        }
        const bool num = is_digit(c);
        VToken t;
        t.numeric = num;
        while (i < v.size() && (num ? is_digit(v[i]) : is_alpha(v[i]))) {
            char ch = v[i];
            if (!num && ch >= 'A' && ch <= 'Z')
                ch = static_cast<char>(ch - 'A' + 'a');
            t.text.push_back(ch);
            ++i;
        }
        out.push_back(std::move(t));
    }
    return out;
}

/// Pre-release tag rank, or -1 when the token is not a recognised tag.
[[nodiscard]] inline int prerelease_rank(std::string_view t) noexcept {
    if (t == "dev")
        return 0;
    if (t == "alpha")
        return 1;
    if (t == "beta")
        return 2;
    if (t == "pre" || t == "preview")
        return 3;
    if (t == "rc")
        return 4;
    return -1;
}

/// Total preorder key of one position, compared field by field (cls, n, text): class 0
/// recognised pre-release (n = rank), class 1 END or an all-zero numeric token (so
/// 1.0 == 1.0.0), class 2 any other alpha token (text), class 3 non-zero numeric (n = digit
/// count, text = digits without leading zeros: length then lexicographic).
struct TokKey {
    int cls{1};
    std::size_t n{0};
    std::string_view text;
    auto operator<=>(const TokKey&) const = default;
};

[[nodiscard]] inline TokKey key_of(const std::vector<VToken>& toks, std::size_t i) noexcept {
    if (i >= toks.size())
        return {1, 0, {}};
    const VToken& t = toks[i];
    if (t.numeric) {
        std::string_view s = t.text;
        while (!s.empty() && s.front() == '0')
            s.remove_prefix(1);
        if (s.empty())
            return {1, 0, {}};
        return {3, s.size(), s};
    }
    if (const int r = prerelease_rank(t.text); r >= 0)
        return {0, static_cast<std::size_t>(r), {}};
    return {2, 0, t.text};
}

} // namespace detail

/// The catalogue's own TRANSITIVE total preorder on version strings (see the file comment for
/// why the NVD comparator is not reused). Positional lexicographic compare with an END
/// sentinel padding the shorter side; each position maps to (class, subkey): class 0
/// recognised pre-release tag (dev < alpha < beta < pre = preview < rc), class 1 END or an
/// all-zero numeric token, class 2 any other alpha token (case-insensitive lexicographic),
/// class 3 non-zero numeric (leading zeros stripped, length then lexicographic, overflow-safe).
/// The first unequal position decides; all equal -> 0. Resolves the cycle as
/// 1.0rc < 1.0 < 1.0a. Agrees with nvd_version_compare on its documented examples (1.10 > 1.9;
/// 2.0 > 2.0-rc1; 9.8p1 > 9.8; 1.0.2a > 1.0.2; 1.0 == 1.0.0; 1:2.3 == 2.3). The ONE
/// documented divergence: a zero numeric token against an alpha token at the same position
/// ("1.0.0" vs "1.0.a") orders the alpha higher, where NVD orders any numeric higher.
[[nodiscard]] inline int catalog_version_compare(std::string_view a, std::string_view b) {
    const auto ta = detail::tokenize(a);
    const auto tb = detail::tokenize(b);
    const std::size_t n = std::max(ta.size(), tb.size());
    for (std::size_t i = 0; i < n; ++i) {
        if (const auto c = detail::key_of(ta, i) <=> detail::key_of(tb, i); c != 0)
            return c < 0 ? -1 : 1;
    }
    return 0;
}

/// Total tie rule on top of the preorder: compare > 0 wins; compare == 0 (1.0 vs 1.0.0, pre vs
/// preview) -> more installs wins -> the lexicographically greater string wins. Input-order
/// independent, so the fleet-newest pick is deterministic across refreshes.
[[nodiscard]] inline bool newer_than(std::string_view v, std::int64_t v_installs,
                                     std::string_view best, std::int64_t best_installs) {
    if (const int c = catalog_version_compare(v, best); c != 0)
        return c > 0;
    if (v_installs != best_installs)
        return v_installs > best_installs;
    return v > best;
}

struct NewestPick {
    std::string name;
    std::string version;
    std::int64_t installs{0};
};

/// Streaming fleet-newest fold. Rows must arrive grouped by name (the caller's
/// ORDER BY name, version); a title straddling two fetches is handled by the carried state.
/// '' versions are skipped, so a title whose versions are all '' yields no pick.
class NewestFold {
public:
    void feed(std::string_view name, std::string_view version, std::int64_t installs,
              std::vector<NewestPick>& out) {
        if (!have_name_ || name != name_) {
            flush(out);
            name_.assign(name);
            have_name_ = true;
        }
        if (version.empty())
            return;
        if (!have_best_ || newer_than(version, installs, best_version_, best_installs_)) {
            best_version_.assign(version);
            best_installs_ = installs;
            have_best_ = true;
        }
    }

    /// Emit the trailing title (call once after the last row).
    void finish(std::vector<NewestPick>& out) {
        flush(out);
        have_name_ = false;
    }

private:
    void flush(std::vector<NewestPick>& out) {
        if (have_name_ && have_best_)
            out.push_back({name_, best_version_, best_installs_});
        have_best_ = false;
    }

    std::string name_;
    std::string best_version_;
    std::int64_t best_installs_{0};
    bool have_name_{false};
    bool have_best_{false};
};

// ── Search hygiene ───────────────────────────────────────────────────────────

/// Backslash-escape the ILIKE metacharacters (\\ % _) so a search term matches literally
/// under `ESCAPE '\\'`. Same contract as nvd_db.cpp's SQLite-side lambda (left untouched).
[[nodiscard]] inline std::string like_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        if (c == '\\' || c == '%' || c == '_')
            out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

/// Cut at a UTF-8 codepoint start so the result is at most `max_bytes` and never ends in a
/// split sequence; no ellipsis (this value is a search term, not display text).
[[nodiscard]] inline std::string clamp_utf8(std::string_view s, std::size_t max_bytes) {
    if (s.size() <= max_bytes)
        return std::string(s);
    std::size_t cut = max_bytes;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0U) == 0x80U)
        --cut;
    return std::string(s.substr(0, cut));
}

// ── Bounds ───────────────────────────────────────────────────────────────────

inline constexpr std::size_t kSearchMaxBytes = 128;
inline constexpr int kNewestFetchRows = 10000;
inline constexpr std::size_t kNewestFlushRows = 5000;
inline constexpr std::string_view kSearchStatementTimeout = "5s";
/// Wall budget for the WHOLE catalogue refresh, checked between statements and between every
/// cursor FETCH / temp-table INSERT batch (the per-statement 60 s bound stays in the store).
inline constexpr std::chrono::seconds kRollupRefreshBudget{600};

} // namespace yuzu::server::software_catalog
