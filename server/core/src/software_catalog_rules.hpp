#pragma once

/// @file software_catalog_rules.hpp
/// Pure decision core for the Software catalogue rollup (M.9 PR-1): the grain mask,
/// the OS-family table (and the OpenAPI/MCP ecosystem renderers `ecosystem_json_enum_items()` /
/// `ecosystem_pipe_list()` generated from it, plus `expand_ecosystem_tokens()`, used by the MCP
/// tool catalogue; rest_api_v1.cpp keeps its own copy until a REST-only follow-up), the
/// catalogue's own TRANSITIVE version order, the
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

/// Row order is the published order of the OpenAPI and MCP ecosystem enums; a mid-table insert
/// shifts positions, so say so in the changelog.
inline constexpr std::array<EcosystemFamily, 12> kEcosystemFamilies{{
    {"windows", "windows"},
    {"optional_feature", "windows"},
    {"msi", "windows"},
    {"macos", "macos"},
    {"macos_pkgutil", "macos"},
    {"brew", "macos"},
    {"rpm", "linux"},
    {"deb", "linux"},
    {"apk", "linux"},
    {"pacman", "linux"},
    {"snap", "linux"},
    {"flatpak", "linux"},
}};

/// The table is non-empty, every ecosystem is `[a-z_]+` and every family `[a-z]+` (so none is
/// empty), and no ecosystem repeats. A row commented out of the initializer while the declared
/// size is kept leaves a value-initialised (empty) row, which every consumer of the table would
/// otherwise carry silently. The charset is what the renderers below splice unescaped into SQL
/// literals, JSON strings and a `|` list; tests/test_software_vocabulary_consistency.py's table
/// parser (`{"([a-z_]+)", "[a-z]+"}`) is the other side of the same contract: widen both together.
// ponytail: the duplicate scan is O(n^2) in constexpr steps. MSVC's default /constexpr:steps is
// 100000 and its step accounting is unmeasured here; re-measure on the Windows leg past ~50 rows,
// or drop the scan (the vocabulary test already rejects duplicates).
[[nodiscard]] consteval bool ecosystem_table_well_formed() {
    constexpr auto name_ok = [](std::string_view s, bool underscore) {
        if (s.empty())
            return false;
        for (const char c : s) {
            if ((c < 'a' || c > 'z') && !(underscore && c == '_'))
                return false;
        }
        return true;
    };
    if (kEcosystemFamilies.empty())
        return false;
    for (std::size_t i = 0; i < kEcosystemFamilies.size(); ++i) {
        if (!name_ok(kEcosystemFamilies[i].ecosystem, true) ||
            !name_ok(kEcosystemFamilies[i].family, false))
            return false;
        for (std::size_t j = i + 1; j < kEcosystemFamilies.size(); ++j) {
            if (kEcosystemFamilies[i].ecosystem == kEcosystemFamilies[j].ecosystem)
                return false;
        }
    }
    return true;
}
static_assert(ecosystem_table_well_formed(),
              "kEcosystemFamilies: an empty table, an empty or duplicate row (a commented-out "
              "entry with the declared size kept?), or a name outside the charset the renderers "
              "assume (ecosystem [a-z_], family [a-z])");

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

/// JSON array items (no brackets, table order) for the OpenAPI and MCP `ecosystem` enums. Every
/// literal comes from the constexpr table (never input).
[[nodiscard]] inline std::string ecosystem_json_enum_items() {
    std::string out;
    for (const auto& e : kEcosystemFamilies) {
        if (!out.empty())
            out += ", ";
        out += '"';
        out += e.ecosystem;
        out += '"';
    }
    return out;
}

/// `a|b|c` list (table order) for the OpenAPI /inventory/software and MCP query_installed_software
/// descriptions.
[[nodiscard]] inline std::string ecosystem_pipe_list() {
    std::string out;
    for (const auto& e : kEcosystemFamilies) {
        if (!out.empty())
            out += '|';
        out += e.ecosystem;
    }
    return out;
}

/// Expands the ecosystem placeholders in a template with values generated from
/// kEcosystemFamilies: `"@@ECOSYSTEM_ENUM@@"` (quotes included) -> the quoted table items,
/// `"@@ECOSYSTEM_ENUM_OR_EMPTY@@"` -> `"", ` + the items, `@@ECOSYSTEM_LIST@@` (bare) -> the
/// pipe list. The quotes belong to the two ENUM tokens, so an unquoted enum token is left intact.
/// A missing or malformed token is not an error here; the consumer guards its template
/// (build_catalogue()'s boot refusal in mcp_server.cpp).
/// One allocation, sized to the largest the string reaches (the final size, the template's when
/// every substitution shrinks it, or a mid-way peak when substitutions mix growing and
/// shrinking): reserve() runs on an empty string (no capacity doubling),
/// so the append and the in-place replaces below never reallocate for any well-formed table.
[[nodiscard]] inline std::string expand_ecosystem_tokens(std::string_view tmpl) {
    const std::string items = ecosystem_json_enum_items();
    const std::pair<std::string_view, std::string> subs[] = {
        {"\"@@ECOSYSTEM_ENUM@@\"", items},
        {"\"@@ECOSYSTEM_ENUM_OR_EMPTY@@\"", "\"\", " + items},
        {"@@ECOSYSTEM_LIST@@", ecosystem_pipe_list()},
    };
    // Same token order and counts as the replace loop below, so `peak` is the largest size the
    // in-place replaces reach (a table whose substitutions mix growing and shrinking ones peaks
    // mid-way).
    std::size_t size = tmpl.size();
    std::size_t peak = size;
    for (const auto& [tok, val] : subs) {
        for (std::size_t pos = tmpl.find(tok); pos != std::string_view::npos;
             pos = tmpl.find(tok, pos + tok.size())) {
            size = size - tok.size() + val.size();
            peak = std::max(peak, size);
        }
    }
    std::string out;
    out.reserve(peak);
    out.append(tmpl);
    for (const auto& [tok, val] : subs) {
        for (std::size_t pos = 0; (pos = out.find(tok, pos)) != std::string::npos;
             pos += val.size()) {
            out.replace(pos, tok.size(), val);
        }
    }
    return out;
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

/// Tokenise on ANY non-alphanumeric byte and on digit<->alpha transitions. Modelled on the
/// NVD tokenizer (file-private there), which is narrower: it breaks only on `. - _ + ~`.
/// A leading "N:" epoch is dropped so an rpm epoch cannot outrank another ecosystem's
/// spelling of the same version.
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

/// The catalogue's own TRANSITIVE total preorder on version strings. nvd_version_compare is
/// deliberately not reused: it is cyclic — "1.0" < "1.0a" (an unknown alpha tail ranks
/// higher), "1.0a" < "1.0rc" (positional 'a' < 'r'), "1.0rc" < "1.0" (a pre-release tail
/// ranks lower) — so a running max over it depends on input order.
/// Positional lexicographic compare with an END sentinel padding the shorter side; each
/// position maps to (class, subkey): class 0 recognised pre-release tag (dev < alpha < beta <
/// pre = preview < rc), class 1 END or an all-zero numeric token, class 2 any other alpha
/// token (case-insensitive lexicographic), class 3 non-zero numeric (leading zeros stripped,
/// length then lexicographic, overflow-safe). The first unequal position decides; all equal
/// -> 0. Orders that triple as 1.0rc < 1.0 < 1.0a whatever the input order. Agrees with
/// nvd_version_compare on its documented examples (1.10 > 1.9; 2.0 > 2.0-rc1; 9.8p1 > 9.8;
/// 1.0.2a > 1.0.2; 1.0 == 1.0.0; 1:2.3 == 2.3). Documented divergences from NVD: (1) a zero
/// numeric token against an alpha token at the same position ("1.0.0" vs "1.0.a") orders the
/// alpha higher, where NVD orders any numeric higher; (2) an unrecognised alpha tag against a
/// pre-release tag orders by class (pre-release lower), so 1.0rc < 1.0p, where NVD compares
/// the letters positionally (1.0p < 1.0rc); (3) any non-alphanumeric byte separates tokens
/// here, NVD only `. - _ + ~`.
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
