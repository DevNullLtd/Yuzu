// file_search_query.hpp -- the query model of the on-demand file search: a leaf-name Pattern, the
// name semantics that canonicalise it and the candidate names, and the query hash that binds a
// result cursor to the query that produced it.
//
// Pattern language (deliberately tiny, so the matcher is provably bounded): '*' matches any run of
// bytes including none; '?' matches one UTF-8 scalar (or one byte where the bytes at that position
// are not a well-formed scalar); every other byte, '[' and ']' included, is a literal. No classes,
// no escapes, no regex. Leaf names only: '/' and NUL are refused.
//
// The matcher is COMPLETE under exactly those semantics: it accepts a name if and only if SOME
// way of spending each '*' makes the pattern consume the name. It does not backtrack: it tracks,
// pattern byte by pattern byte, the set of name offsets the pattern so far can end at, so the work
// is at most (canonical pattern bytes) * (canonical name bytes + 1) and no recursion or heap use
// beyond the canonical name. A '?' width depends on the name position, so a single backtrack
// point (the last star) is NOT enough once a pattern has two stars and a '?'.
//
// This hashes the query text, never file content. Platform-agnostic pure C++ with no OS call and
// no I/O: the zero-dependency leaf-helper convention of this directory.
#pragma once

#include "sha256.hpp"
#include "wire_utf8.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::shared::file_search {

// Limits on the RAW pattern, before a run of '*' collapses to one and before canonicalisation:
// every '*' counts, a run included.
inline constexpr std::size_t kMaxPatternBytes = 128;
inline constexpr std::size_t kMaxStars = 4;
inline constexpr std::size_t kMinLiteralBytes = 3;
// A canonical pattern or name longer than this cannot be matched (bounds the matcher's work).
inline constexpr std::size_t kMaxCanonicalPatternBytes = 4 * kMaxPatternBytes;
inline constexpr std::size_t kMaxCanonicalNameBytes = 4 * 255;

enum class PatternError { empty, too_long, too_many_stars, too_few_literals, forbidden_byte };

using Canonicaliser = std::function<std::string(std::string_view)>;

/// How names are compared: the id is bound into the query hash; canon maps both the pattern and
/// every candidate name to the form that is compared byte for byte.
struct NameSemantics {
    std::string id;
    Canonicaliser canon;
};

[[nodiscard]] inline NameSemantics byte_exact() {
    return {"bytes", [](std::string_view s) { return std::string(s); }};
}

/// Folds A-Z to a-z and leaves every other byte alone. Full Unicode case folding and
/// normalisation need OS services (ICU / CharLowerW / CFString), so an OS leg injects those as its
/// own NameSemantics; this one is the portable floor.
[[nodiscard]] inline NameSemantics ascii_case_fold() {
    return {"ascii_fold", [](std::string_view s) {
                std::string out(s);
                for (auto& c : out)
                    if (c >= 'A' && c <= 'Z')
                        c = static_cast<char>(c - 'A' + 'a');
                return out;
            }};
}

class Pattern {
public:
    [[nodiscard]] static std::expected<Pattern, PatternError> compile(std::string_view raw,
                                                                      const NameSemantics& sem) {
        if (raw.empty())
            return std::unexpected(PatternError::empty);
        if (raw.size() > kMaxPatternBytes)
            return std::unexpected(PatternError::too_long);
        std::string collapsed;
        collapsed.reserve(raw.size());
        std::size_t stars = 0, literals = 0;
        for (const char c : raw) {
            if (c == '/' || c == '\0')
                return std::unexpected(PatternError::forbidden_byte);
            if (c == '*') {
                ++stars;
                if (!collapsed.empty() && collapsed.back() == '*')
                    continue;
            } else if (c != '?') {
                ++literals;
            }
            collapsed.push_back(c);
        }
        if (stars > kMaxStars)
            return std::unexpected(PatternError::too_many_stars);
        if (literals < kMinLiteralBytes)
            return std::unexpected(PatternError::too_few_literals);
        Pattern p;
        p.canon_fn_ = sem.canon;
        p.sem_id_ = sem.id;
        p.canonical_ = p.canon_fn_ ? p.canon_fn_(collapsed) : collapsed;
        if (p.canonical_.size() > kMaxCanonicalPatternBytes)
            return std::unexpected(PatternError::too_long);
        return p;
    }

    [[nodiscard]] bool matches(std::string_view raw_name) const {
        std::size_t steps = 0;
        return matches_counted(raw_name, steps);
    }

    /// matches(), also reporting the matcher's work: one step per (pattern byte, name offset) cell
    /// it visits, so steps grow by at most (canonical pattern bytes) * (canonical name bytes + 1);
    /// lets a test assert the worst-case bound. A name over the canonical cap costs no steps.
    [[nodiscard]] bool matches_counted(std::string_view raw_name, std::size_t& steps) const {
        const std::string name = canon_fn_ ? canon_fn_(raw_name) : std::string(raw_name);
        if (name.size() > kMaxCanonicalNameBytes)
            return false;
        // rows[r][n]: the pattern bytes consumed so far can end exactly at name offset n.
        std::array<std::array<bool, kMaxCanonicalNameBytes + 1>, 2> rows{};
        auto* cur = &rows[0];
        auto* nxt = &rows[1];
        (*cur)[0] = true;
        const std::size_t cells = name.size() + 1;
        for (const char pc : canonical_) {
            steps += cells;
            if (pc == '*') {
                // Any run of bytes, including none: every offset at or after a reachable one.
                for (std::size_t n = 1; n < cells; ++n)
                    (*cur)[n] = (*cur)[n] || (*cur)[n - 1];
                continue;
            }
            std::fill_n(nxt->begin(), cells, false);
            bool any = false;
            for (std::size_t n = 0; n < name.size(); ++n) {
                if (!(*cur)[n])
                    continue;
                if (pc == '?') {
                    const std::size_t len = utf8_scalar_len(name, n);
                    (*nxt)[n + (len == 0 ? 1 : len)] = true;
                    any = true;
                } else if (pc == name[n]) {
                    (*nxt)[n + 1] = true;
                    any = true;
                }
            }
            if (!any)
                return false;
            std::swap(cur, nxt);
        }
        return (*cur)[name.size()];
    }

    [[nodiscard]] const std::string& canonical() const noexcept { return canonical_; }
    [[nodiscard]] const std::string& semantics_id() const noexcept { return sem_id_; }

private:
    Pattern() = default;
    Canonicaliser canon_fn_;
    std::string canonical_;
    std::string sem_id_;
};

enum class Kinds { files, directories, both };

struct Query {
    Pattern pattern;
    Kinds kinds{Kinds::files};
    std::string root;
};

/// First 16 bytes of SHA-256 over a domain-separated, length-prefixed serialisation of the query.
/// It binds a cursor to its query; it is not a secret.
[[nodiscard]] inline std::array<std::uint8_t, 16> query_hash(const Query& q) {
    std::string buf = "yuzu.file_search.query.v1";
    const auto put_str = [&buf](const std::string& s) {
        const auto n = static_cast<std::uint32_t>(s.size());
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<char>((n >> (8 * i)) & 0xFFu));
        buf += s;
    };
    put_str(q.pattern.canonical());
    put_str(q.pattern.semantics_id());
    buf.push_back(static_cast<char>(q.kinds));
    put_str(q.root);
    Sha256 sha;
    sha.update(buf.data(), buf.size());
    const auto digest = sha.raw_digest();
    std::array<std::uint8_t, 16> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    return out;
}

} // namespace yuzu::shared::file_search
