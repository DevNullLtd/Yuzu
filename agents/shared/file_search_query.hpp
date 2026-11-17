// file_search_query.hpp -- the query model of the on-demand file search: a leaf-name Pattern, the
// name semantics that canonicalise it and the candidate names, and the query hash that binds a
// result cursor to the query that produced it.
//
// Pattern language (deliberately tiny, so the matcher is provably bounded): '*' matches any run of
// bytes including none; '?' matches one UTF-8 scalar (or one byte where the bytes at that position
// are not a well-formed scalar); every other byte, '[' and ']' included, is a literal. No classes,
// no escapes, no regex. Leaf names only: '/' and NUL are refused.
//
// This hashes the query text, never file content. Platform-agnostic pure C++ with no OS call and
// no I/O: the zero-dependency leaf-helper convention of this directory.
#pragma once

#include "sha256.hpp"
#include "wire_utf8.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::shared::file_search {

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
/// own NameSemantics in a later PR; this one is the portable floor.
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
                if (!collapsed.empty() && collapsed.back() == '*')
                    continue;
                ++stars;
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

    /// matches(), also reporting the matcher's loop iterations (bounded by
    /// (canonical name + 1) * (canonical pattern + 1)); lets a test assert the worst-case bound.
    [[nodiscard]] bool matches_counted(std::string_view raw_name, std::size_t& steps) const {
        const std::string name = canon_fn_ ? canon_fn_(raw_name) : std::string(raw_name);
        if (name.size() > kMaxCanonicalNameBytes)
            return false;
        const std::string_view pat = canonical_;
        std::size_t p = 0, n = 0;
        constexpr auto npos = std::string_view::npos;
        std::size_t star = npos, star_n = 0; // the one backtrack point: the last star
        for (;;) {
            ++steps;
            if (p < pat.size()) {
                if (pat[p] == '*') {
                    star = p++;
                    star_n = n;
                    continue;
                }
                if (n < name.size()) {
                    if (pat[p] == '?') {
                        const std::size_t len = utf8_scalar_len(name, n);
                        n += len == 0 ? 1 : len;
                        ++p;
                        continue;
                    }
                    if (pat[p] == name[n]) {
                        ++p;
                        ++n;
                        continue;
                    }
                }
            } else if (n == name.size()) {
                return true;
            }
            // Mismatch, or the name ran out with pattern left (a '?' may have swallowed a whole
            // scalar that the star could have split): retry with the last star one byte longer.
            if (star == npos || star_n >= name.size())
                return false;
            p = star + 1;
            n = ++star_n;
        }
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
    const std::string hex = sha256_hex(buf);
    const auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    std::array<std::uint8_t, 16> out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    return out;
}

} // namespace yuzu::shared::file_search
