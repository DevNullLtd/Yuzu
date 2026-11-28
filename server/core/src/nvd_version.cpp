#include "nvd_version.hpp"

#include "vers_range.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

// Drop a leading "N:" epoch (digits followed by ':'). NVD CPE version ranges
// never carry epochs, so we ignore them on both sides rather than let an
// inventory-side epoch (e.g. an rpm "1:2.3") sort above every NVD bound.
std::string_view strip_epoch(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] >= '0' && s[i] <= '9'))
        ++i;
    if (i > 0 && i < s.size() && s[i] == ':')
        return s.substr(i + 1);
    return s;
}

bool is_sep(char c) {
    return c == '.' || c == '-' || c == '_' || c == '+' || c == '~';
}

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

// Split a version (epoch already stripped) into segments, breaking on
// separators and on digit<->alpha transitions. Separators are discarded.
std::vector<std::string_view> tokenize(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        if (is_sep(s[i])) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        const bool numeric = is_digit(s[i]);
        while (i < s.size() && !is_sep(s[i]) && is_digit(s[i]) == numeric)
            ++i;
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

bool token_is_numeric(std::string_view t) {
    return !t.empty() && is_digit(t.front());
}

bool token_is_zero(std::string_view t) {
    for (char c : t)
        if (c != '0')
            return false;
    return true;
}

// Overflow-safe unsigned integer compare of two all-digit tokens.
int numeric_compare(std::string_view a, std::string_view b) {
    auto strip = [](std::string_view s) {
        std::size_t i = 0;
        while (i + 1 < s.size() && s[i] == '0')
            ++i;
        return s.substr(i);
    };
    a = strip(a);
    b = strip(b);
    if (a.size() != b.size())
        return a.size() < b.size() ? -1 : 1;
    const int c = a.compare(b);
    return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

// Rank of a recognised pre-release tag (lower = earlier). std::nullopt for a
// token that is not a known pre-release identifier (e.g. "p", "patch", "k").
//
// Only unambiguous multi-letter words are treated as pre-release. Single
// letters are deliberately EXCLUDED: the tokenizer cannot tell an attached
// letter-release ("1.0.2a", an OpenSSL patch ABOVE 1.0.2) from a delimited
// tag ("1.0.0-a"), and letter-releases are far more common in real version
// strings than "-a"-style alpha markers. Ranking "a"/"b" as pre-release made
// "1.0.2a" sort BELOW "1.0.2", flipping vulnerable<->fixed against a version
// bound (governance c1735cd3 cpp-expert S1). So "a"/"b" fall through here and
// are compared as ordinary (higher) alpha patch tokens.
std::optional<int> prerelease_rank(std::string_view t) {
    std::string lower;
    lower.reserve(t.size());
    for (char c : t)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    static const std::array<std::pair<std::string_view, int>, 6> kTags = {{
        {"dev", 0},
        {"alpha", 1},
        {"beta", 2},
        {"pre", 3},
        {"preview", 3},
        {"rc", 4},
    }};
    for (const auto& [tag, rank] : kTags)
        if (lower == tag)
            return rank;
    return std::nullopt;
}

int alpha_compare(std::string_view a, std::string_view b) {
    // Case-insensitive lexicographic.
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const char ca = static_cast<char>(std::tolower(static_cast<unsigned char>(a[i])));
        const char cb = static_cast<char>(std::tolower(static_cast<unsigned char>(b[i])));
        if (ca != cb)
            return ca < cb ? -1 : 1;
    }
    if (a.size() != b.size())
        return a.size() < b.size() ? -1 : 1;
    return 0;
}

// Decide the sign contributed by the trailing (extra) segments of the longer
// side. `sign` is +1 when the extras belong to `a`, -1 when they belong to `b`.
// Trailing zeros are padding (skip); a non-zero numeric or unknown-alpha extra
// makes the longer side higher; a pre-release extra makes it lower.
int tail_sign(const std::vector<std::string_view>& tokens, std::size_t start, int sign) {
    for (std::size_t j = start; j < tokens.size(); ++j) {
        const std::string_view t = tokens[j];
        if (token_is_numeric(t)) {
            if (!token_is_zero(t))
                return sign;
        } else if (prerelease_rank(t)) {
            return -sign;
        } else {
            return sign;
        }
    }
    return 0;
}

} // namespace

int nvd_version_compare(std::string_view a, std::string_view b) {
    const std::vector<std::string_view> ta = tokenize(strip_epoch(a));
    const std::vector<std::string_view> tb = tokenize(strip_epoch(b));

    const std::size_t n = std::min(ta.size(), tb.size());
    for (std::size_t i = 0; i < n; ++i) {
        const std::string_view sa = ta[i];
        const std::string_view sb = tb[i];
        const bool na = token_is_numeric(sa);
        const bool nb = token_is_numeric(sb);
        if (na && nb) {
            if (const int c = numeric_compare(sa, sb))
                return c;
        } else if (na) {
            return 1; // numeric core outranks an alpha tag at the same position
        } else if (nb) {
            return -1;
        } else {
            const auto ra = prerelease_rank(sa);
            const auto rb = prerelease_rank(sb);
            if (ra && rb) {
                if (*ra != *rb)
                    return *ra < *rb ? -1 : 1;
            } else if (const int c = alpha_compare(sa, sb)) {
                return c;
            }
        }
    }

    if (ta.size() > n)
        return tail_sign(ta, n, 1);
    if (tb.size() > n)
        return tail_sign(tb, n, -1);
    return 0;
}

bool nvd_version_in_range(std::string_view installed, const VersionRange& r) {
    const bool has_bound = !r.start_including.empty() || !r.start_excluding.empty() ||
                           !r.end_including.empty() || !r.end_excluding.empty();
    if (has_bound) {
        // The shared interval core (vers_range.hpp): the inclusive pair and the exclusive pair are
        // each one interval, and all four bounds must hold.
        return vers::in_interval(installed, r.start_including, true, r.end_including, true,
                                 nvd_version_compare) &&
               vers::in_interval(installed, r.start_excluding, false, r.end_excluding, false,
                                 nvd_version_compare);
    }

    // No range: the CPE version field decides.
    if (r.exact.empty() || r.exact == "*" || r.exact == "-")
        return true; // "all versions of this product"
    return nvd_version_compare(installed, r.exact) == 0;
}

} // namespace yuzu::server
