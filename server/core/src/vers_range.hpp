#pragma once

/// @file vers_range.hpp
/// Pure `vers:` (VERSion Range, the purl-spec companion) parser and evaluator, plus `in_interval`,
/// the one interval core shared by the software lookup routes and the CVE matcher. No I/O, no
/// store, no clock: the comparator is a template parameter so each caller keeps its own order
/// (the lookup uses `software_catalog::catalog_version_compare`, the matcher
/// `nvd_version_compare`).
///
/// Rules this file owns (each stated once, here):
///  * GRAMMAR: `vers:<scheme>/<c1>|<c2>|...`. A constraint is a comparator (`=` `!=` `<` `<=` `>`
///    `>=`) followed by a version; a bare version means `=`; `*` alone (nothing else) matches every
///    version. Versions are percent-decoded. The whole text is bounded (kMaxInputBytes,
///    kMaxConstraints) and carries no control byte or space; the parser never echoes caller text
///    in an error.
///  * SCHEMES: generic, semver, maven, npm, pypi and nuget are evaluated, ALL under the one
///    comparator the caller passes (the catalogue's). That is a documented approximation: a
///    scheme's own edge ordering (maven qualifiers, pypi post/dev releases, epochs) can differ.
///    deb and rpm are refused by name (their ordering is not implemented); anything else is
///    unknown (the scheme is checked against that closed list, so any other text, however it is
///    spelled, is unknown). A refused or unknown scheme is an error, never an unbounded match.
///  * NORMAL FORM (`normalize`): constraints sorted by version; a version listed twice, or two
///    lower bounds (`>` `>=`) or two upper bounds (`<` `<=`) in a row among the interval
///    constraints, is refused. `=` and `!=` stand outside the alternation.
///  * CONTAINMENT (`contains`): the VERS algorithm. `=` match wins, then a `!=` match refuses;
///    the remaining interval constraints are walked pairwise (an upper bound first and a lower
///    bound last are the open ends). A range of `!=` constraints alone matches every other
///    version; a range holding `=` constraints and no interval matches only those.
///  * `from_bounds` is the lookup's `version_min`/`version_max` as a Range, so one evaluator
///    serves both forms. It is built, not normalised: min above max is the empty set, as it
///    always was.

#include <algorithm>
#include <array>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::vers {

inline constexpr std::size_t kMaxInputBytes = 1024;
inline constexpr std::size_t kMaxConstraints = 32;

inline constexpr std::string_view kInvalidIntervalList =
    "vers constraints are not a valid interval list";

enum class Op { kEq, kNe, kLt, kLe, kGt, kGe };

struct Constraint {
    Op op{Op::kEq};
    std::string version;
};

struct Range {
    bool all{false}; ///< `vers:<scheme>/*`
    std::vector<Constraint> constraints;
};

/// Membership of `v` in the interval between `lo` and `hi`; an empty bound is open. The one core
/// behind both the lookup ranges and the CVE matcher's CPE start/end bounds.
template <class Cmp>
[[nodiscard]] bool in_interval(std::string_view v, std::string_view lo, bool lo_incl,
                               std::string_view hi, bool hi_incl, Cmp&& cmp) {
    if (!lo.empty()) {
        const int c = cmp(v, lo);
        if (lo_incl ? c < 0 : c <= 0)
            return false;
    }
    if (!hi.empty()) {
        const int c = cmp(v, hi);
        if (hi_incl ? c > 0 : c >= 0)
            return false;
    }
    return true;
}

namespace detail {

inline constexpr std::string_view kShape = "invalid vers (expected vers:<scheme>/<constraints>)";

[[nodiscard]] inline bool is_lower(Op o) noexcept { return o == Op::kGt || o == Op::kGe; }
[[nodiscard]] inline bool is_upper(Op o) noexcept { return o == Op::kLt || o == Op::kLe; }
[[nodiscard]] inline bool is_interval(Op o) noexcept { return is_lower(o) || is_upper(o); }

[[nodiscard]] inline int hex_val(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/// Percent-decode; the shape error on a bad escape or a control byte in the result.
[[nodiscard]] inline std::expected<std::string, std::string> percent_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in.size())
                return std::unexpected(std::string(kShape));
            const int hi = hex_val(in[i + 1]);
            const int lo = hex_val(in[i + 2]);
            if (hi < 0 || lo < 0)
                return std::unexpected(std::string(kShape));
            c = static_cast<char>(hi * 16 + lo);
            i += 2;
        }
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f)
            return std::unexpected(std::string(kShape));
        out.push_back(c);
    }
    return out;
}

} // namespace detail

/// Parse `text` into a Range (NOT yet normalised: call `normalize` with the comparator). The error
/// is the 400 message; it never contains caller text.
[[nodiscard]] inline std::expected<Range, std::string> parse(std::string_view text) {
    using detail::kShape;
    if (text.size() > kMaxInputBytes)
        return std::unexpected("vers too long");
    for (const char ch : text) {
        const auto u = static_cast<unsigned char>(ch);
        if (u <= 0x20 || u == 0x7f)
            return std::unexpected("invalid vers (control or space byte)");
    }
    constexpr std::string_view kPrefix = "vers:";
    if (!text.starts_with(kPrefix))
        return std::unexpected(std::string(kShape));
    text.remove_prefix(kPrefix.size());
    const auto slash = text.find('/');
    if (slash == std::string_view::npos)
        return std::unexpected(std::string(kShape));
    const std::string_view scheme = text.substr(0, slash);
    std::string_view body = text.substr(slash + 1);

    // Only the fixed deb/rpm literals are ever echoed back; any other scheme is just "unknown".
    constexpr std::array<std::string_view, 6> kSupported{"generic", "semver", "maven",
                                                         "npm",     "pypi",   "nuget"};
    if (scheme == "deb" || scheme == "rpm")
        return std::unexpected("vers scheme " + std::string(scheme) + " is not supported yet");
    if (std::ranges::find(kSupported, scheme) == kSupported.end())
        return std::unexpected("unknown vers scheme");

    Range r;
    if (body == "*") {
        r.all = true;
        return r;
    }
    if (body.empty())
        return std::unexpected("invalid vers (no constraints)");
    if (static_cast<std::size_t>(std::ranges::count(body, '|')) + 1 > kMaxConstraints)
        return std::unexpected("vers has too many constraints");

    while (true) {
        const auto bar = body.find('|');
        std::string_view part = body.substr(0, bar);
        if (part.find('*') != std::string_view::npos)
            return std::unexpected("invalid vers (* must stand alone)");
        Op op = Op::kEq;
        std::size_t skip = 0;
        if (part.starts_with("!=")) {
            op = Op::kNe;
            skip = 2;
        } else if (part.starts_with("<=")) {
            op = Op::kLe;
            skip = 2;
        } else if (part.starts_with(">=")) {
            op = Op::kGe;
            skip = 2;
        } else if (part.starts_with('<')) {
            op = Op::kLt;
            skip = 1;
        } else if (part.starts_with('>')) {
            op = Op::kGt;
            skip = 1;
        } else if (part.starts_with('=')) {
            skip = 1;
        }
        part.remove_prefix(skip);
        if (part.empty() || part.front() == '<' || part.front() == '>' || part.front() == '=' ||
            part.front() == '!')
            return std::unexpected(std::string(kShape));
        auto version = detail::percent_decode(part);
        if (!version)
            return std::unexpected(version.error());
        r.constraints.push_back({op, std::move(*version)});
        if (bar == std::string_view::npos)
            break;
        body.remove_prefix(bar + 1);
    }
    return r;
}

/// Sort the constraints by version under `cmp` and refuse a list that is not a valid interval
/// list (see the file banner). `all` ranges are already in normal form.
template <class Cmp>
[[nodiscard]] std::expected<void, std::string> normalize(Range& r, Cmp&& cmp) {
    if (r.all)
        return {};
    std::ranges::stable_sort(r.constraints, [&](const Constraint& a, const Constraint& b) {
        return cmp(a.version, b.version) < 0;
    });
    bool have_prev = false;
    bool prev_lower = false;
    for (std::size_t i = 0; i < r.constraints.size(); ++i) {
        const Constraint& c = r.constraints[i];
        if (i > 0 && cmp(r.constraints[i - 1].version, c.version) == 0)
            return std::unexpected(std::string(kInvalidIntervalList));
        if (!detail::is_interval(c.op))
            continue;
        const bool lower = detail::is_lower(c.op);
        if (have_prev && prev_lower == lower)
            return std::unexpected(std::string(kInvalidIntervalList));
        have_prev = true;
        prev_lower = lower;
    }
    return {};
}

/// The VERS containment algorithm over a normalised (or from_bounds) Range.
template <class Cmp>
[[nodiscard]] bool contains(const Range& r, std::string_view v, Cmp&& cmp) {
    if (r.all)
        return true;
    bool has_eq = false;
    bool has_ne = false;
    std::vector<const Constraint*> iv;
    for (const auto& c : r.constraints) {
        if (c.op == Op::kEq) {
            if (cmp(v, c.version) == 0)
                return true;
            has_eq = true;
        } else if (c.op == Op::kNe) {
            if (cmp(v, c.version) == 0)
                return false;
            has_ne = true;
        } else {
            iv.push_back(&c);
        }
    }
    if (iv.empty())
        return !has_eq && has_ne; // only `!=`: every other version
    const Constraint& first = *iv.front();
    if (detail::is_upper(first.op) && in_interval(v, {}, false, first.version, first.op == Op::kLe, cmp))
        return true;
    const Constraint& last = *iv.back();
    if (detail::is_lower(last.op) && in_interval(v, last.version, last.op == Op::kGe, {}, false, cmp))
        return true;
    for (std::size_t i = 0; i + 1 < iv.size(); ++i) {
        const Constraint& lo = *iv[i];
        const Constraint& hi = *iv[i + 1];
        if (detail::is_lower(lo.op) && detail::is_upper(hi.op) &&
            in_interval(v, lo.version, lo.op == Op::kGe, hi.version, hi.op == Op::kLe, cmp))
            return true;
    }
    return false;
}

/// `version_min`/`version_max` (inclusive, an empty bound is open) as a Range. At least one bound
/// must be non-empty.
[[nodiscard]] inline Range from_bounds(std::string_view min, std::string_view max) {
    Range r;
    if (!min.empty())
        r.constraints.push_back({Op::kGe, std::string(min)});
    if (!max.empty())
        r.constraints.push_back({Op::kLe, std::string(max)});
    return r;
}

} // namespace yuzu::server::vers
