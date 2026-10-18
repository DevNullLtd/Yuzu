#pragma once

/// @file model_param_helpers.hpp
/// Query-parameter and cursor-payload helpers shared by the pure REST/MCP read models
/// (`software_catalogue_model.cpp`, `crypto_library_model.cpp`). Both models parse the same
/// `std::multimap` parameter bag, refuse the same unbindable text, and encode their keyset
/// cursors with the same length-prefixed payload and FNV-1a filter fingerprint, so the helpers
/// live ONCE here (review #6056 A10) rather than as two copies that could drift.
///
/// Pure: no httplib, no MCP, no libpq, no store types. Every function is `inline` (header-only),
/// so both translation units see one definition.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "utf8_sanitize.hpp"

namespace yuzu::server::model_detail {

/// Field separator of a length-prefixed payload (ASCII unit separator).
inline constexpr char kSep = '\x1f';

using Params = std::multimap<std::string, std::string>;

/// True for text Postgres can bind: strict UTF-8 and no NUL. Anything else would surface as a
/// store error (SQLSTATE 22021) and be reported as a retryable 503 instead of a caller 400.
[[nodiscard]] inline bool valid_text(std::string_view v) {
    return v.find('\0') == std::string_view::npos && ::yuzu::server::sanitize_utf8_strict(v) == v;
}

/// Value of `key`, or nullptr when absent. A repeated key sets `err` (and yields nullptr): the
/// values differ, since identical pairs collapse in the HTTP layer.
[[nodiscard]] inline const std::string* find_param(const Params& p, const std::string& key,
                                                   std::optional<std::string>& err) {
    const auto [lo, hi] = p.equal_range(key);
    if (lo == hi)
        return nullptr;
    if (std::next(lo) != hi) {
        err = "repeated query parameter " + key;
        return nullptr;
    }
    return &lo->second;
}

/// Full-consume signed decimal; nullopt on any defect (empty, sign-only, trailing bytes, range).
[[nodiscard]] inline std::optional<std::int64_t> parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    return v;
}

/// Digits only (no sign), full-consume, within int64; nullopt otherwise.
[[nodiscard]] inline std::optional<std::int64_t> parse_nonneg(std::string_view s) {
    if (s.empty() || !std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return parse_i64(s);
}

/// `<len>:<bytes>` + kSep per field: no byte content (the separator included) can shift a field
/// boundary.
[[nodiscard]] inline std::string
length_prefixed(std::initializer_list<const std::string*> fields) {
    std::string s;
    for (const std::string* f : fields) {
        s += std::to_string(f->size());
        s += ':';
        s += *f;
        s += kSep;
    }
    return s;
}

/// Inverse of length_prefixed(): exactly `n` `<len>:<bytes>` + kSep fields, nothing before or
/// after. The length is a full-consume decimal and is checked against what remains before any
/// span is taken, so no field content (the separator included) can move a boundary. The views
/// point into `in`, which must outlive them.
[[nodiscard]] inline std::optional<std::vector<std::string_view>>
read_length_prefixed(std::string_view in, std::size_t n) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto colon = in.find(':', pos);
        if (colon == std::string_view::npos)
            return std::nullopt;
        const auto len = parse_nonneg(in.substr(pos, colon - pos));
        const std::size_t remaining = in.size() - (colon + 1);
        // the field plus its trailing separator must fit
        if (!len || static_cast<std::uint64_t>(*len) >= remaining)
            return std::nullopt;
        const auto end = colon + 1 + static_cast<std::size_t>(*len);
        if (in[end] != kSep)
            return std::nullopt;
        out.push_back(in.substr(colon + 1, static_cast<std::size_t>(*len)));
        pos = end + 1;
    }
    if (pos != in.size())
        return std::nullopt;
    return out;
}

/// 64-bit FNV-1a of `s` as 16 lowercase hex digits (a cursor's filter fingerprint: a binding,
/// not an authenticator).
[[nodiscard]] inline std::string fnv1a_hex16(std::string_view s) {
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : s) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 1099511628211ULL;
    }
    return std::format("{:016x}", h);
}

[[nodiscard]] inline bool is_lower_hex16(std::string_view s) {
    return s.size() == 16 && std::ranges::all_of(s, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

} // namespace yuzu::server::model_detail
