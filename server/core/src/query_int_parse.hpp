#pragma once

/// @file query_int_parse.hpp
/// Strict integer parsing for HTTP query parameters, shared by every REST route
/// family (#4644 and its Gate 7 sweep). Pure and I/O-free: no httplib.h, no store.
///
/// Why this exists: `std::stoi`/`std::stoll` accept leading digits followed by
/// anything (`stoi("0x1")` -> 0, `stoll("1e9")` -> 1, `stoi("100abc")` -> 100), so a
/// malformed filter or page size silently became a different, valid-looking one.
/// Overflow and the empty string already threw; what these add is rejecting every
/// value that is not ONE base-10 integer.

#include <charconv>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

namespace yuzu::server {

/// Full-consumption signed-integer parse: the WHOLE string must be one base-10
/// integer. Rejects empty, trailing garbage ("100abc", "1e9", "0x1"), embedded or
/// surrounding whitespace, a leading '+', and out-of-range values (no wraparound,
/// no clamping). A leading '-' is accepted (the range check is the caller's), and
/// zero-padding ("007") is accepted -- a client legitimately sending `status=007`
/// is not malformed, unlike a stored value that must round-trip.
template <typename T>
[[nodiscard]] std::optional<T> parse_query_int(std::string_view s) {
    static_assert(std::is_integral_v<T> && std::is_signed_v<T>);
    T v{};
    const char* const begin = s.data();
    const char* const end = begin + s.size();
    const auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return v;
}

/// Drop-in replacements for `std::stoi` / `std::stoll` at call sites that already
/// wrap the parse in `try { ... } catch (const std::exception&) { 400 }`: same
/// shape, but a value that is not ONE base-10 integer throws `std::invalid_argument`
/// instead of being silently truncated at the first non-digit.
[[nodiscard]] inline int strict_stoi(std::string_view s) {
    if (const auto v = parse_query_int<int>(s))
        return *v;
    throw std::invalid_argument("not a base-10 integer");
}

[[nodiscard]] inline long long strict_stoll(std::string_view s) {
    if (const auto v = parse_query_int<long long>(s))
        return *v;
    throw std::invalid_argument("not a base-10 integer");
}

} // namespace yuzu::server
