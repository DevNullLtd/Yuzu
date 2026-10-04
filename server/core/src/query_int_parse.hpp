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
#include <cstdint>
#include <limits>
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

/// SSE replay cursor taken from a `Last-Event-ID` request HEADER (browser EventSource sets it on
/// its own auto-reconnect, so a malformed value is inference, not caller intent). A valid header
/// is one non-negative base-10 integer and replays events with id > value. A malformed one
/// (`-1`, `5abc`, empty, overflow) is served LIVE ONLY: `since_id` is the maximum cursor, which
/// no event id exceeds, so NOTHING is replayed (a cursor of 0 would replay the whole ring
/// buffer). `live_only` tells the caller to skip the replay-gap probe, where `since_id + 1` would
/// wrap. Shared by `/api/v1/events` and the workflow stream so the two cannot drift.
struct SseReplayCursor {
    std::uint64_t since_id{0};
    bool live_only{false};
};

[[nodiscard]] inline SseReplayCursor sse_cursor_from_header(std::string_view value) {
    if (const auto v = parse_query_int<long long>(value); v && *v >= 0)
        return {static_cast<std::uint64_t>(*v), false};
    return {std::numeric_limits<std::uint64_t>::max(), true};
}

/// A rollout percentage from a form/query value: EMPTY means `empty_default` (the route's own
/// documented default, 100 on the OTA routes), a malformed value is rejected (nullopt, the caller
/// answers 400 and stores nothing -- a typo must never become a full-fleet rollout), and a valid
/// integer is clamped to 0..100 as the routes have always documented. One helper for the OTA
/// upload route (multipart, which TestRouteSink cannot drive) and the rollout route, so a unit
/// test of THIS function covers both.
[[nodiscard]] inline std::optional<int> parse_rollout_pct(std::string_view s, int empty_default = 100) {
    if (s.empty())
        return empty_default;
    const auto v = parse_query_int<int>(s);
    if (!v)
        return std::nullopt;
    return *v < 0 ? 0 : (*v > 100 ? 100 : *v);
}

} // namespace yuzu::server
