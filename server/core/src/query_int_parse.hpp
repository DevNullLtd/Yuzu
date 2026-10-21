#pragma once

/// @file query_int_parse.hpp
/// Strict integer parsing for HTTP query parameters, shared by every REST route
/// family (#4644 and its sweep). Pure and I/O-free: no httplib.h, no store.
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
/// integer is clamped to 0..100 as the routes have always documented. Used by the OTA upload
/// route (multipart, which TestRouteSink cannot drive), so a unit test of THIS function covers
/// it; the rollout (change) route uses the stricter `parse_rollout_pct_strict` below.
[[nodiscard]] inline std::optional<int> parse_rollout_pct(std::string_view s, int empty_default = 100) {
    if (s.empty())
        return empty_default;
    const auto v = parse_query_int<int>(s);
    if (!v)
        return std::nullopt;
    return *v < 0 ? 0 : (*v > 100 ? 100 : *v);
}

/// The CHANGE-rollout variant of `parse_rollout_pct` (the route that edits an EXISTING package's
/// percentage; the upload route keeps the lenient one above). There a missing value must not
/// default to 100 and an over-range value must not clamp to 100: both would flip an existing
/// package to a FULL-FLEET rollout on a blank or typo'd field, so each is rejected (nullopt, the
/// caller answers 400 and changes nothing). A negative value keeps its documented clamp to 0 (the
/// least exposure, never a full-fleet value).
[[nodiscard]] inline std::optional<int> parse_rollout_pct_strict(std::string_view s) {
    if (s.empty())
        return std::nullopt;
    const auto v = parse_query_int<int>(s);
    if (!v || *v > 100)
        return std::nullopt;
    return *v < 0 ? 0 : *v;
}

/// Read the OPTIONAL `since`/`until` epoch-second bounds from a JSON request body into
/// presence-tracked optionals (#4644). `Json` is nlohmann's type, taken as a template parameter
/// so this header never includes it. A key that is ABSENT leaves its side unset (unbounded). A
/// PRESENT key must be one JSON integer in signed 64-bit range (a string, float, bool, null, or
/// a value above INT64_MAX is refused: `body.value("since", 0)` threw on those, an uncaught
/// exception, and a lenient reader would have turned them into "unbounded"). `since` must be
/// `>= 0` (a literal 0 is a harmless bound: every stored timestamp is positive, so it matches
/// exactly what an absent `since` matches); `until` must be `>= 1` (`until: 0` would bound the
/// read at the epoch and match nothing, and as a computed window that collapsed it used to read as
/// "the whole table"). Returns nullopt when accepted, else the 400 message for the caller to wrap
/// in its route's error envelope. Shared by the legacy and v1 inventory query routes so the two
/// cannot drift.
template <typename Json>
[[nodiscard]] std::optional<std::string> read_json_epoch_window(const Json& body,
                                                                std::optional<std::int64_t>& since,
                                                                std::optional<std::int64_t>& until) {
    const auto read = [&body](const char* key, std::optional<std::int64_t>& out) -> bool {
        if (!body.contains(key))
            return true;
        const auto& v = body[key];
        if (!v.is_number_integer())
            return false;
        if (v.is_number_unsigned() &&
            v.template get<std::uint64_t>() >
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            return false;
        out = v.template get<std::int64_t>();
        return true;
    };
    if (!read("since", since))
        return "since must be a JSON integer that fits in a signed 64-bit value";
    if (!read("until", until))
        return "until must be a JSON integer that fits in a signed 64-bit value";
    if (since && *since < 0)
        return "since must not be negative";
    if (until && *until <= 0)
        return "until must be a positive epoch second or omitted";
    return std::nullopt;
}

/// Strict JSON-body integer, the REST twin of mcp_server.cpp's `param_int_strict` (#4644). `Json`
/// is nlohmann's type, taken as a template parameter so this header never includes it. ABSENT
/// yields `def`. A PRESENT key must be one JSON integer in signed 64-bit range: a string, float,
/// bool, null, or a value above INT64_MAX yields nullopt (the caller answers 400), never a
/// truncation, a thrown type error, or a wrap to a different valid value. Range rules stay with
/// the caller. A `body` that is not a JSON object also yields `def`: a caller whose body is not
/// optional must reject a discarded or non-object document BEFORE calling (the engine-credential
/// mint does).
template <typename Json>
[[nodiscard]] std::optional<std::int64_t> read_json_int_strict(const Json& body, const char* key,
                                                                std::int64_t def) {
    if (!body.is_object() || !body.contains(key))
        return def;
    const auto& v = body[key];
    if (!v.is_number_integer())
        return std::nullopt;
    if (v.is_number_unsigned() &&
        v.template get<std::uint64_t>() >
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        return std::nullopt;
    return v.template get<std::int64_t>();
}

/// Read an OPTIONAL page-size `limit` from a JSON request body (#4644). `Json` is nlohmann's type,
/// taken as a template parameter so this header never includes it. ABSENT yields `default_value`.
/// A PRESENT key must be one JSON integer: a string, float, bool or null is refused (the old
/// `body.value("limit", 100)` threw on those or truncated a float), and the value is read as 64
/// bits so a large integer can no longer wrap through a narrower read (4294967297 read as int is
/// 1). An unsigned value above INT64_MAX saturates (it is then clamped like any other oversize
/// value). A value below 1 is refused; one above `max_value` is clamped to it, as these routes have
/// always documented. Returns nullopt when accepted (`out` holds the narrowed result), else the 400
/// message for the caller to wrap in its route's error envelope. Shared by the legacy and v1
/// inventory query routes so the two cannot drift.
template <typename Json>
[[nodiscard]] std::optional<std::string> read_json_page_limit(const Json& body, const char* key,
                                                              int default_value, int max_value,
                                                              int& out) {
    out = default_value;
    if (!body.contains(key))
        return std::nullopt;
    const auto& v = body[key];
    if (!v.is_number_integer())
        return std::string(key) + " must be a JSON integer";
    std::int64_t wide{};
    if (v.is_number_unsigned() &&
        v.template get<std::uint64_t>() >
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        wide = std::numeric_limits<std::int64_t>::max();
    else
        wide = v.template get<std::int64_t>();
    if (wide < 1)
        return std::string(key) + " must be at least 1";
    out = wide > max_value ? max_value : static_cast<int>(wide);
    return std::nullopt;
}

} // namespace yuzu::server
