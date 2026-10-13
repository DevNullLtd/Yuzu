#pragma once

/// @file list_keyset.hpp
/// Pure keyset-pagination primitives for newest-first lists ordered by `(order key DESC, id DESC)`:
/// a position, its opaque cursor token, and a strict bounded integer parse.
///
/// std-only, no I/O, no store, no transport include — safe for REST, MCP and a presentation-side
/// client to share. The cursor is a POSITION only: it carries no filter fingerprint, so changing a
/// filter mid-walk starts a different valid walk, never a wrong row (the order key never changes
/// after insert, so a position stays valid while the rows around it change). Visibility is NOT
/// part of the token either: a store must AND the caller's scope into the query alongside the
/// position, so a forged position can only ever narrow what the caller was already allowed to see.
///
/// Token shape: `<prefix><order_key>:<base64url(id)>`, e.g. `w1:1735689600:YWJj`. The prefix names
/// the list and its token version (`w1:` = workflow executions, v1). Decoding is strict and
/// canonical: a token that does not re-encode to exactly itself is refused, so each position has
/// exactly one spelling.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::keyset {

/// Upper bounds a decoded token must satisfy. `kCursorMaxBytes` is also the request-side cap the
/// REST and MCP parsers apply before decoding.
inline constexpr std::size_t kCursorMaxBytes = 2048;
inline constexpr std::size_t kIdMaxBytes = 128;

/// The `(order key, id)` of the last row a page served; the next page is every row strictly
/// older than it under the list's total order.
struct Position {
    std::int64_t key{0};
    std::string id;
    bool operator==(const Position&) const = default;
};

[[nodiscard]] std::string encode_cursor(std::string_view prefix, const Position& p);

/// nullopt for anything that is not exactly what `encode_cursor(prefix, p)` produces: wrong or
/// missing prefix, over `kCursorMaxBytes`, a non-canonical or negative key, an empty / over-long /
/// NUL-bearing id, or base64url that is not strictly canonical.
[[nodiscard]] std::optional<Position> decode_cursor(std::string_view prefix, std::string_view cursor);

/// Whole-string decimal parse into `[lo, hi]`: no sign other than `-`, no whitespace, no suffix,
/// nothing outside int64. nullopt when `s` is not exactly such an integer.
[[nodiscard]] std::optional<std::int64_t> parse_int(std::string_view s, std::int64_t lo,
                                                    std::int64_t hi);

} // namespace yuzu::server::keyset
