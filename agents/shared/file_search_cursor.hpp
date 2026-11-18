// file_search_cursor.hpp -- the resume cursor of the on-demand file search, its wire token and the
// transition validator.
//
// Token = "fs1:" + padded base64 of a fixed-layout body (all integers little-endian):
//   version u8 = 1 | query_hash 16 bytes | sequence u64 | generation u32 | prior_gaps u32 |
//   root_dev u64 | root_file_id u64 | ndirs u8 | per dir: name_len u16, name, dev u64, file_id u64 |
//   after_len u16, after
// The body has one spelling per Cursor (fixed-width fields, explicit lengths, no trailing bytes)
// and the strict base64 decoder refuses every non-canonical base64 spelling, so decoding is
// canonical by construction: encode_cursor(decode_cursor(t)) == t for every accepted token. The
// unit tests and the cursor fuzz harness assert exactly that.
//
// Trust rule for consumers: the decoder is pure, it opens nothing. Cursor names are only ever
// COMPARED with the entries of a real directory listing, never joined into a path that is opened.
// There is no MAC or secret: a forged cursor can only move the resume point inside the same
// validated query (the query hash must match), which is the accepted design.
//
// Recovery: the agent keeps no cursor state. The same cursor replayed re-walks the same slice
// (duplicates possible, no skip of its own). A crash mid-slice issues no cursor, so the caller
// retries the previous one. A slice that completes the walk issues no cursor and may return the resume
// position itself, so strictly_advances applies only to a cursor that is issued. One cursor covers
// one root, so a failing volume never advances another volume's position.
// Retries of one cursor are counted by the caller and bounded (file_search_governor.hpp: stalls).
//
// Transitions: strictly_advances accepts exactly two, each with the same query hash,
// sequence + 1 (no wrap) and a non-decreasing prior_gaps.
//   ORDINARY: same generation, every root identity half the previous cursor knows unchanged (a half
//             that is 0 is unknown and may become known on any slice, not only the first; a known half
//             that changes or returns to 0 needs a generation step; the rule lives in
//             file_search_position.hpp) and a walk_order strictly later position.
//   RESTART:  generation + 1 (no wrap). The position and the root identity are then
//             unconstrained: the ordered walker restarts a replaced directory from its first entry
//             and a replaced root from its start, which legitimately returns an EARLIER position or
//             a new root identity.
// A backward or equal position without a generation step is always refused. How many restarts one
// search may take is bounded by the governor (max_restarts), not by this validator.
// Frame identities are NOT compared here, on purpose: the ordered walker is the one place that
// reads them (it restarts a frame whose known identity changed, and that slice arrives here as a
// RESTART). A comparison in this validator would be a second copy of the walker's rule. What no
// resume can detect is listed in the walker's banner (walk_ordered, NOT DETECTED).
//
// Coverage: gap rows are slice-local. The cursor carries only their running count (prior_gaps),
// so a final slice can never report complete after an earlier slice reported a gap. That count is
// caller-held and unauthenticated like the rest of the cursor: a caller that edits it degrades
// only its own answer.
//
// Platform-agnostic pure C++, no OS call, no I/O: the zero-dependency leaf-helper convention of
// this directory (docs/cpp-conventions.md).
#pragma once

#include "base64.hpp"
#include "file_search_position.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::shared::file_search {

inline constexpr std::string_view kCursorPrefix = "fs1:";
inline constexpr std::size_t kMaxCursorTokenBytes = 32 * 1024;

using QueryHash = std::array<std::uint8_t, 16>;

/// generation = how many times this root's walk has restarted after a replaced directory or root.
/// prior_gaps = the saturating count of gaps earlier slices reported. A search starts from
/// `Cursor{query_hash}`.
struct Cursor {
    QueryHash query_hash{};
    std::uint64_t sequence{0};
    std::uint32_t generation{0};
    std::uint32_t prior_gaps{0};
    Position position{};
    bool operator==(const Cursor&) const = default;
};

enum class CursorError {
    too_long,
    bad_prefix,
    bad_base64,
    bad_version,
    truncated,
    trailing_bytes,
    bad_position,
    query_mismatch
};

namespace detail {

inline constexpr std::uint8_t kCursorVersion = 1;

inline void put_le(std::string& out, std::uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i)
        out += static_cast<char>((v >> (8 * i)) & 0xFF);
}

/// The unvalidated body serialiser (ndirs and name lengths are cast to their field widths).
/// encode_cursor validates first; tests use this to craft hostile bodies.
[[nodiscard]] inline std::string cursor_body(const Cursor& c) {
    std::string b;
    b += static_cast<char>(kCursorVersion);
    b.append(reinterpret_cast<const char*>(c.query_hash.data()), c.query_hash.size());
    put_le(b, c.sequence, 8);
    put_le(b, c.generation, 4);
    put_le(b, c.prior_gaps, 4);
    put_le(b, c.position.root_dev, 8);
    put_le(b, c.position.root_file_id, 8);
    b += static_cast<char>(c.position.dirs.size() & 0xFF);
    for (const auto& f : c.position.dirs) {
        put_le(b, f.name.size(), 2);
        b += f.name;
        put_le(b, f.dev, 8);
        put_le(b, f.file_id, 8);
    }
    put_le(b, c.position.after.size(), 2);
    b += c.position.after;
    return b;
}

/// Bounds-checked little-endian reader; every take fails closed once the input is short.
class BodyReader {
public:
    explicit BodyReader(std::string_view s) noexcept : s_(s) {}
    [[nodiscard]] bool uint(std::uint64_t& v, int bytes) noexcept {
        if (s_.size() - at_ < static_cast<std::size_t>(bytes))
            return false;
        v = 0;
        for (int i = 0; i < bytes; ++i)
            v |= static_cast<std::uint64_t>(static_cast<unsigned char>(s_[at_ + static_cast<std::size_t>(i)]))
                 << (8 * i);
        at_ += static_cast<std::size_t>(bytes);
        return true;
    }
    [[nodiscard]] bool text(std::string& out, std::size_t n) {
        if (s_.size() - at_ < n)
            return false;
        out.assign(s_.substr(at_, n));
        at_ += n;
        return true;
    }
    [[nodiscard]] bool at_end() const noexcept { return at_ == s_.size(); }

private:
    std::string_view s_;
    std::size_t at_{0};
};

} // namespace detail

/// Empty for a Cursor whose position is not valid_position (a producer bug, or a listed name over
/// kMaxNameBytes; decode_cursor of the empty token is bad_prefix), so a hostile name can never be
/// written to the wire. Empty from a slice that did not complete is an error, never "finished".
[[nodiscard]] inline std::string encode_cursor(const Cursor& c) {
    if (!valid_position(c.position))
        return {};
    std::string token{kCursorPrefix};
    token += base64_encode(detail::cursor_body(c));
    return token;
}

[[nodiscard]] inline std::expected<Cursor, CursorError> decode_cursor(std::string_view token,
                                                                      const QueryHash& expected) {
    using E = CursorError;
    if (token.size() > kMaxCursorTokenBytes)
        return std::unexpected(E::too_long);
    if (!token.starts_with(kCursorPrefix))
        return std::unexpected(E::bad_prefix);
    const auto body = base64_decode(token.substr(kCursorPrefix.size()));
    if (!body)
        return std::unexpected(E::bad_base64);

    detail::BodyReader r(*body);
    std::uint64_t v = 0;
    if (!r.uint(v, 1))
        return std::unexpected(E::truncated);
    if (v != detail::kCursorVersion)
        return std::unexpected(E::bad_version);

    Cursor c;
    for (auto& byte : c.query_hash) {
        if (!r.uint(v, 1))
            return std::unexpected(E::truncated);
        byte = static_cast<std::uint8_t>(v);
    }
    if (!r.uint(c.sequence, 8))
        return std::unexpected(E::truncated);
    if (!r.uint(v, 4))
        return std::unexpected(E::truncated);
    c.generation = static_cast<std::uint32_t>(v);
    if (!r.uint(v, 4))
        return std::unexpected(E::truncated);
    c.prior_gaps = static_cast<std::uint32_t>(v);
    if (!r.uint(c.position.root_dev, 8) || !r.uint(c.position.root_file_id, 8))
        return std::unexpected(E::truncated);
    std::uint64_t ndirs = 0;
    if (!r.uint(ndirs, 1))
        return std::unexpected(E::truncated);
    for (std::uint64_t i = 0; i < ndirs; ++i) { // at most 255: a u8
        Frame f;
        std::uint64_t len = 0;
        if (!r.uint(len, 2) || !r.text(f.name, static_cast<std::size_t>(len)) || !r.uint(f.dev, 8) ||
            !r.uint(f.file_id, 8))
            return std::unexpected(E::truncated);
        c.position.dirs.push_back(std::move(f));
    }
    std::uint64_t after_len = 0;
    if (!r.uint(after_len, 2) || !r.text(c.position.after, static_cast<std::size_t>(after_len)))
        return std::unexpected(E::truncated);
    if (!r.at_end())
        return std::unexpected(E::trailing_bytes);
    if (!valid_position(c.position))
        return std::unexpected(E::bad_position);
    if (c.query_hash != expected)
        return std::unexpected(E::query_mismatch);
    return c;
}

/// The ONE place a transition is built: sequence + 1, generation + 1 when `restarted`,
/// prior_gaps + gaps_this_slice saturating at UINT32_MAX, the given position.
[[nodiscard]] inline Cursor next_cursor(const Cursor& previous, Position position, bool restarted,
                                        std::size_t gaps_this_slice) noexcept {
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint32_t>::max)();
    Cursor n;
    n.query_hash = previous.query_hash;
    n.sequence = previous.sequence + 1;
    n.generation = previous.generation + (restarted ? 1u : 0u);
    const std::uint64_t gaps = gaps_this_slice > kMax ? kMax : static_cast<std::uint64_t>(gaps_this_slice);
    const std::uint64_t total = static_cast<std::uint64_t>(previous.prior_gaps) + gaps;
    n.prior_gaps = static_cast<std::uint32_t>(total > kMax ? kMax : total);
    n.position = std::move(position);
    return n;
}

/// True for exactly the ORDINARY and RESTART transitions described in the banner.
[[nodiscard]] inline bool strictly_advances(const Cursor& previous, const Cursor& next) noexcept {
    if (previous.query_hash != next.query_hash)
        return false;
    if (previous.sequence == (std::numeric_limits<std::uint64_t>::max)() ||
        next.sequence != previous.sequence + 1)
        return false;
    if (next.prior_gaps < previous.prior_gaps)
        return false;
    if (previous.generation != (std::numeric_limits<std::uint32_t>::max)() &&
        next.generation == previous.generation + 1)
        return true; // RESTART: position and root identity are unconstrained
    if (next.generation != previous.generation)
        return false;
    const auto& p = previous.position;
    const auto& n = next.position;
    if (identity_changed(p.root_dev, p.root_file_id, n.root_dev, n.root_file_id))
        return false; // a known half changed or went back to unknown: that needs a generation step
    return walk_order(p, n) < 0;
}

} // namespace yuzu::shared::file_search
