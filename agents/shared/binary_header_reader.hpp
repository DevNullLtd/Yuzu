/**
 * binary_header_reader.hpp -- the one bounded byte reader and endian loader shared by the PE, ELF
 * and Mach-O header readers. Leaf: STL only, no OS header, no I/O of its own, no logging, nothing
 * thrown by design (allocation aside).
 *
 * Every offset and length a header field names is attacker-chosen. This file is the single place
 * that decides whether a read of the SOURCE is in range, in budget and answered honestly. The
 * format readers add only format-level range checks (a range inside one section, segment, slice
 * or buffer), each written overflow-safe: subtraction form, checked_add / checked_mul, or sums
 * of values already capped.
 */

#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::shared::binary_header {

enum class ParseError { io, truncated, not_this_format, malformed, limit_exceeded };

[[nodiscard]] constexpr std::string_view to_token(ParseError e) noexcept {
    switch (e) {
    case ParseError::io: return "io";
    case ParseError::truncated: return "truncated";
    case ParseError::not_this_format: return "not_this_format";
    case ParseError::malformed: return "malformed";
    case ParseError::limit_exceeded: return "limit_exceeded";
    }
    return "unknown";
}

// nullopt = I/O error; fewer bytes than asked only at end of data. This is the contract of
// FileView::read_at (component_walk.hpp), so a caller passes {fv.read_at, fv.size}, and checks
// fv.unchanged() afterwards: a file rewritten between two reads parses torn and nothing says so.
using ReadAt = std::function<std::optional<std::string>(std::uint64_t offset, std::size_t len)>;

struct Source {
    ReadAt read_at;
    std::uint64_t size{0};
};

// BORROWS: the returned Source holds a pointer into `bytes`; the caller keeps those bytes alive
// for as long as the Source (or any Reader built from it) is used. The reinterpret_cast is
// std::byte to char: char may alias any object and has no alignment requirement, and the bytes
// are only read (const).
[[nodiscard]] inline Source span_source(std::span<const std::byte> bytes) {
    return Source{[bytes](std::uint64_t offset, std::size_t len) -> std::optional<std::string> {
                      if (offset >= bytes.size())
                          return std::string{};
                      const std::size_t n =
                          len < bytes.size() - static_cast<std::size_t>(offset)
                              ? len
                              : bytes.size() - static_cast<std::size_t>(offset);
                      return std::string(reinterpret_cast<const char*>(bytes.data()) + offset, n);
                  },
                  bytes.size()};
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add(std::uint64_t a,
                                                                 std::uint64_t b) noexcept {
    if (b > UINT64_MAX - a)
        return std::nullopt;
    return a + b;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_mul(std::uint64_t a,
                                                                 std::uint64_t b) noexcept {
    if (a != 0 && b > UINT64_MAX / a)
        return std::nullopt;
    return a * b;
}

// The shared endian decision: bounds-checked, byte-wise (no alignment or host-order assumption).
template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> load(std::string_view bytes, std::size_t off,
                                              std::endian order) noexcept {
    if (off > bytes.size() || sizeof(T) > bytes.size() - off)
        return std::nullopt;
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        const auto b = static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[off + i]));
        const std::size_t shift = order == std::endian::little ? i : sizeof(T) - 1 - i;
        v |= b << (8 * shift);
    }
    return static_cast<T>(v);
}

// Total work one Reader may ask of its Source.
struct ReadBudget {
    std::uint64_t max_bytes{4ull * 1024 * 1024};
    std::size_t max_reads{4096};
};

class Reader {
public:
    explicit Reader(const Source& src, ReadBudget budget = {}) : src_(src), budget_(budget) {}
    Reader(const Reader&) = delete; // a copy would carry its own counters and fork the budget
    Reader& operator=(const Reader&) = delete;

    // truncated: offset+len overflows or passes the source size. limit_exceeded: either budget
    // would be passed; both decided BEFORE read_at is called. io: read_at is empty or gave nullopt.
    // truncated: read_at answered fewer than len bytes. malformed: it answered more.
    [[nodiscard]] std::expected<std::string, ParseError> read(std::uint64_t offset,
                                                              std::size_t len) {
        const auto end = checked_add(offset, len);
        if (!end || *end > src_.size)
            return std::unexpected(ParseError::truncated);
        // bytes_ <= max_bytes always holds: it only grows by a len this test has admitted.
        if (len > budget_.max_bytes - bytes_ || reads_ >= budget_.max_reads)
            return std::unexpected(ParseError::limit_exceeded);
        if (!src_.read_at)
            return std::unexpected(ParseError::io);
        bytes_ += len;
        ++reads_;
        auto got = src_.read_at(offset, len);
        if (!got)
            return std::unexpected(ParseError::io);
        if (got->size() > len)
            return std::unexpected(ParseError::malformed);
        if (got->size() < len)
            return std::unexpected(ParseError::truncated);
        return std::move(*got);
    }

    // Reads min(max_len, size - offset) bytes and returns them up to the first NUL (excluded).
    // limit_exceeded when none of those bytes is a NUL.
    [[nodiscard]] std::expected<std::string, ParseError> read_c_string(std::uint64_t offset,
                                                                       std::size_t max_len) {
        if (offset > src_.size)
            return std::unexpected(ParseError::truncated);
        const std::uint64_t avail = src_.size - offset;
        const std::size_t n = max_len < avail ? max_len : static_cast<std::size_t>(avail);
        auto got = read(offset, n);
        if (!got)
            return got;
        const auto nul = got->find('\0');
        if (nul == std::string::npos)
            return std::unexpected(ParseError::limit_exceeded);
        got->resize(nul);
        return got;
    }

    [[nodiscard]] std::uint64_t size() const noexcept { return src_.size; }

private:
    Source src_;
    ReadBudget budget_;
    std::uint64_t bytes_{0};
    std::size_t reads_{0};
};

} // namespace yuzu::shared::binary_header
