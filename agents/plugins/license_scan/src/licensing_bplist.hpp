/**
 * licensing_bplist.hpp — bounded top-level string lookup in a binary property
 * list (`bplist00`), for the license_scan macOS mas_receipt surface (SAM.10).
 *
 * PURE and plugin-local: bytes in, optional<string> out. No filesystem, no
 * CoreFoundation, no allocation beyond the returned string. It reads exactly
 * one thing — the string value of a named key in the TOP-LEVEL dictionary
 * (CFBundleDisplayName / CFBundleName / CFBundleShortVersionString of an
 * app's Info.plist) — and refuses everything else: nested containers, ints,
 * dates, data, uids and every string that is not 7-bit ASCII (marker 0x5x) or
 * UTF-16BE (marker 0x6x, accepted as a value only, never as a key) are
 * `nullopt`, never a partial answer.
 *
 * Hostile input is the design case (an Info.plist is writable by whoever owns
 * the bundle). Every length, offset, count and reference in the file is an
 * attacker-controlled unsigned 64-bit value, so:
 *   - each value is compared against its cap BEFORE it is used in arithmetic,
 *     an index or a size_t conversion;
 *   - every bounds check is written in SUBTRACTION form against a bound that
 *     was itself validated first (`n <= limit - pos` after `pos <= limit`),
 *     never as "position plus length, compared with the limit", which wraps
 *     for a crafted length;
 *   - there is no recursion and no loop whose trip count is not capped
 *     (objects <= kBplistMaxObjects, dict entries <= objects);
 *   - a key is compared in place, never materialised, so a dictionary whose
 *     key references all point at one large string cannot multiply a copy.
 * Any structural defect in the file layout (bad trailer, offset table not
 * inside the file) or in an object on the path the lookup actually examines
 * (an object offset outside the object region, a reference >= object count, a
 * lone UTF-16 surrogate) returns nullopt for the whole lookup. The lookup
 * stops at the first matching key, so a defect in a later dictionary entry or
 * in an object it never visits does not affect a lookup that resolved before
 * reaching it.
 *
 * Format reference: Apple CFBinaryPList.c. Layout: 8-byte "bplist00" header,
 * objects, an offset table (one big-endian offset per object), then a 32-byte
 * trailer {5 unused, sort version, offset_size, ref_size, num_objects(u64),
 * top_object(u64), offset_table_offset(u64)}.
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_BPLIST_HPP
#define YUZU_LICENSE_SCAN_LICENSING_BPLIST_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::license_scan {

/// Most objects a plist may declare (an app Info.plist holds tens to a few
/// hundred). Also bounds the dictionary entry count and the offset table.
inline constexpr std::size_t kBplistMaxObjects = 65536;

/// Longest string payload accepted, in bytes (UTF-16: 2 bytes per unit).
inline constexpr std::size_t kBplistMaxStringBytes = 64 * 1024;

namespace bplist_detail {

using Bytes = std::span<const std::uint8_t>;

inline constexpr std::size_t kHeaderSize = 8;
inline constexpr std::size_t kTrailerSize = 32;

/// `n` bytes at `pos`, big-endian. The caller has already proved n <= 8 and
/// n <= size - pos.
[[nodiscard]] inline std::uint64_t read_be(Bytes b, std::size_t pos, std::size_t n) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i)
        v = (v << 8) | b[pos + i];
    return v;
}

[[nodiscard]] inline bool valid_width(std::size_t w) noexcept {
    return w == 1 || w == 2 || w == 4 || w == 8;
}

/// The validated shape of one plist. Built once by parse_layout; every later
/// read is relative to these already-checked bounds.
struct Layout {
    Bytes bytes;
    std::size_t offset_size = 0;
    std::size_t ref_size = 0;
    std::size_t num_objects = 0;
    std::size_t table_start = 0; ///< offset table start == end of the object region
    std::uint64_t top_object = 0;
};

[[nodiscard]] inline std::optional<Layout> parse_layout(Bytes bytes) noexcept {
    constexpr std::string_view kMagic = "bplist00";
    if (bytes.size() < kHeaderSize + kTrailerSize)
        return std::nullopt;
    for (std::size_t i = 0; i < kMagic.size(); ++i) {
        if (bytes[i] != static_cast<std::uint8_t>(kMagic[i]))
            return std::nullopt;
    }

    const std::size_t trailer = bytes.size() - kTrailerSize;
    const std::size_t offset_size = bytes[trailer + 6];
    const std::size_t ref_size = bytes[trailer + 7];
    if (!valid_width(offset_size) || !valid_width(ref_size))
        return std::nullopt;

    // num_objects first: once it is <= kBplistMaxObjects, the offset-table
    // byte count below (<= 65536 * 8) cannot overflow anything.
    const std::uint64_t num_objects = read_be(bytes, trailer + 8, 8);
    if (num_objects < 1 || num_objects > kBplistMaxObjects)
        return std::nullopt;
    // top_object is NOT range-checked here: object_offset() is its only consumer
    // and rejects index >= num_objects itself.
    const std::uint64_t top_object = read_be(bytes, trailer + 16, 8);

    // The offset table lies after the header and ends at or before the
    // trailer. Both ends are compared against already-validated bounds.
    const std::uint64_t table_start = read_be(bytes, trailer + 24, 8);
    const std::uint64_t region_end = trailer;
    if (table_start < kHeaderSize || table_start > region_end)
        return std::nullopt;
    const std::uint64_t table_bytes = num_objects * offset_size;
    if (table_bytes > region_end - table_start)
        return std::nullopt;

    Layout l;
    l.bytes = bytes;
    l.offset_size = offset_size;
    l.ref_size = ref_size;
    l.num_objects = static_cast<std::size_t>(num_objects);
    l.table_start = static_cast<std::size_t>(table_start);
    l.top_object = top_object;
    return l;
}

/// Start of object `index` (caller has proved index < num_objects), or
/// nullopt when its stored offset is not inside the object region.
[[nodiscard]] inline std::optional<std::size_t> object_offset(const Layout& l,
                                                              std::uint64_t index) noexcept {
    if (index >= l.num_objects)
        return std::nullopt;
    // index < num_objects and the table fits before the trailer (parse_layout),
    // so this position and its read are in range.
    const auto slot = static_cast<std::size_t>(index);
    const std::size_t pos = l.table_start + slot * l.offset_size;
    const std::uint64_t off = read_be(l.bytes, pos, l.offset_size);
    if (off < kHeaderSize || off >= l.table_start)
        return std::nullopt;
    return static_cast<std::size_t>(off);
}

/// A container/string length plus where its payload begins.
struct Counted {
    std::uint64_t count = 0;
    std::size_t payload = 0; ///< first byte after the marker (and extended length)
};

/// Decode the count of the object at `off` (off < table_start). Low marker
/// nibble 0..14 is the count; 0xF means an int object follows (1, 2, 4 or 8
/// bytes, read unsigned — an 8-byte "negative" is just a huge count that the
/// caller's cap then rejects).
[[nodiscard]] inline std::optional<Counted> read_counted(const Layout& l,
                                                         std::size_t off) noexcept {
    const std::uint8_t nibble = l.bytes[off] & 0x0F;
    if (nibble != 0x0F)
        return Counted{nibble, off + 1};

    // Need the int marker byte AND at least one payload byte inside the region.
    if (l.table_start - off < 2)
        return std::nullopt;
    const std::uint8_t im = l.bytes[off + 1];
    if ((im >> 4) != 0x1 || (im & 0x0F) > 3)
        return std::nullopt;
    const std::size_t nbytes = std::size_t{1} << (im & 0x0F);
    const std::size_t int_start = off + 2; // <= table_start (table_start - off >= 2)
    if (nbytes > l.table_start - int_start)
        return std::nullopt;
    return Counted{read_be(l.bytes, int_start, nbytes), int_start + nbytes};
}

/// True iff the string object at `off` is exactly the ASCII `key`. No
/// allocation; the work is bounded by key.size(). Only marker 0x5x can match:
/// CoreFoundation writes a string as ASCII (0x5x) whenever it round-trips as
/// ASCII, and the Info.plist keys looked up here always do, so a UTF-16 (0x6x)
/// object never names one of them. (Values are different: see decode_string.)
[[nodiscard]] inline bool string_equals(const Layout& l, std::size_t off,
                                        std::string_view key) noexcept {
    if ((l.bytes[off] >> 4) != 0x5)
        return false;
    const auto c = read_counted(l, off);
    if (!c || c->count != key.size())
        return false;
    if (key.size() > l.table_start - c->payload)
        return false;
    for (std::size_t i = 0; i < key.size(); ++i) {
        if (l.bytes[c->payload + i] != static_cast<std::uint8_t>(key[i]))
            return false;
    }
    return true;
}

inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

/// Decode the string object at `off` to UTF-8: 0x5x ASCII (7-bit only — a high
/// byte would put invalid UTF-8 on the wire) or 0x6x UTF-16BE (surrogates must
/// pair). Anything else, or any bound violation, is nullopt.
[[nodiscard]] inline std::optional<std::string> decode_string(const Layout& l,
                                                              std::size_t off) {
    const std::uint8_t kind = l.bytes[off] >> 4;
    if (kind != 0x5 && kind != 0x6)
        return std::nullopt;
    const auto c = read_counted(l, off);
    if (!c)
        return std::nullopt;

    // Cap the count BEFORE forming a byte length from it.
    const std::size_t unit = kind == 0x5 ? 1 : 2;
    if (c->count > kBplistMaxStringBytes / unit)
        return std::nullopt;
    const std::size_t count = static_cast<std::size_t>(c->count);
    const std::size_t nbytes = count * unit;
    if (nbytes > l.table_start - c->payload)
        return std::nullopt;

    std::string out;
    if (kind == 0x5) {
        out.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t b = l.bytes[c->payload + i];
            if (b >= 0x80)
                return std::nullopt;
            out.push_back(static_cast<char>(b));
        }
        return out;
    }

    const auto unit_at = [&](std::size_t i) -> std::uint32_t {
        return (static_cast<std::uint32_t>(l.bytes[c->payload + 2 * i]) << 8) |
               l.bytes[c->payload + 2 * i + 1];
    };
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint32_t u = unit_at(i);
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (count - i < 2)
                return std::nullopt; // high surrogate with nothing after it
            const std::uint32_t lo = unit_at(i + 1);
            if (lo < 0xDC00 || lo > 0xDFFF)
                return std::nullopt;
            append_utf8(out, 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
            ++i;
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            return std::nullopt; // low surrogate with no high before it
        } else {
            append_utf8(out, u);
        }
    }
    return out;
}

} // namespace bplist_detail

/// String value of `key` in the top-level dictionary of the `bplist00` image
/// `bytes`, as UTF-8. nullopt when the key is absent, its value is not an
/// ASCII/UTF-16 string, or the image is malformed in any way. `key` must be
/// plain ASCII (the three Info.plist keys); a non-ASCII `key` is nullopt.
/// First match wins when a (malformed) dictionary repeats a key.
[[nodiscard]] inline std::optional<std::string> bplist_string_for_key(
    std::span<const std::uint8_t> bytes, std::string_view key) {
    using namespace bplist_detail;
    for (const char ch : key) {
        if (static_cast<std::uint8_t>(ch) >= 0x80)
            return std::nullopt;
    }
    const auto layout = parse_layout(bytes);
    if (!layout)
        return std::nullopt;
    const Layout& l = *layout;

    const auto top = object_offset(l, l.top_object);
    if (!top || (l.bytes[*top] >> 4) != 0xD)
        return std::nullopt;
    const auto dict = read_counted(l, *top);
    if (!dict || dict->count > l.num_objects)
        return std::nullopt;
    const std::size_t count = static_cast<std::size_t>(dict->count);

    // count <= 65536 and ref_size <= 8, so this cannot overflow; the whole
    // reference block (keys then values) must sit inside the object region.
    const std::size_t refs_bytes = 2 * count * l.ref_size;
    if (refs_bytes > l.table_start - dict->payload)
        return std::nullopt;
    const std::size_t keys_at = dict->payload;
    const std::size_t values_at = keys_at + count * l.ref_size;

    for (std::size_t k = 0; k < count; ++k) {
        const std::uint64_t key_ref = read_be(l.bytes, keys_at + k * l.ref_size, l.ref_size);
        const auto key_off = object_offset(l, key_ref);
        if (!key_off)
            return std::nullopt;
        if (!string_equals(l, *key_off, key))
            continue;
        const std::uint64_t value_ref = read_be(l.bytes, values_at + k * l.ref_size, l.ref_size);
        const auto value_off = object_offset(l, value_ref);
        if (!value_off)
            return std::nullopt;
        return decode_string(l, *value_off);
    }
    return std::nullopt;
}

} // namespace yuzu::license_scan

#endif // YUZU_LICENSE_SCAN_LICENSING_BPLIST_HPP
