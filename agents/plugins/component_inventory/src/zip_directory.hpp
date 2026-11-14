#pragma once

/**
 * zip_directory.hpp - bounded ZIP central-directory reader.
 *
 * Pure: no file I/O, no inflate. The caller reads the last
 * min(file_size, kMaxTailBytes) bytes of an archive, asks
 * find_central_directory() where the directory is, reads exactly that range,
 * and walks it with for_each_central_entry(). Every length and offset in the
 * archive is attacker-chosen, so each one is checked against the bytes
 * actually in hand before it is used, every addition is overflow-checked, and
 * no container of all entries is ever built (the visitor sees one entry at a
 * time, so the entry count needs no cap of its own; the format allows at most
 * 65,534 without ZIP64).
 *
 * The limits are wide on purpose: an archive whose directory cannot be
 * enumerated makes the whole scan incomplete (ADR-0028 Decision 4), so a
 * limit below what ordinary large archives carry would hold a host's whole
 * answer back.
 *
 * An archive may have bytes in front of it (an executable jar's launch
 * script, a self-extractor stub) that its internal offsets do not count.
 * find_central_directory() measures them as ZipTail::prefix, the way Java's
 * ZipFile does: ZipTail::cd_offset is already absolute, and the local header
 * of an entry is at tail.prefix + entry.local_header_offset.
 *
 * The end record's entry count and the directory's length must agree. A
 * reader that walks the directory by its length (Python's zipfile does)
 * still sees every record, so a count lowered below the records really
 * present would hide entries from this reader that such a reader loads.
 * for_each_central_entry() refuses that directory; it never lists a part
 * of it as the whole.
 *
 * ZIP64, multi-disk archives and encrypted entries are refused, never
 * guessed at; the caller reports the archive as not enumerated.
 */

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace yuzu::component_inventory {

enum class ZipError {
    not_zip,
    truncated,
    zip64_unsupported,
    directory_too_large,
    bad_record,
};

struct ZipEntry {
    std::string_view name; // view into the caller's directory buffer
    std::uint16_t method{0};
    std::uint64_t comp_size{0};
    std::uint64_t uncomp_size{0};
    /// As written in the archive: relative to the archive start, NOT adjusted
    /// for ZipTail::prefix. The absolute file offset of the local header is
    /// tail.prefix + local_header_offset (local_data_offset() applies it).
    std::uint64_t local_header_offset{0};
};

struct ZipTail {
    /// ABSOLUTE file offset of the central directory (the end record's
    /// offset plus `prefix`): read cd_size bytes at exactly this offset.
    std::uint64_t cd_offset{0};
    std::uint64_t cd_size{0};
    std::uint32_t entries{0};
    /// Bytes in front of the archive proper (an executable jar's launch
    /// script, a self-extractor stub); 0 for an ordinary archive. The
    /// archive's internal offsets do not count these bytes.
    std::uint64_t prefix{0};
};

inline constexpr std::uint64_t kMaxCdBytes = 16ULL * 1024 * 1024;
inline constexpr std::size_t kMaxEntryNameLen = 1024;
/// End record (22) + the longest comment a 16-bit length can describe.
inline constexpr std::size_t kMaxTailBytes = 22 + 65535;
/// The fixed part of a local file header: what a caller reads at local_header_at() before
/// local_data_offset().
inline constexpr std::size_t kLocalHeaderLen = 30;

namespace zip_detail {

inline constexpr std::size_t kEocdLen = 22;
inline constexpr std::size_t kZip64LocatorLen = 20;
inline constexpr std::size_t kCentralHeaderLen = 46;
inline constexpr std::uint32_t kEocdSig = 0x06054b50U;
inline constexpr std::uint32_t kZip64LocatorSig = 0x07064b50U;
inline constexpr std::uint32_t kCentralSig = 0x02014b50U;
inline constexpr std::uint32_t kLocalSig = 0x04034b50U;
inline constexpr std::uint16_t kEncryptedFlag = 0x0001U;

// Callers guarantee off + width <= b.size() before calling.
inline std::uint16_t u16(std::span<const std::byte> b, std::size_t off) {
    return static_cast<std::uint16_t>(static_cast<unsigned>(b[off]) |
                                      (static_cast<unsigned>(b[off + 1]) << 8));
}

inline std::uint32_t u32(std::span<const std::byte> b, std::size_t off) {
    return static_cast<std::uint32_t>(u16(b, off)) |
           (static_cast<std::uint32_t>(u16(b, off + 2)) << 16);
}

inline std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) {
    if (b > UINT64_MAX - a)
        return std::nullopt;
    return a + b;
}

} // namespace zip_detail

/**
 * Locate the central directory from the archive tail.
 *
 * @param tail      the last min(file_size, kMaxTailBytes) bytes of the file
 * @param file_size total size of the file in bytes
 */
inline std::expected<ZipTail, ZipError> find_central_directory(std::span<const std::byte> tail,
                                                               std::uint64_t file_size) {
    using namespace zip_detail;
    if (tail.size() > file_size)
        return std::unexpected(ZipError::bad_record);
    if (tail.size() < kEocdLen)
        return std::unexpected(ZipError::not_zip);

    // Scan backwards. A candidate counts only if its comment length lands
    // exactly on the end of the buffer, so a signature planted inside the
    // archive comment (or in entry data) is skipped, not followed.
    for (std::size_t pos = tail.size() - kEocdLen + 1; pos-- > 0;) {
        if (u32(tail, pos) != kEocdSig)
            continue;
        if (static_cast<std::size_t>(u16(tail, pos + 20)) != tail.size() - pos - kEocdLen)
            continue;

        // ponytail: ZIP64 is refused. A ZIP64 archive is reported as not
        // enumerated and the scan as incomplete; upgrade path is to read the
        // ZIP64 end record via the locator and lift the 32-bit sentinels.
        if (pos >= kZip64LocatorLen && u32(tail, pos - kZip64LocatorLen) == kZip64LocatorSig)
            return std::unexpected(ZipError::zip64_unsupported);

        const std::uint16_t disk = u16(tail, pos + 4);
        const std::uint16_t cd_disk = u16(tail, pos + 6);
        const std::uint16_t entries_here = u16(tail, pos + 8);
        const std::uint16_t entries_total = u16(tail, pos + 10);
        const std::uint32_t cd_size = u32(tail, pos + 12);
        const std::uint32_t cd_offset = u32(tail, pos + 16);

        if (entries_here == 0xFFFFU || entries_total == 0xFFFFU || cd_size == 0xFFFFFFFFU ||
            cd_offset == 0xFFFFFFFFU)
            return std::unexpected(ZipError::zip64_unsupported);
        if (disk != 0 || cd_disk != 0 || entries_here != entries_total)
            return std::unexpected(ZipError::bad_record);
        // Refused from the end record alone, before any directory byte is read.
        if (cd_size > kMaxCdBytes)
            return std::unexpected(ZipError::directory_too_large);

        // The directory ends where this end record begins. Any gap between
        // the recorded cd_offset and where the directory really starts is the
        // prefix (as Java's ZipFile does); a directory that would start
        // before the recorded offset, or before byte 0, is malformed.
        const std::uint64_t eocd_abs = file_size - (tail.size() - pos);
        if (cd_size > eocd_abs)
            return std::unexpected(ZipError::bad_record);
        const std::uint64_t cd_abs = eocd_abs - cd_size;
        if (cd_offset > cd_abs)
            return std::unexpected(ZipError::bad_record);

        return ZipTail{cd_abs, cd_size, entries_total, cd_abs - cd_offset};
    }
    return std::unexpected(ZipError::not_zip);
}

/**
 * Visit exactly `declared_entries` central-directory records, one at a time.
 * `cd` must be the whole directory (ZipTail::cd_size bytes) and the count
 * must account for all of it: fewer records than declared is `truncated`;
 * any byte left after the last declared record (more records than the end
 * record counts, or stray bytes) is `bad_record`. That error is returned
 * after the declared records were visited, so a caller discards what it
 * collected on any error. on_entry(const ZipEntry&) returns false to stop
 * early without an error (the rest of the directory is then not checked).
 * ZipEntry::name points into `cd`.
 */
template <typename Fn>
std::expected<void, ZipError> for_each_central_entry(std::span<const std::byte> cd,
                                                     std::uint32_t declared_entries,
                                                     Fn&& on_entry) {
    using namespace zip_detail;
    std::size_t pos = 0;
    for (std::uint32_t i = 0; i < declared_entries; ++i) {
        if (cd.size() - pos < kCentralHeaderLen)
            return std::unexpected(ZipError::truncated);
        if (u32(cd, pos) != kCentralSig)
            return std::unexpected(ZipError::bad_record);

        const std::uint16_t flags = u16(cd, pos + 8);
        const std::uint32_t comp = u32(cd, pos + 20);
        const std::uint32_t uncomp = u32(cd, pos + 24);
        const std::size_t name_len = u16(cd, pos + 28);
        const std::size_t extra_len = u16(cd, pos + 30);
        const std::size_t comment_len = u16(cd, pos + 32);
        const std::uint16_t disk_start = u16(cd, pos + 34);
        const std::uint32_t local_off = u32(cd, pos + 42);

        if (comp == 0xFFFFFFFFU || uncomp == 0xFFFFFFFFU || local_off == 0xFFFFFFFFU)
            return std::unexpected(ZipError::zip64_unsupported);
        if ((flags & kEncryptedFlag) != 0 || disk_start != 0)
            return std::unexpected(ZipError::bad_record);
        if (name_len > kMaxEntryNameLen)
            return std::unexpected(ZipError::bad_record);

        // Three 16-bit lengths cannot overflow size_t; compare against the
        // bytes remaining after the fixed header before touching any of them.
        const std::size_t remaining = cd.size() - pos - kCentralHeaderLen;
        if (name_len + extra_len + comment_len > remaining)
            return std::unexpected(ZipError::truncated);

        // The span holds std::byte; view it as chars without a type pun.
        const char* name_ptr =
            static_cast<const char*>(static_cast<const void*>(cd.data() + pos + kCentralHeaderLen));
        ZipEntry entry;
        entry.name = std::string_view(name_ptr, name_len);
        entry.method = u16(cd, pos + 10);
        entry.comp_size = comp;
        entry.uncomp_size = uncomp;
        entry.local_header_offset = local_off;

        if (!static_cast<bool>(on_entry(static_cast<const ZipEntry&>(entry))))
            return {};

        pos += kCentralHeaderLen + name_len + extra_len + comment_len;
    }
    // Every directory byte must belong to a declared record. A directory
    // whose count is short of its records is refused, not recounted.
    if (pos != cd.size())
        return std::unexpected(ZipError::bad_record);
    return {};
}

/**
 * Absolute file offset of an entry's local header: tail.prefix +
 * entry.local_header_offset, overflow-checked (nullopt on overflow). A caller
 * never adds the prefix itself: that is the arithmetic the prepended-bytes
 * handling depends on.
 */
inline std::optional<std::uint64_t> local_header_at(const ZipTail& tail, const ZipEntry& entry) {
    return zip_detail::checked_add(tail.prefix, entry.local_header_offset);
}

/**
 * Absolute file offset of an entry's data, from its local header bytes
 * (the caller reads kLocalHeaderLen-or-more bytes at local_header_at(); the
 * local name/extra lengths may differ from the central ones, so they are read
 * here, not assumed). `prefix` is ZipTail::prefix; it is a required argument
 * so a caller cannot forget it.
 */
inline std::expected<std::uint64_t, ZipError> local_data_offset(
    std::span<const std::byte> local_header, const ZipEntry& entry, std::uint64_t prefix) {
    using namespace zip_detail;
    if (local_header.size() < kLocalHeaderLen)
        return std::unexpected(ZipError::truncated);
    if (u32(local_header, 0) != kLocalSig)
        return std::unexpected(ZipError::bad_record);
    const std::uint64_t var_len =
        static_cast<std::uint64_t>(u16(local_header, 26)) + u16(local_header, 28);
    const auto start = checked_add(prefix, entry.local_header_offset);
    const auto base = start ? checked_add(*start, kLocalHeaderLen) : std::nullopt;
    if (!base)
        return std::unexpected(ZipError::bad_record);
    const auto off = checked_add(*base, var_len);
    if (!off)
        return std::unexpected(ZipError::bad_record);
    return *off;
}

} // namespace yuzu::component_inventory
