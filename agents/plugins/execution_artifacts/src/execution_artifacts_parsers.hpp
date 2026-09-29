#pragma once

/**
 * execution_artifacts_parsers.hpp — pure binary/text parsers for the three
 * execution-artifact sources this plugin reads: the AppCompatCache
 * ("ShimCache") registry value, the Amcache `InventoryApplicationFile`
 * subkey, and Prefetch (`.pf`) files.
 *
 * Header-only and OS-free (firewall_parsers.hpp / power_health_parsers.hpp
 * precedent): every function here takes a plain `std::span<const uint8_t>`
 * or already-decoded text, NEVER a live registry handle or Windows type, so
 * the whole surface is unit-tested on every host. The impure shell (P32's
 * execution_artifacts_win.cpp) owns every Windows API call and hands its raw
 * bytes to these functions through that span boundary.
 *
 * Never throws. Every fallible function returns `std::expected<T,
 * ParseError>` — a byte-count sniff, a magic mismatch, or a size field the
 * remaining buffer cannot back are all ORDINARY, EXPECTED outcomes for
 * artifacts this plugin does not control the shape of, never a crash.
 *
 * BOUNDED BY CONSTRUCTION: every count read from untrusted input is checked
 * against both a hard cap AND the actual remaining buffer size BEFORE it is
 * used to size a loop or reserve() a container — see this package's spec
 * ("boundaries": parsers never allocate proportional to an untrusted count
 * before bounds-checking it against the buffer size).
 *
 * Byte-order note (firewall_parsers.hpp precedent): every multi-byte field
 * below is little-endian on the wire, and every deployment target this repo
 * builds for (x86_64, ARM64) is itself little-endian, so a plain memcpy into
 * a same-width integer reads them correctly — no byte-swapping helper is
 * needed or used.
 *
 * PREFETCH VERSION NOTE (load-bearing, differs from earlier planning). Every
 * REAL captured Windows 10/11 `.pf.decompressed` fixture (A1's capture,
 * 2026-09-06) carries version DWORD 31 (0x1F) at offset 0, not 30 — 30 is
 * the Windows 8.1 format version; Windows 10/11 moved to 31. The run-count
 * field for that format was likewise verified BY OFFSET against the real
 * fixtures (cross-checked against each file's own recorded invocation
 * count) to sit at absolute offset 0xC8, not 0xD0 — see
 * `kFileInfoV26V30V31RunCountOffset`'s comment for the byte-level evidence.
 * Versions 26/30 share this same trailing layout per libscca's documented
 * FILE_INFORMATION_26 structure; version 31 was verified to match it too.
 */

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <expected>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <span>
#include <utility>
#include <vector>

namespace yuzu::execution_artifacts {

/// One typed parse failure. `token` is a short machine-stable reason (see
/// the file header's token list); `offset` is the byte offset into the
/// input span where the failure was detected, for diagnostics only.
struct ParseError {
    std::string token;
    size_t offset{0};
};

template <class T>
using Result = std::expected<T, ParseError>;

namespace detail {

inline ParseError err(std::string_view token, size_t offset) {
    return ParseError{std::string{token}, offset};
}

/// Reads a little-endian POD of width `sizeof(T)` at `offset`, bounds-checked
/// against `in.size()`. `token` names the failure this call site attributes
/// a short read to (callers use context-specific tokens: truncated_header
/// vs truncated_entry).
template <class T>
Result<T> read_le(std::span<const uint8_t> in, size_t offset, std::string_view token) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset + sizeof(T) > in.size())
        return std::unexpected(err(token, offset));
    T v{};
    std::memcpy(&v, in.data() + offset, sizeof(T));
    return v;
}

inline Result<uint16_t> read_u16(std::span<const uint8_t> in, size_t offset,
                                  std::string_view token) {
    return read_le<uint16_t>(in, offset, token);
}
inline Result<uint32_t> read_u32(std::span<const uint8_t> in, size_t offset,
                                  std::string_view token) {
    return read_le<uint32_t>(in, offset, token);
}
inline Result<uint64_t> read_u64(std::span<const uint8_t> in, size_t offset,
                                  std::string_view token) {
    return read_le<uint64_t>(in, offset, token);
}

/// FILETIME (100ns ticks since 1601-01-01) -> Unix epoch milliseconds.
/// A raw value smaller than the 1601->1970 delta cannot be a valid post-1970
/// timestamp (a zeroed/uninitialised field, most commonly) and maps to 0
/// rather than an underflowed negative — same honest-sentinel convention as
/// tar_mapdrive_collector.cpp's filetime_to_epoch, adapted to milliseconds.
constexpr uint64_t kFiletimeEpochDelta100ns = 116444736000000000ULL;
inline int64_t filetime_to_epoch_ms(uint64_t ticks100ns) {
    if (ticks100ns < kFiletimeEpochDelta100ns)
        return 0;
    return static_cast<int64_t>((ticks100ns - kFiletimeEpochDelta100ns) / 10000ULL);
}

/// UTF-16LE -> UTF-8, replacing anything outside the BMP fast path with '?'
/// (this plugin only ever decodes filesystem paths and executable names —
/// never displaying untrusted text at a security boundary that would need a
/// stricter decoder). A lone/invalid surrogate is likewise replaced, never
/// propagated as a decode failure — the caller already has a bounds-checked
/// byte range; a malformed code unit inside it is not a reason to fail the
/// whole parse.
inline std::string utf16le_to_utf8(std::span<const uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size()); // pessimistic (ASCII shrinks 2:1) but O(1) and bounded by bytes.size()
    size_t i = 0;
    while (i + 1 < bytes.size()) {
        uint16_t unit = static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
        i += 2;
        uint32_t cp = unit;
        if (unit >= 0xD800 && unit <= 0xDBFF && i + 1 < bytes.size()) {
            uint16_t low =
                static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + ((static_cast<uint32_t>(unit) - 0xD800) << 10) +
                     (static_cast<uint32_t>(low) - 0xDC00);
                i += 2;
            } else {
                cp = '?';
            }
        } else if (unit >= 0xD800 && unit <= 0xDFFF) {
            cp = '?';
        }
        if (cp == 0) // NUL-terminated fixed-width fields (Prefetch exe_name)
            break;
        if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
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
    return out;
}

} // namespace detail

// ─────────────────────────────────────────────────────────── ShimCache ────
//
// AppCompatCache ("ShimCache") registry value layout, Windows 10/11
// ("win10" scheme — the only scheme this parser targets; earlier XP/7/8
// layouts use a different, unsupported header and entry shape and sniff to
// `unknown_version`).
//
//   offset 0                     header size / scheme sniff (DWORD): 0x34 or
//                                0x30 identify the win10 scheme; anything
//                                else is unknown_version
//   [header_size .. entries)     one entry per iteration:
//     +0   "10ts" magic (4 bytes, ASCII)
//     +4   unknown (DWORD)
//     +8   entry_size (DWORD) — total bytes this entry occupies, header
//          through end of data
//     +12  path_len (WORD) — length of the UTF-16LE path IN BYTES
//     +14  path (path_len bytes, UTF-16LE)
//     +14+path_len  last_modified (FILETIME, 8 bytes)
//     +22+path_len  data_size (DWORD)
//     +26+path_len  data (data_size bytes) — never surfaced by this plugin

struct ShimCacheRow {
    std::string path;
    int64_t last_modified_epoch_ms{0};
    uint32_t data_size{0};
    /// No exec-flag bit exists in this layout (documented in this package's
    /// spec) — always "-". Kept as a field rather than omitted so every row
    /// this plugin ever emits has the same shape a consumer can rely on.
    static constexpr std::string_view insert_flag = "-";
};

struct ShimCacheResult {
    std::string scheme; // "win10"
    std::vector<ShimCacheRow> rows;
};

constexpr size_t kShimCacheMaxEntries = 100000;
constexpr uint32_t kShimCacheMaxEntrySize = 64 * 1024;      // 64 KiB
constexpr uint32_t kShimCacheMaxPathLen = 32 * 1024;        // 32 KiB

inline Result<ShimCacheResult> parse_shimcache(std::span<const uint8_t> in) {
    auto header = detail::read_u32(in, 0, "truncated_header");
    if (!header)
        return std::unexpected(header.error());

    std::string scheme;
    if (*header == 0x34 || *header == 0x30)
        scheme = "win10";
    else
        return std::unexpected(detail::err("unknown_version", 0));

    const size_t header_size = *header;
    if (in.size() < header_size)
        return std::unexpected(detail::err("truncated_header", in.size()));

    ShimCacheResult out;
    out.scheme = scheme;

    size_t off = header_size;
    while (off < in.size()) {
        if (out.rows.size() >= kShimCacheMaxEntries)
            return std::unexpected(detail::err("oversize_count", off));

        if (off + 4 > in.size())
            return std::unexpected(detail::err("truncated_entry", off));
        // Magic is compared as raw bytes, not via read_u32 + numeric compare,
        // so the token stays "bad_magic" (an ASCII mismatch) rather than
        // "truncated_entry" for a full-but-wrong 4 bytes.
        static constexpr uint8_t kMagic[4] = {'1', '0', 't', 's'};
        if (std::memcmp(in.data() + off, kMagic, 4) != 0)
            return std::unexpected(detail::err("bad_magic", off));

        auto entry_size = detail::read_u32(in, off + 8, "truncated_entry");
        if (!entry_size)
            return std::unexpected(entry_size.error());
        if (*entry_size > kShimCacheMaxEntrySize)
            return std::unexpected(detail::err("oversize_count", off + 8));
        // entry_size is attacker/artifact-controlled and must never be
        // trusted past what the buffer actually has left — a declared size
        // that overruns the remaining bytes is a truncated entry, not a
        // valid one to advance the cursor by (see this file's header
        // invariant: every untrusted count is checked against the actual
        // remaining buffer, not just a hard cap).
        if (*entry_size > in.size() - off)
            return std::unexpected(detail::err("truncated_entry", off + 8));

        auto path_len = detail::read_u16(in, off + 12, "truncated_entry");
        if (!path_len)
            return std::unexpected(path_len.error());
        if (*path_len > kShimCacheMaxPathLen)
            return std::unexpected(detail::err("bad_path_length", off + 12));

        const size_t path_off = off + 14;
        if (path_off + *path_len > in.size())
            return std::unexpected(detail::err("bad_path_length", path_off));

        ShimCacheRow row;
        row.path = detail::utf16le_to_utf8(in.subspan(path_off, *path_len));

        const size_t ft_off = path_off + *path_len;
        auto ft = detail::read_u64(in, ft_off, "truncated_entry");
        if (!ft)
            return std::unexpected(ft.error());
        row.last_modified_epoch_ms = detail::filetime_to_epoch_ms(*ft);

        const size_t data_size_off = ft_off + 8;
        auto data_size = detail::read_u32(in, data_size_off, "truncated_entry");
        if (!data_size)
            return std::unexpected(data_size.error());
        row.data_size = *data_size;

        const size_t data_off = data_size_off + 4;
        // The data bytes themselves are never surfaced (this package's
        // boundaries: never emit file contents) so they are not copied —
        // only validated to be in-range when entry_size claims to cover
        // them, so a truncated trailing entry is still caught.
        if (data_off + *data_size > in.size())
            return std::unexpected(detail::err("truncated_entry", data_off));

        if (*entry_size < (path_off + *path_len + *data_size) - off) // excludes FILETIME+data_size DWORD, per A1's capture
            return std::unexpected(detail::err("truncated_entry", off + 8));
        out.rows.push_back(std::move(row));

        // Advance by the entry's own declared size when it is internally
        // consistent (>= the fixed+variable fields just consumed); a
        // corrupt/zero entry_size would otherwise infinite-loop, so fall
        // back to the bytes actually consumed in that case.
        const size_t consumed = (data_off + *data_size) - off;
        off += (*entry_size >= consumed) ? *entry_size : consumed;
    }

    return out;
}

// ────────────────────────────────────────────────────────────  AmCache  ────
//
// Input is already-decoded text: a sequence of (subkey_name, {value_name ->
// value_text}) pairs, as read from `Root\InventoryApplicationFile\<subkey>`
// by the impure shell (P32) after `RegLoadAppKeyW`. This function performs
// no registry I/O of its own — it is a pure text->row mapping so its
// behaviour is identical whether the input came from a live hive load or
// (for tests) a `reg query`-style export.

struct AmCacheRow {
    std::string lower_case_long_path;
    /// FileId with its leading "0000" prefix stripped and lowercased down to
    /// a 40-hex-character SHA-1, or "-" when the field is absent or does not
    /// match that shape (malformed_fields counts the latter).
    std::string sha1;
    std::string size;
    std::string link_date;
    std::string publisher;
    std::string binary_type;
    std::string product_name;
    std::string product_version;
};

struct AmCacheResult {
    std::vector<AmCacheRow> rows;
    /// Count of rows whose FileId value was present but did not parse to a
    /// well-formed SHA-1 (wrong length/prefix/non-hex) — never silently
    /// dropped, and never conflated with "FileId absent" (which is not a
    /// malformed field, just a missing one; both map the row's sha1 to "-").
    size_t malformed_fields{0};
};

namespace detail {

inline bool is_hex_lower(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/// FileId as stored by Amcache is a 44-hex-character string: a 4-hex-digit
/// "0000" prefix (a flags/reserved nibble pair this plugin does not surface)
/// followed by the 40-hex-character SHA-1. Anything else — wrong length,
/// wrong prefix, non-hex characters — is malformed.
inline std::string normalise_file_id(std::string_view raw, bool& out_malformed) {
    out_malformed = false;
    if (raw.empty())
        return "-";
    std::string lower;
    lower.reserve(raw.size());
    for (char c : raw)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower.size() != 44 || lower.compare(0, 4, "0000") != 0) {
        out_malformed = true;
        return "-";
    }
    std::string_view sha1 = std::string_view{lower}.substr(4);
    for (char c : sha1) {
        if (!is_hex_lower(c)) {
            out_malformed = true;
            return "-";
        }
    }
    return std::string{sha1};
}

inline std::string get_or_empty(const std::map<std::string, std::string>& values,
                                 std::string_view key) {
    auto it = values.find(std::string{key});
    return it == values.end() ? std::string{} : it->second;
}

} // namespace detail

inline AmCacheResult
parse_amcache_inventory_application_file(
    const std::vector<std::pair<std::string, std::map<std::string, std::string>>>& subkeys) {
    AmCacheResult out;
    out.rows.reserve(subkeys.size());
    for (const auto& [name, values] : subkeys) {
        (void)name; // the subkey name itself carries no field this row needs
        AmCacheRow row;
        row.lower_case_long_path = detail::get_or_empty(values, "LowerCaseLongPath");
        bool malformed = false;
        row.sha1 = detail::normalise_file_id(detail::get_or_empty(values, "FileId"), malformed);
        if (malformed)
            ++out.malformed_fields;
        row.size = detail::get_or_empty(values, "Size");
        row.link_date = detail::get_or_empty(values, "LinkDate");
        row.publisher = detail::get_or_empty(values, "Publisher");
        row.binary_type = detail::get_or_empty(values, "BinaryType");
        row.product_name = detail::get_or_empty(values, "ProductName");
        row.product_version = detail::get_or_empty(values, "ProductVersion");
        out.rows.push_back(std::move(row));
    }
    return out;
}

// ────────────────────────────────────────────────────────────  Prefetch  ───
//
// MAM decompression sniff, then the decompressed `.pf` layout. Version 23
// (Vista/7) uses a single last-run FILETIME and a run-count field at a
// different absolute offset than versions 26/30/31 (Windows 8.1/10/11),
// which carry up to 8 last-run FILETIMEs. Offsets below are ABSOLUTE file
// offsets into the decompressed buffer, not relative to the file-information
// block's own start (0x54) — verified against A1's three real
// `.pf.decompressed` captures (DOSKEY/OUTPUT/REG), each cross-checked
// against its own filename-encoded invocation-count hint.

constexpr uint32_t kMamMaxUncompressedSize = 64u * 1024 * 1024; // 64 MiB

/// True when `in` begins with the MAM (`MAM\x04`) compression marker.
inline bool is_mam_compressed(std::span<const uint8_t> in) {
    static constexpr uint8_t kMagic[4] = {'M', 'A', 'M', 0x04};
    return in.size() >= 4 && std::memcmp(in.data(), kMagic, 4) == 0;
}

/// Reads the MAM header's claimed uncompressed size, bounds-checked against
/// `kMamMaxUncompressedSize` — the impure shell uses this to size its
/// `RtlDecompressBufferEx` output buffer without trusting an attacker/
/// corruption-controlled DWORD directly.
inline Result<uint32_t> mam_uncompressed_size(std::span<const uint8_t> in) {
    if (!is_mam_compressed(in))
        return std::unexpected(detail::err("bad_magic", 0));
    auto size = detail::read_u32(in, 4, "truncated_header");
    if (!size)
        return std::unexpected(size.error());
    if (*size > kMamMaxUncompressedSize)
        return std::unexpected(detail::err("oversize_count", 4));
    return *size;
}

struct PrefetchResult {
    std::string exe_name;
    std::string hash_hex; // 8 uppercase hex digits, e.g. "DDFD0A8D"
    uint32_t version{0};
    uint32_t run_count{0};
    std::vector<int64_t> last_runs_epoch_ms; // most-recent-first, <=8 entries
    uint32_t volume_count{0};
    uint32_t file_ref_count{0};
};

constexpr size_t kPrefetchMaxVolumes = 4096;
constexpr size_t kPrefetchMaxFileRefs = 65535;
constexpr size_t kPrefetchMaxLastRuns = 8;

// Fixed absolute offsets, all header-relative to the decompressed buffer.
constexpr size_t kPrefetchVersionOffset = 0x00;
constexpr size_t kPrefetchSignatureOffset = 0x04;
constexpr size_t kPrefetchFileSizeOffset = 0x0C;
constexpr size_t kPrefetchExeNameOffset = 0x10;
constexpr size_t kPrefetchExeNameBytes = 60;
constexpr size_t kPrefetchHashOffset = 0x4C; // 76

// File-information block common prefix (present at the same absolute offset
// for every supported version — verified against all three real captures).
constexpr size_t kFileInfoVolumesInfoCountOffset = 0x70; // number of volumes
constexpr size_t kFileInfoVolumesInfoSizeField = 0x74;   // total byte size of the volumes-info block

// v23 (Vista/7): one last-run FILETIME, run count at 0x98.
//
// v17 (XP/2003) is deliberately NOT supported here even though its magic/
// version field is well documented: the publicly documented XP/2003 layout
// places these same fields 8 bytes earlier (0x78/0x90) than v23, and unlike
// every other version in this file this offset pair has never been checked
// against a real byte-level capture. Treating v17 as "close enough" to v23
// would silently misparse a real v17 file using the wrong offsets, which is
// worse than reporting it unsupported. Re-add it only after doing for v17
// what was done for v26/30/31 below: pin the offsets against an actual XP/
// 2003 SCCA capture, not documentation alone.
constexpr size_t kFileInfoV23LastRunOffset = 0x80;
constexpr size_t kFileInfoV23RunCountOffset = 0x98;

// v26/30/31 (Win 8.1/10/11): up to 8 last-run FILETIMEs starting at 0x80 (64
// bytes, 8 * 8), run count at 0xC8.
//
// EVIDENCE (not from documentation — pinned against A1's real captures,
// 2026-09-06): DOSKEY.EXE-DDFD0A8D.pf.decompressed has exactly 2 non-zero
// FILETIMEs in the 0x80-0xBF slot array and the DWORD at 0xC8 reads 2;
// OUTPUT.EXE-EE9CBC0B.pf.decompressed has exactly 1 non-zero slot and 0xC8
// reads 1; REG.EXE-6A8B6960.pf.decompressed has all 8 slots non-zero (it was
// invoked 8+ times before capture) and 0xC8 reads 11. The DWORD at 0xD0 is 0
// in all three real files; the DWORD one further along, at 0xD4, is instead
// a large volume-count-shaped number (0x2200 range) in all three — clearly a
// different field, not run count. This is why this parser uses 0xC8, not the
// 0xD0 first assumed during planning.
constexpr size_t kFileInfoV26V30V31LastRunOffset = 0x80;
constexpr size_t kFileInfoV26V30V31RunCountOffset = 0xC8;

// Volumes-information array absolute offset (a fixed early field in the
// common file-information prefix, alongside the volume COUNT and byte-SIZE
// fields above).
constexpr size_t kFileInfoVolumesInfoOffsetField = 0x6C;

// Volume-entry stride: the fixed byte distance between consecutive entries
// in the volumes-info block, per libscca's documented Volume Information
// structure.
//
// v30/31 (Win 8.1/10/11) = 96 bytes (0x60) -- BYTE-VERIFIED against
// OUTPUT.EXE-EE9CBC0B and REG.EXE-6A8B6960's real SECOND volume entries:
// at entry_start + 0x60, both decode to a well-formed UTF-16LE
// "\VOLUME{...}" device-path string when read at the offset that entry's
// own +0x00/+0x04 fields declare (the alternative, +0x68, decodes to
// garbage there for both files). v23/26 (XP-era through Win7) = 104 bytes
// (0x68) per libscca -- documentation-derived, NOT independently verified
// against a real capture (every real fixture on this hardware parses as
// v31; see real_prefetch_captures() in the test file). Every entry this
// parser walks is bounds- and consistency-checked against the block's own
// declared size (kFileInfoVolumesInfoSizeField) regardless of version, so
// a wrong stride for v23/26 fails the whole parse (truncated_entry /
// oversize_count) rather than silently misreading -- see parse_prefetch's
// volume loop.
constexpr size_t kVolumeEntryStrideV23V26 = 0x68; // 104
constexpr size_t kVolumeEntryStrideV30V31 = 0x60; // 96

// Volume-entry sub-fields, relative to the VOLUMES-INFO BLOCK START (i.e.
// kFileInfoVolumesInfoOffsetField's own value) PLUS this entry's own
// index*stride -- NOT relative to the entry's start on their own, which an
// earlier revision of this parser assumed for entry 0 (block start and
// entry 0's start coincide, so the two bases were indistinguishable until
// a second entry was ever read). Byte-verified against OUTPUT/REG.EXE's
// real two-volume file-information blocks: entry 1's device-path fields
// only decode correctly when +0x00/+0x04 are read block-relative.
//
// +0x14 holds the (block-relative) byte offset of this volume's
// file-references sub-block; +0x18 holds that sub-block's own total byte
// size. The sub-block itself is
// [u32 version][u32 count][u64 unknown][count x u64 NTFS file references],
// and refs_size == 16 + count*8 holds exactly in every one of the 5 real
// volumes across A1's three fixtures (DOSKEY: 1 volume / 15 refs; OUTPUT:
// 2 volumes / 7 + 16 = 23 refs; REG.EXE: 2 volumes / 3 + 29 = 32 refs) --
// parse_prefetch's volume loop verifies this relationship (as a `<=`, to
// tolerate trailing padding a real file might carry) rather than trusting
// it, and sums file_ref_count across every declared volume, not just
// entry 0.
constexpr size_t kVolumeEntryFileRefsOffsetField = 0x14;
constexpr size_t kVolumeEntryFileRefsSizeField = 0x18;
constexpr size_t kFileRefsBlockHeaderBytes = 16; // [u32 version][u32 count][u64 unknown]
// The refs sub-block's own leading version DWORD -- byte-verified as this
// constant in all 5 real volumes examined across the 3 in-tree fixtures.
// Checked in the volume loop below as a semantic anchor beyond pure
// bounds/size arithmetic (see that check's own comment).
constexpr uint32_t kFileRefsBlockVersion = 3;

inline bool is_supported_prefetch_version(uint32_t v) {
    // v17 (XP/2003) is excluded on purpose — see the note above
    // kFileInfoV23LastRunOffset. XP/2003 is long EOL'd (2014/2015) and this
    // plugin already scopes to Win10/11 elsewhere, so an unverified offset
    // guess for an unreachable OS isn't worth the risk of silently
    // fabricating data from a real v17 file.
    return v == 23 || v == 26 || v == 30 || v == 31;
}

inline Result<PrefetchResult> parse_prefetch(std::span<const uint8_t> in) {
    auto version = detail::read_u32(in, kPrefetchVersionOffset, "truncated_header");
    if (!version)
        return std::unexpected(version.error());
    if (!is_supported_prefetch_version(*version))
        return std::unexpected(detail::err("unknown_version", kPrefetchVersionOffset));

    if (in.size() < kPrefetchSignatureOffset + 4)
        return std::unexpected(detail::err("truncated_header", kPrefetchSignatureOffset));
    static constexpr uint8_t kSig[4] = {'S', 'C', 'C', 'A'};
    if (std::memcmp(in.data() + kPrefetchSignatureOffset, kSig, 4) != 0)
        return std::unexpected(detail::err("bad_magic", kPrefetchSignatureOffset));

    auto file_size = detail::read_u32(in, kPrefetchFileSizeOffset, "truncated_header");
    if (!file_size)
        return std::unexpected(file_size.error());
    // The header declares its own total payload size; a buffer shorter than
    // that declaration is a truncated capture (e.g. only the early header
    // fields survived), not a well-formed file whose later fields happen to
    // read as zero -- reject it here rather than let the reads below run
    // past real data into whatever the decompressed buffer's tail holds.
    if (in.size() < *file_size)
        return std::unexpected(detail::err("truncated_header", kPrefetchFileSizeOffset));

    if (in.size() < kPrefetchExeNameOffset + kPrefetchExeNameBytes)
        return std::unexpected(detail::err("truncated_header", kPrefetchExeNameOffset));

    PrefetchResult out;
    out.version = *version;
    out.exe_name =
        detail::utf16le_to_utf8(in.subspan(kPrefetchExeNameOffset, kPrefetchExeNameBytes));

    auto hash = detail::read_u32(in, kPrefetchHashOffset, "truncated_header");
    if (!hash)
        return std::unexpected(hash.error());
    out.hash_hex = std::format("{:08X}", *hash);

    const bool is_v23 = (*version == 23);
    const size_t last_run_off = is_v23 ? kFileInfoV23LastRunOffset : kFileInfoV26V30V31LastRunOffset;
    const size_t run_count_off = is_v23 ? kFileInfoV23RunCountOffset : kFileInfoV26V30V31RunCountOffset;
    const size_t n_last_runs = is_v23 ? 1 : kPrefetchMaxLastRuns;
    if (*file_size < run_count_off + 4)
        return std::unexpected(detail::err("truncated_entry", run_count_off));

    for (size_t i = 0; i < n_last_runs; ++i) {
        auto ft = detail::read_u64(in, last_run_off + i * 8, "truncated_entry");
        if (!ft)
            return std::unexpected(ft.error());
        if (*ft != 0)
            out.last_runs_epoch_ms.push_back(detail::filetime_to_epoch_ms(*ft));
    }

    auto run_count = detail::read_u32(in, run_count_off, "truncated_entry");
    if (!run_count)
        return std::unexpected(run_count.error());
    if (*run_count == 0xFFFFFFFFu)
        return std::unexpected(detail::err("oversize_count", run_count_off));
    out.run_count = *run_count;

    auto volume_count = detail::read_u32(in, kFileInfoVolumesInfoCountOffset, "truncated_entry");
    if (!volume_count)
        return std::unexpected(volume_count.error());
    if (*volume_count > kPrefetchMaxVolumes)
        return std::unexpected(detail::err("oversize_count", kFileInfoVolumesInfoCountOffset));
    out.volume_count = *volume_count;

    // file_ref_count: the TOTAL number of NTFS file references SUMMED
    // across EVERY declared volume entry (README.md / execution_artifacts.
    // yaml's documented "Total number of NTFS file references, summed
    // across every declared volume entry in the file-information block
    // (not just the first)" -- whole-file, not volume-0-only). Every
    // entry is walked and bounds-checked; a truncated or over-cap value in
    // ANY entry fails the whole parse with a named reason rather than
    // silently under-counting or defaulting to 0 -- indistinguishable from
    // "this file genuinely referenced zero volumes' worth of files"
    // (routed-concerns.md's execution_artifacts row, clause (1): never an
    // empty success for malformed input). The refs_size/count consistency
    // check below, plus the refs sub-block's own version-field check,
    // doubles as this loop's own layout self-check: a NATURALLY wrong
    // stride (kVolumeEntryStrideV23V26 is documentation-derived and
    // unpinned by a real capture -- see its own comment) reads unrelated
    // file bytes as a refs sub-block, and both reviewers of PR #4444's
    // round-3 review independently confirmed this fails closed in both
    // directions (a real 96-byte or 112-byte layout misread as 104).
    // This is NOT an unconditional guarantee, though: both reviewers also
    // independently constructed a synthetic layout where bytes at the
    // WRONG stride-104 offset coincidentally satisfy every check below
    // (refs-block bounds, size-vs-count consistency, and now the version
    // constant too) and got a full, fabricated success instead of a
    // failure -- a deliberately crafted file can still pass. The realistic
    // (non-adversarial) failure mode fails closed; a SYSTEM/admin-tier
    // local attacker with write access to C:\Windows\Prefetch\ who wanted
    // to defeat this check specifically already has far more direct ways
    // to feed this plugin bad data at that privilege tier (see issue
    // #4467's regression test for the constructed-coincidence case kept
    // as a permanent, documented residual).
    if (out.volume_count > 0) {
        auto vol_info_off =
            detail::read_u32(in, kFileInfoVolumesInfoOffsetField, "truncated_entry");
        if (!vol_info_off)
            return std::unexpected(vol_info_off.error());
        auto vol_info_size =
            detail::read_u32(in, kFileInfoVolumesInfoSizeField, "truncated_entry");
        if (!vol_info_size)
            return std::unexpected(vol_info_size.error());

        const uint64_t block_start = *vol_info_off;
        const uint64_t block_size = *vol_info_size;
        if (block_start + block_size > *file_size)
            return std::unexpected(detail::err("truncated_entry", kFileInfoVolumesInfoSizeField));

        const size_t stride = (*version == 23 || *version == 26) ? kVolumeEntryStrideV23V26
                                                                  : kVolumeEntryStrideV30V31;
        const uint64_t entries_bytes = static_cast<uint64_t>(out.volume_count) * stride;
        if (entries_bytes > block_size)
            return std::unexpected(detail::err("truncated_entry", kFileInfoVolumesInfoSizeField));

        uint64_t total_refs = 0;
        for (uint32_t i = 0; i < out.volume_count; ++i) {
            const uint64_t entry = block_start + static_cast<uint64_t>(i) * stride;

            auto refs_off = detail::read_u32(
                in, static_cast<size_t>(entry + kVolumeEntryFileRefsOffsetField),
                "truncated_entry");
            if (!refs_off)
                return std::unexpected(refs_off.error());
            auto refs_size = detail::read_u32(
                in, static_cast<size_t>(entry + kVolumeEntryFileRefsSizeField), "truncated_entry");
            if (!refs_size)
                return std::unexpected(refs_size.error());

            const uint64_t refs_block_start = block_start + static_cast<uint64_t>(*refs_off);
            const uint64_t refs_block_size = *refs_size;
            if (refs_block_start + refs_block_size > block_start + block_size ||
                refs_block_size < kFileRefsBlockHeaderBytes)
                return std::unexpected(detail::err(
                    "truncated_entry",
                    static_cast<size_t>(entry) + kVolumeEntryFileRefsSizeField));

            // The refs sub-block is [u32 version][u32 count][u64 unknown]
            // [count x u64 refs]. The version DWORD is byte-verified as the
            // constant 3 in all 5 real volumes examined across the 3
            // in-tree fixtures -- checking it here is a semantic anchor,
            // not just a bounds/size coincidence: a genuinely wrong stride
            // reading unrelated file bytes as a refs sub-block would need
            // to ALSO land the exact 4-byte value 3 at this specific
            // offset to pass, on top of every other bounds/size check
            // below, which meaningfully narrows (though — see this
            // function's own doc comment above — does not eliminate) the
            // "constructed coincidence" window a wrong v23/v26 stride
            // assumption could otherwise slip through.
            auto refs_version =
                detail::read_u32(in, static_cast<size_t>(refs_block_start), "truncated_entry");
            if (!refs_version)
                return std::unexpected(refs_version.error());
            if (*refs_version != kFileRefsBlockVersion)
                return std::unexpected(
                    detail::err("truncated_entry", static_cast<size_t>(refs_block_start)));

            // The count DWORD is 4 bytes into the sub-block, right after
            // the version DWORD just checked above.
            auto refs_count =
                detail::read_u32(in, static_cast<size_t>(refs_block_start) + 4, "truncated_entry");
            if (!refs_count)
                return std::unexpected(refs_count.error());
            const uint64_t declared_bytes =
                kFileRefsBlockHeaderBytes + static_cast<uint64_t>(*refs_count) * 8;
            if (*refs_count > kPrefetchMaxFileRefs || declared_bytes > refs_block_size)
                return std::unexpected(
                    detail::err("oversize_count", static_cast<size_t>(refs_block_start) + 4));

            total_refs += *refs_count;
            if (total_refs > kPrefetchMaxFileRefs)
                return std::unexpected(
                    detail::err("oversize_count", static_cast<size_t>(refs_block_start) + 4));
        }
        out.file_ref_count = static_cast<uint32_t>(total_refs);
    }

    return out;
}

// Prefetch absence tokens (#4391) -- emitted by the impure shell in place of
// the old single "prefetch_disabled" literal when FindFirstFileW sees zero
// `.pf` files, distinguishing three forensically distinct situations:
inline constexpr std::string_view kPrefetchDisabled = "prefetch_disabled";
inline constexpr std::string_view kPrefetchEvidenceAbsent = "prefetch_evidence_absent";
inline constexpr std::string_view kPrefetchStateUnknown = "prefetch_state_unknown";

/// Maps the registry's `EnablePrefetcher` DWORD (PrefetchParameters) to one
/// of the three tokens above. Called ONLY when the enumeration of
/// `C:\Windows\Prefetch\*.pf` saw zero files.
///
///  - `nullopt` (the registry value/key could not be read at all, for any
///    reason -- missing, wrong type, access denied) -> `prefetch_state_unknown`:
///    we have no idea whether prefetching is even configured on.
///  - `0` -> `prefetch_disabled`: the prefetcher is off; zero `.pf` files is
///    exactly what a correctly-functioning system produces.
///  - `1`, `2`, or `3` -- Microsoft's documented settings (1 = application
///    prefetching only, 2 = boot prefetching only, 3 = both) -- ->
///    `prefetch_evidence_absent`: prefetching is configured ON, so `.pf`
///    files should exist; their absence is CONSISTENT WITH, but not proof
///    of, removal after the fact. This does not consult the SysMain service
///    state: a disabled SysMain leaves the directory empty with the value
///    still 3, which also maps here.
///  - any other value -> `prefetch_state_unknown`: an undocumented setting
///    has no established meaning and must never be turned into an
///    evidence claim.
constexpr std::string_view prefetch_absence_token(std::optional<uint32_t> enable_prefetcher) noexcept {
    if (!enable_prefetcher)
        return kPrefetchStateUnknown;
    switch (*enable_prefetcher) {
        case 0:
            return kPrefetchDisabled;
        case 1:
        case 2:
        case 3:
            return kPrefetchEvidenceAbsent;
        default:
            return kPrefetchStateUnknown;
    }
}

} // namespace yuzu::execution_artifacts
