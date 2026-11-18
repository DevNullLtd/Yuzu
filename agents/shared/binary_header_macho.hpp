/**
 * binary_header_macho.hpp -- bounded Mach-O thin and universal (fat) header and load-command
 * reader. Leaf: binary_header_reader.hpp and the STL only, no OS header (every Mach-O constant is a
 * plain number with a comment naming it), no I/O of its own, nothing thrown by design.
 *
 * Every byte of the file is attacker-chosen. One Reader and one ReadBudget serve the whole file;
 * every slice read is first bounds-checked against the slice's own [offset, offset + size) and then
 * issued at slice offset + relative offset, so a slice can never be completed from its neighbour's
 * bytes. A thin file's parse failure is the function's error; a universal file's is the slice's, and
 * one slice fails the others only by spending the shared ReadBudget (they then end limit_exceeded).
 *
 * Decoded: the Mach-O header, LC_ID_DYLIB, LC_UUID, LC_BUILD_VERSION, the four
 * LC_VERSION_MIN_* commands and LC_SOURCE_VERSION. Every other command is skipped by its size.
 * When a command kind repeats, the first one wins. LC_BUILD_VERSION and the LC_VERSION_MIN_*
 * commands fill the one build_version, so the first of either kind wins.
 */

#pragma once

#include "binary_header_reader.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared::binary_header {

struct MachoLimits {
    std::size_t max_fat_archs{16};
    std::size_t max_load_commands{1024};
    std::size_t max_commands_bytes{512 * 1024};
    std::size_t max_string_bytes{1024};
};

struct MachoDylibId {
    // Not sanitised: the bytes of the file, as in PeStringTable.
    std::string name;
    std::uint32_t timestamp{0};
    std::uint32_t current_version{0};       // 16.8.8 packing, see format_dylib_version
    std::uint32_t compatibility_version{0}; // 16.8.8 packing
};

struct MachoBuildVersion {
    std::uint32_t platform{0}; // PLATFORM_* (1 macOS, 2 iOS, 3 tvOS, 4 watchOS, ...)
    std::uint32_t minos{0};    // 16.8.8 packing
    std::uint32_t sdk{0};      // 16.8.8 packing
};

struct MachoSlice {
    std::uint64_t offset{0};
    std::uint64_t size{0};
    std::optional<ParseError> error; // set: only the fat_arch fields hold (offset, size, cpu_type, cpu_subtype); byte_order is the table's, the rest defaults
    bool is64{false};
    std::endian byte_order{std::endian::little};
    std::uint32_t cpu_type{0};
    std::uint32_t cpu_subtype{0};
    std::uint32_t file_type{0};
    std::uint32_t flags{0};
    std::uint32_t load_command_count{0};
    std::optional<MachoDylibId> id_dylib;
    std::optional<std::array<std::uint8_t, 16>> uuid;
    std::optional<MachoBuildVersion> build_version;
    std::optional<std::uint64_t> source_version; // raw A.B.C.D.E packing (24.10.10.10.10)
};

struct MachoInfo {
    bool fat{false};
    std::vector<MachoSlice> slices; // one for a thin file
};

// X.Y.Z from the 16.8.8 packing of a Mach-O version word.
[[nodiscard]] inline std::string format_dylib_version(std::uint32_t v) {
    return std::to_string(v >> 16) + '.' + std::to_string((v >> 8) & 0xFFu) + '.' +
           std::to_string(v & 0xFFu);
}

namespace macho_detail {

// Magics, read as a big-endian u32 of the file's first four bytes.
inline constexpr std::uint32_t kFatMagic = 0xCAFEBABEu;    // FAT_MAGIC
inline constexpr std::uint32_t kFatMagic64 = 0xCAFEBABFu;  // FAT_MAGIC_64
inline constexpr std::uint32_t kMhMagic = 0xFEEDFACEu;     // MH_MAGIC, file is big-endian
inline constexpr std::uint32_t kMhMagic64 = 0xFEEDFACFu;   // MH_MAGIC_64, file is big-endian
inline constexpr std::uint32_t kMhCigam = 0xCEFAEDFEu;     // MH_CIGAM, file is little-endian
inline constexpr std::uint32_t kMhCigam64 = 0xCFFAEDFEu;   // MH_CIGAM_64, file is little-endian

inline constexpr std::size_t kFatHeaderBytes = 8;   // struct fat_header: magic, nfat_arch
inline constexpr std::size_t kFatArchBytes = 20;    // struct fat_arch
inline constexpr std::size_t kFatArch64Bytes = 32;  // struct fat_arch_64
inline constexpr std::size_t kHeader32Bytes = 28;   // struct mach_header
inline constexpr std::size_t kHeader64Bytes = 32;   // struct mach_header_64 (the larger of the two)

inline constexpr std::uint32_t kLcIdDylib = 0x0D;           // LC_ID_DYLIB
inline constexpr std::uint32_t kLcUuid = 0x1B;              // LC_UUID
inline constexpr std::uint32_t kLcVersionMinMacosx = 0x24;  // LC_VERSION_MIN_MACOSX
inline constexpr std::uint32_t kLcVersionMinIphoneos = 0x25; // LC_VERSION_MIN_IPHONEOS
inline constexpr std::uint32_t kLcSourceVersion = 0x2A;     // LC_SOURCE_VERSION
inline constexpr std::uint32_t kLcVersionMinTvos = 0x2F;    // LC_VERSION_MIN_TVOS
inline constexpr std::uint32_t kLcVersionMinWatchos = 0x30; // LC_VERSION_MIN_WATCHOS
inline constexpr std::uint32_t kLcBuildVersion = 0x32;      // LC_BUILD_VERSION

inline constexpr std::size_t kMinDylibCmd = 24;       // dylib_command
inline constexpr std::size_t kMinUuidCmd = 24;        // uuid_command: 8 + 16
inline constexpr std::size_t kMinBuildVersionCmd = 24; // build_version_command (tools[] ignored)
inline constexpr std::size_t kMinVersionMinCmd = 16;  // version_min_command
inline constexpr std::size_t kMinSourceVersionCmd = 16; // source_version_command

[[nodiscard]] constexpr bool is_fat_magic(std::uint32_t m) noexcept {
    return m == kFatMagic || m == kFatMagic64;
}

[[nodiscard]] inline std::uint32_t u32(std::string_view b, std::size_t off, std::endian o) noexcept {
    return load<std::uint32_t>(b, off, o).value_or(0); // callers have checked the length
}

// Read [rel, rel + len) of the slice starting at `base`: bounded by the slice, then issued at
// base + rel on the shared Reader.
[[nodiscard]] inline std::expected<std::string, ParseError>
slice_read(Reader& r, std::uint64_t base, std::uint64_t slice_size, std::uint64_t rel,
           std::size_t len) {
    const auto end = checked_add(rel, len);
    const auto at = checked_add(base, rel);
    if (!end || !at || *end > slice_size)
        return std::unexpected(ParseError::truncated);
    return r.read(*at, len);
}

// The first min(size, 32) bytes of the slice, already read by the caller.
[[nodiscard]] inline std::expected<MachoSlice, ParseError>
parse_thin(Reader& r, std::uint64_t base, std::uint64_t size, std::string_view head,
           const MachoLimits& lim) {
    if (head.size() < 4)
        return std::unexpected(ParseError::truncated);
    const std::uint32_t magic = u32(head, 0, std::endian::big);
    MachoSlice s;
    s.offset = base;
    s.size = size;
    switch (magic) {
    case kMhMagic: s.is64 = false; s.byte_order = std::endian::big; break;
    case kMhMagic64: s.is64 = true; s.byte_order = std::endian::big; break;
    case kMhCigam: s.is64 = false; s.byte_order = std::endian::little; break;
    case kMhCigam64: s.is64 = true; s.byte_order = std::endian::little; break;
    default:
        return std::unexpected(is_fat_magic(magic) ? ParseError::malformed
                                                   : ParseError::not_this_format);
    }
    const std::size_t hdr = s.is64 ? kHeader64Bytes : kHeader32Bytes;
    if (head.size() < hdr)
        return std::unexpected(ParseError::truncated);

    const std::endian o = s.byte_order;
    s.cpu_type = u32(head, 4, o);
    s.cpu_subtype = u32(head, 8, o);
    s.file_type = u32(head, 12, o);
    const std::uint32_t ncmds = u32(head, 16, o);
    const std::uint32_t sizeofcmds = u32(head, 20, o);
    s.flags = u32(head, 24, o);
    s.load_command_count = ncmds;
    if (ncmds > lim.max_load_commands || sizeofcmds > lim.max_commands_bytes)
        return std::unexpected(ParseError::limit_exceeded);

    auto cmds_read = slice_read(r, base, size, hdr, sizeofcmds);
    if (!cmds_read)
        return std::unexpected(cmds_read.error());
    const std::string_view area = *cmds_read;

    std::size_t pos = 0;
    for (std::uint32_t i = 0; i < ncmds; ++i) {
        if (area.size() - pos < 8)
            return std::unexpected(ParseError::malformed);
        const std::uint32_t cmd = u32(area, pos, o);
        const std::size_t csz = u32(area, pos + 4, o);
        if (csz < 8 || csz % 4 != 0 || csz > area.size() - pos)
            return std::unexpected(ParseError::malformed);
        const std::string_view c = area.substr(pos, csz);
        pos += csz;

        switch (cmd) {
        case kLcIdDylib: {
            if (csz < kMinDylibCmd)
                return std::unexpected(ParseError::malformed);
            const std::size_t name_off = u32(c, 8, o);
            if (name_off < kMinDylibCmd || name_off >= csz)
                return std::unexpected(ParseError::malformed);
            const auto nul = c.find('\0', name_off);
            if (nul == std::string_view::npos)
                return std::unexpected(ParseError::malformed);
            if (nul - name_off > lim.max_string_bytes)
                return std::unexpected(ParseError::limit_exceeded);
            if (!s.id_dylib)
                s.id_dylib = MachoDylibId{std::string(c.substr(name_off, nul - name_off)),
                                          u32(c, 12, o), u32(c, 16, o), u32(c, 20, o)};
            break;
        }
        case kLcUuid: {
            if (csz < kMinUuidCmd)
                return std::unexpected(ParseError::malformed);
            if (!s.uuid) {
                std::array<std::uint8_t, 16> id{};
                for (std::size_t k = 0; k < id.size(); ++k)
                    id[k] = static_cast<std::uint8_t>(c[8 + k]);
                s.uuid = id;
            }
            break;
        }
        case kLcBuildVersion: {
            if (csz < kMinBuildVersionCmd)
                return std::unexpected(ParseError::malformed);
            // ntools 8-byte tool entries follow the fixed part; a command too small for them is one
            // the loader refuses.
            if (static_cast<std::uint64_t>(u32(c, 20, o)) * 8 > csz - kMinBuildVersionCmd)
                return std::unexpected(ParseError::malformed);
            if (!s.build_version)
                s.build_version = MachoBuildVersion{u32(c, 8, o), u32(c, 12, o), u32(c, 16, o)};
            break;
        }
        case kLcVersionMinMacosx:
        case kLcVersionMinIphoneos:
        case kLcVersionMinTvos:
        case kLcVersionMinWatchos: {
            if (csz < kMinVersionMinCmd)
                return std::unexpected(ParseError::malformed);
            // PLATFORM_MACOS 1, PLATFORM_IOS 2, PLATFORM_TVOS 3, PLATFORM_WATCHOS 4
            const std::uint32_t platform = cmd == kLcVersionMinMacosx      ? 1
                                           : cmd == kLcVersionMinIphoneos ? 2
                                           : cmd == kLcVersionMinTvos     ? 3
                                                                          : 4;
            if (!s.build_version)
                s.build_version = MachoBuildVersion{platform, u32(c, 8, o), u32(c, 12, o)};
            break;
        }
        case kLcSourceVersion: {
            if (csz < kMinSourceVersionCmd)
                return std::unexpected(ParseError::malformed);
            if (!s.source_version) {
                // u64 in the slice's byte order
                s.source_version = load<std::uint64_t>(c, 8, o).value_or(0);
            }
            break;
        }
        default: break; // skipped by its size
        }
    }
    return s;
}

} // namespace macho_detail

[[nodiscard]] inline std::expected<MachoInfo, ParseError>
read_macho(const Source& src, const MachoLimits& lim = {}, ReadBudget budget = {}) {
    using namespace macho_detail;
    if (src.size < 4)
        return std::unexpected(ParseError::not_this_format);
    Reader r(src, budget);
    const std::uint64_t head_len = src.size < kHeader64Bytes ? src.size : kHeader64Bytes;
    auto head_read = r.read(0, static_cast<std::size_t>(head_len));
    if (!head_read)
        return std::unexpected(head_read.error());
    const std::string_view head = *head_read;
    const std::uint32_t magic = u32(head, 0, std::endian::big);

    MachoInfo info;
    if (!is_fat_magic(magic)) {
        auto thin = parse_thin(r, 0, src.size, head, lim);
        if (!thin)
            return std::unexpected(thin.error());
        info.slices.push_back(std::move(*thin));
        return info;
    }

    // Universal. nfat_arch is the field a Java class file (same four magic bytes) fills with its
    // version word, at least 45: such a count is refused whatever max_fat_archs allows.
    if (head.size() < kFatHeaderBytes)
        return std::unexpected(ParseError::truncated);
    const bool is64 = magic == kFatMagic64;
    const std::uint32_t nfat = u32(head, 4, std::endian::big);
    if (nfat == 0 || nfat >= 45)
        return std::unexpected(ParseError::not_this_format);
    if (nfat > lim.max_fat_archs) // a real universal binary over the caller's cap, as PE and ELF report theirs
        return std::unexpected(ParseError::limit_exceeded);
    const std::size_t entry = is64 ? kFatArch64Bytes : kFatArchBytes;
    const auto table_len = checked_mul(nfat, entry);
    if (!table_len)
        return std::unexpected(ParseError::truncated);
    auto table_read = r.read(kFatHeaderBytes, static_cast<std::size_t>(*table_len));
    if (!table_read)
        return std::unexpected(table_read.error());
    const std::string_view table = *table_read;

    info.fat = true;
    for (std::uint32_t i = 0; i < nfat; ++i) {
        const std::size_t at = static_cast<std::size_t>(i) * entry;
        MachoSlice s;
        s.byte_order = std::endian::big;
        s.cpu_type = u32(table, at, std::endian::big);
        s.cpu_subtype = u32(table, at + 4, std::endian::big);
        if (is64) {
            s.offset = load<std::uint64_t>(table, at + 8, std::endian::big).value_or(0);
            s.size = load<std::uint64_t>(table, at + 16, std::endian::big).value_or(0);
        } else {
            s.offset = u32(table, at + 8, std::endian::big);
            s.size = u32(table, at + 12, std::endian::big);
        }
        const auto end = checked_add(s.offset, s.size);
        if (!end || *end > src.size || s.size < 4) {
            s.error = ParseError::truncated;
        } else {
            const std::size_t n =
                s.size < kHeader64Bytes ? static_cast<std::size_t>(s.size) : kHeader64Bytes;
            auto sh = slice_read(r, s.offset, s.size, 0, n);
            if (!sh) {
                s.error = sh.error();
            } else {
                auto parsed = parse_thin(r, s.offset, s.size, *sh, lim);
                if (parsed)
                    s = std::move(*parsed);
                else
                    s.error = parsed.error();
            }
        }
        info.slices.push_back(std::move(s));
    }
    return info;
}

} // namespace yuzu::shared::binary_header
