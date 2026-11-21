/**
 * file_search_extents.hpp -- the extent model of a matched file, its flag tokens, the request the Linux
 * shell makes and the extents row. Pure: no OS header, no I/O; the shells (file_search_extents_linux.cpp,
 * file_search_extents_macos.cpp) only bind the system calls and fill this model.
 *
 * WHAT IS RECORDED. For a matched regular file: up to kMaxExtents extents, each a logical offset, a
 * physical offset, a length and a set of flags, then the count of extents seen (exact, or a lower bound
 * where the system cannot count without listing). Offsets are the numbers the filesystem reports; what
 * they are offsets INTO depends on the filesystem (a block device, a btrfs logical address space, an APFS
 * container) and the `btrfs_logical` flag marks the one case the leg can name. Nothing here reads a byte
 * of the file and none is hashed: the file is opened and never read.
 *
 * The request carries flags 0 on purpose. The sync flag of the Linux interface writes the file's dirty
 * pages back before it answers; a search must never cause a write.
 */
#pragma once

#include <file_search_names.hpp>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace yuzu::file_search {

namespace fsr = yuzu::shared::file_search;

/// Extents listed per file; the rest are counted.
inline constexpr std::size_t kMaxExtents = 32;

/// Extent flags, in the order their tokens are printed.
enum ExtentFlag : std::uint32_t {
    kResident = 1u << 0,     // the data lives inside the metadata, not in blocks of its own
    kDelalloc = 1u << 1,     // space is promised but not allocated yet: no physical offset
    kShared = 1u << 2,       // blocks shared with another file
    kCompressed = 1u << 3,   // the filesystem stores the data encoded (compression)
    kEncrypted = 1u << 4,    // the filesystem encrypts the data
    kUnwritten = 1u << 5,    // allocated but never written: reads as zeros
    kUnallocated = 1u << 6,  // a hole: no space is allocated for this range
    kBtrfsLogical = 1u << 7, // the physical offset is a btrfs logical address, not a device offset
};

inline constexpr const char* kExtentFlagTokens[] = {"resident",  "delalloc",    "shared",   "compressed",
                                                    "encrypted", "unwritten",   "unallocated", "btrfs_logical"};

[[nodiscard]] inline std::string format_extent_flags(std::uint32_t flags) {
    std::string out;
    for (std::size_t i = 0; i < std::size(kExtentFlagTokens); ++i) {
        if ((flags & (1u << i)) == 0)
            continue;
        if (!out.empty())
            out += '+';
        out += kExtentFlagTokens[i];
    }
    return out.empty() ? std::string{"-"} : out;
}

/// The Linux extent interface's flag bits, spelled here so this header needs no kernel header.
namespace fiemap_bits {
inline constexpr std::uint32_t kFmDelalloc = 0x00000004;
inline constexpr std::uint32_t kFmEncoded = 0x00000008;
inline constexpr std::uint32_t kFmEncrypted = 0x00000080;
inline constexpr std::uint32_t kFmDataInline = 0x00000200;
inline constexpr std::uint32_t kFmUnwritten = 0x00000800;
inline constexpr std::uint32_t kFmShared = 0x00002000;
} // namespace fiemap_bits

/// Our flags from one Linux extent's flag word. Bits that say nothing the row reports (last extent,
/// location unknown, not block aligned, tail-packed, merged) are not reported. `encoded` is the
/// filesystem's own encoding of the data (compression on the filesystems that set it) and reads as
/// `compressed`. `logical_addresses` is true when the file is on btrfs.
[[nodiscard]] constexpr std::uint32_t flags_from_fiemap(std::uint32_t fm_flags, bool logical_addresses) noexcept {
    std::uint32_t f = 0;
    if ((fm_flags & fiemap_bits::kFmDataInline) != 0)
        f |= kResident;
    if ((fm_flags & fiemap_bits::kFmDelalloc) != 0)
        f |= kDelalloc;
    if ((fm_flags & fiemap_bits::kFmShared) != 0)
        f |= kShared;
    if ((fm_flags & fiemap_bits::kFmEncoded) != 0)
        f |= kCompressed;
    if ((fm_flags & fiemap_bits::kFmEncrypted) != 0)
        f |= kEncrypted;
    if ((fm_flags & fiemap_bits::kFmUnwritten) != 0)
        f |= kUnwritten;
    if (logical_addresses)
        f |= kBtrfsLogical;
    return f;
}

/// Our flags on macOS: a range whose device offset reads -1 is a hole, and a file whose attributes say it
/// shares blocks with another marks every extent shared.
[[nodiscard]] constexpr std::uint32_t flags_from_macos(bool hole, bool shares_blocks) noexcept {
    return (hole ? kUnallocated : 0u) | (shares_blocks ? kShared : 0u);
}

struct Extent {
    std::uint64_t logical{0};
    std::uint64_t physical{0};
    std::uint64_t length{0};
    std::uint32_t flags{0};
    bool operator==(const Extent&) const = default;
};

/// ok: the extents (and the count) are the answer. compressed: the filesystem keeps the file compressed
/// and reports no extents for it (macOS answers ENOTSUP). unsupported: this filesystem or system does
/// not report extents. failed: the read failed.
enum class ExtentsState { ok, compressed, unsupported, failed };

[[nodiscard]] constexpr const char* to_token(ExtentsState s) noexcept {
    switch (s) {
    case ExtentsState::ok:
        return "ok";
    case ExtentsState::compressed:
        return "compressed";
    case ExtentsState::unsupported:
        return "unsupported";
    case ExtentsState::failed:
        return "failed";
    }
    return "failed";
}

struct FileExtents {
    ExtentsState state{ExtentsState::unsupported};
    std::vector<Extent> extents; // at most kMaxExtents
    std::uint64_t total{0};      // extents seen, listed or not
    bool total_exact{true};      // false: `total` is a lower bound

    /// Counts one extent seen and keeps it while there is room.
    void add(const Extent& e) {
        if (extents.size() < kMaxExtents)
            extents.push_back(e);
        ++total;
    }
};

/// The first request of the Linux shell: the whole file, no flags, room for kMaxExtents extents. A second
/// request with extent_count 0 asks only how many extents the file has.
struct FiemapRequest {
    std::uint64_t start{0};
    std::uint64_t length{~std::uint64_t{0}};
    std::uint32_t flags{0}; // never the sync flag: it writes the file's dirty pages back
    std::uint32_t extent_count{static_cast<std::uint32_t>(kMaxExtents)};
};

[[nodiscard]] constexpr FiemapRequest fiemap_request() noexcept { return {}; }

[[nodiscard]] constexpr FiemapRequest fiemap_count_request() noexcept {
    FiemapRequest r;
    r.extent_count = 0;
    return r;
}

/// `extents|<dev:id>|<state>|<total>|<list>`: <total> is the count or `>=<count>` for a lower bound; <list>
/// is up to kMaxExtents of `<logical>:<physical>:<length>:<flags>` joined by ',', or `-` for none. The
/// identity is the key of the file's match row.
[[nodiscard]] inline std::string format_extents_row(fsr::FileIdentity id, const FileExtents& x) {
    std::string row = "extents|" + fsr::format_file_identity(id) + "|" + to_token(x.state) + "|";
    if (!x.total_exact)
        row += ">=";
    row += std::to_string(x.total);
    row += '|';
    if (x.extents.empty()) {
        row += '-';
        return row;
    }
    for (std::size_t i = 0; i < x.extents.size(); ++i) {
        const Extent& e = x.extents[i];
        if (i != 0)
            row += ',';
        row += std::to_string(e.logical) + ":" + std::to_string(e.physical) + ":" + std::to_string(e.length) + ":" +
               format_extent_flags(e.flags);
    }
    return row;
}

} // namespace yuzu::file_search
