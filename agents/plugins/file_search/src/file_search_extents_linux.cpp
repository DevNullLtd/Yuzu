/**
 * file_search_extents_linux.cpp -- the Linux extents shell: FS_IOC_FIEMAP over the descriptor of a matched
 * regular file. Self-gated to __linux__ (empty elsewhere), so the plugin's source list names it on every OS.
 *
 * THE REQUEST CARRIES FLAGS 0 (fiemap_request, file_search_extents.hpp). The interface's sync flag writes
 * the file's dirty pages back before it answers, and a search must never cause a write; without it a file
 * with data not yet allocated answers with a delayed-allocation extent and no physical offset.
 *
 * TWO REQUESTS AT MOST. The first asks for up to kMaxExtents extents. If it fills its room and the last
 * extent it returned is not marked last, the file has more, and a second request with room for none asks
 * only how many extents there are. If that second request fails the count is the lower bound already seen.
 *
 * WHAT A FAILURE READS AS. A filesystem that does not implement the interface (tmpfs, overlay without it)
 * answers ENOTTY or EOPNOTSUPP: state `unsupported`. Any other failure is `failed`. Neither is an error of
 * the search: the match is still reported, with the state in its extents row.
 *
 * The physical offsets are what the filesystem reports. On btrfs they are logical addresses in its own
 * address space, not device offsets, and every extent says so (the btrfs_logical flag).
 */
#include "file_search_legs.hpp"

#if defined(__linux__)

#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>

namespace yuzu::file_search {

namespace {

/// btrfs's statfs magic (linux/magic.h BTRFS_SUPER_MAGIC), spelled here so the header is not needed.
constexpr std::uint32_t kBtrfsMagic = 0x9123683EU;

constexpr std::size_t kBufferBytes = sizeof(struct fiemap) + kMaxExtents * sizeof(struct fiemap_extent);

/// One FIEMAP request in a buffer aligned for its header, with room for kMaxExtents extents after it (a
/// request that asks for none uses only the header).
struct FiemapBuffer {
    alignas(struct fiemap) unsigned char bytes[kBufferBytes]{};

    [[nodiscard]] struct fiemap* map() noexcept { return reinterpret_cast<struct fiemap*>(bytes); }
    [[nodiscard]] const struct fiemap_extent* extents() const noexcept {
        return reinterpret_cast<const struct fiemap_extent*>(bytes + sizeof(struct fiemap));
    }
};

/// The kernel's answer to `want`, or the errno it failed with (an interrupted call is retried).
[[nodiscard]] std::expected<FiemapBuffer, int> ask(int fd, const FiemapRequest& want) noexcept {
    FiemapBuffer r; // zeroed
    struct fiemap* m = r.map();
    m->fm_start = want.start;
    m->fm_length = want.length;
    m->fm_flags = want.flags; // always 0
    m->fm_extent_count = want.extent_count;
    for (;;) {
        if (::ioctl(fd, FS_IOC_FIEMAP, m) == 0)
            return r;
        if (errno != EINTR)
            return std::unexpected(errno);
    }
}

} // namespace

FileExtents read_file_extents(int fd, const struct stat& /*st*/) {
    FileExtents out;
    struct statfs fs {};
    const bool logical = ::fstatfs(fd, &fs) == 0 && static_cast<std::uint32_t>(fs.f_type) == kBtrfsMagic;

    auto first = ask(fd, fiemap_request());
    if (!first) {
        const int err = first.error();
        out.state = (err == ENOTTY || err == EOPNOTSUPP || err == ENOSYS) ? ExtentsState::unsupported
                                                                          : ExtentsState::failed;
        return out;
    }
    FiemapBuffer& r = *first;
    out.state = ExtentsState::ok;
    const std::size_t mapped = std::min<std::size_t>(r.map()->fm_mapped_extents, kMaxExtents);
    bool last = false;
    for (std::size_t i = 0; i < mapped; ++i) {
        const struct fiemap_extent& e = r.extents()[i];
        out.add({e.fe_logical, e.fe_physical, e.fe_length, flags_from_fiemap(e.fe_flags, logical)});
        last = (e.fe_flags & FIEMAP_EXTENT_LAST) != 0;
    }
    if (mapped < kMaxExtents || last)
        return out; // the kernel returned them all

    auto count = ask(fd, fiemap_count_request());
    if (count && count->map()->fm_mapped_extents >= out.total)
        out.total = count->map()->fm_mapped_extents;
    else
        out.total_exact = false; // the count could not be had: what was seen is a lower bound
    return out;
}

} // namespace yuzu::file_search

#endif // defined(__linux__)
