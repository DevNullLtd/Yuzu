/**
 * file_search_extents_macos.cpp -- the macOS extents shell: F_LOG2PHYS_EXT over the descriptor of a matched
 * regular file, and getattrlist for the one attribute that says its blocks are shared. Self-gated to
 * __APPLE__ (empty elsewhere), so the plugin's source list names it on every OS.
 *
 * WHAT IS ASKED. The file's logical range in pieces: each call names an offset and the bytes still to map,
 * and the system answers the device offset of that offset and how many bytes follow contiguously. A device
 * offset of -1 is a hole (no space allocated), reported as an unallocated extent with no physical offset.
 * The offsets are what the system reports for the volume (an APFS container offset), and are never
 * reinterpreted. Nothing is read from the file and nothing is written: both calls are queries on a
 * descriptor the caller opened O_RDONLY | O_NONBLOCK | O_NOFOLLOW.
 *
 * COMPRESSED FILES. A file the filesystem keeps compressed has no extents to report: the call answers
 * ENOTSUP. That is the state `compressed` when the file carries the compressed flag, and `unsupported`
 * when it does not (a filesystem that cannot map at all).
 *
 * SHARED. getattrlist's extended common attribute reports whether the file shares all of its blocks with
 * another (a clone). `shared` is set on every allocated extent of such a file and on no other: a file that
 * shares only some blocks (a clone that was partly rewritten) reads unshared, because the system names no
 * extent that is shared, and a flag that could be wrong for a given extent is not reported.
 *
 * BOUNDS. At most kMaxProbes calls per file. A file that needs more reads as the extents seen so far with a
 * count that is a lower bound, never as an unbounded loop. Every call must advance by at least one byte or
 * the read ends as a lower bound.
 */
#include "file_search_legs.hpp"

#if defined(__APPLE__)

#include <fcntl.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>

namespace yuzu::file_search {

namespace {

/// F_LOG2PHYS_EXT calls per file; the answer past this is a lower bound.
constexpr std::size_t kMaxProbes = 256;

/// The device offset the system reports for a range with no space behind it.
constexpr std::int64_t kHole = -1;

/// True when the filesystem says this file shares ALL of its blocks with another file. A failed call or an
/// attribute the filesystem did not return reads false: shared is only ever reported when it was said.
[[nodiscard]] bool shares_all_blocks(int fd) noexcept {
    struct attrlist wanted {};
    wanted.bitmapcount = ATTR_BIT_MAP_COUNT;
    wanted.commonattr = ATTR_CMN_RETURNED_ATTRS;
    wanted.forkattr = ATTR_CMNEXT_EXT_FLAGS; // the extended common attributes ride in forkattr
    struct {
        std::uint32_t length;
        attribute_set_t returned;
        std::uint64_t ext_flags;
    } __attribute__((packed)) reply{};
    if (::fgetattrlist(fd, &wanted, &reply, sizeof reply, FSOPT_ATTR_CMN_EXTENDED) != 0)
        return false;
    if ((reply.returned.forkattr & ATTR_CMNEXT_EXT_FLAGS) == 0)
        return false;
    return (reply.ext_flags & EF_SHARES_ALL_BLOCKS) != 0;
}

} // namespace

FileExtents read_file_extents(int fd, const struct stat& st) {
    FileExtents out;
    out.state = ExtentsState::ok;
    const std::uint64_t size = st.st_size > 0 ? static_cast<std::uint64_t>(st.st_size) : 0;
    if (size == 0)
        return out; // no bytes, no extents: an exact zero

    const bool shared = shares_all_blocks(fd);
    std::uint64_t offset = 0;
    std::size_t probes = 0;
    while (offset < size) {
        if (probes++ >= kMaxProbes) {
            out.total_exact = false;
            return out;
        }
        struct log2phys map {};
        map.l2p_flags = 0;
        map.l2p_contigbytes = static_cast<off_t>(size - offset); // bytes still to map
        map.l2p_devoffset = static_cast<off_t>(offset);          // IN: where in the file
        if (::fcntl(fd, F_LOG2PHYS_EXT, &map) == -1) {
            if (errno == EINTR) {
                --probes; // an interrupted call is retried, not counted against the bound
                continue;
            }
            const int err = errno;
            out = FileExtents{};
            out.state = err == ENOTSUP ? ((st.st_flags & UF_COMPRESSED) != 0 ? ExtentsState::compressed
                                                                             : ExtentsState::unsupported)
                                       : ExtentsState::failed;
            return out;
        }
        if (map.l2p_contigbytes <= 0) { // the system made no progress: stop, and say the count is partial
            out.total_exact = false;
            return out;
        }
        const bool hole = map.l2p_devoffset == kHole;
        const std::uint64_t length = std::min<std::uint64_t>(static_cast<std::uint64_t>(map.l2p_contigbytes), size - offset);
        Extent e;
        e.logical = offset;
        e.physical = hole ? 0 : static_cast<std::uint64_t>(map.l2p_devoffset);
        e.length = length;
        e.flags = flags_from_macos(hole, shared && !hole);
        out.add(e);
        offset += length;
    }
    return out;
}

} // namespace yuzu::file_search

#endif // defined(__APPLE__)
