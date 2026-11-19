// network_fstype.hpp -- one shared "can this filesystem type block on a remote server" predicate,
// the macOS-client extension of it, and the pure /proc/self/mountinfo text parser that feeds it.
//
// A read-only collector that walks directories on an operator-mountable path (an NFS-mounted
// /opt/java, an automounted tree) must not touch a mount whose server may be down: an
// uninterruptible open/getdents/read/statvfs pins a worker of the agent's ONE bounded command
// pool (shared with every plugin, quarantine dispatch included) until the server returns, and a
// hard mount can hold it for minutes to forever. Callers read /proc/self/mountinfo, pass each
// entry's filesystem type here, and skip the paths under a match. Consumers: the runtimes walk,
// filesystem_posture's `mounts` leg (governance G4-04: a name this list misses is an
// availability risk, not a missing number), privacy_permissions' macOS leg and
// remote_access_audit's macOS leg, which use `is_network_mount_fstype` (the same list plus the
// macOS-only names webdav, afpfs, macfuse, osxfuse), and remote_access_audit's Linux leg, which
// reads the mount table through `network_mount_points`.
//
// This is a DENY-list by name and is inherently incomplete -- the durable fix is a known-local
// allowlist, which needs its own review. It covers the network, cluster and paravirtualised types
// whose backing store is remote: nfs, nfs3, nfs4, cifs, smb3, smbfs, afs, ceph, glusterfs, 9p,
// virtiofs, lustre, beegfs, gfs2, ocfs2, gpfs, panfs, vboxsf, vmhgfs, prl_fs, autofs (a direct-map
// trigger point blocks on traversal), and the "fuse.<suffix>" types that are network-backed. It does
// NOT see a STACKED filesystem (an overlay/ecryptfs/loop over a dead network mount reports its own
// local type) or a bare `fuse` mount (many are local): that needs a bounded-call seam in agent
// core, not a longer list. Echo's
// echo_mapdrive_collector.cpp keeps a deliberately different, map-drive-specific set.
//
// Platform-agnostic pure C++, no OS call, no I/O: the zero-dependency leaf-helper convention of
// this directory. `network_mount_points` parses TEXT the caller already read; reading the file
// stays the caller's job.
//
// Two additions serve an on-demand file search that must stay on local disks: `mount_entries`
// parses the same text into one MountEntry per well-formed line (plus a `malformed` count so an
// allow-list consumer can fail CLOSED on a table it could not read in full), and
// `is_searchable_local_fstype` is the exact, case-sensitive ALLOW-list of local filesystem names
// (the Windows names are volume-type names; the "fixed disk" half of the Windows rule is a
// drive-type check the Windows leg makes separately). `dev_major:dev_minor` is a mount label for
// searching each filesystem once, NOT a substitute for the device identity fstat reports (they
// differ on btrfs subvolumes). `mount_entries` is deliberately stricter than
// `network_mount_points` on a malformed line: it counts the line and yields no entry, while the
// unchanged deny-list parser, which never reads the device field, may still report that line's
// mount point.
// The deny-list consumers named above have not moved to this allow-list; for them it is still the
// durable fix that needs its own review.
// `malformed` cannot see every short read: text cut between two lines, or inside the last line's
// super-options, still parses clean. A reader that stopped at its size cap or on an error must
// report the table unreadable itself.
#pragma once

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared {

[[nodiscard]] inline bool is_network_fstype(std::string_view fstype) noexcept {
    constexpr std::string_view kExact[] = {"nfs",   "nfs3",      "nfs4",   "cifs",   "smb3",
                                           "smbfs", "afs",       "ceph",   "glusterfs", "9p",
                                           "virtiofs", "lustre", "beegfs", "gfs2",   "ocfs2",
                                           "gpfs",  "panfs",     "vboxsf", "vmhgfs", "prl_fs",
                                           "autofs"};
    for (const auto s : kExact) {
        if (fstype == s) return true;
    }
    constexpr std::string_view kFusePrefix = "fuse.";
    if (fstype.substr(0, kFusePrefix.size()) == kFusePrefix) {
        const auto suffix = fstype.substr(kFusePrefix.size());
        constexpr std::string_view kFuseSuffixes[] = {"sshfs",  "s3fs",      "davfs", "rclone",
                                                      "cephfs", "glusterfs", "nfs",   "smb",
                                                      "ceph-fuse", "vmhgfs-fuse", "prl_fsd"};
        for (const auto s : kFuseSuffixes) {
            if (suffix == s) return true;
        }
    }
    return false;
}

/// The shared deny-list plus the macOS client names it lacks: `webdav`, `afpfs` and the macFUSE
/// FUSE-over-anything family (`macfuse`, `osxfuse`) -- a user-run FUSE daemon serving a home can
/// hang exactly like a dead server.
[[nodiscard]] inline bool is_network_mount_fstype(std::string_view fstype) noexcept {
    return is_network_fstype(fstype) || fstype == "webdav" || fstype == "afpfs" ||
           fstype == "macfuse" || fstype == "osxfuse";
}

/// Decodes the octal escapes /proc/self/mountinfo uses inside a field (\040 space, \011 tab,
/// \012 newline, \134 backslash). A malformed escape is kept verbatim.
[[nodiscard]] inline std::string unescape_mountinfo(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const bool octal = s[i] == '\\' && i + 3 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '3' &&
                           s[i + 2] >= '0' && s[i + 2] <= '7' && s[i + 3] >= '0' && s[i + 3] <= '7';
        if (!octal) {
            out += s[i];
            continue;
        }
        out += static_cast<char>(((s[i + 1] - '0') << 6) | ((s[i + 2] - '0') << 3) | (s[i + 3] - '0'));
        i += 3;
    }
    return out;
}

/// The mount points of network-backed filesystems in /proc/self/mountinfo text. A line is
/// `id parent maj:min root mount_point options [optional...] - fstype source super_options`;
/// the mount point is field 5 and the filesystem type follows the ` - ` separator. A malformed
/// line is skipped (it names no mount we can avoid); a well-formed line of a local type is not
/// reported.
[[nodiscard]] inline std::vector<std::string> network_mount_points(std::string_view mountinfo) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < mountinfo.size()) {
        const auto nl = mountinfo.find('\n', pos);
        const std::string_view line =
            mountinfo.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? mountinfo.size() : nl + 1;
        const auto sep = line.find(" - ");
        if (sep == std::string_view::npos) continue;
        const std::string_view head = line.substr(0, sep);
        std::string_view mount_point; // the 5th space-separated field of the head
        std::size_t start = 0;
        for (int field = 0; field <= 4 && start <= head.size(); ++field) {
            const auto sp = head.find(' ', start);
            const auto end = sp == std::string_view::npos ? head.size() : sp;
            if (field == 4) mount_point = head.substr(start, end - start);
            start = end + 1;
        }
        if (mount_point.empty()) continue;
        const auto after = line.substr(sep + 3);
        const auto fstype = after.substr(0, after.find(' '));
        if (!is_network_fstype(fstype)) continue;
        out.push_back(unescape_mountinfo(mount_point));
    }
    return out;
}

/// One mount from /proc/self/mountinfo. `dev_major:dev_minor` labels the mount; it is not the
/// fstat device identity.
struct MountEntry {
    std::string mount_point;
    std::string root;
    std::string fstype;
    std::string source;
    std::uint32_t dev_major{0};
    std::uint32_t dev_minor{0};
};

struct MountTable {
    std::vector<MountEntry> entries;
    std::size_t malformed{0}; ///< non-blank lines that yielded no entry
};

namespace detail {
[[nodiscard]] inline bool parse_dev_number(std::string_view s, std::uint32_t& out) noexcept {
    if (s.empty()) return false;
    const char* const end = s.data() + s.size();
    const auto r = std::from_chars(s.data(), end, out);
    return r.ec == std::errc{} && r.ptr == end;
}
} // namespace detail

/// Parses /proc/self/mountinfo text into entries, in table order. A blank line is ignored; a line
/// with no ` - `, fewer than six non-empty head fields (a doubled space leaves an empty one), a
/// `maj:min` that is not digits:digits, no fstype, or a tail that ends before the super-options is
/// counted in `malformed` and yields no entry. The source may be empty (the kernel writes it as it
/// was given to mount: ` - tmpfs  rw`); the super-options always start with ro or rw.
[[nodiscard]] inline MountTable mount_entries(std::string_view mountinfo) {
    MountTable table;
    std::size_t pos = 0;
    while (pos < mountinfo.size()) {
        const auto nl = mountinfo.find('\n', pos);
        const std::string_view line =
            mountinfo.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? mountinfo.size() : nl + 1;
        if (line.empty()) continue;
        const auto sep = line.find(" - ");
        if (sep == std::string_view::npos) {
            ++table.malformed;
            continue;
        }
        const std::string_view head = line.substr(0, sep);
        std::string_view f[6];
        std::size_t start = 0;
        int n = 0;
        while (n < 6 && start <= head.size()) {
            const auto sp = head.find(' ', start);
            const auto end = sp == std::string_view::npos ? head.size() : sp;
            f[n++] = head.substr(start, end - start);
            start = end + 1;
        }
        bool head_complete = n == 6;
        for (const auto field : f)
            head_complete = head_complete && !field.empty();
        const auto colon = head_complete ? f[2].find(':') : std::string_view::npos;
        MountEntry e;
        const std::string_view after = line.substr(sep + 3);
        const auto fs_end = after.find(' ');
        const std::string_view fstype = after.substr(0, fs_end);
        // `src_end` is the space between the source and the super-options; a line cut before the
        // super-options has none, or nothing after it.
        const auto src_end =
            fs_end == std::string_view::npos ? fs_end : after.find(' ', fs_end + 1);
        const bool tail_complete = src_end != std::string_view::npos && src_end + 1 < after.size();
        if (!head_complete || !tail_complete || fstype.empty() || colon == std::string_view::npos ||
            !detail::parse_dev_number(f[2].substr(0, colon), e.dev_major) ||
            !detail::parse_dev_number(f[2].substr(colon + 1), e.dev_minor)) {
            ++table.malformed;
            continue;
        }
        e.root = unescape_mountinfo(f[3]);
        e.mount_point = unescape_mountinfo(f[4]);
        e.fstype = std::string(fstype);
        e.source = unescape_mountinfo(after.substr(fs_end + 1, src_end - fs_end - 1));
        table.entries.push_back(std::move(e));
    }
    return table;
}

/// Exact, case-sensitive allow-list of local filesystem names a search may enter. Everything
/// else (vfat, ntfs, fuseblk, fuse, overlay, squashfs, tmpfs, network types, "") is false.
[[nodiscard]] inline bool is_searchable_local_fstype(std::string_view fstype) noexcept {
    constexpr std::string_view kLocal[] = {"ext2",  "ext3", "ext4", "xfs",  "btrfs", "zfs", "f2fs",
                                           "apfs",  "hfs",  "NTFS", "ReFS", "FAT",   "FAT32", "exFAT"};
    for (const auto s : kLocal) {
        if (fstype == s) return true;
    }
    return false;
}

} // namespace yuzu::shared
