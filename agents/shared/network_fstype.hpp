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
// core, not a longer list. TAR's
// tar_mapdrive_collector.cpp keeps a deliberately different, map-drive-specific set.
//
// Platform-agnostic pure C++, no OS call, no I/O: the zero-dependency leaf-helper convention of
// this directory. `network_mount_points` parses TEXT the caller already read; reading the file
// stays the caller's job.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
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

} // namespace yuzu::shared
