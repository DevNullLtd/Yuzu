// network_fstype.hpp -- one shared "can this filesystem type block on a remote server" predicate.
//
// A read-only collector that walks directories on an operator-mountable path (an NFS-mounted
// /opt/java, an automounted tree) must not touch a mount whose server may be down: an
// uninterruptible open/getdents/read/statvfs pins a worker of the agent's ONE bounded command
// pool (shared with every plugin, quarantine dispatch included) until the server returns, and a
// hard mount can hold it for minutes to forever. Callers read /proc/self/mountinfo, pass each
// entry's filesystem type here, and skip the paths under a match. Consumers: the runtimes walk
// and filesystem_posture's `mounts` leg (governance G4-04: a name this list misses is an
// availability risk, not a missing number).
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
// this directory.
#pragma once

#include <string_view>

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

} // namespace yuzu::shared
