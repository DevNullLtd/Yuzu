/**
 * test_filesystem_posture_parsers.cpp — PKG-CORE (Wave-1): pure-function
 * tests for filesystem_posture_parsers.hpp and (peer H2) the shared
 * filesystem_posture_legs.hpp seam.
 *
 * Section (E1): parser fixtures driven from the REAL captures at
 * scratchpad/devteam-wave6-1b-fsposture/captures/ (see captures/PROVENANCE.md
 * for the full provenance table); each fixture below carries that file's
 * label verbatim in a comment. SEVERAL groups are not capture-backed, and
 * each is labelled at its own fixture rather than counted here — the
 * non-observed errno rows of classify_quotactl_errno and
 * classify_getattrlist_quota, parse_btrfs_super_options,
 * is_device_mapper_source, and the mountinfo malformed probe. (An earlier
 * revision of this sentence claimed exactly one such group, which was already
 * false when written — governance Gate 3, quality-engineer.) The former
 * parse_gmt_multistring synthetic round-trip was removed with its parser
 * when the Windows snapshots leg moved to VSS/COM (verified on a live
 * Windows host 2026-09-03), so no synthetic fixture remains here.
 *
 * Section (E2): formatter smoke tests (peer H2) -- this is what compiles
 * AND EXECUTES filesystem_posture_legs.hpp in wave 1, the same wave that
 * authors the seam. The formatters are pure (no I/O, no logging), so
 * exercising them here stays within the pure-unit-test rule.
 */
#include <catch2/catch_test_macros.hpp>

#include "filesystem_posture_legs.hpp"
#include "filesystem_posture_parsers.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::filesystem_posture;

namespace {

std::vector<std::byte> hex_to_bytes(std::string_view hex) {
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9')
            return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f')
            return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
            return static_cast<unsigned>(c - 'A' + 10);
        return 0;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const unsigned byte_val = (nibble(hex[i]) << 4) | nibble(hex[i + 1]);
        out.push_back(static_cast<std::byte>(byte_val));
    }
    return out;
}

// host: braga (macOS 26.5.1 arm64) → Docker Desktop 29.7.2, `alpine:3.20`, kernel 7.0.12-linuxkit
// command: docker run --rm alpine:3.20 sh -c 'cat /proc/self/mountinfo'
// date: 2026-09-02
// kind: real (container overlay shape)
constexpr const char* kMountinfoContainerOverlay = R"MNT_OVERLAY(205 147 0:58 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1583/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs,upperdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1584/fs,workdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1584/work,nouserxattr
207 205 0:81 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
208 205 0:82 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
209 208 0:83 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
210 205 0:84 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
211 210 0:41 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
212 208 0:79 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
213 208 0:85 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
214 205 254:1 /docker/containers/d7cf4a90b62bf641f5fe93088fc5695a1a008d0d13773162d5ae74be19b133d3/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw,discard
215 205 254:1 /docker/containers/d7cf4a90b62bf641f5fe93088fc5695a1a008d0d13773162d5ae74be19b133d3/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw,discard
216 205 254:1 /docker/containers/d7cf4a90b62bf641f5fe93088fc5695a1a008d0d13773162d5ae74be19b133d3/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw,discard
148 207 0:81 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
149 207 0:81 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
150 207 0:81 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
151 207 0:81 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
152 207 0:81 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
153 207 0:82 /null /proc/interrupts rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
154 207 0:82 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
155 207 0:82 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
156 207 0:86 / /proc/scsi ro,relatime - tmpfs tmpfs ro,size=4k,nr_inodes=1
157 207 0:82 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
158 210 0:86 / /sys/firmware ro,relatime - tmpfs tmpfs ro,size=4k,nr_inodes=1
)MNT_OVERLAY";

// host: same VM, PID-1 namespace
// command: docker run --rm --privileged --pid=host alpine:3.20 sh -c 'cat /proc/1/mountinfo'
// date: 2026-09-02
// kind: real (VM-native shape; 4 rows carry `shared:N` optional fields)
constexpr const char* kMountinfoVmNative = R"MNT_VMNATIVE(26 32 254:16 / /oldroot ro,relatime - erofs /dev/root ro,user_xattr,acl,cache_strategy=readaround
27 26 0:7 / /oldroot/dev rw,relatime - devtmpfs devtmpfs rw,size=4061136k,nr_inodes=1015284,mode=755
28 26 0:24 / /oldroot/proc rw,nosuid,nodev,noexec,relatime - proc proc rw
29 26 0:25 / /oldroot/run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=812452k,mode=755
32 1 0:26 / / rw,relatime - overlay overlay rw,lowerdir=/,upperdir=/run/rootfs.upper,workdir=/run/rootfs.workdir,uuid=on,nouserxattr
33 32 0:7 / /dev rw,nosuid,noexec,relatime - devtmpfs devtmpfs rw,size=4061136k,nr_inodes=1015284,mode=755
34 32 0:29 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
35 32 0:30 / /run rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=812452k,mode=755
36 32 0:31 / /var rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=4062260k,mode=755
37 32 0:32 / /host_mnt rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=812452k,mode=755
38 32 0:33 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=812452k
39 33 0:23 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
40 33 0:34 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw
41 33 0:35 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,mode=620,ptmxmode=666
42 32 0:36 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
43 42 0:8 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime - securityfs securityfs rw
44 42 0:9 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw
45 42 0:37 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime - configfs configfs rw
46 42 0:38 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime - fusectl fusectl rw
47 42 0:39 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime - pstore none rw
48 42 0:40 / /sys/fs/bpf rw,nodev,relatime - bpf bpffs rw
49 42 0:41 /../.. /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw
50 35 0:5 net:[4026532334] /run/netns/services rw - nsfs nsfs rw
51 35 0:42 / /run/rpc_pipefs rw,relatime - rpc_pipefs rpc_pipefs rw
52 34 0:44 / /proc/sys/fs/binfmt_misc rw,relatime - binfmt_misc binfmt_misc rw
53 37 0:43 / /host_mnt/Users rw,nosuid,nodev,relatime - virtiofs virtiofs0 rw,ignore_atime,no_xattr
54 37 0:45 / /host_mnt/Volumes rw,nosuid,nodev,relatime - virtiofs virtiofs1 rw,ignore_atime,no_xattr
55 37 0:46 / /host_mnt/private rw,nosuid,nodev,relatime - virtiofs virtiofs2 rw,ignore_atime,no_xattr
56 37 0:47 / /host_mnt/tmp rw,nosuid,nodev,relatime - virtiofs virtiofs3 rw,ignore_atime,no_xattr
57 37 0:48 / /host_mnt/var/folders rw,nosuid,nodev,relatime - virtiofs virtiofs4 rw,ignore_atime,no_xattr
58 35 0:49 / /run/rosetta.orig rw,relatime - virtiofs ROSETTA rw,negative_dentry_timeout=3600,entry_timeout=3600,attr_timeout=3600,ignore_atime,no_flush,keep_cache
59 36 254:1 / /var/lib rw,relatime - ext4 /dev/vda1 rw,discard
60 44 0:14 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw
61 35 0:50 / /run/jfs rw,nosuid,nodev,relatime - fuse.rawBridge rawBridge rw,user_id=0,group_id=0,allow_other,max_read=131072
62 35 0:51 / /run/rosetta rw,nosuid,nodev,relatime - fuse.rosetta-mount rosetta-mount rw,user_id=0,group_id=0,allow_other
63 35 0:52 / /run/mutagen-file-shares-mark rw,nosuid,nodev,relatime - selfowner /var/lib/mutagen/file-shares rw,mark
64 35 0:53 / /run/mutagen-file-shares rw,nosuid,nodev,relatime - selfowner /run/mutagen-file-shares-mark rw
65 59 254:1 /docker /var/lib/docker rw,relatime shared:1 - ext4 /dev/vda1 rw,discard
81 65 0:54 / /var/lib/docker/rootfs/overlayfs/5b39ddbcee47957bc2f6684600d5e9c507c511ed7d87f2ccf858e1634cfaac62 rw,relatime shared:2 - overlay overlay rw,lowerdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/562/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/525/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/524/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/523/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/522/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/521/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/520/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/519/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/518/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/517/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/516/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/515/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/514/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/513/fs,upperdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/563/fs,workdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/563/work,nouserxattr
82 35 0:5 net:[4026532558] /run/docker/netns/e18e5a8ce364 rw - nsfs nsfs rw
112 65 0:56 / /var/lib/docker/rootfs/overlayfs/20442ef1a63cdf8bc139acdaf26d5564c34b5918a6cf50f8943faa807b907251 rw,relatime shared:3 - overlay overlay rw,lowerdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1037/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/534/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/533/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/525/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/524/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/523/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/522/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/521/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/520/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/519/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/518/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/517/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/516/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/515/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/514/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/513/fs,upperdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1038/fs,workdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1038/work,nouserxattr
113 35 0:5 net:[4026532694] /run/docker/netns/91998d54b972 rw - nsfs nsfs rw
142 65 0:58 / /var/lib/docker/rootfs/overlayfs/c4075a1d7571beefde5fc2cce219a92ab1ca5b85916effca0d6d021a47e885a7 rw,relatime shared:4 - overlay overlay rw,lowerdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1586/fs:/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs,upperdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1587/fs,workdir=/var/lib/desktop-containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/1587/work,nouserxattr
143 35 0:5 net:[4026532829] /run/docker/netns/54d7f8c3d163 rw - nsfs nsfs rw
)MNT_VMNATIVE";

// host: braga, macOS 26.5.1 arm64
// command: fs_snapshot_list(open("/",O_RDONLY), {bitmapcount=ATTR_BIT_MAP_COUNT,
//          commonattr=ATTR_BULK_REQUIRED}, buf, 65536, 0) -> 3 entries, 344 bytes, hex-dumped
// date: 2026-09-02
// kind: real (binary fixture); meta: returned_count=3 total_bytes=344
//       sizeof(attribute_set_t)=20 sizeof(attrreference_t)=8
constexpr const char* kFsSnapshotListRootHex =
    "7800000001000080000000000000000000000000000000000800000055000000636f6d2e6170706c652e6f732e757064"
    "6174652d4536363530383836383935353639343741444636323142303035334234434131363632414542363732393539"
    "304235413544343343333136364643314345384600000000980000000100008000000000000000000000000000000000"
    "0800000075000000636f6d2e6170706c652e6f732e7570646174652d3133344443343543414643393432353534443738"
    "313742463737313136364234323230374535334432453131413245384341414243433832313846413432303230374145"
    "464330313638324631383439393642394531323445414445384639350000000048000000010000800000000000000000"
    "00000000000000000800000025000000636f6d2e6170706c652e6f732e7570646174652d4d5355507265706172655570"
    "6461746500000000";

} // namespace

// ============================================================================
// (E1) Parser fixtures — real captures
// ============================================================================

TEST_CASE("filesystem_posture: parse_proc_mountinfo -- real container-overlay capture",
         "[filesystem_posture]") {
    auto parsed = parse_proc_mountinfo(kMountinfoContainerOverlay);
    CHECK(parsed.entries.size() == 22);
    CHECK(parsed.malformed_lines == 0);
    CHECK_FALSE(parsed.truncated);
    // Zero optional fields anywhere in this capture (container overlay shape).
    for (const auto& e : parsed.entries)
        CHECK(e.optional_fields.empty());
}

TEST_CASE("filesystem_posture: parse_proc_mountinfo -- real VM-native capture",
         "[filesystem_posture]") {
    auto parsed = parse_proc_mountinfo(kMountinfoVmNative);
    CHECK(parsed.entries.size() == 44);
    CHECK(parsed.malformed_lines == 0);
    CHECK_FALSE(parsed.truncated);

    int shared_count = 0;
    for (const auto& e : parsed.entries) {
        for (const auto& f : e.optional_fields) {
            if (f == "shared:1" || f == "shared:2" || f == "shared:3" || f == "shared:4")
                ++shared_count;
        }
    }
    CHECK(shared_count == 4);

    // Four nsfs rows whose root contains a colon and brackets (net:[4026532xxx]).
    int nsfs_bracket_roots = 0;
    for (const auto& e : parsed.entries) {
        if (e.fstype == "nsfs" && e.root.find(':') != std::string::npos &&
            e.root.find('[') != std::string::npos)
            ++nsfs_bracket_roots;
    }
    CHECK(nsfs_bracket_roots == 4);
}

TEST_CASE("filesystem_posture: parse_proc_mountinfo -- malformed lines are skipped, not fatal",
         "[filesystem_posture]") {
    // Constructed grammar probe (not a capture): one well-formed line, one
    // with too few fields, one whose fixed trailing slot isn't "-".
    constexpr const char* kMixed = "205 147 0:58 / / rw,relatime - overlay overlay rw\n"
                                   "too few fields here\n"
                                   "1 2 0:1 / / rw x overlay overlay rw\n";
    auto parsed = parse_proc_mountinfo(kMixed);
    CHECK(parsed.entries.size() == 1);
    CHECK(parsed.malformed_lines == 2);
}

TEST_CASE("filesystem_posture: unescape_mountinfo_octal -- known escapes decode; malformed/"
         "unrecognized escapes pass through literally",
         "[filesystem_posture]") {
    CHECK(unescape_mountinfo_octal("a\\040b") == "a b");
    CHECK(unescape_mountinfo_octal("a\\011b") == "a\tb");
    CHECK(unescape_mountinfo_octal("a\\012b") == "a\nb");
    CHECK(unescape_mountinfo_octal("a\\134b") == "a\\b");
    CHECK(unescape_mountinfo_octal("plain") == "plain");
    // Well-formed 3-digit octal but not one of the four -- literal passthrough.
    CHECK(unescape_mountinfo_octal("a\\177b") == "a\\177b");
    // Non-octal digit after backslash -- never dropped, reconstructed byte for byte.
    CHECK(unescape_mountinfo_octal("a\\999b") == "a\\999b");
    // Truncated escape at end of string -- never dropped.
    CHECK(unescape_mountinfo_octal("a\\1") == "a\\1");
}

TEST_CASE("filesystem_posture: quota_state_token -- pinned lowercase wire tokens",
         "[filesystem_posture]") {
    CHECK(quota_state_token(QuotaState::Configured) == "configured");
    CHECK(quota_state_token(QuotaState::None) == "none");
    CHECK(quota_state_token(QuotaState::NotEnabled) == "not_enabled");
    CHECK(quota_state_token(QuotaState::UnsupportedFs) == "unsupported_fs");
    CHECK(quota_state_token(QuotaState::NoBlockDevice) == "no_block_device");
    CHECK(quota_state_token(QuotaState::PermissionDenied) == "permission_denied");
    CHECK(quota_state_token(QuotaState::Unavailable) == "unavailable");
}

TEST_CASE("filesystem_posture: classify_quotactl_errno -- split evidence provenance (peer M7)",
         "[filesystem_posture]") {
    // captures/linux-quotactl-probe.txt, taken 2026-09-02: real quotactl(2)
    // Q_GETFMT/Q_GETINFO/Q_GETQUOTA probe on the Docker Desktop VM.
    CHECK(classify_quotactl_errno(3) == QuotaState::NotEnabled);     // ESRCH -- observed on /dev/vda1
    CHECK(classify_quotactl_errno(38) == QuotaState::UnsupportedFs); // ENOSYS -- observed on /dev/root
    CHECK(classify_quotactl_errno(2) ==
         QuotaState::NoBlockDevice); // ENOENT -- observed on overlay & /nonexistent

    // documented-inference from quotactl(2) -- not capture-backed (peer M7):
    // the probe ran privileged on one VM and never produced these errnos.
    CHECK(classify_quotactl_errno(15) == QuotaState::NoBlockDevice);     // ENOTBLK
    CHECK(classify_quotactl_errno(1) == QuotaState::PermissionDenied);  // EPERM
    CHECK(classify_quotactl_errno(13) == QuotaState::PermissionDenied); // EACCES
    CHECK(classify_quotactl_errno(5) == QuotaState::Unavailable);       // EIO
    CHECK(classify_quotactl_errno(0) == QuotaState::Configured);
}

TEST_CASE("filesystem_posture: classify_getattrlist_quota -- rc/err/size classification (peer M14)",
         "[filesystem_posture]") {
    // Every APFS volume on the capture host returned rc=0 quota=0 reserved=0
    // on 2026-09-02 -- the (0,0,*,*) rows below are capture-backed; the
    // errno-driven rows are documented-inference from getattrlist(2), not
    // separately observed.
    CHECK(classify_getattrlist_quota(0, 0, 0, 0) == QuotaState::None);
    CHECK(classify_getattrlist_quota(0, 0, 53687091200ULL, 0) == QuotaState::Configured);
    CHECK(classify_getattrlist_quota(-1, 1 /* EPERM */, 0, 0) == QuotaState::PermissionDenied);
    CHECK(classify_getattrlist_quota(-1, 13 /* EACCES */, 0, 0) == QuotaState::PermissionDenied);
    CHECK(classify_getattrlist_quota(-1, 45 /* ENOTSUP */, 0, 0) == QuotaState::UnsupportedFs);
    CHECK(classify_getattrlist_quota(-1, 5 /* EIO */, 0, 0) == QuotaState::Unavailable);
}

TEST_CASE("filesystem_posture: parse_btrfs_super_options -- constructed grammar probe (no real "
         "btrfs host available; captures/linux-sysfs-block.txt records the negative result, "
         "2026-09-02)",
         "[filesystem_posture]") {
    auto sv = parse_btrfs_super_options("rw,relatime,ssd,space_cache,subvolid=256,subvol=/@");
    CHECK(sv.present);
    CHECK(sv.subvolid == "256");
    CHECK(sv.subvol == "/@");

    auto none = parse_btrfs_super_options("rw,discard");
    CHECK_FALSE(none.present);
}

TEST_CASE("filesystem_posture: is_device_mapper_source -- pinned predicate (peer M4), constructed "
         "grammar probe (no dm host available; captures/linux-sysfs-block.txt records the "
         "negative result, 2026-09-02)",
         "[filesystem_posture]") {
    CHECK(is_device_mapper_source("/dev/mapper/vg0-root"));
    CHECK(is_device_mapper_source("/dev/dm-3"));
    CHECK_FALSE(is_device_mapper_source("/dev/sda1"));
    CHECK_FALSE(is_device_mapper_source("/dev/disk/by-uuid/x"));
    CHECK_FALSE(is_device_mapper_source("dm-3"));
}

TEST_CASE("filesystem_posture: normalize_mount_flags -- fixed order, unknown tokens dropped",
         "[filesystem_posture]") {
    CHECK(normalize_mount_flags("rw,relatime,nosuid,attr2,inode64,somejunk") == "rw,nosuid,relatime");
    CHECK(normalize_mount_flags("ro") == "ro");
    CHECK(normalize_mount_flags("") == "");
}

TEST_CASE("filesystem_posture: is_network_fstype -- fixed network fstype set",
         "[filesystem_posture]") {
    // The shared predicate (agents/shared/network_fstype.hpp), pinned entry by entry: dropping
    // or misspelling one name silently re-exposes a hang-prone mount type.
    for (const char* t : {"nfs", "nfs3", "nfs4", "cifs", "smb3", "smbfs", "afs", "ceph", "glusterfs",
                          "9p", "virtiofs", "lustre", "beegfs", "gfs2", "ocfs2", "gpfs", "panfs",
                          "vboxsf", "vmhgfs", "prl_fs", "autofs", "fuse.sshfs", "fuse.s3fs", "fuse.davfs",
                          "fuse.rclone", "fuse.cephfs", "fuse.glusterfs", "fuse.nfs", "fuse.smb",
                          "fuse.ceph-fuse", "fuse.vmhgfs-fuse", "fuse.prl_fsd"}) {
        INFO("fstype: " << t);
        CHECK(is_network_fstype(t));
    }
    // Negatives; fuse.rosetta-mount is a real VM-native capture row (a FUSE mount, not a network one).
    for (const char* t : {"", "fuse.rosetta-mount", "ext4", "xfs", "tmpfs", "overlay", "nfsd", "fuse",
                          "fuse.", "fuse.overlayfs", "fuse.sshfsx", "cifsx", "NFS"}) {
        INFO("fstype: " << t);
        CHECK_FALSE(is_network_fstype(t));
    }
}

TEST_CASE("filesystem_posture: parse_fs_snapshot_list_buffer -- real macOS fs_snapshot_list "
         "capture",
         "[filesystem_posture]") {
    auto bytes = hex_to_bytes(kFsSnapshotListRootHex);
    REQUIRE(bytes.size() == 344);
    auto result = parse_fs_snapshot_list_buffer(std::span<const std::byte>(bytes), 3);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.malformed);
    REQUIRE(result.names.size() == 3);
    CHECK(result.names[0] ==
         "com.apple.os.update-E665088689556947ADF621B0053B4CA1662AEB6729590B5A5D43C3166FC1CE8F");
    CHECK(result.names[1] == "com.apple.os.update-134DC45CAFC942554D7817BF771166B42207E53D2E11A2E8"
                            "CAABCC8218FA420207AEFC01682F184996B9E124EADE8F95");
    CHECK(result.names[2] == "com.apple.os.update-MSUPrepareUpdate");
}

TEST_CASE("filesystem_posture: parse_fs_snapshot_list_buffer -- truncated buffer sets malformed, "
         "no out-of-bounds read",
         "[filesystem_posture]") {
    auto bytes = hex_to_bytes(kFsSnapshotListRootHex);
    bytes.resize(100); // truncate the real 344-byte capture to 100 bytes
    auto result = parse_fs_snapshot_list_buffer(std::span<const std::byte>(bytes), 3);
    CHECK(result.malformed);
    CHECK(result.names.size() < 3);
}

TEST_CASE("filesystem_posture: parse_fs_snapshot_list_buffer -- attribute reference is bounded "
         "independently of the outer record length (peer PKG-004)",
         "[filesystem_posture]") {
    // Constructed grammar probe: a single 32-byte record whose OUTER length
    // is valid (record_length=32, within the 32-byte buffer) but whose
    // attr_dataoffset/attr_length derive a name span reaching far past the
    // buffer. If the derived-offset bounds check regressed, this would
    // dereference out of range instead of setting malformed.
    std::vector<std::byte> bytes(32);
    auto put_u32 = [&bytes](std::size_t offset, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    };
    put_u32(0, 32);         // record_length -- fits the outer buffer exactly
    put_u32(24, 0x7fffffff); // attr_dataoffset -- wildly out of range
    put_u32(28, 1);          // attr_length

    const auto result = parse_fs_snapshot_list_buffer(bytes, 1);
    CHECK(result.malformed);
    CHECK(result.names.empty());
}

TEST_CASE("filesystem_posture: parse_fs_snapshot_list_buffer -- zero attr_length and a non-NUL "
         "final byte are rejected (peer PKG-006)",
         "[filesystem_posture]") {
    std::vector<std::byte> zero_length(32);
    auto put_u32 = [](std::vector<std::byte>& b, std::size_t offset, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            b[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    };
    put_u32(zero_length, 0, 32);
    put_u32(zero_length, 24, 0);
    put_u32(zero_length, 28, 0); // attr_length == 0 -- no NUL to recover
    CHECK(parse_fs_snapshot_list_buffer(zero_length, 1).malformed);

    // attr_dataoffset=8 places the name at byte 32 (just past the 32-byte
    // header), leaving it untouched by the header writes above so it keeps
    // its initial 'x' fill -- a non-NUL final byte where attr_length=1
    // claims a NUL-terminated single-byte name.
    std::vector<std::byte> unterminated(33, std::byte{'x'});
    put_u32(unterminated, 0, 33);
    put_u32(unterminated, 24, 8);
    put_u32(unterminated, 28, 1);
    CHECK(parse_fs_snapshot_list_buffer(unterminated, 1).malformed);
}

// ============================================================================
// (E2) Formatter smoke tests -- compiles AND executes filesystem_posture_legs.hpp
// ============================================================================

TEST_CASE("filesystem_posture: format_mount_row -- pinned pipe-delimited bytes",
         "[filesystem_posture]") {
    CHECK(format_mount_row("/", "/dev/disk3s1s1", "apfs", "-", 494384795648ULL, 10ULL, 5ULL,
                           "ro,nosuid") == "mount|/|/dev/disk3s1s1|apfs|-|494384795648|10|5|ro,nosuid");

    // std::nullopt renders as the literal '-' for every byte-count column.
    auto row = format_mount_row("/mnt", "/dev/sdb1", "ext4", "rw", std::nullopt, std::nullopt,
                                std::nullopt, "rw");
    CHECK(row == "mount|/mnt|/dev/sdb1|ext4|rw|-|-|-|rw");
    CHECK_FALSE(row.ends_with('\n'));

    // A mount_point containing '|' round-trips through the SDK's OWN escaping
    // -- the expected string is built by calling safe_output_field directly
    // so this assertion tracks the SDK's escaping, not a private copy of it.
    const std::string escaped_mp = yuzu::util::safe_output_field("/weird|path");
    auto escaped_row =
        format_mount_row("/weird|path", "/dev/x", "ext4", "rw", std::nullopt, std::nullopt,
                         std::nullopt, "rw");
    CHECK(escaped_row == "mount|" + escaped_mp + "|/dev/x|ext4|rw|-|-|-|rw");

    // Every independently-escaped field has its own call site to
    // safe_output_field (peer PKG-003) -- exercise device, fstype and
    // options with delimiter-bearing values so removing any one call site
    // would fail this test, not just the mount_point case above.
    const auto device = yuzu::util::safe_output_field("dev|ice");
    const auto fstype = yuzu::util::safe_output_field("fs|type");
    const auto options = yuzu::util::safe_output_field("opt|ions");
    CHECK(format_mount_row("/", "dev|ice", "fs|type", "opt|ions", std::nullopt, std::nullopt,
                           std::nullopt, "rw") ==
          "mount|/|" + device + "|" + fstype + "|" + options + "|-|-|-|rw");
}

TEST_CASE("filesystem_posture: format_quota_row -- literal volume scope, wire token",
         "[filesystem_posture]") {
    auto row = format_quota_row("/", QuotaState::Configured, 53687091200ULL, 1024ULL, "-");
    CHECK(row == "quota|/|volume|configured|53687091200|1024|-");
    CHECK_FALSE(row.ends_with('\n'));

    auto none_row =
        format_quota_row("/mnt", QuotaState::NoBlockDevice, std::nullopt, std::nullopt, "overlay");
    CHECK(none_row == "quota|/mnt|volume|no_block_device|-|-|overlay");

    // detail has its own escaping call site (peer PKG-003).
    const auto detail = yuzu::util::safe_output_field("quota|detail");
    CHECK(format_quota_row("/", QuotaState::None, std::nullopt, std::nullopt, "quota|detail") ==
          "quota|/|volume|none|-|-|" + detail);
}

TEST_CASE("filesystem_posture: format_snapshot_row -- fixed kind literal emitted verbatim",
         "[filesystem_posture]") {
    auto row = format_snapshot_row("/", "com.apple.os.update-XYZ", "apfs", "-");
    CHECK(row == "snapshot|/|com.apple.os.update-XYZ|apfs|-");
    CHECK_FALSE(row.ends_with('\n'));

    auto none_row =
        format_snapshot_row("/mnt", "-", "none", "no btrfs or device-mapper mount found");
    CHECK(none_row == "snapshot|/mnt|-|none|no btrfs or device-mapper mount found");

    // name and detail each have their own escaping call site (peer PKG-003).
    const auto name = yuzu::util::safe_output_field("snap|name");
    const auto detail = yuzu::util::safe_output_field("snap|detail");
    CHECK(format_snapshot_row("/", "snap|name", "apfs", "snap|detail") ==
          "snapshot|/|" + name + "|apfs|" + detail);
}
