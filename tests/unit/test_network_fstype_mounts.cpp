// Pure tests for mount_entries() and is_searchable_local_fstype() in
// agents/shared/network_fstype.hpp: fixture text in, entries out, no I/O.
#include <catch2/catch_test_macros.hpp>

#include <network_fstype.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::shared;

namespace {

constexpr std::string_view kRealShape =
    "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro\n"
    "30 22 8:1 / /boot/efi rw,relatime shared:7 master:2 - vfat /dev/sda1 rw,fmask=0077\n"
    "31 22 0:25 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n"
    "40 22 0:40 / /mnt/my\\040share rw,relatime shared:20 - nfs4 srv:/export/my\\040share rw,vers=4.2\n"
    "41 22 0:41 / /var/lib/docker/overlay2/x/merged rw,relatime - overlay overlay rw,lowerdir=/a\n"
    "42 22 8:2 /sub /bind rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
    "43 22 0:44 /@home /home rw,relatime shared:30 - btrfs /dev/nvme0n1p3 rw,subvol=/@home\n";

} // namespace

TEST_CASE("mount_entries: real-shape table parses exactly, in order", "[network_fstype]") {
    const auto t = mount_entries(kRealShape);
    CHECK(t.malformed == 0);
    REQUIRE(t.entries.size() == 7);
    CHECK(t.entries[0].mount_point == "/");
    CHECK(t.entries[0].root == "/");
    CHECK(t.entries[0].fstype == "ext4");
    CHECK(t.entries[0].source == "/dev/sda2");
    CHECK(t.entries[0].dev_major == 8);
    CHECK(t.entries[0].dev_minor == 2);
    CHECK(t.entries[1].mount_point == "/boot/efi");
    CHECK(t.entries[1].fstype == "vfat");
    CHECK(t.entries[1].dev_minor == 1);
    CHECK(t.entries[2].fstype == "proc");
    CHECK(t.entries[2].source == "proc");
    CHECK(t.entries[3].mount_point == "/mnt/my share");
    CHECK(t.entries[3].fstype == "nfs4");
    CHECK(t.entries[3].source == "srv:/export/my share");
    CHECK(t.entries[3].dev_major == 0);
    CHECK(t.entries[3].dev_minor == 40);
    CHECK(t.entries[4].fstype == "overlay");
    CHECK(t.entries[4].mount_point == "/var/lib/docker/overlay2/x/merged");
    CHECK(t.entries[5].mount_point == "/bind");
    CHECK(t.entries[5].root == "/sub");
    CHECK(t.entries[6].fstype == "btrfs");
    CHECK(t.entries[6].root == "/@home");
    CHECK(t.entries[6].source == "/dev/nvme0n1p3");
}

TEST_CASE("mount_entries: root is octal-decoded like the mount point and source",
          "[network_fstype]") {
    // The root is the path inside the filesystem that a bind mount exposes; an escaped one must
    // reach the entry decoded, whether the escape is mid-field, a backslash, or the last bytes.
    const auto t = mount_entries(
        "44 22 8:3 /my\\040dir /mnt/a\\040b rw,relatime shared:2 - ext4 /dev/sda3 rw\n"
        "45 22 8:3 /a\\134b /bind rw,relatime - ext4 /dev/sda3 rw\n"
        "46 22 8:3 /trail\\040 /bind2 rw,relatime - ext4 /dev/sda3 rw\n");
    CHECK(t.malformed == 0);
    REQUIRE(t.entries.size() == 3);
    CHECK(t.entries[0].root == "/my dir");
    CHECK(t.entries[0].mount_point == "/mnt/a b");
    CHECK(t.entries[1].root == "/a\\b");
    CHECK(t.entries[2].root == "/trail ");
    CHECK(t.entries[2].mount_point == "/bind2");
}

TEST_CASE("mount_entries: each malformed shape counts once and adds no entry", "[network_fstype]") {
    for (const char* line : {
             "22 1 8:2 / / rw,relatime ext4 /dev/sda2 rw",         // no separator
             "22 1 8:2 / - ext4 /dev/sda2 rw",                     // short head
             "22 1 8:x / / rw - nfs4 srv:/e rw",                   // 8:x
             "22 1 8 / / rw - ext4 /dev/sda2 rw",                  // no colon
             "22 1 :2 / / rw - ext4 /dev/sda2 rw",                 // empty major
             "22 1 8: / / rw - ext4 /dev/sda2 rw",                 // empty minor
             "22 1 -8:2 / / rw - ext4 /dev/sda2 rw",               // sign
             "22 1 8x:2 / / rw - ext4 /dev/sda2 rw",               // digits then junk, major
             "22 1 8:2x / / rw - ext4 /dev/sda2 rw",               // digits then junk, minor
             "22 1 8:2 / / rw - ",                                 // missing fstype
             "22 1 8:2 / /mnt  - ext4 /dev/sda2 rw",               // doubled space, no options
             "22 1 8:2  / /mnt rw - ext4 /dev/sda2 rw",            // empty root mid-head
             "22  8:2 / /mnt rw - ext4 /dev/sda2 rw",              // empty parent id mid-head
             "22 1 8:2 / / rw - ext4",                             // cut after the fstype
             "22 1 8:2 / / rw - ext4 ",                            // cut before the source
             "22 1 8:2 / / rw - ext4 /dev/sd",                     // cut inside the source
             "22 1 8:2 / / rw - ext4 /dev/sda2 ",                  // cut before the super-options
         }) {
        INFO("line: " << line);
        const auto t = mount_entries(std::string(line) + "\n");
        CHECK(t.malformed == 1);
        CHECK(t.entries.empty());
    }
    // Blank lines neither count nor add.
    const auto blank = mount_entries("\n\n");
    CHECK(blank.malformed == 0);
    CHECK(blank.entries.empty());
    // A bad line between good ones leaves both good ones.
    const auto mixed = mount_entries(
        "1 0 8:1 / /a rw - ext4 /dev/a rw\nbad line\n2 0 8:2 / /b rw - xfs /dev/b rw\n");
    CHECK(mixed.malformed == 1);
    REQUIRE(mixed.entries.size() == 2);
    CHECK(mixed.entries[1].mount_point == "/b");
    // An empty source is a field, not a cut: the kernel prints one for a mount made with an empty
    // device string.
    const auto unnamed = mount_entries("50 22 0:50 / /mnt/t rw - tmpfs  rw,size=1k\n");
    CHECK(unnamed.malformed == 0);
    REQUIRE(unnamed.entries.size() == 1);
    CHECK(unnamed.entries[0].source.empty());
}

TEST_CASE("mount_entries: differential with network_mount_points on well-formed input",
          "[network_fstype]") {
    for (const std::string_view text :
         {kRealShape, std::string_view{""},
          std::string_view{"1 0 0:5 / /n rw - nfs4 s:/e rw\n2 0 0:6 / /a rw - autofs x rw\n"
                           "3 0 0:7 / /f rw - fuse.sshfs u@h:/ rw\n4 0 8:1 / /l rw - ext4 /d rw\n"}}) {
        const auto t = mount_entries(text);
        REQUIRE(t.malformed == 0);
        std::vector<std::string> net;
        for (const auto& e : t.entries) {
            if (is_network_fstype(e.fstype)) net.push_back(e.mount_point);
        }
        CHECK(net == network_mount_points(text));
    }
}

TEST_CASE("mount_entries: malformed device keeps the deny-list wider, allow-list fails closed",
          "[network_fstype]") {
    const std::string text = "40 22 8:x / /mnt/nfs rw - nfs4 srv:/e rw\n";
    const auto points = network_mount_points(text);
    REQUIRE(points.size() == 1);
    CHECK(points[0] == "/mnt/nfs");
    const auto t = mount_entries(text);
    CHECK(t.entries.empty());
    CHECK(t.malformed == 1);
}

TEST_CASE("is_searchable_local_fstype: exact allow-list", "[network_fstype]") {
    for (const char* t : {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "apfs", "hfs", "NTFS",
                          "ReFS", "FAT", "FAT32", "exFAT"}) {
        INFO("fstype: " << t);
        CHECK(is_searchable_local_fstype(t));
        CHECK_FALSE(is_network_fstype(t));
        CHECK_FALSE(is_network_mount_fstype(t));
    }
    for (const char* t : {"vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "fuse", "fuse.sshfs", "nfs",
                          "nfs4", "cifs", "overlay", "squashfs", "tmpfs", "proc", "autofs", "EXT4",
                          "ext4 ", ""}) {
        INFO("fstype: '" << t << "'");
        CHECK_FALSE(is_searchable_local_fstype(t));
    }
}

TEST_CASE("mount_entries: hostile input neither overflows, throws nor loops", "[network_fstype]") {
    const auto big = mount_entries(std::string(4u * 1024 * 1024, 'a'));
    CHECK(big.malformed == 1);
    CHECK(big.entries.empty());
    const auto huge = mount_entries("1 0 18446744073709551616:0 / /x rw - ext4 /d rw\n");
    CHECK(huge.malformed == 1);
    CHECK(huge.entries.empty());
    const auto minor = mount_entries("1 0 0:4294967296 / /x rw - ext4 /d rw\n");
    CHECK(minor.malformed == 1);
}

TEST_CASE("under_network_mount: segment-boundary match, a root mount covers everything",
          "[network_fstype]") {
    const std::vector<std::string> mounts{"/Users/js", "/mnt/nfs"};
    CHECK(under_network_mount("/Users/js", mounts));            // exact
    CHECK(under_network_mount("/Users/js/homebrew", mounts));   // a child
    CHECK_FALSE(under_network_mount("/Users/jsmith", mounts));  // shared name prefix, other segment
    CHECK_FALSE(under_network_mount("/Users", mounts));         // an ancestor is not under
    CHECK_FALSE(under_network_mount("/Users/js", {}));          // empty mount list
    const std::vector<std::string> root{"/"};
    CHECK(under_network_mount("/Users/anyone", root));
}

TEST_CASE("touches_network_mount: under a mount or containing one", "[network_fstype]") {
    const std::vector<std::string> mounts{"/Users/js/homebrew"};
    CHECK(touches_network_mount("/Users/js/homebrew/Cellar", mounts)); // under
    CHECK(touches_network_mount("/Users/js", mounts));                 // contains
    CHECK(touches_network_mount("/Users", mounts));                    // contains
    CHECK(touches_network_mount("/", mounts));                         // contains
    CHECK_FALSE(touches_network_mount("/Users/jsmith", mounts));       // unrelated sibling
    CHECK_FALSE(touches_network_mount("/Users/js/homebrew2", mounts)); // segment boundary
    CHECK_FALSE(touches_network_mount("/Users/js", {}));
}
