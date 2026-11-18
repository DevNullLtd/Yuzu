/**
 * test_local_path_policy.cpp -- WP10 (security fix package): the shared "may a plugin open this
 * operator- or user-supplied path / connect to this address" predicates.
 *
 *   agents/shared/local_path_policy.hpp      UNC / device / non-fixed-drive / network-mount refusal
 *   agents/shared/outbound_address_policy.hpp resolve-once address vetting (http_client, windows_updates)
 *   agents/shared/bounded_file_hash.hpp      regular-file-only, capped, deadline-bounded hash
 *
 * The decision functions are pure and run on every host; the Windows drive type is injected so the
 * Windows spellings are exercised here on Linux. Nothing here ships an attack: every case asserts a
 * REFUSAL (or that a plain local path still passes).
 */
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <bounded_file_hash.hpp>
#ifndef _WIN32
#include <openssl/evp.h>
#endif
#include <bounded_wait.hpp>
#include <helper_budget.hpp>
#include <ioc_examined.hpp>
#include <windows_updates_parsers.hpp>
#include <stdexcept>
#ifndef _WIN32
#include <image_hash_cache.hpp>
#endif
#include <http_client_download.hpp>
#include <local_path_policy.hpp>
#include <outbound_address_policy.hpp>
#include <sha256.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#endif

namespace fs = std::filesystem;
namespace lp = yuzu::shared::local_path;
namespace ob = yuzu::shared::outbound;

namespace {

// A fake drive table: C: and D: fixed (3), E: removable (2), Z: network (4), anything else absent.
unsigned fake_drive_type(char letter) {
    switch (letter) {
    case 'C': case 'c': case 'D': case 'd': return 3;
    case 'E': case 'e': return 2;
    case 'Z': case 'z': return 4;
    default: return 1; // DRIVE_NO_ROOT_DIR
    }
}

lp::Refusal win(std::string_view p) { return lp::win_refusal(p, fake_drive_type); }

} // namespace

// ── Windows spellings (pure; the drive type is injected) ────────────────────────────────────────

TEST_CASE("local_path: Windows UNC and device spellings are refused", "[shared][local_path]") {
    for (const char* p : {"\\\\host\\share\\f.txt", "//host/share/f.txt", "\\\\host\\share",
                          "\\\\?\\UNC\\host\\share\\f", "\\\\?\\unc\\host\\share\\f",
                          "\\\\.\\PhysicalDrive0", "\\\\.\\pipe\\x", "\\\\?\\GLOBALROOT\\Device\\X",
                          "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\f",
                          "\\??\\C:\\x", "\\??\\UNC\\host\\share", "\\Device\\Mup\\host\\share",
                          "\\device\\LanmanRedirector\\host", "\\SystemRoot\\system32\\x"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::network_or_device);
    }
}

TEST_CASE("local_path: a drive letter must be a fixed disk", "[shared][local_path]") {
    CHECK(win("C:\\Windows\\notepad.exe") == lp::Refusal::none);
    CHECK(win("d:/data/file.bin") == lp::Refusal::none);
    CHECK(win("C:\\") == lp::Refusal::none);
    CHECK(win("C:") == lp::Refusal::none);
    CHECK(win("\\\\?\\C:\\Windows\\x") == lp::Refusal::none); // long-path spelling of a fixed drive
    // A mapped network drive, removable media and a drive that does not exist all refuse.
    CHECK(win("Z:\\share\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("\\\\?\\Z:\\share\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("E:\\usb\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("Q:\\nope") == lp::Refusal::non_fixed_drive);
    // Drive-relative spellings reach the drive too: the type check must run for them.
    CHECK(win("Z:file") == lp::Refusal::non_fixed_drive);
    CHECK(win("Z:") == lp::Refusal::non_fixed_drive);
    CHECK(win("Z:/x") == lp::Refusal::non_fixed_drive);
    CHECK(win("E:file.txt") == lp::Refusal::non_fixed_drive);
    CHECK(win("C:file") == lp::Refusal::none);
    CHECK(win("1:file") == lp::Refusal::none); // not a drive letter: an ordinary relative name
}

TEST_CASE("local_path: Windows spellings normalise to one drive-letter form", "[shared][local_path]") {
    CHECK(lp::win_normalise_spelling("C:\\a\\b.txt") == "C:\\a\\b.txt");
    CHECK(lp::win_normalise_spelling("C:/a/b.txt") == "C:\\a\\b.txt");
    CHECK(lp::win_normalise_spelling("\\\\?\\C:\\a\\b.txt") == "C:\\a\\b.txt");
    CHECK(lp::win_normalise_spelling("C:\\a\\.\\b\\..\\c.txt") == "C:\\a\\c.txt");
    CHECK(lp::win_normalise_spelling("C:\\a\\\\b") == "C:\\a\\b");
    CHECK(lp::win_normalise_spelling("C:\\..\\..\\x") == "C:\\x");   // never above the root
    CHECK(lp::win_normalise_spelling("C:\\") == "C:\\");
    CHECK(lp::win_normalise_spelling("rel\\x") == "rel\\x");           // caller absolutises first
    CHECK(lp::win_normalise_spelling("\\\\?\\UNC\\h\\s") == "\\\\?\\UNC\\h\\s"); // untouched: still refused
}

TEST_CASE("local_path: relative and current-drive-rooted Windows paths pass", "[shared][local_path]") {
    CHECK(win("logs\\app.log") == lp::Refusal::none);
    CHECK(win("..\\up\\f") == lp::Refusal::none);
    CHECK(win("\\Windows\\System32\\drivers\\etc\\hosts") == lp::Refusal::none);
    CHECK(win("") == lp::Refusal::none); // the caller owns the empty-path error
}

TEST_CASE("local_path: reserved DOS device names are refused in any component", "[shared][local_path]") {
    for (const char* p : {"NUL ", "NUL.", "nul . ", "C:\\x\\CON  ", "NUL", "con", "C:\\dir\\NUL", "C:\\dir\\nul.txt", "COM1", "lpt9.log",
                          "C:\\x\\AUX", "CONIN$", "CONOUT$", "C:\\a\\prn.", "dir\\COM3\\f"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::network_or_device);
    }
    // Names that merely START like a device are ordinary files.
    for (const char* p : {"C:\\x\\console.txt", "C:\\x\\com10", "C:\\x\\lpt0", "C:\\x\\nullable",
                          "C:\\x\\com", "C:\\x\\auxiliary.dll"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::none);
    }
}

TEST_CASE("local_path: superscript COM/LPT reserved names are refused", "[shared][local_path]") {
    // U+00B9, U+00B2, U+00B3 in UTF-8: reserved on Windows 10 and later.
    for (const char* p : {"C:\\x\\COM\xC2\xB9", "COM\xC2\xB2", "lpt\xC2\xB3.txt", "C:\\a\\LPT\xC2\xB9"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::network_or_device);
    }
    // Not reserved: COM with another superscript digit, or a non-superscript two-byte letter.
    for (const char* p : {"C:\\x\\COM\xC2\xB0", "C:\\x\\COM\xC3\xA9"})
        CHECK(win(p) == lp::Refusal::none);
}

TEST_CASE("network_fstype: network-capable FUSE clients and the legacy network types are listed",
          "[shared][network_fstype]") {
    for (const char* t : {"smb2", "fuse.mfsmount", "fuse.seaweedfs", "fuse.s3ql", "fuse.curlftpfs",
                          "fuse.juicefs", "fuse.onedrive", "fuse.davfs2", "fuse.gcsfuse", "fuse.goofys", "fuse.blobfuse2", "fuse.juicefs",
                          "fuse.s3fs", "fuse.sshfs", "nfs4", "cifs", "ncpfs", "coda", "autofs"})
        CHECK(yuzu::shared::is_network_fstype(t));
    // Local filesystems and local FUSE are not listed.
    for (const char* t : {"ext4", "xfs", "btrfs", "tmpfs", "overlay", "fuse", "fuse.portal",
                          "fuse.lxcfs", "fuse.gvfsd-fuse", "proc", "sysfs"})
        CHECK_FALSE(yuzu::shared::is_network_fstype(t));
}

TEST_CASE("network_fstype: every listed network FUSE suffix and every known-local FUSE suffix",
          "[shared][network_fstype]") {
    for (const char* sfx : {"sshfs", "s3fs", "davfs", "rclone", "cephfs", "glusterfs", "nfs", "smb",
                            "ceph-fuse", "vmhgfs-fuse", "prl_fsd", "gcsfuse", "goofys", "blobfuse",
                            "blobfuse2", "ossfs", "obsfs", "cosfs", "juicefs", "mfsmount", "moosefs",
                            "lizardfs", "seaweedfs", "weed", "curlftpfs", "httpfs2", "s3ql", "onedrive",
                            "google-drive-ocamlfuse", "davfs2", "fuse-nfs"}) {
        INFO(sfx);
        CHECK(yuzu::shared::is_network_fstype(std::string("fuse.") + sfx));
    }
    // The ten known-local subtypes: never reported by the strict reading, and the lax one never
    // lists them either.
    const std::vector<std::string> local = {"portal", "gvfsd-fuse", "lxcfs", "snapfuse", "squashfuse",
                                            "ntfs-3g", "ntfs3g", "fuseiso", "archivemount", "encfs"};
    std::string text;
    int id = 40;
    for (const auto& l : local) {
        CHECK(yuzu::shared::is_known_local_fuse_suffix(l));
        text += std::to_string(id++) + " 22 0:9 / /mnt/" + l + " rw - fuse." + l + " src rw\n";
    }
    CHECK(yuzu::shared::network_mount_points(text, /*strict=*/true).empty());
    CHECK(yuzu::shared::network_mount_points(text, /*strict=*/false).empty());
    CHECK_FALSE(yuzu::shared::is_known_local_fuse_suffix("sshfs"));
    CHECK_FALSE(yuzu::shared::is_known_local_fuse_suffix(""));
}

TEST_CASE("network_fstype: the strict reading adds unlisted FUSE and overlays over network mounts",
          "[shared][network_fstype]") {
    const std::string text =
        "30 22 0:25 / /mnt/nfs rw - nfs4 srv:/e rw\n"
        "31 22 0:26 / /mnt/gcs rw - fuse.gcsfuse bucket rw\n"
        "32 22 0:27 / /mnt/unknown rw - fuse.chaosfs chaos rw\n"
        "33 22 0:28 / /mnt/plain rw - fuse plain rw\n"
        "34 22 0:29 / /run/portal rw - fuse.portal portal rw\n"
        "35 22 0:30 / /var/lib/ctr rw - overlay overlay rw,lowerdir=/mnt/nfs/lower:/ro,upperdir=/var/up,workdir=/var/w\n"
        "36 22 0:31 / /var/lib/ok rw - overlay overlay rw,lowerdir=/usr/share/lower,upperdir=/var/up2,workdir=/var/w2\n"
        "37 22 0:32 / /srv/uponfs rw - overlay overlay rw,lowerdir=/ro,upperdir=/mnt/nfs/up,workdir=/mnt/nfs/w\n";
    const auto lax = yuzu::shared::network_mount_points(text);
    CHECK(std::find(lax.begin(), lax.end(), "/mnt/nfs") != lax.end());
    CHECK(std::find(lax.begin(), lax.end(), "/mnt/gcs") != lax.end());       // listed suffix
    CHECK(std::find(lax.begin(), lax.end(), "/mnt/unknown") == lax.end());   // unchanged for others
    CHECK(std::find(lax.begin(), lax.end(), "/var/lib/ctr") == lax.end());
    const auto strict = yuzu::shared::network_mount_points(text, /*strict=*/true);
    const auto has = [&](const char* m) { return std::find(strict.begin(), strict.end(), m) != strict.end(); };
    CHECK(has("/mnt/nfs"));
    CHECK(has("/mnt/gcs"));
    CHECK(has("/mnt/unknown"));   // unlisted FUSE subtype
    CHECK(has("/mnt/plain"));     // bare fuse
    CHECK_FALSE(has("/run/portal")); // known-local FUSE
    CHECK(has("/var/lib/ctr"));   // overlay lowerdir on NFS
    CHECK(has("/srv/uponfs"));    // overlay upperdir/workdir on NFS
    CHECK_FALSE(has("/var/lib/ok")); // overlay over local dirs
}

TEST_CASE("local_path: a leading control character or space is refused rather than guessed at",
          "[shared][local_path]") {
    CHECK(win(" \\\\host\\share") == lp::Refusal::network_or_device);
    CHECK(win("\t C:\\x") == lp::Refusal::network_or_device);
}

TEST_CASE("local_path: win_drive_letter extracts only a real drive designator", "[shared][local_path]") {
    CHECK(lp::win_drive_letter("C:\\x") == 'C');
    CHECK(lp::win_drive_letter("c:") == 'c');
    CHECK(lp::win_drive_letter("\\\\?\\D:\\x") == 'D');
    CHECK(lp::win_drive_letter("\\\\?\\UNC\\h\\s") == 0);
    CHECK(lp::win_drive_letter("\\\\h\\s") == 0);
    CHECK(lp::win_drive_letter("1:\\x") == 0);
    CHECK(lp::win_drive_letter("C:file") == 'C'); // drive-relative still names drive C
    CHECK(lp::win_drive_letter("Z:/x") == 'Z');
    CHECK(lp::win_drive_letter("9:file") == 0);
    CHECK(lp::win_drive_letter(":x") == 0);
    CHECK(lp::win_drive_letter("") == 0);
}

TEST_CASE("local_path: the drive-type callback runs only for a drive-letter spelling",
          "[shared][local_path]") {
    int calls = 0;
    auto counting = [&](char) { ++calls; return 3u; };
    CHECK(lp::win_refusal("rel\\x", counting) == lp::Refusal::none);
    CHECK(calls == 0);
    CHECK(lp::win_refusal("\\\\h\\s", counting) == lp::Refusal::network_or_device);
    CHECK(calls == 0); // a UNC path is refused lexically, never asking the OS
    CHECK(lp::win_refusal("C:\\x", counting) == lp::Refusal::none);
    CHECK(calls == 1);
}

TEST_CASE("local_path: refusal tokens are stable and never carry the path", "[shared][local_path]") {
    CHECK(lp::refusal_token(lp::Refusal::network_or_device) == "path_refused:network_or_device");
    CHECK(lp::refusal_token(lp::Refusal::non_fixed_drive) == "path_refused:non_fixed_drive");
    CHECK(lp::refusal_token(lp::Refusal::mount_table_unreadable) ==
          "path_refused:mount_table_unreadable");
    CHECK_FALSE(lp::refused(lp::Refusal::none));
    CHECK(lp::refused(lp::Refusal::unresolvable));
}

// ── POSIX: network mounts from mountinfo text ───────────────────────────────────────────────────

#ifndef _WIN32 // posix_refusal absolutises with std::filesystem::absolute: a drive-prefixed path on MSVC
TEST_CASE("local_path: a path on or under a network mount is refused; siblings are not",
          "[shared][local_path]") {
    const std::string mountinfo =
        "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
        "30 22 0:25 / /mnt/nfs rw,relatime - nfs4 srv:/export rw\n"
        "31 22 0:26 / /mnt/space\\040dir rw - cifs //srv/share rw\n"
        "32 22 0:27 / /mnt/auto rw - autofs systemd-1 rw\n";
    const auto mounts = yuzu::shared::network_mount_points(mountinfo);
    REQUIRE(mounts.size() == 3);

    CHECK(lp::posix_refusal("/mnt/nfs", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/nfs/a/b", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/nfs/../nfs/x", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt//nfs/./x", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/space dir/f", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/auto/home", mounts) == lp::Refusal::network_or_device);
    // A `..` that climbs OUT of the mount is judged on the normalised path.
    CHECK(lp::posix_refusal("/mnt/nfs/../local", mounts) == lp::Refusal::none);
    // Segment boundary: /mnt/nfs2 is not under /mnt/nfs.
    CHECK(lp::posix_refusal("/mnt/nfs2/f", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("/var/log/syslog", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("/", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("", mounts) == lp::Refusal::none);
}
#endif

TEST_CASE("local_path: a network root filesystem refuses everything", "[shared][local_path]") {
    CHECK(lp::posix_under_mount("/anything/at/all", {"/"}));
    CHECK_FALSE(lp::posix_under_mount("/anything", {}));
    CHECK_FALSE(lp::posix_under_mount("/anything", {""}));
}

#ifndef _WIN32
// posix_judge resolves symlinks. The mount list is injected, so these run the real lstat/readlink
// walk against a temp tree without needing a real network mount.
TEST_CASE("local_path: a symlinked PARENT that points under a network mount is refused",
          "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto mount = fs::canonical(tmp.path) / "mnt_nfs"; // pretend this is a network mount
    REQUIRE(fs::create_directory(mount));
    { std::ofstream(mount / "secret.txt") << "x"; }
    fs::create_directory_symlink(mount, tmp.path / "link");           // link -> the "mount"
    fs::create_symlink(mount / "secret.txt", tmp.path / "leaf_link"); // leaf link into the "mount"
    fs::create_directory(tmp.path / "plain");
    { std::ofstream(tmp.path / "plain" / "f.txt") << "x"; }
    const std::vector<std::string> mounts{mount.string()};

    // The reproduced bypass: a LEXICAL judge reads /tmp/x/link/a as local.
    CHECK(lp::posix_refusal((tmp.path / "link" / "a").string(), mounts) == lp::Refusal::none);
    // The resolving judge follows the parent link and refuses.
    CHECK(lp::posix_judge((tmp.path / "link" / "a").string(), mounts).refusal ==
          lp::Refusal::network_or_device);
    CHECK(lp::posix_judge((tmp.path / "link" / "secret.txt").string(), mounts).refusal ==
          lp::Refusal::network_or_device);
    // A LEAF link into the mount (the open would not follow it, a stat would).
    CHECK(lp::posix_judge((tmp.path / "leaf_link").string(), mounts).refusal ==
          lp::Refusal::network_or_device);
    // `..` is resolved physically: plain/../link/x goes through the link too.
    CHECK(lp::posix_judge((tmp.path / "plain" / ".." / "link" / "x").string(), mounts).refusal ==
          lp::Refusal::network_or_device);
    // A link chain.
    fs::create_directory_symlink(tmp.path / "link", tmp.path / "link2");
    CHECK(lp::posix_judge((tmp.path / "link2" / "a").string(), mounts).refusal ==
          lp::Refusal::network_or_device);

    // Ordinary local paths still pass, and the result is the resolved path.
    const auto ok = lp::posix_judge((tmp.path / "plain" / "f.txt").string(), mounts);
    CHECK(ok.refusal == lp::Refusal::none);
    CHECK(ok.resolved == (fs::canonical(tmp.path) / "plain" / "f.txt").string());
    // A path that does not exist is judged lexically (nothing to follow).
    const auto missing = lp::posix_judge((tmp.path / "plain" / "nope" / "x").string(), mounts);
    CHECK(missing.refusal == lp::Refusal::none);
    CHECK(missing.resolved == (fs::canonical(tmp.path) / "plain" / "nope" / "x").string());
    // An empty mount list never refuses.
    CHECK(lp::posix_judge((tmp.path / "link" / "a").string(), {}).refusal == lp::Refusal::none);
}

TEST_CASE("local_path: a `..` after a missing component cannot expose un-stat'ed links",
          "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto mount = fs::canonical(tmp.path) / "mnt_nfs";
    REQUIRE(fs::create_directory(mount));
    fs::create_directory_symlink(mount, tmp.path / "lnk");
    const std::vector<std::string> mounts{mount.string()};
    // d/missing/../lnk/a: lexically that is d/lnk/a-less; physically `missing` does not exist, so
    // the `..` cannot be resolved and the walk must not guess. (Before the fix the splice cancelled
    // `missing` and returned refusal=none with resolved=<tmp>/lnk/a, an un-judged link into the mount.)
    const auto j = lp::posix_judge((tmp.path / "missing" / ".." / "lnk" / "a").string(), mounts);
    CHECK(j.refusal == lp::Refusal::unresolvable);
    CHECK(j.resolved.empty());
    // A `..` BEFORE any missing component is resolved physically as before.
    fs::create_directory(tmp.path / "real");
    CHECK(lp::posix_judge((tmp.path / "real" / ".." / "lnk" / "a").string(), mounts).refusal ==
          lp::Refusal::network_or_device);
}

TEST_CASE("local_path: the checked open refuses a swapped component and a pseudo filesystem",
          "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto base = fs::canonical(tmp.path);
    { std::ofstream(base / "f.txt") << "plain"; }
    auto ok = lp::posix_open_checked((base / "f.txt").string(), O_RDONLY | O_NONBLOCK);
    CHECK(ok.opened());
    CHECK(ok.refusal == lp::Refusal::none);

    // Absent is a definitive answer, distinct from every refusal.
    auto gone = lp::posix_open_checked((base / "nope.txt").string(), O_RDONLY);
    CHECK_FALSE(gone.opened());
    CHECK(gone.absent);
    CHECK(gone.refusal == lp::Refusal::none);
    auto gone_dir = lp::posix_open_checked((base / "nodir" / "f").string(), O_RDONLY);
    CHECK(gone_dir.absent);

    // A symlink in the path (a component swapped in after judging) is refused, never followed.
    fs::create_directory(base / "real");
    { std::ofstream(base / "real" / "f.txt") << "real"; }
    fs::create_directory_symlink(base / "real", base / "swapped");
    auto via_link = lp::posix_open_checked((base / "swapped" / "f.txt").string(), O_RDONLY);
    CHECK_FALSE(via_link.opened());
    CHECK(via_link.refusal == lp::Refusal::unresolvable);
    fs::create_symlink(base / "f.txt", base / "leaf_link");
    auto leaf = lp::posix_open_checked((base / "leaf_link").string(), O_RDONLY);
    CHECK_FALSE(leaf.opened());
    CHECK(leaf.refusal == lp::Refusal::unresolvable);

#ifdef __linux__
    // The OPENED file's filesystem decides, not the path text: /proc is pseudo.
    auto proc = lp::posix_open_checked("/proc/version", O_RDONLY | O_NONBLOCK);
    CHECK_FALSE(proc.opened());
    CHECK(proc.refusal == lp::Refusal::pseudo_filesystem);
#endif
}

#ifdef __linux__
TEST_CASE("local_path: a rename-swap race never opens through the swapped-in link",
          "[shared][local_path]") {
    // A component is exchanged (renameat2 RENAME_EXCHANGE) between a real directory and a symlink
    // to ANOTHER directory while the checked open runs. Every open must see the real file or be
    // refused; none may land on the other directory's file.
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto base = fs::canonical(tmp.path);
    fs::create_directory(base / "p");
    fs::create_directory(base / "other");
    { std::ofstream(base / "p" / "f") << "real"; }
    { std::ofstream(base / "other" / "f") << "FORBIDDEN"; }
    fs::create_directory_symlink(base / "other", base / "q");
    std::atomic<bool> stop{false};
    std::thread flipper([&] {
        const std::string a = (base / "p").string(), b = (base / "q").string();
        while (!stop.load()) {
            if (::syscall(SYS_renameat2, AT_FDCWD, a.c_str(), AT_FDCWD, b.c_str(), 2 /*RENAME_EXCHANGE*/) != 0)
                break;
        }
    });
    int landed_forbidden = 0, opened_real = 0;
    const std::string target = (base / "p" / "f").string();
    for (int i = 0; i < 4000; ++i) {
        auto o = lp::posix_open_checked(target, O_RDONLY | O_NONBLOCK);
        if (!o.opened())
            continue;
        char buf[16]{};
        const auto n = ::read(o.file.fd(), buf, sizeof(buf));
        const std::string got(buf, n > 0 ? static_cast<std::size_t>(n) : 0);
        if (got == "FORBIDDEN") ++landed_forbidden;
        if (got == "real") ++opened_real;
    }
    stop = true;
    flipper.join();
    CHECK(landed_forbidden == 0);
    INFO("opened_real=" << opened_real);
}
#endif

namespace {
std::string file_sha256(const char* path) {
    std::ifstream in(path, std::ios::binary);
    yuzu::shared::Sha256 h;
    char buf[65536];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
        h.update(buf, static_cast<std::size_t>(in.gcount()));
    return h.hex_digest();
}
std::string file_sha1(const char* path) {
    std::ifstream in(path, std::ios::binary);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    char buf[65536];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<std::size_t>(in.gcount()));
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    EVP_DigestFinal_ex(ctx, out, &n);
    EVP_MD_CTX_free(ctx);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    for (unsigned i = 0; i < n; ++i) {
        hex += kHex[out[i] >> 4];
        hex += kHex[out[i] & 15];
    }
    return hex;
}
} // namespace

namespace {
// Run `fn` on a thread and fail (instead of wedging the suite) if it does not finish in `ms`.
template <class Fn>
bool finishes_within(std::chrono::milliseconds ms, Fn fn) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread t([done, fn = std::move(fn)]() mutable { fn(); done->store(true); });
    const auto limit = std::chrono::steady_clock::now() + ms;
    while (!done->load() && std::chrono::steady_clock::now() < limit)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    if (done->load()) {
        t.join();
        return true;
    }
    t.detach(); // a regression leaks one blocked thread, never the whole run
    return false;
}
} // namespace

TEST_CASE("local_path: a FIFO or a /dev/zero symlink is refused promptly, on both the O_PATH and the plain O_RDONLY legs",
          "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lpfifo_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto base = fs::canonical(tmp.path);
    const auto fifo = base / "trap.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    fs::create_symlink("/dev/zero", base / "zero_link");
    { std::ofstream(base / "ok.txt") << "x"; }

    // path_flag O_RDONLY forces the macOS (no O_PATH) code path on Linux.
    for (const int path_flag : {lp::kPathFlag, static_cast<int>(O_RDONLY)}) {
        INFO("path_flag=" << path_flag);
        // Shared state captured BY VALUE: a hung helper that is detached must never write to a dead
        // stack frame.
        struct Seen { std::atomic<bool> fifo_refused{false}, zero_refused{false}, ok_opens{false}; };
        auto seen = std::make_shared<Seen>();
        const std::string fifo_s = fifo.string(), zero_s = (base / "zero_link").string(),
                          ok_s = (base / "ok.txt").string();
        const bool prompt = finishes_within(std::chrono::seconds(5), [seen, fifo_s, zero_s, ok_s, path_flag] {
            auto f = lp::posix_open_checked(fifo_s, O_RDONLY, /*require_regular=*/true, path_flag);
            seen->fifo_refused = !f.opened() && f.not_regular;
            // /dev/zero behind a symlink: the leaf is a link, refused without being followed.
            auto z = lp::posix_open_checked(zero_s, O_RDONLY, true, path_flag);
            seen->zero_refused = !z.opened();
            auto o = lp::posix_open_checked(ok_s, O_RDONLY, true, path_flag);
            seen->ok_opens = o.opened();
        });
        REQUIRE(prompt); // not hung
        CHECK(seen->fifo_refused.load());
        CHECK(seen->zero_refused.load());
        CHECK(seen->ok_opens.load());
    }
    // /dev/zero itself (a device node, not a link) is refused as not regular.
    auto dev_refused = std::make_shared<std::atomic<bool>>(false);
    REQUIRE(finishes_within(std::chrono::seconds(5), [dev_refused] {
        auto d = lp::posix_open_checked("/dev/zero", O_RDONLY, true, O_RDONLY);
        *dev_refused = !d.opened();
    }));
    CHECK(dev_refused->load());
}

TEST_CASE("local_path: the hop limit and errno handling of the resolving judge", "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto base = fs::canonical(tmp.path);
    fs::create_directory(base / "d");
    // A chain of 5 links resolves; a chain of 45 exceeds the 40-hop limit and fails closed.
    fs::create_directory_symlink(base / "d", base / "l0");
    for (int i = 1; i < 45; ++i)
        fs::create_directory_symlink(base / ("l" + std::to_string(i - 1)), base / ("l" + std::to_string(i)));
    CHECK(lp::posix_judge((base / "l4" / "x").string(), {}).refusal == lp::Refusal::none);
    CHECK(lp::posix_judge((base / "l44" / "x").string(), {}).refusal == lp::Refusal::unresolvable);

    // A component that is a regular file: ENOTDIR below it is a clean "nothing there", not a failure.
    { std::ofstream(base / "file") << "x"; }
    const auto under_file = lp::posix_judge((base / "file" / "child").string(), {});
    CHECK(under_file.refusal == lp::Refusal::none);
    CHECK(under_file.err == 0);

    // An unreadable directory (EACCES on lstat of its child) fails closed WITH the errno.
    if (::getuid() != 0) {
        fs::create_directory(base / "locked");
        { std::ofstream(base / "locked" / "f") << "x"; }
        fs::permissions(base / "locked", fs::perms::none);
        const auto j = lp::posix_judge((base / "locked" / "f").string(), {});
        fs::permissions(base / "locked", fs::perms::owner_all);
        CHECK(j.refusal == lp::Refusal::unresolvable);
        CHECK(j.err == EACCES);
    }
}

TEST_CASE("image hash cache: the key is the opened image's identity, not path text",
          "[shared][image_cache]") {
    yuzu::test::TempDir tmp{"yuzu_test_imgc_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto base = fs::canonical(tmp.path);
    const auto exe = base / "app";
    struct stat a{}, b{}, c{};
    { std::ofstream(exe, std::ios::binary) << "first image"; }
    REQUIRE(::stat(exe.c_str(), &a) == 0);
    const auto key1 = yuzu::shared::image_identity_key(a);

    // The SAME path text now names different content (rewritten in place: same inode): a different key.
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    { std::ofstream(exe, std::ios::binary | std::ios::trunc) << "a different, longer image"; }
    REQUIRE(::stat(exe.c_str(), &b) == 0);
    CHECK(a.st_ino == b.st_ino);
    const auto key2 = yuzu::shared::image_identity_key(b);
    CHECK(key1 != key2);

    // Same size and inode but a different mtime (a same-length rewrite): still a different key.
    { std::ofstream(exe, std::ios::binary | std::ios::trunc) << "A DIFFERENT, LONGER IMAGE"; }
    struct timespec times[2] = {{0, 0}, {b.st_mtim.tv_sec + 5, 0}};
    REQUIRE(::utimensat(AT_FDCWD, exe.c_str(), times, 0) == 0);
    REQUIRE(::stat(exe.c_str(), &c) == 0);
    CHECK(b.st_size == c.st_size);
    CHECK(key2 != yuzu::shared::image_identity_key(c));

    // Every component of the identity matters, asserted on SYNTHETIC stat values so the result never
    // depends on the filesystem's timestamp granularity: a same-size rewrite whose mtime was put back
    // with utimensat() still moves ctime (the owner cannot set it), so ctime alone must change the key.
    struct stat s0{};
    s0.st_dev = 7; s0.st_ino = 11; s0.st_size = 100;
    s0.st_mtim = {1000, 5}; s0.st_ctim = {2000, 9};
    const auto base_key = yuzu::shared::image_identity_key(s0);
    CHECK(yuzu::shared::image_identity_key(s0) == base_key); // deterministic
    { auto v = s0; v.st_dev = 8;            CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    { auto v = s0; v.st_ino = 12;           CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    { auto v = s0; v.st_size = 101;         CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    { auto v = s0; v.st_mtim.tv_sec = 1001; CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    { auto v = s0; v.st_mtim.tv_nsec = 6;   CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    // A far-future timestamp must not overflow the key arithmetic (sec * 1e9 + nsec is undefined
    // behaviour past ~9.2e9 s) nor collide with a neighbour: the fields are written separately.
    {
        auto v = s0;
        v.st_mtim.tv_sec = static_cast<decltype(v.st_mtim.tv_sec)>(0x7ffffffffffffff0LL);
        v.st_mtim.tv_nsec = 5;
        auto w = v;
        w.st_mtim.tv_sec -= 1;
        CHECK(yuzu::shared::image_identity_key(v) != yuzu::shared::image_identity_key(w));
        CHECK(yuzu::shared::image_identity_key(v) == yuzu::shared::image_identity_key(v));
    }
    { auto v = s0; v.st_ctim.tv_sec = 2001; CHECK(yuzu::shared::image_identity_key(v) != base_key); }
    { auto v = s0; v.st_ctim.tv_nsec = 10;  CHECK(yuzu::shared::image_identity_key(v) != base_key); } // ctime only

    // The cache returns what was stored under a key and nothing for another.
    yuzu::shared::ImageHashCache cache;
    cache.put(key1, "hash-one");
    CHECK(cache.get(key1) == std::optional<std::string>("hash-one"));
    CHECK_FALSE(cache.get(key2).has_value());

    // Bounded: it empties itself at 8192 entries instead of growing with the number of images.
    yuzu::shared::ImageHashCache bounded;
    for (int i = 0; i < 8200; ++i)
        bounded.put("k" + std::to_string(i), "h");
    CHECK_FALSE(bounded.get("k0").has_value());
    CHECK(bounded.get("k8199").has_value());
}

#ifdef __linux__
TEST_CASE("local_path: the open-time filesystem check refuses network, FUSE and pseudo types",
          "[shared][local_path]") {
    namespace d = lp::detail;
    using R = lp::Refusal;
    for (const unsigned long t : {0x6969ul /*NFS*/, 0x517Bul /*SMB*/, 0xFE534D42ul /*SMB2*/,
                                  0xFF534D42ul /*CIFS*/, 0x00C36400ul /*CEPH*/, 0x65735546ul /*FUSE*/,
                                  0x01021997ul /*9P*/, 0x5346414Ful /*AFS*/, 0x73757245ul /*CODA*/,
                                  0x564Cul /*NCP*/, 0x0BD00BD0ul /*LUSTRE*/, 0x47504653ul /*GPFS*/,
                                  0x7461636ful /*OCFS2*/, 0x01161970ul /*GFS2*/}) {
        INFO(std::hex << t);
        CHECK(d::refusal_for_fs_type(t) == R::network_or_device);
    }
    for (const unsigned long t : {0x9fa0ul /*proc*/, 0x62656572ul /*sysfs*/, 0x64626720ul /*debugfs*/,
                                  0x27e0ebul /*cgroup*/, 0x63677270ul /*cgroup2*/, 0x73636673ul /*securityfs*/,
                                  0x74726163ul /*tracefs*/, 0xcafe4a11ul /*bpf*/}) {
        INFO(std::hex << t);
        CHECK(d::refusal_for_fs_type(t) == R::pseudo_filesystem);
    }
    for (const unsigned long t : {0xEF53ul /*ext4*/, 0x01021994ul /*tmpfs*/, 0x9123683Eul /*btrfs*/,
                                  0x58465342ul /*xfs*/, 0x794c7630ul /*overlayfs*/})
        CHECK(d::refusal_for_fs_type(t) == R::none);
}
#endif

TEST_CASE("bounded_wait: a helper slot is released by the worker, completed or timed out",
          "[shared][bounded_wait]") {
    namespace sh = yuzu::shared;
    const auto settled = [](int want) {
        for (int i = 0; i < 400; ++i) {
            if (sh::detail::g_outstanding_bounded_calls.load() == want)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    };
    const int base = sh::detail::g_outstanding_bounded_calls.load();
    // Completed: the slot is released.
    auto done = sh::bounded_call_ex(std::chrono::seconds(5), [] { return 7; });
    CHECK(done.status == sh::BoundedCallStatus::Completed);
    CHECK(settled(base));
    // Timed out: the caller returns, the worker still holds the slot, and RELEASES it when it ends.
    auto slow = sh::bounded_call_ex(std::chrono::milliseconds(30), [] {
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        return 1;
    });
    CHECK(slow.status == sh::BoundedCallStatus::TimedOut);
    CHECK(sh::detail::g_outstanding_bounded_calls.load() == base + 1); // still held by the worker
    CHECK(settled(base));                                               // released by the worker
}

TEST_CASE("local_path: a symlink loop fails closed", "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    fs::create_symlink(tmp.path / "b", tmp.path / "a");
    fs::create_symlink(tmp.path / "a", tmp.path / "b");
    CHECK(lp::posix_judge((tmp.path / "a" / "x").string(), {}).refusal == lp::Refusal::unresolvable);
}

TEST_CASE("local_path: /proc, /sys and /dev paths are pseudo-filesystem paths", "[shared][local_path]") {
    for (const char* p : {"/proc", "/proc/kmsg", "/proc/self/exe", "/sys/kernel", "/dev/zero", "/dev"})
        CHECK(lp::posix_pseudo_fs_path(p));
    for (const char* p : {"/procfs/x", "/system", "/devices/x", "/data/proc/kmsg", "/", "/tmp"})
        CHECK_FALSE(lp::posix_pseudo_fs_path(p));
}

TEST_CASE("local_path: a guard snapshot resolves paths and reports the pseudo filesystem",
          "[shared][local_path]") {
#if defined(__linux__) || defined(__APPLE__)
    const lp::LocalPathGuard guard;
    const auto j = guard.judge("/proc/self/../self/status");
    if (j.refusal == lp::Refusal::mount_table_unreadable)
        SKIP("mount table unreadable in this sandbox: the guard fails closed (asserted below)");
    // Whatever the mount table says about /proc, the resolved text names the pseudo filesystem.
    if (j.refusal == lp::Refusal::none)
        CHECK(lp::posix_pseudo_fs_path(j.resolved));
    CHECK(guard.judge("").refusal == lp::Refusal::none); // empty path: the caller owns that error
#endif
}
#endif // !_WIN32


// ── Outbound address classification ─────────────────────────────────────────────────────────────

namespace {
ob::AddressClass v4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return ob::classify_ipv4({static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b),
                              static_cast<std::uint8_t>(c), static_cast<std::uint8_t>(d)});
}
ob::AddressClass v6(std::initializer_list<unsigned> bytes) {
    ob::Ipv6 b{};
    std::size_t i = 0;
    for (const unsigned x : bytes)
        b[i++] = static_cast<std::uint8_t>(x);
    return ob::classify_ipv6(b);
}
} // namespace

TEST_CASE("outbound: IPv4 classes", "[shared][outbound]") {
    CHECK(v4(8, 8, 8, 8) == ob::AddressClass::Public);
    CHECK(v4(93, 184, 216, 34) == ob::AddressClass::Public);
    CHECK(v4(127, 0, 0, 1) == ob::AddressClass::Loopback);
    CHECK(v4(127, 255, 255, 254) == ob::AddressClass::Loopback);
    CHECK(v4(0, 0, 0, 0) == ob::AddressClass::Unspecified);
    CHECK(v4(0, 1, 2, 3) == ob::AddressClass::Unspecified);
    CHECK(v4(10, 1, 2, 3) == ob::AddressClass::Private);
    CHECK(v4(172, 16, 0, 1) == ob::AddressClass::Private);
    CHECK(v4(172, 31, 255, 255) == ob::AddressClass::Private);
    CHECK(v4(172, 32, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(172, 15, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(192, 168, 1, 1) == ob::AddressClass::Private);
    CHECK(v4(100, 64, 0, 1) == ob::AddressClass::Private); // CGNAT
    CHECK(v4(100, 127, 255, 255) == ob::AddressClass::Private);
    CHECK(v4(100, 128, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(169, 254, 169, 254) == ob::AddressClass::LinkLocal); // cloud metadata
    CHECK(v4(168, 63, 129, 16) == ob::AddressClass::CloudMetadata);   // Azure WireServer (was Public)
    CHECK(v4(100, 100, 100, 200) == ob::AddressClass::CloudMetadata); // Alibaba (was Private)
    CHECK(v4(168, 63, 129, 17) == ob::AddressClass::Public);          // only the one address
    CHECK(v4(224, 0, 0, 1) == ob::AddressClass::Multicast);
    CHECK(v4(239, 255, 255, 250) == ob::AddressClass::Multicast);
    CHECK(v4(240, 0, 0, 1) == ob::AddressClass::Reserved);
    CHECK(v4(255, 255, 255, 255) == ob::AddressClass::Reserved);
    CHECK(v4(198, 18, 0, 1) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 19, 255, 255) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 20, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(192, 0, 2, 5) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 51, 100, 5) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(203, 0, 113, 5) == ob::AddressClass::OtherNonGlobal);
}

TEST_CASE("outbound: IPv6 classes including the embedded-IPv4 forms", "[shared][outbound]") {
    CHECK(v6({0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}) ==
          ob::AddressClass::Public);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Loopback);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) == ob::AddressClass::Unspecified);
    CHECK(v6({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::LinkLocal);
    CHECK(v6({0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x54}) ==
          ob::AddressClass::CloudMetadata); // fd00:ec2::254 (AWS IMDS over IPv6)
    CHECK(v6({0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Private);
    CHECK(v6({0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Multicast);
    CHECK(v6({0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // site-local
    CHECK(v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // documentation
    CHECK(v6({0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // outside 2000::/3

    // IPv4-mapped (::ffff:a.b.c.d) is judged by the embedded IPv4 address (the #647 bypass).
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}) == ob::AddressClass::Loopback);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5}) == ob::AddressClass::Private);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254}) ==
          ob::AddressClass::LinkLocal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}) == ob::AddressClass::Public);
    // IPv4-compatible ::a.b.c.d (deprecated) is classified by the embedded address, never public.
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) == ob::AddressClass::OtherNonGlobal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1}) == ob::AddressClass::Loopback);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254}) == ob::AddressClass::LinkLocal);
    // SIIT ::ffff:0:a.b.c.d: the same.
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 169, 254, 169, 254}) == ob::AddressClass::LinkLocal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 8, 8, 8, 8}) == ob::AddressClass::OtherNonGlobal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 10, 0, 0, 5}) == ob::AddressClass::Private);
    // NAT64 well-known prefix 64:ff9b::/96: embedded IPv4 decides; local-use 64:ff9b:1::/48 refuses.
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1}) ==
          ob::AddressClass::Loopback);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254}) ==
          ob::AddressClass::LinkLocal);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) ==
          ob::AddressClass::Public);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 1, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) ==
          ob::AddressClass::OtherNonGlobal);
    // 6to4 2002:AABB:CCDD::/48 embeds the IPv4 address in bytes 2..5.
    CHECK(v6({0x20, 0x02, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Loopback);
}

TEST_CASE("outbound: the two caller tiers", "[shared][outbound]") {
    // http_client connects only to public addresses.
    CHECK(ob::is_public(ob::AddressClass::Public));
    CHECK_FALSE(ob::is_public(ob::AddressClass::Private));
    CHECK_FALSE(ob::is_public(ob::AddressClass::OtherNonGlobal));
    // windows_updates' patch-source probe still reaches a private WSUS server.
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::Public));
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::Private));
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::OtherNonGlobal));
    for (const auto c : {ob::AddressClass::Loopback, ob::AddressClass::Unspecified,
                         ob::AddressClass::LinkLocal, ob::AddressClass::Multicast,
                         ob::AddressClass::Reserved, ob::AddressClass::CloudMetadata})
        CHECK(ob::never_probeable(c));
}

namespace {
ob::ResolvedAddress addr4(unsigned a, unsigned b, unsigned c, unsigned d) {
    ob::ResolvedAddress r;
    r.bytes[0] = static_cast<std::uint8_t>(a);
    r.bytes[1] = static_cast<std::uint8_t>(b);
    r.bytes[2] = static_cast<std::uint8_t>(c);
    r.bytes[3] = static_cast<std::uint8_t>(d);
    return r;
}
} // namespace

TEST_CASE("outbound: a resolver answer with ANY non-public address is refused", "[shared][outbound]") {
    using S = ob::VetStatus;
    CHECK(ob::vet_addresses({}).status == S::resolution_failed); // fail closed
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8)}).status == S::ok);
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8), addr4(1, 1, 1, 1)}).status == S::ok);
    CHECK(ob::vet_addresses({addr4(127, 0, 0, 1)}).status == S::refused);
    // Mixed: one public and one private answer. Not "use the public one".
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8), addr4(10, 0, 0, 5)}).status == S::refused);
    CHECK(ob::vet_addresses({addr4(10, 0, 0, 5), addr4(8, 8, 8, 8)}).status == S::refused);
}

TEST_CASE("outbound: a name that resolves public THEN private is judged on ONE lookup",
          "[shared][outbound]") {
    // The DNS-rebinding case (#647): the first lookup answers a public address, every later
    // lookup a private one. vet_host calls the resolver exactly once, and the answer it vetted is
    // the connect target, so the second (private) answer can never be the one connected to.
    int lookups = 0;
    auto rebinding_resolver = [&]() -> std::vector<ob::ResolvedAddress> {
        return ++lookups == 1 ? std::vector{addr4(93, 184, 216, 34)}
                              : std::vector{addr4(169, 254, 169, 254)};
    };
    const auto outcome = ob::vet_host(rebinding_resolver);
    CHECK(outcome.verdict.status == ob::VetStatus::ok);
    CHECK(lookups == 1);
    REQUIRE(outcome.answers.size() == 1);
    CHECK(outcome.answers[outcome.verdict.index].bytes[0] == 93); // the vetted address is the target

    // And the mirror: a name whose FIRST answer is private is refused outright.
    lookups = 0;
    auto private_first = [&]() -> std::vector<ob::ResolvedAddress> {
        return ++lookups == 1 ? std::vector{addr4(169, 254, 169, 254)}
                              : std::vector{addr4(93, 184, 216, 34)};
    };
    CHECK(ob::vet_host(private_first).verdict.status == ob::VetStatus::refused);
    CHECK(lookups == 1);
}

TEST_CASE("outbound: connect order tries IPv4 first and only judged addresses", "[shared][outbound]") {
    ob::ResolvedAddress v6a;
    v6a.is_v6 = true;
    v6a.bytes = {0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
    const auto order = ob::connect_order({v6a, addr4(93, 184, 216, 34), addr4(1, 1, 1, 1)});
    REQUIRE(order.size() == 3);
    CHECK_FALSE(order[0].is_v6);
    CHECK(order[0].bytes[0] == 93);
    CHECK(order[1].bytes[0] == 1);
    CHECK(order[2].is_v6);
}

// ── Bounded regular-file hash ───────────────────────────────────────────────────────────────────

TEST_CASE("bounded_file_hash: the stream core caps bytes and honours the deadline", "[shared][bounded_hash]") {
    namespace sh = yuzu::shared;
    const std::string data(200 * 1024, 'x');
    auto reader_for = [&data](std::size_t& off) {
        return [&data, &off](unsigned char* buf, std::size_t len) -> long long {
            const auto n = std::min(len, data.size() - off);
            std::memcpy(buf, data.data() + off, n);
            off += n;
            return static_cast<long long>(n);
        };
    };
    const auto deadline_far = sh::HashClock::now() + std::chrono::hours(1);

    std::size_t off = 0;
    auto ok = sh::hash_stream_bounded(reader_for(off), data.size(), deadline_far);
    CHECK(ok.status == sh::HashStatus::ok);
    CHECK(ok.hex == sh::sha256_hex(data));

    off = 0;
    CHECK(sh::hash_stream_bounded(reader_for(off), data.size() - 1, deadline_far).status ==
          sh::HashStatus::oversize);

    off = 0;
    CHECK(sh::hash_stream_bounded(reader_for(off), data.size(),
                                  sh::HashClock::now() - std::chrono::seconds(1))
              .status == sh::HashStatus::timeout);

    auto failing = [](unsigned char*, std::size_t) -> long long { return -1; };
    CHECK(sh::hash_stream_bounded(failing, 1024, deadline_far).status == sh::HashStatus::unreadable);
}

#ifndef _WIN32

namespace {
int open_nonblock(const fs::path& p) {
    return ::open(p.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
}
struct Fd {
    int fd;
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
};
} // namespace

TEST_CASE("bounded_file_hash: a regular file hashes while a FIFO or a directory or an oversize file refuse",
          "[shared][bounded_hash]") {
    namespace sh = yuzu::shared;
    yuzu::test::TempDir tmp{"yuzu_test_bfh_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto deadline_far = sh::HashClock::now() + std::chrono::hours(1);

    const auto file = tmp.path / "f.bin";
    {
        std::ofstream o(file, std::ios::binary);
        o << "hello world";
    }
    {
        Fd f{open_nonblock(file)};
        REQUIRE(f.fd >= 0);
        const auto r = sh::hash_fd_regular(f.fd, 1024, deadline_far);
        CHECK(r.status == sh::HashStatus::ok);
        CHECK(r.hex == sh::sha256_hex("hello world"));
    }
    {
        Fd f{open_nonblock(file)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 5, deadline_far).status == sh::HashStatus::oversize);
    }
    // A FIFO opens O_NONBLOCK without a writer and must be refused by fstat, never read (a read
    // of the old unbounded ifstream path would block the worker forever).
    const auto fifo = tmp.path / "p.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    {
        Fd f{open_nonblock(fifo)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 1024, deadline_far).status == sh::HashStatus::not_regular);
    }
    {
        Fd f{open_nonblock(tmp.path)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 1024, deadline_far).status == sh::HashStatus::not_regular);
    }
}

#endif // !_WIN32 (the POSIX bounded-hash descriptor tests)

// ── http_client download: completeness and finalize rules (pure) ─────────────────────────────────

namespace hc = yuzu::http_client;

namespace {
hc::DownloadObservation good_obs(std::uint64_t n) {
    hc::DownloadObservation o;
    o.transport_ok = true;
    o.final_status = 200;
    o.has_length = true;
    o.declared_length = n;
    o.body_size = n;
    return o;
}
} // namespace

TEST_CASE("http_client download: only a complete 2xx body is acceptable", "[shared][http_client]") {
    CHECK(hc::download_failure(good_obs(10)).empty());

    auto non2xx = good_obs(10);
    non2xx.rejected_status = 404; // the response handler aborted the transfer
    non2xx.transport_ok = false;
    CHECK(hc::download_failure(non2xx) == "download failed: HTTP 404"); // the status, not "connection error"

    auto status500 = good_obs(10);
    status500.final_status = 500;
    CHECK(hc::download_failure(status500) == "download failed: HTTP 500");
    auto redirect = good_obs(10);
    redirect.final_status = 302; // a 3xx is not a successful download
    CHECK_FALSE(hc::download_failure(redirect).empty());

    auto conn = good_obs(10);
    conn.transport_ok = false;
    CHECK(hc::download_failure(conn) == "download failed: HTTP connection error");

    auto big = good_obs(10);
    big.size_exceeded = true;
    CHECK(hc::download_failure(big).find("maximum size") != std::string::npos);
    auto oom = good_obs(10);
    oom.out_of_memory = true;
    CHECK(hc::download_failure(oom).find("out of memory") != std::string::npos);
    auto tls = good_obs(10);
    tls.https_unsupported = true;
    CHECK(hc::download_failure(tls).find("HTTPS not supported") != std::string::npos);
}

TEST_CASE("http_client download: a truncated or length-less body is refused unless a hash verifies it",
          "[shared][http_client]") {
    // Declared 100, received 40: truncated.
    auto cut = good_obs(100);
    cut.body_size = 40;
    CHECK(hc::download_failure(cut).find("shorter than Content-Length") != std::string::npos);

    // Close-delimited, no Content-Length, no expected_hash: indistinguishable from a cut body.
    auto no_len = good_obs(0);
    no_len.has_length = false;
    no_len.body_size = 40;
    CHECK(hc::download_failure(no_len).find("not verifiable") != std::string::npos);
    // ... unless an expected_hash will verify it, or the framing is chunked (httplib verifies it).
    no_len.hash_will_verify = true;
    CHECK(hc::download_failure(no_len).empty());
    no_len.hash_will_verify = false;
    no_len.chunked = true;
    CHECK(hc::download_failure(no_len).empty());
}

TEST_CASE("http_client download: finalize verifies, then replaces atomically, or writes nothing",
          "[shared][http_client]") {
    yuzu::test::TempDir tmp{"yuzu_test_hcdl_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto dest = tmp.path / "payload.bin";
    const std::string good = "new content";
    const std::string good_hash = yuzu::shared::sha256_hex(good);
    const auto read_all = [](const fs::path& p) {
        std::ifstream in(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    };
    const auto entries = [&] {
        std::size_t n = 0;
        for ([[maybe_unused]] const auto& e : fs::directory_iterator(tmp.path))
            ++n;
        return n;
    };
    { std::ofstream(dest, std::ios::binary) << "original"; }

    // Hash MISMATCH: nothing written, the existing file is exactly as it was, no temp left behind.
    auto bad = hc::finalize_download(good, std::string(64, '0'), dest);
    CHECK(bad.status == hc::FinalizeStatus::hash_mismatch);
    CHECK(bad.hash == good_hash);
    CHECK(read_all(dest) == "original");
    CHECK(entries() == 1);

    // The pin is case-insensitive.
    std::string upper = good_hash;
    for (auto& c : upper)
        if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
    auto ok_upper = hc::finalize_download(good, upper, dest);
    CHECK(ok_upper.status == hc::FinalizeStatus::ok);
    CHECK(read_all(dest) == good);
    CHECK(entries() == 1);

    // No pin: the body is written.
    auto no_pin = hc::finalize_download("other", "", dest);
    CHECK(no_pin.status == hc::FinalizeStatus::ok);
    CHECK(read_all(dest) == "other");

    // write_file_atomic FAILURE: the destination's parent is a regular file, so the temp cannot be
    // created. The failure is reported and the existing file at `dest` is untouched.
    const auto blocker = tmp.path / "blocker";
    { std::ofstream(blocker) << "i am a file"; }
    auto wf = hc::finalize_download(good, "", blocker / "child.bin");
    CHECK(wf.status == hc::FinalizeStatus::write_failed);
    CHECK_FALSE(wf.message.empty());
    CHECK(read_all(dest) == "other");
}

// ── The real plugins, end to end ────────────────────────────────────────────────────────────────
//
// These load the built plugin by path. A plugin library that cannot be found is a FAILURE, not a
// skip: the plugins are link_depends of the test executable, so "not found" means the build wiring
// broke, and a skip would turn every assertion below into a silent pass.

#ifndef _WIN32

namespace {

fs::path find_plugin(const std::string& name) {
#if defined(__APPLE__)
    const std::string lib = name + ".dylib";
#else
    const std::string lib = name + ".so";
#endif
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / name / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / name / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / name / lib);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

LoadedPlugin load_or_fail(const std::string& name) {
    const auto path = find_plugin(name);
    if (path.empty())
        FAIL("plugin library '" << name << "' not found: it is a link_depends of the test executable");
    auto handle = yuzu::agent::PluginHandle::load(path);
    if (!handle.has_value())
        FAIL("plugin '" << name << "' failed to load");
    const auto* descriptor = handle->descriptor();
    if (descriptor == nullptr)
        FAIL("plugin '" << name << "' has no descriptor");
    return LoadedPlugin{std::move(*handle), descriptor};
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("ioc plugin: a FIFO returns promptly and is named in a coverage row",
          "[shared][local_path][ioc]") {
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocfifo_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto fifo = tmp.path / "trap.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    const auto regular = tmp.path / "real.txt";
    { std::ofstream(regular, std::ios::binary) << "hello world"; }

    const std::string paths = fifo.string() + "," + regular.string();
    const std::string want = yuzu::shared::sha256_hex("hello world");
    std::vector<YuzuParam> params{{"file_hashes", want.c_str()}, {"file_paths", paths.c_str()}};

    yuzu::agent::LocalDispatcher dispatcher;
    // The old code opened the FIFO with std::ifstream and blocked the worker forever; the new code
    // opens non-blocking and fstat()s the descriptor. Reaching the next line IS part of the test.
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(r.rc == 0);
    // The regular file still matches: hashing each file once did not drop the good path.
    CHECK(contains(r.captured, "hash|" + want + "|true|"));
    // The FIFO is named, with its cause, in a structured row, and the summary says partial.
    CHECK(contains(r.captured, "coverage|" + fifo.string() + "|not_examined|not_regular"));
    CHECK(contains(r.captured, "coverage|*|partial|1 of 2 file path(s) examined"));

    // Only the FIFO: the hash row is a miss that says it did not look everywhere.
    const std::string only_fifo = fifo.string();
    std::vector<YuzuParam> p2{{"file_hashes", want.c_str()}, {"file_paths", only_fifo.c_str()}};
    const auto r2 = dispatcher.run(plugin.descriptor, "check", p2);
    CHECK(r2.rc == 0);
    CHECK(contains(r2.captured, "hash|" + want + "|false|"));
    CHECK(contains(r2.captured, "1 path(s) NOT examined"));
}

TEST_CASE("ioc plugin: a complete run says so, and a /proc file is never hashed",
          "[shared][local_path][ioc]") {
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocok_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto regular = tmp.path / "real.txt";
    { std::ofstream(regular, std::ios::binary) << "hello world"; }
    const std::string want = yuzu::shared::sha256_hex("hello world");
    const std::string one = regular.string();
    yuzu::agent::LocalDispatcher dispatcher;

    std::vector<YuzuParam> ok{{"file_hashes", want.c_str()}, {"file_paths", one.c_str()}};
    const auto r = dispatcher.run(plugin.descriptor, "check", ok);
    CHECK(r.rc == 0);
    CHECK(contains(r.captured, "coverage|*|complete|1 of 1 file path(s) examined"));
    CHECK_FALSE(contains(r.captured, "not_examined"));

    // /proc/kmsg is S_ISREG with st_size 0 and, read by root, consumes the kernel ring buffer. It
    // is refused BEFORE any open (so this is deterministic for root and non-root alike).
    const std::string kmsg = "/proc/kmsg";
    std::vector<YuzuParam> pr{{"file_hashes", want.c_str()}, {"file_paths", kmsg.c_str()}};
    const auto r2 = dispatcher.run(plugin.descriptor, "check", pr);
    CHECK(r2.rc == 0);
    CHECK(contains(r2.captured, "coverage|/proc/kmsg|not_examined|pseudo_filesystem"));
    CHECK(contains(r2.captured, "coverage|*|partial|0 of 1 file path(s) examined"));
}

TEST_CASE("ioc plugin: an absent file is a definitive answer and does not make a clean run partial",
          "[shared][local_path][ioc]") {
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocabs_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto regular = tmp.path / "real.txt";
    { std::ofstream(regular, std::ios::binary) << "hello world"; }
    const std::string want = yuzu::shared::sha256_hex("hello world");
    const std::string paths = (tmp.path / "absent.bin").string() + "," + regular.string();
    std::vector<YuzuParam> params{{"file_hashes", want.c_str()}, {"file_paths", paths.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(r.rc == 0);
    CHECK(contains(r.captured, "hash|" + want + "|true|"));
    CHECK(contains(r.captured, "file|" + (tmp.path / "absent.bin").string() + "|false|File not found"));
    // The absent path is examined (definitively not there): nothing is "not_examined".
    CHECK_FALSE(contains(r.captured, "not_examined"));
    CHECK(contains(r.captured, "coverage|*|complete|2 of 2 file path(s) examined"));

    // Hash that matches nothing, only an absent path: still a clean miss, not "NOT examined".
    const std::string only_absent = (tmp.path / "absent.bin").string();
    std::vector<YuzuParam> p2{{"file_hashes", want.c_str()}, {"file_paths", only_absent.c_str()}};
    const auto r2 = dispatcher.run(plugin.descriptor, "check", p2);
    CHECK(contains(r2.captured, "hash|" + want + "|false|No matching files found"));
    CHECK_FALSE(contains(r2.captured, "NOT examined"));
}

TEST_CASE("ioc plugin: an unreadable path is not examined (EACCES), not a clean absence",
          "[shared][local_path][ioc]") {
    if (::getuid() == 0)
        SKIP("root bypasses permission checks: EACCES cannot be provoked");
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocacc_"};
    REQUIRE(fs::create_directory(tmp.path));
    fs::create_directory(tmp.path / "locked");
    { std::ofstream(tmp.path / "locked" / "f.txt") << "x"; }
    fs::permissions(tmp.path / "locked", fs::perms::none);
    const std::string p = (tmp.path / "locked" / "f.txt").string();
    std::vector<YuzuParam> params{{"file_paths", p.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    fs::permissions(tmp.path / "locked", fs::perms::owner_all);
    CHECK(contains(r.captured, "coverage|" + p + "|not_examined|unreadable"));
    CHECK(contains(r.captured, "coverage|*|partial|0 of 1 file path(s) examined"));
    CHECK_FALSE(contains(r.captured, "|false|File not found"));
}

TEST_CASE("ioc plugin: a `..` after a missing component is not examined",
          "[shared][local_path][ioc]") {
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocdd_"};
    REQUIRE(fs::create_directory(tmp.path));
    { std::ofstream(tmp.path / "f.txt") << "x"; }
    const std::string p = (tmp.path / "missing" / ".." / "f.txt").string();
    std::vector<YuzuParam> params{{"file_paths", p.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(contains(r.captured, "coverage|" + p + "|not_examined|unresolvable"));
}

TEST_CASE("ioc plugin: a symlinked leaf is hashed through its resolved target",
          "[shared][local_path][ioc]") {
    // /bin/sh-style links must keep working (the old ifstream followed them); the leaf is opened
    // no-follow only AFTER it has been resolved and judged.
    auto plugin = load_or_fail("ioc");
    yuzu::test::TempDir tmp{"yuzu_test_iocln_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto target = tmp.path / "target.txt";
    { std::ofstream(target, std::ios::binary) << "hello world"; }
    fs::create_symlink(target, tmp.path / "link.txt");
    const std::string want = yuzu::shared::sha256_hex("hello world");
    const std::string via_link = (tmp.path / "link.txt").string();
    std::vector<YuzuParam> params{{"file_hashes", want.c_str()}, {"file_paths", via_link.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(contains(r.captured, "hash|" + want + "|true|"));
    CHECK(contains(r.captured, "coverage|*|complete|"));
}

TEST_CASE("ioc plugin: more file_paths than the cap is refused and not silently truncated",
          "[shared][local_path][ioc]") {
    auto plugin = load_or_fail("ioc");
    std::string many;
    for (int i = 0; i < 65; ++i)
        many += (i ? ",/nonexistent/yuzu_test_" : "/nonexistent/yuzu_test_") + std::to_string(i);
    std::vector<YuzuParam> params{{"file_paths", many.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(r.rc == 1);
    CHECK(contains(r.captured, "Too many file_paths"));
}

TEST_CASE("http_client plugin: a name that resolves to loopback is blocked before any request",
          "[shared][outbound][http_client]") {
    auto plugin = load_or_fail("http_client");
    yuzu::agent::LocalDispatcher dispatcher;

    // `localhost` resolves (from /etc/hosts) to loopback: refused on the ONE lookup, no connect.
    std::vector<YuzuParam> get_params{{"url", "http://localhost:1/"}};
    const auto g = dispatcher.run(plugin.descriptor, "get", get_params);
    CHECK(g.rc == 1);
    CHECK(contains(g.captured, "SSRF blocked"));

    // A refused download leaves an existing destination exactly as it was and creates no sibling.
    yuzu::test::TempDir tmp{"yuzu_test_httpdl_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto dest = tmp.path / "payload.bin";
    { std::ofstream(dest, std::ios::binary) << "original"; }
    const std::string dest_s = dest.string();
    std::vector<YuzuParam> dl{{"url", "http://localhost:1/x"}, {"path", dest_s.c_str()}};
    const auto d = dispatcher.run(plugin.descriptor, "download", dl);
    CHECK(d.rc == 1);
    CHECK(contains(d.captured, "SSRF blocked"));
    std::ifstream in(dest, std::ios::binary);
    CHECK(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()) ==
          "original");
    std::size_t entries = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator(tmp.path))
        ++entries;
    CHECK(entries == 1);
    // The completeness/hash/write rules themselves are covered by the pure http_client_download
    // tests above: a real transfer cannot target loopback (the SSRF guard refuses it by design).
}

TEST_CASE("disk_space plugin: a local path is still measured and a symlink into a network mount is not a bypass",
          "[shared][local_path][disk_space]") {
    auto plugin = load_or_fail("disk_space");
    yuzu::test::TempDir tmp{"yuzu_test_disk_"};
    REQUIRE(fs::create_directory(tmp.path));
    const std::string where = tmp.path.string();
    std::vector<YuzuParam> params{{"path", where.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "free", params);
    CHECK(r.rc == 0);
    CHECK(contains(r.captured, "disk|"));
}

TEST_CASE("windows_updates plugin: one dispatch deadline covers every target",
          "[shared][outbound][windows_updates]") {
    // Round trip only: 16 RFC 1918 targets at timeout 1 s finish and every target is reported. The
    // deadline arithmetic itself (both branches, a fake clock) is the plan_target test below.
    auto plugin = load_or_fail("windows_updates");
    std::string many;
    for (int i = 0; i < 16; ++i)
        many += (i ? ",http://10.255.255." : "http://10.255.255.") + std::to_string(i + 1) + ":9/";
    std::vector<YuzuParam> params{{"targets", many.c_str()}, {"timeout_seconds", "1"}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto t0 = std::chrono::steady_clock::now();
    const auto r = dispatcher.run(plugin.descriptor, "patch_connectivity", params);
    const auto took = std::chrono::steady_clock::now() - t0;
    CHECK(r.rc == 0);
    CHECK(took < std::chrono::seconds(90));
    CHECK(contains(r.captured, "summary|targets_tested|16|"));
    // Over the cap is refused outright, with no probing.
    std::string seventeen = many + ",http://10.255.255.17:9/";
    std::vector<YuzuParam> p2{{"targets", seventeen.c_str()}, {"timeout_seconds", "1"}};
    const auto r2 = dispatcher.run(plugin.descriptor, "patch_connectivity", p2);
    CHECK(r2.rc == 1);
    CHECK(contains(r2.captured, "error|too many targets"));
}

TEST_CASE("windows_updates plugin: the TCP probe path runs to completion (addrinfo freed once)",
          "[shared][outbound][windows_updates]") {
    // test_tcp owns its getaddrinfo list in an RAII guard. A second, manual freeaddrinfo at the end
    // of the function was a double free (glibc: 'free(): double free detected', abort). An RFC 1918
    // target passes the address-class refusal and reaches test_tcp; the 1 s probe timeout bounds it.
    auto plugin = load_or_fail("windows_updates");
    std::vector<YuzuParam> params{{"targets", "http://10.255.255.1:9/"}, {"timeout_seconds", "1"}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "patch_connectivity", params);
    CHECK(r.rc == 0);
    CHECK(contains(r.captured, "target|http://10.255.255.1:9/|dns_ok|true"));
    CHECK(contains(r.captured, "tcp_ok|"));
    CHECK(contains(r.captured, "summary|targets_tested|1|"));
}

TEST_CASE("procfetch plugin: this process's image is hashed through its exe link and the run completes",
          "[shared][local_path][procfetch]") {
#ifdef __linux__
    auto plugin = load_or_fail("procfetch");
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "procfetch_fetch");
    CHECK(r.rc == 0);
    const std::string mine = std::to_string(::getpid()) + "|";
    const auto at = r.captured.find("\n" + mine);
    const auto row_start = at != std::string::npos ? at + 1 : r.captured.find(mine);
    REQUIRE(row_start != std::string::npos);
    const auto eol = r.captured.find('\n', row_start);
    const std::string row = r.captured.substr(row_start, eol == std::string::npos ? std::string::npos : eol - row_start);
    // pid|name|path|sha1: the sha1 is the last field, 40 lowercase hex characters.
    const auto last = row.rfind('|');
    REQUIRE(last != std::string::npos);
    const std::string sha1 = row.substr(last + 1);
    CHECK(sha1.size() == 40);
    CHECK(sha1.find_first_not_of("0123456789abcdef") == std::string::npos);
    // The VALUE, not the shape: the SHA-1 of this very executable, computed independently.
    CHECK(sha1 == file_sha1("/proc/self/exe"));
#else
    SUCCEED("Linux-only");
#endif
}

TEST_CASE("processes plugin: list_hashed hashes this process's own image through the exe link",
          "[shared][local_path][processes]") {
#ifdef __linux__
    auto plugin = load_or_fail("processes");
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin.descriptor, "list_hashed");
    CHECK(r.rc == 0);
    const std::string mine = "proc|" + std::to_string(::getpid()) + "|";
    const auto at = r.captured.find(mine);
    REQUIRE(at != std::string::npos);
    const auto eol = r.captured.find('\n', at);
    const std::string row = r.captured.substr(at, eol == std::string::npos ? std::string::npos : eol - at);
    // proc|pid|name|sha256|path -- the sha256 field is 64 lowercase hex characters.
    std::vector<std::string> f;
    for (std::size_t s2 = 0;;) {
        const auto bar = row.find('|', s2);
        f.push_back(row.substr(s2, bar == std::string::npos ? std::string::npos : bar - s2));
        if (bar == std::string::npos) break;
        s2 = bar + 1;
    }
    REQUIRE(f.size() >= 5);
    CHECK(f[3].size() == 64);
    CHECK(f[3].find_first_not_of("0123456789abcdef") == std::string::npos);
    // The VALUE, not the shape: it is the SHA-256 of this very executable, read independently.
    CHECK(f[3] == file_sha256("/proc/self/exe"));
#else
    SUCCEED("Linux-only: the exe-link hash path");
#endif
}

#endif // !_WIN32

TEST_CASE("windows_updates: plan_target clamps to what is left of the dispatch and skips at the deadline",
          "[shared][windows_updates]") {
    using clock = std::chrono::steady_clock;
    using yuzu::windows_updates::plan_target;
    const auto t0 = clock::time_point{} + std::chrono::hours(1); // a fake clock reading
    const auto deadline = t0 + std::chrono::seconds(60);

    // Plenty left: the requested timeout stands.
    auto p = plan_target(deadline, t0, 5);
    CHECK_FALSE(p.skip);
    CHECK(p.timeout_s == 5);
    // The requested timeout (60) is clamped to what is left (40): the AFTER-lookup call is what makes
    // a slow lookup shorten the connect that follows.
    p = plan_target(deadline, t0 + std::chrono::seconds(20), 60);
    CHECK_FALSE(p.skip);
    CHECK(p.timeout_s == 40);
    // Under a second left: nothing useful fits, skipped.
    CHECK(plan_target(deadline, deadline - std::chrono::milliseconds(500), 5).skip);
    // At and past the deadline: skipped.
    CHECK(plan_target(deadline, deadline, 5).skip);
    CHECK(plan_target(deadline, deadline + std::chrono::seconds(3), 5).skip);
    // Exactly one second left: a 1 s timeout, never 0.
    p = plan_target(deadline, deadline - std::chrono::seconds(1), 30);
    CHECK_FALSE(p.skip);
    CHECK(p.timeout_s == 1);
    // Worst case end to end: lookup 58 s, then the connect is clamped to the 2 s that remain, so the
    // whole target ends at 60 s, not 58 + 60.
    const auto after_lookup = t0 + std::chrono::seconds(58);
    p = plan_target(deadline, after_lookup, 60);
    CHECK(p.timeout_s == 2);
}

TEST_CASE("bounded_wait: a throwing fn ends the call at once instead of waiting out the timeout",
          "[shared][bounded_wait]") {
    const auto t0 = std::chrono::steady_clock::now();
    auto r = yuzu::shared::bounded_call_ex(std::chrono::seconds(20), []() -> int { throw std::runtime_error("x"); });
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
    CHECK(r.status == yuzu::shared::BoundedCallStatus::TimedOut);
    CHECK_FALSE(r.value.has_value());
}

TEST_CASE("helper budget: a stuck helper counts, the cap is reached, and a skipped hash is a marker not an empty string",
          "[shared][bounded_wait]") {
    using yuzu::shared::BoundedCallStatus;
    yuzu::shared::HelperBudget b{2};
    CHECK(b.may_start());
    b.note(BoundedCallStatus::Completed); // a completed call costs nothing
    CHECK(b.may_start());
    b.note(BoundedCallStatus::TimedOut);
    CHECK(b.may_start());
    b.note(BoundedCallStatus::Rejected);
    CHECK_FALSE(b.may_start()); // two helpers left behind: no third is started
    CHECK(b.stuck() == 2);
    // The row field: a hash and a genuine empty stay as they are; a timeout or refusal is the marker.
    CHECK(yuzu::shared::hash_field_for(BoundedCallStatus::Completed, "abc") == "abc");
    CHECK(yuzu::shared::hash_field_for(BoundedCallStatus::Completed, "").empty());
    CHECK(yuzu::shared::hash_field_for(BoundedCallStatus::TimedOut, "") == "hash_unavailable:timeout");
    CHECK(yuzu::shared::hash_field_for(BoundedCallStatus::Rejected, "") == "hash_unavailable:timeout");
    CHECK(std::string{yuzu::shared::kHashUnavailableSkipped} == "hash_unavailable:skipped");
    // The Windows procfetch leg builds its causes through the same helper.
    CHECK(yuzu::shared::hash_unavailable("not_examined") == "hash_unavailable:not_examined");
    CHECK(yuzu::shared::hash_unavailable("unreadable") == "hash_unavailable:unreadable");
    CHECK(yuzu::shared::hash_unavailable("not_regular").rfind(yuzu::shared::kHashUnavailablePrefix, 0) == 0);
    // The cap sits below action budget / per-image budget, or it could never trip first (2 x 30 s < 120 s).
    static_assert(2 * 30 < 120);
}

TEST_CASE("ioc: a timeout (which includes a throwing helper) and a refused helper are never examined and never absent",
          "[shared][ioc]") {
    using yuzu::shared::BoundedCallStatus;
    yuzu::ioc::Examined ok;
    ok.path = "/p"; ok.exists = true; ok.size = 3;
    for (const auto st : {BoundedCallStatus::TimedOut, BoundedCallStatus::Rejected}) {
        const auto e = yuzu::ioc::examined_from_call("/p", st, ok); // a value present is still not trusted
        CHECK(e.cause == "timeout");
        CHECK_FALSE(e.absent);
        CHECK_FALSE(e.exists);
        CHECK(e.path == "/p");
    }
    CHECK(yuzu::ioc::examined_from_call("/p", BoundedCallStatus::Completed, std::nullopt).cause == "timeout");
    const auto good = yuzu::ioc::examined_from_call("/p", BoundedCallStatus::Completed, ok);
    CHECK(good.cause.empty());
    CHECK(good.exists);
}

// The mountinfo-text constructor is a POSIX-only test seam (local_path_policy.hpp).
#if defined(__linux__) || defined(__APPLE__)
TEST_CASE("local_path: a guard built from a mountinfo table refuses a path under a network mount",
          "[shared][local_path][disk_space]") {
    // The deterministic form of the disk_space refusal: the plugin refuses before any statvfs.
    const lp::LocalPathGuard guard{std::string{
        "30 1 0:27 / / rw - ext4 /dev/sda1 rw\n41 30 0:38 / /mnt/share rw - nfs4 srv:/export rw\n"}};
    CHECK(lp::refused(guard.refusal("/mnt/share")));
    CHECK(lp::refused(guard.refusal("/mnt/share/deep/file")));
    CHECK_FALSE(lp::refused(guard.refusal("/mnt/sharex")));
    CHECK_FALSE(lp::refused(guard.refusal("/")));
}
#endif
