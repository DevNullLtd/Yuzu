/**
 * test_certificates_linux_store.cpp -- real syscall-level tests for
 * certificates_linux_store.hpp, run against a TempDir on disk.
 *
 * `#ifndef _WIN32`, not `#ifdef __linux__`: every syscall this header
 * touches (openat/fstatat/readlinkat/unlinkat/readdir) is plain POSIX, so
 * these tests exercise the REAL filesystem/syscall path on macOS CI too --
 * only the production call sites in certificates_plugin.cpp are Linux-only
 * (a flat /etc/ssl/certs PEM directory is a Linux distribution convention).
 *
 * TOCTOU/enumeration outcomes that need a deterministic swap at an exact
 * instant (a symlink retargeted mid-recheck, a readdir failure landing on a
 * specific call) are forced via the injected `StoreSyscalls` fakes -- each
 * fake performs whatever swap it needs to exercise INSIDE the call, then
 * (ordinarily) delegates to the real syscall, exactly like
 * test_confined_fs_posix.cpp:397-420's `FstatatSeamGuard` pattern. Because
 * `StoreSyscalls` holds plain function pointers (no captures), the fakes
 * below carry their per-test state in file-scope statics, reset at the top
 * of each TEST_CASE that uses them -- safe because Catch2 runs these cases
 * serially in one process, never concurrently.
 */

#ifndef _WIN32

#include <catch2/catch_test_macros.hpp>

#include <certificates_linux_store.hpp>

#include "certificates_pem_fixtures.hpp" // kRealSystemDefaultCertPem (shared with test_certificates_x509.cpp)
#include "test_helpers.hpp"              // yuzu::test::TempDir

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

using namespace yuzu::certificates_linux;
namespace fs = std::filesystem;

namespace {

// The real System.keychain capture's thumbprint (see
// certificates_pem_fixtures.hpp's provenance comment on
// kRealSystemDefaultCertPem) -- already canonical (uppercase, colon-free).
constexpr const char* kNeedle = "E363C8FA8D5CC5087456542669F6C633267587F2";

void write_file(const fs::path& p, std::string_view contents) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << contents;
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

CertDir open_store(const fs::path& dir) {
    return open_cert_dir(dir.c_str());
}

// ── Injected-fake state for the recheck-swap scenarios ──────────────────────
// Plain function pointers can't capture, so each fake reads its target from
// these file-scope statics -- reset explicitly at the top of every TEST_CASE
// that uses one, per the file banner's "serial, not concurrent" rule.

fs::path g_symlink_path;
fs::path g_symlink_new_target;
int g_symlink_fstatat_calls = 0;
// The retarget must land on the RECHECK's own AT_SYMLINK_NOFOLLOW call, not
// read_cert_entry's match-time identity capture (also AT_SYMLINK_NOFOLLOW,
// and also routed through this fake -- it shares `sys` with the recheck).
// That match-time call is always the first fstatat this fake sees for a
// symlink entry; the recheck's is the second -- swapping on the second call
// is what makes match-time and recheck identity genuinely differ.
int retarget_symlink_fstatat(int dirfd, const char* name, struct stat* st, int flags) {
    ++g_symlink_fstatat_calls;
    if (flags == AT_SYMLINK_NOFOLLOW && g_symlink_fstatat_calls == 2) {
        std::error_code ec;
        fs::remove(g_symlink_path, ec);
        fs::create_symlink(g_symlink_new_target, g_symlink_path, ec);
    }
    return ::fstatat(dirfd, name, st, flags);
}

// Swaps the FILE living at the symlink's target path (leaving the link's own
// text and inode untouched) on the recheck's own AT_SYMLINK_NOFOLLOW call --
// the "rename-over-replaced at the SAME path text" scenario delete_matching_cert's
// own doc comment names explicitly: the link is unchanged, only the inode its
// (unchanged) target text resolves to is different. Call counting mirrors
// retarget_symlink_fstatat above -- call 1 is read_cert_entry's match-time
// capture, call 2 is the recheck's own link stat, so swapping on call 2 lands
// strictly before the recheck's follow-to-target fstatat (flags=0) that must
// observe the new inode.
fs::path g_same_path_target;
fs::path g_same_path_replacement;
int g_same_path_fstatat_calls = 0;
int swap_target_contents_fstatat(int dirfd, const char* name, struct stat* st, int flags) {
    ++g_same_path_fstatat_calls;
    if (flags == AT_SYMLINK_NOFOLLOW && g_same_path_fstatat_calls == 2) {
        std::error_code ec;
        fs::rename(g_same_path_replacement, g_same_path_target, ec);
    }
    return ::fstatat(dirfd, name, st, flags);
}

fs::path g_regular_entry_path;
fs::path g_regular_replacement_path;
int swap_regular_fstatat(int dirfd, const char* name, struct stat* st, int flags) {
    if (flags == AT_SYMLINK_NOFOLLOW) {
        std::error_code ec;
        fs::rename(g_regular_replacement_path, g_regular_entry_path, ec);
    }
    return ::fstatat(dirfd, name, st, flags);
}

int failing_fstatat(int, const char*, struct stat*, int) {
    errno = EIO;
    return -1;
}

struct dirent* failing_readdir_immediately(DIR*) {
    errno = EIO;
    return nullptr;
}

int failing_unlinkat(int, const char*, int) {
    errno = EACCES;
    return -1;
}

// Delegates to the real readdir until it has returned the entry named
// `g_post_match_target`, then makes the VERY NEXT call fail with EIO --
// modelling a readdir failure on entries scanned AFTER the match, whatever
// those entries' real names would have been.
std::string g_post_match_target;
bool g_post_match_seen = false;
struct dirent* post_match_eio_readdir(DIR* d) {
    if (g_post_match_seen) {
        errno = EIO;
        return nullptr;
    }
    errno = 0;
    struct dirent* e = ::readdir(d);
    if (e && std::string_view{e->d_name} == g_post_match_target)
        g_post_match_seen = true;
    return e;
}

} // namespace

// ── (a) regular .pem matching the needle ─────────────────────────────────────

TEST_CASE("delete_matching_cert: regular .pem matching the needle is deleted",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kDeleted);
    CHECK(scan.entry == "a.pem");
    CHECK(scan.unlink_err == 0);
    CHECK_FALSE(scan.enumeration_failed);
    CHECK(scan.unreadable_entries == 0);
    CHECK_FALSE(fs::exists(tmp.path / "a.pem"));
}

// ── (b) symlink to a target outside the dir ──────────────────────────────────

TEST_CASE("delete_matching_cert: symlink entry deletes the link, target survives",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path target = tmp.path / "outside_target.pem"; // outside the enumerated store dir
    const fs::path store = tmp.path / "store";
    fs::create_directories(store);
    write_file(target, kRealSystemDefaultCertPem);
    fs::create_symlink(target, store / "link.pem");
    const std::string target_before = read_file(target);

    auto dir = open_store(store);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kDeleted);
    CHECK(scan.entry == "link.pem");
    CHECK(scan.unlink_err == 0);
    CHECK_FALSE(fs::exists(store / "link.pem"));
    CHECK(fs::exists(target));
    CHECK(read_file(target) == target_before);
}

// ── (c) symlink retarget during the recheck ──────────────────────────────────

TEST_CASE("delete_matching_cert: symlink retargeted during recheck is kChanged",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path target = tmp.path / "outside_target.pem";
    const fs::path other_target = tmp.path / "other_target.pem";
    const fs::path store = tmp.path / "store";
    fs::create_directories(store);
    write_file(target, kRealSystemDefaultCertPem);
    write_file(other_target, "not a certificate, just needs to exist");
    fs::create_symlink(target, store / "link.pem");

    g_symlink_path = store / "link.pem";
    g_symlink_new_target = other_target;
    g_symlink_fstatat_calls = 0;
    StoreSyscalls sys;
    sys.fstatat = &retarget_symlink_fstatat;

    auto dir = open_store(store);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kChanged);
    CHECK(scan.entry == "link.pem");
    CHECK(scan.unlink_err == 0);
    REQUIRE(fs::is_symlink(store / "link.pem"));
    CHECK(fs::read_symlink(store / "link.pem") == other_target);
}

// ── symlink target replaced at the SAME path text during the recheck ────────
// Distinct from (c) above: there the LINK is retargeted to a different path;
// here the link's own text and inode never change -- only the file living at
// the path it already points to is swapped out from under it.

TEST_CASE("delete_matching_cert: symlink target replaced at the same path text is kChanged",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path target = tmp.path / "outside_target.pem";
    const fs::path replacement = tmp.path / "replacement.pem";
    const fs::path store = tmp.path / "store";
    fs::create_directories(store);
    write_file(target, kRealSystemDefaultCertPem);
    write_file(replacement, kExpiredCertPem);
    fs::create_symlink(target, store / "link.pem");

    g_same_path_target = target;
    g_same_path_replacement = replacement;
    g_same_path_fstatat_calls = 0;
    StoreSyscalls sys;
    sys.fstatat = &swap_target_contents_fstatat;

    auto dir = open_store(store);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kChanged);
    CHECK(scan.entry == "link.pem");
    CHECK(scan.unlink_err == 0);
    // The link itself is untouched -- still present, still pointing at the
    // same path text -- but the delete was refused rather than silently
    // acting on whatever now lives at that path.
    REQUIRE(fs::is_symlink(store / "link.pem"));
    CHECK(fs::read_symlink(store / "link.pem") == target);
    CHECK(read_file(target) == kExpiredCertPem);
}

// ── (d) inode swap on a regular entry during the recheck ─────────────────────

TEST_CASE("delete_matching_cert: regular entry inode-swapped during recheck is kChanged",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);
    const fs::path replacement = tmp.path / "replacement.pem";
    write_file(replacement, "not a certificate, just a fresh inode");

    g_regular_entry_path = tmp.path / "a.pem";
    g_regular_replacement_path = replacement;
    StoreSyscalls sys;
    sys.fstatat = &swap_regular_fstatat;

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kChanged);
    CHECK(scan.entry == "a.pem");
    CHECK(scan.unlink_err == 0);
    // The swapped-in file survives under the original entry's name -- it was
    // never the identity that was matched, so classify_delete_recheck
    // refused the unlink.
    REQUIRE(fs::exists(tmp.path / "a.pem"));
    CHECK(read_file(tmp.path / "a.pem") == "not a certificate, just a fresh inode");
}

// ── (e) fstatat failure on the recheck ───────────────────────────────────────

TEST_CASE("delete_matching_cert: fstatat failure on the recheck is kUnverifiable",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);

    StoreSyscalls sys;
    sys.fstatat = &failing_fstatat;

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kUnverifiable);
    CHECK(scan.entry == "a.pem");
    CHECK(scan.unlink_err == 0);
    CHECK(fs::exists(tmp.path / "a.pem"));
}

// ── (f) readdir failure before any match ─────────────────────────────────────

TEST_CASE("delete_matching_cert: readdir failure before any match is kEnumerationFailed",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);

    StoreSyscalls sys;
    sys.readdir = &failing_readdir_immediately;

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kEnumerationFailed);
    CHECK(scan.enumeration_failed);
    CHECK(scan.enum_err == EIO);
    CHECK(fs::exists(tmp.path / "a.pem"));
}

// ── (g) unreadable .pem entry (chmod 000) ────────────────────────────────────

TEST_CASE("delete_matching_cert: an unreadable entry is kUnreadableEntries",
          "[certificates][linux_store]") {
    if (::geteuid() == 0) {
        WARN("running as root: chmod 000 does not block root's own reads, skipping");
        return;
    }
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path unreadable = tmp.path / "unreadable.pem";
    write_file(unreadable, kRealSystemDefaultCertPem);
    REQUIRE(::chmod(unreadable.c_str(), 0000) == 0);

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kUnreadableEntries);
    CHECK(scan.unreadable_entries == 1);
    CHECK_FALSE(scan.enumeration_failed);

    ::chmod(unreadable.c_str(), 0644); // let TempDir's destructor clean it up
}

// ── (h) FIFO entry is skipped, not matched ───────────────────────────────────

TEST_CASE("delete_matching_cert: a FIFO named *.pem is skipped, resulting in kNotFound",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path fifo = tmp.path / "x.pem";
    REQUIRE(::mkfifo(fifo.c_str(), 0644) == 0);

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kNotFound);
    CHECK(scan.unreadable_entries == 0);
    CHECK(fs::exists(fifo));
}

// ── (i) a non-.pem/.crt name is never opened ─────────────────────────────────

TEST_CASE("delete_matching_cert: a non-.pem/.crt entry is never opened",
          "[certificates][linux_store]") {
    if (::geteuid() == 0) {
        WARN("running as root: chmod 000 does not block root's own reads, skipping");
        return;
    }
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    // An entry that WOULD surface as unreadable if is_cert_entry_name's
    // extension filter were bypassed -- if for_each_cert_entry never even
    // calls read_cert_entry on it (the correct behavior), unreadable_entries
    // stays 0 and the scan concludes kNotFound.
    const fs::path not_a_cert = tmp.path / "notacert.txt";
    write_file(not_a_cert, "not a pem");
    REQUIRE(::chmod(not_a_cert.c_str(), 0000) == 0);

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kNotFound);
    CHECK(scan.unreadable_entries == 0);

    ::chmod(not_a_cert.c_str(), 0644);
}

// ── (j) open_cert_dir outcomes ───────────────────────────────────────────────

TEST_CASE("open_cert_dir: a missing path is kAbsent", "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    // Deliberately not created -- tmp.path does not exist on disk.
    auto dir = open_store(tmp.path);
    CHECK(dir.state == CertDirOpen::kAbsent);
}

TEST_CASE("open_cert_dir: a regular file at the path is kUnreadable (ENOTDIR)",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path.parent_path());
    write_file(tmp.path, "not a directory");
    auto dir = open_store(tmp.path);
    CHECK(dir.state == CertDirOpen::kUnreadable);
    CHECK(dir.err == ENOTDIR);
}

TEST_CASE("open_cert_dir: a symlinked directory is kUnreadable",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    const fs::path real_dir = tmp.path / "real";
    const fs::path link_dir = tmp.path / "link";
    fs::create_directories(real_dir);
    fs::create_directory_symlink(real_dir, link_dir);

    auto dir = open_store(link_dir);
    CHECK(dir.state == CertDirOpen::kUnreadable);
    // O_DIRECTORY | O_NOFOLLOW on a symlinked directory is ELOOP on macOS;
    // on Linux the same combination can surface as ENOTDIR (the kernel's
    // O_NOFOLLOW check on a final symlink component with O_DIRECTORY set --
    // see fs/namei.c's link_path_walk/do_last handling). Both are refusals
    // of the symlink root and both classify_cert_dir_open folds into
    // kUnreadable; only the state matters here, not which errno produced it.
    CHECK((dir.err == ELOOP || dir.err == ENOTDIR));
}

// ── held-dirfd confinement across a directory replacement ────────────────────
// open_cert_dir's own doc comment: "a directory swapped for another between
// two separate opens cannot make this code enumerate one directory and act
// on another" -- because every syscall below is dirfd-relative, never a fresh
// pathname lookup. Proven here with real syscalls only: no injection is
// needed because the held fd from open_store, taken BEFORE the rename, stays
// bound to the original directory's inode regardless of what the pathname
// resolves to afterward.

TEST_CASE("delete_matching_cert: directory replaced after open still acts on the held directory",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    const fs::path store = tmp.path / "store";
    const fs::path moved_aside = tmp.path / "moved_aside";
    fs::create_directories(store);
    write_file(store / "original.pem", kRealSystemDefaultCertPem);

    auto dir = open_store(store);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    // Rename the already-opened directory aside, then create a DECOY
    // directory at the original path containing an entry with the same
    // needle -- a path-based reopen would find and delete the decoy instead.
    fs::rename(store, moved_aside);
    fs::create_directories(store);
    write_file(store / "decoy.pem", kRealSystemDefaultCertPem);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle);
    CHECK(scan.kind == DeleteScanKind::kDeleted);
    CHECK(scan.entry == "original.pem");
    CHECK(scan.unlink_err == 0);
    CHECK_FALSE(scan.enumeration_failed);
    CHECK_FALSE(fs::exists(moved_aside / "original.pem"));
    // The decoy at the (new) original path is untouched -- the held
    // descriptor never re-resolved the pathname.
    CHECK(fs::exists(store / "decoy.pem"));
}

// ── (k) enumeration failure AFTER a successful deletion ──────────────────────

TEST_CASE("delete_matching_cert: readdir failure after a successful delete keeps kDeleted",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);

    g_post_match_target = "a.pem";
    g_post_match_seen = false;
    StoreSyscalls sys;
    sys.readdir = &post_match_eio_readdir;

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kDeleted);
    CHECK(scan.entry == "a.pem");
    CHECK(scan.unlink_err == 0);
    CHECK(scan.enumeration_failed);
    CHECK(scan.enum_err == EIO);
    CHECK_FALSE(fs::exists(tmp.path / "a.pem"));
}

// ── (l) unlinkat failure on the recheck-approved entry ───────────────────────

TEST_CASE("delete_matching_cert: unlinkat failure is kUnlinkFailed, file survives",
          "[certificates][linux_store]") {
    yuzu::test::TempDir tmp{"yuzu_test_certs_store_"};
    fs::create_directories(tmp.path);
    write_file(tmp.path / "a.pem", kRealSystemDefaultCertPem);

    StoreSyscalls sys;
    sys.unlinkat = &failing_unlinkat;

    auto dir = open_store(tmp.path);
    REQUIRE(dir.state == CertDirOpen::kOpened);

    auto scan = delete_matching_cert(dir.fd.get(), kNeedle, sys);
    CHECK(scan.kind == DeleteScanKind::kUnlinkFailed);
    CHECK(scan.entry == "a.pem");
    CHECK(scan.unlink_err == EACCES);
    CHECK_FALSE(scan.enumeration_failed);
    REQUIRE(fs::exists(tmp.path / "a.pem"));
    CHECK(read_file(tmp.path / "a.pem") == kRealSystemDefaultCertPem);
}

#endif // !defined(_WIN32)
