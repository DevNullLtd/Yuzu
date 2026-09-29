/**
 * test_certificates_store_honesty.cpp -- pure vectors for the Windows/Linux
 * certificate-store honesty helpers in certificates_macos_parsers.hpp
 * (canonical_thumbprint, is_cert_entry_name, classify_cert_dir_open,
 * classify_cert_entry_open, CertEntryIdentity, classify_delete_recheck).
 *
 * Everything here runs against fixture bools/ints/strings -- no `open`,
 * `readdir`, `readlinkat`, or `fstatat` syscall, no real filesystem, no
 * platform required -- because the helpers are pure by design (same
 * header-for-testability pattern as test_certificates_macos.cpp). Runs on
 * every host, incl. MSVC.
 *
 * is_cert_entry_name is the Linux directory filter used by a readdir(3)
 * d_name enumeration (peer review F4/F5); its accept/reject boundary must
 * match std::filesystem::path::extension() exactly -- the parity test below
 * runs both against the real std::filesystem API, not merely by inspection.
 *
 * classify_delete_recheck's vectors close #3245 (TOCTOU: the match was
 * established on one inode, the unlink must act on the same one) and peer
 * review F2 (a symlink whose link_target text is unchanged but whose
 * resolved target inode differs -- a package update renaming a new
 * certificate over the old target path).
 */

#include <catch2/catch_test_macros.hpp>

#include <certificates_macos_parsers.hpp> // the SHARED pure helpers (no hand copy)

#include <cerrno>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

using namespace yuzu::certificates_macos;

// ── canonical_thumbprint ─────────────────────────────────────────────────────

TEST_CASE("canonical_thumbprint uppercases mixed-case hex", "[certificates][honesty]") {
    CHECK(canonical_thumbprint("aB12cD34eF56789012345678901234567890aBcD") ==
          "AB12CD34EF56789012345678901234567890ABCD");
}

TEST_CASE("canonical_thumbprint leaves already-uppercase input unchanged",
          "[certificates][honesty]") {
    const std::string up = "AB12CD34EF56789012345678901234567890ABCD";
    CHECK(canonical_thumbprint(up) == up);
}

TEST_CASE("canonical_thumbprint is a fold: lower and upper canonicalize identically",
          "[certificates][honesty]") {
    const std::string lower = "ab12cd34ef56789012345678901234567890abcd";
    const std::string upper = "AB12CD34EF56789012345678901234567890ABCD";
    CHECK(canonical_thumbprint(lower) == canonical_thumbprint(upper));
}

// ── win_store_fallback_allowed ───────────────────────────────────────────────

// #4377 asymmetry: the read path (list/details, via enumerate_store) may
// disclose a LocalMachine->CurrentUser fallback; the delete path may not --
// a destructive action must never target a store the caller did not name.
// delete_cert_win does not actually call this predicate at all (it has no
// fallback branch to guard): its CURRENT_USER exclusion is enforced
// structurally (exactly one CertOpenStore call, no CERT_SYSTEM_STORE_
// CURRENT_USER reference in the function body) -- verified manually by
// reviewers reading the function, not by an automated check. The kDelete
// vector below is therefore a decision-record of the asymmetry, not a test
// that exercises delete's production path.
TEST_CASE("win_store_fallback_allowed: read may fall back, delete may not",
          "[certificates][honesty]") {
    CHECK(win_store_fallback_allowed(WinStoreAction::kRead));
    CHECK_FALSE(win_store_fallback_allowed(WinStoreAction::kDelete));
}

// ── is_cert_entry_name ───────────────────────────────────────────────────────

TEST_CASE("is_cert_entry_name accepts .pem/.crt suffixed names", "[certificates][honesty]") {
    CHECK(is_cert_entry_name("a.pem"));
    CHECK(is_cert_entry_name("ca-certificates.crt"));
    CHECK(is_cert_entry_name("x.y.pem"));
}

TEST_CASE("is_cert_entry_name rejects dot-files, wrong-case, and dotless names",
          "[certificates][honesty]") {
    CHECK_FALSE(is_cert_entry_name(".pem"));
    CHECK_FALSE(is_cert_entry_name("a.PEM"));
    CHECK_FALSE(is_cert_entry_name("a.pem.bak"));
    CHECK_FALSE(is_cert_entry_name("a.crt~"));
    CHECK_FALSE(is_cert_entry_name("."));
    CHECK_FALSE(is_cert_entry_name(".."));
    CHECK_FALSE(is_cert_entry_name(""));
    CHECK_FALSE(is_cert_entry_name("pem"));
}

TEST_CASE("is_cert_entry_name parity with std::filesystem::path::extension()",
          "[certificates][honesty]") {
    auto extension_says_cert = [](std::string_view name) {
        auto ext = std::filesystem::path(name).extension().string();
        return ext == ".pem" || ext == ".crt";
    };
    for (std::string_view name : {"a.pem", "ca-certificates.crt", "x.y.pem", ".pem", "a.PEM",
                                   "a.pem.bak", "a.crt~", ".", "..", "", "pem"}) {
        CHECK(is_cert_entry_name(name) == extension_says_cert(name));
    }
}

// ── classify_cert_dir_open ───────────────────────────────────────────────────

TEST_CASE("classify_cert_dir_open: ok is always kOpened regardless of err",
          "[certificates][honesty]") {
    CHECK(classify_cert_dir_open(true, 0) == CertDirOpen::kOpened);
}

TEST_CASE("classify_cert_dir_open: ENOENT means the store is simply absent",
          "[certificates][honesty]") {
    CHECK(classify_cert_dir_open(false, ENOENT) == CertDirOpen::kAbsent);
}

TEST_CASE("classify_cert_dir_open: ENOTDIR is unreadable, not absent -- something "
          "non-directory sits at the store path",
          "[certificates][honesty]") {
    CHECK(classify_cert_dir_open(false, ENOTDIR) == CertDirOpen::kUnreadable);
}

TEST_CASE("classify_cert_dir_open: EACCES/EPERM/EIO are unreadable, not absent",
          "[certificates][honesty]") {
    CHECK(classify_cert_dir_open(false, EACCES) == CertDirOpen::kUnreadable);
    CHECK(classify_cert_dir_open(false, EPERM) == CertDirOpen::kUnreadable);
    CHECK(classify_cert_dir_open(false, EIO) == CertDirOpen::kUnreadable);
}

// ── classify_cert_entry_open ─────────────────────────────────────────────────

TEST_CASE("classify_cert_entry_open: ok is always kOpened", "[certificates][honesty]") {
    CHECK(classify_cert_entry_open(true, 0) == CertEntryOpen::kOpened);
}

TEST_CASE("classify_cert_entry_open: ELOOP is the O_NOFOLLOW symlink signature",
          "[certificates][honesty]") {
    CHECK(classify_cert_entry_open(false, ELOOP) == CertEntryOpen::kSymlink);
}

TEST_CASE("classify_cert_entry_open: ENOENT means the entry vanished mid-scan",
          "[certificates][honesty]") {
    CHECK(classify_cert_entry_open(false, ENOENT) == CertEntryOpen::kVanished);
}

TEST_CASE("classify_cert_entry_open: EACCES/EMFILE are genuine unreadable failures",
          "[certificates][honesty]") {
    CHECK(classify_cert_entry_open(false, EACCES) == CertEntryOpen::kUnreadable);
    CHECK(classify_cert_entry_open(false, EMFILE) == CertEntryOpen::kUnreadable);
}

// ── classify_delete_recheck ──────────────────────────────────────────────────

namespace {

CertEntryIdentity regular_identity(std::uint64_t dev, std::uint64_t ino) {
    CertEntryIdentity id;
    id.is_symlink = false;
    id.dev = dev;
    id.ino = ino;
    return id;
}

CertEntryIdentity symlink_identity(std::uint64_t dev, std::uint64_t ino,
                                   std::string link_target, std::uint64_t target_dev,
                                   std::uint64_t target_ino) {
    CertEntryIdentity id;
    id.is_symlink = true;
    id.dev = dev;
    id.ino = ino;
    id.link_target = std::move(link_target);
    id.target_dev = target_dev;
    id.target_ino = target_ino;
    return id;
}

} // namespace

TEST_CASE("classify_delete_recheck: identical regular-file identity proceeds",
          "[certificates][honesty]") {
    auto id = regular_identity(1, 100);
    CHECK(classify_delete_recheck(id, id) == DeleteRecheck::kProceed);
}

TEST_CASE("classify_delete_recheck: identical symlink identity proceeds",
          "[certificates][honesty]") {
    auto id = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 1, 300);
    CHECK(classify_delete_recheck(id, id) == DeleteRecheck::kProceed);
}

TEST_CASE("classify_delete_recheck: differing entry inode changes the decision",
          "[certificates][honesty]") {
    auto at_match = regular_identity(1, 100);
    auto at_unlink = regular_identity(1, 101);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: differing entry device changes the decision",
          "[certificates][honesty]") {
    auto at_match = regular_identity(1, 100);
    auto at_unlink = regular_identity(2, 100);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: a regular-to-symlink flip changes the decision "
          "even with the same entry dev/ino",
          "[certificates][honesty]") {
    auto at_match = regular_identity(1, 100);
    auto at_unlink = symlink_identity(1, 100, "/usr/share/ca-certificates/example.crt", 1, 300);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: a retargeted symlink (different link_target) changes "
          "the decision",
          "[certificates][honesty]") {
    auto at_match = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 1, 300);
    // target_ino held at 300 (unchanged from at_match) so this vector isolates the
    // link_target TEXT comparison alone -- a classifier that ignored link_target and
    // compared only target_ino would wrongly pass this as kProceed (A1-02).
    auto at_unlink = symlink_identity(1, 200, "/usr/share/ca-certificates/other.crt", 1, 300);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: same link inode and same link_target text but a "
          "different resolved target inode changes the decision (F2 rename-over-target)",
          "[certificates][honesty]") {
    auto at_match = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 1, 300);
    auto at_unlink = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 1, 999);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: a differing target device changes the decision",
          "[certificates][honesty]") {
    auto at_match = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 1, 300);
    auto at_unlink = symlink_identity(1, 200, "/usr/share/ca-certificates/example.crt", 2, 300);
    CHECK(classify_delete_recheck(at_match, at_unlink) == DeleteRecheck::kChanged);
}

TEST_CASE("classify_delete_recheck: a missing at_unlink capture fails closed as kUnknown",
          "[certificates][honesty]") {
    auto at_match = regular_identity(1, 100);
    CHECK(classify_delete_recheck(at_match, std::nullopt) == DeleteRecheck::kUnknown);
}

TEST_CASE("classify_delete_recheck: a missing at_match capture fails closed as kUnknown",
          "[certificates][honesty]") {
    auto at_unlink = regular_identity(1, 100);
    CHECK(classify_delete_recheck(std::nullopt, at_unlink) == DeleteRecheck::kUnknown);
}

TEST_CASE("classify_delete_recheck: both captures missing fails closed as kUnknown",
          "[certificates][honesty]") {
    CHECK(classify_delete_recheck(std::nullopt, std::nullopt) == DeleteRecheck::kUnknown);
}
