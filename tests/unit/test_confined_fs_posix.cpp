#ifndef _WIN32

// Filesystem-backed unit tests for confined_fs_posix.cpp, driven through
// the exported confined_fs.hpp API against a real temp directory tree.
// std::filesystem is used here ONLY for fixture setup (create dirs/files/
// symlinks/renames) -- production code never path-resolves below the root;
// see confined_fs_posix.cpp. Deterministic: no threads, no sleeping; the
// wall-time-cap test relies on max_wall=0 plus the monotonic property of
// steady_clock, never a manufactured delay.

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iterator>
#include <map>
#include <limits>
#include <system_error>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace yuzu::agent::confined_fs;
namespace fs = std::filesystem;

// Forward declarations for the POSIX-only fstat/fstatat TEST SEAM defined in
// confined_fs_posix.cpp (mirrors the Windows leg's
// detail::set_ntcreatefile_for_test declared in confined_fs.hpp -- this one
// has no header declaration since it is not part of the exported platform
// contract, only linked directly by this test TU).
// Seams are declared in confined_fs.hpp (POSIX branch) -- no hand-redeclaration.

namespace {

void write_file(const fs::path& p, std::string_view content = "x") {
    std::ofstream out(p, std::ios::binary);
    out << content;
}

std::vector<EntryOutcome> sorted_entries(std::vector<EntryOutcome> v) {
    std::sort(v.begin(), v.end(),
              [](const EntryOutcome& a, const EntryOutcome& b) { return a.rel_path < b.rel_path; });
    return v;
}

MatchFn match_all() {
    return [](std::string_view, const EntryMeta&) { return true; };
}

MatchFn suffix_match(std::string suffix) {
    return [suffix](std::string_view rel_path, const EntryMeta&) {
        return rel_path.size() >= suffix.size() &&
               rel_path.compare(rel_path.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
}

/// Fake fstat/fstatat that always fails with EIO -- used to exercise the
/// real POSIX metadata-failure recovery paths (root identity capture,
/// per-entry fstatat) deterministically, without racing a live TOCTOU
/// window.
int failing_fstat(int, struct stat*) {
    errno = EIO;
    return -1;
}
int failing_fstatat(int, const char*, struct stat*, int) {
    errno = EIO;
    return -1;
}

/// RAII installers for the seams above -- guarantee restoration even if a
/// REQUIRE/CHECK inside the guarded scope throws.
struct FstatSeamGuard {
    explicit FstatSeamGuard(detail::FstatFn fn) { detail::set_fstat_for_test(fn, true); }
    ~FstatSeamGuard() { detail::set_fstat_for_test(nullptr, false); }
    FstatSeamGuard(const FstatSeamGuard&) = delete;
    FstatSeamGuard& operator=(const FstatSeamGuard&) = delete;
};
struct FstatatSeamGuard {
    explicit FstatatSeamGuard(detail::FstatatFn fn) { detail::set_fstatat_for_test(fn, true); }
    ~FstatatSeamGuard() { detail::set_fstatat_for_test(nullptr, false); }
    FstatatSeamGuard(const FstatatSeamGuard&) = delete;
    FstatatSeamGuard& operator=(const FstatatSeamGuard&) = delete;
};

constexpr DeleteLimits generous_limits() {
    return DeleteLimits{
        /*max_entries=*/10'000,
        /*max_bytes=*/10'000'000,
        /*max_wall=*/std::chrono::milliseconds{60'000},
        /*max_depth=*/64,
        /*max_open_dirs=*/256,
    };
}

/// A directory nest `root/lvl1/.../lvlDEPTH/victim.tmp`, plus an unrelated
/// `outside/victim.tmp`. `deepest_dir`/`deepest_rel` name the depth-DEPTH
/// directory itself -- the swap target in the adversarial tests below.
struct NestedTree {
    fs::path root_dir;
    fs::path outside_dir;
    fs::path outside_victim;
    fs::path deepest_dir;
    std::string deepest_rel;
};

NestedTree build_nested_tree(const fs::path& tmp_root, int depth) {
    NestedTree t;
    t.root_dir = tmp_root / "root";
    fs::create_directories(t.root_dir);
    t.outside_dir = tmp_root / "outside";
    fs::create_directories(t.outside_dir);
    t.outside_victim = t.outside_dir / "victim.tmp";
    write_file(t.outside_victim);

    fs::path cur = t.root_dir;
    std::string rel;
    for (int i = 1; i <= depth; ++i) {
        cur /= "lvl" + std::to_string(i);
        fs::create_directory(cur);
        rel = rel.empty() ? "lvl" + std::to_string(i) : rel + "/lvl" + std::to_string(i);
    }
    write_file(cur / "victim.tmp");
    t.deepest_dir = cur;
    t.deepest_rel = rel;
    return t;
}

/// Pre-walk swap variant, run for a given depth: the depth-N directory is
/// already a symlink to `outside` before `delete_matching` ever starts.
void run_prewalk_swap_test(int depth) {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_swap_pre_"};
    NestedTree t = build_nested_tree(tmp.path, depth);

    const fs::path moved_aside(t.deepest_dir.string() + ".moved");
    fs::rename(t.deepest_dir, moved_aside);
    fs::create_directory_symlink(t.outside_dir, t.deepest_dir);

    OpenRootResult opened = open_root(t.root_dir);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, match_all(), generous_limits());

    const EntryOutcome* found = nullptr;
    for (const auto& e : result.entries) {
        if (e.rel_path == t.deepest_rel) {
            found = &e;
            break;
        }
    }
    REQUIRE(found != nullptr);
    CHECK(found->status == EntryStatus::Skipped);
    CHECK(found->reason == Reason::SymlinkRejected);
    CHECK(fs::exists(t.outside_victim));
}

/// Mid-walk interposition variant, run for a given depth: `open_root` +
/// `open_dir_at` down to the depth-N directory FIRST (holding its fd open),
/// THEN the swap happens underneath the already-held fd, then
/// `enumerate_at`/`unlink_at` are driven directly on that fd -- proving the
/// walk binds to the inode the fd refers to, not the path used to reach it.
void run_midwalk_swap_test(int depth) {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_swap_mid_"};
    NestedTree t = build_nested_tree(tmp.path, depth);

    OpenRootResult opened = open_root(t.root_dir);
    REQUIRE(opened.root.has_value());
    const FileIdentity root_id = opened.root->identity();

    std::vector<OpenDirResult> chain;
    int cur_fd = opened.root->fd_.get();
    for (int i = 1; i <= depth; ++i) {
        OpenDirResult r = open_dir_at(cur_fd, "lvl" + std::to_string(i), root_id);
        REQUIRE(r.reason == Reason::None);
        cur_fd = r.fd.get();
        chain.push_back(std::move(r));
    }

    const fs::path moved_aside(t.deepest_dir.string() + ".moved");
    fs::rename(t.deepest_dir, moved_aside);
    fs::create_directory_symlink(t.outside_dir, t.deepest_dir);

    EnumBudget budget{100, std::chrono::steady_clock::now() + std::chrono::seconds{60}};
    EnumerateResult enum_result = enumerate_at(cur_fd, root_id, budget);
    REQUIRE(enum_result.reason == Reason::None);
    bool saw_victim = false;
    for (const auto& e : enum_result.entries) {
        if (e.name == "victim.tmp")
            saw_victim = true;
    }
    REQUIRE(saw_victim);

    UnlinkOutcome outcome = unlink_at(cur_fd, "victim.tmp", UnlinkKind::File, std::numeric_limits<std::uint64_t>::max());
    CHECK(outcome.status == EntryStatus::Deleted);

    CHECK(fs::exists(t.outside_victim));
    CHECK_FALSE(fs::exists(moved_aside / "victim.tmp"));
}

} // namespace

// ── (1) Happy path ──────────────────────────────────────────────────────

TEST_CASE("delete_matching deletes matched files and leaves the rest", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_happy_"};
    fs::create_directories(tmp.path / "sub");
    write_file(tmp.path / "keep.txt");
    write_file(tmp.path / "a.tmp");
    write_file(tmp.path / "sub" / "b.tmp");
    write_file(tmp.path / "sub" / "keep2.txt");

    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    REQUIRE(opened.reason == Reason::None);

    DeleteResult result = delete_matching(*opened.root, suffix_match(".tmp"), generous_limits());

    CHECK(result.stop_reason == Reason::None);
    auto entries = sorted_entries(result.entries);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].rel_path == "a.tmp");
    CHECK(entries[0].status == EntryStatus::Deleted);
    CHECK(entries[0].reason == Reason::None);
    CHECK(entries[0].os_error == 0);
    CHECK(entries[1].rel_path == "sub/b.tmp");
    CHECK(entries[1].status == EntryStatus::Deleted);
    CHECK(entries[1].reason == Reason::None);
    CHECK(entries[1].os_error == 0);

    CHECK(fs::exists(tmp.path / "keep.txt"));
    CHECK(fs::exists(tmp.path / "sub" / "keep2.txt"));
    CHECK_FALSE(fs::exists(tmp.path / "a.tmp"));
    CHECK_FALSE(fs::exists(tmp.path / "sub" / "b.tmp"));
}

// ── (2) open_root refusals ───────────────────────────────────────────────

TEST_CASE("open_root refuses a symlinked root and a file root", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_openroot_"};
    const fs::path real_dir = tmp.path / "real";
    fs::create_directories(real_dir);
    const fs::path link = tmp.path / "link";
    fs::create_directory_symlink(real_dir, link);

    OpenRootResult sym_result = open_root(link);
    CHECK_FALSE(sym_result.root.has_value());
    CHECK(sym_result.reason == Reason::RootInvalid);

    const fs::path file_path = tmp.path / "file.txt";
    write_file(file_path);
    OpenRootResult file_result = open_root(file_path);
    CHECK_FALSE(file_result.root.has_value());
    CHECK(file_result.reason == Reason::RootInvalid);
}

TEST_CASE("a real root fstat failure closes the fd and reports RootInvalid, no leak",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_rootfstatfail_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);

    // RAII, not a bare ::open/::close pair: every CHECK/REQUIRE below can
    // throw, and a manually-closed fd would leak out of this scope if one did.
    // The fd NUMBER is what the assertion needs, so it is copied out of the
    // owner before the owner releases it.
    int probe1_fd = -1;
    {
        yuzu::agent::ScopedFd probe1{::open("/dev/null", O_RDONLY)};
        REQUIRE(probe1.get() >= 0);
        probe1_fd = probe1.get();
    }

    {
        FstatSeamGuard guard(failing_fstat);
        OpenRootResult result = open_root(root_dir);
        CHECK_FALSE(result.root.has_value());
        CHECK(result.reason == Reason::RootInvalid);
        CHECK(result.os_error == EIO);
    }

    // If open_root's ScopedFd had failed to close the root fd on the fstat
    // failure path above, the next lowest-numbered fd would land one higher
    // than probe1 instead of reusing the exact same number.
    int probe2_fd = -1;
    {
        yuzu::agent::ScopedFd probe2{::open("/dev/null", O_RDONLY)};
        REQUIRE(probe2.get() >= 0);
        probe2_fd = probe2.get();
    }
    CHECK(probe2_fd == probe1_fd);
}

// ── (3) In-tree symlink entry ────────────────────────────────────────────

TEST_CASE("a symlink entry inside the root is skipped and its target survives", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_symlink_entry_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    const fs::path outside_dir = tmp.path / "outside";
    fs::create_directories(outside_dir);
    const fs::path victim = outside_dir / "victim.tmp";
    write_file(victim);
    fs::create_symlink(victim, root_dir / "link.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, match_all(), generous_limits());

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].rel_path == "link.tmp");
    CHECK(result.entries[0].status == EntryStatus::Skipped);
    CHECK(result.entries[0].reason == Reason::SymlinkRejected);
    CHECK(fs::exists(victim));
}

// ── Direct primitive fault coverage (open_dir_at / enumerate_at / unlink_at,
//    called directly rather than through delete_matching, so a fault in the
//    primitive itself can't be masked by walker-level checks) ─────────────

// The byte cap must FAIL CLOSED when the entry cannot be measured at delete
// time. An earlier revision deleted anyway and charged the tally 0: measured, a
// 4096-byte file was removed under a 1-byte remaining budget while reporting
// Deleted/bytes=0, so the cap was bypassed invisibly rather than weakened.
// Reproduces the attack an external reviewer demonstrated against the previous
// measure-by-name implementation: a 1-byte entry was measured, a 4096-byte file
// was swapped over that name, and unlinkat removed 4096 bytes under a 10-byte
// remaining budget while charging 1. Capture-then-measure closes it -- by the
// time the swap lands, our inode is already bound to an unpredictable name and
// the attacker has only replaced a name we no longer act on.
// G1 regression (governance security-guardian, verified): the restore path used a
// plain renameat, which REPLACES its destination. A local user who recreates the
// entry's original name during the capture window therefore had that file silently
// unlinked by the restore -- bytes deleted uncharged against the cap, on an entry
// MatchFn was never asked about and that appears in no outcome. Restore is now
// no-replace: the intruding file survives and the outcome says the tree changed.
TEST_CASE("a refused delete never destroys a file created at the entry's name",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_restore_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "target.tmp", std::string(4096, 'x')); // will breach the cap

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    static fs::path s_root;
    s_root = root_dir;
    UnlinkOutcome outcome{};
    {
        // Fires during the measurement, i.e. while the entry is captured aside:
        // the attacker plants their own file at the now-free original name.
        FstatatSeamGuard guard{[](int dirfd, const char* nm, struct stat* st, int flags) -> int {
            std::ofstream f(s_root / "target.tmp");
            f << "ATTACKER-DATA";
            return ::fstatat(dirfd, nm, st, flags);
        }};
        outcome = unlink_at(opened.root->fd_.get(), "target.tmp", UnlinkKind::File, 1);
    }

    // Nothing was deleted, and the intruding file is intact.
    REQUIRE(fs::exists(root_dir / "target.tmp"));
    std::ifstream in(root_dir / "target.tmp");
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(content == "ATTACKER-DATA");

    // The outcome must SAY the tree changed rather than reporting a clean refusal.
    CHECK(outcome.status == EntryStatus::Failed);
    CHECK(outcome.reason == Reason::CaptureOrphaned);
    CHECK(outcome.bytes == 0);

    // The captured 4096-byte entry is still present under its capture name.
    bool orphan_present = false;
    std::uintmax_t orphan_size = 0;
    for (const auto& e : fs::directory_iterator(root_dir))
        if (e.path().filename().string().rfind(".yuzu_cfs_capture_", 0) == 0) {
            orphan_present = true;
            orphan_size = fs::file_size(e.path());
        }
    CHECK(orphan_present);
    CHECK(orphan_size == 4096);
}

TEST_CASE("unlink_at cannot be made to delete a file swapped in after measurement",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_swapcap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "victim.tmp", "x");                       // 1 byte, the target
    write_file(root_dir / "big.tmp", std::string(4096, 'x'));       // the attacker's payload

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    static fs::path s_root;
    s_root = root_dir;
    UnlinkOutcome outcome{};
    {
        // The seam fires during the measurement, which is the exact instant the
        // attacker gets to act. It renames the large file over the ORIGINAL name.
        FstatatSeamGuard guard{[](int dirfd, const char* nm, struct stat* st, int flags) -> int {
            std::error_code ec;
            fs::rename(s_root / "big.tmp", s_root / "victim.tmp", ec);
            return ::fstatat(dirfd, nm, st, flags);
        }};
        outcome = unlink_at(opened.root->fd_.get(), "victim.tmp", UnlinkKind::File, 10);
    }

    // The 1-byte inode we captured is what got deleted, and it is what we charged.
    CHECK(outcome.status == EntryStatus::Deleted);
    CHECK(outcome.bytes == 1);
    // The attacker's 4096-byte file was NOT deleted under the 10-byte budget --
    // it is still sitting at the name they moved it to.
    CHECK(fs::exists(root_dir / "victim.tmp"));
    CHECK(fs::file_size(root_dir / "victim.tmp") == 4096);
    // And no capture-prefixed orphan was left behind.
    for (const auto& e : fs::directory_iterator(root_dir))
        CHECK(e.path().filename().string().rfind(".yuzu_cfs_capture_", 0) != 0);
}

TEST_CASE("unlink_at refuses to delete when it cannot measure the entry", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_measfail_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "big.tmp", std::string(4096, 'x'));

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    UnlinkOutcome outcome{};
    {
        FstatatSeamGuard guard{[](int, const char*, struct stat*, int) -> int {
            errno = EACCES;
            return -1;
        }};
        outcome = unlink_at(opened.root->fd_.get(), "big.tmp", UnlinkKind::File, 1);
    }

    CHECK(outcome.status == EntryStatus::Failed);
    CHECK(outcome.reason == Reason::OsError);
    CHECK(outcome.os_error == EACCES);
    CHECK(outcome.bytes == 0);
    CHECK(fs::exists(root_dir / "big.tmp")); // never deleted uncharged
}

TEST_CASE("capture_identity agrees with the identity open_root pinned", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_ident_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    // capture_identity is exported for reuse, but every other test reaches it
    // only through open_root, so a field-mapping regression (dev/ino swapped or
    // truncated) would be invisible.
    const auto direct = capture_identity(opened.root->fd_.get());
    REQUIRE(direct.has_value());
    CHECK(*direct == opened.root->identity());

    struct stat st{};
    REQUIRE(::stat(root_dir.c_str(), &st) == 0);
    CHECK(direct->dev == static_cast<std::uint64_t>(st.st_dev));
    CHECK(direct->ino == static_cast<std::uint64_t>(st.st_ino));
}

TEST_CASE("open_root refuses a root path containing an embedded NUL", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_rootnul_"};
    const fs::path real_root = tmp.path / "root";
    fs::create_directories(real_root);
    write_file(real_root / "victim.tmp");

    // "<root>\0/decoy" truncates at the NUL when handed to a C API, so an
    // unchecked open_root would silently pin <root> while the caller believes
    // it named something else -- every later operation is then confined to the
    // wrong tree. Must be refused before the first syscall.
    std::string poisoned = real_root.string();
    poisoned.push_back('\0');
    poisoned += "/decoy";
    OpenRootResult r = open_root(fs::path{poisoned});

    CHECK_FALSE(r.root.has_value());
    CHECK(r.reason == Reason::RootInvalid);
    CHECK(fs::exists(real_root / "victim.tmp"));
}

TEST_CASE("open_dir_at refuses a directory swapped for a symlink before the open",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_odaswap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir / "child");
    const fs::path outside_dir = tmp.path / "outside";
    fs::create_directories(outside_dir);
    write_file(outside_dir / "victim.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());
    const FileIdentity root_id = opened.root->identity();

    fs::remove(root_dir / "child");
    fs::create_directory_symlink(outside_dir, root_dir / "child");

    // Direct call: if open_dir_at ever lost O_NOFOLLOW, this would silently
    // follow the symlink into `outside` instead of refusing it.
    OpenDirResult r = open_dir_at(opened.root->fd_.get(), "child", root_id);
    CHECK_FALSE(r.fd.valid());
    CHECK(r.reason == Reason::SymlinkRejected);
    CHECK(fs::exists(outside_dir / "victim.tmp"));
}

TEST_CASE("open_dir_at refuses a child that crosses the root's device", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_devbound_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir / "child");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());
    const FileIdentity real_id = opened.root->identity();

    // A deliberately WRONG root identity -- same inode space, a fabricated
    // different `dev` -- exercises the post-open device re-verify without
    // needing a second real filesystem/mount.
    const FileIdentity fake_id{real_id.dev + 1, real_id.ino};

    OpenDirResult r = open_dir_at(opened.root->fd_.get(), "child", fake_id);
    CHECK_FALSE(r.fd.valid());
    CHECK(r.reason == Reason::DeviceBoundary);
}

TEST_CASE("open_dir_at refuses invalid names before touching the filesystem", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_odainvalidname_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir / "real");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());
    const FileIdentity root_id = opened.root->identity();
    const int fd = opened.root->fd_.get();

    const std::vector<std::string> bad_names{
        "../x",
        "a/b",
        std::string("a\0b", 3),
    };
    for (const auto& bad : bad_names) {
        OpenDirResult r = open_dir_at(fd, bad, root_id);
        CHECK_FALSE(r.fd.valid());
        CHECK(r.reason == Reason::InvalidName);
    }

    CHECK(fs::exists(root_dir / "real"));
}

TEST_CASE("enumerate_at uses an independent description across two direct calls on one fd",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_enumreuse_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");
    write_file(root_dir / "b.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());
    const int fd = opened.root->fd_.get();
    const FileIdentity root_id = opened.root->identity();
    const EnumBudget budget{1000, std::chrono::steady_clock::now() + std::chrono::seconds{60}};

    // Two direct calls on the SAME held fd, bypassing delete_matching's own
    // independent root frame entirely: if enumerate_at shared the directory
    // read offset (e.g. via dup(dir_fd) instead of its own fresh
    // openat(dir_fd, ".")), the second call would resume from wherever the
    // first call's readdir cursor stopped and see nothing.
    EnumerateResult first = enumerate_at(fd, root_id, budget);
    CHECK(first.reason == Reason::None);
    CHECK(first.entries.size() == 2);

    EnumerateResult second = enumerate_at(fd, root_id, budget);
    CHECK(second.reason == Reason::None);
    CHECK(second.entries.size() == 2);
}

TEST_CASE("enumerate_at itself stops with WallTimeCap on an already-past deadline",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_enumwall_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const EnumBudget budget{1000, std::chrono::steady_clock::now() - std::chrono::seconds{1}};
    EnumerateResult result = enumerate_at(opened.root->fd_.get(), opened.root->identity(), budget);

    CHECK(result.reason == Reason::WallTimeCap);
    CHECK(result.entries.empty());
}

TEST_CASE(
    "enumerate_at itself truncates with EntryCap when the budget is smaller than the directory",
    "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_enumentrycap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    for (int i = 0; i < 5; ++i)
        write_file(root_dir / ("f" + std::to_string(i) + ".tmp"));

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const EnumBudget budget{2, std::chrono::steady_clock::now() + std::chrono::seconds{60}};
    EnumerateResult result = enumerate_at(opened.root->fd_.get(), opened.root->identity(), budget);

    CHECK(result.reason == Reason::EntryCap);
    CHECK(result.entries.size() == 2);
}

TEST_CASE("a real fstatat failure surfaces as DirEntry.stat_error and Failed(OsError)",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_statatfail_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "f.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    DeleteResult result = [&] {
        FstatatSeamGuard guard(failing_fstatat);
        return delete_matching(*opened.root, match_all(), generous_limits());
    }();

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].rel_path == "f.tmp");
    CHECK(result.entries[0].status == EntryStatus::Failed);
    CHECK(result.entries[0].reason == Reason::OsError);
    CHECK(result.entries[0].os_error == EIO);
    CHECK(fs::exists(root_dir / "f.tmp"));
}

TEST_CASE("unlink_at removes only the symlink entry itself, never its target", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_unlinklink_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    const fs::path outside_dir = tmp.path / "outside";
    fs::create_directories(outside_dir);
    const fs::path target = outside_dir / "target.tmp";
    write_file(target);
    fs::create_symlink(target, root_dir / "link.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    UnlinkOutcome outcome = unlink_at(opened.root->fd_.get(), "link.tmp", UnlinkKind::File, std::numeric_limits<std::uint64_t>::max());
    CHECK(outcome.status == EntryStatus::Deleted);

    std::error_code ec;
    const auto st = fs::symlink_status(root_dir / "link.tmp", ec);
    CHECK(st.type() == fs::file_type::not_found);
    CHECK(fs::exists(target));
}

// ── (4) Adversarial swap at depths 1, 2, 3 -- pre-walk and mid-walk ──────

TEST_CASE("adversarial swap at depth 1, pre-walk", "[confined_fs]") { run_prewalk_swap_test(1); }
TEST_CASE("adversarial swap at depth 2, pre-walk", "[confined_fs]") { run_prewalk_swap_test(2); }
TEST_CASE("adversarial swap at depth 3, pre-walk", "[confined_fs]") { run_prewalk_swap_test(3); }

TEST_CASE("adversarial swap at depth 1, mid-walk interposition", "[confined_fs]") {
    run_midwalk_swap_test(1);
}
TEST_CASE("adversarial swap at depth 2, mid-walk interposition", "[confined_fs]") {
    run_midwalk_swap_test(2);
}
TEST_CASE("adversarial swap at depth 3, mid-walk interposition", "[confined_fs]") {
    run_midwalk_swap_test(3);
}

// ── (5) Caps ──────────────────────────────────────────────────────────────

TEST_CASE("entry cap stops the walk with StopWalk(EntryCap)", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_entrycap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    for (int i = 0; i < 5; ++i)
        write_file(root_dir / ("f" + std::to_string(i) + ".tmp"));

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const DeleteLimits limits{/*max_entries=*/3, /*max_bytes=*/1'000'000,
                               /*max_wall=*/std::chrono::milliseconds{60'000}, /*max_depth=*/32, /*max_open_dirs=*/64};
    DeleteResult result = delete_matching(*opened.root, match_all(), limits);

    // A directory of 5 with a cap of 3 is a NON-EMPTY truncated batch: it
    // must be processed (3 deletions), not silently dropped just because
    // the directory as a whole wasn't fully enumerated.
    CHECK(result.stop_reason == Reason::EntryCap);
    REQUIRE(result.entries.size() == 3);
    CHECK(result.tally.entries_seen == 3);
    for (const auto& e : result.entries) {
        CHECK(e.status == EntryStatus::Deleted);
        CHECK(e.reason == Reason::None);
    }
    int remaining = 0;
    for (int i = 0; i < 5; ++i) {
        if (fs::exists(root_dir / ("f" + std::to_string(i) + ".tmp")))
            ++remaining;
    }
    CHECK(remaining == 2);
}

TEST_CASE("byte cap skips an oversized file but a following smaller one still deletes",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_bytecap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "big.tmp", std::string(2000, 'x'));
    write_file(root_dir / "small.tmp", "ok");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const DeleteLimits limits{/*max_entries=*/1000, /*max_bytes=*/100,
                               /*max_wall=*/std::chrono::milliseconds{60'000}, /*max_depth=*/32, /*max_open_dirs=*/64};
    DeleteResult result = delete_matching(*opened.root, match_all(), limits);

    auto entries = sorted_entries(result.entries);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].rel_path == "big.tmp");
    CHECK(entries[0].status == EntryStatus::Skipped);
    CHECK(entries[0].reason == Reason::ByteCap);
    CHECK(entries[1].rel_path == "small.tmp");
    CHECK(entries[1].status == EntryStatus::Deleted);

    CHECK(fs::exists(root_dir / "big.tmp"));
    CHECK_FALSE(fs::exists(root_dir / "small.tmp"));
}

TEST_CASE("wall-time cap of zero stops immediately with nothing deleted", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_wallcap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const DeleteLimits limits{/*max_entries=*/1000, /*max_bytes=*/1'000'000,
                               /*max_wall=*/std::chrono::milliseconds{0}, /*max_depth=*/32, /*max_open_dirs=*/64};
    DeleteResult result = delete_matching(*opened.root, match_all(), limits);

    CHECK(result.stop_reason == Reason::WallTimeCap);
    CHECK(result.entries.empty());
    CHECK(result.tally.entries_seen == 0);
    CHECK(fs::exists(root_dir / "a.tmp"));
}

TEST_CASE("depth cap skips a directory past max_depth but still deletes shallow entries",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_depthcap_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir / "lvl1" / "lvl2");
    write_file(root_dir / "shallow.tmp");
    write_file(root_dir / "lvl1" / "lvl2" / "deep.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    const DeleteLimits limits{/*max_entries=*/1000, /*max_bytes=*/1'000'000,
                               /*max_wall=*/std::chrono::milliseconds{60'000}, /*max_depth=*/1, /*max_open_dirs=*/64};
    DeleteResult result = delete_matching(*opened.root, match_all(), limits);

    auto entries = sorted_entries(result.entries);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].rel_path == "lvl1/lvl2");
    CHECK(entries[0].status == EntryStatus::Skipped);
    CHECK(entries[0].reason == Reason::DepthCap);
    CHECK(entries[1].rel_path == "shallow.tmp");
    CHECK(entries[1].status == EntryStatus::Deleted);

    CHECK(fs::exists(root_dir / "lvl1" / "lvl2" / "deep.tmp"));
    CHECK_FALSE(fs::exists(root_dir / "shallow.tmp"));
}

// ── (6) Default-constructed DeleteLimits ─────────────────────────────────

TEST_CASE("a default-constructed DeleteLimits deletes nothing on a populated tree",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_defaultlimits_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, match_all(), DeleteLimits{});

    CHECK(result.entries.empty());
    CHECK(result.tally.bytes_deleted == 0);
    CHECK(fs::exists(root_dir / "a.tmp"));
}

// ── (7) InvalidName ───────────────────────────────────────────────────────

TEST_CASE("unlink_at refuses invalid names before touching the filesystem", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_invalidname_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "real.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());
    const int fd = opened.root->fd_.get();

    const std::vector<std::string> bad_names{
        "../x",
        "a/b",
        std::string("a\0b", 3),
    };
    for (const auto& bad : bad_names) {
        UnlinkOutcome outcome = unlink_at(fd, bad, UnlinkKind::File, std::numeric_limits<std::uint64_t>::max());
        CHECK(outcome.status == EntryStatus::Failed);
        CHECK(outcome.reason == Reason::InvalidName);
    }

    CHECK(fs::exists(root_dir / "real.tmp"));
}

// ── (8) Root reuse ────────────────────────────────────────────────────────

TEST_CASE("a ConfinedRoot supports two sequential delete_matching calls", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_reuse_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");
    write_file(root_dir / "b.log");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    DeleteResult first = delete_matching(*opened.root, suffix_match(".tmp"), generous_limits());
    CHECK(first.stop_reason == Reason::None);
    REQUIRE(first.entries.size() == 1);
    CHECK(first.entries[0].rel_path == "a.tmp");
    CHECK(first.entries[0].status == EntryStatus::Deleted);
    CHECK_FALSE(fs::exists(root_dir / "a.tmp"));
    CHECK(fs::exists(root_dir / "b.log"));

    DeleteResult second = delete_matching(*opened.root, suffix_match(".log"), generous_limits());
    CHECK(second.stop_reason == Reason::None);
    REQUIRE(second.entries.size() == 1);
    CHECK(second.entries[0].rel_path == "b.log");
    CHECK(second.entries[0].status == EntryStatus::Deleted);
    CHECK_FALSE(fs::exists(root_dir / "b.log"));
}

// ── (9) A throwing MatchFn ────────────────────────────────────────────────

TEST_CASE("a throwing MatchFn stops the walk with MatchError, consistent with the filesystem",
          "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_matcherror_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");
    write_file(root_dir / "z_throws.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    MatchFn throwing = [](std::string_view rel_path, const EntryMeta&) -> bool {
        if (rel_path == "z_throws.tmp")
            throw std::runtime_error("boom");
        return true;
    };

    DeleteResult result = delete_matching(*opened.root, throwing, generous_limits());

    CHECK(result.stop_reason == Reason::MatchError);
    for (const auto& e : result.entries) {
        const bool exists = fs::exists(root_dir / e.rel_path);
        if (e.status == EntryStatus::Deleted)
            CHECK_FALSE(exists);
        else
            CHECK(exists);
    }
    // z_throws.tmp itself is never acted on -- the throw happens inside the
    // match call, before any decision that could delete it.
    CHECK(fs::exists(root_dir / "z_throws.tmp"));
}

TEST_CASE("a MatchFn that throws on its first invocation stops before any deletion",
          "[confined_fs]") {
    // Distinguishes "the walk stopped at the first entry" from "the walk
    // caught the throw and kept going": the throwing entry is whichever one
    // readdir happens to visit FIRST (order-independent -- a stateful
    // closure throws only on invocation #1, never by matching a name), and
    // every later invocation returns true. A walker that faultily continued
    // past the throw would delete every remaining fixture file; a correct
    // one stops immediately, leaving all three untouched and reporting no
    // outcomes at all.
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_matcherrorfirst_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "a.tmp");
    write_file(root_dir / "b.tmp");
    write_file(root_dir / "c.tmp");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    bool first_call = true;
    MatchFn throw_once_first = [&first_call](std::string_view, const EntryMeta&) -> bool {
        if (first_call) {
            first_call = false;
            throw std::runtime_error("boom");
        }
        return true;
    };

    DeleteResult result = delete_matching(*opened.root, throw_once_first, generous_limits());

    CHECK(result.stop_reason == Reason::MatchError);
    CHECK(result.entries.empty());
    CHECK(fs::exists(root_dir / "a.tmp"));
    CHECK(fs::exists(root_dir / "b.tmp"));
    CHECK(fs::exists(root_dir / "c.tmp"));
}


// ── POSIX end-to-end: the real enumerator's timestamp ───────────────────────
//
// Gate 1 (Codex FV-2, Kimi F2, Spec F3): the pure conversion was tested
// exhaustively and the POPULATE step not at all. Reverting the assignment in
// confined_fs_posix.cpp to omit the timestamp left every POSIX assertion green,
// because no test observed `meta.mtime` from a real file.
//
// This exercises the whole path a consumer depends on: a real file with a real
// mtime, read through the held root fd by the same fstatat the walk already
// performs, delivered to a MatchFn, and controlling what is actually unlinked.
TEST_CASE("POSIX enumeration supplies a real file's mtime and age can select on it",
          "[confined_fs][mtime]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_posix_mtime_"};
    const fs::path root_dir = tmp.path / "root";
    fs::create_directories(root_dir);
    write_file(root_dir / "old.tmp");
    write_file(root_dir / "new.tmp");
    write_file(root_dir / "epoch.tmp");

    // Whole-second, far from "now", so the assertion cannot pass by accident
    // and does not depend on the clock during the test.
    constexpr std::int64_t kOldSeconds = 946'684'800;  // 2000-01-01T00:00:00Z
    constexpr std::int64_t kNewSeconds = 1'893'456'000; // 2030-01-01T00:00:00Z
    auto set_mtime = [&](const fs::path& p, std::int64_t secs) {
        struct timespec times[2];
        times[0].tv_sec = static_cast<time_t>(secs); times[0].tv_nsec = 0; // atime
        times[1].tv_sec = static_cast<time_t>(secs); times[1].tv_nsec = 0; // mtime
        REQUIRE(::utimensat(AT_FDCWD, p.c_str(), times, AT_SYMLINK_NOFOLLOW) == 0);
    };
    set_mtime(root_dir / "old.tmp", kOldSeconds);
    set_mtime(root_dir / "new.tmp", kNewSeconds);
    // THE ASYMMETRY, pinned. On POSIX st_mtime == 0 is a genuine 1970-01-01
    // timestamp and the optional is ENGAGED; on Windows a FILETIME of 0 means
    // "not set" and yields nullopt. That difference is deliberate and is the
    // single most likely thing a later reader "harmonises" -- and doing so would
    // pass every other test here while silently converting real epoch-dated
    // files into "unknown age", which the documented consumer shape
    // (`if (!meta.mtime) return false;`) then exempts from cleanup forever.
    set_mtime(root_dir / "epoch.tmp", 0);

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    // 1. The enumerator itself reports the real values.
    const EnumBudget budget{1000, std::chrono::steady_clock::now() + std::chrono::seconds{60}};
    EnumerateResult enumerated =
        enumerate_at(opened.root->fd_.get(), opened.root->identity(), budget);
    // Assert the enumeration SUCCEEDED, not merely that it returned two rows: a
    // budget-truncated or errored walk could also yield two. The Windows twin
    // already asserts this.
    REQUIRE(enumerated.reason == Reason::None);
    REQUIRE(enumerated.entries.size() == 3);
    std::map<std::string, std::optional<std::int64_t>> by_name;
    for (const auto& e : enumerated.entries) by_name[e.name] = e.meta.mtime;
    CHECK(by_name["old.tmp"] == std::optional<std::int64_t>{kOldSeconds});
    CHECK(by_name["new.tmp"] == std::optional<std::int64_t>{kNewSeconds});
    // Engaged, and holding zero -- NOT nullopt.
    REQUIRE(by_name["epoch.tmp"].has_value());
    CHECK(by_name["epoch.tmp"] == std::optional<std::int64_t>{0});

    // 2. And an age policy over those values selects correctly end-to-end.
    constexpr std::int64_t kCutoff = 1'500'000'000; // between the two
    MatchFn older_than_cutoff = [](std::string_view, const EntryMeta& meta) {
        if (!meta.mtime) return false;
        return *meta.mtime < kCutoff;
    };
    DeleteLimits limits{};
    limits.max_entries = 100;
    limits.max_bytes = 1'000'000;
    limits.max_wall = std::chrono::milliseconds{60'000};
    limits.max_depth = 4;
    limits.max_open_dirs = 4;

    DeleteResult result = delete_matching(*opened.root, older_than_cutoff, limits);
    REQUIRE(result.stop_reason == Reason::None);
    CHECK_FALSE(fs::exists(root_dir / "old.tmp"));
    CHECK(fs::exists(root_dir / "new.tmp"));
    // An epoch-dated file IS old, and is treated as such rather than as unknown.
    CHECK_FALSE(fs::exists(root_dir / "epoch.tmp"));
}

#endif // !_WIN32
