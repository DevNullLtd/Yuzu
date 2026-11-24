// Windows-only tests for confined_fs_win.cpp -- entire file `#ifdef _WIN32`.
// Real filesystem, real junctions (built WITHOUT admin via
// FSCTL_SET_REPARSE_POINT + a hand-built IO_REPARSE_TAG_MOUNT_POINT buffer --
// CreateSymbolicLinkW needs privilege, so it is never used here). Mirrors the
// POSIX suite's scenarios; path-based Win32 calls (CreateDirectoryW,
// MoveFileExW, DeviceIoControl) are FIXTURE setup only -- production code
// under test never takes a path-based mutation path.

#ifdef _WIN32

#include <yuzu/agent/confined_fs.hpp>

// AFTER confined_fs.hpp, which pulls <windows.h>: <winioctl.h> depends on the
// base Windows types and does not include them itself, so the order is
// load-bearing. It is REQUIRED for FSCTL_SET_REPARSE_POINT, which <windows.h>
// does NOT provide under WIN32_LEAN_AND_MEAN (set by confined_fs.hpp). The
// off-Windows header stand-in used during development declared that constant
// itself, so the omission compiled there and failed only on the first real MSVC
// build; the stand-in has since been split to mirror the real header layout.
#include <winioctl.h>
#include <winternl.h> // NTSTATUS and the NtCreateFile signature, for the create-options spy
#include <yuzu/agent/confined_fs_rules.hpp>

#include "test_helpers.hpp" // yuzu::test::TempDir
#include "win_junction_test_support.hpp" // yuzu::test::create_junction / JunctionCleanup

#include <catch2/catch_test_macros.hpp>

#include <limits>
#include <map>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::agent::confined_fs;
using yuzu::test::create_junction;
using yuzu::test::JunctionCleanup;

namespace {

// Raw WriteFile rather than std::ofstream/<fstream>: libc++'s <fstream>
// itself branches on `_WIN32` internally and expects real Windows CRT
// entry points (_wfopen, _fseeki64, ...) that a syntax-check-only shim
// cannot supply -- this sidesteps that host limitation, not a functional
// concern for what the test needs (writing a small fixture file).
void write_file(const std::filesystem::path& path, std::string_view content) {
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    yuzu::agent::confined_fs::WinHandle owned(h);
    DWORD written = 0;
    REQUIRE(WriteFile(owned.get(), content.data(), static_cast<DWORD>(content.size()), &written,
                       nullptr));
}

MatchFn always_match = [](std::string_view, const EntryMeta&) { return true; };

DeleteLimits open_limits() {
    return DeleteLimits{/*max_entries=*/1000, /*max_bytes=*/1'000'000,
                         /*max_wall=*/std::chrono::milliseconds{30'000}, /*max_depth=*/8, /*max_open_dirs=*/64};
}

void sort_by_rel_path(std::vector<EntryOutcome>& entries) {
    std::sort(entries.begin(), entries.end(),
              [](const EntryOutcome& a, const EntryOutcome& b) { return a.rel_path < b.rel_path; });
}

// PLAN-013-mirroring pre-walk swap: the junction is planted BEFORE
// delete_matching ever runs. Depth 1 = directly under root.
void run_pre_walk_junction_swap(int depth) {
    INFO("pre-walk junction swap at depth " << depth);

    yuzu::test::TempDir victim{"yuzu_test_confined_win_victim_"};
    std::filesystem::create_directories(victim.path);
    write_file(victim.path / "victim.txt", "keep-me");

    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_root_"};
    std::filesystem::create_directories(root_dir.path);

    std::filesystem::path parent_path = root_dir.path;
    std::string rel_prefix;
    for (int i = 1; i < depth; ++i) {
        const std::string level = "level" + std::to_string(i);
        parent_path /= level;
        std::filesystem::create_directories(parent_path);
        rel_prefix = rel_prefix.empty() ? level : rel_prefix + "/" + level;
    }
    const std::string swap_name = "level" + std::to_string(depth);
    const std::filesystem::path swap_path = parent_path / swap_name;

    REQUIRE(create_junction(swap_path, victim.path));
    JunctionCleanup cleanup{swap_path};

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, always_match, open_limits());

    const std::string expected_rel = rel_prefix.empty() ? swap_name : rel_prefix + "/" + swap_name;
    const auto it = std::find_if(result.entries.begin(), result.entries.end(),
                                  [&](const EntryOutcome& e) { return e.rel_path == expected_rel; });
    REQUIRE(it != result.entries.end());
    CHECK(it->status == EntryStatus::Skipped);
    CHECK(it->reason == Reason::ReparseRejected);
    CHECK(std::filesystem::exists(victim.path / "victim.txt"));
}

// Mid-walk swap: a chain of directory HANDLEs is opened via the exported
// primitives FIRST (simulating a walk that has already descended to the
// swapped entry's parent); only THEN is the real directory moved aside and
// a junction planted with the same name. The already-open parent handle is
// then used directly (enumerate_at / open_dir_at / unlink_at) -- proving
// the swap is caught even though the handle predates it.
void run_mid_walk_junction_swap(int depth) {
    INFO("mid-walk junction swap at depth " << depth);

    yuzu::test::TempDir victim{"yuzu_test_confined_win_victim_"};
    std::filesystem::create_directories(victim.path);
    write_file(victim.path / "victim.txt", "keep-me");

    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_root_"};
    std::filesystem::create_directories(root_dir.path);

    std::filesystem::path parent_path = root_dir.path;
    for (int i = 1; i < depth; ++i) {
        parent_path /= ("level" + std::to_string(i));
        std::filesystem::create_directories(parent_path);
    }
    const std::string swap_name = "level" + std::to_string(depth);
    const std::filesystem::path swap_path = parent_path / swap_name;
    std::filesystem::create_directories(swap_path);
    write_file(swap_path / "inner.txt", "real-content");

    OpenRootResult root_opened = open_root(root_dir.path);
    REQUIRE(root_opened.root.has_value());
    const FileIdentity root_id = root_opened.root->identity();

    // Chain of HELD handles all the way DOWN TO the directory that will be
    // swapped (levels 1..depth). C004: an earlier version stopped one level
    // short, so `current` was the swap target's PARENT and the test merely
    // re-observed the planted junction by name -- the pre-walk shape wearing a
    // mid-walk label. The property that actually needs proving is that a handle
    // opened BEFORE the swap stays bound to the inode it opened, not to the path.
    std::vector<OpenDirResult> chain;
    HANDLE parent_of_swap = root_opened.root->h_.get();
    HANDLE held_swap = INVALID_HANDLE_VALUE;
    for (int i = 1; i <= depth; ++i) {
        const std::string level = (i == depth) ? swap_name : ("level" + std::to_string(i));
        OpenDirResult next = open_dir_at(parent_of_swap, level, root_id);
        REQUIRE(next.reason == Reason::None);
        if (i == depth)
            held_swap = next.h.get();
        else
            parent_of_swap = next.h.get();
        chain.push_back(std::move(next));
    }
    REQUIRE(held_swap != INVALID_HANDLE_VALUE);

    // Now interpose: move the held directory aside and plant a junction to an
    // outside tree at the path it used to occupy.
    yuzu::test::TempDir aside{"yuzu_test_confined_win_aside_"};
    std::filesystem::create_directories(aside.path);
    const std::filesystem::path aside_path = aside.path / "moved";
    REQUIRE(MoveFileExW(swap_path.c_str(), aside_path.c_str(), MOVEFILE_WRITE_THROUGH));
    REQUIRE(create_junction(swap_path, victim.path));
    JunctionCleanup cleanup{swap_path};

    EnumBudget budget{100, std::chrono::steady_clock::now() + std::chrono::seconds(30)};

    // THE MID-WALK ASSERTION: enumerate and delete through the handle held since
    // before the swap. It must still see the MOVED directory's own contents --
    // not the junction's target -- and the unlink must remove the file that
    // travelled with the inode.
    EnumerateResult through_held = enumerate_at(held_swap, root_id, budget);
    REQUIRE(through_held.reason == Reason::None);
    const auto inner = std::find_if(through_held.entries.begin(), through_held.entries.end(),
                                    [](const DirEntry& e) { return e.name == "inner.txt"; });
    REQUIRE(inner != through_held.entries.end());

    UnlinkOutcome removed = unlink_at(held_swap, "inner.txt", UnlinkKind::File,
                                      std::numeric_limits<std::uint64_t>::max(), root_id);
    CHECK(removed.status == EntryStatus::Deleted);
    CHECK_FALSE(std::filesystem::exists(aside_path / "inner.txt")); // the moved inode's file
    CHECK(std::filesystem::exists(victim.path / "victim.txt"));     // outside tree untouched

    // The parent-side view is still worth asserting: from the parent, the newly
    // planted junction must be seen as a reparse point and refused, never traversed.
    EnumerateResult from_parent = enumerate_at(parent_of_swap, root_id, budget);
    REQUIRE(from_parent.reason == Reason::None);
    const auto found = std::find_if(from_parent.entries.begin(), from_parent.entries.end(),
                                     [&](const DirEntry& e) { return e.name == swap_name; });
    REQUIRE(found != from_parent.entries.end());
    CHECK(found->meta.type == EntryType::Reparse);

    OpenDirResult reopened = open_dir_at(parent_of_swap, swap_name, root_id);
    CHECK_FALSE(reopened.h.valid());
    CHECK(reopened.reason == Reason::ReparseRejected);

    UnlinkOutcome unlinked = unlink_at(parent_of_swap, swap_name, UnlinkKind::EmptyDirectory,
                                       std::numeric_limits<std::uint64_t>::max(), root_id);
    CHECK(unlinked.status == EntryStatus::Failed);
    CHECK(unlinked.reason == Reason::ReparseRejected);

    CHECK(std::filesystem::exists(victim.path / "victim.txt"));
}

} // namespace

TEST_CASE("open_root refuses a root path containing an embedded NUL", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_rootnul_"};
    const std::filesystem::path real_root = tmp.path / L"root";
    std::filesystem::create_directories(real_root);

    // c_str() truncates at the NUL, so an unchecked open_root would pin
    // <root> while the caller believes it named something else.
    std::wstring poisoned = real_root.wstring();
    poisoned.push_back(L'\0');
    poisoned += L"\\decoy";

    OpenRootResult r = open_root(std::filesystem::path{poisoned});
    CHECK_FALSE(r.root.has_value());
    CHECK(r.reason == Reason::RootInvalid);
}

TEST_CASE("delete_matching honours a non-default entry cap", "[confined_fs]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_entrycap_"};
    const std::filesystem::path root_dir = tmp.path / L"root";
    std::filesystem::create_directories(root_dir);
    for (const wchar_t* n : {L"a.tmp", L"b.tmp", L"c.tmp", L"d.tmp", L"e.tmp"})
        write_file(root_dir / n, "x");

    OpenRootResult opened = open_root(root_dir);
    REQUIRE(opened.root.has_value());

    DeleteLimits limits = open_limits();
    limits.max_entries = 3;
    DeleteResult result = delete_matching(*opened.root, [](std::string_view, const EntryMeta&) { return true; },
                                          limits);

    CHECK(result.stop_reason == Reason::EntryCap);
    CHECK(result.tally.entries_seen <= 3);
}

TEST_CASE("delete_matching happy path deletes matched files with exact sorted outcomes",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_happy_"};
    std::filesystem::create_directories(root_dir.path);
    std::filesystem::create_directories(root_dir.path / "sub");
    write_file(root_dir.path / "a.txt", "x");
    write_file(root_dir.path / "sub" / "b.txt", "yy");
    write_file(root_dir.path / "sub" / "c.log", "zzz");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    MatchFn match_txt = [](std::string_view p, const EntryMeta&) { return p.ends_with(".txt"); };
    DeleteResult result = delete_matching(*opened.root, match_txt, open_limits());

    REQUIRE(result.stop_reason == Reason::None);
    sort_by_rel_path(result.entries);
    // "sub" itself is RecurseIntoDir -- never appended as an outcome; c.log
    // is SkipEntry(NameFilteredOut) -- deliberately unrecorded (bounded-output
    // rule). Only the two matched, deleted files remain.
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].rel_path == "a.txt");
    CHECK(result.entries[0].status == EntryStatus::Deleted);
    CHECK(result.entries[1].rel_path == "sub/b.txt");
    CHECK(result.entries[1].status == EntryStatus::Deleted);
    CHECK_FALSE(std::filesystem::exists(root_dir.path / "a.txt"));
    CHECK_FALSE(std::filesystem::exists(root_dir.path / "sub" / "b.txt"));
    CHECK(std::filesystem::exists(root_dir.path / "sub" / "c.log"));
}

TEST_CASE("open_root refuses a reparse-point root", "[confined_fs]") {
    yuzu::test::TempDir target{"yuzu_test_confined_win_target_"};
    std::filesystem::create_directories(target.path);

    yuzu::test::TempDir parent{"yuzu_test_confined_win_parent_"};
    std::filesystem::create_directories(parent.path);
    const std::filesystem::path junction_path = parent.path / "junction_root";
    REQUIRE(create_junction(junction_path, target.path));
    JunctionCleanup cleanup{junction_path};

    OpenRootResult opened = open_root(junction_path);
    CHECK_FALSE(opened.root.has_value());
    CHECK(opened.reason == Reason::RootInvalid);
}

TEST_CASE("delete_matching skips a junction entry; outside victim stays intact",
          "[confined_fs]") {
    yuzu::test::TempDir victim_dir{"yuzu_test_confined_win_victim_"};
    std::filesystem::create_directories(victim_dir.path);
    write_file(victim_dir.path / "victim.txt", "keep-me");

    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_root_"};
    std::filesystem::create_directories(root_dir.path);
    const std::filesystem::path junction_path = root_dir.path / "link";
    REQUIRE(create_junction(junction_path, victim_dir.path));
    JunctionCleanup cleanup{junction_path};

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, always_match, open_limits());

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].rel_path == "link");
    CHECK(result.entries[0].status == EntryStatus::Skipped);
    CHECK(result.entries[0].reason == Reason::ReparseRejected);
    CHECK(std::filesystem::exists(victim_dir.path / "victim.txt"));
}

TEST_CASE("pre-walk junction swap at depths 1-3: outside victim survives", "[confined_fs]") {
    for (const int depth : {1, 2, 3})
        run_pre_walk_junction_swap(depth);
}

TEST_CASE("mid-walk junction swap on a HELD handle at depths 1-3: outside victim survives",
          "[confined_fs]") {
    for (const int depth : {1, 2, 3})
        run_mid_walk_junction_swap(depth);
}

TEST_CASE("delete_matching with default (zero) limits deletes nothing", "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_defaults_"};
    std::filesystem::create_directories(root_dir.path);
    write_file(root_dir.path / "a.txt", "x");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    DeleteResult result = delete_matching(*opened.root, always_match, DeleteLimits{});

    CHECK(result.stop_reason == Reason::EntryCap);
    CHECK(result.entries.empty());
    CHECK(std::filesystem::exists(root_dir.path / "a.txt"));
}

TEST_CASE("delete_matching with max_wall=0 stops immediately", "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_wall0_"};
    std::filesystem::create_directories(root_dir.path);
    write_file(root_dir.path / "a.txt", "x");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    DeleteLimits limits{100, 1'000'000, std::chrono::milliseconds{0}, 8, /*max_open_dirs=*/64};
    DeleteResult result = delete_matching(*opened.root, always_match, limits);

    CHECK(result.stop_reason == Reason::WallTimeCap);
    CHECK(std::filesystem::exists(root_dir.path / "a.txt"));
}

TEST_CASE("open_dir_at and unlink_at refuse structurally invalid names before any syscall",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_invalid_"};
    std::filesystem::create_directories(root_dir.path);

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());
    const HANDLE root_handle = opened.root->h_.get();
    const FileIdentity& root_id = opened.root->identity();

    SECTION("..") {
        OpenDirResult r = open_dir_at(root_handle, "..", root_id);
        CHECK(r.reason == Reason::InvalidName);
    }
    SECTION("embedded backslash") {
        OpenDirResult r = open_dir_at(root_handle, "a\\b", root_id);
        CHECK(r.reason == Reason::InvalidName);
    }
    SECTION("embedded NUL") {
        const std::string name("a\0b", 3);
        UnlinkOutcome r = unlink_at(root_handle, name, UnlinkKind::File, std::numeric_limits<std::uint64_t>::max(), root_id);
        CHECK(r.reason == Reason::InvalidName);
    }
    SECTION("oversize name (> USHORT bytes once widened)") {
        const std::string name(70000, 'a');
        UnlinkOutcome r = unlink_at(root_handle, name, UnlinkKind::File, std::numeric_limits<std::uint64_t>::max(), root_id);
        CHECK(r.reason == Reason::InvalidName);
    }
}

TEST_CASE("delete_matching can run twice against the same ConfinedRoot (root reuse)",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_reuse_"};
    std::filesystem::create_directories(root_dir.path);
    write_file(root_dir.path / "a.txt", "x");
    write_file(root_dir.path / "b.txt", "y");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    MatchFn match_a = [](std::string_view p, const EntryMeta&) { return p == "a.txt"; };
    DeleteResult first = delete_matching(*opened.root, match_a, open_limits());
    CHECK(first.stop_reason == Reason::None);
    REQUIRE(first.entries.size() == 1);
    CHECK(first.entries[0].status == EntryStatus::Deleted);
    CHECK_FALSE(std::filesystem::exists(root_dir.path / "a.txt"));

    MatchFn match_b = [](std::string_view p, const EntryMeta&) { return p == "b.txt"; };
    DeleteResult second = delete_matching(*opened.root, match_b, open_limits());
    CHECK(second.stop_reason == Reason::None);
    REQUIRE(second.entries.size() == 1);
    CHECK(second.entries[0].status == EntryStatus::Deleted);
    CHECK_FALSE(std::filesystem::exists(root_dir.path / "b.txt"));
}

TEST_CASE("open_dir_at and unlink_at refuse a spoofed root_id (DeviceBoundary)",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_devbound_"};
    std::filesystem::create_directories(root_dir.path);
    std::filesystem::create_directories(root_dir.path / "sub");
    write_file(root_dir.path / "a.txt", "x");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());
    const HANDLE root_handle = opened.root->h_.get();
    // Same volume, deliberately wrong serial: open_dir_at/unlink_at must
    // refuse on the root_id comparison alone, with no second physical
    // volume needed to exercise it.
    const FileIdentity wrong_id{opened.root->identity().volume_serial + 1,
                                 opened.root->identity().file_index};

    OpenDirResult dir_r = open_dir_at(root_handle, "sub", wrong_id);
    CHECK_FALSE(dir_r.h.valid());
    CHECK(dir_r.reason == Reason::DeviceBoundary);

    UnlinkOutcome unlink_r = unlink_at(root_handle, "a.txt", UnlinkKind::File, std::numeric_limits<std::uint64_t>::max(), wrong_id);
    CHECK(unlink_r.status == EntryStatus::Failed);
    CHECK(unlink_r.reason == Reason::DeviceBoundary);
    CHECK(std::filesystem::exists(root_dir.path / "a.txt"));
}

TEST_CASE("unlink_at charges the byte cap against the LIVE size on real NTFS",
          "[confined_fs]") {
    // The Windows half of the byte-cap-fails-open defense (the live re-measure
    // plus the deliberate omission of FILE_SHARE_WRITE on the delete handle)
    // was previously exercised only through the fake-Ops walk tests, never on
    // a real NTFS volume -- while the POSIX leg had three direct cases. That
    // left an 8-line defense, in a class that has already regressed once,
    // with no tripwire on its own leg: a refactor adding FILE_SHARE_WRITE or
    // dropping the re-measure would keep every existing test green.
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_bytecap_"};
    std::filesystem::create_directories(root_dir.path);
    write_file(root_dir.path / "big.txt", std::string(5000, 'x'));

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());
    const HANDLE root_handle = opened.root->h_.get();
    const FileIdentity root_id = opened.root->identity();

    // Budget deliberately below the file's real on-disk size: the leg must
    // measure the object it holds open and refuse, not delete it uncharged.
    UnlinkOutcome refused = unlink_at(root_handle, "big.txt", UnlinkKind::File,
                                      /*max_bytes_remaining=*/100, root_id);
    CHECK(refused.status == EntryStatus::Skipped);
    CHECK(refused.reason == Reason::ByteCap);
    CHECK(refused.bytes == 0);
    CHECK(std::filesystem::exists(root_dir.path / "big.txt"));

    // Same file, a budget that accommodates it: deleted, and charged what was
    // really removed rather than any enumerated or assumed size.
    UnlinkOutcome removed = unlink_at(root_handle, "big.txt", UnlinkKind::File,
                                      /*max_bytes_remaining=*/10000, root_id);
    CHECK(removed.status == EntryStatus::Deleted);
    CHECK(removed.bytes == 5000);
    CHECK_FALSE(std::filesystem::exists(root_dir.path / "big.txt"));
}

TEST_CASE("enumerate_at flags a lone-surrogate on-disk name as name_invalid, "
          "and delete_matching skips it without deleting",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_surrogate_"};
    std::filesystem::create_directories(root_dir.path);

    // A lone high surrogate cannot round-trip through UTF-8 (win_str.hpp
    // substitutes U+FFFD on the way back out); NTFS itself does not validate
    // UTF-16 well-formedness, so a file with this on-disk name is
    // constructible without admin. Composed as a std::filesystem::path (its
    // native representation on Windows IS std::wstring) so the raw code unit
    // survives untouched -- no UTF-8 round-trip happens on the way in.
    const std::wstring bad_component = L"x" + std::wstring(1, static_cast<wchar_t>(0xD800));
    write_file(root_dir.path / std::filesystem::path(bad_component), "x");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    EnumBudget budget{100, std::chrono::steady_clock::now() + std::chrono::seconds(30)};
    EnumerateResult enumerated =
        enumerate_at(opened.root->h_.get(), opened.root->identity(), budget);
    REQUIRE(enumerated.reason == Reason::None);
    REQUIRE(enumerated.entries.size() == 1);
    CHECK(enumerated.entries[0].name_invalid);

    DeleteResult deleted = delete_matching(*opened.root, always_match, open_limits());
    REQUIRE(deleted.entries.size() == 1);
    CHECK(deleted.entries[0].status == EntryStatus::Skipped);
    CHECK(deleted.entries[0].reason == Reason::InvalidName);
}

TEST_CASE("Unsupported fail-closed path via the ntdll injection seam deletes nothing",
          "[confined_fs]") {
    yuzu::test::TempDir root_dir{"yuzu_test_confined_win_unsupported_"};
    std::filesystem::create_directories(root_dir.path);
    write_file(root_dir.path / "a.txt", "x");

    OpenRootResult opened = open_root(root_dir.path);
    REQUIRE(opened.root.has_value());

    detail::set_ntcreatefile_for_test(nullptr, /*enable=*/true);
    struct Restore {
        ~Restore() { detail::set_ntcreatefile_for_test(nullptr, /*enable=*/false); }
    } restore_guard;

    // open_root already ran (CreateFileW, not NtCreateFile-gated); everything
    // past it goes through nt_open_relative, which now resolves to a null
    // function pointer -- unlink_at must refuse, never delete.
    DeleteResult result = delete_matching(*opened.root, always_match, open_limits());

    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].status == EntryStatus::Failed);
    CHECK(result.entries[0].reason == Reason::Unsupported);
    CHECK(std::filesystem::exists(root_dir.path / "a.txt"));
}


// ── Windows end-to-end: the real enumerator's LastWriteTime ─────────────────
//
// Gate 1 (Codex FV-3, Kimi F3): the pure FILETIME conversion is exhaustively
// tested, but nothing observed the value the ACTUAL enumerator supplies.
// Reverting the assignment in confined_fs_win.cpp to drop the timestamp left
// every Windows assertion green — and that TU does not compile on the macOS
// dev host at all, so this case is also the only thing that will exercise the
// wiring before it reaches production.
//
// This runs on the CI Windows leg. It sets an exact whole-second FILETIME with
// SetFileTime, reads it back through the held root handle, and then lets an age
// policy decide what is unlinked.
TEST_CASE("Windows enumeration supplies LastWriteTime and age can select on it",
          "[confined_fs][mtime]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_mtime_"};
    std::filesystem::create_directories(tmp.path);
    write_file(tmp.path / "old.tmp", "old");
    write_file(tmp.path / "new.tmp", "new");

    // Whole-second Unix instants, converted to FILETIME ticks with the inverse
    // of the arithmetic under test — written out longhand here deliberately, so
    // this case cannot pass by sharing a bug with filetime_to_unix_seconds.
    constexpr std::int64_t kTicksPerSecond = 10'000'000;
    constexpr std::int64_t kEpochDeltaSeconds = 11'644'473'600;
    constexpr std::int64_t kOldSeconds = 946'684'800;   // 2000-01-01T00:00:00Z
    constexpr std::int64_t kNewSeconds = 1'893'456'000; // 2030-01-01T00:00:00Z
    auto set_mtime = [](const std::filesystem::path& p, std::int64_t unix_seconds) {
        const std::int64_t ticks = (unix_seconds + kEpochDeltaSeconds) * kTicksPerSecond;
        FILETIME ft;
        ft.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFULL);
        ft.dwHighDateTime = static_cast<DWORD>(static_cast<std::uint64_t>(ticks) >> 32);
        // Adopted immediately into the file's own RAII owner rather than
        // closed by hand: a REQUIRE between acquisition and CloseHandle would
        // unwind past the manual close and leak the HANDLE.
        WinHandle owned{::CreateFileW(p.wstring().c_str(), FILE_WRITE_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                      FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
        REQUIRE(owned.get() != INVALID_HANDLE_VALUE);
        REQUIRE(::SetFileTime(owned.get(), nullptr, nullptr, &ft));
    };
    set_mtime(tmp.path / "old.tmp", kOldSeconds);
    set_mtime(tmp.path / "new.tmp", kNewSeconds);

    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());

    // 1. The enumerator reports the real values.
    const EnumBudget budget{1000, std::chrono::steady_clock::now() + std::chrono::seconds{60}};
    EnumerateResult enumerated =
        enumerate_at(opened.root->h_.get(), opened.root->identity(), budget);
    REQUIRE(enumerated.reason == Reason::None);
    std::map<std::string, std::optional<std::int64_t>> by_name;
    for (const auto& e : enumerated.entries) by_name[e.name] = e.meta.mtime;
    CHECK(by_name["old.tmp"] == std::optional<std::int64_t>{kOldSeconds});
    CHECK(by_name["new.tmp"] == std::optional<std::int64_t>{kNewSeconds});

    // 2. And an age policy over them selects correctly end-to-end.
    constexpr std::int64_t kCutoff = 1'500'000'000;
    MatchFn older_than_cutoff = [](std::string_view, const EntryMeta& meta) {
        if (!meta.mtime) return false;
        return *meta.mtime < kCutoff;
    };
    DeleteResult result = delete_matching(*opened.root, older_than_cutoff, open_limits());
    REQUIRE(result.stop_reason == Reason::None);
    CHECK_FALSE(std::filesystem::exists(tmp.path / "old.tmp"));
    CHECK(std::filesystem::exists(tmp.path / "new.tmp"));
}

// ── Windows: the listing fields, the file-id class, the cloud policy and the attribute-only open ──────────
//
// The cloud admission itself is covered by the pure rule's cases (test_confined_fs_rules.cpp) and by the
// live run on the real host: a real cloud directory is not built here, because registering a sync root is
// machine-wide state.

namespace {

std::uint64_t read_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i)
        v = (v << 8) | p[i];
    return v;
}

/// The two halves of the opened handle's 128-bit FileIdInfo; nullopt where the filesystem does not answer.
struct IdHalves {
    std::uint64_t low;
    std::uint64_t high;
};
std::optional<IdHalves> file_id_info(HANDLE h) {
    FILE_ID_INFO info{};
    if (!GetFileInformationByHandleEx(h, FileIdInfo, &info, sizeof(info)))
        return std::nullopt;
    return IdHalves{read_u64(info.FileId.Identifier), read_u64(info.FileId.Identifier + 8)};
}

bool is_ntfs(HANDLE h) {
    wchar_t name[MAX_PATH + 1] = {};
    return GetVolumeInformationByHandleW(h, nullptr, 0, nullptr, nullptr, nullptr, name, MAX_PATH) &&
           std::wstring_view(name) == L"NTFS";
}

const EnumBudget kBudget{1000, std::chrono::steady_clock::time_point::max()};

std::map<std::string, DirEntry> by_name(const EnumerateResult& r) {
    std::map<std::string, DirEntry> out;
    for (const auto& e : r.entries)
        out.emplace(e.name, e);
    return out;
}

// NtCreateFile spy: forwards to the real function and records the access mask and create options of every
// open, so a test can state what an open asks for.
using NtCreateFileSig = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                         PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NtCreateFileSig g_real_nt_create_file = nullptr;
struct SeenOpen {
    ACCESS_MASK access;
    ULONG options;
};
std::vector<SeenOpen> g_seen_opens;

NTSTATUS NTAPI spy_nt_create_file(PHANDLE h, ACCESS_MASK access, POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK io,
                                  PLARGE_INTEGER alloc, ULONG attrs, ULONG share, ULONG disposition,
                                  ULONG options, PVOID ea, ULONG ea_length) {
    g_seen_opens.push_back({access, options});
    return g_real_nt_create_file(h, access, oa, io, alloc, attrs, share, disposition, options, ea, ea_length);
}

struct NtCreateFileSpy {
    NtCreateFileSpy() {
        g_real_nt_create_file = reinterpret_cast<NtCreateFileSig>(
            reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile")));
        g_seen_opens.clear();
        detail::set_ntcreatefile_for_test(reinterpret_cast<void*>(&spy_nt_create_file), /*enable=*/true);
    }
    ~NtCreateFileSpy() { detail::set_ntcreatefile_for_test(nullptr, /*enable=*/false); }
    NtCreateFileSpy(const NtCreateFileSpy&) = delete;
    NtCreateFileSpy& operator=(const NtCreateFileSpy&) = delete;
};

constexpr ULONG kNoRecallOption = 0x00400000UL;  // FILE_OPEN_NO_RECALL
constexpr ULONG kDirectoryFileOption = 0x00000001UL;
constexpr ULONG kNonDirectoryFileOption = 0x00000040UL;
constexpr ULONG kOpenReparsePointOption = 0x00200000UL;

} // namespace

TEST_CASE("the default listing carries attributes and the reparse tag, a junction lists with its tag, and no id",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_listing_"};
    std::filesystem::create_directories(tmp.path / "sub");
    std::filesystem::create_directories(tmp.path / "target");
    write_file(tmp.path / "a.txt", "hello");
    REQUIRE(create_junction(tmp.path / "junc", tmp.path / "target"));
    JunctionCleanup cleanup{tmp.path / "junc"};

    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    const EnumerateResult listing = enumerate_at(opened.root->h_.get(), opened.root->identity(), kBudget);
    REQUIRE(listing.reason == Reason::None);
    const auto entries = by_name(listing);
    REQUIRE(entries.size() == 4);
    for (const auto& [name, e] : entries)
        CHECK(e.meta.file_id == 0); // the default class never reads an id
    CHECK((entries.at("sub").meta.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    CHECK(entries.at("sub").meta.reparse_tag == 0);
    CHECK((entries.at("a.txt").meta.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
    CHECK(entries.at("a.txt").meta.reparse_tag == 0);
    CHECK(entries.at("a.txt").meta.size_bytes == 5);
    CHECK(entries.at("junc").meta.type == EntryType::Reparse);
    CHECK((entries.at("junc").meta.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
    CHECK(entries.at("junc").meta.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT);
}

TEST_CASE("want_file_ids lists non-zero ids equal to the low half of each handle's FileIdInfo, entries otherwise identical",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_ids_"};
    std::filesystem::create_directories(tmp.path / "sub");
    std::filesystem::create_directories(tmp.path / "target");
    write_file(tmp.path / "a.txt", "hello");
    write_file(tmp.path / "b.txt", "");
    REQUIRE(create_junction(tmp.path / "junc", tmp.path / "target"));
    JunctionCleanup cleanup{tmp.path / "junc"};

    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    if (!is_ntfs(opened.root->h_.get())) {
        SKIP("skipped: the temp directory is not on NTFS");
    }
    const HANDLE root_handle = opened.root->h_.get();
    const FileIdentity& root_id = opened.root->identity();

    const auto plain = by_name(enumerate_at(root_handle, root_id, kBudget));
    EnumBudget with_ids = kBudget;
    with_ids.want_file_ids = true;
    const EnumerateResult listing = enumerate_at(root_handle, root_id, with_ids);
    REQUIRE(listing.reason == Reason::None);
    const auto entries = by_name(listing);
    REQUIRE(entries.size() == plain.size());
    for (const auto& [name, e] : entries) {
        INFO(name);
        CHECK(e.meta.file_id != 0);
        // the same record layout facts as the default class
        const auto& p = plain.at(name).meta;
        CHECK(e.meta.type == p.type);
        CHECK(e.meta.size_bytes == p.size_bytes);
        CHECK(e.meta.mtime == p.mtime);
        CHECK(e.meta.attributes == p.attributes);
        CHECK(e.meta.reparse_tag == p.reparse_tag);
    }
    CHECK(entries.at("junc").meta.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT);

    // the id the listing gives equals the low half of the opened handle's FileIdInfo, whose upper half is zero
    for (const char* file : {"a.txt", "b.txt"}) {
        OpenFileResult f = open_file_attributes_at(root_handle, file, root_id);
        REQUIRE(f.h.valid());
        const auto ids = file_id_info(f.h.get());
        REQUIRE(ids.has_value());
        CHECK(ids->high == 0);
        CHECK(entries.at(file).meta.file_id == ids->low);
    }
    OpenDirResult d = open_dir_at(root_handle, "sub", root_id);
    REQUIRE(d.h.valid());
    const auto dir_ids = file_id_info(d.h.get());
    REQUIRE(dir_ids.has_value());
    CHECK(dir_ids->high == 0);
    CHECK(entries.at("sub").meta.file_id == dir_ids->low);
}

TEST_CASE("open_dir_at returns the attributes of an ordinary directory and no reparse tag",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_dirattrs_"};
    std::filesystem::create_directories(tmp.path / "sub");
    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    for (const ReparseDirs policy : {ReparseDirs::refuse, ReparseDirs::allow_populated_cloud}) {
        OpenDirResult r = open_dir_at(opened.root->h_.get(), "sub", opened.root->identity(), policy);
        REQUIRE(r.h.valid());
        CHECK(r.reason == Reason::None);
        CHECK((r.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        CHECK((r.attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
        CHECK(r.reparse_tag == 0);
    }
}

TEST_CASE("open_file_attributes_at reads size, time and attributes, refuses a directory, a missing and an invalid name, and cannot read",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_fileattrs_"};
    std::filesystem::create_directories(tmp.path / "sub");
    write_file(tmp.path / "a.txt", "hello");
    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    const HANDLE root_handle = opened.root->h_.get();
    const FileIdentity& root_id = opened.root->identity();

    OpenFileResult f = open_file_attributes_at(root_handle, "a.txt", root_id);
    REQUIRE(f.h.valid());
    CHECK(f.reason == Reason::None);
    CHECK(f.size == 5);
    CHECK(f.mtime.has_value());
    CHECK((f.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
    CHECK(f.reparse_tag == 0);
    // the handle has no data right: a read through it is refused
    char byte = 0;
    DWORD got = 0;
    const BOOL read_ok = ReadFile(f.h.get(), &byte, 1, &got, nullptr);
    const DWORD read_error = GetLastError(); // straight after the call: CHECK_FALSE may itself touch the last error
    CHECK_FALSE(read_ok);
    CHECK(read_error == ERROR_ACCESS_DENIED);

    CHECK_FALSE(open_file_attributes_at(root_handle, "sub", root_id).h.valid()); // the kernel refuses a directory
    const OpenFileResult missing = open_file_attributes_at(root_handle, "nope.txt", root_id);
    CHECK_FALSE(missing.h.valid());
    CHECK(missing.reason == Reason::OsError);
    CHECK(open_file_attributes_at(root_handle, "..", root_id).reason == Reason::InvalidName);
    CHECK(open_file_attributes_at(root_handle, "a\\b", root_id).reason == Reason::InvalidName);
    const FileIdentity wrong_id{root_id.volume_serial + 1, root_id.file_index};
    CHECK(open_file_attributes_at(root_handle, "a.txt", wrong_id).reason == Reason::DeviceBoundary);
}

TEST_CASE("no open sends FILE_OPEN_NO_RECALL, and the directory open is the same under both reparse policies",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_options_"};
    std::filesystem::create_directories(tmp.path / "sub");
    write_file(tmp.path / "a.txt", "x");
    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    const HANDLE root_handle = opened.root->h_.get();
    const FileIdentity& root_id = opened.root->identity();

    const NtCreateFileSpy spy;
    OpenDirResult refuse = open_dir_at(root_handle, "sub", root_id, ReparseDirs::refuse);
    OpenDirResult allow = open_dir_at(root_handle, "sub", root_id, ReparseDirs::allow_populated_cloud);
    OpenFileResult file = open_file_attributes_at(root_handle, "a.txt", root_id);
    REQUIRE(refuse.h.valid());
    REQUIRE(allow.h.valid());
    REQUIRE(file.h.valid());
    REQUIRE(g_seen_opens.size() == 3);
    for (const auto& seen : g_seen_opens)
        CHECK((seen.options & kNoRecallOption) == 0);
    CHECK(g_seen_opens[0].options == g_seen_opens[1].options); // identical under both policies
    CHECK(g_seen_opens[0].access == g_seen_opens[1].access);
    CHECK((g_seen_opens[0].options & kDirectoryFileOption) != 0);
    // the file open: attribute rights only, a non-directory, opened as itself
    CHECK(g_seen_opens[2].access == (FILE_READ_ATTRIBUTES | SYNCHRONIZE));
    CHECK((g_seen_opens[2].options & kNonDirectoryFileOption) != 0);
    CHECK((g_seen_opens[2].options & kOpenReparsePointOption) != 0);
    CHECK((g_seen_opens[2].options & kDirectoryFileOption) == 0);
}

TEST_CASE("the allow_populated_cloud policy still refuses a junction and a directory symlink, with their attributes and tag",
          "[confined_fs][cloud]") {
    yuzu::test::TempDir tmp{"yuzu_test_confined_win_links_"};
    std::filesystem::create_directories(tmp.path / "target");
    REQUIRE(create_junction(tmp.path / "junc", tmp.path / "target"));
    JunctionCleanup cleanup{tmp.path / "junc"};
    // a directory symlink needs the unprivileged-create flag (Developer Mode) or a privilege: skipped without
    const bool have_symlink = CreateSymbolicLinkW((tmp.path / "sym").c_str(), (tmp.path / "target").c_str(),
                                                  SYMBOLIC_LINK_FLAG_DIRECTORY |
                                                      SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;
    JunctionCleanup sym_cleanup{tmp.path / "sym"};
    if (!have_symlink)
        WARN("directory symlink case skipped: the account cannot create a symbolic link");

    OpenRootResult opened = open_root(tmp.path);
    REQUIRE(opened.root.has_value());
    for (const ReparseDirs policy : {ReparseDirs::refuse, ReparseDirs::allow_populated_cloud}) {
        OpenDirResult j = open_dir_at(opened.root->h_.get(), "junc", opened.root->identity(), policy);
        CHECK_FALSE(j.h.valid());
        CHECK(j.reason == Reason::ReparseRejected);
        CHECK((j.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
        CHECK(j.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT);
        if (have_symlink) {
            OpenDirResult l = open_dir_at(opened.root->h_.get(), "sym", opened.root->identity(), policy);
            CHECK_FALSE(l.h.valid());
            CHECK(l.reason == Reason::ReparseRejected);
            CHECK(l.reparse_tag == IO_REPARSE_TAG_SYMLINK);
        }
    }
}

#endif // _WIN32
