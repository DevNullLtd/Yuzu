// Pure unit tests for confined_fs_walk.hpp's walk_delete, driven by a FAKE
// in-memory Ops. No filesystem, no OS headers -- this file includes only
// confined_fs_rules.hpp + confined_fs_walk.hpp.

#include <yuzu/agent/confined_fs_rules.hpp>
#include <yuzu/agent/confined_fs_walk.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::agent::confined_fs;

namespace {

// A fake in-memory directory tree. Directories are keyed by an opaque int
// id; each holds a list of DirEntry plus (for subdirectories) the child id
// to open. No real fd/HANDLE ever exists.
struct FakeDir {
    std::vector<DirEntry> entries;
    std::map<std::string, int> subdirs;      // name -> child dir id
    std::map<std::string, Reason> refusals;  // name -> open_dir policy refusal
    std::map<std::string, int> os_errors_open; // name -> os_error for OsError refusal
    bool enumerate_os_error = false;
    bool enumerate_internal_error = false;
    bool open_dir_throws = false;
    int enumerate_os_error_code = 0;
};

class FakeOps {
public:
    using DirHandle = int; // just the dir id; move-only isn't needed for an int

    explicit FakeOps(std::chrono::steady_clock::time_point start_time) : now_(start_time) {}

    int add_dir() {
        int id = next_id_++;
        dirs_[id] = FakeDir{};
        return id;
    }

    FakeDir& dir(int id) { return dirs_[id]; }

    void advance(std::chrono::milliseconds by) { now_ += by; }

    std::chrono::steady_clock::time_point now() { return now_; }

    OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name) {
        FakeDir& p = dirs_.at(parent);
        if (p.open_dir_throws)
            throw std::runtime_error("fake open_dir failure");
        if (auto it = p.refusals.find(name); it != p.refusals.end())
            return OpenDirRes<DirHandle>{std::nullopt, it->second, 0};
        if (auto it = p.os_errors_open.find(name); it != p.os_errors_open.end())
            return OpenDirRes<DirHandle>{std::nullopt, Reason::OsError, it->second};
        int child = p.subdirs.at(name);
        return OpenDirRes<DirHandle>{child, Reason::None, 0};
    }

    EnumerateResult enumerate(DirHandle& d, const EnumBudget& budget) {
        FakeDir& fd = dirs_.at(d);
        last_budget_ = budget;
        ++enumerate_calls_;
        if (fd.enumerate_os_error)
            return EnumerateResult{{}, Reason::OsError, fd.enumerate_os_error_code};
        if (fd.enumerate_internal_error)
            return EnumerateResult{{}, Reason::Internal, 0};
        if (now() >= budget.deadline)
            return EnumerateResult{{}, Reason::WallTimeCap, 0};
        std::vector<DirEntry> out;
        for (auto& e : fd.entries) {
            if (out.size() >= budget.max_entries)
                return EnumerateResult{out, Reason::EntryCap, 0};
            out.push_back(e);
        }
        Reason r = out.size() < fd.entries.size() ? Reason::EntryCap : Reason::None;
        return EnumerateResult{out, r, 0};
    }

    UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind kind,
                         std::uint64_t max_bytes_remaining) {
        (void)kind;
        ++unlink_calls_;
        unlinked_names_.push_back(name);
        if (auto it = fail_unlink_.find(std::pair{parent, name}); it != fail_unlink_.end())
            return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, it->second, 0};
        // Models a leg re-measuring the entry immediately before deleting it.
        // By default nothing changed since enumeration, so the live size IS the
        // enumerated size; `live_size_` overrides it to model an entry swapped
        // out from under us between enumeration and delete.
        std::uint64_t live = 0;
        for (const auto& e : dirs_.at(parent).entries)
            if (e.name == name)
                live = e.meta.size_bytes;
        if (auto it = live_size_.find(name); it != live_size_.end())
            live = it->second;
        if (live > max_bytes_remaining)
            return UnlinkOutcome{EntryStatus::Skipped, Reason::ByteCap, 0, 0};
        return UnlinkOutcome{EntryStatus::Deleted, Reason::None, 0, live};
    }

    void fail_unlink_with(DirHandle parent, const std::string& name, int errnum) {
        fail_unlink_[{parent, name}] = errnum;
    }

    std::chrono::steady_clock::time_point now_;
    std::map<int, FakeDir> dirs_;
    int next_id_ = 0;
    int unlink_calls_ = 0;
    int enumerate_calls_ = 0;
    std::vector<std::string> unlinked_names_;
    std::map<std::pair<int, std::string>, int> fail_unlink_;
    std::map<std::string, std::uint64_t> live_size_;
    EnumBudget last_budget_{};
};

DirEntry file_entry(std::string name, std::uint64_t size = 10) {
    return DirEntry{std::move(name), EntryMeta{EntryType::RegularFile, size, true}, 0, false};
}

DirEntry dir_entry(std::string name) {
    return DirEntry{std::move(name), EntryMeta{EntryType::Directory, 0, true}, 0, false};
}

constexpr DeleteLimits kOpenLimits{
    /*max_entries=*/1000,
    /*max_bytes=*/1'000'000,
    /*max_wall=*/std::chrono::milliseconds{60'000},
    /*max_depth=*/32,
    /*max_open_dirs=*/64,
};

MatchFn always_match = [](std::string_view, const EntryMeta&) { return true; };
MatchFn never_match = [](std::string_view, const EntryMeta&) { return false; };

} // namespace

TEST_CASE("walk_delete happy path deletes every matched regular file", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::None);
    REQUIRE(result.entries.size() == 2);
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
    REQUIRE(result.entries[1].status == EntryStatus::Deleted);
    REQUIRE(result.tally.entries_seen == 2);
    REQUIRE(result.tally.bytes_deleted == 20);
    REQUIRE(ops.unlink_calls_ == 2);
}

TEST_CASE("walk_delete lazy match: MatchFn never called for structurally-rejected entries",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(root).subdirs["subdir"] = child;
    ops.dir(root).entries = {
        DirEntry{"link", EntryMeta{EntryType::Symlink, 0, true}, 0, false},
        DirEntry{"junction", EntryMeta{EntryType::Reparse, 0, true}, 0, false},
        DirEntry{"other-device", EntryMeta{EntryType::RegularFile, 1, false}, 0, false},
        dir_entry("subdir"),
        DirEntry{"weird", EntryMeta{EntryType::Other, 0, true}, 0, false},
        DirEntry{"bad-stat", EntryMeta{}, 5, false},
        DirEntry{"bad-name", EntryMeta{EntryType::RegularFile, 1, true}, 0, true},
    };

    int match_calls = 0;
    MatchFn counting = [&](std::string_view, const EntryMeta&) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, kOpenLimits);

    // NOT None: the fixture includes a stat_error entry, which is a Failed
    // outcome -- the walker could not examine it, so it was not visited and not
    // deliberately skipped. Under the stop_reason contract that is incompleteness
    // and the caller must be told. A Skipped(InvalidName)/Symlink/Reparse entry
    // would NOT set it: those are deliberate policy refusals, i.e. completed visits.
    REQUIRE(result.stop_reason == Reason::OsError);
    REQUIRE(match_calls == 0);
    // NameFilteredOut aside, every entry above is structurally decided
    // without ever needing the match result.
    REQUIRE(result.tally.entries_seen == 7);
}

TEST_CASE("walk_delete lazy match: MatchFn IS called for an otherwise-deletable file",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    int match_calls = 0;
    MatchFn counting = [&](std::string_view, const EntryMeta&) {
        ++match_calls;
        return true;
    };

    walk_delete<FakeOps>(root, ops, counting, kOpenLimits);
    REQUIRE(match_calls == 1);
}

TEST_CASE("walk_delete lazy match: MatchFn not called past the entry cap", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 0;

    int match_calls = 0;
    MatchFn counting = [&](std::string_view, const EntryMeta&) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, limits);
    REQUIRE(match_calls == 0);
    REQUIRE(result.stop_reason == Reason::EntryCap);
}

// The outer exception firewall (walk.hpp) must catch a throw from ANY Ops
// member, not just the MatchFn throw the inner catch handles. Found independently
// by both external reviewers: every prior test reached Internal by RETURNING it
// from enumerate, so the catch(...) itself was never exercised.
TEST_CASE("walk_delete: a throwing Ops member is contained as Internal", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(root).subdirs["sub"] = child;
    ops.dir(root).entries = {dir_entry("sub")};
    ops.dir(root).open_dir_throws = true;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);
    REQUIRE(result.stop_reason == Reason::Internal);
    REQUIRE(ops.unlink_calls_ == 0);
}

// The saturating deadline (walk.hpp) is always executed but was never asserted
// against a value that actually takes the clamp branch, so a regression to raw
// `now() + max_wall` -- signed overflow, potentially a deadline in the PAST --
// would not fail any test. Found independently by both external reviewers.
TEST_CASE("walk_delete: an extreme max_wall saturates instead of overflowing",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt", 10)};

    DeleteLimits limits = kOpenLimits;
    limits.max_wall = std::chrono::milliseconds::max();

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    // A wrapped deadline would land in the past and stop the walk immediately.
    REQUIRE(result.stop_reason == Reason::None);
    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
    REQUIRE(ops.last_budget_.deadline > ops.now());
}

// The enumeration budget must be max_entries MINUS what has already been seen.
// The existing passthrough test only asserted the first directory, where
// entries_seen is still 0, so the subtraction itself was unproven.
TEST_CASE("walk_delete: the enumerate budget subtracts entries already seen",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(root).subdirs["sub"] = child;
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt"), dir_entry("sub")};
    ops.dir(child).entries = {file_entry("c.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 10;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(result.stop_reason == Reason::None);
    // Root consumed 3 entries before the child was enumerated, so the child's
    // budget must be 10 - 3 = 7, not the raw 10.
    REQUIRE(ops.last_budget_.max_entries == 7);
}

// Gate 8 (security-guardian): OpenDirCap shipped as a new fail-closed
// enforcement branch with no test at all. The bound is on concurrently-open
// directory handles, which is +2 above the stack depth (the popped frame still
// owns its handle and the freshly-opened child is live), so this asserts the
// documented meaning rather than the implementation's arithmetic.
TEST_CASE("walk_delete stops when it would exceed the open-directory cap",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    std::vector<DirEntry> kids;
    for (int i = 0; i < 6; ++i) {
        int child = ops.add_dir();
        const std::string nm = "sub" + std::to_string(i);
        ops.dir(root).subdirs[nm] = child;
        kids.push_back(dir_entry(nm));
    }
    ops.dir(root).entries = kids;

    DeleteLimits limits = kOpenLimits;
    limits.max_open_dirs = 3; // permits one descent, then stops

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(result.stop_reason == Reason::OpenDirCap);
    REQUIRE(ops.unlink_calls_ == 0); // a cap stop deletes nothing it had not already
}

// Zero permits nothing, exactly as every other cap in DeleteLimits does.
TEST_CASE("walk_delete with max_open_dirs zero descends into nothing", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(root).subdirs["sub"] = child;
    ops.dir(root).entries = {dir_entry("sub")};

    DeleteLimits limits = kOpenLimits;
    limits.max_open_dirs = 0;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(result.stop_reason == Reason::OpenDirCap);
}

// B001 regression: the byte cap must be charged what the leg MEASURED at delete
// time, not the size seen during enumeration. An attacker who controls the tree
// can swap a small enumerated file for a large one; charging the stale size would
// let the delete blow through the blast-radius cap it exists to enforce.
TEST_CASE("walk_delete charges the byte cap the size measured at delete time",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    // Enumeration reports 10 bytes each; "swapped.txt" is really 5000 on disk.
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("swapped.txt")};
    ops.live_size_["swapped.txt"] = 5000;

    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);

    // The swap is refused by the leg's re-measure, not silently deleted.
    REQUIRE(result.tally.bytes_deleted == 10);
    bool swapped_refused = false;
    for (const auto& e : result.entries)
        if (e.rel_path == "swapped.txt") {
            CHECK(e.status == EntryStatus::Skipped);
            CHECK(e.reason == Reason::ByteCap);
            swapped_refused = true;
        }
    REQUIRE(swapped_refused);

    // ...and the walk as a whole reports INCOMPLETE. A ByteCap skip is a
    // budget stopping work we selected and intended to do, exactly like
    // DepthCap -- not a policy refusal like Symlink/Reparse/InvalidName,
    // which are completed visits and correctly leave None. This matters
    // because the byte budget does not replenish: once exhausted, every
    // later match is skipped too, so reporting None here would tell a
    // caller "nothing was left undone" about a walk that may have deleted
    // nothing at all for its entire remaining traversal.
    CHECK(result.stop_reason == Reason::ByteCap);
}

TEST_CASE("walk_delete: a policy refusal is a COMPLETED visit and leaves stop_reason None",
          "[confined_fs]") {
    // The companion to the assertion above, pinning the other half of the
    // contract so a future change cannot collapse the two. A walk whose only
    // blemish is a deliberate refusal must NOT report incompleteness --
    // "any skip => non-None" is the wrong reading and would make every
    // symlink rejection look like a failed cleanup run.
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {
        file_entry("keep.txt"),
        DirEntry{"link", EntryMeta{EntryType::Symlink, 0, true}, 0, false},
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    bool link_refused = false;
    for (const auto& e : result.entries)
        if (e.rel_path == "link") {
            CHECK(e.status == EntryStatus::Skipped);
            CHECK(e.reason == Reason::SymlinkRejected);
            link_refused = true;
        }
    REQUIRE(link_refused);
    CHECK(result.stop_reason == Reason::None);
}

// The companion case, and the one that actually exercises the TALLY: a file
// swapped for a larger one that still FITS the budget is deleted, and the cap
// must be charged what was really removed. Charging the enumerated size here
// would let a sequence of grown files walk past max_bytes while every
// individual delete looked in-budget.
TEST_CASE("walk_delete charges the measured size when a grown entry still fits",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("grown.txt", 10)}; // enumerated at 10
    ops.live_size_["grown.txt"] = 50;                      // really 50 on disk

    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);

    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
    REQUIRE(result.tally.bytes_deleted == 50); // measured, NOT the enumerated 10
}

// Regression: an enumerate reason the walker has no specific policy for must
// STOP the walk, not fall through every branch and silently truncate the
// directory while reporting stop_reason None. Reason::Internal is what a
// platform shell's own exception firewall reports on allocation failure.
TEST_CASE("walk_delete: an unhandled enumerate reason stops the walk", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};
    ops.dir(root).enumerate_internal_error = true;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);
    REQUIRE(result.stop_reason == Reason::Internal);
    REQUIRE(ops.unlink_calls_ == 0);
}

// Regression: a NON-EMPTY batch truncated by the entry budget must still report
// EntryCap. The walker previously reported the cap only when the truncated batch
// came back empty, so a directory larger than max_entries processed its capped
// entries and then returned stop_reason None — telling the caller the tree had
// been exhaustively visited when it had not.
TEST_CASE("walk_delete: a non-empty truncated batch still reports EntryCap", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt"), file_entry("c.txt"),
                             file_entry("d.txt"), file_entry("e.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 3;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(result.stop_reason == Reason::EntryCap);
    REQUIRE(result.tally.entries_seen <= 3);
    REQUIRE(result.entries.size() <= 3);
}

TEST_CASE("walk_delete: MatchFn throwing stops the walk with MatchError and keeps partial results",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("throws.txt"), file_entry("c.txt")};

    MatchFn throwing = [](std::string_view rel_path, const EntryMeta&) -> bool {
        if (rel_path == "throws.txt")
            throw std::runtime_error("boom");
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, throwing, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::MatchError);
    // a.txt was deleted before the throw; c.txt was never reached.
    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].rel_path == "a.txt");
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
}

TEST_CASE("walk_delete: a stat_error entry is Failed(OsError) and never unlinked",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {DirEntry{"broken", EntryMeta{}, /*stat_error=*/13, false}};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Failed);
    REQUIRE(result.entries[0].reason == Reason::OsError);
    REQUIRE(result.entries[0].os_error == 13);
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: a name_invalid entry is Skipped(InvalidName) and MatchFn not called",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {
        DirEntry{"bad\x00name", EntryMeta{EntryType::RegularFile, 1, true}, 0, true}};

    int match_calls = 0;
    MatchFn counting = [&](std::string_view, const EntryMeta&) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, kOpenLimits);
    REQUIRE(match_calls == 0);
    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Skipped);
    REQUIRE(result.entries[0].reason == Reason::InvalidName);
}

TEST_CASE("walk_delete: an enumerate OsError fails that directory and siblings still walked",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int broken_child = ops.add_dir();
    ops.dir(broken_child).enumerate_os_error = true;
    ops.dir(broken_child).enumerate_os_error_code = 5;

    int ok_child = ops.add_dir();
    ops.dir(ok_child).entries = {file_entry("sibling.txt")};

    ops.dir(root).subdirs["broken"] = broken_child;
    ops.dir(root).subdirs["ok"] = ok_child;
    ops.dir(root).entries = {dir_entry("broken"), dir_entry("ok")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    // NOT None: the broken child's subtree was never visited, so claiming an
    // exhaustive walk here would be a false completion signal. This assertion
    // previously required None and thereby pinned the defect.
    REQUIRE(result.stop_reason == Reason::OsError);
    bool found_broken_failed = false;
    bool found_sibling_deleted = false;
    for (auto& e : result.entries) {
        if (e.rel_path == "broken" && e.status == EntryStatus::Failed &&
            e.reason == Reason::OsError && e.os_error == 5)
            found_broken_failed = true;
        if (e.rel_path == "ok/sibling.txt" && e.status == EntryStatus::Deleted)
            found_sibling_deleted = true;
    }
    REQUIRE(found_broken_failed);
    REQUIRE(found_sibling_deleted);
}

TEST_CASE("walk_delete: EnumBudget passthrough reflects max_entries minus entries_seen",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 42;

    walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(ops.last_budget_.max_entries == 42); // entries_seen was 0 at the (only) enumerate call
}

TEST_CASE("walk_delete: wall-time truncation of enumeration stops immediately, nothing processed",
          "[confined_fs]") {
    auto start = std::chrono::steady_clock::now();
    FakeOps ops{start};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_wall = std::chrono::milliseconds{0};
    ops.advance(std::chrono::milliseconds{1}); // now() >= deadline at first enumerate

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);

    REQUIRE(result.stop_reason == Reason::WallTimeCap);
    REQUIRE(result.entries.empty());
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: NameFilteredOut entries are absent from output but counted",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, never_match, kOpenLimits);

    REQUIRE(result.entries.empty());
    REQUIRE(result.tally.entries_seen == 2);
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: directories are never passed to unlink", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(child).entries = {file_entry("leaf.txt")};
    ops.dir(root).subdirs["sub"] = child;
    ops.dir(root).entries = {dir_entry("sub")};

    walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    for (auto& name : ops.unlinked_names_)
        REQUIRE(name != "sub");
    REQUIRE(ops.unlinked_names_.size() == 1);
    REQUIRE(ops.unlinked_names_[0] == "leaf.txt");
}

TEST_CASE("walk_delete: open_dir policy refusal is Skipped, OsError refusal is Failed",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).refusals["policy-refused"] = Reason::SymlinkRejected;
    ops.dir(root).os_errors_open["os-refused"] = 7;
    ops.dir(root).entries = {dir_entry("policy-refused"), dir_entry("os-refused")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 2);
    auto find = [&](const std::string& name) -> const EntryOutcome& {
        for (auto& e : result.entries)
            if (e.rel_path == name)
                return e;
        throw std::runtime_error("not found");
    };
    REQUIRE(find("policy-refused").status == EntryStatus::Skipped);
    REQUIRE(find("policy-refused").reason == Reason::SymlinkRejected);
    REQUIRE(find("os-refused").status == EntryStatus::Failed);
    REQUIRE(find("os-refused").reason == Reason::OsError);
    REQUIRE(find("os-refused").os_error == 7);
}

TEST_CASE("walk_delete: unlink failure is Failed with the os_error preserved", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt", 999)};
    ops.fail_unlink_with(root, "a.txt", 42);

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Failed);
    REQUIRE(result.entries[0].reason == Reason::OsError);
    REQUIRE(result.entries[0].os_error == 42);
    // bytes_deleted must not grow on a failed delete.
    REQUIRE(result.tally.bytes_deleted == 0);
}

TEST_CASE("walk_delete: bytes_deleted grows only on successful deletes", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("ok.txt", 30), file_entry("bad.txt", 999)};
    ops.fail_unlink_with(root, "bad.txt", 1);

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.tally.bytes_deleted == 30);
}

// ── The metadata contract between walker and predicate ──────────────────────
//
// Gate 1 (all four reviewers, independently): the change's whole purpose is
// that an entry's real modification time reaches a caller's MatchFn, and that
// was asserted NOWHERE. Every existing predicate discards its EntryMeta
// argument, so — as Kimi put it — reverting the one-line pass-through in
// walk_delete left the entire suite green. Compilation proved the two-argument
// SHAPE; nothing proved WHICH metadata was forwarded, or that age could
// actually control deletion.
TEST_CASE("walk_delete forwards the entry's own metadata to MatchFn",
          "[confined_fs][mtime]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();

    DirEntry old_file = file_entry("old.tmp");
    old_file.meta.mtime = 1'000;
    old_file.meta.size_bytes = 11;
    DirEntry new_file = file_entry("new.tmp");
    new_file.meta.mtime = 2'000;
    new_file.meta.size_bytes = 22;
    DirEntry undated = file_entry("undated.tmp");
    undated.meta.mtime = std::nullopt;
    undated.meta.size_bytes = 33;
    ops.dir(root).entries = {old_file, new_file, undated};

    // Record exactly what the predicate is handed, keyed by the path it is
    // handed alongside — so a forwarding bug that supplies the WRONG entry's
    // metadata fails, not just one that supplies none.
    std::map<std::string, std::optional<std::int64_t>> seen_mtime;
    std::map<std::string, std::uint64_t> seen_size;
    MatchFn observe = [&](std::string_view rel_path, const EntryMeta& meta) {
        seen_mtime[std::string{rel_path}] = meta.mtime;
        seen_size[std::string{rel_path}] = meta.size_bytes;
        return false; // delete nothing; this case is about delivery only
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, observe, kOpenLimits);
    REQUIRE(result.stop_reason == Reason::None);

    REQUIRE(seen_mtime.size() == 3);
    CHECK(seen_mtime["old.tmp"] == std::optional<std::int64_t>{1'000});
    CHECK(seen_mtime["new.tmp"] == std::optional<std::int64_t>{2'000});
    CHECK_FALSE(seen_mtime["undated.tmp"].has_value());
    // The size travels through the same struct, so pinning it here catches a
    // forwarding bug that hands over a DEFAULT-constructed meta rather than
    // the entry's own.
    CHECK(seen_size["old.tmp"] == 11);
    CHECK(seen_size["new.tmp"] == 22);
    CHECK(seen_size["undated.tmp"] == 33);
}

TEST_CASE("walk_delete: a MatchFn can select by age, and an undated entry is refused",
          "[confined_fs][mtime]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();

    DirEntry old_file = file_entry("old.tmp");
    old_file.meta.mtime = 1'000;
    DirEntry new_file = file_entry("new.tmp");
    new_file.meta.mtime = 2'000;
    DirEntry undated = file_entry("undated.tmp");
    undated.meta.mtime = std::nullopt;
    ops.dir(root).entries = {old_file, new_file, undated};

    // The shape a real consumer writes: absence is handled BEFORE any
    // arithmetic, which is the whole reason mtime is an optional rather than a
    // sentinel. An undated entry is refused rather than treated as ancient.
    constexpr std::int64_t kCutoff = 1'500;
    MatchFn older_than_cutoff = [&](std::string_view, const EntryMeta& meta) {
        if (!meta.mtime) return false; // unknown age -> do not act
        return *meta.mtime < kCutoff;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, older_than_cutoff, kOpenLimits);
    REQUIRE(result.stop_reason == Reason::None);

    // Exactly one entry deleted, and it is the old one by NAME -- not merely a
    // count, which a wrong-entry bug would satisfy.
    std::vector<std::string> deleted;
    for (const auto& e : result.entries)
        if (e.status == EntryStatus::Deleted) deleted.push_back(e.rel_path);
    REQUIRE(deleted.size() == 1);
    CHECK(deleted[0] == "old.tmp");
    CHECK(ops.unlink_calls_ == 1);
}
