/**
 * test_filesystem_find_by_hash.cpp -- the bounded find_by_hash walk core (#5624).
 *
 * The walk is driven with injected fakes (clock, cancel predicate, hasher, directory probe, mount
 * list), so every bound is exercised without a sleep, a process or the network; the real
 * no-follow hashers (hash_entry_posix / hash_entry_win) are driven over a TempDir. The real
 * plugin through LocalDispatcher is test_filesystem_find_by_hash_dispatcher.cpp.
 *
 * UNGUARDED TU on every OS; only the symlink / FIFO / permission cases are #ifndef _WIN32.
 */
#include <catch2/catch_test_macros.hpp>

#include "filesystem_dispatcher_test_support.hpp"
#include "filesystem_find_by_hash.hpp"
#include "test_helpers.hpp"

#include <network_fstype.hpp>
#include <sha256.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <functional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fbh = yuzu::filesystem::find_by_hash;
namespace fs = std::filesystem;

using yuzu::test::filesystem_dispatcher_support::Tree;
#ifndef _WIN32
using yuzu::test::filesystem_dispatcher_support::running_as_root;
#else
using yuzu::test::filesystem_dispatcher_support::create_junction;
using yuzu::test::filesystem_dispatcher_support::JunctionCleanup;
using yuzu::test::filesystem_dispatcher_support::make_file_reparse_point;
#endif

namespace {

constexpr std::string_view kTarget =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr std::string_view kMiss =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr std::string_view kEmptySha =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// What the fake hooks saw, in call order.
struct Probe {
    std::vector<fs::path> hashed;
    std::vector<fs::path> entered;
};

/// A fake env: every file whose name does not start with "miss" matches kTarget; every path asked
/// of can_enter / hash_entry is recorded.
fbh::WalkEnv fake_env(Probe& probe) {
    fbh::WalkEnv env;
    env.hash_entry = [&probe](const fs::directory_entry& e, fbh::HashBudget&,
                              const fbh::WalkLimits&) {
        probe.hashed.push_back(e.path());
        std::error_code ec;
        const auto size = fs::file_size(e.path(), ec);
        const bool miss = e.path().filename().string().rfind("miss", 0) == 0;
        return fbh::HashOutcome{fbh::HashKind::hashed, std::string{miss ? kMiss : kTarget}, size};
    };
    env.can_enter = [&probe](const fs::path& p) {
        probe.entered.push_back(p);
        return true;
    };
    return env;
}

struct Walked {
    fbh::WalkOutcome out;
    std::vector<std::string> rows;
};

Walked walk(const Tree& t, int max_depth, const fbh::WalkLimits& limits, const fbh::WalkEnv& env,
            std::string_view target = kTarget) {
    Walked w;
    w.out = fbh::walk_find_by_hash(t.str(), target, max_depth, limits, env,
                                   [&w](const std::string& row) { w.rows.push_back(row); });
    return w;
}

std::set<std::string> matched_paths(const Walked& w) {
    std::set<std::string> out;
    for (const auto& r : w.rows) {
        const auto second = r.find('|', 6);
        out.insert(r.substr(6, second - 6));
    }
    return out;
}

/// The real hasher for this OS.
fbh::HashOutcome real_hash(const fs::directory_entry& e, fbh::HashBudget& b,
                           const fbh::WalkLimits& lim) {
#ifdef _WIN32
    return fbh::hash_entry_win(e, b, lim);
#else
    return fbh::hash_entry_posix(e, b, lim);
#endif
}

fbh::WalkEnv real_env() {
    fbh::WalkEnv env;
    env.hash_entry = real_hash;
#ifndef _WIN32
    env.can_enter = fbh::can_enter_posix;
#endif
    return env;
}

/// One run of the real hasher over `p` with the budget's observable end state: the outcome, why the
/// budget stopped (if it did) and the admitted-byte counter.
struct HashRun {
    fbh::HashOutcome outcome;
    fbh::StopReason stop{fbh::StopReason::none};
    fbh::WalkCounters counters;
};

HashRun hash_run(
    const fs::path& p, const fbh::WalkLimits& lim = {},
    std::function<bool()> cancelled = [] { return false; }) {
    HashRun run;
    fbh::HashBudget budget{lim, [] { return fbh::Clock::now(); }, std::move(cancelled),
                           run.counters};
    run.outcome = real_hash(fs::directory_entry{p}, budget, lim);
    run.stop = budget.stop();
    return run;
}

fbh::HashOutcome hash_direct(const fs::path& p, const fbh::WalkLimits& lim = {}) {
    return hash_run(p, lim).outcome;
}

/// A manually advanced clock.
struct FakeClock {
    fbh::Clock::time_point t{};
    [[nodiscard]] std::function<fbh::Clock::time_point()> fn() {
        return [this] {
            return t;
        };
    }
};

} // namespace

// -- Constants ----------------------------------------------------------------------------------

TEST_CASE("find_by_hash bounds: the shipped limits are the documented ones", "[find_by_hash]") {
    const fbh::WalkLimits lim;
    CHECK(lim.deadline == std::chrono::seconds{20});
    CHECK(lim.max_files_visited == 50'000);
    CHECK(lim.max_bytes_hashed == 4ULL * 1024 * 1024 * 1024);
    CHECK(lim.max_results == 100);
    CHECK(lim.max_file_bytes == 10ULL * 1024 * 1024 * 1024);
    CHECK(fbh::kHashChunk == 64 * 1024);
}

// -- Bounds -------------------------------------------------------------------------------------

TEST_CASE("find_by_hash file cap: the walk stops at max_files_visited with an exact trailer",
          "[find_by_hash]") {
    Tree t;
    for (int i = 0; i < 5; ++i)
        t.write("f" + std::to_string(i));
    Probe probe;
    fbh::WalkLimits lim;
    lim.max_files_visited = 3;
    const auto w = walk(t, 3, lim, fake_env(probe));
    CHECK(w.out.stop == fbh::StopReason::file_cap);
    CHECK(w.out.c.visited == 3);
    CHECK(w.out.trailer_needed());
    CHECK(w.out.constrained());
    CHECK(fbh::format_trailer(w.out) ==
          "truncated|file_cap|visited=3|hashed=0|skipped_unreadable=0|skipped_symlink=0|"
          "skipped_not_regular=0|skipped_oversize=0|skipped_network_mount=0");
    CHECK(probe.hashed.size() == 3);
}

TEST_CASE("find_by_hash file cap: a tree of exactly max_files_visited entries is clean",
          "[find_by_hash]") {
    Tree t;
    for (int i = 0; i < 3; ++i)
        t.write("f" + std::to_string(i));
    Probe probe;
    fbh::WalkLimits lim;
    lim.max_files_visited = 3;
    const auto w = walk(t, 3, lim, fake_env(probe));
    CHECK(w.out.stop == fbh::StopReason::none);
    CHECK(w.out.c.visited == 3);
    CHECK_FALSE(w.out.trailer_needed());
}

TEST_CASE(
    "find_by_hash byte cap: stops mid-walk, counts only admitted bytes, emits no abandoned match",
    "[find_by_hash]") {
    Tree t;
    for (int i = 0; i < 3; ++i)
        t.write("f" + std::to_string(i), std::string(10, 'z'));
    Probe probe;
    auto env = fake_env(probe);
    // Hash through the budget exactly as the real hashers do: one consume per file-sized chunk.
    env.hash_entry = [&probe](const fs::directory_entry& e, fbh::HashBudget& b,
                              const fbh::WalkLimits&) {
        probe.hashed.push_back(e.path());
        if (!b.consume(10))
            return fbh::HashOutcome{fbh::HashKind::stopped, {}, 0};
        return fbh::HashOutcome{fbh::HashKind::hashed, std::string{kTarget}, 10};
    };
    fbh::WalkLimits lim;
    lim.max_bytes_hashed = 25;
    const auto w = walk(t, 3, lim, env);
    CHECK(w.out.stop == fbh::StopReason::byte_cap);
    CHECK(w.out.c.hashed_bytes == 20);
    CHECK(w.out.c.visited == 3);
    CHECK(w.rows.size() == 2); // the third file was abandoned, never reported
    CHECK(w.out.matches == 2);
    CHECK(fbh::format_trailer(w.out) ==
          "truncated|byte_cap|visited=3|hashed=20|skipped_unreadable=0|skipped_symlink=0|"
          "skipped_not_regular=0|skipped_oversize=0|skipped_network_mount=0");
}

TEST_CASE(
    "find_by_hash deadline: N files x a per-file cost over the budget stop the walk, no sleep",
    "[find_by_hash]") {
    // The issue's minimal tree: each file charges 700 ms against a 2 s deadline. Before the
    // bound, this walk visited every entry however long it took.
    Tree t;
    for (int i = 0; i < 10; ++i)
        t.write("f" + std::to_string(i));
    FakeClock clock;
    Probe probe;
    auto env = fake_env(probe);
    env.now = clock.fn();
    env.hash_entry = [&](const fs::directory_entry& e, fbh::HashBudget&, const fbh::WalkLimits&) {
        probe.hashed.push_back(e.path());
        clock.t += std::chrono::milliseconds{700};
        return fbh::HashOutcome{fbh::HashKind::hashed, std::string{kMiss}, 1};
    };
    fbh::WalkLimits lim;
    lim.deadline = std::chrono::seconds{2};
    const auto w = walk(t, 3, lim, env);
    CHECK(w.out.stop == fbh::StopReason::deadline);
    CHECK(w.out.c.visited == 3); // 0.7 s, 1.4 s, 2.1 s: the fourth entry's check trips
    CHECK(probe.hashed.size() == 3);
    CHECK(w.out.constrained());
    CHECK(fbh::format_trailer(w.out).starts_with("truncated|deadline|visited=3|"));
}

TEST_CASE("find_by_hash cancel: the predicate flipping mid-walk ends it as cancelled",
          "[find_by_hash]") {
    Tree t;
    for (int i = 0; i < 6; ++i)
        t.write("f" + std::to_string(i));
    Probe probe;
    auto env = fake_env(probe);
    env.cancelled = [&probe] {
        return probe.hashed.size() >= 2;
    };
    const auto w = walk(t, 3, {}, env);
    CHECK(w.out.stop == fbh::StopReason::cancelled);
    CHECK(w.out.c.visited == 2);
    CHECK(w.out.constrained());
    CHECK(fbh::format_trailer(w.out).starts_with("truncated|cancelled|visited=2|"));
}

TEST_CASE("find_by_hash max_results: the cap truncates only when entries remain",
          "[find_by_hash]") {
    Tree t;
    for (int i = 0; i < 4; ++i)
        t.write("f" + std::to_string(i));
    Probe probe;
    fbh::WalkLimits lim;
    lim.max_results = 3;

    // 4 matching files, cap 3: a fourth entry remains -> truncated|max_results.
    auto w = walk(t, 3, lim, fake_env(probe));
    CHECK(w.rows.size() == 3);
    CHECK(w.out.matches == 3);
    CHECK(w.out.stop == fbh::StopReason::max_results);
    CHECK(w.out.constrained());
    CHECK(fbh::format_trailer(w.out).starts_with("truncated|max_results|"));

    // exactly 3 files, cap 3: nothing is left to look at -> clean.
    fs::remove(t.root / "f3");
    Probe probe2;
    w = walk(t, 3, lim, fake_env(probe2));
    CHECK(w.rows.size() == 3);
    CHECK(w.out.stop == fbh::StopReason::none);
    CHECK_FALSE(w.out.trailer_needed());
}

TEST_CASE("find_by_hash budget: the first bound to trip is sticky and cancel outranks the deadline",
          "[find_by_hash]") {
    FakeClock clock;
    fbh::WalkCounters c;
    fbh::WalkLimits lim;
    lim.deadline = std::chrono::seconds{1};
    lim.max_bytes_hashed = 100;
    bool cancelled = false;
    fbh::HashBudget b{lim, clock.fn(), [&] { return cancelled; }, c};

    CHECK(b.check());
    CHECK(b.consume(60));
    CHECK(c.hashed_bytes == 60);
    CHECK_FALSE(b.consume(41)); // 60 + 41 > 100
    CHECK(b.stop() == fbh::StopReason::byte_cap);
    CHECK(c.hashed_bytes == 60); // the refused chunk is not counted
    cancelled = true;
    clock.t += std::chrono::seconds{5};
    CHECK_FALSE(b.check()); // sticky: later conditions do not rewrite the reason
    CHECK(b.stop() == fbh::StopReason::byte_cap);

    fbh::WalkCounters c2;
    FakeClock clock2;
    bool cancelled2 = true;
    fbh::HashBudget b2{lim, clock2.fn(), [&] { return cancelled2; }, c2};
    clock2.t += std::chrono::seconds{5}; // both conditions hold at once
    CHECK_FALSE(b2.check());
    CHECK(b2.stop() == fbh::StopReason::cancelled);

    fbh::WalkCounters c3;
    FakeClock clock3;
    fbh::HashBudget b3{lim, clock3.fn(), [] { return false; }, c3};
    clock3.t += std::chrono::seconds{1}; // now() >= deadline_at
    CHECK_FALSE(b3.consume(1));
    CHECK(b3.stop() == fbh::StopReason::deadline);
    CHECK(c3.hashed_bytes == 0);
}

// -- Depth --------------------------------------------------------------------------------------

TEST_CASE("find_by_hash depth: max_depth matches the old slash-count meaning and never opens a "
          "directory at the limit",
          "[find_by_hash]") {
    Tree t;
    t.write("f1.txt");
    t.write("d1/f2.txt");
    t.write("d1/d2/f3.txt");
    t.write("d1/d2/d3/f4.txt");
    const auto rel = [&](const Walked& w) {
        std::set<std::string> out;
        for (const auto& p : matched_paths(w))
            out.insert(fs::path(p).lexically_relative(t.root).generic_string());
        return out;
    };

    {
        Probe probe;
        const auto w = walk(t, 1, {}, fake_env(probe));
        CHECK(rel(w) == std::set<std::string>{"f1.txt"}); // root's children are depth 1
        // d1 sits AT the limit: it is never probed (nor opened), only the root is.
        CHECK(probe.entered == std::vector<fs::path>{t.root});
        CHECK_FALSE(w.out.trailer_needed());
    }
    {
        Probe probe;
        const auto w = walk(t, 2, {}, fake_env(probe));
        CHECK(rel(w) == std::set<std::string>{"f1.txt", "d1/f2.txt"});
        CHECK(probe.entered == std::vector<fs::path>{t.root, t.root / "d1"});
    }
    {
        Probe probe;
        const auto w = walk(t, 3, {}, fake_env(probe));
        CHECK(rel(w) == std::set<std::string>{"f1.txt", "d1/f2.txt", "d1/d2/f3.txt"});
        CHECK(probe.entered == std::vector<fs::path>{t.root, t.root / "d1", t.root / "d1" / "d2"});
    }
    {
        Probe probe;
        const auto w = walk(t, 4, {}, fake_env(probe));
        CHECK(rel(w).size() == 4);
    }
}

// -- Symlinks, special files, unreadable --------------------------------------------------------

#ifndef _WIN32

TEST_CASE("find_by_hash symlinks: a directory loop and file links are counted, never followed",
          "[find_by_hash]") {
    Tree t;
    t.write("real/file.txt");
    fs::create_directory_symlink(t.root, t.root / "loop");              // back to the root
    fs::create_symlink(t.root / "real" / "file.txt", t.root / "flink"); // to a regular file
    fs::create_symlink(t.root / "nowhere", t.root / "dangling");        // to nothing
    Probe probe;
    const auto w = walk(t, 10, {}, fake_env(probe));
    CHECK(w.out.c.skipped_symlink == 3);
    CHECK(probe.hashed == std::vector<fs::path>{t.root / "real" / "file.txt"});
    CHECK(w.out.c.visited == 5); // real, real/file.txt, loop, flink, dangling
    CHECK(w.out.matches == 1);
    CHECK(w.out.trailer_needed());
    CHECK_FALSE(w.out.constrained()); // by-design exclusions alone do not constrain the result
}

TEST_CASE("find_by_hash symlinks: the real hasher refuses a leaf symlink (ELOOP)",
          "[find_by_hash]") {
    Tree t;
    const auto target = t.write("target.txt", "hello");
    fs::create_symlink(target, t.root / "link.txt");
    CHECK(hash_direct(t.root / "link.txt").kind == fbh::HashKind::symlink);
    CHECK(hash_direct(target).kind == fbh::HashKind::hashed);
}

TEST_CASE("find_by_hash symlinks: a symlink in an ANCESTOR component is refused where the OS can",
          "[find_by_hash]") {
    Tree t;
    t.write("real/file.txt", "hello");
    fs::create_directory_symlink(t.root / "real", t.root / "link");
    const auto got = hash_direct(t.root / "link" / "file.txt");
#if defined(__linux__)
    if (fbh::detail::openat2_unavailable().load()) {
        SKIP("openat2 is not available on this kernel: the fallback is leaf-only by design");
    }
#endif
    CHECK(got.kind == fbh::HashKind::symlink);
}

#if defined(__linux__)
TEST_CASE("find_by_hash symlinks: with openat2 unavailable the fallback is leaf-only no-follow",
          "[find_by_hash]") {
    Tree t;
    const auto target = t.write("real/file.txt", "hello");
    fs::create_directory_symlink(t.root / "real", t.root / "link");
    fs::create_symlink(target, t.root / "leaf");
    struct Restore {
        bool saved = fbh::detail::openat2_unavailable().load();
        ~Restore() { fbh::detail::openat2_unavailable().store(saved); }
    } restore;
    fbh::detail::openat2_unavailable().store(true); // what an ENOSYS answer remembers

    CHECK(hash_direct(t.root / "leaf").kind == fbh::HashKind::symlink); // O_NOFOLLOW on the leaf
    const auto via_ancestor = hash_direct(t.root / "link" / "file.txt");
    CHECK(via_ancestor.kind == fbh::HashKind::hashed); // the disclosed residual of the fallback
    CHECK(via_ancestor.hex == yuzu::shared::sha256_hex("hello"));
}
#endif

TEST_CASE("find_by_hash FIFO: a pipe in the tree is counted and never handed to the hasher",
          "[find_by_hash]") {
    Tree t;
    t.write("file.txt");
    REQUIRE(::mkfifo((t.root / "pipe").c_str(), 0600) == 0);
    Probe probe;
    const auto w = walk(t, 3, {}, fake_env(probe));
    CHECK(w.out.c.skipped_not_regular == 1);
    CHECK(probe.hashed == std::vector<fs::path>{t.root / "file.txt"});
    CHECK(w.out.trailer_needed());
    CHECK_FALSE(w.out.constrained());
}

TEST_CASE("find_by_hash FIFO: the real hasher classifies a pipe on its own descriptor and returns",
          "[find_by_hash]") {
    // O_NONBLOCK keeps this open from blocking on a FIFO with no writer.
    Tree t;
    REQUIRE(::mkfifo((t.root / "pipe").c_str(), 0600) == 0);
    CHECK(hash_direct(t.root / "pipe").kind == fbh::HashKind::not_regular);
}

TEST_CASE("find_by_hash unreadable: a file without read permission is counted and constrains",
          "[find_by_hash]") {
    if (running_as_root())
        SKIP("root reads a mode-000 file; the unreadable case needs an unprivileged user");
    Tree t;
    const auto locked = t.write("locked.txt", "secret");
    t.write("open.txt", "plain");
    REQUIRE(::chmod(locked.c_str(), 0) == 0);
    const auto w = walk(t, 3, {}, real_env(), yuzu::shared::sha256_hex("plain"));
    ::chmod(locked.c_str(), 0600);
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(w.out.matches == 1);
    CHECK(w.out.constrained());
}

TEST_CASE("find_by_hash unreadable: a directory the probe refuses is counted and not entered",
          "[find_by_hash]") {
    Tree t;
    t.write("locked/inside.txt");
    t.write("open.txt");
    Probe probe;
    auto env = fake_env(probe);
    env.can_enter = [&](const fs::path& p) {
        probe.entered.push_back(p);
        return p.filename() != "locked";
    };
    const auto w = walk(t, 3, {}, env);
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(probe.hashed == std::vector<fs::path>{t.root / "open.txt"});
    CHECK(w.out.constrained());
}

TEST_CASE(
    "find_by_hash unreadable: a real mode-000 directory is counted through the directory open",
    "[find_by_hash]") {
    if (running_as_root())
        SKIP("root lists a mode-000 directory; the unreadable case needs an unprivileged user");
    Tree t;
    t.write("locked/inside.txt", "x");
    REQUIRE(::chmod((t.root / "locked").c_str(), 0) == 0);
    const auto w = walk(t, 3, {}, real_env());
    ::chmod((t.root / "locked").c_str(), 0700);
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(w.out.constrained());
}

TEST_CASE("find_by_hash unreadable root: an unreadable root is counted, never a clean empty walk",
          "[find_by_hash]") {
    Tree t;
    t.write("f.txt");
    Probe probe;
    auto env = fake_env(probe);
    env.can_enter = [](const fs::path&) {
        return false;
    };
    const auto w = walk(t, 3, {}, env);
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(w.out.c.visited == 0);
    CHECK(probe.hashed.empty());
    CHECK(w.out.constrained());
    CHECK(fbh::format_trailer(w.out) ==
          "truncated|none|visited=0|hashed=0|skipped_unreadable=1|skipped_symlink=0|"
          "skipped_not_regular=0|skipped_oversize=0|skipped_network_mount=0");
}

TEST_CASE(
    "find_by_hash unreadable root: a real mode-000 root is counted through the directory open",
    "[find_by_hash]") {
    if (running_as_root())
        SKIP("root lists a mode-000 directory; the unreadable case needs an unprivileged user");
    Tree t;
    t.write("f.txt");
    REQUIRE(::chmod(t.root.c_str(), 0) == 0);
    const auto w = walk(t, 3, {}, real_env());
    ::chmod(t.root.c_str(), 0700);
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(w.out.c.visited == 0);
}

TEST_CASE("find_by_hash can_enter_posix: a listable directory, and nothing else",
          "[find_by_hash]") {
    Tree t;
    t.write("dir/inside.txt");
    const auto file = t.write("plain.txt");
    REQUIRE(::chmod(file.c_str(), 0700) == 0); // executable, but a file: not listable
    fs::create_directory_symlink(t.root / "dir", t.root / "dirlink");
    CHECK(fbh::can_enter_posix(t.root));
    CHECK(fbh::can_enter_posix(t.root / "dir"));
    CHECK_FALSE(fbh::can_enter_posix(file));               // not a directory (ENOTDIR)
    CHECK_FALSE(fbh::can_enter_posix(t.root / "absent"));  // ENOENT
    CHECK_FALSE(fbh::can_enter_posix(t.root / "dirlink")); // a symlink is never entered
    if (!running_as_root()) {
        REQUIRE(::chmod((t.root / "dir").c_str(), 0) == 0);
        CHECK_FALSE(fbh::can_enter_posix(t.root / "dir"));
        REQUIRE(::chmod((t.root / "dir").c_str(), 0400) == 0); // listable names, no search bit
        CHECK_FALSE(fbh::can_enter_posix(t.root / "dir"));
        ::chmod((t.root / "dir").c_str(), 0700);
    }
}

#endif // !_WIN32

#ifdef _WIN32

// -- Windows reparse points ---------------------------------------------------------------------
// Real NTFS reparse points, built without a privilege (tests/unit/filesystem_dispatcher_test_
// support.hpp). They pin the three Windows no-follow anchors: the junction check in the walk, the
// FILE_FLAG_OPEN_REPARSE_POINT open and the reparse-attribute check in hash_entry_win.

TEST_CASE("find_by_hash junctions: a junction is counted and never entered or hashed through",
          "[find_by_hash]") {
    Tree t;
    const auto secret = t.write("tree/real/secret.txt", "secret");
    const fs::path link = t.root / "tree" / "link";
    REQUIRE(create_junction(link, t.root / "tree" / "real"));
    const JunctionCleanup cleanup{link}; // removes the junction itself, before the Tree goes
    Probe probe;
    auto env = real_env();
    env.hash_entry = [&](const fs::directory_entry& e, fbh::HashBudget& b,
                         const fbh::WalkLimits& l) {
        probe.hashed.push_back(e.path());
        return real_hash(e, b, l);
    };
    const auto w = walk(t, 5, {}, env, yuzu::shared::sha256_hex("secret"));
    CHECK(w.out.c.skipped_symlink == 1);
    CHECK(w.out.c.visited == 4); // tree, tree/real, tree/real/secret.txt, tree/link
    CHECK(probe.hashed == std::vector<fs::path>{secret}); // nothing under tree/link was reached
    CHECK(matched_paths(w) == std::set<std::string>{secret.string()});
    CHECK(w.out.trailer_needed());
    CHECK_FALSE(w.out.constrained()); // a by-design exclusion alone does not constrain
}

TEST_CASE("find_by_hash reparse points: the real Windows hasher reports a file reparse point",
          "[find_by_hash]") {
    Tree t;
    const auto p = t.write("tagged.bin", "x");
    REQUIRE(make_file_reparse_point(p));
    CHECK(hash_direct(p).kind == fbh::HashKind::symlink);
    // Through the walk the file is never read through: whether std::filesystem lists the tagged
    // file as a regular file (the hasher then reports the reparse point) or as something else, it
    // is counted as skipped and its content is not matched.
    const auto w = walk(t, 3, {}, real_env(), yuzu::shared::sha256_hex("x"));
    CHECK(w.out.matches == 0);
    CHECK(w.out.c.skipped_symlink + w.out.c.skipped_not_regular == 1);
}

TEST_CASE("find_by_hash win_root_drive_refused: only a fixed disk or a nonexistent drive proceeds",
          "[find_by_hash]") {
    const struct {
        UINT type;
        bool refused;
    } cases[] = {
        {DRIVE_UNKNOWN, true}, {DRIVE_NO_ROOT_DIR, false}, {DRIVE_REMOVABLE, true},
        {DRIVE_FIXED, false},  {DRIVE_REMOTE, true},       {DRIVE_CDROM, true},
        {DRIVE_RAMDISK, true},
    };
    for (const auto& c : cases) {
        INFO("GetDriveTypeW answer " << c.type);
        CHECK(fbh::win_root_drive_refused(c.type) == c.refused);
    }
}

#endif // _WIN32

// -- Real hasher --------------------------------------------------------------------------------

TEST_CASE("find_by_hash real hasher: digest equals the in-memory SHA-256 across chunk boundaries",
          "[find_by_hash]") {
    Tree t;
    std::string content(3 * fbh::kHashChunk + 17, '\0');
    for (std::size_t i = 0; i < content.size(); ++i)
        content[i] = static_cast<char>('a' + (i % 23));
    const auto p = t.write("big.bin", content);
    const auto got = hash_direct(p);
    REQUIRE(got.kind == fbh::HashKind::hashed);
    CHECK(got.hex == yuzu::shared::sha256_hex(content));
    CHECK(got.size == content.size());

    const auto w = walk(t, 3, {}, real_env(), yuzu::shared::sha256_hex(content));
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0] == "match|" + p.string() + "|" + std::to_string(content.size()));
    CHECK(w.out.c.hashed_bytes == content.size());
}

TEST_CASE("find_by_hash real hasher: the byte cap stops a large file mid-stream",
          "[find_by_hash]") {
    // The real per-OS hasher (hash_entry_win on Windows, hash_entry_posix elsewhere), not a fake:
    // without the per-chunk budget.consume() a large file would be read to the end however small
    // the cap.
    Tree t;
    const auto p = t.write("big.bin", std::string(3 * fbh::kHashChunk + 17, 'q'));
    fbh::WalkLimits lim;
    lim.max_bytes_hashed = 2 * fbh::kHashChunk;
    const auto got = hash_run(p, lim);
    CHECK(got.outcome.kind == fbh::HashKind::stopped);
    CHECK(got.stop == fbh::StopReason::byte_cap);
    CHECK(got.counters.hashed_bytes ==
          2 * fbh::kHashChunk); // two chunks admitted, the third refused
}

TEST_CASE("find_by_hash real hasher: a cancelled budget stops a large file before it hashes a byte",
          "[find_by_hash]") {
    Tree t;
    const auto p = t.write("big.bin", std::string(3 * fbh::kHashChunk + 17, 'q'));
    const auto got = hash_run(p, {}, [] { return true; });
    CHECK(got.outcome.kind == fbh::HashKind::stopped);
    CHECK(got.stop == fbh::StopReason::cancelled);
    CHECK(got.counters.hashed_bytes == 0);
}

TEST_CASE("find_by_hash empty files are hashed, not skipped", "[find_by_hash]") {
    Tree t;
    const auto p = t.write("empty.txt", "");
    const auto got = hash_direct(p);
    REQUIRE(got.kind == fbh::HashKind::hashed);
    CHECK(got.hex == kEmptySha);
    CHECK(got.size == 0);
    const auto w = walk(t, 3, {}, real_env(), kEmptySha);
    CHECK(w.rows == std::vector<std::string>{"match|" + p.string() + "|0"});
    CHECK_FALSE(w.out.trailer_needed());
}

TEST_CASE("find_by_hash oversize: a file over max_file_bytes is counted but does not constrain",
          "[find_by_hash]") {
    Tree t;
    t.write("big.bin", "12345");
    t.write("ok.bin", "1234");
    fbh::WalkLimits lim;
    lim.max_file_bytes = 4;
    const auto w = walk(t, 3, lim, real_env(), yuzu::shared::sha256_hex("1234"));
    CHECK(w.out.c.skipped_oversize == 1);
    CHECK(w.out.matches == 1);
    CHECK(w.out.trailer_needed());
    CHECK_FALSE(w.out.constrained());
}

// -- Network mounts -----------------------------------------------------------------------------

TEST_CASE("find_by_hash mountinfo fixture: only the network-backed mount points are listed",
          "[find_by_hash]") {
    const std::string text =
        "36 25 0:32 / /mnt/nfs rw,relatime shared:1 - nfs4 server:/export rw,vers=4.2\n"
        "37 25 8:1 / /mnt/local rw,relatime shared:2 - ext4 /dev/sda1 rw\n"
        "38 25 0:40 / /mnt/with\\040space rw - cifs //srv/share rw\n";
    CHECK(yuzu::shared::network_mount_points(text) ==
          std::vector<std::string>{"/mnt/nfs", "/mnt/with space"});
}

TEST_CASE("find_by_hash mounts: a mount point under the walk is skipped before any hook sees it",
          "[find_by_hash]") {
    Tree t;
    t.write("nfs/secret.txt");
    t.write("nfs/deeper/secret2.txt");
    t.write("local/ok.txt");
    t.write("other.txt");
    Probe probe;
    auto env = fake_env(probe);
    env.network_mounts = {(t.root / "nfs").string()};
    const auto w = walk(t, 5, {}, env);

    CHECK(w.out.c.skipped_network_mount == 1);
    CHECK(w.out.constrained());
    CHECK(w.out.matches == 2);
    CHECK(w.out.c.visited == 4); // nfs, local, local/ok.txt, other.txt
    const auto under_nfs = [&](const fs::path& p) {
        return fbh::is_under_mount(p.string(), env.network_mounts);
    };
    CHECK(std::none_of(probe.hashed.begin(), probe.hashed.end(), under_nfs));
    CHECK(std::none_of(probe.entered.begin(), probe.entered.end(), under_nfs));
}

TEST_CASE("find_by_hash mounts: a root on a mount is refused before any hook runs",
          "[find_by_hash]") {
    Tree t;
    t.write("f.txt");
    for (const auto& mount : {t.str(), t.root.parent_path().string()}) {
        Probe probe;
        auto env = fake_env(probe);
        env.network_mounts = {mount};
        const auto w = walk(t, 3, {}, env);
        CHECK(w.out.c.skipped_network_mount == 1);
        CHECK(w.out.c.visited == 0);
        CHECK(probe.entered.empty()); // not even the root readability probe
        CHECK(probe.hashed.empty());
        CHECK(w.out.constrained());
    }
}

TEST_CASE("find_by_hash is_under_mount: path-boundary matching", "[find_by_hash]") {
    const std::vector<std::string> nfs{"/mnt/nfs"};
    CHECK(fbh::is_under_mount("/mnt/nfs", nfs));
    CHECK(fbh::is_under_mount("/mnt/nfs/x/y", nfs));
    CHECK_FALSE(fbh::is_under_mount("/mnt/nfsx", nfs));
    CHECK_FALSE(fbh::is_under_mount("/mnt", nfs));
    CHECK_FALSE(fbh::is_under_mount("/mnt/nf", nfs));
    CHECK(fbh::is_under_mount("/anything/at/all", {"/"}));
    CHECK(fbh::is_under_mount("/mnt/nfs/x", {"/mnt/nfs/"})); // a trailing slash on the mount
    CHECK_FALSE(fbh::is_under_mount("/mnt/nfs", {""}));      // an empty entry names nothing
    CHECK_FALSE(fbh::is_under_mount("/mnt/nfs", {}));
}

#ifndef _WIN32
TEST_CASE("find_by_hash root_lexically_under_mount: aliases of a mount point are refused",
          "[find_by_hash]") {
    const std::vector<std::string> nfs{"/mnt/nfs"};
    for (const char* alias :
         {"/mnt/nfs", "/mnt/nfs/", "/mnt//nfs", "/mnt/./nfs", "/mnt/x/../nfs", "/mnt/nfs/sub/.."})
        CHECK(fbh::root_lexically_under_mount(alias, nfs));
    CHECK_FALSE(fbh::root_lexically_under_mount("/mnt/nfsx", nfs));
    CHECK_FALSE(fbh::root_lexically_under_mount("/mnt/nfs/../local", nfs));
}
#endif

// -- Output formatting --------------------------------------------------------------------------

TEST_CASE("find_by_hash clean run: no skips, no trailer, matches only", "[find_by_hash]") {
    Tree t;
    t.write("a.txt");
    t.write("d/b.txt");
    t.write("d/miss.txt");
    Probe probe;
    const auto w = walk(t, 3, {}, fake_env(probe));
    CHECK(w.out.matches == 2);
    CHECK(w.out.stop == fbh::StopReason::none);
    CHECK_FALSE(w.out.trailer_needed());
    CHECK_FALSE(w.out.constrained());
}

TEST_CASE("find_by_hash format_match_row: the shared row-field escaping", "[find_by_hash]") {
    CHECK(fbh::format_match_row("/tmp/a.txt", 12) == "match|/tmp/a.txt|12");
    CHECK(fbh::format_match_row("a\nb\rc", 1) == "match|a b c|1");         // CR/LF fold to a space
    CHECK(fbh::format_match_row("a|b", 1) == "match|a\\|b|1");             // '|' is escaped
    CHECK(fbh::format_match_row("C:\\dir\\f", 5) == "match|C:\\dir\\f|5"); // interior: untouched
    CHECK(fbh::format_match_row("foo\\", 3) == "match|foo/|3");    // trailing backslash folds
    CHECK(fbh::format_match_row("a\\|b", 3) == "match|a\\\\|b|3"); // interior before a pipe
}

TEST_CASE("find_by_hash format_trailer: every stop token and the none case", "[find_by_hash]") {
    const struct {
        fbh::StopReason reason;
        const char* token;
    } cases[] = {
        {fbh::StopReason::none, "none"},           {fbh::StopReason::deadline, "deadline"},
        {fbh::StopReason::file_cap, "file_cap"},   {fbh::StopReason::byte_cap, "byte_cap"},
        {fbh::StopReason::cancelled, "cancelled"}, {fbh::StopReason::max_results, "max_results"}};
    for (const auto& c : cases) {
        fbh::WalkOutcome o;
        o.stop = c.reason;
        o.c.visited = 7;
        o.c.hashed_bytes = 4096;
        o.c.skipped_unreadable = 1;
        o.c.skipped_symlink = 2;
        o.c.skipped_not_regular = 3;
        o.c.skipped_oversize = 4;
        o.c.skipped_network_mount = 5;
        CHECK(fbh::format_trailer(o) ==
              std::string{"truncated|"} + c.token +
                  "|visited=7|hashed=4096|skipped_unreadable=1|skipped_symlink=2|"
                  "skipped_not_regular=3|skipped_oversize=4|skipped_network_mount=5");
    }
}

TEST_CASE("find_by_hash trailer_needed / constrained: the two predicates differ on by-design skips",
          "[find_by_hash]") {
    fbh::WalkOutcome o;
    CHECK_FALSE(o.trailer_needed());
    CHECK_FALSE(o.constrained());
    o.c.skipped_symlink = 1;
    CHECK(o.trailer_needed());
    CHECK_FALSE(o.constrained());
    o = {};
    o.c.skipped_not_regular = 1;
    CHECK(o.trailer_needed());
    CHECK_FALSE(o.constrained());
    o = {};
    o.c.skipped_oversize = 1;
    CHECK(o.trailer_needed());
    CHECK_FALSE(o.constrained());
    o = {};
    o.c.skipped_unreadable = 1;
    CHECK(o.trailer_needed());
    CHECK(o.constrained());
    o = {};
    o.c.skipped_network_mount = 1;
    CHECK(o.trailer_needed());
    CHECK(o.constrained());
    o = {};
    o.stop = fbh::StopReason::max_results;
    CHECK(o.trailer_needed());
    CHECK(o.constrained());
}

TEST_CASE("find_by_hash constrained_reason: the provenance names the first applicable cause",
          "[find_by_hash]") {
    fbh::WalkOutcome o;
    o.c.skipped_network_mount = 1;
    CHECK(fbh::constrained_reason(o) == "filesystem:skipped_network_mount");
    o.c.skipped_unreadable = 1; // unreadable outranks a mount skip
    CHECK(fbh::constrained_reason(o) == "filesystem:skipped_unreadable");
    o.stop = fbh::StopReason::deadline; // a tripped bound outranks both
    CHECK(fbh::constrained_reason(o) == "filesystem:deadline");
    o.stop = fbh::StopReason::max_results;
    CHECK(fbh::constrained_reason(o) == "filesystem:max_results");
}

// -- Streaming hasher (POSIX) -------------------------------------------------------------------

#ifndef _WIN32

TEST_CASE("find_by_hash hash_stream: an interrupted read re-checks cancel before it is retried",
          "[find_by_hash]") {
    // A signal storm: every read is interrupted. The retry loop must honour cancel / deadline,
    // otherwise a cancelled hash never ends. The fake gives up (EOF) after 1000 reads so a
    // broken loop FAILS this test rather than hanging the suite.
    int reads = 0;
    fbh::WalkCounters c;
    fbh::HashBudget budget{fbh::WalkLimits{}, [] { return fbh::Clock::now(); },
                           [&reads] { return reads >= 3; }, c};
    const auto got = fbh::hash_stream(
        [&reads](unsigned char*, std::size_t) -> long long {
            ++reads;
            if (reads > 1000)
                return 0;
            errno = EINTR;
            return -1;
        },
        budget, 0);
    CHECK(got.kind == fbh::HashKind::stopped);
    CHECK(reads == 3);
    CHECK(budget.stop() == fbh::StopReason::cancelled);
}

TEST_CASE("find_by_hash hash_stream: digest, byte cap and read errors", "[find_by_hash]") {
    const std::string data = "the quick brown fox jumps over the lazy dog";
    const auto source = [&data](std::size_t chunk) {
        return [&data, chunk, off = std::size_t{0}](unsigned char* buf,
                                                    std::size_t len) mutable -> long long {
            const auto n = std::min({chunk, len, data.size() - off});
            std::copy_n(data.data() + off, n, buf);
            off += n;
            return static_cast<long long>(n);
        };
    };
    {
        fbh::WalkCounters c;
        fbh::HashBudget b{fbh::WalkLimits{}, [] { return fbh::Clock::now(); }, [] { return false; },
                          c};
        const auto got = fbh::hash_stream(source(7), b, data.size());
        REQUIRE(got.kind == fbh::HashKind::hashed);
        CHECK(got.hex == yuzu::shared::sha256_hex(data));
        CHECK(got.size == data.size());
        CHECK(c.hashed_bytes == data.size());
    }
    {
        fbh::WalkCounters c;
        fbh::WalkLimits lim;
        lim.max_bytes_hashed = 20;
        fbh::HashBudget b{lim, [] { return fbh::Clock::now(); }, [] { return false; }, c};
        const auto got = fbh::hash_stream(source(7), b, data.size());
        CHECK(got.kind == fbh::HashKind::stopped);
        CHECK(b.stop() == fbh::StopReason::byte_cap);
        CHECK(c.hashed_bytes == 14); // two 7-byte chunks admitted, the third would pass 20
    }
    {
        fbh::WalkCounters c;
        fbh::HashBudget b{fbh::WalkLimits{}, [] { return fbh::Clock::now(); }, [] { return false; },
                          c};
        const auto got = fbh::hash_stream(
            [](unsigned char*, std::size_t) -> long long {
                errno = EIO;
                return -1;
            },
            b, 0);
        CHECK(got.kind == fbh::HashKind::unreadable);
    }
}

#endif // !_WIN32
