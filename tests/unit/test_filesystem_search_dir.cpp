/**
 * test_filesystem_search_dir.cpp -- the search_dir core over the shared bounded walk (#6478).
 *
 * The walk is driven with injected fakes (clock, cancel predicate, directory probe, mount list), so
 * every bound is exercised without a sleep, a process or the network. The real plugin through
 * LocalDispatcher is test_filesystem_search_dir_dispatcher.cpp.
 *
 * MUTATION NOTES (what each case catches):
 *   clean run        -- walk_search_dir not honouring MatchType, or a wrong row shape.
 *   depth            -- the old separator-count depth test (a directory AT max_depth was opened).
 *   deadline / cap / cancel / max_results -- search_dir lacking the walker's bound, or a
 *                       max_results stop with nothing left to look at (the look-ahead).
 *   symlinks / FIFO / junction -- entry classification through is_directory() (stats THROUGH a
 *                       link) instead of symlink_status.
 *   unreadable       -- a probe refusal turned into a silent skip.
 *   mounts           -- the mount check running after a stat, or the guard row missing.
 *   escaping         -- a row built without acl::row_field (separator injection, invalid UTF-8,
 *                       a trailing backslash); the formatter's file suffix.
 *   closing rows     -- search_dir's count row carrying fbh::format_outcome_rows' default label
 *                       (matches_found) instead of its own (total_matches); the guard row, trailer
 *                       and count ORDER is pinned in test_filesystem_find_by_hash.cpp.
 *   dataless policy  -- walk_bounded not switching the thread's dataless-materialization policy off
 *                       before its first touch of the root (the first probe call and the name
 *                       predicate would read the default), or not restoring it.
 *
 * UNGUARDED TU on every OS; the symlink and FIFO cases are #ifndef _WIN32, the junction case is
 * #ifdef _WIN32, the dataless-policy case is #ifdef __APPLE__ and the raw-byte-name case is
 * #ifdef __linux__.
 */
#include <catch2/catch_test_macros.hpp>

#include "filesystem_dispatcher_test_support.hpp"
#include "filesystem_search_dir.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/resource.h> // getiopolicy_np
#endif
#endif

namespace fbh = yuzu::filesystem::find_by_hash;
namespace sd = yuzu::filesystem::search_dir;
namespace fs = std::filesystem;

using yuzu::test::filesystem_dispatcher_support::Tree;
#ifdef _WIN32
using yuzu::test::filesystem_dispatcher_support::create_junction;
using yuzu::test::filesystem_dispatcher_support::JunctionCleanup;
#endif

namespace {

struct Probe {
    std::vector<fs::path> entered;
};

fbh::WalkEnv fake_env(Probe& probe) {
    fbh::WalkEnv env;
    env.can_enter = [&probe](const fs::path& p) {
        probe.entered.push_back(p);
        return true;
    };
    return env;
}

struct Walked {
    fbh::WalkOutcome out;
    std::vector<std::string> rows;
    [[nodiscard]] std::vector<std::string> sorted() const {
        auto r = rows;
        std::sort(r.begin(), r.end());
        return r;
    }
};

const std::function<bool(std::string_view)> kAnyName = [](std::string_view) {
    return true;
};

Walked walk(const Tree& t, sd::MatchType type, int max_depth, const fbh::WalkLimits& limits,
            const fbh::WalkEnv& env,
            const std::function<bool(std::string_view)>& pred = kAnyName) {
    Walked w;
    w.out = sd::walk_search_dir(t.str(), pred, type, max_depth, limits, env,
                                [&w](const std::string& row) { w.rows.push_back(row); });
    return w;
}

std::string row_of(const fs::path& p, bool dir) {
    return sd::format_result_row(p.string(), dir);
}

std::vector<std::string> sorted_of(std::vector<std::string> v) {
    std::sort(v.begin(), v.end());
    return v;
}

} // namespace

// -- Vocabulary and closing rows ------------------------------------------------------------------

TEST_CASE("search_dir: parse_match_type accepts exactly the three documented values",
          "[filesystem][search_dir]") {
    CHECK(sd::parse_match_type("directories") == sd::MatchType::directories);
    CHECK(sd::parse_match_type("files") == sd::MatchType::files);
    CHECK(sd::parse_match_type("both") == sd::MatchType::both);
    CHECK(!sd::parse_match_type("").has_value());
    CHECK(!sd::parse_match_type("file").has_value());
    CHECK(!sd::parse_match_type("Directories").has_value());
}

TEST_CASE("search_dir: the closing count row carries search_dir's own label",
          "[filesystem][search_dir]") {
    fbh::WalkOutcome o;
    o.matches = 3;
    CHECK(fbh::format_outcome_rows(o, sd::kCountLabel) ==
          std::vector<std::string>{"total_matches|3"});
}

TEST_CASE("search_dir: limits_for uses the search_dir entry cap and the caller's max_results",
          "[filesystem][search_dir]") {
    const auto l = sd::limits_for(7);
    CHECK(l.max_files_visited == sd::kMaxEntriesVisited);
    CHECK(l.max_results == 7);
    CHECK(l.deadline == fbh::kWalkDeadline);
}

// -- Clean runs and depth -------------------------------------------------------------------------

TEST_CASE("search_dir: match_type files, directories and both give the exact rows",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("top.txt");
    t.write("d1/inner.txt");
    Probe probe;
    const auto env = fake_env(probe);

    const auto files = walk(t, sd::MatchType::files, 5, sd::limits_for(100), env);
    CHECK(files.sorted() == sorted_of({row_of(t.root / "top.txt", false),
                                       row_of(t.root / "d1" / "inner.txt", false)}));
    CHECK(files.out.matches == 2);
    CHECK(!files.out.trailer_needed());
    CHECK(!files.out.constrained());

    const auto dirs = walk(t, sd::MatchType::directories, 5, sd::limits_for(100), env);
    CHECK(dirs.rows == std::vector<std::string>{row_of(t.root / "d1", true)});
    CHECK(dirs.out.matches == 1);
    CHECK(!dirs.out.trailer_needed());
    CHECK(!dirs.out.constrained());

    const auto both = walk(t, sd::MatchType::both, 5, sd::limits_for(100), env);
    CHECK(both.sorted() == sorted_of({row_of(t.root / "top.txt", false),
                                      row_of(t.root / "d1", true),
                                      row_of(t.root / "d1" / "inner.txt", false)}));
    CHECK(both.out.matches == 3);
    CHECK(!both.out.trailer_needed());
    CHECK(!both.out.constrained());
}

TEST_CASE("search_dir: the predicate sees the bare name, not the path", "[filesystem][search_dir]") {
    Tree t;
    t.write("keep/target.txt");
    t.write("other.txt");
    Probe probe;
    const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), fake_env(probe),
                        [](std::string_view n) { return n == "target.txt"; });
    CHECK(w.rows == std::vector<std::string>{row_of(t.root / "keep" / "target.txt", false)});
}

TEST_CASE("search_dir: root children are depth 1; a directory AT max_depth is matched, never opened",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("a/b/c.txt");
    {
        Probe probe;
        const auto w = walk(t, sd::MatchType::both, 1, sd::limits_for(100), fake_env(probe));
        CHECK(w.rows == std::vector<std::string>{row_of(t.root / "a", true)});
        // only the root was ever asked of the probe: no subdirectory was opened
        CHECK(probe.entered == std::vector<fs::path>{t.root});
    }
    {
        Probe probe;
        const auto w = walk(t, sd::MatchType::both, 2, sd::limits_for(100), fake_env(probe));
        CHECK(w.sorted() == sorted_of({row_of(t.root / "a", true),
                                       row_of(t.root / "a" / "b", true)}));
        // a/b sits at depth 2 = max_depth: matched, not entered
        CHECK(probe.entered == std::vector<fs::path>{t.root, t.root / "a"});
    }
    {
        Probe probe;
        const auto w = walk(t, sd::MatchType::files, 3, sd::limits_for(100), fake_env(probe));
        CHECK(w.rows == std::vector<std::string>{row_of(t.root / "a" / "b" / "c.txt", false)});
    }
}

// -- Bounds ---------------------------------------------------------------------------------------

TEST_CASE("search_dir: an injected clock past the deadline stops the walk and constrains",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("a.txt");
    t.write("b.txt");
    t.write("c.txt");
    Probe probe;
    auto env = fake_env(probe);
    fbh::Clock::time_point now{};
    env.now = [&now] { return now; };
    // the first name looked at moves the clock past the deadline
    const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), env,
                        [&now](std::string_view) {
                            now += fbh::kWalkDeadline + std::chrono::milliseconds{1};
                            return true;
                        });
    CHECK(w.out.stop == fbh::StopReason::deadline);
    CHECK(w.out.c.visited == 1);
    CHECK(w.out.matches == 1);
    CHECK(w.out.constrained());
    CHECK(fbh::format_outcome_rows(w.out).front().rfind("truncated|deadline|visited=1|", 0) == 0);
}

TEST_CASE("search_dir: the entry cap trips as file_cap with exact counters; a tree at the cap is clean",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("a.txt");
    t.write("b.txt");
    t.write("c.txt");
    Probe probe;
    auto limits = sd::limits_for(100);
    limits.max_files_visited = 2;
    const auto capped = walk(t, sd::MatchType::files, 5, limits, fake_env(probe));
    CHECK(capped.out.stop == fbh::StopReason::file_cap);
    CHECK(capped.out.c.visited == 2);
    CHECK(capped.out.matches == 2);
    CHECK(capped.out.constrained());

    limits.max_files_visited = 3;
    const auto exact = walk(t, sd::MatchType::files, 5, limits, fake_env(probe));
    CHECK(exact.out.stop == fbh::StopReason::none);
    CHECK(exact.out.c.visited == 3);
    CHECK(!exact.out.trailer_needed());
}

TEST_CASE("search_dir: a cancel that flips mid-walk ends it as cancelled", "[filesystem][search_dir]") {
    Tree t;
    t.write("a.txt");
    t.write("b.txt");
    Probe probe;
    auto env = fake_env(probe);
    bool cancel = false;
    env.cancelled = [&cancel] { return cancel; };
    const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), env,
                        [&cancel](std::string_view) {
                            cancel = true;
                            return true;
                        });
    CHECK(w.out.stop == fbh::StopReason::cancelled);
    CHECK(w.out.c.visited == 1);
    CHECK(w.out.constrained());
}

TEST_CASE("search_dir: max_results truncates only when entries remain", "[filesystem][search_dir]") {
    {
        Tree t; // files
        t.write("a.txt");
        t.write("b.txt");
        Probe probe;
        const auto cut = walk(t, sd::MatchType::files, 5, sd::limits_for(1), fake_env(probe));
        CHECK(cut.out.stop == fbh::StopReason::max_results);
        CHECK(cut.rows.size() == 1);
        const auto exact = walk(t, sd::MatchType::files, 5, sd::limits_for(2), fake_env(probe));
        CHECK(exact.out.stop == fbh::StopReason::none);
        CHECK(exact.rows.size() == 2);
    }
    {
        Tree t; // directories
        fs::create_directories(t.root / "d1");
        fs::create_directories(t.root / "d2");
        Probe probe;
        const auto cut = walk(t, sd::MatchType::directories, 5, sd::limits_for(1), fake_env(probe));
        CHECK(cut.out.stop == fbh::StopReason::max_results);
        const auto exact =
            walk(t, sd::MatchType::directories, 5, sd::limits_for(2), fake_env(probe));
        CHECK(exact.out.stop == fbh::StopReason::none);
        CHECK(exact.rows.size() == 2);
    }
}

// -- Skips ----------------------------------------------------------------------------------------

#ifndef _WIN32

TEST_CASE("search_dir: symlinks are counted, never matched and never followed",
          "[filesystem][search_dir]") {
    Tree t;
    const auto real = t.write("real/file.txt");
    fs::create_symlink(real, t.root / "filelink");
    fs::create_symlink(t.root / "real", t.root / "dirlink");
    fs::create_symlink(t.root, t.root / "real" / "loop");
    Probe probe;
    const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), fake_env(probe));
    CHECK(w.sorted() == sorted_of({row_of(t.root / "real", true),
                                   row_of(t.root / "real" / "file.txt", false)}));
    CHECK(w.out.c.skipped_symlink == 3);
    CHECK(w.out.trailer_needed());
    CHECK(!w.out.constrained()); // a by-design exclusion does not constrain
}

TEST_CASE("search_dir: a FIFO is counted skipped_not_regular and never matched as a file",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("plain.txt");
    REQUIRE(::mkfifo((t.root / "pipe").c_str(), 0600) == 0);
    Probe probe;
    const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), fake_env(probe));
    CHECK(w.rows == std::vector<std::string>{row_of(t.root / "plain.txt", false)});
    CHECK(w.out.c.skipped_not_regular == 1);
}

#else

TEST_CASE("search_dir: a junction is counted and never entered", "[filesystem][search_dir]") {
    Tree t;
    t.write("real/file.txt");
    const fs::path link = t.root / "link";
    REQUIRE(create_junction(link, t.root / "real"));
    const JunctionCleanup cleanup{link};
    Probe probe;
    const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), fake_env(probe));
    CHECK(w.sorted() == sorted_of({row_of(t.root / "real", true),
                                   row_of(t.root / "real" / "file.txt", false)}));
    CHECK(w.out.c.skipped_symlink == 1);
}

#endif

TEST_CASE("search_dir: a directory the probe refuses is counted and constrains, its name still matches",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("locked/inside.txt");
    Probe probe;
    auto env = fake_env(probe);
    const fs::path locked = t.root / "locked";
    env.can_enter = [&locked](const fs::path& p) { return p != locked; };
    const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), env);
    CHECK(w.rows == std::vector<std::string>{row_of(locked, true)});
    CHECK(w.out.c.skipped_unreadable == 1);
    CHECK(w.out.constrained());
}

TEST_CASE("search_dir: mounts are refused before any hook runs and before symlink_status",
          "[filesystem][search_dir]") {
    Tree t;
    t.write("net/inside.txt");
    t.write("local.txt");
    {
        // the root itself on a mount: refused, no hook consulted
        Probe probe;
        auto env = fake_env(probe);
        env.network_mounts = {t.str()};
        const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), env);
        CHECK(w.rows.empty());
        CHECK(w.out.c.skipped_network_mount == 1);
        CHECK(w.out.c.visited == 0);
        CHECK(probe.entered.empty());
        CHECK(w.out.constrained());
    }
    {
        // a mount point under the walk: skipped, neither matched nor entered
        Probe probe;
        auto env = fake_env(probe);
        env.network_mounts = {(t.root / "net").string()};
        const auto w = walk(t, sd::MatchType::both, 5, sd::limits_for(100), env);
        CHECK(w.rows == std::vector<std::string>{row_of(t.root / "local.txt", false)});
        CHECK(w.out.c.skipped_network_mount == 1);
        CHECK(probe.entered == std::vector<fs::path>{t.root});
        CHECK(w.out.constrained());
    }
    {
        // an unreadable mount table: the walk still runs, constrained, the guard row first
        Probe probe;
        auto env = fake_env(probe);
        env.mount_table_complete = false;
        const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), env);
        CHECK(w.out.matches == 2);
        CHECK(w.out.mount_table_incomplete);
        CHECK(w.out.constrained());
        CHECK(fbh::format_outcome_rows(w.out).front() == "network_mount_guard|unavailable");
    }
}

#ifdef __APPLE__
TEST_CASE("search_dir: the walk switches dataless materialization off from its first touch and restores it",
          "[filesystem][search_dir]") {
    // The policy is per THREAD and the walk runs on this one, so the walk's own hooks (the probe,
    // the name predicate) can read it while the walk is in progress.
    const auto policy = [] {
        return ::getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD);
    };
    const int before = policy();
    REQUIRE(before != IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
    Tree t;
    t.write("only.txt");
    std::vector<int> at_probe;
    std::vector<int> at_name;
    fbh::WalkEnv env;
    env.can_enter = [&at_probe, &policy](const fs::path&) {
        at_probe.push_back(policy());
        return true;
    };
    const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), env,
                        [&at_name, &policy](std::string_view) {
                            at_name.push_back(policy());
                            return true;
                        });
    REQUIRE(w.rows.size() == 1);
    REQUIRE(at_probe.size() == 1); // the root probe: the walk's first touch of the filesystem
    CHECK(at_probe.front() == IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
    REQUIRE(at_name.size() == 1);
    CHECK(at_name.front() == IOPOL_MATERIALIZE_DATALESS_FILES_OFF);
    CHECK(policy() == before);
}
#endif

// -- Escaping -------------------------------------------------------------------------------------

TEST_CASE("search_dir: result rows go through row_field", "[filesystem][search_dir]") {
    // One name with a pipe, CR LF, a byte that is not UTF-8 (0xFF) and a trailing backslash:
    // row_field escapes the pipe, folds CR LF to two spaces, shows the bad byte as '?' and folds
    // the backslash to '/' (the split literal stops the hex escape swallowing the 'd').
    CHECK(sd::format_result_row("/r/a|b\r\nc\xff" "d\\", true) ==
          "result|/r/a\\|b  c?d/|directory");
    // the only every-OS literal pin of the file suffix at this level (row_of calls the formatter)
    CHECK(sd::format_result_row("/r/plain.txt", false) == "result|/r/plain.txt|file");
}

#ifdef __linux__
TEST_CASE("search_dir: a real file whose name holds 0xFF is matched on its raw name and reported with '?'",
          "[filesystem][search_dir]") {
    Tree t;
    const std::string raw_name{"bad\xff" "name"};
    {
        std::ofstream f{t.root / fs::path{raw_name}};
        if (!f)
            SKIP("this filesystem refuses a file name that is not valid UTF-8");
    }
    Probe probe;
    const auto w = walk(t, sd::MatchType::files, 5, sd::limits_for(100), fake_env(probe),
                        [&raw_name](std::string_view n) { return n == raw_name; });
    CHECK(w.rows == std::vector<std::string>{"result|" + t.str() + "/bad?name|file"});
}
#endif
