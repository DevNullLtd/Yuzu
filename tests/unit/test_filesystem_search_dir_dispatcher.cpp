/**
 * test_filesystem_search_dir_dispatcher.cpp -- loads the ACTUAL built filesystem plugin via
 * PluginHandle::load and drives `search_dir` through yuzu::agent::LocalDispatcher (#6478), so the
 * real shell around the walk core runs on the build host: the parameter and root checks, the
 * mount refusal that precedes validate_path, the real per-OS readability probe, the regex bound,
 * the row order, the trailer and the typed result status. test_filesystem_search_dir.cpp covers
 * the walk core and its bounds with fakes.
 *
 * MUTATION NOTES (what each case catches):
 *   clean run / error rows -- a shell that reorders its checks or changes an existing error row.
 *   regex bound            -- a regex compile without the GNU library's __polynomial flag, or a
 *                             regex_error escaping the name predicate (the suite timeout is the
 *                             oracle: no sleep, no timer).
 *   lookahead refusal      -- a regex lookahead reaching the engine (the has_lookahead check
 *                             dropped from the shell, or applied in glob mode).
 *   shutdown latch         -- search_dir not wired to the agent's cancel signal.
 *   mount refusal          -- validate_path running before the mount check (a dead mount blocks),
 *                             for the root AND for the base_dir arm (a base_dir on a mount that is
 *                             not looked at, or looked at after validate_path's canonical call).
 *   error order            -- a root check that runs before the parameter checks (a bad root with a
 *                             bad parameter must answer the parameter error).
 *   dataless policy        -- the restore after the walk; that the walk switches it off at all is
 *                             pinned at the core, test_filesystem_search_dir.cpp.
 *   trailer / status       -- a skip that is not reported, or reported with the wrong status.
 *   unpaired surrogate     -- a name conversion that throws on a Windows name with no UTF-8 form:
 *                             such a name ended the whole walk with an error row.
 *
 * UNGUARDED TU on every OS; the symlink, permission and live-mount cases are #ifndef _WIN32, the
 * UNC cases and the unpaired-surrogate case are #ifdef _WIN32, the dataless-policy case is
 * #ifdef __APPLE__, and the back-reference case and an arm of the ambiguous-alternation case are
 * #if defined(__GLIBCXX__).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.h>

#include "filesystem_dispatcher_test_support.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <network_fstype.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <posix_secure_read.hpp>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/mount.h> // getmntinfo_r_np
#include <sys/param.h>
#include <sys/resource.h> // getiopolicy_np
#endif
#endif

namespace fs = std::filesystem;

using yuzu::test::filesystem_dispatcher_support::captured_rows;
using yuzu::test::filesystem_dispatcher_support::load_or_fail;
using yuzu::test::filesystem_dispatcher_support::LoadedPlugin;
using yuzu::test::filesystem_dispatcher_support::Tree;
#ifndef _WIN32
using yuzu::test::filesystem_dispatcher_support::running_as_root;
#endif

namespace {

using Rows = std::vector<std::string>;
using Args = std::vector<std::pair<std::string, std::string>>;

yuzu::agent::LocalDispatcher::Result search_dir(const LoadedPlugin& p, const Args& args) {
    std::vector<YuzuParam> params;
    params.reserve(args.size());
    for (const auto& [k, v] : args)
        params.push_back({k.c_str(), v.c_str()});
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(p.descriptor, "search_dir", params);
}

yuzu::agent::LocalDispatcher::Result search(const LoadedPlugin& p, const Tree& t,
                                            const std::string& pattern, Args extra = {}) {
    Args args{{"root", t.root.string()}, {"pattern", pattern}};
    args.insert(args.end(), extra.begin(), extra.end());
    return search_dir(p, args);
}

std::string trailer(const std::string& stop, int visited, int unreadable = 0, int symlink = 0,
                    int not_regular = 0, int network_mount = 0) {
    return "truncated|" + stop + "|visited=" + std::to_string(visited) +
           "|hashed=0|skipped_unreadable=" + std::to_string(unreadable) +
           "|skipped_symlink=" + std::to_string(symlink) +
           "|skipped_not_regular=" + std::to_string(not_regular) +
           "|skipped_oversize=0|skipped_network_mount=" + std::to_string(network_mount);
}

/// The exact rows of a run refused for sitting on a network mount.
Rows mount_refusal_rows() {
    return {trailer("none", 0, 0, 0, 0, 1), "total_matches|0"};
}

/// The five checks of a run refused on its mount spelling alone (the root and base_dir cases).
void check_mount_refusal(const yuzu::agent::LocalDispatcher::Result& r) {
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) == mount_refusal_rows());
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "filesystem:skipped_network_mount");
}

} // namespace

TEST_CASE("filesystem search_dir: a clean run writes exactly the result rows then the count",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("one.txt");
    const auto result = search(*plugin, t, "*.txt", {{"match_type", "files"}});
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          Rows{"result|" + (t.root / "one.txt").string() + "|file", "total_matches|1"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

TEST_CASE("filesystem search_dir: match_type defaults to directories", "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("sub/f.txt");
    const auto result = search(*plugin, t, "*");
    CHECK(captured_rows(result.captured) ==
          Rows{"result|" + (t.root / "sub").string() + "|directory", "total_matches|1"});
}

TEST_CASE("filesystem search_dir: error rows for bad parameters and roots",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const auto file = t.write("plain.txt");
    Tree other;
    {
        const auto r = search_dir(*plugin, {{"root", t.str()}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|missing required parameters: root, pattern"});
    }
    {
        const auto r = search(*plugin, t, "*", {{"match_type", "dirs"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|invalid match_type (expected directories, files or both)"});
    }
    {
        const auto r = search(*plugin, t, std::string(257, 'a'));
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) == Rows{"error|pattern too long (max 256 chars)"});
    }
    {
        // exactly at the cap: accepted (a glob that matches nothing here)
        const auto r = search(*plugin, t, std::string(256, 'a'));
        CHECK(r.rc == 0);
        CHECK(captured_rows(r.captured) == Rows{"total_matches|0"});
    }
    {
        const auto r = search_dir(*plugin, {{"root", (t.root / "absent").string()}, {"pattern", "*"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|root is not accessible or outside allowed base directory"});
    }
    {
        const auto r = search_dir(*plugin, {{"root", file.string()}, {"pattern", "*"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) == Rows{"error|root is not a directory"});
    }
    {
        const auto r = search(*plugin, t, "*", {{"base_dir", other.str()}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|root is not accessible or outside allowed base directory"});
    }
    {
        // a bad root AND a bad parameter: the parameter is judged first, before validate_path
        // touches the root
        const auto r = search_dir(
            *plugin,
            {{"root", (t.root / "absent").string()}, {"pattern", "*"}, {"match_type", "dirs"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|invalid match_type (expected directories, files or both)"});
    }
}

TEST_CASE("filesystem search_dir: regex mode matches, and a nested-quantifier regex is refused",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("foo.txt");
    t.write("bar.log");
    {
        const auto r = search(*plugin, t, "f.*\\.txt", {{"regex", "true"}, {"match_type", "files"}});
        CHECK(r.rc == 0);
        CHECK(captured_rows(r.captured) ==
              Rows{"result|" + (t.root / "foo.txt").string() + "|file", "total_matches|1"});
    }
    {
        const auto r = search(*plugin, t, "(a+)+", {{"regex", "true"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|regex contains nested quantifiers (potential ReDoS)"});
    }
    {
        const auto r = search(*plugin, t, std::string(257, 'a'), {{"regex", "true"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) == Rows{"error|pattern too long (max 256 chars)"});
    }
}

TEST_CASE("filesystem search_dir: a regex lookahead is refused before it reaches the engine",
          "[filesystem][search_dir][dispatcher]") {
    // Nesting depth 3 at most: unrefused, each pattern returns at once without the refusal row,
    // so a missing check FAILS this case and never hangs it. Deeper shapes are pinned on the pure
    // predicate (test_filesystem_search_dir.cpp) and never executed.
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write(std::string(48, 'a'));
    t.write("a.log");
    for (const std::string pattern : {"(?=.*(?=.*(?=.*x)))", "^(?!.*\\.bak$).*\\.log$"}) {
        INFO(pattern);
        const auto r = search(*plugin, t, pattern, {{"regex", "true"}, {"match_type", "files"}});
        CHECK(r.rc == 1);
        CHECK(captured_rows(r.captured) ==
              Rows{"error|regex lookahead is not supported (use (?: to group)"});
    }
    {
        // the non-capturing group is still accepted
        const auto r =
            search(*plugin, t, "^(?:a|b)\\.log$", {{"regex", "true"}, {"match_type", "files"}});
        CHECK(r.rc == 0);
        CHECK(captured_rows(r.captured) ==
              Rows{"result|" + (t.root / "a.log").string() + "|file", "total_matches|1"});
    }
    {
        // glob mode has no groups: the same bytes are an ordinary pattern that matches nothing here
        const auto r = search(*plugin, t, "(?=x)", {{"match_type", "files"}});
        CHECK(r.rc == 0);
        CHECK(captured_rows(r.captured) == Rows{"total_matches|0"});
    }
}

TEST_CASE("filesystem search_dir: an ambiguous-alternation regex over a long name RETURNS",
          "[filesystem][search_dir][dispatcher]") {
    // `(a|aa)+b` passes the nested-quantifier heuristic. With a backtracking executor one name of 64
    // 'a's would outlive the walk deadline; the suite timeout is the oracle here, no timer.
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write(std::string(64, 'a'));
    const auto r = search(*plugin, t, "(a|aa)+b", {{"regex", "true"}, {"match_type", "files"}});
#if defined(__GLIBCXX__)
    // the GNU library's breadth-first executor: a clean, empty answer
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) == Rows{"total_matches|0"});
#else
    // a library that gives up on a too-costly match: the run ends with the error row, last
    CHECK(r.rc == 1);
    const auto rows = captured_rows(r.captured);
    REQUIRE(!rows.empty());
    CHECK(rows.back() == "error|regex too complex for a file name (simplify the pattern)");
#endif
}

#if defined(__GLIBCXX__)
TEST_CASE("filesystem search_dir: a back-reference regex is refused at compile on the GNU library",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("aa");
    const auto r = search(*plugin, t, "(a)\\1", {{"regex", "true"}});
    CHECK(r.rc == 1);
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].rfind("error|invalid regex: ", 0) == 0);
}
#endif

TEST_CASE("filesystem search_dir: the shutdown latch stops the walk before it visits anything",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    // The latch is one process-wide flag in the agent core that the loaded plugin reads, so put
    // back whatever was there rather than clearing it.
    struct LatchRestore {
        const bool previous = yuzu::agent::subprocess_cancel_requested();
        ~LatchRestore() { yuzu::agent::request_subprocess_cancel(previous); }
    } latch_restore;
    Tree t;
    t.write("a.txt");
    yuzu::agent::request_subprocess_cancel(true);
    const auto r = search(*plugin, t, "*", {{"match_type", "files"}});
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) == Rows{trailer("cancelled", 0), "total_matches|0"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "filesystem:cancelled");
}

TEST_CASE("filesystem search_dir: max_results=1 over two matches is CONSTRAINED / PARTIAL",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("a.txt");
    t.write("b.txt");
    const auto r = search(*plugin, t, "*.txt", {{"match_type", "files"}, {"max_results", "1"}});
    CHECK(r.rc == 0);
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].rfind("result|", 0) == 0);
    CHECK(rows[1] == trailer("max_results", 1));
    CHECK(rows[2] == "total_matches|1");
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "filesystem:max_results");
}

TEST_CASE("filesystem search_dir: a non-ASCII name is reported as UTF-8",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const fs::path file = t.root / fs::path{std::u8string{u8"雪.txt"}};
    std::ofstream{file, std::ios::binary} << "x";
    const auto u8 = file.u8string();
    const auto r = search(*plugin, t, "*.txt", {{"match_type", "files"}});
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          Rows{"result|" + std::string{reinterpret_cast<const char*>(u8.data()), u8.size()} +
                   "|file",
               "total_matches|1"});
}

#ifdef _WIN32

TEST_CASE("filesystem search_dir: a UNC root is refused on its spelling, before validate_path",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    check_mount_refusal(
        search_dir(*plugin, {{"root", "\\\\yuzu-test-nowhere\\share"}, {"pattern", "*"}}));
}

TEST_CASE("filesystem search_dir: a UNC base_dir is refused on its spelling, before validate_path",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t; // a local root: only the base_dir arm can refuse this run
    check_mount_refusal(search(*plugin, t, "*", {{"base_dir", "\\\\yuzu-test-nowhere\\share"}}));
}

TEST_CASE("filesystem search_dir: a name with an unpaired surrogate does not end the walk",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const fs::path plain = t.write("plain.txt");
    // 'a', the unpaired high surrogate U+D800, 'b.txt': a name Windows accepts and UTF-8 cannot
    // hold. Created through the \\?\ spelling, which hands the name to the file system as it is.
    const std::wstring odd = L"\\\\?\\" + t.root.native() + L"\\a" +
                             std::wstring{static_cast<wchar_t>(0xD800)} + L"b.txt";
    {
        // Scoped: opened with no sharing, the file cannot be deleted until the handle closes.
        const yuzu::agent::confined_fs::WinHandle h{CreateFileW(
            odd.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
        REQUIRE(h.valid());
    }
    const yuzu::test::ScopeExit cleanup{[&odd] { DeleteFileW(odd.c_str()); }};
    // The other file is still found ...
    const auto other = search(*plugin, t, "plain*", {{"match_type", "files"}});
    CHECK(other.rc == 0);
    CHECK(captured_rows(other.captured) ==
          Rows{"result|" + plain.string() + "|file", "total_matches|1"});
    // ... and the odd one is matched and reported with U+FFFD in the surrogate's place.
    const auto lossy = search(*plugin, t, "a*b.txt", {{"match_type", "files"}});
    CHECK(lossy.rc == 0);
    CHECK(captured_rows(lossy.captured) ==
          Rows{"result|" + t.root.string() + "\\a\xEF\xBF\xBD" "b.txt|file", "total_matches|1"});
    // search_dir matches the name in that form: the reported name, given as the pattern, finds it.
    const auto shown = search(*plugin, t, "a\xEF\xBF\xBD" "b.txt", {{"match_type", "files"}});
    CHECK(captured_rows(shown.captured) == captured_rows(lossy.captured));
}

#else

namespace {

// ponytail: second copy of the helper in test_filesystem_find_by_hash_dispatcher.cpp; fold both
// into filesystem_dispatcher_test_support.hpp (follow-up: #8301).
/// The network mount points in the live kernel mount table, read from the test's side with the same
/// shared classifiers the plugin uses.
std::vector<std::string> live_network_mounts() {
#if defined(__linux__)
    constexpr std::size_t kMountinfoCap = 16 * 1024 * 1024;
    const auto table = yuzu::shared::read_file_no_follow("/proc/self/mountinfo", kMountinfoCap);
    if (!table.ok())
        return {};
    return yuzu::shared::network_mount_points(table.data);
#elif defined(__APPLE__)
    struct statfs* raw = nullptr;
    const int n = ::getmntinfo_r_np(&raw, MNT_NOWAIT);
    const std::unique_ptr<struct statfs, decltype(&::free)> table{raw, &::free};
    std::vector<std::string> out;
    for (int i = 0; raw != nullptr && i < n; ++i) {
        if (yuzu::shared::is_network_mount_fstype(table.get()[i].f_fstypename))
            out.emplace_back(table.get()[i].f_mntonname);
    }
    return out;
#else
    return {};
#endif
}

} // namespace

TEST_CASE("filesystem search_dir: a root on a live network mount is refused before it is touched",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    const auto mounts = live_network_mounts();
    if (mounts.empty())
        SKIP("no network mount in the live mount table (the Windows UNC case pins the same rows)");
    // A name that exists nowhere under the mount: were validate_path to run first the answer would
    // be an error row (rc 1); the shell must refuse on the table alone.
    const std::string root = (fs::path(mounts.front()) / "yuzu_test_never_touched").string();
    check_mount_refusal(search_dir(*plugin, {{"root", root}, {"pattern", "*"}}));
}

TEST_CASE("filesystem search_dir: a base_dir on a live network mount is refused before it is touched",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    const auto mounts = live_network_mounts();
    if (mounts.empty())
        SKIP("no network mount in the live mount table (the Windows UNC case pins the same rows)");
    // A local root: only the base_dir arm can refuse this run. Were validate_path to run first,
    // canonical(base_dir) would touch the mount and the answer would be an error row.
    Tree t;
    const std::string base = (fs::path(mounts.front()) / "yuzu_test_never_touched").string();
    check_mount_refusal(search(*plugin, t, "*", {{"base_dir", base}}));
}

TEST_CASE("filesystem search_dir: a symlink is skipped by design -- trailer, still UNDECLARED",
          "[filesystem][search_dir][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const auto real = t.write("real.txt");
    fs::create_symlink(real, t.root / "alias.txt"); // would double-report a followed link
    const auto r = search(*plugin, t, "*.txt", {{"match_type", "files"}});
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          Rows{"result|" + real.string() + "|file", trailer("none", 2, 0, 1), "total_matches|1"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

TEST_CASE("filesystem search_dir: an unreadable subdirectory is CONSTRAINED / PARTIAL",
          "[filesystem][search_dir][dispatcher]") {
    if (running_as_root())
        SKIP("root lists a mode-000 directory; the unreadable case needs an unprivileged user");
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("locked/inside.txt");
    REQUIRE(::chmod((t.root / "locked").c_str(), 0) == 0);
    yuzu::test::ScopeExit restore{[&] { ::chmod((t.root / "locked").c_str(), 0700); }};
    const auto r = search(*plugin, t, "*");
    CHECK(r.rc == 0);
    CHECK(captured_rows(r.captured) ==
          Rows{"result|" + (t.root / "locked").string() + "|directory", trailer("none", 1, 1),
               "total_matches|1"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "filesystem:skipped_unreadable");
}

#ifdef __APPLE__
TEST_CASE("filesystem search_dir: the dataless-materialization policy is restored after a run",
          "[filesystem][search_dir][dispatcher]") {
    // The walk switches this per-THREAD policy off and LocalDispatcher runs it on this thread, so
    // a missed restore would show here. This is the restore half through the real shell; that the
    // walk switches the policy off DURING the walk is observed at the core, in
    // test_filesystem_search_dir.cpp, where the walk's own hooks run on the walking thread.
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    const auto policy = [] {
        return ::getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD);
    };
    const int before = policy();
    Tree t;
    t.write("a.txt");
    CHECK(search(*plugin, t, "*").rc == 0);
    CHECK(policy() == before);
}
#endif

#endif // _WIN32
