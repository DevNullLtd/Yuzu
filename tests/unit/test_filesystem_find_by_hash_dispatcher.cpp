/**
 * test_filesystem_find_by_hash_dispatcher.cpp -- loads the ACTUAL built filesystem plugin via
 * PluginHandle::load and drives `find_by_hash` through yuzu::agent::LocalDispatcher (#5624), so
 * the real shell around the walk core runs on the build host: the parameter and root checks, the
 * real per-OS hasher and readability probe, the row order, the trailer and the typed result
 * status. test_filesystem_find_by_hash.cpp covers the walk core and its bounds with fakes.
 *
 * UNGUARDED TU on every OS; only the symlink / permission cases are #ifndef _WIN32.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/plugin.h>

#include "filesystem_dispatcher_test_support.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <network_fstype.hpp>
#include <sha256.hpp>

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <posix_secure_read.hpp>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/mount.h> // getmntinfo_r_np
#include <sys/param.h>
#endif
#endif

namespace fs = std::filesystem;

using yuzu::test::filesystem_dispatcher_support::captured_rows;
using yuzu::test::filesystem_dispatcher_support::load_or_fail;
using yuzu::test::filesystem_dispatcher_support::LoadedPlugin;
using yuzu::test::filesystem_dispatcher_support::Tree;
#ifndef _WIN32
using yuzu::test::filesystem_dispatcher_support::running_as_root;
#else
using yuzu::test::filesystem_dispatcher_support::create_junction;
using yuzu::test::filesystem_dispatcher_support::JunctionCleanup;
#endif

namespace {

/// The exact rows of a run that was refused for sitting on a network mount: nothing visited, one
/// skipped_network_mount, a zero count.
const std::vector<std::string>& mount_refusal_rows() {
    static const std::vector<std::string> rows{
        "truncated|none|visited=0|hashed=0|skipped_unreadable=0|skipped_symlink=0|"
        "skipped_not_regular=0|skipped_oversize=0|skipped_network_mount=1",
        "matches_found|0"};
    return rows;
}

yuzu::agent::LocalDispatcher::Result find_by_hash(const LoadedPlugin& p, const std::string& dir,
                                                  const std::string& sha256,
                                                  const char* max_depth = nullptr) {
    std::vector<YuzuParam> params{{"directory", dir.c_str()}, {"sha256", sha256.c_str()}};
    if (max_depth)
        params.push_back({"max_depth", max_depth});
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(p.descriptor, "find_by_hash", params);
}

} // namespace

TEST_CASE("filesystem find_by_hash: a clean run writes exactly the match row and the count",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const std::string content = "find me";
    const auto hit = t.write("sub/hit.txt", content);
    t.write("other.txt", "something else");
    const auto result = find_by_hash(*plugin, t.root.string(), yuzu::shared::sha256_hex(content));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{"match|" + hit.string() + "|" + std::to_string(content.size()),
                                   "matches_found|1"});
    // a clean run declares nothing: the agent derives the coarse status from rc alone
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

TEST_CASE("filesystem find_by_hash: the target digest is matched case-insensitively",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("hit.txt", "case");
    std::string upper = yuzu::shared::sha256_hex("case");
    for (auto& c : upper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    const auto result = find_by_hash(*plugin, t.root.string(), upper);
    CHECK(captured_rows(result.captured).back() == "matches_found|1");
}

TEST_CASE("filesystem find_by_hash: no match is a bare count",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("a.txt", "a");
    const auto result = find_by_hash(*plugin, t.root.string(), std::string(64, '0'));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) == std::vector<std::string>{"matches_found|0"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

TEST_CASE(
    "filesystem find_by_hash: max_depth bounds the walk and a bound reached by design is silent",
    "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("d1/deep.txt", "deep");
    const auto digest = yuzu::shared::sha256_hex("deep");
    const auto shallow = find_by_hash(*plugin, t.root.string(), digest, "1");
    CHECK(captured_rows(shallow.captured) == std::vector<std::string>{"matches_found|0"});
    CHECK(shallow.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    const auto deeper = find_by_hash(*plugin, t.root.string(), digest, "2");
    CHECK(captured_rows(deeper.captured).back() == "matches_found|1");
}

TEST_CASE("filesystem find_by_hash: empty files are hashed",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const auto empty = t.write("empty.txt", "");
    const auto result = find_by_hash(*plugin, t.root.string(), yuzu::shared::sha256_hex(""));
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{"match|" + empty.string() + "|0", "matches_found|1"});
}

TEST_CASE("filesystem find_by_hash: missing parameters and a bad root keep their error rows",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    {
        yuzu::agent::LocalDispatcher dispatcher;
        const auto result = dispatcher.run(plugin->descriptor, "find_by_hash");
        CHECK(result.rc == 1);
        CHECK(captured_rows(result.captured) ==
              std::vector<std::string>{"error|missing required parameters: directory, sha256"});
    }
    Tree t;
    const auto file = t.write("plain.txt", "x");
    const std::string digest(64, '0');
    {
        const auto result = find_by_hash(*plugin, file.string(), digest);
        CHECK(result.rc == 1);
        CHECK(captured_rows(result.captured) ==
              std::vector<std::string>{"error|path is not a directory"});
    }
    {
        const auto result = find_by_hash(*plugin, (t.root / "absent").string(), digest);
        CHECK(result.rc == 1);
        CHECK(captured_rows(result.captured) ==
              std::vector<std::string>{"error|directory is not accessible"});
    }
}

#ifdef _WIN32

TEST_CASE("filesystem find_by_hash: a UNC root is refused on its spelling, before validate_path",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    // \\yuzu-test-nowhere\share names no server. The refusal is decided on the spelling alone, so
    // it is exactly the refusal rows with rc 0. Were validate_path (exists / canonical, which
    // resolve the name) to run first, the answer would be `error|directory is not accessible`
    // with rc 1 after a name-resolution wait.
    const auto result = find_by_hash(*plugin, "\\\\yuzu-test-nowhere\\share", std::string(64, '0'));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) == mount_refusal_rows());
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "filesystem:skipped_network_mount");
}

TEST_CASE("filesystem find_by_hash: a junction is skipped by design -- trailer, still UNDECLARED",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const std::string content = "junctioned";
    const auto hit = t.write("tree/real/secret.txt", content);
    const fs::path link = t.root / "tree" / "link";
    REQUIRE(create_junction(link, t.root / "tree" / "real"));
    const JunctionCleanup cleanup{link}; // removes the junction itself, before the Tree goes
    const auto result = find_by_hash(*plugin, t.root.string(), yuzu::shared::sha256_hex(content));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{
              "match|" + hit.string() + "|" + std::to_string(content.size()),
              "truncated|none|visited=4|hashed=" + std::to_string(content.size()) +
                  "|skipped_unreadable=0|skipped_symlink=1|skipped_not_regular=0|"
                  "skipped_oversize=0|skipped_network_mount=0",
              "matches_found|1"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

#endif // _WIN32

#ifndef _WIN32

namespace {

/// The network mount points in the live kernel mount table, read from the test's side with the same
/// shared classifiers the plugin uses (Linux: /proc/self/mountinfo through network_mount_points;
/// macOS: getmntinfo_r_np through is_network_mount_fstype).
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

TEST_CASE("filesystem find_by_hash: a root on a live network mount is refused before it is touched",
          "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    const auto mounts = live_network_mounts();
    if (mounts.empty())
        SKIP("no network mount in the live mount table (the Windows UNC case pins the same rows)");
    // A name that exists nowhere under the mount. Were validate_path to run first it would answer
    // `error|directory is not accessible` (rc 1); the shell must refuse on the table alone.
    const std::string root = (fs::path(mounts.front()) / "yuzu_test_never_touched").string();
    const auto result = find_by_hash(*plugin, root, std::string(64, '0'));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) == mount_refusal_rows());
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "filesystem:skipped_network_mount");
}

TEST_CASE(
    "filesystem find_by_hash: a symlink is skipped by design -- trailer, but still UNDECLARED",
    "[filesystem][find_by_hash][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const std::string content = "linked";
    const auto hit = t.write("hit.txt", content);
    fs::create_symlink(t.root / "nowhere", t.root / "dangling");
    fs::create_symlink(hit, t.root / "alias.txt"); // would double-report a followed link
    const auto result = find_by_hash(*plugin, t.root.string(), yuzu::shared::sha256_hex(content));
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{
              "match|" + hit.string() + "|" + std::to_string(content.size()),
              "truncated|none|visited=3|hashed=" + std::to_string(content.size()) +
                  "|skipped_unreadable=0|skipped_symlink=2|skipped_not_regular=0|"
                  "skipped_oversize=0|skipped_network_mount=0",
              "matches_found|1"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
}

TEST_CASE("filesystem find_by_hash: an unreadable subdirectory is CONSTRAINED / PARTIAL",
          "[filesystem][find_by_hash][dispatcher]") {
    if (running_as_root())
        SKIP("root lists a mode-000 directory; the unreadable case needs an unprivileged user");
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    const std::string content = "visible";
    const auto hit = t.write("hit.txt", content);
    t.write("locked/inside.txt", "hidden");
    REQUIRE(::chmod((t.root / "locked").c_str(), 0) == 0);
    const auto result = find_by_hash(*plugin, t.root.string(), yuzu::shared::sha256_hex(content));
    ::chmod((t.root / "locked").c_str(), 0700);
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{
              "match|" + hit.string() + "|" + std::to_string(content.size()),
              "truncated|none|visited=2|hashed=" + std::to_string(content.size()) +
                  "|skipped_unreadable=1|skipped_symlink=0|skipped_not_regular=0|"
                  "skipped_oversize=0|skipped_network_mount=0",
              "matches_found|1"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "filesystem:skipped_unreadable");
}

TEST_CASE(
    "filesystem find_by_hash: an unreadable ROOT is CONSTRAINED / PARTIAL, never a clean zero",
    "[filesystem][find_by_hash][dispatcher]") {
    if (running_as_root())
        SKIP("root lists a mode-000 directory; the unreadable case needs an unprivileged user");
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    Tree t;
    t.write("f.txt", "x");
    REQUIRE(::chmod(t.root.c_str(), 0) == 0);
    const auto result = find_by_hash(*plugin, t.root.string(), std::string(64, '0'));
    ::chmod(t.root.c_str(), 0700);
    CHECK(result.rc == 0);
    CHECK(captured_rows(result.captured) ==
          std::vector<std::string>{
              "truncated|none|visited=0|hashed=0|skipped_unreadable=1|skipped_symlink=0|"
              "skipped_not_regular=0|skipped_oversize=0|skipped_network_mount=0",
              "matches_found|0"});
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "filesystem:skipped_unreadable");
}

#endif // !_WIN32
