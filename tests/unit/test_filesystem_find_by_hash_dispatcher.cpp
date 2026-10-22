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

#include <sha256.hpp>

#include <cctype>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
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

#ifndef _WIN32

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
