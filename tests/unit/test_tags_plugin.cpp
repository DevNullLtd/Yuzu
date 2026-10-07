/**
 * test_tags_plugin.cpp -- TU-inclusion seam over tags_plugin.cpp (#4728):
 * drives save_tags()/load_tags() directly, so the tags plugin's move onto the
 * shared atomic write is proven without loading the plugin or running init().
 * Same seam as test_asset_tags_sync_lock.cpp: the plugin's C export is renamed
 * away so this executable does not define `yuzu_plugin_descriptor`, and the
 * anonymous-namespace globals (`g_tags`, `g_tags_path`) are reachable here.
 *
 * Nothing in this file exercises execute(); only the persistence path.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/plugin.hpp>

#include "test_helpers.hpp"

#undef YUZU_PLUGIN_EXPORT
#define YUZU_PLUGIN_EXPORT(ClassName) /* no C export in the test executable */
#include "tags_plugin.cpp"
#undef YUZU_PLUGIN_EXPORT

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

namespace tfs = std::filesystem;

std::size_t entry_count(const tfs::path& dir) {
    std::error_code ec;
    return static_cast<std::size_t>(
        std::distance(tfs::directory_iterator(dir, ec), tfs::directory_iterator{}));
}

} // namespace

TEST_CASE("tags: save_tags round-trips through load_tags and leaves no temp",
          "[agent][tags_plugin]") {
    yuzu::test::TempDir dir{"yuzu_test_tags_"};
    g_tags_path = dir.path / "tags.json"; // parent is created by the shared primitive
    yuzu::test::ScopeExit reset{[] {
        g_tags.clear();
        g_tags_path.clear();
    }};
    g_tags = {{"role", "web"}, {"env", "prod"}};

    REQUIRE(save_tags());
    const auto saved = g_tags;
    g_tags.clear();
    load_tags();

    CHECK(g_tags == saved);
    CHECK(entry_count(dir.path) == 1); // tags.json only: no `.tmp.*` sibling
}

#ifndef _WIN32
TEST_CASE("tags: save_tags creates the file at 0666 & ~umask, not 0600",
          "[agent][tags_plugin]") {
    yuzu::test::TempDir dir{"yuzu_test_tags_"};
    g_tags_path = dir.path / "tags.json";
    yuzu::test::ScopeExit reset{[] {
        g_tags.clear();
        g_tags_path.clear();
    }};
    g_tags = {{"k", "v"}};

    save_tags();

    const mode_t u = ::umask(0);
    ::umask(u);
    struct stat st{};
    REQUIRE(::stat(g_tags_path.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == (0666 & ~u));
}

TEST_CASE("tags: an existing 0600 tags.json keeps 0600 across save_tags", "[agent][tags_plugin]") {
    yuzu::test::TempDir dir{"yuzu_test_tags_"};
    g_tags_path = dir.path / "tags.json";
    yuzu::test::ScopeExit reset{[] {
        g_tags.clear();
        g_tags_path.clear();
    }};
    g_tags = {{"k", "v"}};
    REQUIRE(save_tags());
    REQUIRE(::chmod(g_tags_path.c_str(), 0600) == 0);

    g_tags["k"] = "w";
    REQUIRE(save_tags());

    struct stat st{};
    REQUIRE(::stat(g_tags_path.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    g_tags.clear();
    load_tags();
    CHECK(g_tags["k"] == "w");
}

TEST_CASE("tags: save_tags replaces tags.json by rename, never in place", "[agent][tags_plugin]") {
    yuzu::test::TempDir dir{"yuzu_test_tags_"};
    g_tags_path = dir.path / "tags.json";
    yuzu::test::ScopeExit reset{[] {
        g_tags.clear();
        g_tags_path.clear();
    }};
    g_tags = {{"a", "1"}};
    save_tags();

    // Hold the OLD file open across the second save. A rename swaps the directory
    // entry to a new inode and leaves the old one intact for its readers; a
    // truncating in-place write (the pre-#4728 behaviour) keeps the inode and
    // overwrites what the reader sees. Deterministic -- no reader races a writer.
    struct stat before{};
    REQUIRE(::stat(g_tags_path.c_str(), &before) == 0);
    const int old_fd = ::open(g_tags_path.c_str(), O_RDONLY);
    REQUIRE(old_fd >= 0);
    yuzu::test::ScopeExit close_old{[&] { ::close(old_fd); }};

    g_tags = {{"a", "2"}, {"b", "3"}};
    save_tags();

    struct stat after{};
    REQUIRE(::stat(g_tags_path.c_str(), &after) == 0);
    CHECK(after.st_ino != before.st_ino);

    struct stat old_now{};
    REQUIRE(::fstat(old_fd, &old_now) == 0);
    CHECK(old_now.st_nlink == 0); // the old inode was unlinked by the rename, not rewritten

    std::string old_view;
    char buf[256];
    for (ssize_t n = ::read(old_fd, buf, sizeof buf); n > 0; n = ::read(old_fd, buf, sizeof buf))
        old_view.append(buf, static_cast<std::size_t>(n));
    CHECK(old_view.find("\"a\": \"1\"") != std::string::npos); // wholly old
    CHECK(old_view.find("\"b\"") == std::string::npos);

    g_tags.clear();
    load_tags();
    CHECK(g_tags.count("b") == 1);
}
#endif

TEST_CASE("tags: a failed save returns false, is logged, does not throw, and leaves the parent "
          "untouched",
          "[agent][tags_plugin]") {
    yuzu::test::TempDir dir{"yuzu_test_tags_"};
    std::error_code ec;
    tfs::create_directories(dir.path, ec); // TempDir only reserves the name
    REQUIRE_FALSE(ec);
    const auto blocker = dir.path / "blocker";
    {
        std::ofstream f(blocker, std::ios::binary);
        f << "x";
    }
    g_tags_path = blocker / "tags.json"; // parent is a regular file
    yuzu::test::ScopeExit reset{[] {
        g_tags.clear();
        g_tags_path.clear();
    }};
    g_tags = {{"k", "v"}};

    CHECK_FALSE(save_tags());

    std::ifstream in(blocker, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(bytes == "x");
    CHECK(entry_count(dir.path) == 1);
}
