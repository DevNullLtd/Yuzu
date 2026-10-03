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
#include <sys/stat.h>
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

    save_tags();
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
#endif

TEST_CASE("tags: a failed save is logged, does not throw, and leaves the parent untouched",
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

    CHECK_NOTHROW(save_tags());

    std::ifstream in(blocker, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(bytes == "x");
    CHECK(entry_count(dir.path) == 1);
}
