/**
 * test_filesystem_local_dispatcher.cpp -- loads the ACTUAL built filesystem
 * plugin (filesystem.dylib/.so/.dll) via PluginHandle::load and drives
 * `replace` through yuzu::agent::LocalDispatcher (pattern:
 * test_filesystem_posture_local_dispatcher.cpp). #4728: `replace` is one of the
 * three production call sites of the plugin's atomic_write_file adapter over
 * yuzu::shared::write_file_atomic, and no other test reaches it (the
 * test_filesystem_actions.cpp helper suite exercises replicas, not the plugin).
 *
 * One case: the replacement lands, no temp sibling survives, and on POSIX the
 * file mode follows the umask (owner_only_mode=false at the production site).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the
// build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("filesystem plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("filesystem plugin library not found -- skipping LocalDispatcher round-trip test (run "
         "from the build root, or via `meson test`, to exercise it)");
}

fs::path find_filesystem_plugin() {
    const std::string lib_name = std::string{"filesystem"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "filesystem" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "filesystem" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "filesystem" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "filesystem" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "filesystem" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "filesystem" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

std::string read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("filesystem plugin: replace persists through the shared atomic write",
          "[agent][filesystem_plugin]") {
    auto handle = [&]() -> std::optional<yuzu::agent::PluginHandle> {
        auto path = find_filesystem_plugin();
        if (path.empty())
            return std::nullopt;
        auto h = yuzu::agent::PluginHandle::load(path);
        if (!h.has_value())
            return std::nullopt;
        return std::move(*h);
    }();
    if (!handle || !handle->descriptor()) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir dir{"yuzu_test_fs_replace_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec); // TempDir only reserves the name
    REQUIRE_FALSE(ec);
    const auto file = dir.path / "target.txt";
    {
        std::ofstream f(file, std::ios::binary);
        f << "hello world";
    }

    const std::string path_str = file.string();
    const std::array<YuzuParam, 3> params{
        {{"path", path_str.c_str()}, {"search", "world"}, {"replacement", "yuzu"}}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto r = dispatcher.run(handle->descriptor(), "replace", params);

    CHECK(r.rc == 0);
    CHECK(r.captured.find("replacements_made|1") != std::string::npos);
    CHECK(read_all(file) == "hello yuzu");

    // Exactly the one file: neither a `.tmp.*` nor a legacy `.yuzu_tmp` sibling.
    std::size_t entries = 0;
    for (const auto& e : fs::directory_iterator(dir.path, ec)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1);

#ifndef _WIN32
    const mode_t u = ::umask(0);
    ::umask(u);
    struct stat st{};
    REQUIRE(::stat(file.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == (0666 & ~u));
#endif
}
