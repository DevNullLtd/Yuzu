/**
 * test_filesystem_get_acl_dispatcher.cpp -- loads the ACTUAL built filesystem plugin via
 * PluginHandle::load and drives `get_acl` through yuzu::agent::LocalDispatcher, so the real
 * per-OS acquisition leg (Linux getxattr, macOS acl_get_file, Windows GetNamedSecurityInfo)
 * runs on the build host. test_filesystem_acl_parsers.cpp covers the decoders; this TU covers
 * the shell around them: the row order, the failure rows and, on Linux, the default-ACL-only
 * aggregation.
 *
 * UNGUARDED TU on every OS; only per-OS assertions inside a test body are #if'd.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <sys/xattr.h>
#endif

namespace fs = std::filesystem;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_plugin() {
    const std::string lib_name = std::string{"filesystem"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "filesystem" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "filesystem" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "filesystem" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "filesystem" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
};

/// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin is a broken build and
/// must not report "All tests passed".
std::optional<LoadedPlugin> load_or_fail() {
    auto path = find_plugin();
    if (!path.empty()) {
        if (auto loaded = yuzu::agent::PluginHandle::load(path)) {
            if (const auto* d = loaded->descriptor())
                return LoadedPlugin{std::move(*loaded), d};
        }
    }
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    const bool under_meson = std::getenv("MESON_BUILD_ROOT") != nullptr;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (under_meson)
        FAIL("filesystem plugin library not found under meson test -- it did not build, or "
             "link_depends is not forcing it to build before this test runs");
    WARN("filesystem plugin library not found -- skipping the LocalDispatcher round-trip");
    return std::nullopt;
}

yuzu::agent::LocalDispatcher::Result get_acl(const LoadedPlugin& p, const std::string& path) {
    const YuzuParam params[] = {{"path", path.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(p.descriptor, "get_acl", params);
}

fs::path make_file(const yuzu::test::TempDir& d) {
    fs::create_directories(d.path);
    auto f = d.path / "f";
    std::ofstream{f} << "x";
    return f;
}

}  // namespace

TEST_CASE("filesystem get_acl: a missing path parameter is refused", "[filesystem][acl][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "get_acl");
    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "error|missing required parameter: path");
}

TEST_CASE("filesystem get_acl: a path that does not exist is an error, not an empty ACL",
          "[filesystem][acl][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    yuzu::test::TempDir dir{"yuzu_test_acl_"};
    const auto result = get_acl(*plugin, (dir.path / "absent").string());
    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    CHECK(starts_with(rows.back(), "error|"));
    for (const auto& r : rows)
        CHECK_FALSE(starts_with(r, "acl|"));
}

TEST_CASE("filesystem get_acl: a plain file reports owner, mode and an acl row, rc 0",
          "[filesystem][acl][dispatcher]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    yuzu::test::TempDir dir{"yuzu_test_acl_"};
    const auto result = get_acl(*plugin, make_file(dir).string());
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows)
        CHECK_FALSE(starts_with(r, "error|"));
#if defined(_WIN32)
    CHECK(starts_with(rows[0], "sddl|"));
    bool control = false;
    for (const auto& r : rows)
        control = control || starts_with(r, "control|");
    CHECK(control);
#else
    REQUIRE(rows.size() >= 5);
    CHECK(starts_with(rows[0], "owner|"));
    CHECK(starts_with(rows[1], "group|"));
    CHECK(starts_with(rows[2], "permissions|"));
    CHECK(starts_with(rows[3], "mode|"));
    CHECK(starts_with(rows[4], "acl|"));  // none, extended or unsupported -- never absent
#endif
}

#if defined(__linux__)
TEST_CASE("filesystem get_acl: a directory with only a default ACL reports it as extended",
          "[filesystem][acl][dispatcher][linux]") {
    auto plugin = load_or_fail();
    if (!plugin)
        return;
    yuzu::test::TempDir dir{"yuzu_test_acl_"};
    fs::create_directories(dir.path);
    // The real captured default-ACL xattr (fixtures/wave11/filesystem_acl/linux).
    const std::string blob = [] {
        const std::string hex = "0200000001000700ffffffff02000700e903000004000500ffffffff"
                                "08000500ea03000010000700ffffffff20000500ffffffff";
        std::string out;
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
            out.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        return out;
    }();
    if (::setxattr(dir.path.c_str(), "system.posix_acl_default", blob.data(), blob.size(), 0) !=
        0) {
        WARN("filesystem under the temp dir does not accept POSIX ACL xattrs -- skipping");
        return;
    }
    const auto result = get_acl(*plugin, dir.path.string());
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);
    bool extended = false;
    std::size_t ace_rows = 0;
    for (const auto& r : rows) {
        extended = extended || r == "acl|extended|-";
        if (starts_with(r, "ace|")) {
            ++ace_rows;
            CHECK(r.size() > 8);
            CHECK(r.substr(r.size() - 8) == "|default");
        }
    }
    CHECK(extended);
    CHECK(ace_rows == 5);
}
#endif
