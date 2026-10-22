/**
 * filesystem_dispatcher_test_support.hpp -- helpers shared by the filesystem plugin's unit TUs
 * that load the ACTUAL built plugin through yuzu::agent::LocalDispatcher (get_acl, find_by_hash)
 * and by the find_by_hash walk-core TU. Header-only, inline: a plugin locator / loader, a
 * captured-output splitter, and the canonical-root TempDir fixture. The per-action dispatch
 * wrappers stay TU-local on purpose (each binds a different action and parameter list).
 */
#pragma once

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "test_helpers.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace yuzu::test::filesystem_dispatcher_support {

namespace fs = std::filesystem;

#if defined(_WIN32)
inline constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
inline constexpr const char* kPluginExt = ".dylib";
#else
inline constexpr const char* kPluginExt = ".so";
#endif

/// The non-empty lines of a captured command-context output, CR stripped.
inline std::vector<std::string> captured_rows(const std::string& captured) {
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

inline fs::path find_plugin() {
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
inline std::optional<LoadedPlugin> load_or_fail() {
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

/// A TempDir whose root is canonical: the real no-follow hasher (O_NOFOLLOW_ANY refuses the
/// /var -> /private/var link of a macOS temp path) sees a path with no symlink component, and the
/// plugin, which canonicalises its root, reports match rows in the same spelling.
struct Tree {
    yuzu::test::TempDir tmp{"yuzu_test_fbh_"};
    fs::path root;
    Tree() {
        fs::create_directories(tmp.path);
        root = fs::canonical(tmp.path);
    }
    fs::path write(const std::string& rel, std::string_view content = "x") const {
        const fs::path p = root / fs::path(rel).make_preferred();
        fs::create_directories(p.parent_path());
        std::ofstream{p, std::ios::binary} << content;
        return p;
    }
    [[nodiscard]] std::string str() const { return root.string(); }
};

#ifndef _WIN32
inline bool running_as_root() {
    return ::geteuid() == 0;
}
#endif

} // namespace yuzu::test::filesystem_dispatcher_support
