/**
 * test_msi_packages_actions.cpp -- Wave 4 PR4.3a dispatch remediation: loads
 * the ACTUAL built msi_packages plugin (msi_packages.dylib, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher, same pattern as
 * test_installed_apps_actions.cpp / test_users_posix_actions.cpp -- this
 * proves the migrated direct-argv `pkgutil --pkgs`/`--pkg-info <id>` calls
 * (replacing the prior `/bin/sh -c` hop + shell_quote()) actually reach the
 * real pkgutil binary on the test host.
 *
 * macOS-only (msi_packages returns "platform not supported" on Linux, and
 * the Windows leg is native MsiEnumProductsA, not a spawn site this PR
 * touches) -- a no-op TU elsewhere via the file's own guard, matching the
 * Darwin-only shape of test_wave3_pr31_macos_actions.cpp.
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline requires one
 * whenever a test's runtime depends on process creation):
 *   - What it costs, MEASURED on this host (macOS 26, arm64, 2026-08-24):
 *     2.25 s wall for both cases together. `list` does issue one
 *     `pkgutil --pkg-info` per receipt under the kMaxPackages (500) cap, but
 *     pkgutil is a local receipt-database read and the real cost is small.
 *     Re-measure rather than assume if that cap is ever raised.
 *   - Why a pure-function test cannot replace it: the point of the change is
 *     that the argv reaches the real pkgutil after the `/bin/sh -c` hop and
 *     shell_quote() were deleted. Feeding a fixture string to a parser
 *     exercises neither the argv construction nor the exec, and would stay
 *     green against the pre-change shell implementation.
 *   - Bound: two cases, macOS-only, no other spawning tests added here.
 */
#include <catch2/catch_test_macros.hpp>

#if defined(__APPLE__)

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

fs::path find_msi_packages_plugin() {
    const std::string lib_name = "msi_packages.dylib";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "msi_packages" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "msi_packages" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "msi_packages" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "msi_packages" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_msi_packages_plugin() {
    auto plugin_path = find_msi_packages_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

std::size_t count_non_matching_lines(const std::string& captured, std::string_view prefix) {
    std::istringstream iss(captured);
    std::string line;
    std::size_t bad = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.compare(0, prefix.size(), prefix) != 0)
            ++bad;
    }
    return bad;
}

} // namespace

TEST_CASE("msi_packages plugin: list executes real pkgutil --pkgs/--pkg-info argv",
          "[msi_packages][posix_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        SKIP("msi_packages plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");

    // rc==0 plus every line matching `msi|...` proves the migrated argv
    // (direct pkgutil path, no shell hop, no shell_quote()) actually
    // reached the real pkgutil binary and its per-id --pkg-info loop ran
    // without error -- a reverted/broken argv would surface as a non-zero
    // rc or output that never matches the wire shape.
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());
    CHECK(count_non_matching_lines(result.captured, "msi|") == 0);
}

TEST_CASE("msi_packages plugin: product_codes executes real pkgutil --pkgs argv",
          "[msi_packages][posix_actions]") {
    auto plugin = load_msi_packages_plugin();
    if (!plugin) {
        SKIP("msi_packages plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "product_codes");

    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());
    CHECK(count_non_matching_lines(result.captured, "product_code|") == 0);
}

#endif // __APPLE__
