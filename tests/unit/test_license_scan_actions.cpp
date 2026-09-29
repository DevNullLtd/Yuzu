/**
 * test_license_scan_actions.cpp — Wave 4 PR4.3b: loads the ACTUAL built
 * license_scan plugin (license_scan.dylib/.so) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher (test_users_posix_actions.cpp's
 * pattern), proving the plugin dispatches end to end after the Linux-leg
 * runner migration (licensing_linux.cpp) and the CONSTRAINED/rung-2
 * descriptor demotion.
 *
 * SCOPE, stated honestly: on macOS this exercises NONE of the Linux runner
 * migration -- licensing_macos.cpp's run_platform_surfaces is pure filesystem
 * glob + plist parsing with no subprocess at all. There it is a load-and-
 * dispatch smoke test: it proves the built plugin loads over the ABI and
 * answers "surfaces", nothing more. The Linux assertion below is the part that
 * covers migrated code, and it only runs on Linux (CI).
 *
 * "surfaces" always returns rc 0 by design (ADR-0024 D3: probe_status
 * reporting never fails the call), and each platform's run_platform_surfaces
 * appends at least one ProbeOutcome, so one `probe_status|` line is guaranteed
 * on every host.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_license_scan_plugin() {
    const std::string lib_name = std::string{"license_scan"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "license_scan" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "license_scan" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "license_scan" /
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

std::optional<LoadedPlugin> load_license_scan_plugin() {
    auto plugin_path = find_license_scan_plugin();
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

} // namespace

TEST_CASE("license_scan plugin: surfaces reports probe_status diagnostics via LocalDispatcher",
          "[license_scan]") {
    // Deliberately NOT a WARN-and-skip -- see the same note in
    // test_software_actions_actions.cpp. tests/meson.build links this plugin
    // in, so a load failure is a real defect and must go red rather than
    // pass with zero assertions.
    auto plugin = load_license_scan_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "surfaces");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("probe_status|") != std::string::npos);

#ifdef __linux__
    // Only on Linux does this dispatch reach the migrated code. pkg_metadata is
    // the surface licensing_linux.cpp's runner migration rewrote, and
    // run_pkg_metadata_surface pushes its outcome on EVERY path, so its absence
    // means the migrated surface did not run at all.
    //
    // Governance Gate 4 (unhappy-path UP-9): the ORIGINAL substring check here
    // matched `probe_status|pkg_metadata|ok|...` AND
    // `probe_status|pkg_metadata|error|rpm_query_failed` equally -- so this
    // test stayed green even with the migrated argv path completely broken
    // (a reverted fix, a wrong tool path, a silently reintroduced shell hop
    // that no-ops), as long as SOME probe_status line for the surface still
    // appeared. Any dev or CI host running this suite has rpm or dpkg-query,
    // so pinning `|ok|` specifically proves the migrated argv actually
    // reached the real tool and succeeded, not merely that the surface was
    // attempted.
    INFO("full captured output: " << result.captured);
    CHECK(result.captured.find("probe_status|pkg_metadata|ok|") != std::string::npos);
#endif
}

#endif // !_WIN32
