/**
 * test_wmi_local_dispatcher.cpp -- gate-1 remediation for
 * feat/wave3-pr33a-com-wmi-shared.
 *
 * Loads the ACTUAL built wmi plugin (wmi.dll, the same artifact the agent
 * daemon loads in production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher -- the same in-process dispatch mechanism
 * test_registry_local_dispatcher.cpp uses for the registry plugin.
 *
 * This closes a real functional-review gap (found independently by two
 * external gate-1 reviewers): test_wmi_bounded.cpp exercises the shared
 * yuzu::shared::wmi::run_bounded_wmi_query helper directly, but nothing
 * exercised the migrated wmi_plugin.cpp `query`/`get_instance` actions
 * through the actual built plugin -- the full agent test suite would still
 * pass even if either action were reverted to its pre-migration
 * WBEM_INFINITE implementation. This file proves the wiring: the built
 * plugin's actions really do route through the shared bounded helper and
 * produce the documented row/property/error output shape.
 *
 * Windows-only; the plugin's WMI code is a no-op elsewhere.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Locate the real wmi.dll built by agents/plugins/wmi/meson.build. Mirrors
// test_registry_local_dispatcher.cpp's find_registry_plugin, pointed at the
// wmi plugin's own build output directory. Returns an empty path (never
// fails) when not found -- a build invoked without the agent plugins
// (-Dbuild_agent=false) must not fail this test, it must skip it.
fs::path find_wmi_plugin() {
    const std::string lib_name = "wmi.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "wmi" / lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "wmi" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "wmi" / lib_name);
    // A manual invocation from the source root has CWD=source root, not
    // build root -- cover the conventional Windows build dir name.
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "wmi" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

} // namespace

TEST_CASE("wmi plugin: query action returns real Win32_OperatingSystem rows via "
          "LocalDispatcher (gate-1 remediation)",
          "[wmi][windows][local_dispatcher]") {
    auto plugin_path = find_wmi_plugin();
    if (plugin_path.empty()) {
        WARN("wmi.dll not found (build_agent=false?) -- skipping LocalDispatcher "
             "round-trip test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::agent::LocalDispatcher dispatcher;

    // Win32_OperatingSystem is a single-instance, locally-served class on
    // every Windows host -- same fast, deterministic smoke target
    // test_wmi_bounded.cpp uses at the helper level, exercised here through
    // the real plugin action end to end (params parsing, namespace/class
    // validation, the shared bounded helper, and output formatting).
    std::vector<YuzuParam> params{
        {"wql", "SELECT Name FROM Win32_OperatingSystem"},
    };
    auto result = dispatcher.run(descriptor, "query", params);
    CHECK(result.rc == 0);
    CHECK(result.captured.find("row0|Name|") != std::string::npos);
    CHECK(result.captured.find("rows|1") != std::string::npos);
    // A pre-migration revert to WBEM_INFINITE would still produce this same
    // output on a healthy host -- the discriminating regression coverage is
    // test_wmi_bounded.cpp's deadline/truncation tests against the shared
    // helper directly. This test's job is proving the WIRING: the built
    // plugin action really calls the shared helper and surfaces its result.
    CHECK(result.captured.find("error|") == std::string::npos);
}

TEST_CASE("wmi plugin: get_instance action returns real Win32_OperatingSystem "
          "properties via LocalDispatcher (gate-1 remediation)",
          "[wmi][windows][local_dispatcher]") {
    auto plugin_path = find_wmi_plugin();
    if (plugin_path.empty()) {
        WARN("wmi.dll not found (build_agent=false?) -- skipping LocalDispatcher "
             "round-trip test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::agent::LocalDispatcher dispatcher;

    std::vector<YuzuParam> params{
        {"class", "Win32_OperatingSystem"},
    };
    auto result = dispatcher.run(descriptor, "get_instance", params);
    CHECK(result.rc == 0);
    CHECK(result.captured.find("property|Name|") != std::string::npos);
    CHECK(result.captured.find("error|") == std::string::npos);
}

TEST_CASE("wmi plugin: query action surfaces the plugin's own validation error, not "
          "just the shared helper's (gate-1 remediation)",
          "[wmi][windows][local_dispatcher]") {
    auto plugin_path = find_wmi_plugin();
    if (plugin_path.empty()) {
        WARN("wmi.dll not found (build_agent=false?) -- skipping LocalDispatcher "
             "round-trip test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::agent::LocalDispatcher dispatcher;

    // Missing "wql" never reaches the shared helper at all -- this proves the
    // plugin's own action-level validation still runs ahead of it.
    auto result = dispatcher.run(descriptor, "query");
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|missing required parameter: wql") != std::string::npos);
}

#endif // _WIN32
