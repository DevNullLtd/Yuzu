/**
 * test_component_inventory_local_dispatcher.cpp -- loads the ACTUAL built component_inventory
 * plugin (component_inventory.dylib / .so / .dll) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no platform guard on this TU (a guarded dispatcher TU
 * is how a sibling plugin once shipped a compiled-out Windows leg and stayed green). Only the
 * expectations differ per host.
 *
 * `scan` and `native` are dispatched on Windows ONLY, where the planned leg answers at once. On Linux
 * and macOS a dispatch would walk this host's real application roots for up to 45 s, which the unit
 * suites must not do, and the plugin takes its roots from nothing a request or the environment can
 * supply, so a test cannot point it at a temporary tree. The populated answers are pinned in
 * test_component_scan.cpp and test_component_native_scan.cpp over an in-memory tree and a
 * materialised one, and the real end-to-end run is the sample capture taken against a host.
 *
 * MUTATION: adding a third action, changing a declared leg, or loading the wrong plugin fails the
 * descriptor case; removing the report_planned call on the Windows path, or letting `native` reach
 * the unknown-action guard, fails the planned-row cases.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the build is
/// genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("component_inventory plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("component_inventory plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_plugin() {
    const std::string lib_name = std::string{"component_inventory"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "component_inventory" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "component_inventory" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "component_inventory" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "component_inventory" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_plugin() {
    auto path = find_plugin();
    if (path.empty())
        return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded)
        return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d)
        return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

} // namespace

TEST_CASE("component_inventory plugin: exactly two actions, `scan` and `native`, with the declared legs",
          "[runtime][component_inventory][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    CHECK(std::string_view{plugin->descriptor->name} == "component_inventory");
    CHECK(std::string_view{plugin->descriptor->version} == "1.1.0");

    std::vector<std::string> actions;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a)
        actions.emplace_back(*a);
    REQUIRE(actions.size() == 2);
    CHECK(actions[0] == "scan");
    CHECK(actions[1] == "native");

    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    REQUIRE(plugin->descriptor->action_descriptor_count == 2);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        CHECK(std::string_view{d.action} == actions[i]);
        CHECK(d.linux_leg.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(d.linux_leg.rung == 1);
        CHECK(d.macos_leg.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(d.macos_leg.rung == 1);
        CHECK(d.windows_leg.support == YUZU_SUPPORT_PLANNED);
    }
}

TEST_CASE("component_inventory plugin: an unknown action is refused with one non-status line",
          "[component_inventory][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");

    // The request-supplied name goes through safe_output_field: a pipe cannot open a second field.
    const auto hostile = dispatcher.run(plugin->descriptor, "no|such\\");
    CHECK(hostile.rc != 0);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
}

#if defined(_WIN32)
TEST_CASE("component_inventory plugin: the Windows leg answers the planned row at once, for both actions",
          "[component_inventory][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"scan", "native"}) {
        const auto result = dispatcher.run(plugin->descriptor, action);
        CHECK(result.rc == 0); // a planned leg is not a failed command
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + action + "|unsupported|windows:planned");
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    }
}
#endif
