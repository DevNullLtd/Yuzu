/**
 * test_firmware_posture_local_dispatcher.cpp -- loads the ACTUAL built firmware_posture plugin
 * via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally -- no platform guard on any TEST_CASE (a guarded
 * dispatcher TU hid a never-loaded plugin on PR6.1-b). Assertions are row FAMILIES that hold on
 * ANY host of the OS (a CI VM without DMI or a firmware node is legitimate), never host values.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

std::size_t count_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    return static_cast<std::size_t>(std::count_if(
        rows.begin(), rows.end(), [&](const std::string& r) { return r.rfind(prefix, 0) == 0; }));
}

// Under `meson test` a missing plugin means the build is broken -- never "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("firmware_posture plugin library not found under meson test -- the plugin did not "
             "build, or link_depends does not order it before this test");
    WARN("firmware_posture plugin library not found -- skipping (run from the build root)");
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_plugin() {
    const fs::path rel = fs::path{"agents"} / "plugins" / "firmware_posture" /
                         (std::string{"firmware_posture"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT")) candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-windows", "build-linux"})
        candidates.push_back(fs::path{dir} / rel);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (!fs::exists(p, ec) || ec) continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(p, ec));
        if (!handle.has_value() || !handle->descriptor()) return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

} // namespace

// Fails under: a descriptor leg dropped, PLANNED declared, or the rung changed.
TEST_CASE("firmware_posture plugin: one `firmware` action, all three OS legs declared at rung 1",
          "[firmware_posture][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    REQUIRE(plugin->descriptor->action_descriptor_count == 1);
    const auto& d = plugin->descriptor->action_descriptors[0];
    CHECK(std::string_view{d.action} == "firmware");
    for (const auto* leg : {&d.linux_leg, &d.macos_leg, &d.windows_leg}) CHECK(leg->rung == 1);
    CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK((d.linux_leg.fallback != nullptr && d.macos_leg.fallback != nullptr));
}

// Fails under: a leg that emits no rows, the wrong grammar, or a status that disagrees with rc.
TEST_CASE("firmware_posture plugin: `firmware` yields >= 3 well-formed rows on this host",
          "[firmware_posture][actions]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "firmware");
    const auto rows = captured_rows(result.captured);

    CHECK(count_prefix(rows, "firmware|") >= 3);
    for (const auto& r : rows) {
        INFO("row: " << r);
        CHECK((r.rfind("firmware|", 0) == 0 || r.rfind("constrained|", 0) == 0));
    }
    // The three always-emitted fields are present as data, `absent` or `unreadable` on any host.
    for (const char* family : {"firmware|vendor|", "firmware|version|", "firmware|release_date|"})
        CHECK(count_prefix(rows, family) >= 1);

    // rc and the typed status agree, and an OK run never contains an `unreadable` row.
    CHECK((result.rc == 0) == (result.result_status == YUZU_RESULT_STATUS_OK));
    if (result.result_status == YUZU_RESULT_STATUS_OK) {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        for (const auto& r : rows) CHECK(r.find("|unreadable|") == std::string::npos);
    }
    if (std::string{kPluginExt} == ".dylib") {
        // hw.model always exists on macOS; version_source proves the IOKit leg ran.
        CHECK(count_prefix(rows, "firmware|model|") == 1);
        CHECK(count_prefix(rows, "firmware|version_source|") == 1);
    }
}

TEST_CASE("firmware_posture plugin: an unknown action is refused with an escaped row",
          "[firmware_posture][actions]") {
    auto plugin = load_plugin();
    if (!plugin) return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no|such\naction");
    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no\\|such action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}
