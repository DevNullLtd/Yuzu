/**
 * test_windows_optional_features_local_dispatcher.cpp — loads the ACTUAL
 * built windows_optional_features plugin (windows_optional_features.dylib/
 * .so/.dll) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher, exercising the real per-OS legs end to end
 * on the build host.
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally -- NO `#ifdef`/`#if
 * defined(_WIN32)` platform guard anywhere in this file. A platform-guarded
 * dispatcher TU is exactly the shape that hid a dead Windows leg on
 * PR6.1-b (feedback-platform-guarded-tests-hide-dead-legs) -- this file's
 * per-branch assertions below (Windows real rows vs. non-Windows exact
 * unsupported row) are what would have caught it here.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
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

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : row) {
        if (c == '|') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    f.push_back(cur);
    return f;
}

// Mirrors test_power_health_local_dispatcher.cpp's require_plugin_or_skip:
// under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the
// build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("windows_optional_features plugin library not found under meson test — the plugin "
             "did not build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("windows_optional_features plugin library not found -- skipping LocalDispatcher "
         "round-trip test (run from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_windows_optional_features_plugin() {
    const std::string lib_name = std::string{"windows_optional_features"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "windows_optional_features" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "windows_optional_features" /
                            lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "windows_optional_features" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" /
                            "windows_optional_features" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" /
                            "windows_optional_features" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" /
                            "windows_optional_features" / lib_name);

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

std::optional<LoadedPlugin> load_windows_optional_features_plugin() {
    auto plugin_path = find_windows_optional_features_plugin();
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

// Closed vocabulary for the `state` field of a `feature|` row.
const std::unordered_set<std::string> kClosedStates{
    "enabled", "disabled", "pending_enable", "pending_disable", "superseded",
    "partially_installed", "unknown"};

} // namespace

TEST_CASE("windows_optional_features plugin: ABI4 descriptors declare all three OS legs for "
          "every action, never #ifdef'd out (plugin.h:115-136)",
          "[windows_optional_features][descriptors]") {
    auto plugin = load_windows_optional_features_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 2);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
    }
}

TEST_CASE("windows_optional_features plugin: list -- real DISM rows on Windows, an exact "
          "unsupported row elsewhere",
          "[windows_optional_features][actions]") {
    auto plugin = load_windows_optional_features_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    // No compile-time platform branch here (boundary: "no platform #ifdef
    // in the dispatcher test TU") -- which branch below fires is decided by
    // what the REAL plugin actually reported, at runtime, on this host.
    if (rows.size() == 1) {
        const auto f = split_fields(rows[0]);
        if (f.size() == 3 && f[0] == "feature" && f[1] == "unsupported") {
            // Non-Windows leg: the exact unsupported row.
            INFO("row: " << rows[0]);
            CHECK((f[2] == "macos:dism:unsupported" || f[2] == "linux:dism:unsupported"));
            CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            return;
        }
    }

    // Windows leg: real DISM rows. CI Windows runners are full installs --
    // api_unavailable would itself be a failure here, so it is explicitly
    // excluded, named, rather than silently tolerated as "just another row".
    REQUIRE(rows.size() >= 20);
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f.size() == 4);
        CHECK(f[0] == "feature");
        INFO("row: " << r);
        CHECK(kClosedStates.contains(f[2]));
        CHECK((f[3] == "0" || f[3] == "1"));
    }
}

TEST_CASE("windows_optional_features plugin: info feature=NetFx3 -- one real row on Windows",
          "[windows_optional_features][actions]") {
    auto plugin = load_windows_optional_features_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    const YuzuParam params[] = {{"feature", "NetFx3"}};
    auto result = dispatcher.run(plugin->descriptor, "info", params);
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    const auto f = split_fields(rows[0]);

    // No compile-time platform branch here either -- decided by what the
    // real plugin reported.
    if (f.size() == 3 && f[0] == "feature_info" && f[1] == "unsupported") {
        CHECK((f[2] == "macos:dism:unsupported" || f[2] == "linux:dism:unsupported"));
        return;
    }

    // feature_info|<name>|<display_name>|<state>|<restart_type>|<description>
    // -- discriminator + 5 data columns = 6 pipe-delimited fields (the-rig,
    // 2026-09-08: this assertion read 5 and failed 6 == 5 against a real
    // NetFx3 row; format_feature_info_row's own shape test in
    // test_windows_optional_features_parsers.cpp already pins 6).
    REQUIRE(f.size() == 6);
    CHECK(f[0] == "feature_info");
    CHECK(f[1] == "NetFx3");
    CHECK(kClosedStates.contains(f[3]));
}

TEST_CASE("windows_optional_features plugin: info feature=../evil is refused before any DISM "
          "call, on every OS, in well under 100ms",
          "[windows_optional_features][actions]") {
    auto plugin = load_windows_optional_features_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    const YuzuParam params[] = {{"feature", "../evil"}};

    const auto start = std::chrono::steady_clock::now();
    auto result = dispatcher.run(plugin->descriptor, "info", params);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.rc == 1);
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() < 100);
}
