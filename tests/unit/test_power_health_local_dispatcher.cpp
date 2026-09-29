/**
 * test_power_health_local_dispatcher.cpp — Wave 6 W1B: loads the ACTUAL
 * built power_health plugin (power_health.dylib/.so/.dll) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher
 * (test_filesystem_posture_local_dispatcher.cpp's pattern), exercising the
 * three READ-ONLY actions' real per-OS legs end to end on the build host.
 *
 * NEVER dispatches set_power_plan — the plugin's one mutating action stays
 * untested here by design (fixture-driven coverage of its decision logic
 * lives in test_power_health_parsers.cpp's resolve_power_scheme cases; the
 * Windows-only sequencing itself gets its real signal from the-rig's MSVC
 * build at integration, per this package's spec).
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally — see
 * test_filesystem_posture_local_dispatcher.cpp's header comment for why a
 * platform-guarded dispatcher TU is exactly the shape that hid a dead
 * Windows leg on PR6.1-b. This file is the one that would have caught it
 * here.
 *
 * VERIFICATION-PROTOCOL COMPLIANCE (P-006): the battery test below executes
 * the REAL leg. On a host with no system battery it emits an EXPLICIT named
 * SKIP — never a silent pass — via Catch2's SKIP() (test_guardian_engine
 * .cpp's precedent). With a battery present it asserts real values (percent
 * 0-100, a real state, not the 255/unknown sentinel). The SKIP's ABSENCE on
 * a battery-bearing host is the signal that the real leg ran.
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

// Mirrors test_filesystem_posture_local_dispatcher.cpp's require_plugin_or_skip:
// under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the
// build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("power_health plugin library not found under meson test — the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("power_health plugin library not found -- skipping LocalDispatcher round-trip test "
         "(run from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_power_health_plugin() {
    const std::string lib_name = std::string{"power_health"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "power_health" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "power_health" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "power_health" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "power_health" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "power_health" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "power_health" /
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

std::optional<LoadedPlugin> load_power_health_plugin() {
    auto plugin_path = find_power_health_plugin();
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

TEST_CASE("power_health plugin: ABI4 descriptors declare all three OS legs for every action, "
          "never #ifdef'd out (plugin.h:115-136)",
          "[power_health][descriptors]") {
    auto plugin = load_power_health_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 4);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        // Every leg must be authored (not the ABI<4 zero value) regardless
        // of which OS actually built this binary -- the whole point of the
        // never-#ifdef rule is that even a macOS build's struct still
        // carries a real Windows/Linux declaration.
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
    }
}

TEST_CASE("power_health plugin: battery action — real leg, explicit SKIP on no-battery hardware "
          "(P-006, never a silent pass)",
          "[power_health][actions]") {
    auto plugin = load_power_health_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "battery");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    bool any_present = false;
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f.size() == 7);
        CHECK(f[0] == "battery");
        if (f[1] == "1")
            any_present = true;
    }

    if (!any_present) {
        SKIP("no system battery on this host — battery-present leg not exercised");
        return;
    }

    // A battery IS present: assert REAL values, never the undeclared
    // sentinel -- this is the assertion whose absence would let a
    // reconstructed/undeclared reading pass as a genuine capture.
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        if (f[1] != "1")
            continue;
        const int percent = std::stoi(f[3]);
        INFO("row: " << r);
        CHECK(percent >= 0);
        CHECK(percent <= 100);
        // A present battery must carry a state the OS actually reported.
        // `unknown` is the "we could not read it" sentinel and is never a
        // legitimate answer here — that is the whole point of this assertion.
        //
        // Pinned to the CLOSED set rather than only excluding `unknown`: a
        // future state added to the enum but never described in the user manual
        // or the YAML schema would otherwise slip through this check silently,
        // which is how `not_charging` came to be missing in the first place —
        // real hardware reported `battery|1|unknown|99|-1|-1|-1` and only an
        // out-of-band laptop run caught it (PR #4009 review). CI hosts have no
        // battery, so this loop SKIPs above and cannot catch it either.
        const bool known_state = f[2] == "charging" || f[2] == "discharging" ||
                                 f[2] == "full" || f[2] == "not_charging";
        CHECK(known_state);
        CHECK(f[2] != "unknown");
    }
}

TEST_CASE("power_health plugin: thermal action shape — a zero-instance/constrained result is an "
          "explicit success line, never silent-empty",
          "[power_health][actions]") {
    auto plugin = load_power_health_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "thermal");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f.size() >= 3);
        CHECK(f[0] == "thermal");
        CHECK((f[1] == "ok" || f[1] == "constrained" || f[1] == "unavailable"));
    }
}

TEST_CASE("power_health plugin: power_plan action shape — Windows enumerates schemes, macOS "
          "reports unsupported, Linux reports planned; never crashes on any of the three",
          "[power_health][actions]") {
    auto plugin = load_power_health_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "power_plan");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f.size() >= 3);
        CHECK(f[0] == "power_plan");
    }
}
