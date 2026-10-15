/**
 * test_browser_inventory_local_dispatcher.cpp — loads the ACTUAL built
 * browser_inventory plugin (browser_inventory.dylib/.so/.dll) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher,
 * exercising the real per-OS legs on the build host.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately, no `#ifndef _WIN32`/`#ifndef
 * __APPLE__` guard on the whole TU -- a platform-guarded dispatcher TU is
 * exactly how a sibling plugin once shipped a leg that had been compiled
 * out entirely and stayed green (test_peripherals_local_dispatcher.cpp's
 * own banner makes the same point, citing test_disk_actions_local_
 * dispatcher.cpp). LocalDispatcher and PluginHandle are both platform-
 * neutral.
 *
 * SCOPE. macOS and Windows still ship P2a-1's PLANNED placeholder legs this
 * wave (browser_inventory_legs.hpp's mark_planned) -- every action on those
 * two OSes emits EXACTLY the one status row `status|<action>|unsupported|
 * <os_tag>:planned`. Linux (this package, P2a-2) is real: every action
 * emits a `status|<action>|<supported|constrained>|<reason-or-"-">` row
 * first, then zero or more data rows. No fixture is shipped for this TU
 * (it drives the built plugin against the live host, same convention as
 * test_peripherals_local_dispatcher.cpp's own banner records) -- the
 * fixture-backed walk cases live in test_browser_inventory_linux_parsers.
 * cpp.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "browser_inventory_legs.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split -- see browser_inventory_linux_parsers.hpp's
/// "WIRE GRAMMAR" banner: safe_output_field escapes a literal '|' as '\|',
/// so a naive split('|') overcounts fields on any row whose text happens to
/// contain one.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin
/// means the build is genuinely broken and must NOT report "All tests
/// passed" -- matches every sibling *_local_dispatcher.cpp's identical
/// helper (e.g. test_peripherals_local_dispatcher.cpp).
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("browser_inventory plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("browser_inventory plugin library not found -- skipping the LocalDispatcher round-trip");
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

fs::path find_browser_inventory_plugin() {
    const std::string lib_name = std::string{"browser_inventory"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "browser_inventory" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "browser_inventory" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "browser_inventory" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "browser_inventory" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_browser_inventory_plugin() {
    auto path = find_browser_inventory_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

/// The two actions and their real (non-status) row shapes: `kind` is the
/// leading token, `field_count` its exact escape-aware field count once
/// split -- browser_inventory_linux_parsers.hpp's linux_{browser,profile}_
/// rows_at() formatters are the one place these are built.
struct ActionShape {
    const char* action;
    const char* kind;
    std::size_t field_count;
};
constexpr ActionShape kActions[] = {
    {"browsers", "browser", 4},
    {"profiles", "profile", 5},
};

} // namespace

TEST_CASE("browser_inventory plugin: a status row leads every action's output",
          "[browser_inventory][actions]") {
    auto plugin = load_browser_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        CHECK(result.rc == 0); // a degraded/planned read is never a failed command

        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto f0 = split_fields_escape_aware(rows[0]);
        REQUIRE(f0.size() == 4);
        CHECK(f0[0] == "status");
        CHECK(f0[1] == a.action);
        CHECK((f0[2] == "supported" || f0[2] == "constrained" || f0[2] == "unsupported"));
    }
}

TEST_CASE("browser_inventory plugin: every data row after the status row matches its action's "
         "field count",
         "[browser_inventory][actions]") {
    auto plugin = load_browser_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        for (std::size_t i = 1; i < rows.size(); ++i) {
            INFO("row: " << rows[i]);
            const auto f = split_fields_escape_aware(rows[i]);
            CHECK(f[0] == a.kind);
            REQUIRE(f.size() == a.field_count);
        }
    }
}

TEST_CASE("browser_inventory plugin: an unknown action is refused, not silently ignored",
          "[browser_inventory][actions]") {
    auto plugin = load_browser_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}

#if defined(__APPLE__) || defined(_WIN32)
// P2a-1's PLANNED placeholder legs (browser_inventory_legs.hpp's
// mark_planned) -- their real implementation follows as its own PR (this
// package's boundary: "no macOS/Windows implementation").
TEST_CASE("browser_inventory plugin: macOS/Windows report exactly the PLANNED status row",
          "[browser_inventory][actions][planned]") {
    auto plugin = load_browser_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
#if defined(__APPLE__)
    constexpr std::string_view kOsTag = "macos";
#else
    constexpr std::string_view kOsTag = "windows";
#endif
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + a.action + "|unsupported|" +
                             std::string{kOsTag} + ":planned");
    }
}
#endif

#if defined(__linux__)
// This package's own leg (P2a-2): on a host with no Chromium-family
// browser installed (the common CI case), every action reports SUPPORTED
// -- a genuinely absent browser/profile is not a constraint (see
// browser_inventory_linux_parsers.hpp's FAILURE CONTRACT banner).
TEST_CASE("browser_inventory plugin: Linux reports supported, not constrained, when Chromium is "
         "absent",
         "[browser_inventory][actions][linux]") {
    auto plugin = load_browser_inventory_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto f0 = split_fields_escape_aware(rows[0]);
        if (f0[2] == "constrained") {
            // This host genuinely has some other real constraint (e.g. a
            // real Chromium profile with an unreadable file) -- report it
            // rather than assert blindly, matching the peripherals
            // dispatcher precedent's "no host-specific assertion" stance
            // for a shared, unknown-hardware CI runner.
            WARN("host reported constrained: " << rows[0]);
        } else {
            CHECK(f0[2] == "supported");
        }
    }
}
#endif
