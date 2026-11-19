/**
 * test_inventory_sync_action_table.cpp — pins installed_software_actions() against
 * the REAL built plugin descriptors.
 *
 * The table's `source` strings are a stored, hashed column: renaming an action in
 * a plugin without updating the table silently changes the rows and forces a
 * fleet-wide resend (#5330). So this test loads the actual plugin binaries rather
 * than a catalogue copy.
 *
 * Resolution: when MESON_BUILD_ROOT is set (a hand-run harness may set it) the sole
 * candidate is <root>/agents/plugins/<plugin>/<plugin><ext>. `meson test` does not
 * export it; it runs the test from the build root, so the working-directory-relative
 * agents/plugins/<plugin>/<plugin><ext> is the operative path there, and the
 * build-<os> fallbacks only serve a hand run from the source root. A missing library
 * is a failure, never a skip.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "sync_source_installed_software.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kExt = ".dylib";
#else
constexpr const char* kExt = ".so";
#endif

// getenv matches the sibling *_local_dispatcher.cpp helpers; MSVC's C4996 is silenced locally.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
fs::path find_plugin(const std::string& plugin) {
    const std::string lib = plugin + kExt;
    const fs::path rel = fs::path{"agents"} / "plugins" / plugin / lib;
    if (const char* root = std::getenv("MESON_BUILD_ROOT"))
        return fs::path{root} / rel;
    std::vector<fs::path> candidates{rel};
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / rel);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return rel;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace

TEST_CASE("installed-software action table matches real plugin descriptors",
          "[sync][table]") {
    const auto table = yuzu::agent::installed_software_actions();
    REQUIRE_FALSE(table.empty());

    // No (plugin, action) pair twice: a duplicate would dispatch the action twice per cycle.
    auto sorted = table;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());

    for (const auto& [plugin_sv, action_sv, limit] : table) {
        static_cast<void>(limit);
        const std::string plugin{plugin_sv};
        const auto path = find_plugin(plugin);
        INFO("plugin=" << plugin << " action=" << action_sv << " path=" << path.string());

        auto loaded = yuzu::agent::PluginHandle::load(path);
        REQUIRE(loaded.has_value());
        const YuzuPluginDescriptor* d = loaded->descriptor();
        REQUIRE(d != nullptr);

        CHECK(std::string_view{d->name} == plugin_sv);

        bool in_actions = false;
        for (const char* const* a = d->actions; a && *a; ++a)
            if (std::string_view{*a} == action_sv) in_actions = true;
        CHECK(in_actions);
    }
}

TEST_CASE("the hardware drivers_inventory row is last in the table and resolves to the real plugin",
          "[sync][table]") {
    // hardware.drivers_inventory joined the daily sync as the LAST row: the facet order is the
    // order sections are planned in, and the server's kSoftwareSources vocabulary follows it
    // (tests/test_software_vocabulary_consistency.py compares the ordered lists).
    const auto table = yuzu::agent::installed_software_actions();
    REQUIRE_FALSE(table.empty());
    CHECK(table.back() == std::make_tuple(std::string_view{"hardware"},
                                          std::string_view{"drivers_inventory"},
                                          std::chrono::seconds{120}));

    auto loaded = yuzu::agent::PluginHandle::load(find_plugin("hardware"));
    REQUIRE(loaded.has_value());
    const YuzuPluginDescriptor* d = loaded->descriptor();
    REQUIRE(d != nullptr);
    CHECK(std::string_view{d->name} == "hardware");
    bool declared = false;
    for (const char* const* a = d->actions; a && *a; ++a)
        declared = declared || std::string_view{*a} == "drivers_inventory";
    CHECK(declared);
}

TEST_CASE("the action table pins each action's time limit: three slow ones at 120 s, the rest at 60 s",
          "[sync][table]") {
    // The limit is how long the sync thread waits for one action before reporting `timeout`; every
    // collector test overrides it, so the table values are pinned here. The slow three are the
    // registry walk, the DISM enumeration and the driver roster.
    const std::set<std::string> slow = {"installed_apps.list_inventory", "windows_optional_features.list",
                                        "hardware.drivers_inventory"};
    std::size_t slow_seen = 0;
    std::size_t fast_seen = 0;
    for (const auto& [plugin, action, limit] : yuzu::agent::installed_software_actions()) {
        const std::string source = std::string(plugin) + "." + std::string(action);
        INFO(source);
        if (slow.contains(source)) {
            CHECK(limit == std::chrono::seconds{120});
            ++slow_seen;
        } else {
            CHECK(limit == std::chrono::seconds{60});
            ++fast_seen;
        }
    }
    CHECK(slow_seen == 3);
    CHECK(fast_seen == 8);
}
