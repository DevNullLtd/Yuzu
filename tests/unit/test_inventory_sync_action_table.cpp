/**
 * test_inventory_sync_action_table.cpp — pins installed_software_actions() against
 * the REAL built plugin descriptors.
 *
 * The table's `source` strings are a stored, hashed column: renaming an action in
 * a plugin without updating the table silently changes the rows and forces a
 * fleet-wide resend (#5330). So this test loads the actual plugin binaries rather
 * than a catalogue copy.
 *
 * MESON_BUILD_ROOT is exact-match only: when set, the sole candidate is
 * <root>/agents/plugins/<plugin>/<plugin><ext>, so a stale artifact from another
 * build dir can never satisfy the pin. (test_disk_actions_local_dispatcher.cpp
 * keeps relative/build-<os> fallbacks for hand-running; they apply here only when
 * MESON_BUILD_ROOT is unset.) A missing library is a failure, never a skip.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "sync_source_installed_software.hpp"

#include <cstdlib>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
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

} // namespace

TEST_CASE("installed-software action table matches real plugin descriptors",
          "[sync][table]") {
    const auto table = yuzu::agent::installed_software_actions();
    REQUIRE_FALSE(table.empty());

    std::set<std::pair<std::string_view, std::string_view>> seen;
    std::map<std::string, yuzu::agent::PluginHandle> handles; // alive to end of test

    for (const auto& [plugin_sv, action_sv] : table) {
        const std::string plugin{plugin_sv};
        INFO("plugin=" << plugin << " action=" << action_sv);

        CHECK(seen.emplace(plugin_sv, action_sv).second); // no duplicate pair

        auto it = handles.find(plugin);
        if (it == handles.end()) {
            const auto path = find_plugin(plugin);
            INFO("path=" << path.string());
            std::error_code ec;
            REQUIRE(fs::exists(path, ec));
            auto loaded = yuzu::agent::PluginHandle::load(path);
            REQUIRE(loaded.has_value());
            it = handles.emplace(plugin, std::move(*loaded)).first;
        }
        const YuzuPluginDescriptor* d = it->second.descriptor();
        REQUIRE(d != nullptr);

        CHECK(std::string_view{d->name} == plugin_sv);

        bool in_actions = false;
        for (const char* const* a = d->actions; a && *a; ++a)
            if (std::string_view{*a} == action_sv) in_actions = true;
        CHECK(in_actions);

        if (d->action_descriptor_count > 0) {
            bool in_desc = false;
            for (size_t i = 0; i < d->action_descriptor_count; ++i)
                if (d->action_descriptors[i].action &&
                    std::string_view{d->action_descriptors[i].action} == action_sv)
                    in_desc = true;
            CHECK(in_desc);
        }
    }
}
