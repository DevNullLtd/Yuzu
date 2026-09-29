/**
 * test_wifi_local_dispatcher.cpp -- PKG-WIFI remediation (test_users_posix_
 * actions.cpp's own rationale, ported to wifi): no test proves the migrated
 * D-Bus/argv ladder actually reaches a real plugin binary, only its pure
 * parsers in isolation (test_wifi_parsers.cpp). Loads the ACTUAL built wifi
 * plugin (wifi.dylib/.so, the same artifact the agent daemon loads in
 * production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher, the same pattern test_users_posix_actions.cpp
 * established -- this is wifi's POSIX (macOS + Linux) counterpart.
 *
 * On this macOS build host, `connected` always takes the CoreWLAN leg
 * (wifi_corewlan.mm), untouched by this migration; `list_networks` exercises
 * the argv-ized airport/system_profiler fallback chain. Neither the Linux
 * NetworkManager D-Bus rung nor the Linux nmcli/iw/iwlist/iwconfig argv legs
 * are reachable from a macOS test host -- that Linux-only code only meets a
 * compiler in CI (see the package report's "unverifiable without a Linux NM
 * host" note). On a Linux CI host this test instead exercises whichever of
 * the D-Bus/nmcli/iw legs the runner actually reaches.
 *
 * Content assertions are deliberately loose (a record-prefix substring, or
 * the platform's own honest sentinel) rather than pinned to specific
 * network data -- every list_networks/connected code path (a real record,
 * an error marker, or an info sentinel) is `wifi|`/`connected|`-prefixed
 * respectively, so only a broken migration (e.g. a silently reverted shell
 * hop, or a dropped return) produces neither.
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

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at the
// wifi plugin's own build output.
fs::path find_wifi_plugin() {
    const std::string lib_name = std::string{"wifi"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "wifi" / lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "wifi" / lib_name);

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

std::optional<LoadedPlugin> load_wifi_plugin() {
    auto plugin_path = find_wifi_plugin();
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

TEST_CASE("wifi plugin: connected reaches the real platform mechanism end to end",
          "[wifi][posix_actions]") {
    auto plugin = load_wifi_plugin();
    if (!plugin) {
        WARN("wifi plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "connected");
    CHECK(result.rc == 0);
    // Reverting the migrated D-Bus/argv path (wrong tool, wrong flags, a
    // shell hop that silently no-ops, a broken sd-bus call, or a dropped
    // CoreWLAN call on macOS) would either fail this call or produce output
    // that matches neither a real `connected|` record nor the production
    // "Not connected" sentinel -- both share the same "connected|" prefix,
    // so this only passes if the real platform mechanism actually ran and
    // emitted something.
    CHECK(result.captured.find("connected|") != std::string::npos);
}

TEST_CASE("wifi plugin: list_networks reaches the real platform mechanism end to end",
          "[wifi][posix_actions]") {
    auto plugin = load_wifi_plugin();
    if (!plugin) {
        WARN("wifi plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_networks");
    CHECK(result.rc == 0);
    // Every list_networks code path -- a real NetworkManager/nmcli/airport
    // scan record, a raw iw/iwlist scan_output blob, a "no tools available"
    // error marker, or the honest "scan unavailable" info sentinel -- emits
    // at least one `wifi|`-prefixed line; only a broken migration (e.g. a
    // reverted shell hop, or a dropped return) produces nothing.
    CHECK(result.captured.find("wifi|") != std::string::npos);
}

// The ABI4 capability descriptor is the machine-readable claim the #2204
// capability matrix is generated from, and nothing else asserted it -- stale
// or untrue rung/mechanism metadata passed the whole suite. This is the
// regression guard for the class of defect where the descriptor advertises an
// acquisition path the binary cannot actually take.
TEST_CASE("wifi plugin: capability descriptors state the rung this binary can actually reach",
          "[wifi][posix_actions][descriptor]") {
    // REQUIRE, not a WARN-and-return: `load_wifi_plugin()` returns nullopt on a
    // failed dlopen OR a null descriptor, and tests/meson.build's link_depends
    // guarantees the artifact exists -- so the only remaining causes are
    // exactly the ABI/descriptor regressions this test was written to catch.
    // Skipping on them would make it pass vacuously in the one case that matters.
    auto plugin = load_wifi_plugin();
    REQUIRE(plugin.has_value());

    const auto* d = plugin->descriptor;
    REQUIRE(d->action_descriptors != nullptr);
    REQUIRE(d->action_descriptor_count == 2);

    const YuzuActionDescriptor* list_networks = nullptr;
    const YuzuActionDescriptor* connected = nullptr;
    for (std::size_t i = 0; i < d->action_descriptor_count; ++i) {
        const auto& a = d->action_descriptors[i];
        REQUIRE(a.action != nullptr);
        if (std::string_view{a.action} == "list_networks")
            list_networks = &a;
        else if (std::string_view{a.action} == "connected")
            connected = &a;
    }
    REQUIRE(list_networks != nullptr);
    REQUIRE(connected != nullptr);

    // macOS scan is CONSTRAINED rung 2 by roadmap decision -- the native
    // Location-gated scan belongs to the user-context-bridge programme, not
    // here. A silent promotion to "supported" would be a false capability
    // claim to every operator reading the matrix.
    CHECK(list_networks->macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(list_networks->macos_leg.rung == 2);

    // macOS connected is the shipped CoreWLAN native leg (rung 1), left
    // untouched by this migration -- still CONSTRAINED because Location
    // Services can withhold SSID/BSSID from a background daemon.
    CHECK(connected->macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(connected->macos_leg.rung == 1);

    // The Linux rung is a build-time fact: without libsystemd the whole
    // sd-bus body is compiled out and the honest answer is rung 2.
#if defined(YUZU_HAVE_LIBSYSTEMD)
    constexpr int kExpectedLinuxRung = 1;
#else
    constexpr int kExpectedLinuxRung = 2;
#endif
    CHECK(list_networks->linux_leg.rung == kExpectedLinuxRung);
    CHECK(connected->linux_leg.rung == kExpectedLinuxRung);

    // Both Linux legs are CONSTRAINED, not SUPPORTED: the AP-property
    // traversal has never returned a real access point on any host (the
    // NetworkManager used to verify the D-Bus contract was a container with
    // no radio). Promoting either without that evidence is the claim this
    // assertion exists to block -- see the rationale at YUZU_WIFI_LINUX_SUPPORT.
    CHECK(list_networks->linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(connected->linux_leg.support == YUZU_SUPPORT_CONSTRAINED);

    // Both Linux legs must name their argv fallback: the roadmap requires the
    // nmcli rung-2 descent be DECLARED, not merely implemented.
    REQUIRE(list_networks->linux_leg.fallback != nullptr);
    REQUIRE(connected->linux_leg.fallback != nullptr);
    CHECK(std::string_view{list_networks->linux_leg.fallback}.find("nmcli") !=
          std::string_view::npos);
    CHECK(std::string_view{connected->linux_leg.fallback}.find("nmcli") != std::string_view::npos);
}

#endif // !_WIN32
