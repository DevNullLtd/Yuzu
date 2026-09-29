/**
 * test_software_actions_actions.cpp — Wave 4 PR4.3b: loads the ACTUAL built
 * software_actions plugin (software_actions.dylib/.so, the same artifact the
 * agent daemon loads in production) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher (test_users_posix_actions.cpp's
 * pattern) — proves the migrated argv actually reaches the real
 * dpkg-query/rpm/pkgutil tool, not just that the pure parsers are correct in
 * isolation.
 *
 * ONLY `installed_count` is dispatched here — it is fast and fully local
 * (dpkg-query/rpm on Linux, pkgutil --pkgs on macOS, and on Windows a native
 * registry read with no subprocess at all). `list_upgradable` is
 * deliberately NEVER dispatched from a unit test: on macOS it shells out to
 * `softwareupdate -l`, which hits Apple's catalog over the network and can
 * take tens of seconds — exactly the slow/network-dependent shape the repo's
 * test-efficiency discipline keeps out of the unit suites.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cctype>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
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

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at the
// software_actions plugin's own build output.
fs::path find_software_actions_plugin() {
    const std::string lib_name = std::string{"software_actions"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "software_actions" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "software_actions" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "software_actions" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "software_actions" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "software_actions" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "software_actions" /
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

std::optional<LoadedPlugin> load_software_actions_plugin() {
    auto plugin_path = find_software_actions_plugin();
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

#ifndef _WIN32

TEST_CASE("software_actions plugin: installed_count reports a real digit count via "
          "dpkg-query/rpm/pkgutil argv",
          "[software_actions]") {
    // Deliberately NOT a WARN-and-skip. tests/meson.build links the
    // software_actions plugin into this executable, so it is always present
    // when this case runs; a skip would let a plugin-load failure -- exactly
    // what a broken migration looks like -- pass as green with ZERO
    // assertions, which the repo treats as a policy-floor violation when
    // offered as closure evidence.
    auto plugin = load_software_actions_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "installed_count");
    CHECK(result.rc == 0);

    // A reverted/broken migration (wrong tool, wrong argv, a silently
    // reintroduced shell hop that no-ops) would either fail this call or
    // produce output that never matches `count|<digits>` -- this line only
    // appears if the real dpkg-query/rpm/pkgutil argv actually ran and the
    // pure parser counted its output correctly.
    auto pos = result.captured.find("count|");
    REQUIRE(pos != std::string::npos);
    auto rest = result.captured.substr(pos + 6);
    while (!rest.empty() && (rest.back() == '\n' || rest.back() == '\r'))
        rest.pop_back();
    REQUIRE_FALSE(rest.empty());
    for (char c : rest) {
        CHECK(std::isdigit(static_cast<unsigned char>(c)));
    }
    // Any dev or CI host has dpkg/rpm/pkgutil records. Without this the case
    // is satisfied by `count|0` -- the exact fabricated zero the degrade paths
    // were changed to stop emitting. Non-default-config assumption: today's
    // CI runners (GH-hosted, self-hosted Big Tam/Wee Tam) are full OS
    // installs, so this holds; it would need revisiting against a genuinely
    // minimal/containerized image with zero installed-software records.
    // std::from_chars rather than std::stoll: it does not throw, so a
    // non-digit capture (the isdigit loop above having already failed) still
    // fails via a clean REQUIRE rather than an uncaught-exception diagnostic
    // that points at the wrong line.
    long long count = 0;
    auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), count);
    REQUIRE(ec == std::errc{});
    CHECK(count > 0);
}

#else // _WIN32

TEST_CASE("software_actions plugin: installed_count reads the Uninstall key natively (rung 1)",
          "[software_actions]") {
    // The Windows leg of installed_count is the ONLY rung-1 path in this
    // plugin: RegOpenKeyExW + RegQueryInfoKeyW, zero subprocesses, replacing a
    // `powershell -Command` shell-out. It is Windows-only code, so this is the
    // only place it can be exercised end to end -- the pure
    // installed_count_line() tests cover the emit decision but never touch the
    // registry. Cheap and fully local (one registry open + one query), so it
    // respects the unit-suite efficiency discipline: no subprocess, no
    // network, no clock.
    auto plugin = load_software_actions_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "installed_count");

    // rc 0 == the registry read succeeded. HKLM\...\Uninstall is readable by
    // any user on every supported Windows, so a failure here is a real defect,
    // not an environment quirk.
    CHECK(result.rc == 0);

    auto pos = result.captured.find("count|");
    REQUIRE(pos != std::string::npos);
    auto rest = result.captured.substr(pos + 6);
    while (!rest.empty() && (rest.back() == '\n' || rest.back() == '\r'))
        rest.pop_back();
    REQUIRE_FALSE(rest.empty());
    for (char c : rest) {
        CHECK(std::isdigit(static_cast<unsigned char>(c)));
    }
    // A real Windows host always has Uninstall subkeys. A zero here would mean
    // the native read silently returned nothing -- the fabricated-zero shape
    // this plugin's degrade path was changed to avoid. Non-default-config
    // assumption: today's runners (GH-hosted windows-latest, self-hosted Wee
    // Tam) are full OS installs, so this holds; it would need revisiting
    // against a genuinely minimal/containerized Windows image.
    // std::from_chars rather than std::stoll: it does not throw, so a
    // non-digit capture (the isdigit loop above having already failed) still
    // fails via a clean REQUIRE rather than an uncaught-exception diagnostic.
    long long count = 0;
    auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), count);
    REQUIRE(ec == std::errc{});
    CHECK(count > 0);
}

#endif // _WIN32
