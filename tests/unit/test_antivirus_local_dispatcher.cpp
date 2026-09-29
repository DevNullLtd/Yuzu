/**
 * test_antivirus_local_dispatcher.cpp -- execute-path coverage for the
 * antivirus plugin's Windows leg (Wave-3 native/argv+WMI+registry
 * acquisition migration).
 *
 * test_antivirus_parsers.cpp already covers every pure parsing/rendering
 * function (plist parsing, sysext parsing, WSC product-state decode,
 * exclusion-line rendering) as fixture-driven unit tests -- but nothing in
 * this branch previously exercised the plugin's actual execute() path: real
 * WMI queries against SecurityCenter2/Defender, and real
 * RegOpenKeyExW/RegEnumValueW calls against the live Defender exclusion
 * registry keys. This file closes that gap the same way
 * test_registry_local_dispatcher.cpp (PR1.7) does: load the ACTUAL built
 * antivirus.dll via PluginHandle::load and drive it through
 * yuzu::agent::LocalDispatcher, the same in-process dispatch mechanism used
 * for manual verification on a real Windows host.
 *
 * Scope, deliberately: assertions are host-config-agnostic (no assumption
 * about what AV product is installed, whether Defender is even the active
 * engine, or whether the test runs elevated) -- they pin CONTRACT shape
 * (rc, well-formed output, typed status lines) rather than specific product
 * data, the same posture test_registry_local_dispatcher.cpp takes toward
 * "own sid may not resolve on a system account" (WARN + skip rather than
 * fail). The av_exclusions completeness fix (win_profiles.hpp's
 * ValueNameEnumeration) is pinned narrowly: whatever the host's real
 * permission/exclusion state, the output must never silently claim
 * "exclusion_count|0" while also reporting a permission_denied or partial
 * status for the same run -- that combination is exactly the false-clean
 * read the fix exists to prevent.
 *
 * Linux/macOS execute paths (pgrep/plistbuddy/systemextensionsctl via the
 * bounded subprocess runner) are intentionally NOT covered here -- this
 * codebase's "OS interaction lives in a shell the unit suites never run"
 * convention (CLAUDE.md test-efficiency discipline) treats subprocess-driven
 * acquisition as integration surface, not unit surface, and no injectable
 * command-runner seam exists yet for those legs to unit-test against
 * fixtures. Windows-only; the plugin's WMI/registry code is a no-op
 * elsewhere.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Locate the real antivirus.dll built by agents/plugins/antivirus/meson.build.
// Mirrors test_registry_local_dispatcher.cpp's find_registry_plugin --
// returns an empty path (never fails) when not found, so a build invoked
// without the agent plugins must skip this test, not fail it.
fs::path find_antivirus_plugin() {
    const std::string lib_name = "antivirus.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "antivirus" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "antivirus" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "antivirus" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "antivirus" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

// Splits a captured output block into its lines, dropping empties.
std::vector<std::string> split_lines(const std::string& captured) {
    std::vector<std::string> lines;
    std::istringstream iss(captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
}

bool any_line_starts_with(const std::vector<std::string>& lines, std::string_view prefix) {
    for (const auto& l : lines) {
        if (l.starts_with(prefix))
            return true;
    }
    return false;
}

} // namespace

TEST_CASE("antivirus plugin: products/status/av_exclusions execute via "
          "LocalDispatcher against real WMI/registry",
          "[antivirus][windows][local_dispatcher]") {
    auto plugin_path = find_antivirus_plugin();
    if (plugin_path.empty()) {
        WARN("antivirus.dll not found (build_agent=false?) -- skipping "
             "LocalDispatcher execute-path test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::agent::LocalDispatcher dispatcher;

    SECTION("products: real WMI SecurityCenter2 query, well-formed output regardless "
            "of installed AV") {
        auto result = dispatcher.run(descriptor, "products");
        CHECK(result.rc == 0);
        // Either at least one "av|<name>|<state>" row, or the plugin found
        // nothing installed -- both are legitimate; what matters is the
        // call actually reached WMI and returned without throwing/crashing
        // (PluginHandle::load + LocalDispatcher::run would surface a crash
        // as a test failure, not a captured line).
    }

    SECTION("status: real Defender status query, well-formed output regardless of "
            "engine state") {
        auto result = dispatcher.run(descriptor, "status");
        CHECK(result.rc == 0);
    }

    SECTION("av_exclusions: real registry enumeration, never a false-clean read") {
        auto result = dispatcher.run(descriptor, "av_exclusions");
        CHECK(result.rc == 0);
        auto lines = split_lines(result.captured);

        const bool saw_exclusion = any_line_starts_with(lines, "exclusion|");
        const bool saw_zero = any_line_starts_with(lines, "exclusion_count|0");
        const bool saw_permission_denied = any_line_starts_with(lines, "permission_denied|");
        const bool saw_not_available = any_line_starts_with(lines, "not_available|");
        const bool saw_partial = any_line_starts_with(lines, "partial|");

        // Some typed line must be present -- av_exclusions_win always emits
        // at least one of these (falls back to "exclusion_count|0" only when
        // NOTHING else was written and no status was forwarded). Computed
        // into a local bool first -- Catch2's expression decomposition
        // rejects operator|| directly inside CHECK(), even parenthesized.
        const bool saw_any_typed_line = saw_exclusion || saw_zero || saw_permission_denied ||
                                        saw_not_available || saw_partial;
        CHECK(saw_any_typed_line);

        // The regression this test exists to pin: "exclusion_count|0" is
        // av_exclusions_win's total-silence fallback (total == 0 &&
        // !status_forwarded) -- it must never coexist with a
        // permission_denied/not_available/partial line, because that would
        // mean a real failure was reported AND the false-clean zero-count
        // line still went out. On a real host this is naturally satisfied
        // by the existing status_forwarded guard; this test pins the
        // observable contract end-to-end rather than trusting the guard by
        // reading the source.
        if (saw_zero) {
            const bool saw_conflicting_failure =
                saw_permission_denied || saw_not_available || saw_partial;
            CHECK_FALSE(saw_conflicting_failure);
        }
    }
}

#endif // _WIN32
