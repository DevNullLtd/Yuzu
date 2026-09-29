/**
 * test_app_control_local_dispatcher.cpp -- loads the ACTUAL built app_control
 * plugin via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally -- no platform guard on any
 * TEST_CASE (a guarded dispatcher TU hid a never-loaded plugin on PR6.1-b). Which
 * expectation applies is decided at runtime from the loaded library's extension:
 * a non-Windows build MUST produce the exact unsupported row and an UNAVAILABLE
 * status, so a dead non-Windows leg fails here instead of skipping.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "../../agents/plugins/app_control/src/app_control_parsers.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
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
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
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
        FAIL("app_control plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    WARN("app_control plugin library not found -- skipping (run from the build root, or via "
         "`meson test`, to exercise it)");
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_app_control_plugin() {
    const fs::path rel =
        fs::path{"agents"} / "plugins" / "app_control" / (std::string{"app_control"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-windows", "build-linux"})
        candidates.push_back(fs::path{dir} / rel);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (!fs::exists(p, ec) || ec)
            continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(p, ec));
        if (!handle.has_value() || !handle->descriptor())
            return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("app_control plugin: all three OS legs declared; Linux/macOS unsupported with a fallback "
          "string, Windows rung 1",
          "[app_control][descriptors]") {
    auto plugin = load_app_control_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    REQUIRE(plugin->descriptor->action_descriptor_count == 2);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    std::unordered_set<std::string> seen;
    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        REQUIRE(d.action != nullptr);
        INFO("action: " << d.action);
        seen.insert(d.action);
        CHECK(d.linux_leg.support == YUZU_SUPPORT_UNSUPPORTED);
        CHECK(d.macos_leg.support == YUZU_SUPPORT_UNSUPPORTED);
        CHECK(d.linux_leg.fallback != nullptr);
        CHECK(d.macos_leg.fallback != nullptr);
        // wdac_policy is declared SUPPORTED (only VerifiedAndReputablePolicyState=0 was observed,
        // and the legacy SiPolicy.p7b is reported by presence only); applocker_policy's CIM
        // property names and SrpV2 layout never were observed, so its Windows leg is declared
        // CONSTRAINED.
        CHECK(d.windows_leg.support == (std::string_view{d.action} == "wdac_policy"
                                            ? YUZU_SUPPORT_SUPPORTED
                                            : YUZU_SUPPORT_CONSTRAINED));
        CHECK(d.windows_leg.rung == 1);
    }
    CHECK(seen == std::unordered_set<std::string>{"wdac_policy", "applocker_policy"});
}

TEST_CASE("app_control plugin: each action -- exact unsupported row + UNAVAILABLE off Windows, "
          "closed-vocabulary rows on Windows",
          "[app_control][actions]") {
    auto plugin = load_app_control_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    for (const std::string action : {"wdac_policy", "applocker_policy"}) {
        INFO("action: " << action);
        yuzu::agent::LocalDispatcher dispatcher;
        auto result = dispatcher.run(plugin->descriptor, action);
        const auto rows = captured_rows(result.captured);

        if (std::string{kPluginExt} != ".dll") {
            CHECK(result.rc == 1);
            REQUIRE(rows.size() == 1);
            CHECK(rows[0] == action + "|unsupported|windows_only_concept");
            CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == "windows_only_concept");
            continue;
        }

        // Windows: real rows, or a constrained row with a matching typed status --
        // never an empty success. rc 0 iff status OK.
        REQUIRE_FALSE(rows.empty());
        CHECK((result.rc == 0) == (result.result_status == YUZU_RESULT_STATUS_OK));
        if (result.rc == 0) { // an OK run names its source (README "Result status")
            const std::string_view prov = result.result_provenance;
            using namespace yuzu::app_control;
            CHECK((action == "wdac_policy" ? prov == kProvenanceCiPolicy
                                           : prov == kProvenanceSrpV2 || prov == kProvenanceCim));
        }
        for (const auto& r : rows) {
            INFO("row: " << r);
            const bool known = r.rfind("wdac|", 0) == 0 || r.rfind("wdac_cip|", 0) == 0 ||
                               r.rfind("applocker|", 0) == 0 || r.rfind("constrained|", 0) == 0;
            CHECK(known);
            if (r.rfind("constrained|", 0) == 0)
                CHECK((result.result_status == YUZU_RESULT_STATUS_CONSTRAINED ||
                       result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED));
        }

        // Each action answers with its OWN row family, whatever this host holds: a wdac_policy
        // that returned applocker rows (or a lone stub row) fails here.
        if (result.rc != 0) {
            CHECK(count_prefix(rows, "constrained|") == 1);
        } else if (action == "wdac_policy") {
            // Every host answers the .cip question (none row or files). A present-but-empty
            // CI\Policy key is legitimate and emits no wdac| row, so that count is not asserted.
            CHECK(count_prefix(rows, "wdac_cip|") >= 1);
            CHECK(count_prefix(rows, "applocker|") == 0);
        } else {
            CHECK(count_prefix(rows, "applocker|") >= 1);
            CHECK(count_prefix(rows, "wdac") == 0);
        }
    }
}

TEST_CASE("app_control plugin: an unknown action is refused with an escaped row, never ignored",
          "[app_control][actions]") {
    auto plugin = load_app_control_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    // The request-supplied name lands in a pipe-delimited stream: `|` is escaped and a newline
    // folds to a space (yuzu::util::safe_output_field), so one bad name is exactly one row.
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no|such\naction");
    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no\\|such action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED); // never reported a typed status
}
