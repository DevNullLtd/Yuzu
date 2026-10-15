/**
 * test_execution_artifacts_local_dispatcher.cpp — loads the ACTUAL built
 * execution_artifacts plugin (execution_artifacts.dylib/.so/.dll) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher
 * (test_app_usage_local_dispatcher.cpp's pattern), UNGUARDED — init() is
 * never called here. init() is NOT a no-op any more (it captures
 * agent.data_dir for the amcache leg's scratch directory) -- on Windows
 * that means an uninitialized amcache dispatch deterministically reports
 * `constrained|data_dir_unset` rather than reaching real collection code,
 * which this file's own assertions already treat as an ordinary
 * `constrained|` outcome. The init()-exercising amcache coverage lives in
 * test_execution_artifacts_win_local.cpp (P32), which DOES call init()
 * with a real agent.data_dir.
 *
 * RUNS ON ALL THREE PLATFORMS unconditionally, per
 * test_filesystem_posture_local_dispatcher.cpp's precedent for why a
 * platform-guarded dispatcher TU hides a dead leg. On Linux/macOS every
 * action must report `<action>|unsupported|windows_only_artefact`, exit code 1 —
 * this is THIS package's (P31) portion of the contract, and is fully
 * exercised on every build host. The Windows branch (P32's
 * execution_artifacts_win.cpp) is extended by P32's own test additions;
 * this file's Windows-branch assertions here are deliberately loose (accept
 * either real rows or a named constrained token) since P31 owns no Windows
 * collection code — see this package's spec, "boundaries": "No Windows API
 * calls in this package".
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
#include <utility>
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

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("execution_artifacts plugin library not found under meson test — the plugin did "
             "not build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("execution_artifacts plugin library not found -- skipping LocalDispatcher round-trip "
         "test (run from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_execution_artifacts_plugin() {
    const std::string lib_name = std::string{"execution_artifacts"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "execution_artifacts" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "execution_artifacts" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);

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

std::optional<LoadedPlugin> load_execution_artifacts_plugin() {
    auto plugin_path = find_execution_artifacts_plugin();
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

TEST_CASE("execution_artifacts plugin: ABI4 descriptors declare all three OS legs for every "
          "action, never #ifdef'd out (plugin.h:115-136)",
          "[execution_artifacts][descriptors]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 3);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
        // Non-Windows legs are a fixed UNSUPPORTED across all three actions
        // (this package's spec: "linux/macos {UNSUPPORTED, 0, nullptr, ...}").
        CHECK(d.linux_leg.support == YUZU_SUPPORT_UNSUPPORTED);
        CHECK(d.macos_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    }
}

// Runs on ALL THREE PLATFORMS unconditionally, same rationale as the
// descriptor test above. This plugin's file header claims "EACH ENTRY
// POINT IS INDEPENDENT: a failure in one artefact source never blocks the
// other two". The strongest local proof of that available on this host: no
// two actions share mutable state, so dispatching them in one order and
// then the reverse order must produce identical per-action results. A
// GENUINE "ShimCache fails for real while Amcache/Prefetch really succeed"
// case is NOT reachable from here -- collect_shimcache/collect_amcache/
// collect_prefetch (execution_artifacts_win.cpp) call RegQueryValueExW/
// CreateFileW/RegLoadAppKeyW directly, with no injectable reader seam, so
// distinguishing "real success" from "genuinely constrained" for one
// source in isolation needs either real Windows hardware with a
// deliberately broken environment for exactly one source, or a production
// seam refactor -- both out of scope for this test-only pass.
TEST_CASE("execution_artifacts plugin: dispatching one action never affects another's result -- "
          "no state shared across the shimcache/amcache/prefetch branches",
          "[execution_artifacts][actions][independence]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;

    auto run_all = [&](std::initializer_list<const char*> order) {
        std::vector<std::pair<std::string, int>> results;
        for (const char* action : order) {
            auto result = dispatcher.run(plugin->descriptor, action);
            const auto rows = captured_rows(result.captured);
            results.emplace_back(rows.empty() ? std::string{} : rows.front(), result.rc);
        }
        return results;
    };

    const auto forward = run_all({"shimcache", "amcache", "prefetch"});
    const auto reverse = run_all({"prefetch", "amcache", "shimcache"});
    REQUIRE(forward.size() == 3);
    REQUIRE(reverse.size() == 3);

    // Match up by action, not position: forward[0]/reverse[2] are both
    // shimcache, forward[1]/reverse[1] both amcache, forward[2]/reverse[0]
    // both prefetch.
    CHECK(forward[0] == reverse[2]); // shimcache, run 1st then 3rd
    CHECK(forward[1] == reverse[1]); // amcache, run 2nd both times
    CHECK(forward[2] == reverse[0]); // prefetch, run 3rd then 1st
}

#if !defined(_WIN32)

TEST_CASE("execution_artifacts plugin: every action reports <action>|unsupported|windows_only_artefact "
          "on a non-Windows build, exit 1",
          "[execution_artifacts][actions]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"shimcache", "amcache", "prefetch"}) {
        INFO("action: " << action);
        // UNGUARDED — no init() call: execute() alone must answer, exactly
        // like every other action-dispatch test in this repo.
        auto result = dispatcher.run(plugin->descriptor, action);

        CHECK(result.rc == 1);
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == "windows_only_artefact");

        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front() == std::string{action} + "|unsupported|windows_only_artefact");
    }
}

#else // defined(_WIN32)

TEST_CASE("execution_artifacts plugin: every action on Windows returns real rows or a named "
          "constrained token, never silent-empty (extended by P32)",
          "[execution_artifacts][actions]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"shimcache", "amcache", "prefetch"}) {
        INFO("action: " << action);
        auto result = dispatcher.run(plugin->descriptor, action);

        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty()); // never an empty success, on any host

        const std::string kind = std::string{action};
        const bool is_success_row = rows.front().rfind(kind + "|", 0) == 0;
        const bool is_constrained = rows.front().rfind("constrained|", 0) == 0;
        CHECK((is_success_row || is_constrained));
        if (is_success_row)
            CHECK(result.rc == 0);
        else
            CHECK(result.rc == 1);
    }
}

#endif
