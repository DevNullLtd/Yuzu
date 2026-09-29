/**
 * test_script_exec_win_actions.cpp -- whole-branch review round 3 (BR3-003):
 * script_exec's `exec`/`powershell` actions had zero Windows LocalDispatcher
 * coverage even though this branch replaces BOTH plugins' private Windows
 * launchers -- test_script_exec_actions.cpp (the POSIX twin this file
 * mirrors) is a `#ifndef _WIN32` TU, and test_script_exec_parsers.cpp never
 * loads the real plugin or spawns a child on either platform. Loads the
 * ACTUAL built script_exec plugin (script_exec.dll, the same artifact the
 * agent daemon loads in production) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher -- the same in-process dispatch
 * pattern test_windows_updates_win_actions.cpp established for other
 * Windows-only plugins.
 *
 * The `powershell` case in particular is the direct end-to-end exercise of
 * BR3-001's fix: do_powershell resolves its PowerShell launch path via
 * yuzu::agent::windows_system_directory() (GetSystemDirectoryW, cached) at
 * call time rather than trusting a compile-time "C:\Windows\System32"
 * literal, and this test proves that resolved path is a real, executable
 * PowerShell 5.1 on a genuine Windows host, not merely well-formed text a
 * pure parser test would accept unchecked.
 *
 * Windows-only; a no-op TU elsewhere via this file's own #ifdef _WIN32
 * guard, matching test_script_exec_actions.cpp's #ifndef _WIN32 split.
 *
 * DISCLOSED: this suite has never been executed -- this host is macOS, and
 * these cases only ever run on the Windows CI leg, which is the actual
 * enforcement point for a Windows-only backend (per CLAUDE.md's Darwin
 * Compatibility guidance: this host is compile-checked only for Windows
 * code). Registered in tests/meson.build's Windows-guarded section so they
 * genuinely compile and run there, not merely exist in the tree.
 */
#include <catch2/catch_test_macros.hpp>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::windows_system_directory (BR4-005)
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Mirrors test_script_exec_actions.cpp's find_script_exec_plugin, pointed at
// the Windows build output extension.
fs::path find_script_exec_plugin() {
    const std::string lib_name = "script_exec.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "script_exec" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "script_exec" /
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

std::optional<LoadedPlugin> load_script_exec_plugin() {
    auto plugin_path = find_script_exec_plugin();
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

TEST_CASE("script_exec plugin (Windows): exec streams real cmd.exe output through the runner",
          "[script_exec][windows][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a benign
    // "plugin not built this configuration" case (BR-005 precedent).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // An already-absolute command -- resolve_executable's ABSOLUTE branch,
    // never touching runner_default_cwd()/windows_system_directory() at
    // all (that path is exercised by the powershell case below, whose
    // launch path is ALWAYS resolved that way). cmd.exe's own /c parses
    // the rest of the reassembled command line as one command, so this
    // proves the runner's argv->command-line reconstruction round-trips
    // correctly for a real Windows child.
    //
    // BR4-005 (whole-branch review round 4): runtime-resolved via
    // yuzu::agent::windows_system_directory() rather than a hard-coded
    // "C:\\Windows\\System32" literal -- the hard-coded form fails this
    // whole test (fs::copy_file/CreateProcessW can't find the literal)
    // before ever exercising anything on the relocated-system (non-`C:`)
    // configuration BR3-001's runtime resolution fix exists to protect,
    // silently hiding exactly the class of regression that fix closes.
    const std::string cmd_exe = yuzu::agent::windows_system_directory() + "\\cmd.exe";
    std::vector<YuzuParam> params{{"command", cmd_exe.c_str()}, {"args", "/c echo happy-path-win"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|happy-path-win");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin (Windows): powershell resolves and runs a real PowerShell 5.1 "
          "end to end (BR3-001)",
          "[script_exec][windows][actions]") {
    auto plugin = load_script_exec_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"script", "Write-Output 'hello-from-powershell-test'"}};
    auto result = dispatcher.run(plugin->descriptor, "powershell", params);

    // A failure here (rather than an assertion mismatch below) would mean
    // yuzu::agent::windows_system_directory() resolution itself failed
    // (GetSystemDirectoryW returning 0 -- do_powershell's own fail-closed
    // branch, never reached on any real Windows host) or the resolved
    // launch path did not actually point at a real, executable
    // PowerShell -- exactly the class of defect a pure parser fixture
    // cannot catch.
    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|hello-from-powershell-test");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin (Windows): exec with an unresolvable bare command reports "
          "status|error without ever calling the runner",
          "[script_exec][windows][actions]") {
    auto plugin = load_script_exec_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A bare name with no separator that resolve_executable's real PATH
    // search (and the runner_default_cwd() join for a relative form) will
    // not find on any normal test host -- exercises the early-return path
    // (no subprocess spawn attempted at all), same shape as the POSIX
    // twin's identical case.
    std::vector<YuzuParam> params{{"command", "yuzu-test-definitely-missing-binary-xyz"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc == 1);
    auto status_pos = result.captured.find("status|error");
    auto exit_pos = result.captured.find("exit_code|-1");
    REQUIRE(status_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    CHECK(status_pos < exit_pos);
}

#endif // _WIN32
