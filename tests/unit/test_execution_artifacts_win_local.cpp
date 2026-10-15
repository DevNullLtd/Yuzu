/**
 * test_execution_artifacts_win_local.cpp — P32's per-artifact shape
 * assertions, on top of test_execution_artifacts_local_dispatcher.cpp's
 * generic "real row or named constrained token" check (P31, this package's
 * dependency): each of the three Windows-leg actions gets its own targeted
 * assertion here, one TEST_CASE per artifact.
 *
 * Same loading harness as test_execution_artifacts_local_dispatcher.cpp --
 * LocalDispatcher over the ACTUAL built execution_artifacts.dylib/.so/.dll
 * -- so this exercises the real compiled leg, never a mock. UNGUARDED TU
 * (compiles and runs on every OS, test_filesystem_posture_local_dispatcher
 * .cpp's precedent for why a platform-guarded test TU hides a dead leg):
 * non-Windows hosts assert the fixed <action>|unsupported|windows_only_artefact
 * outcome (P31's contract, this package's own copy of that assertion so the
 * check lives with the rest of this file's per-artifact coverage); Windows
 * hosts get this package's (P32) per-artifact assertions below.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

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

[[maybe_unused]] bool any_row_starts_with(const std::vector<std::string>& rows,
                                          std::string_view prefix) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("execution_artifacts plugin library not found under meson test — the plugin did "
             "not build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("execution_artifacts plugin library not found -- skipping the win-local shape checks "
         "(run from the build root, or via `meson test`, to exercise it)");
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

#if defined(_WIN32)
// Whether THIS test process's token is elevated -- plugin_capture.cpp:157's
// precedent (same TokenElevation query; this file keeps its own minimal
// RAII rather than reaching into agents/core's Guardian-internal
// guard_win_handle.hpp for one short-lived token handle).
bool current_process_is_elevated() {
    struct TokenHandle {
        HANDLE h{nullptr};
        ~TokenHandle() {
            if (h)
                CloseHandle(h);
        }
    } token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.h))
        return false;
    TOKEN_ELEVATION te{};
    DWORD got = 0;
    if (!GetTokenInformation(token.h, TokenElevation, &te, sizeof te, &got))
        return false;
    return te.TokenIsElevated != 0;
}
#endif

} // namespace

#if !defined(_WIN32)

TEST_CASE("execution_artifacts win-local: non-Windows still reports "
          "<action>|unsupported|windows_only_artefact for all three actions",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"shimcache", "amcache", "prefetch"}) {
        INFO("action: " << action);
        auto result = dispatcher.run(plugin->descriptor, action);
        CHECK(result.rc == 1);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front() == std::string{action} + "|unsupported|windows_only_artefact");
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == "windows_only_artefact");
    }
}

#else // defined(_WIN32)

TEST_CASE("execution_artifacts win-local: shimcache returns real rows or a named constrained "
          "token, never an empty success",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "shimcache");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const bool has_success_row = any_row_starts_with(rows, "shimcache|");
    const bool has_constrained_row = any_row_starts_with(rows, "constrained|");
    CHECK((has_success_row || has_constrained_row));
    if (has_success_row)
        CHECK(result.rc == 0);
    else
        CHECK(result.rc == 1);
}

TEST_CASE("execution_artifacts win-local: prefetch returns real rows when Prefetch is enabled, "
          "else a named constrained/prefetch_error token -- never silent-empty",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "prefetch");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const bool has_success_row = any_row_starts_with(rows, "prefetch|");
    const bool has_named_reason =
        any_row_starts_with(rows, "constrained|") || any_row_starts_with(rows, "prefetch_error|");
    CHECK((has_success_row || has_named_reason));
    if (has_success_row && !has_named_reason)
        CHECK(result.rc == 0);
}

TEST_CASE("execution_artifacts win-local: amcache without init() (so agent.data_dir was never "
          "configured) reports the named data_dir_unset token, never an empty result",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    // Deliberately skip init() -- this is the "test/tool didn't configure
    // agent.data_dir" case execution_artifacts_win.cpp's collect_amcache
    // banner describes; must never fall back to guessing a location.
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "amcache");
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "constrained|data_dir_unset");
    CHECK(result.rc == 1);
}

TEST_CASE("execution_artifacts win-local: amcache, with agent.data_dir pointed at a real "
          "scratch dir, returns real rows or a named constrained token -- never an empty "
          "success -- and leaves the scratch dir empty afterward either way",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::test::TempDir data_dir("yuzu_test_execution_artifacts_data_dir_");
    std::error_code ec;
    fs::create_directories(data_dir.path, ec);
    REQUIRE_FALSE(ec);

    // Declared AFTER `plugin` (the library must outlive the context --
    // plugin_capture.cpp:352-354's precedent).
    yuzu::agent::StandalonePluginContext ctx(
        "execution_artifacts",
        std::unordered_map<std::string, std::string>{{"agent.data_dir", data_dir.path.string()}});
    if (plugin->descriptor->init)
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "amcache");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    // The round-1 fix's own defect (round-2 finding 1): a verifier that can
    // NEVER pass still produces a "real row or constrained" green test,
    // because dest_dir_acl IS a named constrained token. That false-green
    // is exactly why this assertion is split three ways instead of one
    // permissive OR -- a permanently-broken amcache leg must show up as a
    // FAILING test, not a passing one.
    const bool has_success_row = any_row_starts_with(rows, "amcache|");
    const bool has_dest_dir_token = any_row_starts_with(rows, "constrained|dest_dir_");
    const bool has_other_constrained_row =
        any_row_starts_with(rows, "constrained|") && !has_dest_dir_token;
    CAPTURE(result.captured);
    CHECK_FALSE(has_dest_dir_token);
    CHECK((has_success_row || has_other_constrained_row));
    if (has_success_row) {
        CHECK(result.rc == 0);
        if (current_process_is_elevated()) {
            // Elevated (or LocalSystem/service) access to
            // C:\Windows\appcompat\Programs\Amcache.hve is exactly this
            // leg's documented prerequisite -- under it, the leg must be
            // CAPABLE of producing a real, non-empty path, proving
            // collect_amcache's registry-value reads genuinely work end to
            // end and aren't silently defaulting every field to empty.
            //
            // This does NOT mean every row has one: root-caused live on
            // the-rig (2026-09-17) via `reg load`+`reg query` against a
            // copy of the real hive -- several InventoryApplicationFile
            // subkeys (observed: built-in driver files like
            // 1394kdbg.sys/1394ohci.sys) genuinely carry ONLY ProgramId
            // and FileId in the registry itself, no LowerCaseLongPath/
            // Size/LinkDate/etc. at all. That is real AmCache data
            // sparseness on this Windows build, not a read failure --
            // get_or_empty() (execution_artifacts_parsers.hpp) correctly
            // returns "" for a value that is genuinely absent, and
            // RegEnumKeyExW's enumeration order is not something this
            // plugin controls, so a sparse entry can legitimately land at
            // rows.front(). Asserting on THE FIRST row (as this test did
            // before) was the test's own bug, not production code's --
            // check that AT LEAST ONE row has a real path instead.
            const bool any_row_has_path = std::any_of(
                rows.begin(), rows.end(), [](const std::string& r) {
                    if (r.rfind("amcache|", 0) != 0)
                        return false;
                    const auto first_pipe = r.find('|');
                    const auto second_pipe = r.find('|', first_pipe + 1);
                    return second_pipe != std::string::npos && second_pipe > first_pipe + 1;
                });
            CHECK(any_row_has_path);
        }
    } else if (has_other_constrained_row) {
        CHECK(result.rc == 1);
    }

    if (plugin->descriptor->shutdown)
        plugin->descriptor->shutdown(ctx.get());

    // The scratch directory ScratchDirGuard owns is created AND removed
    // entirely within collect_amcache's own scope -- nothing under
    // data_dir should survive the dispatch above, success or failure.
    bool data_dir_empty = true;
    for (const auto& entry : fs::directory_iterator(data_dir.path, ec))
        (void)entry, data_dir_empty = false;
    CHECK_FALSE(ec);
    CHECK(data_dir_empty);
}

#endif
