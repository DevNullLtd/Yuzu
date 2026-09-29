/**
 * test_content_dist_actions.cpp -- LocalDispatcher round-trip coverage for
 * `content_dist`'s `execute_staged` action, same shape as
 * test_users_posix_actions.cpp: loads the ACTUAL built content_dist plugin
 * (content_dist.dylib/.so, the same artifact the agent daemon loads in
 * production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher.
 *
 * HONEST COVERAGE SPLIT (read before extending this file):
 *
 *   - THIS FILE covers only the pre-runner dispatch gates that are actually
 *     reachable through LocalDispatcher WITHOUT the plugin having been
 *     init()'d: missing-filename parameter validation, unsafe-filename
 *     rejection, and the file-not-staged check. `do_execute` beyond that
 *     point is gated on a hash re-verification read from agent KV (#808),
 *     and `content_dist_plugin.cpp`'s `PluginContext`/KV plumbing only
 *     becomes live once `init()` sets its module-global `g_ctx` from a REAL
 *     `PluginContextImpl` -- which is anonymous-namespace TU-local in
 *     agent.cpp (dispatch_with_capture, the shim LocalDispatcher::run calls
 *     into, invokes `descriptor->execute` directly and never
 *     `descriptor->init`). There is no legitimate way to drive a staged,
 *     hash-verified `execute_staged` end to end at the unit level, so this
 *     file does not attempt one -- proving these three gates already proves
 *     dispatch plumbing works and that a migrated action still reaches real
 *     validation code, without spawning anything. The same KV-hash-gate
 *     wall also puts the Linux shebang-payload rejection (CDX-002) out of
 *     this file's reach: it runs AFTER the hash re-verification passes, so
 *     it is covered instead by pure fixture tests on `is_shebang_payload`
 *     in test_content_dist_exec_parsers.cpp, not here.
 *   - The RUNNER-FACING mapping (what SubprocessOptions execute_staged runs
 *     with, and how a completed run's SubprocessResult becomes the
 *     status|/exit_code|/output| wire lines) is covered by pure fixture
 *     tests over constructed values in test_content_dist_exec_parsers.cpp --
 *     no plugin load, no process spawn.
 *   - The runner itself (yuzu::agent::run_bounded_subprocess's actual
 *     fork/exec/reap machinery) is covered by the core suite,
 *     test_subprocess_runner.cpp.
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

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at
// content_dist's own build output. Empty path (never a hard failure) when
// not found, so a build without agent plugins skips rather than fails.
fs::path find_content_dist_plugin() {
    const std::string lib_name = std::string{"content_dist"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "content_dist" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "content_dist" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "content_dist" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "content_dist" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "content_dist" /
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

std::optional<LoadedPlugin> load_content_dist_plugin() {
    auto plugin_path = find_content_dist_plugin();
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

TEST_CASE("content_dist plugin: execute_staged rejects a missing filename parameter",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // No "filename" param at all -- exercises do_execute's first guard,
    // reachable before the plugin's KV/hash machinery is ever touched.
    auto result = dispatcher.run(plugin->descriptor, "execute_staged");
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|missing required parameter: filename") !=
          std::string::npos);
}

TEST_CASE("content_dist plugin: execute_staged rejects an unsafe filename",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // Path traversal attempt -- is_safe_filename() rejects it before
    // do_execute ever touches the staging directory or agent KV.
    std::vector<YuzuParam> params{{"filename", "../../etc/passwd"}};
    auto result = dispatcher.run(plugin->descriptor, "execute_staged", params);
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|invalid filename") != std::string::npos);
}

TEST_CASE("content_dist plugin: execute_staged reports file-not-staged for a well-formed "
          "filename that was never staged",
          "[agent][content_dist][posix_actions]") {
    auto plugin = load_content_dist_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A syntactically valid filename (passes is_safe_filename) that this
    // test never staged first -- proves the fs::exists() gate in
    // `do_execute` runs, and that dispatch reaches it without the plugin
    // ever having been init()'d (LocalDispatcher's dispatch_with_capture
    // shim calls descriptor->execute directly, never descriptor->init --
    // see this file's header comment). A random-ish name avoids colliding
    // with a file another test or a real agent run happened to stage in
    // the same shared staging directory. (The same reasoning excludes the
    // Linux shebang pre-check added for CDX-002 from this file: it sits
    // AFTER the KV hash gate in `do_execute`, so it is unreachable here too
    // -- covered instead by pure fixture tests on `is_shebang_payload` in
    // test_content_dist_exec_parsers.cpp.)
    std::vector<YuzuParam> params{
        {"filename", "test-content-dist-actions-nonexistent-payload.bin"}};
    auto result = dispatcher.run(plugin->descriptor, "execute_staged", params);
    CHECK(result.rc != 0);
    CHECK(result.captured.find("error|file not staged: "
                               "test-content-dist-actions-nonexistent-payload.bin") !=
          std::string::npos);
}

#endif // !_WIN32
