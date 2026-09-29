/**
 * test_event_logs_posix_actions.cpp -- Wave-4 PR4.2 native-acquisition
 * migration remediation (test_event_logs_parsers.cpp only exercises the
 * pure event_logs_parsers.hpp header; test_event_logs_macos.cpp only
 * exercises the pure `log show` SubprocessResult classifier -- neither
 * proves the plugin's actual do_errors/do_query handlers execute). Loads
 * the ACTUAL built event_logs plugin (event_logs.dylib/.so, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher -- the same in-process
 * dispatch pattern test_users_posix_actions.cpp / test_windows_updates_
 * posix_actions.cpp established.
 *
 * This is the required action-dispatch-level test for the migrated Linux
 * leg (bounded sd_journal behind systemd_guard, falling back to a bounded
 * journalctl argv invocation) and covers macOS's unchanged `log show` leg
 * for free (same #ifndef _WIN32 scope). Deliberately does NOT assert which
 * acquisition leg ran -- native sd_journal, the journalctl fallback, and
 * macOS `log show` all agree on the row-prefix shape, and the honest-empty
 * sentinel row ("error|none|-|...") satisfies the same prefix check as a
 * real row, so this stays host-agnostic by construction rather than by
 * skip-on-mismatch.
 *
 * Hard failure, not WARN-and-skip, when the plugin isn't found: tests/
 * meson.build's link_depends on event_logs_plugin_lib orders the plugin
 * build ahead of this test binary, so on a correctly configured CI leg the
 * plugin is ALWAYS present -- its absence is a real regression, not a
 * benign skip case (CLAUDE.md floors a WARN-and-pass here as "a
 * false-green test offered as closure evidence for a blocking finding",
 * the exact shape test_windows_updates_win_actions.cpp / test_sccm_win_
 * actions.cpp were remediated for).
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at the
// event_logs plugin's own build output.
fs::path find_event_logs_plugin() {
    const std::string lib_name = std::string{"event_logs"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "event_logs" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "event_logs" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "event_logs" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "event_logs" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "event_logs" /
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

std::optional<LoadedPlugin> load_event_logs_plugin() {
    auto plugin_path = find_event_logs_plugin();
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

// LocalDispatcher::Result::captured newline-joins each write_output() call
// with no trailing newline and no embedded newlines (safe_output_field
// folds CR/LF before a row is ever written) -- splitting on '\n' recovers
// exactly the rows the plugin emitted.
bool every_nonempty_line_has_prefix(std::string_view captured, std::string_view prefix) {
    std::size_t pos = 0;
    while (true) {
        auto nl = captured.find('\n', pos);
        const std::string_view line =
            (nl == std::string_view::npos) ? captured.substr(pos) : captured.substr(pos, nl - pos);
        if (!line.empty() && !line.starts_with(prefix))
            return false;
        if (nl == std::string_view::npos)
            return true;
        pos = nl + 1;
    }
}

// macOS-only: `log show`'s "permission_denied" tag (event_logs_macos.hpp's
// LogShowOutcome::store_permission_denied) means this process's privilege
// tier -- non-root, no login session -- cannot open the local unified-log
// data store AT ALL (EX_NOPERM/77), independent of Full Disk Access. Proven
// by a differential probe (darwin-guardian investigation, PR #3578): a root
// headless daemon opens the store and gets real rows; the identical predicate
// as a non-root headless service account (every CI runner, by the agent
// privilege model's own design -- docs/agent-privilege-model.md) gets
// EX_NOPERM every time, even with every FDA grant tried. A real login
// session (this is why it never reproduces on a developer's own Mac) also
// opens the store. Production is unaffected: the macOS agent runs as a root
// LaunchDaemon. SKIP rather than FAIL here so this test still catches a
// genuine acquisition regression (wrong tool, wrong argv, a shell hop that
// silently no-ops) on any host that CAN open the store, while never
// red-ing CI purely because of the runner's privilege tier -- see
// docs/darwin-compat.md.
#if defined(__APPLE__)
bool is_macos_log_store_permission_denied(const std::string& captured) {
    return captured.find("|permission_denied|") != std::string::npos;
}
#endif

} // namespace

TEST_CASE("event_logs plugin: errors executes the real acquisition leg, every row error|-prefixed",
          "[event_logs][posix_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"log", "System"}, {"hours", "1"}};
    auto result = dispatcher.run(plugin->descriptor, "errors", params);
#if defined(__APPLE__)
    if (is_macos_log_store_permission_denied(result.captured)) {
        SKIP("macOS log show could not open the local log store in this process's privilege "
             "tier (non-root, no login session) -- see docs/darwin-compat.md. Not a plugin "
             "regression: production runs as a root LaunchDaemon, which can open the store.");
    }
#endif
    CHECK(result.rc == 0);
    // A leg that silently emitted NOTHING would satisfy rc==0 and vacuously
    // satisfy the prefix check below (every_nonempty_line_has_prefix is true
    // for empty input). The plugin's contract is that it always emits either
    // real rows or the honest-empty sentinel row, so bare silence is a real
    // regression and must fail here rather than read as a pass.
    CHECK_FALSE(result.captured.empty());
    // A reverted/broken leg (wrong tool, wrong argv, or a shell hop that
    // silently no-ops) either fails this call or produces a row that never
    // matches "error|" -- this only passes if a real acquisition leg
    // (native sd_journal, the journalctl fallback, or macOS `log show`)
    // actually ran and its result was formatted through win/journal row
    // helpers or the plugin's own honest-empty sentinel, never bare silence.
    CHECK(every_nonempty_line_has_prefix(result.captured, "error|"));
}

TEST_CASE("event_logs plugin: query with missing required params fails cleanly",
          "[event_logs][posix_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "query"); // no "log"/"filter" params
    CHECK(result.rc == 1);
    CHECK(result.captured.find("error|") != std::string::npos);
}

TEST_CASE("event_logs plugin: query executes the real acquisition leg, every row event|-prefixed",
          "[event_logs][posix_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"log", "System"}, {"filter", "a"}, {"count", "5"}};
    auto result = dispatcher.run(plugin->descriptor, "query", params);
#if defined(__APPLE__)
    if (is_macos_log_store_permission_denied(result.captured)) {
        SKIP("macOS log show could not open the local log store in this process's privilege "
             "tier (non-root, no login session) -- see docs/darwin-compat.md. Not a plugin "
             "regression: production runs as a root LaunchDaemon, which can open the store.");
    }
#endif
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty()); // bare silence is a regression, not a pass
    CHECK(every_nonempty_line_has_prefix(result.captured, "event|"));
}

TEST_CASE("event_logs plugin: descriptor advertises the migrated version and ABI4 declarations",
          "[event_logs][posix_actions]") {
    // The runtime advertisement is what the server's capability matrix and the
    // os-capability-matrix generated block are derived from, so it can drift
    // away from the implemented migration with every other test still green.
    // Pin the parts this PR changed: the 1.0.0 -> 1.1.0 bump, ABI4 (required
    // for per-action capability declarations to exist at all), and the two
    // migrated actions each carrying a declaration.
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());
    const auto* d = plugin->descriptor;

    REQUIRE(d->version != nullptr);
    CHECK(std::string_view{d->version} == "1.1.0");
    CHECK(std::string_view{d->name} == "event_logs");
    CHECK(d->abi_version == 4);
    REQUIRE(d->action_descriptors != nullptr);
    CHECK(d->action_descriptor_count == 2); // errors + query, both migrated
}

TEST_CASE("event_logs plugin: an unknown action fails with the standard unknown-action message",
          "[event_logs][posix_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "bogus_action");
    CHECK(result.rc == 1);
    CHECK(result.captured.find("unknown action") != std::string::npos);
}

#endif // !_WIN32
