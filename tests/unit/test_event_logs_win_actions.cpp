/**
 * test_event_logs_win_actions.cpp -- Wave-4 PR4.2 native-acquisition
 * migration remediation (test_event_logs_parsers.cpp only exercises the
 * pure event_logs_parsers.hpp header -- it never calls do_errors/do_query,
 * so it stays green even if the wevtapi migration were reverted to the old
 * PowerShell Get-WinEvent _popen leg). Loads the ACTUAL built event_logs
 * plugin (event_logs.dll, the same artifact the agent daemon loads in
 * production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher -- the same in-process dispatch pattern
 * test_windows_updates_win_actions.cpp / test_sccm_win_actions.cpp
 * established.
 *
 * This is the required action-dispatch-level test for the migrated Windows
 * leg (wevtapi EvtQuery/EvtRender, bounded EvtNext wait).
 *
 * Hard failure, not WARN-and-skip, when the plugin isn't found: tests/
 * meson.build's link_depends on event_logs_plugin_lib orders the plugin
 * build ahead of this test binary, so on a correctly configured Windows CI
 * leg the plugin is ALWAYS present -- its absence is a real regression, not
 * a benign skip case (the false-green shape both external reviewers
 * remediated on test_windows_updates_win_actions.cpp / test_sccm_win_
 * actions.cpp).
 *
 * "errors"/"query" against the real System/Application channels only assert
 * the row PREFIX ("error|"/"event|"), never rc-implies-success: a
 * non-elevated CI runner account can legitimately hit ERROR_ACCESS_DENIED
 * against a channel, and describe_evt_query_failure's typed failure path
 * still writes a prefixed row and returns rc==0 (the plugin's own honest-
 * degradation contract -- see event_logs_plugin.cpp's EvtQueryOutcome
 * handling) -- so a permission_denied/timeout/other-error row is just as
 * legal here as a populated or honest-empty one. The THIRD case below
 * deliberately queries a channel that cannot exist on any host, which
 * discriminates the typed ERROR_EVT_CHANNEL_NOT_FOUND path from every other
 * outcome and is pinned as a hard CHECK.
 */
#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Mirrors test_windows_updates_win_actions.cpp's find_windows_updates_plugin,
// pointed at the event_logs plugin's own build output.
fs::path find_event_logs_plugin() {
    const std::string lib_name = "event_logs.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "event_logs" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "event_logs" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "event_logs" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "event_logs" /
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

// See test_event_logs_posix_actions.cpp's identical helper: captured is
// newline-joined rows with no embedded newlines (safe_output_field folds
// CR/LF before a row is ever written).
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

} // namespace

TEST_CASE("event_logs plugin (Windows): errors executes the real bounded wevtapi "
          "EvtQuery/EvtRender leg, every row error|-prefixed",
          "[event_logs][win_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"log", "System"}, {"hours", "24"}};
    auto result = dispatcher.run(plugin->descriptor, "errors", params);
    CHECK(result.rc == 0);
    // A reverted argv/API (e.g. back to the deleted PowerShell Get-WinEvent
    // shell-out) either fails or produces a row that never matches
    // "error|" -- this only passes if the real EvtQuery/EvtRender path
    // actually ran, whether it found events, found none (honest-empty
    // sentinel), or hit a typed failure (permission_denied on a
    // non-elevated runner is legal and still row-prefixed).
    //
    // The non-empty check is load-bearing: every_nonempty_line_has_prefix is
    // vacuously true for empty input, so without it a leg that emitted
    // NOTHING would pass both assertions. The plugin always emits real rows,
    // the honest-empty sentinel, or a typed failure row -- never silence.
    CHECK_FALSE(result.captured.empty());
    CHECK(every_nonempty_line_has_prefix(result.captured, "error|"));
}

TEST_CASE("event_logs plugin (Windows): query executes the real bounded wevtapi leg, "
          "every row event|-prefixed",
          "[event_logs][win_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{
        {"log", "Application"}, {"filter", "Windows"}, {"count", "10"}};
    auto result = dispatcher.run(plugin->descriptor, "query", params);
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty()); // bare silence is a regression, not a pass
    CHECK(every_nonempty_line_has_prefix(result.captured, "event|"));
}

TEST_CASE("event_logs plugin (Windows): errors against a nonexistent channel reports the "
          "honest channel-not-found message, not a generic failure",
          "[event_logs][win_actions]") {
    auto plugin = load_event_logs_plugin();
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // No host has a channel named this -- discriminates
    // EvtQueryOutcome::kChannelNotFound (ERROR_EVT_CHANNEL_NOT_FOUND /
    // ERROR_FILE_NOT_FOUND) from every other outcome (access-denied,
    // timeout, other-error, or a real populated/empty result).
    std::vector<YuzuParam> params{{"log", "YuzuNoSuchChannel12345"}, {"hours", "24"}};
    auto result = dispatcher.run(plugin->descriptor, "errors", params);
    CHECK(result.rc == 0);
    // Hard CHECK, not WARN: describe_evt_query_failure's kChannelNotFound
    // branch deterministically produces this exact message -- a reverted/
    // broken EvtQuery call, or one that collapsed every failure into the
    // generic "Event log query failed" string, would NOT reproduce it.
    CHECK(result.captured.find("Event log channel not found or unavailable") !=
          std::string::npos);
}

#endif // _WIN32
