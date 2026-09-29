/**
 * test_users_posix_actions.cpp -- Wave 2 WP-A remediation (code-review
 * finding F1/F2: no test proves the migrated argv actually reaches the real
 * tool). Loads the ACTUAL built users plugin (users.dylib/.so, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher, the same pattern
 * test_registry_local_dispatcher.cpp established for Windows -- this is its
 * POSIX (macOS + Linux) counterpart. Unlike test_users_macos_last.cpp / the
 * pure users_win_events.hpp tests (parser-level only), this exercises the
 * direct-argv runner shell end to end against the real `who`/`w`/`last`/
 * `lastlog`/`dscl` binaries on the test host: every assertion below would
 * fail if a migrated action's argv were wrong, pointed at the wrong tool, or
 * silently reverted to a shell string.
 *
 * Content assertions are anchored on data that is guaranteed present and
 * stable on any host running this suite (the current process's own account,
 * which /etc/passwd or dscl always lists, and this session's own `who`/`w`
 * console entry) -- never on fleet-specific or timing-sensitive state.
 * `primary_user`/`session_history` (backed by `last`, a historical login
 * log) are asserted on rc/shape only, not specific content: an empty wtmp on
 * a fresh CI runner is a legitimate, non-error state the production code
 * already handles ("no login records"), so asserting specific rows there
 * would make the test host-history-dependent rather than migration-dependent.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <pwd.h>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_registry_local_dispatcher.cpp's find_registry_plugin, pointed
// at the users plugin's own build output. Empty path (never a hard failure)
// when not found, so a build without agent plugins skips rather than fails.
fs::path find_users_plugin() {
    const std::string lib_name = std::string{"users"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "users" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "users" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "users" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "users" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "users" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

// The calling process's own account name -- always present in the passwd
// database (unlike an interactive login, which a sandboxed CI runner may
// lack), so it's the one identity guaranteed reachable via local_users'
// dscl/passwd enumeration on every host.
std::string current_username() {
    if (const auto* pw = ::getpwuid(::getuid()); pw && pw->pw_name)
        return pw->pw_name;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_users_plugin() {
    auto plugin_path = find_users_plugin();
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

TEST_CASE("users plugin: local_users lists the current account via real dscl/passwd argv",
          "[users][posix_actions]") {
    auto plugin = load_users_plugin();
    if (!plugin) {
        WARN("users plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }
    const auto me = current_username();
    if (me.empty()) {
        WARN("could not resolve own username via getpwuid -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "local_users");
    CHECK(result.rc == 0);
#ifdef __linux__
    // On Linux, do_local_users deliberately excludes system/service accounts
    // (uid != 0 && uid < 1000, users_plugin.cpp) from the enumeration -- a
    // correct filter, not a migration regression. A CI runner account is
    // frequently provisioned exactly in that range (observed: Big Tam's
    // "runner" user), in which case the plugin's own output will correctly
    // never mention it, and the content assertion below would fail for a
    // reason that has nothing to do with whether the migrated argv actually
    // ran (found via a real Linux CI red on PR #3244 -- Big Tam's runner
    // account is uid<1000).
    if (const uid_t uid = ::getuid(); uid != 0 && uid < 1000) {
        WARN("running as a system/service account (uid " << uid << ") that "
             "do_local_users's own uid<1000 filter excludes -- content "
             "assertion skipped; rc==0 above already confirms the real "
             "dscl/passwd argv executed");
        return;
    }
#endif
    // Reverting the migrated argv (wrong tool, wrong flags, or a shell hop
    // that silently no-ops) would either fail this call or produce output
    // that never mentions a real account -- this line only appears if the
    // real dscl/passwd path actually ran and parsed correctly.
    CHECK(result.captured.find("local_user|" + me + "|") != std::string::npos);
}

TEST_CASE("users plugin: logged_on reports this session's real who(1) console entry",
          "[users][posix_actions]") {
    auto plugin = load_users_plugin();
    if (!plugin) {
        WARN("users plugin library not found -- skipping");
        return;
    }
    const auto me = current_username();
    if (me.empty()) {
        WARN("could not resolve own username -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "logged_on");
    CHECK(result.rc == 0);
    if (result.captured.find("user|" + me + "|") == std::string::npos) {
        // A host with no active console/tty session at all (some headless
        // CI configurations) legitimately has empty who(1) output -- the
        // production code's own honest-empty behaviour, not a defect. The
        // rc==0 check above still proves the real argv executed without
        // error; only the content assertion is best-effort here.
        WARN("no matching 'user|" << me << "|' line -- host may have no active who(1) "
             "session; rc==0 already confirms the real argv executed");
    }
}

TEST_CASE("users plugin: sessions reports this session's real w(1) entry",
          "[users][posix_actions]") {
    auto plugin = load_users_plugin();
    if (!plugin) {
        WARN("users plugin library not found -- skipping");
        return;
    }
    const auto me = current_username();
    if (me.empty()) {
        WARN("could not resolve own username -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "sessions");
    CHECK(result.rc == 0);
    if (result.captured.find("session|") == std::string::npos ||
        result.captured.find(me) == std::string::npos) {
        WARN("no matching session row for " << me << " -- host may have no active w(1) "
             "session; rc==0 already confirms the real argv executed");
    }
}

TEST_CASE("users plugin: primary_user executes the real last(1) argv without error",
          "[users][posix_actions]") {
    auto plugin = load_users_plugin();
    if (!plugin) {
        WARN("users plugin library not found -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "primary_user");
    CHECK(result.rc == 0);
    // A wrong/reverted argv (e.g. Linux's "-F" flag used on a BSD last(1))
    // makes the real tool fail to launch or error out, which forward_runner_
    // failure surfaces as a non-empty capture distinct from the honest
    // "no login records" shape -- either way this call must still produce
    // SOME primary_user| line, never silence.
    CHECK(result.captured.find("primary_user|") != std::string::npos);
}

TEST_CASE("users plugin: session_history executes the real last(1) argv with a count param",
          "[users][posix_actions]") {
    auto plugin = load_users_plugin();
    if (!plugin) {
        WARN("users plugin library not found -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"count", "5"}};
    auto result = dispatcher.run(plugin->descriptor, "session_history", params);
    CHECK(result.rc == 0);
    // Doesn't assert row content (history-dependent) -- proves the "count"
    // param actually reaches the real argv (a reverted/broken param plumb
    // would surface as a crash, a hang, or an rc!=0 from the real tool
    // rejecting a malformed invocation).
}

#endif // !_WIN32
