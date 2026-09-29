/**
 * test_hardware_device_identity_posix_actions.cpp -- Wave 3 PR3.2 gate-1
 * remediation (code-review finding: no test proves the migrated
 * hardware/device_identity actions actually reach their real native
 * (sysctlbyname/IOKit) or bounded-runner (system_profiler/dsconfigad) call
 * sites -- only their downstream pure parsers were covered). Mirrors
 * test_users_posix_actions.cpp's established pattern (born from the
 * identical Wave-2 WP-A finding "no test proves the migrated argv actually
 * reaches the real tool"): loads the ACTUAL built hardware/device_identity
 * plugins via PluginHandle::load and drives them through
 * yuzu::agent::LocalDispatcher, the same in-process artifact the agent
 * daemon loads in production.
 *
 * macOS only (this is where every migrated action in this PR is exercisable
 * on a real, unprivileged CI/dev host without external state -- Apple
 * hardware always reports "Apple Inc." as manufacturer, and every Mac has a
 * real IOKit serial/UUID and at least one internal disk). The Linux legs
 * (native /sys/block walk, sd-bus SSSD InfoPipe call) require fixture
 * injection or a Linux host with mockable D-Bus/sysfs state to exercise at
 * the action-dispatch level and are intentionally left to a follow-up
 * (tracked alongside #2380) rather than guessed at here.
 *
 * For the two bounded-runner call sites this file CAN reach (bios, disks --
 * both resolve fixed literal argv per docs/agent-spawn-sink-manifest.md,
 * never a PATH-relative lookup), PATH is cleared before dispatch: a
 * regression to a bare "system_profiler"/"dsconfigad" (PATH-relative,
 * losing the absolute-argv contract) would fail these assertions even
 * though it would pass with a normal PATH.
 */
#include <catch2/catch_test_macros.hpp>

#if defined(__APPLE__)

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at each
// of this PR's two plugins' own build output. Empty path (never a hard
// failure) when not found, so a build without agent plugins skips rather
// than fails.
fs::path find_plugin(const char* plugin_name) {
    const std::string lib_name = std::string{plugin_name} + ".dylib";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / plugin_name /
                                 lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / plugin_name / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / plugin_name / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / plugin_name /
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

// Returns nullopt ONLY when the plugin genuinely isn't part of this build
// (mirrors test_users_posix_actions.cpp's find_users_plugin precedent: a
// build without agent plugins skips rather than fails). A path that EXISTS
// but fails to load or expose a descriptor is a real regression (ABI break,
// missing dependency, wrong architecture) -- REQUIRE-fail rather than
// silently return nullopt, so that case can't be confused with "not built
// here" (governance Gate-3 quality-engineer finding: the two were
// previously indistinguishable, letting a load regression pass as a skip).
std::optional<LoadedPlugin> load_plugin(const char* plugin_name) {
    auto plugin_path = find_plugin(plugin_name);
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);
    return LoadedPlugin{std::move(*handle), descriptor};
}

// RAII PATH clearer for the two absolute-argv bounded-runner call sites this
// file exercises (bios, disks). Restores the prior value (or unsets, if it
// was unset) on scope exit regardless of test outcome.
class ClearedPath {
public:
    ClearedPath() {
        if (const char* p = std::getenv("PATH")) {
            had_prev_ = true;
            prev_ = p;
        }
        ::setenv("PATH", "", 1);
    }
    ~ClearedPath() {
        if (had_prev_)
            ::setenv("PATH", prev_.c_str(), 1);
        else
            ::unsetenv("PATH");
    }
    ClearedPath(const ClearedPath&) = delete;
    ClearedPath& operator=(const ClearedPath&) = delete;

private:
    bool had_prev_ = false;
    std::string prev_;
};

} // namespace

TEST_CASE("hardware plugin: manufacturer reads the real sysctlbyname value",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "manufacturer");
    CHECK(result.rc == 0);
    // Every real Mac reports "Apple Inc." here (native sysctlbyname or its
    // hardcoded fallback for the rare missing-key case) -- a broken/reverted
    // read that silently returned empty or crashed would not produce this
    // exact line.
    CHECK(result.captured.find("manufacturer|Apple Inc.") != std::string::npos);
}

TEST_CASE("hardware plugin: model reads a real non-sentinel sysctlbyname value",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "model");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("model|") != std::string::npos);
    // The honest-failure sentinel is "model|unknown" -- a real hw.model read
    // never produces it on macOS.
    CHECK(result.captured.find("model|unknown") == std::string::npos);
}

TEST_CASE("hardware plugin: processors reads real sysctlbyname CPU data",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "processors");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("cpu|") != std::string::npos);
    // "cpu|0|unknown|0|0|0" is the honest-failure row emitted when the
    // sysctlbyname reads produced nothing -- unreachable on a real host.
    CHECK(result.captured.find("cpu|0|unknown|0|0|0") == std::string::npos);
}

TEST_CASE("hardware plugin: memory reads the real hw.memsize total",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "memory");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("dimm|") != std::string::npos);
    CHECK(result.captured.find("dimm|total|unknown|unknown|0") == std::string::npos);
}

TEST_CASE("hardware plugin: system reads real IOKit serial + UUID",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "system");
    CHECK(result.rc == 0);
    // Reverting IOServiceGetMatchingService/IORegistryEntryCreateCFProperty
    // to the old `ioreg | awk` popen (or breaking the new IOKit read) would
    // surface as "unknown" here -- both fields are always real on real Mac
    // hardware.
    CHECK(result.captured.find("serial|unknown") == std::string::npos);
    CHECK(result.captured.find("system_uuid|unknown") == std::string::npos);
}

TEST_CASE("hardware plugin: bios runs the real bounded system_profiler with PATH cleared",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    ClearedPath cleared_path;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "bios");
    CHECK(result.rc == 0);
    // Absolute-argv contract (docs/agent-spawn-sink-manifest.md
    // hardware/do_bios#1): a PATH-relative regression would fail to launch
    // system_profiler with PATH cleared and fall to the "unknown" sentinel.
    CHECK(result.captured.find("bios_vendor|Apple") != std::string::npos);
    CHECK(result.captured.find("bios_version|unknown") == std::string::npos);
}

TEST_CASE("hardware plugin: disks runs the real bounded system_profiler with PATH cleared",
          "[hardware][macos][posix_actions]") {
    auto plugin = load_plugin("hardware");
    if (!plugin) {
        WARN("hardware plugin library not found -- skipping");
        return;
    }
    ClearedPath cleared_path;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "disks");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("disk|") != std::string::npos);
    // Every Mac has at least one internal disk -- the honest-empty sentinel
    // ("disk|0|unknown|0|unknown|unknown") is unreachable on a real host
    // unless the runner call itself failed (wrong argv, PATH regression,
    // timeout).
    CHECK(result.captured.find("disk|0|unknown|0|unknown|unknown") == std::string::npos);
}

TEST_CASE("device_identity plugin: domain runs the real bounded dsconfigad with PATH cleared",
          "[device_identity][macos][posix_actions]") {
    auto plugin = load_plugin("device_identity");
    if (!plugin) {
        WARN("device_identity plugin library not found -- skipping");
        return;
    }
    ClearedPath cleared_path;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "domain");
    // rc==0 alone proves the real dsconfigad-via-runner path (or its
    // gethostname/getaddrinfo fallback) executed without crashing; most
    // dev/CI hosts are not AD-bound, so content is asserted on shape only
    // (a "domain|" line is always present, joined true or false).
    CHECK(result.rc == 0);
    CHECK(result.captured.find("domain|") != std::string::npos);
}

TEST_CASE("device_identity plugin: ou runs the real bounded dsconfigad with PATH cleared",
          "[device_identity][macos][posix_actions]") {
    auto plugin = load_plugin("device_identity");
    if (!plugin) {
        WARN("device_identity plugin library not found -- skipping");
        return;
    }
    ClearedPath cleared_path;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "ou");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("ou|") != std::string::npos);
}

#endif // __APPLE__
