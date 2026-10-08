/**
 * test_installed_apps_win_actions.cpp -- plugin-loaded Windows `list`/`query`
 * coverage for installed_apps (#4716). The pure parsers and the registry walk
 * are covered elsewhere (test_installed_apps_parsers.cpp,
 * test_installed_apps_registry_walk.cpp, which plants records under a
 * process-suffixed scratch key); this TU proves only the PLUGIN-LOADED path
 * shape on the real host hive: it loads the ACTUAL built installed_apps.dll
 * (the artifact the agent daemon loads in production) via PluginHandle::load
 * and drives it through yuzu::agent::LocalDispatcher, the same pattern as
 * test_event_logs_win_actions.cpp. The one content assertion is against a
 * per-process fixture planted under the real HKCU Uninstall root and removed on
 * exit; no assertion depends on a host record.
 *
 * Hard failure, not WARN-and-skip, when the plugin isn't found (tests/meson.build's
 * link_depends orders the plugin build ahead of this binary) AND when the host hive
 * reads degraded (rc 1): a runner image with one unreadable Uninstall key would
 * otherwise make the fixture assertions below vacuous forever. The degraded
 * error-row contract is pinned by the pure tests, not here.
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline requires one
 * whenever a test's runtime depends on I/O or process creation):
 *   - Cost: registry reads (the Uninstall hives) plus one fixture key
 *     created and deleted per case; NO subprocess is spawned on Windows. Runtime is bounded by hive size (typically well
 *     under a second on a CI runner).
 *   - Why a pure-function test cannot replace it: the pure parsers/walk cannot
 *     show that the plugin entry point wires them into emitted rows with a
 *     non-degraded result status; only the loaded plugin can.
 *   - Bound: two cases, both Windows-only; the whole body compiles empty on
 *     other platforms.
 */
#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <win_reg_handle.hpp>

#include "local_dispatcher.hpp"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Mirrors test_event_logs_win_actions.cpp's find_event_logs_plugin, pointed at
// the installed_apps plugin's own build output.
fs::path find_installed_apps_plugin() {
    const std::string lib_name = "installed_apps.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "installed_apps" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "installed_apps" /
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

std::optional<LoadedPlugin> load_installed_apps_plugin() {
    auto plugin_path = find_installed_apps_plugin();
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

/// Escape-aware field split (same rule as test_installed_apps_actions.cpp): a
/// backslash-escaped '|' does not start a new field.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

std::vector<std::string> lines_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream iss(captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(std::move(line));
    }
    return out;
}

bool has_drive_letter_prefix(const std::string& s) {
    return s.size() >= 3 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':' &&
           (s[2] == '/' || s[2] == '\\');
}

// A per-process Uninstall entry planted under the REAL HKCU Uninstall root: the
// loaded plugin walks HKEY_CURRENT_USER in-process, so it enumerates this entry
// without any admin right. Process-suffixed (never a fixed name) because several
// runner agents share one HKCU (#1871). The destructor removes the key on every
// exit path; the HKEY itself is owned by yuzu::win::RegKey and closed before the
// constructor returns, so the delete is never held open. The bracketed pid keeps
// the `query` substring match from also hitting another process's entry.
struct ScratchUninstallEntry {
    std::wstring sub;
    std::string display_name;
    std::string expected_location; // as `list` emits it: backslashes folded to '/'
    bool ok{false};

    ScratchUninstallEntry() {
        const std::string pid = std::to_string(GetCurrentProcessId());
        const std::string leaf = "YuzuTest_InstalledApps_" + pid;
        display_name = "YuzuTest InstalledApps [" + pid + "]";
        expected_location = "C:/Program Files/" + leaf;
        sub = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" +
              std::wstring(leaf.begin(), leaf.end());

        HKEY raw{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                            nullptr, &raw, nullptr) != ERROR_SUCCESS)
            return;
        yuzu::win::RegKey key{raw};
        ok = set_sz(key.get(), L"DisplayName", display_name) &&
             set_sz(key.get(), L"DisplayVersion", "1.0") &&
             set_sz(key.get(), L"Publisher", "Yuzu test") &&
             set_sz(key.get(), L"InstallLocation", "C:\\Program Files\\" + leaf);
    }
    ~ScratchUninstallEntry() { RegDeleteKeyW(HKEY_CURRENT_USER, sub.c_str()); }
    ScratchUninstallEntry(const ScratchUninstallEntry&) = delete;
    ScratchUninstallEntry& operator=(const ScratchUninstallEntry&) = delete;

private:
    // ASCII-only values: widening is a byte-for-byte copy.
    static bool set_sz(HKEY key, const wchar_t* name, const std::string& value) {
        const std::wstring w(value.begin(), value.end());
        const DWORD bytes = static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t));
        return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(w.c_str()),
                              bytes) == ERROR_SUCCESS;
    }
};

} // namespace

TEST_CASE("installed_apps plugin (Windows): list over the real hive, 7-field app rows and "
          "healthy status",
          "[installed_apps][win_actions]") {
    auto plugin = load_installed_apps_plugin();
    REQUIRE(plugin.has_value());
    const ScratchUninstallEntry entry; // planted before dispatch, removed on every exit path
    REQUIRE(entry.ok);

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    const auto lines = lines_of(result.captured);
    REQUIRE_FALSE(lines.empty()); // the plugin never emits silence

    INFO("first row: " << lines.front());
    REQUIRE(result.rc == 0); // degraded host hive is a red result here, never a skip (see header)

    // rc 0 is a healthy acquisition. The healthy path declares no status, and
    // LocalDispatcher returns the raw value (the daemon's effective-status
    // fallback does not run here), so UNDECLARED is effective OK. An explicitly
    // degraded/error status must still fail.
    CHECK((result.result_status == YUZU_RESULT_STATUS_UNDECLARED ||
           result.result_status == YUZU_RESULT_STATUS_OK));

    std::size_t fixture_rows = 0;
    for (const auto& l : lines) {
        if (l.starts_with("warning|"))
            continue;
        INFO("row: " << l);
        REQUIRE(l.starts_with("app|"));
        const auto fields = split_fields_escape_aware(l);
        REQUIRE(fields.size() == 7);
        // fields: app|name|version|publisher|install_date|install_location|bundle_id.
        // No shape check on arbitrary host rows: a raw REG_EXPAND_SZ
        // (%ProgramFiles%\Vendor) or UNC (//srv/share) location is legitimate. The
        // location contract is asserted on the planted fixture row below.
        if (fields[1] != entry.display_name)
            continue;
        ++fixture_rows;
        CHECK(fields[5] == entry.expected_location);
        CHECK(has_drive_letter_prefix(fields[5]));
    }
    CHECK(fixture_rows == 1);
}

TEST_CASE("installed_apps plugin (Windows): query finds the planted per-process entry",
          "[installed_apps][win_actions]") {
    auto plugin = load_installed_apps_plugin();
    REQUIRE(plugin.has_value());
    const ScratchUninstallEntry entry;
    REQUIRE(entry.ok);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"name", entry.display_name.c_str()}};
    auto result = dispatcher.run(plugin->descriptor, "query", params);
    const auto lines = lines_of(result.captured);
    REQUIRE_FALSE(lines.empty());

    INFO("first row: " << lines.front());
    REQUIRE(result.rc == 0); // degraded host hive is a red result here, never a skip (see header)

    // Deterministic: the unique display name matches exactly the planted entry.
    REQUIRE(lines.front() == "found|true");
    REQUIRE(lines.size() == 2);
    CHECK(lines[1] == "app|" + entry.display_name + "|1.0|Yuzu test");
}

#endif // _WIN32
