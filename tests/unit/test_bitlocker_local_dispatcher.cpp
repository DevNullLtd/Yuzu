/**
 * test_bitlocker_local_dispatcher.cpp -- execute-path coverage for the
 * bitlocker plugin's Windows leg (Wave-3 native-acquisition migration off
 * the raw `manage-bde -status` popen onto in-process
 * Win32_EncryptableVolume WMI + per-volume GetConversionStatus()/
 * GetEncryptionMethod() method calls).
 *
 * test_bitlocker_windows_wmi.cpp already covers every pure WMI-row-mapping
 * function (parse_encryptable_volumes, parse_conversion_status,
 * parse_encryption_method, format_volume_row, ...) as fixture-driven unit
 * tests -- but nothing in this branch previously exercised the plugin's
 * actual execute() path against a real WMI provider. This file closes that
 * gap the same way test_registry_local_dispatcher.cpp (PR1.7) and
 * test_antivirus_local_dispatcher.cpp do: load the ACTUAL built
 * bitlocker.dll via PluginHandle::load and drive it through
 * yuzu::agent::LocalDispatcher.
 *
 * Scope, deliberately: assertions are host-config-agnostic (no assumption
 * about whether BitLocker is on, whether the run is elevated, or how many
 * volumes exist) -- they pin CONTRACT shape (rc, well-formed output) rather
 * than a specific encryption state. One assertion IS host-independent and
 * is the actual regression pin for the encryption_method fix: whenever a
 * `volume|` row is emitted, its method field (5th of 6) is never the raw
 * lowercase literal "unknown" that the pre-fix code hardcoded
 * unconditionally -- it is now either a real WMI-decoded method or the
 * honestly-capitalized "Unknown" degrade value, which is a materially
 * different (and truthful) signal to a caller checking for the old bug's
 * exact sentinel.
 *
 * Linux/macOS execute paths (libblkid/sysfs, fdesetup/diskutil) are
 * intentionally NOT covered here, same reasoning as
 * test_antivirus_local_dispatcher.cpp. Windows-only; the plugin's WMI code
 * is a no-op elsewhere.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Locate the real bitlocker.dll built by agents/plugins/bitlocker/meson.build.
fs::path find_bitlocker_plugin() {
    const std::string lib_name = "bitlocker.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "bitlocker" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "bitlocker" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "bitlocker" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "bitlocker" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

std::vector<std::string> split_lines(const std::string& captured) {
    std::vector<std::string> lines;
    std::istringstream iss(captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
}

std::vector<std::string> split_fields(const std::string& line) {
    std::vector<std::string> fields;
    size_t pos = 0;
    while (pos <= line.size()) {
        auto p = line.find('|', pos);
        if (p == std::string::npos) {
            fields.push_back(line.substr(pos));
            break;
        }
        fields.push_back(line.substr(pos, p - pos));
        pos = p + 1;
    }
    return fields;
}

} // namespace

TEST_CASE("bitlocker plugin: state executes via LocalDispatcher against real WMI",
          "[bitlocker][windows][local_dispatcher]") {
    auto plugin_path = find_bitlocker_plugin();
    if (plugin_path.empty()) {
        WARN("bitlocker.dll not found (build_agent=false?) -- skipping "
             "LocalDispatcher execute-path test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(descriptor, "state");
    auto lines = split_lines(result.captured);

    if (result.rc != 0) {
        // Total WMI query failure (e.g. unprivileged run against the
        // admin-only MicrosoftVolumeEncryption namespace) -- report_bitlocker_
        // status() returns false, execute() maps that to rc=1. The contract
        // is an "error|" line, never a silent empty failure.
        bool saw_error = false;
        for (const auto& l : lines) {
            if (l.starts_with("error|")) {
                saw_error = true;
                break;
            }
        }
        CHECK(saw_error);
        WARN("bitlocker state query failed on this host (likely unprivileged run against "
             "the admin-only namespace) -- skipping the per-volume method-field pin");
        return;
    }

    // Success: either "volume|none|no_encryptable_volumes" (no encryptable
    // volumes at all) or one "volume|<drive>|<conversion>|<pct>|<method>|
    // <protection>" row per volume.
    REQUIRE_FALSE(lines.empty());

    for (const auto& line : lines) {
        if (!line.starts_with("volume|"))
            continue;
        auto fields = split_fields(line);
        if (fields.size() != 6)
            continue; // the "volume|none|no_encryptable_volumes" 3-field sentinel

        const std::string& method = fields[4];
        // The actual regression pin: the pre-fix code hardcoded this field
        // to the literal lowercase "unknown" unconditionally -- it must
        // never be that exact sentinel again. A real value (e.g.
        // "XTS-AES 128") or the honest degrade "Unknown" (capitalized, from
        // encryption_method_text's fallback) are both acceptable; the raw
        // lowercase literal is not.
        CHECK(method != "unknown");
        CHECK_FALSE(method.empty());
    }
}

#endif // _WIN32
