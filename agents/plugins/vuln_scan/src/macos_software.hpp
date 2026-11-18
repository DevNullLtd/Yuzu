#pragma once

/**
 * macos_software.hpp — portable decisions for the macOS software enumeration (WP13c).
 *
 * Pure code (no I/O, no popen) so the status contract is testable on every host even though
 * the system_profiler call itself only runs under __APPLE__.
 *
 * Coverage contract: the macOS software list is `system_profiler SPApplicationsDataType` apps
 * ONLY. Homebrew is never read (the root agent must not exec a user-owned `brew`), so every
 * macOS action that consumes the list reports CONSTRAINED + PARTIAL: a result with no CVE rows
 * means only that no built-in rule matched the enumerated apps. An enumeration that returned no
 * apps (failed, timed out, empty) is a different, worse condition and carries its own token.
 */

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::vuln {

// Absolute argv[0] for the macOS software enumeration: never resolved through the daemon PATH.
inline constexpr std::string_view kMacosSystemProfilerCmd =
    "/usr/sbin/system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null";

// macOS config-check commands. Every argv[0] is an absolute path to a fixed Apple system tool,
// so popen's /bin/sh never resolves a bare name through the (root) daemon's PATH.
inline constexpr std::string_view kMacosSpctlCmd = "/usr/sbin/spctl --status 2>&1";
inline constexpr std::string_view kMacosFdesetupCmd = "/usr/bin/fdesetup status 2>&1";
inline constexpr std::string_view kMacosCsrutilCmd = "/usr/bin/csrutil status 2>&1";
inline constexpr std::string_view kMacosSocketfilterfwCmd =
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1";
inline constexpr std::string_view kMacosSystemsetupCmd =
    "/usr/sbin/systemsetup -getremotelogin 2>&1";
inline constexpr std::string_view kMacosDefaultsCmd =
    "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate "
    "AutomaticCheckEnabled 2>&1";

inline constexpr std::array<std::string_view, 7> kMacosCommands = {
    kMacosSystemProfilerCmd, kMacosSpctlCmd,        kMacosFdesetupCmd,  kMacosCsrutilCmd,
    kMacosSocketfilterfwCmd, kMacosSystemsetupCmd,  kMacosDefaultsCmd};

// Result-status provenance tokens (^macos:[a-z0-9_]+(:[a-z0-9_]+)*$).
inline constexpr std::string_view kMacosHomebrewNotScanned = "macos:vuln_scan:homebrew_not_scanned";
inline constexpr std::string_view kMacosSystemProfilerUnreadable =
    "macos:vuln_scan:system_profiler_unreadable";

struct MacosApp {
    std::string name;
    std::string version;
};

struct MacosEnumeration {
    std::vector<MacosApp> apps;
    bool readable = false; // the command ran, exited 0, and yielded at least one app
};

namespace detail {
inline bool is_word_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}
} // namespace detail

/// Parse raw `system_profiler SPApplicationsDataType -detailLevel mini` output. The line filter
/// that used to be a `| grep -E '^ {4}\w|Version:'` pipe (which also swallowed system_profiler's
/// exit status) is applied here. `command_ok` is false when the command failed to start or
/// exited non-zero.
inline MacosEnumeration parse_system_profiler_apps(std::string_view out, bool command_ok) {
    MacosEnumeration r;
    std::string current_name;
    std::string current_version;
    size_t pos = 0;
    while (pos <= out.size()) {
        size_t nl = out.find('\n', pos);
        std::string_view raw =
            out.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? out.size() + 1 : nl + 1;
        if (!raw.empty() && raw.back() == '\r')
            raw.remove_suffix(1);

        const bool name_shape = raw.size() > 4 && raw.substr(0, 4) == "    " &&
                                detail::is_word_char(raw[4]);
        if (!name_shape && raw.find("Version:") == std::string_view::npos)
            continue;

        auto start = raw.find_first_not_of(" \t");
        if (start == std::string_view::npos)
            continue;
        std::string_view line = raw.substr(start);

        if (line.substr(0, 8) == "Version:") {
            auto colon = line.find(':');
            current_version = colon + 2 <= line.size() ? std::string(line.substr(colon + 2)) : "";
        } else if (!line.empty() && line.back() == ':') {
            if (!current_name.empty())
                r.apps.push_back({current_name, current_version});
            current_name = std::string(line.substr(0, line.size() - 1));
            current_version.clear();
        }
    }
    if (!current_name.empty())
        r.apps.push_back({current_name, current_version});
    r.readable = command_ok && !r.apps.empty();
    return r;
}

/// The provenance token for a macOS action that consumed the software list. Always
/// CONSTRAINED/PARTIAL; an unreadable enumeration outranks the standing Homebrew exclusion.
inline std::string_view macos_status_token(const MacosEnumeration& e) {
    return e.readable ? kMacosHomebrewNotScanned : kMacosSystemProfilerUnreadable;
}

} // namespace yuzu::vuln
