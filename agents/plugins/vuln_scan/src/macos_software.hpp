#pragma once

/**
 * macos_software.hpp — portable decisions for the macOS software enumeration (WP13c).
 *
 * Pure code (no I/O, no subprocess) so the status contract is testable on every host even though
 * the system_profiler call itself only runs under __APPLE__.
 *
 * Coverage contract: the macOS software list is `system_profiler SPApplicationsDataType` apps
 * ONLY. Homebrew is never read (the root agent must not exec a user-owned `brew`), so every
 * macOS action that consumes the list reports CONSTRAINED + PARTIAL: a result with no CVE rows
 * means only that no built-in rule matched the enumerated apps. An enumeration that returned no
 * apps (failed, timed out, empty) is a different, worse condition and carries its own token.
 */

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <vector>

namespace yuzu::vuln {

// macOS commands. Each is a pre-split argv whose argv[0] is an absolute path to a fixed Apple
// system tool, run by yuzu::agent::run_bounded_subprocess (execve: no shell, no PATH search, a
// wall-clock deadline, an output cap, process-group kill). The runner itself lives in agent-core,
// so this header stays I/O-free and only defines WHAT is run and how its result is judged.
using Argv = std::vector<std::string>;

inline const Argv kMacosSystemProfilerCmd = {"/usr/sbin/system_profiler", "SPApplicationsDataType",
                                             "-detailLevel", "mini"};
inline const Argv kMacosSpctlCmd = {"/usr/sbin/spctl", "--status"};
inline const Argv kMacosFdesetupCmd = {"/usr/bin/fdesetup", "status"};
inline const Argv kMacosCsrutilCmd = {"/usr/bin/csrutil", "status"};
inline const Argv kMacosSocketfilterfwCmd = {"/usr/libexec/ApplicationFirewall/socketfilterfw",
                                             "--getglobalstate"};
inline const Argv kMacosSystemsetupCmd = {"/usr/sbin/systemsetup", "-getremotelogin"};
inline const Argv kMacosDefaultsCmd = {"/usr/bin/defaults", "read",
                                       "/Library/Preferences/com.apple.SoftwareUpdate",
                                       "AutomaticCheckEnabled"};

inline std::vector<const Argv*> macos_commands() {
    return {&kMacosSystemProfilerCmd, &kMacosSpctlCmd,   &kMacosFdesetupCmd, &kMacosCsrutilCmd,
            &kMacosSocketfilterfwCmd, &kMacosSystemsetupCmd, &kMacosDefaultsCmd};
}

// Bounds for every macOS command: a stalled tool cannot park a worker, a runaway cannot grow RSS.
inline constexpr long long kMacosCommandDeadlineMs = 60'000;
inline constexpr std::size_t kMacosCommandMaxOutput = 8u * 1024u * 1024u;

// Result-status provenance tokens (^macos:[a-z0-9_]+(:[a-z0-9_]+)*$).
inline constexpr std::string_view kMacosHomebrewNotScanned = "macos:vuln_scan:homebrew_not_scanned";
inline constexpr std::string_view kMacosSystemProfilerUnreadable =
    "macos:vuln_scan:system_profiler_unreadable";
inline constexpr std::string_view kMacosConfigUnreadable = "macos:vuln_scan:config_unreadable";

// In-band coverage notes: the operator-visible half of the result status (the status token itself
// reaches only the agent log). Emitted as rows in the SAME output as the CONSTRAINED status.
inline constexpr std::string_view kCoverageNoteHomebrew =
    "Homebrew formulae and casks are not scanned";
inline constexpr std::string_view kCoverageNoteUnreadable =
    "The software list is empty because system_profiler returned no applications; this is not a clean result";
// Detail text of a config check whose read failed (severity INFO, never a verdict).
inline constexpr std::string_view kConfigUnknownDetail = "Unknown (read failed)";

struct MacosApp {
    std::string name;
    std::string version;
};

struct MacosEnumeration {
    std::vector<MacosApp> apps;
    bool readable = false; // the command ran, exited 0, and yielded at least one app
};

namespace detail {
inline std::string_view trim(std::string_view v) {
    const auto a = v.find_first_not_of(" \t\r\n");
    if (a == std::string_view::npos)
        return {};
    const auto b = v.find_last_not_of(" \t\r\n");
    return v.substr(a, b - a + 1);
}

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
        std::string_view line = detail::trim(raw.substr(start));

        if (line.substr(0, 8) == "Version:") {
            current_version = std::string(detail::trim(line.substr(8)));
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

/// What one action run learned about the completeness of what it read. Default = nothing to
/// declare (Windows, Linux, and a macOS config_scan whose reads all succeeded).
struct CoverageState {
    bool macos_software = false;   // the action consumed the macOS software list
    bool sp_readable = true;       // ... and system_profiler produced applications
    bool config_unreadable = false; // a config check's read failed (INFO "Unknown" row emitted)
};

/// Provenance token for the CONSTRAINED/PARTIAL status; empty = declare nothing. An unreadable
/// software list outranks an unreadable config read, which outranks the standing Homebrew gap.
inline std::string_view coverage_token(const CoverageState& c) {
    if (c.macos_software && !c.sp_readable)
        return kMacosSystemProfilerUnreadable;
    if (c.config_unreadable)
        return kMacosConfigUnreadable;
    if (c.macos_software)
        return kMacosHomebrewNotScanned;
    return {};
}

/// Text of the in-band coverage row; empty = no row (non-macOS, and config_scan).
inline std::string_view coverage_note(const CoverageState& c) {
    if (!c.macos_software)
        return {};
    return c.sp_readable ? kCoverageNoteHomebrew : kCoverageNoteUnreadable;
}

/// `severity|category|title|detail` row for cve_scan/scan (matches the placeholder row's shape).
inline std::string coverage_row(std::string_view note) {
    return "INFO|scan|Coverage|" + std::string(note);
}

/// `summary|<key>|<value>` row for summary (summary's own row shape; value is text, like TOTAL's).
inline std::string coverage_summary_row(std::string_view note) {
    return "summary|COVERAGE|" + std::string(note);
}

} // namespace yuzu::vuln
