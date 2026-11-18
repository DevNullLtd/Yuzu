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

// Bounds: a stalled tool cannot park a pool worker, a runaway cannot grow RSS. One action's worst
// case is the profiler (60 s) plus six status tools (10 s each) = 120 s.
inline constexpr long long kMacosCommandDeadlineMs = 60'000; // system_profiler
inline constexpr long long kMacosToolDeadlineMs = 10'000;    // spctl/fdesetup/csrutil/...
inline constexpr std::size_t kMacosCommandMaxOutput = 8u * 1024u * 1024u;
// system_profiler is run process-wide single-flight and its result (success OR failure) is reused
// for this long, so concurrent or repeated actions neither stack subprocesses nor retry a hang.
inline constexpr long long kMacosProfilerCacheMs = 45'000;

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
    "The macOS software list could not be read completely (system_profiler failed, timed out, "
    "exceeded the output cap or returned no applications); not a clean result";
inline constexpr std::string_view kCoverageNoteConfig =
    "One or more macOS configuration checks could not be read; each is reported as an UNREADABLE "
    "row, not as a finding";
// Detail text of a config check whose read failed (severity UNREADABLE, never a verdict).
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
} // namespace detail

/// Fold literal backslashes to '/' in a value bound for a pipe-delimited row. The server decoder
/// (result_parsing.hpp) undoes only `\|`, so a trailing backslash would swallow the pipe
/// separator; folding follows the shared `safe_output_field` convention (sdk string_utils.hpp).
inline std::string fold_backslashes(std::string_view v) {
    std::string out(v);
    for (char& c : out)
        if (c == '\\')
            c = '/';
    return out;
}

/// Parse raw `system_profiler SPApplicationsDataType -detailLevel mini` output structurally:
///   - a NAME line is exactly four spaces, then a non-space byte, and ends with ':' (names may
///     start with any non-space byte, including non-ASCII); a line whose name text starts with
///     "Version:" is never a name;
///   - a VERSION line is a "Version:" line indented DEEPER than four spaces, and counts only after
///     a name (the first one per app wins).
/// Anything else is ignored. `command_ok` is false when the command did not run to a clean end
/// (failed, timed out, over the output cap): the apps are then DROPPED, never returned as a partial
/// list that would feed CVE matching or inventory.
inline MacosEnumeration parse_system_profiler_apps(std::string_view out, bool command_ok) {
    MacosEnumeration r;
    std::string current_name;
    std::string current_version;
    bool have_name = false;
    bool have_version = false;
    const auto flush = [&] {
        if (have_name)
            r.apps.push_back({current_name, current_version});
        current_name.clear();
        current_version.clear();
        have_name = have_version = false;
    };
    size_t pos = 0;
    while (pos <= out.size()) {
        size_t nl = out.find('\n', pos);
        std::string_view raw =
            out.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? out.size() + 1 : nl + 1;
        if (!raw.empty() && raw.back() == '\r')
            raw.remove_suffix(1);

        const auto indent = raw.find_first_not_of(' ');
        if (indent == std::string_view::npos)
            continue;
        const std::string_view body = detail::trim(raw.substr(indent));
        if (body.empty())
            continue;
        if (indent == 4 && raw[4] != '\t' && body.back() == ':') {
            if (body.substr(0, 8) == "Version:")
                continue; // a name line never starts "Version:"
            flush();
            current_name = std::string(body.substr(0, body.size() - 1));
            have_name = true;
        } else if (indent > 4 && have_name && !have_version && body.substr(0, 8) == "Version:") {
            current_version = std::string(detail::trim(body.substr(8)));
            have_version = true;
        }
    }
    flush();
    if (!command_ok)
        r.apps.clear();
    r.readable = command_ok && !r.apps.empty();
    return r;
}

/// What one action run learned about the completeness of what it read. Default = nothing to
/// declare (Windows, Linux, and a macOS config_scan whose reads all succeeded).
struct CoverageState {
    bool macos_software = false;    // the action consumed the macOS software list
    bool sp_readable = true;        // ... and system_profiler ran cleanly and produced applications
    bool config_unreadable = false; // a macOS config check's read failed (UNREADABLE row emitted)
};

/// Provenance token for the CONSTRAINED/PARTIAL status; empty = declare nothing. The provenance is
/// ONE token, so when causes stack the precedence is: unreadable software list, then unreadable
/// config read, then the standing Homebrew gap. EVERY cause is still reported in-band by
/// coverage_notes().
inline std::string_view coverage_token(const CoverageState& c) {
    if (c.macos_software && !c.sp_readable)
        return kMacosSystemProfilerUnreadable;
    if (c.config_unreadable)
        return kMacosConfigUnreadable;
    if (c.macos_software)
        return kMacosHomebrewNotScanned;
    return {};
}

struct CoverageNote {
    std::string_view severity; // "INFO" (known standing gap) or "UNREADABLE" (a read failed)
    std::string_view text;
};

/// Every in-band coverage note for this run, in a stable order; empty = nothing to say.
inline std::vector<CoverageNote> coverage_notes(const CoverageState& c) {
    std::vector<CoverageNote> n;
    if (c.macos_software)
        n.push_back(c.sp_readable ? CoverageNote{"INFO", kCoverageNoteHomebrew}
                                  : CoverageNote{"UNREADABLE", kCoverageNoteUnreadable});
    if (c.config_unreadable)
        n.push_back({"UNREADABLE", kCoverageNoteConfig});
    return n;
}

/// `severity|category|title|detail` row (matches the placeholder row's shape).
inline std::string coverage_row(const CoverageNote& n) {
    return std::string(n.severity) + "|scan|Coverage|" + std::string(n.text);
}

/// `summary|<key>|<value>` row for summary (summary's own row shape; value is text, like TOTAL's).
inline std::string coverage_summary_row(const CoverageNote& n) {
    return "summary|COVERAGE|" + std::string(n.text);
}

} // namespace yuzu::vuln
