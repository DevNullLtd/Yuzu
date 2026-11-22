#pragma once

/**
 * macos_software.hpp — portable decisions for the macOS software enumeration.
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

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cve_rules.hpp"

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
// The update-check setting is read TWICE and the worse answer wins (see macos_check_result_dual):
//   - the BARE domain goes through CFPreferences and may see a managed (MDM) or per-user value;
//     its key-absent text WAS measured (macOS 27.0.1, euid 501 only), and whether it cascades to
//     the system plist is not;
//   - the /Library/Preferences PATH form reads only the system plist; its output WAS measured
//     (macOS 27.0.1, one host: key absent -> the absent-key line, exit 1).
// A read whose text is not one the table recognises is UNREADABLE, never a pass.
inline const Argv kMacosDefaultsCmd = {"/usr/bin/defaults", "read", "com.apple.SoftwareUpdate",
                                       "AutomaticCheckEnabled"};
inline const Argv kMacosDefaultsPathCmd = {"/usr/bin/defaults", "read",
                                           "/Library/Preferences/com.apple.SoftwareUpdate",
                                           "AutomaticCheckEnabled"};

inline std::vector<const Argv*> macos_commands() {
    return {&kMacosSystemProfilerCmd, &kMacosSpctlCmd,   &kMacosFdesetupCmd, &kMacosCsrutilCmd,
            &kMacosSocketfilterfwCmd, &kMacosSystemsetupCmd, &kMacosDefaultsCmd,
            &kMacosDefaultsPathCmd};
}

// Bounds: a stalled tool cannot park a pool worker, a runaway cannot grow RSS. One action's worst
// case is the profiler (60 s) plus seven 10 s status reads (five tools, the update-check `defaults`
// read twice) = 130 s ceiling if every command runs to its deadline (about 146 s with the runner's
// 2 s drain grace per command); the typical time is not measured. A waiter behind an overdue
// flight waits at most 75 s.
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
inline constexpr std::string_view kMacosCveInputIncomplete = "macos:vuln_scan:cve_input_incomplete";
inline constexpr std::string_view kMacosSoftwareListUnrecognised =
    "macos:vuln_scan:software_list_unrecognised";

// In-band coverage notes: the operator-visible half of the result status (the completeness and
// provenance token are in the agent log only). Emitted as rows in the SAME output as the CONSTRAINED status.
inline constexpr std::string_view kCoverageNoteHomebrew =
    "Homebrew formulae and casks are not scanned";
inline constexpr std::string_view kCoverageNoteUnreadable =
    "The macOS software list could not be read completely (system_profiler failed, timed out, "
    "exceeded the output cap, returned no applications, or most applications had no recognised "
    "Version line); not a clean result";
inline constexpr std::string_view kCoverageNoteConfig =
    "One or more macOS configuration checks could not be read; each is reported as an UNREADABLE "
    "row, not as a finding";
// Detail text of a config check whose read failed (severity UNREADABLE, never a verdict).
inline constexpr std::string_view kConfigUnknownDetail = "Unknown (read failed)";
// Detail of the macOS open-port row: the check does not exist there (a standing unavailability,
// not a failed read, so it does not raise the config_unreadable status token).
inline constexpr std::string_view kOpenPortUnavailableDetail =
    "open-port check is not available on macOS";

struct MacosApp {
    std::string name;
    std::string version;
};

struct MacosEnumeration {
    std::vector<MacosApp> apps;
    bool readable = false; // the command ran, exited 0, and yielded at least one app
    std::size_t suspect_lines = 0; // lines that look like a name or version but were not recognised
};

/// A version CVE matching can compare: non-empty, starting with an ASCII digit and with no segment
/// too large for the comparison ("17.0.1", not "", "Unknown", "v100.0.1", an NBSP-prefixed value or
/// "1.99999999999999999999"). Pre-release and letter suffixes ("131.0b2", "3.9rc1") pass this test
/// but may not be ordered correctly against a fixed version.
inline bool usable_version(std::string_view v) {
    return !v.empty() && v.front() >= '0' && v.front() <= '9' && !version_has_overflowing_segment(v);
}

/// How many DISTINCT applications match a built-in CVE rule's product text (ASCII
/// case-insensitive substring, as the matcher does) but have no usable version. `rules` is any
/// range whose elements have a `product` string_view (yuzu::vuln::kCveRules).
template <class Rules>
inline std::size_t count_unusable_cve_apps(const std::vector<MacosApp>& apps, const Rules& rules) {
    const auto lower = [](std::string_view s) {
        std::string o(s);
        for (char& c : o)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return o;
    };
    std::size_t n = 0;
    for (const auto& app : apps) {
        if (usable_version(app.version))
            continue;
        const std::string name = lower(app.name);
        for (const auto& rule : rules)
            if (name.find(lower(rule.product)) != std::string::npos) {
                ++n;
                break;
            }
    }
    return n;
}

// Per-field bounds: a NUL would cut the row at the C-string plugin ABI and an enormous name would
// become an oversize frame. NUL bytes are replaced with '?', over-long text is truncated.
inline constexpr std::size_t kMaxNameBytes = 1024;
inline constexpr std::size_t kMaxVersionBytes = 256;

inline std::string bound_text(std::string_view v, std::size_t max_bytes) {
    std::string out(v.substr(0, max_bytes));
    for (char& c : out)
        if (c == '\0')
            c = '?';
    return out;
}

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
/// Lines that do not fit (a name without ':' or at an odd indent, a leading tab, a second Version in
/// a block, a Version before any name or not directly after its name line, indent 0 other than the
/// "Applications:" header, indent 1-2, a property-indent line after a blank that does not follow
/// a name, and a line at indent 5 or deeper after TWO OR MORE blank lines that follow a name) are
/// counted in `suspect_lines`; they never become apps. One shape at indent 0 is legitimate and not
/// counted: a non-blank line that directly follows a property line with no blank between (a
/// property value that wraps onto further lines, as the multi-line `Get Info String` of a real
/// application does); it is part of that property, and the lines after it keep the property
/// context. Measured on macOS 27.0.1 (529 application blocks): every name line is followed by
/// exactly ONE blank line, so a name line followed by two or more is the shape a dropped line
/// leaves. A lost name line that takes its adjacent blank line with it leaves a block
/// byte-identical to a canonical one and cannot be told.
/// `command_ok` is false when the command did not run to a clean end (failed, timed out, over the
/// output cap): the apps are then DROPPED, never returned as a partial
/// list that would feed CVE matching or inventory.
inline MacosEnumeration parse_system_profiler_apps(std::string_view out, bool command_ok) {
    MacosEnumeration r;
    std::string current_name;
    std::string current_version;
    bool have_name = false;
    bool have_version = false;
    char last_kind = 'H'; // kind of the last non-blank line: H header, N name, P anything else
    bool blank_since = false;
    int blank_run = 0; // consecutive blank lines directly before the current line
    const auto flush = [&] {
        if (have_name)
            r.apps.push_back({bound_text(current_name, kMaxNameBytes),
                              bound_text(current_version, kMaxVersionBytes)});
        current_name.clear();
        current_version.clear();
        have_name = have_version = false;
    };
    if (out.starts_with("\xEF\xBB\xBF")) // a UTF-8 byte-order mark before the first line
        out.remove_prefix(3);
    size_t pos = 0;
    while (pos <= out.size()) {
        size_t nl = out.find('\n', pos);
        std::string_view raw =
            out.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? out.size() + 1 : nl + 1;
        if (!raw.empty() && raw.back() == '\r')
            raw.remove_suffix(1);

        const auto indent = raw.find_first_not_of(' ');
        if (indent == std::string_view::npos) {
            blank_since = true;
            ++blank_run;
            continue;
        }
        const std::string_view body = detail::trim(raw.substr(indent));
        if (body.empty()) {
            blank_since = true;
            ++blank_run;
            continue;
        }
        // Grammar guards: a line the real report never contains means a name or property may have
        // been dropped or reshaped, so the list may be missing an application.
        const bool tab = raw[indent] == '\t';
        // A wrapped property value: indent 0, directly after a property line, no blank between.
        const bool wrapped = indent == 0 && !tab && last_kind == 'P' && !blank_since;
        if (tab || (indent == 0 && body != "Applications:" && !wrapped) || indent == 1 || indent == 2 ||
            ((indent > 4 || indent == 3) && blank_since && last_kind != 'N') ||
            (indent > 4 && last_kind == 'N' && blank_run >= 2))
            ++r.suspect_lines;
        const char prev_kind = last_kind; // the kind of the previous non-blank line
        last_kind = (indent == 4 && !tab && body.back() == ':' && body.substr(0, 8) != "Version:") ? 'N'
                    : indent == 0 && !wrapped                                                       ? 'H'
                                                                                                    : 'P';
        blank_since = false;
        blank_run = 0;
        if (tab)
            continue;
        if (indent == 4 && raw[4] != '\t' && body.back() == ':') {
            if (body.substr(0, 8) == "Version:") {
                ++r.suspect_lines; // a name line never starts "Version:"
                continue;
            }
            flush();
            current_name = std::string(body.substr(0, body.size() - 1));
            have_name = true;
        } else if (indent > 4 && body.substr(0, 8) == "Version:") {
            if (!have_name) {
                ++r.suspect_lines; // a Version line before any name
            } else if (!have_version) {
                const auto value = detail::trim(body.substr(8));
                if (!value.empty()) { // an empty value must not consume the app's one version
                    current_version = std::string(value);
                    have_version = true;
                    // The first Version must directly follow its name line (the measured shape). A
                    // Version after another property means the name line (and its own Version) may
                    // have been lost and this one belongs to the previous application.
                    if (prev_kind != 'N')
                        ++r.suspect_lines;
                }
            } else {
                ++r.suspect_lines; // a second Version line in one block: a name line was dropped
            }
        } else if (indent == 3 || indent == 5 || (indent == 4 && body.back() != ':')) {
            // a name or property line at an indent the real output never uses
            if (body.back() == ':' || indent == 4 || body.substr(0, 8) == "Version:")
                ++r.suspect_lines;
        }
    }
    flush();
    // A localized or reshaped "Version:" label leaves apps without a version; CVE matching skips
    // them and the scan reads clean. English labels only are understood: when MORE THAN HALF of the
    // apps have no recognised version, the read is unreadable (this covers every app unversioned and
    // a report that mixes labels). A real Mac lists nearly every application with a version.
    // Every unrecognised name/version-shaped line counts as one more unusable application.
    const auto unversioned = std::count_if(r.apps.begin(), r.apps.end(),
                                           [](const MacosApp& a) { return a.version.empty(); }) +
                             static_cast<std::ptrdiff_t>(r.suspect_lines);
    const auto total = static_cast<std::ptrdiff_t>(r.apps.size() + r.suspect_lines);
    if (!r.apps.empty() && unversioned * 2 > total)
        r.apps.clear();
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
    std::size_t cve_inputs_unusable = 0; // apps matching a CVE rule that had no usable version
    std::size_t software_unrecognised = 0; // profiler lines not recognised in an otherwise read list
};

/// Provenance token for the CONSTRAINED/PARTIAL status; empty = declare nothing. The provenance is
/// ONE token, so when causes stack the precedence is: unreadable software list, then unusable CVE
/// inputs, then unrecognised software-list lines, then an unreadable config read, then the standing
/// Homebrew gap. EVERY cause is still reported in-band by coverage_notes().
inline std::string_view coverage_token(const CoverageState& c) {
    if (c.macos_software && !c.sp_readable)
        return kMacosSystemProfilerUnreadable;
    if (c.cve_inputs_unusable > 0)
        return kMacosCveInputIncomplete;
    if (c.software_unrecognised > 0)
        return kMacosSoftwareListUnrecognised;
    if (c.config_unreadable)
        return kMacosConfigUnreadable;
    if (c.macos_software)
        return kMacosHomebrewNotScanned;
    return {};
}

/// Set cov.cve_inputs_unusable from the apps just listed (macOS software only).
template <class Rules>
inline void update_cve_inputs(CoverageState& cov, const std::vector<MacosApp>& apps,
                              const Rules& rules) {
    if (cov.macos_software)
        cov.cve_inputs_unusable = count_unusable_cve_apps(apps, rules);
}

/// True when an application's version must be skipped, never string-compared (macOS software only).
inline bool skip_unusable_for_compare(bool macos_software, std::string_view version) {
    return macos_software && !usable_version(version);
}

/// The "No vulnerabilities" placeholder is a claim of a clean scan: it is printed only when the
/// software list was readable, no CVE input was unusable and no profiler line was unrecognised.
inline bool want_clean_placeholder(const CoverageState& c) {
    return !(c.macos_software && !c.sp_readable) && c.cve_inputs_unusable == 0 &&
           c.software_unrecognised == 0;
}

struct CoverageNote {
    std::string_view severity; // "INFO" (known standing gap) or "UNREADABLE" (a read failed)
    std::string text;
};

/// The note for applications that matched a built-in CVE rule but had no usable version.
inline std::string cve_input_note(std::size_t n) {
    return std::to_string(n) + " application(s) matching a built-in CVE rule had no usable version; "
                               "not a clean result";
}

/// The note for profiler lines that were not recognised in a list that was otherwise read.
inline std::string software_unrecognised_note(std::size_t n) {
    return std::to_string(n) + " line(s) of the software list were not recognised; applications may "
                               "be missing; not a clean result";
}

/// Every in-band coverage note for this run, in a stable order; empty = nothing to say.
inline std::vector<CoverageNote> coverage_notes(const CoverageState& c) {
    std::vector<CoverageNote> n;
    if (c.macos_software)
        n.push_back(c.sp_readable ? CoverageNote{"INFO", std::string(kCoverageNoteHomebrew)}
                                  : CoverageNote{"UNREADABLE", std::string(kCoverageNoteUnreadable)});
    if (c.cve_inputs_unusable > 0)
        n.push_back({"UNREADABLE", cve_input_note(c.cve_inputs_unusable)});
    if (c.software_unrecognised > 0)
        n.push_back({"UNREADABLE", software_unrecognised_note(c.software_unrecognised)});
    if (c.config_unreadable)
        n.push_back({"UNREADABLE", std::string(kCoverageNoteConfig)});
    return n;
}

/// `severity|category|title|detail` row (matches the placeholder row's shape).
inline std::string coverage_row(const CoverageNote& n) {
    return std::string(n.severity) + "|scan|Coverage|" + n.text;
}

/// `summary|<key>|<value>` row for summary (summary's own row shape; value is text, like TOTAL's).
inline std::string coverage_summary_row(const CoverageNote& n) {
    return "summary|COVERAGE|" + n.text;
}

} // namespace yuzu::vuln
