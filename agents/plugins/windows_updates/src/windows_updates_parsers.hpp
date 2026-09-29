#pragma once

/**
 * windows_updates_parsers.hpp — pure parse/format helpers for the
 * windows_updates plugin's `installed` and `missing` actions.
 *
 * Header-only and OS-free (the discovery_parsers.hpp / firewall_parsers.hpp
 * pattern) so every shell-out's text format, and the WMI/WUA COM result
 * shapes, are unit-tested on every host (test_windows_updates_parsers.cpp) --
 * the run_bounded_subprocess calls and the Windows COM/WMI plumbing in
 * windows_updates_plugin.cpp are the impure shell.
 *
 * WmiRow (agents/shared/wmi_bounded.hpp) and the live WUA COM interfaces are
 * both _WIN32-gated types, so the two Windows-sourced formatters below take
 * small portable synthetic structs (HotfixRow / UpdateRow) instead -- the
 * plugin's Windows leg maps a WmiRow / IUpdate into one of these before
 * calling in, and this file compiles and is tested on every platform.
 */

#include <yuzu/plugin.h>          // YuzuResultStatus / YuzuResultCompleteness (portable, C ABI)
#include <yuzu/string_utils.hpp>  // yuzu::util::safe_output_field (BR-07)

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::windows_updates {

using yuzu::util::safe_output_field;

// ── installed (Windows: WMI Win32_QuickFixEngineering) ─────────────────────

struct HotfixRow {
    std::string hotfix_id;
    std::string description;
    std::string installed_on;
};

/// Format hotfix rows into the plugin's `update|kb_id|description|date`
/// wire shape. Every field is safe_output_field-escaped: HotFixID/
/// InstalledOn are provider-supplied strings, not compile-time literals, so
/// they get the same BR-07 treatment as Description.
[[nodiscard]] inline std::vector<std::string> format_hotfix_rows(
    const std::vector<HotfixRow>& rows) {
    std::vector<std::string> out;
    out.reserve(rows.size());
    for (const auto& r : rows) {
        out.push_back(std::format("update|{}|{}|{}", safe_output_field(r.hotfix_id),
                                  safe_output_field(r.description),
                                  safe_output_field(r.installed_on)));
    }
    return out;
}

// ── missing (Windows: WUA COM IUpdateCollection) ───────────────────────────

struct UpdateRow {
    std::string title;
    std::string msrc_severity; // may be empty -- not every update is a security update
};

/// Format available-update rows into the plugin's `available|title|severity`
/// wire shape. An empty msrc_severity formats to a trailing empty field
/// (matches the old PowerShell pipeline's `$u.MsrcSeverity`, which was blank
/// for the same non-security-update case) -- never dropped or defaulted to a
/// placeholder, so a consumer can tell "no severity" from "field missing".
[[nodiscard]] inline std::vector<std::string> format_update_rows(
    const std::vector<UpdateRow>& rows) {
    std::vector<std::string> out;
    out.reserve(rows.size());
    for (const auto& r : rows) {
        out.push_back(std::format("available|{}|{}", safe_output_field(r.title),
                                  safe_output_field(r.msrc_severity)));
    }
    return out;
}

// ── missing (Windows: run_bounded_wmi_query error token) ───────────────────

struct WmiFailureStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
};

/// Classify a yuzu::shared::wmi::BoundedQueryResult::error token into the
/// ABI4 result-status seam by hand. run_bounded_wmi_query returns its own
/// typed error (a stable string token), not a yuzu::agent::SubprocessResult,
/// so runner_status.hpp's classify_runner_failure doesn't apply to it --
/// this is the WMI-side equivalent of that same mapping.
///
/// com_init_failed / wbem_locator_failed / wmi_connect_failed_<hr> mean the
/// WMI/COM plumbing itself never came up (UNAVAILABLE -- there is no
/// connection to have degraded). wmi_query_failed_<hr> / wmi_next_timeout /
/// wmi_deadline_exceeded / wmi_next_failed_<hr> mean the connection worked
/// but the query itself degraded mid-flight (CONSTRAINED). Both are
/// PARTIAL: neither shape leaves the caller with a result it should treat as
/// a complete, trustworthy enumeration. An unrecognised token (a future
/// error shape this file hasn't been taught yet) falls into the CONSTRAINED
/// branch -- the honest middle ground between "definitely never connected"
/// and silently treating an unknown failure as success.
[[nodiscard]] inline WmiFailureStatus classify_wmi_error(const std::string& token) {
    if (token == "com_init_failed" || token.starts_with("wbem_locator_failed") ||
        token.starts_with("wmi_connect_failed_")) {
        return WmiFailureStatus{YUZU_RESULT_STATUS_UNAVAILABLE,
                                YUZU_RESULT_COMPLETENESS_PARTIAL, "wmi_bounded:" + token};
    }
    return WmiFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                            "wmi_bounded:" + token};
}

// ── installed (Linux: rpm -qa --last) ───────────────────────────────────────

/// Parse `rpm -qa --last` lines ("package-name  date", double-space
/// separated) into the plugin's `package|name|date` wire shape. A line
/// without the double-space separator (unexpected rpm output shape) falls
/// back to `package|<line>|-` rather than being dropped -- matches the
/// pre-migration popen parser's fallback exactly.
[[nodiscard]] inline std::vector<std::string> parse_rpm_last(
    const std::vector<std::string>& lines) {
    std::vector<std::string> out;
    out.reserve(lines.size());
    for (const auto& line : lines) {
        auto sep = line.find("  ");
        if (sep != std::string::npos) {
            // rpm pads the name/date gap to a fixed column with a run of
            // spaces, not exactly two -- skip the whole run so the date
            // field doesn't retain leading padding.
            auto date_start = line.find_first_not_of(' ', sep);
            auto date = date_start == std::string::npos ? std::string{} : line.substr(date_start);
            out.push_back(std::format("package|{}|{}", safe_output_field(line.substr(0, sep)),
                                      safe_output_field(date)));
        } else {
            out.push_back(std::format("package|{}|-", safe_output_field(line)));
        }
    }
    return out;
}

// ── installed/missing (Linux: apt list --installed / --upgradable) ─────────

struct AptListEntry {
    std::string name;
    std::string version;
};

/// Parse one `apt list` data line ("name/repo version arch [...]") into
/// {name, version}. Returns nullopt for the "Listing..." header apt always
/// prints first, or any line without both a '/' and a following space.
[[nodiscard]] inline std::optional<AptListEntry> parse_apt_list_line(std::string_view line) {
    if (line.starts_with("Listing"))
        return std::nullopt;
    auto slash = line.find('/');
    auto space = line.find(' ');
    if (slash == std::string_view::npos || space == std::string_view::npos)
        return std::nullopt;
    auto name = std::string(line.substr(0, slash));
    auto rest = line.substr(space + 1);
    auto ver_end = rest.find(' ');
    auto version = std::string(ver_end != std::string_view::npos ? rest.substr(0, ver_end) : rest);
    return AptListEntry{std::move(name), std::move(version)};
}

/// `apt list --installed` -> `package|name|version`. Unlike
/// parse_apt_upgradable, a non-matching non-header line still gets a
/// `package|<line>|-` fallback row -- matches the pre-migration parser,
/// which wrote something for every line except the header.
[[nodiscard]] inline std::vector<std::string> parse_apt_installed(
    const std::vector<std::string>& lines) {
    std::vector<std::string> out;
    for (const auto& line : lines) {
        if (line.starts_with("Listing"))
            continue;
        if (auto entry = parse_apt_list_line(line)) {
            out.push_back(std::format("package|{}|{}", safe_output_field(entry->name),
                                      safe_output_field(entry->version)));
        } else {
            out.push_back(std::format("package|{}|-", safe_output_field(line)));
        }
    }
    return out;
}

/// `apt list --upgradable` -> `available|name|version`. No fallback branch:
/// a non-matching line is silently dropped, matching the pre-migration
/// parser exactly (it only ever set its `found` flag on a successful
/// name/version parse).
[[nodiscard]] inline std::vector<std::string> parse_apt_upgradable(
    const std::vector<std::string>& lines) {
    std::vector<std::string> out;
    for (const auto& line : lines) {
        if (auto entry = parse_apt_list_line(line)) {
            out.push_back(std::format("available|{}|{}", safe_output_field(entry->name),
                                      safe_output_field(entry->version)));
        }
    }
    return out;
}

// ── missing (Linux fallback: yum check-update) ──────────────────────────────

/// `yum check-update` -> `available|<line>`, dropping the "Loaded"/"Loading"
/// plugin-banner lines yum prints on stderr-merged output. Blank-line
/// filtering (the old `| grep -v '^$'`) needs no code here: run_bounded_
/// subprocess's SubprocessResult::lines already drops blank lines.
[[nodiscard]] inline std::vector<std::string> parse_yum_checkupdate(
    const std::vector<std::string>& lines) {
    std::vector<std::string> out;
    out.reserve(lines.size());
    for (const auto& line : lines) {
        if (line.starts_with("Loaded") || line.starts_with("Loading"))
            continue;
        out.push_back(std::format("available|{}", safe_output_field(line)));
    }
    return out;
}

// ── missing (macOS: softwareupdate -l) ──────────────────────────────────────

/// `softwareupdate -l` -> `available|<line>`, trimming leading
/// whitespace/`*` bullets and dropping banner/status lines ("Software
/// Update", "Finding...", "No new..."). A line that is ENTIRELY whitespace/
/// `*` (find_first_not_of returns npos) is left un-trimmed rather than
/// cleared -- a verbatim carry-over of the pre-migration parser's own
/// behaviour for that edge case, not a new decision made here.
[[nodiscard]] inline std::vector<std::string> parse_softwareupdate_list(
    const std::vector<std::string>& lines) {
    std::vector<std::string> out;
    for (const auto& line : lines) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t*");
        if (start != std::string::npos)
            trimmed = trimmed.substr(start);
        if (trimmed.empty() || trimmed.starts_with("Software Update"))
            continue;
        if (trimmed.starts_with("Finding") || trimmed.starts_with("No new"))
            continue;
        out.push_back(std::format("available|{}", safe_output_field(trimmed)));
    }
    return out;
}

// ── installed (macOS: system_profiler SPInstallHistoryDataType) ────────────

namespace detail {
[[nodiscard]] constexpr bool is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
} // namespace detail

/// Parse raw `system_profiler SPInstallHistoryDataType` output into the
/// plugin's `update|name|date` wire shape.
///
/// Two steps, both done here now that the old `grep -E '^ {4}\w|Install
/// Date:' | head -100` pipeline stage is gone (run_bounded_subprocess has no
/// shell to pipe through):
///  1. Filter to just the lines the grep pattern would have kept: a line
///     with EXACTLY 4 leading spaces then a word character (an entry-name
///     header), or a line containing "Install Date:" anywhere (unanchored,
///     matching grep's un-anchored second alternative) -- capped at the
///     first 100 MATCHING lines, same as the old `| head -100` acting on
///     the already-grepped stream.
///  2. Pair each name header with its following "Install Date:" line into
///     one `update|name|date` row (the original block-accumulation state
///     machine, unchanged).
[[nodiscard]] inline std::vector<std::string> parse_install_history_macos(
    const std::vector<std::string>& raw_lines) {
    std::vector<std::string> filtered;
    filtered.reserve(raw_lines.size() < 100 ? raw_lines.size() : 100);
    for (const auto& line : raw_lines) {
        const bool is_name_line = line.size() >= 5 && line[0] == ' ' && line[1] == ' ' &&
                                  line[2] == ' ' && line[3] == ' ' && detail::is_word_char(line[4]);
        const bool is_date_line = line.find("Install Date:") != std::string::npos;
        if (is_name_line || is_date_line) {
            filtered.push_back(line);
            if (filtered.size() >= 100)
                break;
        }
    }

    std::vector<std::string> out;
    std::string current_name;
    for (const auto& line : filtered) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t");
        if (start != std::string::npos)
            trimmed = trimmed.substr(start);

        if (trimmed.starts_with("Install Date:")) {
            auto date = trimmed.substr(14);
            auto ds = date.find_first_not_of(" ");
            if (ds != std::string::npos)
                date = date.substr(ds);
            if (!current_name.empty()) {
                out.push_back(std::format("update|{}|{}", safe_output_field(current_name),
                                          safe_output_field(date)));
            }
            current_name.clear();
        } else if (!trimmed.empty() && trimmed.back() == ':') {
            current_name = trimmed.substr(0, trimmed.size() - 1);
        }
    }
    if (!current_name.empty()) {
        out.push_back(std::format("update|{}|-", safe_output_field(current_name)));
    }
    return out;
}

} // namespace yuzu::windows_updates
