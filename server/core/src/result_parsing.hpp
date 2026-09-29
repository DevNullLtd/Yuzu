#pragma once

/// @file result_parsing.hpp
/// Shared utilities for parsing pipe-delimited plugin output into columns.
/// Used by: SSE row rendering, ResponseStore facet extraction, DashboardRoutes
/// fragment rendering.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

// -- Column schemas per plugin ------------------------------------------------

/// Default column schema for unknown plugins.
inline const std::vector<std::string> kDefaultColumns{"Agent", "Output"};

/// Sentinel: TAR SQL results use dynamic schemas (sent via __schema__ protocol line).
inline const std::vector<std::string> kTarDynamic{"Agent", "Output"};

/// Check if a line is a TAR protocol line (__schema__ or __total__).
inline bool is_tar_protocol_line(const std::string& line) {
    return line.starts_with("__schema__|") || line.starts_with("__total__|");
}

/// Parse column names from a __schema__|col1|col2|... line.
inline std::vector<std::string> parse_tar_schema_line(const std::string& line) {
    std::vector<std::string> cols;
    if (!line.starts_with("__schema__|")) return cols;
    size_t pos = 11; // skip "__schema__|"
    while (pos <= line.size()) {
        auto p = line.find('|', pos);
        if (p == std::string::npos) {
            cols.push_back(line.substr(pos));
            break;
        }
        cols.push_back(line.substr(pos, p - pos));
        pos = p + 1;
    }
    return cols;
}

/// Returns the column names for a given plugin.
inline const std::vector<std::string>& columns_for_plugin(const std::string& plugin) {
    static const std::unordered_map<std::string, std::vector<std::string>> kSchemas{
        {"chargen",     {"Agent", "Output"}},
        {"procfetch",   {"Agent", "PID", "Name", "Path", "SHA-1"}},
        // netstat: static fallback for the netstat_list action (7 cols after
        // Agent). The `attribution` action's 9-column schema (adds Process
        // Name/Process Path) rides the content-definition result_schema via
        // DashboardRoutes::resolve_render_columns instead of a kSchemas
        // entry here -- see roadmap D2 (#3403) -- so this stays netstat_list
        // shaped rather than trying to serve both actions from one static row.
        {"netstat",     {"Agent", "Proto", "Local Addr", "Local Port",
                         "Remote Addr", "Remote Port", "State", "PID"}},
        {"vuln_scan",   {"Agent", "Severity", "Category", "Title", "Detail"}},
        {"tar",         {"Agent", "Output"}}, // Dynamic: overridden by __schema__ protocol
    };
    static const std::vector<std::string> kKeyValue{"Agent", "Key", "Value"};
    static const std::unordered_set<std::string> kKeyValuePlugins{
        "status",          "device_identity", "os_info",       "hardware",
        "users",           "installed_apps",  "msi_packages",  "network_config",
        "diagnostics",     "agent_actions",   "processes",     "services",
        "filesystem",      "network_diag",    "network_actions","firewall",
        "antivirus",       "bitlocker",       "windows_updates","event_logs",
        "sccm",            "script_exec",     "software_actions","interaction"};

    auto it = kSchemas.find(plugin);
    if (it != kSchemas.end()) return it->second;
    if (kKeyValuePlugins.contains(plugin)) return kKeyValue;
    return kDefaultColumns;
}

// -- Per-cell operator hints --------------------------------------------------
//
// A rendered cell's raw value can have a non-obvious meaning an operator
// reading the results table has no way to infer from the value alone (#4187:
// autoruns' `enabled=unknown` reads as "maybe disabled?" without context --
// it actually means the scan couldn't determine enablement at all, a
// completeness gap, not a disabled-vs-enabled fact). Table-driven so this
// stays a small, reviewable list of (plugin, row-kind, column, value) ->
// hint entries rather than a plugin-name branch inside the shared renderer
// every plugin's rows pass through.

struct CellHint {
    std::string_view plugin;
    std::string_view row_kind; // fields[0] to match; empty = any row kind
    std::size_t field_index;
    std::string_view value;
    std::string_view hint;
};

inline const std::vector<CellHint>& cell_hints() {
    static const std::vector<CellHint> kHints{
        // field_index 7 = the `enabled` column in autoruns' format_row
        // (agents/plugins/autoruns/src/autoruns_parsers.hpp) -- keep this
        // in sync with that function's own field-order comment if a column
        // is ever inserted before `enabled`.
        {"autoruns", "autorun", 7, "unknown",
         "unknown = enablement could not be determined from the available "
         "evidence (a directory scan was capped or hit a read error, the "
         "rung-2 systemctl fallback text carries no enablement evidence, or "
         "a Windows Scheduled Task's COM/XML read failed) -- not the same as "
         "disabled. See the autoruns user manual and the source's own status "
         "reason for the specific cause."},
    };
    return kHints;
}

/// Returns a non-empty operator-facing hint for `fields[field_index]` when
/// this exact (plugin, row-kind, column, value) combination has a
/// documented non-obvious meaning; otherwise an empty string_view (the
/// overwhelmingly common case -- most cells need no hint).
inline std::string_view cell_hint_for(const std::string& plugin,
                                      const std::vector<std::string>& fields,
                                      std::size_t field_index) {
    if (field_index >= fields.size()) return {};
    for (const auto& h : cell_hints()) {
        if (h.plugin != plugin) continue;
        if (h.field_index != field_index) continue;
        if (!h.row_kind.empty() && (fields.empty() || fields[0] != h.row_kind)) continue;
        if (fields[field_index] != h.value) continue;
        return h.hint;
    }
    return {};
}

// -- Pipe-delimited field splitting -------------------------------------------

/// Find the next unescaped '|' starting at @p pos. Returns npos if not found.
inline size_t find_unescaped_pipe(const std::string& s, size_t pos) {
    while (pos < s.size()) {
        auto p = s.find('|', pos);
        if (p == std::string::npos) return std::string::npos;
        if (p > 0 && s[p - 1] == '\\') { pos = p + 1; continue; }
        return p;
    }
    return std::string::npos;
}

/// Remove backslash-escaping from pipe characters: "foo\|bar" → "foo|bar".
inline std::string unescape_pipes(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '|') continue;
        out += s[i];
    }
    return out;
}

/// Split a pipe-delimited output line into fields according to the plugin schema.
/// The first column ("Agent") is NOT included — the caller prepends the agent name.
inline std::vector<std::string> split_fields(const std::string& plugin,
                                             const std::string& line) {
    // vuln_scan: severity|category|title|detail (4 fields, last is remainder)
    if (plugin == "vuln_scan") {
        std::vector<std::string> parts;
        size_t pos = 0;
        for (int i = 0; i < 3; ++i) {
            auto p = find_unescaped_pipe(line, pos);
            if (p == std::string::npos) {
                parts.push_back(unescape_pipes(line.substr(pos)));
                return parts;
            }
            parts.push_back(unescape_pipes(line.substr(pos, p - pos)));
            pos = p + 1;
        }
        parts.push_back(unescape_pipes(line.substr(pos))); // remainder = detail
        return parts;
    }
    // key|value plugins: split into exactly 2 (key, rest)
    auto& cols = columns_for_plugin(plugin);
    if (cols.size() == 3) { // Agent + Key + Value
        auto sep = find_unescaped_pipe(line, 0);
        if (sep != std::string::npos)
            return {unescape_pipes(line.substr(0, sep)), unescape_pipes(line.substr(sep + 1))};
        return {unescape_pipes(line), ""};
    }
    // Default: split on all pipes
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= line.size()) {
        auto p = find_unescaped_pipe(line, pos);
        if (p == std::string::npos) {
            parts.push_back(unescape_pipes(line.substr(pos)));
            break;
        }
        parts.push_back(unescape_pipes(line.substr(pos, p - pos)));
        pos = p + 1;
    }
    return parts;
}

// -- Output line iteration ----------------------------------------------------

/// Split multi-line output into individual lines, trimming trailing \r.
inline std::vector<std::string> split_output_lines(const std::string& raw_output) {
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos < raw_output.size()) {
        auto nl = raw_output.find('\n', pos);
        std::string line = (nl == std::string::npos)
                               ? raw_output.substr(pos)
                               : raw_output.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
        pos = (nl == std::string::npos) ? raw_output.size() : nl + 1;
    }
    return lines;
}

} // namespace yuzu::server
