#pragma once

// Shared "live device read" kind table + plugin-output field parser.
//
// The /device "Get live info" feature exists on two surfaces: the dashboard HTML
// path (device_routes.cpp render_live_result) and the agentic-first REST JSON path
// (rest_api_v1.cpp live_result_json). Both dispatch the SAME read-only instructions
// and parse the SAME wire format. Keeping the kind->(plugin,action,audit_action)
// table and the `proc|pid|name|sha256|path` / `uptime_*|value` extraction in ONE
// place stops the two from drifting — a wire-format change on the agent now moves a
// single header, not two translation units in lockstep (governance architect S2).
//
// Header-only (inline): no new TU / meson wiring; both callers include it.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::live {

// One "Get live info" panel = one real plugin instruction dispatched at the device
// NOW. `kind` is an ALLOWLIST token; each kind carries its own audit verb so a
// usage-class read (what processes a person runs) stays separately countable from a
// machine-health read (uptime) — the works-council access-audit posture.
struct LiveKind {
    std::string plugin;
    std::string action;
    std::string label;
    std::string audit_action;
    // Optional SECONDARY dispatch joined at render (the dashboard process_tree card
    // dispatches network_diag/connections alongside processes/list_tree and joins by
    // PID). Empty for kinds with no join. The shared REST surface ignores these — it
    // does not yet render the dashboard-only multi-card kinds (A1 backfill, #1649).
    std::string plugin2;
    std::string action2;
    // Generic pipe-row rendering (round-3 item 11 — physical-kit panels). A non-empty
    // `columns` means this kind's output is a flat `<row_prefix>|field1|field2|...`
    // table with no bespoke parsing/typed-row struct: device_routes.cpp's
    // render_live_result() dispatches it straight to the shared
    // render_device_live_generic(columns, rows) renderer (device_ui.cpp) instead of a
    // one-off render_device_live_KIND function. Leave both empty for every kind that
    // still has (or needs) a bespoke renderer — this is additive, not a replacement
    // for the existing typed-row kinds above.
    std::string row_prefix;
    std::vector<std::string> columns;
};

inline std::optional<LiveKind> resolve_kind(const std::string& kind) {
    if (kind == "uptime")
        return LiveKind{"os_info", "uptime", "Uptime", "device.live.uptime"};
    if (kind == "processes")
        return LiveKind{"processes", "list_hashed", "Running processes", "device.live.processes"};
    return std::nullopt;
}

// Split newline-joined write_output() lines: tolerate a trailing '\r' and drop empty
// lines (matches both legacy renderers).
inline std::vector<std::string> split_lines(const std::string& output) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < output.size()) {
        const auto nl = output.find('\n', pos);
        std::string line =
            output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
    return lines;
}

struct ProcRow {
    std::int64_t pid{0};
    std::string name;
    std::string sha256;
    std::string path;
};

// Parse `proc|pid|name|sha256|path` rows (tolerate the shorter `proc|pid|name` and
// `proc|pid|name|sha256` forms). Bounds-safe on any input — a malformed/truncated
// line yields a best-effort row or is skipped, never an out-of-range substr.
inline std::vector<ProcRow> parse_processes(const std::string& output) {
    std::vector<ProcRow> procs;
    for (const auto& l : split_lines(output)) {
        if (l.rfind("proc|", 0) != 0)
            continue;
        const auto a = l.find('|');        // after "proc"
        const auto b = l.find('|', a + 1); // after pid
        if (b == std::string::npos)
            continue;
        const auto c = l.find('|', b + 1); // after name
        ProcRow p;
        try {
            p.pid = std::stoll(l.substr(a + 1, b - a - 1));
        } catch (...) {
            p.pid = 0;
        }
        if (c == std::string::npos) {
            p.name = l.substr(b + 1);
        } else {
            p.name = l.substr(b + 1, c - b - 1);
            const auto e = l.find('|', c + 1); // after sha256 (path may contain none)
            if (e == std::string::npos) {
                p.sha256 = l.substr(c + 1);
            } else {
                p.sha256 = l.substr(c + 1, e - c - 1);
                p.path = l.substr(e + 1);
            }
        }
        procs.push_back(std::move(p));
    }
    return procs;
}

struct Uptime {
    std::optional<std::string> display; // present iff an `uptime_display|` line existed
    std::optional<std::int64_t> seconds;
};

inline Uptime parse_uptime(const std::string& output) {
    Uptime u;
    for (const auto& l : split_lines(output)) {
        const auto bar = l.find('|');
        if (bar == std::string::npos)
            continue;
        const auto k = l.substr(0, bar);
        const auto v = l.substr(bar + 1);
        if (k == "uptime_display") {
            u.display = v;
        } else if (k == "uptime_seconds") {
            try {
                u.seconds = static_cast<std::int64_t>(std::stoll(v));
            } catch (...) {
            }
        }
    }
    return u;
}

} // namespace yuzu::server::live
