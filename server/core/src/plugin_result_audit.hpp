#pragma once

/**
 * plugin_result_audit.hpp -- turns the registry plugin's `audit|...` output lines into
 * `registry.write` audit rows. Pure: no I/O, no store call, no clock (the caller passes the time);
 * the rules below are exercised by tests/unit/server/test_plugin_result_audit.cpp.
 *
 * THE BINDING. Plugin output is data an endpoint produced, so a line that merely STARTS with
 * `audit|` is evidence of nothing. A row is extracted only when the frame's command_id is exactly
 * what the server mints for a registry command (`registry-` plus 16 or 32 lowercase hex digits; the
 * plugin name keeps the operator's spelling, so it is compared ASCII-case-insensitively) AND the
 * frame's `CommandResponse.action` (stamped by the AGENT on every plugin-output RUNNING frame and on
 * the final frame, agents/core/src/agent.cpp CommandContextImpl::action) is one of the three
 * MUTATING actions. A read action's output can never mint a row, and an agent that stamps no action
 * (every agent that predates the stamp) produces none: fail-closed, documented. A read action's
 * output is never parsed for `audit|` lines, so the action gate is the control, not the content.
 * The rows stay ASSERTED BY THE ENDPOINT: the server checks the shape of the id and the stamped
 * action, not a dispatch record.
 *
 * BOUNDS. At most kMaxRegistryAuditLinesPerFrame lines per frame, each cut to
 * kMaxRegistryAuditLineBytes on a character boundary, every control byte neutralised. A frame
 * over a bound is reported (`truncated`) and the excess is not recorded; a cut line's row carries
 * the server token `cut=1`. Across frames the caller applies a per-agent budget
 * (kRegistryAuditBudget*), because a bound per frame is not a bound on frames.
 *
 * ROW SHAPE. docs/user-manual/audit-log.md. `result` is the FIRST `|result=` token of the WHOLE
 * line (read before any cut), never `dry_run=`. `detail` is the trusted `agent=<id>` token FIRST,
 * then `cut=1` when the line was cut, then the line: a crafted line cannot forge a server token for
 * a reader that takes the first match. `target_type` is `command`, the spelling of the dispatch
 * rows the `command_id` joins to.
 *
 * FIELD CONTRACT (a requirement on the plugin that produces the lines; this header cannot recover
 * from a violation). One record per line, LF-terminated. No `|`, LF or CR inside a field: a registry
 * key or value name can hold them, so the producer escapes them (otherwise that text could pick the
 * row's result or forge a second row). Put `result=` before any caller-sized field: it is read from
 * the whole line, but a line over the byte bound loses its tail. At most
 * kMaxRegistryAuditLinesPerFrame lines and kMaxRegistryAuditLineBytes bytes per line.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <yuzu/log_token.hpp>

#include "audit_store.hpp"

namespace yuzu::server {

/// The registry plugin's three state-changing actions -- the only ones whose output is audited.
inline constexpr std::array<std::string_view, 3> kRegistryMutatingActions{
    "set_value", "delete_value", "delete_key"};

[[nodiscard]] constexpr bool is_registry_mutating_action(std::string_view action) noexcept {
    return std::ranges::find(kRegistryMutatingActions, action) != kRegistryMutatingActions.end();
}

inline constexpr std::size_t kMaxRegistryAuditLinesPerFrame = 300;
inline constexpr std::size_t kMaxRegistryAuditLineBytes = 4096;

/// Per-agent row budget (bounded_audit_budget.hpp), applied across frames. Far above the volume of a
/// legitimate agent (one row per write): its job is to stop an enrolled agent that loops
/// 300-line frames from writing millions of 365-day evidence rows, not to ration normal use. The
/// agent table is sized for a fleet-wide change answered inside one window; beyond it, further
/// agents share one overflow bucket (sampling), and `yuzu_server_registry_audit_dropped_total`
/// says so.
inline constexpr std::size_t kRegistryAuditBudgetRows = 600;
inline constexpr std::int64_t kRegistryAuditBudgetWindowMs = 60'000;
inline constexpr std::size_t kRegistryAuditBudgetAgents = 262'144;

/// `plugin` is the registry plugin, compared ASCII-case-insensitively (command_routes.cpp mints the
/// id from the RAW request spelling; classify is case-insensitive, so `Registry` runs the write on
/// the endpoint).
[[nodiscard]] constexpr bool is_registry_plugin(std::string_view plugin) noexcept {
    constexpr std::string_view kName = "registry";
    return std::ranges::equal(plugin, kName, [](char a, char b) { return (a | 0x20) == b; });
}

/// The command ids the server mints for a registry command: the plugin name as the operator typed
/// it, `-`, then lowercase hex of 8 bytes (command_routes.cpp, the legacy forwarder in server.cpp)
/// or 16 bytes (dispatch_confined and the scheduled enqueue in server.cpp). Anything else did not
/// come from a server dispatch of the registry plugin. A valid shape is still forgeable by an
/// endpoint (it is only a shape): the rows are asserted by the agent.
[[nodiscard]] constexpr bool is_minted_registry_command_id(std::string_view id) noexcept {
    constexpr std::string_view kName = "registry";
    const std::size_t tail = id.size() > kName.size() + 1 ? id.size() - kName.size() - 1 : 0;
    return (tail == 16 || tail == 32) && is_registry_plugin(id.substr(0, kName.size())) &&
           id[kName.size()] == '-' &&
           std::ranges::all_of(id.substr(kName.size() + 1), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

/// The value of the line's `result=` field ("" when absent): the text after the FIRST `|result=` up
/// to the next `|` or the end of the line.
[[nodiscard]] inline std::string_view registry_audit_result(std::string_view line) noexcept {
    constexpr std::string_view kKey = "|result=";
    const std::size_t at = line.find(kKey);
    if (at == std::string_view::npos)
        return {};
    const std::size_t start = at + kKey.size();
    return line.substr(start, std::min(line.find('|', start), line.size()) - start);
}

/// One `audit|` line, as it will be recorded.
struct RegistryAuditLine {
    std::string text;  ///< control bytes neutralised, cut to kMaxRegistryAuditLineBytes
    bool ok{false};    ///< the whole line's first `|result=` token was `ok` (read before any cut)
    bool cut{false};   ///< the line was longer than kMaxRegistryAuditLineBytes; `text` is its prefix
};

struct RegistryAuditLines {
    std::vector<RegistryAuditLine> lines;
    bool truncated{false}; ///< `audit|` lines past kMaxRegistryAuditLinesPerFrame were dropped
};

/// The `audit|...` lines of one output frame (output lines are LF-separated), bounded and
/// neutralised as described above.
[[nodiscard]] inline RegistryAuditLines extract_registry_audit_lines(std::string_view output) {
    RegistryAuditLines out;
    for (std::size_t pos = 0; pos < output.size();) {
        const std::size_t nl = std::min(output.find('\n', pos), output.size());
        std::string_view line = output.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.starts_with("audit|"))
            continue;
        if (out.lines.size() == kMaxRegistryAuditLinesPerFrame) {
            out.truncated = true;
            break;
        }
        RegistryAuditLine l;
        l.ok = registry_audit_result(line) == "ok";
        if (line.size() > kMaxRegistryAuditLineBytes) {
            // Back off to a character boundary: a UTF-8 sequence is at most 4 bytes, so at most 3
            // continuation bytes precede the cut. Anything longer is not UTF-8 and is cut at the
            // bound (sanitize_pg_text repairs a split character at INSERT).
            std::size_t back = 0;
            while (back < 3 &&
                   (static_cast<unsigned char>(line[kMaxRegistryAuditLineBytes - back]) & 0xC0) ==
                       0x80)
                ++back;
            if ((static_cast<unsigned char>(line[kMaxRegistryAuditLineBytes - back]) & 0xC0) !=
                0x80)
                line = line.substr(0, kMaxRegistryAuditLineBytes - back);
            else
                line = line.substr(0, kMaxRegistryAuditLineBytes);
            l.cut = true;
        }
        l.text = std::string{line};
        // Every ASCII control byte (CR, NUL, ESC, BEL ...): the log file is an escape-interpreting
        // sink.
        std::ranges::replace_if(
            l.text, [](unsigned char c) { return c < 0x20 || c == 0x7F; }, '_');
        out.lines.push_back(std::move(l));
    }
    return out;
}

[[nodiscard]] inline AuditEvent make_registry_audit_event(std::string_view agent_id,
                                                          std::string_view command_id,
                                                          const RegistryAuditLine& line,
                                                          std::int64_t now_epoch_s) {
    AuditEvent ev;
    ev.timestamp = now_epoch_s;
    ev.principal = "agent:" + std::string{agent_id};
    ev.principal_role = "agent";
    ev.action = "registry.write";
    ev.target_type = "command";
    ev.target_id = std::string{command_id};
    // The trusted tokens go FIRST: the line is endpoint text, and a ` agent=<other>` or ` cut=1`
    // inside it must not be what a first-match reader finds (the role.elevation.granted convention).
    ev.detail = "agent=" + yuzu::log_token(agent_id) + (line.cut ? " cut=1 " : " ") + line.text;
    ev.result = line.ok ? "success" : "failure";
    return ev;
}

/// What one output frame owes the audit log, decided without I/O. The caller persists `events` and
/// reports the two flags, so it never re-derives the gate.
struct RegistryAuditFrame {
    std::vector<AuditEvent> events;
    bool truncated{false};     ///< a bound was hit: lines past the cap dropped, or a line was cut
    bool unmintable_id{false}; ///< registry mutating frame, command_id not a minted shape: ignored
};

/// Nothing unless `plugin` is `registry`, `action` is one of the mutating actions and `command_id`
/// is a minted registry id (a registry mutating frame that fails only the last test is flagged
/// `unmintable_id`).
[[nodiscard]] inline RegistryAuditFrame
registry_audit_events_for_frame(std::string_view agent_id, std::string_view command_id,
                                std::string_view plugin, std::string_view action,
                                std::string_view output, std::int64_t now_epoch_s) {
    RegistryAuditFrame frame;
    if (!is_registry_plugin(plugin) || !is_registry_mutating_action(action))
        return frame;
    if (!is_minted_registry_command_id(command_id)) {
        frame.unmintable_id = true;
        return frame;
    }
    const auto extracted = extract_registry_audit_lines(output);
    frame.truncated = extracted.truncated;
    frame.events.reserve(extracted.lines.size());
    for (const auto& line : extracted.lines) {
        frame.truncated = frame.truncated || line.cut;
        frame.events.push_back(make_registry_audit_event(agent_id, command_id, line, now_epoch_s));
    }
    return frame;
}

} // namespace yuzu::server
