#pragma once

/**
 * plugin_result_audit.hpp -- turns the registry plugin's `audit|...` output lines into `registry.write`
 * audit rows. Pure: no I/O, no store call, no clock (the caller passes the time); every rule
 * is pinned by tests/unit/server/test_plugin_result_audit.cpp.
 *
 * THE BINDING. Plugin output is data an endpoint produced, so a line that merely STARTS with `audit|`
 * is evidence of nothing. A row is extracted only when the frame's command_id names the `registry`
 * plugin AND the frame's `CommandResponse.action` -- stamped by the AGENT on every ordinary output
 * frame (agents/core/src/agent.cpp CommandContextImpl::action) -- is one of the three MUTATING actions.
 * A read action's output can never mint a row, and an agent that stamps no action (every agent that
 * predates the stamp) produces none: fail-closed, documented. The plugin also sanitises every registry-controlled
 * string a read action renders, so a read cannot contain an `audit|` line in the first place.
 *
 * BOUNDS. kMaxRegistryAuditLinesPerFrame lines per frame, each cut to kMaxRegistryAuditLineBytes.
 * ROW SHAPE. docs/user-manual/audit-log.md; `result` is the line's own `result=`, never `dry_run=`.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/log_token.hpp>

#include "audit_store.hpp"

namespace yuzu::server {

/// The registry plugin's three state-changing actions -- the only ones whose output is audited.
inline constexpr std::array<std::string_view, 3> kRegistryMutatingActions{"set_value", "delete_value",
                                                                         "delete_key"};

[[nodiscard]] constexpr bool is_registry_mutating_action(std::string_view action) noexcept {
    return std::ranges::find(kRegistryMutatingActions, action) != kRegistryMutatingActions.end();
}

inline constexpr std::size_t kMaxRegistryAuditLinesPerFrame = 300;
inline constexpr std::size_t kMaxRegistryAuditLineBytes = 4096;

/// The `audit|...` lines of one output frame (output lines are LF-separated), bounded and
/// neutralised as described above.
[[nodiscard]] inline std::vector<std::string> extract_registry_audit_lines(std::string_view output) {
    std::vector<std::string> out;
    for (std::size_t pos = 0; pos < output.size() && out.size() < kMaxRegistryAuditLinesPerFrame;) {
        const std::size_t nl = std::min(output.find('\n', pos), output.size());
        std::string_view line = output.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.starts_with("audit|")) continue;
        if (line.size() > kMaxRegistryAuditLineBytes) {
            std::size_t cut = kMaxRegistryAuditLineBytes;
            while (cut > 0 && (static_cast<unsigned char>(line[cut]) & 0xC0) == 0x80) --cut;
            line = line.substr(0, cut);
        }
        std::string s{line};
        for (char& c : s)
            if (c == '\r' || c == '\0') c = '_';
        out.push_back(std::move(s));
    }
    return out;
}

/// The value of the line's `result=` field ("" when absent). Fields are `|`-separated tokens that
/// the plugin guarantees contain no `|`.
[[nodiscard]] inline std::string_view registry_audit_result(std::string_view line) noexcept {
    constexpr std::string_view kKey = "|result=";
    const std::size_t at = line.find(kKey);
    if (at == std::string_view::npos) return {};
    const std::size_t start = at + kKey.size();
    return line.substr(start, std::min(line.find('|', start), line.size()) - start);
}

[[nodiscard]] inline AuditEvent make_registry_audit_event(std::string_view agent_id,
                                                          std::string_view command_id,
                                                          std::string_view line,
                                                          std::int64_t now_epoch_s) {
    AuditEvent ev;
    ev.timestamp = now_epoch_s;
    ev.principal = "agent:" + std::string{agent_id};
    ev.principal_role = "agent";
    ev.action = "registry.write";
    ev.target_type = "Command";
    ev.target_id = std::string{command_id};
    ev.detail = std::string{line} + " agent=" + yuzu::log_token(agent_id);
    ev.result = registry_audit_result(line) == "ok" ? "success" : "failure";
    return ev;
}

/// Everything one output frame owes the audit log: nothing unless `plugin` is `registry` and
/// `action` is one of the mutating actions.
[[nodiscard]] inline std::vector<AuditEvent> registry_audit_events_for_frame(
    std::string_view agent_id, std::string_view command_id, std::string_view plugin,
    std::string_view action, std::string_view output, std::int64_t now_epoch_s) {
    std::vector<AuditEvent> events;
    if (plugin != "registry" || !is_registry_mutating_action(action)) return events;
    for (const auto& line : extract_registry_audit_lines(output))
        events.push_back(make_registry_audit_event(agent_id, command_id, line, now_epoch_s));
    return events;
}

} // namespace yuzu::server
