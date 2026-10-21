#pragma once

/**
 * plugin_result_audit.hpp -- turns the registry plugin's `audit|...` output lines into
 * `registry.write` audit rows. Pure: no I/O, no store call, no clock (the caller passes the time);
 * every rule is pinned by tests/unit/server/test_plugin_result_audit.cpp.
 *
 * THE BINDING. Plugin output is data an endpoint produced, so a line that merely STARTS with
 * `audit|` is evidence of nothing. A row is extracted only when the frame's command_id has a shape
 * the server could have minted AND names the `registry` plugin (ASCII-case-insensitively: the id
 * carries the spelling the operator typed, the agent runs the catalogue's) AND the frame's
 * `CommandResponse.action` (stamped by the AGENT on every ordinary output frame, agents/core/src/
 * agent.cpp CommandContextImpl::action) is one of the three MUTATING actions. A read action's
 * output can never mint a row, and an agent that stamps no action (every agent that predates the
 * stamp) produces none: fail-closed, documented. The binding does not depend on read output being
 * clean: a read action's output is never parsed for `audit|` lines, so the action gate (plugin ==
 * registry AND a stamped mutating action) is the control.
 *
 * BOUNDS. kMaxRegistryAuditLinesPerFrame lines per frame, each cut to kMaxRegistryAuditLineBytes,
 * and a command_id of at most kMaxServerCommandIdBytes (it becomes every row's target_id, and a
 * frame is built whole before the first INSERT, so an unbounded id would be multiplied by the line
 * cap). ROW SHAPE. docs/user-manual/audit-log.md; `result` is the line's own `result=`, never
 * `dry_run=`; `detail` is the trusted `agent=<id>` token FIRST, then the line (a crafted line
 * cannot forge the token for a reader that takes the first match).
 *
 * FIELD CONTRACT. The `result` is the FIRST `|result=` token of the line, so a producer must not
 * emit a `|` inside a field (a key or value name can hold one): otherwise that text could pick the
 * row's result. The escaping belongs to the producing plugin; this header cannot recover it.
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
inline constexpr std::array<std::string_view, 3> kRegistryMutatingActions{
    "set_value", "delete_value", "delete_key"};

[[nodiscard]] constexpr bool is_registry_mutating_action(std::string_view action) noexcept {
    return std::ranges::find(kRegistryMutatingActions, action) != kRegistryMutatingActions.end();
}

inline constexpr std::size_t kMaxRegistryAuditLinesPerFrame = 300;
inline constexpr std::size_t kMaxRegistryAuditLineBytes = 4096;
inline constexpr std::size_t kMaxServerCommandIdBytes = 160;
// A generous cap on an endpoint-supplied id, not a bound on every id the server mints (a 128-byte
// plugin ident plus "-" plus 32 hex is 161). The ids that can name the registry plugin are
// `<registry>-<16 hex>` (command_routes.cpp) or `<registry>-<32 hex>` (dispatch_confined and the
// scheduled enqueue in server.cpp): at most 8 + 1 + 32 bytes, and the cap must never drop below it.
static_assert(kMaxServerCommandIdBytes >= sizeof("registry") - 1 + 1 + 32);

/// The command_id shapes the server mints are `<plugin>-<16 or 32 hex>` or 32 hex, the plugin at
/// most 128 bytes of [A-Za-z0-9_.-] (command_routes.cpp bad_ident). This tests charset and length
/// only: the necessary shape of a server-minted id, not proof that one was minted. Anything else
/// came from the agent, not the server.
[[nodiscard]] constexpr bool is_server_minted_command_id(std::string_view id) noexcept {
    return !id.empty() && id.size() <= kMaxServerCommandIdBytes &&
           std::ranges::all_of(id, [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '.' || c == '-';
           });
}

/// `plugin` is the registry plugin, compared ASCII-case-insensitively (command_routes.cpp mints the
/// id from the RAW request spelling; classify is case-insensitive, so `Registry` runs the write on
/// the endpoint).
[[nodiscard]] constexpr bool is_registry_plugin(std::string_view plugin) noexcept {
    constexpr std::string_view kName = "registry";
    return std::ranges::equal(plugin, kName, [](char a, char b) { return (a | 0x20) == b; });
}

/// The `audit|...` lines of one output frame (output lines are LF-separated), bounded and
/// neutralised as described above. `*truncated` (when given) is set when a further `audit|` line
/// was found past kMaxRegistryAuditLinesPerFrame: those lines are dropped, not recorded.
[[nodiscard]] inline std::vector<std::string>
extract_registry_audit_lines(std::string_view output, bool* truncated = nullptr) {
    std::vector<std::string> out;
    for (std::size_t pos = 0; pos < output.size();) {
        const std::size_t nl = std::min(output.find('\n', pos), output.size());
        std::string_view line = output.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.starts_with("audit|"))
            continue;
        if (out.size() == kMaxRegistryAuditLinesPerFrame) {
            if (truncated != nullptr)
                *truncated = true;
            break;
        }
        if (line.size() > kMaxRegistryAuditLineBytes) {
            std::size_t cut = kMaxRegistryAuditLineBytes;
            while (cut > 0 && (static_cast<unsigned char>(line[cut]) & 0xC0) == 0x80)
                --cut;
            line = line.substr(0, cut);
        }
        std::string s{line};
        // Every ASCII control byte (CR, NUL, ESC, BEL ...): the log file is an escape-interpreting
        // sink.
        std::ranges::replace_if(
            s, [](unsigned char c) { return c < 0x20 || c == 0x7F; }, '_');
        out.push_back(std::move(s));
    }
    return out;
}

/// The value of the line's `result=` field ("" when absent). Fields are `|`-separated tokens that
/// the plugin guarantees contain no `|`.
[[nodiscard]] inline std::string_view registry_audit_result(std::string_view line) noexcept {
    constexpr std::string_view kKey = "|result=";
    const std::size_t at = line.find(kKey);
    if (at == std::string_view::npos)
        return {};
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
    // The trusted token goes FIRST: the line is endpoint text, and a ` agent=<other>` inside it
    // must not be what a first-match reader finds (the role.elevation.granted convention).
    ev.detail = "agent=" + yuzu::log_token(agent_id) + " " + std::string{line};
    ev.result = registry_audit_result(line) == "ok" ? "success" : "failure";
    return ev;
}

/// What one output frame owes the audit log, decided without I/O. The caller persists `events` and
/// logs the two flags, so it never re-derives the gate.
struct RegistryAuditFrame {
    std::vector<AuditEvent> events;
    bool truncated{false};     ///< audit| lines past kMaxRegistryAuditLinesPerFrame were dropped
    bool unmintable_id{false}; ///< registry mutating frame, command_id not server-mintable: ignored
};

/// Nothing unless `plugin` is `registry`, `action` is one of the mutating actions and `command_id`
/// has a shape the server could have minted (a registry mutating frame that fails only the last
/// test is flagged `unmintable_id`).
[[nodiscard]] inline RegistryAuditFrame
registry_audit_events_for_frame(std::string_view agent_id, std::string_view command_id,
                                std::string_view plugin, std::string_view action,
                                std::string_view output, std::int64_t now_epoch_s) {
    RegistryAuditFrame frame;
    if (!is_registry_plugin(plugin) || !is_registry_mutating_action(action))
        return frame;
    if (!is_server_minted_command_id(command_id)) {
        frame.unmintable_id = true;
        return frame;
    }
    for (const auto& line : extract_registry_audit_lines(output, &frame.truncated))
        frame.events.push_back(make_registry_audit_event(agent_id, command_id, line, now_epoch_s));
    return frame;
}

} // namespace yuzu::server
