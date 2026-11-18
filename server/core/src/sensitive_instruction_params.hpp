#pragma once

/// @file sensitive_instruction_params.hpp
/// PR3136 review remediation (blocker): a small, explicit list of instruction
/// parameter KEYS that must never reach a persisted parameter_values column.
/// `grant_secret` is content_dist.upload_file's one-time upload-grant
/// secret — docs/adr/3004-artifact-blob-storage.md's "Credential shape and
/// verification" section promises it never appears in a log line, an audit
/// `detail` field, or a second database column beyond the store's own
/// sha256(secret). `grant_id` is redacted alongside it, defense-in-depth, as
/// the lookup key for that secret's own store row.
///
/// Two consumers, by dispatch shape:
///   - One-shot dispatch paths (workflow_routes.cpp, mcp_server.cpp,
///     rest_api_v1.cpp's result-set producer) build a request-scoped params
///     map, dispatch with it immediately, then persist a COPY for
///     audit/history only — `redact_sensitive_instruction_params` strips the
///     persisted copy while the live dispatch still uses the raw map.
///   - Schedules (schedule_engine.cpp) have no such split: the PERSISTED
///     blob is the only record `ScheduleRunner::dispatch_tracked` reads back
///     to fire a FUTURE dispatch, so redacting it would silently break
///     re-dispatch instead of merely protecting a history row.
///     `schedule_params_contain_sensitive_key` is used instead to REFUSE
///     persisting a schedule at all when it carries one of these keys — a
///     single-redemption, ~15-minute-TTL credential cannot survive as a
///     repeatable schedule regardless of this leak, so refusal is the
///     correct fix on both functional and security grounds, not merely the
///     safer one.
///
/// `client_secret` is the shipped `server.directory.sync_entra` definition's
/// Entra app-registration secret (content/definitions/directory_sync.yaml),
/// a long-lived credential: it is stripped from every persisted copy, refused
/// in a schedule, and masked by the Console, like the grant keys.
///
/// EXTEND this list for the next secret-carrying instruction parameter
/// — never hand-roll a second per-callsite redaction or rejection.
///
/// WP06 F12: the MCP approval ticket's bound subject (`approvals.scope_expression`,
/// a plain TEXT column returned by every approvals read) used to be the raw
/// tool arguments. `redact_tool_args_for_ticket` below is the ONE function that
/// turns tool arguments into that subject's persisted form: every secret-bearing
/// key at ANY depth (the keys above plus `kRedactedToolArgKeys`) is replaced by
/// an unkeyed, domain-separated SHA-256 marker. A changed secret still changes
/// the marker (so a recall with different arguments mismatches), and the same
/// secret recalls exactly, with no key custody (stable across restarts and
/// replicas, ADR-0010 posture: never a plain secret column). Fails CLOSED
/// (nullopt) on over-depth or a digest failure: the caller refuses the mint.

#include "sha256_hex.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

inline constexpr std::string_view kRedactedInstructionParamKeys[] = {"grant_secret", "grant_id",
                                                                     "client_secret"};

[[nodiscard]] inline bool is_redacted_instruction_param_key(std::string_view key) {
    for (auto redacted : kRedactedInstructionParamKeys)
        if (key == redacted)
            return true;
    return false;
}

/// Tool-argument keys redacted in an approval ticket subject beyond the
/// instruction-param keys above: `secret` is `confirm_engine_rotation` /
/// `confirm_api_token_rotation`'s raw successor bearer credential.
inline constexpr std::string_view kRedactedToolArgKeys[] = {"secret"};

[[nodiscard]] inline bool is_redacted_tool_arg_key(std::string_view key) {
    if (is_redacted_instruction_param_key(key))
        return true;
    for (auto redacted : kRedactedToolArgKeys)
        if (key == redacted)
            return true;
    return false;
}

inline constexpr int kTicketRedactMaxDepth = 64;

namespace detail {
[[nodiscard]] inline bool ticket_depth_exceeded_impl(const nlohmann::json& node, int depth) {
    if (depth > kTicketRedactMaxDepth)
        return true;
    if (node.is_object()) {
        for (auto it = node.begin(); it != node.end(); ++it)
            if (ticket_depth_exceeded_impl(it.value(), depth + 1))
                return true;
    } else if (node.is_array()) {
        for (const auto& el : node)
            if (ticket_depth_exceeded_impl(el, depth + 1))
                return true;
    }
    return false;
}
[[nodiscard]] inline bool ticket_depth_exceeded(const nlohmann::json& node) {
    return ticket_depth_exceeded_impl(node, 0);
}
[[nodiscard]] inline bool redact_ticket_node(nlohmann::json& node, int depth) {
    if (depth > kTicketRedactMaxDepth)
        return false;
    if (node.is_object()) {
        for (auto it = node.begin(); it != node.end(); ++it) {
            if (is_redacted_tool_arg_key(it.key())) {
                const std::string raw =
                    it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
                auto h = sha256_hex(std::string("yuzu-ticket-arg-v1\0", 19) + raw);
                if (!h)
                    return false;
                it.value() = "<redacted:sha256:" + *h + ">";
            } else if (!redact_ticket_node(it.value(), depth + 1)) {
                return false;
            }
        }
    } else if (node.is_array()) {
        for (auto& el : node)
            if (!redact_ticket_node(el, depth + 1))
                return false;
    }
    return true;
}
} // namespace detail

/// The persisted/bound form of MCP tool arguments for an approval ticket
/// subject. nullopt = could not be computed (over-depth or digest failure): refuse the
/// mint, never fall back to the raw arguments. `*over_depth` (optional) is set when the cause is
/// the caller's nesting (a request fault, not retryable) rather than a digest fault.
///
/// SCOPE OF THE REDACTION: keys are matched in the JSON structure. A secret embedded as text
/// INSIDE a string value (a JSON or YAML document passed as one string argument) is NOT parsed:
/// no approval-gated MCP tool takes such an argument that carries a credential today (the
/// string-typed document arguments are `yaml_source`/`features_json`-style definitions, which hold
/// no secret keys), and a NEW tool that does must pass the credential as its own key. This is a
/// documented residual, pinned by tests/unit/server/test_sensitive_instruction_params.cpp.
[[nodiscard]] inline std::optional<nlohmann::json> redact_tool_args_for_ticket(nlohmann::json args,
                                                                               bool* over_depth = nullptr) {
    if (over_depth)
        *over_depth = false;
    if (!detail::redact_ticket_node(args, 0)) {
        if (over_depth)
            *over_depth = detail::ticket_depth_exceeded(args);
        return std::nullopt;
    }
    return args;
}

/// Strip every redacted key from a copy of `params`. Call this ONLY at a
/// PERSISTENCE site (an executions/audit row) — never before building the
/// in-memory CommandRequest, which still needs the raw value.
[[nodiscard]] inline std::unordered_map<std::string, std::string>
redact_sensitive_instruction_params(std::unordered_map<std::string, std::string> params) {
    for (auto redacted : kRedactedInstructionParamKeys)
        params.erase(std::string(redacted));
    return params;
}

/// True if a canonical (already-validated, object-shaped) schedule
/// parameters JSON string carries a redacted key. Used to REFUSE schedule
/// creation outright rather than silently storing a value the schedule can
/// never safely re-dispatch.
[[nodiscard]] inline bool schedule_params_contain_sensitive_key(std::string_view canonical_json) {
    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(canonical_json);
    } catch (const nlohmann::json::exception&) {
        return false; // malformed input is a separate validator's job to reject
    }
    if (!parsed.is_object())
        return false;
    for (const auto& [key, value] : parsed.items())
        if (is_redacted_instruction_param_key(key))
            return true;
    return false;
}

}  // namespace yuzu::server
