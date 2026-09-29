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
/// EXTEND this list for the next secret-carrying instruction parameter
/// (`directory_sync.client_secret` is a known pre-existing case with the
/// same exposure, tracked separately as systemic — PR3136 review) — never
/// hand-roll a second per-callsite redaction or rejection.

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

inline constexpr std::string_view kRedactedInstructionParamKeys[] = {"grant_secret", "grant_id"};

[[nodiscard]] inline bool is_redacted_instruction_param_key(std::string_view key) {
    for (auto redacted : kRedactedInstructionParamKeys)
        if (key == redacted)
            return true;
    return false;
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
