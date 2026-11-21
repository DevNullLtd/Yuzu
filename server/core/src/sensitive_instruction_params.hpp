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
/// A SECOND list, `kUnretainedInstructionParamKeys`, holds parameters that are NOT secrets but are
/// never kept: an agent-issued resume token (`cursor`, the continuation parameter the capability
/// catalogue declares) is meaningful only to the dispatch it continues, so a stored copy of a
/// request carries no use and only widens what a reader of the history can see. They are erased
/// from the execution record (every create-before-dispatch site calls the redactor below) and
/// refused in a schedule exactly like the secrets above; for an `execute_instruction` call the
/// approval's bound subject leaves them out too (`approval_continuation.hpp`, `ticket_subject`).
/// They are deliberately NOT in `kRedactedInstructionParamKeys`: that list is the SECRET
/// classification, and four other consumers read it (the Console mask `YUZU_OX_SECRET_PARAMS`, the
/// `secret_params` hint in `instruction_definition_model.cpp`, the sensitive flag in
/// `hardware_action_form.hpp`, and the wording of the schedule refusal). A resume token must not
/// make a form mask its field or a definition advertise a secret. Every `continuation_param` the
/// catalogue declares MUST be listed here (`test_capability_catalogue.cpp` pins it). A name on this
/// second list is reserved for every plugin: it is keyed by bare parameter name, so any instruction
/// parameter with that name is erased from the execution record and refused in a schedule,
/// whichever plugin declares it.
///
/// What still holds a token: a cursor placed in a bundle step or a definition run stays in that
/// approval's recorded arguments, and the cursor each slice issues is stored as its `cursor` result
/// row in the Forensics tier. The agent seals the token, so no stored copy of it shows a name the
/// search found.

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

inline constexpr std::string_view kRedactedInstructionParamKeys[] = {"grant_secret", "grant_id",
                                                                     "client_secret"};

/// Parameters that are never retained and are not secrets (see the file header). The agent's resume
/// token: the server dispatches it to the agent unchanged and erases it from the execution record
/// in the redactor below; the file header says what still holds it.
inline constexpr std::string_view kUnretainedInstructionParamKeys[] = {"cursor"};

[[nodiscard]] inline bool is_redacted_instruction_param_key(std::string_view key) {
    for (auto redacted : kRedactedInstructionParamKeys)
        if (key == redacted)
            return true;
    return false;
}

[[nodiscard]] inline bool is_unretained_instruction_param_key(std::string_view key) {
    for (auto unretained : kUnretainedInstructionParamKeys)
        if (key == unretained)
            return true;
    return false;
}

/// Strip every redacted key AND every unretained key from a copy of `params`. Call this ONLY at a
/// PERSISTENCE site (an executions/audit row) — never before building the
/// in-memory CommandRequest, which still needs the raw value.
[[nodiscard]] inline std::unordered_map<std::string, std::string>
redact_sensitive_instruction_params(std::unordered_map<std::string, std::string> params) {
    for (auto redacted : kRedactedInstructionParamKeys)
        params.erase(std::string(redacted));
    for (auto unretained : kUnretainedInstructionParamKeys)
        params.erase(std::string(unretained));
    return params;
}

namespace detail {
/// The one parse loop behind both schedule predicates: true if a canonical (already-validated,
/// object-shaped) schedule parameters JSON string has a key `is_listed` accepts. Malformed or
/// non-object input is false: a separate validator's job to reject.
template <typename KeyPredicate>
[[nodiscard]] bool schedule_params_have_key(std::string_view canonical_json,
                                            KeyPredicate is_listed) {
    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(canonical_json);
    } catch (const nlohmann::json::exception&) {
        return false; // malformed input is a separate validator's job to reject
    }
    if (!parsed.is_object())
        return false;
    for (const auto& [key, value] : parsed.items())
        if (is_listed(key))
            return true;
    return false;
}
} // namespace detail

/// True if a canonical (already-validated, object-shaped) schedule
/// parameters JSON string carries a redacted key. Used to REFUSE schedule
/// creation outright rather than silently storing a value the schedule can
/// never safely re-dispatch.
[[nodiscard]] inline bool schedule_params_contain_sensitive_key(std::string_view canonical_json) {
    return detail::schedule_params_have_key(canonical_json, is_redacted_instruction_param_key);
}

/// The same refusal for an unretained key (a resume token): a schedule's stored blob is what fires,
/// so it cannot be redacted, and a token is meaningless outside the dispatch that issued it.
[[nodiscard]] inline bool schedule_params_contain_unretained_key(std::string_view canonical_json) {
    return detail::schedule_params_have_key(canonical_json, is_unretained_instruction_param_key);
}

}  // namespace yuzu::server
