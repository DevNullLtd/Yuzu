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
///
/// ACCEPTED DESIGN TRADE-OFFS (recorded, not defects): the marker is UNKEYED, so a low-entropy
/// value (a short `grant_id`, a guessable secret) could be confirmed offline by someone who can
/// read `approvals.scope_expression` (Approval:Read) - `grant_id` is the lookup key of a
/// single-redemption credential and `secret` is a high-entropy bearer value, and a keyed digest
/// would need key custody that survives restarts and replicas for no gain on those values; and
/// the marker of a typed value hashes its JSON text, so the same secret sent as a string and as
/// a number binds two different markers (a recall must repeat the original argument exactly). A
/// `url` string value has only its userinfo (`user:pass@`) replaced by the same kind of marker.
///
/// KEY-SPELLING RESIDUAL (recorded, not a defect today): a key matches only when its bytes equal a
/// listed name exactly, in lower case. `Secret`, `clientSecret`, `client-secret`, `password` and
/// `token` are NOT matched, nor is a key that merely contains a listed name. No shipped
/// approval-gated tool or definition carries a secret under any of those spellings, so nothing
/// shipped leaks, but a custom definition may name a parameter `password` or `token`, and a new
/// secret-carrying parameter or tool argument must be added to the list under the exact name it
/// is sent as (`tests/unit/server/test_sensitive_instruction_params.cpp` pins this rule), and
/// widening the matcher itself (case folding, separators, substrings) is a security decision.

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

#include "sha256_hex.hpp"

#include <nlohmann/json.hpp>

#include <optional>
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

[[nodiscard]] inline bool is_unretained_instruction_param_key(std::string_view key) {
    for (auto unretained : kUnretainedInstructionParamKeys)
        if (key == unretained)
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
            if (it.key() == "url" && it.value().is_string()) {
                // A destination URL may embed credentials (`https://user:pass@host/..`). The
                // userinfo is replaced by a SHA-256 marker (the rest stays readable), so an
                // approvals read never returns it and a recall with different userinfo still
                // mismatches.
                const std::string url = it.value().get<std::string>();
                const auto scheme = url.find("://");
                if (scheme != std::string::npos) {
                    const auto auth_begin = scheme + 3;
                    const auto auth_end = url.find_first_of("/?#", auth_begin);
                    const auto authority = url.substr(
                        auth_begin, auth_end == std::string::npos ? std::string::npos : auth_end - auth_begin);
                    if (const auto at = authority.rfind('@'); at != std::string::npos) {
                        auto h = sha256_hex(std::string("yuzu-ticket-arg-v1\0", 19) + authority.substr(0, at));
                        if (!h)
                            return false;
                        it.value() = url.substr(0, auth_begin) + "<redacted:sha256:" + *h + ">@" +
                                     authority.substr(at + 1) +
                                     (auth_end == std::string::npos ? std::string{} : url.substr(auth_end));
                    }
                }
            } else if (is_redacted_tool_arg_key(it.key())) {
                // The TYPED JSON text, for strings too: the string "5" and the number 5 are
                // different arguments and must bind different markers. `replace` keeps invalid
                // UTF-8 from throwing out of the handler.
                const std::string raw =
                    it.value().dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
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
