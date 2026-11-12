#pragma once

/**
 * @file dex_score_policy_mcp.hpp
 * The pure half of the MCP twins of GET/PUT/DELETE /api/v1/dex/score-policy (#6087):
 * arguments -> DexScorePolicyWriteRequest, write status -> JSON-RPC code, and the success
 * payload. Header-only and free of httplib and store types, so the unit suite feeds it fixture
 * values; the handlers in mcp_tools_dex.cpp are the thin shell around it.
 *
 * Deliberately NOT named mcp_tool*.hpp: the seam-closure lane pins that header family, and this
 * file belongs to the DEX score policy, not to the registry seam.
 *
 * Nothing here validates a policy document, parses an If-Match value or judges a revision:
 * those stay in apply_dex_score_policy (dex_score_policy_writer.hpp), the one write path the
 * REST routes also use. The request builder only checks the SHAPE of the MCP arguments.
 */

#include "dex_score_policy_writer.hpp"
#include "mcp_jsonrpc.hpp" // kInvalidParams, kInternalError

#include <nlohmann/json.hpp>
#include <yuzu/log_token.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Build the writer's request from `tools/call` arguments. Strict: an unknown key, a
/// non-object `document`, a non-string `if_match` (or one longer than the writer's cap) and a
/// non-boolean `dry_run` are refused with a message naming the argument and never echoing a
/// value. `approval_id` is accepted on a reset only (the generic approval gate consumes it
/// before the handler runs); `dry_run` and `document` exist on a put only. An absent `if_match`
/// stays nullopt so apply answers its own 428-class refusal and writes its own denied row. The
/// request's `actor` is left empty: the handler sets it from the resolved caller.
[[nodiscard]] inline std::expected<DexScorePolicyWriteRequest, std::string>
dex_score_policy_mcp_request(DexScorePolicyWriteRequest::Op op, const nlohmann::json& args) {
    using Op = DexScorePolicyWriteRequest::Op;
    DexScorePolicyWriteRequest rq;
    rq.op = op;
    if (!args.is_object())
        return std::unexpected(std::string("arguments must be a JSON object"));
    const bool put = op == Op::Put;
    for (const auto& [key, value] : args.items()) {
        (void)value;
        const bool known = key == "if_match" || (put ? key == "document" || key == "dry_run"
                                                     : key == "approval_id");
        if (!known) {
            // Cap first, neutralise second: log_token turns a multibyte sequence the cap cut
            // into '_' (one per stray byte), so the message stays valid UTF-8; the other way
            // round would cut a passed-through sequence mid-character.
            return std::unexpected("unknown argument '" + ::yuzu::log_token(key.substr(0, 64)) +
                                   "'");
        }
    }
    if (const auto it = args.find("if_match"); it != args.end()) {
        if (!it->is_string())
            return std::unexpected(std::string("if_match must be a string"));
        if (it->get_ref<const std::string&>().size() > kDexScorePolicyIfMatchMaxBytes)
            return std::unexpected("if_match is longer than " +
                                   std::to_string(kDexScorePolicyIfMatchMaxBytes) + " bytes");
        rq.if_match = it->get<std::string>();
    }
    if (!put)
        return rq;
    const auto doc = args.find("document");
    if (doc == args.end() || !doc->is_object())
        return std::unexpected(std::string("document must be a JSON object"));
    rq.body = doc->dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (const auto it = args.find("dry_run"); it != args.end()) {
        if (!it->is_boolean())
            return std::unexpected(std::string("dry_run must be a boolean"));
        rq.dry_run = it->get<bool>() ? "true" : "false";
    }
    return rq;
}

/// JSON-RPC code of a refused or failed write, derived from the writer's own HTTP table
/// (dex_score_policy_http_status) so the classification lives in one place: the 4xx class
/// (428/400/409) is the caller's input (non-retryable -32602); the 5xx class (every 503) is a
/// retryable internal error. Ok has no error code: 0.
[[nodiscard]] constexpr int dex_score_policy_mcp_code(DexScorePolicyWriteStatus s) noexcept {
    return s == DexScorePolicyWriteStatus::Ok
               ? 0
               : (dex_score_policy_http_status(s) >= 500 ? mcp::kInternalError
                                                         : mcp::kInvalidParams);
}

/// A fixed token naming the status, for the generic mcp.<tool> row: never the message (which
/// can carry the stored revision) and never the document.
[[nodiscard]] constexpr std::string_view
dex_score_policy_mcp_status_token(DexScorePolicyWriteStatus s) noexcept {
    switch (s) {
    case DexScorePolicyWriteStatus::Ok:
        return "ok";
    case DexScorePolicyWriteStatus::IfMatchMissing:
        return "if_match_missing";
    case DexScorePolicyWriteStatus::IfMatchMalformed:
        return "if_match_malformed";
    case DexScorePolicyWriteStatus::Stale:
        return "stale";
    case DexScorePolicyWriteStatus::Invalid:
        return "invalid";
    case DexScorePolicyWriteStatus::WriterBusy:
        return "writer_busy";
    case DexScorePolicyWriteStatus::StoreUnavailable:
        return "store_unavailable";
    case DexScorePolicyWriteStatus::OutcomeUnknown:
        return "outcome_unknown";
    case DexScorePolicyWriteStatus::AuditUnavailable:
        return "audit_unavailable";
    }
    return "unknown";
}

/// apply words its If-Match refusals for the REST header ("If-Match header required: ...",
/// "If-Match must not be empty"); over MCP the value is the `if_match` argument. Rewrites that
/// leading phrase to "If-Match (the if_match argument)" and leaves every other message as is.
[[nodiscard]] inline std::string dex_score_policy_mcp_message(std::string_view apply_message) {
    constexpr std::string_view kPrefix = "If-Match";
    constexpr std::string_view kHeader = " header";
    if (!apply_message.starts_with(kPrefix))
        return std::string(apply_message);
    auto rest = apply_message.substr(kPrefix.size());
    if (rest.starts_with(kHeader))
        rest.remove_prefix(kHeader.size());
    return std::string(kPrefix) + " (the if_match argument)" + std::string(rest);
}

/// apply's remediation names the REST read ("GET /api/v1/dex/score-policy ..."); over MCP the
/// same read is get_dex_score_policy. Appends that pointer when the REST wording is present.
[[nodiscard]] inline std::string dex_score_policy_mcp_remediation(std::string_view apply_remediation) {
    std::string out(apply_remediation);
    if (out.find("GET /api/v1/dex/score-policy") != std::string::npos)
        out += " (over MCP: get_dex_score_policy)";
    return out;
}

/// The success payload: the REST 200 body's keys (in_force + previous_revision, `dry_run` when
/// the write was a dry run), plus `audit_persisted:false` ONLY when a row after the change
/// failed to persist. The key is never `true`, matching the other registry write tools.
[[nodiscard]] inline nlohmann::json
dex_score_policy_mcp_success_json(const DexScorePolicyWriteResult& r, bool audit_persisted) {
    auto j = dex_score_policy_in_force_json(r.in_force);
    j["previous_revision"] = r.previous_revision;
    if (r.dry_run)
        j["dry_run"] = true;
    if (!audit_persisted)
        j["audit_persisted"] = false;
    return j;
}

} // namespace yuzu::server
