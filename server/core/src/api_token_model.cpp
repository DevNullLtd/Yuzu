#include "api_token_model.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

std::string api_token_list_item_json(const ApiToken& t) {
    nlohmann::json item{
        {"token_id", t.token_id},   {"name", t.name},
        {"principal_id", t.principal_id}, {"created_at", t.created_at},
        {"expires_at", t.expires_at}, {"last_used_at", t.last_used_at},
        {"revoked", t.revoked},
    };
    if (!t.scope_service.empty())
        item["scope_service"] = t.scope_service;
    // Echo the MCP tier so an operator can verify what they minted (authdb
    // Q3 / consistency #6 - the field is settable now, so it must be
    // readable back).
    if (!t.mcp_tier.empty())
        item["mcp_tier"] = t.mcp_tier;
    // P2 #11: surface an in-flight rotation so it isn't invisible from this
    // list - omitted entirely for a token that has never participated in one
    // (empty/0 is the store's own "never rotated" sentinel).
    if (!t.rotation_group.empty())
        item["rotation_group"] = t.rotation_group;
    if (!t.supersedes_token_id.empty())
        item["supersedes_token_id"] = t.supersedes_token_id;
    if (t.overlap_expires_at != 0)
        item["overlap_expires_at"] = t.overlap_expires_at;
    if (t.confirmed_at != 0)
        item["confirmed_at"] = t.confirmed_at;
    // error_handler_t::replace: name is operator-authored and could carry
    // invalid UTF-8; dump()'s strict default would throw with no
    // exception_handler wired on either call site (#2970B-class precedent).
    return item.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::string api_token_create_ack_json(const std::string& token, const std::string& name,
                                      const std::string& scope_service, bool audit_ok) {
    nlohmann::json resp{{"token", token}, {"name", name}};
    if (!scope_service.empty())
        resp["scope_service"] = scope_service;
    if (!audit_ok)
        resp["audit_persisted"] = false;
    return resp.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server
