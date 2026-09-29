#include "product_pack_model.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

nlohmann::json product_pack_row_json(const ProductPack& p) {
    nlohmann::json items = nlohmann::json::array();
    for (const auto& item : p.items) {
        items.push_back(
            {{"kind", item.kind}, {"item_id", item.item_id}, {"name", item.name}});
    }
    nlohmann::json j;
    j["id"] = p.id;
    j["name"] = p.name;
    j["version"] = p.version;
    j["description"] = p.description;
    j["item_count"] = p.items.size();
    j["items"] = std::move(items);
    j["installed_at"] = p.installed_at;
    j["verified"] = p.verified;
    return j;
}

nlohmann::json product_pack_detail_json(const ProductPack& p) {
    nlohmann::json items = nlohmann::json::array();
    for (const auto& item : p.items) {
        items.push_back({{"kind", item.kind},
                         {"item_id", item.item_id},
                         {"name", item.name},
                         {"yaml_source", item.yaml_source}});
    }
    nlohmann::json j;
    j["id"] = p.id;
    j["name"] = p.name;
    j["version"] = p.version;
    j["description"] = p.description;
    j["yaml_source"] = p.yaml_source;
    j["items"] = std::move(items);
    j["installed_at"] = p.installed_at;
    j["verified"] = p.verified;
    return j;
}

// Mirrors rest_api_v1.cpp's license_error_status/sw_deploy_error_status shape
// (see the original workflow_routes.cpp comment this was hoisted from):
// ProductPackStore's list()/get() are std::expected, and uninstall() returns a
// machine-checkable "not_found: " prefix — this classifier keeps every REST
// surface's status codes correct instead of collapsing every failure to a
// blanket 400/503. kProductPackDbErrorPrefix (a genuine DB/lease failure) ->
// 503; "not_found:" -> 404; anything else (signature rejection, validation,
// business-rule error) -> 400.
int product_pack_error_status(const std::string& err) {
    if (err.starts_with("not_found:"))
        return 404;
    if (err.starts_with(yuzu::server::kProductPackDbErrorPrefix))
        return 503;
    return 400;
}

// Mirrors rest_api_v1.cpp's sw_deploy_client_message/device_token_client_message:
// a kProductPackDbErrorPrefix error carries a raw PQerrorMessage() fragment
// (connection string detail, occasionally host:port) that is internal
// implementation detail, not caller-actionable feedback. Logs the real error
// server-side and returns a generic constant instead. A not_found/validation
// error (never carries the prefix) is safe to echo verbatim — it's
// operator-authored request feedback, not database internals.
std::string product_pack_client_message(const char* op, const std::string& err) {
    if (err.starts_with(yuzu::server::kProductPackDbErrorPrefix)) {
        spdlog::error("{}: {}", op, err);
        return "service unavailable";
    }
    return err;
}

} // namespace yuzu::server
