#include "offload_target_model.hpp"

namespace yuzu::server {

nlohmann::json offload_target_json(const OffloadTarget& t) {
    return nlohmann::json{
        {"id", t.id},
        {"name", t.name},
        {"url", t.url},
        {"auth_type", offload_auth_type_to_string(t.auth_type)},
        {"has_credential", t.has_credential},
        {"event_types", t.event_types},
        {"batch_size", t.batch_size},
        {"enabled", t.enabled},
        {"created_at", t.created_at},
        // auth_credential intentionally omitted from API responses - not
        // even the encrypted blob (ADR-0010).
    };
}

nlohmann::json offload_delivery_json(const OffloadDelivery& d) {
    return nlohmann::json{
        {"id", d.id},
        {"target_id", d.target_id},
        {"event_type", d.event_type},
        {"event_count", d.event_count},
        {"payload", d.payload},
        {"status_code", d.status_code},
        {"delivered_at", d.delivered_at},
        {"error", d.error},
    };
}

} // namespace yuzu::server
