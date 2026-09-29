#include "result_set_model.hpp"

namespace yuzu::server {

nlohmann::json result_set_json(const ResultSet& r) {
    return {
        {"id", r.id},
        {"name", r.name},
        {"owner_principal", r.owner_principal},
        {"created_at", r.created_at},
        {"ttl_at", r.ttl_at},
        {"last_used_at", r.last_used_at},
        {"pinned", r.pinned},
        {"parent_id", r.parent_id.value_or("")},
        {"source_kind", r.source_kind},
        {"status", to_string(r.status)},
        {"source_execution_id", r.source_execution_id},
        {"device_count", r.device_count},
    };
}

} // namespace yuzu::server
