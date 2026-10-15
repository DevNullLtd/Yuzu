#include "app_usage_read_model.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

using json = nlohmann::json;

std::string app_usage_json(const AppUsageModel& model, bool audit_persisted) {
    json apps = json::array();
    for (const auto& r : model.apps) {
        apps.push_back({{"exe_key", r.exe_key},
                        {"first_seen", r.first_seen},
                        {"last_seen", r.last_seen},
                        {"run_count_30d", r.run_count_30d},
                        {"total_seconds_30d", r.total_seconds_30d}});
    }
    json out{{"agent_id", model.agent_id}, {"collected_at", model.collected_at}};
    out["apps"] = std::move(apps);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

} // namespace yuzu::server
