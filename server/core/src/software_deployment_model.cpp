#include "software_deployment_model.hpp"

namespace yuzu::server {

nlohmann::json software_deployment_row_json(const SoftwareDeployment& d) {
    return nlohmann::json{
        {"id", d.id},
        {"package_id", d.package_id},
        {"status", d.status},
        {"created_by", d.created_by},
        {"created_at", d.created_at},
        {"started_at", d.started_at},
        {"completed_at", d.completed_at},
        {"agents_targeted", d.agents_targeted},
        {"agents_success", d.agents_success},
        {"agents_failure", d.agents_failure},
    };
}

} // namespace yuzu::server
