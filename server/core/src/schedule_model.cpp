#include "schedule_model.hpp"

namespace yuzu::server {

nlohmann::json schedule_row_json(const InstructionSchedule& s) {
    return nlohmann::json{
        {"id", s.id},
        {"name", s.name},
        {"definition_id", s.definition_id},
        {"frequency_type", s.frequency_type},
        {"enabled", s.enabled},
        {"next_execution_at", s.next_execution_at},
        {"execution_count", s.execution_count},
    };
}

} // namespace yuzu::server
