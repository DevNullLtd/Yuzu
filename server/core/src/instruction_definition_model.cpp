#include "instruction_definition_model.hpp"

namespace yuzu::server {

nlohmann::json instruction_definition_row_json(const InstructionDefinition& d) {
    nlohmann::json j;
    j["id"] = d.id;
    j["name"] = d.name;
    j["version"] = d.version;
    j["type"] = d.type;
    j["plugin"] = d.plugin;
    j["action"] = d.action;
    j["description"] = d.description;
    j["enabled"] = d.enabled;
    j["instruction_set_id"] = d.instruction_set_id;
    j["created_at"] = d.created_at;
    j["updated_at"] = d.updated_at;
    return j;
}

nlohmann::json instruction_definition_detail_json(const InstructionDefinition& d) {
    nlohmann::json j = instruction_definition_row_json(d);
    j["gather_ttl_seconds"] = d.gather_ttl_seconds;
    j["response_ttl_days"] = d.response_ttl_days;
    j["created_by"] = d.created_by;
    j["approval_mode"] = d.approval_mode;
    j["parameter_schema"] = d.parameter_schema;
    j["result_schema"] = d.result_schema;
    j["yaml_source"] = d.yaml_source;
    return j;
}

nlohmann::json instruction_definition_export_json(const InstructionDefinition& d) {
    nlohmann::json j = instruction_definition_detail_json(d);
    j["concurrency_mode"] = d.concurrency_mode;
    j["platforms"] = d.platforms;
    j["min_agent_version"] = d.min_agent_version;
    j["required_plugins"] = d.required_plugins;
    j["readable_payload"] = d.readable_payload;
    j["visualization_spec"] = d.visualization_spec;
    j["response_templates_spec"] = d.response_templates_spec;
    return j;
}

} // namespace yuzu::server
