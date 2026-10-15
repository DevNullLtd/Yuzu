#include "response_query_model.hpp"

#include "data_export.hpp"

namespace yuzu::server {

nlohmann::json response_query_row_json(const StoredResponse& r) {
    return nlohmann::json{
        {"id", r.id},
        {"instruction_id", r.instruction_id},
        {"agent_id", r.agent_id},
        {"execution_id", r.execution_id},
        {"status", r.status},
        {"output", r.output},
        {"error_detail", r.error_detail},
        {"timestamp", r.timestamp},
        {"plugin", r.plugin},
        {"received_at_ms", r.received_at_ms},
    };
}

nlohmann::json response_aggregate_row_json(const AggregationResult& r) {
    return nlohmann::json{
        {"group_value", r.group_value},
        {"count", r.count},
        {"aggregate_value", r.aggregate_value},
    };
}

std::string response_export_csv_row(const StoredResponse& r) {
    std::string row;
    row += std::to_string(r.id) + ",";
    row += data_export::csv_escape(r.instruction_id) + ",";
    row += data_export::csv_escape(r.agent_id) + ",";
    row += data_export::csv_escape(r.execution_id) + ",";
    row += std::to_string(r.status) + ",";
    row += data_export::csv_escape(r.output) + ",";
    row += data_export::csv_escape(r.error_detail) + ",";
    row += std::to_string(r.timestamp) + ",";
    row += data_export::csv_escape(r.plugin) + ",";
    row += std::to_string(r.received_at_ms) + "\r\n";
    return row;
}

} // namespace yuzu::server
