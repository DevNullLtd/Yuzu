#include "execution_statistics_model.hpp"

#include <nlohmann/json.hpp>

#include <format>

namespace yuzu::server {

namespace {

/// JSON-quote a single string value (RFC 8259 escaping) by reusing
/// nlohmann::json's own string serializer -- used ONLY for the string fields
/// below (agent_id/definition_id). See the header's formatting note for why
/// the double fields are hand-formatted with std::format instead of routed
/// through nlohmann::json. error_handler_t::replace (matching
/// bundle_service.cpp/analytics_event_store.cpp/approval_routes.cpp's own
/// string-dump call sites) rather than the strict default: these fields
/// ultimately trace back to store-persisted agent_id/definition_id values,
/// and dump()'s strict default throws on invalid UTF-8 with no
/// exception_handler wired on this route (cpp-expert gov finding).
std::string q(std::string_view s) {
    return nlohmann::json(s).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace

std::string fleet_execution_summary_json(const FleetExecutionSummary& s) {
    return std::format(
        R"({{"total_executions":{},"executions_today":{},"active_agents":{},)"
        R"("overall_success_rate":{:.2f},"avg_duration_seconds":{:.2f}}})",
        s.total_executions, s.executions_today, s.active_agents, s.overall_success_rate,
        s.avg_duration_seconds);
}

std::string fleet_statistics_json(const FleetExecutionSummary& s) {
    return std::format(
        R"({{"executions":{{"total":{},"today":{},"success_rate":{:.2f},)"
        R"("avg_duration_seconds":{:.2f}}},"active_agents":{}}})",
        s.total_executions, s.executions_today, s.overall_success_rate, s.avg_duration_seconds,
        s.active_agents);
}

std::string agent_execution_stats_row_json(const AgentExecutionStats& s) {
    return std::format(
        R"({{"agent_id":{},"total_executions":{},"success_count":{},"failure_count":{},)"
        R"("success_rate":{:.2f},"avg_duration_seconds":{:.2f},"last_execution_at":{}}})",
        q(s.agent_id), s.total_executions, s.success_count, s.failure_count, s.success_rate,
        s.avg_duration_seconds, s.last_execution_at);
}

std::string definition_execution_stats_row_json(const DefinitionExecutionStats& s) {
    return std::format(
        R"({{"definition_id":{},"total_executions":{},"total_agents":{},)"
        R"("success_rate":{:.2f},"avg_duration_seconds":{:.2f}}})",
        q(s.definition_id), s.total_executions, s.total_agents, s.success_rate,
        s.avg_duration_seconds);
}

} // namespace yuzu::server
