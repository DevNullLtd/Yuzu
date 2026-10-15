#include "execution_model.hpp"

#include <algorithm>
#include <cmath>

namespace yuzu::server {

nlohmann::json execution_list_row_json(const ExecutionListRow& row) {
    return nlohmann::json{
        {"id", row.id},
        {"definition_id", row.definition_id},
        {"definition_name", row.definition_name},
        {"status", row.status},
        {"dispatched_by", row.dispatched_by},
        {"dispatched_at", row.dispatched_at},
        {"agents_targeted", row.agents_targeted},
        {"agents_responded", row.agents_responded},
        {"agents_success", row.agents_success},
        {"agents_failure", row.agents_failure},
        {"completed_at", row.completed_at},
        {"rerun_of", row.rerun_of},
        {"error_preview", row.error_preview},
    };
}

nlohmann::json execution_agent_status_json(const AgentExecStatus& a) {
    return nlohmann::json{
        {"agent_id", a.agent_id},
        {"status", a.status},
        {"dispatched_at", a.dispatched_at},
        {"first_response_at", a.first_response_at},
        {"completed_at", a.completed_at},
        {"exit_code", a.exit_code},
        {"error_detail", a.error_detail},
    };
}

namespace {

// Matches execution_scope_rules.hpp::confined_projection's definition of
// "responded" — running must never count as terminal.
bool is_terminal_status(const std::string& status) {
    return status == "success" || status == "failure" || status == "timeout" ||
           status == "rejected";
}

} // namespace

ExecutionKpi compute_execution_kpi(const std::vector<AgentExecStatus>& agents) {
    ExecutionKpi k;
    std::vector<double> durations_ms;
    durations_ms.reserve(agents.size());
    for (const auto& a : agents) {
        if (!is_terminal_status(a.status))
            continue;
        ++k.total;
        if (a.status == "success")
            ++k.succeeded;
        else
            ++k.failed;
        if (a.completed_at > 0 && a.dispatched_at > 0 && a.completed_at >= a.dispatched_at) {
            durations_ms.push_back(static_cast<double>(a.completed_at - a.dispatched_at) *
                                   1000.0);
        }
    }
    if (!durations_ms.empty()) {
        std::sort(durations_ms.begin(), durations_ms.end());
        k.has_duration_data = true;
        auto percentile = [&](double p) {
            const double idx = p * static_cast<double>(durations_ms.size() - 1);
            const auto lo = static_cast<size_t>(std::floor(idx));
            const auto hi = static_cast<size_t>(std::ceil(idx));
            if (lo == hi)
                return durations_ms[lo];
            const double frac = idx - static_cast<double>(lo);
            return durations_ms[lo] + (durations_ms[hi] - durations_ms[lo]) * frac;
        };
        k.p50_ms = percentile(0.50);
        k.p95_ms = percentile(0.95);
    }
    return k;
}

nlohmann::json execution_kpi_json(const ExecutionKpi& k) {
    nlohmann::json j{
        {"total", k.total},
        {"succeeded", k.succeeded},
        {"failed", k.failed},
    };
    if (k.has_duration_data) {
        j["p50_ms"] = k.p50_ms;
        j["p95_ms"] = k.p95_ms;
    } else {
        j["p50_ms"] = nullptr;
        j["p95_ms"] = nullptr;
    }
    return j;
}

nlohmann::json execution_child_row_json(const Execution& c) {
    return nlohmann::json{
        {"id", c.id},
        {"status", c.status},
        {"dispatched_at", c.dispatched_at},
    };
}

nlohmann::json execution_response_row_json(const StoredResponse& r) {
    return nlohmann::json{
        {"agent_id", r.agent_id},
        {"execution_id", r.execution_id},
        {"status", r.status},
        {"output", r.output},
        {"timestamp", r.timestamp},
    };
}

} // namespace yuzu::server
