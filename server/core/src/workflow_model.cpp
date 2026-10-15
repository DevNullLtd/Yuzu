#include "workflow_model.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard

namespace yuzu::server {

namespace {

nlohmann::json workflow_step_json(const WorkflowStep& s) {
    return nlohmann::json{
        {"index", s.index},
        {"instruction_id", s.instruction_id},
        {"condition", s.condition},
        {"retry_count", s.retry_count},
        {"retry_delay_seconds", s.retry_delay_seconds},
        {"foreach", s.foreach_source},
        {"label", s.label},
        {"on_failure", s.on_failure},
    };
}

} // namespace

nlohmann::json workflow_row_json(const Workflow& w) {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& s : w.steps)
        steps.push_back(workflow_step_json(s));
    return nlohmann::json{
        {"id", w.id},
        {"name", w.name},
        {"description", w.description},
        {"steps", steps},
        {"step_count", static_cast<int64_t>(w.steps.size())},
        {"created_at", w.created_at},
        {"updated_at", w.updated_at},
    };
}

nlohmann::json workflow_detail_json(const Workflow& w) {
    auto j = workflow_row_json(w);
    j["yaml_source"] = w.yaml_source;
    return j;
}

bool workflow_execution_visible(const WorkflowExecution& we, const authz::VisibleSet& scope) {
    if (!scope)
        return true;
    auto parsed = nlohmann::json::parse(we.agent_ids_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array())
        return false; // malformed/absent agent_ids -- fail closed, never open.
    // Full scan, no early exit -- see header doc comment (mirrors
    // execution_scope_rules.hpp's execution_visible() anti-timing-oracle
    // rationale).
    bool visible = false;
    for (const auto& a : parsed) {
        if (!a.is_string())
            continue;
        visible = authz::in_scope(scope, a.get_ref<const std::string&>()) || visible;
    }
    return visible;
}

nlohmann::json confined_workflow_agent_ids_json(const std::string& agent_ids_json,
                                                const authz::VisibleSet& scope) {
    // agent_ids_json is a stored JSON-text column; parse permissively
    // (malformed/legacy rows must not fail the whole response).
    auto parsed_agent_ids = nlohmann::json::parse(agent_ids_json, nullptr, false);
    nlohmann::json agent_ids = nlohmann::json::array();
    if (!parsed_agent_ids.is_discarded() && parsed_agent_ids.is_array()) {
        for (const auto& a : parsed_agent_ids) {
            if (!a.is_string())
                continue;
            const auto& id = a.get_ref<const std::string&>();
            if (!authz::in_scope(scope, id))
                continue;
            agent_ids.push_back(id);
        }
    }
    return agent_ids;
}

namespace {

// The raw fleet-wide dispatch count for a step's FULL target-agent list
// (`workflow_routes.cpp`'s `dispatch_fn`: `{"agents_reached", sent}`) --
// never the confined caller's visible subset. Strip it for a confined
// caller rather than attempt an honest per-viewer recompute: nothing else
// in `result_json` carries a per-agent breakdown to recompute FROM (see
// `workflow_engine.cpp`'s step-dispatch loop), so omission is the only
// non-disclosing option, matching `last_error_detail.clear()`'s approach
// for the sibling `Execution` confined projection.
void strip_agents_reached(nlohmann::json& j) {
    if (j.is_object())
        j.erase("agents_reached");
}

} // namespace

nlohmann::json confined_workflow_step_result_json(const std::string& result_json, bool confined) {
    // #2437-class guard: check nesting on the RAW stored text BEFORE parse.
    // WorkflowEngine's own dispatch-result write path (workflow_engine.cpp)
    // guards against a poisoned result reaching this column, but that
    // write-side guard cannot heal a row already stored before it shipped,
    // or one written by direct DB manipulation - this read path stays
    // reachable against such a row, and every OTHER stored-data read path in
    // this fix (Guardian dashboard, result-set re-eval, inventory reads,
    // discovery catalogs) got the same treatment for the same reason.
    if (mcp::json_exceeds_depth(result_json, mcp::kMcpMaxJsonDepth))
        return nlohmann::json{{"error", "stored result exceeded maximum JSON nesting depth"}};
    auto result = nlohmann::json::parse(result_json, nullptr, false);
    if (result.is_discarded())
        return nullptr;
    if (confined) {
        if (result.is_array()) {
            for (auto& elem : result)
                strip_agents_reached(elem);
        } else {
            strip_agents_reached(result);
        }
    }
    return result;
}

nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope) {
    nlohmann::json agent_ids = confined_workflow_agent_ids_json(we.agent_ids_json, scope);

    nlohmann::json steps = nlohmann::json::array();
    for (const auto& sr : we.step_results) {
        steps.push_back(nlohmann::json{
            {"step_index", sr.step_index},
            {"instruction_id", sr.instruction_id},
            {"status", sr.status},
            {"result", confined_workflow_step_result_json(sr.result_json,
                                                           static_cast<bool>(scope))},
            {"started_at", sr.started_at},
            {"completed_at", sr.completed_at},
            {"attempt", sr.attempt},
        });
    }

    return nlohmann::json{
        {"id", we.id},
        {"workflow_id", we.workflow_id},
        {"status", we.status},
        {"agent_ids", agent_ids},
        {"current_step", we.current_step},
        {"started_at", we.started_at},
        {"completed_at", we.completed_at},
        {"steps", steps},
    };
}

} // namespace yuzu::server
