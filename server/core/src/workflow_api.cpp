#include "workflow_api_local.hpp"

#include "workflow_engine.hpp"

namespace yuzu::server {

/// Store-backed `WorkflowApi` implementation — a thin wrap of
/// `WorkflowEngine::list_workflows`/`get_workflow`/`get_execution`/
/// `query_executions_page` (ADR-0031 WS-A4, eighth family). Behaviour
/// preserved exactly: every one of these engine methods returns a checked
/// `std::expected` to its REST v1/MCP callers (unlike the `schedule` family's
/// own pre-seam unchecked `query_schedules()`), so this seam introduces no
/// new honest-empty-vs-failure distinction — it only removes the direct
/// presentation → store reach.
class LocalWorkflowApi final : public WorkflowApi {
public:
    explicit LocalWorkflowApi(WorkflowEngine& engine) : engine_(engine) {}

    LocalWorkflowApi(const LocalWorkflowApi&) = delete;
    LocalWorkflowApi& operator=(const LocalWorkflowApi&) = delete;

    [[nodiscard]] std::expected<std::vector<Workflow>, std::string>
    list_workflows(const WorkflowQuery& q) const override {
        return engine_.list_workflows(q);
    }

    [[nodiscard]] std::expected<std::optional<Workflow>, std::string>
    get_workflow(const std::string& id) const override {
        return engine_.get_workflow(id);
    }

    [[nodiscard]] std::expected<std::optional<WorkflowExecution>, std::string>
    get_workflow_execution(const std::string& id) const override {
        return engine_.get_execution(id);
    }

    // The store takes the scope as plain data (no authz dependency), so the set is flattened
    // here; engaged-empty stays engaged-empty (deny-all), never widened to "no filter".
    [[nodiscard]] std::expected<WorkflowExecutionPage, std::string>
    list_workflow_executions(const WorkflowExecutionListQuery& q,
                             const authz::VisibleSet& scope) const override {
        std::optional<std::vector<std::string>> visible;
        if (scope)
            visible.emplace(scope->begin(), scope->end());
        return engine_.query_executions_page(q, visible);
    }

    // A straight forward to the engine; see the interface comment for why this carries no
    // authorization of its own. `engine_` is non-const (execute writes), the API object is
    // shared as `const WorkflowApi`, and the engine serialises its own writes.
    [[nodiscard]] std::expected<std::string, std::string>
    execute_workflow(const std::string& workflow_id, const std::vector<std::string>& agent_ids,
                     StepDispatchFn dispatch_fn, ConditionEvalFn condition_fn) const override {
        return engine_.execute(workflow_id, agent_ids, std::move(dispatch_fn),
                               std::move(condition_fn));
    }

private:
    WorkflowEngine& engine_;
};

std::shared_ptr<WorkflowApi> make_local_workflow_api(WorkflowEngine& engine) {
    return std::make_shared<LocalWorkflowApi>(engine);
}

} // namespace yuzu::server
