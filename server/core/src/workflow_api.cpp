#include "workflow_api_local.hpp"

#include "workflow_engine.hpp"

namespace yuzu::server {

/// Store-backed `WorkflowApi` implementation — a thin wrap of
/// `WorkflowEngine::list_workflows`/`get_workflow`/`get_execution` (ADR-0031
/// WS-A4, eighth family). Behaviour preserved exactly: every one of these
/// three engine methods already returned a checked `std::expected` to its
/// pre-seam REST v1/MCP callers (unlike the `schedule` family's own
/// pre-seam unchecked `query_schedules()`), so this seam introduces no new
/// honest-empty-vs-failure distinction — it only removes the direct
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

private:
    WorkflowEngine& engine_;
};

std::shared_ptr<WorkflowApi> make_local_workflow_api(WorkflowEngine& engine) {
    return std::make_shared<LocalWorkflowApi>(engine);
}

} // namespace yuzu::server
