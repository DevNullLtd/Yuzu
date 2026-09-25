#pragma once

/// @file test_workflow_api_double.hpp
/// FnWorkflowApi — a test-only `WorkflowApi` adapter backed by plain
/// `std::function`s, mirroring `FnScheduleApi`/`FnVerifyApi`. Lets a route/
/// MCP test inject an ARBITRARY result for any of the three methods —
/// including a store FAILURE (`std::unexpected`) — without standing up a
/// real `WorkflowEngine`/Postgres connection.
///
/// NOT for production use — the production factory is
/// `make_local_workflow_api` (workflow_api_local.hpp).

#include "workflow_api.hpp"

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnWorkflowApi final : public yuzu::server::WorkflowApi {
public:
    using ListFn = std::function<std::expected<std::vector<yuzu::server::Workflow>, std::string>(
        const yuzu::server::WorkflowQuery&)>;
    using GetFn = std::function<std::expected<std::optional<yuzu::server::Workflow>, std::string>(
        const std::string&)>;
    using GetExecutionFn =
        std::function<std::expected<std::optional<yuzu::server::WorkflowExecution>, std::string>(
            const std::string&)>;

    FnWorkflowApi(ListFn list_fn, GetFn get_fn, GetExecutionFn get_execution_fn)
        : list_fn_(std::move(list_fn)), get_fn_(std::move(get_fn)),
          get_execution_fn_(std::move(get_execution_fn)) {}

    [[nodiscard]] std::expected<std::vector<yuzu::server::Workflow>, std::string>
    list_workflows(const yuzu::server::WorkflowQuery& q) const override {
        if (!list_fn_)
            return std::unexpected(std::string{"FnWorkflowApi: list_workflows unwired"});
        return list_fn_(q);
    }

    [[nodiscard]] std::expected<std::optional<yuzu::server::Workflow>, std::string>
    get_workflow(const std::string& id) const override {
        if (!get_fn_)
            return std::unexpected(std::string{"FnWorkflowApi: get_workflow unwired"});
        return get_fn_(id);
    }

    [[nodiscard]] std::expected<std::optional<yuzu::server::WorkflowExecution>, std::string>
    get_workflow_execution(const std::string& id) const override {
        if (!get_execution_fn_)
            return std::unexpected(std::string{"FnWorkflowApi: get_workflow_execution unwired"});
        return get_execution_fn_(id);
    }

private:
    ListFn list_fn_;
    GetFn get_fn_;
    GetExecutionFn get_execution_fn_;
};

} // namespace yuzu::server::test
