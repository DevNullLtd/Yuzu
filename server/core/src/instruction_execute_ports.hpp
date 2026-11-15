#pragma once

/// @file instruction_execute_ports.hpp
/// Binds `instruction_execute::Ports` (instruction_execute.hpp) to the production stores. Both
/// surfaces (the v1 REST route and the MCP tool) take the same `StoreBindings` from server.cpp,
/// so they cannot disagree about which store a seam reaches. Every pointer is optional and
/// non-owning; a null one leaves its seam unset, which the core reads as "unavailable" and fails
/// closed (it never reads an unset seam as "no check").

#include "dispatch_denial_text.hpp"
#include "instruction_execute.hpp"

#include <functional>
#include <memory>

namespace yuzu::server {
class ApprovalManager;
class CommandCapabilityRegistry;
class ExecutionTracker;
class InstructionStore;
class ManagementGroupStore;
} // namespace yuzu::server

namespace yuzu::server::instruction_execute {

struct StoreBindings {
    InstructionStore* instruction_store{nullptr};
    ExecutionTracker* execution_tracker{nullptr};
    /// null = no approval manager: a non-auto definition answers 503.
    ApprovalManager* approval_manager{nullptr};
    ManagementGroupStore* mgmt_store{nullptr};
    /// The destructive-targeting classifier (`CommandCapabilityRegistry::classify`).
    const CommandCapabilityRegistry* capability_registry{nullptr};
    /// The chokepoint dry run; the SAME closure server.cpp hands RestApiV1 and McpServer.
    std::function<std::expected<CommandCapability, detail::DispatchDenial>(
        const DispatchCaller&, std::string_view, std::string_view)>
        authorize;
    /// Shared with the legacy execute route in production (one compiled-validator cache).
    std::shared_ptr<instr::ParamValidatorCache> validators;
    /// The ADR-1007 sibling closure (`command_dispatch_concurrency_fn` in server.cpp).
    DispatchFn dispatch;
    yuzu::MetricsRegistry* metrics{nullptr};
};

/// Everything except `audit`, which is per request and bound by the surface.
[[nodiscard]] Ports make_ports(const StoreBindings& b);

} // namespace yuzu::server::instruction_execute
