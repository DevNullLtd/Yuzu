#include "instruction_execute_ports.hpp"

#include "approval_manager.hpp"
#include "command_capability.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"

namespace yuzu::server::instruction_execute {

Ports make_ports(const StoreBindings& b) {
    Ports p;
    if (auto* store = b.instruction_store) {
        p.lookup_definition = [store](const std::string& id) -> DefinitionLookup {
            if (!store->is_open())
                return std::unexpected(std::string("instruction store not open"));
            return store->get_definition(id);
        };
    }
    p.validators = b.validators.get();
    if (auto* reg = b.capability_registry) {
        p.classify = [reg](std::string_view plugin, std::string_view action) {
            return reg->classify(plugin, action);
        };
    }
    p.authorize = b.authorize;
    if (auto* am = b.approval_manager) {
        p.submit_approval = [am](const std::string& definition_id, const std::string& submitted_by,
                                 const std::string& scope_expression, const std::string& plugin,
                                 const std::string& action)
            -> std::expected<std::string, ApprovalSubmitError> {
            // ApprovalOrigin::kInstruction: refused at the MCP recall (origin_redeemable_as), and
            // no interactive redemption exists. plugin/action are snapshotted so a future
            // redemption inherits the definition-mutation protection (#1398 hardening).
            auto r = am->submit_typed(definition_id, submitted_by, scope_expression, "",
                                      ApprovalOrigin::kInstruction, plugin, action);
            if (!r)
                return std::unexpected(ApprovalSubmitError{
                    r.error().kind == SubmitFailure::kQueueFull, std::move(r.error().message)});
            return std::move(*r);
        };
        // nullopt = the count could not be read (the cap then refuses, it never admits).
        p.pending_count_for = [am](const std::string& user) -> std::optional<int> {
            auto n = am->pending_count_for_checked(user);
            if (!n)
                return std::nullopt;
            return *n;
        };
    }
    if (auto* mg = b.mgmt_store) {
        p.visible_agents = [mg](const std::string& user) { return mg->get_visible_agents(user); };
    }
    if (auto* tracker = b.execution_tracker) {
        p.create_execution = [tracker](const ExecutionRow& row) -> std::optional<std::string> {
            Execution exec;
            exec.definition_id = row.definition_id;
            exec.status = "running";
            exec.scope_expression = row.scope_expression;
            exec.parameter_values = row.parameter_values;
            exec.dispatched_by = row.dispatched_by;
            if (auto created = tracker->create_execution(exec); created.has_value())
                return *created;
            return std::nullopt;
        };
        p.mark_cancelled = [tracker](const std::string& id, const std::string& user) {
            return tracker->mark_cancelled(id, user);
        };
        p.set_agents_targeted = [tracker](const std::string& id, int n) {
            return tracker->set_agents_targeted(id, n);
        };
        p.refresh_counts = [tracker](const std::string& id) { tracker->refresh_counts(id); };
    }
    p.dispatch = b.dispatch;
    p.metrics = b.metrics;
    return p;
}

} // namespace yuzu::server::instruction_execute
