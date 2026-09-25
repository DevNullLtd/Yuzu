#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

#include "stream_budget.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "approval_manager.hpp"
#include "authz_gates.hpp" // yuzu::server::authz::FleetReadGate (#1712 / #3290 Phase 2)
#include "authz_model.hpp" // yuzu::server::authz::VisibleSet (K-R7-02 / #1788)
#include "custom_properties_store.hpp"
#include "dispatch_caller.hpp" // PLAN-006: DispatchCaller — the principal threaded to dispatch_fn
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "policy_store.hpp"
#include "product_pack_store.hpp"
#include "response_store.hpp"
#include "schedule_api.hpp" // ADR-0031 WS-A4 (seventh family): ScheduleApi — replaces a direct ScheduleEngine reach
#include "tag_store.hpp"
#include "workflow_api.hpp" // ADR-0031 WS-A4 (eighth family): WorkflowApi — replaces a direct WorkflowEngine reach for the read triad
#include "workflow_engine.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class CommandCapabilityRegistry;

/// Workflow, product-pack, execution fragment, and scope-estimate routes.
/// Extracted from ServerImpl::start_web_server() for god-object decomposition.
class WorkflowRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req)>;

    /// Callback for scope expression evaluation.
    /// Returns (matched_count, total_agents).
    using ScopeEstimateFn = std::function<std::pair<std::size_t, std::size_t>(
        const std::string& expression, const std::string& principal)>;

    /// Command dispatch callback — sends a command to agents via gRPC.
    /// Returns (command_id, number_of_agents_reached).
    ///
    /// PR 2: optional `execution_id` parameter threads the
    /// command_id→execution_id mapping into the dispatch path so the
    /// mapping is registered with `AgentServiceImpl` BEFORE any RPC is
    /// sent (closes the UP2-4 FAST-agent race where a sub-millisecond
    /// loopback agent could reply before the post-dispatch
    /// register-mapping call). Empty `execution_id` skips registration
    /// (callers that don't track executions, e.g. raw command path).
    ///
    /// K-R7-02 / PLAN-006: the trailing `caller` carries the caller's identity
    /// alongside its Execution:Execute visible set so workflow/instruction
    /// dispatch narrows to it AND records who asked, via the shared
    /// `dispatch_confined` seam, exactly as /api/command and MCP do.
    /// `exec_visible` nullopt == unfiltered (background/system callers only).
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller)>;

    /// ADR-1007 — a DELIBERATE SIBLING of `CommandDispatchFn`, not a widening
    /// of it. `CommandDispatchFn`'s shape is shared verbatim by dashboard,
    /// REST v1, and MCP wiring in server.cpp (all assigned from the SAME
    /// `command_dispatch_caller_fn` lambda) — changing its signature breaks
    /// every one of those assignments for a gate that applies to exactly two
    /// call sites in THIS file. A second, narrowly-scoped type is how the
    /// #881/#1788 "second copy of a chokepoint" hazard is avoided here: this
    /// is not a second copy of the confined-dispatch RULE (both closures
    /// still route through the one `dispatch_confined` seam in server.cpp),
    /// only a second, additive PARAMETER LIST for the two call sites that
    /// have a resolved `InstructionDefinition` (and therefore a
    /// `concurrency_mode`) in hand.
    using ConcurrencyDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller,
        const std::string& definition_id, const std::string& concurrency_mode)>;

    /// K-R7-02 / PLAN-006: resolves the caller's DispatchCaller (identity +
    /// Execution:Execute visible set) from the request. Wired in server.cpp to
    /// a closure that resolves the session and calls `derive_dispatch_caller`;
    /// an UNWIRED callback fails CLOSED on visibility (the handler passes an
    /// empty principal alongside a present-EMPTY set — deny all, never nullopt).
    using CallerFn =
        std::function<yuzu::server::DispatchCaller(const httplib::Request&)>;

    /// #1712 / #3290 Phase 2 — the injected-callback twin of
    /// `AuthRoutes::require_fleet_read`, backing the executions-drawer
    /// detail route's real per-agent/service confinement (same shape as
    /// `McpServer::FleetReadFn`/`RestApiV1::FleetReadFn`/
    /// `DashboardRoutes::FleetReadFn` — server.cpp wires the SAME
    /// conversion lambda into all of them so they cannot drift). MUST be
    /// that route's SOLE authorization gate — never stacked with `perm_fn`
    /// for the same `(securable_type, operation)` (the BLOCKING defect
    /// `require_fleet_read`'s own doc comment warns against). Default-
    /// constructed (empty `Deps` field) ⇒ the route fails CLOSED (503
    /// "unwired"), mirroring the sibling surfaces' identical contract.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// PR 2.5 — deps-struct refactor (#670).
    ///
    /// `register_routes` had grown to 16 arguments across two overloads.
    /// PR 3 adds the SSE event-bus pointer — the trigger to land the
    /// struct refactor BEFORE more callbacks accrete. Callers construct
    /// one `Deps` and both overloads take it by value.
    ///
    /// Field ordering follows the original register_routes parameter
    /// order so the diff at call sites is mechanical. Pointer fields
    /// default to nullptr where the previous overload accepted defaults.
    struct Deps {
        /// THE shared admission budget for held-open responses (ADR-0034). The executions
        /// drawer holds a worker thread for as long as an operator leaves the tab open, so it
        /// leases from the same counter as every other streaming surface. nullptr = no
        /// admission control (test harnesses only).
        yuzu::server::detail::StreamBudget* stream_budget{nullptr};
        AuthFn auth_fn;
        PermFn perm_fn;
        /// #1712 / #3290 Phase 2 — see FleetReadFn's doc comment above.
        /// Used ONLY by the executions-drawer detail route
        /// (/fragments/executions/{id}/detail); every other route in this
        /// file keeps using `perm_fn` above unchanged.
        FleetReadFn fleet_read_fn;
        AuditFn audit_fn;
        EmitEventFn emit_fn;
        ScopeEstimateFn scope_fn;
        /// Kept for the legacy unversioned GET/mutator routes above (`GET
        /// /api/workflows[/{id}]`, `GET /api/workflow-executions/{id}`,
        /// `POST /api/workflows`, `DELETE /api/workflows/{id}`,
        /// `POST /api/workflows/{id}/execute`) and the ProductPackStore
        /// install/uninstall fan-out (`make_item_delete_fn`) — none of these
        /// has a public REST v1/MCP twin of its own, so they are deliberately
        /// OUTSIDE the `WorkflowApi` seam below (mirrors the `schedule`
        /// family's own legacy-mutator carve-out). The three READ routes that
        /// DO have a public twin (`GET /api/v1/workflows[/{id}]`,
        /// `GET /api/v1/workflow-executions/{id}`) route through
        /// `workflow_api` instead, below.
        WorkflowEngine* workflow_engine{nullptr};
        ExecutionTracker* execution_tracker{nullptr};
        /// ADR-0031 WS-A4 (eighth family): the workflow-read seam — replaces
        /// a direct `WorkflowEngine*` reach for `GET /api/v1/workflows`,
        /// `GET /api/v1/workflows/{id}` and `GET /api/v1/workflow-executions/
        /// {id}` (the seamed read triad; the legacy unversioned GET routes
        /// and every mutator above keep their own `WorkflowEngine*` wiring,
        /// unaffected by this seam). Unwired (default-constructed null
        /// `shared_ptr`) ⇒ each of the three v1 routes answers its own
        /// pre-seam "workflow engine not available" 503 exactly, since
        /// `workflow_api` is constructed if-and-only-if `workflow_engine_`
        /// is (server.cpp) — see `workflow_api.hpp`'s own doc comment for
        /// the full carve-out list.
        std::shared_ptr<const WorkflowApi> workflow_api;
        /// ADR-0031 WS-A4 (seventh family): the schedule-read seam — replaces
        /// a direct `ScheduleEngine*` reach for `GET /fragments/schedules` /
        /// `GET /api/v1/schedules` (the seamed read triad; the unversioned
        /// legacy `/api/schedules` mutators in `schedule_routes.cpp` are a
        /// separate, untouched capability and keep their own `ScheduleEngine*`
        /// wiring, unaffected by this seam). Unwired (default-constructed
        /// null `shared_ptr`) ⇒ each route answers its OWN pre-seam
        /// `!schedule_engine` behaviour exactly, and the two differ: the
        /// fragment answers 200 with `<div class="empty-state">Not
        /// available</div>`, while REST v1 answers 503 (adversarial-review-kimi
        /// round: this comment previously said "both routes answer 503",
        /// which was never true of the fragment).
        std::shared_ptr<const ScheduleApi> schedule_api;
        ProductPackStore* product_pack_store{nullptr};
        InstructionStore* instruction_store{nullptr};
        PolicyStore* policy_store{nullptr};
        CommandDispatchFn command_dispatch_fn;
        /// ADR-1007. Default-constructed (empty) ⇒ the two call sites that
        /// use it fall back to `command_dispatch_fn` with no concurrency
        /// gate — same as today, never a hard failure — matching this
        /// codebase's "an unwired optional gate is a no-op, not a 503"
        /// convention for gates that do not universally apply (unlike
        /// `FleetReadFn`'s deliberate fail-closed-on-unwired contract, which
        /// gates a universally-required authorization check).
        ConcurrencyDispatchFn command_dispatch_fn_concurrency;
        /// K-R7-02 / PLAN-006: per-request DispatchCaller derivation for the
        /// execute handlers. nullptr → the handlers fail CLOSED on visibility
        /// (empty principal, present-empty visible set, deny all) rather than
        /// dispatching unfiltered.
        CallerFn caller_fn;
        ApprovalManager* approval_manager{nullptr};
        ResponseStore* response_store{nullptr};
        /// PR 3 — per-execution SSE event bus for `/sse/executions/{id}`.
        /// When non-null, `ExecutionTracker` publishers (update_agent_status,
        /// refresh_counts, mark_cancelled) emit transitions onto this bus
        /// and the SSE handler subscribes per-connection. nullptr leaves
        /// the SSE route unregistered (test harnesses that don't need it).
        class ExecutionEventBus* execution_event_bus{nullptr};
        /// #2500 — counts `yuzu_server_dispatch_target_rejected_total` when a
        /// caller-supplied targeting argument names nothing and the execute
        /// route refuses it. nullptr = no metric (test harnesses that do not
        /// assert on it); the REFUSAL itself never depends on this being wired.
        yuzu::MetricsRegistry* metrics{nullptr};
        /// BR-001 (branch review) — the SAME `CommandCapabilityRegistry` the
        /// other three operator-facing dispatch surfaces (`/api/command`,
        /// MCP `execute_instruction`, the exec console) consult via
        /// `evaluate_destructive_targeting`/`requires_explicit_targets`
        /// (`dispatch_destructive_gate.hpp`) to refuse an untargeted
        /// Destructive dispatch or a non-single-target Forensics read.
        /// `POST /api/instructions/:id/execute` is a FOURTH real
        /// plugin.action dispatch producer that this gate had missed. A
        /// plain, never-conditional `ServerImpl` member in production
        /// (mirrors `command_routes::Deps::capability_registry`) — always
        /// wired there, exactly like that sibling field; a test harness
        /// that leaves this nullptr is asserting an unwired-classifier
        /// configuration never reached in production.
        const yuzu::server::CommandCapabilityRegistry* capability_registry{nullptr};
    };

    /// Production overload — wraps `httplib::Server&` in an HttplibRouteSink
    /// and delegates to the sink-based overload below. New code should keep
    /// using this entrypoint; the sink overload exists for in-process unit
    /// tests that bypass httplib::Server's TSan-hostile acceptor thread (#438).
    void register_routes(httplib::Server& svr, Deps deps);

    /// Sink-based overload — used by tests. See `tests/unit/server/test_route_sink.hpp`.
    void register_routes(class HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
