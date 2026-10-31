#pragma once

/// @file instruction_execute.hpp
/// The ONE copy of "execute a stored instruction DEFINITION" for the v1 REST twin
/// (`POST /api/v1/instructions/{id}/execute`, instruction_execute_routes.cpp) and the MCP
/// twin (`execute_instruction_definition`, mcp_instruction_execute.cpp). Ledger row
/// `post.api-instructions-param-execute` (#2146, ADR-1005 Decision 4).
///
/// WHY A SHARED CORE. The two surfaces differ only in transport (an A4 REST envelope versus a
/// JSON-RPC result), in how they authenticate and in the audit action they write. Everything
/// that decides WHO IS REACHED, WHAT RUNS and WHETHER A HUMAN MUST FIRST APPROVE is below, once.
/// A second copy is how the identical defect survives on one surface after the other is fixed
/// (the lesson dispatch_destructive_gate.hpp records for #3685).
///
/// This does NOT replace the legacy `POST /api/instructions/{id}/execute` handler in
/// workflow_routes.cpp, which keeps its own hand-written pipeline on purpose (the five
/// zero-reach cascades are likewise left alone, see dispatch_zero_reach.hpp).
///
/// PIPELINE, in order. Every deterministic refusal happens BEFORE the one step that creates a
/// human-visible ticket, so a refused call never queues an approval, mints a tier ticket or
/// creates an execution row:
///   1. definition lookup            store fault -> StoreUnavailable, absent -> NotFound
///   2. dispatch authorization       the shared chokepoint's dry run for (def.plugin, def.action)
///                                   (classify + RBAC + approval gate + kill switch) -> DispatchDenied
///   3. body shape                   a JSON object; `check_targeting_shape` on the PARSED body
///   4. stored parameter_schema      fail CLOSED on an unpreparable schema; reject a violation
///   5. destructive targeting        `evaluate_destructive_targeting` + `confine_destructive_targets`
///   6. the definition's approval_mode (NOT the tier ladder): see below
///   7. audit `requested`, FAIL CLOSED   -> nothing is dispatched without durable evidence
///   8. execution row (with `definition_id`), then ONE confined dispatch carrying
///      `def.id`/`def.concurrency_mode` (the ADR-1007 per-device claim is taken, and released for
///      every undelivered target, inside `wire_and_dispatch_confined`)
///   9. zero-reach -> `classify_zero_reach`; success -> targeted count + counters refresh
///
/// APPROVAL COMPOSITION (owner ruling, 2026-10-30; the binding security rule). The definition's
/// own `approval_mode` is evaluated FIRST and INDEPENDENTLY of any MCP tier mechanism. An
/// operator-tier token's auto-approval and a supervised-tier ticket that C8 consumed are TIER
/// facts about the caller; neither is an input to this module, and `Request` deliberately has no
/// field through which one could arrive. `auto` dispatches; `always` and any unknown value
/// (fail closed) need approval; `role-gated` needs approval unless the caller is an effective
/// administrator (`DispatchCaller::principal_is_admin`, JIT-elevation aware). A call that needs
/// approval is answered `PendingApproval` and dispatches NOTHING. There is no redemption path
/// for such a ticket: it is minted with `ApprovalOrigin::kInstruction`, which the MCP recall
/// refuses (`origin_redeemable_as`), and no interactive redemption exists. An administrator
/// still reaches `role-gated` definitions because the token or session carries the creator's
/// role: that is a ROLE fact, not a tier fact.
///
/// DispatchCaller CONSTRUCTION. This module never builds a `DispatchCaller`: the surface hands
/// one in, derived from its own session (REST: `caller_from_session`; MCP: `caller_fn`). The only
/// field it reads that carries approval authority is `principal_is_admin`, and it never writes
/// `approval_provenance`; NO adapter stamps `Ticket` for this capability, REST or MCP (sec-F1:
/// a tier ticket binds arguments, not the stored definition's plugin/action, so it must never
/// lift the pair's ExecuteGate; dispatch_caller.hpp, stamping site 2 excludes this tool).
///
/// Everything impure arrives through `Ports` so the pipeline is testable without Postgres
/// (InstructionStore, ApprovalManager and ExecutionTracker are all Postgres-backed).

#include "agent_registry.hpp"            // detail::DispatchDenial
#include "command_capability.hpp"        // CommandCapability / ClassificationError
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp"    // ConfinedDispatchOutcome
#include "dispatch_zero_reach.hpp"       // ZeroReachCause
#include "instruction_param_schema.hpp"  // instr::ParamValidatorCache
#include "instruction_store.hpp"         // InstructionDefinition

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::instruction_execute {

enum class Surface : std::uint8_t { kRest, kMcp };

/// `route` label of `yuzu_server_dispatch_target_rejected_total` and
/// `yuzu_server_instruction_param_rejected_total` for a surface. Both are pre-seeded in
/// server.cpp / seed_instruction_param_rejected_metrics. REST shares the legacy route's label
/// because it is the same capability; MCP shares `execute_instruction`'s `mcp` label.
[[nodiscard]] constexpr std::string_view route_label(Surface s) noexcept {
    return s == Surface::kRest ? "instruction_execute" : "mcp";
}

/// `surface` label of `yuzu_exec_tracker_bookkeeping_failed_total` (pre-seeded: rest, mcp).
[[nodiscard]] constexpr std::string_view bookkeeping_label(Surface s) noexcept {
    return s == Surface::kRest ? "rest" : "mcp";
}

/// What the surface asks for. `body` is the request JSON: REST its parsed body, MCP its
/// `arguments` object minus control-plane keys. Keys read: `agent_ids`, `scope`, `params`.
struct Request {
    Surface surface{Surface::kRest};
    std::string definition_id;
    nlohmann::json body;
    /// The caller, fully derived by the surface. `principal` is the audit/approval identity,
    /// `exec_visible` the confinement set, `principal_is_admin` the role-gated bypass.
    DispatchCaller caller;
    /// 0 = no cap. The MCP surface bounds one principal's share of the global pending
    /// approval queue (an agentic loop must not fill the cap shared with every human).
    int submitter_pending_cap{0};
};

using DefinitionLookup = std::expected<std::optional<InstructionDefinition>, std::string>;

/// What gets persisted as the execution row; the production binding fills an `Execution`.
struct ExecutionRow {
    std::string definition_id;
    std::string scope_expression;
    std::string parameter_values; ///< REDACTED copy (sensitive_instruction_params.hpp)
    std::string dispatched_by;
};

using DispatchFn = std::function<ConfinedDispatchOutcome(
    const std::string& plugin, const std::string& action,
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const std::unordered_map<std::string, std::string>& parameters,
    const std::string& execution_id, const DispatchCaller& caller,
    const std::string& definition_id, const std::string& concurrency_mode)>;

/// Per request, bound by the surface (it owns the audit action and target).
/// `result` is one of "denied", "failure", "pending", "requested", "success". Returns whether
/// the row persisted. Never throws (the core also guards it).
using AuditHook = std::function<bool(std::string_view result, const std::string& detail)>;

struct Ports {
    /// Unset reads as "store unavailable".
    std::function<DefinitionLookup(const std::string&)> lookup_definition;
    /// Required (the cache is shared with the legacy route in production).
    instr::ParamValidatorCache* validators{nullptr};
    /// The destructive-targeting classifier. Unset -> `ClassifierUnavailable` (fail closed).
    std::function<std::expected<CommandCapability, ClassificationError>(std::string_view,
                                                                         std::string_view)>
        classify;
    /// The chokepoint dry run. Unset -> `Misconfigured` (fail closed, never "no gate").
    std::function<std::expected<CommandCapability, detail::DispatchDenial>(
        const DispatchCaller&, std::string_view, std::string_view)>
        authorize;
    /// `ApprovalManager::submit(def, user, scope, "", kInstruction, plugin, action)`. Unset means
    /// there is no approval manager: a non-auto definition then answers `ApprovalUnavailable`.
    std::function<std::expected<std::string, std::string>(
        const std::string& definition_id, const std::string& submitted_by,
        const std::string& scope_expression, const std::string& plugin, const std::string& action)>
        submit_approval;
    /// `ApprovalManager::pending_count_for`; only consulted when `submitter_pending_cap > 0`.
    std::function<int(const std::string&)> pending_count_for;
    /// `ManagementGroupStore::get_visible_agents`. nullopt = absent or degraded = FAIL CLOSED
    /// (the opposite of `authz::VisibleSet`'s nullopt, see DestructiveVisibleAgents).
    std::function<std::optional<std::vector<std::string>>(const std::string&)> visible_agents;
    /// Execution ledger. Unset `create_execution` = no tracker: dispatch runs with an empty id.
    std::function<std::optional<std::string>(const ExecutionRow&)> create_execution;
    std::function<bool(const std::string& id, const std::string& user)> mark_cancelled;
    std::function<bool(const std::string& id, int agents)> set_agents_targeted;
    std::function<void(const std::string& id)> refresh_counts;
    DispatchFn dispatch;
    yuzu::MetricsRegistry* metrics{nullptr};
};

enum class RefusalKind : std::uint8_t {
    kStoreUnavailable,     ///< 503: the definition store is unavailable or errored
    kNotFound,             ///< 404: no such definition
    kBadRequest,           ///< 400: body type, targeting shape, params violation, untargeted destructive
    kNoVisibleTarget,      ///< 404: a destructive pair whose named targets are all out of scope
    kDispatchDenied,       ///< the chokepoint dry run refused; see Refusal::denial
    kSchemaInvalid,        ///< 500: the stored parameter_schema cannot be prepared (fail closed)
    kApprovalUnavailable,  ///< 503: non-auto definition and no approval manager
    kApprovalSubmitFailed, ///< 500: the approval store could not take the ticket
    kApprovalCapReached,   ///< 429-class: this principal already holds the cap of pending approvals
    kClassifierUnavailable,///< 503: the destructive-targeting classifier is not wired
    kMisconfigured,        ///< 500: a required port is unwired
    kAuditUnavailable,     ///< 503 + Sec-Audit-Failed: nothing was dispatched without durable evidence
    kDispatchFailed,       ///< 500: the dispatch threw; the execution row (if any) was cancelled
};

struct Refusal {
    RefusalKind kind{RefusalKind::kBadRequest};
    /// Closed token for audit and the wire `reason` ("" when none applies).
    std::string reason;
    std::string message;
    std::string remediation;
    /// Honest retry hint in ms; nullopt = not retryable (the wire carries null).
    std::optional<int> retry_after_ms;
    /// Engaged for kDispatchDenied.
    std::optional<detail::DispatchDenial> denial;
    /// The definition's pair, set with `denial`: the denial text names it ("approval required
    /// for testplug.gated"), so the renderers must not pass empty strings.
    std::string plugin;
    std::string action;
};

struct PendingApproval {
    std::string approval_id;
    std::string approval_mode;
    std::string definition_id;
};

struct Dispatched {
    std::string command_id;
    std::string execution_id;
    int agents_reached{0};
    std::string definition_id;
    std::string plugin;
    std::string action;
};

struct ZeroReach {
    ZeroReachCause cause{ZeroReachCause::Generic};
    std::string command_id;
    std::string execution_id;
    std::string message;
    std::string definition_id;
    std::string plugin;
    std::string action;
    std::size_t agents_quarantined{0};
    std::size_t agents_unknown_plugin{0};
    std::size_t agents_kill_switched_os{0};
};

struct Outcome {
    std::variant<Refusal, PendingApproval, Dispatched, ZeroReach> result;
    /// True when a row the core wrote best-effort (a denial, the pending row, the final row)
    /// did not persist. The surface reports it (REST: `Sec-Audit-Failed`; MCP:
    /// `audit_persisted:false`). The fail-closed `requested` row is a Refusal instead.
    bool audit_dropped{false};
};

/// What `prepare` hands to the dispatch stage.
struct Plan {
    InstructionDefinition def;
    std::vector<std::string> agent_ids;
    std::string scope; ///< the caller's scope expression; empty when none was named
    std::unordered_map<std::string, std::string> params;
};

struct PrepareOutcome {
    std::variant<Refusal, PendingApproval, Plan> result;
    bool audit_dropped{false};
};

/// Steps 1-6. Writes an audit row only for a refusal or a pending approval. MCP calls this
/// alone as its pre-mint probe, so a refused call mints no tier ticket.
[[nodiscard]] PrepareOutcome prepare(const Request& rq, const Ports& ports, const AuditHook& audit);

/// Steps 1-9.
[[nodiscard]] Outcome run(const Request& rq, const Ports& ports, const AuditHook& audit);

/// The approval verdict for a definition, factored so tests pin the matrix without a store.
/// `approval_mode` is the stored string; `caller_is_admin` is `principal_is_admin`.
[[nodiscard]] bool definition_needs_approval(std::string_view approval_mode,
                                             bool caller_is_admin) noexcept;

} // namespace yuzu::server::instruction_execute
