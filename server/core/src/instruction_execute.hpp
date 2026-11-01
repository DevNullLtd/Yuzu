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
#include "event_emit.hpp"                // EventEmitHook
#include "instruction_param_schema.hpp"  // instr::ParamValidatorCache
#include "instruction_store.hpp"         // InstructionDefinition

#include <nlohmann/json.hpp>

#include <array>
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

/// One principal's share of the global pending-approval queue (`ApprovalManager::
/// kMaxPendingApprovals`, 1000). ONE constant for every surface that creates a pending approval
/// on a principal's behalf: REST `POST /api/v1/instructions/{id}/execute`, MCP
/// `execute_instruction_definition` and the MCP C8 ticket mint. An agentic loop (or a script)
/// must not be able to fill the cap it shares with every human and every schedule.
inline constexpr int kSubmitterPendingCap = 25;

/// `reason` label of `yuzu_server_approval_submit_refused_total`, and the same token the audit
/// row and the wire `reason` carry. CLOSED set, every member pre-seeded at boot in server.cpp from
/// this array. `approval_cap_reached` is the per-principal cap above; `approval_unavailable` is
/// "no approval manager wired" (a server defect: 503 with a null `retry_after_ms`);
/// `approval_queue_full` is the GLOBAL 1000-row pending queue being full (nobody can submit
/// until a human reviewer decides a pending approval or the 7-day expiry clears one: a retry
/// loop cannot help, so it carries no `retry_after_ms`); `approval_submit_failed` is any other
/// store fault refusing the row (retryable). Only refusals at the approval-submit step count: a
/// refusal earlier in `prepare` (targeting, params, gate) creates no approval and counts under
/// its own family.
inline constexpr char kApprovalRefusedMetric[] = "yuzu_server_approval_submit_refused_total";
inline constexpr char kReasonApprovalCapReached[] = "approval_cap_reached";
inline constexpr char kReasonApprovalUnavailable[] = "approval_unavailable";
inline constexpr char kReasonApprovalSubmitFailed[] = "approval_submit_failed";
inline constexpr char kReasonApprovalQueueFull[] = "approval_queue_full";
inline constexpr std::array<std::string_view, 4> kApprovalRefusedReasons{
    kReasonApprovalCapReached, kReasonApprovalUnavailable, kReasonApprovalSubmitFailed,
    kReasonApprovalQueueFull};

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
    /// 0 = no cap. Every production surface sets `kSubmitterPendingCap`: it bounds one principal's
    /// share of the global pending approval queue (an agentic loop or a script must not fill the
    /// cap shared with every human). Only a test leaves it 0.
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

/// Why an approval submit failed, as much as the surface needs to answer it truthfully: a full
/// global queue is not a store fault (only a reviewer or the expiry clears it).
struct ApprovalSubmitError {
    bool queue_full{false};
    std::string message;
};

struct Ports {
    /// Unset reads as "store unavailable".
    std::function<DefinitionLookup(const std::string&)> lookup_definition;
    /// Required (the cache is shared with the legacy route in production). NOT owned: in
    /// production the pointee is `ServerImpl::param_validator_cache_`, a member declared BEFORE
    /// `web_server_`, and `ServerImpl::stop()` halts the web server (so no handler holding these
    /// ports can still run) before any member is destroyed.
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
    std::function<std::expected<std::string, ApprovalSubmitError>(
        const std::string& definition_id, const std::string& submitted_by,
        const std::string& scope_expression, const std::string& plugin, const std::string& action)>
        submit_approval;
    /// `ApprovalManager::pending_count_for_checked`; only consulted when `submitter_pending_cap
    /// > 0`. `nullopt` = the count could not be read: the cap then REFUSES (503
    /// `approval_unavailable`, a retryable store fault), it never reads as zero and admits.
    std::function<std::optional<int>(const std::string&)> pending_count_for;
    /// `ManagementGroupStore::get_visible_agents`. nullopt = absent or degraded = FAIL CLOSED
    /// (the opposite of `authz::VisibleSet`'s nullopt, see DestructiveVisibleAgents).
    std::function<std::optional<std::vector<std::string>>(const std::string&)> visible_agents;
    /// Execution ledger. Unset `create_execution` = no tracker: dispatch runs with an empty id.
    std::function<std::optional<std::string>(const ExecutionRow&)> create_execution;
    std::function<bool(const std::string& id, const std::string& user)> mark_cancelled;
    std::function<bool(const std::string& id, int agents)> set_agents_targeted;
    std::function<void(const std::string& id)> refresh_counts;
    DispatchFn dispatch;
    /// NOT owned: null (counting off) or `ServerImpl::metrics_`, a member that outlives the web
    /// server for the same reason as `validators` above (`stop()` halts it before member
    /// destruction).
    yuzu::MetricsRegistry* metrics{nullptr};
};

enum class RefusalKind : std::uint8_t {
    kStoreUnavailable,     ///< 503: the definition store is unavailable or errored
    kNotFound,             ///< 404: no such definition
    kBadRequest,           ///< 400: body type, targeting shape, params violation, untargeted destructive
    kNoVisibleTarget,      ///< 404: a destructive pair whose named targets are all out of scope
    kDispatchDenied,       ///< the chokepoint dry run refused; see Refusal::denial
    kSchemaInvalid,        ///< 500: the stored parameter_schema cannot be prepared (fail closed)
    kApprovalUnavailable,  ///< 503: no approval manager (a server defect: NO retry hint), or the pending count
                           ///< could not be read (a store fault: retryable)
    kApprovalSubmitFailed, ///< 500: the approval store could not take the ticket (a store fault; retryable)
    kApprovalQueueFull,    ///< 503: the global pending queue is full (only a reviewer or the expiry clears it: NO retry hint)
    kApprovalCapReached,   ///< 429-class: this principal already holds the cap of pending approvals
    kClassifierUnavailable,///< 503: the destructive-targeting classifier is not wired
    kMisconfigured,        ///< 500: a required port is unwired (a server defect: NO retry hint, ever)
    kAuditUnavailable,     ///< 503 + Sec-Audit-Failed: nothing was dispatched without durable evidence
    kDispatchFailed,       ///< 500: the dispatch threw (any exception type); the execution row (if any) is left
                           ///< `running` (NOT cancelled: agents may hold the command), a `failure` audit row is
                           ///< written, and NO retry is advertised (agents may have been sent it)
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

/// Steps 1-6. Writes an audit row for a refusal from step 2 on (`denied`, or `failure` for an
/// unusable stored schema or an approval that could not be queued) and for a pending approval.
/// It writes NONE for step 1 (an unknown definition, a store fault), a missing port, or the
/// classifier being unavailable: only `requested` (step 7) is guaranteed before the effect.
/// MCP calls this alone as its pre-mint probe, so a refused call mints no tier ticket.
///
/// `emit` (optional, bound per request by the surface) publishes the events the LEGACY
/// `POST /api/instructions/{id}/execute` publishes, so the twins match it: `approval.created`
/// when this call created the pending approval (once, at the creation, so an MCP probe that
/// answers `pending_approval` and a REST call emit exactly one each), and `instruction.executed`
/// when a dispatch reached at least one agent. Both with null attributes and payload, as the
/// legacy route does. A refusal, a zero-reach and a throwing dispatch emit nothing. Best effort,
/// after the audit row; it can never change the outcome.
[[nodiscard]] PrepareOutcome prepare(const Request& rq, const Ports& ports, const AuditHook& audit,
                                     const EventEmitHook& emit = {});

/// Steps 1-9.
[[nodiscard]] Outcome run(const Request& rq, const Ports& ports, const AuditHook& audit,
                          const EventEmitHook& emit = {});

/// The approval verdict for a definition, factored so tests pin the matrix without a store.
/// `approval_mode` is the stored string; `caller_is_admin` is `principal_is_admin`.
[[nodiscard]] bool definition_needs_approval(std::string_view approval_mode,
                                             bool caller_is_admin) noexcept;

} // namespace yuzu::server::instruction_execute
