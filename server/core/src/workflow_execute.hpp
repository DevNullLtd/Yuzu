#pragma once

/// @file workflow_execute.hpp
/// The ONE shared sequence behind `POST /api/v1/workflows/{id}/execute` and the MCP tool
/// `execute_workflow` (#2146 batch B, ledger row `post.api-workflows-param-execute`). REST and
/// MCP each parse their own envelope, run their own surface gate (`Workflow:Execute`) and map the
/// outcome onto their own error shape; everything between those two ends is HERE, once, so the
/// two surfaces cannot disagree about what a workflow run is allowed to do.
///
/// The legacy `POST /api/workflows/{id}/execute` (workflow_routes.cpp) is a different, older
/// handler and is NOT routed through this file. Where it differs, the difference is deliberate:
///   * FAIL CLOSED when the approval gate or the instruction store is not wired or not open
///     (owner ruling 2026-10-30). The legacy handler SKIPS its per-step approval check in that
///     case and goes on to dispatch.
///   * the `requested` audit row is written (and must persist) BEFORE anything is dispatched; a
///     late targeting denial is audited at the moment the step is refused, not after the
///     response; the legacy handler audits both after the fact.
///   * an unclassified step is refused up front instead of failing later at the chokepoint.
///
/// Ports, not stores: every dependency arrives as a `std::function` or a flag, so the whole
/// sequence is testable without Postgres (reads go through `WorkflowApi`, which `FnWorkflowApi`
/// doubles; the run goes through the `WorkflowRunFn` port, `workflow_run_port.hpp`).
/// `make_instruction_lookup` is the one adapter from the real
/// `InstructionStore`.
///
/// TWO HALVES, as `instruction_execute::prepare`/`run`. `prepare_workflow_execute` is steps 1-4
/// and has NO effect on the endpoints: it writes only denial rows, and MCP calls it alone as the
/// pre-mint probe, so a call that is going to be refused mints no approval ticket and burns none.
/// `run_workflow_execute` is steps 5-6. `apply_workflow_execute` is the two in a row.
///
/// ORDER (each step refuses before the next runs; nothing is dispatched until step 6):
///   1. wiring: engine/API, instruction store open, approval gate present, classifier,
///      authorizer, dispatcher, audit sink, a resolvable principal.  -> kUnavailable / kNoPrincipal
///   2. read the workflow; no steps is refused.                    -> kStoreFailed / kWorkflowNotFound
///   3. per step: the instruction exists (unknown -> 400); the shared chokepoint's dry run for its
///      (plugin, action) admits THIS caller, once per distinct pair (RBAC, the ExecuteGate against
///      the caller's real `approval_provenance`, the all-OS kill switch) -> kDispatchDenied (403,
///      not retryable); then its approval mode admits this caller (`auto` always; `role-gated` only
///      for `caller.principal_is_admin`, which already mirrors the JIT-elevation-aware
///      `effective_role`; `always` and any unknown mode never).
///      A consumed MCP approval ticket does NOT relax either check: the ticket binds the workflow
///      id and agent list, not the step list, and the REST twin has no ticket to relax it with.
///   4. per step: the capability is classified, and a Destructive/Forensics pair is targeted
///      explicitly (`evaluate_destructive_targeting`); a Destructive pair whose named agents are
///      all outside the caller's visible set is refused as `destructive_no_visible_target`.
///   5. the `requested` audit row. A persist failure refuses the run (kAuditFailed).
///   6. `WorkflowExecutePorts::run`, whose per-step dispatch callback re-runs the approval-mode and
///      targeting checks of steps 3 and 4 against a FRESH read of the instruction (so a definition
///      edited after the preflight is refused at dispatch, audited there) and then dispatches
///      through the caller's own `DispatchCaller`, so the shared chokepoint confines each step to
///      the caller.
///
/// AUTHORITY IS ALL-OR-NOTHING, REACH IS PER STEP. Steps 1-4 decide what the CALLER may run and
/// refuse the whole call, sending nothing, when any step fails them. Which DEVICES a step reaches
/// is decided later, per step, at the dispatch chokepoint (visibility, containment, plugin
/// presence, the per-OS kill switch, concurrency claims): a step that then reaches nobody is
/// reported in `steps` with its reason, and an earlier step has already been sent. The preflight
/// does NOT promise that every step will reach a device, only that the caller is allowed to ask.
///
/// The `DispatchCaller` is the CALLER's, derived once by the transport (`caller_fn`), with
/// `approval_provenance` left as the transport set it: REST leaves it `None`, MCP stamps `Ticket`
/// only after the C8 gate consumed a ticket (dispatch_caller.hpp, stamping site 2). It is passed
/// through unchanged to every step; this file never rebuilds a caller from a principal string.

#include "agent_registry.hpp" // detail::DispatchDenial (the authorize port's error type)
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_zero_reach.hpp"
#include "workflow_api.hpp"
#include "workflow_run_port.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class InstructionStore;

/// The slice of an `InstructionDefinition` the sequence reads. Decoupled from the store type so
/// the ports (and the tests) never need Postgres.
struct WorkflowStepInstruction {
    std::string id;
    std::string plugin;
    std::string action;
    std::string approval_mode; ///< "auto" | "role-gated" | "always" (anything else fails closed)
    std::string concurrency_mode;
};

/// `nullopt` = the store answered and has no such instruction; `unexpected` = a store fault
/// (never treated as "no such instruction").
using WorkflowInstructionLookupFn =
    std::function<std::expected<std::optional<WorkflowStepInstruction>, std::string>(
        const std::string& instruction_id)>;

using WorkflowClassifyFn =
    std::function<std::expected<CommandCapability, ClassificationError>(std::string_view plugin,
                                                                       std::string_view action)>;

/// The shared chokepoint's dry run (`classify_and_authorize_dispatch` plus the all-OS kill
/// switch), the same closure `execute_instruction_definition` and the quarantine routes take
/// (server.cpp's `authorize_dispatch`). It is given the CALLER's own `DispatchCaller`, so RBAC and
/// the ExecuteGate are judged against the real `principal_is_admin` and `approval_provenance`. It
/// cannot see a per-OS withhold (no target), which stays a per-step reach outcome.
using WorkflowAuthorizeFn = std::function<std::expected<CommandCapability, detail::DispatchDenial>(
    const DispatchCaller& caller, std::string_view plugin, std::string_view action)>;

/// Send one step. The transport wraps its confined dispatcher (and, on REST, the ADR-1007
/// per-device concurrency variant when wired). `agent_ids` is the request's own list.
using WorkflowStepDispatchFn = std::function<ConfinedDispatchOutcome(
    const WorkflowStepInstruction& def, const std::vector<std::string>& agent_ids,
    const std::unordered_map<std::string, std::string>& params, const DispatchCaller& caller)>;

/// Persist one audit row (action, result, target_id, detail); `true` = durably written or audit
/// is off. Wraps `detail::try_persist_audit`, so a throw is already a `false`.
using WorkflowAuditFn =
    std::function<bool(const std::string& action, const std::string& result,
                       const std::string& target_id, const std::string& detail)>;

struct WorkflowExecutePorts {
    /// Reads only (`get_workflow`, `get_workflow_execution`).
    const WorkflowApi* api{nullptr};
    /// Starts the run; the engine adapter built in server.cpp. Unset == engine not available.
    WorkflowRunFn run;
    /// `InstructionStore* != nullptr && is_open()`, computed by the transport at call time.
    bool instruction_store_open{false};
    /// `ApprovalManager* != nullptr`. The manager is not consulted for a decision (per-step
    /// approval is decided from the instruction's approval mode); its absence means the approval
    /// subsystem is not wired, and the run is refused rather than dispatched without it.
    bool approval_gate_available{false};
    WorkflowInstructionLookupFn lookup;
    WorkflowClassifyFn classify;
    /// Required (unset == dispatch not available, fail closed): called once per distinct step
    /// pair in `prepare_workflow_execute`.
    WorkflowAuthorizeFn authorize;
    WorkflowStepDispatchFn dispatch;
    WorkflowAuditFn audit;
    /// Optional: bumps `yuzu_server_dispatch_target_rejected_total{route="workflow",reason}`.
    std::function<void(std::string_view reason)> count_target_rejected;
    /// Optional: bumps `yuzu_server_dispatch_denied_total{reason}` with the chokepoint's own
    /// denial token (`forbidden`, `approval_required`, `kill_switched`, ...).
    std::function<void(std::string_view reason)> count_dispatch_denied;
};

struct WorkflowExecuteRequest {
    std::string workflow_id;
    std::vector<std::string> agent_ids; ///< from `parse_workflow_execute_body`: non-empty, bounded
    DispatchCaller caller;
    std::string audit_context; ///< "surface=rest" / "surface=mcp": a literal, never caller text
};

/// A parse refusal for the request body. `reason` is a closed token (the
/// `yuzu_server_dispatch_target_rejected_total` label vocabulary where one exists);
/// `message` is operator-facing and carries no caller-derived text.
struct WorkflowExecuteBodyError {
    std::string reason;
    std::string message;
};

/// Parse the PARSED request body (REST body or MCP arguments). Requires an object with a
/// non-empty `agent_ids` array of strings (<= kExecInstrAgentIdsMaxItems entries of
/// <= kExecInstrIdentMaxLen bytes). `agent_ids` is REQUIRED: a workflow run names its devices
/// explicitly (an omitted list is not "the fleet" here). `scope` is refused outright (this
/// operation has no scope arm). Unknown keys are ignored except that `scope` is not allowed.
/// Runs `check_targeting_shape` on the parsed object, per its precondition.
[[nodiscard]] std::expected<std::vector<std::string>, WorkflowExecuteBodyError>
parse_workflow_execute_body(const nlohmann::json& body);

enum class WorkflowExecuteStatus {
    kOk,                         ///< run started; see `execution_id` and `steps`
    kUnavailable,                ///< a port is unwired / the instruction store is closed (503, nothing done)
    kNoPrincipal,                ///< the caller has no resolvable principal (500)
    kStoreFailed,                ///< a store read failed (503, retryable)
    kWorkflowNotFound,           ///< no such workflow, or soft-deleted (404)
    kInvalidWorkflow,            ///< the workflow has no steps (400)
    kUnknownInstruction,         ///< a step names an instruction that does not exist (400)
    kApprovalRequired,           ///< a step's approval mode does not admit this caller (403)
    kDispatchDenied,             ///< the chokepoint dry run refuses this caller a step's pair (403, not retryable)
    kUnclassifiedStep,           ///< a step's plugin.action is not in the capability catalogue (400)
    kDestructiveUntargeted,      ///< a Destructive/Forensics step is not explicitly targeted (400)
    kDestructiveNoVisibleTarget, ///< ... or every named agent is outside the caller's view (404)
    kAuditFailed,                ///< the `requested` row did not persist; nothing was dispatched (503)
    kNoAgentsReached,            ///< the run started but no step reached any agent (503/reason)
    kExecuteFailed,              ///< the engine refused the run (400), message in `message`
};

/// One dispatch attempt as recorded while the engine drove the steps. Retries and `foreach`
/// expansion produce more than one entry for a step.
struct WorkflowStepDispatchNote {
    std::string instruction_id;
    std::string command_id;
    int agents_reached{0};
    /// Empty when `agents_reached > 0`. Otherwise a `zero_reach_token` ("no_agents_reached",
    /// "quarantined", ...) or "late_denied" (the definition changed after the preflight and the
    /// refreshed step no longer passed).
    std::string reason;
    bool retryable{false};
    std::size_t agents_quarantined{0};
    std::size_t agents_unknown_plugin{0};
    std::size_t agents_kill_switched_os{0};
};

struct WorkflowExecuteOutcome {
    WorkflowExecuteStatus status{WorkflowExecuteStatus::kUnavailable};
    /// Operator-facing text for every non-kOk status. Never raw store text.
    std::string message;
    /// Machine token for a refusal (`destructive_untargeted`, `approval_required`,
    /// `dispatch_denied`, ...), and for kNoAgentsReached the dominant zero-reach cause.
    std::string reason;
    /// What the caller can do about a refusal; set for kDispatchDenied (the chokepoint's own
    /// wording, the ExecuteGate case rewritten because no ticket lifts a workflow step's gate).
    std::string remediation;
    bool retryable{false};
    /// Set for kOk and kNoAgentsReached (the run exists in both).
    std::string execution_id;
    /// The engine's recorded status after the step loop ("completed", "failed", ...), or
    /// "unknown" when it could not be read back. Dispatch-level only: it says the commands were
    /// SENT, not that any device finished.
    std::string run_status;
    std::vector<WorkflowStepDispatchNote> steps;
    bool late_denied{false};
    /// False only when the closing outcome row failed to persist after the run had started.
    bool audit_persisted{true};
};

/// What `prepare_workflow_execute` hands to `run_workflow_execute`: only what the second half
/// needs. The workflow and its instructions are re-read by the run itself (per step, fresh), so
/// nothing a stale snapshot could widen is carried across.
struct WorkflowExecutePlan {
    std::size_t step_count{0};
};

/// Steps 1-4 of the banner. No effect on any endpoint, no `requested` row. A refusal is returned
/// as the outcome the transport renders; a refusal from the per-step checks also writes its
/// `denied` audit row (and, for a dispatch denial, counts `count_dispatch_denied`), exactly as
/// `instruction_execute::prepare` does for its authorize refusal. A store fault, an unwired port
/// and an unknown workflow write NO row (nothing identified the call yet).
[[nodiscard]] std::expected<WorkflowExecutePlan, WorkflowExecuteOutcome>
prepare_workflow_execute(const WorkflowExecutePorts& ports, const WorkflowExecuteRequest& req);

/// Steps 5-6. `plan` must come from `prepare_workflow_execute` on the same ports and request.
[[nodiscard]] WorkflowExecuteOutcome run_workflow_execute(const WorkflowExecutePorts& ports,
                                                          const WorkflowExecuteRequest& req,
                                                          const WorkflowExecutePlan& plan);

/// Run the sequence in the header banner: prepare, then run. Never throws for an expected
/// refusal; a thrown port is the caller's to catch (the transports wrap it, as they wrap every
/// other handler body).
[[nodiscard]] WorkflowExecuteOutcome apply_workflow_execute(const WorkflowExecutePorts& ports,
                                                            const WorkflowExecuteRequest& req);

/// The pure per-step admission verdict, exposed so the preflight, the dispatch-time re-check and
/// the tests share one function.
enum class StepAdmission {
    kAdmitted,
    kApprovalRequired,
    kUnclassified,
    kDestructiveUntargeted,
    kDestructiveNoVisibleTarget,
};

struct StepAdmissionDecision {
    StepAdmission verdict{StepAdmission::kAdmitted};
    std::string_view reason;  ///< metric/audit token for a refusal
    std::string_view message; ///< operator-facing text for a targeting refusal
};

/// `approval_blocked`: true when the instruction's approval mode does not admit the caller
/// (`principal_is_admin` is the JIT-elevation-aware flag on `DispatchCaller`).
[[nodiscard]] bool step_approval_blocked(std::string_view approval_mode, bool principal_is_admin);

[[nodiscard]] StepAdmissionDecision admit_step(const WorkflowStepInstruction& def,
                                               const WorkflowClassifyFn& classify,
                                               const std::vector<std::string>& agent_ids,
                                               const DispatchCaller& caller);

/// The success body both transports return for a started run (kOk or kNoAgentsReached):
/// `execution_id`, `workflow_id`, `status` (the engine's recorded dispatch-level status) and
/// `steps` (one entry per dispatch attempt: `instruction_id`, `command_id`, `agents_reached`,
/// plus `reason`/`retryable` and the withheld counts when nothing was reached), `late_denied`,
/// and `audit_persisted:false` only when the closing audit row failed. One builder so REST and
/// MCP cannot drift on field set.
[[nodiscard]] nlohmann::json workflow_execute_result_json(const WorkflowExecuteOutcome& o,
                                                          const std::string& workflow_id);

/// Adapter from the real store; the returned function holds `store` by pointer, which must
/// outlive it (the server owns the store for the process lifetime). A null `store` yields an
/// empty function.
[[nodiscard]] WorkflowInstructionLookupFn make_instruction_lookup(InstructionStore* store);

} // namespace yuzu::server
