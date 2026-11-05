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
///      A consumed MCP approval ticket does NOT relax either check: it is not a stamping site for
///      `approval_provenance`, and the REST twin has no ticket to relax it with. When the request
///      carries `expected_step_effects`, each step's instruction is first held to the effect the
///      ticket was bound to (`definition_changed`, before the checks above).
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
/// A THROW after the `requested` row (any port: the engine, a step dispatch, the read-back) never
/// escapes `run_workflow_execute`. The engine closes its own row `failed` and skips the rest, and
/// the sequence writes the closing `failure` row and answers `kRunFailed`: NOT retryable, because
/// steps may already have been sent, carrying `execution_id` and `agents_sent` so the caller reads
/// the run (`get_workflow_execution`) instead of re-sending. Only a throw BEFORE that row (the
/// prepare half, the `requested` row itself) escapes, and a transport maps that one retryable:
/// nothing had been sent.
///
/// THE CLOSING LABEL. The closing `workflow.execute` row is `success` only for
/// `WorkflowRunOutcome::kSucceeded` (see `classify_workflow_run`): the engine's recorded status is
/// `completed`, no step was refused at send time and every dispatch attempt reached an agent.
/// Anything else is `failure` with `run_outcome=failed|partial|interrupted|aborted` in the detail.
/// The engine's final state is read back through the existing `WorkflowApi::get_workflow_execution`
/// after the run: the run is synchronous and the engine finalizes its row before `run` returns, so
/// the read cannot see an earlier state, and an unreadable row ("unknown") is never success. The
/// transports map the outcome identically: kOk -> 202 `status:"completed"`; a run that sent
/// something but did not succeed (kRunIncomplete) -> 202 with `status:"partial"|"aborted"|"interrupted"` and
/// `retryable:false`; a run that reached nobody (kNoAgentsReached) -> the zero-reach error.
///
/// ADMISSION AND THE BUDGET. A run is SYNCHRONOUS: the transport's worker thread is held for the
/// whole run, retry sleeps included, so each transport first calls `admit_workflow_run` (before
/// any read of the workflow, before the `requested` row, and on MCP before the approval ticket is
/// consumed): it refuses a draining server (`kDraining`, 503) and leases from the ONE shared
/// `StreamBudget` on `SseSurface::kWorkflowRun` (`kRunCapReached`, 429; 2 per principal). The
/// lease lives exactly as long as the transport's call. The run itself is bounded by
/// `kWorkflowSyncBudget` (60 s): `prepare_workflow_execute` refuses a workflow whose worst-case
/// retry sleep exceeds it (`kExceedsSyncBudget`, 400, nothing done and so no ticket), and the
/// engine stops a run at its deadline (below). The precheck models sleeps only: it does not
/// model dispatch time or `foreach` fan-out (every item is a dispatch inside an attempt), so the
/// deadline is the real bound.
/// A run stopped at its deadline skips its remaining steps, closes `failed`, and ends
/// `WorkflowRunOutcome::kAborted` with `deadline_exceeded` and reason `deadline_exceeded`.
///
/// SHUTDOWN. A server that is DRAINING lets a run in flight finish its dispatching: the engine
/// abandons any retry the run had not yet made and goes on with the remaining steps, and the
/// shutdown waits for the run (the engine's in-flight count is part of the drain wait, capped).
/// A server that is STOPPING ends the run: the engine tells the sequence (`on_interrupted`), the
/// run answers `WorkflowRunOutcome::kInterrupted` as a typed 2xx `status:"interrupted"` with
/// reason `server_shutdown` and `retryable:false`, and its closing audit row is `failure` with
/// `run_outcome=interrupted reason=server_shutdown`.
///
/// AUTHORITY IS ALL-OR-NOTHING, REACH IS PER STEP. Steps 1-4 decide what the CALLER may run and
/// refuse the whole call, sending nothing, when any step fails them. Which DEVICES a step reaches
/// is decided later, per step, at the dispatch chokepoint (visibility, containment, plugin
/// presence, the per-OS kill switch, concurrency claims): a step that then reaches nobody is
/// reported in `steps` with its reason, and an earlier step has already been sent. The preflight
/// does NOT promise that every step will reach a device, only that the caller is allowed to ask.
///
/// The `DispatchCaller` is the CALLER's, derived once by the transport (`caller_fn`), with
/// `approval_provenance` left as the transport set it: both REST and MCP leave it `None`, and MCP
/// does so even after the C8 gate consumed a ticket (`execute_workflow` is not a stamping site,
/// dispatch_caller.hpp). It is passed through unchanged to every step; this file never rebuilds a
/// caller from a principal string.
///
/// STEP-EFFECT BINDING (MCP supervised tier only). The C8 approval ticket for `execute_workflow`
/// binds the ORDERED step effects as well as the call's arguments: `workflow_effect_binding`
/// renders `effect=["workflow",N,[first K "plugin.action"],"<sha256>"]` (summary first, hash
/// second) over the ordered `(instruction_id, plugin, action, approval_mode, concurrency_mode)`
/// tuples, and MCP prepends it to the canonical arguments exactly as `execute_instruction_definition`
/// does. A workflow is immutable by id, so the mutable input behind an approved ticket is the
/// stored instruction definitions its steps name. `WorkflowExecuteRequest::expected_step_effects`
/// carries the bound tuples into the run: `prepare_workflow_execute` and every per-step dispatch
/// re-read the instruction and refuse `definition_changed` when a step's tuple moved, before
/// anything is sent for that step. REST has no ticket and leaves it unset.

#include "agent_registry.hpp" // detail::DispatchDenial (the authorize port's error type)
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_zero_reach.hpp"
#include "stream_budget.hpp" // detail::StreamBudget: a run leases from the ONE held-open budget
#include "workflow_api.hpp"
#include "workflow_run_port.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class InstructionStore;

/// The wall-clock budget of ONE synchronous workflow run, from the moment the transport takes
/// the call to the moment the engine must have stopped dispatching (owner ruling, 2026-11-04;
/// Fable op-7: never above 60 s). Three things are held to it: the run's `deadline`
/// (`WorkflowRunControl`, so no attempt starts after it and no retry delay runs past it),
/// `prepare_workflow_execute`'s worst-case sleep check (a workflow whose retries could sleep
/// longer than this is refused up front), and the retry hint of a refused admission. A caller
/// or an intermediary that gives up before it has no idempotency key, so the budget stays short.
inline constexpr std::chrono::seconds kWorkflowSyncBudget{60};

/// `Retry-After` / `retry_after_ms` of a run refused for capacity or for a draining server. A run
/// holds its worker for up to `kWorkflowSyncBudget`, so a slot usually frees well inside a minute;
/// 5 s is the platform's stream-cap retry floor (`kMcpStreamCapRetryAfterMs`, mcp_stream.hpp).
inline constexpr std::int64_t kWorkflowRunCapRetryAfterMs = 5000;

/// A run refused at ADMISSION (before any read of the workflow or the `requested` row):
/// `yuzu_server_workflow_run_refused_total{reason}`. The first two are the shared
/// `StreamBudget`'s own reject tokens, the third is a server that is draining (the budget's
/// `try_acquire` does not consult its `closing_` flag, so the adapters refuse on `draining`
/// explicitly). A closed set; every member is pre-seeded to 0 at boot.
inline constexpr char kWorkflowRunRefusedMetric[] = "yuzu_server_workflow_run_refused_total";
inline constexpr char kWorkflowRunsInFlightMetric[] = "yuzu_server_workflow_runs_in_flight";
inline constexpr char kWorkflowRunRefusedDraining[] = "draining";
inline constexpr std::array<std::string_view, 3> kWorkflowRunRefusedReasons{
    detail::StreamBudget::kRejectGlobal, detail::StreamBudget::kRejectPerPrincipal,
    kWorkflowRunRefusedDraining};

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

/// SHA-256 as 64 lowercase hex characters, or `nullopt` on a provider failure (never a digest of
/// zeros). Unset on `WorkflowExecutePorts` == `sha256_hex` (sha256_hex.hpp); a seam so the
/// fail-closed path is testable.
using WorkflowDigestFn = std::function<std::optional<std::string>(std::string_view data)>;

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
    /// Optional: the digest used by `workflow_effect_binding` (default: `sha256_hex`).
    WorkflowDigestFn digest;
    /// Optional: bumps `yuzu_server_dispatch_target_rejected_total{route="workflow",reason}`.
    std::function<void(std::string_view reason)> count_target_rejected;
    /// Optional: bumps `yuzu_server_dispatch_denied_total{reason}` with the chokepoint's own
    /// denial token (`forbidden`, `approval_required`, `kill_switched`, ...).
    std::function<void(std::string_view reason)> count_dispatch_denied;
    /// Optional: bumps `yuzu_server_dispatch_fanout_throw_total{route="workflow",phase="dispatch"}`
    /// when a run throws after its `requested` row.
    std::function<void()> count_run_threw;
};

/// instruction id -> `workflow_step_effect` text: what one step's instruction resolved to when the
/// MCP approval ticket's effect line was computed.
using WorkflowStepEffects = std::unordered_map<std::string, std::string>;

struct WorkflowExecuteRequest {
    std::string workflow_id;
    std::vector<std::string> agent_ids; ///< from `parse_workflow_execute_body`: non-empty, bounded
    DispatchCaller caller;
    std::string audit_context; ///< "surface=rest" / "surface=mcp": a literal, never caller text
    /// MCP supervised tier only: the step effects the consumed ticket was bound to (the probe's
    /// snapshot, whose digest the ticket match proved equal to the approved one). Unset on REST,
    /// which has no ticket, and on any call that carried none: nothing then holds the lookup.
    std::optional<WorkflowStepEffects> expected_step_effects;
    /// When the run must stop, set by the transport when it takes the call (`now +
    /// kWorkflowSyncBudget`) so the time prepare spent counts against it. Unset falls back to
    /// `now + kWorkflowSyncBudget` at the start of the run: a run is never unbounded.
    std::optional<std::chrono::steady_clock::time_point> deadline;
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
    kOk,                         ///< the run COMPLETED and every dispatch attempt reached an agent (202)
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
    kNoAgentsReached,            ///< the run started and ended with no step having reached any agent (503/reason; outcome failed or aborted)
    kExecuteFailed,              ///< the engine refused the run (400), message in `message`
    kDefinitionChanged,          ///< a step's instruction moved from the ticket-bound effect (400, nothing sent for it)
    kEffectDigestFailed,         ///< the step-effect digest could not be computed (500, no ticket minted)
    kRunFailed,                  ///< the run THREW after the `requested` row: steps may have been sent (500, NOT retryable)
    kRunIncomplete,              ///< the run ran and sent something but did not fully succeed: `partial`, `aborted` or `interrupted` (2xx, typed status, NOT retryable)
    kExceedsSyncBudget,          ///< the workflow's worst-case retry sleep exceeds `kWorkflowSyncBudget` (400, nothing done, no ticket)
    kRunCapReached,              ///< admission: this principal or the server holds as many runs/streams as it may (429, retryable, nothing done)
    kDraining,                   ///< admission: the server is shutting down and starts no new run (503, retryable, nothing done)
};

/// How a run that reached the engine ended, judged from what the engine recorded and what the
/// steps did. `kSucceeded` is the ONLY value that labels the closing `workflow.execute` row
/// `success`; every other value labels it `failure` and rides in the row's detail as
/// `run_outcome=<token>` (`workflow_run_outcome_token`). A run is `kSucceeded` only if ALL of:
/// the engine's recorded status is `completed`, no step was refused at send time
/// (`late_denied`), and every dispatch attempt reached at least one agent. The others, tested
/// in this order:
///   * `kAborted`     a step was refused at send time (`late_denied`): its definition moved off the
///                    preflight or off the ticket-bound effect, or it no longer passed admission;
///                    OR the run reached its deadline (`kWorkflowSyncBudget`) and the engine
///                    stopped it (`deadline_exceeded`). Takes precedence: the run was cut short,
///                    whatever else it did.
///   * `kInterrupted` the engine ended the run because the server is stopping (the engine told the
///                    sequence through `WorkflowRunControl::on_interrupted`, at the moment it
///                    acted): the unstarted steps are skipped `server_shutdown` and the execution
///                    is closed `failed`. Typed 2xx `status:"interrupted"`, reason
///                    `server_shutdown`, `retryable:false`, whether or not anything was sent.
///                    A server that is merely DRAINING does not interrupt a run.
///   * `kFailed`      no dispatch attempt reached any agent: the engine ended `failed` (or in any
///                    status other than `completed`, or unreadable) with nothing sent, or every
///                    attempt reached nobody and the failed step's policy (abort, skip_remaining)
///                    ended the run.
///   * `kPartial`     at least one attempt reached an agent but the run is not `kSucceeded`: some
///                    attempt reached nobody, or the engine ended in a status other than
///                    `completed` after a send. A step retried to success still counts its failed
///                    attempt, so such a run reads `partial`: the label errs toward failure.
enum class WorkflowRunOutcome {
    kSucceeded,
    kFailed,
    kPartial,
    kInterrupted,
    kAborted,
};

/// The closed token for `outcome` (`succeeded`, `failed`, `partial`, `interrupted`, `aborted`):
/// the `run_outcome=` audit detail and, for `partial` and `aborted`, the 2xx body's `status`.
[[nodiscard]] std::string_view workflow_run_outcome_token(WorkflowRunOutcome outcome);

/// One dispatch attempt as recorded while the engine drove the steps. Retries and `foreach`
/// expansion produce more than one entry for a step.
struct WorkflowStepDispatchNote {
    std::string instruction_id;
    std::string command_id;
    int agents_reached{0};
    /// Empty when `agents_reached > 0`. Otherwise a `zero_reach_token` ("no_agents_reached",
    /// "quarantined", ...), "late_denied" (the definition changed after the preflight and the
    /// refreshed step no longer passed) or "definition_changed" (it moved off the effect the
    /// approval ticket was bound to).
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
    /// Set for kOk, kRunIncomplete and kNoAgentsReached (the run exists in all), and for kRunFailed when the
    /// engine had admitted the run before the throw ("" otherwise).
    std::string execution_id;
    /// kRunFailed only: a lower bound on the agents the send path had accepted a send to when the
    /// run threw, summed over the steps (0 = none known). Never a receipt.
    int agents_sent{0};
    /// The engine's recorded status after the step loop ("completed", "failed", ...), or
    /// "unknown" when it could not be read back. Dispatch-level only: it says the commands were
    /// SENT, not that any device finished.
    std::string run_status;
    std::vector<WorkflowStepDispatchNote> steps;
    /// A step was refused at dispatch after the preflight (its definition changed); the step's
    /// note reason is `late_denied`, or `definition_changed` when it moved off the ticket-bound
    /// effect.
    bool late_denied{false};
    /// Set for every outcome of a run that finished the step loop (kOk, kNoAgentsReached,
    /// kRunIncomplete); `kSucceeded` for anything else.
    WorkflowRunOutcome run_outcome{WorkflowRunOutcome::kSucceeded};
    /// The run reached its deadline and the engine stopped it: the remaining steps were skipped
    /// and the execution closed `failed`. Always paired with `run_outcome == kAborted`.
    bool deadline_exceeded{false};
    /// The server stopped and the engine ended the run (`kInterrupted`), reason `server_shutdown`.
    bool interrupted{false};
    /// False only when the closing outcome row failed to persist after the run had started.
    bool audit_persisted{true};
};

/// The ONE judgement of how a finished run ended. `run_status` is the engine's recorded status
/// after the step loop ("unknown" when it could not be read back, which is never success).
[[nodiscard]] WorkflowRunOutcome
classify_workflow_run(std::string_view run_status, bool late_denied,
                      const std::vector<WorkflowStepDispatchNote>& steps,
                      bool deadline_exceeded = false, bool interrupted = false);

/// What `admit_workflow_run` decided. `lease` is engaged iff the run is admitted and must be held
/// for the WHOLE run (a stack object in the transport, so a return or a throw releases it);
/// `refusal` is the outcome to render (`kRunCapReached` or `kDraining`) and is set iff `lease` is
/// not. A refusal wrote nothing and read nothing: no audit row (the counter is its only record,
/// like the streamed-POST cap on MCP's own admission), no ticket spent.
struct WorkflowRunAdmission {
    detail::StreamBudget::Lease lease;
    std::optional<WorkflowExecuteOutcome> refusal;
};

/// THE admission step of a synchronous workflow run, one copy for REST v1 and MCP (and the legacy
/// route). Refuses first when the server is draining (`draining` set and true), then leases from
/// `budget` on `SseSurface::kWorkflowRun` keyed by `principal` with the per-principal share
/// `kPerPrincipalWorkflowRun`. Counts `kWorkflowRunRefusedMetric{reason}` on a refusal. A null
/// `budget` is an unmetered seam (a test harness; production always wires the one budget), and
/// then only the draining refusal applies. Never throws for a refusal.
[[nodiscard]] WorkflowRunAdmission
admit_workflow_run(detail::StreamBudget* budget, const std::function<bool()>& draining,
                   const std::string& principal, yuzu::MetricsRegistry* metrics);

/// What `prepare_workflow_execute` hands to `run_workflow_execute`. The run needs only
/// `step_count`: the workflow and its instructions are re-read by the run itself (per step,
/// fresh), so nothing a stale snapshot could widen is carried across. `steps` is for the MCP
/// probe's ticket binding (`workflow_effect_binding`, `workflow_step_effects`) and is never read
/// by the run.
struct WorkflowExecutePlan {
    std::size_t step_count{0};
    /// The instruction each step resolved to, in step order (the preflight's own reads).
    std::vector<WorkflowStepInstruction> steps;
};

/// One step's bound effect: the JSON array `[instruction_id, plugin, action, approval_mode,
/// concurrency_mode]`. Invalid UTF-8 is replaced, not thrown, so two values differing only in
/// invalid bytes bind identically (the `effect_binding` precedent; the authorizer refuses an
/// unknown pair either way).
[[nodiscard]] std::string workflow_step_effect(const WorkflowStepInstruction& def);

/// `workflow_step_effect` for every step, keyed by instruction id.
[[nodiscard]] WorkflowStepEffects workflow_step_effects(const WorkflowExecutePlan& plan);

/// The ticket's effect line for `plan`, ending in `\n`:
/// `effect=["workflow",N,[first K "plugin.action"],"<sha256 over the ordered tuples>"]`. A digest
/// failure returns a `kEffectDigestFailed` outcome (500): the caller refuses the call and mints no
/// ticket. Pure apart from `ports.digest`; no audit row.
[[nodiscard]] std::expected<std::string, WorkflowExecuteOutcome>
workflow_effect_binding(const WorkflowExecutePorts& ports, const WorkflowExecutePlan& plan);

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
/// refusal. A port that throws BEFORE the `requested` row is the caller's to catch (the transports
/// wrap it, and answer retryable: nothing was sent); one that throws after it is answered as
/// `kRunFailed` (see the banner).
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

/// The success body both transports return for a started run (kOk, kRunIncomplete or
/// kNoAgentsReached): `execution_id`, `workflow_id`, `status` and `steps` (one entry per dispatch
/// attempt: `instruction_id`, `command_id`, `agents_reached`, plus `reason`/`retryable` and the
/// withheld counts when nothing was reached), `late_denied`, and `audit_persisted:false` only when
/// the closing audit row failed. `status` is the engine's recorded dispatch-level status
/// (`completed` for a full success). For kRunIncomplete it is the run's outcome token instead
/// (`partial`, `aborted` or `interrupted`), the engine's own status moves to `run_status`, and `message` and
/// `retryable:false` are added: a client that reads only `status` can never mistake an
/// incomplete run for a completed one. One builder so REST and MCP cannot drift on field set.
[[nodiscard]] nlohmann::json workflow_execute_result_json(const WorkflowExecuteOutcome& o,
                                                          const std::string& workflow_id);

/// Adapter from the real store; the returned function holds `store` by pointer, which must
/// outlive it (the server owns the store for the process lifetime). A null `store` yields an
/// empty function.
[[nodiscard]] WorkflowInstructionLookupFn make_instruction_lookup(InstructionStore* store);

} // namespace yuzu::server
