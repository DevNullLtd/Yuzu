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
/// `completed`, no step was refused at send time and every step's FINAL attempt reached an agent
/// (a step that failed and was retried to success counts as reached; a step the engine left failed
/// under `onFailure: continue` does not).
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
/// CREDENTIAL LIVENESS (per-step re-authority, owner ruling D2a). The transport supplies
/// `WorkflowExecuteRequest::reauthorize`, a re-validation of the credential that made the call.
/// The run asks it from the same `before_attempt` hook that carries the deadline (so the engine
/// needs no field of its own): after the deadline test, before each dispatch attempt, i.e. once
/// before each step's first attempt and once on waking from each retry sleep, never per sleep
/// slice. A `foreach` step is asked per item (each item is an attempt). `kValid` and
/// `kValidStale` continue; `kRevoked` stops the run; `kIndeterminate` (or a throw) is asked
/// once more after `reauthorize_retry_delay` (at most `kReauthorizeRetryDelay`, never past the
/// deadline) and a second non-continue answer stops the run, fail closed. A stopped run is
/// answered as `WorkflowRunOutcome::kAborted` with reason `credential_revoked` or
/// `credential_indeterminate`: a typed 2xx `status:"aborted"`, `retryable:false`, even when
/// nothing had been sent; the engine records the unstarted steps `skipped` ("run stopped", the
/// same as a deadline stop) and finalizes the execution `failed` through the guarded UPDATE.
/// WHAT THIS IS NOT. It re-checks that the credential is still live, and the RBAC grants the
/// shared dispatch chokepoint judges anew at every send, so a role removed mid-run is caught
/// there per step. It does NOT re-derive the `DispatchCaller`: `principal_is_admin` (JIT
/// elevation) and `exec_visible` (group scope) are the snapshot taken when the call was taken,
/// so an elevation that expires or a group narrowing during the run is bounded only by the
/// 60 s deadline (D2b, a follow-up). `kValidStale` is accepted for the whole run (at most 60 s).
///
/// AUTHORITY IS ALL-OR-NOTHING, REACH IS PER STEP. Steps 1-4 decide what the CALLER may run and
/// refuse the whole call, sending nothing, when any step fails them. Which DEVICES a step reaches
/// is decided later, per step, at the dispatch chokepoint (visibility, containment, plugin
/// presence, the per-OS kill switch, concurrency claims): a step that then reaches nobody is
/// reported in `steps` with its reason, and an earlier step has already been sent. The preflight
/// does NOT promise that every step will reach a device, only that the caller is allowed to ask.
///
/// IDEMPOTENCY (#2146, ADR-1005 A4). A caller whose response is lost cannot tell "never started"
/// from "started", and a blind re-send dispatches every step twice. So the call carries a client
/// KEY (REST `Idempotency-Key` header, optional; MCP `idempotency_key`, REQUIRED) and a repeat of
/// it is answered with the run the key is bound to, sending nothing:
///   * the key is `[A-Za-z0-9._:-]`, 8 to 128 bytes, bound-checked by the transport BEFORE any
///     ticket, lease or read (`check_workflow_idempotency_key`); it is scoped to the PRINCIPAL
///     (never global) and bound for the life of the run's row. An empty principal never holds a key.
///   * the REQUEST FINGERPRINT is sha256 over `wf-exec-v2\n`, the workflow id and the agent ids
///     SORTED and DEDUPED, each framed as `<byte length>:<bytes>` (no id can forge a separator).
///     It deliberately EXCLUDES the step digest: a later edit to
///     an instruction must not turn a retry into a 422 that pushes the client to a new key, which
///     is a second dispatch. The same key with a different fingerprint is `kIdempotencyConflict`
///     (REST 422, MCP -32602, reason `idempotency_key_conflict`), terminal.
///   * THE PRE-CHECK (`check_workflow_idempotency`) runs after the wiring check and BEFORE the
///     workflow is read or any step is judged (a since-deleted workflow or a raised approval mode
///     must not hide the replay), and the transports run it BEFORE admission, the lease and the
///     approval ticket: a replay is a short read, not a held-open worker, so it is answered while
///     the server drains and when the run cap is full, and a retry with a spent or no ticket gets
///     it without a new approval. A lookup fault is `kStoreFailed` (retryable), nothing written:
///     it must never read as "no run bound".
///   * THE CLAIM is the engine's, atomic with the run's admission (`WorkflowRunControl::
///     idempotency`). A call that passed the pre-check and lost the race has already written its
///     `requested` row; it closes it `denied reason=idempotent_duplicate` (or
///     `idempotency_key_conflict` when the winner's fingerprint differs) and answers as a replay.
///   * THE REPLAY BODY is deliberately THIN (`workflow_idempotent_replay_json`): the run's id,
///     workflow, status, `idempotent_replay:true` and `started_at`. The engine persists no
///     per-step outcome beyond each dispatch's return, so the original response cannot be rebuilt,
///     and a stored copy would be a second source of truth: the caller reads the run with
///     `get_workflow_execution`. `running` carries `retry_after_ms` 2000 and means POLL, never
///     re-send; a `running` row older than `kIdempotentRunStaleAfter` is `indeterminate` (a crash
///     or a dropped finalize leaves it `running` forever), not retryable, no retry hint. Every
///     other status is final, and a deliberate re-run needs a NEW key.
///   * THE REPLAY'S STATUS IS THE FIRST ANSWER'S CLASS, derived from the STORED step results, not
///     from the engine's coarse run status (an `onFailure: continue` step that reached nobody
///     leaves the engine row `completed`). A terminal run is read back (`get_workflow_execution`)
///     and judged by `classify_stored_workflow_run`, which feeds the SAME `classify_workflow_run`
///     the first answer used: `completed` ONLY for `kSucceeded`, else `partial`, `failed`,
///     `aborted` or `interrupted`. What the rows record is enough for every class but one
///     distinction: a run the deadline stopped and a run the credential check stopped are both
///     `aborted` (the replay does not say which), a step refused at send time is recognised by the
///     `late_denied:`/`definition_changed:` prefix of its stored error, and the engine's stop
///     tokens (`kStepReason*`) carry the rest. Anything the rows cannot prove is never
///     `completed`: a completed run with an unsettled or missing step row, or one that cannot be
///     read back, is `indeterminate`; a failed or cancelled run that cannot be read back is
///     `failed`. A step-result write the engine dropped (best effort) therefore costs precision,
///     never correctness.
///   * AUDIT: a terminal replay (every status but `running`) writes one `workflow.execute`
///     `success` row `idempotent_replay=true run_status=<replay status>`; a `running` replay writes NONE
///     (a client polling every 2 s would write 30 rows a minute; the counter is its record). The
///     key is neutralised (`clip_token`) in every detail. `yuzu_server_workflow_run_idempotent_total
///     {outcome=replayed|in_progress|conflict}` counts them.
///   * RETENTION: none. The key lives with its run row and nothing deletes that row; any future
///     prune of the run table owns the clock-guarded-retention obligation.
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
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

// Defined in <yuzu/server/auth.hpp>. Opaquely forward-declared (the underlying type is pinned
// there) so this header stays off the auth header's include cost, as mcp_stream.hpp does.
namespace yuzu::server::auth {
enum class CredentialCheck : int;
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

/// How long a run waits before it asks again when the credential check could not be answered
/// (`kIndeterminate`): one retry, never more, and never past the run's deadline. A request may
/// carry a shorter value (`WorkflowExecuteRequest::reauthorize_retry_delay`, for tests).
inline constexpr std::chrono::milliseconds kReauthorizeRetryDelay{1000};

/// The bounds of a client idempotency key (REST `Idempotency-Key`, MCP `idempotency_key`).
inline constexpr std::size_t kIdempotencyKeyMinLen = 8;
inline constexpr std::size_t kIdempotencyKeyMaxLen = 128;

/// A run that is still `running` this long after it started is answered as `indeterminate`, not
/// `running`: the budget is 60 s, and a row left running past it (the process died after the
/// claim, or the final status write was dropped) would otherwise be polled forever. 180 s is the
/// 60 s run budget plus slack for the longest finalize retry and clock disagreement between replicas.
inline constexpr std::chrono::seconds kIdempotentRunStaleAfter{180};

/// `retry_after_ms` / `Retry-After` of a replay whose run is still in progress: poll the run.
inline constexpr std::int64_t kIdempotentRunningRetryAfterMs = 2000;

/// `yuzu_server_workflow_run_idempotent_total{outcome}`: a repeat of an idempotency key that was
/// answered without sending anything. `replayed` (a terminal run: completed, failed or
/// indeterminate), `in_progress` (the run is still running) and `conflict` (the same key with a
/// different request). A closed set, every member pre-seeded to 0 at boot.
inline constexpr char kWorkflowRunIdempotentMetric[] = "yuzu_server_workflow_run_idempotent_total";
inline constexpr std::array<std::string_view, 3> kWorkflowRunIdempotentOutcomes{
    "replayed", "in_progress", "conflict"};

/// The `status` of a replay body (`workflow_idempotent_replay_json`). A closed set.
inline constexpr std::string_view kReplayRunning = "running";
inline constexpr std::string_view kReplayCompleted = "completed";
inline constexpr std::string_view kReplayPartial = "partial";
inline constexpr std::string_view kReplayFailed = "failed";
inline constexpr std::string_view kReplayAborted = "aborted";
inline constexpr std::string_view kReplayInterrupted = "interrupted";
inline constexpr std::string_view kReplayIndeterminate = "indeterminate";

/// The prefixes the dispatch callback puts on the error of a step it refuses at send time, so the
/// stored step result (`{"error": ...}`) says why long after the run's memory is gone:
/// `late_denied:` (the refreshed step no longer passes admission) and `definition_changed:` (it
/// moved off the effect the approval ticket was bound to). `classify_stored_workflow_run` reads
/// them back; they are a contract, not decoration.
inline constexpr std::string_view kStepErrorLateDenied = "late_denied: ";
inline constexpr std::string_view kStepErrorDefinitionChanged = "definition_changed: ";

/// The closing reasons of a run the credential check stopped (`WorkflowExecuteOutcome::reason`,
/// the closing audit row's `reason=` and the 2xx body's `reason`). A closed pair.
inline constexpr std::string_view kReasonCredentialRevoked = "credential_revoked";
inline constexpr std::string_view kReasonCredentialIndeterminate = "credential_indeterminate";

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
    /// Optional: the digest behind the idempotency request fingerprint (default: `sha256_hex`).
    /// Its own seam, not `digest`, so the effect-binding refusal and the fingerprint refusal can
    /// each be driven alone: an MCP call always carries a key, so with one shared seam the
    /// fingerprint would fail first and the effect-binding failure could never be reached.
    WorkflowDigestFn fingerprint_digest;
    /// Optional: bumps `yuzu_server_dispatch_target_rejected_total{route="workflow",reason}`.
    std::function<void(std::string_view reason)> count_target_rejected;
    /// Optional: bumps `yuzu_server_dispatch_denied_total{reason}` with the chokepoint's own
    /// denial token (`forbidden`, `approval_required`, `kill_switched`, ...).
    std::function<void(std::string_view reason)> count_dispatch_denied;
    /// Optional: bumps `yuzu_server_dispatch_fanout_throw_total{route="workflow",phase="dispatch"}`
    /// when a run throws after its `requested` row.
    std::function<void()> count_run_threw;
    /// Optional: bumps `yuzu_server_workflow_run_idempotent_total{outcome}`.
    std::function<void(std::string_view outcome)> count_idempotent;
    /// Optional: epoch seconds now, to age a `running` replay against `started_at` (default: the
    /// system clock, the clock the engine stamped `started_at` with). A seam for the stale test.
    std::function<std::int64_t()> now_epoch;
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
    /// Re-asks whether the caller's CREDENTIAL is still live (`AuthRoutes::revalidate_stream`
    /// against the principal and the request that started the call). The run asks it from its
    /// `before_attempt` hook: before every dispatch attempt, which is once before each step's
    /// first attempt and once on waking from each retry sleep (never per sleep slice). `kValid`
    /// and `kValidStale` continue; `kRevoked` stops the run; `kIndeterminate` is asked once
    /// more after `reauthorize_retry_delay` and then stops the run (fail closed). A throw is
    /// `kIndeterminate`. Unset == no check (an unmetered seam like `StreamBudget*` on the
    /// siblings): production transports always set it. It is a LIVENESS check, not an authority
    /// re-derivation: the `DispatchCaller` above is not rebuilt, so see the banner.
    std::function<auth::CredentialCheck()> reauthorize;
    /// The wait before the single retry of an indeterminate `reauthorize` answer.
    std::chrono::milliseconds reauthorize_retry_delay{kReauthorizeRetryDelay};
    /// The client's idempotency key, already bound-checked by the transport
    /// (`check_workflow_idempotency_key`). Empty == a keyless call, whose behaviour is unchanged.
    /// Non-empty requires a non-empty `caller.principal`, whatever `caller.system` says.
    std::string idempotency_key;
    /// The transport ran `check_workflow_idempotency` itself (it must, before admission) and
    /// found no run bound, so `apply_workflow_execute` need not read it a second time. A run that
    /// raced past the pre-check is still caught by the engine's atomic claim.
    bool idempotency_prechecked{false};
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
    kOk,                         ///< the run COMPLETED and every step's final attempt reached an agent (202)
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
    kIdempotentReplay,           ///< the idempotency key is bound to a run: answered with the thin replay body, nothing sent (202)
    kIdempotencyConflict,        ///< the key is bound to a DIFFERENT request (422, terminal, nothing sent)
};

/// How a run that reached the engine ended, judged from what the engine recorded and what the
/// steps did. `kSucceeded` is the ONLY value that labels the closing `workflow.execute` row
/// `success`; every other value labels it `failure` and rides in the row's detail as
/// `run_outcome=<token>` (`workflow_run_outcome_token`). A run is judged by each step's FINAL
/// outcome, never by its attempts (see `WorkflowStepFinal`), and is `kSucceeded` only if ALL of:
/// the engine's recorded status is `completed`, no step was refused at send time
/// (`late_denied`), and every step's final attempt reached at least one agent. The others,
/// tested in this order:
///   * `kAborted`     a step was refused at send time (`late_denied`): its definition moved off the
///                    preflight or off the ticket-bound effect, or it no longer passed admission;
///                    OR the run reached its deadline (`kWorkflowSyncBudget`) and the engine
///                    stopped it (`deadline_exceeded`); OR the credential check stopped it
///                    (`credential_stop`: the caller's credential was revoked, or could not be
///                    confirmed after the one retry). Takes precedence: the run was cut short,
///                    whatever else it did.
///   * `kInterrupted` the engine ended the run because the server is stopping (the engine told the
///                    sequence through `WorkflowRunControl::on_interrupted`, at the moment it
///                    acted): the unstarted steps are skipped `server_shutdown` and the execution
///                    is closed `failed`. Typed 2xx `status:"interrupted"`, reason
///                    `server_shutdown`, `retryable:false`, whether or not anything was sent.
///                    A server that is merely DRAINING does not interrupt a run.
///   * `kFailed`      nothing was sent: the engine ended `failed` (or in any status other than
///                    `completed`, or unreadable) with nothing sent, or every attempt reached
///                    nobody and the failed step's policy (abort, skip_remaining) ended the run;
///                    also a run whose dispatch callback THREW (the stored rows say so), whatever
///                    it had sent before.
///   * `kPartial`     at least one step reached an agent but the run is not `kSucceeded`: some
///                    step's final attempt reached nobody (an `onFailure: continue` step the
///                    engine left failed), or the engine ended in a status other than `completed`
///                    after a send.
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
    /// The step's `WorkflowStep::index` and the 1-based attempt this entry is, both announced by
    /// the engine through `WorkflowRunControl::on_attempt`. `step_index` stays -1 (and `attempt`
    /// 1) for a run port that never announces one: such an entry is then its own step. The
    /// `attempt` is in the response `steps` entry so a reader can tell a retry from a new step.
    int step_index{-1};
    int attempt{1};
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
    /// The credential check stopped the run: `kReasonCredentialRevoked` or
    /// `kReasonCredentialIndeterminate`, empty otherwise. Always paired with `run_outcome ==
    /// kAborted` and `status == kRunIncomplete`, even when nothing had been sent.
    std::string credential_stop;
    /// False only when the closing outcome row failed to persist after the run had started.
    bool audit_persisted{true};
    /// kIdempotentReplay only: the run the key is bound to answered instead of a new one.
    /// `replay_status` is one of kReplayRunning/Completed/Failed/Indeterminate, `run_status` the
    /// engine's own, `started_at` the run's start (epoch seconds).
    bool idempotent_replay{false};
    std::string replay_status;
    std::int64_t started_at{0};
};

/// One step's FINAL outcome: what it came to after its last attempt, which is what the engine
/// itself recorded for the step. A step whose first attempt reached nobody and whose retry
/// reached an agent is `reached` (the run did not fail there); a step the engine left failed is
/// not, whatever it did before. `foreach`: an attempt is every item of one attempt number, and
/// the step is `reached` only if EVERY item of its last attempt reached an agent, exactly the
/// engine's own rule for a step to succeed (today's engine sends one item: a dispatch
/// acknowledgement has no array to iterate). Steps the run never attempted (skipped by a
/// condition, or after an abort) have no final.
struct WorkflowStepFinal {
    int step_index{-1};
    int attempt{1}; ///< the last attempt the step made
    bool reached{false}; ///< the last attempt reached an agent on every dispatch it made
    bool sent{false};    ///< any attempt of the step reached an agent: something left the server
};

/// What cut a run short or marked it, besides how its steps ended. All independent; the
/// classifier's precedence orders them (`threw`, then `late_denied`/`bound_stop`, then
/// `interrupted`).
struct WorkflowRunFacts {
    /// A step was refused at send time (`late_denied` / `definition_changed`).
    bool late_denied{false};
    /// The deadline, or the caller's credential check, stopped the run. Both are `kAborted`, so the
    /// classifier never needs to tell them apart.
    bool bound_stop{false};
    /// The stopping server ended the run.
    bool interrupted{false};
    /// A dispatch callback threw. The first answer never sets this (a throw is answered as
    /// `kRunFailed` before any classification); the replay recovers it from the stored rows.
    bool threw{false};
};

/// The ONE judgement of how a run ended, for the first answer AND the idempotent replay, over
/// per-step FINAL outcomes. `run_status` is the engine's recorded status ("unknown" when it could
/// not be read back, which is never success). No `finals` and `completed` is `kSucceeded` (every
/// step skipped by its condition).
[[nodiscard]] WorkflowRunOutcome
classify_workflow_run(std::string_view run_status, const WorkflowRunFacts& facts,
                      const std::vector<WorkflowStepFinal>& finals);

/// The finals of a run from its dispatch notes and the last attempt the engine announced for each
/// step (`attempts`: step index -> attempt; `WorkflowRunControl::on_attempt`). A step is `reached`
/// iff it has at least one note at its last attempt and every note of that attempt reached an
/// agent; an announced attempt with no note (the run was stopped first, the dispatch failed before
/// it recorded one) is not reached. A note with no step index is its own step.
[[nodiscard]] std::vector<WorkflowStepFinal>
workflow_step_finals(const std::vector<WorkflowStepDispatchNote>& notes,
                     const std::map<int, int>& attempts);

/// The class a STORED run ended in, from the rows the engine persisted (`get_workflow_execution`):
/// the same `classify_workflow_run` over the stored per-step results, with the facts recovered
/// from the stored step texts. `nullopt` == the rows cannot prove an outcome: the engine says
/// `completed` and a step row is still `pending`/`running`, unknown or absent, or carries a skip
/// other than the condition's. Never `kSucceeded` unless every attempted step is `success`.
[[nodiscard]] std::optional<WorkflowRunOutcome>
classify_stored_workflow_run(const WorkflowExecution& stored);

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

/// Run the sequence in the header banner: the idempotency pre-check (unless the transport ran
/// it), prepare, then run. Never throws for an expected
/// refusal. A port that throws BEFORE the `requested` row is the caller's to catch (the transports
/// wrap it, and answer retryable: nothing was sent); one that throws after it is answered as
/// `kRunFailed` (see the banner).
[[nodiscard]] WorkflowExecuteOutcome apply_workflow_execute(const WorkflowExecutePorts& ports,
                                                            const WorkflowExecuteRequest& req);

/// Shape-checks the workflow id a transport received, reason `invalid_workflow_id` (REST 400, MCP
/// -32602, never retryable): 1 to `kExecInstrIdentMaxLen` bytes, no control byte (NUL included),
/// valid UTF-8 (`definition_id_is_malformed`, the instruction twin's own step-0 predicate). The
/// transport calls it BEFORE any read, lease, ticket or fingerprint: the Postgres binding passes
/// the id as a C string, so `"foo\0xyz"` would run workflow `foo` under audit, fingerprint and
/// ticket records of a different string, and an invalid-UTF-8 id raises SQLSTATE 22021, which
/// would read as a retryable 503 for an input that can never succeed. The message never echoes
/// the id. `nullopt` == fine.
[[nodiscard]] std::optional<WorkflowExecuteBodyError> check_workflow_id(std::string_view id);

/// Bound-checks a client idempotency key: 8 to 128 bytes of `[A-Za-z0-9._:-]`. `nullopt` == fine.
/// The transport calls it before any ticket, lease or read, so a bad key spends nothing. The
/// message names the rule and never echoes the key.
[[nodiscard]] std::optional<WorkflowExecuteBodyError>
check_workflow_idempotency_key(std::string_view key);

/// The request fingerprint stored with a claim and compared on a repeat: sha256 over
/// `wf-exec-v2\n` followed by the workflow id and then each agent id (sorted, deduped), each
/// written as `<decimal byte length>:<bytes>`. The length prefix makes the framing unambiguous
/// for any bytes, so no choice of ids can make two different requests share a preimage.
/// `nullopt` on a digest failure (never a digest of zeros): the caller refuses the call.
[[nodiscard]] std::optional<std::string>
workflow_request_fingerprint(const WorkflowExecutePorts& ports, const std::string& workflow_id,
                             const std::vector<std::string>& agent_ids);

/// The idempotency pre-check (see the banner). `nullopt` == proceed: the call is keyless, or no run
/// is bound to its key. Otherwise the outcome to render: `kIdempotentReplay`,
/// `kIdempotencyConflict`, `kStoreFailed` (the lookup failed: retryable, nothing written),
/// `kUnavailable`/`kNoPrincipal` (wiring or an empty principal) or `kEffectDigestFailed` (the
/// fingerprint could not be computed: audited, no ticket). Writes at most one audit row (a terminal
/// replay, a conflict or a digest failure) and bumps the idempotent counter; never dispatches.
[[nodiscard]] std::optional<WorkflowExecuteOutcome>
check_workflow_idempotency(const WorkflowExecutePorts& ports, const WorkflowExecuteRequest& req);

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
/// attempt: `instruction_id`, `attempt` (1-based; a retry of a step has the next number, and a
/// new step starts again at 1), `command_id`, `agents_reached`, plus `reason`/`retryable` and the
/// withheld counts when nothing was reached), `late_denied`, and `audit_persisted:false` only when
/// the closing audit row failed. `status` is the engine's recorded dispatch-level status
/// (`completed` for a full success). For kRunIncomplete it is the run's outcome token instead
/// (`partial`, `aborted` or `interrupted`), the engine's own status moves to `run_status`, and `message` and
/// `retryable:false` are added: a client that reads only `status` can never mistake an
/// incomplete run for a completed one. One builder so REST and MCP cannot drift on field set.
[[nodiscard]] nlohmann::json workflow_execute_result_json(const WorkflowExecuteOutcome& o,
                                                          const std::string& workflow_id);

/// The THIN body of a `kIdempotentReplay` outcome, for both transports: `execution_id`,
/// `workflow_id`, `status` (running | completed | partial | failed | aborted | interrupted |
/// indeterminate), `idempotent_replay:true` and `started_at`, plus a `message`; `retry_after_ms`
/// 2000 while running; `retryable:false` and (for indeterminate) a `remediation` otherwise. No
/// `reason`: the rows do not say which of the deadline and the credential check stopped an
/// `aborted` run. NO `steps` and no `late_denied`: the engine does
/// not persist them, so read the run with `get_workflow_execution`.
[[nodiscard]] nlohmann::json workflow_idempotent_replay_json(const WorkflowExecuteOutcome& o,
                                                             const std::string& workflow_id);

/// Adapter from the real store; the returned function holds `store` by pointer, which must
/// outlive it (the server owns the store for the process lifetime). A null `store` yields an
/// empty function.
[[nodiscard]] WorkflowInstructionLookupFn make_instruction_lookup(InstructionStore* store);

} // namespace yuzu::server
