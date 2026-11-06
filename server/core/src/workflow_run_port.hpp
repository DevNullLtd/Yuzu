#pragma once

/// @file workflow_run_port.hpp
/// The core-internal port through which the shared workflow-execute sequence
/// (`workflow_execute.hpp`) starts a run. It is NOT part of `WorkflowApi`: that seam is the
/// public, versioned READ surface (ADR-0031 B3, INV-31-4), and a method taking an in-process
/// step callback is not HTTP-shaped. server.cpp builds one `WorkflowRunFn` from `workflow_engine_`
/// and hands the same closure to the REST route deps and to the MCP server (the shape of
/// `set_workflow_concurrency_dispatch_fn`); a null function is "engine not available".
///
/// The engine admits the run, calls `dispatch_fn` for each step SYNCHRONOUSLY on the calling
/// thread (retry sleeps included), and returns the execution id once the step loop has finished.
/// A failed step is recorded in the execution, not returned. `std::unexpected` carries the
/// engine's own text: a `kDbErrorPrefix` store failure (genericize before display) or
/// "workflow not found: ..." / "workflow has no steps". A THROW out of `dispatch_fn`,
/// `condition_fn` or `control.on_admitted` is not returned either: the engine first closes the
/// run `failed` (the unstarted steps skipped) and then RETHROWS, so the port propagates the
/// exception to its caller after the finalize and never answers it as a value. Once
/// `control.on_admitted` has fired the port never returns `std::unexpected` at all: it returns the
/// execution id or rethrows, so every `std::unexpected` (a store failure, "not found", an
/// idempotent replay) means NOTHING was admitted or dispatched.
///
/// The idempotency pre-check (`WorkflowIdempotencyLookupFn`, below) is the second core-internal
/// port of the execute sequence and lives here for the same reason: it is not a public resource.
///
/// The port has NO authorization, confinement, approval-mode or audit logic of its own: the
/// caller decides all of that before the call and supplies a `dispatch_fn` that confines each step
/// to the caller. Calling it directly would dispatch to the named agents unconfined.

#include "dispatch_caller.hpp" // DispatchCaller: the lookup is asked on behalf of a caller
#include "workflow_types.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// What the server's shutdown asks of a run in flight. Ordered: a higher level includes the lower.
///   * `kNone`      nothing: the run is untouched.
///   * `kDraining`  the server is draining (its listener is held open for in-flight work): a run
///                  abandons any retry it has not yet made (the pending retry is treated as
///                  exhausted and no delay is slept) but KEEPS dispatching its remaining steps.
///   * `kStop`      the server is stopping: nothing more is dispatched. The run is finalized
///                  `failed`, its unstarted steps are marked skipped with reason
///                  `server_shutdown`, and the caller is told through `on_interrupted`.
enum class WorkflowStopLevel {
    kNone,
    kDraining,
    kStop,
};

/// A client's idempotency claim on a run: the key is bound to `principal` for the life of the
/// run's row, and `fingerprint` is what the claim stores so a repeat of the key can be told from a
/// DIFFERENT request under the same key. All three are required together (the store's CHECK
/// refuses a key without the other two). Built by `workflow_execute.cpp`; the engine only stores
/// and compares them.
struct WorkflowIdempotencyClaim {
    std::string principal;
    std::string key;
    std::string fingerprint;
};

/// The run an idempotency claim lost to: reported through `WorkflowRunControl::on_replay` when the
/// engine finds the key already bound, in the same transaction as the lost claim. Nothing was
/// written and nothing will be dispatched; the run port then returns `std::unexpected` whose text
/// starts with `kWorkflowIdempotentReplayError`.
struct WorkflowRunReplay {
    std::string execution_id;
    std::string workflow_id;
    std::string fingerprint;
    std::string status;
    std::int64_t started_at{0};
};

/// The `reason` token the engine writes into a step's stored result when it stops or fails a run
/// (`workflow_step_results.result_json`). They are the contract between the engine that writes
/// them and the reader that classifies a stored run (the idempotent replay,
/// `workflow_execute.cpp`): `run stopped` is a run the deadline or the caller's credential check
/// ended, `server_shutdown` a run the stopping server ended, `dispatch_exception` a step whose
/// dispatch callback threw, `condition not met` a step skipped by its own condition (the one
/// skip a completed run legitimately holds). The text beside them (`error`) is for people.
inline constexpr char kStepReasonRunStopped[] = "run stopped";
inline constexpr char kStepReasonServerShutdown[] = "server_shutdown";
inline constexpr char kStepReasonDispatchException[] = "dispatch_exception";
inline constexpr char kStepReasonConditionNotMet[] = "condition not met";

/// The error text a run port returns when `on_replay` was called. A caller that set `on_replay`
/// reads the replay from there and must not parse this text.
inline constexpr char kWorkflowIdempotentReplayError[] = "idempotent replay";

/// Per-run controls. Every member is optional and an unset member is no hook, so a caller that
/// sets none gets the engine's plain behaviour. The engine consumes the members it supports; a
/// member it does not yet consume is ignored, which for the safety hooks would be a silent
/// fail-open, so each consumed member has its own test that sets only that member
/// (`test_workflow_engine.cpp`, "every run-control hook is consumed"). Members are added here as
/// the engine gains the matching hook, so the port signature never changes. `on_admitted` is read
/// from here only: `WorkflowEngine::execute` has no separate parameter for it.
///
/// Consumed today: `on_admitted`, `on_attempt`, `before_attempt`, `deadline`, `should_stop`,
/// `on_interrupted`, `idempotency`, `on_replay`, `principal`, `correlation_id` and
/// `stored_copy_first`.
struct WorkflowRunControl {
    /// Called once with the new run's execution id after the engine has admitted the run and
    /// before the first step is dispatched.
    std::function<void(const std::string& execution_id)> on_admitted;
    /// Called before every dispatch attempt (each retry and each foreach item included), ahead of
    /// `before_attempt`, with the step's `WorkflowStep::index` and the 1-based attempt number (the
    /// items of one `foreach` attempt share it). It is how a caller that records what each
    /// dispatch did attributes it to a step: the dispatch callback itself is told only the
    /// instruction id, and a workflow may name one instruction in several steps. An attempt the
    /// hook announced but the dispatch callback never answered (the run was stopped, the callback
    /// failed before it recorded anything) is still an attempt of that step.
    std::function<void(int step_index, int attempt)> on_attempt;
    /// Called before every dispatch attempt (each retry and each foreach item included); `false`
    /// stops the run: the attempt is not made, the step is recorded failed, the remaining steps
    /// are skipped and the execution is finalized `failed`. The caller records why it said no.
    std::function<bool()> before_attempt;
    /// Wall-clock bound for the whole run (steady clock). It always cuts a retry delay to the time
    /// left. It stops an attempt at or after it, with the same stop as `before_attempt`, ONLY when
    /// `before_attempt` is unset: a caller that installs the hook owns the decision (and the reason
    /// it recorded), and the engine does not compare the clock a second time. A dispatch already
    /// in flight is not interrupted.
    std::optional<std::chrono::steady_clock::time_point> deadline;
    /// Polled at the top of every step and every attempt and during retry sleeps (at most one
    /// sliced wait, `kInterruptibleWaitSlice`, behind a change). The engine also holds an
    /// engine-level default (`WorkflowEngine::set_should_stop`, the server's shutdown state) and
    /// acts on the HIGHER of the two answers. See `WorkflowStopLevel`.
    std::function<WorkflowStopLevel()> should_stop;
    /// Called once, from the engine, when it ENDS the run because the level read `kStop`: the
    /// caller learns the run was interrupted at the moment the engine acted, never inferred
    /// afterwards. Not called for `kDraining` (the run goes on) or for a deadline.
    std::function<void()> on_interrupted;
    /// Unset == a keyless run (the legacy route, and any caller that sent no key): admission is
    /// exactly what it was. Set: the engine claims `(principal, key)` ATOMICALLY with the run's
    /// admission, in the one transaction that creates the execution row. There are three
    /// outcomes, and none is a retry: ADMITTED (the run goes on, the row carries the claim);
    /// REPLAY (the key is already bound to a run: `on_replay` is called with that run and the
    /// port returns `std::unexpected` starting with `kWorkflowIdempotentReplayError`; nothing was
    /// written); NOT FOUND (no run is bound to the key and the workflow is gone or
    /// soft-deleted: the ordinary "workflow not found" error, never mistaken for a replay).
    std::optional<WorkflowIdempotencyClaim> idempotency;
    /// Called once with the run the key is bound to, when the claim found one. Required to be set
    /// with `idempotency` (the caller has no other way to tell a replay from an error).
    std::function<void(const WorkflowRunReplay&)> on_replay;
    /// Who started the run and under which call, stored on the run's own row whether or not the
    /// call is keyed, so an unkeyed run still names its actor and an audit row that carries only
    /// the call's `correlation_id=` (the `requested` row, which is written before any execution id
    /// exists) joins to the run. Empty stores NULL (the legacy route and any caller that sets
    /// neither). For a KEYED run the stored principal is `idempotency->principal` (the key's
    /// namespace), which the sequence sets to the same value. Never consulted for admission.
    std::string principal;
    std::string correlation_id;
    /// Which of the named agent ids the run row's stored copy keeps FIRST when the list is longer
    /// than `kStoredAgentIdsMax` (`stored_agent_ids_json`, workflow_model.hpp). Storage only: the
    /// run always targets the full list. A confined caller sets it to its own dispatch
    /// (`Execution:Execute`) visible set, which keeps the run visible to that caller only while
    /// that set lies within the scope its reads are checked against (`Workflow:Read`); unset keeps
    /// the first ids in request order.
    std::function<bool(const std::string&)> stored_copy_first;
};

using WorkflowRunFn = std::function<std::expected<std::string, std::string>(
    const std::string& workflow_id, const std::vector<std::string>& agent_ids,
    StepDispatchFn dispatch_fn, ConditionEvalFn condition_fn, const WorkflowRunControl& control)>;

/// The run `caller`'s idempotency key is bound to, or `nullopt` when none is: the pre-check
/// behind a repeat of `POST /api/v1/workflows/{id}/execute` / `execute_workflow`, which answers
/// with that run instead of starting another. It is a core-internal port beside `WorkflowRunFn`,
/// NOT a `WorkflowApi` method: it is the read half of the execute operation, not a public
/// resource, and a method taking a principal on the versioned read seam would let any presentation
/// or MCP caller ask about another principal's keys (ADR-0031 B3, INV-31-4). The principal is the
/// authenticated `caller`'s own (`caller.principal`); a key is bound per principal, so the
/// question can only ever be "has THIS caller already run this key". The execute sequence asks it
/// only with the `DispatchCaller` its transport derived, never with a principal read from a
/// request. Returns run metadata, no steps and no agent ids. `std::unexpected` is a genuine read
/// failure (a `kDbErrorPrefix` store text, genericize before display) and is NEVER "no run
/// bound": the sequence refuses the call, retryable, rather than risk a second dispatch. A null
/// function is "engine not available".
using WorkflowIdempotencyLookupFn =
    std::function<std::expected<std::optional<WorkflowIdempotentRun>, std::string>(
        const DispatchCaller& caller, const std::string& idempotency_key)>;

} // namespace yuzu::server
