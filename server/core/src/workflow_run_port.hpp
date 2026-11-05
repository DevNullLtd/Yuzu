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
/// "workflow not found: ..." / "workflow has no steps".
///
/// The port has NO authorization, confinement, approval-mode or audit logic of its own: the
/// caller decides all of that before the call and supplies a `dispatch_fn` that confines each step
/// to the caller. Calling it directly would dispatch to the named agents unconfined.

#include "workflow_types.hpp"

#include <chrono>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Per-run controls. Every member is optional and an unset member is no hook, so a caller that
/// sets none gets the engine's plain behaviour. The engine adapter consumes the members it
/// supports; a member it does not yet consume is ignored. Members are added here as the engine
/// gains the matching hook, so the port signature never changes.
struct WorkflowRunControl {
    /// Called once with the new run's execution id after the engine has admitted the run and
    /// before the first step is dispatched.
    std::function<void(const std::string& execution_id)> on_admitted;
    /// Called before every dispatch attempt; `false` stops the run.
    std::function<bool()> before_attempt;
    /// Wall-clock bound for the whole run (steady clock; retry sleeps count against it).
    std::optional<std::chrono::steady_clock::time_point> deadline;
    /// Polled between attempts and during retry sleeps; `true` stops the run.
    std::function<bool()> should_stop;
};

using WorkflowRunFn = std::function<std::expected<std::string, std::string>(
    const std::string& workflow_id, const std::vector<std::string>& agent_ids,
    StepDispatchFn dispatch_fn, ConditionEvalFn condition_fn, const WorkflowRunControl& control)>;

} // namespace yuzu::server
