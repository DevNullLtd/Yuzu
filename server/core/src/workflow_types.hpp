#pragma once

/// @file workflow_types.hpp
/// Pure POD types for the multi-step workflow read surface (ADR-0031 WS-A4,
/// the EIGHTH family through the seam — `WorkflowApi`, `workflow_api.hpp`).
/// Relocated out of `workflow_engine.hpp` (which `#include`s this back, so
/// every existing includer keeps seeing these types transitively — an
/// ODR-safe relocation, not a duplication, mirroring `schedule_types.hpp`'s
/// split out of `schedule_engine.hpp` and `compliance_types.hpp`'s out of
/// `policy_store.hpp`) so the abstract `workflow_api.hpp` can depend on them
/// without ever reaching the Postgres-backed `WorkflowEngine` class or its
/// `pg::PgPool&` constructor dependency.
///
/// No I/O, no store type, std-only plus the equally pure `list_keyset.hpp` — safe for a future
/// presentation-side client to include directly.

#include "list_keyset.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

struct WorkflowStep {
    int index{0};
    std::string instruction_id;     // InstructionDefinition ID to execute
    std::string condition;          // CEL/compliance expression — skip step if false
    int retry_count{0};             // Number of retries on failure
    int retry_delay_seconds{5};     // Delay between retries
    std::string foreach_source;     // If set, expand step per result item from previous step
    std::string label;              // Human-readable step label
    std::string on_failure;         // "abort" (default), "continue", "skip_remaining"
};

struct Workflow {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::vector<WorkflowStep> steps;
    int64_t created_at{0};
    int64_t updated_at{0};
};

// ── Dispatch callback type ───────────────────────────────────────────────────
// The workflow engine invokes this callback to dispatch a step to agents.
// Returns a JSON result string on success, or a StepDispatchError on failure.
// (Relocated from workflow_engine.hpp so the store-free run port, `workflow_run_port.hpp`, can name
// it without reaching the Postgres-backed engine class; std-only, so the pure-header rule holds.)

/// Why a step dispatch failed. `permanent` means no retry can succeed (a refusal of the caller's
/// authority, a definition that changed under the run, a spent deadline): the engine records the
/// step failed and applies its `on_failure` policy at once, with no retry and no retry sleep.
/// Constructible from a string, meaning TRANSIENT, so a callback that returns
/// `std::unexpected(std::string)` keeps its meaning (the step is retried `retry_count` times).
struct StepDispatchError {
    std::string message;
    bool permanent{false};

    StepDispatchError() = default;
    StepDispatchError(std::string m, bool is_permanent = false)
        : message(std::move(m)), permanent(is_permanent) {}
    StepDispatchError(const char* m) : message(m) {}
};

using StepDispatchFn = std::function<std::expected<std::string, StepDispatchError>(
    const std::string& instruction_id,
    const std::string& agent_ids_json,
    const std::string& parameters_json)>;

// ── Condition evaluator callback type ────────────────────────────────────────
// Evaluates a compliance/CEL expression against result fields.
// Returns true if the condition is satisfied.
using ConditionEvalFn = std::function<bool(
    const std::string& expression,
    const std::map<std::string, std::string>& result_fields)>;

enum class WorkflowExecutionStatus {
    kPending,
    kRunning,
    kCompleted,
    kFailed,
    kCancelled
};

enum class StepStatus {
    kPending,
    kRunning,
    kSuccess,
    kFailed,
    kSkipped
};

struct WorkflowStepResult {
    int step_index{0};
    std::string instruction_id;
    std::string status;         // "pending", "running", "success", "failed", "skipped"
    std::string result_json;    // JSON output from step execution
    int64_t started_at{0};
    int64_t completed_at{0};
    int attempt{1};             // Current attempt number (for retries)
};

struct WorkflowExecution {
    std::string id;
    std::string workflow_id;
    std::string status;         // "pending", "running", "completed", "failed", "cancelled"
    // JSON array of the DISTINCT agent IDs the run named, capped, with one trailing marker object on
    // a truncated copy (`stored_agent_ids_json`); the run itself targets the full list.
    std::string agent_ids_json;
    int64_t started_at{0};
    int64_t completed_at{0};
    int current_step{0};

    // Populated by get_execution()
    std::vector<WorkflowStepResult> step_results;
};

/// The run a client's idempotency key is bound to (`WorkflowIdempotencyLookupFn`, workflow_run_port.hpp): just
/// enough to answer a repeat of the call without reading the run's steps. `request_fingerprint`
/// is the opaque value the claim stored (workflow_execute.hpp computes it).
struct WorkflowIdempotentRun {
    std::string execution_id;
    std::string workflow_id;
    std::string request_fingerprint;
    std::string status; // the engine's recorded status: "running", "completed", "failed", ...
    int64_t started_at{0}; // epoch seconds, as WorkflowExecution::started_at
};

struct WorkflowQuery {
    std::string name_filter;
    int limit{100};
};

/// One row of the workflow-execution LIST (`WorkflowEngine::query_executions_page`). Metadata
/// only: deliberately no `agent_ids` (can be ~100k ids and names the fleet), no step results and
/// no `agents_reached` — a list row never discloses fleet size or out-of-scope agent ids to a
/// confined caller.
struct WorkflowExecutionSummary {
    std::string id;
    std::string workflow_id;
    std::string workflow_name;
    bool workflow_deleted{false}; // ADR-0064: a soft-deleted workflow keeps its history
    std::string status;           // "pending", "running", "completed", "failed", "cancelled"
    int current_step{0};
    int64_t started_at{0};
    int64_t completed_at{0};
};

/// Filters, paging and mode of one workflow-execution list read. Pure data — the caller validates
/// it (strict keys, bounds, cursor) before it reaches the store; the store clamps `limit` again as
/// defence in depth.
struct WorkflowExecutionListQuery {
    std::string workflow_id;             // exact filter; empty = every workflow
    std::string status;                  // exact filter; empty = every status
    std::optional<int64_t> since;        // started_at >= since (epoch seconds)
    std::optional<int64_t> until;        // started_at <  until (epoch seconds)
    int limit{50};                       // page size (rows), 1..kWorkflowExecutionListMax
    std::optional<keyset::Position> after; // resume strictly after this (started_at, id)
    /// At most one row per workflow: its newest run among those passing every other filter AND the
    /// caller's visibility. Ordered by workflow id, not paged (no `after`).
    bool latest_per_workflow{false};
};

inline constexpr int kWorkflowExecutionListMax = 500;

struct WorkflowExecutionPage {
    std::vector<WorkflowExecutionSummary> rows;
    /// Set only in the newest-first mode, only when more rows exist: the position of the last
    /// row returned. Derived from a row the caller was allowed to see, never from a hidden one.
    std::optional<keyset::Position> next;
    /// `latest_per_workflow` only: more workflows matched than `limit` allowed.
    bool truncated_by_cap{false};
};

} // namespace yuzu::server
