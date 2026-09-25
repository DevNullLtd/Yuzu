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
/// No I/O, no store type, std-only — safe for a future presentation-side
/// client to include directly.

#include <cstdint>
#include <string>
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
    std::string agent_ids_json; // JSON array of target agent IDs
    int64_t started_at{0};
    int64_t completed_at{0};
    int current_step{0};

    // Populated by get_execution()
    std::vector<WorkflowStepResult> step_results;
};

struct WorkflowQuery {
    std::string name_filter;
    int limit{100};
};

} // namespace yuzu::server
