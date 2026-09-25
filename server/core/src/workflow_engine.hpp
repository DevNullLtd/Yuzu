#pragma once

/// @file workflow_engine.hpp
/// Postgres-backed multi-step instruction orchestration store (ADR-0006/0009/0064). Schema
/// `workflow_engine`, four tables (`workflows`, `workflow_steps`, `workflow_executions`,
/// `workflow_step_results`).
///
/// Posture (ADR-0012 §1): fail-CLOSED construction — a reachable database whose schema can't
/// migrate/open is a fatal startup error (`startup_failed_`), a posture UPGRADE from the SQLite
/// era (construction was unconditional/best-effort, `is_open()` was never checked by any caller).
///
/// Delete semantics (ADR-0064): `delete_workflow` SOFT-deletes (`workflows.deleted_at` stamped,
/// row never physically removed) — a workflow that has ever executed keeps its execution history
/// attached and queryable forever; a soft-deleted workflow is treated as absent by every ordinary
/// read (`get_workflow`/`list_workflows`) and cannot start a new execution (enforced atomically at
/// admission — see `execute()`). This is a deliberate product decision, not a mechanical FK port —
/// see ADR-0064 "Delete semantics" for the full reasoning (verified `/codex opine` review).
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment). The legacy
/// `workflows.db` is never read for data; construction logs a one-time "fresh start, no legacy
/// backfill" line, and the caller (`server.cpp`) runs `legacy_sqlite_probe::warn_if_legacy_rows()`
/// over the legacy file so a locally-wrong "no production fleet" premise gets a loud signal.

#include "workflow_types.hpp" // ADR-0031 WS-A4 (eighth family): relocated pure POD types

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu {
class MetricsRegistry;
} // namespace yuzu

namespace yuzu::server {

// ── Dispatch callback type ───────────────────────────────────────────────────
// The workflow engine invokes this callback to dispatch a step to agents.
// Returns a JSON result string on success, or an error string on failure.
using StepDispatchFn = std::function<std::expected<std::string, std::string>(
    const std::string& instruction_id,
    const std::string& agent_ids_json,
    const std::string& parameters_json)>;

// ── Condition evaluator callback type ────────────────────────────────────────
// Evaluates a compliance/CEL expression against result fields.
// Returns true if the condition is satisfied.
using ConditionEvalFn = std::function<bool(
    const std::string& expression,
    const std::map<std::string, std::string>& result_fields)>;

// ── WorkflowEngine ──────────────────────────────────────────────────────────

class WorkflowEngine {
public:
    explicit WorkflowEngine(pg::PgPool& pool);

    WorkflowEngine(const WorkflowEngine&) = delete;
    WorkflowEngine& operator=(const WorkflowEngine&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for write-outcome counters
    /// (`yuzu_server_workflow_engine_writes_total{op,result}` — `op` one of
    /// `create_workflow`/`delete_workflow`/`execute`/`cancel_execution`). Set-before-traffic
    /// contract, same as every other metrics-emitting store on this ladder.
    void set_metrics(yuzu::MetricsRegistry* metrics) noexcept { metrics_ = metrics; }

    // ── Workflow CRUD ────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_workflow(const std::string& yaml_source);

    /// `unexpected(msg)` (prefixed `kDbErrorPrefix`) is a genuine read failure — never treat it
    /// as "no workflows".
    std::expected<std::vector<Workflow>, std::string> list_workflows(
        const WorkflowQuery& q = {}) const;

    /// `nullopt` = a successful read finding none (or the workflow is soft-deleted — ADR-0064).
    /// `unexpected(msg)` (prefixed `kDbErrorPrefix`) = a genuine read failure — never treat the
    /// latter as "not found".
    std::expected<std::optional<Workflow>, std::string> get_workflow(const std::string& id) const;

    /// Soft-deletes (ADR-0064) — the row is never physically removed, so execution history stays
    /// attached and queryable. `unexpected("not_found: ...")` when no such workflow exists or it
    /// was already deleted; `unexpected(msg)` (prefixed `kDbErrorPrefix`) is a genuine failure.
    std::expected<void, std::string> delete_workflow(const std::string& id);

    // ── Execution ────────────────────────────────────────────────────────
    /// Start a workflow execution against a set of agents.
    /// dispatch_fn is called for each step to send commands.
    /// condition_fn evaluates if-conditions on step results.
    /// Fails (workflow-not-found error) if the workflow does not exist OR was soft-deleted —
    /// admission is checked atomically at execution-row creation (ADR-0064 "New atomicity"),
    /// closing the race between an earlier `get_workflow` read and this call.
    std::expected<std::string, std::string> execute(
        const std::string& workflow_id,
        const std::vector<std::string>& agent_ids,
        StepDispatchFn dispatch_fn,
        ConditionEvalFn condition_fn = nullptr);

    /// Get execution status with step results.
    std::expected<std::optional<WorkflowExecution>, std::string> get_execution(
        const std::string& id) const;

    /// List recent executions for a workflow (or all if workflow_id is empty).
    std::expected<std::vector<WorkflowExecution>, std::string> list_executions(
        const std::string& workflow_id = {}, int limit = 50) const;

    /// Cancel a running execution.
    std::expected<void, std::string> cancel_execution(const std::string& id);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    std::string generate_id() const;

    // Note: every DB-touching helper (step loading, step-result CRUD, execution-status update)
    // is a file-local free function in workflow_engine.cpp taking the live `PGconn*` explicitly
    // — never a class member — so every call site's lease/transaction scope is visible at the
    // call site itself, matching the pre-migration code's `{ std::unique_lock ...; helper(); }`
    // shape 1:1. Never hold a lease/conn across a dispatch call or the retry `sleep_for` in
    // `execute()` (ADR-0064 "Lease discipline").

    // Expand foreach results into individual dispatch items
    std::vector<std::string> expand_foreach(const std::string& foreach_source,
                                             const std::string& prev_result_json) const;
};

} // namespace yuzu::server
