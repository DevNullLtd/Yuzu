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

#include "workflow_run_port.hpp" // WorkflowRunControl (the per-run hooks execute() consumes)
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

// `StepDispatchFn` (the per-step dispatch callback `execute()` invokes) and `ConditionEvalFn` (the
// step-condition evaluator) now live in `workflow_types.hpp`, included above, so the store-free
// `WorkflowRunFn` port can name them. Same types, same namespace: no includer changes.

// ── Execution-list SQL ──────────────────────────────────────────────────────

/// Server-side bound on one execution-list read (`SET LOCAL statement_timeout`; same idiom as
/// ExecutionTracker's children read): the confined predicate parses `agent_ids_json` per candidate
/// row, so a pathological table must end as an honest degrade, never a wedged pool connection.
/// Production never passes another value; the argument exists so a test can end a lock-held read
/// in milliseconds. It must be positive: PostgreSQL reads 0 as "no timeout".
inline constexpr std::chrono::milliseconds kExecutionPageStatementTimeout{1500};

/// The statement and its positional parameters for one `query_executions_page` read. Built by a
/// pure function (no database) so the exact text, the parameter order and the position of the
/// visibility clause relative to `ORDER BY`/`LIMIT` are unit-pinned. `$n` placeholders only —
/// no caller value is ever spliced into the text.
struct ExecutionPageSql {
    /// Runs first, in the same transaction as `sql`: the read's `SET LOCAL statement_timeout`.
    std::string statement_timeout_sql;
    std::string sql;
    std::vector<std::string> params;
    /// The page size the statement was built for: `q.limit` clamped to
    /// [1, kWorkflowExecutionListMax]. `sql` selects `limit + 1` rows and the store trims to this
    /// value, so both bounds come from this one field.
    int limit{0};
};

/// Builds the list statement for `q` (already validated; `limit` is clamped to
/// [1, kWorkflowExecutionListMax]). Selects `limit + 1` rows: the extra row is the sentinel
/// `query_executions_page` trims off to decide "more exist" without a count. `visible_agents`
/// engaged adds the confinement predicate (engaged-empty adds `1=0`, never an unfiltered read).
/// The predicate is NOT a byte-for-byte image of `workflow_execution_visible()`: see the
/// divergence list on `query_executions_page`.
[[nodiscard]] ExecutionPageSql build_execution_page_sql(
    const WorkflowExecutionListQuery& q,
    const std::optional<std::vector<std::string>>& visible_agents,
    std::chrono::milliseconds statement_timeout = kExecutionPageStatementTimeout);

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
    ///
    /// A failed step is recorded, not returned; a `permanent` StepDispatchError is not retried and
    /// is not slept on (the step's `on_failure` policy applies at once). A THROW from `dispatch_fn`,
    /// `condition_fn` or `on_admitted` is a failed, never-retried step: the execution is closed
    /// `failed` through the guarded finalize, the remaining steps are marked skipped, and the
    /// exception is rethrown to the caller, so a run is never left `running` behind a throw.
    /// `on_admitted` is called once with the new execution id after admission and before the first
    /// step.
    ///
    /// `control` carries the run's bounds (`workflow_run_port.hpp`): before every dispatch attempt
    /// the engine asks `control.before_attempt` and compares `control.deadline` with the steady
    /// clock; either refusing STOPS the run (the attempt is not made, the step is recorded failed,
    /// the remaining steps are skipped `run stopped`, the execution is finalized `failed` through
    /// the same guarded UPDATE, and `on_failure` does not apply). A retry delay is cut to the time
    /// left before the deadline. A default `control` is no bound: the legacy route's behaviour.
    std::expected<std::string, std::string> execute(
        const std::string& workflow_id,
        const std::vector<std::string>& agent_ids,
        StepDispatchFn dispatch_fn,
        ConditionEvalFn condition_fn = nullptr,
        std::function<void(const std::string& execution_id)> on_admitted = nullptr,
        const WorkflowRunControl& control = {});

    /// Get execution status with step results.
    std::expected<std::optional<WorkflowExecution>, std::string> get_execution(
        const std::string& id) const;

    /// List recent executions for a workflow (or all if workflow_id is empty).
    std::expected<std::vector<WorkflowExecution>, std::string> list_executions(
        const std::string& workflow_id = {}, int limit = 50) const;

    /// One page of the workflow-execution LIST: newest first by `(started_at, id)`, or, with
    /// `q.latest_per_workflow`, each workflow's newest run by workflow id. Metadata rows only
    /// (no agent ids, no step results), joined to the workflow name in the same statement.
    ///
    /// `visible_agents` is the caller's admitted agent set as plain data (the `authz::VisibleSet`
    /// shape without the authz dependency): `nullopt` = unfiltered; engaged = a run is returned
    /// only if at least one string element of its `agent_ids_json` is in the set — the SQL image
    /// of `workflow_execution_visible()` (workflow_model.hpp), applied BEFORE `ORDER BY`/`LIMIT`
    /// (ADR-0017 INV-3) so an invisible run can never consume a page slot, and a cursor or page
    /// length can never reveal one. Engaged-empty is deny-all and answers an empty page without
    /// touching the database. Malformed or non-array `agent_ids_json` is not visible to a confined
    /// caller (fail closed).
    ///
    /// The image is faithful for every document the engine itself writes (a JSON array of
    /// strings). It diverges from the C++ predicate where PostgreSQL's jsonb and nlohmann accept
    /// different JSON, and each divergence is pinned by a test row with its direction: a document
    /// jsonb refuses (a `\u0000` escape, a UTF-8 byte-order mark) is hidden from a confined caller
    /// here but shown by the C++ predicate (fails closed); a document jsonb accepts and nlohmann
    /// rejects (a number past double range, `["a1",1e400]`) is shown here when it also names an
    /// in-scope string id, and hidden by the C++ predicate, so the list can offer a run whose
    /// detail read answers not-visible. In `latest_per_workflow` mode either case can change which
    /// run is a workflow's latest. No out-of-scope run is ever exposed: a shown run always names an
    /// in-scope agent.
    ///
    /// `unexpected(msg)` (prefixed `kDbErrorPrefix`) is a genuine failure — engine not open, pool
    /// exhausted, statement timeout (`statement_timeout`) or query error — and is never an
    /// empty page. The caller must genericize it before rendering.
    std::expected<WorkflowExecutionPage, std::string> query_executions_page(
        const WorkflowExecutionListQuery& q,
        const std::optional<std::vector<std::string>>& visible_agents,
        std::chrono::milliseconds statement_timeout = kExecutionPageStatementTimeout) const;

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
