#include "workflow_engine.hpp"

#include "mcp_jsonrpc.hpp" // json_exceeds_depth / kMcpMaxJsonDepth (#2437-class depth guard)
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "workflow_claim_outcome.hpp"
#include "workflow_model.hpp" // stored_agent_ids_json
#include "workflow_wait.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <random>
#include <thread>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "workflow_engine";

// Bounded acquires (ADR-0012 §2). Every runtime acquire in this file is bounded — the retry
// loop's `sleep_for` and every `dispatch_fn` call happen with NO lease/conn held (ADR-0064
// "Lease discipline").
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};
// The ONE retry of a run's final status write, when the first attempt could not get a lease: a
// row left `running` is an orphan nothing sweeps, so the retry is allowed to wait out a busy pool.
constexpr std::chrono::milliseconds kFinalizeRetryTimeout{10000};
// The most the final status write's retry may keep waiting once a server stop is seen, checked
// between tries only: a lease acquire already in flight (a pool connect can run up to its connect
// timeout, 10 s) and the first non-persist try are not interruptible, so this is best-effort and
// the process stays bounded by the web server's 15 s shutdown bound, then the hard exit.
constexpr std::chrono::milliseconds kFinalizeStopBudget{3000};

/// Counts one run in `WorkflowEngine::in_flight_` for exactly the scope it is alive in, so no
/// path out of `execute()` (a return, a rethrow) can leak the count and hold a shutdown drain.
class InFlightRun {
public:
    explicit InFlightRun(std::atomic<int>& n) noexcept : n_(n) {
        n_.fetch_add(1, std::memory_order_acq_rel);
    }
    ~InFlightRun() { n_.fetch_sub(1, std::memory_order_acq_rel); }
    InFlightRun(const InFlightRun&) = delete;
    InFlightRun& operator=(const InFlightRun&) = delete;

private:
    std::atomic<int>& n_;
};

/// Why a run was stopped (`kNone`: it was not). Selects the reason on the steps it skips.
enum class StopCause { kNone, kBound, kShutdown };

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE workflows ("
         "  id          TEXT   PRIMARY KEY,"
         "  name        TEXT   NOT NULL,"
         "  description TEXT   NOT NULL DEFAULT '',"
         "  yaml_source TEXT   NOT NULL,"
         "  created_at  BIGINT NOT NULL DEFAULT 0,"
         "  updated_at  BIGINT NOT NULL DEFAULT 0,"
         "  deleted_at  BIGINT NOT NULL DEFAULT 0"
         ");"
         "CREATE TABLE workflow_steps ("
         "  workflow_id         TEXT    NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,"
         "  step_index          INTEGER NOT NULL,"
         "  instruction_id      TEXT    NOT NULL,"
         "  condition            TEXT    NOT NULL DEFAULT '',"
         "  retry_count          INTEGER NOT NULL DEFAULT 0,"
         "  retry_delay_seconds  INTEGER NOT NULL DEFAULT 5,"
         "  foreach_source        TEXT    NOT NULL DEFAULT '',"
         "  label                 TEXT    NOT NULL DEFAULT '',"
         "  on_failure            TEXT    NOT NULL DEFAULT 'abort',"
         "  PRIMARY KEY (workflow_id, step_index)"
         ");"
         // No ON DELETE clause (defaults to NO ACTION/RESTRICT) — ADR-0064 "Delete semantics":
         // delete_workflow() soft-deletes and never issues a DELETE on workflows, so this FK is
         // defense-in-depth against a future hard-purge tool, never exercised by this PR's code.
         "CREATE TABLE workflow_executions ("
         "  id             TEXT    PRIMARY KEY,"
         "  workflow_id    TEXT    NOT NULL REFERENCES workflows(id),"
         "  status         TEXT    NOT NULL DEFAULT 'pending',"
         "  agent_ids_json TEXT    NOT NULL DEFAULT '[]',"
         "  started_at     BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at   BIGINT  NOT NULL DEFAULT 0,"
         "  current_step   INTEGER NOT NULL DEFAULT 0"
         ");"
         "CREATE TABLE workflow_step_results ("
         "  execution_id   TEXT    NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,"
         "  step_index     INTEGER NOT NULL,"
         "  instruction_id TEXT    NOT NULL,"
         "  status         TEXT    NOT NULL DEFAULT 'pending',"
         "  result_json    TEXT    NOT NULL DEFAULT '{}',"
         "  started_at     BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at   BIGINT  NOT NULL DEFAULT 0,"
         "  attempt        INTEGER NOT NULL DEFAULT 1,"
         "  PRIMARY KEY (execution_id, step_index)"
         ");"
         "CREATE INDEX idx_wf_exec_workflow ON workflow_executions(workflow_id);"
         // No separate index on workflow_step_results(execution_id) — governance finding
         // (architect): the PK (execution_id, step_index) btree already serves an
         // execution_id-only equality lookup on its leading column; a dedicated index would be
         // pure redundant write/storage cost.
         "CREATE INDEX idx_workflows_deleted ON workflows(deleted_at) WHERE deleted_at = 0;"},
        // v2 (Echo rename, upgrade window): workflow steps, their recorded results and the
        // workflow source follow the renamed definition ids. Idempotent.
        {2,
         "UPDATE workflow_steps SET instruction_id = replace(instruction_id, "
         "'crossplatform.tar.', 'crossplatform.echo.') WHERE instruction_id LIKE 'crossplatform.tar.%';"
         "UPDATE workflow_step_results SET instruction_id = replace(instruction_id, "
         "'crossplatform.tar.', 'crossplatform.echo.') WHERE instruction_id LIKE 'crossplatform.tar.%';"
         "UPDATE workflows SET yaml_source = replace(yaml_source, "
         "'crossplatform.tar.', 'crossplatform.echo.') WHERE yaml_source LIKE '%crossplatform.tar.%';"},
        // v3 (#2146, idempotent execute): a client key claimed on the run's own row, plus the
        // run's actor and call. `idempotency_key` and `request_fingerprint` are NULL on every
        // keyless run (the legacy route and any call that sent no key), so the partial UNIQUE
        // index holds only keyed rows and a keyless INSERT never touches it. `principal` and
        // `correlation_id` are stored on EVERY run the execute twins start, keyed or not (NULL
        // for the legacy route), so an unkeyed run still names its actor and the audit rows that
        // carry the same `correlation_id=` join to it. The CHECK makes a key without its principal
        // or fingerprint unstorable (a NULL principal never conflicts under a unique index, so
        // such a row would silently stop being idempotent) and an empty principal unstorable (it
        // would be one shared key namespace); it says nothing about the unkeyed row's columns.
        // Plain (transactional) index build on a table the fresh-database hard cutover guarantees
        // is empty (docs/postgres-store-playbook.md "Recorded exception"). No backfill: an
        // existing run has no key. Every statement is re-run safe (a rewound version stamp, or an
        // index built by hand ahead of the migration): the CHECK is dropped before it is added.
        {3,
         "ALTER TABLE workflow_executions "
         "  ADD COLUMN IF NOT EXISTS principal           TEXT,"
         "  ADD COLUMN IF NOT EXISTS idempotency_key     TEXT,"
         "  ADD COLUMN IF NOT EXISTS request_fingerprint TEXT,"
         "  ADD COLUMN IF NOT EXISTS correlation_id      TEXT;"
         "ALTER TABLE workflow_executions DROP CONSTRAINT IF EXISTS wf_exec_idem_complete;"
         "ALTER TABLE workflow_executions ADD CONSTRAINT wf_exec_idem_complete CHECK ("
         "  idempotency_key IS NULL OR "
         "  (principal IS NOT NULL AND principal <> '' AND request_fingerprint IS NOT NULL));"
         "CREATE UNIQUE INDEX IF NOT EXISTS idx_wf_exec_idem "
         "  ON workflow_executions(principal, idempotency_key) "
         "  WHERE idempotency_key IS NOT NULL;"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    patch_manager.cpp / offload_target_store.cpp's own file-local copies) ────

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

/// The fate of the claim transaction `xid` according to Postgres itself (`pg_xact_status`), on a
/// fresh lease: the original one is gone with the failed transaction. No lease, a failed query or
/// a NULL answer is `kUnknown`.
ClaimTxnOutcome claim_txn_outcome(pg::PgPool& pool, const std::string& xid) {
    auto lease = pool.try_acquire_for(kReadTimeout);
    if (!lease)
        return ClaimTxnOutcome::kUnknown;
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT pg_xact_status($1::xid8)",
                                       std::vector<std::string>{xid});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0 ||
        PQgetisnull(res.get(), 0, 0))
        return ClaimTxnOutcome::kUnknown;
    return classify_xact_status(std::string_view(PQgetvalue(res.get(), 0, 0)));
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string gen_id() {
    thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

/// Minimal YAML value extractor — matches the pattern used across all Yuzu stores.
std::string extract_yaml_value(const std::string& yaml, const std::string& key) {
    auto search = key + ":";
    auto pos = yaml.find(search);
    while (pos != std::string::npos) {
        if (pos > 0 && yaml[pos - 1] != '\n' && yaml[pos - 1] != ' ' && yaml[pos - 1] != '\t') {
            pos = yaml.find(search, pos + 1);
            continue;
        }
        auto vstart = pos + search.size();
        while (vstart < yaml.size() && (yaml[vstart] == ' ' || yaml[vstart] == '\t'))
            ++vstart;
        if (vstart >= yaml.size() || yaml[vstart] == '\n')
            return {};
        auto eol = yaml.find('\n', vstart);
        if (eol == std::string::npos)
            eol = yaml.size();
        auto val = yaml.substr(vstart, eol - vstart);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
            val.pop_back();
        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }
        if (val == ">" || val == "|")
            return {};
        return val;
    }
    return {};
}

/// Extract a YAML sequence block into a list of maps representing steps.
/// Each step is a mapping under "- instruction:" within the steps: block.
struct RawStep {
    std::string instruction;
    std::string condition;
    std::string retry_count;
    std::string retry_delay;
    std::string foreach_source;
    std::string label;
    std::string on_failure;
};

std::vector<RawStep> extract_steps(const std::string& yaml) {
    std::vector<RawStep> steps;

    // Find the "steps:" block
    auto steps_pos = yaml.find("steps:");
    if (steps_pos == std::string::npos)
        return steps;

    // Find the start of the list (first "- " after "steps:")
    auto search_start = yaml.find('\n', steps_pos);
    if (search_start == std::string::npos)
        return steps;

    // Determine the indentation level of list items
    RawStep current;
    bool in_step = false;
    std::string::size_type pos = search_start + 1;

    while (pos < yaml.size()) {
        auto eol = yaml.find('\n', pos);
        if (eol == std::string::npos)
            eol = yaml.size();

        auto line = yaml.substr(pos, eol - pos);
        // Strip trailing CR
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        // Check if this is a non-indented line (end of steps block)
        if (!line.empty() && line[0] != ' ' && line[0] != '\t' && line[0] != '-') {
            if (in_step)
                steps.push_back(current);
            break;
        }

        // Trim leading whitespace to find content
        auto trimmed = line;
        auto first_non_space = trimmed.find_first_not_of(" \t");
        if (first_non_space != std::string::npos)
            trimmed = trimmed.substr(first_non_space);

        // New list item starts with "- "
        if (trimmed.starts_with("- ")) {
            if (in_step)
                steps.push_back(current);
            current = RawStep{};
            in_step = true;
            // The rest after "- " might be "instruction: ..."
            auto rest = trimmed.substr(2);
            auto colon = rest.find(':');
            if (colon != std::string::npos) {
                auto key = rest.substr(0, colon);
                auto val = rest.substr(colon + 1);
                // Trim val
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.erase(val.begin());
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                    val.pop_back();
                // Strip quotes
                if (val.size() >= 2 &&
                    ((val.front() == '"' && val.back() == '"') ||
                     (val.front() == '\'' && val.back() == '\''))) {
                    val = val.substr(1, val.size() - 2);
                }
                if (key == "instruction") current.instruction = val;
                else if (key == "label") current.label = val;
                else if (key == "condition" || key == "if") current.condition = val;
                else if (key == "foreach") current.foreach_source = val;
                else if (key == "onFailure") current.on_failure = val;
            }
        } else if (in_step && !trimmed.empty()) {
            // Continuation of current step (key: value pair)
            auto colon = trimmed.find(':');
            if (colon != std::string::npos) {
                auto key = trimmed.substr(0, colon);
                auto val = trimmed.substr(colon + 1);
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.erase(val.begin());
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                    val.pop_back();
                if (val.size() >= 2 &&
                    ((val.front() == '"' && val.back() == '"') ||
                     (val.front() == '\'' && val.back() == '\''))) {
                    val = val.substr(1, val.size() - 2);
                }
                if (key == "instruction") current.instruction = val;
                else if (key == "label") current.label = val;
                else if (key == "condition" || key == "if") current.condition = val;
                else if (key == "retryCount") current.retry_count = val;
                else if (key == "retryDelay") current.retry_delay = val;
                else if (key == "foreach") current.foreach_source = val;
                else if (key == "onFailure") current.on_failure = val;
            }
        }

        pos = eol + 1;
    }
    // Push last step if still in one
    if (in_step)
        steps.push_back(current);

    return steps;
}

// ── DB-touching helpers (file-local, take the live `PGconn*` explicitly) ─────
// Every call site controls its own lease/transaction scope — see workflow_engine.hpp's private
// section comment and ADR-0064 "Lease discipline". None of these are declared in the header.

// Authoritative child read — returns unexpected(kDbErrorPrefix) on a genuine query failure
// rather than an empty vector, so a caller can never mistake "workflow_steps failed to read"
// for "this workflow has no steps" (governance finding: the parent read was widened to
// std::expected, but this child read had kept the SQLite-era fail-soft shape underneath it).
std::expected<std::vector<WorkflowStep>, std::string> wf_load_steps(PGconn* conn,
                                                                     const std::string& workflow_id) {
    std::vector<WorkflowStep> steps;
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT step_index, instruction_id, condition, retry_count, retry_delay_seconds, "
        "foreach_source, label, on_failure FROM workflow_engine.workflow_steps "
        "WHERE workflow_id = $1 ORDER BY step_index",
        std::vector<std::string>{workflow_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("WorkflowEngine: load_steps failed for {}: {}", workflow_id,
                     PQresultErrorMessage(res.get()));
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(res.get()));
    }
    const int rows = PQntuples(res.get());
    steps.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        WorkflowStep s;
        s.index = static_cast<int>(to_i64(col(res.get(), i, 0)));
        s.instruction_id = col_str(res.get(), i, 1);
        s.condition = col_str(res.get(), i, 2);
        s.retry_count = static_cast<int>(to_i64(col(res.get(), i, 3)));
        s.retry_delay_seconds = static_cast<int>(to_i64(col(res.get(), i, 4)));
        s.foreach_source = col_str(res.get(), i, 5);
        s.label = col_str(res.get(), i, 6);
        s.on_failure = col_str(res.get(), i, 7);
        steps.push_back(std::move(s));
    }
    return steps;
}

/// UPSERT — mirrors the SQLite era's `INSERT OR REPLACE` (a step's result row is created
/// `pending` at admission, then overwritten in place as it moves through `running`/`success`/
/// `failed`/`skipped`).
void wf_create_step_result(PGconn* conn, const std::string& execution_id,
                            const WorkflowStepResult& sr) {
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO workflow_engine.workflow_step_results "
        "(execution_id, step_index, instruction_id, status, result_json, started_at, "
        " completed_at, attempt) "
        "VALUES ($1, $2::int, $3, $4, $5, $6::bigint, $7::bigint, $8::int) "
        "ON CONFLICT (execution_id, step_index) DO UPDATE SET "
        "  instruction_id = EXCLUDED.instruction_id, status = EXCLUDED.status, "
        "  result_json = EXCLUDED.result_json, started_at = EXCLUDED.started_at, "
        "  completed_at = EXCLUDED.completed_at, attempt = EXCLUDED.attempt",
        std::vector<std::string>{execution_id, std::to_string(sr.step_index), sr.instruction_id,
                                 sr.status, sr.result_json, std::to_string(sr.started_at),
                                 std::to_string(sr.completed_at), std::to_string(sr.attempt)});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("WorkflowEngine: create_step_result failed for {}/{}: {}", execution_id,
                    sr.step_index, PQresultErrorMessage(res.get()));
}

void wf_update_step_result(PGconn* conn, const std::string& execution_id, int step_index,
                            const std::string& status, const std::string& result_json) {
    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE workflow_engine.workflow_step_results SET status = $1, result_json = $2, "
        "completed_at = $3::bigint WHERE execution_id = $4 AND step_index = $5::int",
        std::vector<std::string>{status, result_json, std::to_string(now_epoch()), execution_id,
                                 std::to_string(step_index)});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("WorkflowEngine: update_step_result failed for {}/{}: {}", execution_id,
                    step_index, PQresultErrorMessage(res.get()));
}

void wf_update_attempt(PGconn* conn, const std::string& execution_id, int step_index,
                       int attempt) {
    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE workflow_engine.workflow_step_results SET attempt = $1::int "
        "WHERE execution_id = $2 AND step_index = $3::int",
        std::vector<std::string>{std::to_string(attempt), execution_id,
                                 std::to_string(step_index)});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("WorkflowEngine: update_attempt failed for {}/{}: {}", execution_id,
                    step_index, PQresultErrorMessage(res.get()));
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

WorkflowEngine::WorkflowEngine(pg::PgPool& pool)
    : pool_(pool), write_timeout_(kWriteTimeout), finalize_retry_timeout_(kFinalizeRetryTimeout) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime acquire elsewhere in
    // this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("WorkflowEngine: no database connection at construction ({}) — workflow "
                      "engine disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("WorkflowEngine: schema migration failed — workflow engine disabled");
        return;
    }
    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no migrate_from_sqlite here,
    // unconditionally, no flag. The caller (server.cpp) separately runs
    // legacy_sqlite_probe::warn_if_legacy_rows() over the legacy workflows.db.
    spdlog::info("WorkflowEngine initialized (schema {}) — fresh start, no legacy backfill",
                kStoreName);
}

std::string WorkflowEngine::generate_id() const {
    return gen_id();
}

std::vector<std::string> WorkflowEngine::expand_foreach(
    const std::string& foreach_source, const std::string& prev_result_json) const {
    std::vector<std::string> items;
    try {
        auto result = nlohmann::json::parse(prev_result_json, nullptr, false);
        if (result.is_discarded())
            return items;

        // If foreach_source names a field, extract array from that field
        nlohmann::json arr;
        if (result.contains(foreach_source) && result[foreach_source].is_array()) {
            arr = result[foreach_source];
        } else if (result.is_array()) {
            arr = result;
        } else {
            // Treat the whole result as a single item
            items.push_back(prev_result_json);
            return items;
        }

        for (const auto& item : arr) {
            items.push_back(item.dump());
        }
    } catch (const std::exception&) {
        // Parse failure — single item
        items.push_back(prev_result_json);
    }
    return items;
}

// ── Workflow CRUD ───────────────────────────────────────────────────────────

std::expected<std::string, std::string> WorkflowEngine::create_workflow(
    const std::string& yaml_source) {

    // Validate kind
    auto kind = extract_yaml_value(yaml_source, "kind");
    if (!kind.empty() && kind != "Workflow") {
        return std::unexpected(kind_mismatch_error("Workflow", kind));
    }

    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        return std::unexpected("workflow name is required (metadata.displayName or metadata.name)");

    auto description = extract_yaml_value(yaml_source, "description");

    // Parse steps
    auto raw_steps = extract_steps(yaml_source);
    if (raw_steps.empty())
        return std::unexpected("workflow must have at least one step");

    std::vector<WorkflowStep> steps;
    for (int i = 0; i < static_cast<int>(raw_steps.size()); ++i) {
        auto& rs = raw_steps[i];
        if (rs.instruction.empty())
            return std::unexpected("step " + std::to_string(i) + " missing instruction ID");

        WorkflowStep s;
        s.index = i;
        s.instruction_id = rs.instruction;
        s.condition = rs.condition;
        s.foreach_source = rs.foreach_source;
        s.label = rs.label;
        s.on_failure = rs.on_failure.empty() ? "abort" : rs.on_failure;

        if (!rs.retry_count.empty()) {
            try {
                s.retry_count = std::clamp(std::stoi(rs.retry_count), 0, 10);
            } catch (...) {}
        }
        if (!rs.retry_delay.empty()) {
            try {
                s.retry_delay_seconds = std::clamp(std::stoi(rs.retry_delay), 0, 3600);
            } catch (...) {}
        }

        steps.push_back(std::move(s));
    }

    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");

    auto id = generate_id();
    auto now = std::to_string(now_epoch());

    // New atomicity (ADR-0064): the workflow-row insert and every step-row insert are one
    // transaction — the SQLite era issued each as its own unchecked statement.
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "INSERT INTO workflow_engine.workflows "
            "(id, name, description, yaml_source, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5::bigint, $5::bigint)",
            std::vector<std::string>{id, name, description, yaml_source, now});
        if (res.status() != PGRES_COMMAND_OK) {
            spdlog::error("WorkflowEngine::create_workflow: insert failed: {}",
                          PQresultErrorMessage(res.get()));
            return false;
        }

        for (const auto& s : steps) {
            // Defense-in-depth (unreachable in practice — already rejected above): an
            // empty instruction_id now aborts the whole transaction rather than being
            // silently skipped, so a caller never sees "created" for a workflow missing a
            // step it asked for (ADR-0064 "New atomicity").
            if (s.instruction_id.empty()) {
                spdlog::error("WorkflowEngine::create_workflow: empty instruction_id for step "
                              "{} — aborting",
                              s.index);
                return false;
            }
            pg::PgResult sres = pg::exec_params(
                conn,
                "INSERT INTO workflow_engine.workflow_steps "
                "(workflow_id, step_index, instruction_id, condition, retry_count, "
                " retry_delay_seconds, foreach_source, label, on_failure) "
                "VALUES ($1, $2::int, $3, $4, $5::int, $6::int, $7, $8, $9)",
                std::vector<std::string>{id, std::to_string(s.index), s.instruction_id,
                                         s.condition, std::to_string(s.retry_count),
                                         std::to_string(s.retry_delay_seconds), s.foreach_source,
                                         s.label, s.on_failure});
            if (sres.status() != PGRES_COMMAND_OK) {
                spdlog::error("WorkflowEngine::create_workflow: step insert failed: {}",
                              PQresultErrorMessage(sres.get()));
                return false;
            }
        }
        return true;
    });

    if (metrics_)
        metrics_->counter("yuzu_server_workflow_engine_writes_total",
                          {{"op", "create_workflow"}, {"result", ok ? "success" : "failed"}})
            .increment();
    if (!ok)
        return std::unexpected(std::string(kDbErrorPrefix) + "failed to create workflow");

    spdlog::info("WorkflowEngine: created workflow '{}' ({}), {} steps", name, id, steps.size());
    return id;
}

std::expected<std::vector<Workflow>, std::string> WorkflowEngine::list_workflows(
    const WorkflowQuery& q) const {
    std::vector<Workflow> result;
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    std::string sql = "SELECT id, name, description, yaml_source, created_at, updated_at "
                      "FROM workflow_engine.workflows WHERE deleted_at = 0";
    std::vector<std::string> params;
    int idx = 1;
    if (!q.name_filter.empty()) {
        // ILIKE, not LIKE: SQLite's LIKE is case-insensitive for ASCII by default (the
        // pre-migration behavior); Postgres's plain LIKE is case-sensitive.
        sql += " AND name ILIKE $" + std::to_string(idx++);
        params.push_back("%" + q.name_filter + "%");
    }
    sql += " ORDER BY created_at DESC LIMIT $" + std::to_string(idx);
    // Clamp to at least 1: SQLite silently treated a negative LIMIT as "unlimited" (an
    // undocumented quirk no caller relies on — the REST layer never validates or advertises
    // it); Postgres rejects a negative LIMIT outright. Clamping avoids turning a stray negative
    // q.limit into a query-failure 503 without reproducing the unlimited-rows quirk.
    params.push_back(std::to_string(std::max(q.limit, 1)));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) +
                               PQresultErrorMessage(res.get()));

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        Workflow w;
        w.id = col_str(res.get(), i, 0);
        w.name = col_str(res.get(), i, 1);
        w.description = col_str(res.get(), i, 2);
        w.yaml_source = col_str(res.get(), i, 3);
        w.created_at = to_i64(col(res.get(), i, 4));
        w.updated_at = to_i64(col(res.get(), i, 5));
        auto steps_result = wf_load_steps(lease.get(), w.id);
        if (!steps_result)
            return std::unexpected(steps_result.error());
        w.steps = std::move(*steps_result);
        result.push_back(std::move(w));
    }
    return result;
}

std::expected<std::optional<Workflow>, std::string> WorkflowEngine::get_workflow(
    const std::string& id) const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, name, description, yaml_source, created_at, updated_at "
        "FROM workflow_engine.workflows WHERE id = $1 AND deleted_at = 0",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) +
                               PQresultErrorMessage(res.get()));
    if (PQntuples(res.get()) == 0)
        return std::nullopt;

    Workflow w;
    w.id = col_str(res.get(), 0, 0);
    w.name = col_str(res.get(), 0, 1);
    w.description = col_str(res.get(), 0, 2);
    w.yaml_source = col_str(res.get(), 0, 3);
    w.created_at = to_i64(col(res.get(), 0, 4));
    w.updated_at = to_i64(col(res.get(), 0, 5));
    auto steps_result = wf_load_steps(lease.get(), w.id);
    if (!steps_result)
        return std::unexpected(steps_result.error());
    w.steps = std::move(*steps_result);
    return w;
}

std::expected<void, std::string> WorkflowEngine::delete_workflow(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    // Soft-delete (ADR-0064): stamps deleted_at rather than issuing a DELETE, so execution
    // history for this workflow stays physically intact and queryable. Idempotent-guarded —
    // `AND deleted_at = 0` means a second call reports not_found, matching the pre-migration
    // bool contract's "false" meaning for both "never existed" and "already deleted".
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE workflow_engine.workflows SET deleted_at = $1::bigint "
        "WHERE id = $2 AND deleted_at = 0 RETURNING id",
        std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (metrics_)
            metrics_->counter("yuzu_server_workflow_engine_writes_total",
                              {{"op", "delete_workflow"}, {"result", "failed"}})
                .increment();
        return std::unexpected(std::string(kDbErrorPrefix) +
                               PQresultErrorMessage(res.get()));
    }

    const bool deleted = PQntuples(res.get()) > 0;
    // A not-found id is a caller mistake (a bad id, or a legitimate double-delete), never a
    // store-health signal — only a genuine DB failure (above) or an actual delete counts here,
    // matching PatchManager's convention that this counter reflects store outcome, not caller
    // input (governance finding).
    if (metrics_ && deleted)
        metrics_->counter("yuzu_server_workflow_engine_writes_total",
                          {{"op", "delete_workflow"}, {"result", "success"}})
            .increment();
    if (!deleted)
        return std::unexpected("not_found: workflow not found: " + id);

    spdlog::info("WorkflowEngine: soft-deleted workflow {}", id);
    return {};
}

// ── Execute workflow ────────────────────────────────────────────────────────

std::expected<std::string, std::string> WorkflowEngine::execute(
    const std::string& workflow_id,
    const std::vector<std::string>& agent_ids,
    StepDispatchFn dispatch_fn,
    ConditionEvalFn condition_fn,
    const WorkflowRunControl& control) {

    if (!dispatch_fn)
        return std::unexpected("dispatch function is required");
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");

    // From here to the end of the final status write (a throw included) this run holds the
    // shutdown drain: counted in-process, never from the table.
    const InFlightRun in_flight(in_flight_);

    // Load workflow
    auto workflow_result = get_workflow(workflow_id);
    if (!workflow_result)
        return std::unexpected(workflow_result.error());
    if (!*workflow_result)
        return std::unexpected("workflow not found: " + workflow_id);
    const Workflow workflow = **workflow_result;

    if (workflow.steps.empty())
        return std::unexpected("workflow has no steps");

    auto exec_id = generate_id();
    auto now = std::to_string(now_epoch());
    // The text every step is dispatched with is the FULL list; the run row stores a bounded copy.
    const std::string agent_str = nlohmann::json(agent_ids).dump();
    const std::string stored_agent_str = stored_agent_ids_json(agent_ids, control.stored_copy_first);

    // New atomicity (ADR-0064): execution-row creation + every step-result pre-creation are one
    // transaction. The execution insert is an INSERT...SELECT...WHERE deleted_at = 0, which
    // atomically re-proves the workflow is still active at admission time — closing the race
    // between the get_workflow() read above and this statement (a concurrent delete_workflow()
    // in between now fails admission here instead of silently orphaning a new execution against
    // a since-deleted workflow).
    //
    // IDEMPOTENCY (#2146). A keyed call adds `ON CONFLICT (principal, idempotency_key) WHERE
    // idempotency_key IS NOT NULL DO NOTHING` (the inference clause must name the partial index's
    // predicate, or Postgres finds no arbiter), so the claim and the admission are ONE statement:
    // exactly one of two concurrent calls with the same key inserts. ZERO rows is then ambiguous
    // (the workflow was soft-deleted/removed, or the key is taken), and only a read in this same
    // transaction can tell which: a row bound to (principal, key) is a REPLAY, none is the
    // ordinary "workflow not found". READ COMMITTED: a loser that waited on the winner's
    // uncommitted insert sees the winner's row once it commits.
    enum class Admission { kAdmitted, kReplay, kNotFound };
    Admission admission = Admission::kNotFound;
    WorkflowRunReplay replay;
    const auto& claim = control.idempotency;
    // The claim's own transaction id, captured before anything is written, and whether the body
    // reached its commit-ready end as an admission. Together they let a failed COMMIT be told from
    // a lost acknowledgement (below): an unknown outcome is asked of Postgres, never guessed.
    std::string claim_xid;
    bool admitted_body_done = false;
    auto claim_lease = pool_.try_acquire_for(kWriteTimeout);
    bool ok = pool_.with_txn_on(std::move(claim_lease), [&](PGconn* conn) -> bool {
        {
            pg::PgResult xid = pg::exec_params(conn, "SELECT pg_current_xact_id()::text",
                                               std::vector<std::string>{});
            if (xid.status() != PGRES_TUPLES_OK || PQntuples(xid.get()) == 0)
                return false;
            claim_xid = col_str(xid.get(), 0, 0);
        }
        // `principal` and `correlation_id` are stored on every row the twins admit (NULL when the
        // caller supplied none); a KEYED row's principal is the claim's, the key's namespace.
        pg::PgResult ires = claim
            ? pg::exec_params(
                  conn,
                  "INSERT INTO workflow_engine.workflow_executions "
                  "(id, workflow_id, status, agent_ids_json, started_at, current_step, "
                  " principal, idempotency_key, request_fingerprint, correlation_id) "
                  "SELECT $1, w.id, 'running', $3, $4::bigint, 0, $5, $6, $7, NULLIF($8, '') "
                  "FROM workflow_engine.workflows w WHERE w.id = $2 AND w.deleted_at = 0 "
                  "ON CONFLICT (principal, idempotency_key) WHERE idempotency_key IS NOT NULL "
                  "DO NOTHING RETURNING id",
                  std::vector<std::string>{exec_id, workflow_id, stored_agent_str, now, claim->principal,
                                           claim->key, claim->fingerprint,
                                           control.correlation_id})
            : pg::exec_params(
                  conn,
                  "INSERT INTO workflow_engine.workflow_executions "
                  "(id, workflow_id, status, agent_ids_json, started_at, current_step, "
                  " principal, correlation_id) "
                  "SELECT $1, w.id, 'running', $3, $4::bigint, 0, NULLIF($5, ''), NULLIF($6, '') "
                  "FROM workflow_engine.workflows w WHERE w.id = $2 AND w.deleted_at = 0 "
                  "RETURNING id",
                  std::vector<std::string>{exec_id, workflow_id, stored_agent_str, now,
                                           control.principal, control.correlation_id});
        if (ires.status() != PGRES_TUPLES_OK) {
            spdlog::error("WorkflowEngine::execute: execution insert failed: {}",
                          PQresultErrorMessage(ires.get()));
            return false;
        }
        if (PQntuples(ires.get()) == 0) {
            if (claim) {
                pg::PgResult bound = pg::exec_params(
                    conn,
                    "SELECT id, workflow_id, request_fingerprint, status, started_at "
                    "FROM workflow_engine.workflow_executions "
                    "WHERE principal = $1 AND idempotency_key = $2",
                    std::vector<std::string>{claim->principal, claim->key});
                if (bound.status() != PGRES_TUPLES_OK) {
                    spdlog::error("WorkflowEngine::execute: idempotency read failed: {}",
                                  PQresultErrorMessage(bound.get()));
                    return false;
                }
                if (PQntuples(bound.get()) > 0) {
                    admission = Admission::kReplay;
                    replay.execution_id = col_str(bound.get(), 0, 0);
                    replay.workflow_id = col_str(bound.get(), 0, 1);
                    replay.fingerprint = col_str(bound.get(), 0, 2);
                    replay.status = col_str(bound.get(), 0, 3);
                    replay.started_at = to_i64(col(bound.get(), 0, 4));
                }
            }
            // Replay, or the workflow vanished/soft-deleted since get_workflow() above: commit
            // the (no-op) txn; the caller gets the replay or the ordinary not-found error.
            return true;
        }
        admission = Admission::kAdmitted;

        for (const auto& step : workflow.steps) {
            pg::PgResult sres = pg::exec_params(
                conn,
                "INSERT INTO workflow_engine.workflow_step_results "
                "(execution_id, step_index, instruction_id, status, started_at) "
                "VALUES ($1, $2::int, $3, 'pending', 0)",
                std::vector<std::string>{exec_id, std::to_string(step.index),
                                         step.instruction_id});
            if (sres.status() != PGRES_COMMAND_OK) {
                spdlog::error("WorkflowEngine::execute: step-result pre-create failed: {}",
                              PQresultErrorMessage(sres.get()));
                return false;
            }
        }
        if (claim_hooks_.in_txn_tail)
            claim_hooks_.in_txn_tail(conn);
        admitted_body_done = true;
        return true;
    });
    if (ok && claim_hooks_.lose_commit_ack)
        ok = false;

    // A COMMIT that failed after a body that finished as an ADMISSION may still have committed:
    // the run is then bound (its key, its row) and only the acknowledgement was lost. Failing the
    // call would leave a running row nothing will ever dispatch, its key burned and, on MCP, its
    // ticket spent, until the stale rule calls it indeterminate. Ask Postgres for the
    // transaction's fate (pg_pool.hpp CHAOS-1/CHAOS-1b: never a row-exists read) and, if it
    // committed, go on with the id this call minted. Rolled back or undeterminable fails as before.
    if (!ok && admitted_body_done && admission == Admission::kAdmitted && !claim_xid.empty()) {
        switch (claim_txn_outcome(pool_, claim_xid)) {
        case ClaimTxnOutcome::kCommitted:
            spdlog::error("WorkflowEngine::execute: the admission COMMIT of execution {} was "
                          "reported failed but Postgres confirms transaction {} committed (a "
                          "lost acknowledgement); proceeding with the run",
                          exec_id, claim_xid);
            ok = true;
            break;
        case ClaimTxnOutcome::kRolledBack:
            break;
        case ClaimTxnOutcome::kUnknown:
            spdlog::error("WorkflowEngine::execute: the admission COMMIT of execution {} failed "
                          "and the outcome of transaction {} could not be confirmed; the row may "
                          "still appear as a running run that was never dispatched",
                          exec_id, claim_xid);
            break;
        }
    }

    if (!ok)
        return std::unexpected(std::string(kDbErrorPrefix) + "failed to admit execution");
    if (admission == Admission::kReplay) {
        if (control.on_replay)
            control.on_replay(replay);
        return std::unexpected(std::string(kWorkflowIdempotentReplayError));
    }
    if (admission != Admission::kAdmitted)
        return std::unexpected("workflow not found: " + workflow_id);

    // Every write from here on is standalone/best-effort (ADR-0064 "Mid-execution write
    // degradation") — a lease timeout mid-execute degrades to unrecorded history for that one
    // write rather than aborting an in-flight, possibly already-dispatched fleet operation.
    auto with_write_lease = [&](auto&& fn) {
        auto lease = pool_.try_acquire_for(write_timeout_);
        if (!lease) {
            spdlog::warn("WorkflowEngine::execute: lease unavailable mid-execution — a write "
                        "for execution {} was dropped (best-effort history, ADR-0064)",
                        exec_id);
            return;
        }
        fn(lease.get());
    };

    // The run's bounds (WorkflowRunControl), asked before EVERY dispatch attempt. When the caller
    // installed `before_attempt`, it alone decides (the caller owns the reason it said no, and
    // a clock read here that disagreed with its own by a microsecond would stop a run the caller
    // never recorded as stopped); `deadline` then only bounds the retry delay. With no hook, a
    // passed deadline stops the run.
    //
    // SHUTDOWN is asked first and is the engine's own: the higher of the run's `should_stop` and
    // the engine-level default (`set_should_stop`). `kStop` ends the run exactly as a passed
    // bound does, but with its own cause, so the skipped steps carry `server_shutdown` and the
    // caller hears `on_interrupted` at the moment the engine acts.
    const auto stop_level = [&]() {
        auto level = WorkflowStopLevel::kNone;
        if (control.should_stop)
            level = control.should_stop();
        if (should_stop_)
            level = std::max(level, should_stop_());
        return level;
    };
    StopCause stop_cause = StopCause::kNone;
    const auto note_stop = [&](StopCause cause) {
        if (stop_cause != StopCause::kNone)
            return;
        stop_cause = cause;
        if (cause == StopCause::kShutdown && control.on_interrupted)
            control.on_interrupted();
    };
    const auto stop_before_attempt = [&]() {
        if (stop_level() == WorkflowStopLevel::kStop) {
            note_stop(StopCause::kShutdown);
            return true;
        }
        const bool bound = control.before_attempt
                               ? !control.before_attempt()
                               : (control.deadline &&
                                  std::chrono::steady_clock::now() >= *control.deadline);
        if (bound)
            note_stop(StopCause::kBound);
        return bound;
    };
    // The two stop tokens a step's stored result carries, under `reason`, whether the step was
    // skipped or was the one in flight (workflow_run_port.hpp: kStepReason*). A reader of the
    // stored rows (the idempotent replay) tells a shutdown from a run bound from these alone.
    const auto stop_reason = [&stop_cause]() {
        return stop_cause == StopCause::kShutdown ? std::string(kStepReasonServerShutdown)
                                                  : std::string(kStepReasonRunStopped);
    };
    const auto skip_reason_json = [&stop_reason]() {
        return nlohmann::json({{"reason", stop_reason()}}).dump();
    };
    bool run_stopped = false;

    // Execute steps sequentially
    std::string prev_result_json = "{}";
    bool execution_failed = false;
    // A throw out of dispatch_fn / condition_fn / control.on_admitted must not leave the row
    // `running`: `thrown` carries it past the finalize below, which closes the execution as usual.
    std::exception_ptr thrown;
    int current_step_index = -1; // the step in flight (-1: none yet)
    bool current_step_open = false; // its result row is not yet written

    try {
        if (control.on_admitted)
            control.on_admitted(exec_id);

        for (const auto& step : workflow.steps) {
            // A stop that arrived between steps ends the run before this step begins: this step
            // and every later one is skipped, nothing is dispatched.
            if (stop_level() == WorkflowStopLevel::kStop) {
                note_stop(StopCause::kShutdown);
                run_stopped = true;
                spdlog::warn("WorkflowEngine: execution {} stopped before step {} (server "
                             "shutdown); skipping the remaining steps",
                             exec_id, step.index);
                with_write_lease([&](PGconn* c) {
                    for (const auto& remaining : workflow.steps) {
                        if (remaining.index >= step.index)
                            wf_update_step_result(c, exec_id, remaining.index, "skipped",
                                                  skip_reason_json());
                    }
                });
                execution_failed = true;
                break;
            }
            current_step_index = step.index;
            current_step_open = true;
            // Check if execution was cancelled
            {
                auto exec_check = get_execution(exec_id);
                if (exec_check && *exec_check && (*exec_check)->status == "cancelled") {
                    execution_failed = true;
                    break;
                }
            }

            // Update current step - `WHERE status = 'running'` guards this write the same way
            // finalize's is guarded (governance finding, security-guardian + docs-writer,
            // independently): without it, a concurrent cancel_execution() landing between the
            // cancellation check above and this write could flip status back to 'running', making
            // the loop (and finalize afterwards) forget the cancellation ever happened. `RETURNING id`
            // makes the CAS observable (governance finding, security-guardian): a CONFIRMED zero-row
            // result means the guard didn't match - status was no longer 'running', i.e. a cancel landed
            // in the window between the check above and this write - so the loop stops immediately
            // instead of dispatching one more step past the cancel. A lease timeout or query failure is
            // NOT treated as a mismatch (that would break the ADR-0064 degrade-and-continue posture for
            // an ordinary transient failure) - only a definite, executed CAS that matched zero rows
            // stops the loop. Currently unreachable in production (cancel_execution has no caller),
            // closed as the same defense-in-depth as the finalize fix.
            bool cas_ran = false;
            bool cas_matched = false;
            with_write_lease([&](PGconn* c) {
                pg::PgResult res = pg::exec_params(
                    c,
                    "UPDATE workflow_engine.workflow_executions SET status = 'running', "
                    "current_step = $1::int WHERE id = $2 AND status = 'running' RETURNING id",
                    std::vector<std::string>{std::to_string(step.index), exec_id});
                if (res.status() != PGRES_TUPLES_OK) {
                    spdlog::warn("WorkflowEngine: current-step update failed for {}: {}", exec_id,
                                PQresultErrorMessage(res.get()));
                    return;
                }
                cas_ran = true;
                cas_matched = PQntuples(res.get()) > 0;
            });
            if (cas_ran && !cas_matched) {
                execution_failed = true;
                break;
            }

            // Evaluate condition if present
            if (!step.condition.empty() && condition_fn) {
                // Parse previous result into fields map
                std::map<std::string, std::string> fields;
                try {
                    auto prev = nlohmann::json::parse(prev_result_json, nullptr, false);
                    if (!prev.is_discarded() && prev.is_object()) {
                        for (auto& [k, v] : prev.items()) {
                            fields["result." + k] = v.is_string() ? v.get<std::string>() : v.dump();
                        }
                    }
                } catch (...) {}

                if (!condition_fn(step.condition, fields)) {
                    // Condition not met - skip step
                    with_write_lease([&](PGconn* c) {
                        wf_update_step_result(
                            c, exec_id, step.index, "skipped",
                            nlohmann::json({{"reason", kStepReasonConditionNotMet}}).dump());
                    });
                    spdlog::info("WorkflowEngine: step {} skipped (condition: {})", step.index,
                                step.condition);
                    current_step_open = false;
                    continue;
                }
            }

            // Mark step as running
            with_write_lease([&](PGconn* c) {
                WorkflowStepResult sr;
                sr.step_index = step.index;
                sr.instruction_id = step.instruction_id;
                sr.status = "running";
                sr.started_at = now_epoch();
                wf_create_step_result(c, exec_id, sr);
            });

            // Determine dispatch items (foreach expansion)
            std::vector<std::string> dispatch_params;
            if (!step.foreach_source.empty()) {
                dispatch_params = expand_foreach(step.foreach_source, prev_result_json);
            } else {
                dispatch_params.push_back("{}");
            }

            // Dispatch with retry logic - no lease/conn held across a dispatch_fn call or
            // sleep_for (ADR-0064 "Lease discipline").
            bool step_succeeded = false;
            std::string step_result;

            for (int attempt = 1; attempt <= (step.retry_count + 1); ++attempt) {
                // For foreach, aggregate results
                nlohmann::json foreach_results = nlohmann::json::array();
                bool foreach_failed = false;
                bool permanent_failure = false; // no retry, no retry sleep

                for (const auto& params : dispatch_params) {
                    if (control.on_attempt)
                        control.on_attempt(step.index, attempt);
                    if (stop_before_attempt()) {
                        // Not retried, not slept on, and the step's on_failure policy does not
                        // apply: the whole run ends after this step is recorded.
                        run_stopped = true;
                        foreach_failed = true;
                        permanent_failure = true;
                        foreach_results.push_back(nlohmann::json(
                            {{"error", stop_cause == StopCause::kShutdown
                                           ? "run stopped before this attempt (server shutdown)"
                                           : "run stopped before this attempt"},
                             {"reason", stop_reason()}}));
                        break;
                    }
                    auto dispatch_result = dispatch_fn(step.instruction_id, agent_str, params);
                    // #2437-class guard: StepDispatchFn's documented contract (workflow_engine.hpp)
                    // is "returns a JSON result string" with no depth bound. Today's one wired
                    // caller (workflow_routes.cpp's dispatch_fn) only ever returns a small
                    // fixed-shape dispatch acknowledgment, but that closure's own comment notes the
                    // step-dispatch path does not yet correlate a step's real agent-reported
                    // response back through this same return value (tracked as future work) - so
                    // this is the chokepoint that has to hold regardless of which caller is wired
                    // today, not a guard against a live exploit path. Reject on the RAW text BEFORE
                    // the parse below (or anything else) interprets it: nlohmann::json::parse
                    // tolerates very deep input, but .dump() a few lines down, and every downstream
                    // consumer chained off prev_result_json (expand_foreach's array-iteration branch
                    // AND its "treat whole result as single item" fallback, plus the step condition
                    // evaluator) IS unboundedly recursive and SIGSEGVs the whole process well under
                    // 1 MiB of nesting. A depth violation here closes every one of those downstream
                    // traversals at once, since none of them can ever be reached with unchecked
                    // content that didn't pass through this one call first. Fails CLOSED onto the
                    // SAME error path an ordinary dispatch failure already uses just below:
                    // foreach_failed=true, a safe (non-nested) placeholder recorded in
                    // foreach_results, and NO poisoned structure ever enters
                    // foreach_results/step_result/prev_result_json. Never logs the payload, only
                    // identifiers.
                    const bool depth_exceeded =
                        dispatch_result && yuzu::server::mcp::json_exceeds_depth(
                                                *dispatch_result, yuzu::server::mcp::kMcpMaxJsonDepth);
                    if (dispatch_result && !depth_exceeded) {
                        // #4030 Gate 8 fix (Gate 4 unhappy-path finding UP-2):
                        // an un-guarded parse embeds the nlohmann `<discarded>`
                        // sentinel as literal text when `*dispatch_result` is
                        // not valid JSON, producing an invalid JSON document
                        // once `.dump()`'d downstream (verified via compile+
                        // run). Matches the read-side guard already applied at
                        // workflow_model.cpp's `confined_workflow_step_result_json`.
                        auto parsed = nlohmann::json::parse(*dispatch_result, nullptr, false);
                        foreach_results.push_back(parsed.is_discarded() ? nlohmann::json(nullptr)
                                                                        : parsed);
                    } else {
                        foreach_failed = true;
                        if (depth_exceeded) {
                            spdlog::error(
                                "WorkflowEngine: step {} (execution {}, instruction {}, agents {}) "
                                "dispatch result nested past the depth guard (max {}); treating as "
                                "a failed dispatch, cannot be safely parsed",
                                step.index, exec_id, step.instruction_id, agent_str,
                                yuzu::server::mcp::kMcpMaxJsonDepth);
                        }
                        foreach_results.push_back(nlohmann::json(
                            {{"error", depth_exceeded
                                           ? "dispatch result exceeded maximum JSON nesting depth"
                                           : dispatch_result.error().message}}));
                        if (!depth_exceeded && dispatch_result.error().permanent)
                            permanent_failure = true;
                    }
                    // A permanent failure repeats for every remaining item, so it ends the
                    // expansion as well as the retries.
                    if (permanent_failure)
                        break;
                }

                if (!foreach_failed) {
                    step_succeeded = true;
                    step_result = dispatch_params.size() == 1
                        ? foreach_results[0].dump()
                        : foreach_results.dump();
                    break;
                }

                // Retry if attempts remain (never after a permanent failure)
                if (!permanent_failure && attempt <= step.retry_count) {
                    // The pending retry ends here, un-made, when the server is stopping (the whole
                    // run stops) or draining (this step fails under its own on_failure policy and
                    // the run goes on). Either way no delay is slept for it.
                    const auto end_retry = [&](WorkflowStopLevel level) {
                        permanent_failure = true;
                        if (level == WorkflowStopLevel::kStop) {
                            note_stop(StopCause::kShutdown);
                            run_stopped = true;
                            foreach_results.push_back(nlohmann::json(
                                {{"error", "run stopped before the retry (server shutdown)"},
                                 {"reason", stop_reason()}}));
                        } else {
                            spdlog::warn("WorkflowEngine: step {} (execution {}) retry abandoned: "
                                         "the server is draining",
                                         step.index, exec_id);
                            foreach_results.push_back(nlohmann::json(
                                {{"error", "retry abandoned: the server is draining"}}));
                        }
                        step_result = foreach_results.dump();
                    };
                    if (const auto level = stop_level(); level != WorkflowStopLevel::kNone) {
                        end_retry(level);
                    } else {
                        spdlog::warn("WorkflowEngine: step {} attempt {}/{} failed, retrying in {}s",
                                     step.index, attempt, step.retry_count + 1,
                                     step.retry_delay_seconds);
                        // The delay never runs past the deadline: the next attempt then finds the
                        // run out of time and stops it, instead of the run sleeping on after the
                        // bound.
                        const auto delay = bounded_retry_delay(
                            step.retry_delay_seconds,
                            control.deadline
                                ? std::optional<std::chrono::steady_clock::duration>(
                                      *control.deadline - std::chrono::steady_clock::now())
                                : std::nullopt);
                        if (delay > std::chrono::steady_clock::duration::zero() &&
                            interruptible_wait(delay, [&] {
                                return stop_level() != WorkflowStopLevel::kNone;
                            }) == WaitResult::kWoken) {
                            if (const auto woke_level = stop_level();
                                woke_level != WorkflowStopLevel::kNone)
                                end_retry(woke_level);
                        }
                    }
                } else {
                    step_result = foreach_results.dump();
                }

                with_write_lease([&](PGconn* c) {
                    wf_update_attempt(c, exec_id, step.index, attempt);
                });
                if (permanent_failure)
                    break;
            }

            // Record step result
            with_write_lease([&](PGconn* c) {
                wf_update_step_result(c, exec_id, step.index,
                                      step_succeeded ? "success" : "failed", step_result);
            });
            current_step_open = false;

            if (run_stopped) {
                spdlog::warn("WorkflowEngine: execution {} stopped at step {} ({}); skipping the "
                             "remaining steps",
                             exec_id, step.index,
                             stop_cause == StopCause::kShutdown ? "server shutdown"
                                                                : "run bound reached");
                with_write_lease([&](PGconn* c) {
                    for (const auto& remaining : workflow.steps) {
                        if (remaining.index > step.index) {
                            wf_update_step_result(c, exec_id, remaining.index, "skipped",
                                                  skip_reason_json());
                        }
                    }
                });
                execution_failed = true;
                break;
            }

            if (step_succeeded) {
                prev_result_json = step_result;
            } else {
                // Handle failure based on on_failure policy
                if (step.on_failure == "continue") {
                    spdlog::warn("WorkflowEngine: step {} failed, continuing (on_failure=continue)",
                                 step.index);
                    prev_result_json = step_result;
                } else if (step.on_failure == "skip_remaining") {
                    spdlog::warn("WorkflowEngine: step {} failed, skipping remaining steps",
                                 step.index);
                    with_write_lease([&](PGconn* c) {
                        for (const auto& remaining : workflow.steps) {
                            if (remaining.index > step.index) {
                                wf_update_step_result(c, exec_id, remaining.index, "skipped",
                                                      R"({"reason":"previous step failed"})");
                            }
                        }
                    });
                    execution_failed = true;
                    break;
                } else {
                    // "abort" - default
                    spdlog::error("WorkflowEngine: step {} failed, aborting workflow", step.index);
                    with_write_lease([&](PGconn* c) {
                        for (const auto& remaining : workflow.steps) {
                            if (remaining.index > step.index) {
                                wf_update_step_result(c, exec_id, remaining.index, "skipped",
                                                      R"({"reason":"workflow aborted"})");
                            }
                        }
                    });
                    execution_failed = true;
                    break;
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("WorkflowEngine: execution {} step {} threw: {}", exec_id,
                      current_step_index, e.what());
        thrown = std::current_exception();
    } catch (...) {
        spdlog::error("WorkflowEngine: execution {} step {} threw a non-standard exception",
                      exec_id, current_step_index);
        thrown = std::current_exception();
    }
    if (thrown) {
        // Never retried: the throw left the loop. The in-flight step is failed and every later
        // step skipped, best effort (a write that cannot happen must not stop the finalize).
        execution_failed = true;
        try {
            with_write_lease([&](PGconn* c) {
                if (current_step_open)
                    wf_update_step_result(c, exec_id, current_step_index, "failed",
                                          nlohmann::json({{"error", "step dispatch threw"},
                                                          {"reason", kStepReasonDispatchException}})
                                              .dump());
                for (const auto& remaining : workflow.steps) {
                    if (remaining.index > current_step_index) {
                        wf_update_step_result(c, exec_id, remaining.index, "skipped",
                                              R"({"reason":"workflow aborted"})");
                    }
                }
            });
        } catch (...) { // NOLINT(bugprone-empty-catch): the finalize below must still run
        }
    }

    // Finalize execution — `WHERE status = 'running'` guards against clobbering a status a
    // concurrent cancel_execution() already moved to 'cancelled' (governance finding,
    // cpp-expert): the pre-migration mutex serialized cancel vs. finalize, so whichever ran last
    // silently won — a pre-existing "last writer wins" characteristic, not something this port
    // introduced. Postgres removes that serialization, so finalize needs its own guard to keep
    // the same "never overwrite a terminal cancel" property cancel_execution()'s own atomic
    // UPDATE already enforces from the other direction. Currently unreachable in production
    // (cancel_execution has no REST/MCP caller today), but this closes the gap correctly ahead
    // of that route being wired.
    // `finalize_status` is what we PROVE landed in the database — never assumed from the
    // in-process `execution_failed` bool alone (governance finding, sre + cpp-expert +
    // happy-path, independently convergent): a lease-acquire timeout drops the write entirely
    // (logged, no exception), and the WHERE-guard can legitimately match zero rows if a
    // concurrent cancel_execution() already moved the row to 'cancelled'. Reporting "success" in
    // either case — as an unconditional metric/log keyed only on `execution_failed` would —
    // would claim a write that didn't happen, or misreport a cancellation as a step failure.
    std::optional<std::string> finalize_status;
    // Landed: our write matched the running row. NoMatch: it executed and matched nothing (a
    // cancel already moved the row). Dropped: no lease, or the statement failed, so nothing was
    // written; only that is worth a second try.
    enum class FinalizeTry { kLanded, kNoMatch, kDropped };
    // `persist` keeps asking for a lease until `lease_timeout` is spent: one `try_acquire_for`
    // on a saturated pool gives up after the pool's own fast-fail (500 ms) whatever timeout it
    // was given, which would make the retry no longer than the first try. An empty answer is
    // followed by a back-off sleep (a pool whose connect breaker is armed answers empty at once),
    // and once a stop is seen the wait is cut to `kFinalizeStopBudget`.
    const auto try_finalize = [&](std::chrono::milliseconds lease_timeout,
                                  bool persist) -> FinalizeTry {
        const auto try_lease = [&](std::chrono::milliseconds t) { return pool_.try_acquire_for(t); };
        auto lease = persist
            ? acquire_within(
                  std::chrono::duration_cast<std::chrono::steady_clock::duration>(lease_timeout),
                  try_lease, [&] { return stop_level() == WorkflowStopLevel::kStop; },
                  std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                      kFinalizeStopBudget))
            : try_lease(lease_timeout);
        if (!lease) {
            spdlog::warn("WorkflowEngine::execute: lease unavailable for the final status write "
                         "of execution {}",
                         exec_id);
            return FinalizeTry::kDropped;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "UPDATE workflow_engine.workflow_executions SET status = $1, completed_at = $2::bigint "
            "WHERE id = $3 AND status = 'running' RETURNING status",
            std::vector<std::string>{execution_failed ? "failed" : "completed",
                                     std::to_string(now_epoch()), exec_id});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::warn("WorkflowEngine: finalize status update failed for {}: {}", exec_id,
                         PQresultErrorMessage(res.get()));
            return FinalizeTry::kDropped;
        }
        if (PQntuples(res.get()) == 0)
            return FinalizeTry::kNoMatch;
        finalize_status = col_str(res.get(), 0, 0); // "failed" or "completed": confirmed written
        return FinalizeTry::kLanded;
    };
    auto finalize_try = try_finalize(write_timeout_, /*persist=*/false);
    if (finalize_try == FinalizeTry::kDropped) {
        // The row would otherwise stay `running` with nothing to close it: one more try, with a
        // longer lease, before giving up on it.
        spdlog::warn("WorkflowEngine: final status write for execution {} dropped; retrying once "
                     "with a longer lease",
                     exec_id);
        finalize_try = try_finalize(finalize_retry_timeout_, /*persist=*/true);
    }
    if (finalize_try == FinalizeTry::kDropped) {
        spdlog::error("WorkflowEngine: execution {} was NOT finalized: the final status write "
                      "failed twice, so the row stays 'running' until something closes it",
                      exec_id);
        if (metrics_) {
            try {
                metrics_->counter("yuzu_server_workflow_finalize_failed_total", {}).increment();
            } catch (...) { // NOLINT(bugprone-empty-catch): observability must not fail the run
            }
        }
    }

    // Determine the real outcome for the log line (and, via the completed/not-completed split
    // below, the metric). If our own write landed, trust it. If not (lease timeout, or the guard
    // matched zero rows), read back what's actually there rather than guessing — a concurrent
    // cancel_execution() is the only thing that can move status off 'running' before finalize, so
    // the LOG distinguishes "cancelled" from "failed"; the metric still buckets both under
    // result="failed" (unchanged two-value cardinality) so an unexpected value can never leak
    // into a metric label.
    std::string outcome = finalize_status.value_or("");
    if (outcome.empty()) {
        auto exec_check = get_execution(exec_id);
        outcome = (exec_check && *exec_check && (*exec_check)->status == "cancelled")
            ? "cancelled" : "failed";
    }

    if (metrics_)
        metrics_->counter("yuzu_server_workflow_engine_writes_total",
                          {{"op", "execute"},
                           {"result", outcome == "completed" ? "success" : "failed"}})
            .increment();
    spdlog::info("WorkflowEngine: execution {} {}", exec_id, outcome);
    if (thrown)
        std::rethrow_exception(thrown);
    return exec_id;
}

// ── Execution queries ───────────────────────────────────────────────────────

std::expected<std::optional<WorkflowIdempotentRun>, std::string> WorkflowEngine::find_execution_by_key(
    const std::string& principal, const std::string& idempotency_key) const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, workflow_id, request_fingerprint, status, started_at "
        "FROM workflow_engine.workflow_executions WHERE principal = $1 AND idempotency_key = $2",
        std::vector<std::string>{principal, idempotency_key});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(res.get()));
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    WorkflowIdempotentRun run;
    run.execution_id = col_str(res.get(), 0, 0);
    run.workflow_id = col_str(res.get(), 0, 1);
    run.request_fingerprint = col_str(res.get(), 0, 2);
    run.status = col_str(res.get(), 0, 3);
    run.started_at = to_i64(col(res.get(), 0, 4));
    return run;
}

std::expected<std::optional<WorkflowExecution>, std::string> WorkflowEngine::get_execution(
    const std::string& id) const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, workflow_id, status, agent_ids_json, started_at, completed_at, "
        "current_step FROM workflow_engine.workflow_executions WHERE id = $1",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) +
                               PQresultErrorMessage(res.get()));
    if (PQntuples(res.get()) == 0)
        return std::nullopt;

    WorkflowExecution exec;
    exec.id = col_str(res.get(), 0, 0);
    exec.workflow_id = col_str(res.get(), 0, 1);
    exec.status = col_str(res.get(), 0, 2);
    exec.agent_ids_json = col_str(res.get(), 0, 3);
    exec.started_at = to_i64(col(res.get(), 0, 4));
    exec.completed_at = to_i64(col(res.get(), 0, 5));
    exec.current_step = static_cast<int>(to_i64(col(res.get(), 0, 6)));

    // Load step results — same lease/connection, second statement (PatchManager::get_deployment
    // precedent), not a nested acquire.
    pg::PgResult sres = pg::exec_params(
        lease.get(),
        "SELECT step_index, instruction_id, status, result_json, started_at, completed_at, "
        "attempt FROM workflow_engine.workflow_step_results WHERE execution_id = $1 "
        "ORDER BY step_index",
        std::vector<std::string>{id});
    if (sres.status() == PGRES_TUPLES_OK) {
        const int rows = PQntuples(sres.get());
        exec.step_results.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            WorkflowStepResult sr;
            sr.step_index = static_cast<int>(to_i64(col(sres.get(), i, 0)));
            sr.instruction_id = col_str(sres.get(), i, 1);
            sr.status = col_str(sres.get(), i, 2);
            sr.result_json = col_str(sres.get(), i, 3);
            sr.started_at = to_i64(col(sres.get(), i, 4));
            sr.completed_at = to_i64(col(sres.get(), i, 5));
            sr.attempt = static_cast<int>(to_i64(col(sres.get(), i, 6)));
            exec.step_results.push_back(std::move(sr));
        }
    } else {
        // Authoritative child read (same reasoning as wf_load_steps above) — a genuine
        // step-results query failure must surface as a typed failure, never as a successful
        // execution row with silently-empty step_results.
        spdlog::error("WorkflowEngine::get_execution: step-results query failed for {}: {}", id,
                     PQresultErrorMessage(sres.get()));
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(sres.get()));
    }

    return exec;
}

std::expected<std::vector<WorkflowExecution>, std::string> WorkflowEngine::list_executions(
    const std::string& workflow_id, int limit) const {
    std::vector<WorkflowExecution> result;
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    std::string sql = "SELECT id, workflow_id, status, agent_ids_json, started_at, "
                      "completed_at, current_step FROM workflow_engine.workflow_executions";
    std::vector<std::string> params;
    int idx = 1;
    if (!workflow_id.empty()) {
        sql += " WHERE workflow_id = $" + std::to_string(idx++);
        params.push_back(workflow_id);
    }
    sql += " ORDER BY started_at DESC LIMIT $" + std::to_string(idx);
    // Clamp — see list_workflows()'s identical comment.
    params.push_back(std::to_string(std::max(limit, 1)));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) +
                               PQresultErrorMessage(res.get()));

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        WorkflowExecution exec;
        exec.id = col_str(res.get(), i, 0);
        exec.workflow_id = col_str(res.get(), i, 1);
        exec.status = col_str(res.get(), i, 2);
        exec.agent_ids_json = col_str(res.get(), i, 3);
        exec.started_at = to_i64(col(res.get(), i, 4));
        exec.completed_at = to_i64(col(res.get(), i, 5));
        exec.current_step = static_cast<int>(to_i64(col(res.get(), i, 6)));
        result.push_back(std::move(exec));
    }
    return result;
}

// ── Execution list ───────────────────────────────────────────────────────────

namespace {

// `agent_ids_json` as jsonb, or an empty array when it is not valid JSON or not an array. Nested
// CASE on purpose: AND does not fix evaluation order, and a bare `::jsonb` cast would error the
// whole statement on one bad legacy row. Same intent as `workflow_execution_visible()`: malformed
// or non-array input yields no agents, so a confined caller never sees the run (fail closed).
// `pg_input_is_valid` is PostgreSQL 16+ (the documented floor).
//
// NOT a byte-for-byte image of that C++ oracle: jsonb and nlohmann accept different JSON. Every
// document the engine writes (`nlohmann::json(vector<string>).dump()`, execute()) agrees on both
// sides; the shapes below can only arrive by a write that bypasses the engine, and each is pinned
// with its direction in the "SQL visibility predicate" tests:
//   - jsonb refuses a `\u0000` escape or a UTF-8 byte-order mark; nlohmann takes both. The whole
//     document is "not an array" here, so a confined caller does NOT see the run (safe direction).
//   - jsonb takes a number past double range (`["a1",1e400]`); nlohmann rejects the document. A
//     confined caller whose scope holds "a1" DOES see the run here while the oracle hides it, so a
//     listed run's detail read can answer not-visible. The run still names an in-scope agent, so
//     nothing out of scope is exposed. In latest-per-workflow mode it can change which run is a
//     workflow's latest.
//   - Probed on PostgreSQL 18.6 (default max_stack_depth, 2 MB): an array nested about 18,700
//     levels deep (a document of about 37 KB) hits the stack-depth guard, a hard error
//     `pg_input_is_valid` does not trap; 18,650 levels is accepted. A stored row that deep fails
//     the statement, so every confined list answers the typed degrade (503, never rows) until the
//     row is gone. The engine only ever writes a flat array of strings, so only a bypassing write
//     can store one.
constexpr const char* kGuardedAgentIdsJsonb =
    "CASE WHEN pg_input_is_valid(e.agent_ids_json, 'jsonb') "
    "THEN (CASE WHEN jsonb_typeof(e.agent_ids_json::jsonb) = 'array' "
    "THEN e.agent_ids_json::jsonb ELSE '[]'::jsonb END) "
    "ELSE '[]'::jsonb END";

} // namespace

ExecutionPageSql build_execution_page_sql(
    const WorkflowExecutionListQuery& q,
    const std::optional<std::vector<std::string>>& visible_agents,
    std::chrono::milliseconds statement_timeout) {
    ExecutionPageSql out;
    int idx = 1;
    const auto bind = [&](std::string v) {
        out.params.push_back(std::move(v));
        return "$" + std::to_string(idx++);
    };
    out.limit = std::clamp(q.limit, 1, kWorkflowExecutionListMax);
    out.statement_timeout_sql =
        "SET LOCAL statement_timeout = '" + std::to_string(std::max<std::int64_t>(statement_timeout.count(), 1)) + "ms'"; // 0 means no timeout in PG

    out.sql = std::string("SELECT ") + (q.latest_per_workflow ? "DISTINCT ON (e.workflow_id) " : "") +
              "e.id, e.workflow_id, w.name, (w.deleted_at <> 0), e.status, e.current_step, "
              "e.started_at, e.completed_at "
              "FROM workflow_engine.workflow_executions e "
              "JOIN workflow_engine.workflows w ON w.id = e.workflow_id WHERE 1=1";
    if (!q.workflow_id.empty())
        out.sql += " AND e.workflow_id = " + bind(q.workflow_id);
    if (!q.status.empty())
        out.sql += " AND e.status = " + bind(q.status);
    if (q.since)
        out.sql += " AND e.started_at >= " + bind(std::to_string(*q.since)) + "::bigint";
    if (q.until)
        out.sql += " AND e.started_at < " + bind(std::to_string(*q.until)) + "::bigint";
    // The position is ANDed with every other clause, including the visibility clause below, so a
    // forged position can only narrow what the caller may already see.
    if (q.after && !q.latest_per_workflow) {
        const auto at = bind(std::to_string(q.after->key));
        out.sql += " AND (e.started_at < " + at + "::bigint OR (e.started_at = " + at +
                   "::bigint AND e.id < " + bind(q.after->id) + "))";
    }
    // Visibility MUST precede ORDER BY/LIMIT — ADR-0017 INV-3 (CRITICAL): applied after, an
    // invisible run would consume a page slot and a confined caller would get a short page.
    if (visible_agents) {
        if (visible_agents->empty()) {
            out.sql += " AND 1=0"; // visible to nobody
        } else {
            std::vector<std::string_view> sv(visible_agents->begin(), visible_agents->end());
            out.sql += std::string(" AND EXISTS (SELECT 1 FROM jsonb_array_elements(") +
                       kGuardedAgentIdsJsonb +
                       ") AS a(v) WHERE jsonb_typeof(a.v) = 'string' AND (a.v #>> '{}') = ANY(" +
                       bind(pg::to_text_array(sv)) + "::text[]))";
        }
    }
    out.sql += q.latest_per_workflow ? " ORDER BY e.workflow_id, e.started_at DESC, e.id DESC"
                                     : " ORDER BY e.started_at DESC, e.id DESC";
    // +1 sentinel row: trimmed off by the caller; its presence is the "more exist" signal.
    out.sql += " LIMIT " + bind(std::to_string(out.limit + 1)) + "::bigint";
    return out;
}

std::expected<WorkflowExecutionPage, std::string> WorkflowEngine::query_executions_page(
    const WorkflowExecutionListQuery& q,
    const std::optional<std::vector<std::string>>& visible_agents,
    std::chrono::milliseconds statement_timeout) const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    if (visible_agents && visible_agents->empty())
        return WorkflowExecutionPage{}; // deny-all: nothing to read, nothing to disclose
    const auto built = build_execution_page_sql(q, visible_agents, statement_timeout);
    const int limit = built.limit;

    WorkflowExecutionPage page;
    std::string err;
    const bool committed = pool_.with_txn_for(kReadTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t =
            pg::exec_params(c, built.statement_timeout_sql.c_str(), std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK) {
            err = PQresultErrorMessage(t.get());
            return false;
        }
        pg::PgResult res = pg::exec_params(c, built.sql.c_str(), built.params);
        if (res.status() != PGRES_TUPLES_OK) {
            err = PQresultErrorMessage(res.get());
            return false;
        }
        const int rows = PQntuples(res.get());
        const int take = std::min(rows, limit);
        page.rows.reserve(static_cast<std::size_t>(take));
        for (int i = 0; i < take; ++i) {
            WorkflowExecutionSummary s;
            s.id = col_str(res.get(), i, 0);
            s.workflow_id = col_str(res.get(), i, 1);
            s.workflow_name = col_str(res.get(), i, 2);
            s.workflow_deleted = col(res.get(), i, 3)[0] == 't';
            s.status = col_str(res.get(), i, 4);
            s.current_step = static_cast<int>(to_i64(col(res.get(), i, 5)));
            s.started_at = to_i64(col(res.get(), i, 6));
            s.completed_at = to_i64(col(res.get(), i, 7));
            page.rows.push_back(std::move(s));
        }
        if (rows > limit) {
            if (q.latest_per_workflow)
                page.truncated_by_cap = true;
            else
                page.next = keyset::Position{page.rows.back().started_at, page.rows.back().id};
        }
        return true;
    });
    if (!committed) {
        if (err.empty())
            err = "pool exhausted or transaction failed";
        spdlog::warn("WorkflowEngine::query_executions_page degraded: {}", err);
        return std::unexpected(std::string(kDbErrorPrefix) + err);
    }
    return page;
}

std::expected<void, std::string> WorkflowEngine::cancel_execution(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    // Atomic transition (governance finding): a separate SELECT-then-UPDATE let a concurrent
    // execute() finalize the same row to completed/failed between the two statements, and the
    // unconditional UPDATE would still overwrite that terminal status back to "cancelled". The
    // WHERE clause makes the pending/running check and the write one statement — the same class
    // of fix create_workflow/execute's admission guard already applies elsewhere in this file.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE workflow_engine.workflow_executions SET status = 'cancelled', "
        "completed_at = $1::bigint WHERE id = $2 AND status IN ('pending', 'running') "
        "RETURNING id",
        std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (metrics_)
            metrics_->counter("yuzu_server_workflow_engine_writes_total",
                              {{"op", "cancel_execution"}, {"result", "failed"}})
                .increment();
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(res.get()));
    }

    if (PQntuples(res.get()) > 0) {
        if (metrics_)
            metrics_->counter("yuzu_server_workflow_engine_writes_total",
                              {{"op", "cancel_execution"}, {"result", "success"}})
                .increment();
        return {};
    }

    // Zero rows: either unknown id or already-terminal — the UPDATE above already made the real
    // decision atomically; this follow-up read only shapes which message to return.
    pg::PgResult check = pg::exec_params(
        lease.get(), "SELECT status FROM workflow_engine.workflow_executions WHERE id = $1",
        std::vector<std::string>{id});
    if (check.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(check.get()));
    if (PQntuples(check.get()) == 0)
        return std::unexpected("execution not found");
    return std::unexpected("execution is already " + col_str(check.get(), 0, 0));
}

std::expected<ExecutionTableEstimate, std::string> WorkflowEngine::execution_table_estimate() const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");
    // The same bounds as the other maintenance-tick samplers (count_stale_agents): this runs on a
    // serial thread shared with the revocation sweep, so both the acquire and the statement are
    // capped.
    constexpr std::chrono::milliseconds kSampleAcquireTimeout{250};
    std::optional<ExecutionTableEstimate> out;
    std::string failure = "pool exhausted";
    const bool ran = pool_.with_txn_for(kSampleAcquireTimeout, [&](PGconn* c) -> bool {
        failure = "sample failed";
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        // One catalog row: reltuples is -1 until the first vacuum/analyze and n_live_tup restarts
        // from 0 after a crash, so each covers the other's blind spot. Neither scans the table.
        pg::PgResult res = pg::exec_params(
            c,
            "SELECT GREATEST(COALESCE(s.n_live_tup, 0), GREATEST(r.reltuples, 0)::bigint)::bigint, "
            "pg_total_relation_size(r.oid)::bigint "
            "FROM pg_class r LEFT JOIN pg_stat_user_tables s ON s.relid = r.oid "
            "WHERE r.oid = 'workflow_engine.workflow_executions'::regclass",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return false;
        out = ExecutionTableEstimate{to_i64(col(res.get(), 0, 0)), to_i64(col(res.get(), 0, 1))};
        return true;
    });
    if (!ran || !out)
        return std::unexpected(std::string(kDbErrorPrefix) + failure);
    return *out;
}

void WorkflowEngine::refresh_table_size_metrics() noexcept {
    if (!metrics_)
        return;
    try {
        if (auto est = execution_table_estimate()) {
            metrics_->gauge(kWorkflowExecutionsRowsMetric).set(static_cast<double>(est->rows));
            metrics_->gauge(kWorkflowExecutionsBytesMetric).set(static_cast<double>(est->bytes));
        } else {
            metrics_->counter(kWorkflowExecutionsStatsUnavailableMetric).increment();
        }
    } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail the maintenance tick
    }
}

} // namespace yuzu::server
