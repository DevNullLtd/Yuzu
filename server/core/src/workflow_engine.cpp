#include "workflow_engine.hpp"

#include "mcp_jsonrpc.hpp" // json_exceeds_depth / kMcpMaxJsonDepth (#2437-class depth guard)
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
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

WorkflowEngine::WorkflowEngine(pg::PgPool& pool) : pool_(pool) {
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
    ConditionEvalFn condition_fn) {

    if (!dispatch_fn)
        return std::unexpected("dispatch function is required");
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "workflow engine not available");

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
    const std::string agent_str = nlohmann::json(agent_ids).dump();

    // New atomicity (ADR-0064): execution-row creation + every step-result pre-creation are one
    // transaction. The execution insert is an INSERT...SELECT...WHERE deleted_at = 0, which
    // atomically re-proves the workflow is still active at admission time — closing the race
    // between the get_workflow() read above and this statement (a concurrent delete_workflow()
    // in between now fails admission here instead of silently orphaning a new execution against
    // a since-deleted workflow).
    bool admitted = false;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult ires = pg::exec_params(
            conn,
            "INSERT INTO workflow_engine.workflow_executions "
            "(id, workflow_id, status, agent_ids_json, started_at, current_step) "
            "SELECT $1, w.id, 'running', $3, $4::bigint, 0 "
            "FROM workflow_engine.workflows w WHERE w.id = $2 AND w.deleted_at = 0 "
            "RETURNING id",
            std::vector<std::string>{exec_id, workflow_id, agent_str, now});
        if (ires.status() != PGRES_TUPLES_OK) {
            spdlog::error("WorkflowEngine::execute: execution insert failed: {}",
                          PQresultErrorMessage(ires.get()));
            return false;
        }
        if (PQntuples(ires.get()) == 0) {
            // Workflow vanished/soft-deleted since get_workflow() above — commit the (no-op)
            // txn; `admitted` stays false and the caller gets the ordinary not-found error.
            return true;
        }
        admitted = true;

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
        return true;
    });

    if (!ok)
        return std::unexpected(std::string(kDbErrorPrefix) + "failed to admit execution");
    if (!admitted)
        return std::unexpected("workflow not found: " + workflow_id);

    // Every write from here on is standalone/best-effort (ADR-0064 "Mid-execution write
    // degradation") — a lease timeout mid-execute degrades to unrecorded history for that one
    // write rather than aborting an in-flight, possibly already-dispatched fleet operation.
    auto with_write_lease = [&](auto&& fn) {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease) {
            spdlog::warn("WorkflowEngine::execute: lease unavailable mid-execution — a write "
                        "for execution {} was dropped (best-effort history, ADR-0064)",
                        exec_id);
            return;
        }
        fn(lease.get());
    };

    // Execute steps sequentially
    std::string prev_result_json = "{}";
    bool execution_failed = false;

    for (const auto& step : workflow.steps) {
        // Check if execution was cancelled
        {
            auto exec_check = get_execution(exec_id);
            if (exec_check && *exec_check && (*exec_check)->status == "cancelled") {
                execution_failed = true;
                break;
            }
        }

        // Update current step — `WHERE status = 'running'` guards this write the same way
        // finalize's is guarded (governance finding, security-guardian + docs-writer,
        // independently): without it, a concurrent cancel_execution() landing between the
        // cancellation check above and this write could flip status back to 'running', making
        // the loop (and finalize afterwards) forget the cancellation ever happened. `RETURNING id`
        // makes the CAS observable (governance finding, security-guardian): a CONFIRMED zero-row
        // result means the guard didn't match — status was no longer 'running', i.e. a cancel landed
        // in the window between the check above and this write — so the loop stops immediately
        // instead of dispatching one more step past the cancel. A lease timeout or query failure is
        // NOT treated as a mismatch (that would break the ADR-0064 degrade-and-continue posture for
        // an ordinary transient failure) — only a definite, executed CAS that matched zero rows
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
                // Condition not met — skip step
                with_write_lease([&](PGconn* c) {
                    wf_update_step_result(c, exec_id, step.index, "skipped",
                                          R"({"reason":"condition not met"})");
                });
                spdlog::info("WorkflowEngine: step {} skipped (condition: {})", step.index,
                            step.condition);
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

        // Dispatch with retry logic — no lease/conn held across a dispatch_fn call or
        // sleep_for (ADR-0064 "Lease discipline").
        bool step_succeeded = false;
        std::string step_result;

        for (int attempt = 1; attempt <= (step.retry_count + 1); ++attempt) {
            // For foreach, aggregate results
            nlohmann::json foreach_results = nlohmann::json::array();
            bool foreach_failed = false;

            for (const auto& params : dispatch_params) {
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
                                       : dispatch_result.error()}}));
                }
            }

            if (!foreach_failed) {
                step_succeeded = true;
                step_result = dispatch_params.size() == 1
                    ? foreach_results[0].dump()
                    : foreach_results.dump();
                break;
            }

            // Retry if attempts remain
            if (attempt <= step.retry_count) {
                spdlog::warn("WorkflowEngine: step {} attempt {}/{} failed, retrying in {}s",
                             step.index, attempt, step.retry_count + 1, step.retry_delay_seconds);
                std::this_thread::sleep_for(
                    std::chrono::seconds(step.retry_delay_seconds));
            } else {
                step_result = foreach_results.dump();
            }

            with_write_lease([&](PGconn* c) {
                wf_update_attempt(c, exec_id, step.index, attempt);
            });
        }

        // Record step result
        with_write_lease([&](PGconn* c) {
            wf_update_step_result(c, exec_id, step.index,
                                  step_succeeded ? "success" : "failed", step_result);
        });

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
                // "abort" — default
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
    with_write_lease([&](PGconn* c) {
        pg::PgResult res = pg::exec_params(
            c,
            "UPDATE workflow_engine.workflow_executions SET status = $1, completed_at = $2::bigint "
            "WHERE id = $3 AND status = 'running' RETURNING status",
            std::vector<std::string>{execution_failed ? "failed" : "completed",
                                     std::to_string(now_epoch()), exec_id});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::warn("WorkflowEngine: finalize status update failed for {}: {}", exec_id,
                        PQresultErrorMessage(res.get()));
            return;
        }
        if (PQntuples(res.get()) > 0)
            finalize_status = col_str(res.get(), 0, 0); // "failed" or "completed" — confirmed written
    });

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
    return exec_id;
}

// ── Execution queries ───────────────────────────────────────────────────────

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

} // namespace yuzu::server
