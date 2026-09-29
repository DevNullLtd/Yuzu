#include "schedule_engine.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "schedule_params_parsers.hpp"
#include "sensitive_instruction_params.hpp" // schedule_params_contain_sensitive_key (#3136 blocker)
#include "store_errors.hpp" // kDbErrorPrefix (query_schedules_checked, #4030 review finding)

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "schedule_engine";

// Bounded acquires (ADR-0012 §2). No hot-path caller here — every runtime
// acquire uses the ordinary CRUD budget (matches PatchManager/DirectorySync).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// query_schedules()/query_schedules_checked() row cap. No creation-side
// ceiling exists (create_schedule has no count check), so a fleet can
// legitimately exceed this — query_schedules_checked() detects and reports
// it via ScheduleListResult::truncated (#4030 review finding).
constexpr int kScheduleListCap = 100;

std::string generate_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

InstructionSchedule row_to_schedule(PGresult* r, int i) {
    InstructionSchedule s;
    s.id = col_str(r, i, 0);
    s.name = col_str(r, i, 1);
    s.definition_id = col_str(r, i, 2);
    s.frequency_type = col_str(r, i, 3);
    s.interval_minutes = static_cast<int>(to_i64(col(r, i, 4)));
    s.time_of_day = col_str(r, i, 5);
    s.day_of_week = static_cast<int>(to_i64(col(r, i, 6)));
    s.day_of_month = static_cast<int>(to_i64(col(r, i, 7)));
    s.scope_expression = col_str(r, i, 8);
    s.requires_approval = to_bool(col(r, i, 9));
    s.enabled = to_bool(col(r, i, 10));
    s.next_execution_at = to_i64(col(r, i, 11));
    s.last_executed_at = to_i64(col(r, i, 12));
    s.execution_count = static_cast<int>(to_i64(col(r, i, 13)));
    s.created_by = col_str(r, i, 14);
    s.created_at = to_i64(col(r, i, 15));
    s.parameter_values = col_str(r, i, 16);
    return s;
}

constexpr const char* kSelectAllCols =
    "id, name, definition_id, frequency_type, interval_minutes, "
    "time_of_day, day_of_week, day_of_month, scope_expression, "
    "requires_approval, enabled, next_execution_at, last_executed_at, "
    "execution_count, created_by, created_at, parameter_values";

bool is_valid_frequency(const std::string& freq) {
    return freq == "once" || freq == "interval" || freq == "daily" || freq == "weekly" ||
           freq == "monthly";
}

int64_t compute_initial_next_execution(const std::string& frequency_type, int interval_minutes) {
    auto now = now_epoch();

    if (frequency_type == "once") {
        return now;
    }
    if (frequency_type == "interval") {
        return now + static_cast<int64_t>(interval_minutes) * 60;
    }
    if (frequency_type == "daily") {
        return now + 86400;
    }
    if (frequency_type == "weekly") {
        return now + 7 * 86400;
    }
    if (frequency_type == "monthly") {
        return now + 30 * 86400;
    }

    return now;
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Folds the SQLite-era v1+v2 ladder (v2 added parameter_values, PR1.5a)
    // into a single v1 DDL — no separate migration step on a fresh Postgres
    // schema (ADR-0009 fresh-start-by-default). Adds a partial index on
    // (next_execution_at) that the SQLite era never had — evaluate_due()'s
    // WHERE clause (enabled=1 AND next_execution_at>0 AND
    // next_execution_at<=now) and its ORDER BY next_execution_at both match
    // this index's predicate/column exactly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE schedules ("
         "  id                 TEXT    PRIMARY KEY,"
         "  name               TEXT    NOT NULL,"
         "  definition_id      TEXT    NOT NULL,"
         "  frequency_type     TEXT    NOT NULL DEFAULT 'once',"
         "  interval_minutes   INTEGER NOT NULL DEFAULT 60,"
         "  time_of_day        TEXT    NOT NULL DEFAULT '00:00',"
         "  day_of_week        INTEGER NOT NULL DEFAULT 0,"
         "  day_of_month       INTEGER NOT NULL DEFAULT 1,"
         "  scope_expression   TEXT    NOT NULL DEFAULT '',"
         "  requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,"
         "  enabled            BOOLEAN NOT NULL DEFAULT TRUE,"
         "  next_execution_at  BIGINT  NOT NULL DEFAULT 0,"
         "  last_executed_at   BIGINT  NOT NULL DEFAULT 0,"
         "  execution_count    INTEGER NOT NULL DEFAULT 0,"
         "  created_by         TEXT    NOT NULL DEFAULT '',"
         "  created_at         BIGINT  NOT NULL DEFAULT 0,"
         "  parameter_values   TEXT    NOT NULL DEFAULT '{}'"
         ");"
         "CREATE INDEX idx_schedules_due ON schedules(next_execution_at) "
         "  WHERE enabled AND next_execution_at > 0;"},
    };
    return kMigrations;
}

} // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

ScheduleEngine::ScheduleEngine(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ScheduleEngine: no database connection at construction ({}) — schedule "
                      "engine disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ScheduleEngine: schema migration failed — schedule engine disabled");
        return;
    }
    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag. The caller
    // (server.cpp) separately runs legacy_sqlite_probe::warn_if_legacy_rows()
    // over the legacy instructions.db so a locally-wrong "no production
    // fleet" premise still gets a loud signal.
    spdlog::info("ScheduleEngine initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

void ScheduleEngine::stop() {
    // No engine-side resources to stop: the poller thread that drives
    // evaluate_due/advance_schedule (#1191) is owned by ServerImpl
    // (schedule_tick_thread_, joined in stop() before the stores), the same
    // ownership shape as policy_eval_thread_ / preflight_runner_thread_.
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<InstructionSchedule> ScheduleEngine::query_schedules(const ScheduleQuery& q) const {
    std::vector<InstructionSchedule> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    std::string sql =
        std::string("SELECT ") + kSelectAllCols + " FROM schedule_engine.schedules WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.enabled_only) {
        sql += " AND enabled = TRUE";
    }
    sql += " ORDER BY name ASC LIMIT " + std::to_string(kScheduleListCap);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ScheduleEngine::query_schedules: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return results;
    }

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_schedule(res.get(), i));
    return results;
}

// Checked twin of query_schedules() above (#4030 review finding, blocking):
// the same three degraded conditions that method silently folds into an
// empty vector -- engine not open, pool-lease timeout, and a failed SQL
// query -- are reported as std::unexpected here instead, mirroring
// WorkflowEngine::list_workflows's identical shape (workflow_engine.cpp) so
// GET /api/v1/schedules and MCP list_schedules can emit the same honest
// 503/retry_after_ms their sibling GET /api/v1/workflows already does rather
// than serializing a false empty-success response.
std::expected<ScheduleListResult, std::string>
ScheduleEngine::query_schedules_checked(const ScheduleQuery& q) const {
    if (!open_)
        return std::unexpected(std::string(kDbErrorPrefix) + "schedule engine not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDbErrorPrefix) + "pool exhausted");

    std::string sql =
        std::string("SELECT ") + kSelectAllCols + " FROM schedule_engine.schedules WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.enabled_only) {
        sql += " AND enabled = TRUE";
    }
    // #4030 review finding (blocking): query one row PAST the cap so a real
    // fleet size of exactly kScheduleListCap is never misreported as
    // truncated -- the simpler "returned == limit" heuristic used by MCP
    // query_responses's hit_cap would false-positive on that boundary here,
    // since (unlike query_responses) this query has no caller-supplied limit
    // to compare against, only the one fixed cap. The sentinel row is
    // trimmed back off below, never returned to the caller.
    sql += " ORDER BY name ASC LIMIT " + std::to_string(kScheduleListCap + 1);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDbErrorPrefix) + PQresultErrorMessage(res.get()));

    ScheduleListResult out;
    const int rows = PQntuples(res.get());
    out.truncated = rows > kScheduleListCap;
    const int take = out.truncated ? kScheduleListCap : rows;
    out.schedules.reserve(static_cast<std::size_t>(take));
    for (int i = 0; i < take; ++i)
        out.schedules.push_back(row_to_schedule(res.get(), i));
    return out;
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
ScheduleEngine::create_schedule(const InstructionSchedule& sched) {
    if (!open_)
        return std::unexpected("database not open");
    if (sched.name.empty())
        return std::unexpected("name is required");
    if (sched.definition_id.empty())
        return std::unexpected("definition_id is required");
    if (!is_valid_frequency(sched.frequency_type))
        return std::unexpected(
            "frequency_type must be one of: once, interval, daily, weekly, monthly");
    // Floor guard: a 0/negative interval would compute next_execution_at ==
    // now and, now that the ScheduleRunner poller drives evaluate_due
    // (#1191), re-fire on every tick forever. advance_schedule clamps the
    // same way for pre-floor legacy rows.
    if (sched.frequency_type == "interval" && sched.interval_minutes < 1)
        return std::unexpected("interval_minutes must be >= 1");
    // Persistence-layer backstop (PR1.5a): schedule_routes.cpp already
    // validates+canonicalizes the caller-supplied `parameters` field before
    // it reaches here, but this call is what makes that guarantee hold for
    // EVERY caller of create_schedule, not just the REST route — including
    // an empty sched.parameter_values, which canonicalizes to "{}" rather
    // than being stored as truly empty. Re-canonicalizing an
    // already-canonical string is a cheap no-op re-serialization.
    auto canon_params = validate_and_canonicalize_schedule_params(sched.parameter_values);
    if (!canon_params)
        return std::unexpected(std::string(to_string(canon_params.error())));

    // #3136 blocker: a schedule's parameter_values is the SOLE record
    // ScheduleRunner::dispatch_tracked reads back to fire every future
    // occurrence (schedule_runner.cpp) — unlike the one-shot dispatch paths
    // (workflow_routes.cpp, mcp_server.cpp, rest_api_v1.cpp), there is no
    // separate raw in-memory value to redact FROM: the persisted blob IS
    // what gets redispatched. Redacting it here would silently break
    // re-dispatch instead of merely protecting a history row, so a
    // grant_secret-bearing schedule is refused outright — a single-
    // redemption, ~15-minute-TTL credential cannot survive as a repeatable
    // schedule regardless of this leak. See sensitive_instruction_params.hpp.
    if (schedule_params_contain_sensitive_key(*canon_params))
        return std::unexpected(
            "parameters contain a one-time credential (grant_secret/grant_id) that cannot be "
            "scheduled — mint a fresh grant and dispatch it directly instead");

    auto id = sched.id.empty() ? generate_id() : sched.id;
    auto now = now_epoch();
    auto next = sched.next_execution_at > 0
                    ? sched.next_execution_at
                    : compute_initial_next_execution(sched.frequency_type, sched.interval_minutes);

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "INSERT INTO schedule_engine.schedules "
            "(id, name, definition_id, frequency_type, interval_minutes, "
            " time_of_day, day_of_week, day_of_month, scope_expression, "
            " requires_approval, enabled, next_execution_at, last_executed_at, "
            " execution_count, created_by, created_at, parameter_values) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            std::vector<std::string>{
                id, sched.name, sched.definition_id, sched.frequency_type,
                std::to_string(sched.interval_minutes), sched.time_of_day,
                std::to_string(sched.day_of_week), std::to_string(sched.day_of_month),
                sched.scope_expression, sched.requires_approval ? "true" : "false",
                sched.enabled ? "true" : "false", std::to_string(next),
                std::to_string(sched.last_executed_at), std::to_string(sched.execution_count),
                sched.created_by, std::to_string(sched.created_at > 0 ? sched.created_at : now),
                *canon_params});
        if (res.status() != PGRES_COMMAND_OK) {
            spdlog::error("ScheduleEngine::create_schedule: insert failed: {}",
                          PQresultErrorMessage(res.get()));
            return false;
        }
        return true;
    });

    if (!ok)
        return std::unexpected("insert failed (pool degraded or transaction failed)");

    spdlog::info("ScheduleEngine: created schedule '{}' (id={}, freq={})", sched.name, id,
                 sched.frequency_type);
    return id;
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

bool ScheduleEngine::delete_schedule(const std::string& id, const std::string& created_by) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    // M-01/L-01 (#1806): owner-scoped RETURNING delete — created_by is
    // enforced at the SQL WHERE clause (the sole seam, matching
    // deployment_run_store's owner-scope pattern) instead of a separate
    // pre-check, so there is no TOCTOU window between "is this mine" and
    // "delete it".
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM schedule_engine.schedules WHERE id=$1 AND created_by=$2 RETURNING id",
        std::vector<std::string>{id, created_by});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

bool ScheduleEngine::set_enabled(const std::string& id, bool enabled,
                                 const std::string& created_by) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    // M-01 (#1806): same owner-scoped RETURNING pattern as delete_schedule.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE schedule_engine.schedules SET enabled=$1 WHERE id=$2 AND created_by=$3 "
        "RETURNING id",
        std::vector<std::string>{enabled ? "true" : "false", id, created_by});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

// ---------------------------------------------------------------------------
// Evaluate due schedules
// ---------------------------------------------------------------------------

std::vector<InstructionSchedule> ScheduleEngine::evaluate_due() const {
    std::vector<InstructionSchedule> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    auto now = now_epoch();

    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM schedule_engine.schedules WHERE enabled = TRUE"
                      " AND next_execution_at > 0"
                      " AND next_execution_at <= $1"
                      " ORDER BY next_execution_at ASC";

    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ScheduleEngine::evaluate_due: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return results;
    }

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_schedule(res.get(), i));
    return results;
}

// ---------------------------------------------------------------------------
// Advance schedule after firing
// ---------------------------------------------------------------------------

void ScheduleEngine::advance_schedule(const std::string& id) {
    if (!open_)
        return;

    // Collapses the SQLite-era locked SELECT-then-C++-arithmetic-then-UPDATE
    // (a read-modify-write spanning two statements — the actual race the
    // app-level shared_mutex existed to cover, since SQLITE_OPEN_FULLMUTEX
    // only serialized each individual call, not the pair) into ONE atomic
    // statement. The frequency arithmetic moves into a SQL CASE so the whole
    // read-compute-write happens inside a single round trip under
    // Postgres's own row-level locking — no app-level lock needed.
    auto now = std::to_string(now_epoch());
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "UPDATE schedule_engine.schedules SET "
            "  next_execution_at = CASE frequency_type "
            "    WHEN 'once' THEN 0 "
            "    WHEN 'interval' THEN $1::bigint + GREATEST(interval_minutes, 1) * 60 "
            "    WHEN 'daily' THEN $1::bigint + 86400 "
            "    WHEN 'weekly' THEN $1::bigint + 604800 "
            "    WHEN 'monthly' THEN $1::bigint + 2592000 "
            // Deliberate divergence from the old C++ arithmetic this
            // replaces, which defaulted an unrecognized frequency_type to 0
            // (disabling the schedule). This CASE's ELSE instead leaves
            // next_execution_at unchanged (governance PR review, 2026-08-31,
            // Doomgoose: on a row that was just found due, that means it
            // stays due and re-fires every subsequent poller tick). Confirmed
            // unreachable on every current write path: create_schedule
            // validates via is_valid_frequency, no UPDATE ... SET
            // frequency_type exists anywhere, and ADR-0009's fresh-start
            // cutover means no legacy row can carry a stale value either. Not
            // fixed to match the old default because doing so silently
            // (re-adding a fourth WHEN-less branch) would be just as easy to
            // miss again — pinned here instead so a future editor sees it.
            "    ELSE next_execution_at "
            "  END, "
            "  last_executed_at = $1::bigint, "
            "  execution_count = execution_count + 1 "
            "WHERE id = $2 "
            "RETURNING next_execution_at, frequency_type",
            std::vector<std::string>{now, id});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ScheduleEngine::advance_schedule: update failed for id={}: {}", id,
                          PQresultErrorMessage(res.get()));
            return false;
        }
        // Zero rows affected = today's silent no-op shape (id does not
        // exist) — not a failure.
        if (PQntuples(res.get()) > 0) {
            spdlog::debug("ScheduleEngine: advanced schedule id={} (freq={}, next_at={})", id,
                          col_str(res.get(), 0, 1), col_str(res.get(), 0, 0));
        }
        return true;
    });

    // L-02 (#1806) parity: a discarded failure left a failed advance silent
    // — the schedule would stay at its old next_execution_at and re-fire on
    // every subsequent poller tick instead of just this one. with_txn_for
    // itself logs nothing on a lease/BEGIN failure, so log here too.
    if (!ok) {
        spdlog::error("ScheduleEngine::advance_schedule: failed for id={} (pool degraded or "
                      "transaction failed)",
                      id);
    }
}

} // namespace yuzu::server
