#include "patch_manager.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>
#include <regex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "patch_manager";
constexpr const char* kInventoryCols =
    "agent_id, kb_id, title, severity, status, released_at, scanned_at";
constexpr const char* kDeploymentCols =
    "id, kb_id, title, status, created_by, reboot_needed, created_at, completed_at, "
    "total_targets, completed_targets, failed_targets, reboot_delay_seconds, reboot_at";
constexpr const char* kTargetCols = "agent_id, status, error, started_at, completed_at";

// Bounded acquires (ADR-0012 §2). No hot-path caller here (unlike
// OffloadTargetStore's fire_event) — every runtime acquire uses the
// ordinary CRUD budget.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// Bounds deploy_patch's unnest()-driven target batch insert. An
// unbounded agent_ids list would hold the shared pool connection for
// the duration of the insert, contributing to pool starvation for
// unrelated stores under a near-fleet-wide deploy request. 5000
// matches the DoS-cap default used for the same class of bulk
// operator-supplied fleet-wide list elsewhere (fleet-viz machines_max).
constexpr std::size_t kMaxDeployTargets = 5000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Folds the SQLite-era out-of-ledger `ALTER TABLE patch_deployments ADD
    // COLUMN reboot_delay_seconds/reboot_at` hack (patch_manager.cpp:81-87
    // pre-migration) directly into this single v1 DDL — no separate
    // migration step needed on a fresh Postgres schema.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE patch_inventory ("
         "  agent_id    TEXT   NOT NULL,"
         "  kb_id       TEXT   NOT NULL,"
         "  title       TEXT   NOT NULL DEFAULT '',"
         "  severity    TEXT   NOT NULL DEFAULT 'Unspecified',"
         "  status      TEXT   NOT NULL DEFAULT 'missing',"
         "  released_at BIGINT NOT NULL DEFAULT 0,"
         "  scanned_at  BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (agent_id, kb_id)"
         ");"
         "CREATE TABLE patch_deployments ("
         "  id                   TEXT    PRIMARY KEY,"
         "  kb_id                TEXT    NOT NULL,"
         "  title                TEXT    NOT NULL DEFAULT '',"
         "  status               TEXT    NOT NULL DEFAULT 'pending',"
         "  created_by           TEXT    NOT NULL DEFAULT '',"
         "  reboot_needed        BOOLEAN NOT NULL DEFAULT FALSE,"
         "  reboot_delay_seconds INTEGER NOT NULL DEFAULT 300,"
         "  reboot_at            BIGINT  NOT NULL DEFAULT 0,"
         "  created_at           BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at         BIGINT  NOT NULL DEFAULT 0,"
         "  total_targets        INTEGER NOT NULL DEFAULT 0,"
         "  completed_targets    INTEGER NOT NULL DEFAULT 0,"
         "  failed_targets       INTEGER NOT NULL DEFAULT 0"
         ");"
         "CREATE TABLE patch_deployment_targets ("
         "  deployment_id TEXT    NOT NULL REFERENCES patch_deployments(id) ON DELETE CASCADE,"
         "  agent_id      TEXT    NOT NULL,"
         "  status        TEXT    NOT NULL DEFAULT 'pending',"
         "  error         TEXT    NOT NULL DEFAULT '',"
         "  started_at    BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at  BIGINT  NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (deployment_id, agent_id)"
         ");"
         "CREATE INDEX idx_patch_inv_kb ON patch_inventory(kb_id);"
         "CREATE INDEX idx_patch_inv_status ON patch_inventory(status);"
         "CREATE INDEX idx_patch_inv_agent ON patch_inventory(agent_id);"
         "CREATE INDEX idx_patch_depl_status ON patch_deployments(status);"
         "CREATE INDEX idx_patch_depl_targets ON patch_deployment_targets(deployment_id);"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    offload_target_store.cpp / auth_db.cpp's own file-local copies) ───────

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

PatchDeployment row_to_deployment(PGresult* r, int i) {
    PatchDeployment d;
    d.id = col_str(r, i, 0);
    d.kb_id = col_str(r, i, 1);
    d.title = col_str(r, i, 2);
    d.status = col_str(r, i, 3);
    d.created_by = col_str(r, i, 4);
    d.reboot_if_needed = to_bool(col(r, i, 5));
    d.created_at = to_i64(col(r, i, 6));
    d.completed_at = to_i64(col(r, i, 7));
    d.total_targets = static_cast<int>(to_i64(col(r, i, 8)));
    d.completed_targets = static_cast<int>(to_i64(col(r, i, 9)));
    d.failed_targets = static_cast<int>(to_i64(col(r, i, 10)));
    d.reboot_delay_seconds = static_cast<int>(to_i64(col(r, i, 11)));
    d.reboot_at = to_i64(col(r, i, 12));
    return d;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

PatchManager::PatchManager(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("PatchManager: no database connection at construction ({}) — patch "
                      "manager disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("PatchManager: schema migration failed — patch manager disabled");
        return;
    }
    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag. The caller
    // (server.cpp) separately runs legacy_sqlite_probe::warn_if_legacy_rows()
    // over the legacy patches.db so a locally-wrong "no production fleet"
    // premise still gets a loud signal.
    spdlog::info("PatchManager initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

std::string PatchManager::generate_id() const {
    return gen_id();
}

// ── Patch inventory ──────────────────────────────────────────────────────────

void PatchManager::record_patches(const std::string& agent_id,
                                  const std::vector<PatchInfo>& patches) {
    if (!open_ || patches.empty())
        return;

    // De-duplicate on kb_id, LAST occurrence wins — matches the SQLite era's
    // per-row INSERT OR REPLACE semantics (a later row for the same kb_id
    // silently overwrote an earlier one within the same call). A single
    // batch INSERT ... ON CONFLICT DO UPDATE cannot express that: Postgres
    // rejects a statement that would affect the same conflict target twice
    // ("ON CONFLICT DO UPDATE command cannot affect row a second time"),
    // which would otherwise fail the WHOLE upsert — silently stalling this
    // agent's entire inventory report, not just the duplicated row — on a
    // scan report containing the same kb_id more than once.
    std::unordered_map<std::string, const PatchInfo*> latest;
    latest.reserve(patches.size());
    for (const auto& p : patches)
        latest[p.kb_id] = &p;

    std::vector<std::string_view> kb_ids, titles, severities, statuses;
    std::vector<std::string> released_ats;
    kb_ids.reserve(latest.size());
    titles.reserve(latest.size());
    severities.reserve(latest.size());
    statuses.reserve(latest.size());
    released_ats.reserve(latest.size());
    for (const auto& [kb_id, p] : latest) {
        kb_ids.emplace_back(p->kb_id);
        titles.emplace_back(p->title);
        severities.emplace_back(p->severity);
        statuses.emplace_back(p->status);
        released_ats.push_back(std::to_string(p->released_at));
    }
    std::vector<std::string_view> released_at_views(released_ats.begin(), released_ats.end());

    const std::string now_str = std::to_string(now_epoch());

    // Whole batch in one transaction — translated 1:1 from the SQLite-era
    // explicit BEGIN TRANSACTION/COMMIT wrapping this same per-patch loop.
    // A single unnest()-driven batch INSERT (rather than N round trips
    // inside the txn) keeps a large scan report from paying N statement
    // round trips (preflight_run_store.cpp's run_device seed insert is the
    // existing precedent for this shape).
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "INSERT INTO patch_manager.patch_inventory "
            "(agent_id, kb_id, title, severity, status, released_at, scanned_at) "
            "SELECT $1, u.kb_id, u.title, u.severity, u.status, u.released_at::bigint, $7::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) "
            "  AS u(kb_id, title, severity, status, released_at) "
            "ON CONFLICT (agent_id, kb_id) DO UPDATE SET "
            "  title = EXCLUDED.title, severity = EXCLUDED.severity, "
            "  status = EXCLUDED.status, released_at = EXCLUDED.released_at, "
            "  scanned_at = EXCLUDED.scanned_at",
            std::vector<std::string>{agent_id, pg::to_text_array(kb_ids), pg::to_text_array(titles),
                                     pg::to_text_array(severities), pg::to_text_array(statuses),
                                     pg::to_text_array(released_at_views), now_str});
        if (res.status() != PGRES_COMMAND_OK) {
            spdlog::error("PatchManager::record_patches: insert failed for agent {}: {}",
                          agent_id, PQresultErrorMessage(res.get()));
            return false;
        }
        return true;
    });

    if (ok) {
        spdlog::info("PatchManager: recorded {} patches for agent {}", patches.size(), agent_id);
    } else {
        // with_txn_for returns false silently on a lease-acquire/BEGIN
        // failure too (not just an INSERT failure, which already logs its
        // own line above) — log here so a degraded pool doesn't drop an
        // agent's whole inventory report with zero trace.
        spdlog::warn("PatchManager::record_patches: failed to record {} patches for agent {} "
                    "(pool degraded or transaction failed)",
                    patches.size(), agent_id);
    }
    if (metrics_)
        metrics_->counter("yuzu_server_patch_manager_writes_total",
                          {{"op", "record_patches"}, {"result", ok ? "success" : "failed"}})
            .increment();
}

std::vector<PatchInfo> PatchManager::query_patches(const PatchQuery& query,
                                                    const std::string& status_filter) const {
    std::vector<PatchInfo> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    std::string sql =
        std::string("SELECT ") + kInventoryCols + " FROM patch_manager.patch_inventory WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;
    if (!status_filter.empty()) {
        sql += " AND status = $" + std::to_string(idx++);
        params.push_back(status_filter);
    }
    if (!query.agent_id.empty()) {
        sql += " AND agent_id = $" + std::to_string(idx++);
        params.push_back(query.agent_id);
    }
    if (!query.severity.empty()) {
        sql += " AND severity = $" + std::to_string(idx++);
        params.push_back(query.severity);
    }
    sql += " ORDER BY scanned_at DESC LIMIT $" + std::to_string(idx);
    params.push_back(std::to_string(query.limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PatchManager::query_patches: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return result;
    }

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        PatchInfo p;
        p.agent_id = col_str(res.get(), i, 0);
        p.kb_id = col_str(res.get(), i, 1);
        p.title = col_str(res.get(), i, 2);
        p.severity = col_str(res.get(), i, 3);
        p.status = col_str(res.get(), i, 4);
        p.released_at = to_i64(col(res.get(), i, 5));
        p.scanned_at = to_i64(col(res.get(), i, 6));
        result.push_back(std::move(p));
    }
    return result;
}

std::vector<PatchInfo> PatchManager::get_missing_patches(const PatchQuery& query) const {
    return query_patches(query, "missing");
}

std::vector<PatchInfo> PatchManager::get_installed_patches(const PatchQuery& query) const {
    return query_patches(query, "installed");
}

std::vector<std::pair<std::string, int>> PatchManager::get_fleet_patch_summary(int limit) const {
    std::vector<std::pair<std::string, int>> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT kb_id, COUNT(DISTINCT agent_id) AS agent_count "
        "FROM patch_manager.patch_inventory WHERE status = 'missing' "
        "GROUP BY kb_id ORDER BY agent_count DESC LIMIT $1",
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PatchManager::get_fleet_patch_summary: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return result;
    }

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace_back(col_str(res.get(), i, 0), static_cast<int>(to_i64(col(res.get(), i, 1))));
    return result;
}

// ── Deployment ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
PatchManager::deploy_patch(const std::string& kb_id,
                           const std::vector<std::string>& agent_ids,
                           bool reboot_if_needed,
                           const std::string& created_by,
                           int reboot_delay_seconds,
                           int64_t reboot_at) {
    return deploy_patch({kb_id, agent_ids, reboot_if_needed, created_by,
                         reboot_delay_seconds, reboot_at});
}

std::expected<std::string, std::string>
PatchManager::deploy_patch(const DeploymentRequest& req) {
    const auto& kb_id = req.kb_id;
    bool reboot_if_needed = req.reboot_if_needed;
    const auto& created_by = req.created_by;
    int reboot_delay_seconds = req.reboot_delay_seconds;
    int64_t reboot_at = req.reboot_at;

    if (kb_id.empty())
        return std::unexpected("kb_id is required");

    // KB IDs must be KBnnnnn format — reject anything else to prevent
    // PowerShell -match injection when the kb_id is interpolated into scripts
    static const std::regex kb_pattern("^KB\\d{4,10}$", std::regex::icase);
    if (!std::regex_match(kb_id, kb_pattern))
        return std::unexpected("invalid KB ID format (must be KBnnnnnnn)");

    if (req.agent_ids.empty())
        return std::unexpected("at least one agent_id is required");

    // De-duplicate, preserving order. The SQLite era inserted target rows
    // via an unchecked sqlite3_step() per agent_id — a caller-supplied
    // duplicate silently failed its own INSERT (PK collision on
    // (deployment_id, agent_id)) while total_targets was still set from
    // agent_ids.size(), leaving total_targets inconsistent with the actual
    // row count. This migration wraps the deployment + target inserts in
    // one transaction (new atomicity — see ADR-0062), so a duplicate would
    // now fail the WHOLE deploy instead of silently under-counting; de-dup
    // up front keeps a duplicate agent_id from being a hard error and keeps
    // total_targets accurate.
    std::vector<std::string> agent_ids;
    agent_ids.reserve(req.agent_ids.size());
    std::unordered_set<std::string_view> seen;
    seen.reserve(req.agent_ids.size());
    for (const auto& id : req.agent_ids) {
        if (seen.insert(id).second)
            agent_ids.push_back(id);
    }

    if (agent_ids.size() > kMaxDeployTargets) {
        if (metrics_)
            metrics_->counter("yuzu_server_patch_manager_writes_total",
                              {{"op", "deploy_patch"}, {"result", "rejected_oversized"}})
                .increment();
        return std::unexpected("too many target agents (max " +
                               std::to_string(kMaxDeployTargets) + ")");
    }

    if (!open_)
        return std::unexpected("patch manager not available");

    reboot_delay_seconds = std::clamp(reboot_delay_seconds, 60, 86400);
    const auto id = generate_id();
    const auto now = now_epoch();

    std::vector<std::string_view> agent_id_views(agent_ids.begin(), agent_ids.end());

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Title enrichment from inventory — same transaction as the writes
        // below, so the stored title is consistent with whatever inventory
        // row this read observed.
        std::string title;
        {
            pg::PgResult tres = pg::exec_params(
                conn, "SELECT title FROM patch_manager.patch_inventory WHERE kb_id = $1 LIMIT 1",
                std::vector<std::string>{kb_id});
            if (tres.status() == PGRES_TUPLES_OK && PQntuples(tres.get()) > 0)
                title = col_str(tres.get(), 0, 0);
        }

        pg::PgResult dres = pg::exec_params(
            conn,
            "INSERT INTO patch_manager.patch_deployments "
            "(id, kb_id, title, status, created_by, reboot_needed, "
            " reboot_delay_seconds, reboot_at, created_at, total_targets) "
            "VALUES ($1, $2, $3, 'pending', $4, $5::boolean, $6::integer, $7::bigint, "
            "        $8::bigint, $9::integer)",
            std::vector<std::string>{id, kb_id, title, created_by,
                                     reboot_if_needed ? "true" : "false",
                                     std::to_string(reboot_delay_seconds),
                                     std::to_string(reboot_at), std::to_string(now),
                                     std::to_string(agent_ids.size())});
        if (dres.status() != PGRES_COMMAND_OK) {
            spdlog::error("PatchManager::deploy_patch: deployment insert failed: {}",
                          PQresultErrorMessage(dres.get()));
            return false;
        }

        pg::PgResult ttres = pg::exec_params(
            conn,
            "INSERT INTO patch_manager.patch_deployment_targets (deployment_id, agent_id, status) "
            "SELECT $1, a, 'pending' FROM unnest($2::text[]) AS t(a)",
            std::vector<std::string>{id, pg::to_text_array(agent_id_views)});
        if (ttres.status() != PGRES_COMMAND_OK) {
            spdlog::error("PatchManager::deploy_patch: target rows insert failed: {}",
                          PQresultErrorMessage(ttres.get()));
            return false;
        }
        return true;
    });

    if (metrics_)
        metrics_->counter("yuzu_server_patch_manager_writes_total",
                          {{"op", "deploy_patch"}, {"result", ok ? "success" : "failed"}})
            .increment();
    if (!ok)
        return std::unexpected("failed to create deployment");

    spdlog::info("PatchManager: created deployment {} for {} targeting {} agents",
                 id, kb_id, agent_ids.size());
    return id;
}

std::optional<PatchDeployment> PatchManager::get_deployment(const std::string& id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kDeploymentCols +
         " FROM patch_manager.patch_deployments WHERE id = $1")
            .c_str(),
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;

    PatchDeployment d = row_to_deployment(res.get(), 0);

    pg::PgResult tres = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kTargetCols +
         " FROM patch_manager.patch_deployment_targets WHERE deployment_id = $1")
            .c_str(),
        std::vector<std::string>{id});
    if (tres.status() == PGRES_TUPLES_OK) {
        const int rows = PQntuples(tres.get());
        d.targets.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            PatchDeploymentTarget t;
            t.agent_id = col_str(tres.get(), i, 0);
            t.status = col_str(tres.get(), i, 1);
            t.error = col_str(tres.get(), i, 2);
            t.started_at = to_i64(col(tres.get(), i, 3));
            t.completed_at = to_i64(col(tres.get(), i, 4));
            d.targets.push_back(std::move(t));
        }
    }

    return d;
}

std::vector<PatchDeployment> PatchManager::list_deployments(int limit) const {
    std::vector<PatchDeployment> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kDeploymentCols +
         " FROM patch_manager.patch_deployments ORDER BY created_at DESC LIMIT $1")
            .c_str(),
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("PatchManager::list_deployments: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return result;
    }

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(row_to_deployment(res.get(), i));
    return result;
}

std::expected<void, std::string>
PatchManager::cancel_deployment(const std::string& id) {
    auto depl = get_deployment(id);
    if (!depl)
        return std::unexpected("deployment not found");

    if (depl->status == "completed" || depl->status == "cancelled")
        return std::unexpected("deployment already " + depl->status);

    if (!open_)
        return std::unexpected("database not available");

    // Both writes in ONE transaction — governance Gate 4 unhappy-path fix.
    // The SQLite-era shape (and this migration's own first draft) issued the
    // deployment-status UPDATE and the target-rows UPDATE as two SEPARATE
    // lease acquisitions. A lease failure on the FIRST (silently returning,
    // no error surfaced) while the SECOND still succeeded reported overall
    // SUCCESS to the caller with the deployment's own `status` column never
    // actually changed — a false-success report with no reconciler left to
    // ever correct it (execute_deployment/recalculate_deployment_progress,
    // the only code that ever revisited a deployment's state, are both
    // deleted in this same migration). One transaction makes this
    // all-or-nothing instead.
    const auto now = std::to_string(now_epoch());
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult dres = pg::exec_params(
            conn,
            "UPDATE patch_manager.patch_deployments SET status = 'cancelled', completed_at = $1 "
            "WHERE id = $2",
            std::vector<std::string>{now, id});
        if (dres.status() != PGRES_COMMAND_OK) {
            spdlog::error("PatchManager::cancel_deployment: deployment status update failed: {}",
                          PQresultErrorMessage(dres.get()));
            return false;
        }

        pg::PgResult tres = pg::exec_params(
            conn,
            "UPDATE patch_manager.patch_deployment_targets SET status = 'cancelled', "
            "completed_at = $1 WHERE deployment_id = $2 AND status IN "
            "('pending', 'scanning', 'downloading', 'installing', 'verifying', 'rebooting')",
            std::vector<std::string>{now, id});
        if (tres.status() != PGRES_COMMAND_OK) {
            spdlog::error("PatchManager::cancel_deployment: target update failed: {}",
                          PQresultErrorMessage(tres.get()));
            return false;
        }
        return true;
    });

    if (metrics_)
        metrics_->counter("yuzu_server_patch_manager_writes_total",
                          {{"op", "cancel_deployment"}, {"result", ok ? "success" : "failed"}})
            .increment();
    if (!ok)
        return std::unexpected("failed to cancel deployment");

    spdlog::info("PatchManager: cancelled deployment {}", id);
    return {};
}

void PatchManager::update_target_status(const std::string& deployment_id,
                                        const std::string& agent_id,
                                        const std::string& status,
                                        const std::string& error) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return;

    const auto now = std::to_string(now_epoch());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE patch_manager.patch_deployment_targets "
        "SET status = $1, error = $2, "
        "    started_at = CASE WHEN started_at = 0 THEN $3::bigint ELSE started_at END, "
        "    completed_at = CASE WHEN $1 IN ('completed', 'failed', 'cancelled') "
        "                        THEN $3::bigint ELSE completed_at END "
        "WHERE deployment_id = $4 AND agent_id = $5",
        std::vector<std::string>{status, error, now, deployment_id, agent_id});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("PatchManager::update_target_status: update failed for {}/{}: {}",
                    deployment_id, agent_id, PQresultErrorMessage(res.get()));
}

} // namespace yuzu::server
