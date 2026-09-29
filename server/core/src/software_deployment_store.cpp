#include "software_deployment_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_deployment_store";

// Authoritative store (ADR-0012 §1) — operator-initiated deployment intent,
// no in-memory layer behind it. Not a hot path (operator-driven, low
// frequency), so budgets are generous relative to a heartbeat-path store's,
// same values as DeploymentStore/ADR-0043.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// gov UP-5 precedent: bounded materialization regardless of table growth —
// an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

int to_int(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int>(std::strtol(s, nullptr, 10));
}

// Agent status's documented intended progression (AgentDeploymentStatus::
// status comment): pending -> downloading -> installing -> verifying ->
// {success, failed, rolled_back} (terminal, tied). update_agent_status uses
// only the "unrecognised" (rank 5) case, to reject an invalid status string
// before it reaches the upsert — UNLIKE the deployment table,
// update_agent_status is itself an unguarded upsert on the live path, so
// this rank does not otherwise gate a transition direction.
int agent_lifecycle_rank(std::string_view status) {
    if (status == "pending")
        return 0;
    if (status == "downloading")
        return 1;
    if (status == "installing")
        return 2;
    if (status == "verifying")
        return 3;
    if (status == "success" || status == "failed" || status == "rolled_back")
        return 4;
    return 5; // unrecognised
}

bool is_fk_violation(const pg::PgResult& res) {
    const char* sqlstate = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return sqlstate && std::string_view(sqlstate) == "23503";
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE software_packages ("
         "  id               TEXT PRIMARY KEY,"
         "  name             TEXT NOT NULL,"
         "  version          TEXT NOT NULL DEFAULT '',"
         "  platform         TEXT NOT NULL DEFAULT '',"
         "  installer_type   TEXT NOT NULL DEFAULT '',"
         "  content_hash     TEXT NOT NULL DEFAULT '',"
         "  content_url      TEXT NOT NULL DEFAULT '',"
         "  silent_args      TEXT NOT NULL DEFAULT '',"
         "  verify_command   TEXT NOT NULL DEFAULT '',"
         "  rollback_command TEXT NOT NULL DEFAULT '',"
         "  size_bytes       BIGINT NOT NULL DEFAULT 0,"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  created_by       TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_swpkg_name ON software_packages(name);"
         "CREATE INDEX idx_swpkg_platform ON software_packages(platform);"

         "CREATE TABLE software_deployments ("
         "  id               TEXT PRIMARY KEY,"
         "  package_id       TEXT NOT NULL REFERENCES software_packages(id),"
         "  scope_expression TEXT NOT NULL DEFAULT '',"
         "  status           TEXT NOT NULL DEFAULT 'staged',"
         "  created_by       TEXT NOT NULL DEFAULT '',"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  started_at       BIGINT NOT NULL DEFAULT 0,"
         "  completed_at     BIGINT NOT NULL DEFAULT 0,"
         "  agents_targeted  INTEGER NOT NULL DEFAULT 0,"
         "  agents_success   INTEGER NOT NULL DEFAULT 0,"
         "  agents_failure   INTEGER NOT NULL DEFAULT 0);"
         "CREATE INDEX idx_swdep_status ON software_deployments(status);"
         "CREATE INDEX idx_swdep_package ON software_deployments(package_id);"
         "CREATE INDEX idx_swdep_created ON software_deployments(created_at);"

         // No separate index on agent_software_status(deployment_id): the
         // PRIMARY KEY (deployment_id, agent_id) below already gives
         // Postgres a leading-column btree index, unlike the pre-migration
         // SQLite schema (kept as a distinct idx_agentstatus_dep there).
         "CREATE TABLE agent_software_status ("
         "  deployment_id TEXT NOT NULL REFERENCES software_deployments(id),"
         "  agent_id      TEXT NOT NULL,"
         "  status        TEXT NOT NULL DEFAULT 'pending',"
         "  started_at    BIGINT NOT NULL DEFAULT 0,"
         "  completed_at  BIGINT NOT NULL DEFAULT 0,"
         "  error         TEXT NOT NULL DEFAULT '',"
         "  PRIMARY KEY (deployment_id, agent_id));"
         "CREATE INDEX idx_agentstatus_agent ON agent_software_status(agent_id);"},
    };
    return kMigrations;
}

constexpr const char* kPackageCols = "id, name, version, platform, installer_type, content_hash, "
                                     "content_url, silent_args, verify_command, "
                                     "rollback_command, size_bytes, created_at, created_by";

SoftwarePackage read_package(PGresult* res, int i) {
    SoftwarePackage p;
    int col = 0;
    p.id = PQgetvalue(res, i, col++);
    p.name = PQgetvalue(res, i, col++);
    p.version = PQgetvalue(res, i, col++);
    p.platform = PQgetvalue(res, i, col++);
    p.installer_type = PQgetvalue(res, i, col++);
    p.content_hash = PQgetvalue(res, i, col++);
    p.content_url = PQgetvalue(res, i, col++);
    p.silent_args = PQgetvalue(res, i, col++);
    p.verify_command = PQgetvalue(res, i, col++);
    p.rollback_command = PQgetvalue(res, i, col++);
    p.size_bytes = to_i64(PQgetvalue(res, i, col++));
    p.created_at = to_i64(PQgetvalue(res, i, col++));
    p.created_by = PQgetvalue(res, i, col++);
    return p;
}

constexpr const char* kDeploymentCols =
    "id, package_id, scope_expression, status, created_by, created_at, started_at, "
    "completed_at, agents_targeted, agents_success, agents_failure";

SoftwareDeployment read_deployment(PGresult* res, int i) {
    SoftwareDeployment d;
    int col = 0;
    d.id = PQgetvalue(res, i, col++);
    d.package_id = PQgetvalue(res, i, col++);
    d.scope_expression = PQgetvalue(res, i, col++);
    d.status = PQgetvalue(res, i, col++);
    d.created_by = PQgetvalue(res, i, col++);
    d.created_at = to_i64(PQgetvalue(res, i, col++));
    d.started_at = to_i64(PQgetvalue(res, i, col++));
    d.completed_at = to_i64(PQgetvalue(res, i, col++));
    d.agents_targeted = to_int(PQgetvalue(res, i, col++));
    d.agents_success = to_int(PQgetvalue(res, i, col++));
    d.agents_failure = to_int(PQgetvalue(res, i, col++));
    return d;
}

constexpr const char* kAgentStatusCols =
    "deployment_id, agent_id, status, started_at, completed_at, error";

AgentDeploymentStatus read_agent_status(PGresult* res, int i) {
    AgentDeploymentStatus a;
    int col = 0;
    a.deployment_id = PQgetvalue(res, i, col++);
    a.agent_id = PQgetvalue(res, i, col++);
    a.status = PQgetvalue(res, i, col++);
    a.started_at = to_i64(PQgetvalue(res, i, col++));
    a.completed_at = to_i64(PQgetvalue(res, i, col++));
    a.error = PQgetvalue(res, i, col++);
    return a;
}

} // namespace

// ── ID generation ────────────────────────────────────────────────────────────

// Preserves the pre-migration store's exact ID format: two independent
// 64-bit mt19937_64 draws formatted as 16 hex chars each (32 total). NOT a
// cryptographic random source — `id` is a non-security surrogate key
// (uniqueness, not unguessability, is what matters).
std::string SoftwareDeploymentStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    const auto hi = dist(rng);
    const auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

// ── Construction ─────────────────────────────────────────────────────────────

SoftwareDeploymentStore::SoftwareDeploymentStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareDeploymentStore: no database connection at construction ({}) — "
                      "software deployment persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareDeploymentStore: schema migration failed — software deployment "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

// ── Packages ─────────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_package(const SoftwarePackage& pkg) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (pkg.name.empty())
        return std::unexpected("name is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.software_packages "
        "(id, name, version, platform, installer_type, content_hash, content_url, silent_args, "
        " verify_command, rollback_command, size_bytes, created_at, created_by) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::bigint,$12::bigint,$13) RETURNING id",
        std::vector<std::string>{id, pkg.name, pkg.version, pkg.platform, pkg.installer_type,
                                 pkg.content_hash, pkg.content_url, pkg.silent_args,
                                 pkg.verify_command, pkg.rollback_command,
                                 std::to_string(pkg.size_bytes), std::to_string(now),
                                 pkg.created_by});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "create_package failed: " + PQerrorMessage(lease.get()));

    spdlog::info("SoftwareDeploymentStore: created package {} ({})", id, pkg.name);
    return id;
}

std::expected<std::vector<SoftwarePackage>, std::string> SoftwareDeploymentStore::list_packages() {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kPackageCols +
                      " FROM software_deployment_store.software_packages ORDER BY created_at "
                      "DESC LIMIT $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "list_packages failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<SoftwarePackage> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_package(res.get(), i));
    return out;
}

std::expected<std::optional<SoftwarePackage>, std::string>
SoftwareDeploymentStore::get_package(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kPackageCols +
                      " FROM software_deployment_store.software_packages WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_package failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<SoftwarePackage>{std::nullopt};
    return std::optional<SoftwarePackage>{read_package(res.get(), 0)};
}

std::expected<void, std::string> SoftwareDeploymentStore::delete_package(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM software_deployment_store.software_packages WHERE id=$1 RETURNING id",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (is_fk_violation(res))
            return std::unexpected(
                "package is referenced by an existing deployment and cannot be deleted");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "delete_package failed: " + PQerrorMessage(lease.get()));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("package not found");
    return {};
}

// ── Deployments ──────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_deployment(const SoftwareDeployment& dep) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (dep.package_id.empty())
        return std::unexpected("package_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.software_deployments "
        "(id, package_id, scope_expression, status, created_by, created_at, agents_targeted) "
        "VALUES ($1,$2,$3,'staged',$4,$5::bigint,$6::int) RETURNING id",
        std::vector<std::string>{id, dep.package_id, dep.scope_expression, dep.created_by,
                                 std::to_string(now), std::to_string(dep.agents_targeted)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (is_fk_violation(res))
            return std::unexpected("package_id does not exist");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "create_deployment failed: " + PQerrorMessage(lease.get()));
    }

    spdlog::info("SoftwareDeploymentStore: created deployment {} for package {}", id,
                 dep.package_id);
    return id;
}

std::expected<std::vector<SoftwareDeployment>, std::string>
SoftwareDeploymentStore::list_deployments(const std::string& status) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res;
    if (status.empty()) {
        std::string sql = std::string("SELECT ") + kDeploymentCols +
                          " FROM software_deployment_store.software_deployments ORDER BY "
                          "created_at DESC LIMIT $1";
        res = pg::exec_params(lease.get(), sql.c_str(),
                              std::vector<std::string>{std::to_string(kListRowCap)});
    } else {
        std::string sql = std::string("SELECT ") + kDeploymentCols +
                          " FROM software_deployment_store.software_deployments WHERE status=$1 "
                          "ORDER BY created_at DESC LIMIT $2";
        res = pg::exec_params(
            lease.get(), sql.c_str(),
            std::vector<std::string>{status, std::to_string(kListRowCap)});
    }
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "list_deployments failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<SoftwareDeployment> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_deployment(res.get(), i));
    return out;
}

std::expected<std::optional<SoftwareDeployment>, std::string>
SoftwareDeploymentStore::get_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kDeploymentCols +
                      " FROM software_deployment_store.software_deployments WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_deployment failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<SoftwareDeployment>{std::nullopt};
    return std::optional<SoftwareDeployment>{read_deployment(res.get(), 0)};
}

namespace {

// Shared shape for the three guarded single-UPDATE transitions below
// (start/cancel/rollback) — mirrors DeploymentStore::cancel_job's
// not-found-vs-wrong-state disambiguation, applied to all three here per
// ADR-0051 (kickoff lesson: route handlers need the split to map
// 404/400/503 instead of one catch-all).
std::expected<void, std::string>
guarded_transition(pg::PgPool& pool, const std::string& id, const char* update_sql,
                   const char* wrong_state_msg, const char* op_name) {
    auto lease = pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    // App-computed timestamp (never DB-side now()), matching every other
    // write in this store (create_package/create_deployment).
    pg::PgResult res = pg::exec_params(
        lease.get(), update_sql, std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + op_name +
                               " failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) > 0)
        return {};

    pg::PgResult check = pg::exec_params(
        lease.get(), "SELECT status FROM software_deployment_store.software_deployments WHERE id=$1",
        std::vector<std::string>{id});
    if (check.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + op_name +
                               " disambiguation read failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(check.get()) > 0)
        return std::unexpected(wrong_state_msg);
    return std::unexpected("deployment not found");
}

} // namespace

std::expected<void, std::string> SoftwareDeploymentStore::start_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='deploying', "
        "started_at=$1::bigint WHERE id=$2 AND status='staged' RETURNING id",
        "deployment is not staged", "start_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::cancel_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='cancelled', "
        "completed_at=$1::bigint WHERE id=$2 AND status IN ('staged','deploying') "
        "RETURNING id",
        "only staged or deploying deployments can be cancelled", "cancel_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::rollback_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='rolled_back', "
        "completed_at=$1::bigint WHERE id=$2 AND status IN "
        "('deploying','verifying','completed') RETURNING id",
        "only deploying, verifying, or completed deployments can be rolled back",
        "rollback_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::update_agent_status(const std::string& deployment_id,
                                             const AgentDeploymentStatus& status) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (agent_lifecycle_rank(status.status) == 5)
        return std::unexpected("invalid status");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.agent_software_status "
        "(deployment_id, agent_id, status, started_at, completed_at, error) "
        "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6) "
        "ON CONFLICT (deployment_id, agent_id) DO UPDATE SET status=EXCLUDED.status, "
        "started_at=EXCLUDED.started_at, completed_at=EXCLUDED.completed_at, "
        "error=EXCLUDED.error RETURNING deployment_id",
        std::vector<std::string>{deployment_id, status.agent_id, status.status,
                                 std::to_string(status.started_at),
                                 std::to_string(status.completed_at), status.error});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (is_fk_violation(res))
            return std::unexpected("deployment_id does not exist");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "update_agent_status failed: " + PQerrorMessage(lease.get()));
    }
    return {};
}

std::expected<void, std::string>
SoftwareDeploymentStore::refresh_counts(const std::string& deployment_id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE software_deployment_store.software_deployments SET "
        "agents_success = (SELECT COUNT(*) FROM software_deployment_store.agent_software_status "
        "  WHERE deployment_id = $1 AND status = 'success'), "
        "agents_failure = (SELECT COUNT(*) FROM software_deployment_store.agent_software_status "
        "  WHERE deployment_id = $1 AND status = 'failed') "
        "WHERE id = $1 RETURNING id",
        std::vector<std::string>{deployment_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "refresh_counts failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("deployment not found");
    return {};
}

std::expected<std::vector<AgentDeploymentStatus>, std::string>
SoftwareDeploymentStore::get_agent_statuses(const std::string& deployment_id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kAgentStatusCols +
                      " FROM software_deployment_store.agent_software_status WHERE "
                      "deployment_id=$1 ORDER BY agent_id LIMIT $2";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{deployment_id, std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_agent_statuses failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<AgentDeploymentStatus> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_agent_status(res.get(), i));
    return out;
}

std::expected<int, std::string> SoftwareDeploymentStore::active_count() {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM software_deployment_store.software_deployments WHERE status IN "
        "('deploying','verifying')",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "active_count failed: " + PQerrorMessage(lease.get()));
    return to_int(PQgetvalue(res.get(), 0, 0));
}

} // namespace yuzu::server
