#include "deployment_run_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_retention_guard.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "deployment_run_store";

constexpr std::chrono::milliseconds kWriteTimeout{3000};
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr int kRowCap = 20000;     // device rows materialised per read
constexpr int kListCap = 200;      // deployments listed

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL — the runner sets search_path to the store schema for the
    // migration txn; runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE deployments ("
         "  deployment_id     TEXT PRIMARY KEY,"
         "  source_run_id     TEXT NOT NULL DEFAULT '',"
         "  created_by        TEXT NOT NULL DEFAULT '',"
         "  name              TEXT NOT NULL DEFAULT '',"
         "  artifact_url      TEXT NOT NULL DEFAULT '',"
         "  artifact_filename TEXT NOT NULL DEFAULT '',"
         "  artifact_sha256   TEXT NOT NULL DEFAULT '',"
         "  exec_args         TEXT NOT NULL DEFAULT '',"
         "  status            TEXT NOT NULL DEFAULT 'running',"
         "  created_at_ms     BIGINT NOT NULL,"
         "  completed_at_ms   BIGINT NOT NULL DEFAULT 0,"
         "  total             INT NOT NULL DEFAULT 0,"
         "  succeeded         INT NOT NULL DEFAULT 0,"
         "  failed            INT NOT NULL DEFAULT 0,"
         "  skipped           INT NOT NULL DEFAULT 0,"
         "  active            INT NOT NULL DEFAULT 0);"
         "CREATE INDEX deployments_owner_idx  ON deployments (created_by, created_at_ms DESC);"
         "CREATE INDEX deployments_status_idx ON deployments (status);"
         // At most ONE running deployment per source pre-flight run — the race-safe
         // backstop to the create-time resume guard, so a second 'Deploy' click (or
         // a concurrent create) can't mint a duplicate run that re-installs the
         // cohort (#governance security HIGH-1).
         "CREATE UNIQUE INDEX deployments_one_running_per_run "
         "  ON deployments (source_run_id) WHERE status = 'running';"
         "CREATE TABLE deployment_device ("
         "  deployment_id TEXT NOT NULL REFERENCES deployments(deployment_id) ON DELETE CASCADE,"
         "  agent_id      TEXT NOT NULL,"
         "  hostname      TEXT NOT NULL DEFAULT '',"
         "  os            TEXT NOT NULL DEFAULT '',"
         "  step          TEXT NOT NULL DEFAULT 'pending',"
         "  exit_code     BIGINT NOT NULL DEFAULT 0," // int64 model (parse_i64 saturates) — NOT int4

         "  error         TEXT NOT NULL DEFAULT '',"
         "  updated_at_ms BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (deployment_id, agent_id));"},
        // WS-10 (#2508): durable anchor + dedup state for the clock-guarded,
        // single-writer retention prune (shared shape, see run_retention_prune).
        {2, "CREATE TABLE IF NOT EXISTS retention_meta ("
            "  key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
        // WS-10 (#2508): leading `created_at_ms` index so the retention guard's
        // EXISTS probe is index-eligible (deployments_owner_idx leads on created_by,
        // not the timestamp). Small table (retention-pruned) → a plain in-txn CREATE
        // INDEX is fine (no CONCURRENTLY needed).
        {3, "CREATE INDEX IF NOT EXISTS deployments_created_at_idx ON deployments (created_at_ms);"},
    };
    return kMigrations;
}

// WS-10 retention-guard constants — PER-STORE. deployment runs are non-regenerable
// records of a STATEFUL install on a device cohort; identical retention profile to
// the sibling preflight store (ms column, ~60s prune cadence on the shared
// preflight thread, 14-day retention), so these values are chosen the same way —
// independently, for that profile, NOT copied from a mismatched store's constant.
constexpr std::int64_t kPruneBigStepFloorMs = 86'400'000;      // 24h absolute
constexpr std::int64_t kPruneImplausibilityMs = 86'400'000;    // created_at_ms is never future
constexpr std::int64_t kPruneMinPlausibleMs = 946'684'800'000; // year 2000 in ms
constexpr std::int64_t kPruneCapPerPass = 5'000;               // bounded drain per pass

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_int(const char* s) { return static_cast<int>(to_i64(s)); }

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr const char* kDeploymentCols =
    "deployment_id, source_run_id, created_by, name, artifact_url, artifact_filename, "
    "artifact_sha256, exec_args, status, created_at_ms, completed_at_ms, total, succeeded, "
    "failed, skipped, active";

DeploymentRow read_deployment(PGresult* res, int i) {
    DeploymentRow r;
    int c = 0;
    r.deployment_id = PQgetvalue(res, i, c++);
    r.source_run_id = PQgetvalue(res, i, c++);
    r.created_by = PQgetvalue(res, i, c++);
    r.name = PQgetvalue(res, i, c++);
    r.artifact_url = PQgetvalue(res, i, c++);
    r.artifact_filename = PQgetvalue(res, i, c++);
    r.artifact_sha256 = PQgetvalue(res, i, c++);
    r.exec_args = PQgetvalue(res, i, c++);
    r.status = PQgetvalue(res, i, c++);
    r.created_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.completed_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.total = to_int(PQgetvalue(res, i, c++));
    r.succeeded = to_int(PQgetvalue(res, i, c++));
    r.failed = to_int(PQgetvalue(res, i, c++));
    r.skipped = to_int(PQgetvalue(res, i, c++));
    r.active = to_int(PQgetvalue(res, i, c++));
    return r;
}

// to_text_array wants string_views; the candidate vectors outlive the call.
std::vector<std::string_view> as_views(const std::vector<std::string>& v) {
    std::vector<std::string_view> out;
    out.reserve(v.size());
    for (const auto& s : v)
        out.emplace_back(s);
    return out;
}

std::vector<std::string> returned_ids(const pg::PgResult& res) {
    std::vector<std::string> out;
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.emplace_back(PQgetvalue(res.get(), i, 0));
    return out;
}

} // namespace

DeploymentRunStore::DeploymentRunStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeploymentRunStore: no database connection at construction ({}) — deployment "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeploymentRunStore: schema migration failed — deployment persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

bool DeploymentRunStore::create_deployment(const DeploymentRow& dep,
                                           const std::vector<preflight::PreflightTarget>& targets) {
    if (!open_ || dep.deployment_id.empty())
        return false;
    std::vector<std::string_view> agent_ids, hostnames, oses;
    agent_ids.reserve(targets.size());
    hostnames.reserve(targets.size());
    oses.reserve(targets.size());
    for (const auto& t : targets) {
        agent_ids.emplace_back(t.agent_id);
        hostnames.emplace_back(t.hostname);
        oses.emplace_back(t.os);
    }
    const std::string ts = std::to_string(now_ms());
    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult r1 = pg::exec_params(
            conn,
            "INSERT INTO deployment_run_store.deployments "
            "(deployment_id, source_run_id, created_by, name, artifact_url, artifact_filename, "
            " artifact_sha256, exec_args, status, created_at_ms, total, active) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'running',$9::bigint,$10::int,$10::int) "
            "RETURNING deployment_id",
            std::vector<std::string>{dep.deployment_id, dep.source_run_id, dep.created_by, dep.name,
                                     dep.artifact_url, dep.artifact_filename, dep.artifact_sha256,
                                     dep.exec_args, std::to_string(dep.created_at_ms),
                                     std::to_string(static_cast<int>(targets.size()))});
        if (r1.status() != PGRES_TUPLES_OK) {
            spdlog::warn("DeploymentRunStore: deployment insert failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (targets.empty())
            return true;
        pg::PgResult r2 = pg::exec_params(
            conn,
            "INSERT INTO deployment_run_store.deployment_device "
            "(deployment_id, agent_id, hostname, os, step, updated_at_ms) "
            "SELECT $1, a, h, o, 'pending', $5::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[]) AS t(a, h, o)",
            std::vector<std::string>{dep.deployment_id, pg::to_text_array(agent_ids),
                                     pg::to_text_array(hostnames), pg::to_text_array(oses), ts});
        if (r2.status() != PGRES_COMMAND_OK && r2.status() != PGRES_TUPLES_OK) {
            spdlog::warn("DeploymentRunStore: cohort seed insert failed: {}", PQerrorMessage(conn));
            return false;
        }
        return true;
    });
}

std::optional<DeploymentRow> DeploymentRunStore::get_deployment(const std::string& deployment_id,
                                                                const std::string& created_by) {
    if (!open_ || deployment_id.empty())
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    std::string sql = std::string("SELECT ") + kDeploymentCols +
                      " FROM deployment_run_store.deployments WHERE deployment_id = $1";
    std::vector<std::string> params{deployment_id};
    if (!created_by.empty()) {
        sql += " AND created_by = $2"; // owner-scope at the seam
        params.push_back(created_by);
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_deployment(res.get(), 0);
}

std::vector<DeploymentRow> DeploymentRunStore::list_deployments(const std::string& viewer,
                                                                bool is_admin, int limit) {
    std::vector<DeploymentRow> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const int cap = (limit > 0 && limit < kListCap) ? limit : kListCap;
    const std::string sql_admin =
        std::string("SELECT ") + kDeploymentCols +
        " FROM deployment_run_store.deployments ORDER BY created_at_ms DESC LIMIT $1::bigint";
    const std::string sql_owner =
        std::string("SELECT ") + kDeploymentCols +
        " FROM deployment_run_store.deployments WHERE created_by = $1 ORDER BY created_at_ms DESC "
        "LIMIT $2::bigint";
    pg::PgResult res =
        is_admin ? pg::exec_params(lease.get(), sql_admin.c_str(),
                                   std::vector<std::string>{std::to_string(cap)})
                 : pg::exec_params(lease.get(), sql_owner.c_str(),
                                   std::vector<std::string>{viewer, std::to_string(cap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_deployment(res.get(), i));
    return out;
}

std::optional<std::string>
DeploymentRunStore::find_running_for_run(const std::string& source_run_id,
                                         const std::string& created_by) {
    if (!open_ || source_run_id.empty())
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT deployment_id FROM deployment_run_store.deployments "
        "WHERE source_run_id = $1 AND created_by = $2 AND status = 'running' LIMIT 1",
        std::vector<std::string>{source_run_id, created_by});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return std::string(PQgetvalue(res.get(), 0, 0));
}

std::vector<std::string>
DeploymentRunStore::succeeded_agents_for_run(const std::string& source_run_id,
                                             const std::string& created_by) {
    std::vector<std::string> out;
    if (!open_ || source_run_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT d.agent_id "
        "FROM deployment_run_store.deployment_device d "
        "JOIN deployment_run_store.deployments dep ON d.deployment_id = dep.deployment_id "
        "WHERE dep.source_run_id = $1 AND dep.created_by = $2 AND d.step = 'succeeded' "
        "LIMIT $3::bigint",
        std::vector<std::string>{source_run_id, created_by, std::to_string(kRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.emplace_back(PQgetvalue(res.get(), i, 0));
    return out;
}

std::vector<DeploymentDeviceRow> DeploymentRunStore::get_devices(const std::string& deployment_id) {
    std::vector<DeploymentDeviceRow> out;
    if (!open_ || deployment_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, step, exit_code, error, updated_at_ms "
        "FROM deployment_run_store.deployment_device WHERE deployment_id = $1 "
        "ORDER BY hostname LIMIT $2::bigint",
        std::vector<std::string>{deployment_id, std::to_string(kRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DeploymentDeviceRow d;
        d.agent_id = PQgetvalue(res.get(), i, 0);
        d.hostname = PQgetvalue(res.get(), i, 1);
        d.os = PQgetvalue(res.get(), i, 2);
        d.step = PQgetvalue(res.get(), i, 3);
        d.exit_code = to_i64(PQgetvalue(res.get(), i, 4));
        d.error = PQgetvalue(res.get(), i, 5);
        d.updated_at_ms = to_i64(PQgetvalue(res.get(), i, 6));
        out.push_back(std::move(d));
    }
    return out;
}

bool DeploymentRunStore::apply_results(const std::string& deployment_id,
                                       const std::vector<DeviceTransition>& transitions) {
    if (!open_ || deployment_id.empty())
        return false;
    if (transitions.empty())
        return true;
    std::vector<std::string> agents, froms, tos, exits, errors;
    agents.reserve(transitions.size());
    froms.reserve(transitions.size());
    tos.reserve(transitions.size());
    exits.reserve(transitions.size());
    errors.reserve(transitions.size());
    for (const auto& t : transitions) {
        agents.push_back(t.agent_id);
        froms.push_back(t.from_step);
        tos.push_back(t.to_step);
        exits.push_back(std::to_string(t.exit_code));
        errors.push_back(t.error);
    }
    const std::string ts = std::to_string(now_ms());
    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // ONE batched, source-step-GUARDED update: a row only moves if it is still
        // in its expected `from_step`, so a concurrent advance that already moved
        // it is a silent no-op (the keystone of execute-once correctness).
        pg::PgResult r = pg::exec_params(
            conn,
            "UPDATE deployment_run_store.deployment_device AS d "
            "SET step = v.to_step, exit_code = v.exit_code::bigint, error = v.error, "
            "    updated_at_ms = $7::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) "
            "  AS v(agent, from_step, to_step, exit_code, error) "
            "WHERE d.deployment_id = $1 AND d.agent_id = v.agent AND d.step = v.from_step",
            std::vector<std::string>{deployment_id, pg::to_text_array(as_views(agents)),
                                     pg::to_text_array(as_views(froms)),
                                     pg::to_text_array(as_views(tos)),
                                     pg::to_text_array(as_views(exits)),
                                     pg::to_text_array(as_views(errors)), ts});
        if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK) {
            spdlog::warn("DeploymentRunStore: apply_results failed (dep={}): {}", deployment_id,
                         PQerrorMessage(conn));
            return false;
        }
        return true;
    });
}

std::vector<std::string>
DeploymentRunStore::claim_for_stage(const std::string& deployment_id,
                                    const std::vector<std::string>& candidates) {
    if (!open_ || deployment_id.empty() || candidates.empty())
        return {};
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return {};
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_run_store.deployment_device "
        "SET step='staging', updated_at_ms=$3::bigint "
        "WHERE deployment_id=$1 AND agent_id = ANY($2::text[]) AND step='pending' "
        "RETURNING agent_id",
        std::vector<std::string>{deployment_id, pg::to_text_array(as_views(candidates)),
                                 std::to_string(now_ms())});
    return returned_ids(res);
}

std::vector<std::string>
DeploymentRunStore::claim_for_exec(const std::string& deployment_id,
                                   const std::vector<std::string>& candidates) {
    if (!open_ || deployment_id.empty() || candidates.empty())
        return {};
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return {};
    // THE execute-once CAS: only rows still in 'staged' transition + are RETURNED;
    // a concurrent / post-restart advance matches zero for an already-claimed row.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_run_store.deployment_device "
        "SET step='executing', updated_at_ms=$3::bigint "
        "WHERE deployment_id=$1 AND agent_id = ANY($2::text[]) AND step='staged' "
        "RETURNING agent_id",
        std::vector<std::string>{deployment_id, pg::to_text_array(as_views(candidates)),
                                 std::to_string(now_ms())});
    return returned_ids(res);
}

int DeploymentRunStore::mark_skipped(const std::string& deployment_id,
                                     const std::vector<std::string>& agent_ids) {
    if (!open_ || deployment_id.empty() || agent_ids.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return 0;
    // Only devices NOT yet executed (pending / staged) — a 'staging'/'executing'
    // device is in flight and must not be skipped out from under a dispatch.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_run_store.deployment_device "
        "SET step='skipped', error='out of scope at dispatch', updated_at_ms=$3::bigint "
        "WHERE deployment_id=$1 AND agent_id = ANY($2::text[]) AND step IN ('pending','staged') "
        "RETURNING agent_id",
        std::vector<std::string>{deployment_id, pg::to_text_array(as_views(agent_ids)),
                                 std::to_string(now_ms())});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return PQntuples(res.get());
}

bool DeploymentRunStore::refresh_counts(const std::string& deployment_id) {
    if (!open_ || deployment_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_run_store.deployments d SET "
        "  total=c.total, succeeded=c.succeeded, failed=c.failed, skipped=c.skipped, "
        "  active=c.active "
        "FROM (SELECT "
        "    count(*) AS total, "
        "    count(*) FILTER (WHERE step='succeeded') AS succeeded, "
        "    count(*) FILTER (WHERE step='failed') AS failed, "
        "    count(*) FILTER (WHERE step='skipped') AS skipped, "
        "    count(*) FILTER (WHERE step IN ('pending','staging','staged','executing')) AS active "
        "  FROM deployment_run_store.deployment_device WHERE deployment_id=$1) c "
        "WHERE d.deployment_id=$1 RETURNING d.deployment_id",
        std::vector<std::string>{deployment_id});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

bool DeploymentRunStore::complete_deployment(const std::string& deployment_id,
                                             std::int64_t completed_at_ms) {
    if (!open_ || deployment_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;
    // Settled-check IN SQL: complete only if running AND nothing is still in flight,
    // so completion is correct regardless of the caller's (possibly stale) read.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_run_store.deployments SET status='complete', completed_at_ms=$2::bigint "
        "WHERE deployment_id=$1 AND status='running' AND NOT EXISTS ("
        "  SELECT 1 FROM deployment_run_store.deployment_device "
        "  WHERE deployment_id=$1 AND step IN ('pending','staging','staged','executing')) "
        "RETURNING deployment_id",
        std::vector<std::string>{deployment_id, std::to_string(completed_at_ms)});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

int DeploymentRunStore::run_retention_prune(std::int64_t retention_window_ms) {
    if (!open_)
        return -1;
    // WS-10 (#2508): clock-guarded, single-writer, capped retention. Part-6
    // missing-anchor = Decline: a deployment run is a non-regenerable record of a
    // stateful install; a from-boot skewed clock must not silently delete it.
    const pg::ClockGuardedPruneSpec spec{
        .store_label = kStoreName,
        .target_table = "deployment_run_store.deployments",
        .ts_column = "created_at_ms",
        .now_expr = "(EXTRACT(EPOCH FROM now())*1000)::bigint",
        .meta_table = "deployment_run_store.retention_meta",
        .anchor_key = "deployments_prune_last_pass_now",
        .settled_key = "deployments_prune_bootstrap_settled",
        .facts_key = "deployments_prune_last_anomaly_facts",
        .advisory_lock_key = "hashtext('deployment_run_store:deployments_prune')",
        .retention_window = retention_window_ms,
        .big_step_floor = kPruneBigStepFloorMs,
        .implausibility_bound = kPruneImplausibilityMs,
        .min_plausible_reading = kPruneMinPlausibleMs,
        .cap_per_pass = kPruneCapPerPass,
        .missing_anchor = pg::MissingAnchorPolicy::Decline,
    };
    const auto r = pg::run_clock_guarded_prune(pool_, spec, kWriteTimeout);
    return r.error ? -1 : r.deleted;
}

bool DeploymentRunStore::delete_deployment(const std::string& deployment_id,
                                           const std::string& created_by) {
    if (!open_ || deployment_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;
    // Owner-scope enforced HERE at the sole seam: a non-owner / unknown id deletes
    // 0 rows. deployment_device cascades via the FK ON DELETE CASCADE.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM deployment_run_store.deployments WHERE deployment_id=$1 AND created_by=$2 "
        "RETURNING deployment_id",
        std::vector<std::string>{deployment_id, created_by});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
