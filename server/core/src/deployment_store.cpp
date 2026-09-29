#include "deployment_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "deployment_store";

// Authoritative store (ADR-0012 §1) — operator-initiated deployment intent,
// no in-memory layer behind it. Not a hot path (operator-driven, low
// frequency), so budgets are generous relative to e.g. a gRPC-heartbeat-path
// store's.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// gov UP-5: bounded materialization regardless of table growth — an
// operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE deployment_jobs ("
         "  id            TEXT PRIMARY KEY,"
         "  target_host   TEXT NOT NULL,"
         "  os            TEXT NOT NULL DEFAULT 'linux',"
         "  method        TEXT NOT NULL DEFAULT 'manual',"
         "  status        TEXT NOT NULL DEFAULT 'pending',"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  started_at    BIGINT NOT NULL DEFAULT 0,"
         "  completed_at  BIGINT NOT NULL DEFAULT 0,"
         "  error         TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_deployment_status ON deployment_jobs(status);"
         "CREATE INDEX idx_deployment_created ON deployment_jobs(created_at);"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) — the
        // backfill idempotency marker it was the sole purpose of no longer has a
        // writer. Version-bumped (not edited into v1) because v1 has actually run
        // against real dev/UAT databases — see ADR-0043's Update.
        {2, "DROP TABLE IF EXISTS sqlite_backfill_source;"},
    };
    return kMigrations;
}

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

bool is_valid_hostname_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

DeploymentJob read_job(PGresult* res, int i) {
    DeploymentJob j;
    int col = 0;
    j.id = PQgetvalue(res, i, col++);
    j.target_host = PQgetvalue(res, i, col++);
    j.os = PQgetvalue(res, i, col++);
    j.method = PQgetvalue(res, i, col++);
    j.status = PQgetvalue(res, i, col++);
    j.created_at = to_i64(PQgetvalue(res, i, col++));
    j.started_at = to_i64(PQgetvalue(res, i, col++));
    j.completed_at = to_i64(PQgetvalue(res, i, col++));
    j.error = PQgetvalue(res, i, col++);
    return j;
}

constexpr const char* kJobCols =
    "id, target_host, os, method, status, created_at, started_at, completed_at, error";

} // namespace

// ── ID generation ────────────────────────────────────────────────────────────

// Mirrors AccessReviewStore::generate_campaign_id — a 64-bit mt19937_64 value
// formatted as 16 hex chars. NOT a cryptographic random source: `id` is a
// non-security surrogate key (uniqueness, not unguessability, is what
// matters — nothing is authorized by knowing a deployment job id). Preserves
// the pre-migration SQLite store's exact ID format.
std::string DeploymentStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    char buf[17]{};
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(dist(rng)));
    return std::string{buf};
}

// ── Construction ─────────────────────────────────────────────────────────────

DeploymentStore::DeploymentStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeploymentStore: no database connection at construction ({}) — "
                      "deployment persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeploymentStore: schema migration failed — deployment persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
DeploymentStore::create_job(const std::string& target_host, const std::string& os,
                            const std::string& method) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    if (target_host.empty())
        return std::unexpected("target_host is required");

    // Validate hostname: must match DNS rules — [a-zA-Z0-9._-] only, max 253
    // chars. The REST layer's manual-deployment install command
    // (discovery_routes.cpp) is a fixed per-OS string that does NOT
    // interpolate target_host today — this allowlist is defense-in-depth
    // against a future caller (e.g. an "ssh" method executor) templating a
    // shell/SSH command from this field without its own validation, not a
    // guard against an injection this store's current callers can reach.
    if (target_host.size() > 253)
        return std::unexpected("target_host exceeds DNS limit of 253 characters");
    if (!std::all_of(target_host.begin(), target_host.end(), is_valid_hostname_char))
        return std::unexpected(
            "target_host contains invalid characters (only [a-zA-Z0-9._-] allowed)");
    // A leading '-' is a valid DNS-allowlist character sequence but never a
    // valid DNS label (RFC 1123: a label starts/ends alphanumeric) — it is
    // also exactly the SSH-option-injection shape ("-oProxyCommand=...",
    // "-Jjump.host", "-Ffile") the allowlist's own doc comment names as the
    // future risk it defends against (gov fjarvis MEDIUM — empirically
    // verified: "-Jjump.evil.com"/"-Ffile" passed the allowlist above before
    // this check existed). Reject it now, while it is still free.
    if (target_host.front() == '-' || target_host.back() == '-')
        return std::unexpected("target_host must not start or end with '-'");

    if (os != "windows" && os != "linux" && os != "darwin")
        return std::unexpected("os must be windows, linux, or darwin");

    if (method != "ssh" && method != "group_policy" && method != "manual")
        return std::unexpected("method must be ssh, group_policy, or manual");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO deployment_store.deployment_jobs "
        "(id, target_host, os, method, status, created_at) "
        "VALUES ($1,$2,$3,$4,'pending',$5::bigint) RETURNING id",
        std::vector<std::string>{id, target_host, os, method, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "create_job failed: " +
                               PQerrorMessage(lease.get()));

    spdlog::info("DeploymentStore: created job {} for {} ({})", id, target_host, method);
    return id;
}

std::expected<std::vector<DeploymentJob>, std::string> DeploymentStore::list_jobs() {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kJobCols +
                      " FROM deployment_store.deployment_jobs ORDER BY created_at DESC LIMIT $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "list_jobs failed: " +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<DeploymentJob> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_job(res.get(), i));
    return out;
}

std::expected<std::optional<DeploymentJob>, std::string>
DeploymentStore::get_job(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    std::string sql =
        std::string("SELECT ") + kJobCols + " FROM deployment_store.deployment_jobs WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "get_job failed: " +
                               PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<DeploymentJob>{std::nullopt};
    return std::optional<DeploymentJob>{read_job(res.get(), 0)};
}

std::expected<void, std::string>
DeploymentStore::update_status(const std::string& id, const std::string& status,
                               const std::string& error) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    if (status != "pending" && status != "running" && status != "completed" &&
        status != "failed" && status != "cancelled")
        return std::unexpected("invalid status");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    const std::int64_t now = now_epoch();
    pg::PgResult res;
    if (status == "running") {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, started_at=$2::bigint, "
            "error=$3 WHERE id=$4 RETURNING id",
            std::vector<std::string>{status, std::to_string(now), error, id});
    } else if (status == "completed" || status == "failed") {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, completed_at=$2::bigint, "
            "error=$3 WHERE id=$4 RETURNING id",
            std::vector<std::string>{status, std::to_string(now), error, id});
    } else {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, error=$2 WHERE id=$3 "
            "RETURNING id",
            std::vector<std::string>{status, error, id});
    }
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "update_status failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("job not found");
    return {};
}

std::expected<void, std::string> DeploymentStore::cancel_job(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    // Single guarded UPDATE — no separate check-then-write round trip, so a
    // concurrent second cancel or status update can never race this into an
    // inconsistent state (the mutation itself is race-safe regardless of
    // what follows below).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_store.deployment_jobs SET status='cancelled', "
        "error='cancelled by operator' WHERE id=$1 AND status IN ('pending','running') "
        "RETURNING id",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "cancel_job failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) > 0)
        return {};

    // Zero rows matched — distinguish not-found from wrong-state for the
    // caller's error message. Best-effort ONLY with respect to a concurrent
    // writer racing the UPDATE above (that can change which of the two
    // business-error cases applies, never the guarded UPDATE's own
    // correctness) — a genuine READ FAILURE on this disambiguation query is
    // NOT folded into "job not found" (gov consistency-auditor finding,
    // hardening round): that would misreport a DB outage as a business
    // error and lose the kDeploymentDbErrorPrefix the route classifier
    // depends on, exactly the defect class this commit closes elsewhere.
    pg::PgResult check = pg::exec_params(
        lease.get(), "SELECT status FROM deployment_store.deployment_jobs WHERE id=$1",
        std::vector<std::string>{id});
    if (check.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) +
                               "cancel_job disambiguation read failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(check.get()) > 0)
        return std::unexpected("only pending or running jobs can be cancelled");
    return std::unexpected("job not found");
}

} // namespace yuzu::server
