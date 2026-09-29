#include "update_registry.hpp"

#include "ota_signature_sidecar.hpp"

#include "nvd_db.hpp" // compare_versions()
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "update_registry";

// Bounded acquires (ADR-0012 §2). This store sits behind the gRPC OTA
// handlers (CheckForUpdate/DownloadUpdate) as well as the admin Settings
// surface — neither is a hot per-heartbeat path the way OffloadTargetStore's
// fire_event is, so one ordinary CRUD budget covers both. Construction is
// the only unbounded acquire.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE update_packages ("
         "  platform    TEXT    NOT NULL,"
         "  arch        TEXT    NOT NULL,"
         "  version     TEXT    NOT NULL,"
         "  sha256      TEXT    NOT NULL,"
         "  filename    TEXT    NOT NULL,"
         "  mandatory   BOOLEAN NOT NULL DEFAULT FALSE,"
         "  rollout_pct INTEGER NOT NULL DEFAULT 100,"
         // Kept TEXT (ISO-8601), not TIMESTAMPTZ -- byte-identical round-trip
         // with the pre-migration column, no caller changes (see the header
         // doc comment).
         "  uploaded_at TEXT    NOT NULL DEFAULT '',"
         "  file_size   BIGINT  NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (platform, arch, version)"
         ");"},
    };
    return kMigrations;
}

std::string col_str(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? std::string() : std::string(PQgetvalue(res, row, c));
}
bool col_bool(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return false;
    const char* v = PQgetvalue(res, row, c);
    return v != nullptr && (v[0] == 't' || v[0] == 'T' || v[0] == '1');
}
int col_int(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return 0;
    // strtol, not atoi, for consistency with col_i64 below (cpp-expert NICE,
    // adversarial review 2026-08-28) — this file is the template for 2
    // sibling migrations, so a lone atoi outlier is a copy-paste risk even
    // though rollout_pct's int4 range makes it harmless here.
    return static_cast<int>(std::strtol(PQgetvalue(res, row, c), nullptr, 10));
}
std::int64_t col_i64(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return 0;
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(res, row, c), nullptr, 10));
}

UpdatePackage row_to_pkg(PGresult* res, int row) {
    UpdatePackage pkg;
    pkg.platform = col_str(res, row, 0);
    pkg.arch = col_str(res, row, 1);
    pkg.version = col_str(res, row, 2);
    pkg.sha256 = col_str(res, row, 3);
    pkg.filename = col_str(res, row, 4);
    pkg.mandatory = col_bool(res, row, 5);
    pkg.rollout_pct = col_int(res, row, 6);
    pkg.uploaded_at = col_str(res, row, 7);
    pkg.file_size = col_i64(res, row, 8);
    return pkg;
}

constexpr const char* kSelectCols = "platform, arch, version, sha256, filename, mandatory, "
                                    "rollout_pct, uploaded_at, file_size";

// Read/write-degrade observability (gov sre finding, adversarial review
// 2026-08-28): mirrors InstructionStore's `note_read_degrade`/
// `note_write_degrade` convention (#1675) — plain counters, no rate-limited
// DegradeSampler, since this store's call pattern (admin-driven writes,
// per-heartbeat but not per-request reads) isn't the log-flood-prone hot
// path RuntimeConfigStore's sampler exists for.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";

void note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_update_registry_read_degrade_total", {{"reason", reason}})
            .increment();
}

void note_write_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_update_registry_write_degrade_total", {{"reason", reason}})
            .increment();
}

} // namespace

UpdateRegistry::UpdateRegistry(pg::PgPool& pool, const std::filesystem::path& update_dir)
    : pool_(pool), update_dir_(update_dir) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("UpdateRegistry: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("UpdateRegistry: schema migration failed");
        return;
    }
    // Post-migration projection smoke-read (playbook "Runner guards" second-line-of-
    // defense): `run()`'s duplicate/non-monotonic version guard catches a version
    // collision baked into THIS binary's own migrations() vector, but not a version
    // already recorded in schema_meta by a DIFFERENT binary whose schema doesn't match
    // what this binary's runtime queries actually select (ApiTokenStore precedent).
    // Fail closed here rather than surfacing `undefined column` on whichever request
    // runs first.
    {
        const std::string smoke_sql =
            std::string("SELECT ") + kSelectCols + " FROM update_registry.update_packages LIMIT 0";
        pg::PgResult smoke =
            pg::exec_params(lease.get(), smoke_sql.c_str(), std::vector<std::string>{});
        if (smoke.status() != PGRES_TUPLES_OK) {
            spdlog::error("UpdateRegistry: post-migration schema projection check failed — "
                          "update_packages is missing an expected column: {}",
                          PQresultErrorMessage(smoke.get()));
            return;
        }
    }
    lease.reset();
    open_ = true;
    spdlog::info("UpdateRegistry initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

UpdateRegistry::~UpdateRegistry() = default;

bool UpdateRegistry::upsert_package(const UpdatePackage& pkg) {
    if (!open_) {
        note_write_degrade(metrics_, kReasonStoreNotOpen);
        return false;
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        note_write_degrade(metrics_, kReasonPoolTimeout);
        spdlog::error("UpdateRegistry: upsert_package skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO update_registry.update_packages "
        "(platform, arch, version, sha256, filename, mandatory, rollout_pct, uploaded_at, "
        "file_size) "
        "VALUES ($1, $2, $3, $4, $5, $6::boolean, $7::int, $8, $9::bigint) "
        "ON CONFLICT (platform, arch, version) DO UPDATE SET "
        "  sha256 = EXCLUDED.sha256, filename = EXCLUDED.filename, "
        "  mandatory = EXCLUDED.mandatory, rollout_pct = EXCLUDED.rollout_pct, "
        "  uploaded_at = EXCLUDED.uploaded_at, file_size = EXCLUDED.file_size "
        "RETURNING platform",
        std::vector<std::string>{pkg.platform, pkg.arch, pkg.version, pkg.sha256, pkg.filename,
                                 pkg.mandatory ? "true" : "false",
                                 std::to_string(pkg.rollout_pct), pkg.uploaded_at,
                                 std::to_string(pkg.file_size)});
    if (res.status() != PGRES_TUPLES_OK) {
        note_write_degrade(metrics_, kReasonQueryError);
        spdlog::error("UpdateRegistry: upsert_package failed for {}/{}/{}: {}", pkg.platform,
                      pkg.arch, pkg.version, PQerrorMessage(lease.get()));
        return false;
    }
    spdlog::info("UpdateRegistry: upserted package {}/{}/{} ({})", pkg.platform, pkg.arch,
                 pkg.version, pkg.filename);
    return true;
}

void UpdateRegistry::remove_package(const std::string& platform, const std::string& arch,
                                    const std::string& version) {
    if (!open_) {
        note_write_degrade(metrics_, kReasonStoreNotOpen);
        return;
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        note_write_degrade(metrics_, kReasonPoolTimeout);
        spdlog::error("UpdateRegistry: remove_package skipped, no connection in time ({})",
                      pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM update_registry.update_packages "
        "WHERE platform = $1 AND arch = $2 AND version = $3",
        std::vector<std::string>{platform, arch, version});
    if (res.status() != PGRES_COMMAND_OK) {
        note_write_degrade(metrics_, kReasonQueryError);
        spdlog::error("UpdateRegistry: remove_package failed for {}/{}/{}: {}", platform, arch,
                      version, PQerrorMessage(lease.get()));
        return;
    }
    spdlog::info("UpdateRegistry: removed package {}/{}/{}", platform, arch, version);
}

UpdateRegistry::RolloutChange UpdateRegistry::update_rollout_checked(const std::string& platform,
                                                                     const std::string& arch,
                                                                     const std::string& version,
                                                                     int rollout_pct) {
    RolloutChange out; // kUnavailable until proven otherwise
    if (!open_) {
        note_write_degrade(metrics_, kReasonStoreNotOpen);
        return out;
    }

    // Acquire FIRST, then with_txn_on — deliberately not with_txn_for, which
    // collapses "no connection" and "the transaction failed" into one false.
    // This store reports its degrades BY REASON
    // (yuzu_server_update_registry_write_degrade_total{reason}), and the whole
    // point of this store's absent-vs-degraded distinction is not conflating
    // causes; folding a pool timeout into query_error would undo that in the
    // metric.
    // Nothing runs between the acquire and the call, per with_txn_on's contract.
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        note_write_degrade(metrics_, kReasonPoolTimeout);
        spdlog::error("UpdateRegistry: update_rollout skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }

    // ONE transaction, row-locked. The read that produces the audited `from=`
    // and the write it describes must be the same transaction, or a concurrent
    // write to this key can slip between them and the audit row asserts a
    // transition from a value it did not replace. See the header comment.
    //
    // FOR UPDATE, not a bare SELECT: the lock is what makes a second writer on
    // the same key wait rather than interleave. It is row-scoped, so rollouts of
    // DIFFERENT packages still proceed concurrently.
    const bool txn_ok = pool_.with_txn_on(std::move(lease), [&](PGconn* conn) -> bool {
        pg::PgResult sel = pg::exec_params(
            conn,
            "SELECT rollout_pct, mandatory FROM update_registry.update_packages "
            "WHERE platform = $1 AND arch = $2 AND version = $3 FOR UPDATE",
            std::vector<std::string>{platform, arch, version});
        if (sel.status() != PGRES_TUPLES_OK) {
            spdlog::error("UpdateRegistry: update_rollout read failed for {}/{}/{}: {}", platform,
                          arch, version, PQerrorMessage(conn));
            return false; // roll back; out stays kUnavailable
        }
        if (PQntuples(sel.get()) == 0) {
            // A genuine absence, reported by the store rather than inferred from
            // a degrade. Commit the no-op so this is not confused with a failure.
            out.status = PackageLookup::kAbsent;
            return true;
        }

        // The file's own column helpers, not a hand-rolled atoi/char compare —
        // they already handle NULL and the boolean spellings consistently.
        //
        // Recorded HERE, before the UPDATE is attempted, and deliberately: the
        // row's existence and its prior values are established by this SELECT
        // and stay true even if the write below fails. Setting them only on the
        // success path collapsed a failed write onto kUnavailable, which then
        // audited `existence_unknown=true` about a package the store had just
        // returned. `committed` — set by the caller from the transaction's own
        // outcome — is what says whether the write landed.
        out.status = PackageLookup::kFound;
        out.prior_rollout_pct = col_int(sel.get(), 0, 0);
        out.prior_mandatory = col_bool(sel.get(), 0, 1);

        // Writes ONLY rollout_pct. upsert_package writes the whole snapshot
        // back, which is what let a concurrent writer's change to any other
        // column be silently discarded by a rollout edit.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE update_registry.update_packages SET rollout_pct = $4::int "
            "WHERE platform = $1 AND arch = $2 AND version = $3 RETURNING rollout_pct",
            std::vector<std::string>{platform, arch, version, std::to_string(rollout_pct)});
        if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) == 0) {
            spdlog::error("UpdateRegistry: update_rollout write failed for {}/{}/{}: {}", platform,
                          arch, version, PQerrorMessage(conn));
            return false;
        }

        return true;
    });

    // `status` survives a failed transaction; `committed` does not. The SELECT
    // inside the transaction really did observe the row, so an existence and a
    // prior value learned there stay known even though the write rolled back —
    // and the caller audits both facts separately.
    out.committed = txn_ok && out.status == PackageLookup::kFound;

    if (!txn_ok) {
        // A statement failed, or the COMMIT did not land. Neither is absence,
        // and neither may claim a transition.
        //
        // A lost COMMIT RESPONSE after Postgres actually committed also lands
        // here (pg_pool.hpp documents that ambiguity). That is safe for this
        // caller and only for this caller: the audit row says `attempted_`, never
        // that the value changed. Do NOT grow a compensating action on this
        // branch without resolving the ambiguity first (pg_xact_status) — the
        // #3481 CHAOS-1 trap.
        note_write_degrade(metrics_, kReasonQueryError);
        return out;
    }
    if (out.committed) {
        spdlog::info("UpdateRegistry: rollout for {}/{}/{} {}% -> {}%", platform, arch, version,
                     out.prior_rollout_pct, rollout_pct);
    }
    return out;
}

std::vector<UpdatePackage> UpdateRegistry::list_packages() const {
    std::vector<UpdatePackage> packages;
    if (!open_) {
        note_read_degrade(metrics_, kReasonStoreNotOpen);
        return packages;
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        note_read_degrade(metrics_, kReasonPoolTimeout);
        spdlog::error("UpdateRegistry: list_packages skipped, no connection in time ({})",
                      pool_.last_error());
        return packages;
    }
    const std::string sql = std::string("SELECT ") + kSelectCols +
                            " FROM update_registry.update_packages ORDER BY platform, arch, "
                            "uploaded_at DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        note_read_degrade(metrics_, kReasonQueryError);
        spdlog::error("UpdateRegistry: list_packages failed: {}", PQerrorMessage(lease.get()));
        return packages;
    }
    const int rows = PQntuples(res.get());
    packages.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        packages.push_back(row_to_pkg(res.get(), i));
    return packages;
}

std::optional<UpdatePackage> UpdateRegistry::latest_for(const std::string& platform,
                                                        const std::string& arch) const {
    if (!open_) {
        note_read_degrade(metrics_, kReasonStoreNotOpen);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        note_read_degrade(metrics_, kReasonPoolTimeout);
        spdlog::error("UpdateRegistry: latest_for skipped, no connection in time ({})",
                      pool_.last_error());
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kSelectCols +
                            " FROM update_registry.update_packages WHERE platform = $1 AND "
                            "arch = $2";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{platform, arch});
    if (res.status() != PGRES_TUPLES_OK) {
        note_read_degrade(metrics_, kReasonQueryError);
        spdlog::error("UpdateRegistry: latest_for failed for {}/{}: {}", platform, arch,
                      PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::optional<UpdatePackage> best;
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        UpdatePackage pkg = row_to_pkg(res.get(), i);
        if (!best.has_value() || compare_versions(pkg.version, best->version) > 0)
            best = std::move(pkg);
    }
    return best;
}

bool UpdateRegistry::is_eligible(const std::string& agent_id, int rollout_pct) {
    return rollout_pct >= 100 ||
           (std::hash<std::string>{}(agent_id) % 100) < static_cast<unsigned>(rollout_pct);
}

std::filesystem::path UpdateRegistry::binary_path(const UpdatePackage& pkg) const {
    // REVALIDATE AT READ TIME, not only at upload. The upload-time guard (#3863)
    // protects new rows, but every consumer derives its on-disk path from the
    // STORED row: `CheckForUpdate` serves the sidecar beside it, and the delete
    // route unlinks both. A row written before that guard landed — or by direct
    // database access — would otherwise have its traversal filename resolved
    // here and then read from, or deleted, outside `update_dir_`.
    //
    // Returning an EMPTY path rather than a joined one is deliberate: joining an
    // empty or malformed name yields `update_dir_` itself, and handing that to a
    // remove() is far worse than handing it nothing. `exists()`, `remove()` and
    // `ifstream` on an empty path all fail benignly, so every existing caller
    // degrades to "no such package" without needing to learn a new contract.
    if (!is_safe_package_filename(pkg.filename)) {
        spdlog::error("UpdateRegistry: refusing to resolve a path for {}/{}/{} — stored filename "
                      "'{}' is not a bare filename; the row predates the upload guard or was "
                      "written out of band",
                      pkg.platform, pkg.arch, pkg.version, pkg.filename);
        return {};
    }
    return update_dir_ / pkg.filename;
}

std::filesystem::path UpdateRegistry::signature_path(const UpdatePackage& pkg) const {
    // Derived from the binary path, never from a separately-supplied name: the
    // filename is operator-controlled, and letting the signature location be
    // named independently would allow a package to point at some other
    // package's signature.
    //
    // The empty-path case must NOT be appended to: `signature_sidecar_path({})`
    // would yield the relative name ".sig", which resolves against the process
    // working directory rather than against nothing.
    auto binary = binary_path(pkg);
    if (binary.empty())
        return {};
    return signature_sidecar_path(binary);
}

} // namespace yuzu::server
