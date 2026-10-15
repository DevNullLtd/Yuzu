#include "access_review_store.hpp"

#include "pg/pg_array.hpp"
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

constexpr const char* kStoreName = "access_review_store";

// Authoritative store (ADR-0012 §1) — SOC 2 evidence. Bounded acquires still
// apply (never block the pool unboundedly), but this is an admin/compliance
// surface, not a hot path, so the budgets are generous relative to e.g.
// EnginePrincipalStore's auth-lookup timeouts.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE access_review_campaign ("
         "  campaign_id    TEXT PRIMARY KEY,"
         "  title          TEXT NOT NULL,"
         "  status         TEXT NOT NULL CHECK (status IN ('open','closed')),"
         "  created_by     TEXT NOT NULL,"
         "  created_at_ms  BIGINT NOT NULL,"
         "  closed_by      TEXT NOT NULL DEFAULT '',"
         "  closed_at_ms   BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX access_review_campaign_status_idx ON access_review_campaign (status);"
         "CREATE TABLE access_review_attestation ("
         "  campaign_id     TEXT NOT NULL REFERENCES access_review_campaign(campaign_id) "
         "                  ON DELETE CASCADE,"
         "  principal_type  TEXT NOT NULL CHECK (principal_type IN ('user','group','engine')),"
         "  principal_id    TEXT NOT NULL,"
         "  role_name       TEXT NOT NULL,"
         "  decision        TEXT NOT NULL CHECK (decision IN ('pending','attested',"
         "                  'flagged_revoke')),"
         "  reviewer        TEXT NOT NULL DEFAULT '',"
         "  decided_at_ms   BIGINT NOT NULL DEFAULT 0,"
         "  justification   TEXT NOT NULL DEFAULT '',"
         "  grant_snapshot  TEXT NOT NULL DEFAULT '',"
         "  PRIMARY KEY (campaign_id, principal_type, principal_id, role_name));"},
        // A3 (RBAC delivery plan): stamp each campaign with the fleet's RBAC
        // enforcement state at open. DEFAULT '' is honest-empty for every row
        // that predates this column — never '' -> 'degraded' backfill, and
        // never a value a live open_campaign() call may pass (validated in
        // C++ before the insert, mirroring record_attestation's decision
        // check). CHECK mirrors the other closed-vocabulary columns on this
        // table (status, decision) — an empty string is the ONLY value the
        // check allows without also being one open_campaign() itself accepts.
        {2,
         "ALTER TABLE access_review_campaign ADD COLUMN rbac_enforcement TEXT NOT NULL DEFAULT '' "
         "CHECK (rbac_enforcement IN ('', 'enabled', 'disabled', 'degraded'));"},
    };
    return kMigrations;
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// Mirrors DeploymentStore::generate_id — a 64-bit mt19937_64 value formatted
// as 16 hex chars. NOT a cryptographic random source: `campaign_id` is a
// non-security surrogate key (uniqueness, not unguessability, is what
// matters here — nothing is authorized by knowing this id). Minted BY THIS
// STORE (not the caller/route layer) per the task contract for
// `open_campaign`.
std::string generate_campaign_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    char buf[17]{};
    std::snprintf(buf, sizeof(buf), "%016llx",
                 static_cast<unsigned long long>(dist(rng)));
    return std::string{buf};
}

AccessReviewCampaignRow read_campaign(PGresult* res, int i) {
    AccessReviewCampaignRow c;
    int col = 0;
    c.campaign_id = PQgetvalue(res, i, col++);
    c.title = PQgetvalue(res, i, col++);
    c.status = PQgetvalue(res, i, col++);
    c.created_by = PQgetvalue(res, i, col++);
    c.created_at_ms = to_i64(PQgetvalue(res, i, col++));
    c.closed_by = PQgetvalue(res, i, col++);
    c.closed_at_ms = to_i64(PQgetvalue(res, i, col++));
    c.rbac_enforcement = PQgetvalue(res, i, col++);
    return c;
}

constexpr const char* kCampaignCols = "campaign_id, title, status, created_by, created_at_ms, "
                                      "closed_by, closed_at_ms, rbac_enforcement";

AccessReviewAttestationRow read_attestation(PGresult* res, int i) {
    AccessReviewAttestationRow a;
    int col = 0;
    a.campaign_id = PQgetvalue(res, i, col++);
    a.principal_type = PQgetvalue(res, i, col++);
    a.principal_id = PQgetvalue(res, i, col++);
    a.role_name = PQgetvalue(res, i, col++);
    a.decision = PQgetvalue(res, i, col++);
    a.reviewer = PQgetvalue(res, i, col++);
    a.decided_at_ms = to_i64(PQgetvalue(res, i, col++));
    a.justification = PQgetvalue(res, i, col++);
    a.grant_snapshot = PQgetvalue(res, i, col++);
    return a;
}

constexpr const char* kAttestationCols =
    "campaign_id, principal_type, principal_id, role_name, decision, reviewer, decided_at_ms, "
    "justification, grant_snapshot";

} // namespace

AccessReviewStore::AccessReviewStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AccessReviewStore: no database connection at construction ({}) — access "
                      "review persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error(
            "AccessReviewStore: schema migration failed — access review persistence disabled");
        return;
    }
    open_ = true;
}

std::expected<std::string, std::string>
AccessReviewStore::open_campaign(std::string title, std::string created_by,
                                 const std::vector<GrantRef>& frozen_population,
                                 std::string rbac_enforcement) {
    if (!open_)
        return std::unexpected("database not open");
    if (title.empty())
        return std::unexpected("title cannot be empty");
    if (created_by.empty())
        return std::unexpected("created_by cannot be empty");
    if (rbac_enforcement != "enabled" && rbac_enforcement != "disabled" &&
        rbac_enforcement != "degraded")
        return std::unexpected("rbac_enforcement must be 'enabled', 'disabled', or 'degraded'");

    const std::string campaign_id = generate_campaign_id();
    const std::int64_t created_at = now_ms();

    // Parallel arrays for the frozen-population batch insert (unnest), same
    // idiom as PreflightRunStore::create_run — one round-trip regardless of
    // population size, rather than N inserts inside a single held lease.
    std::vector<std::string_view> ptypes, pids, rnames, snapshots;
    ptypes.reserve(frozen_population.size());
    pids.reserve(frozen_population.size());
    rnames.reserve(frozen_population.size());
    snapshots.reserve(frozen_population.size());
    for (const auto& g : frozen_population) {
        ptypes.emplace_back(g.principal_type);
        pids.emplace_back(g.principal_id);
        rnames.emplace_back(g.role_name);
        snapshots.emplace_back(g.grant_snapshot);
    }

    std::string error_msg;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult r1 = pg::exec_params(
            conn,
            "INSERT INTO access_review_store.access_review_campaign "
            "(campaign_id, title, status, created_by, created_at_ms, rbac_enforcement) "
            "VALUES ($1,$2,'open',$3,$4::bigint,$5) RETURNING campaign_id",
            std::vector<std::string>{campaign_id, title, created_by,
                                     std::to_string(created_at), rbac_enforcement});
        if (r1.status() != PGRES_TUPLES_OK || PQntuples(r1.get()) == 0) {
            error_msg = std::string("campaign insert failed: ") + PQerrorMessage(conn);
            return false;
        }
        if (frozen_population.empty())
            return true;
        pg::PgResult r2 = pg::exec_params(
            conn,
            "INSERT INTO access_review_store.access_review_attestation "
            "(campaign_id, principal_type, principal_id, role_name, decision, grant_snapshot) "
            "SELECT $1, t, i, r, 'pending', s "
            "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS g(t, i, r, s)",
            std::vector<std::string>{campaign_id, pg::to_text_array(ptypes),
                                     pg::to_text_array(pids), pg::to_text_array(rnames),
                                     pg::to_text_array(snapshots)});
        if (r2.status() != PGRES_COMMAND_OK && r2.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("attestation freeze insert failed: ") + PQerrorMessage(conn);
            return false;
        }
        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "open_campaign failed" : error_msg);
    return campaign_id;
}

std::expected<void, std::string>
AccessReviewStore::record_attestation(const std::string& campaign_id,
                                      const std::string& principal_type,
                                      const std::string& principal_id,
                                      const std::string& role_name, std::string decision,
                                      std::string reviewer, std::string justification) {
    if (!open_)
        return std::unexpected("database not open");
    if (decision != "attested" && decision != "flagged_revoke")
        return std::unexpected("decision must be 'attested' or 'flagged_revoke'");
    if (campaign_id.empty() || principal_type.empty() || principal_id.empty() ||
        role_name.empty())
        return std::unexpected("campaign_id/principal_type/principal_id/role_name required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    // The `EXISTS (... status='open')` guard makes a closed campaign's
    // attestation rows immutable — no separate pre-check-then-write race
    // (the whole thing is one statement).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE access_review_store.access_review_attestation "
        "SET decision=$5, reviewer=$6, decided_at_ms=$7::bigint, justification=$8 "
        "WHERE campaign_id=$1 AND principal_type=$2 AND principal_id=$3 AND role_name=$4 "
        "  AND EXISTS (SELECT 1 FROM access_review_store.access_review_campaign c "
        "              WHERE c.campaign_id=$1 AND c.status='open') "
        "RETURNING campaign_id",
        std::vector<std::string>{campaign_id, principal_type, principal_id, role_name, decision,
                                 reviewer, std::to_string(now_ms()), justification});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("record_attestation write failed: ") +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected(
            "not_found: no pending grant matches (campaign_id, principal_type, principal_id, "
            "role_name) in an open campaign — it was never in the frozen population, the "
            "campaign is closed, or the campaign_id is unknown");
    return {};
}

std::expected<CampaignView, std::string>
AccessReviewStore::get_campaign(const std::string& campaign_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (campaign_id.empty())
        return std::unexpected("not_found: campaign_id required");

    // Both reads share one REPEATABLE READ transaction so a concurrent
    // attestation write between the campaign-row read and the attestation-rows
    // read can't yield inconsistent metadata vs rows/pending_count: a plain
    // `with_txn_for` only issues `BEGIN` (READ COMMITTED), under which each
    // statement takes its own snapshot and the two SELECTs could still
    // straddle a concurrent record_attestation COMMIT. `SET TRANSACTION
    // ISOLATION LEVEL REPEATABLE READ` as the first statement pins both
    // reads to the one snapshot taken at that point.
    CampaignView view;
    std::string error_msg;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kReadTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult iso_res{PQexec(conn, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")};
        if (iso_res.status() != PGRES_COMMAND_OK) {
            error_msg =
                std::string("get_campaign: failed to set REPEATABLE READ isolation: ") +
                PQerrorMessage(conn);
            return false;
        }

        std::string csql = std::string("SELECT ") + kCampaignCols +
                           " FROM access_review_store.access_review_campaign WHERE campaign_id=$1";
        pg::PgResult cres =
            pg::exec_params(conn, csql.c_str(), std::vector<std::string>{campaign_id});
        if (cres.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("get_campaign read failed: ") + PQerrorMessage(conn);
            return false;
        }
        if (PQntuples(cres.get()) == 0) {
            not_found = true;
            return false;
        }
        view.campaign = read_campaign(cres.get(), 0);

        std::string asql = std::string("SELECT ") + kAttestationCols +
                           " FROM access_review_store.access_review_attestation "
                           "WHERE campaign_id=$1 ORDER BY principal_type, principal_id, role_name";
        pg::PgResult ares =
            pg::exec_params(conn, asql.c_str(), std::vector<std::string>{campaign_id});
        if (ares.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("get_campaign attestation read failed: ") +
                       PQerrorMessage(conn);
            return false;
        }

        const int rows = PQntuples(ares.get());
        view.attestations.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            auto a = read_attestation(ares.get(), i);
            if (a.decision == "pending")
                ++view.pending_count;
            view.attestations.push_back(std::move(a));
        }
        return true;
    });

    if (!ok) {
        if (not_found)
            return std::unexpected("not_found: no campaign with this id");
        return std::unexpected(error_msg.empty() ? "get_campaign failed" : error_msg);
    }
    return view;
}

std::expected<void, std::string>
AccessReviewStore::close_campaign(const std::string& campaign_id, const std::string& closed_by) {
    if (!open_)
        return std::unexpected("database not open");
    if (campaign_id.empty())
        return std::unexpected("not_found: campaign_id required");
    if (closed_by.empty())
        return std::unexpected("closed_by cannot be empty");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE access_review_store.access_review_campaign "
        "SET status='closed', closed_by=$2, closed_at_ms=$3::bigint "
        "WHERE campaign_id=$1 AND status='open' RETURNING campaign_id",
        std::vector<std::string>{campaign_id, closed_by, std::to_string(now_ms())});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("close_campaign write failed: ") +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: campaign missing or already closed");
    return {};
}

std::expected<std::vector<AccessReviewCampaignRow>, std::string> AccessReviewStore::list_campaigns() {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    // Bounded (see .hpp doc) — a compliance/auditor list surface, not a
    // paged operational feed.
    std::string sql = std::string("SELECT ") + kCampaignCols +
                      " FROM access_review_store.access_review_campaign "
                      "ORDER BY created_at_ms DESC, campaign_id DESC LIMIT 500";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("list_campaigns read failed: ") +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<AccessReviewCampaignRow> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_campaign(res.get(), i));
    return out;
}

} // namespace yuzu::server
