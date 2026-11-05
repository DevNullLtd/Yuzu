#include "access_review_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
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

// The ONE definition of "the reviewer is the subject of this grant" (#4752),
// spliced into both the guarded UPDATE and its diagnosing SELECT so the two
// can never drift. Expects alias `a` on access_review_attestation and the
// reviewer as $5. Exact byte comparison, no case folding — a fold that is wrong
// in the permissive direction would let someone sign off their own access
// (same stance as `is_self_target` / `same_human_root`).
//   user   — the grant's principal_id is the reviewer's username.
//   engine — the engine's owner, FROZEN into grant_snapshot at campaign open
//            (`owner_or_email` holds `owner_username` for engine rows). Frozen,
//            not live: the reviewed population is frozen at open and this needs
//            no cross-store read. The key name is a CONTRACT with the handlers
//            that write the snapshot (rest_api_v1.cpp / mcp_server.cpp open
//            routes); renaming it there turns this arm into a silent no-op, so
//            the REST and MCP engine-owner tests are its tripwire.
//            `pg_input_is_valid(.., 'jsonb')` (PostgreSQL 16+, the project
//            floor) makes the cast safe for ANY text — empty, legacy or
//            malformed — and it sits INSIDE the CASE, whose branches Postgres
//            evaluates in order, so the cast is never reached for a bad value
//            or for a non-engine row. A snapshot that is valid JSON but not an
//            object, or has no owner key, yields NULL -> '' (attestable).
//   group  — not covered (no owner; membership is a cross-store read). Known,
//            documented limit.
constexpr const char* kSelfSubject =
    "(a.principal_type='user' AND a.principal_id=$5) OR "
    "(a.principal_type='engine' AND COALESCE(CASE WHEN a.principal_type='engine' "
    "AND pg_input_is_valid(a.grant_snapshot, 'jsonb') "
    "THEN (a.grant_snapshot::jsonb)->>'owner_or_email' END, '') = $5)";

// Upper bound for every caller-supplied identifier on the attestation path.
// Postgres stops reading a bound parameter at the first NUL, so an identifier
// carrying one would MATCH the real row while the caller's full bytes went on
// into the audit target; and the audit table has no column bound. Rejecting
// both here (rather than in each transport) keeps ONE copy of the rule.
//
// 512 is deliberately generous: `auth::is_valid_principal` caps every prefixed
// principal (oidc:/saml:/ad:/engine:) at 255 bytes and a local username is far
// shorter, and rbac_store.cpp's kMaxExternalIdLength is also 512, so no real
// grant's principal_id can be refused by it. (A provider's raw
// "oidc:"+iss+"#"+sub could reach 516, but such a principal cannot be created.)
constexpr std::size_t kMaxIdentifierBytes = 512;

// The reviewer's free-text justification is stored as evidence. A NUL byte would
// silently truncate it (libpq stops reading a parameter at the first NUL) and its
// size was otherwise bounded only by the request-body cap, so it gets the same
// refuse-don't-truncate treatment with a limit sized for prose.
constexpr std::size_t kMaxJustificationBytes = 8192;

[[nodiscard]] bool bad_identifier(const std::string& s) {
    return s.size() > kMaxIdentifierBytes || s.find('\0') != std::string::npos;
}

// Log-safe rendering of a campaign id: control characters become '?', truncated.
[[nodiscard]] std::string log_safe(const std::string& s) {
    std::string out;
    out.reserve(std::min<std::size_t>(s.size(), 64));
    for (unsigned char c : s) {
        if (out.size() >= 64)
            break;
        out.push_back((c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c));
    }
    return out;
}

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
        return std::unexpected(std::string(kBadRequestPrefix) +
                               " decision must be 'attested' or 'flagged_revoke'");
    if (campaign_id.empty() || principal_type.empty() || principal_id.empty() ||
        role_name.empty())
        return std::unexpected(std::string(kBadRequestPrefix) +
                               " campaign_id/principal_type/principal_id/role_name required");
    if (bad_identifier(campaign_id) || bad_identifier(principal_type) ||
        bad_identifier(principal_id) || bad_identifier(role_name) || bad_identifier(reviewer))
        return std::unexpected(std::string(kBadRequestPrefix) +
                               " an identifier contains a NUL byte or exceeds 512 bytes");
    if (justification.size() > kMaxJustificationBytes ||
        justification.find('\0') != std::string::npos)
        return std::unexpected(std::string(kBadRequestPrefix) +
                               " justification contains a NUL byte or exceeds 8192 bytes");

    // Fail closed on an unidentified reviewer, the same way `is_self_target`
    // treats an empty username as "self": without an identity the
    // reviewer-vs-subject comparison below has nothing to compare.
    if (reviewer.empty())
        return std::unexpected(std::string(kBadRequestPrefix) + " reviewer required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    // The decision is written by ONE statement whose WHERE clause carries
    // every rule, so there is no check-then-write race and no caller can
    // skip a rule:
    //   * `EXISTS (... status='open' FOR SHARE)` — a closed campaign's rows are
    //     immutable evidence. FOR SHARE is load-bearing: without it the check is
    //     a snapshot read, so an attestation already waiting on a row lock could
    //     commit AFTER a concurrent close and land a final decision in a closed
    //     campaign (verified). The share lock makes a close wait for in-flight
    //     attests and makes a later attest re-check the new status; attests
    //     share the lock with each other, and close_campaign touches only the
    //     campaign row, so there is no lock-order cycle.
    //   * `decision='pending'` — a decision is FINAL (#4752; owner ruling
    //     2026-11-05). The first Attest/Flag sticks; a second reviewer, or
    //     the subject, can never replace it. Also closes #2326 item 2.
    //   * `kSelfSubject` — separation of duties: the reviewer may not be the
    //     subject of the grant (user), nor the owner of an engine principal
    //     as frozen into `grant_snapshot` at campaign open.
    // `COALESCE(..., '')` is load-bearing: `NOT (true AND NULL)` is NULL, which
    // a WHERE clause treats as false, so an engine row with an empty snapshot
    // would otherwise become unattestable instead of attestable.
    const std::string update_sql =
        std::string("UPDATE access_review_store.access_review_attestation a "
                    "SET reviewer=$5, decision=$6, decided_at_ms=$7::bigint, justification=$8 "
                    "WHERE a.campaign_id=$1 AND a.principal_type=$2 AND a.principal_id=$3 "
                    "  AND a.role_name=$4 AND a.decision='pending' AND NOT (") +
        kSelfSubject +
        ") AND EXISTS (SELECT 1 FROM access_review_store.access_review_campaign c "
        "              WHERE c.campaign_id=$1 AND c.status='open' FOR SHARE) "
        "RETURNING a.campaign_id";
    pg::PgResult res = pg::exec_params(
        lease.get(), update_sql.c_str(),
        std::vector<std::string>{campaign_id, principal_type, principal_id, role_name, reviewer,
                                 decision, std::to_string(now_ms()), justification});
    if (res.status() != PGRES_TUPLES_OK) {
        // The libpq text can carry schema / constraint / JSON fragments, so it
        // is logged here and never returned to the (REST / MCP) client.
        const char* sqlstate = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        spdlog::error("AccessReviewStore::record_attestation: write failed "
                      "(campaign={}, sqlstate={}): {}",
                      log_safe(campaign_id), sqlstate ? sqlstate : "?",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string("record_attestation write failed"));
    }
    if (PQntuples(res.get()) != 0)
        return {};

    // Zero rows: say WHY. This read only chooses the error text — the write
    // above is the sole guard, so a campaign closing between the two
    // statements can at worst mislabel a refusal, never permit a write.
    const std::string why_sql =
        std::string("SELECT c.status, a.decision, (") + kSelfSubject +
        ") AS is_self "
        "FROM access_review_store.access_review_attestation a "
        "JOIN access_review_store.access_review_campaign c ON c.campaign_id = a.campaign_id "
        "WHERE a.campaign_id=$1 AND a.principal_type=$2 AND a.principal_id=$3 "
        "  AND a.role_name=$4";
    pg::PgResult why = pg::exec_params(
        lease.get(), why_sql.c_str(),
        std::vector<std::string>{campaign_id, principal_type, principal_id, role_name, reviewer});
    if (why.status() != PGRES_TUPLES_OK) {
        const char* sqlstate = PQresultErrorField(why.get(), PG_DIAG_SQLSTATE);
        spdlog::error("AccessReviewStore::record_attestation: diagnosis failed "
                      "(campaign={}, sqlstate={}): {}",
                      log_safe(campaign_id), sqlstate ? sqlstate : "?",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string("record_attestation diagnosis failed"));
    }
    if (PQntuples(why.get()) == 0 || std::string_view(PQgetvalue(why.get(), 0, 0)) != "open")
        return std::unexpected(
            "not_found: no pending grant matches (campaign_id, principal_type, principal_id, "
            "role_name) in an open campaign — it was never in the frozen population, the "
            "campaign is closed, or the campaign_id is unknown");
    // Self-attestation outranks already-decided: a subject trying to overwrite
    // a decision about their own grant is the security-relevant signal.
    if (std::string_view(PQgetvalue(why.get(), 0, 2)) == "t")
        return std::unexpected(
            std::string(kSelfAttestationPrefix) +
            " the acting reviewer is the subject of this grant (or the owner of this engine "
            "principal) and may not decide it — another reviewer must");
    // The recorded decision comes from a CHECK-constrained column
    // ('attested' | 'flagged_revoke'), so it is safe to echo, and it lets a
    // caller whose first response was lost recover the state instead of
    // guessing (and flipping) it.
    return std::unexpected(
        std::string(kAlreadyDecidedPrefix) + " this grant already has a recorded decision ('" +
        std::string(PQgetvalue(why.get(), 0, 1)) +
        "') in this open campaign and decisions are final — open a new campaign to "
        "re-review it");
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
    if (res.status() != PGRES_TUPLES_OK) {
        // Same posture as record_attestation: the libpq text stays in the server
        // log (with the sqlstate, e.g. 55P03 when the close waits on a lock) and the
        // client gets a fixed string.
        const char* sqlstate = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        spdlog::error("AccessReviewStore::close_campaign: write failed (campaign={}, sqlstate={}): {}",
                      log_safe(campaign_id), sqlstate ? sqlstate : "?",
                      PQerrorMessage(lease.get()));
        return std::unexpected(std::string("close_campaign write failed"));
    }
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
