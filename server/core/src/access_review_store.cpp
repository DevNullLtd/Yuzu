#include "access_review_store.hpp"

#include "access_review_model.hpp"
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
        {1, "CREATE TABLE access_review_campaign ("
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
        // #4752: keep every attestation decision, and require the reviewer to differ from the
        // subject of the grant. HYBRID design: the current-state row keeps its primary key and
        // gains `decision_seq`; the new history table is the evidence trail. The STORE writes
        // the history row (in record_attestation, inside the same transaction as the state
        // change); the database only GUARDS, so a state change that is not exactly one appended
        // history row is refused. A writer trigger was rejected because an `IS DISTINCT FROM`
        // trigger records value changes, not decisions (an identical repeat attest would leave
        // no history). A bare UPDATE from an earlier binary against a migrated schema fails
        // (SQLSTATE class 23) and does not bypass the reviewer rule; the deployment contract
        // excludes earlier binaries, so this is a backstop, not a supported configuration.
        //
        // Honest limits: append-only against the application path and ordinary SQL, NOT
        // against the application credential. The runner creates the schema under that role, so
        // it owns the tables and can DISABLE TRIGGER USER (DISABLE TRIGGER ALL is refused to a
        // non-superuser: the foreign keys' system triggers), forge a history row that matches,
        // TRUNCATE (row triggers do not fire on TRUNCATE, which is why a test fixture's
        // TRUNCATE ... CASCADE still works) or DROP TABLE; a role granted TRUNCATE can too. A
        // data-only restore into a migrated schema is refused by the guard: restore schema and
        // data together. A future migration that touches attestation rows must DISABLE TRIGGER
        // USER inside its own transaction (the ca_store v4 rule).
        //
        // Statement order matters. The refusal runs first so a legacy self-recorded decision
        // surfaces the readable message below rather than the history CHECK's. Every guard is
        // created AFTER the backfill (which writes through no guard), and the deferred
        // consistency trigger LAST. Function bodies schema-qualify their table names: a trigger
        // function runs on a pooled connection that has no store search_path.
        //
        // Hard cutover (docs/user-manual/upgrading.md "Deployment contract"): a database
        // carried forward from a build that let a reviewer decide their own grant is REFUSED
        // here, every boot, until it is replaced. Every other legacy decided row backfills as
        // seq 1 with previous_decision '' (not recorded; never read as 'pending').
        //
        // ADD COLUMN and ADD CONSTRAINT take ACCESS EXCLUSIVE (CREATE TRIGGER takes SHARE ROW
        // EXCLUSIVE), so the pool's 10 s lock_timeout is raised to 30 s as in ca_store v3/v4.
        // The backfill is expected to be empty under the deployment contract; the
        // statement_timeout bounds a carried-forward one.
        {3, "SET LOCAL lock_timeout = '30s'; "
            "SET LOCAL statement_timeout = '300s'; "
            R"sql(
DO $do$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM access_review_store.access_review_attestation
   WHERE principal_type = 'user' AND principal_id = reviewer AND decision <> 'pending';
  IF n > 0 THEN
    RAISE EXCEPTION 'access_review_store: % decision row(s) were recorded by the subject of the grant under an earlier build; this build keeps every decision and requires the reviewer to differ from the subject, so these rows cannot be carried forward. Deploy into a fresh database (docs/user-manual/upgrading.md "Deployment contract"). To list them: SELECT campaign_id, principal_id, role_name FROM access_review_store.access_review_attestation WHERE principal_type = ''user'' AND principal_id = reviewer AND decision <> ''pending''', n
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
END
$do$;
ALTER TABLE access_review_attestation ADD COLUMN decision_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE access_review_attestation_history (
  campaign_id       TEXT NOT NULL REFERENCES access_review_campaign(campaign_id) ON DELETE RESTRICT,
  principal_type    TEXT NOT NULL CHECK (principal_type IN ('user','group','engine')),
  principal_id      TEXT NOT NULL,
  role_name         TEXT NOT NULL,
  seq               INTEGER NOT NULL CHECK (seq >= 1),
  decision          TEXT NOT NULL CHECK (decision IN ('attested','flagged_revoke')),
  previous_decision TEXT NOT NULL CHECK (previous_decision IN ('','pending','attested','flagged_revoke')),
  reviewer          TEXT NOT NULL,
  justification     TEXT NOT NULL DEFAULT '',
  decided_at_ms     BIGINT NOT NULL,
  PRIMARY KEY (campaign_id, principal_type, principal_id, role_name, seq),
  FOREIGN KEY (campaign_id, principal_type, principal_id, role_name)
    REFERENCES access_review_attestation(campaign_id, principal_type, principal_id, role_name)
    ON DELETE RESTRICT,
  CONSTRAINT access_review_history_reviewer_not_subject
    CHECK (NOT (principal_type = 'user' AND principal_id = reviewer)));
INSERT INTO access_review_attestation_history
  (campaign_id, principal_type, principal_id, role_name, seq, decision, previous_decision,
   reviewer, justification, decided_at_ms)
  SELECT campaign_id, principal_type, principal_id, role_name, 1, decision, '', reviewer,
         justification, decided_at_ms
    FROM access_review_attestation WHERE decision <> 'pending';
UPDATE access_review_attestation SET decision_seq = 1 WHERE decision <> 'pending';
ALTER TABLE access_review_attestation ADD CONSTRAINT access_review_attestation_seq_chk
  CHECK ((decision = 'pending') = (decision_seq = 0));
CREATE FUNCTION access_review_store.access_review_attestation_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.decision <> 'pending' OR NEW.decision_seq <> 0 THEN
      RAISE EXCEPTION 'access_review_attestation: a row is inserted pending at seq 0 only (decisions are appended through the history table)' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'access_review_attestation: rows are never deleted (campaign evidence)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.campaign_id <> OLD.campaign_id OR NEW.principal_type <> OLD.principal_type
     OR NEW.principal_id <> OLD.principal_id OR NEW.role_name <> OLD.role_name
     OR NEW.grant_snapshot <> OLD.grant_snapshot THEN
    RAISE EXCEPTION 'access_review_attestation: key and grant_snapshot are immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.decision_seq <> OLD.decision_seq + 1 THEN
    RAISE EXCEPTION 'access_review_attestation: decision_seq must advance by exactly one (old %, new %)', OLD.decision_seq, NEW.decision_seq USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM access_review_store.access_review_attestation_history h
                  WHERE h.campaign_id = NEW.campaign_id AND h.principal_type = NEW.principal_type
                    AND h.principal_id = NEW.principal_id AND h.role_name = NEW.role_name
                    AND h.seq = NEW.decision_seq AND h.decision = NEW.decision
                    AND h.reviewer = NEW.reviewer AND h.decided_at_ms = NEW.decided_at_ms
                    AND h.justification = NEW.justification
                    AND h.previous_decision = OLD.decision) THEN
    RAISE EXCEPTION 'access_review_attestation: no matching history row at seq % (decisions are appended, never overwritten)', NEW.decision_seq USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER access_review_attestation_guard BEFORE INSERT OR UPDATE OR DELETE
  ON access_review_attestation
  FOR EACH ROW EXECUTE FUNCTION access_review_store.access_review_attestation_guard();
CREATE FUNCTION access_review_store.access_review_history_keep() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'access_review_attestation_history: a decision row cannot be % (history is append-only)', lower(TG_OP) USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER access_review_history_keep BEFORE UPDATE OR DELETE
  ON access_review_attestation_history
  FOR EACH ROW EXECUTE FUNCTION access_review_store.access_review_history_keep();
CREATE FUNCTION access_review_store.access_review_history_consistent() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access_review_store.access_review_attestation a
                  WHERE a.campaign_id = NEW.campaign_id AND a.principal_type = NEW.principal_type
                    AND a.principal_id = NEW.principal_id AND a.role_name = NEW.role_name
                    AND a.decision_seq >= NEW.seq
                    AND (a.decision_seq <> NEW.seq
                         OR (a.decision = NEW.decision AND a.reviewer = NEW.reviewer
                             AND a.decided_at_ms = NEW.decided_at_ms))) THEN
    RAISE EXCEPTION 'access_review_attestation_history: seq % committed ahead of the current decision (history and state must advance together)', NEW.seq USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER access_review_history_consistent AFTER INSERT
  ON access_review_attestation_history
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION access_review_store.access_review_history_consistent();
)sql"},
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
    a.decision_seq = static_cast<std::int32_t>(to_i64(PQgetvalue(res, i, col++)));
    return a;
}

constexpr const char* kAttestationCols =
    "campaign_id, principal_type, principal_id, role_name, decision, reviewer, decided_at_ms, "
    "justification, grant_snapshot, decision_seq";

AttestationHistoryRow read_history(PGresult* res, int i) {
    AttestationHistoryRow h;
    int col = 4; // the grant's 4-tuple (cols 0-3) is the merge key, read by the caller
    h.seq = static_cast<std::int32_t>(to_i64(PQgetvalue(res, i, col++)));
    h.decision = PQgetvalue(res, i, col++);
    h.previous_decision = PQgetvalue(res, i, col++);
    h.reviewer = PQgetvalue(res, i, col++);
    h.justification = PQgetvalue(res, i, col++);
    h.justification_truncated = std::string_view(PQgetvalue(res, i, col++)) == "t";
    h.decided_at_ms = to_i64(PQgetvalue(res, i, col++));
    return h;
}

// The grant's latest entry (h.seq = the state row's decision_seq, $3 below is the preview length)
// keeps its whole justification; every other entry is cut to its first $3 CHARACTERS by the
// database (`left` counts characters, so on a UTF8 database a multibyte sequence is never split;
// on a single-byte encoding it counts bytes), and the flag says whether anything was cut. Done in
// SQL so the discarded text is never read into this process.
// `a` is the state row (LEFT JOINed: a history row whose state row is missing still reaches the
// merge below, which reports it, and is treated as superseded here).
constexpr const char* kHistoryCols =
    "h.campaign_id, h.principal_type, h.principal_id, h.role_name, h.seq, h.decision, "
    "h.previous_decision, h.reviewer, "
    "CASE WHEN h.seq = a.decision_seq THEN h.justification "
    "     ELSE left(h.justification, $3::integer) END, "
    "(h.seq IS DISTINCT FROM a.decision_seq AND length(h.justification) > $3::integer), "
    "h.decided_at_ms";

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
    // libpq binds c_str() (pg/pg_exec.hpp): an embedded NUL would truncate the stored value, so
    // the campaign recorded would not carry the title or creator named. Refuse before the pool is
    // touched.
    if (title.find('\0') != std::string::npos)
        return std::unexpected("bad_request: title contains a NUL byte");
    if (created_by.find('\0') != std::string::npos)
        return std::unexpected("bad_request: created_by contains a NUL byte");
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

std::expected<AttestationOutcome, std::string> AccessReviewStore::record_attestation(
    const std::string& campaign_id, const std::string& principal_type,
    const std::string& principal_id, const std::string& role_name, std::string decision,
    std::string reviewer, std::string justification) {
    if (!open_)
        return std::unexpected("database not open");
    if (decision != "attested" && decision != "flagged_revoke")
        return std::unexpected("decision must be 'attested' or 'flagged_revoke'");
    if (!valid_campaign_id(campaign_id))
        return std::unexpected("bad_request: campaign_id invalid");
    if (principal_type.empty() || principal_id.empty() || role_name.empty())
        return std::unexpected("campaign_id/principal_type/principal_id/role_name required");
    // The decision's author is recorded in the history and is half of the reviewer-differs-from-
    // subject comparison, so an empty reviewer is refused (close_campaign does the same for
    // closed_by).
    if (reviewer.empty())
        return std::unexpected("bad_request: reviewer cannot be empty");
    // libpq binds c_str() (pg/pg_exec.hpp): an embedded NUL would truncate the value, so the
    // row written or matched would not be the one named. Refuse before the pool is touched.
    const auto has_nul = [](const std::string& s) {
        return s.find('\0') != std::string::npos;
    };
    if (has_nul(principal_type))
        return std::unexpected("bad_request: principal_type contains a NUL byte");
    if (has_nul(principal_id))
        return std::unexpected("bad_request: principal_id contains a NUL byte");
    if (has_nul(role_name))
        return std::unexpected("bad_request: role_name contains a NUL byte");
    // The same caps the transports enforce before their gate (access_review_model.hpp); here as
    // the backstop for a caller that skips it, so no stored row names an unbounded tuple.
    if (!attest_grant_fields_within_bounds(principal_type, principal_id, role_name))
        return std::unexpected("bad_request: " + std::string(kGrantFieldInvalidMessage));
    if (has_nul(reviewer))
        return std::unexpected("bad_request: reviewer contains a NUL byte");
    if (has_nul(justification))
        return std::unexpected("bad_request: justification contains a NUL byte");
    if (justification.size() > kMaxJustificationBytes)
        return std::unexpected("bad_request: justification exceeds " +
                               std::to_string(kMaxJustificationBytes) + " bytes");

    // Reviewer != subject for a user grant (#4752), byte-exact (no case folding). Decided from
    // the arguments alone, before any lease, so it precedes `not_found` for a missing or closed
    // campaign; the UPDATE's own predicate below is the backstop. The engine-owner and
    // group-member rules need other stores and are the route layer's, not this store's.
    if (principal_type == "user" && principal_id == reviewer)
        return std::unexpected("forbidden: reviewer is the subject of this grant");

    // One timestamp bound into both statements: the state guard compares it byte-exact against
    // the history row.
    const std::string decided_at = std::to_string(now_ms());

    AttestationOutcome outcome;
    std::string error_msg;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Lock order: the attestation row, then the campaign row (close_campaign takes only
        // the campaign row, so there is no cycle). FOR SHARE on the campaign makes a close wait
        // for this decision to commit; an attest after a close sees 'closed' and is refused.
        pg::PgResult pre = pg::exec_params(
            conn,
            "SELECT a.decision, a.decision_seq, c.status "
            "FROM access_review_store.access_review_attestation a "
            "JOIN access_review_store.access_review_campaign c ON c.campaign_id = a.campaign_id "
            "WHERE a.campaign_id=$1 AND a.principal_type=$2 AND a.principal_id=$3 "
            "  AND a.role_name=$4 "
            "FOR UPDATE OF a FOR SHARE OF c",
            std::vector<std::string>{campaign_id, principal_type, principal_id, role_name});
        if (pre.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("record_attestation read failed: ") + PQerrorMessage(conn);
            return false;
        }
        if (PQntuples(pre.get()) == 0 || std::string_view{PQgetvalue(pre.get(), 0, 2)} != "open") {
            not_found = true;
            return false;
        }
        const std::string old_decision = PQgetvalue(pre.get(), 0, 0);
        const std::int32_t old_seq = static_cast<std::int32_t>(to_i64(PQgetvalue(pre.get(), 0, 1)));
        // Per-grant cap, decided under the row lock so two racing attests cannot both pass it.
        // Returning false rolls the transaction back: no history row, state unchanged.
        if (old_seq >= kMaxDecisionsPerGrant) {
            error_msg = "bad_request: " + std::string(kDecisionCapMessage);
            return false;
        }
        const std::string new_seq = std::to_string(old_seq + 1);

        pg::PgResult hist = pg::exec_params(
            conn,
            "INSERT INTO access_review_store.access_review_attestation_history "
            "(campaign_id, principal_type, principal_id, role_name, seq, decision, "
            " previous_decision, reviewer, justification, decided_at_ms) "
            "VALUES ($1,$2,$3,$4,$5::integer,$6,$7,$8,$9,$10::bigint)",
            std::vector<std::string>{campaign_id, principal_type, principal_id, role_name, new_seq,
                                     decision, old_decision, reviewer, justification, decided_at});
        if (hist.status() != PGRES_COMMAND_OK) {
            error_msg =
                std::string("record_attestation history write failed: ") + PQerrorMessage(conn);
            return false;
        }

        // The row lock above makes a zero-row UPDATE unreachable through the public API; it is
        // still checked, because a `true` return here would COMMIT the history row just
        // inserted (PgPool::with_txn_for rolls back only on `false`) and the next attest would
        // collide with it on the primary key. The deferred consistency trigger is the database
        // backstop for the same case.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE access_review_store.access_review_attestation "
            "SET decision=$6, reviewer=$7, decided_at_ms=$8::bigint, justification=$9, "
            "    decision_seq=$5::integer "
            "WHERE campaign_id=$1 AND principal_type=$2 AND principal_id=$3 AND role_name=$4 "
            "  AND decision_seq=$10::integer "
            "  AND NOT (principal_type='user' AND principal_id=$7) "
            "  AND EXISTS (SELECT 1 FROM access_review_store.access_review_campaign c "
            "              WHERE c.campaign_id=$1 AND c.status='open') "
            "RETURNING decision_seq",
            std::vector<std::string>{campaign_id, principal_type, principal_id, role_name, new_seq,
                                     decision, reviewer, decided_at, justification,
                                     std::to_string(old_seq)});
        if (upd.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("record_attestation write failed: ") + PQerrorMessage(conn);
            return false;
        }
        if (PQntuples(upd.get()) == 0) {
            spdlog::error("AccessReviewStore: attestation UPDATE matched no row after the locked "
                          "pre-read; rolling back the history row (campaign {})",
                          campaign_id);
            error_msg = "record_attestation write failed: the decision did not advance";
            return false;
        }
        outcome.previous_decision = old_decision;
        outcome.seq = old_seq + 1;
        return true;
    });

    if (!ok) {
        if (not_found)
            return std::unexpected(
                "not_found: no frozen grant matches (campaign_id, principal_type, principal_id, "
                "role_name) in an open campaign");
        return std::unexpected(error_msg.empty()
                                   ? "record_attestation failed: database unavailable or the "
                                     "decision was not committed, try again"
                                   : error_msg);
    }
    return outcome;
}

std::expected<CampaignView, std::string>
AccessReviewStore::get_campaign(const std::string& campaign_id, bool include_history) {
    if (!open_)
        return std::unexpected("database not open");
    if (!valid_campaign_id(campaign_id))
        return std::unexpected("bad_request: campaign_id invalid");

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

        if (include_history) {
            // Same snapshot as the two reads above. Both result sets are ordered by the grant's
            // 4-tuple, so a history row's grant is found by a forward merge, not a search.
            // Each grant returns only its latest kMaxDecisionsPerGrant entries (`seq` greater than
            // the state row's decision_seq minus the cap), so a grant carrying more rows than the
            // write cap allows cannot make this read unbounded. That holds for rows written
            // through the application path; rows added by other means (owner-level SQL with the
            // guard triggers disabled, e.g. a forged pending state row with more history rows
            // above its decision_seq) are outside the guarantee.
            // decision_seq stays the total count, so truncation reads as decision_seq > entries.
            // The LEFT JOIN + COALESCE keep a history row whose state row is missing, so the
            // merge below still reports that corruption instead of the row silently vanishing.
            // A second bound, in kHistoryCols: every entry but the latest returns a justification
            // preview, so entries x grants cannot multiply the 4 KiB stored text.
            std::string hsql =
                std::string("SELECT ") + kHistoryCols +
                " FROM access_review_store.access_review_attestation_history h "
                "LEFT JOIN access_review_store.access_review_attestation a "
                "  ON a.campaign_id = h.campaign_id AND a.principal_type = h.principal_type "
                " AND a.principal_id = h.principal_id AND a.role_name = h.role_name "
                "WHERE h.campaign_id=$1 "
                "  AND h.seq > COALESCE(a.decision_seq, 0) - $2::integer "
                "ORDER BY h.principal_type, h.principal_id, h.role_name, h.seq";
            pg::PgResult hres = pg::exec_params(
                conn, hsql.c_str(),
                std::vector<std::string>{campaign_id, std::to_string(kMaxDecisionsPerGrant),
                                         std::to_string(kHistoryJustificationPreviewChars)});
            if (hres.status() != PGRES_TUPLES_OK) {
                error_msg =
                    std::string("get_campaign history read failed: ") + PQerrorMessage(conn);
                return false;
            }
            const int hrows = PQntuples(hres.get());
            std::size_t at = 0;
            for (int i = 0; i < hrows; ++i) {
                const std::string_view ptype = PQgetvalue(hres.get(), i, 1);
                const std::string_view pid = PQgetvalue(hres.get(), i, 2);
                const std::string_view role = PQgetvalue(hres.get(), i, 3);
                while (at < view.attestations.size() &&
                       !(view.attestations[at].principal_type == ptype &&
                         view.attestations[at].principal_id == pid &&
                         view.attestations[at].role_name == role))
                    ++at;
                if (at == view.attestations.size()) {
                    error_msg = "get_campaign history row has no matching attestation row";
                    return false;
                }
                view.attestations[at].history.push_back(read_history(hres.get(), i));
            }
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
    if (!valid_campaign_id(campaign_id))
        return std::unexpected("bad_request: campaign_id invalid");
    if (closed_by.empty())
        return std::unexpected("closed_by cannot be empty");
    // libpq binds c_str() (pg/pg_exec.hpp): a NUL would truncate the recorded closer.
    if (closed_by.find('\0') != std::string::npos)
        return std::unexpected("bad_request: closed_by contains a NUL byte");

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
