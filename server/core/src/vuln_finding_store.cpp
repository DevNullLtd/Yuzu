#include "vuln_finding_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "vuln_finding_store";

// Bounded acquires (ADR-0012 lease discipline). A reconcile is a background
// engine write; the reads back a user-facing dashboard.
constexpr std::chrono::milliseconds kWriteTimeout{5000};
constexpr std::chrono::milliseconds kReadTimeout{3000};
// Hard cap on findings a single query materialises regardless of the caller's
// limit (a per-agent finding list the page renders).
constexpr int kFindingRowCap = 5000;
// Hard cap on the findings vector a single reconcile batch may carry. A batch
// larger than this holds the per-agent advisory lock + write lease across N
// per-row round-trips, so an unbounded batch is both a lease-hold hazard and a
// producer bug (the expected count is tens). Reject outright. (PR-4 FOLLOW-UP:
// if a genuine batch ever approaches this, switch the upsert loop to a single
// batched `unnest`-driven multi-row INSERT rather than raising the cap — that is
// the real fix, deliberately out of scope for this store-hardening pass.)
constexpr std::size_t kReconcileMaxFindings = 10000;

// Locale-independent double formatting for a float8 text parameter. std::format
// emits '.' as the decimal separator regardless of the process `LC_NUMERIC`
// (std::to_string(double) does NOT — a comma-decimal locale emits "7,5" and PG
// rejects it with 22P02, rolling back the whole reconcile). Mirrors the sibling
// AppPerfDailyStore::fmt_double. Callers MUST pre-check std::isfinite — a NaN/Inf
// would stringify to a "nan"/"inf" token PG cannot parse.
std::string fmt_double(double v) { return std::format("{}", v); }

const std::vector<pg::PgMigration>& migrations_impl() {
    // Unqualified DDL: the runner sets search_path to the store schema for the
    // migration txn. Runtime statements below schema-qualify explicitly.
    //
    // UNITS: every timestamp column is epoch MILLISECONDS (`_ms`).
    // SoftwareInventoryStore is SECONDS — never copy across the boundary.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE finding ("
         "  agent_id         TEXT NOT NULL,"
         "  cve_id           TEXT NOT NULL,"
         "  package_name     TEXT NOT NULL,"
         "  status           TEXT NOT NULL DEFAULT 'potential' "
         "    CHECK (status IN ('potential','vulnerable')),"
         "  package_version  TEXT NOT NULL DEFAULT '',"
         "  ecosystem        TEXT NOT NULL DEFAULT '',"
         "  severity         TEXT NOT NULL DEFAULT 'unknown' "
         "    CHECK (severity IN ('critical','high','medium','low','none','unknown')),"
         "  cvss             DOUBLE PRECISION,"
         "  fixed_in         TEXT,"
         "  confidence       TEXT NOT NULL DEFAULT 'low' "
         "    CHECK (confidence IN ('high','low')),"
         "  feed_synced_at_ms BIGINT NOT NULL DEFAULT 0,"
         "  first_seen_ms    BIGINT NOT NULL,"
         "  last_seen_ms     BIGINT NOT NULL,"
         "  resolved_at_ms   BIGINT,"
         // No CHECK(resolved_at_ms >= first_seen_ms): a clock step-back at reconcile
         // would otherwise reject a legitimate resolve and roll back the whole pass.
         "  PRIMARY KEY (agent_id, cve_id, package_name));"
         // Open findings for one agent (the per-device drill).
         "CREATE INDEX finding_agent_open_idx ON finding (agent_id) "
         "  WHERE resolved_at_ms IS NULL;"
         // Open findings by status+severity (the fleet severity rollup).
         "CREATE INDEX finding_sev_open_idx ON finding (status, severity) "
         "  WHERE resolved_at_ms IS NULL;"
         "CREATE TABLE agent_coverage ("
         "  agent_id          TEXT PRIMARY KEY,"
         "  last_run_at_ms    BIGINT NOT NULL DEFAULT 0,"
         "  feed_synced_at_ms BIGINT NOT NULL DEFAULT 0,"
         "  total_packages    INT NOT NULL DEFAULT 0,"
         "  potential         INT NOT NULL DEFAULT 0,"
         "  vulnerable        INT NOT NULL DEFAULT 0,"
         "  assessed_clean    INT NOT NULL DEFAULT 0,"
         "  not_assessed      INT NOT NULL DEFAULT 0,"
         "  na_no_identity    INT NOT NULL DEFAULT 0,"
         "  na_no_version     INT NOT NULL DEFAULT 0,"
         "  na_absent         INT NOT NULL DEFAULT 0,"
         "  na_os_native      INT NOT NULL DEFAULT 0,"
         "  na_low_confidence INT NOT NULL DEFAULT 0);"},
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
int to_int(const char* s) { return static_cast<int>(to_i64(s)); }

// Normalize a severity to the CHECK vocab: lowercased, and anything outside the
// set collapses to "unknown" (severity is normalized-not-rejected, unlike status
// / confidence which are bound as-is and rely on the column CHECK). Mirrors the
// finding.severity CHECK exactly.
// Trim leading/trailing ASCII whitespace and lowercase. Shared by severity
// normalization (write + filter) and the status filter so a mixed-case /
// whitespace-padded filter matches the canonically-stored value.
std::string lower_trim(std::string_view s) {
    auto is_ws = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && is_ws(static_cast<unsigned char>(s.front())))
        s.remove_prefix(1);
    while (!s.empty() && is_ws(static_cast<unsigned char>(s.back())))
        s.remove_suffix(1);
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

std::string normalize_severity(std::string_view sev) {
    // Trim leading/trailing ASCII whitespace first so incidental feed whitespace
    // ("high ", " critical") does not collapse a real severity to "unknown". We
    // deliberately trim ONLY whitespace — arbitrary punctuation ("Critical!")
    // still legitimately falls outside the vocab and becomes "unknown".
    std::string s = lower_trim(sev);
    static constexpr std::array<std::string_view, 6> kVocab = {
        "critical", "high", "medium", "low", "none", "unknown"};
    for (auto v : kVocab)
        if (s == v)
            return s;
    return "unknown";
}

// A severity CASE-rank for ORDER BY so critical sorts first (a plain
// `ORDER BY severity` would sort alphabetically — critical, high, low, medium...
// — putting 'low' above 'medium'). Kept in one place; both order clauses reuse it.
constexpr const char* kSeverityRankSql =
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 3 WHEN 'none' THEN 4 ELSE 5 END";

// text-format column → optional<double>; nullopt when the cell is SQL NULL.
std::optional<double> get_opt_double(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return std::nullopt;
    const char* s = PQgetvalue(res, row, col);
    return (s != nullptr) ? std::optional<double>{std::strtod(s, nullptr)} : std::nullopt;
}

// text-format column → optional<int64>; nullopt when the cell is SQL NULL.
std::optional<std::int64_t> get_opt_i64(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return std::nullopt;
    return to_i64(PQgetvalue(res, row, col));
}

// text-format column → optional<string>; nullopt when the cell is SQL NULL.
std::optional<std::string> get_opt_text(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return std::nullopt;
    return std::optional<std::string>{PQgetvalue(res, row, col)};
}

constexpr const char* kFindingCols =
    "agent_id, cve_id, package_name, status, package_version, ecosystem, severity, "
    "cvss, fixed_in, confidence, feed_synced_at_ms, first_seen_ms, last_seen_ms, resolved_at_ms";

FindingRow read_finding(PGresult* res, int i) {
    FindingRow r;
    int c = 0;
    r.agent_id = PQgetvalue(res, i, c++);
    r.cve_id = PQgetvalue(res, i, c++);
    r.package_name = PQgetvalue(res, i, c++);
    r.status = PQgetvalue(res, i, c++);
    r.package_version = PQgetvalue(res, i, c++);
    r.ecosystem = PQgetvalue(res, i, c++);
    r.severity = PQgetvalue(res, i, c++);
    r.cvss = get_opt_double(res, i, c++);
    r.fixed_in = get_opt_text(res, i, c++);
    r.confidence = PQgetvalue(res, i, c++);
    r.feed_synced_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.first_seen_ms = to_i64(PQgetvalue(res, i, c++));
    r.last_seen_ms = to_i64(PQgetvalue(res, i, c++));
    r.resolved_at_ms = get_opt_i64(res, i, c++);
    return r;
}

} // namespace

const std::vector<pg::PgMigration>& VulnFindingStore::migrations() { return migrations_impl(); }

VulnFindingStore::VulnFindingStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("VulnFindingStore: no database connection at construction ({}) — "
                      "vulnerability finding persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations_impl())) {
        spdlog::error("VulnFindingStore: schema migration failed — vulnerability finding "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

bool VulnFindingStore::reconcile_agent(const AgentReconcile& r) {
    if (!open_ || r.agent_id.empty())
        return false;
    const std::string agent_id = r.agent_id;

    // (FIX 5) Bound the batch. An unbounded findings vector holds the per-agent
    // advisory lock + write lease across findings.size() per-row round-trips; a
    // batch this large is a PR-4 producer bug, not a legitimate host. Reject it
    // outright rather than lease-starve the pool.
    if (r.findings.size() > kReconcileMaxFindings) {
        spdlog::error("VulnFindingStore::reconcile_agent: batch of {} findings for agent '{}' "
                      "exceeds cap {} — rejecting (producer bug)",
                      r.findings.size(), agent_id, kReconcileMaxFindings);
        return false;
    }

    // (FIX 4) Reject an embedded NUL in any identity field. exec_params binds
    // each value as a NUL-terminated C string (no explicit length), so a NUL
    // silently truncates the value at libpq — which could collide two distinct
    // identities onto one PK row. The PR-4 producer sanitizes, but the store now
    // also rejects rather than trusts (defence-in-depth boundary check).
    auto has_nul = [](std::string_view s) { return s.find('\0') != std::string_view::npos; };
    if (has_nul(agent_id))
        return false;
    for (const auto& f : r.findings)
        if (has_nul(f.cve_id) || has_nul(f.package_name))
            return false;

    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // (0) Self-protecting per-agent serialization. PR-4 single-flight does
        // not exist yet, so the store protects itself: two overlapping passes for
        // one agent under READ COMMITTED could otherwise interleave (one pass's
        // sweep resolving a row the other just inserted). Transaction-scoped —
        // released at COMMIT/ROLLBACK; distinct agents hash to distinct keys so
        // steady-state contention is nil.
        //
        // CROSS-STORE NAMESPACE (do not remove the prefix): pg_advisory_xact_lock
        // keys are a SINGLE cluster-wide 64-bit space, NOT scoped per schema. The
        // sibling SoftwareInventoryStore full-replace path locks
        // hashtextextended('software_inventory_store:' || agent_id, 0), the same per-store prefix
        // this store uses (it was the bare agent id until a valid agent id collided with a
        // fixed-string job key, #6965). A bare
        // hashtextextended(agent_id, 0) here would collide with it on the same
        // agent_id, so a slow inventory ingest for agent X would needlessly block a
        // vuln reconcile for X (and vice versa) past this txn's timeout even though
        // the two touch disjoint tables. The 'vuln_finding_store:' key prefix folds
        // a per-store namespace into the hash so the key is disjoint from
        // software_inventory's — while two vuln reconciles for the SAME agent still
        // hash identically and serialize (same formula, same agent_id).
        {
            pg::PgResult lk = pg::exec_params(
                conn,
                "SELECT pg_advisory_xact_lock(hashtextextended('vuln_finding_store:' || $1, 0))",
                std::vector<std::string>{agent_id});
            if (lk.status() != PGRES_TUPLES_OK)
                return false;
        }

        // (1) Derive a MONOTONIC run_ts in-txn (NTP-step-back safe): one greater
        // than the stored last_run_at_ms if the wall clock has not advanced past
        // it. This keeps first_seen/last_seen/resolved_at strictly ordered even
        // across a backwards clock step (test S4).
        std::int64_t last_run = 0;
        // Prior coverage tallies — also drive the UP-2 mass-resolve backstop below.
        std::int64_t prior_potential = 0;
        std::int64_t prior_vulnerable = 0;
        std::int64_t prior_total_packages = 0;
        {
            pg::PgResult lr = pg::exec_params(
                conn,
                "SELECT last_run_at_ms, potential, vulnerable, total_packages "
                "FROM vuln_finding_store.agent_coverage WHERE agent_id = $1",
                std::vector<std::string>{agent_id});
            if (lr.status() != PGRES_TUPLES_OK)
                return false;
            if (PQntuples(lr.get()) == 1) {
                last_run = to_i64(PQgetvalue(lr.get(), 0, 0));
                prior_potential = to_i64(PQgetvalue(lr.get(), 0, 1));
                prior_vulnerable = to_i64(PQgetvalue(lr.get(), 0, 2));
                prior_total_packages = to_i64(PQgetvalue(lr.get(), 0, 3));
            }
        }
        const std::int64_t run_ts = std::max(now_ms(), last_run + 1);
        const std::string run_ts_s = std::to_string(run_ts);

        // (2) Upsert every finding ALWAYS (observed rows are refreshed whether or
        // not the pass is authoritative). first_seen_ms is insert-only (NOT in the
        // DO UPDATE SET); last_seen_ms and resolved_at_ms are reset on every touch.
        // A per-row failure (e.g. a CHECK violation on a bad status/confidence)
        // returns false → the whole txn rolls back (no partial write).
        for (const auto& f : r.findings) {
            std::vector<std::optional<std::string>> params{
                agent_id,
                f.cve_id,
                f.package_name,
                f.status, // bound as-is: an out-of-vocab value trips the CHECK → rollback
                f.package_version,
                f.ecosystem,
                normalize_severity(f.severity), // severity IS normalized to the vocab
                // cvss: locale-independent format AND finite-guarded. A
                // non-finite value (NaN/Inf from a bad PR-4 feed row) binds SQL
                // NULL rather than a "nan"/"inf" token that would 22P02 and abort
                // the whole reconcile — cvss is optional, so absence is honest.
                (f.cvss && std::isfinite(*f.cvss))
                    ? std::optional<std::string>{fmt_double(*f.cvss)}
                    : std::nullopt,
                f.fixed_in, // already optional → SQL NULL when absent
                f.confidence, // bound as-is → CHECK-enforced
                std::to_string(f.feed_synced_at_ms),
                run_ts_s};
            pg::PgResult up = pg::exec_params(
                conn,
                "INSERT INTO vuln_finding_store.finding "
                "(agent_id, cve_id, package_name, status, package_version, ecosystem, severity, "
                " cvss, fixed_in, confidence, feed_synced_at_ms, first_seen_ms, last_seen_ms, "
                " resolved_at_ms) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::double precision,$9,$10,$11::bigint,"
                "        $12::bigint,$12::bigint,NULL) "
                "ON CONFLICT (agent_id, cve_id, package_name) DO UPDATE SET "
                "  status = EXCLUDED.status, package_version = EXCLUDED.package_version, "
                "  ecosystem = EXCLUDED.ecosystem, severity = EXCLUDED.severity, "
                "  cvss = EXCLUDED.cvss, fixed_in = EXCLUDED.fixed_in, "
                "  confidence = EXCLUDED.confidence, feed_synced_at_ms = EXCLUDED.feed_synced_at_ms, "
                "  last_seen_ms = EXCLUDED.last_seen_ms, resolved_at_ms = NULL",
                params);
            if (up.status() != PGRES_COMMAND_OK && up.status() != PGRES_TUPLES_OK)
                return false;
        }

        // (FIX 3, UP-2 backstop) Defence-in-depth against a mis-set authoritative
        // flag mass-false-resolving an agent. The TRUE suspect signal is a
        // ZERO-total_packages coverage (`r.coverage.total_packages == 0`): the
        // inventory read itself returned nothing, so there is no basis to resolve
        // anything. When that lands against an agent that PREVIOUSLY had state
        // (prior open findings OR a non-zero prior package count), it is almost
        // certainly a "whole inventory vanished" bad read from a PR-4 producer bug.
        // Treat it like a non-authoritative pass: SKIP the sweep + dispose +
        // coverage clobber (keep-last-good), still return true.
        //
        // CRITICAL — do NOT key this on `findings.empty()`: an authoritative pass
        // with total_packages > 0 but empty findings is a GENUINELY-PATCHED agent
        // (inventory still present, all vulns fixed) and MUST sweep-resolve the
        // now-fixed findings. Suppressing that would leave patched findings open
        // forever (a false-positive worse than the bug this guards).
        const bool authoritative_effective =
            r.authoritative &&
            !(r.coverage.total_packages == 0 &&
              (prior_potential + prior_vulnerable > 0 || prior_total_packages > 0));
        if (r.authoritative && !authoritative_effective) {
            spdlog::warn("VulnFindingStore::reconcile_agent: authoritative pass for agent '{}' "
                         "reported zero total_packages while prior state existed (open={}, "
                         "prior_total_packages={}) — treating as non-authoritative to avoid a "
                         "mass false-resolve (suspected inventory-read failure / producer bug)",
                         agent_id, prior_potential + prior_vulnerable, prior_total_packages);
        }

        // Steps (3)–(5) are AUTHORITATIVE-ONLY. A non-authoritative (suspect /
        // partial) pass refreshes observed findings only: NO dispose, NO resolve
        // sweep, NO coverage clobber (keep-last-good — the B1 fix).
        if (authoritative_effective) {
            // (3) OVAL-reassessed-clean fold: delete the disposed tuples outright
            // (a definitively-clean reassessment removes the row rather than
            // resolving it). Empty in M1a.
            if (!r.disposed_clean.empty()) {
                std::vector<std::string_view> cves, pkgs;
                cves.reserve(r.disposed_clean.size());
                pkgs.reserve(r.disposed_clean.size());
                for (const auto& k : r.disposed_clean) {
                    cves.emplace_back(k.cve_id);
                    pkgs.emplace_back(k.package_name);
                }
                pg::PgResult del = pg::exec_params(
                    conn,
                    "DELETE FROM vuln_finding_store.finding "
                    "WHERE agent_id = $1 AND (cve_id, package_name) IN "
                    "  (SELECT c, p FROM unnest($2::text[], $3::text[]) AS t(c, p))",
                    std::vector<std::string>{agent_id, pg::to_text_array(cves),
                                             pg::to_text_array(pkgs)});
                if (del.status() != PGRES_COMMAND_OK && del.status() != PGRES_TUPLES_OK)
                    return false;
            }

            // (4) Disappear sweep: every still-open finding not touched this pass
            // (last_seen_ms < run_ts) is resolved at run_ts. Because run_ts is
            // strictly greater than any last_seen_ms stamped in step (2), a row
            // just re-observed this pass is NEVER swept.
            pg::PgResult sweep = pg::exec_params(
                conn,
                "UPDATE vuln_finding_store.finding SET resolved_at_ms = $2::bigint "
                "WHERE agent_id = $1 AND last_seen_ms < $2::bigint AND resolved_at_ms IS NULL",
                std::vector<std::string>{agent_id, run_ts_s});
            if (sweep.status() != PGRES_COMMAND_OK && sweep.status() != PGRES_TUPLES_OK)
                return false;

            // (5) Coverage upsert: the counters are ground truth this pass;
            // last_run_at_ms = run_ts.
            const auto& cov = r.coverage;
            pg::PgResult cu = pg::exec_params(
                conn,
                "INSERT INTO vuln_finding_store.agent_coverage "
                "(agent_id, last_run_at_ms, feed_synced_at_ms, total_packages, potential, "
                " vulnerable, assessed_clean, not_assessed, na_no_identity, na_no_version, "
                " na_absent, na_os_native, na_low_confidence) "
                "VALUES ($1,$2::bigint,$3::bigint,$4::int,$5::int,$6::int,$7::int,$8::int,"
                "        $9::int,$10::int,$11::int,$12::int,$13::int) "
                "ON CONFLICT (agent_id) DO UPDATE SET "
                "  last_run_at_ms = EXCLUDED.last_run_at_ms, "
                "  feed_synced_at_ms = EXCLUDED.feed_synced_at_ms, "
                "  total_packages = EXCLUDED.total_packages, potential = EXCLUDED.potential, "
                "  vulnerable = EXCLUDED.vulnerable, assessed_clean = EXCLUDED.assessed_clean, "
                "  not_assessed = EXCLUDED.not_assessed, na_no_identity = EXCLUDED.na_no_identity, "
                "  na_no_version = EXCLUDED.na_no_version, na_absent = EXCLUDED.na_absent, "
                "  na_os_native = EXCLUDED.na_os_native, na_low_confidence = EXCLUDED.na_low_confidence",
                std::vector<std::string>{agent_id, run_ts_s, std::to_string(cov.feed_synced_at_ms),
                                         std::to_string(cov.total_packages),
                                         std::to_string(cov.potential),
                                         std::to_string(cov.vulnerable),
                                         std::to_string(cov.assessed_clean),
                                         std::to_string(cov.not_assessed),
                                         std::to_string(cov.na_no_identity),
                                         std::to_string(cov.na_no_version),
                                         std::to_string(cov.na_absent),
                                         std::to_string(cov.na_os_native),
                                         std::to_string(cov.na_low_confidence)});
            if (cu.status() != PGRES_COMMAND_OK && cu.status() != PGRES_TUPLES_OK)
                return false;
        }
        return true;
    });
}

std::vector<FindingRow> VulnFindingStore::query_findings(std::string_view agent_id,
                                                         const FindingQuery& q) {
    std::vector<FindingRow> out;
    if (!open_ || agent_id.empty())
        return out; // list-read shape: empty for degrade AND no-rows
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;

    int limit = (q.limit > 0 && q.limit < kFindingRowCap) ? q.limit : kFindingRowCap;

    std::string sql =
        std::string("SELECT ") + kFindingCols + " FROM vuln_finding_store.finding WHERE agent_id = $1";
    std::vector<std::string> params{std::string(agent_id)};
    int p = 1;
    if (!q.include_resolved)
        sql += " AND resolved_at_ms IS NULL";
    // Normalize the filter values to the canonical stored form (lowercased +
    // trimmed) so a mixed-case filter ("Critical", "HIGH", "Potential") matches —
    // severity is normalize_severity()d on write, and status is stored lowercase
    // (CHECK vocab). Without this a "Critical" filter silently returns empty.
    if (q.status && !q.status->empty()) {
        sql += " AND status = $" + std::to_string(++p);
        params.push_back(lower_trim(*q.status));
    }
    if (q.severity && !q.severity->empty()) {
        sql += " AND severity = $" + std::to_string(++p);
        params.push_back(normalize_severity(*q.severity));
    }
    sql += " ORDER BY " + std::string(kSeverityRankSql) + ", last_seen_ms DESC LIMIT $" +
           std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(read_finding(res.get(), i));
    return out;
}

CoverageRead VulnFindingStore::get_agent_coverage(std::string_view agent_id) {
    // AUTHORITATIVE three-way read: a store/pool/query degrade is Degraded,
    // distinct from a never-correlated agent (NotFound).
    CoverageRead r; // defaults to Degraded
    if (!open_ || agent_id.empty())
        return r; // !open_ / precondition-miss both surface as Degraded (no false NotFound)
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return r;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, last_run_at_ms, feed_synced_at_ms, total_packages, potential, "
        "vulnerable, assessed_clean, not_assessed, na_no_identity, na_no_version, na_absent, "
        "na_os_native, na_low_confidence "
        "FROM vuln_finding_store.agent_coverage WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return r; // Degraded
    if (PQntuples(res.get()) == 0) {
        r.status = CoverageRead::Status::NotFound;
        return r;
    }
    AgentCoverage c;
    int col = 0;
    c.agent_id = PQgetvalue(res.get(), 0, col++);
    c.last_run_at_ms = to_i64(PQgetvalue(res.get(), 0, col++));
    c.feed_synced_at_ms = to_i64(PQgetvalue(res.get(), 0, col++));
    c.total_packages = to_int(PQgetvalue(res.get(), 0, col++));
    c.potential = to_int(PQgetvalue(res.get(), 0, col++));
    c.vulnerable = to_int(PQgetvalue(res.get(), 0, col++));
    c.assessed_clean = to_int(PQgetvalue(res.get(), 0, col++));
    c.not_assessed = to_int(PQgetvalue(res.get(), 0, col++));
    c.na_no_identity = to_int(PQgetvalue(res.get(), 0, col++));
    c.na_no_version = to_int(PQgetvalue(res.get(), 0, col++));
    c.na_absent = to_int(PQgetvalue(res.get(), 0, col++));
    c.na_os_native = to_int(PQgetvalue(res.get(), 0, col++));
    c.na_low_confidence = to_int(PQgetvalue(res.get(), 0, col++));
    r.status = CoverageRead::Status::Ok;
    r.row = std::move(c);
    return r;
}

std::optional<FleetVulnSummary> VulnFindingStore::fleet_summary() {
    // AUTHORITATIVE: nullopt on any store/pool/query degrade, NEVER a silent zero.
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    FleetVulnSummary s;
    // (a) coverage aggregate.
    {
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT count(*), COALESCE(sum(total_packages),0), COALESCE(sum(potential),0), "
            "COALESCE(sum(vulnerable),0), COALESCE(sum(assessed_clean),0), "
            "COALESCE(sum(not_assessed),0) FROM vuln_finding_store.agent_coverage",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return std::nullopt;
        s.agent_count = to_i64(PQgetvalue(res.get(), 0, 0));
        s.total_packages = to_i64(PQgetvalue(res.get(), 0, 1));
        s.potential_packages = to_i64(PQgetvalue(res.get(), 0, 2));
        s.vulnerable_packages = to_i64(PQgetvalue(res.get(), 0, 3));
        s.assessed_clean = to_i64(PQgetvalue(res.get(), 0, 4));
        s.not_assessed = to_i64(PQgetvalue(res.get(), 0, 5));
    }
    // (b) open-finding counts (total + critical + high), excluding resolved rows.
    {
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT count(*), "
            "count(*) FILTER (WHERE severity = 'critical'), "
            "count(*) FILTER (WHERE severity = 'high') "
            "FROM vuln_finding_store.finding WHERE resolved_at_ms IS NULL",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return std::nullopt;
        s.open_findings = to_i64(PQgetvalue(res.get(), 0, 0));
        s.critical_open = to_i64(PQgetvalue(res.get(), 0, 1));
        s.high_open = to_i64(PQgetvalue(res.get(), 0, 2));
    }
    return s;
}

void VulnFindingStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return;
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a coverage
    // row without its findings, or vice versa.
    pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult d1 =
            pg::exec_params(c, "DELETE FROM vuln_finding_store.finding WHERE agent_id = $1",
                            std::vector<std::string>{id});
        pg::PgResult d2 =
            pg::exec_params(c, "DELETE FROM vuln_finding_store.agent_coverage WHERE agent_id = $1",
                            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
}

} // namespace yuzu::server
