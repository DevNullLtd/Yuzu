#include "software_licensing_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_licensing_store";

// Bounded acquires (ADR-0012 lease discipline). The ingest-path methods
// (stored_hash / touch / replace_agent_licenses / delete_agent) run on the
// gRPC thread (direct ReportInventory / gateway ProxyInventory) so they give
// up fast on a saturated pool — best-effort, the agent retries next cycle.
// Reads + the evaluator's posture/alert writes can wait a little longer.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// The staleness count may run on a shared serial sweep (the sibling's
// metrics-sweep lesson, CH-IN3/UP-2): a SHORT acquire plus a per-statement
// execution cap so it can never stall that thread.
constexpr std::chrono::milliseconds kStaleCountAcquireTimeout{250};
// Hard ceilings on rows a single read will materialise, independent of any
// caller limit, so the store can never allocate an unbounded result set. The
// per-agent set is capped upstream by the R5 blob caps (≤ 10 000 records);
// the fleet-distinct and posture sets are one row per product — bounded.
constexpr int kAgentRowCap = 20000;
constexpr int kDistinctRowCap = 20000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in
    // `software_licensing_store`. Runtime statements below schema-qualify
    // explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Per-agent sync parent (roadmap §7.2). content_hash is the RAW
         // received blob bytes' SHA-256, recomputed by the ingest seam and
         // persisted VERBATIM (ADR-0024 Decision 3 / roadmap D-2 — never
         // re-derived from parsed rows). effective_user_ref_mode is the
         // blob's config-stable `cfg|user_ref` record (roadmap D-10).
         // first_seen/last_seen are the SERVER receipt time (#1685 /
         // ADR-0016 clock-skew rule) — the C-10 staleness read keys on
         // last_seen, served by the index below.
         "CREATE TABLE agent_license_state ("
         "  agent_id                TEXT PRIMARY KEY,"
         "  content_hash            TEXT NOT NULL DEFAULT '',"
         "  effective_user_ref_mode TEXT NOT NULL DEFAULT '',"
         "  first_seen              BIGINT NOT NULL,"
         "  last_seen               BIGINT NOT NULL);"
         "CREATE INDEX agent_license_state_lastseen_idx ON agent_license_state (last_seen);"
         // Detected licence rows, replaced wholesale per agent on each stored
         // sync. Same-schema FK ON DELETE CASCADE onto the parent (cross-
         // schema FKs are banned — ADR-0024 Decision 4; within one store they
         // are the normal tool). confidence and exe_hints ship in migration
         // v1: hash-skip means a column added later would stay empty forever
         // on stable estates — confidence is how operators weight heuristic
         // rows (ADR-0024 Decisions 1/2/7); exe_hints is the R6 product↔exe
         // bridge. expiry_at is the agent-observed epoch (0 =
         // none); the partial index serves the evaluator's expiry sweep
         // without indexing the expiry-less majority.
         "CREATE TABLE agent_licenses ("
         "  id           BIGSERIAL PRIMARY KEY,"
         "  agent_id     TEXT NOT NULL REFERENCES agent_license_state (agent_id) ON DELETE CASCADE,"
         "  product      TEXT NOT NULL DEFAULT '',"
         "  vendor       TEXT NOT NULL DEFAULT '',"
         "  version      TEXT NOT NULL DEFAULT '',"
         "  license_type TEXT NOT NULL DEFAULT '',"
         "  state        TEXT NOT NULL DEFAULT '',"
         "  expiry_at    BIGINT NOT NULL DEFAULT 0,"
         "  channel      TEXT NOT NULL DEFAULT '',"
         "  key_hint     TEXT NOT NULL DEFAULT '',"
         "  detector     TEXT NOT NULL DEFAULT '',"
         "  confidence   TEXT NOT NULL DEFAULT '',"
         "  exe_hints    TEXT NOT NULL DEFAULT '',"
         "  user_scope   TEXT NOT NULL DEFAULT '',"
         "  user_ref     TEXT NOT NULL DEFAULT '',"
         "  collected_at BIGINT NOT NULL DEFAULT 0,"
         "  first_seen   BIGINT NOT NULL,"
         "  last_seen    BIGINT NOT NULL);"
         "CREATE INDEX agent_licenses_agent_idx  ON agent_licenses (agent_id);"
         "CREATE INDEX agent_licenses_state_idx  ON agent_licenses (state);"
         "CREATE INDEX agent_licenses_expiry_idx ON agent_licenses (expiry_at) "
         "WHERE expiry_at > 0;"
         // NB: the evaluator's posture-rollup (license_posture_rollup) and
         // alert-dedup (license_alert_state) tables are NOT created here — per
         // ADR-0024 "Placement under ADR-1005" the compliance evaluator and its
         // posture/alert state are the SAM use-case-engine module's, in the
         // module's own database, not in-server (store ownership follows the
         // layer, ADR-1005). The in-server store is raw discovery only.
         },
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Read-degrade observability (#1675 convention) ────────────────────────────
// Reason labels + sampled-WARN machinery mirror SoftwareInventoryStore /
// DeviceInventoryStore (a further per-store copy is the convention). The
// counter joins the SHARED read-degrade family with the wire-source label so
// the existing YuzuInventoryReadDegraded alert covers this source too.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", "software_licensing"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

// Parse a Postgres text-format integer cell into int64 (BIGINT columns and
// count(*) are text on the wire). Leaves 0 on a parse failure.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v);
    return v;
}

// Shared SELECT column list for agent_licenses reads, order matched by
// fill_license_row (id/agent_id are query keys, not row fields).
constexpr const char* kLicenseCols =
    "product, vendor, version, license_type, state, expiry_at, channel, key_hint, "
    "detector, confidence, exe_hints, user_scope, user_ref, collected_at, first_seen, last_seen";

void fill_license_row(const pg::PgResult& res, int row, AgentLicenseRow& out) {
    out.product = PQgetvalue(res.get(), row, 0);
    out.vendor = PQgetvalue(res.get(), row, 1);
    out.version = PQgetvalue(res.get(), row, 2);
    out.license_type = PQgetvalue(res.get(), row, 3);
    out.state = PQgetvalue(res.get(), row, 4);
    out.expiry_at = result_i64(res, row, 5);
    out.channel = PQgetvalue(res.get(), row, 6);
    out.key_hint = PQgetvalue(res.get(), row, 7);
    out.detector = PQgetvalue(res.get(), row, 8);
    out.confidence = PQgetvalue(res.get(), row, 9);
    out.exe_hints = PQgetvalue(res.get(), row, 10);
    out.user_scope = PQgetvalue(res.get(), row, 11);
    out.user_ref = PQgetvalue(res.get(), row, 12);
    out.collected_at = result_i64(res, row, 13);
    out.first_seen = result_i64(res, row, 14);
    out.last_seen = result_i64(res, row, 15);
}


} // namespace

SoftwareLicensingStore::SoftwareLicensingStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareLicensingStore: no database connection at construction ({}) — "
                      "software licensing persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareLicensingStore: schema migration failed — software licensing "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

std::expected<std::optional<std::string>, LicensingReadError>
SoftwareLicensingStore::stored_hash(std::string_view agent_id) {
    // Ingest-path helper (the seam's hash-skip compare): a degrade maps to
    // kError at the seam, so plain warn logging suffices here (the sibling
    // hash-only precedent) — the samplers guard the fan-out read surfaces.
    if (!open_ || agent_id.empty())
        return std::unexpected(LicensingReadError::kDegraded);
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("SoftwareLicensingStore: stored_hash skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return std::unexpected(LicensingReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT content_hash FROM software_licensing_store.agent_license_state "
        "WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("SoftwareLicensingStore: stored_hash failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{}; // cold cache → the seam answers need_full
    return std::optional<std::string>{PQgetvalue(res.get(), 0, 0)};
}

bool SoftwareLicensingStore::touch(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("SoftwareLicensingStore: touch skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return false;
    }
    // last_seen is the SERVER receipt time (#1685) — never an agent-supplied
    // stamp. RETURNING carries the row-hit result (#1033): zero tuples = the
    // state row is missing (a touch on a cold cache is a caller sequencing
    // bug; the seam should have answered need_full off stored_hash).
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE software_licensing_store.agent_license_state SET last_seen = $2::bigint "
        "WHERE agent_id = $1 RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), std::to_string(now_secs())});
    if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) != 1) {
        spdlog::warn("SoftwareLicensingStore: touch failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

bool SoftwareLicensingStore::replace_agent_licenses(std::string_view agent_id,
                                                    const std::vector<AgentLicenseRow>& rows,
                                                    std::string_view content_hash,
                                                    std::string_view effective_user_ref_mode) {
    if (!open_ || agent_id.empty())
        return false;
    // first_seen/last_seen are the SERVER receipt time on the state row AND
    // the child rows (#1685); the agent's collected_at is persisted as data,
    // never as a freshness stamp.
    const std::int64_t ts = now_secs();
    const std::string agent_id_s{agent_id};

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full-replaces for THIS agent (the software-
        // inventory UP-IN2/3 lesson): two in-flight fulls under READ COMMITTED
        // interleave (B's DELETE cannot see A's fresh rows) and both row sets
        // survive with a parent hash matching neither. Blocking (not try_) on
        // purpose — the loser waits, then does its own clean replace; bounded
        // by the pool's statement_timeout. The key is salted with the store
        // name so a same-agent replace in ANOTHER store's tables never
        // contends (advisory lock keys are database-wide, not schema-scoped).
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('software_licensing:' || $1, 0))",
            std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        // Parent upsert FIRST (the children's FK targets it): persist the
        // seam-recomputed raw-blob hash VERBATIM + the effective user-ref
        // mode; keep first_seen on conflict, refresh the rest.
        pg::PgResult par = pg::exec_params(
            c,
            "INSERT INTO software_licensing_store.agent_license_state "
            "(agent_id, content_hash, effective_user_ref_mode, first_seen, last_seen) "
            "VALUES ($1, $2, $3, $4::bigint, $4::bigint) "
            "ON CONFLICT (agent_id) DO UPDATE SET "
            "  content_hash = EXCLUDED.content_hash, "
            "  effective_user_ref_mode = EXCLUDED.effective_user_ref_mode, "
            "  last_seen = EXCLUDED.last_seen "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id_s, std::string(content_hash),
                                     std::string(effective_user_ref_mode), std::to_string(ts)});
        if (par.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_licenses WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        // Batched insert (#1664 pattern): one statement, per-row columns as
        // parallel arrays, so the parameter count is a constant 16 regardless
        // of row count (up to the R5 10k-record cap arrives here). Skip when
        // empty — a legitimate replace-to-empty; the DELETE above cleared the
        // rows.
        if (!rows.empty()) {
            // 12 text columns as string_view arrays over the caller's rows;
            // the 2 BIGINT columns need owned decimal strings first.
            std::vector<std::string_view> text_cols[12];
            for (auto& col : text_cols)
                col.reserve(rows.size());
            std::vector<std::string> expiry_strs;
            std::vector<std::string> collected_strs;
            expiry_strs.reserve(rows.size());
            collected_strs.reserve(rows.size());
            for (const auto& r : rows) {
                text_cols[0].emplace_back(r.product);
                text_cols[1].emplace_back(r.vendor);
                text_cols[2].emplace_back(r.version);
                text_cols[3].emplace_back(r.license_type);
                text_cols[4].emplace_back(r.state);
                text_cols[5].emplace_back(r.channel);
                text_cols[6].emplace_back(r.key_hint);
                text_cols[7].emplace_back(r.detector);
                text_cols[8].emplace_back(r.confidence);
                text_cols[9].emplace_back(r.exe_hints);
                text_cols[10].emplace_back(r.user_scope);
                text_cols[11].emplace_back(r.user_ref);
                expiry_strs.push_back(std::to_string(r.expiry_at));
                collected_strs.push_back(std::to_string(r.collected_at));
            }
            std::vector<std::string_view> expiry_views(expiry_strs.begin(), expiry_strs.end());
            std::vector<std::string_view> collected_views(collected_strs.begin(),
                                                          collected_strs.end());
            // push_back (not a braced init-list) so each to_text_array prvalue
            // is MOVED into params (the sibling's cpp-expert note). Constant
            // 16 params: $1 agent_id, $2 receipt time, $3..$16 arrays.
            std::vector<std::string> params;
            params.reserve(16);
            params.push_back(agent_id_s);
            params.push_back(std::to_string(ts));
            for (const auto& col : text_cols)
                params.push_back(pg::to_text_array(col));
            params.push_back(pg::to_text_array(expiry_views));
            params.push_back(pg::to_text_array(collected_views));
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO software_licensing_store.agent_licenses "
                "(agent_id, product, vendor, version, license_type, state, channel, key_hint, "
                "detector, confidence, exe_hints, user_scope, user_ref, expiry_at, collected_at, "
                "first_seen, last_seen) "
                "SELECT $1, p, v, ver, lt, st, ch, kh, det, conf, eh, us, ur, ex, ca, "
                "$2::bigint, $2::bigint "
                "FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], "
                "$8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], "
                "$14::text[], $15::bigint[], $16::bigint[]) "
                "AS t(p, v, ver, lt, st, ch, kh, det, conf, eh, us, ur, ex, ca)",
                params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });
    if (!ok)
        spdlog::warn("SoftwareLicensingStore: replace transaction failed for agent={}", agent_id);
    return ok;
}

std::optional<std::vector<AgentLicenseRow>>
SoftwareLicensingStore::agent_licenses(std::string_view agent_id) {
    // AUTHORITATIVE read (ADR-0024 Decision 4): a degrade returns nullopt,
    // never a silent empty — an empty licence drill on a degrade would read as
    // "nothing detected". An empty agent_id is a precondition miss → empty
    // value.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AgentLicenseRow> out;
    if (agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kLicenseCols +
                            " FROM software_licensing_store.agent_licenses "
                            "WHERE agent_id = $1 ORDER BY product, vendor, version, id "
                            "LIMIT $2::bigint";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::string(agent_id), std::to_string(kAgentRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AgentLicenseRow r;
        fill_license_row(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::vector<DetectedProduct>> SoftwareLicensingStore::distinct_products() {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT product, vendor FROM software_licensing_store.agent_licenses "
        "ORDER BY product, vendor LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(kDistinctRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    std::vector<DetectedProduct> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        DetectedProduct p;
        p.product = PQgetvalue(res.get(), i, 0);
        p.vendor = PQgetvalue(res.get(), i, 1);
        out.push_back(std::move(p));
    }
    return out;
}

bool SoftwareLicensingStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a parent
    // state row without its child rows or vice versa (the sibling's Gate-2
    // rationale). The child DELETE is explicit even though the FK cascades —
    // the intent stays visible and survives an FK refactor. The commit result is
    // RETURNED to the caller (the decommission cascade), which logs and records a
    // false as Failed — a rolled-back erasure is never reported as a completed
    // Art.17 delete; the next decommission pass self-heals.
    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Take the SAME per-agent advisory lock replace_agent_licenses holds,
        // with the IDENTICAL key derivation ('software_licensing:' || agent_id).
        // Without it a decommission and an in-flight full-replace ingest for THIS
        // agent interleave under READ COMMITTED: the ingest's INSERT can land
        // AFTER the delete's DELETE, resurrecting the just-erased user_ref PII and
        // breaking the ADR-0024 Decision-11 erasure guarantee. Serialising the two
        // on this lock closes that race — the loser waits, then runs cleanly.
        // Blocking (not try_) on purpose, bounded by the pool's lock_timeout.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('software_licensing:' || $1, 0))",
            std::vector<std::string>{id});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult d1 = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_licenses WHERE agent_id = $1",
            std::vector<std::string>{id});
        pg::PgResult d2 = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_license_state WHERE agent_id = $1",
            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
    if (!committed)
        spdlog::debug("SoftwareLicensingStore: delete_agent did not commit for agent={} ({})",
                      agent_id, pool_.last_error());
    return committed;
}

std::optional<std::int64_t>
SoftwareLicensingStore::count_stale_agents(std::int64_t stale_before_secs) {
    if (!open_)
        return std::nullopt;
    std::optional<std::int64_t> result;
    // Run inside a txn so `SET LOCAL statement_timeout` caps the count's
    // EXECUTION, not merely the lease acquire (the sibling CH-IN3/UP-2
    // lesson): a caller on a shared serial sweep must never wait out the
    // pool's 30s default behind a bloated-table scan. The last_seen index
    // (migration v1) keeps the steady-state plan an index range scan; the cap
    // defends against bloat / plan regression. A timeout errors the SELECT →
    // ROLLBACK → nullopt → the caller holds its previous value.
    pool_.with_txn_for(kStaleCountAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res =
            pg::exec_params(c,
                            "SELECT count(*) FROM software_licensing_store.agent_license_state "
                            "WHERE last_seen < $1::bigint",
                            std::vector<std::string>{std::to_string(stale_before_secs)});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return false;
        const char* txt = PQgetvalue(res.get(), 0, 0);
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), 0, 0));
        std::int64_t count = 0;
        if (std::from_chars(txt, txt + len, count).ec != std::errc{})
            return false;
        result = count;
        return true;
    });
    return result;
}

} // namespace yuzu::server
