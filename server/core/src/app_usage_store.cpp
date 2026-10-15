#include "app_usage_store.hpp"

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

constexpr const char* kStoreName = "app_usage_store";

// Bounded acquires (ADR-0012 lease discipline). The ingest-path methods run
// on the gRPC thread (direct ReportInventory / gateway ProxyInventory) so
// they give up fast on a saturated pool — best-effort, the agent retries next
// cycle. Reads can wait a little longer.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// The staleness count may run on a shared serial sweep: a SHORT acquire plus
// a per-statement execution cap so it can never stall that thread.
constexpr std::chrono::milliseconds kStaleCountAcquireTimeout{250};
// Hard ceiling on rows a single read will materialise, independent of any
// caller limit. The per-agent set is capped upstream by the ingest seam's
// 5000-record cap.
constexpr int kAgentRowCap = 20000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in `app_usage_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Per-agent sync parent. content_hash is the RAW received blob
         // bytes' SHA-256, recomputed by the ingest seam and persisted
         // VERBATIM (mirrors SoftwareLicensingStore — never re-derived from
         // parsed rows). collected_at is the agent-supplied BATCH collection
         // time — every agent_last_used row from one replace shares it, so it
         // is persisted here on the parent, not derived from a child row: an
         // empty replace-to-empty has no child row to carry it, and this
         // column is what keeps that case's collected_at honest instead of
         // reading back as "never collected". first_seen/last_seen/updated_at
         // are the SERVER receipt time (#1685 / ADR-0016 clock-skew rule) —
         // the staleness read keys on last_seen, served by the index below.
         "CREATE TABLE usage_state ("
         "  agent_id     TEXT PRIMARY KEY,"
         "  content_hash TEXT NOT NULL DEFAULT '',"
         "  collected_at BIGINT NOT NULL DEFAULT 0,"
         "  first_seen   TIMESTAMPTZ NOT NULL,"
         "  last_seen    TIMESTAMPTZ NOT NULL,"
         "  updated_at   TIMESTAMPTZ NOT NULL);"
         "CREATE INDEX usage_state_lastseen_idx ON usage_state (last_seen);"
         // Per-executable last-used rows, replaced wholesale per agent on
         // each stored sync. Same-schema FK ON DELETE CASCADE onto the
         // parent. first_seen/last_seen/run_count_30d/total_seconds_30d are
         // the AGENT-OBSERVED values (the payload); collected_at is the
         // agent-supplied collection time, persisted as data only.
         "CREATE TABLE agent_last_used ("
         "  agent_id           TEXT NOT NULL REFERENCES usage_state (agent_id) ON DELETE CASCADE,"
         "  exe_key            TEXT NOT NULL DEFAULT '',"
         "  first_seen         BIGINT NOT NULL DEFAULT 0,"
         "  last_seen          BIGINT NOT NULL DEFAULT 0,"
         "  run_count_30d      BIGINT NOT NULL DEFAULT 0,"
         "  total_seconds_30d  BIGINT NOT NULL DEFAULT 0,"
         "  collected_at       BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (agent_id, exe_key));"
         "CREATE INDEX agent_last_used_agent_idx ON agent_last_used (agent_id);"},
    };
    return kMigrations;
}

// ── Read-degrade observability (#1675 convention) ────────────────────────────
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

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", "app_usage"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v);
    return v;
}

constexpr const char* kUsageCols =
    "exe_key, first_seen, last_seen, run_count_30d, total_seconds_30d, collected_at";

void fill_row(const pg::PgResult& res, int row, AgentLastUsedRow& out) {
    out.exe_key = PQgetvalue(res.get(), row, 0);
    out.first_seen = result_i64(res, row, 1);
    out.last_seen = result_i64(res, row, 2);
    out.run_count_30d = result_i64(res, row, 3);
    out.total_seconds_30d = result_i64(res, row, 4);
    out.collected_at = result_i64(res, row, 5);
}

} // namespace

AppUsageStore::AppUsageStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AppUsageStore: no database connection at construction ({}) — app_usage "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AppUsageStore: schema migration failed — app_usage persistence disabled");
        return;
    }
    open_ = true;
}

std::expected<std::optional<std::string>, AppUsageReadError>
AppUsageStore::stored_hash(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return std::unexpected(AppUsageReadError::kDegraded);
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("AppUsageStore: stored_hash skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT content_hash FROM app_usage_store.usage_state WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("AppUsageStore: stored_hash failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{}; // cold cache → the seam answers need_full
    return std::optional<std::string>{PQgetvalue(res.get(), 0, 0)};
}

bool AppUsageStore::touch(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("AppUsageStore: touch skipped for agent={}, no connection ({})", agent_id,
                     pool_.last_error());
        return false;
    }
    // last_seen/updated_at are the SERVER receipt time (#1685) — never an
    // agent-supplied stamp. RETURNING carries the row-hit result: zero tuples
    // = the state row is missing (a touch on a cold cache is a caller
    // sequencing bug; the seam should have answered need_full off stored_hash).
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE app_usage_store.usage_state SET last_seen = now(), updated_at = now() "
        "WHERE agent_id = $1 RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id)});
    if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) != 1) {
        spdlog::warn("AppUsageStore: touch failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

bool AppUsageStore::replace_agent_last_used(std::string_view agent_id,
                                            const std::vector<AgentLastUsedRow>& rows,
                                            std::string_view content_hash,
                                            std::int64_t collected_at) {
    if (!open_ || agent_id.empty())
        return false;
    const std::string agent_id_s{agent_id};

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full-replaces for THIS agent (the
        // software-inventory / software_licensing precedent): two in-flight
        // fulls under READ COMMITTED interleave (B's DELETE cannot see A's
        // fresh rows) and both row sets survive with a parent hash matching
        // neither. Blocking (not try_) on purpose; bounded by the pool's
        // statement_timeout. Key salted with the store name so a same-agent
        // replace in ANOTHER store's tables never contends.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('app_usage:' || $1, 0))",
            std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        // Parent upsert FIRST (the children's FK targets it): persist the
        // seam-recomputed raw-blob hash AND the batch collected_at VERBATIM
        // (both survive an empty `rows` replace — see the file header); keep
        // first_seen on conflict, refresh last_seen/updated_at to the server
        // receipt time.
        pg::PgResult par = pg::exec_params(
            c,
            "INSERT INTO app_usage_store.usage_state "
            "(agent_id, content_hash, collected_at, first_seen, last_seen, updated_at) "
            "VALUES ($1, $2, $3, now(), now(), now()) "
            "ON CONFLICT (agent_id) DO UPDATE SET "
            "  content_hash = EXCLUDED.content_hash, "
            "  collected_at = EXCLUDED.collected_at, "
            "  last_seen = EXCLUDED.last_seen, "
            "  updated_at = EXCLUDED.updated_at "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id_s, std::string(content_hash),
                                     std::to_string(collected_at)});
        if (par.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult del =
            pg::exec_params(c, "DELETE FROM app_usage_store.agent_last_used WHERE agent_id = $1",
                            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        // Batched insert (#1664 pattern): one statement, per-row columns as
        // parallel arrays — parameter count constant regardless of row
        // count. Skip when empty — a legitimate replace-to-empty; the DELETE
        // above cleared the rows.
        if (!rows.empty()) {
            std::vector<std::string_view> exe_keys;
            exe_keys.reserve(rows.size());
            std::vector<std::string> first_seen_strs, last_seen_strs, run_count_strs,
                total_seconds_strs, collected_strs;
            first_seen_strs.reserve(rows.size());
            last_seen_strs.reserve(rows.size());
            run_count_strs.reserve(rows.size());
            total_seconds_strs.reserve(rows.size());
            collected_strs.reserve(rows.size());
            for (const auto& r : rows) {
                exe_keys.emplace_back(r.exe_key);
                first_seen_strs.push_back(std::to_string(r.first_seen));
                last_seen_strs.push_back(std::to_string(r.last_seen));
                run_count_strs.push_back(std::to_string(r.run_count_30d));
                total_seconds_strs.push_back(std::to_string(r.total_seconds_30d));
                collected_strs.push_back(std::to_string(r.collected_at));
            }
            std::vector<std::string_view> first_seen_views(first_seen_strs.begin(),
                                                            first_seen_strs.end());
            std::vector<std::string_view> last_seen_views(last_seen_strs.begin(),
                                                           last_seen_strs.end());
            std::vector<std::string_view> run_count_views(run_count_strs.begin(),
                                                           run_count_strs.end());
            std::vector<std::string_view> total_seconds_views(total_seconds_strs.begin(),
                                                               total_seconds_strs.end());
            std::vector<std::string_view> collected_views(collected_strs.begin(),
                                                           collected_strs.end());
            // push_back (not a braced init-list) so each to_text_array prvalue
            // is MOVED into params. Constant 7 params: $1 agent_id, $2..$7
            // the six per-row arrays (exe_key/first_seen/last_seen/
            // run_count_30d/total_seconds_30d/collected_at).
            std::vector<std::string> params;
            params.reserve(7);
            params.push_back(agent_id_s);
            params.push_back(pg::to_text_array(exe_keys));
            params.push_back(pg::to_text_array(first_seen_views));
            params.push_back(pg::to_text_array(last_seen_views));
            params.push_back(pg::to_text_array(run_count_views));
            params.push_back(pg::to_text_array(total_seconds_views));
            params.push_back(pg::to_text_array(collected_views));
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO app_usage_store.agent_last_used "
                "(agent_id, exe_key, first_seen, last_seen, run_count_30d, total_seconds_30d, "
                "collected_at) "
                "SELECT $1, ek, fs, ls, rc, ts, ca FROM unnest($2::text[], $3::bigint[], "
                "$4::bigint[], $5::bigint[], $6::bigint[], $7::bigint[]) "
                "AS t(ek, fs, ls, rc, ts, ca)",
                params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });
    if (!ok)
        spdlog::warn("AppUsageStore: replace transaction failed for agent={}", agent_id);
    return ok;
}

std::optional<std::vector<AgentLastUsedRow>>
AppUsageStore::get_agent_last_used(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn(
                "AppUsageStore: get_agent_last_used degraded — store not open (occurrence {})",
                d.occurrence);
        return std::nullopt;
    }
    std::vector<AgentLastUsedRow> out;
    if (agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppUsageStore: get_agent_last_used degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kUsageCols +
                            " FROM app_usage_store.agent_last_used WHERE agent_id = $1 "
                            "ORDER BY exe_key LIMIT $2::bigint";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::string(agent_id), std::to_string(kAgentRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppUsageStore: get_agent_last_used degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AgentLastUsedRow r;
        fill_row(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::optional<std::int64_t>, AppUsageReadError>
AppUsageStore::collected_at(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("AppUsageStore: collected_at degraded — store not open (occurrence {})",
                         d.occurrence);
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    if (agent_id.empty())
        return std::optional<std::int64_t>{}; // precondition miss, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("AppUsageStore: collected_at degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT collected_at FROM app_usage_store.usage_state WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppUsageStore: collected_at degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::int64_t>{}; // no state row → never collected
    return std::optional<std::int64_t>{result_i64(res, 0, 0)};
}

std::expected<AppUsageSnapshot, AppUsageReadError>
AppUsageStore::get_agent_usage_snapshot(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn(
                "AppUsageStore: get_agent_usage_snapshot degraded — store not open (occurrence {})",
                d.occurrence);
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    if (agent_id.empty())
        return AppUsageSnapshot{}; // precondition miss, not a degrade — empty rows, collected_at=0

    // Both reads share one REPEATABLE READ transaction so a concurrent
    // replace_agent_last_used/delete_agent landing between the rows read and
    // the collected_at read can't hand back rows from one snapshot paired
    // with collected_at from another — same pattern as
    // access_review_store.cpp's get_campaign (see that file's comment for
    // why a plain with_txn_for/READ COMMITTED isn't enough here).
    AppUsageSnapshot snap;
    std::string error_msg;
    const bool ok = pool_.with_txn_for(kQueryAcquireTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult iso_res{PQexec(conn, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")};
        if (iso_res.status() != PGRES_COMMAND_OK) {
            error_msg = std::string("get_agent_usage_snapshot: failed to set REPEATABLE READ "
                                    "isolation: ") +
                       PQerrorMessage(conn);
            return false;
        }

        const std::string rows_sql = std::string("SELECT ") + kUsageCols +
                                     " FROM app_usage_store.agent_last_used WHERE agent_id = $1 "
                                     "ORDER BY exe_key LIMIT $2::bigint";
        pg::PgResult rows_res = pg::exec_params(
            conn, rows_sql.c_str(),
            std::vector<std::string>{std::string(agent_id), std::to_string(kAgentRowCap)});
        if (rows_res.status() != PGRES_TUPLES_OK) {
            error_msg =
                std::string("get_agent_usage_snapshot rows read failed: ") + PQerrorMessage(conn);
            return false;
        }
        const int n = PQntuples(rows_res.get());
        snap.rows.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            AgentLastUsedRow r;
            fill_row(rows_res, i, r);
            snap.rows.push_back(std::move(r));
        }

        pg::PgResult ca_res = pg::exec_params(
            conn, "SELECT collected_at FROM app_usage_store.usage_state WHERE agent_id = $1",
            std::vector<std::string>{std::string(agent_id)});
        if (ca_res.status() != PGRES_TUPLES_OK) {
            error_msg = std::string("get_agent_usage_snapshot collected_at read failed: ") +
                       PQerrorMessage(conn);
            return false;
        }
        if (PQntuples(ca_res.get()) > 0)
            snap.collected_at = result_i64(ca_res, 0, 0);
        // else: no state row → never collected, snap.collected_at stays 0 (matches
        // collected_at()'s own "no state row" semantics).
        return true;
    });
    if (!ok) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("AppUsageStore: get_agent_usage_snapshot degraded — {} (occurrence {})",
                         error_msg, d.occurrence);
        return std::unexpected(AppUsageReadError::kDegraded);
    }
    return snap;
}

bool AppUsageStore::delete_agent(std::string_view agent_id) {
    if (agent_id.empty()) {
        spdlog::warn("AppUsageStore: delete_agent called with an empty agent_id — refusing "
                     "without touching PG");
        return false;
    }
    if (!open_)
        return false;
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a
    // parent state row without its child rows or vice versa — see the file
    // header: a delete that cleared agent_last_used but left usage_state
    // would make the still-enrolled agent's next sync "touched" and the
    // projection would never repopulate. The commit result is RETURNED to
    // the caller (the decommission cascade), which records a false as
    // Failed — a rolled-back erasure is never reported as a completed
    // delete; the next decommission pass self-heals.
    const bool committed = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Same per-agent advisory lock replace_agent_last_used holds, with
        // the IDENTICAL key derivation ('app_usage:' || agent_id) — closes
        // the same decommission-vs-in-flight-replace race the sibling store
        // documents. Blocking (not try_) on purpose, bounded by the pool's
        // lock_timeout.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('app_usage:' || $1, 0))",
            std::vector<std::string>{id});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult d1 =
            pg::exec_params(c, "DELETE FROM app_usage_store.agent_last_used WHERE agent_id = $1",
                            std::vector<std::string>{id});
        pg::PgResult d2 =
            pg::exec_params(c, "DELETE FROM app_usage_store.usage_state WHERE agent_id = $1",
                            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
    if (!committed)
        spdlog::debug("AppUsageStore: delete_agent did not commit for agent={} ({})", agent_id,
                      pool_.last_error());
    return committed;
}

std::optional<std::int64_t> AppUsageStore::count_stale_agents(std::int64_t stale_before_secs) {
    if (!open_)
        return std::nullopt;
    std::optional<std::int64_t> result;
    pool_.with_txn_for(kStaleCountAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res = pg::exec_params(
            c,
            "SELECT count(*) FROM app_usage_store.usage_state WHERE last_seen < to_timestamp($1)",
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
