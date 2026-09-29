#include "quarantine_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "quarantine_store";

// Bounded acquires (ADR-0012 §2(a)). Quarantine is an operator/dashboard +
// MCP surface, not a per-heartbeat hot path — budgets are generous relative
// to e.g. the gRPC ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// Read-degrade observability (mirrors DiscoveryStore/ManagementGroupStore).
constexpr const char* kReasonStoreClosed = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_quarantine_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres, including the
// backfill path (a bad byte at-rest in a legacy quarantine.db must not
// brick the mandatory backfill). Scrubs invalid UTF-8 to U+FFFD, then
// replaces any embedded NUL (PostgreSQL TEXT cannot store one; libpq's text
// bind C-string-truncates at the first one).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

QuarantineRecord read_record(PGresult* res, int row) {
    QuarantineRecord r;
    int c = 0;
    r.id = to_i64(PQgetvalue(res, row, c++));
    r.agent_id = text_col(res, row, c++);
    r.status = text_col(res, row, c++);
    r.quarantined_by = text_col(res, row, c++);
    r.quarantined_at = to_i64(PQgetvalue(res, row, c++));
    r.released_at = to_i64(PQgetvalue(res, row, c++));
    r.whitelist = text_col(res, row, c++);
    r.reason = text_col(res, row, c++);
    r.last_applied_at = to_i64(PQgetvalue(res, row, c++));
    r.last_confirmed_at = to_i64(PQgetvalue(res, row, c++));
    return r;
}

constexpr const char* kRecordCols =
    "id, agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, reason, "
    "last_applied_at, last_confirmed_at";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so this table lands in `quarantine_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE quarantine_records ("
         "  id              BIGSERIAL PRIMARY KEY,"
         "  agent_id        TEXT NOT NULL,"
         "  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', "
         "'released')),"
         "  quarantined_by  TEXT NOT NULL DEFAULT '',"
         "  quarantined_at  BIGINT NOT NULL DEFAULT 0,"
         "  released_at     BIGINT NOT NULL DEFAULT 0,"
         "  whitelist       TEXT NOT NULL DEFAULT '',"
         "  reason          TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_quarantine_agent ON quarantine_records(agent_id);"
         // gov-fix(architect, Gate 3): a plain index on `status` (ported
         // column-for-column from the legacy SQLite schema) was dropped — the
         // only status-predicated query is `list_quarantined`'s
         // `WHERE status = 'active'`, already servable by the partial unique
         // index below (Postgres can use a partial index whose predicate
         // matches a query's WHERE clause even when the query doesn't filter
         // on the index's own key column). No query filters on any other
         // status value. A second, redundant btree on a 2-value column would
         // be pure write amplification on this append-only history table.
         //
         // Enforces "at most one active record per agent" at the database
         // level — quarantine_device's ON CONFLICT target.
         "CREATE UNIQUE INDEX idx_quarantine_agent_active ON quarantine_records(agent_id) "
         "WHERE status = 'active';"
         // Durable one-time backfill markers (ADR-0009/0040 pattern). Marker-only; the sole
         // writer (migrate_from_sqlite) was retired (#3623, ADR-0047 Update).
         "CREATE TABLE quarantine_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL"
         ");"},
        // #3425: endpoint-containment confirmation state for
        // QuarantineContainmentReconciler. 0 = never, matching this table's
        // existing `released_at` never-happened sentinel — no optional
        // plumbing, no nullable column. A brief ACCESS EXCLUSIVE lock during
        // the ALTER is negligible at this table's size (manually-curated
        // security events, not a telemetry stream — this table is
        // operator-curated, not a high-volume stream).
        {2,
         "ALTER TABLE quarantine_records ADD COLUMN last_applied_at BIGINT NOT NULL DEFAULT 0;"
         "ALTER TABLE quarantine_records ADD COLUMN last_confirmed_at BIGINT NOT NULL DEFAULT 0;"},
        // migrate_from_sqlite() retired (#3623, ADR-0047 Update) — quarantine_meta was its
        // sole idempotency marker. Appended at the next free slot, never renumbering v1/v2
        // (PgMigrationRunner applies only version > current — renumbering an already-shipped
        // version re-applies it against a database that already ran it).
        {3, "DROP TABLE IF EXISTS quarantine_meta;"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────

QuarantineStore::QuarantineStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("QuarantineStore: no database connection at construction ({}) — "
                      "quarantine persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("QuarantineStore: schema migration failed — quarantine persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string>
QuarantineStore::quarantine_device(const std::string& agent_id, const std::string& by,
                                   const std::string& reason, const std::string& whitelist) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Single race-safe statement: the partial unique index
    // idx_quarantine_agent_active is the ON CONFLICT target, replacing the
    // legacy check-then-insert-under-mutex. PQntuples()==0 means the
    // conflict fired (an active record already exists).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO quarantine_store.quarantine_records "
        "(agent_id, status, quarantined_by, quarantined_at, whitelist, reason) "
        "VALUES ($1, 'active', $2, $3::bigint, $4, $5) "
        "ON CONFLICT (agent_id) WHERE status = 'active' DO NOTHING "
        "RETURNING id",
        std::vector<std::string>{sanitize_pg_text(agent_id), sanitize_pg_text(by),
                                 std::to_string(now_secs()), sanitize_pg_text(whitelist),
                                 sanitize_pg_text(reason)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "quarantine_device failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is already quarantined");
    return {};
}

std::expected<void, std::string> QuarantineStore::release_device(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Single guarded UPDATE (the #3062 cancel_job pattern) — not
    // lock-then-check. RETURNING replaces sqlite3_changes() (#1033).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE quarantine_store.quarantine_records SET status = 'released', released_at = "
        "$1::bigint "
        "WHERE agent_id = $2 AND status = 'active' RETURNING id",
        std::vector<std::string>{std::to_string(now_secs()), sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "release_device failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is not quarantined");
    return {};
}

namespace {
// Shared body for mark_endpoint_applied/mark_endpoint_confirmed — same
// guarded-UPDATE-WHERE-active shape as release_device (the #3062 cancel_job
// pattern), differing only in which column is stamped. `record_id` scopes
// the write to the SPECIFIC row a dispatch/status-read was actually about
// (governance Gate 4, unhappy-path Finding A) — `agent_id`+`status='active'`
// alone is not a stable identity across a release-then-requarantine race.
std::expected<void, std::string> mark_endpoint_column(pg::PgPool& pool, const char* column,
                                                       const std::string& agent_id,
                                                       std::int64_t record_id, std::int64_t at,
                                                       bool open) {
    if (!open)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("UPDATE quarantine_store.quarantine_records SET ") + column +
                      " = $1::bigint WHERE agent_id = $2 AND id = $3::bigint AND status = "
                      "'active' RETURNING id";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(at), sanitize_pg_text(agent_id),
                                 std::to_string(record_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + column +
                               " update failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is not quarantined");
    return {};
}
} // namespace

std::expected<void, std::string>
QuarantineStore::mark_endpoint_applied(const std::string& agent_id, std::int64_t record_id,
                                       std::int64_t at) {
    return mark_endpoint_column(pool_, "last_applied_at", agent_id, record_id, at, open_);
}

std::expected<void, std::string>
QuarantineStore::mark_endpoint_confirmed(const std::string& agent_id, std::int64_t record_id,
                                         std::int64_t at) {
    return mark_endpoint_column(pool_, "last_confirmed_at", agent_id, record_id, at, open_);
}

std::expected<std::optional<QuarantineRecord>, std::string>
QuarantineStore::get_status(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::optional<QuarantineRecord>{std::nullopt};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE agent_id = $1 AND status "
                      "= 'active' LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "get_status failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<QuarantineRecord>{std::nullopt};
    return std::optional<QuarantineRecord>{read_record(res.get(), 0)};
}

std::optional<std::vector<QuarantineRecord>> QuarantineStore::list_quarantined() {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — pool acquire timed out "
                         "({})",
                         pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE status = 'active' "
                      "ORDER BY quarantined_at DESC, id DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<QuarantineRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_record(res.get(), i));
    return out;
}

std::optional<std::vector<QuarantineRecord>>
QuarantineStore::get_history(const std::string& agent_id) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — store not open");
        return std::nullopt;
    }
    if (agent_id.empty())
        return std::vector<QuarantineRecord>{};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — pool acquire timed out ({})",
                        pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE agent_id = $1 "
                      "ORDER BY quarantined_at DESC, id DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<QuarantineRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_record(res.get(), i));
    return out;
}

} // namespace yuzu::server
