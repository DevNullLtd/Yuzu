#include "quarantine_store.hpp"

#include "pg/pg_array.hpp"
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
    r.release_requested_at = to_i64(PQgetvalue(res, row, c++));
    r.device_release_owed_at = to_i64(PQgetvalue(res, row, c++));
    return r;
}

// `status` reads "releasing" for an active row with a release requested (no alias: read_record is
// positional, and every WHERE below keeps binding to the table column, so the partial unique index,
// ON CONFLICT and the `status = 'active'` filters see the stored active|released value).
constexpr const char* kRecordCols =
    "id, agent_id, CASE WHEN status = 'active' AND release_requested_at <> 0 THEN 'releasing' ELSE "
    "status END, quarantined_by, quarantined_at, released_at, whitelist, reason, "
    "last_applied_at, last_confirmed_at, release_requested_at, device_release_owed_at";

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
        // PRQ.2: the release is a real, confirmed step. `release_requested_at` marks a record whose
        // release was asked for (read as status `releasing`; the stored status stays active|released so
        // the CHECK, the partial unique index and every active-row query are untouched).
        // `device_release_owed_at` marks a record an operator ended by force before the device
        // confirmed a release. Both: 0 = never, this table's existing sentinel. The partial index
        // serves the owed list the reconciler reads every tick: it holds only force-ended records the
        // device has not confirmed, so it stays tiny.
        {4,
         "ALTER TABLE quarantine_records ADD COLUMN release_requested_at BIGINT NOT NULL DEFAULT 0;"
         "ALTER TABLE quarantine_records ADD COLUMN device_release_owed_at BIGINT NOT NULL DEFAULT "
         "0;"
         "CREATE INDEX idx_quarantine_release_owed ON quarantine_records(agent_id, id) "
         "WHERE status = 'released' AND device_release_owed_at <> 0;"},
        // #7613: the apply fence. `apply_gen` counts the applies ever claimed for the record;
        // `apply_claimed_at` marks one whose dispatch has not returned (0 = none). Both: 0 =
        // never, this table's existing sentinel. v1-v4 above are byte-identical on purpose: the
        // runner pins each applied migration's SHA-256. The ADD COLUMN IF NOT EXISTS makes a
        // re-run after a partial apply safe.
        {5,
         "ALTER TABLE quarantine_records ADD COLUMN IF NOT EXISTS apply_gen BIGINT NOT NULL "
         "DEFAULT 0;"
         "ALTER TABLE quarantine_records ADD COLUMN IF NOT EXISTS apply_claimed_at BIGINT NOT "
         "NULL DEFAULT 0;"},
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

std::expected<std::int64_t, std::string>
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
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::expected<std::int64_t, std::string> QuarantineStore::request_release(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Single guarded UPDATE (the #3062 cancel_job pattern) — not lock-then-check. Idempotent: the
    // CASE keeps the first request's timestamp. RETURNING replaces sqlite3_changes() (#1033) and
    // hands back the record id the rest of the release is scoped to.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE quarantine_store.quarantine_records SET release_requested_at = CASE WHEN "
        "release_requested_at = 0 THEN $1::bigint ELSE release_requested_at END "
        "WHERE agent_id = $2 AND status = 'active' RETURNING id",
        std::vector<std::string>{std::to_string(now_secs()), sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "request_release failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kQuarantineNotQuarantined));
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

namespace {
// One record-scoped guarded UPDATE (mark_endpoint_applied/confirmed, mark_released,
// clear_release_owed) — the #3062 cancel_job pattern. `record_id` scopes the write to the SPECIFIC
// row a dispatch/status-read was actually about (governance Gate 4, unhappy-path Finding A):
// `agent_id`+`status='active'` alone is not a stable identity across a release-then-requarantine
// race. Every member except `extra` is a string literal chosen by the caller, never input; $1 is the
// agent, $2 the record id, $3.. the caller's `extra` values.
struct GuardedUpdate {
    const char* op;        // the calling method's name; appears in the store-error text
    std::string set_sql;   // the SET list
    const char* where_sql; // appended after "agent_id = $1 AND id = $2::bigint AND "
    std::vector<std::string> extra;
    // When set and the UPDATE touched no row: a SELECT on the same lease WHERE agent_id = $1 AND
    // id = $2 AND <held_where>. A row there means the record is still in the state the caller wants
    // to move out of, so what refused the write was the apply fence (`kQuarantineApplyInFlight`);
    // no row means the record is gone or past that state (`kQuarantineNotQuarantined`).
    const char* held_where = nullptr;
};

std::expected<void, std::string> guarded_record_update(pg::PgPool& pool, bool open,
                                                        const std::string& agent_id,
                                                        std::int64_t record_id, GuardedUpdate u) {
    if (!open)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = "UPDATE quarantine_store.quarantine_records SET " + u.set_sql +
                      " WHERE agent_id = $1 AND id = $2::bigint AND " + u.where_sql +
                      " RETURNING id";
    const std::string agent = sanitize_pg_text(agent_id);
    std::vector<std::string> params{agent, std::to_string(record_id)};
    for (auto& e : u.extra)
        params.push_back(std::move(e));
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + u.op +
                               " update failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) != 0)
        return {};
    if (u.held_where == nullptr)
        return std::unexpected(std::string(kQuarantineNotQuarantined));

    const std::string held = std::string("SELECT 1 FROM quarantine_store.quarantine_records "
                                         "WHERE agent_id = $1 AND id = $2::bigint AND ") +
                             u.held_where;
    pg::PgResult chk = pg::exec_params(lease.get(), held.c_str(),
                                       std::vector<std::string>{agent, std::to_string(record_id)});
    if (chk.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + u.op +
                               " check failed: " + PQerrorMessage(lease.get()));
    return std::unexpected(std::string(PQntuples(chk.get()) != 0 ? kQuarantineApplyInFlight
                                                                : kQuarantineNotQuarantined));
}

// The generation and claim terms of a confirmed end ($5 is the fence, $6 the claim cutoff).
constexpr const char* kFencedActiveWhere = "status = 'active' AND apply_gen = $5::bigint AND "
                                           "(apply_claimed_at = 0 OR apply_claimed_at < $6::bigint)";
constexpr const char* kFencedOwedWhere = "status = 'released' AND device_release_owed_at <> 0 AND "
                                         "apply_gen = $3::bigint AND (apply_claimed_at = 0 OR "
                                         "apply_claimed_at < $4::bigint)";
} // namespace

std::expected<void, std::string>
QuarantineStore::mark_released(const std::string& agent_id, std::int64_t record_id, ReleaseEnd end,
                               std::optional<std::int64_t> fence) {
    const std::int64_t now = now_secs();
    const char* set_sql =
        "status = 'released', released_at = $3::bigint, device_release_owed_at = $4::bigint";
    if (end == ReleaseEnd::forced) {
        // The operator's own word, resting on no observation of the device: no fence, no claim
        // check, both apply columns left as they are.
        return guarded_record_update(pool_, open_, agent_id, record_id,
                                     {"mark_released", set_sql, "status = 'active'",
                                      {std::to_string(now), std::to_string(now)}});
    }
    if (!fence) // fail closed, no round trip: nothing proves the answer followed every apply
        return std::unexpected(std::string(kQuarantineApplyInFlight));
    return guarded_record_update(
        pool_, open_, agent_id, record_id,
        {"mark_released",
         set_sql,
         kFencedActiveWhere,
         {std::to_string(now), "0", std::to_string(*fence),
          std::to_string(now - kApplyClaimTtlSecs)},
         "status = 'active'"});
}

std::expected<void, std::string>
QuarantineStore::clear_release_owed(const std::string& agent_id, std::int64_t record_id,
                                    std::optional<std::int64_t> fence) {
    if (!fence)
        return std::unexpected(std::string(kQuarantineApplyInFlight));
    return guarded_record_update(
        pool_, open_, agent_id, record_id,
        {"clear_release_owed",
         "device_release_owed_at = 0",
         kFencedOwedWhere,
         {std::to_string(*fence), std::to_string(now_secs() - kApplyClaimTtlSecs)},
         "status = 'released' AND device_release_owed_at <> 0"});
}

std::expected<void, std::string>
QuarantineStore::mark_endpoint_applied(const std::string& agent_id, std::int64_t record_id,
                                       std::int64_t at) {
    return guarded_record_update(pool_, open_, agent_id, record_id,
                                 {"last_applied_at", "last_applied_at = $3::bigint",
                                  "status = 'active'", {std::to_string(at)}});
}

std::expected<void, std::string>
QuarantineStore::mark_endpoint_confirmed(const std::string& agent_id, std::int64_t record_id,
                                         std::int64_t at) {
    return guarded_record_update(pool_, open_, agent_id, record_id,
                                 {"last_confirmed_at", "last_confirmed_at = $3::bigint",
                                  "status = 'active'", {std::to_string(at)}});
}

std::expected<std::int64_t, std::string>
QuarantineStore::claim_apply(const std::string& agent_id, std::int64_t record_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // One guarded UPDATE: the generation moves and the claim is stamped together, and only while
    // the record is active, no release was asked for, and no other claim is live.
    const std::int64_t now = now_secs();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE quarantine_store.quarantine_records SET apply_gen = apply_gen + 1, "
        "apply_claimed_at = $3::bigint WHERE agent_id = $1 AND id = $2::bigint AND status = "
        "'active' AND release_requested_at = 0 AND (apply_claimed_at = 0 OR apply_claimed_at < "
        "$4::bigint) RETURNING apply_gen",
        std::vector<std::string>{sanitize_pg_text(agent_id), std::to_string(record_id),
                                 std::to_string(now), std::to_string(now - kApplyClaimTtlSecs)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "claim_apply failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kQuarantineNotQuarantined));
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::expected<void, std::string>
QuarantineStore::release_apply_claim(const std::string& agent_id, std::int64_t record_id,
                                     std::int64_t gen) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Conditional on the caller's own generation: a holder whose claim expired and was replaced
    // matches no row, so it cannot drop the replacement's live claim. Zero rows is success.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE quarantine_store.quarantine_records SET apply_claimed_at = 0 WHERE agent_id = $1 "
        "AND id = $2::bigint AND apply_gen = $3::bigint",
        std::vector<std::string>{sanitize_pg_text(agent_id), std::to_string(record_id),
                                 std::to_string(gen)});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "release_apply_claim failed: " + PQerrorMessage(lease.get()));
    return {};
}

std::expected<std::optional<std::int64_t>, std::string>
QuarantineStore::apply_fence_token(const std::string& agent_id, std::int64_t record_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::optional<std::int64_t>{std::nullopt};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT apply_gen FROM quarantine_store.quarantine_records WHERE agent_id = $1 AND id = "
        "$2::bigint AND (apply_claimed_at = 0 OR apply_claimed_at < $3::bigint)",
        std::vector<std::string>{sanitize_pg_text(agent_id), std::to_string(record_id),
                                 std::to_string(now_secs() - kApplyClaimTtlSecs)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "apply_fence_token failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<std::int64_t>{std::nullopt};
    return std::optional<std::int64_t>{to_i64(PQgetvalue(res.get(), 0, 0))};
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
QuarantineStore::list_quarantined_in(const std::vector<std::string>* visible_ids, std::size_t limit) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: list_quarantined_in degraded — store not open");
        return std::nullopt;
    }
    if (visible_ids && visible_ids->empty())
        return std::vector<QuarantineRecord>{}; // deny-all: nothing can match, no round trip
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: list_quarantined_in degraded — pool acquire timed out "
                         "({})",
                         pool_.last_error());
        return std::nullopt;
    }

    std::vector<std::string> params;
    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE status = 'active'";
    if (visible_ids) {
        std::vector<std::string_view> views(visible_ids->begin(), visible_ids->end());
        params.push_back(pg::to_text_array(views));
        sql += " AND agent_id = ANY($1::text[])";
    }
    sql += " ORDER BY quarantined_at DESC, id DESC";
    if (limit != 0)
        sql += " LIMIT " + std::to_string(limit);
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: list_quarantined_in degraded — query failed: {}",
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

std::optional<std::vector<QuarantineRecord>> QuarantineStore::list_release_owed() {
    return list_release_owed_in(nullptr, 0);
}

std::optional<std::vector<QuarantineRecord>>
QuarantineStore::list_release_owed_in(const std::vector<std::string>* visible_ids, std::size_t limit) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: list_release_owed degraded — store not open");
        return std::nullopt;
    }
    if (visible_ids && visible_ids->empty())
        return std::vector<QuarantineRecord>{}; // deny-all: nothing can match, no round trip
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: list_release_owed degraded — pool acquire timed out ({})",
                         pool_.last_error());
        return std::nullopt;
    }

    // A forced record the device has not confirmed, and only while it is the device's LATEST
    // record: a device quarantined again is governed by its new record and never appears here.
    // The caller's scope and LIMIT are applied in the query, so an invisible record can never
    // displace a visible one out of the window.
    std::vector<std::string> params;
    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records q WHERE q.status = 'released' "
                      "AND q.device_release_owed_at <> 0 AND NOT EXISTS (SELECT 1 FROM "
                      "quarantine_store.quarantine_records n WHERE n.agent_id = q.agent_id AND "
                      "n.id > q.id)";
    if (visible_ids) {
        std::vector<std::string_view> views(visible_ids->begin(), visible_ids->end());
        params.push_back(pg::to_text_array(views));
        sql += " AND q.agent_id = ANY($1::text[])";
    }
    sql += " ORDER BY q.quarantined_at DESC, q.id DESC";
    if (limit != 0)
        sql += " LIMIT " + std::to_string(limit);
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: list_release_owed degraded — query failed: {}",
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
