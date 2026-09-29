#include "discovery_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "discovery_store";

// Bounded acquires (ADR-0012 §2(a)). Discovery is an operator/dashboard
// surface fed by agent scan reports — not a per-heartbeat hot path — so the
// budgets are generous relative to e.g. the gRPC ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// Read-degrade observability (mirrors ManagementGroupStore/AccessReviewStore).
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
        metrics->counter("yuzu_server_discovery_read_degrade_total", {{"reason", reason}})
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

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres, agent scan input
// included. Scrubs invalid UTF-8 to U+FFFD, then replaces any embedded NUL
// (PostgreSQL TEXT cannot store one; libpq's text bind C-string-truncates
// at the first one).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

DiscoveredDevice read_device(PGresult* res, int row) {
    DiscoveredDevice d;
    int c = 0;
    d.id = to_i64(PQgetvalue(res, row, c++));
    d.ip_address = text_col(res, row, c++);
    d.mac_address = text_col(res, row, c++);
    d.hostname = text_col(res, row, c++);
    d.managed = to_bool(PQgetvalue(res, row, c++));
    d.agent_id = text_col(res, row, c++);
    d.discovered_by = text_col(res, row, c++);
    d.discovered_at = to_i64(PQgetvalue(res, row, c++));
    d.last_seen = to_i64(PQgetvalue(res, row, c++));
    d.subnet = text_col(res, row, c++);
    return d;
}

constexpr const char* kDeviceCols =
    "id, ip_address, mac_address, hostname, managed, agent_id, discovered_by, discovered_at, "
    "last_seen, subnet";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so this table lands in `discovery_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE discovered_devices ("
         "  id             BIGSERIAL PRIMARY KEY,"
         "  ip_address     TEXT NOT NULL UNIQUE,"
         "  mac_address    TEXT NOT NULL DEFAULT '',"
         "  hostname       TEXT NOT NULL DEFAULT '',"
         "  managed        BOOLEAN NOT NULL DEFAULT FALSE,"
         "  agent_id       TEXT NOT NULL DEFAULT '',"
         "  discovered_by  TEXT NOT NULL DEFAULT '',"
         "  discovered_at  BIGINT NOT NULL DEFAULT 0,"
         "  last_seen      BIGINT NOT NULL DEFAULT 0,"
         "  subnet         TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_discovery_managed ON discovered_devices(managed);"
         "CREATE INDEX idx_discovery_subnet ON discovered_devices(subnet);"},
        // migrate_from_sqlite() retired (ADR-0009 fresh-start-by-default, #3623) —
        // discovery_meta's sole purpose was the backfill idempotency marker, which
        // no longer has a writer. Version-bumped (not edited into v1) because v1
        // has actually run against real dev/UAT databases.
        {2, "DROP TABLE IF EXISTS discovery_meta;"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────

DiscoveryStore::DiscoveryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DiscoveryStore: no database connection at construction ({}) — discovery "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DiscoveryStore: schema migration failed — discovery persistence disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string> DiscoveryStore::upsert_device(const DiscoveredDevice& device) {
    if (!open_)
        return std::unexpected("database not open");
    if (device.ip_address.empty())
        return std::unexpected("ip_address is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    const auto now = now_secs();
    // ON CONFLICT semantics preserved from the legacy SQLite implementation
    // (see the header doc): mac_address/last_seen/subnet always refresh;
    // hostname refreshes only when the new value is non-empty; discovered_at/
    // discovered_by/managed/agent_id are untouched by a re-scan. last_seen is
    // UNCONDITIONALLY "now" on every call (insert or update) — independent of
    // discovered_at, which only falls back to "now" when the caller did not
    // supply one. The two must bind as SEPARATE parameters: reusing one bind
    // slot for both silently couples them, which the legacy sqlite3_bind_int64
    // pair (discovered_at, then a second, unconditional `now` for last_seen)
    // never did. managed/agent_id ARE part of the INSERT column list (a fresh
    // insert honors the caller's values, matching the legacy implementation's
    // bind positions 4/5) but are absent from the DO UPDATE SET clause — the
    // "untouched by a re-scan" guarantee applies only to an ALREADY-EXISTING
    // row, never to a device seen for the first time.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO discovery_store.discovered_devices "
        "(ip_address, mac_address, hostname, managed, agent_id, discovered_by, discovered_at, "
        "last_seen, subnet) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8::bigint, $9) "
        "ON CONFLICT (ip_address) DO UPDATE SET "
        "  mac_address = EXCLUDED.mac_address, "
        "  hostname = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname "
        "                  ELSE discovery_store.discovered_devices.hostname END, "
        "  last_seen = EXCLUDED.last_seen, "
        "  subnet = EXCLUDED.subnet "
        "RETURNING id",
        std::vector<std::string>{
            sanitize_pg_text(device.ip_address), sanitize_pg_text(device.mac_address),
            sanitize_pg_text(device.hostname), device.managed ? "true" : "false",
            sanitize_pg_text(device.agent_id), sanitize_pg_text(device.discovered_by),
            std::to_string(device.discovered_at > 0 ? device.discovered_at : now),
            std::to_string(now), sanitize_pg_text(device.subnet)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("upsert_device failed: ") +
                               PQerrorMessage(lease.get()));
    return {};
}

std::optional<std::vector<DiscoveredDevice>>
DiscoveryStore::list_devices(const std::string& subnet_filter) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — pool acquire timed out ({})",
                        pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kDeviceCols +
                      " FROM discovery_store.discovered_devices ";
    pg::PgResult res;
    if (subnet_filter.empty()) {
        sql += "ORDER BY last_seen DESC";
        res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    } else {
        sql += "WHERE subnet = $1 ORDER BY last_seen DESC";
        // sanitize_pg_text: match the same transform applied on write, so a
        // filter value containing invalid UTF-8/NUL still matches the
        // sanitized bytes actually stored (rather than silently no-op-ing to
        // "no rows found" against the caller's untransformed original).
        res = pg::exec_params(lease.get(), sql.c_str(),
                              std::vector<std::string>{sanitize_pg_text(subnet_filter)});
    }
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<DiscoveredDevice> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_device(res.get(), i));
    return out;
}

std::expected<std::optional<DiscoveredDevice>, std::string>
DiscoveryStore::get_device(const std::string& ip_address) {
    if (!open_)
        return std::unexpected("database not open");
    if (ip_address.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql = std::string("SELECT ") + kDeviceCols +
                      " FROM discovery_store.discovered_devices WHERE ip_address = $1 LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(ip_address)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("get_device failed: ") + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<DiscoveredDevice>{std::nullopt};
    return std::optional<DiscoveredDevice>{read_device(res.get(), 0)};
}

std::expected<void, std::string>
DiscoveryStore::mark_managed(const std::string& ip_address, const std::string& agent_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (ip_address.empty())
        return std::unexpected("ip_address is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE discovery_store.discovered_devices SET managed = TRUE, agent_id = $1 "
        "WHERE ip_address = $2 RETURNING id",
        std::vector<std::string>{sanitize_pg_text(agent_id), sanitize_pg_text(ip_address)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("mark_managed failed: ") +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: no device with this ip_address");
    return {};
}

std::expected<void, std::string> DiscoveryStore::clear_results(const std::string& subnet) {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res;
    if (subnet.empty()) {
        res = pg::exec_params(lease.get(), "DELETE FROM discovery_store.discovered_devices",
                              std::vector<std::string>{});
    } else {
        res = pg::exec_params(lease.get(),
                              "DELETE FROM discovery_store.discovered_devices WHERE subnet = $1",
                              std::vector<std::string>{sanitize_pg_text(subnet)});
    }
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("clear_results failed: ") +
                               PQerrorMessage(lease.get()));
    return {};
}

} // namespace yuzu::server
