#include "offline_endpoint_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "endpoint_state";

// Bounded acquires (gov UP-1): the upsert is on the gRPC heartbeat thread, so
// it must NEVER block on a saturated pool — a short deadline makes it truly
// best-effort (skip the persist, the live in-memory stores stay authoritative).
// The read is a user-facing /viz request and can wait a little longer.
constexpr std::chrono::milliseconds kUpsertAcquireTimeout{250};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{2000};
// Hard cap on rows materialised by query_stale_within (gov sec-LOW / UP-5): the
// viz machines_max ceiling, so the store can never allocate more than the page
// could ever serve even if the table has grown large.
constexpr int kQueryRowCap = 100000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so `endpoints` lands in `endpoint_state`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE endpoints ("
         "  agent_id          TEXT PRIMARY KEY,"
         "  hostname          TEXT NOT NULL DEFAULT '',"
         "  os                TEXT NOT NULL DEFAULT '',"
         "  last_heartbeat_ms BIGINT NOT NULL,"
         "  agent_ts          BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX endpoints_last_heartbeat_idx ON endpoints (last_heartbeat_ms);"},
        // Round-3 Devices-page merge (item 1): last-known agent version/arch so
        // an offline row still shows them on the Hardware list. IF NOT EXISTS
        // makes this safe to re-run against an already-migrated v1 table.
        {2,
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS agent_version TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS arch TEXT NOT NULL DEFAULT '';"},
        // HA WS-5 (ADR-2002 §7a): `session_id` guards a targeted delete on
        // graceful disconnect (remove_if_session) so a stale session's
        // teardown can't clobber a newer re-registration's row; `last_seen_at`
        // is a PG-authored (`now()` in-SQL) liveness clock, separate from the
        // pre-existing `last_heartbeat_ms` replica-clock column (which stays
        // exactly as-is for the viz path — see query_stale_within).
        {3,
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL "
         "DEFAULT now();"
         "CREATE INDEX IF NOT EXISTS endpoints_last_seen_idx ON endpoints (last_seen_at);"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// HA WS-5 governance hardening (Gate 4 consistency-auditor finding,
// 2026-09-22): matches WS-4's `record_route_store_failure` (gateway_service_
// impl.cpp) naming/label convention exactly — `{op,reason}`, `reason` ∈
// {store_unavailable, db_error} — rather than the original narrower
// `{op}`-only counter, which also mis-named itself "_read_" despite firing
// from `remove_if_session` (a write). Documented in
// docs/observability-conventions.md's HA metrics table.
void record_presence_store_failure(yuzu::MetricsRegistry* metrics, std::string_view op,
                                   bool had_lease) {
    const char* reason = had_lease ? "db_error" : "store_unavailable";
    if (metrics) {
        metrics
            ->counter("yuzu_server_agent_presence_store_failed_total",
                      {{"op", std::string(op)}, {"reason", reason}})
            .increment();
    }
}

} // namespace

OfflineEndpointStore::OfflineEndpointStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("OfflineEndpointStore: no database connection at construction ({}) — "
                      "endpoint persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("OfflineEndpointStore: schema migration failed — endpoint persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

bool OfflineEndpointStore::upsert(std::string_view agent_id, std::string_view hostname,
                                  std::string_view os, std::int64_t last_heartbeat_ms,
                                  std::int64_t agent_ts, std::string_view agent_version,
                                  std::string_view arch, std::string_view session_id) {
    if (!open_ || agent_id.empty())
        return false;
    // Bounded acquire (gov UP-1): on a saturated pool, give up fast rather than
    // block the gRPC heartbeat thread. Best-effort persistence — the live
    // in-memory stores remain authoritative.
    auto lease = pool_.try_acquire_for(kUpsertAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: upsert skipped, no connection in time ({})",
                      pool_.last_error());
        record_presence_store_failure(metrics_, "upsert", /*had_lease=*/false);
        return false;
    }
    // Single-statement autocommit upsert; RETURNING carries the result in the
    // step status (no sqlite3_changes()-style mutate-and-count race, #1033).
    // agent_version/arch: a blank incoming value preserves the existing column
    // (CASE ... THEN endpoints.x) — see the header doc comment — while
    // hostname/os/last_heartbeat_ms/agent_ts stay an unconditional EXCLUDED
    // write (pre-v2 behaviour, unchanged). session_id (HA WS-5) is likewise
    // unconditional EXCLUDED — an empty incoming value (a heartbeat that raced
    // session lookup, same race the agent_version/arch blank-preserve comment
    // above describes) blanking a previously-known session_id is harmless:
    // `remove_if_session` only ever matches a NON-empty caller-supplied value
    // against it, so a blanked column just means the NEXT disconnect's
    // session-guarded delete no-ops and the row waits out the TTL instead —
    // always safe (over-inclusion grants no dispatch authority). last_seen_at
    // is PG-authored (`now()` in-SQL, never the replica's `system_clock` —
    // the #3715 precedent) on every call, whether the row is new or existing.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO endpoint_state.endpoints "
        "(agent_id, hostname, os, last_heartbeat_ms, agent_ts, agent_version, arch, session_id, "
        "last_seen_at) "
        "VALUES ($1, $2, $3, $4::bigint, $5::bigint, $6, $7, $8, now()) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  hostname = EXCLUDED.hostname, os = EXCLUDED.os, "
        "  last_heartbeat_ms = EXCLUDED.last_heartbeat_ms, agent_ts = EXCLUDED.agent_ts, "
        "  agent_version = CASE WHEN EXCLUDED.agent_version = '' THEN endpoints.agent_version "
        "                       ELSE EXCLUDED.agent_version END, "
        "  arch = CASE WHEN EXCLUDED.arch = '' THEN endpoints.arch ELSE EXCLUDED.arch END, "
        "  session_id = EXCLUDED.session_id, last_seen_at = EXCLUDED.last_seen_at "
        "RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), std::string(hostname), std::string(os),
                                 std::to_string(last_heartbeat_ms), std::to_string(agent_ts),
                                 std::string(agent_version), std::string(arch),
                                 std::string(session_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: upsert failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "upsert", /*had_lease=*/true);
        return false;
    }
    return true;
}

std::vector<PresenceIdentity> OfflineEndpointStore::query_live_ids(std::chrono::seconds ttl) {
    std::vector<PresenceIdentity> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: query_live_ids skipped, no connection in time ({})",
                      pool_.last_error());
        record_presence_store_failure(metrics_, "query_live_ids", /*had_lease=*/false);
        return out;
    }
    // DATABASE-clock filter (`now()` in-SQL) — never the replica's own
    // `system_clock` (#3715 precedent) — so every replica agrees on which
    // rows are live regardless of local clock skew. LIMIT bounds the
    // materialised set the same way query_stale_within does.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, agent_version, arch FROM endpoint_state.endpoints "
        "WHERE last_seen_at >= now() - ($1::bigint * interval '1 second') "
        "ORDER BY last_seen_at DESC LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(ttl.count()), std::to_string(kQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: query_live_ids failed: {}", PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "query_live_ids", /*had_lease=*/true);
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        PresenceIdentity p;
        p.agent_id = PQgetvalue(res.get(), i, 0);
        p.hostname = PQgetvalue(res.get(), i, 1);
        p.os = PQgetvalue(res.get(), i, 2);
        p.agent_version = PQgetvalue(res.get(), i, 3);
        p.arch = PQgetvalue(res.get(), i, 4);
        out.push_back(std::move(p));
    }
    return out;
}

bool OfflineEndpointStore::remove_if_session(std::string_view agent_id,
                                             std::string_view session_id) {
    if (!open_ || agent_id.empty() || session_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kUpsertAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: remove_if_session skipped, no connection in time ({})",
                      pool_.last_error());
        record_presence_store_failure(metrics_, "remove_if_session", /*had_lease=*/false);
        return false;
    }
    // RETURNING, not a bare DELETE: a DELETE with a WHERE clause that matches
    // ZERO rows (the session mismatch this method exists to guard against)
    // still reports PGRES_COMMAND_OK — "the command succeeded" is not "a row
    // was deleted". RETURNING turns this into a TUPLES_OK read whose row
    // count is the actual outcome, the same idiom upsert() already uses and
    // the #1033-banning rule this codebase holds generally (never infer a
    // mutation's effect from the command status alone).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM endpoint_state.endpoints WHERE agent_id = $1 AND session_id = $2 "
        "RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), std::string(session_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: remove_if_session failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "remove_if_session", /*had_lease=*/true);
        return false;
    }
    // A zero-row RETURNING result here is a legitimate SESSION MISMATCH (the
    // guard this method exists to enforce), never a failure — no counter.
    return PQntuples(res.get()) > 0;
}

std::vector<OfflineEndpoint> OfflineEndpointStore::query_stale_within(std::chrono::seconds window) {
    std::vector<OfflineEndpoint> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: query skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    const std::int64_t window_ms = static_cast<std::int64_t>(window.count()) * 1000;
    const std::int64_t since = now_ms - window_ms;

    // LIMIT caps the materialised set (gov sec-LOW / UP-5) so the store never
    // allocates more rows than the viz page could serve, regardless of table
    // growth. Newest-first, so the cap keeps the most recently-seen hosts.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, last_heartbeat_ms, agent_ts, agent_version, arch "
        "FROM endpoint_state.endpoints "
        "WHERE last_heartbeat_ms >= $1::bigint "
        "ORDER BY last_heartbeat_ms DESC "
        "LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(since), std::to_string(kQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: query failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        OfflineEndpoint ep;
        ep.agent_id = PQgetvalue(res.get(), i, 0);
        ep.hostname = PQgetvalue(res.get(), i, 1);
        ep.os = PQgetvalue(res.get(), i, 2);
        ep.last_heartbeat_ms = to_i64(PQgetvalue(res.get(), i, 3));
        ep.agent_ts = to_i64(PQgetvalue(res.get(), i, 4));
        ep.agent_version = PQgetvalue(res.get(), i, 5);
        ep.arch = PQgetvalue(res.get(), i, 6);
        out.push_back(std::move(ep));
    }
    return out;
}

} // namespace yuzu::server
