#include "offline_endpoint_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/pg_retention_guard.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string_view>
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
// Retention-prune guard constants (#5678 / #1545 UP-4; see run_retention_prune).
// big step floor 7 d: the prune runs hourly per replica, and a weekend/holiday
// shutdown of a lab server must not decline — 7 d is still far below the 37 d
// window. Implausibility 1 d: the prune keys on last_seen_at (PG-authored, so
// never future-dated), and only a small forward skew is tolerated in the
// would-wipe denominator.
constexpr std::int64_t kPruneBigStepFloorMs = 7LL * 24 * 3600 * 1000;
constexpr std::int64_t kPruneImplausibilityMs = 24LL * 3600 * 1000;
constexpr std::int64_t kPruneMinPlausibleMs = 946'684'800'000LL; // 2000-01-01
// kQueryRowCap moved to OfflineEndpointStore::kQueryRowCap (public,
// offline_endpoint_store.hpp) so query_live_ids's truncation test (#4981
// PR-1) can size its fixture against the real value.

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
        // HA WS-5 (ADR-2002 §7a): `session_id` guards a targeted session clear on
        // graceful disconnect (remove_if_session; the row is kept for the
        // offline roster, #5678) so a stale session's
        // teardown can't clobber a newer re-registration's row; `last_seen_at`
        // is a PG-authored (`now()` in-SQL) liveness clock, separate from the
        // pre-existing `last_heartbeat_ms` replica-clock column (which stays
        // exactly as-is for the roster path — see query_stale_within).
        {3,
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS session_id TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL "
         "DEFAULT now();"
         "CREATE INDEX IF NOT EXISTS endpoints_last_seen_idx ON endpoints (last_seen_at);"},
        // #5678 / #1545 UP-4: retention_meta backs pg::run_clock_guarded_prune
        // (anchor + bootstrap-settled + anomaly-facts rows) for the endpoint prune.
        {4, "CREATE TABLE IF NOT EXISTS retention_meta ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
    };
    return kMigrations;
}

bool ieq(std::string_view a, std::string_view b) {
    return std::ranges::equal(a, b, [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) ==
               std::tolower(static_cast<unsigned char>(y));
    });
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
//
// #4981 PR-1 (Finding B): `reason_override` widens the label set to include
// "truncated" (a `query_live_ids` result past `kQueryRowCap`, distinct from
// both a connection failure and a query error) without disturbing the
// `had_lease`-derived default any other caller still relies on.
void record_presence_store_failure(yuzu::MetricsRegistry* metrics, std::string_view op,
                                   bool had_lease, const char* reason_override = nullptr) {
    const char* reason = reason_override ? reason_override : (had_lease ? "db_error" : "store_unavailable");
    if (metrics) {
        metrics
            ->counter("yuzu_server_agent_presence_store_failed_total",
                      {{"op", std::string(op)}, {"reason", reason}})
            .increment();
    }
}

} // namespace

FleetPlatform fleet_platform_of(std::string_view os) {
    if (ieq(os, "windows") || ieq(os, "win"))
        return FleetPlatform::Windows;
    if (ieq(os, "linux") || ieq(os, "lin"))
        return FleetPlatform::Linux;
    if (ieq(os, "darwin") || ieq(os, "macos") || ieq(os, "mac"))
        return FleetPlatform::MacOs;
    return FleetPlatform::Other;
}

FleetStatePartition partition_fleet_state(std::int64_t total, std::int64_t online,
                                          std::int64_t stale) noexcept {
    FleetStatePartition p;
    total = std::max<std::int64_t>(total, 0);
    p.online = std::clamp<std::int64_t>(online, 0, total);
    p.not_seen = std::clamp<std::int64_t>(stale, 0, total - p.online);
    p.offline = total - p.online - p.not_seen;
    return p;
}

FleetEstateReading reconcile_fleet_estate(std::int64_t total, std::int64_t online,
                                          std::int64_t stale) noexcept {
    total = std::max<std::int64_t>(total, 0);
    online = std::max<std::int64_t>(online, 0);
    FleetEstateReading r;
    r.lower_bound = online > total;
    r.total = std::max(total, online);
    const auto p = partition_fleet_state(r.total, online, stale);
    r.online = p.online;
    r.not_seen = p.not_seen;
    r.offline = p.offline;
    return r;
}

FleetEstateReading fleet_estate_reading(const FleetStateCounts& counts,
                                        std::optional<std::size_t> registry_known) noexcept {
    const std::int64_t online =
        registry_known ? static_cast<std::int64_t>(*registry_known) : counts.live;
    return reconcile_fleet_estate(counts.total, online, counts.stale);
}

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
    // agent_version/arch/os: a blank incoming value preserves the existing
    // column (CASE ... THEN endpoints.x) — see the header doc comment — while
    // last_heartbeat_ms/agent_ts stay an unconditional EXCLUDED write
    // (pre-v2 behaviour, unchanged). hostname blank-preserves too (HA WS-5): a
    // replica holding no local AgentSession for a gateway-fronted agent
    // ingests its heartbeat with a blank hostname, which must not erase the
    // owning replica's value. os blank-preserves (#5294): the
    // per-OS kill-switch filter reads it for remote ids, and a heartbeat that
    // missed the session lookup must not erase a known OS. session_id (HA WS-5)
    // blank-preserves too (#5678): a heartbeat that raced the session lookup on
    // a LIVE agent keeps its stored session_id, so it stays present. A blank
    // session on a NEW or just-departed row leaves session_id '' — the agent is
    // NOT present (query_live_ids requires a non-blank session_id) until a
    // session-carrying heartbeat; the accepted fail-closed residual. The same
    // holds for a departed gateway agent that reconnects through a replica whose
    // session-directory lookup is degraded: it stays absent from presence for
    // the duration of the degradation.
    // last_seen_at is PG-authored (`now()` in-SQL, never the replica's
    // `system_clock` — the #3715 precedent) on every call, whether the row is
    // new or existing.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO endpoint_state.endpoints "
        "(agent_id, hostname, os, last_heartbeat_ms, agent_ts, agent_version, arch, session_id, "
        "last_seen_at) "
        "VALUES ($1, $2, $3, $4::bigint, $5::bigint, $6, $7, $8, now()) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  hostname = CASE WHEN EXCLUDED.hostname = '' THEN endpoints.hostname "
        "                  ELSE EXCLUDED.hostname END, "
        "  os = CASE WHEN EXCLUDED.os = '' THEN endpoints.os ELSE EXCLUDED.os END, "
        "  last_heartbeat_ms = EXCLUDED.last_heartbeat_ms, agent_ts = EXCLUDED.agent_ts, "
        "  agent_version = CASE WHEN EXCLUDED.agent_version = '' THEN endpoints.agent_version "
        "                       ELSE EXCLUDED.agent_version END, "
        "  arch = CASE WHEN EXCLUDED.arch = '' THEN endpoints.arch ELSE EXCLUDED.arch END, "
        "  session_id = CASE WHEN EXCLUDED.session_id = '' THEN endpoints.session_id "
        "                    ELSE EXCLUDED.session_id END, "
        "  last_seen_at = EXCLUDED.last_seen_at "
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

std::expected<std::vector<PresenceIdentity>, PresenceReadError>
OfflineEndpointStore::query_live_ids(std::chrono::seconds ttl) {
    if (!open_)
        return std::unexpected(PresenceReadError::StoreUnavailable);
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: query_live_ids skipped, no connection in time ({})",
                      pool_.last_error());
        record_presence_store_failure(metrics_, "query_live_ids", /*had_lease=*/false);
        return std::unexpected(PresenceReadError::StoreUnavailable);
    }
    // DATABASE-clock filter (`now()` in-SQL) — never the replica's own
    // `system_clock` (#3715 precedent) — so every replica agrees on which
    // rows are live regardless of local clock skew. LIMIT is kQueryRowCap+1,
    // not kQueryRowCap (#4981 PR-1): fetching one row past the cap is how a
    // truncated result is DETECTED (a row count of exactly kQueryRowCap is
    // ambiguous — it could be the true, complete live set) rather than
    // silently dropped.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, agent_version, arch FROM endpoint_state.endpoints "
        "WHERE last_seen_at >= now() - ($1::bigint * interval '1 second') "
        "  AND session_id <> '' "
        "ORDER BY last_seen_at DESC LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(ttl.count()),
                                 std::to_string(kQueryRowCap + 1)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: query_live_ids failed: {}", PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "query_live_ids", /*had_lease=*/true);
        return std::unexpected(PresenceReadError::DbError);
    }
    const int rows = PQntuples(res.get());
    if (rows > kQueryRowCap) {
        spdlog::warn("OfflineEndpointStore: query_live_ids result exceeds kQueryRowCap ({}) — "
                     "reporting Truncated rather than a partial set",
                     kQueryRowCap);
        record_presence_store_failure(metrics_, "query_live_ids", /*had_lease=*/true, "truncated");
        return std::unexpected(PresenceReadError::Truncated);
    }
    std::vector<PresenceIdentity> out;
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
    // Presence CLEAR, not a delete (#5678): the row stays so the offline-
    // inclusive /hardware roster keeps listing the device with its real last
    // heartbeat; blanking session_id removes it from query_live_ids.
    // RETURNING, not a bare UPDATE: an UPDATE matching ZERO rows (the session
    // mismatch this method exists to guard against) still reports
    // PGRES_COMMAND_OK, so RETURNING turns the outcome into a row count (the
    // same idiom upsert() uses; never infer a mutation's effect from the
    // command status alone, #1033).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE endpoint_state.endpoints SET session_id = '' "
        "WHERE agent_id = $1 AND session_id = $2 RETURNING agent_id",
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

int OfflineEndpointStore::run_retention_prune(std::chrono::seconds roster_window) {
    if (!open_)
        return -1;
    // #5678 / #1545 UP-4: clock-guarded capped retention. Missing-anchor =
    // Decline: a device's last-seen evidence is non-regenerable, so a
    // from-boot skewed clock must not delete it (preflight_run_store's answer).
    // Window, clock domains and cadence: docs/clock-guarded-retention.md register row.
    // The timestamp is last_seen_at (PG now() on every upsert), NOT the roster's
    // replica-authored last_heartbeat_ms: column and cutoff then share the PG
    // clock domain, so a lagging or future-stamped replica clock can neither
    // expire a live row nor make a dead one immortal. The epoch-ms expression
    // cannot use endpoints_last_seen_idx (hourly seq scan over a fleet-bounded
    // table, bounded by the pool's statement_timeout).
    const auto window_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(roster_window + kPruneMargin)
            .count();
    const pg::ClockGuardedPruneSpec spec{
        .store_label = kStoreName,
        .target_table = "endpoint_state.endpoints",
        .ts_column = "(EXTRACT(EPOCH FROM last_seen_at)*1000)::bigint",
        .now_expr = "(EXTRACT(EPOCH FROM now())*1000)::bigint",
        .meta_table = "endpoint_state.retention_meta",
        .anchor_key = "endpoints_prune_last_pass_now",
        .settled_key = "endpoints_prune_bootstrap_settled",
        .facts_key = "endpoints_prune_last_anomaly_facts",
        .advisory_lock_key = "hashtext('endpoint_state:endpoints_prune')",
        .retention_window = static_cast<std::int64_t>(window_ms),
        .big_step_floor = kPruneBigStepFloorMs,
        .implausibility_bound = kPruneImplausibilityMs,
        .min_plausible_reading = kPruneMinPlausibleMs,
        .cap_per_pass = kPruneCapPerPass,
        .missing_anchor = pg::MissingAnchorPolicy::Decline,
    };
    const auto r = pg::run_clock_guarded_prune(pool_, spec, kQueryAcquireTimeout);
    return r.error ? -1 : r.deleted;
}

bool OfflineEndpointStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    // An operator request, not the heartbeat path: the longer user-facing bound.
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: delete_agent skipped for agent={}, no connection in "
                      "time ({})",
                      agent_id, pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM endpoint_state.endpoints WHERE agent_id = $1 RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: delete_agent failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

std::expected<std::vector<OfflineEndpoint>, PresenceReadError>
OfflineEndpointStore::query_stale_within(std::chrono::seconds window) {
    std::vector<OfflineEndpoint> out;
    if (!open_)
        return std::unexpected(PresenceReadError::StoreUnavailable);
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("OfflineEndpointStore: query_stale_within failed, no connection in time ({})",
                     pool_.last_error());
        record_presence_store_failure(metrics_, "query_stale_within", /*had_lease=*/false);
        return std::unexpected(PresenceReadError::StoreUnavailable);
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
        spdlog::warn("OfflineEndpointStore: query_stale_within failed: {}",
                     PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "query_stale_within", /*had_lease=*/true);
        return std::unexpected(PresenceReadError::DbError);
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

std::expected<FleetStateCounts, PresenceReadError>
OfflineEndpointStore::fleet_state_counts(std::int64_t now_ms, std::chrono::seconds window,
                                         std::chrono::milliseconds stale_after,
                                         std::chrono::seconds live_ttl) {
    if (!open_)
        return std::unexpected(PresenceReadError::StoreUnavailable);
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("OfflineEndpointStore: fleet_state_counts failed, no connection in time ({})",
                     pool_.last_error());
        record_presence_store_failure(metrics_, "fleet_state_counts", /*had_lease=*/false);
        return std::unexpected(PresenceReadError::StoreUnavailable);
    }
    const std::int64_t since = now_ms - static_cast<std::int64_t>(window.count()) * 1000;
    const std::int64_t stale_before = now_ms - stale_after.count();

    // One statement, one row per distinct lower(os) (a handful). The platform
    // bucketing happens in fleet_platform_of so the SQL never restates the
    // spelling list. Same window predicate as query_stale_within.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT lower(os), COUNT(*), COUNT(*) FILTER (WHERE last_heartbeat_ms < $2::bigint), "
        // Same liveness predicate as query_live_ids (DB clock, non-blank session).
        "COUNT(*) FILTER (WHERE session_id <> '' "
        "  AND last_seen_at >= now() - ($3::bigint * interval '1 second')) "
        "FROM endpoint_state.endpoints WHERE last_heartbeat_ms >= $1::bigint GROUP BY lower(os)",
        std::vector<std::string>{std::to_string(since), std::to_string(stale_before),
                                 std::to_string(live_ttl.count())});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("OfflineEndpointStore: fleet_state_counts failed: {}",
                     PQerrorMessage(lease.get()));
        record_presence_store_failure(metrics_, "fleet_state_counts", /*had_lease=*/true);
        return std::unexpected(PresenceReadError::DbError);
    }
    FleetStateCounts c;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        const std::int64_t n = to_i64(PQgetvalue(res.get(), i, 1));
        c.total += n;
        c.stale += to_i64(PQgetvalue(res.get(), i, 2));
        c.live += to_i64(PQgetvalue(res.get(), i, 3));
        switch (fleet_platform_of(PQgetvalue(res.get(), i, 0))) {
            case FleetPlatform::Windows: c.windows += n; break;
            case FleetPlatform::Linux: c.linux_os += n; break;
            case FleetPlatform::MacOs: c.macos += n; break;
            case FleetPlatform::Other: c.other += n; break;
        }
    }
    return c;
}

} // namespace yuzu::server
