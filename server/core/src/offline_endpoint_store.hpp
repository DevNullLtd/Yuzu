#pragma once

/// @file offline_endpoint_store.hpp
/// First born-on-Postgres server store (ADR-0006/0009 greenfield, schema
/// `endpoint_state`). Persists per-agent last-known identity + last-seen so a
/// host that drops out of the in-memory FleetTopologyStore cache (60 s TTL)
/// renders **stale-flagged** on /viz/fleet instead of vanishing. Written on
/// every heartbeat ingest (direct + gateway, via HeartbeatIngestion), read by
/// the viz topology handler. No secrets — plain columns, no SecretCodec.
///
/// **HA WS-5 (ADR-2002 §7a, governance Gate 3 architect finding, 2026-09-22):
/// this store's blast radius is WIDER than the paragraph above states.**
/// `AgentRegistry::all_ids()`/`evaluate_scope()` (via `configure_presence`)
/// merge this store's live rows into cross-replica scope-evaluation
/// visibility — a degraded/misbehaving `OfflineEndpointStore` on a
/// multi-replica deployment now affects live dispatch targeting, not only a
/// stale-cube viz render. It remains fail-SOFT for that consumer by design
/// (a read failure degrades to local-only visibility, never a wrong
/// dispatch — see `AgentRegistry::live_presence()`'s doc comment), so this
/// widening does not change the store's own posture, only who depends on it.
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`endpoint_state.endpoints`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted endpoint row — the last-known identity for an agent the
/// server has seen. Deliberately thin: enough to render a stale placeholder
/// cube, nothing that belongs to the live in-memory topology.
struct OfflineEndpoint {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::int64_t last_heartbeat_ms{0}; ///< Server wall-clock epoch ms at last ingest.
    std::int64_t agent_ts{0};          ///< Agent-emitted snapshot epoch seconds (0 if none).
    /// Round-3 v2 columns (Devices-page merge, item 1): last-known agent
    /// version/arch, so an OFFLINE row still shows a version/arch on the
    /// Hardware list instead of blanking the moment the agent drops off the
    /// live registry. Empty when never observed (pre-migration rows, or a
    /// heartbeat that raced session lookup — see upsert()'s blank-preserve
    /// note below).
    std::string agent_version;
    std::string arch;
};

/// One agent's identity as known to a DIFFERENT replica, for cross-replica
/// scope-evaluation visibility (HA WS-5, ADR-2002 §7a — see
/// `AgentRegistry::evaluate_scope`/`all_ids()`, which merge this in for ids
/// not in that replica's own local live registry, local always winning on
/// conflict). Deliberately excludes `session_id` and plugin capability: a
/// merge caller has no session concept of its own (that's WS-4's fenced
/// `GatewayRouteStore`), and plugin-capability cross-replica visibility
/// (`ids_missing_plugin`) is out of this slice's scope — see WS-5's plan doc.
struct PresenceIdentity {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string agent_version;
    std::string arch;
};

class OfflineEndpointStore {
public:
    /// Borrows the shared pool and runs the `endpoint_state` schema migration
    /// on a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (the server fails closed before reaching here, so in
    /// production the migration runs against a proven-reachable database).
    explicit OfflineEndpointStore(pg::PgPool& pool);

    OfflineEndpointStore(const OfflineEndpointStore&) = delete;
    OfflineEndpointStore& operator=(const OfflineEndpointStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// HA WS-5 governance hardening (Gate 3 sre finding, 2026-09-22):
    /// `query_live_ids`/`remove_if_session` are fail-soft by design (see
    /// their own doc comments — a read failure degrades to local-only
    /// visibility, never a wrong dispatch), but fail-soft must not mean
    /// fail-INVISIBLE now that this store is load-bearing for cross-replica
    /// scope-evaluation correctness. Set ONCE during single-threaded
    /// startup, before serving threads read it without synchronisation —
    /// same idiom as `AppPerfDailyStore::set_metrics` and its siblings. Null
    /// (the default, e.g. unit tests / pre-WS-5 callers) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Upsert one agent's last-known identity + last-seen. Best-effort: returns
    /// false (logged at debug) on an empty lease or a query error so a slow or
    /// blipping database never fails the heartbeat path — the live in-memory
    /// stores remain the source of truth; this is durability on top. Single
    /// statement, autocommit, `INSERT ... ON CONFLICT ... RETURNING`.
    ///
    /// `agent_version`/`arch` (round-3 v2 columns): a BLANK value on the
    /// incoming row NEVER overwrites an already-known non-blank value —
    /// `hostname`/`os` are the ONE per-ingest source of truth (unconditional
    /// EXCLUDED write, matching the pre-v2 columns), but a heartbeat that
    /// raced the session lookup (registry lookup miss) supplies "" here, and
    /// must not blank out a version/arch this store already learned from an
    /// earlier heartbeat for the same agent.
    bool upsert(std::string_view agent_id, std::string_view hostname, std::string_view os,
                std::int64_t last_heartbeat_ms, std::int64_t agent_ts,
                std::string_view agent_version = {}, std::string_view arch = {},
                std::string_view session_id = {});

    /// Every endpoint whose last heartbeat is within `window` of now, newest
    /// first. The viz handler renders those NOT currently online as stale
    /// cubes; rows older than `window` are withheld so a long-departed host
    /// eventually stops cluttering the view. Empty on error (fail-soft: the
    /// page still renders the live fleet).
    [[nodiscard]] std::vector<OfflineEndpoint> query_stale_within(std::chrono::seconds window);

    /// HA WS-5: every agent whose `last_seen_at` is within `ttl` of the
    /// DATABASE clock (`now()` in-SQL, never the replica's own
    /// `system_clock` — the #3715 precedent), for cross-replica
    /// scope-evaluation visibility. Fail-soft: empty on any read error —
    /// presence only WIDENS visibility (it grants no dispatch authority; see
    /// `AgentRegistry::evaluate_scope`), so a degraded read just means "see
    /// local agents only" for that one call, never a hard failure.
    [[nodiscard]] std::vector<PresenceIdentity> query_live_ids(std::chrono::seconds ttl);

    /// Session-guarded delete (HA WS-5): removes the row ONLY when its
    /// stored `session_id` matches — mirrors
    /// `AgentRegistry::remove_agent_if_session`, so a stale/superseded
    /// session's disconnect can never delete a NEWER session's presence
    /// row. Called on graceful disconnect so a departed agent's row does
    /// not linger for the full liveness window — needed to keep the
    /// single-replica monolith's `evaluate_scope` outcome unchanged from
    /// pre-WS-5 behavior (an agent gone from the local registry must also
    /// be gone from presence, not just eventually-stale). Best-effort like
    /// `upsert()`: a failure here just means the row lingers until TTL
    /// expiry, which is always safe (over-inclusion never grants dispatch
    /// authority).
    bool remove_if_session(std::string_view agent_id, std::string_view session_id);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
