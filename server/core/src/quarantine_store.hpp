#pragma once

/// @file quarantine_store.hpp
/// Migrated Postgres store (ADR-0006/0009, schema `quarantine_store`) for
/// Guardian device-quarantine bookkeeping — which agents are currently
/// network-isolated, who isolated them, why, and the full history. Single
/// table, no foreign keys, no secret-bearing columns.
///
/// Posture per ADR-0012 §1: **authoritative** — an active quarantine record
/// is live security containment state, not expendable telemetry (per
/// `docs/yuzu-guardian-design-v1.1.md` §11.7, "Quarantine is a terminal
/// state" that persists until an administrator explicitly lifts it). A
/// runtime error is surfaced via `std::expected`/`std::optional`, never
/// papered over with a silent empty/false result — a `get_status` or
/// `list_quarantined` that silently degraded to "not quarantined" / "nothing
/// quarantined" would mask an ACTIVE containment (fail-open).
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`quarantine_store.quarantine_records`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.
///
/// "At most one active record per agent" is enforced by a partial unique
/// index (`quarantine_records(agent_id) WHERE status = 'active'`), not an
/// in-process mutex — `quarantine_device` is a single `ON CONFLICT ... DO
/// NOTHING` statement, race-safe under concurrent Postgres connections in a
/// way the legacy SQLite `shared_mutex` (scoped to one `sqlite3*` handle)
/// never had to be. `release_device` is a single guarded `UPDATE ... WHERE
/// status = 'active'` (the #3062 `cancel_job` pattern), not lock-then-check.
///
/// Out of scope: the agent-side quarantine firewall enforcement (§11.7) is
/// untouched — this store is only the server-side bookkeeping.
///
/// `migrate_from_sqlite()` retired (#3623, ADR-0047 Update): no production fleet ever ran a
/// pre-Postgres build of this store, so the mandatory fingerprint-verified backfill it
/// implemented (fingerprint-verified per the ADR-0040/RbacStore/DiscoveryStore reference shape,
/// with a design difference from DiscoveryStore's — see ADR-0047 "no natural per-row key")
/// never had real legacy data to protect. `server.cpp` now runs
/// `legacy_sqlite_probe::warn_if_legacy_rows` over `quarantine_records` instead — silent
/// unless real rows are found, never blocks boot.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Prefix on every `quarantine_device`/`release_device` `unexpected(msg)`
/// that reflects a genuine store/pool/query failure (as opposed to a
/// business/state error like "already quarantined") — the route classifier
/// (`rest_api_v1.cpp`) keys off this to answer 503 rather than 400, mirroring
/// `DeploymentStore::kDeploymentDbErrorPrefix` (adversarial-review MEDIUM
/// hardening round, 2026-08-12: write routes previously collapsed every
/// failure, including genuine outages, to 400). A future rename of this
/// prefix must not silently regress every classified 503 back to 400 —
/// callers key off the shared constant, never a local copy of the literal.
inline constexpr const char* kQuarantineDbErrorPrefix = "db_error: ";

struct QuarantineRecord {
    // #3425 governance Gate 4 (unhappy-path, Finding A): the row's own
    // primary key — NOT exposed on REST/MCP (wire surfaces stay unchanged),
    // used ONLY to scope `mark_endpoint_applied`/`mark_endpoint_confirmed`'s
    // guarded UPDATE to the SPECIFIC record a dispatch/status-read was
    // actually about. `agent_id`+`status='active'` alone is not a stable
    // identity: a release-then-requarantine sequence lands a NEW active row
    // for the same `agent_id` while a reconcile cycle for the OLD row is
    // still in flight, and without `id` scoping the stamp write silently
    // lands on the NEW row (whose whitelist was never actually dispatched).
    std::int64_t id{0};
    std::string agent_id;
    std::string status; // "active" or "released"
    std::string quarantined_by;
    std::int64_t quarantined_at{0};
    std::int64_t released_at{0};
    std::string whitelist; // comma-separated IPs
    std::string reason;
    // Schema v2 (#3425): 0 = never, matching `released_at`'s existing
    // never-happened sentinel on this same table — no optional plumbing.
    // Written ONLY by QuarantineContainmentReconciler. `last_applied_at` is
    // set when a system re-dispatch of the STORED whitelist is accepted by
    // the plugin registry (agents_reached > 0); `last_confirmed_at` is set
    // only after a FOLLOW-UP `quarantine.status` read reports `state|active`
    // — dispatch acceptance is not proof of endpoint containment (the same
    // distinction `quarantine_dispatch_decision.hpp` draws for the MCP path).
    std::int64_t last_applied_at{0};
    std::int64_t last_confirmed_at{0};
};

class QuarantineStore {
public:
    /// Borrows the shared pool and runs the `quarantine_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here in production).
    explicit QuarantineStore(pg::PgPool& pool);

    QuarantineStore(const QuarantineStore&) = delete;
    QuarantineStore& operator=(const QuarantineStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_server_quarantine_read_degrade_total{reason}`). Set ONCE during
    /// single-threaded startup, before serving; a null registry (default,
    /// e.g. unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // ── Quarantine operations ────────────────────────────────────────────

    /// Quarantine a device. `std::unexpected("device is already
    /// quarantined")` when an active record already exists for `agent_id`
    /// (the partial unique index conflict, a business/state error — 400 at
    /// REST); any other `unexpected(msg)` a genuine store/pool/query
    /// failure, prefixed `kQuarantineDbErrorPrefix` so the REST route
    /// classifies it 503. AUTHORITATIVE write.
    [[nodiscard]] std::expected<void, std::string>
    quarantine_device(const std::string& agent_id, const std::string& by,
                      const std::string& reason, const std::string& whitelist);

    /// Release a device from quarantine. `std::unexpected("device is not
    /// quarantined")` when no active record exists for `agent_id` (a
    /// business/state error — 400 at REST); any other `unexpected(msg)` a
    /// genuine store/pool/query failure, prefixed `kQuarantineDbErrorPrefix`
    /// so the REST route classifies it 503. AUTHORITATIVE write.
    [[nodiscard]] std::expected<void, std::string> release_device(const std::string& agent_id);

    /// The current active record for `agent_id`, if any. AUTHORITATIVE read:
    /// `std::unexpected(msg)` on a store/pool/query failure (prefixed
    /// `kQuarantineDbErrorPrefix`); a value holding `std::nullopt` when
    /// genuinely not quarantined (including an empty `agent_id`, a
    /// precondition miss); a value holding the row when found.
    [[nodiscard]] std::expected<std::optional<QuarantineRecord>, std::string>
    get_status(const std::string& agent_id);

    /// Every currently-active quarantine record, newest first.
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure —
    /// NEVER a silent empty (an empty *value* is a genuinely empty result).
    [[nodiscard]] std::optional<std::vector<QuarantineRecord>> list_quarantined();

    /// #3425: record that a system-initiated re-dispatch of the STORED
    /// whitelist was accepted by the plugin registry (agents_reached > 0) —
    /// NOT proof of endpoint containment, see `mark_endpoint_confirmed`.
    /// Sole writer: `QuarantineContainmentReconciler`. `record_id` MUST be
    /// the `QuarantineRecord::id` the dispatch was actually built from
    /// (governance Gate 4, unhappy-path Finding A) — the guarded UPDATE is
    /// scoped `WHERE id = record_id AND agent_id = ... AND status =
    /// 'active'`, so a release-then-requarantine race that swaps in a NEW
    /// active row for the same `agent_id` between the read and this write
    /// affects zero rows here (misattributing the stamp to the new,
    /// never-actually-dispatched record) rather than silently succeeding
    /// against the wrong row. `std::unexpected(msg)` prefixed
    /// `kQuarantineDbErrorPrefix` on a genuine store/pool/query failure;
    /// `std::unexpected("device is not quarantined")` (unprefixed business
    /// error, matching `release_device`) when the guarded UPDATE returned
    /// zero rows — covers BOTH "released, nothing active" and "superseded by
    /// a different active record" identically; every existing caller's
    /// handling (erase in-memory state, let the record re-enter fresh next
    /// cycle) is correct for either cause, so this is one error string, not
    /// a fork.
    [[nodiscard]] std::expected<void, std::string>
    mark_endpoint_applied(const std::string& agent_id, std::int64_t record_id, std::int64_t at);

    /// #3425: record that a FOLLOW-UP `quarantine.status` read confirmed
    /// `state|active` on the device's own firewall — the only signal this
    /// store treats as proof of endpoint containment. Same `record_id`
    /// scoping and error contract as `mark_endpoint_applied`.
    [[nodiscard]] std::expected<void, std::string>
    mark_endpoint_confirmed(const std::string& agent_id, std::int64_t record_id, std::int64_t at);

    /// Full quarantine history (active and released) for `agent_id`, newest
    /// first. AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// failure; an empty vector for a genuinely empty `agent_id` or a
    /// genuinely history-less agent.
    [[nodiscard]] std::optional<std::vector<QuarantineRecord>>
    get_history(const std::string& agent_id);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
