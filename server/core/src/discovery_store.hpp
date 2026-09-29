#pragma once

/// @file discovery_store.hpp
/// Migrated Postgres store (ADR-0006/0009, schema `discovery_store`) for
/// network-discovered devices (Issue 7.18) — the raw scan results agents
/// report before an operator promotes a device to a managed agent. Single
/// table, no foreign keys, no secret-bearing columns.
///
/// Posture per ADR-0012 §1: **authoritative** — the operator-set `managed`
/// flag and discovery history are real state, not expendable telemetry (Wave
/// 2's "operator state that cannot be lost" framing). A runtime error is
/// surfaced via `std::expected`/`std::optional`, never papered over with a
/// silent empty/false result.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`discovery_store.discovered_devices`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.
///
/// `upsert_device`'s `ON CONFLICT (ip_address)` preserves the legacy SQLite
/// semantics verified against `discovery_store.cpp`'s prior implementation:
/// `mac_address`/`last_seen`/`subnet` are overwritten (most-recent-seen),
/// `hostname` is overwritten only when the new value is non-empty (a later
/// scan that could not resolve a hostname does not blank out a previously
/// known one), and `discovered_at`/`discovered_by`/`managed`/`agent_id` are
/// NOT touched by the ON CONFLICT branch — first-seen discovery provenance is
/// preserved, and a re-scan of an already-managed device cannot un-manage it
/// (that is `mark_managed`'s job alone).
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b,
/// #3623): no production fleet ever ran a pre-Postgres build of this store —
/// see ADR-0044's Update. `server.cpp` now runs a detect-and-warn probe over
/// the legacy file instead.

#include <cstdint>
#include <expected>
#include <optional>
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

struct DiscoveredDevice {
    std::int64_t id{0};
    std::string ip_address;
    std::string mac_address;
    std::string hostname;
    bool managed{false};       ///< true if IP matches a known enrolled agent
    std::string agent_id;      ///< agent_id if managed
    std::string discovered_by; ///< agent_id of the agent that discovered this device
    std::int64_t discovered_at{0}; ///< epoch seconds, first-seen (preserved across upserts)
    std::int64_t last_seen{0};     ///< epoch seconds, most-recent-seen
    std::string subnet;            ///< the subnet that was scanned
};

class DiscoveryStore {
public:
    /// Borrows the shared pool and runs the `discovery_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here in production).
    explicit DiscoveryStore(pg::PgPool& pool);

    DiscoveryStore(const DiscoveryStore&) = delete;
    DiscoveryStore& operator=(const DiscoveryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_server_discovery_read_degrade_total{reason}`). Set ONCE during
    /// single-threaded startup, before serving; a null registry (default,
    /// e.g. unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Insert a new device or refresh an existing one keyed by `ip_address`
    /// (the UNIQUE natural key). See the header doc for the exact
    /// preserved-vs-overwritten column contract. `ip_address` empty is a
    /// precondition miss. AUTHORITATIVE write: `std::unexpected(msg)` on a
    /// store/pool/query failure, never a silently-dropped write.
    [[nodiscard]] std::expected<void, std::string>
    upsert_device(const DiscoveredDevice& device);

    /// Every discovered device, optionally filtered to one subnet, newest
    /// last-seen first. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query failure — NEVER a silent empty (an empty *value* is a
    /// genuinely empty result).
    [[nodiscard]] std::optional<std::vector<DiscoveredDevice>>
    list_devices(const std::string& subnet_filter = {});

    /// One device by `ip_address`. AUTHORITATIVE read: `std::unexpected(msg)`
    /// on a store/pool/query failure; a value holding `std::nullopt` when
    /// genuinely absent; a value holding the row when found.
    [[nodiscard]] std::expected<std::optional<DiscoveredDevice>, std::string>
    get_device(const std::string& ip_address);

    /// Mark a discovered device managed, recording the enrolled `agent_id`.
    /// `std::unexpected("not_found: ...")` (machine-checkable prefix) when no
    /// device with this `ip_address` exists; any other `unexpected(msg)` is a
    /// genuine write failure.
    [[nodiscard]] std::expected<void, std::string>
    mark_managed(const std::string& ip_address, const std::string& agent_id);

    /// Delete discovery results — every row, or only one subnet's.
    /// AUTHORITATIVE write: `std::unexpected(msg)` on a store/pool/query
    /// failure.
    [[nodiscard]] std::expected<void, std::string>
    clear_results(const std::string& subnet = {});

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
