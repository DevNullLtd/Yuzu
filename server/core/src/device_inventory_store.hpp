#pragma once

/// @file device_inventory_store.hpp
/// Born-on-Postgres typed device-CI projection (ADR-0016, schema
/// `device_inventory_store`). The read-optimized home for the daily-sync
/// framework's `device_ci` source — one row per agent holding the machine's
/// stable hardware / OS identity (a ServiceNow-CMDB-style configuration item),
/// so a device's asset record survives offline.
///
/// COEXISTS with `SoftwareInventoryStore` (the `installed_software` projection)
/// and `AppPerfDailyStore` (`app_perf`) — each daily-sync source that needs typed
/// fleet reads gets its own born-on-PG store. Device-CI is **1:1 per agent**
/// (unlike software's 1:N rows), so the projection is a single table, replaced
/// wholesale on change.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement, uses
/// `RETURNING`. Normalized columns only — NO JSONB. Failure posture (ADR-0012 §1 /
/// ADR-0016 §7):
///   - **Ingest:** fail-soft — a transient PG outage returns kError + nacks; the
///     next sync + the weekly full-floor self-heal.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure is reported as
///     `kDegraded` (reads) / `std::nullopt` (list), NEVER a silent empty (an empty
///     CI roster reads as "no devices", the fail-open ADR-0016 §7 forbids).
///   - `last_seen`/`first_seen` are the **SERVER receipt time**, never the
///     agent-supplied `collected_at` (the #1685 lesson, baked in from day one).

#include "inventory_ingest_outcome.hpp" // InventoryIngestOutcome (shared sync-ingest vocabulary)

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

/// One device-CI record — the typed projection of the `device_ci` canonical wire
/// blob. All collected fields are carried as strings (the exact wire bytes, so
/// `canonical_hash` reproduces the agent's hash); the numeric fields are
/// ADDITIONALLY persisted to BIGINT columns (`apply` parses them). Field order here
/// IS the canonical-blob order (see the agent's `CiRecord` /
/// `device_ci_ingestion.cpp`) — adding/reordering is a coordinated cross-side change.
struct DeviceCiRecord {
    std::string agent_id; ///< not in the blob; set by the ingest seam / read
    std::string manufacturer;
    std::string model;
    std::string serial;
    std::string system_uuid;
    std::string hostname;
    std::string domain;
    std::string ou;
    std::string bios_vendor;
    std::string bios_version;
    std::string bios_date;
    std::string cpu_model;
    std::string cpu_cores;   ///< decimal string (also persisted to BIGINT)
    std::string cpu_threads; ///< decimal string (also persisted to BIGINT)
    std::string ram_bytes;   ///< decimal string (also persisted to BIGINT)
    std::string disks_summary;
    std::string primary_mac;
    std::string macs_summary;
    std::string nic_count; ///< decimal string (also persisted to BIGINT)
    std::string os_name;
    std::string os_version;
    std::string os_build;
    std::string arch;
    std::int64_t first_seen{0}; ///< server receipt time (epoch seconds)
    std::int64_t last_seen{0};  ///< server receipt time (epoch seconds)
};

/// Error type for the authoritative single-record read. The success type is
/// `std::optional<DeviceCiRecord>`: a value == found, `std::nullopt` == absent
/// (read succeeded, no CI record for this agent yet). `std::unexpected(kDegraded)`
/// == store/pool/query failure (the caller shows an error banner vs a "not yet
/// synced" note). Out-params are forbidden in new code (docs/cpp-conventions.md) —
/// hence `std::expected` rather than an enum + out-param.
enum class CiReadError { kDegraded };

class DeviceInventoryStore {
public:
    /// Borrows the shared pool and runs the `device_inventory_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was empty
    /// or the migration failed (the server fails closed before reaching here).
    explicit DeviceInventoryStore(pg::PgPool& pool);

    DeviceInventoryStore(const DeviceInventoryStore&) = delete;
    DeviceInventoryStore& operator=(const DeviceInventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry (read-degrade counter). Set ONCE during
    /// single-threaded startup; read without synchronisation on serving threads.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Canonical content hash over a device-CI record — the SAME bytes the agent
    /// hashes (`device_ci_canonical_blob` + SHA-256). The record's fields are
    /// assumed already UTF-8-scrubbed + clamped by the ingest seam's parse (mirrors
    /// `SoftwareInventoryStore::canonical_hash`, which trusts the seam's clamp), so
    /// this joins positionally + hashes; it does NOT re-clamp. Pure/deterministic.
    [[nodiscard]] static std::string canonical_hash(const DeviceCiRecord& rec);

    /// Hash-skip ingest for the `device_ci` source (ADR-0016 §4).
    ///  - `rec == std::nullopt` → hash-only report: compare `claimed_hash` against
    ///    the stored hash. Match → bump last_seen (kTouched); no row or mismatch →
    ///    kNeedFull.
    ///  - `rec` set → full payload: the server **recomputes** the canonical hash
    ///    from the record (never trusts `claimed_hash`) and upserts the single row →
    ///    kStored. `first_seen` is preserved across updates; `last_seen` is the
    ///    server receipt time.
    /// `collected_at` is part of the contract (proto-carried) but drives no
    /// persisted timestamp (#1685). `rec` is taken by value (moved into the upsert).
    InventoryIngestOutcome apply_device_ci(std::string_view agent_id, std::string_view claimed_hash,
                                           std::optional<DeviceCiRecord> rec,
                                           std::int64_t collected_at);

    /// One agent's CI record (per-device drill). Authoritative: `std::unexpected(
    /// CiReadError::kDegraded)` on a store/pool/query failure; a value holding
    /// `std::nullopt` when there is genuinely no row; a value holding the record
    /// when found.
    [[nodiscard]] std::expected<std::optional<DeviceCiRecord>, CiReadError>
    get_device_ci(std::string_view agent_id);

    /// The whole device-CI roster (the PR2 devices tab source), hostname-sorted,
    /// capped at a hard ceiling regardless of `limit`. Authoritative: `std::nullopt`
    /// on a store/pool/query degrade, NEVER a silent empty. An empty value = no rows.
    [[nodiscard]] std::optional<std::vector<DeviceCiRecord>> list_device_ci(int limit);

    /// Drop an agent's CI record (e.g. on agent removal). Returns true iff the
    /// DELETE executed (COMMAND_OK); false on a closed store, a lease timeout, or
    /// a SQL failure — so the decommission cascade records Failed, not a false
    /// "erased".
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
