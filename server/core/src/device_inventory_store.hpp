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
/// (unlike software's 1:N rows), so the parent is a single row, replaced wholesale on
/// change. The v2 blob adds typed per-kind child tables (cpu, dimm, disk, swap, volume,
/// partition, topology) and a per-section status table, replaced in the same transaction.
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

#include "device_inventory_types.hpp"
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
    /// hashes. PER VERSION: v1 (`blob_version` 1) = positional 22-field join + SHA-256
    /// (`device_ci_canonical_blob`, unchanged so old agents never loop on need_full); v2 =
    /// the sha256 of the received blob that the parser pinned into `content_hash` (empty if
    /// the digest failed; the full-ingest path then answers kError). The record's fields are
    /// assumed already UTF-8-scrubbed + clamped by the ingest seam's parse (mirrors
    /// `SoftwareInventoryStore::canonical_hash`, which trusts the seam's clamp), so
    /// this joins positionally + hashes; it does NOT re-clamp. Pure/deterministic.
    [[nodiscard]] static std::string canonical_hash(const DeviceCiRecord& rec);

    /// Hash-skip ingest for the `device_ci` source (ADR-0016 §4).
    ///  - `rec == std::nullopt` → hash-only report: compare `claimed_hash` against
    ///    the stored hash. Match → bump last_seen (kTouched); no row or mismatch →
    ///    kNeedFull.
    ///  - `rec` set → full payload: the server **recomputes** the canonical hash
    ///    from the record (never trusts `claimed_hash`) and replaces the parent row and
    ///    every v2 child row in ONE transaction under a per-agent advisory lock →
    ///    kStored (any failure rolls back, previous set intact, kError). `first_seen` is preserved across updates; `last_seen` is the
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

    /// The whole device-CI roster (the Hardware list source), hostname-sorted,
    /// capped at a hard ceiling regardless of `limit`. Authoritative: `std::nullopt`
    /// on a store/pool/query degrade, NEVER a silent empty. An empty value = no rows.
    [[nodiscard]] std::optional<std::vector<DeviceCiRecord>> list_device_ci(int limit);

    /// One agent's v2 per-section statuses + list rows (cpu, dimm, disk, swap, volume,
    /// partition, topology; chassis/baseboard/machine_id carry a status only), in the
    /// registry order of `device_ci_kinds.hpp`. Read in ONE REPEATABLE READ transaction so
    /// every section is from the same replace generation. An empty vector means nothing is
    /// stored (a v1 agent, or no record) — NOT "the device has none"; a store/pool/query
    /// failure is `std::unexpected(CiReadError::kDegraded)`, never an empty success.
    /// Personal data (DIMM serials): no route serves this yet — the later REST change must
    /// put it behind the same fail-closed audit as `inventory.device.ci` (ADR-0016).
    [[nodiscard]] std::expected<std::vector<DeviceCiSection>, CiReadError>
    get_device_ci_sections(std::string_view agent_id);

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
