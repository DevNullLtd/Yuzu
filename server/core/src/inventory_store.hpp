#pragma once

/// @file inventory_store.hpp
/// Generic per-source inventory blob store (Issue 7.17) — born on SQLite,
/// migrated to Postgres (ADR-0006/0008/0009/0037, schema `inventory_store`).
/// The sync-framework's generic `(agent_id, plugin) -> data_json` home for
/// every source that has NOT been promoted to its own typed projection; it
/// backs the scope-walking `kInventoryQuery` source + the inventory eval
/// engine (`inventory_eval.hpp`).
///
/// COEXISTS with `SoftwareInventoryStore` (ADR-0016, schema
/// `software_inventory_store`) — this is NOT that store's migration. The
/// typed sources (`installed_software`, `app_perf`, `device_ci`,
/// `software_licensing`) are skipped by the generic gateway/direct ingest
/// loop (`is_typed_inventory_source`) precisely so their rows never land
/// here; every OTHER plugin's blob still lands in this store. See
/// `docs/postgres-migration-ladder.md` and ADR-0037.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`inventory_store.inventory_data`). Mutators check the `PgResult` status
/// directly rather than `sqlite3_changes()` (#1033); none needs `RETURNING`
/// (no caller consumes an affected-row count). Generic plugins must not emit
/// credentials or secret material: `data_json` is stored as plaintext and its
/// sensitivity is otherwise plugin-dependent (ADR-0010).
///
/// Failure posture (ADR-0012 §1), split by operation class:
///  - **Ingest (`upsert`)**: FAIL-SOFT. A transient lease/query failure logs
///    a warning and returns — never throws, never blocks the gRPC/gateway
///    ingest thread. The next changed/full report re-sends the same blob
///    (bounded by the weekly full floor), so a dropped write self-heals
///    (mirrors `SoftwareInventoryStore`'s ingest posture).
///  - **Reads (`list_tables`, `get`, `query`, `get_agent_inventory`,
///    `count`)**: AUTHORITATIVE. A store/pool/query failure is reported as a
///    degrade — `std::nullopt` for the list/count reads, `std::unexpected(
///    InventoryReadError::kDegraded)` for the single-record `get` — NEVER a
///    silent empty. An empty *value* is a genuine zero-row result; a degrade
///    means the store could not be read at all. Callers MUST surface a
///    degrade (503 / banner), never `.value_or({})` it into a silent empty —
///    that re-opens the fail-open hole ADR-0016 §7 / the playbook's
///    anti-patterns list forbid.
///  - **`delete_agent`**: erases PostgreSQL rows for the agent. Returns false
///    if the delete does not commit, so the decommission cascade can retry.
///
/// `migrate_from_sqlite()` retired (#3623, ADR-0037 Update): no production fleet ever ran a
/// pre-Postgres build of this store, so the one-time first-boot backfill it implemented never
/// had real legacy data to protect. `server.cpp` now runs
/// `legacy_sqlite_probe::warn_if_legacy_rows` over `inventory_data` instead — silent unless
/// real rows are found, never blocks boot. `delete_agent` no longer erases anything from a
/// legacy `inventory.db`: a leftover legacy file is never read and never scrubbed by this
/// store — see `docs/user-manual/upgrading.md`'s InventoryStore section for the operator note.

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

// ── Data types ───────────────────────────────────────────────────────────────

struct InventoryRecord {
    std::string agent_id;
    std::string plugin;
    std::string data_json; // Structured JSON blob from the plugin
    int64_t collected_at{0};
};

struct InventoryTable {
    std::string plugin;
    int64_t agent_count{0};      // How many agents have reported this plugin
    int64_t last_collected{0};   // Most recent collection timestamp
};

struct InventoryQuery {
    std::string agent_id;   // Filter by agent (empty = all)
    std::string plugin;     // Filter by plugin (empty = all)
    int64_t since{0};       // epoch seconds, 0 = no lower bound
    int64_t until{0};       // epoch seconds, 0 = no upper bound
    int limit{100};
    int offset{0};
};

/// Error type for the authoritative single-record read. The success type is
/// `std::optional<InventoryRecord>`: a value == found, `std::nullopt` ==
/// genuinely no row for this (agent_id, plugin). `std::unexpected(kDegraded)`
/// == store/pool/query failure — the caller shows a degrade banner/503, never
/// a 404 (mirrors `DeviceInventoryStore::CiReadError` exactly; out-params are
/// forbidden in new code, docs/cpp-conventions.md, hence `std::expected`
/// rather than an enum + out-param).
enum class InventoryReadError { kDegraded };

// ── InventoryStore ──────────────────────────────────────────────────────────

class InventoryStore {
public:
    /// Borrows the shared pool and runs the `inventory_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here, so in production the migration runs against a
    /// proven-reachable database).
    explicit InventoryStore(pg::PgPool& pool);

    InventoryStore(const InventoryStore&) = delete;
    InventoryStore& operator=(const InventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_inventory_read_degrade_total{reason, source="generic"}`, shared
    /// with the typed sibling stores) and the ingest-drop / query-truncation
    /// counters below. Set ONCE during single-threaded startup, before the
    /// gRPC/REST surfaces begin serving — the pointer is read without
    /// synchronisation on the serving threads, so a later swap would race. A
    /// null registry (the default, e.g. in unit tests) disables emission;
    /// every emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Upsert inventory data for an agent+plugin pair. FAIL-SOFT ingest: a
    /// lease/query failure is logged and this returns without throwing — the
    /// agent's next changed/full report re-sends the same blob (a drop bumps
    /// `yuzu_inventory_ingest_dropped_total`). A blank (empty/whitespace-only)
    /// `agent_id` or `plugin` is REJECTED (logged, no write) — never persisted
    /// as an un-erasable orphan the decommission cascade's empty-id guard
    /// could never reach (GDPR). If data already exists for (agent_id,
    /// plugin), it is replaced ONLY when `collected_at` is not older than the
    /// stored row's — a reordered/duplicate older report can never clobber
    /// newer data (a same-instant re-report, `collected_at` equal, still
    /// updates).
    void upsert(const std::string& agent_id, const std::string& plugin,
                const std::string& data_json, int64_t collected_at = 0);

    /// List available inventory "tables" (distinct plugins with agent
    /// counts). AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// degrade, NEVER a silent empty. An empty value = no plugins reported.
    [[nodiscard]] std::optional<std::vector<InventoryTable>> list_tables() const;

    /// Get inventory data for a specific agent+plugin. AUTHORITATIVE read:
    /// see `InventoryReadError` above for the three-state contract (degrade
    /// vs genuinely-absent vs found).
    [[nodiscard]] std::expected<std::optional<InventoryRecord>, InventoryReadError>
    get(const std::string& agent_id, const std::string& plugin) const;

    /// Query inventory across agents with filters. AUTHORITATIVE read:
    /// `std::nullopt` on a store/pool/query degrade, NEVER a silent empty. An
    /// empty value = no rows matched. When the result count hits the
    /// effective row limit or the aggregate 8 MiB payload budget, more rows
    /// may exist past what is returned — this is logged and bumps
    /// `yuzu_inventory_query_truncated_total` so an operator/caller can tell
    /// "capped at N" from "exactly N" (full keyset pagination is a follow-up).
    /// Governance M1 (2026-07-29): pass `truncated` to receive that signal in
    /// process — a caller that PERSISTS the result as a targeting set (the
    /// from-inventory-query result-set route) must refuse a capped read
    /// rather than materialise a silently-incomplete set; the metric alone
    /// cannot reach that decision point. Cap ceiling + exact-at-cap false
    /// positive tracked in #2633 (keyset pagination / limit+1 probe).
    [[nodiscard]] std::optional<std::vector<InventoryRecord>>
    query(const InventoryQuery& q, bool* truncated = nullptr) const;

    /// Get all inventory records for a specific agent. AUTHORITATIVE read:
    /// same nullopt-on-degrade and optional truncation contract as `query`
    /// (this delegates to it).
    [[nodiscard]] std::optional<std::vector<InventoryRecord>>
    get_agent_inventory(const std::string& agent_id, bool* truncated = nullptr) const;

    /// Delete inventory data for an agent from PostgreSQL. Idempotent; returns
    /// false if the delete fails so the decommission cascade can retry and
    /// cannot report a false "erased".
    [[nodiscard]] bool delete_agent(const std::string& agent_id);

    /// Delete every row for one plugin (source), across ALL agents. Mirrors
    /// `delete_agent`'s lease/txn idiom exactly, keyed on `plugin` instead of
    /// `agent_id`. Defence-in-depth (ADR-0016 §5) for the boot-time typed-
    /// source purge (server.cpp): a typed source's rows never belong in this
    /// generic store — `is_typed_inventory_source` is the primary control,
    /// this is hygiene for a newer-agent/older-server window where a typed
    /// blob landed here before the exclusion took effect. Returns false on a
    /// closed store, a lease/lock timeout, or a SQL failure (never throws) —
    /// callers must not treat a false return as fatal (never set
    /// `startup_failed_` on it).
    [[nodiscard]] bool delete_source(std::string_view plugin_name);

    /// Count total inventory records. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query degrade, NEVER a silent zero.
    [[nodiscard]] std::optional<int64_t> count() const;

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
