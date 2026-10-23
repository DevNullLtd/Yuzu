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
/// typed sources (`kTypedInventorySources`, typed_inventory_sources.hpp) are
/// skipped by the generic gateway ingest loop (`is_typed_inventory_source`)
/// precisely so their rows never land here; every OTHER plugin's blob still
/// lands in this store. Every read (`list_tables`, `get`, `query`,
/// `get_agent_inventory`, `count`) also excludes every typed source in SQL, so
/// a stray typed row written by an older server is never readable here
/// (ADR-0070 D12). See
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

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
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
    /// Epoch-second bounds on `collected_at`, PRESENCE-tracked (#4644): unset = no bound on that
    /// side, a set value is a literal inclusive bound; a literal 0 is not "unbounded". The REST
    /// routes reject `until <= 0` and a negative `since`; `since == 0` is a harmless literal bound.
    std::optional<int64_t> since;
    std::optional<int64_t> until;
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
    /// Typed sources are excluded (see the file comment).
    [[nodiscard]] std::optional<std::vector<InventoryTable>> list_tables() const;

    /// Get inventory data for a specific agent+plugin. AUTHORITATIVE read:
    /// see `InventoryReadError` above for the three-state contract (degrade
    /// vs genuinely-absent vs found). A typed source's row reads as absent.
    [[nodiscard]] std::expected<std::optional<InventoryRecord>, InventoryReadError>
    get(const std::string& agent_id, const std::string& plugin) const;

    /// Query inventory across agents with filters; typed sources are
    /// excluded (see the file comment). AUTHORITATIVE read:
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

    /// How a `drain_typed_sources` pass ended.
    enum class TypedPurgeStatus { kCompleted, kStopped, kFailed };
    struct TypedPurgeResult {
        TypedPurgeStatus status{TypedPurgeStatus::kCompleted};
        std::int64_t rows{0}; ///< rows removed so far, whatever the status
        std::string cause;    ///< set when status == kFailed
    };
    struct TypedPurgeOptions {
        int batch_rows{5000};
        int min_batch_rows{100};  ///< a failing batch halves down to this floor
        int max_attempts{4};      ///< retries after a failed batch before giving up
        std::chrono::milliseconds pause{100};   ///< between batches (interruptible)
        std::chrono::milliseconds backoff{500}; ///< x failure count, interruptible
    };

    /// Delete at most `max_rows` stray rows of `kTypedInventorySources` (across ALL
    /// agents) in ONE bounded, time-limited statement. Returns the rows deleted (0 =
    /// nothing left, or a non-positive bound), or `std::nullopt` on a closed store, a
    /// lease timeout or a SQL failure (never throws). The typed list is bound
    /// internally (the read filter's own), so no caller can name other sources.
    [[nodiscard]] std::optional<std::int64_t> purge_typed_sources_batch(int max_rows);

    /// The background pass (ADR-0070 D12 hygiene -- the read filter and the gateway
    /// skip are the controls; this reclaims space): keyset batches in primary-key
    /// order until none remain. A failed batch is retried with backoff at half the
    /// size (down to the floor) before the pass gives up; `should_stop` is polled
    /// between batches and during every pause. Counts
    /// `yuzu_inventory_typed_purge_rows_total` per batch and
    /// `yuzu_inventory_typed_purge_failures_total` once when a pass fails.
    [[nodiscard]] TypedPurgeResult
    drain_typed_sources(const TypedPurgeOptions& opt, const std::function<bool()>& should_stop = {});

    /// Count inventory records, typed sources excluded. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query degrade, NEVER a silent zero.
    [[nodiscard]] std::optional<int64_t> count() const;

private:
    struct PurgeBatch {
        std::int64_t deleted{0};
        std::string last_agent, last_plugin; ///< last key deleted; empty when none
    };
    [[nodiscard]] std::optional<PurgeBatch> purge_batch(int max_rows, const std::string& after_agent,
                                                        const std::string& after_plugin);

    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
