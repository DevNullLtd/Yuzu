#pragma once

/// @file software_inventory_store.hpp
/// Born-on-Postgres typed inventory projection (ADR-0016, schema
/// `software_inventory_store`). The read-optimized home for the daily-sync
/// framework's `installed_software` source — normalized rows so fleet-wide
/// queries ("which devices run X < v") are first-class and the schema ports off
/// Postgres easily.
///
/// COEXISTS with the generic per-source `InventoryStore` (the sync framework's
/// baseline blob store, which also backs the scope-walking `kInventoryQuery`
/// source + the eval engine). This class is NOT a replacement — it is the typed
/// projection for the one source that needs structured fleet queries today.
/// Future high-query sources get their own typed table in this same store.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// uses `RETURNING`. Normalized rows only — NO JSONB/GIN. Failure posture splits by
/// axis (ADR-0012 §1 + ADR-0016 §7) — unlike `OfflineEndpointStore` there is NO
/// in-memory authoritative read layer; this store IS the only server-side read
/// representation of installed software, so it is NOT durability-on-top for reads:
///   - **Data:** a projection — the agent + weekly full-floor are the source of truth.
///   - **Ingest:** fail-soft — a transient PG outage returns kError + nacks; the next
///     sync + the floor self-heal (the agent re-pushes). A blip degrades durability,
///     never correctness.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns `std::nullopt`
///     (logged at warn), NEVER a silent empty. A silent-empty read on a fleet vuln
///     query ("which devices run <CVE>") reads as "installed nowhere" — the fail-open
///     A4 violation ADR-0016 §7 forbids ("surface errors, never silent-empty").
///     `nullopt` = degraded (could not read); an empty *value* = a genuine zero-row
///     result. Staleness is acceptable (return the last projection); failure-as-empty
///     is not.

#include "inventory_ingest_outcome.hpp" // InventoryIngestOutcome

#include <cstdint>
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

/// One installed-software entry. **Machine-wide scope only** — no per-user /
/// username / SID / user-path (ADR-0016: no PII, no works-council trigger).
///
/// Blob contract v2: member order == the wire/hash field order (append-only —
/// the canonical hash and the agent's blob builder walk this exact sequence).
/// Fields an ecosystem does not store are EMPTY, never synthesised: NEVRA +
/// signature populate on Linux package managers per their capability (rpm =
/// full; deb = no signature; apk/pacman = name/EVR only); Windows/macOS rows
/// are kind=app with name/version/publisher only; distro_id/distro_version are
/// stamped on every Linux row from /etc/os-release.
struct SoftwareEntry {
    std::string name;
    std::string version; // upstream version, release/revision stripped (v2)
    std::string publisher; // rpm PACKAGER / deb Maintainer / Windows Publisher
    std::string install_date;
    std::string kind;      // "package" | "app"
    std::string ecosystem; // rpm|deb|apk|pacman|windows|macos|homebrew
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags only)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
};

/// One fleet-query row: which agent carries which entry.
struct SoftwareFleetRow {
    std::string agent_id;
    SoftwareEntry entry;
};

/// One fleet-catalogue row — a software title rolled up across the WHOLE fleet
/// (`software_catalog`). **FLEET-WIDE aggregate, NOT management-group scoped:** the
/// GROUP BY runs in Postgres and cannot apply the per-agent C++ scope predicate the
/// flat-row reads use, so `device_count` spans every management group. Under the
/// GLOBAL `Inventory:Read` gate this matches today's behaviour (ADR-0017 confinement
/// is inert — a confined operator is denied at the gate, a global one sees all), but
/// the day list-view confinement lands this aggregate MUST become scope-aware or stay
/// global-gated. Callers caveat the counts, exactly like the `query_software` route.
struct SoftwareCatalogRow {
    std::string name;
    std::string publisher;         ///< representative publisher (max over the group); may vary
    std::int64_t device_count{0};  ///< COUNT(DISTINCT agent_id) carrying the title
    std::int64_t version_count{0}; ///< COUNT(DISTINCT version) of the title
};

/// One version's install count for a title — the "installs per version" drill.
struct SoftwareVersionCount {
    std::string version;
    std::int64_t device_count{0}; ///< COUNT(DISTINCT agent_id) on this version
};

/// Fleet catalogue query. `name_filter` (case-insensitive substring) narrows the
/// rows by matching EITHER the title OR the publisher (round-3 item 8 — "adobe"
/// surfaces every Adobe title, not only ones with "adobe" in the name itself);
/// empty matches all. `limit` caps the returned rows (ordered by install count);
/// the store also enforces a hard ceiling independent of `limit`.
struct SoftwareCatalogQuery {
    std::string name_filter;
    int limit{200};
};

/// Freshness + headline counts for the catalogue rollup (the `/inventory` Software-tab
/// "as of" stamp + KPI strip, so the page never runs a COUNT). `refreshed_at == 0`
/// means the rollup has never been computed yet ("building" state) — distinct from a
/// refreshed-but-empty fleet (`refreshed_at > 0`, `total_titles == 0`).
struct CatalogRollupMeta {
    std::int64_t refreshed_at{0}; ///< epoch seconds of the last successful refresh; 0 = never
    std::int64_t total_titles{0};
    std::int64_t total_devices{0};
};

/// Fleet-wide software query. Empty filters match all; results are capped.
struct SoftwareFleetQuery {
    std::string agent_id; ///< exact agent filter ("" = all agents)
    std::string name;     ///< exact software-name filter ("" = all names)
    int limit{1000};
    // No offset: see query_software (gov consistency N1) — keyset is the #1634 follow-up.
};

class SoftwareInventoryStore {
public:
    /// Borrows the shared pool and runs the `software_inventory_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was empty
    /// or the migration failed (the server fails closed before reaching here).
    explicit SoftwareInventoryStore(pg::PgPool& pool);

    SoftwareInventoryStore(const SoftwareInventoryStore&) = delete;
    SoftwareInventoryStore& operator=(const SoftwareInventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_inventory_read_degrade_total{reason, source="installed_software"}`, #1675) and any future
    /// store-internal metric. Set ONCE during single-threaded startup, before
    /// the gRPC/REST surfaces begin serving — the pointer is read without
    /// synchronisation on the serving threads, so a later swap would race. A
    /// null registry (the default, e.g. in unit tests) disables emission; every
    /// emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Canonical content hash over a machine-scope software list — the SAME
    /// algorithm the agent uses (sorted+deduplicated; fields unit-separated
    /// 0x1F, entries record-separated 0x1E; SHA-256 hex), so the agent's
    /// claimed hash and the server's recomputed/stored hash are comparable
    /// (ADR-0016 §4). Pure/deterministic; takes its argument by value.
    [[nodiscard]] static std::string canonical_hash(std::vector<SoftwareEntry> entries);

    /// Hash-skip ingest for the `installed_software` source (ADR-0016 §4).
    ///  - `rows == std::nullopt` → hash-only report: compare `claimed_hash`
    ///    against the stored hash. Match → bump last_seen (kTouched); no record
    ///    or mismatch → kNeedFull.
    ///  - `rows` set → full payload: the server **recomputes** the canonical
    ///    hash from these rows and stores THAT (never trusts `claimed_hash`),
    ///    replacing all of this agent's rows + upserting the parent in one
    ///    transaction → kStored.
    /// `collected_at` (epoch seconds, agent-supplied) is part of the ingest
    /// contract but is **intentionally NOT used to stamp `last_seen`/`first_seen`**
    /// — those are the SERVER receipt time so the staleness gauge is immune to
    /// agent clock skew (#1685, ADR-0016 Update 2026-06-27). Retained on the wire
    /// (proto-carried) for a future content-age signal.
    /// `rows` is taken BY VALUE so the full-payload path can `std::move` the
    /// entries into normalization instead of copying up to kMaxEntries structs on
    /// the ingest hot path (UP-8); pass `std::move` at the call site.
    InventoryIngestOutcome apply_installed_software(std::string_view agent_id,
                                                    std::string_view claimed_hash,
                                                    std::optional<std::vector<SoftwareEntry>> rows,
                                                    std::int64_t collected_at);

    /// All installed software for one agent (per-device drill-down), name-sorted.
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure (degraded —
    /// distinct from an empty value = genuinely no rows). An empty `agent_id` is a
    /// precondition miss, not a degrade → empty value. Callers MUST surface a `nullopt`
    /// degrade (e.g. an error/banner), NOT `.value_or({})` it back into a silent empty —
    /// that re-opens the fail-open A4 violation this contract closes (gov UP-5).
    [[nodiscard]] std::optional<std::vector<SoftwareEntry>>
    get_agent_software(std::string_view agent_id);

    /// `inventory_state.last_seen` for one (agent, source) — the SERVER receipt
    /// epoch-seconds of the last ACCEPTED report (full or hash-only touch).
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query degrade; `0` = no
    /// row yet (never synced). Backs the Hardware CI record's "Sync now" poll.
    [[nodiscard]] std::optional<std::int64_t> source_last_seen(std::string_view agent_id,
                                                               std::string_view source);

    /// Fleet-wide query ("which agents run X"). Capped at a hard ceiling regardless
    /// of `limit`. AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure
    /// (degraded — NEVER a silent empty; ADR-0016 §7). An empty value = no matches.
    [[nodiscard]] std::optional<std::vector<SoftwareFleetRow>>
    query_software(const SoftwareFleetQuery& q);

    /// Fleet software catalogue — every title with its (device_count, version_count),
    /// most-installed first (the `/inventory` Software list). Reads the PRECOMPUTED
    /// `catalog_rollup` table (refreshed by `refresh_catalog_rollup`), NOT an on-demand
    /// GROUP BY — the underlying `installed_software` changes only on the daily sync, so
    /// recomputing per request is wasteful and degrades at fleet scale. This read is a
    /// cheap indexed scan of the small rollup. **FLEET-WIDE** (see `SoftwareCatalogRow`):
    /// the rollup is global by construction and CANNOT be per-operator scoped, so the
    /// caller MUST gate on the GLOBAL `Inventory:Read` (ADR-0017). AUTHORITATIVE read:
    /// `std::nullopt` on a store/pool/query degrade, NEVER a silent empty. An empty value
    /// means the rollup has no rows — pair with `catalog_rollup_meta()` to tell a
    /// never-refreshed ("building") rollup from a genuinely empty fleet.
    [[nodiscard]] std::optional<std::vector<SoftwareCatalogRow>>
    software_catalog(const SoftwareCatalogQuery& q);

    /// Installs-per-version for ONE title (the catalogue drill), most-installed first.
    /// Reads the precomputed `version_rollup` (same cadence/scope as `software_catalog`).
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query degrade. An empty `name`
    /// is a precondition miss → empty value (not a degrade).
    [[nodiscard]] std::optional<std::vector<SoftwareVersionCount>>
    software_versions(std::string_view name, int limit);

    /// Recompute the catalogue rollup from `installed_software` and atomically replace
    /// `catalog_rollup` / `version_rollup` / `catalog_rollup_meta` in ONE transaction —
    /// the single expensive `GROUP BY`, run OFF the request path by the background
    /// `SoftwareCatalogRollup` thread on a cadence. KEEP-LAST-GOOD: on any lease/SQL
    /// failure (incl. the generous background `statement_timeout`) the transaction rolls
    /// back, leaving the prior rollup + its freshness stamp intact (the stamp visibly
    /// ages). Returns false on failure (the caller logs/metrics it). Idempotent.
    bool refresh_catalog_rollup();

    /// The catalogue rollup's freshness stamp + headline counts (the Software-tab "as of"
    /// stamp + KPI strip). AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// degrade. The singleton meta row is seeded at migration with `refreshed_at = 0`
    /// (the "building" sentinel), so a successful read always returns a value.
    [[nodiscard]] std::optional<CatalogRollupMeta> catalog_rollup_meta();

    /// Drop an agent's software inventory (e.g. on agent removal). Returns true
    /// iff the transaction committed both deletes; false on a closed store, a
    /// lease timeout, or a SQL failure — so the decommission cascade records the
    /// store Failed rather than a false "erased".
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    /// KEYSET-paged enumeration of the agent_ids that have reported a given
    /// `source` (`inventory_state.source`). Returns up to `limit` ids with
    /// `agent_id > after_id`, ascending. The PK (agent_id, source) makes agent_id
    /// unique per source, so NO DISTINCT is needed. The caller loops with
    /// `after_id = ` the last returned id until it gets a short page. Bounded
    /// lease; returns an empty vector on a degrade (a caller that must distinguish
    /// end-of-pages from degrade should check the page length vs `limit`). The
    /// PR-4 CAVM backfill trigger walks the fleet through this.
    [[nodiscard]] std::vector<std::string>
    list_agent_ids(std::string_view source, std::string_view after_id, int limit);

    /// Count agents whose `installed_software` inventory has not been refreshed
    /// since `stale_before_secs` (epoch seconds) — i.e. `last_seen <
    /// stale_before_secs`. Feeds the `yuzu_inventory_stale_agents` freshness
    /// gauge from the metrics sweep, which shares its serial thread with the
    /// security-relevant revocation-teardown backstop. BOTH the lease acquire
    /// AND the query execution are bounded so neither can stall that teardown
    /// (CH-IN3/UP-2): a 250ms bounded acquire, and a per-statement
    /// `SET LOCAL statement_timeout = '250ms'` inside the txn (the acquire alone
    /// does NOT bound execution — a bloated-table seq-scan would otherwise run to
    /// the pool's 30s statement_timeout). `std::nullopt` on a store/pool/query
    /// degrade (incl. the execution-timeout) — the caller leaves the gauge at its
    /// previous value rather than publishing a false zero, and increments
    /// `yuzu_inventory_stale_count_unavailable_total` so a frozen gauge is
    /// distinguishable from a true low.
    [[nodiscard]] std::optional<std::int64_t> count_stale_agents(std::int64_t stale_before_secs);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
