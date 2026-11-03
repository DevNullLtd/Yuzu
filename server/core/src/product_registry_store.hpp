#pragma once

/// @file product_registry_store.hpp
/// Born-on-Postgres canonical product registry (ADR-0024 Decision 4, schema
/// `product_registry_store`). The SLE catalog's identity plane: one `products`
/// row per canonical product identity (keyed by the deterministic
/// `product_normalize` norm_key) plus the `product_aliases` match links that
/// record how each raw (source, name, publisher) triple was resolved onto a
/// canonical row (ADR-0024 Decision 6 — aliases persist `method` +
/// `confidence` so manual curation and smarter matching can layer on later by
/// editing aliases, without redesign).
///
/// COEXISTS with `SoftwareLicensingStore` (per-agent detected rows + posture)
/// — one-store-per-typed-domain is the established precedent; NO cross-schema
/// SQL or FKs (ADR-0024 Decision 4): cross-store joins happen in C++ in the
/// compliance evaluator.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// uses `RETURNING`. Normalized rows only — NO JSONB/GIN. Failure posture
/// (ADR-0012 §1 / ADR-0024 Decision 4):
///   - **Writes:** fail-soft — they come from the background compliance
///     evaluator's matcher pass; a transient PG outage returns
///     `std::nullopt`/false (logged, never thrown) and the next evaluator
///     cycle re-derives the same deterministic result (soft keys are
///     re-resolved every cycle — roadmap R7).
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns
///     `std::nullopt` / `kDegraded` (logged at warn), NEVER a silent empty.
///     A silent-empty registry read would let a compliance surface render
///     detected products as unmatched/absent — the fail-open lie ADR-0024
///     Decision 4 forbids. An empty *value* = a genuine zero-row result.
///
/// SAM.4 (schema v2) adds the software-title normalisation layer on the same
/// schema: the versioned alias pack (`normalization_pack`), the permanent title
/// dimension (`title_dimension`) and the curation queue (`curation_queue`). The
/// dimension and queue are WRITTEN by `SoftwareTitleDimension` (the ADR-0012 §3
/// cross-store query owner, which reads `software_inventory_store.title_triples`);
/// this class owns the schema, the pack load and the alias reads.
///
/// Alias-key contract: a pack/curated alias is keyed on
/// `software_normalization_pack.hpp::alias_key()` - the normalised title with the
/// extracted edition re-appended - stored in `product_aliases.raw_name`, plus the
/// normalised vendor in `raw_publisher`. There is NO edition wildcard. The tier
/// and ecosystem live in `source` (`pack:<ecosystem>` / `curated:<ecosystem>`,
/// empty ecosystem = wildcard), so the v1 primary key is unchanged.
///
/// Dimension invalidation contract (D14, binding on every future writer): a
/// registry mutation that can change a title's resolution without changing the
/// pack version (a curated alias insert or status flip, a product attribute
/// edit) MUST set `title_dimension.pack_version = ''` (the stale sentinel) for the
/// affected rows - by alias key, or by `product_id` - in the SAME transaction. The
/// normalisation job re-selects any row whose `pack_version` differs from the
/// current pack, so no new column or generation counter is needed. That write MUST
/// first take the blocking `pg_advisory_xact_lock(hashtextextended(
/// 'software_normalization', 0))` that every normalisation pass tries: a pass that
/// selected a row before the mutation commits would otherwise upsert it afterwards,
/// stamping the current `pack_version` over the sentinel and losing the invalidation.
/// `upsert_product` and `upsert_alias` ARE such mutations and follow the contract themselves
/// (the lock, the write and the sentinel in one transaction, only when the write changes a
/// resolution; `upsert_alias` marks every row stale because the alias key cannot be
/// reproduced in SQL). The store's other own mutations
/// (the seed load, which stamps the pack version, and the `ON DELETE SET NULL` foreign key)
/// need no sentinel write. A `products.category`
/// outside `kCategories` is written to the dimension as `other` (its `category` column is
/// constrained to that set).
///
/// Normaliser contract: every stored key (`product_aliases.raw_name`, `products.norm_key`,
/// `title_dimension` resolutions) is derived with `normalize_title`, `normalize_vendor` and
/// `alias_key`. There is no normaliser-version column; a change to the output of any of
/// them REQUIRES a new `pack_version` (the job's `<>` arm then re-normalises every row)
/// and a re-keyed pack.

#include <libpq-fe.h> // PGconn: the static reads below take a caller-pinned connection (see
                      // pg_migration_runner.hpp - include libpq, never re-declare pg_conn)

#include <cstdint>
#include <chrono>
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

/// The advisory-lock key every normalisation pass TRIES and every registry writer that can change
/// a title's resolution BLOCKS on (the dimension invalidation contract above). One spelling:
/// two copies of a catastrophic-if-violated lock key drift apart.
inline constexpr std::string_view kNormalizationLockKey = "software_normalization";
/// How long such a writer waits for a pass to release the lock. It must exceed a pass's budget
/// (`kPassBudget`, software_title_dimension.hpp, which static_asserts that).
inline constexpr std::chrono::seconds kNormalizationLockWait{90};

struct ParsedPack; // software_normalization_pack.hpp

/// One canonical product identity. `norm_key` is the deterministic
/// `product_normalize::norm_key` value (UNIQUE); vendor/title/edition are the
/// normalised forms the matcher operates on; `platform` is a coarse OS hint
/// ("windows" | "linux" | "macos" | "" when unknown/cross-platform).
/// `created_at`/`updated_at` are server receipt time (epoch seconds).
struct ProductRow {
    std::int64_t product_id{0}; ///< BIGSERIAL; 0 only on a default-constructed row
    std::string norm_key;
    std::string vendor;
    std::string title;
    std::string edition;
    std::string platform;
    std::int64_t created_at{0};
    std::int64_t updated_at{0};
    // v2 (SAM.4)
    std::string purl_type;   ///< package-URL type ("" when none exists)
    std::string cpe_product; ///< our own pack/curated column; "" when unset
    std::string origin;      ///< "matcher" | "pack" | "curated" | "birth"
    std::string category;    ///< closed vocabulary, see software_normalization_pack.hpp
};

/// One match link: how a raw (source, raw_name, raw_publisher) triple resolved
/// onto a canonical product. `method` is the winning match tier name
/// ("exact_norm" | "title_vendor" | "token_set" | "birth"); `confidence` the
/// tier confidence (`product_normalize::match_confidence`). Timestamps are
/// server receipt time: `first_matched_at` is preserved across re-upserts,
/// `last_seen_at` refreshes each time the evaluator re-derives the link.
struct ProductAliasRow {
    std::string source; ///< which pipeline minted the link (e.g. "software_licensing", "installed_software")
    std::string raw_name;
    std::string raw_publisher;
    std::int64_t product_id{0};
    std::string method;
    double confidence{0.0};
    std::int64_t first_matched_at{0};
    std::int64_t last_seen_at{0};
    std::string status{"active"}; ///< v2: "active" | "inactive"
    std::string pack_version;     ///< v2: pack that wrote the link ("" for matcher links)
};

/// One pack/curated alias joined to its canonical product, as the title
/// dimension's resolver consumes it. `source` is `pack:<eco>` / `curated:<eco>`.
struct NormalizationAliasRow {
    std::string source;
    std::string raw_name;      ///< alias_key()
    std::string raw_publisher; ///< normalised vendor ("" = wildcard)
    ProductRow product;
};

enum class PackLoadOutcome { loaded, already_present };

/// Error type for the authoritative single-row reads. The success type is an
/// `std::optional<T>`: a value == found, `std::nullopt` == absent (the read
/// succeeded, there is genuinely no such row). `std::unexpected(kDegraded)` ==
/// store/pool/query failure — the caller surfaces an error/banner, never a
/// silent "no match". Mirrors `CiReadError` (out-params are forbidden in new
/// code — docs/cpp-conventions.md).
enum class RegistryReadError { kDegraded };

class ProductRegistryStore {
public:
    /// Borrows the shared pool and runs the `product_registry_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before reaching
    /// here).
    explicit ProductRegistryStore(pg::PgPool& pool);

    ProductRegistryStore(const ProductRegistryStore&) = delete;
    ProductRegistryStore& operator=(const ProductRegistryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter (the shared
    /// `yuzu_inventory_read_degrade_total{reason, source="product_registry"}`
    /// family, #1675 — the SLE-specific `yuzu_server_sle_*` families land with
    /// the evaluator per roadmap R12). Set ONCE during single-threaded
    /// startup, before serving begins; a null registry (the default, e.g. in
    /// unit tests) disables emission — every emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Upsert a canonical product by `norm_key` (the UNIQUE key): insert a new
    /// row (minting a product_id) or refresh vendor/title/edition/platform +
    /// `updated_at` on an existing one (`created_at` is preserved). Returns
    /// the row's product_id via `RETURNING`; `std::nullopt` on a store/pool/
    /// query failure (fail-soft — the evaluator retries next cycle; never
    /// throws). An empty `norm_key` is a precondition miss → `std::nullopt`. Follows the
    /// dimension invalidation contract: blocks on the normalisation lock (bounded by
    /// `kNormalizationLockWait`, 90 s; a failed wait is a `std::nullopt`), reads the current row
    /// under it, upserts, and marks title-dimension rows stale in the same transaction: the
    /// rows resolved to this product when its vendor/title/edition/platform changed, every
    /// unnormalized row when the product is new, and nothing when the write changes nothing.
    [[nodiscard]] std::optional<std::int64_t>
    upsert_product(std::string_view norm_key, std::string_view vendor, std::string_view title,
                   std::string_view edition, std::string_view platform);

    /// Upsert a match link keyed on (source, raw_name, raw_publisher): insert
    /// (stamping `first_matched_at`) or re-point/refresh an existing link
    /// (product_id/method/confidence + `last_seen_at`; `first_matched_at` is
    /// preserved). `product_id` must reference an existing products row (FK) —
    /// a dangling id fails the statement and returns false. Fail-soft: false
    /// on any failure, never throws. Follows the dimension invalidation contract: blocks on
    /// the normalisation lock (bounded by `kNormalizationLockWait`, 90 s), then upserts and, when
    /// the link is new or re-points the product or changes the method, marks EVERY title-dimension
    /// row stale in the same transaction (the alias key cannot be reproduced in SQL). A refresh
    /// that changes neither marks nothing, so a per-cycle caller does not re-queue the dimension.
    [[nodiscard]] bool upsert_alias(std::string_view source, std::string_view raw_name,
                                    std::string_view raw_publisher, std::int64_t product_id,
                                    std::string_view method, double confidence);

    /// Resolve a raw (source, raw_name, raw_publisher) triple to its linked
    /// product_id. AUTHORITATIVE read: `std::unexpected(kDegraded)` on a
    /// store/pool/query failure; a value holding `std::nullopt` when no alias
    /// exists (the matcher should run); a value holding the product_id when
    /// the link is found.
    [[nodiscard]] std::expected<std::optional<std::int64_t>, RegistryReadError>
    resolve_alias(std::string_view source, std::string_view raw_name,
                  std::string_view raw_publisher);

    /// One canonical product by `norm_key`. AUTHORITATIVE read:
    /// `std::unexpected(kDegraded)` on a store/pool/query failure; a value
    /// holding `std::nullopt` when absent; a value holding the row when found.
    [[nodiscard]] std::expected<std::optional<ProductRow>, RegistryReadError>
    get_product(std::string_view norm_key);

    /// All canonical products, norm_key-sorted, capped at a hard ceiling
    /// regardless of `limit` — the matcher's candidate set + the registry
    /// drill. AUTHORITATIVE read: `std::nullopt` on a store/pool/query degrade
    /// (NEVER a silent empty); an empty value = a genuinely empty registry.
    [[nodiscard]] std::optional<std::vector<ProductRow>> list_products(int limit);

    /// All match links for one product, (source, raw_name)-sorted, capped.
    /// AUTHORITATIVE read: `std::nullopt` on a degrade. A `product_id <= 0` is
    /// a precondition miss → empty value (not a degrade).
    [[nodiscard]] std::optional<std::vector<ProductAliasRow>> list_aliases(std::int64_t product_id);

    /// Headline counts for the registry (KPI tiles / diagnostics), one cheap
    /// aggregate each. AUTHORITATIVE reads: `std::nullopt` on a degrade —
    /// never a false zero.
    [[nodiscard]] std::optional<std::int64_t> count_products();
    [[nodiscard]] std::optional<std::int64_t> count_aliases();

    /// Load `pack` as the current alias pack ONLY when no pack row exists (the
    /// boot-time seed path; D8). One transaction behind an advisory lock so two
    /// booting replicas converge: pack row, one product per distinct `norm_key`
    /// (`origin = 'pack'`) and one `pack:<ecosystem>` alias per row. A stored pack
    /// of any version wins - a newer embedded seed is logged, never applied.
    /// Fail-closed for the caller: `std::unexpected(reason)` on any failure.
    [[nodiscard]] std::expected<PackLoadOutcome, std::string>
    load_pack_if_empty(const ParsedPack& pack, std::string_view loaded_by);

    /// The alias read on a CALLER-PINNED connection, for the title dimension owner's
    /// single transaction (a nested lease would need a second pool connection): active
    /// aliases whose `raw_name` (alias key) is in `alias_keys` and whose `source` is
    /// EXACTLY one of `sources` (`pack:<ecosystem>` / `curated:<ecosystem>` - the caller
    /// knows the candidates' ecosystems, so the read is an equality probe on the primary
    /// key's leading column, not a prefix scan), joined to their products. `std::nullopt`
    /// on a SQL failure (no degrade accounting: the caller's pass fails and is retried).
    [[nodiscard]] static std::optional<std::vector<NormalizationAliasRow>>
    read_normalization_aliases(PGconn* conn, const std::vector<std::string_view>& alias_keys,
                               const std::vector<std::string_view>& sources);

    /// The products whose `norm_key` is in `norm_keys` (UNIQUE, so at most one row per
    /// key), on a caller-pinned connection - the dimension's exact-key read. Same
    /// failure contract as `read_normalization_aliases`.
    [[nodiscard]] static std::optional<std::vector<ProductRow>>
    read_products_by_norm_key(PGconn* conn, const std::vector<std::string_view>& norm_keys);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
