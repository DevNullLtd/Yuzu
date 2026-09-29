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
};

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
    /// throws). An empty `norm_key` is a precondition miss → `std::nullopt`.
    [[nodiscard]] std::optional<std::int64_t>
    upsert_product(std::string_view norm_key, std::string_view vendor, std::string_view title,
                   std::string_view edition, std::string_view platform);

    /// Upsert a match link keyed on (source, raw_name, raw_publisher): insert
    /// (stamping `first_matched_at`) or re-point/refresh an existing link
    /// (product_id/method/confidence + `last_seen_at`; `first_matched_at` is
    /// preserved). `product_id` must reference an existing products row (FK) —
    /// a dangling id fails the statement and returns false. Fail-soft: false
    /// on any failure, never throws.
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

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
