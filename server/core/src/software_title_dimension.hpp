#pragma once

/// @file software_title_dimension.hpp
/// SAM.4 software-title normalisation. Two layers in one header:
///
///  1. PURE core - `resolve_title()` decides one title's resolution from the
///     pack/curated aliases for its alias key and the registry's products, with
///     no I/O. Order: curated alias -> pack alias -> `match_product` (with an
///     edition-equality guard) -> birth (OFF) -> `unnormalized`. A title is
///     LABELLED, never guessed: an unresolved title keeps its normalised
///     vendor/product/edition/version and a NULL product.
///
///  2. `SoftwareTitleDimension` - the ADR-0012 §3 cross-store QUERY OWNER (sixth
///     after `DexAppVersionFailuresOwner`). It reads
///     `software_inventory_store.title_triples` and writes
///     `product_registry_store.title_dimension` / `curation_queue` on ONE lease per
///     pass; neither store grows a cross-schema method. Every pass is one bounded
///     transaction opening with `pg_try_advisory_xact_lock` (a peer replica holding
///     it = skip, success). A replay re-selects the same candidates and writes
///     byte-identical rows behind an `IS DISTINCT FROM` guard.
///
/// Alias precedence (D2): tier (curated > pack) first, then specificity
/// (eco,pub) > (eco,'') > ('',pub) > ('',''). There is NO edition wildcard: a
/// title whose normalised edition is E matches only an alias key carrying E.
///
/// Dimension invalidation (D14): a row is re-normalised when its `pack_version`
/// differs from the current pack, when its product was deleted, or when its
/// `pack_version` is '' (the stale sentinel a future curation write sets - see
/// product_registry_store.hpp).

#include "product_normalize.hpp"
#include "product_registry_store.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class SoftwareInventoryStore;

/// Auto-birth (minting a product for an unmatched title) is OFF: the S-2
/// measurement that sizes it has not run (the row's own `< 60 % -> drop` rule
/// applied as the safe default). Flipping this needs a product-minting path in the
/// owner (a `static_assert` in the .cpp stops a silent flip); the schema already
/// carries `origin = 'birth'`, so no migration is needed.
inline constexpr bool kAutoBirthEnabled = false;
inline constexpr std::size_t kAutoBirthMinTokens = 2;

inline constexpr int kPassLimit = 2000;      ///< titles per pass (one transaction)
inline constexpr int kMaxPassesPerTick = 100; ///< passes per hourly tick
inline constexpr int kMatcherCandidateCap = 20000;
inline constexpr std::chrono::seconds kPassBudget{60}; ///< wall budget per pass == statement_timeout

/// A raw installed-software triple (exactly as `title_triples` holds it).
struct TitleKey {
    std::string raw_name;
    std::string raw_publisher;
    std::string ecosystem;
};

/// One title's resolution. `norm_status` is "normalized" | "unnormalized".
struct TitleResolution {
    std::string norm_status;
    std::string method; ///< "curated" | "pack" | exact_norm | title_vendor | token_set | "birth" | ""
    std::optional<std::int64_t> product_id;
    std::string vendor;
    std::string product;
    std::string edition;
    std::string title_version;
    std::string category{"other"};
    std::string purl_type;
    std::string cpe_product;
};

/// Matcher candidates built once per pass from the registry's products.
class ProductIndex {
public:
    ProductIndex() = default;
    explicit ProductIndex(std::vector<ProductRow> products);

    [[nodiscard]] const std::vector<ProductCandidate>& candidates() const noexcept {
        return candidates_;
    }
    [[nodiscard]] const ProductRow* find(std::string_view norm_key) const;
    [[nodiscard]] std::size_t size() const noexcept { return products_.size(); }

private:
    std::vector<ProductRow> products_;
    std::vector<ProductCandidate> candidates_;
    std::unordered_map<std::string, std::size_t> by_key_;
};

/// The pure per-title decision. `aliases_for_key` holds the pack/curated aliases
/// whose `raw_name` equals this title's alias key (any publisher/tier/ecosystem).
/// `cpe_product` comes ONLY from the matched product row (never a resolver).
[[nodiscard]] TitleResolution resolve_title(const TitleKey& key,
                                            const std::vector<NormalizationAliasRow>& aliases_for_key,
                                            const ProductIndex& products, bool auto_birth);

enum class PassOutcome { ok, skipped_peer, no_pack, failed, cancelled, timed_out };

struct PassResult {
    PassOutcome outcome{PassOutcome::failed};
    int processed{0};
    int normalized{0};
    int unnormalized{0};
};

struct TickResult {
    bool errored{false};   ///< a pass failed/timed out/had no pack, or the reconcile failed
    bool cancelled{false}; ///< stopped by the cancel predicate (neither success nor error)
    int passes{0};
    int processed{0};
};

class SoftwareTitleDimension {
public:
    /// All arguments are borrowed. The two store references prove both schemas are
    /// migrated (construction order); the owner's SQL is its own.
    SoftwareTitleDimension(pg::PgPool& pool, ProductRegistryStore& registry,
                           SoftwareInventoryStore& inventory, yuzu::MetricsRegistry* metrics = nullptr);

    SoftwareTitleDimension(const SoftwareTitleDimension&) = delete;
    SoftwareTitleDimension& operator=(const SoftwareTitleDimension&) = delete;

    /// ONE bounded pass in its own transaction. `cancelled` and the 60 s wall
    /// budget are polled every 256 titles and before each write; a trip rolls the
    /// pass back (`cancelled` / `timed_out`). Never throws.
    [[nodiscard]] PassResult run_pass(const std::function<bool()>& cancelled = {});

    /// One hourly tick: passes until a short page / failure / cap / cancel, then the
    /// queue reconcile, then the gauges. Never throws.
    [[nodiscard]] TickResult run_tick(const std::function<bool()>& cancelled = {});

    /// Refresh the curation-queue device counts against the current `title_triples`
    /// and drop `open` rows whose title vanished (rejected rows persist). One
    /// transaction under the same try-lock; true on success or peer skip.
    [[nodiscard]] bool reconcile_queue(const std::function<bool()>& cancelled = {});

    /// Recompute the exposed gauges. A degraded read leaves the previous values
    /// (never a false zero).
    void refresh_gauges();

private:
    pg::PgPool& pool_;
    [[maybe_unused]] ProductRegistryStore& registry_;     // construction-order proof
    [[maybe_unused]] SoftwareInventoryStore& inventory_;  // construction-order proof
    yuzu::MetricsRegistry* metrics_;
    std::string last_pack_version_label_;
};

} // namespace yuzu::server
