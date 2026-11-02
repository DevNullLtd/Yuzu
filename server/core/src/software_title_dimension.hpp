#pragma once

/// @file software_title_dimension.hpp
/// SAM.4 software-title normalisation. Two layers in one header:
///
///  1. PURE core - `resolve_title()` decides one title's resolution from the
///     pack/curated aliases for its alias key and the registry product (if any) whose
///     `norm_key` is exactly `norm_key(raw_name, raw_publisher)`, with no I/O. Order:
///     curated alias -> pack alias -> that exact-key product (method `exact_norm`) ->
///     birth (OFF) -> `unnormalized`. A title is LABELLED, never guessed: an
///     unresolved title keeps its normalised vendor/product/edition/version and a NULL
///     product.
///
///     The SLE matcher's `title_vendor` and `token_set` tiers are deliberately NOT
///     used: both are guesses for an identity (the superset direction labels a bare
///     "Python" as "Python Launcher", "Chrome Remote Desktop Host" as Chrome), and
///     `title_vendor` can in effect only hit a product of a DIFFERENT edition. The key embeds
///     the edition, so the edition guard is structural: a title never resolves to a
///     product of another edition.
///
///  2. `SoftwareTitleDimension` - the ADR-0012 §3 cross-store QUERY OWNER (sixth
///     after `DexAppVersionFailuresOwner`). It reads
///     `software_inventory_store.title_triples` and writes
///     `product_registry_store.title_dimension` / `curation_queue` on ONE lease per
///     pass; neither store grows a cross-schema method. Every pass is one bounded
///     transaction that sets its `statement_timeout` and then takes
///     `pg_try_advisory_xact_lock` (a peer replica holding it = skip, success).
///     Changes-only comes from the candidate query: a settled title (current
///     `pack_version`, resolved or queued) is never selected again, so a replay writes
///     nothing. A settled title is therefore NOT re-resolved when the registry or the
///     fleet changes underneath it: only a new pack version, a deleted product or the
///     stale sentinel below re-selects it.
///
/// Alias precedence: tier (curated > pack) first, then specificity
/// (eco,pub) > (eco,'') > ('',pub) > ('',''). There is NO edition wildcard: a
/// title whose normalised edition is E matches only an alias key carrying E.
///
/// Dimension invalidation: a row is re-normalised when its `pack_version`
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
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class SoftwareInventoryStore;

/// Auto-birth (minting a product for an unmatched title) is OFF: the measurement
/// that would size it has not been made, so the safe default applies. Flipping this
/// needs a product-minting path in the owner (a `static_assert` in the .cpp stops a
/// silent flip); the schema already carries `origin = 'birth'`, so no migration is needed.
inline constexpr bool kAutoBirthEnabled = false;
inline constexpr std::size_t kAutoBirthMinTokens = 2;

inline constexpr int kPassLimit = 2000;      ///< titles per pass (one transaction)
inline constexpr int kMaxPassesPerTick = 100; ///< passes per tick (up to 200,000 titles)
/// Wall budget per pass == statement_timeout. A GUARD, not the bound: the in-lease C++ is
/// O(batch) (normalise + hash lookups over two keyed reads), milliseconds for a full page.
inline constexpr std::chrono::seconds kPassBudget{60};

/// A raw installed-software triple (exactly as `title_triples` holds it).
struct TitleKey {
    std::string raw_name;
    std::string raw_publisher;
    std::string ecosystem;
};

/// One title's resolution. `norm_status` is "normalized" | "unnormalized".
struct TitleResolution {
    std::string norm_status;
    std::string method; ///< "curated" | "pack" | "exact_norm" | "birth" | "" (unnormalized)
    std::optional<std::int64_t> product_id;
    std::string vendor;
    std::string product;
    std::string edition;
    std::string title_version;
    std::string category{"other"};
    std::string purl_type;
    std::string cpe_product;
};

/// The pure per-title decision. `aliases_for_key` holds the pack/curated aliases
/// whose `raw_name` equals this title's alias key (any publisher/tier/ecosystem).
/// `exact_product` is the registry product whose `norm_key` equals
/// `norm_key(raw_name, raw_publisher)`, or null when there is none. `cpe_product`
/// comes ONLY from the matched product row (never a resolver).
[[nodiscard]] TitleResolution resolve_title(const TitleKey& key,
                                            const std::vector<NormalizationAliasRow>& aliases_for_key,
                                            const ProductRow* exact_product, bool auto_birth);

/// `source_pending`: no candidate was selected, `title_triples` is empty and
/// `installed_software` is not - the rollup that fills the candidate source has not
/// completed yet. A clean outcome, distinct from `ok` only so the job can look again soon.
enum class PassOutcome { ok, skipped_peer, no_pack, failed, cancelled, timed_out, source_pending };

struct PassResult {
    PassOutcome outcome{PassOutcome::failed};
    int processed{0};
    int normalized{0};
    int unnormalized{0};
};

struct TickResult {
    bool errored{false};   ///< a pass failed/timed out/had no pack, or the reconcile failed
    bool cancelled{false}; ///< stopped by the cancel predicate (neither success nor error)
    /// The candidate source (`title_triples`) is still empty although installed software
    /// exists: the catalogue rollup has not completed since boot or since the table was
    /// created. A clean tick; the job re-arms early so the first titles are not an hour late.
    /// False on any error or cancel, like `capped`.
    bool source_pending{false};
    /// The tick ran its pass cap and the last pass was a full page: a backlog remains.
    /// False on any error, cancel or peer skip (an immediate retry would re-select the same
    /// batch and repeat the failure), so the job re-arms early ONLY on a healthy backlog.
    bool capped{false};
    int passes{0};
    int processed{0};
};

class SoftwareTitleDimension {
public:
    /// All arguments are borrowed. The two unnamed store references prove both schemas
    /// are migrated (construction order); the owner's SQL is its own and keeps no
    /// handle to either store.
    SoftwareTitleDimension(pg::PgPool& pool, ProductRegistryStore&, SoftwareInventoryStore&,
                           yuzu::MetricsRegistry* metrics = nullptr);

    SoftwareTitleDimension(const SoftwareTitleDimension&) = delete;
    SoftwareTitleDimension& operator=(const SoftwareTitleDimension&) = delete;

    /// ONE bounded pass in its own transaction. `cancelled` and the wall `budget`
    /// (production: `kPassBudget`; a parameter so a test can trip it) are polled every
    /// 256 titles and before each write; a trip rolls the pass back (`cancelled` /
    /// `timed_out`). Does not throw: the body is wrapped in a catch-all that reports `failed`.
    /// `cancelled` must not throw.
    [[nodiscard]] PassResult run_pass(const std::function<bool()>& cancelled = {},
                                      std::chrono::seconds budget = kPassBudget);

    /// One tick: passes until a short page / failure / cap / cancel, then the queue
    /// reconcile, then (unless cancelled) the gauges. `max_passes` is the pass cap
    /// (production: `kMaxPassesPerTick`; a parameter so a test can reach the cap with
    /// a small fixture). Does not throw, because `run_pass`, `reconcile_queue` and
    /// `refresh_gauges` each catch internally; the `cancelled` predicate must not throw.
    [[nodiscard]] TickResult run_tick(const std::function<bool()>& cancelled = {},
                                      int max_passes = kMaxPassesPerTick);

    /// Refresh the curation-queue device counts against the current `title_triples`,
    /// re-queue a present current-pack `unnormalized` title whose open row was pruned
    /// while it was away, and drop `open` rows whose title vanished (rejected rows
    /// persist, and are never reopened). One transaction under the same try-lock; true
    /// on success or peer skip. Only rows whose count moved (or that are a day stale) are
    /// written. There is deliberately no would-wipe guard: an empty `title_triples` empties
    /// the open queue, and only each row's `first_queued_at` is lost (the queue is
    /// regenerated from `title_dimension` as titles return).
    [[nodiscard]] bool reconcile_queue(const std::function<bool()>& cancelled = {});

    /// Recompute the exposed gauges. A degraded read leaves the previous values
    /// (never a false zero).
    void refresh_gauges();

private:
    pg::PgPool& pool_;
    yuzu::MetricsRegistry* metrics_;
    std::string last_pack_version_label_;
};

} // namespace yuzu::server
