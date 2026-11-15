#pragma once

/// @file software_lifecycle_store.hpp
/// Born-on-Postgres software lifecycle store (ADR-0006/0008/0012; schema
/// `software_lifecycle_store`, SAM-23). Two tables: `lifecycle_rule` (shipped, external and imported
/// date rules keyed by product key and dot-component version prefix) and `lifecycle_declared`
/// (dates hosts report about themselves, GLOBAL: one row per distinct fact, never one per host).
/// The lifecycle STATE is not stored: it is computed at read by the pure evaluator
/// (`software_lifecycle_rules.hpp`) from those two tables, so a precedence change or a corrected
/// date never leaves a materialised copy behind. This class owns the schema, the writes, the
/// bounded reads and `evaluate_batch`; it has no route, no MCP tool, no page and no job thread.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at construction on a pinned
/// lease, schema-qualifies every runtime statement and binds every value with `exec_params`. No
/// secrets are stored. Failure posture (ADR-0012 §1):
///   - **Construction:** fail-closed. The server refuses to start when the store cannot open or
///     when the embedded seed cannot be parsed or loaded.
///   - **Seed load (`replace_rules`):** fail-closed. It reports its failure as an error the caller
///     turns into a refused start; a newer binary's seed therefore always replaces the stored
///     `shipped` rows, in one transaction under an advisory lock.
///   - **Reads:** AUTHORITATIVE. A closed store, a pool timeout or a query error returns
///     `std::nullopt` / `Error::Kind::Unavailable`, counted on
///     `yuzu_server_software_lifecycle_store_read_degrade_total{reason}`, NEVER a silent empty. An
///     empty value is a genuine zero-row answer. Lifecycle `unknown` is an evaluation result, not
///     a degrade.
///   - **`upsert_declared`:** fail-soft. Declared facts are re-reported by hosts, so a transient
///     outage returns false (logged, counted on the `write_degrade` counter) and the next report
///     repeats the fact.
///
/// Log levels (the counters are exact; the counted log lines are sampled per log level, `warn`
/// and `error` each separately: the first degrade of that level and every 100th after it, so a
/// storm at one level never hides the first line of the other):
///   - `warn`: the reads and `upsert_declared` degrades (closed store, pool timeout, query
///     error). The caller already gets an explicit nullopt / Unavailable / false, a retry can
///     succeed, and the next host report repeats the fact, so the line only records that it
///     happened.
///   - `error`: `corrupt_row` and `row_cap`. The stored data itself is wrong or over its bound, no
///     retry repairs it, and an operator has to act.
///   - `error`: a `replace_rules` transaction failure. It refuses the boot (the seed load is
///     fail-closed), so it is the line an operator reads to learn why the server did not start.
///
/// Declared facts are never deleted here, so a superseded date stays in `lifecycle_declared` (a few
/// rows per product version). The evaluator decides which row wins; the store keeps both, each
/// with its own `last_seen`. Retention ships with the first producer of declared facts.
///
/// Time: `loaded_at` is the database clock, authored in-SQL. Shipped rows are re-inserted at every
/// start, so `loaded_at` (and `rule_id`) is when this server last loaded the rule, not when its
/// date became known. `last_seen` is the caller's receipt time of the report.

#include "software_lifecycle_rules.hpp"

#include <chrono>
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

/// Most (product_key, version) lookups, or product keys, one read or `evaluate_batch` takes.
inline constexpr std::size_t kLifecycleBatchMax = 500;
/// Most declared facts one `upsert_declared` call takes.
inline constexpr std::size_t kLifecycleDeclaredBatchMax = 5000;

/// One (product key, version) to resolve.
struct LifecycleLookup {
    std::string product_key;
    std::string version;
};

class SoftwareLifecycleStore {
public:
    struct Error {
        enum class Kind {
            Unavailable, ///< store closed, no connection in time, or a read failed
            TooMany,     ///< more than kLifecycleBatchMax lookups; nothing ran
            InvalidInput ///< a key, version, date or negative `now_secs` is unusable; nothing ran
        };
        Kind kind{Kind::Unavailable};
        std::string message;
    };

    explicit SoftwareLifecycleStore(pg::PgPool& pool);

    SoftwareLifecycleStore(const SoftwareLifecycleStore&) = delete;
    SoftwareLifecycleStore& operator=(const SoftwareLifecycleStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Count the two degrade families on `yuzu_server_software_lifecycle_store_{read,write}_degrade_total`.
    void set_metrics(yuzu::MetricsRegistry* metrics) noexcept { metrics_ = metrics; }

    /// Replace every stored rule of `source` (external, imported or shipped) with `rules`, in one
    /// transaction under an advisory lock; idempotent, and other sources are untouched. Every rule
    /// must pass `validate_lifecycle_rule`, carry `source`, and be distinct on
    /// (product_key, version_prefix, event); at most `kLifecycleCsvMaxRows` rules. Returns the
    /// number stored, or the reason nothing changed.
    [[nodiscard]] std::expected<std::size_t, std::string>
    replace_rules(LifecycleSource source, const std::vector<LifecycleRule>& rules);

    /// Record host-declared facts: one row per distinct (product_key, version, event, date); a
    /// repeat keeps the newest `last_seen`. At most `kLifecycleDeclaredBatchMax` facts, each
    /// passing `validate_declared_fact`. False = nothing was written.
    [[nodiscard]] bool upsert_declared(const std::vector<DeclaredFact>& facts);

    /// Every rule of the given product keys (at most `kLifecycleBatchMax`; more is refused).
    /// nullopt = degraded or refused; an empty vector = no rows.
    [[nodiscard]] std::optional<std::vector<LifecycleRule>>
    rules_for(const std::vector<std::string>& product_keys);

    /// Every declared fact of the given exact (product_key, version) pairs (at most
    /// `kLifecycleBatchMax`; more is refused). nullopt = degraded, refused, or more than 20,000
    /// rows. An empty vector = no rows.
    [[nodiscard]] std::optional<std::vector<DeclaredFact>>
    declared_for(const std::vector<LifecycleLookup>& lookups);

    /// Resolve each lookup with the pure evaluator over the stored rows, in input order. At most
    /// `kLifecycleBatchMax` lookups per call: this is the bounded pass.
    [[nodiscard]] std::expected<std::vector<LifecycleEvaluation>, Error>
    evaluate_batch(const std::vector<LifecycleLookup>& lookups, std::string_view today,
                   std::int64_t now_secs);

    /// Test seam: shorten the bounded lease wait. Not for production use.
    void set_acquire_timeout_for_test(std::chrono::milliseconds t) noexcept { timeout_ = t; }

private:
    static constexpr std::chrono::milliseconds kAcquireTimeout{2000};
    std::chrono::milliseconds timeout_{kAcquireTimeout};
    pg::PgPool& pool_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    bool open_{false};
};

} // namespace yuzu::server
