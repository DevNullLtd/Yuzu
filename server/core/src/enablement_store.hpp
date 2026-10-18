#pragma once

/// @file enablement_store.hpp
/// The durable enablement store (ADR-3006 PM1.1b): rules, per-endpoint desired
/// and reported state, and the continuity anchor. A sibling accessor over the
/// `plugin_config_store` schema — PluginConfigStore owns the v3 migration, this
/// class reads and writes the three tables it adds (enablement_rules,
/// enablement_endpoints, enablement_meta).
/// The pure decisions (hashes, caps, the anchor grammar, the loader) are in
/// enablement_state_core.hpp; this file is the SQL shell.
///
/// POSTURE. Authoritative (ADR-0012 s1). Every read returns a typed
/// std::expected<T, Error>; a missing row is NotFound or an empty value, a runtime
/// fault is Unavailable — never collapsed. Every acquire is bounded
/// (try_acquire_for / with_txn_for, plus SET LOCAL statement_timeout on the batch
/// write). The one unbounded acquire is the construction smoke read's sibling in
/// PluginConfigStore, not here.
///
/// CAPS at the boundary: rules (count, units per rule, id, selector, audit_ref),
/// the registration identity, report fields, anchor bytes.
///
/// WIRE SPELLINGS are frozen by the first persisted row: provenance is exactly
/// operator | carried_over | system (enablement_state_core.hpp).
///
/// WRITE-ON-CHANGE. Nothing is rewritten when it would not change: an identical
/// report inside an hour writes nothing, a re-resolution that reaches the same hash re-stamps the row
/// without touching desired_*.
///
/// REGISTRATION-ORDER GUARD. The registry's install order is per-process and
/// in-memory. Each registration carries (boot_id, seq) where seq is assigned under
/// the registry mutex at install time, so within a process seq order IS install
/// order; upsert_on_registration is conditioned on it, and an older registration's
/// observer that completes after a newer one's matches zero rows and cannot
/// overwrite the winner's identity or input_gen. A different boot_id
/// always wins: across processes the write is last-writer, which is the per-replica
/// registry's status quo (cross-replica ordering needs a shared presence seam, not
/// this store).
///
/// input_gen. Bumped by every event that can change an endpoint's resolution input
/// (a registration). set_desired_batch stamps a row resolved only if its input_gen is
/// unchanged at write time, so a change landing between planning and commit leaves
/// the row stale and it is re-resolved — never erased.
///
/// COUNTERS AND THE FENCE. (epoch, counter) is issued ONLY inside set_desired_batch,
/// by the leader, under the epoch fence. Its FIRST data statement is one UPDATE of
/// the single enablement_meta row that (a) reserves the counter range, (b) requires
/// regressed_at IS NULL and (c) embeds LeaderElector::epoch_fence_sql — so the
/// freeze and the fence are indivisible from the reservation. That statement is the
/// first data statement of a READ COMMITTED transaction, which is the isolation
/// contract leader_elector.hpp states for an embedded fence. A paused ex-leader's
/// batch matches zero rows and is rejected (Error::Fenced); a declaration that
/// commits before the statement is seen, one committing concurrently blocks on the
/// row lock and is re-checked. Residual: a handover committing after the statement's
/// snapshot is the same narrow effectively-once window the command outbox accepts
/// (FOR KEY SHARE on the leader_state row is the upgrade path).
/// A batch is bounded: acquire <= 5 s and three statements at <= 5 s each.
///
/// record_report is ONE conditional UPDATE (no read-then-write): the CASE that
/// clears pending_since and the WHERE that suppresses a duplicate are evaluated
/// against the row's current version under its row lock, so a report equal to the
/// PREVIOUS desired state can never clear pending_since for a state issued in
/// between, and concurrent reports serialise on the row.
///
/// LOADER DUTIES (enablement_resolver.hpp, make_persisted_rule): a rule refused at
/// load is quarantined, counted (rules_rejected_total{reason}), logged once with a
/// neutralised id and the label only (never the selector or RE2 text) and listed,
/// never silently omitted; unresolved_units is computed at load with resolve()'s own
/// predicate, gauged and alerted.
///
/// THE CONTINUITY ANCHOR (<data_dir>/enablement-anchor, three lines: store id, epoch,
/// counter) is this host's witness of the highest (epoch, counter) it has seen.
///  - PRESENT and disagreeing (another store id, or ahead of the store, or
///    unreadable) -> the store is declared Regressed: enablement_meta.regressed_at
///    is set, issuing desired state freezes, /readyz reports it.
///  - MISSING is only unwitnessed: counted, latched on /readyz for the boot, then
///    written from the store's current highest. ReportAhead (an agent reporting an
///    (epoch, counter) above the store's) is the second witness, counted here and
///    declared by PM2.1.
///  - The anchor is NEVER lowered: write_anchor reads enablement_meta authoritatively
///    and the file itself on every write; a store behind THIS host's file (a dump
///    restored under a running server) is declared, not overwritten, and nothing is
///    written while regressed.
///  - Durability, stated narrowly: the contents are fsynced BEFORE the rename, so a
///    crash can never leave a torn anchor (a torn file would read as unparseable, a
///    false regression). The directory entry is best-effort: a crash right after the
///    rename may lose the rename and leave the PREVIOUS anchor, which is <= the store
///    (Ok on restart) — never a false regression and never a lowered witness.
///
/// RECOVERY. A crash between a batch commit and the anchor write leaves file < store
/// (Ok on restart). Stamped rows stay stamped (resolved_version is the durable progress).
/// A restore of an older dump on this host leaves store < file (Regressed at boot).
/// A restore onto a host with no file is Unwitnessed. A retired row is never written
/// by registration or a batch. Registration and report writes replay idempotently.

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "enablement_resolver.hpp"
#include "enablement_state_core.hpp"
#include "enablement_units.hpp"
#include "pg/pg_pool.hpp"

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class EnablementStore {
public:
    enum class Error {
        Unavailable,  ///< store not open, or a bounded lease/statement could not be had
        NotFound,     ///< no such row (a genuine miss, not a database error)
        InvalidInput, ///< failed a cap, a grammar or an authoring rule
        WriteFailed,  ///< a write statement failed
        Regressed,    ///< the store is declared regressed: nothing may be issued
        Fenced,       ///< the leader epoch is no longer current: nothing was written
    };
    [[nodiscard]] static std::string_view to_string(Error err);

    using RuleRow = enablement::RuleRow;

    struct LoadedRules {
        std::vector<enablement::Rule> rules;
        std::vector<std::string> quarantined; ///< ids refused at load (never silently omitted)
        std::vector<std::string> unresolved_units;
        std::int64_t rules_version{0}; ///< read in the SAME snapshot as the rows
    };

    struct Identity {
        std::string hostname;
        std::string os;
        std::string arch;
        std::string agent_version;
    };
    /// The (process boot id, in-process install sequence) of a registration.
    struct Registration {
        std::string boot_id;
        std::uint64_t seq{0};
    };

    struct EndpointRow {
        std::string agent_id;
        Identity identity;
        std::string reg_boot_id;
        std::int64_t reg_seq{0};
        std::int64_t input_gen{0};
        std::int64_t resolved_version{0};
        std::vector<std::string> desired_units;
        std::string desired_hash;
        std::int64_t desired_epoch{0};
        std::int64_t desired_counter{0};
        std::int64_t reported_epoch{0};
        std::int64_t reported_counter{0};
        std::string reported_hash;
        bool report_ahead{false};
        bool pending{false};
        /// Age of the pending state in seconds, computed in SQL (so a second replica
        /// answers from the row); nullopt when nothing is pending.
        std::optional<std::int64_t> pending_age_seconds;
        bool has_held_state{false};
        bool retired{false};
    };

    struct BatchWrite {
        std::vector<enablement::DesiredRow> changed;
        std::vector<enablement::StampRow> unchanged; ///< unchanged + skipped rows
        std::int64_t rules_version{0};
        std::string cursor;
        std::string leader_lock_name;
        std::int64_t leader_epoch{0};
    };
    struct BatchResult {
        std::int64_t issued{0};  ///< counters reserved (== changed.size())
        std::int64_t written{0}; ///< rows whose desired_* was written
        std::int64_t stamped{0}; ///< unchanged rows re-stamped
    };

    enum class ReportOutcome { Written, Skipped, Ahead };

    struct MetaRow {
        std::string store_id;
        std::int64_t epoch{1};
        std::int64_t counter{0};
        std::int64_t rules_version{1};
        std::string overlay_hash;
        std::string job_cursor;
        bool regressed{false};
        std::string regressed_reason;
    };

    /// The I/O-free picture /readyz serves.
    struct RegressionState {
        bool regressed{false};
        std::string reason;
        std::int64_t since_ms{0};
        bool anchor_unwitnessed{false};
        std::int64_t report_ahead_endpoints{0};
    };

    enum class AnchorWrite { Written, Refused, Failed };

    /// Borrows the shared pool. `overlay` is this release's unit overlay (used to
    /// validate authored rules and to compute unresolved units); `kinds` are the
    /// durable selector attribute kinds and alias a static catalog that must outlive
    /// the store. Smoke-reads enablement_meta: is_open() is true iff the v3 schema
    /// is present, i.e. PluginConfigStore migrated first.
    EnablementStore(pg::PgPool& pool, enablement::UnitOverlay overlay,
                    std::vector<std::string_view> kinds);

    EnablementStore(const EnablementStore&) = delete;
    EnablementStore& operator=(const EnablementStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }
    /// The unit overlay this release shipped (the resolver resolves against it).
    [[nodiscard]] const enablement::UnitOverlay& overlay() const noexcept { return overlay_; }

    /// Wire the registry for the store's counters and gauges. Set once during
    /// single-threaded startup; every closed label set is pre-seeded.
    void set_metrics(yuzu::MetricsRegistry* m);

    // -- Rules -----------------------------------------------------------------

    /// Author or replace a rule. Validates caps, provenance and (make_rule) that
    /// every named unit exists today; a rule naming only vanished units is
    /// InvalidInput before any write. One transaction: bump rules_version FIRST
    /// (row-locks enablement_meta, so concurrent authors serialise and the cap
    /// cannot be raced), then count ACTIVE rules other than this id and refuse at
    /// kMaxRules, then upsert. Editing an already-active rule at the cap passes.
    [[nodiscard]] std::expected<void, Error> put_rule(const RuleRow& row);
    /// Deactivate (never delete). Same bump-first transaction; never cap-checked.
    [[nodiscard]] std::expected<void, Error> deactivate_rule(std::string_view id);
    [[nodiscard]] std::expected<std::vector<RuleRow>, Error> list_rules(bool active_only) const;
    /// Load every active rule through the loader (see LOADER DUTIES). rules_version
    /// and the rows share ONE REPEATABLE READ snapshot.
    [[nodiscard]] std::expected<LoadedRules, Error> load_rules() const;

    // -- Endpoints -------------------------------------------------------------

    /// Upsert the registration identity (conditioned on the registration-order
    /// guard), bumping input_gen and clearing resolved_version. Best-effort:
    /// failures are counted on write_degrade_total and the registration proceeds.
    void upsert_on_registration(const std::string& agent_id, const Identity& identity,
                                const Registration& registration);
    [[nodiscard]] std::expected<EndpointRow, Error> get_endpoint(std::string_view agent_id) const;
    /// One conditional UPDATE (see the banner). Ahead means the reported (epoch,
    /// counter) exceeds the store's highest; it is counted and flagged, never
    /// declared here (PM2.1 owns the threshold).
    [[nodiscard]] std::expected<ReportOutcome, Error>
    record_report(std::string_view agent_id, std::int64_t epoch, std::int64_t counter,
                  std::string_view hash);

    // -- Desired state ---------------------------------------------------------

    [[nodiscard]] std::expected<BatchResult, Error> set_desired_batch(const BatchWrite& batch);

    // -- Meta, continuity, regression ------------------------------------------

    [[nodiscard]] std::expected<MetaRow, Error> get_meta() const;
    /// Record this release's overlay hash; if it differs, bump rules_version in the
    /// same statement (every row becomes stale). true = it changed.
    [[nodiscard]] std::expected<bool, Error> sync_overlay_hash(std::string_view hash);

    /// Boot-time classification of the anchor file against the store (see the
    /// banner). Regressed declares the store; Unwitnessed counts, latches for
    /// /readyz and writes the anchor from the store's current highest.
    [[nodiscard]] std::expected<enablement::Continuity, Error>
    check_continuity_at_boot(const std::filesystem::path& anchor_path);
    /// Write the anchor from the store's committed highest. Refused (never lowered)
    /// while regressed or when the file is ahead of / foreign to the store.
    AnchorWrite write_anchor(const std::filesystem::path& anchor_path);

    /// Declare / clear a regression (PM2.1 and tests; no route calls them here).
    /// Both UPDATE the meta row, so they serialise with set_desired_batch.
    [[nodiscard]] std::expected<void, Error> set_regressed(std::string_view reason);
    [[nodiscard]] std::expected<void, Error> resolve_regression();
    /// Re-read regressed_at / reason and the report-ahead endpoint count into the
    /// cache that serves /readyz. The cache is never the authority for a write.
    void refresh_regression();
    [[nodiscard]] RegressionState regression() const;
    /// Test seam: set the /readyz cache without a database. Production code must not
    /// call it; the cache is refreshed only by refresh_regression().
    void set_regression_state_for_test(const RegressionState& state);

private:
    void count(const char* name, const char* label_key, const char* label_value) const;
    void count_write_degrade(const char* reason) const;
    void count_read_degrade(const char* reason) const;
    /// A bounded read lease; empty when the store is closed or the pool timed out, and
    /// the degrade reason is counted.
    [[nodiscard]] pg::PgPool::Lease read_lease() const;
    /// The same for a write; empty on the same two causes, not counted (the caller
    /// returns Unavailable, and write_degrade_total is for best-effort writes).
    [[nodiscard]] pg::PgPool::Lease write_lease() const;
    /// set_regressed / resolve_regression: one UPDATE of the meta row, then a cache refresh.
    [[nodiscard]] std::expected<void, Error>
    update_meta_regression(std::string_view set_clause, const std::vector<std::string>& params);
    void apply_regression_cache(bool regressed, std::string reason, std::int64_t since_ms);

    pg::PgPool& pool_;
    enablement::UnitOverlay overlay_;
    std::vector<std::string_view> kinds_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    // The /readyz cache.
    std::atomic<bool> regressed_{false};
    std::atomic<bool> anchor_unwitnessed_{false};
    std::atomic<std::int64_t> report_ahead_endpoints_{0};
    std::atomic<std::int64_t> regressed_since_ms_{0};
    mutable std::mutex reason_mu_;
    std::string regressed_reason_;
};

} // namespace yuzu::server
