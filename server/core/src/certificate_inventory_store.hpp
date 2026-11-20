#pragma once

/// @file certificate_inventory_store.hpp
/// Born-on-Postgres fleet certificate inventory store (slice-2 PR 2a-2a, schema
/// `certificate_inventory_store`, ADR-0070 D12, ADR-0016 §5, ADR-0006/0012): the server half of the
/// `certificate_inventory` daily-sync source. Design:
/// `docs/crypto-slice2-certificate-design.md`, "Server: store, ingest and lifecycle".
///
/// SHAPE. Nine tables: seven lead their key with `agent_id` (decommission and
/// confinement): `agent_state` (hash-skip state), `store_state` (one row per store per
/// device: status, reason, `observed_at`, `status_at`), `cert_location` (where a
/// certificate was seen), `cert_fact` (one row per (device,
/// certificate): the X.509 facts), and the `cert_san` / `cert_eku` / `cert_cdp` children.
/// `agent_state.sample_key` is a random 64-bit CSPRNG value the SERVER draws when it first inserts
/// an agent's row and never changes afterwards (a CSPRNG failure fails that ingest, no fallback; the
/// agent retries), copied onto the agent's `cert_fact` rows and indexed (`cert_fact_sample_idx`) so a
/// later CBOM agreement sample is ordered by a key an agent cannot choose; it is never sent to
/// an agent and no read column list includes it.
/// A `cert_fact` row exists while at least one `cert_location` row references it; the
/// ingest transaction deletes the orphans. The other two are the FLEET-SHARED `dn_dict` (key
/// `dn`, below) and `dn_dict_state` (key `k`: the DB-clock maintenance schedule and the
/// non-leader's reconcile request); the decommission cascade reaches them only through
/// `prune_dn_names`.
///
/// CLOCK. Every `*_at` / `*_seen` column is a TIMESTAMPTZ authored by the DATABASE clock
/// (never the replica's, never the agent's: #1685, ADR-0016 clock-skew rule). One value is
/// read per transaction, after the per-agent lock, from the plain DB clock. No ordering against a
/// previous report is assumed (a DB clock step or restore must not latch anything): the ok-store
/// sweep removes locations whose `full_report_at` DIFFERS from this report's value. Certificate validity columns come from the
/// certificate itself and are stored unclamped.
///
/// SCHEMA LINT. No column is named after a D13 rule id or window field, or
/// `days_remaining` (ADR-0070 D13 "Mechanical checks"). `certificate_inventory_migrations()`
/// is exported so `test_certificate_inventory.cpp` can walk the migration array.
///
/// PER-AGENT SERIALISATION. Ingest (full and hash-skip) and `delete_agent` take the SAME
/// `pg_advisory_xact_lock(hashtextextended(kCertInventoryAgentLockPrefix || agent_id, 0))` first (ingest
/// TRIES it and answers kBusy rather than parking a pooled connection), so a
/// decommission cannot interleave with an ingest's transaction. The retention
/// prune (PR 2a-2d) must take it too.
///
/// DECOMMISSION. `delete_agent` erases every table's rows for the agent in one transaction
/// under the per-agent lock. A still-running agent's next report re-creates its rows; keeping it
/// out is the decommission tombstone, which is a separate, later change.
///
/// FAILURE POSTURE (ADR-0012 §1). Ingest is fail-soft (a transient outage returns `kError`; the
/// seam answers the agent (a full report is asked to resend; a hash-only report is acknowledged and retries next interval)). `delete_agent` returns true only when the
/// transaction committed, so the decommission cascade records a rolled-back erasure as Failed.
/// A store that failed to open is visible on `/readyz`. READS (slice-2 PR 2a-2b, below) answer
/// `CertReadError` on any pool or query fault, never an empty result.
///
/// THE DN DICTIONARY (`dn_dict`, slice-2 PR 2a-2b) - invariants a future author must keep:
///   - It is a FLEET-WIDE, cross-agent table, deliberately NOT keyed by `agent_id` (the one exception to
///     the "every key leads with agent_id" rule above). It holds distinct issuer DNs and CA-subject DNs
///     ONLY, never an end-entity subject, and the read surface applies the caller's scope to
///     `cert_fact`, never to the dictionary (a name resolves for everyone; reaching a device does not).
///   - Ingest only ADDS names (`INSERT .. ON CONFLICT DO NOTHING`, sorted, one statement per report) and
///     raises role flags by a separate sorted UPDATE. NEVER use `ON CONFLICT .. DO UPDATE .. WHERE`
///     here: concurrent multi-chunk reports deadlock (60-90% measured).
///   - It must NOT outlive the facts it names (erasure): the decommission cascade and the periodic
///     background prune delete names no certificate references, ONLY via `prune_dn_names` (lock
///     candidates FOR UPDATE SKIP LOCKED, then a NEW-snapshot DELETE with NOT EXISTS). Ingest
///     takes FOR KEY SHARE on its names (sorted) after the DO NOTHING insert and RE-INSERTS any it
///     finds missing, in the same transaction, so a committed report never leaves a referenced name
///     absent (chaos-verified). The reconcile (every 5 minutes, at every process start before the
///     dictionary reads as ready) is the backstop for names a pre-existing/rolled-back writer
///     skipped: a window of at most one pass, never a permanent miss.
///   - Empty DNs are never entered (`<> ''` at ingest; the reconcile's keyset starts above '').
///   - READINESS is a marker on the table comment (`ready:<ms>`), valid only if a reconcile completed
///     AFTER this process started, with both btree indexes valid. Until then the two substring filters
///     are refused, never answered from a partial dictionary: RETRYABLE (`kReconciling`, with a
///     retry hint) while a reconcile is pending, non-retryable only for a `failed:` dictionary.
///   - The build/reconcile/prune run in `run_dn_dictionary_maintenance` (a leader-gated background
///     pass); boot, the migration and readiness never scan or index `cert_fact`.
///
/// Registered in the agent-decommission cascade (`AgentDecommissionStores::certificate_inventory`,
/// the eighth store).

#include "certificate_read_types.hpp"
#include "pg/pg_background_build.hpp"

#include <atomic>
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

struct pg_conn;
typedef struct pg_conn PGconn;

namespace yuzu::server::pg {
class PgPool;
struct PgMigration;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// The per-agent advisory-lock key prefix: the lock key is hashtextextended(prefix || agent_id, 0).
/// A STABLE constant, deliberately independent of the schema name (renaming the schema must never
/// change the key, or a rolling upgrade would run two keys for one agent). Ingest (full and
/// hash-skip), `delete_agent` and the future retention prune ALL use this one constant.
inline constexpr std::string_view kCertInventoryAgentLockPrefix = "cert_inventory:";



/// The store's migration array (schema `certificate_inventory_store`), for the D13 schema lint.
[[nodiscard]] const std::vector<pg::PgMigration>& certificate_inventory_migrations();

/// Closed store-status vocabulary (design "Store status"). `not_observed` is server-side only.
namespace cert_status {
inline constexpr std::string_view kOk = "ok";
inline constexpr std::string_view kAbsent = "absent";
inline constexpr std::string_view kUnreadable = "unreadable";
inline constexpr std::string_view kConstrained = "constrained";
inline constexpr std::string_view kNotObserved = "not_observed";
} // namespace cert_status

/// Why a read failed. kInvalid is a request the store refuses outright (defence in depth behind
/// the model's validation); every other kind is a degrade (503 + retry, never an empty result).
struct CertReadError {
    enum class Kind {
        kNotOpen,
        kPoolAcquireTimeout,
        kQueryError,
        kInvalid,
        /// A substring filter on a FAILED dictionary: NOT retryable until an operator repairs it.
        /// (A merely not-yet-reconciled one is a retryable kQueryError with `reconciling` set.)
        kSubstringIndexMissing,
        /// A SUMMARY that ran out of its wall budget: its cost grows with the visible fleet, so a
        /// retry re-runs the same scan and fails the same way. NOT retryable; narrow the scope.
        kScaleLimit
    };
    Kind kind{Kind::kQueryError};
    std::string message;
    std::string sqlstate;   ///< the PG SQLSTATE of the failing statement, "" when none
    bool timed_out{false};  ///< SQLSTATE 57014 or the armed wall deadline elapsed
    bool transient_failure{false}; ///< the retryable refusal is a transient pass FAILURE, not the start-up wait
    std::int64_t retry_hint_ms{0}; ///< when reconciling: the hint to send (0 = kReconcileRetryHintMs)
    bool reconciling{false}; ///< a kQueryError that is the EXPECTED post-restart wait (retryable + hint)
};

/// The caller's visible devices: nullopt = unfiltered, present-empty = deny-all.
using CertScopeIds = std::optional<std::vector<std::string>>;

/// One SAN entry. `type` is one of dns, ip, rfc822, uri, upn, dirname, other.
struct CertSan {
    std::string type;
    std::string value;
};

/// The facts of one certificate. An unset optional is UNKNOWN (stored NULL); a set empty string
/// is a real empty value. `der_base64` is the optional whole-DER; this PR stores it and does not
/// parse it (`server_parsed` stays false).
struct CertFactRow {
    std::string sha256; ///< lowercase hex, the row identity
    std::optional<std::string> sha1, tbs_sha256;
    std::optional<int> version;
    std::optional<std::string> serial; ///< canonical uppercase hex
    std::optional<bool> serial_negative;
    std::optional<std::string> subject_dn, issuer_dn, subject_name_sha256, issuer_name_sha256;
    std::optional<std::string> not_before, not_after; ///< RFC 3339 UTC, whole seconds
    std::optional<std::string> key_alg_oid;
    std::optional<int> rsa_modulus_bits;
    std::optional<std::string> ec_curve_oid;
    std::optional<int> ec_order_bits;
    std::optional<std::string> sig_alg_oid, pss_hash_oid, pss_mgf1_hash_oid, spki_sha256, ski,
        aki_key_id;
    std::optional<bool> is_ca;
    std::optional<int> path_len;
    std::optional<std::string> key_usage;
    std::optional<bool> self_signed;
    std::optional<std::string> key_association, key_provider, key_exportable, der_omitted;
    std::optional<std::string> der_base64;
    std::string constrained_fields; ///< comma-joined tokens, '' when none
    std::vector<CertSan> sans;
    std::vector<std::string> ekus;
    std::vector<std::string> cdps;
};

/// One place a certificate was seen. `path` is '' for a store without file paths.
struct CertLocationRow {
    std::string store_id;
    std::string path;
    std::string sha256;
};

/// One `store|` record after parsing. `status` is never `not_observed` (agent never sends it).
struct CertStoreReport {
    std::string store_id;
    std::string scope; ///< 'machine' only in slice 2
    std::string status;
    std::string reason;
};

/// Everything one full report asks the store to apply. `facts` is keyed by `sha256`; a fact is
/// only written when one of its locations lands in an `ok` or `constrained` store.
struct CertReportData {
    std::string blob_version;
    std::vector<CertStoreReport> stores;
    std::vector<CertFactRow> facts;
    std::vector<CertLocationRow> locations;
};

/// What one ingest call did.
enum class CertIngestOutcome {
    kStored,         ///< full report applied
    kTouched,        ///< hash-skip matched; freshness advanced
    kNeedFull,       ///< cold cache or hash mismatch: the agent must resend in full
    kBudgetExceeded, ///< the ingest transaction ran past its (row-scaled) time budget: rolled back
    kBusy,           ///< another report for this agent holds the lock: nothing written, retry
    kError,          ///< pool/SQL failure (transient)
};

/// Why a kNeedFull. Meaningful only for kNeedFull.
enum class CertNeedFullCause { kNone, kCold, kHashMismatch };

struct CertIngestResult {
    CertIngestOutcome outcome{CertIngestOutcome::kError};
    CertNeedFullCause need_full_cause{CertNeedFullCause::kNone};
};

/// Delete the dictionary names in `names` that NO certificate references, inside the caller's
/// transaction: statement 1 locks the candidate rows `FOR UPDATE SKIP LOCKED` (conflicts with the
/// `FOR KEY SHARE` an ingest holds on every name it relies on, so a name an in-flight ingest uses is
/// skipped), statement 2 - a NEW snapshot, taken after the locks are held - deletes only the locked
/// names that no `cert_fact` row references as an issuer or a CA subject. Shared by `delete_agent`
/// and the background prune.
[[nodiscard]] bool prune_dn_names(PGconn* conn, const std::vector<std::string_view>& names);

/// Why the substring filters can or cannot be answered right now.
enum class SubstringState {
    kReady,       ///< a reconcile that started after this process did completed; indexes valid
    kReconciling, ///< not yet: a pass is due or running (a restart, a leader change). RETRYABLE.
    kFailedTransient, ///< the last pass failed on a TRANSIENT cause (57014, 55P03, class 40/08/53):
                      ///< RETRYABLE with a pass-interval hint; never nudges the leader.
    kFailed,      ///< the last pass failed deterministically, or the dictionary is absent. NOT retryable.
};

class CertificateInventoryStore {
public:
    /// Borrows the shared pool and runs the `certificate_inventory_store` migration on a pinned lease.
    /// `is_open()` is false if the lease was empty or the migration failed (the server fails
    /// closed before reaching here).
    explicit CertificateInventoryStore(pg::PgPool& pool);

    CertificateInventoryStore(const CertificateInventoryStore&) = delete;
    CertificateInventoryStore& operator=(const CertificateInventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// True when the DISTINCT-DN dictionary behind the two substring filters is built and its btree
    /// indexes are valid (migration v2 builds it; see certificate_inventory_store.cpp). While false the
    /// read surface REFUSES those filters with CertReadError::Kind::kSubstringIndexMissing
    /// (retryable while reconciling, non-retryable once failed) rather than answer from a half-built dictionary. Boot never fails on it.
    [[nodiscard]] bool substring_index_available() const noexcept {
        return substring_state() == SubstringState::kReady;
    }
    [[nodiscard]] SubstringState substring_state() const noexcept {
        return static_cast<SubstringState>(substring_state_.load(std::memory_order_acquire));
    }
    /// Retry hint (ms) for a kReconciling answer: a poll interval, not an estimate.
    static constexpr std::int64_t kReconcileRetryHintMs = 10000;
    /// Re-check the catalog (NO DDL): picks up an operator's manual repair without a restart. Called
    /// from the fleet gauge pass. Returns the new state; unchanged when the catalog cannot be read.
    bool refresh_substring_index_state();

    /// The BACKGROUND, leader-gated build of the substring-filter dictionary (contract:
    /// pg/pg_background_build.hpp). In order: (1) the two cert_fact btree indexes, CREATE INDEX
    /// CONCURRENTLY, an INVALID leftover dropped first; (2) a batched RECONCILE of `dn_dict` from
    /// cert_fact (loose index scans, bounded batches, each its own short statement; runs at every
    /// process start before ready); (3) the optional trigram index on the small dictionary;
    /// (4) when the database clock says an hour has passed since the last one, the batched removal of names no certificate references; then (5) the marker
    /// `ready:<ms>`. Returns true when the whole run completed. A failure (SQLSTATE 57014 included)
    /// is logged with the real error, recorded as `failed: ...` unless the dictionary is already
    /// ready, and retried at the next cycle - it never throws. `should_stop` is polled between
    /// batches. Holds ONE pooled connection for its whole duration; never called on boot.
    bool run_dn_dictionary_maintenance(const std::function<bool()>& should_stop = {});

    /// The durable DB-clock scheduling state of the background pass.
    struct DictSchedule {
        std::int64_t db_now_ms{0};
        std::int64_t last_pass_start_ms{0};    ///< 0 = never
        std::int64_t last_prune_ms{0};         ///< 0 = never
        std::int64_t reconcile_requested_ms{0}; ///< 0 = never
    };
    [[nodiscard]] std::optional<DictSchedule> read_dn_dictionary_schedule();
    /// A non-leader that finds the dictionary not ready records "reconcile requested at <DB now>"; the
    /// leader's loop polls it and runs a pass when the request postdates its last pass start.
    void request_dn_reconcile();
    /// Prune now (own lease): the names no certificate references. Used by the pass and by tests.
    [[nodiscard]] bool prune_dn_dictionary(const std::function<bool()>& should_stop = {});
    /// Interrupt a running concurrent index build (stop()): safe from any thread, bounded.
    void cancel_running_build() { build_cancel_.cancel(); }
    /// Clear a per-run stop (lost leadership) after the run returned; never for shutdown.
    void clear_build_stop() { build_cancel_.reset_stop(); }
    /// Observe each pass step (`step`, `result`) - the server counts them.
    void set_dn_dict_observer(pg::StepObserver o) { dn_observer_ = std::move(o); }
    /// Unix seconds of the last successful prune recorded in the DB (0 = never); refreshed by
    /// read_dn_dictionary_schedule.
    [[nodiscard]] std::int64_t dn_dict_last_prune_unix_s() const noexcept {
        return last_prune_unix_s_.load(std::memory_order_acquire);
    }
    static constexpr std::int64_t kPruneIntervalMs = 3600000;   ///< hourly, DB clock
    static constexpr std::int64_t kPassIntervalMs = 300000;     ///< reconcile cadence

    /// Apply one full report for `agent_id` in ONE transaction under the per-agent lock.
    /// `content_hash` is the SHA-256 of the raw received bytes, recomputed by the seam. Per-store
    /// rules: ok replaces, absent removes, constrained upserts and keeps, unreadable is untouched,
    /// a stored store missing from the report becomes `not_observed`.
    [[nodiscard]] CertIngestResult ingest_full(std::string_view agent_id,
                                               const CertReportData& report,
                                               std::string_view content_hash);

    /// Hash-skip leg: compare `claimed_hash` to the stored hash under the lock. On a match,
    /// advance `agent_state.last_seen`, every carried store's `status_at`, `observed_at` for
    /// `ok`/`absent` stores only, and `cert_location.last_seen` only for the locations the last
    /// full report carried. A mismatch or a cold cache is kNeedFull.
    [[nodiscard]] CertIngestResult ingest_touch(std::string_view agent_id,
                                                std::string_view claimed_hash);

    /// Erase every table's rows for the agent in ONE transaction under the per-agent lock. Empty id -> false without touching PG. True iff committed.
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    // ── Reads (slice-2 PR 2a-2b) ─────────────────────────────────────────────────
    // Every read pushes the caller's visible-device set into SQL (`agent_id = ANY($n)`): nullopt =
    // unfiltered, present-EMPTY = deny-all, answered with no SQL (ADR-0017 / ADR-0033). Each runs
    // in ONE REPEATABLE READ transaction under a bounded `statement_timeout`, so a page and its
    // children are one snapshot. Defined in certificate_inventory_read.cpp.

    /// One page of (device, certificate) rows ordered by (agent_id, sha256), keyset-continued
    /// after `after`; `limit` is 1..kCertPageMax. `has_more` says rows exist past the page; the
    /// cursor, the truncation flags and the byte budget are the model's to apply.
    [[nodiscard]] std::expected<CertPage, CertReadError>
    list_certificates(const CertReadFilter& filter, const CertScopeIds& scope,
                      const std::optional<CertReadAfter>& after, int limit);

    /// The raw-value rollups over the filtered, scoped set.
    [[nodiscard]] std::expected<CertSummary, CertReadError>
    summarize_certificates(const CertSummaryQuery& query, const CertScopeIds& scope);

    /// Stores per (device, status) over the whole fleet, for the `fleet_store_status` gauge job.
    /// Stores per (OS bucket, status) for the fleet gauge, folded ENTIRELY in SQL: the caller
    /// passes one registry snapshot as two parallel arrays (agent id, OS bucket from
    /// cert_read::fleet_os_bucket), and at most 25 rows come back whatever the fleet size (a
    /// device absent from the snapshot is `unknown`; only the five closed statuses are counted;
    /// zero counts are omitted). The job shares a serial sweep thread with the revocation teardown
    /// backstop, so its bounds are the caller's (the sweep passes a 250 ms acquire and a 500 ms
    /// WALL budget for the whole transaction): a timeout is a CertReadError, never a partial
    /// rollup. Arrays of different lengths are kInvalid.
    [[nodiscard]] std::expected<CertFleetStatusCounts, CertReadError>
    fleet_status_counts(const std::vector<std::string>& agent_ids,
                        const std::vector<std::string>& os_buckets,
                        std::chrono::milliseconds acquire_timeout = std::chrono::milliseconds{3000},
                        std::chrono::milliseconds budget = std::chrono::milliseconds{10000});

    /// Row counts for one agent, for tests and diagnostics: {agent_state, store_state,
    /// cert_location, cert_fact, cert_san, cert_eku, cert_cdp}. nullopt on a failure.
    struct RowCounts {
        std::int64_t agent_state{0}, store_state{0}, cert_location{0}, cert_fact{0}, cert_san{0},
            cert_eku{0}, cert_cdp{0};
    };
    [[nodiscard]] std::optional<RowCounts> row_counts(std::string_view agent_id);

    /// TEST SEAM: shrink the read wall budget to exercise the deadline path.
    void set_read_budget_for_test(std::chrono::milliseconds b) { read_budget_ = b; }

    /// TEST SEAMS. Run inside the transaction (null in production): `after_lock` right after an
    /// ingest has taken the per-agent lock, `after_erase` in `delete_agent` after the deletes and
    /// before the commit. They let a test start a racing call at exactly that point.
    void set_test_hook_after_lock(std::function<void()> hook) {
        test_hook_after_lock_ = std::move(hook);
    }
    /// Fires inside ingest_full's transaction at "after_dict_insert" (names inserted, not yet
    /// pinned), "after_flag_update" (flags raised, not yet pinned) and "after_pin" (every name
    /// FOR KEY SHARE-locked). Tests drive exact interleavings with a prune / decommission / second
    /// ingest from another connection; production never sets it.
    void set_test_hook_dict(std::function<void(std::string_view)> hook) {
        test_hook_dict_ = std::move(hook);
    }
    void set_test_hook_after_erase(std::function<void()> hook) {
        test_hook_after_erase_ = std::move(hook);
    }

    /// Wire a metrics registry (the delete-failed counter). Set once at startup; null disables.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// TEST SEAM. Replaces the row-scaled ingest transaction budget (rows -> duration).
    void set_test_ingest_budget(std::function<std::chrono::steady_clock::duration(std::size_t)> f) {
        ingest_budget_ = std::move(f);
    }

    /// TEST SEAMS: `after_facts` runs inside ingest_full once the fact rows are written;
    /// `child_hash` replaces the child-set digest function (an empty result is an error).
    void set_test_hook_after_facts(std::function<void()> hook) {
        test_hook_after_facts_ = std::move(hook);
    }
    void set_test_child_hash(std::function<std::string(std::string_view)> f) {
        child_hash_ = std::move(f);
    }

private:
    pg::PgPool& pool_;
    std::atomic<int> active_full_{0};
    std::function<void()> test_hook_after_facts_;
    std::function<std::string(std::string_view)> child_hash_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    std::function<std::chrono::steady_clock::duration(std::size_t)> ingest_budget_;
    bool open_{false};
    bool refresh_substring_index_state(PGconn* conn);
    std::chrono::milliseconds read_budget_{15000}; ///< the wall budget of one read transaction
    std::atomic<std::int64_t> started_ms_{0}; ///< DB clock (ms) when this process opened the store
    std::atomic<int> substring_state_{static_cast<int>(SubstringState::kReconciling)};
    std::atomic<bool> state_logged_{false};
    std::atomic<std::int64_t> last_prune_unix_s_{0};
    pg::BuildCancel build_cancel_;
    pg::StepObserver dn_observer_;
    std::function<void()> test_hook_after_lock_;
    std::function<void()> test_hook_after_erase_;
    std::function<void(std::string_view)> test_hook_dict_;
};

} // namespace yuzu::server
