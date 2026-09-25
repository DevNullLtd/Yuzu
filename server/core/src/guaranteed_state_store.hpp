#pragma once

/// @file guaranteed_state_store.hpp
/// Server-side storage for Yuzu Guardian — the "Guaranteed State" system.
/// Migrated to PostgreSQL (ADR-0006/0008/0009/0038, schema
/// `guaranteed_state_store`); was `guaranteed-state.db` (SQLite). See
/// docs/yuzu-guardian-design-v1.1.md §9.1 for the schema design and
/// docs/adr/0038-guaranteed-state-store-postgres-migration.md for the
/// migration's posture decisions (this header follows that ADR verbatim);
/// its Update records `migrate_from_sqlite()`'s retirement
/// (chore/retire-migrate-from-sqlite-batch-b, #3623) — `server.cpp` now runs
/// a detect-and-warn probe over the legacy file instead.
///
/// Responsibilities:
///   - Persist GuaranteedStateRule definitions (yaml_source is authoritative;
///     the denormalised columns are for indexing / listing / RBAC filtering).
///     Caller (REST handler) is responsible for deriving the denormalised
///     fields (severity / os_target / scope_expr) from yaml_source atomically
///     on create/update — the store does NOT re-parse.
///   - Persist GuaranteedStateEvent rows reported by agents (drift detected,
///     drift remediated, guard unhealthy, resilience escalated, etc.).
///   - Reap expired events + their DEX projection via `reap_expired()`, called
///     from the server's maintenance tick (the #2496 `gc_sweep` clock-guarded
///     shape — see the .cpp) so multi-GB/day ingest during a fleet-wide
///     incident does not grow the database unbounded.
///
/// Events are an **immutable audit-style log** — intentionally no foreign key
/// from `guaranteed_state_events.rule_id` to `guaranteed_state_rules(rule_id)`.
/// When a rule is deleted, its historical events remain for forensic review.
/// Time-based expiry is the single retention mechanism.
///
/// ── Posture (ADR-0012 §1 / ADR-0038), split by table family ─────────────────
///  - **Rules + meta reads — AUTHORITATIVE, type-distinguishable** (the
///    catastrophic read): `list_rules` / `rule_names` / `rule_names_for`
///    return `std::expected<std::vector<T>, std::string>`; `get_rule` keeps a
///    three-state `std::expected<std::optional<Row>, GuaranteedStateReadError>`
///    (found / genuinely-absent / degraded — mirrors
///    `DeviceInventoryStore::CiReadError`). `agent_rule_statuses` /
///    `agent_rule_statuses_for_agent` / `errored_rule_count` (enforce-gate/
///    census/ADR-0017 list-read input) are the same
///    `std::expected<..., std::string>` shape. A degraded read
///    collapsing to silent empty would push an EMPTY rule set to the fleet —
///    a Guardian-wide disarm — so every push/reconcile consumer MUST abort
///    (503 / no-op push) on `!result`, never fan out an empty container it
///    cannot distinguish from "no rules configured".
///  - **Rule/meta writes — fail-hard**: `create_rule`/`update_rule`/
///    `delete_rule` stay `std::expected<void, std::string>`, surfaced to the
///    REST caller. `bump_policy_generation` is one atomic
///    `UPDATE ... RETURNING` (cross-process state on Postgres; the SQLite
///    read-modify-write idiom does not port).
///  - **Event/observation ingest — FAIL-SOFT** (mirrors ADR-0037 ingest): a
///    dropped enforcement-history row is re-derivable from the agent's next
///    report cycle; ingest must never block the gRPC thread. Infra-level
///    drops (pool exhaustion / lease timeout / BEGIN-prepare-exec-commit
///    failure) bump the existing `yuzu_server_guardian_events_{dropped,ingest_errors}_total` family (ADR-0037
///    label convention) IN ADDITION to the existing four-way
///    `EventInsertOutcome` classification + its per-outcome atomics below.
///  - **Status upserts — fail-soft with the same counter**; status READS stay
///    type-distinguishable (see above).
///  - **DEX analytic reads — deferred widening (ADR-0038, follow-up #2659).**
///    The ~20 `dex_*` aggregate reads plus `query_events` / `rule_activity` /
///    `daily_remediations` / `query_observations` KEEP their plain
///    `std::vector<T>` / value-type signatures this PR (empty-on-degrade,
///    behavior-identical to the SQLite store) — the `std::optional` widening
///    fans out to ~68 call sites across 5 consumer files and is tracked as a
///    follow-up (#2659), amendable per-file. What THIS PR lands at the store
///    seam: every such read counts+logs a degrade via
///    `yuzu_server_guardian_read_degrade_total{reason}` + a sampled `DegradeSampler`
///    warn on store-not-open / lease-timeout / query-error, so the silent
///    empty is at least visible on `/metrics` even though the return type
///    does not yet distinguish it. None of these reads feeds an
///    enforce/target decision (playbook's deny-or-benign class).
///    **Named exception (#4855):** `dex_device_signal_summary` now ALSO has a
///    type-distinguishable `dex_device_signal_summary_checked` twin
///    (`std::optional`, `dex_read_checked<>`) — the per-device DEX
///    experience-score surfaces (dashboard lens, REST
///    `GET /api/v1/dex/devices/{id}`, MCP `get_dex_device_score`, and the pure
///    per-device `dex_device_score()` helper they all route through) fail
///    closed on a degrade instead of rendering it as a healthy, signal-free
///    100. The plain `dex_device_signal_summary` above stays on the store as
///    a documented, still-empty-on-degrade form (unchanged signature/
///    behaviour, kept for any caller that only wants the #2659 posture) —
///    this widens ONE read for ONE consumer class, not the #2659 fleet-wide
///    set; every other `dex_*` read above is still deferred.

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dex_types.hpp" // ADR-0031 WS-A4: DEX leaf value types relocated here (pure, store-free)
#include "guardian_types.hpp" // ADR-0031 WS-A4 (ninth family): GuaranteedStateRuleRow/EventRow/
                              // EventQuery/ReadError relocated here (pure, store-free) — see that
                              // header's own comment for the ODR-safe relocation shape

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

// Reserved sentinel rule_id marking a RULELESS DEX observation (no live rule).
// Single server-side source of truth — `is_reserved_rule_id` (the projection +
// census guard) and `ingest_guardian_response` (the blast-radius feed gate)
// both reference this, so a rename can't silently desync the two paths
// (gov architect/consistency). MUST stay equal to the agent's
// `kObservationRuleSentinel` (agents/core .../dex_event.hpp) — different binary,
// shared wire convention.
inline constexpr const char* kObservationRuleId = "__observation__";

// GuaranteedStateRuleRow / GuaranteedStateEventRow / GuaranteedStateEventQuery
// / GuaranteedStateReadError were relocated VERBATIM to the pure
// "guardian_types.hpp" (included above) for the ADR-0031 WS-A4 GuardianApi
// seam (ninth family); they remain in namespace yuzu::server and every
// includer keeps seeing them transitively.

// ── Overview aggregation result types (Slice A dashboard overview) ───────────
struct GuardianRuleActivity {
    std::string rule_id;
    int64_t detected{0};        // drift.detected
    int64_t remediated{0};      // drift.remediated
    int64_t failed{0};          // remediation.failed
    int64_t unhealthy{0};       // guard.unhealthy
    int64_t distinct_agents{0}; // distinct agents with any event in the window
    std::string last_activity;  // max timestamp in window ("" if none)
};

struct GuardianDayCount {
    std::string day;        // YYYY-MM-DD
    int64_t remediated{0};
    int64_t failed{0};
};

struct GuardianAgentRuleStatus {
    std::string agent_id;
    std::string rule_id;
    std::string state;       // "compliant" | "drifted" | "errored"
    std::string updated_at;  // ISO-8601 of the event that set it
};

// The DEX read-model value types (GuardianObservationRow + the Dex* observation
// aggregations) were relocated verbatim to the pure "dex_types.hpp" (included
// above) for the ADR-0031 WS-A4 DexApi seam; they remain in namespace
// yuzu::server and every includer keeps seeing them transitively.

// Hard upper bound on `GuaranteedStateEventQuery::limit` and every DEX
// `limit` parameter. Defence-in-depth: materialising millions of rows into a
// std::vector would produce a GB-scale RSS spike.
inline constexpr int kMaxEventsLimit = 10'000;

// Default retention for `guaranteed_state_events` (+ its lockstep
// `guardian_observations` projection). 30 days matches `audit_store`.
// Override via the GuaranteedStateStore constructor.
inline constexpr int kDefaultEventRetentionDays = 30;

// Outcome of a single-event ingest. The agent journal re-sends on every
// reconnect, so a matching-fields event_id redelivery is EXPECTED + idempotent
// — it must be quiet and counted apart from a genuine collision (same
// event_id but MISMATCHED immutable fields). Ingest runs the DEX blast-radius
// + alert observers ONLY on `Inserted`; Redelivered / Conflict / Error all
// return before the observers.
enum class EventInsertOutcome { Inserted, Redelivered, Conflict, Error };
struct EventInsertResult {
    EventInsertOutcome outcome{EventInsertOutcome::Error};
    std::string error; // set for Conflict (mismatch detail) + Error (db message); empty otherwise
    std::int64_t committed_wall_ns{0}; ///< Application-observed wall-clock instant (ns since the
                                        ///< Unix epoch) captured immediately after a successful
                                        ///< COMMIT, for `Inserted` only — 0 for every other
                                        ///< outcome. This is NOT a durable column and NOT the
                                        ///< database's internal commit instant: it is a
                                        ///< benchmark-diagnostic field on this in-memory result
                                        ///< only (#4606 criterion-10 T_server). Never persisted.
};

// GuaranteedStateReadError (the type-distinguishable single-object read
// error surface for `get_rule`) was relocated to "guardian_types.hpp" too —
// see that header's comment.

class GuaranteedStateStore {
public:
    /// Borrows the shared pool and runs the `guaranteed_state_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed. `now_fn`, when set, replaces
    /// `reap_expired()`'s process-clock read (`std::chrono::system_clock`) —
    /// unset (default) uses the real clock; this is a test seam only (mirrors
    /// `PolicyEvaluator::Deps::now_fn`), never wired from production. As of
    /// #2663 (fjarvis review) this value feeds ONLY the cheap pre-transaction
    /// plausibility check — every retention DECISION reads PostgreSQL's own
    /// clock instead (`AuditStore::cleanup_once`'s `#2360/1d` shape), so
    /// `now_fn` can no longer move a reap verdict.
    explicit GuaranteedStateStore(pg::PgPool& pool,
                                   int retention_days = kDefaultEventRetentionDays,
                                   std::function<int64_t()> now_fn = nullptr);

    GuaranteedStateStore(const GuaranteedStateStore&) = delete;
    GuaranteedStateStore& operator=(const GuaranteedStateStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_guardian_read_degrade_total{reason}`
    /// (DEX/analytics reads) and the existing `yuzu_server_guardian_events_{dropped,ingest_errors}_total` family
    /// (fail-soft ingest) and the reap-pass counter. Set ONCE during
    /// single-threaded startup, before serving — the pointer is read without
    /// synchronisation on serving threads. A null registry (default, e.g.
    /// unit tests) disables emission; every emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // Rule CRUD. Mutating methods return `std::expected<void, std::string>`
    // (fail-hard — ADR-0038 posture). Duplicate-UNIQUE collisions (name or
    // rule_id) are reported as an error prefixed with `kConflictPrefix` so
    // REST handlers map them to HTTP 409 (see `store_errors.hpp`).
    std::expected<void, std::string> create_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> update_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> delete_rule(const std::string& rule_id);
    /// Three-state read (ADR-0038 catastrophic-read set): found / genuinely
    /// absent (`std::nullopt`) / degraded (`std::unexpected`). Callers MUST
    /// treat a degrade as "cannot verify" (503), never as "not found" (404).
    std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError>
    get_rule(const std::string& rule_id) const;
    /// AUTHORITATIVE, type-distinguishable (ADR-0038 catastrophic-read set):
    /// `std::unexpected` on a store/pool/query degrade, NEVER a silent empty
    /// vector — the Push fan-out / reconcile / baseline-deploy consumers MUST
    /// abort (503 / no-op push) on `!result`, never fan out an empty set they
    /// cannot distinguish from "no rules configured".
    std::expected<std::vector<GuaranteedStateRuleRow>, std::string> list_rules() const;

    // Event ingest + query. FAIL-SOFT (ADR-0038): a lease/query/transaction
    // failure is logged + counted (`yuzu_server_guardian_events_ingest_errors_total` +
    // `events_ingest_errors_total()`), never throws, never blocks the caller.
    //
    // insert_event_classified() is the primary ingest entry point: it returns the
    // four-way EventInsertResult so the caller gates DEX observers on `Inserted`,
    // treats a matching `Redelivered` as a quiet idempotent no-op, and keeps a
    // mismatched `Conflict` on the loud CC7.3 drop metric. insert_event() is the
    // back-compat convenience wrapper (Inserted/Redelivered -> ok; Conflict/Error ->
    // unexpected) for callers that don't distinguish redelivery (tests, batch seed).
    // [[nodiscard]]: the four-way outcome is what the caller gates the DEX observers on
    // (only `Inserted` may run them).
    [[nodiscard]] EventInsertResult insert_event_classified(const GuaranteedStateEventRow& row);
    std::expected<void, std::string> insert_event(const GuaranteedStateEventRow& row);

    /// Batch ingest: wraps all rows in a single transaction. On failure, the
    /// whole batch is rolled back — see the HARD CONSTRAINT note on the .cpp
    /// definition (no live caller today; must not be used for redelivery-prone
    /// ingress).
    std::expected<std::size_t, std::string>
    insert_events(const std::vector<GuaranteedStateEventRow>& rows);

    // ── DEX / analytics reads (ADR-0038 "deferred widening", #2659) ──────────
    // Plain value-type returns, empty-on-degrade — behavior-identical to the
    // SQLite store. Every degrade path (store not open / lease timeout / query
    // error) counts `yuzu_server_guardian_read_degrade_total{reason}` + a sampled
    // warn log via the store-local DegradeSampler (see the .cpp), so the loss
    // is visible on /metrics even though the type does not yet distinguish it.

    std::vector<GuaranteedStateEventRow> query_events(const GuaranteedStateEventQuery& q = {}) const;

    std::vector<GuardianObservationRow> query_observations(int limit = kMaxEventsLimit) const;

    DexCrashSummary dex_crash_summary(const std::string& since = "",
                                      const std::string& platform = "") const;
    std::vector<DexAppCrashCount> dex_top_apps(const std::string& since = "", int limit = 20) const;
    std::vector<DexAppCrashCount> dex_device_top_apps(const std::string& agent_id,
                                                      const std::string& since = "",
                                                      int limit = 50) const;
    std::vector<DexModuleCrashCount> dex_top_modules(const std::string& since = "", int limit = 20) const;
    std::vector<DexDeviceCrashCount> dex_top_devices(const std::string& since = "", int limit = 20) const;
    std::vector<DexOsCrashCount> dex_crashes_by_os(const std::string& since = "") const;
    std::vector<DexDayCrashCount> dex_crashes_by_day(const std::string& since = "") const;
    std::vector<DexSignalCount> dex_signal_summary(const std::string& since = "",
                                                    const std::string& platform = "") const;
    DexBootStats dex_boot_stats(const std::string& since = "") const;
    std::vector<DexDeviceBoot> dex_slowest_boots(const std::string& since = "",
                                                 int limit = 10) const;

    std::vector<DexSubjectCount> dex_signal_subjects(const std::string& obs_type,
                                                     const std::string& since = "",
                                                     int limit = 20,
                                                     const std::string& platform = "") const;
    std::vector<DexOsCrashCount> dex_signal_by_os(const std::string& obs_type,
                                                  const std::string& since = "") const;
    std::vector<DexDeviceCrashCount> dex_signal_devices(const std::string& obs_type,
                                                        const std::string& since = "",
                                                        int limit = 20,
                                                        const std::string& platform = "") const;
    std::vector<DexDayCrashCount> dex_signal_by_day(const std::string& obs_type,
                                                    const std::string& since = "",
                                                    const std::string& platform = "") const;
    std::vector<DexOsScope> dex_os_signal_scope(const std::string& since = "") const;
    std::vector<DexDaySignal> dex_signal_day_matrix(const std::string& since = "") const;

    DexEntitySummary dex_app_summary(const std::string& process_name,
                                     const std::string& since = "") const;
    std::vector<DexModuleCrashCount> dex_app_modules(const std::string& process_name,
                                                     const std::string& since = "",
                                                     int limit = 20) const;
    std::vector<DexExceptionCount> dex_app_exceptions(const std::string& process_name,
                                                      const std::string& since = "",
                                                      int limit = 20) const;
    std::vector<DexDeviceCrashCount> dex_app_devices(const std::string& process_name,
                                                     const std::string& since = "",
                                                     int limit = 20) const;
    DexEntitySummary dex_device_summary(const std::string& agent_id,
                                        const std::string& since = "") const;
    std::vector<GuardianObservationRow> dex_device_history(const std::string& agent_id,
                                                           const std::string& since = "",
                                                           int limit = 100) const;
    std::optional<GuardianObservationRow> dex_observation(const std::string& event_id) const;
    std::vector<DexSignalCount> dex_device_signal_summary(const std::string& agent_id,
                                                          const std::string& since = "") const;
    /// Type-distinguishable twin of the above (#4855): `std::nullopt` on a
    /// degraded read (store-not-open / pool-timeout / query-error), never
    /// collapsed into an empty vector — the device-score builders need this to
    /// avoid rendering a degraded read as a healthy, signal-free device. Still
    /// bumps `yuzu_server_guardian_read_degrade_total{reason}` on a degrade,
    /// same as the plain form (which is now a thin `.value_or({})` over this).
    std::optional<std::vector<DexSignalCount>>
    dex_device_signal_summary_checked(const std::string& agent_id,
                                      const std::string& since = "") const;

    std::vector<GuardianRuleActivity> rule_activity(const std::string& since = "") const;
    std::vector<GuardianDayCount> daily_remediations(const std::string& since = "") const;

    // ── Status + name lookups (ADR-0038 catastrophic-read set) ───────────────
    /// AUTHORITATIVE, type-distinguishable: feeds the enforce-gate/dashboard
    /// census — empty must stay distinguishable from "could not read".
    std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
    agent_rule_statuses(const std::string& rule_id = "") const;
    std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
    agent_rule_statuses_for_agent(const std::string& agent_id) const;

    /// rule_id -> name for the whole catalogue (Push/reconcile input set).
    std::expected<std::unordered_map<std::string, std::string>, std::string> rule_names() const;
    /// Bounded variant of rule_names(): resolve names ONLY for the given
    /// rule_ids. Empty input -> empty map (success, not degrade).
    std::expected<std::unordered_map<std::string, std::string>, std::string>
    rule_names_for(const std::vector<std::string>& rule_ids) const;

    /// COUNT(DISTINCT rule_id) of rules currently in `errored` state on at
    /// least one agent, joined against the live rule catalogue (ADR-0017
    /// INV-3: confinement applied in SQL, before the aggregate — never a
    /// C++ post-filter over the whole census). `agent_scope`: nullopt = the
    /// whole fleet; engaged (including empty, INV-2) = only those agents,
    /// via `agent_id = ANY($1::text[])` — an engaged-empty scope returns 0
    /// WITHOUT issuing a query (mirrors `rule_names_for`'s empty-input
    /// posture: success, not degrade). AUTHORITATIVE like its
    /// catastrophic-read siblings above: `std::unexpected`, never a silent
    /// 0, on any store/query failure.
    std::expected<std::size_t, std::string>
    errored_rule_count(const std::optional<std::vector<std::string>>& agent_scope) const;

    std::size_t rule_count() const;
    std::size_t event_count() const;

    // Monotonic policy generation — the version stamp of the rule SET, bumped
    // atomically on every create/update/delete. Persisted (survives restart)
    // and strictly increasing.
    std::optional<uint64_t> current_policy_generation() const;

    // Bump the persisted policy generation WITHOUT mutating any rule (the
    // Baseline deploy path). Best-effort: logs on failure (mirrors the
    // original SQLite contract — callers do not currently consume a result).
    void bump_policy_generation();

    // Observability — lock-free cumulative counters for Prometheus scraping.
    uint64_t events_written_total() const noexcept { return events_written_.load(); }
    uint64_t events_reaped_total() const noexcept { return events_reaped_.load(); }
    uint64_t observations_proj_failures_total() const noexcept {
        return observations_proj_failures_.load();
    }
    uint64_t observations_reaped_total() const noexcept { return observations_reaped_.load(); }
    uint64_t events_dropped_total() const noexcept { return events_dropped_.load(); }
    uint64_t events_redelivered_total() const noexcept { return events_redelivered_.load(); }
    uint64_t events_ingest_errors_total() const noexcept { return events_ingest_errors_.load(); }

    /// Clock-guarded retention sweep (#2496 `gc_sweep` shape — ADR-0038,
    /// replaces the SQLite background cleanup thread). Called from the
    /// server's maintenance tick (~60-minute cadence, matching the old
    /// thread's default `cleanup_interval_min`). Reaps
    /// `guaranteed_state_events` AND its lockstep `guardian_observations`
    /// projection in the SAME guarded pass (the PII projection must never
    /// outlive its parent event). One sweeping replica at a time via
    /// `pg_try_advisory_xact_lock`; a durable `gc_meta` reading +
    /// anomaly-fact-set guards against a skewed wall clock mass-expiring
    /// live rows, including the #2579 missing-anchor trigger (a pass that has
    /// not yet reached a verdict on this database, with rows already expired,
    /// declines once and anchors — this store's recorded answer is AuditStore's
    /// decline, not ResultSetStore's opt-out; see the `Facts` construction site).
    /// Emits `yuzu_server_guardian_reap_passes_total{result=swept|noop|declined|
    /// declined_no_anchor|failed|skipped_lock}`.
    void reap_expired();

private:
    pg::PgPool& pool_;
    bool open_{false};
    int retention_days_;
    std::function<int64_t()> now_fn_; // test seam only; see ctor doc
    yuzu::MetricsRegistry* metrics_{nullptr};

    std::atomic<uint64_t> events_written_{0};
    std::atomic<uint64_t> events_reaped_{0};
    std::atomic<uint64_t> observations_proj_failures_{0};
    std::atomic<uint64_t> observations_reaped_{0};
    std::atomic<uint64_t> events_dropped_{0};      // event_id conflict, MISMATCHED payload
    std::atomic<uint64_t> events_redelivered_{0};  // event_id conflict, MATCHING payload
    std::atomic<uint64_t> events_ingest_errors_{0}; // operational ingest fault

    // Compute ttl_expires_at = now + retention_days*86400 in epoch seconds;
    // retention_days <= 0 means "never expire" (returns 0, the sentinel the
    // reaper's `ttl_expires_at > 0` predicate excludes).
    int64_t compute_ttl_epoch() const;
};

} // namespace yuzu::server
