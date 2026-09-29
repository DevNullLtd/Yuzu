#pragma once

/// @file pg_retention_guard.hpp
/// WS-10 (#2508): the clock-guarded, SINGLE-WRITER-safe retention DELETE for
/// Postgres stores, as ONE reviewed implementation the #2508 prunes share
/// (`app_perf_fleet_store`, `preflight_run_store`, `deployment_run_store`).
///
/// WHY SHARED, not copied per store. The routed "clock-guarded retention" concern
/// says "copy the SHAPE, never the numbers." The three #2508 targets are
/// structurally identical Postgres retention deletes differing ONLY in table,
/// timestamp column/unit, and their substrate-tuned constants — so this helper IS
/// the shape, and every number is a per-store parameter (`ClockGuardedPruneSpec`).
/// For catastrophic-if-wrong retention code, one implementation exercised by an
/// exhaustive table test is strictly safer to verify than three hand-copies, and
/// it matches the codebase's single-chokepoint discipline
/// (`dispatch_confined_arms`, `authz_topology_floor`, `body_cap_policy`). The
/// pure decision rule stays the shared `audit_retention::classify` (part 6's
/// "record which way you went" is the per-call-site `missing_anchor` choice +
/// comment; it is NOT hidden in here).
///
/// The seven parts (all implemented here; the reference is
/// `execution_tracker.cpp::reconcile_stale_concurrency_claims` + `audit_store`):
///   1. probe by OUTCOME (would-wipe), excluding implausibly-future rows via a
///      PER-STORE `implausibility_bound` — a FORWARD-SKEW ceiling, NOT a TTL
///      relationship: a row stamped more than `now + bound` ahead is treated as
///      clock-skew noise and dropped from the would-wipe denominator. The #2508
///      columns (`created_at_ms`, `day`) are PAST-dated — a legitimate row is
///      never future — so a small bound (1 day) is correct and a large one would
///      WEAKEN the guard (one far-future row would veto `would_wipe` forever).
///      (Contrast `audit_store`, whose `now + window + slack` horizon is right
///      because ITS column is a FUTURE expiry; that relationship is inapplicable
///      here — do not import it.);
///   2. a PERSISTED clock reading in `retention_meta` (survives restarts);
///   3. SANITISE it — below `min_plausible_reading` (negative/garbage) OR
///      ahead-of-now (a backward shared-clock step) → prev_unusable/BadState,
///      never a quiet re-stamp (mirrors `AuditStore`'s `*prev < 0 || *prev > now`);
///   4. SUPPRESS only a repeat of the SAME full fact set;
///   5. cap every accepted pass UNCONDITIONALLY (`cap_per_pass` LIMIT);
///   6. a DELIBERATE missing-anchor decision (`MissingAnchorPolicy`), recorded
///      at the call site;
///   7. absolute elapsed-time step floor (`big_step_floor`, in the column's unit).
/// SINGLE-WRITER: the whole probe-decide-delete runs in ONE txn whose first
/// statement is `pg_try_advisory_xact_lock(advisory_lock_key)` — a replica that
/// loses the race skips this tick (another drains it; the anchor advances on the
/// winner), so N replicas never race the anchor or the delete. The clock is read
/// from Postgres `now()` in-SQL (the shared clock, #3715), never a replica's
/// `system_clock`, so cross-host skew cannot split the guard.
///
/// UNIT-AGNOSTIC. Everything is expressed in the timestamp COLUMN's native unit,
/// so `now_expr` yields the current time in that unit and `retention_window`,
/// `big_step_floor`, `implausibility_bound` and `min_plausible_reading` are all in
/// that same unit. The two units in use today are BOTH epoch-derived integers:
/// milliseconds for `created_at_ms` (preflight/deployment) and day-floored
/// unix-SECONDS for `app_perf`'s `day` column (a bucket like
/// `(epoch_secs/86400)*86400`, so its `now_expr` is raw epoch seconds, NOT a
/// day-NUMBER). A future store with a true day-number column would need its own
/// `/86400` now_expr and matching constants — do not copy an existing example blind.
///
/// TRUSTED-CONSTANTS CONTRACT (catastrophic — this is a retention chokepoint).
/// The SQL-identifier / SQL-expression spec fields (`target_table`, `ts_column`,
/// `now_expr`, `meta_table`, `*_key`, `advisory_lock_key`) are string-interpolated
/// into the SQL, NOT bound as parameters (an identifier cannot be a `$` param).
/// Every one MUST be a compile-time constant authored at the call site and MUST
/// NEVER carry caller/attacker-controlled input — a runtime-derived value in any
/// of them is a server-side SQL-injection vector. Only the numeric values
/// (`retention_window` → `cutoff`, `cap_per_pass`) are runtime, and those are
/// bound as `$N` params. EXTEND this helper for a new store by adding a call site
/// with constant fields; never route a runtime string through them.

#include "pg_pool.hpp"

#include <yuzu/audit_retention_rules.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::server::pg {

/// Part 6: what a missing durable anchor means for THIS store. Decline = a
/// from-boot skewed clock must not silently delete (non-regenerable data;
/// audit_store's answer). Proceed = the data is regenerable/re-mintable, so a
/// decline buys nothing (ResultSetStore's answer).
enum class MissingAnchorPolicy { Decline, Proceed };

struct ClockGuardedPruneSpec {
    std::string_view store_label;      ///< for logs/metrics, e.g. "app_perf_fleet_store"
    std::string_view target_table;     ///< schema-qualified, e.g. "preflight_run_store.runs"
    std::string_view ts_column;        ///< the retention timestamp column, e.g. "created_at_ms"
    /// SQL yielding "now" in the column's unit, e.g.
    ///   "(EXTRACT(EPOCH FROM now())*1000)::bigint"  (ms — created_at_ms) or
    ///   "(EXTRACT(EPOCH FROM now()))::bigint"       (epoch seconds — app_perf's
    ///                                                day-floored-seconds `day`).
    /// (A true day-NUMBER column would use "…/86400)::bigint"; no store does today.)
    std::string_view now_expr;
    std::string_view meta_table;       ///< schema-qualified retention_meta(key TEXT PK, value TEXT)
    std::string_view anchor_key;       ///< retention_meta key for the persisted reading
    std::string_view settled_key;      ///< retention_meta key for the bootstrap-settled marker
    std::string_view facts_key;        ///< retention_meta key for the last anomaly fact set
    /// SQL bigint expression for the advisory-lock key, DISTINCT per store, e.g.
    ///   "hashtext('preflight_run_store:runs_prune')".
    std::string_view advisory_lock_key;
    std::int64_t retention_window;     ///< delete rows older than now - this (column unit)
    std::int64_t big_step_floor;       ///< part 7 absolute step threshold (column unit)
    std::int64_t implausibility_bound; ///< part 1: forward-skew ceiling — drop rows stamped > now + this ahead from the would-wipe denominator (column unit). For a PAST-dated column keep this SMALL (e.g. 1 day); it is NOT a TTL relationship — see the header.
    std::int64_t min_plausible_reading;///< part 3: an anchor below this is unusable (column unit)
    std::int64_t cap_per_pass;         ///< part 5 unconditional LIMIT
    MissingAnchorPolicy missing_anchor;///< part 6 (recorded at the call site)
    /// Optional CUTOFF alignment (column unit), default 0 = none. When > 0 the
    /// cutoff is floored to a multiple of this (`cutoff = (cutoff/align)*align`) so
    /// a bucketed column deletes on a bucket boundary. It aligns ONLY the cutoff —
    /// `now_expr` MUST stay a RAW reading so the persisted anchor + the part-7
    /// big_step comparison see real elapsed time; flooring the reading itself makes
    /// two adjacent buckets look one full bucket apart and false-fires Step every
    /// boundary crossing. `app_perf`'s day-floored-seconds `day` sets 86400; the
    /// ms stores leave it 0.
    std::int64_t cutoff_align = 0;
};

struct ClockGuardedPruneOutcome {
    int deleted = 0;                                          ///< rows deleted this pass
    audit_retention::Anomaly anomaly = audit_retention::Anomaly::None;
    bool declined = false;    ///< a new anomaly declined this pass
    bool skipped_lock = false;///< another replica held the advisory lock this tick
    bool error = false;       ///< the txn failed (connection/query); nothing deleted
};

/// Run one clock-guarded, single-writer, capped retention pass per the spec.
/// Best-effort: on connection/query failure returns `error=true, deleted=0` and
/// leaves the anchor unchanged (the caller's liveness signal). Logs the outcome
/// (warn on decline, info on delete, debug on lock-skip). Throws only
/// `std::bad_alloc` (building the SQL/param strings); a leak or half-commit is
/// impossible via RAII (PgTxn rollback + Lease release), and the call sites wrap
/// it — but it is not unconditionally `noexcept`.
[[nodiscard]] ClockGuardedPruneOutcome run_clock_guarded_prune(
    PgPool& pool, const ClockGuardedPruneSpec& spec,
    std::chrono::milliseconds acquire_timeout);

} // namespace yuzu::server::pg
