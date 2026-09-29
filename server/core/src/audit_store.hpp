#pragma once

/// @file audit_store.hpp
/// SOC 2 evidence chain — operator actions, agent enrolment, fleet-topology
/// events, background schedule execution, and every behavioural-PII access.
/// Born on PostgreSQL (ADR-0006/0008/0009/0040, schema `audit_store`).
/// Highest-stakes store on the ladder: a lost or silently-truncated audit
/// trail is a compliance failure (CC6.6/CC7.2), not degraded telemetry.
///
/// Retired 2026-09-04 (ADR-0009 hard-cutover Update): the legacy-SQLite
/// backfill (`migrate_from_sqlite`) is gone — no production fleet ever ran a
/// pre-Postgres build, and a leftover `audit.db` gets a boot-time WARN via
/// `legacy_sqlite_probe::warn_if_legacy_rows`, never an import.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`audit_store.audit_events`). No `sqlite3_changes()` (#1033) — mutators use
/// `RETURNING` / `PQcmdTuples`.
///
/// Failure posture (ADR-0012 §1 / ADR-0040), split by operation class — this is
/// the distinguishing decision vs ResponseStore's fail-soft ingest:
///  - **Write (`log`): FAIL-HARD.** A dropped audit event is a compliance
///    failure, not re-derivable telemetry. `log()` keeps its `bool` contract:
///    a store-not-open / pool-acquire-timeout / query error returns `false`,
///    and callers already fail-closed on `false` (behavioural-PII REST routes
///    → 503 + `Sec-Audit-Failed`; `emit_behavioral_audit`, #1647).
///    `emit_failed_` counts every `false`. Single `INSERT`, never a
///    SAVEPOINT-tolerant path.
///  - **Reads (`query`/`total_count`): degrade-distinguishable, DENY on
///    degrade.** The audit trail is authoritative evidence — a store/pool
///    failure MUST NOT read as "no audit events" (that would let a reviewer or
///    a SIEM conclude an absence of activity from an infrastructure blip). Both
///    return `std::optional<…>` / nullopt-on-degrade; the audit-log REST/MCP
///    consumers surface 503, never a false-empty. Stricter than ResponseStore's
///    deny-or-benign carve-out: the audit read is evidence, so degrade → deny.
///  - **Retention (`cleanup_once`): migration-REQUIRED clock guard** — the
///    #2360 guard ported to a single-sweeper advisory lease with durable dedup
///    (see the .cpp). Fail-hard within its advisory-lease-held transaction; a
///    probe/delete failure declines the pass (never a blind delete).
///  - **Backfill: RETIRED (ADR-0009 hard-cutover Update, 2026-09-04).** No
///    production fleet ever ran a pre-Postgres build; a leftover `audit.db`
///    is never read or imported, only WARNed on at boot if it still holds
///    rows (`legacy_sqlite_probe::warn_if_legacy_rows`).

#include <yuzu/audit_retention_rules.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct AuditEvent {
    int64_t id{0};
    int64_t timestamp{0}; // epoch seconds
    std::string principal;
    std::string principal_role;
    std::string action;
    std::string target_type;
    std::string target_id;
    std::string detail;
    std::string source_ip;
    std::string user_agent;
    std::string session_id;
    std::string result;   // "success", "failure", "denied"
    std::string mcp_tool; // MCP tool name if action was MCP-initiated (empty otherwise)
    // Actor class (ADR-1005 Decision 9 / execution-plan Phase 3a), mirroring
    // principal_class.hpp's HTTP request-metric label: "human" (session
    // cookie), "agent" (bearer/API token), "none" (unauthenticated — a failed
    // login, a probe-adjacent request; honest label, not a guess at human vs.
    // agent), or "" for any row this program cannot attribute to an HTTP
    // session/token principal at all (the agent-daemon's own gRPC channel,
    // gateway-proxied calls, server-internal/background writers — a different
    // kind of actor `principal_class_of` was never meant to classify; see its
    // own header comment). "engine" is reserved, live once Phase 4 engine-token
    // sessions exist. Populated at `AuthRoutes::make_audit_event`/
    // `audit_log_for_principal` (the two HTTP-request-shaped constructors) via
    // `principal_class_of(req)`; every other AuditEvent construction leaves it
    // at its default "".
    std::string principal_class;
};

struct AuditQuery {
    std::string principal;
    std::string action;
    std::string target_type;
    std::string target_id;
    int64_t since{0};
    int64_t until{0};
    int limit{100};
    int offset{0};
    // Match any action that starts with one of these prefixes (OR-combined),
    // e.g. {"auth.","mfa.","session."} to scope to the authentication surface
    // (sampled auth-log evidence export, #4 / SOC 2 CC7.2). Empty = no prefix
    // filter. Combines with `action` (exact) if both are set.
    //
    // CONTRACT (Hermes I-1): prefixes are bound as a SQL `LIKE <prefix>%` pattern
    // and are NOT escaped, so a caller must only ever pass code-controlled literal
    // prefixes — never untrusted input, which could smuggle `%`/`_` wildcards.
    // A degenerate all-empty list does NOT widen to "all actions" (query() emits
    // an always-false guard), so it fails closed.
    std::vector<std::string> action_prefixes;
    // When true, the result is a pseudo-random sample rather than newest-first:
    // query() fetches a bounded candidate pool in indexed timestamp order (capped
    // at kAuditSampleScanCap to bound CPU + memory — NOT `ORDER BY RANDOM()`,
    // which would full-scan the window), then shuffles in C++ and truncates to
    // `limit`. When the window holds more than the cap, the pool is the
    // most-recent kAuditSampleScanCap events (a recency bias above the cap —
    // callers presenting this as evidence must surface it). `offset` is ignored.
    bool random_sample{false};
};

// Candidate-pool cap for AuditQuery::random_sample. A sample is drawn from at
// most this many most-recent matching rows; above it the sample is recency-biased
// (see random_sample). Public so the REST layer can report `recency_capped` to an
// auditor (#4 / SOC 2 CC7.2 evidence honesty).
inline constexpr std::size_t kAuditSampleScanCap = 10000;

// ── Retention clock guard (#2360) ──────────────────────────────────────────
//
// Retention deletes rows whose TTL has passed, with "has passed" decided by the
// server's wall clock. One forward step -- a restored VM snapshot, an NTP
// correction after a dead CMOS battery, a hand-set date -- marks the whole
// evidence table expired at once, and an unguarded `DELETE ... WHERE ttl < now`
// then acts on that in a single statement. These constants bound it.
//
// The division of labour matters and is easy to get backwards: the CAP is the
// guarantee, the detectors are best-effort. See `cleanup_once`.

// Rows whose TTL lands more than this far in the future are excluded from the
// "would this pass delete everything datable?" question. See the .cpp's reap for
// the full rationale (condensed from the SQLite guard's, not carried over
// verbatim — one paragraph on the direction of error did not survive): a
// forward-skewed row that can never itself expire must not be counted as a
// survivor, or ONE bad row vetoes the guard for the life of the store.
inline constexpr std::int64_t kAuditTtlFutureSlackSec = 2 * 86'400LL;

// Upper bound on rows deleted by ONE retention pass. The load-bearing half of
// the guard: it applies unconditionally, turning an accepted wipe into a paced
// ageing-out an operator can still catch. Now safe as a per-pass DRAIN RATE for
// the ONE sweeping process (the advisory lease makes "N × 25k" impossible), so
// the 0.6M rows/day @ 60-min-interval calibration stays valid.
inline constexpr std::size_t kMaxAuditDeletesPerPass = 25000;

/// Re-arm delay after a pass that hit the per-pass cap AND left a real backlog.
///
/// The cap bounds how much one pass may delete; it was never meant to bound the
/// DRAIN RATE, but at one pass per hour that is exactly what it did: 25,000/h =
/// 6.94 rows/s, against a store whose own INSERT path measures three orders of
/// magnitude faster. Above that write rate the evidence table grows permanently
/// and never converges, and a one-off backlog (a retention-days reduction, a
/// migrated legacy trail with a longer horizon) takes months to clear. Gate 3
/// performance measured both halves; the figures live in that finding, not here.
///
/// A capped pass costs tens of milliseconds end to end, so re-arming in seconds
/// rather than an hour is close to free: the cap still bounds the lease hold and
/// the transaction size, and the steady state is unchanged because a pass that
/// does NOT hit the cap goes back to the full interval.
inline constexpr int kAuditBacklogRearmSec = 5;

/// The retention guard's outcome probe, in one home so a test can assert its
/// SHAPE (Gate 3 quality-engineer: reverting this query to the counting form it
/// replaced left the entire suite green — the only evidence the fix worked was a
/// hand-run EXPLAIN, so a future revert would ship silently).
///
/// Two properties are load-bearing and are what the test pins:
///   * EXISTS, never a counting aggregate. The guard only ever asks "any?", and
///     a `count(*) FILTER (...)` has no statement-level WHERE, so every row —
///     including the `ttl_expires_at = 0` majority, which sits OUTSIDE the
///     partial index — must be visited before either count is known.
///   * the `ttl_expires_at > 0` predicate, which is what makes the partial index
///     `idx_audit_ttl_id` eligible at all.
///
/// The test deliberately does NOT assert a query plan. The planner is
/// cost-based, and at unit-test table sizes a sequential scan is legitimately
/// cheaper; asserting "Index Only Scan" there would pin an accident.
///
/// The two halves are NOT the same shape, and that asymmetry is deliberate
/// (round-3 performance finding, 1f). Gate 3 performance measured the plans
/// at 5M rows and found the SURVIVOR half — the range check —
/// planner-dependent: it can flip to a Seq Scan once a backlog exists,
/// because bare `EXISTS(SELECT 1 FROM t WHERE range-cond)` gives the planner
/// no signal beyond the range's estimated selectivity, and a wide window
/// (retention_days can be 365) with sparse real matches at the tail is
/// exactly the shape that estimate gets wrong. The EXPIRED half does not
/// need the same treatment: during a genuine backlog the vast majority of
/// rows satisfy `< now`, so EXISTS finds a match within the first few rows
/// under ANY scan strategy — a Seq Scan is not a performance problem there,
/// only on the survivor side, where matches are a needle at the end of the
/// value range. The survivor half is rewritten as
/// `ORDER BY ttl_expires_at LIMIT 1 ... IS NOT NULL`: ordering by the
/// partial index's leading column plus a LIMIT is a plan-independent signal
/// — a Seq Scan would need a full sort before it could apply the LIMIT, so
/// the pre-ordered index path wins regardless of the range's selectivity
/// estimate. Verified locally against a 5M-row scratch table matching this
/// schema (including a stale-statistics variant, ANALYZE run before the
/// survivor rows existed): both forms returned an Index Only Scan there, so
/// the specific Seq Scan flip Gate 3 measured was not reproduced at that
/// scale in this session — the rewrite is applied on the strength of that
/// prior, cited measurement plus the plan-independence argument above, not a
/// fresh repro of the regression itself. Correctness (not just plan shape)
/// is pinned by the store-level clock-guard tests, which exercise both
/// outcomes this probe feeds.
inline constexpr std::string_view kAuditRetentionProbeSql =
    "SELECT EXISTS(SELECT 1 FROM audit_store.audit_events WHERE ttl_expires_at > 0 AND "
    "ttl_expires_at < $1::bigint), (SELECT 1 FROM audit_store.audit_events WHERE "
    "ttl_expires_at > 0 AND ttl_expires_at >= $1::bigint AND ttl_expires_at <= $2::bigint "
    "ORDER BY ttl_expires_at LIMIT 1) IS NOT NULL";

/// How long the retention thread waits before its next pass. Extracted so the
/// DECISION is testable without driving the thread or the clock: the sleep is
/// not the interesting part, the "a binding cap must not wait an hour" rule is.
[[nodiscard]] inline constexpr int audit_next_wait_s(bool cap_bound_with_backlog,
                                                     int cleanup_interval_min) noexcept {
    return cap_bound_with_backlog ? kAuditBacklogRearmSec : cleanup_interval_min * 60;
}

// Threshold for the elapsed-time detector. ABSOLUTE -- how far the clock moved
// has nothing to do with how long rows are kept. Deriving it from the retention
// window is the fatal mistake (at 365d it becomes a YEAR and never fires). Set
// past the point where an outage is itself remarkable; a server genuinely down
// for eight days declines one pass, the right trade for catching a month jump.
inline constexpr std::int64_t kAuditMinBigStepSec = 7 * 86'400LL;

class AuditStore {
public:
    /// Borrows the shared pool and runs the `audit_store` schema migration on a
    /// pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (fail-closed — every operation then declines, the right
    /// posture for an evidence store whose schema is wrong).
    explicit AuditStore(pg::PgPool& pool, int retention_days = 365,
                        int cleanup_interval_min = 60);
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;
    // Non-movable: borrows PgPool& and owns a retention thread + atomics. Already
    // immovable (deleted copy suppresses implicit moves); explicit to document
    // intent and satisfy cppcoreguidelines-special-member-functions.
    AuditStore(AuditStore&&) = delete;
    AuditStore& operator=(AuditStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_audit_read_degrade_total{reason}`
    /// (degrade-distinguishable reads). Set ONCE during single-threaded startup,
    /// before serving — read without synchronisation on serving threads. A null
    /// registry (default, e.g. unit tests) disables emission; every emit site is
    /// null-guarded. The eight retention/write counters below are ALSO exposed as
    /// lock-free atomic accessors, scraped as gauges by the server maintenance
    /// loop independently of this registry.
    ///
    /// Wiring a registry PRE-SEEDS the closed label set to 0, per
    /// docs/observability-conventions.md, so `absent()`-based alerting stays
    /// meaningful on a healthy server before any degrade has ever fired.
    void set_metrics(yuzu::MetricsRegistry* m);

    /// Persist an audit event. FAIL-HARD: returns true iff the row was written.
    /// The bool is part of the SOC 2 CC6.6/CC7.2 evidence-integrity chain —
    /// handlers that emit an audit row as compliance evidence for a privileged
    /// mutation MUST observe the return and surface partial-success. On failure
    /// (store not open, pool-acquire timeout, or query error) `emit_failed_`
    /// increments and the row is lost. `[[nodiscard]]` makes any discard visible.
    [[nodiscard]] bool log(const AuditEvent& event);

    /// Degrade-distinguishable read: `std::nullopt` on a store/pool/query failure
    /// (evidence integrity — a blip must not read as "no audit activity"); an
    /// engaged EMPTY vector is a genuine "no rows". When `q.random_sample` is set
    /// and `out_pool_size` is non-null, `*out_pool_size` receives the candidate
    /// pool size BEFORE shuffle/truncate (<= kAuditSampleScanCap) so the caller
    /// can report `recency_capped` (#4). For non-sample queries it is untouched.
    [[nodiscard]] std::optional<std::vector<AuditEvent>>
    query(const AuditQuery& q = {}, std::size_t* out_pool_size = nullptr) const;

    /// Degrade-distinguishable total row count: `std::nullopt` on degrade.
    [[nodiscard]] std::optional<std::size_t> total_count() const;

    /// The `detail` a reader should see for a row, given its target.
    ///
    /// Keyed on the TARGET -- a `RuntimeConfig` row naming a secret-valued key --
    /// rather than on a writer's action string, so a future writer recording the same
    /// key under a different verb is covered without anyone remembering to extend a
    /// list. A detail that STARTS `value=` keeps that label and loses the value; ANY
    /// other shape is replaced wholesale, because we cannot then tell which part is
    /// the credential. Deliberately not "preserve everything before the first
    /// `value=`" -- that preserved a credential written before the token, and made
    /// the guarantee depend on an ordering nothing enforces.
    ///
    /// A `config.update` on a secret-valued key recorded `value=<the secret>` in
    /// `detail` before that write path was fixed. Those rows are ALREADY on disk on
    /// any install that set the secret before upgrading, and fixing the writer does
    /// nothing for them: the readers serialise `detail` verbatim, so a seeded
    /// Operator (`AuditLog:Read`) could still read a live credential out of history.
    ///
    /// Redaction is applied on READ rather than by rewriting the rows, deliberately.
    /// An audit row is compliance evidence; editing history to hide a mistake is a
    /// worse posture than declining to disclose it, and a DELETE/UPDATE sweep over
    /// audit_events is exactly the kind of thing that must not become routine.
    /// The plaintext therefore remains at rest (unchanged by this) and stops being
    /// DISCLOSED. Operators who set the secret pre-upgrade should still rotate it.
    ///
    /// Idempotent: rows written after the writer fix already hold the placeholder.
    /// `detail` is taken BY VALUE and moved through on the common pass-through path:
    /// this runs per row on every audit read (up to kAuditSampleScanCap rows on
    /// the read path), and a const-ref parameter forced a copy of every row's
    /// detail whether or not it needed redacting. (It used to say "under the
    /// reader lock" — `mtx_` was deleted by the PostgreSQL migration; the
    /// substrate serialises, not a store-level mutex.)
    static std::string sanitized_detail(std::string_view target_type, std::string_view target_id,
                                        std::string detail);

    /// Cumulative audit-event write counts grouped by `result` value. Exposed for
    /// Prometheus scraping; reset at process start. Lock-free reads.
    uint64_t events_written(const std::string& result) const noexcept;

    /// Cumulative count of audit events that failed to persist. Audit pipeline
    /// degradation is a SOC 2 CC7.2 evidence-chain risk; surface it on /metrics.
    uint64_t emit_failed_count() const noexcept {
        return emit_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that DECLINED to delete (clock
    /// anomaly: would-wipe, big elapsed step, or an unusable durable reading).
    uint64_t clock_anomaly_skips_count() const noexcept {
        return clock_anomaly_skips_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of passes declined for the ONE reason that is not a
    /// statement about the clock: there was no usable previous reading to
    /// compare against and rows were already expired (#2579).
    ///
    /// Deliberately NOT folded into `clock_anomaly_skips_count()`, and the
    /// separation is semantic before it is operational. That counter's alert
    /// says the clock "moved in a way that WOULD have wiped audit evidence";
    /// this decline asserts nothing of the sort -- only that nothing can yet
    /// rule it out, which is a weaker claim and a different incident. Sharing
    /// the counter would have made the sibling alert's own description untrue
    /// for this case, and fired it on every server carrying a backlog through
    /// an upgrade.
    ///
    /// Expected to be 0 or 1 per database in the ordinary course: the pass that
    /// declines also anchors the reading, so the next one has a comparison
    /// point. A value that keeps climbing means the anchor is not surviving.
    /// `..._retention_persist_failed_total` is a PARTIAL signal for that, not an
    /// equivalent one: when the reading is destroyed out of band -- a restore
    /// from a pre-v3 backup, a rehydrated replica, a disk rollback -- the write
    /// succeeds every pass and that counter never moves.
    uint64_t bootstrap_declines_count() const noexcept {
        return bootstrap_declines_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that did NOT do their job. The
    /// sites are, on this substrate: any failed statement inside the pass's
    /// transaction (the lease probe, the meta read, the re-anchor, the outcome
    /// probes, the DELETE, the post-delete backlog probe); a pass refused
    /// because the caller's clock was implausible; a pass against a closed
    /// store; and an exception escaping the pass, caught at the thread
    /// boundary (`run_cleanup`'s `catch (...)`). EVERY SITE INSIDE THE
    /// TRANSACTION means nothing was deleted: the whole pass runs in one
    /// transaction, so even the post-delete backlog probe rolls the DELETE
    /// back when it fails. The thread-boundary catch is the ONE exception —
    /// it wraps the WHOLE `cleanup_once` call, including the post-commit
    /// bookkeeping (`rows_deleted_`/`cap_reached_` counters, the `spdlog::info`
    /// summary) that runs AFTER `with_txn_for` has already committed a real
    /// delete, so an exception thrown there (allocation in the log formatter
    /// is the realistic source) counts a pass that DID delete rows as failed.
    /// (An earlier revision of this comment said the opposite — "fires AFTER a
    /// successful delete … merely degraded" — which was true of the retired
    /// SQLite store, where that probe was a warning after a committed delete.
    /// The enumeration was also stale: it counted a `prepare` and a `step` that
    /// no longer exist.)
    /// Scraped SEPARATELY from
    /// `clock_anomaly_skips_count()` on purpose: both leave rows undeleted, but
    /// one means "the guard is protecting the table" and the other means "the
    /// cleanup loop is broken". A single counter could not tell an operator
    /// which, so an unbounded-growth audit table would look like a working guard.
    uint64_t cleanup_failed_count() const noexcept {
        return cleanup_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative rows deleted by retention, and passes that hit the per-pass cap
    /// AND left a backlog behind (expiry outrunning the drain — otherwise
    /// invisible on /metrics).
    uint64_t rows_deleted_count() const noexcept {
        return rows_deleted_.load(std::memory_order_relaxed);
    }
    uint64_t cap_reached_count() const noexcept {
        return cap_reached_.load(std::memory_order_relaxed);
    }

    /// Cumulative retention passes ATTEMPTED. Every other counter here is
    /// silence-means-healthy; an operator alerts on ABSENCE of movement here.
    std::uint64_t retention_passes_count() const noexcept {
        return retention_passes_.load(std::memory_order_relaxed);
    }

    /// The wall-clock reading of the most recent retention pass WHOSE CLOCK
    /// WAS USABLE.
    ///
    /// TWO CLOCKS FEED THIS GAUGE, and the difference is deliberate (#2854).
    ///   * AT CONSTRUCTION it is SEEDED from the durable `audit_retention_meta`
    ///     anchor (`last_pass_now`), which — once at least one `cleanup_once`
    ///     pass has run on Postgres — holds POSTGRESQL's clock, the one
    ///     authority every replica serialises through (see the long note at
    ///     `cleanup_once`'s advisory-lock transaction). On the very first
    ///     Postgres boot, before any `cleanup_once` pass has ever run, no
    ///     anchor row exists yet and the seed is a no-op (`0`, "never ran") —
    ///     the legacy-SQLite continuity path that used to backdate this seed
    ///     on a mid-cutover upgrade is retired (ADR-0009 hard-cutover Update,
    ///     2026-09-04); no production fleet ever had a pre-Postgres reading to
    ///     carry forward.
    ///   * ON EVERY SUBSEQUENT PASS it is overwritten with the CALLER's
    ///     process clock (`cleanup_once`), which is a liveness signal only and
    ///     drives no decision.
    /// Both are epoch seconds and on a time-synced fleet they agree within NTP
    /// slop, so the mixing is safe for the only question asked of this value:
    /// "has a pass been attempted, and how long ago". It is NOT safe to derive
    /// an elapsed-time verdict from it — nothing in `docs/prometheus/yuzu-alerts.yml`
    /// does, and the reason is recorded there.
    ///
    /// THREE SENTINELS ARE LOAD-BEARING:
    ///   * `0` means "no pass has ever run on this DATABASE" — not "not yet in
    ///     this process", which is what it meant before #2854.
    ///   * A NEGATIVE value (other than the anomaly sentinel below) means a
    ///     pass ran and the stamping clock was nonsense (dead CMOS). Stamped
    ///     and seeded unclamped on purpose — a `> 0` filter anywhere would
    ///     silently re-merge it with the `0` "never ran" state.
    ///   * `std::numeric_limits<std::int64_t>::min()` means the seed could
    ///     not establish a trustworthy reading — four distinct causes, all
    ///     mapped to this one value on purpose (#2854): the seed's own
    ///     connection/query could not run at all (so the anchor's existence
    ///     is UNKNOWN, not merely untrusted); the stored value is not a clean
    ///     integer (corrupt/hand-edited state); or it is out of the same
    ///     plausible range `cleanup_once` itself enforces (`kMaxPlausibleNow`).
    ///     Never laundered into `0`, so none of these can silently earn the
    ///     liveness family's "never ran" grace.
    ///
    ///     THE EXACT CORRECTION CONDITION (fold round 3 got this wrong once
    ///     already — read `cleanup_once` itself before touching this again,
    ///     do not paraphrase from memory): the sentinel clears at the next
    ///     pass whose CALLER-SUPPLIED clock is itself plausible
    ///     (`now <= kMaxPlausibleNow`) — even if that pass then declines or
    ///     fails for an unrelated reason (lock contention, an anomaly,
    ///     `!open_`), because the stamp happens before any of those
    ///     decisions. The one case that does NOT clear it: a pass whose
    ///     caller clock is ITSELF implausible returns before the stamp runs
    ///     at all, specifically to avoid poisoning the gauge with a value
    ///     already known to be garbage — "attempted" is not quite right
    ///     either, since that one attempt is counted (`retention_passes_`)
    ///     but does not touch this gauge.
    ///
    ///     External prose (docs, alert-rule comments) should quote this
    ///     paragraph's substance rather than re-deriving it — the causes and
    ///     the correction condition are recorded here, once, so they don't
    ///     drift across sites (#2854 fold round 4).
    ///
    /// KNOWN LIMITATION, still open after the rung-D rule redesign
    /// (#2854): neither `0` nor `INT64_MIN` is actually RESERVED.
    /// `cleanup_once` has no lower bound on the caller-supplied clock it
    /// stamps here (only `now > kMaxPlausibleNow` is rejected), so a caller
    /// passing exactly `0` or exactly `INT64_MIN` would be stamped as a
    /// live reading, indistinguishable from "never ran" or the anomaly
    /// sentinel respectively. In practice `run_cleanup`'s only real caller
    /// passes `std::chrono::system_clock::now()`, which cannot plausibly
    /// produce either value — a theoretical collision, not a reachable one.
    /// The rung-D rules CHOSE their reading of the unreserved values rather
    /// than reserving them: `0` anywhere in a window is treated as
    /// "possibly never ran" and `INT64_MIN` as "unknown, cannot disprove
    /// never-ran" (see the comment blocks above the two liveness rules in
    /// docs/prometheus/yuzu-alerts.yml). A stamped value of exactly `0`
    /// would therefore re-enter the never-ran grace — the collision cost is
    /// a mis-ROUTED page (NeverRan instead of NotRunning), never silence.
    /// Reserving the values server-side remains the durable fix if a caller
    /// beyond run_cleanup ever appears.
    std::int64_t last_pass_unixtime() const noexcept {
        return last_pass_unixtime_.load(std::memory_order_relaxed);
    }

    /// Cumulative failures to persist the retention clock reading. A sustained
    /// non-zero rate means the restart-surviving half of the guard is degraded.
    uint64_t persist_failed_count() const noexcept {
        return persist_failed_.load(std::memory_order_relaxed);
    }

    /// Run exactly ONE retention pass and return the number of rows deleted.
    /// Returns 0 when the pass declined (clock guard), when nothing was
    /// expired, when another replica held the advisory lease, or when the pass
    /// failed. `now` (epoch seconds) is the CALLER's clock — since #2360/1d it
    /// gates only the pre-txn implausibility check and stamps the liveness
    /// gauge (`last_pass_unixtime_`); the retention DECISION itself reads
    /// PostgreSQL's own clock inside the advisory-lock transaction (ADR-0040
    /// "Cross-replica clock divergence"), so a test cannot drive which anomaly
    /// classifies by varying `now` alone — it must read `pg_now(dsn)` (or
    /// hand-write the durable `audit_retention_meta` row) to control the
    /// decision.
    std::size_t cleanup_once(std::int64_t now);

    void start_cleanup();
    void stop_cleanup();

private:
    pg::PgPool& pool_;
    bool open_{false};
    int retention_days_;
    int cleanup_interval_min_;
    yuzu::MetricsRegistry* metrics_{nullptr};

    /// Restores `last_pass_unixtime_` from the durable `audit_retention_meta`
    /// anchor. Called once, at construction (#2854) — see `last_pass_unixtime()`'s
    /// doc for the two-clock / three-sentinel contract this maintains.
    void seed_last_pass_from_anchor();

    // Cumulative event write counters bucketed by `result`. Lock-free.
    std::atomic<uint64_t> events_success_{0};
    std::atomic<uint64_t> events_failure_{0};
    std::atomic<uint64_t> events_denied_{0};
    std::atomic<uint64_t> events_other_{0};
    std::atomic<uint64_t> emit_failed_{0};
    // Retention-guard counters (#2360). Atomic because the /metrics scrape reads
    // them without synchronisation.
    std::atomic<uint64_t> clock_anomaly_skips_{0};
    std::atomic<uint64_t> bootstrap_declines_{0};
    std::atomic<uint64_t> cleanup_failed_{0};
    std::atomic<uint64_t> rows_deleted_{0};
    std::atomic<uint64_t> cap_reached_{0};
    std::atomic<uint64_t> persist_failed_{0};
    // Liveness — stamped on EVERY pass including declined/failed/lock-skipped
    // ones: the question is "did the reaper run at all", not "did it delete".
    std::atomic<uint64_t> retention_passes_{0};
    std::atomic<std::int64_t> last_pass_unixtime_{0};

#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
    void run_cleanup(std::stop_token stop);
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
    void run_cleanup();
#endif
};

} // namespace yuzu::server
