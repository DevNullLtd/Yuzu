#pragma once

/**
 * echo_aggregator.hpp -- Rollup aggregation and retention for Echo warehouse
 *
 * Aggregates live table data into hourly/daily/monthly summary tables.
 * Each rollup is idempotent: tracks last-processed timestamp in echo_config
 * and only processes new data on each invocation.
 */

#include "echo_db.hpp"

#include <yuzu/audit_retention_rules.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::echo {

// ── configure-time pattern-array validation caps (#541) ───────────────────────
//
// `redaction_patterns` and `process_stabilization_exclusions` feed should_redact,
// which is O(patterns × cmdline_length) per process per fast-collect cycle, so an
// unbounded array or pathologically-long element degrades the collector. The
// min-core-length floor guards a separate footgun: a 1–2 char bare substring
// (e.g. "a") matches almost every process name, silently dropping 70-90% of
// process events with no warning.
inline constexpr std::size_t kMaxPatternArrayElements = 256;
inline constexpr std::size_t kMaxPatternLength = 256;
inline constexpr std::size_t kMinExclusionCoreLength = 3;
// Pre-parse byte cap for parse_pattern_config (load path, runs every fast cycle).
// The element/length caps only apply AFTER the whole array is materialised, so a
// multi-MB tampered/legacy stored value would otherwise be fully parsed + copied
// each cycle. A maximal *valid* array is 256 × 256 chars plus JSON punctuation
// (~66 KiB); 128 KiB admits any valid config with headroom while rejecting a
// pathological blob, which is treated as "not parseable" → caller's safe default.
inline constexpr std::size_t kMaxPatternConfigBytes = 128 * 1024;

// Validate a single configure pattern. Returns an error message (suitable for
// the `error|...` configure response) or std::nullopt if valid. Always enforces
// the per-element length cap. When `require_min_core_len` is set (process
// stabilization exclusions), an effective match core shorter than
// kMinExclusionCoreLength is rejected after stripping leading/trailing `*` —
// the operator must use a longer substring. The empty/is_string checks are done
// by the caller during JSON parsing.
[[nodiscard]] std::optional<std::string> validate_config_pattern(std::string_view pattern,
                                                                 bool require_min_core_len);

// Parse a stored pattern-array config value (redaction_patterns /
// process_stabilization_exclusions) into a bounded, sanitised vector. This is
// the RUNTIME defence (#541): configure caps the array at write time, but the
// collect loop re-reads the stored value every fast cycle, so a value written
// before the cap existed — or mutated outside the plugin — must still be bounded
// here. Drops non-string, empty, and over-long (> kMaxPatternLength) elements and
// truncates to kMaxPatternArrayElements. Returns std::nullopt only when the
// stored text is not a JSON array (the caller then applies its own default);
// a valid-but-empty array yields an empty vector (explicit "no patterns").
//
// When `require_min_core_len` is set (the exclusions loader), an element whose
// effective match core — after stripping leading/trailing `*` — is shorter than
// kMinExclusionCoreLength is ALSO dropped, matching the configure-time floor in
// validate_config_pattern. This closes the load-path gap (#541): a sub-floor
// value persisted before the floor existed (a no-tamper upgrade) or written out
// of band would otherwise reach should_redact and silently suppress most process
// events. The redaction loader leaves it false — a short redaction core merely
// over-redacts a command line, it does not drop events.
[[nodiscard]] std::optional<std::vector<std::string>>
parse_pattern_config(std::string_view json_text, bool require_min_core_len = false);

/**
 * Run all pending aggregations for all sources.
 * Reads rollup marks from echo_config, processes new data, updates marks.
 * @param db        The Echo database.
 * @param now_epoch Current epoch seconds.
 * @return Total number of aggregation operations performed.
 */
int run_aggregation(EchoDatabase& db, int64_t now_epoch);

// ── Retention clock guard (#2361) ─────────────────────────────────────────────
//
// Time-based retention deletes rows older than `now - retention_default`, with
// `now` read from the endpoint clock -- the clock in the fleet most likely to be
// wrong. A dead CMOS battery, a long suspend, a cloned VM, or a boot before NTP
// converges all produce a reading that marks every row in a warehouse table
// expired at once, and the delete that follows takes the whole forensic window
// with it. These constants and this state bound that.

// Rows timestamped further ahead than this are excluded from the "would this
// pass delete everything datable?" question. They cannot be too old, so counting
// them as ordinary survivors would let ONE row written under a forward-skewed
// clock veto the guard for the life of the endpoint -- the guard would die
// exactly when it is needed. Same ROLE as the audit store's
// kAuditTtlFutureSlackSec and the journal's kJournalFutureSlackMs, but NOT the
// same value or the same shape: 24h here against 2 days there, and audit's
// column is a FUTURE ttl so its horizon adds the retention window, while this
// one is a PAST timestamp. Substrate-tuned rather than drift -- an endpoint
// skews by smaller amounts more often than a server. Do not "align" them.
inline constexpr int64_t kEchoRetentionFutureSlackSec = 24 * 3600;

// Upper bound on rows one pass deletes from one table. At the 900-second rollup
// cadence this is ~480k rows/day/table, far above the growth rate of any Echo
// warehouse table on an endpoint, so the accepting path keeps up and the latch
// never sits permanently set. Sized as a drain rate, not a batch guess.
inline constexpr int64_t kMaxEchoDeletesPerTablePerPass = 5000;

// The elapsed-time check's threshold. ABSOLUTE, for the same reason as the audit
// sibling: an earlier round used max(tier window, this), which made it a YEAR on
// the monthly tier, so the check could never fire there.
//
// Elapsed wall time cannot distinguish a forward clock jump from the agent simply
// not having run, and on an ENDPOINT not-having-run is routine -- the shortest
// time-based window here is 24h, so a smaller threshold would report every laptop
// switched off over a weekend as a clock anomaly and destroy the fleet signal this
// counter carries. 30 days is past the point where an endpoint being dark is
// itself worth noticing, while still catching what motivates the guard (a dead
// CMOS reporting 1970, a restored snapshot) by orders of magnitude.
//
// It leaves a deliberate dead band: a forward error smaller than 30 days does not
// fire on a table whose own window is shorter. The per-pass cap still bounds it.
inline constexpr int64_t kEchoMinBigStepSec = 30 * 86400;

/// UPPER bound only on a plausible caller clock (a negative reading is the legitimate dead-CMOS
/// case). Shared by run_retention (which refuses to persist a larger one as its anchor) and
/// run_budget (whose floors are all derived from `now`): a reading above it is never trusted
/// to delete anything.
inline constexpr int64_t kEchoMaxPlausibleNow = std::numeric_limits<int64_t>::max() / 4;

/**
 * Per-table clock-guard state for time-based retention. Owned by the plugin and
 * passed into every `run_retention` call so recorded fact sets survive across
 * passes.
 *
 * Deliberately IN-MEMORY, not persisted: a reboot re-declines, which is the
 * right behaviour for the wrong-RTC-at-boot case this exists to catch.
 *
 * The state carries its own mutex for the individual map touches, so reading
 * the counters (e.g. from `echo status`) never waits on a whole pass. It IS held
 * briefly across one database read -- the cap-will-bind probe in the decide
 * step -- which is safe because no EchoDatabase path ever takes this mutex, so
 * no cycle exists; an earlier version of this comment claimed it was never held
 * across a database call at all, which stopped being true in round 4. That does NOT
 * make a pass atomic: each table's probe / decide / update-entry sequence spans
 * several statements, so the CALLER must still serialise whole rollup passes
 * against each other -- a manual `echo rollup` can arrive while the 900-second
 * trigger is mid-pass. EchoPlugin holds `rollup_mu_` for exactly that.
 */
struct RetentionGuardState {
    /// Guards every member below. Held only for brief touches -- the map writes
    /// and one bounded probe -- never for a whole pass, so `echo status` can read
    /// the counters without waiting for a rollup. Serialising the passes
    /// themselves is a separate obligation the caller still owns (EchoPlugin's
    /// `rollup_mu_`); this mutex does not provide it.
    mutable std::mutex mu;
    /// The Facts most recently reported for this table (#2573), keyed by real
    /// table name. PRESENCE is the dedup key, not a bool: a table with an entry
    /// has already declined for the CURRENT fact set, so an identical repeat is
    /// a suppressed drain; a table with NO entry declines on its next anomaly.
    /// Absence means either nothing has been reported yet, or the anomaly the
    /// last entry covered is over -- the two are indistinguishable and don't
    /// need to be, because both mean "the next anomaly should be reported".
    ///
    /// A bool cannot carry anomaly IDENTITY: a DIFFERENT anomaly arriving while
    /// a bool latch was still set was neither declined nor counted, and the
    /// pass deleted (#2573, measured). Comparing the whole Facts set fixes
    /// that -- a Wipe arriving under a standing BadState is a different set
    /// from the BadState alone, and reports on its own merits
    /// (`audit_retention_rules.hpp`).
    ///
    /// One deliberate Echo-specific rule the audit sibling does not need:
    /// Anomaly::NoAnchor is NEVER recorded here. The audit store's durable
    /// `bootstrap_settled` marker is written in the SAME transaction as its
    /// verdict, so a persist failure there rolls back the whole pass, decline
    /// included. Echo's anchor write (`kRetentionLastPassKey`) is a plain
    /// `set_config` that runs independently of this map -- if it keeps
    /// failing, `no_anchor` stays true forever, and RECORDING that fact set
    /// would turn every later identical pass into a suppressed drain, quietly
    /// defeating the exact fail-safe the no-anchor trigger exists to provide.
    /// See `run_retention`'s decide step.
    std::map<std::string, yuzu::server::audit_retention::Facts> last_reported;
    /// Cumulative declines per table, surfaced through the `echo status` action.
    /// The agent has no /metrics endpoint, so this is the operator's only
    /// fleet-readable signal that an endpoint's clock is wrong.
    std::map<std::string, int64_t> declines;
    /// Cumulative probe-read failures per table. Kept SEPARATE from `declines`
    /// for the same reason the audit store separates its two counters: a table
    /// whose probes fail every pass has silently stopped being retained, and a
    /// declines-only surface reports that as "this endpoint's clock is fine".
    std::map<std::string, int64_t> failures;
    /// Cumulative delete/commit failures per table. Separate from `failures`
    /// (which counts unreadable probes) only in cause, not in meaning: both say
    /// "this table is not being retained", which is why the status surface sums
    /// them into one total.
    std::map<std::string, int64_t> delete_failures;
    /// Byte-budget passes skipped because a retention pass above saw the clock refused. Not a
    /// table and not a verdict of its own: it is a consequence of a decline or failure already
    /// counted above, so it is surfaced as `retention_guard|__budget__|<n>` and counts toward
    /// neither status total (counting it would double a clock decline and turn a failures-only
    /// event into a non-zero declines total).
    int64_t budget_skips{0};
};

/// Snapshot of the operator-facing counters, taken under `RetentionGuardState::mu`.
struct RetentionGuardCounters {
    std::map<std::string, int64_t> declines;
    std::map<std::string, int64_t> failures;
    int64_t budget_skips{0};
};

[[nodiscard]] RetentionGuardCounters retention_guard_counters(const RetentionGuardState& guard);

/// Running total of the events that say the retention pass could not trust this pass's clock:
/// clock declines plus probe-read and `__clock_state__` failures. Delete failures are NOT
/// counted: the guard admitted the clock and only a DELETE failed, which says nothing about the
/// reading the byte budget derives its floors from. The budget pass compares this total before
/// and after `run_retention` and skips when it rose.
[[nodiscard]] int64_t retention_clock_events(const RetentionGuardState& guard);

/// The exact `echo status` lines for the retention guard, in emission order:
/// a `retention_guard|<table>|<declines>` line per table that has declined, a
/// `retention_guard_failed|<table>|<failures>` line per table whose probes OR
/// deletes have failed (the two are merged -- both mean "not being retained"),
/// then, when non-zero, `retention_guard|__budget__|<n>` (excluded from both totals), then the
/// always-present totals. Split out from `do_status` purely so
/// the operator-facing format has a test seam -- `EchoPlugin` is a
/// translation-unit-local class and cannot be reached from a test.
[[nodiscard]] std::vector<std::string>
format_retention_guard_lines(const RetentionGuardState& guard);

/**
 * Run retention cleanup for all warehouse tables.
 * Enforces row-count limits on live tables and time-based retention on
 * aggregated tables.
 *
 * Row-count retention is unguarded but no longer unbounded: it still only trims
 * the excess over a fixed ceiling, so no clock reading can make it delete more than it was
 * always going to. Time-based retention is clock-guarded (#2361): a pass that
 * would delete every datable row of a table, that follows a wall-clock jump
 * larger than kEchoMinBigStepSec (an ABSOLUTE threshold -- NOT the tier's
 * retention window), that finds the stored reading IMPLAUSIBLE (ahead of the
 * current clock, negative, or unparseable), or that finds NO stored reading at
 * all (the elapsed-time check cannot run without one -- the first pass after
 * an agent upgrade or a restore), declines and is counted instead.
 *
 * The dedup key is the WHOLE fact set (#2573), not a per-table bool: a decline
 * is recorded and reported only when it differs from what was last reported
 * for that table, so a table that is genuinely all-expired still ages out on
 * later passes (an identical repeat is a suppressed, capped drain), while a
 * DIFFERENT anomaly arriving under a standing one reports on its own merits
 * instead of deleting silently. The no-anchor trigger is never recorded --
 * see `RetentionGuardState::last_reported` for why -- so a missing comparison
 * point declines every pass until the anchor heals rather than spending a
 * one-shot decline that would let a real anomaly on the very next pass go
 * unreported.
 *
 * The caller's own `now_epoch` is also refused outright, before anything is
 * persisted, when implausibly large (kEchoMaxPlausibleNow) -- see the top of
 * the implementation.
 *
 * Every accepted pass deletes at most kMaxEchoDeletesPerTablePerPass rows per
 * table, oldest first -- that cap applies to BOTH retention kinds.
 *
 * @param db        The Echo database.
 * @param now_epoch Current epoch seconds.
 * @param guard     Per-table guard state; see RetentionGuardState for the
 *                  caller's serialisation obligation.
 */
void run_retention(EchoDatabase& db, int64_t now_epoch, RetentionGuardState& guard);

/**
 * Apply an enable/disable transition for an Echo capture source.
 *
 * Updates `<source>_enabled` to `new_value` and maintains the operator-facing
 * `<source>_paused_at` config row used by the Echo dashboard's
 * retention-paused list (PR-A / issue #547). The semantics are:
 *
 *   - enabled→disabled: writes `<source>_paused_at = now_epoch` AND clears the
 *     source's diff baseline (see #538 below).
 *   - disabled→enabled: writes `<source>_paused_at = "0"` (cleared, but kept
 *     present — a missing row would be ambiguous with "never paused").
 *   - no transition (idempotent set): leaves `<source>_paused_at` untouched.
 *
 * The default for `<source>_enabled` if not yet set comes from
 * `CaptureSourceDef::default_enabled` (`"true"` for every source). So the
 * first-ever set registers as a transition only when it differs from that
 * default — the first `<src>_enabled=false` on a fresh DB is a real
 * enabled→disabled transition.
 *
 * #538: on the enabled→disabled transition the source's snapshot-diff baseline
 * (`diff_state_key(source)`) is cleared so a later re-enable starts from a clean
 * snapshot instead of diffing against the frozen pre-pause state — which would
 * emit ghost "stopped" events for every entity that exited during the pause.
 * No-op for sources without a diff baseline (perf/procperf/netqual). The CALLER
 * must serialise this against the collectors (they hold `collect_mu_` for their
 * whole enumerate→diff→set_state cycle); this function takes no lock itself.
 *
 * #538/UP-1 + #1654 (all-or-nothing): every non-usage transition -- the baseline
 * clear on enable->disable, the `_enabled` flag and `_paused_at` -- commits as ONE
 * transaction. If it fails (e.g. SQLITE_BUSY) nothing changed and this returns
 * `false`: never a disabled source with a stale baseline, and never an enabled
 * source with a wiped one.
 *
 * @param db        The Echo database.
 * @param source    Source name (e.g. "process", "tcp", "service", "user").
 * @param new_value Either `"true"` or `"false"`. Other values are rejected
 *                  upstream by the configure action.
 * @param now_epoch Current epoch seconds — used as the paused_at timestamp.
 * @return true iff the transition committed; false when it could not be persisted
 *         (source left in its previous state) or when `new_value` is not
 *         "true"/"false" or `source` is not a registry source.
 */
[[nodiscard]] bool apply_source_enabled_transition(EchoDatabase& db, std::string_view source,
                                                   std::string_view new_value, int64_t now_epoch);

/**
 * Map a capture source to its snapshot-diff baseline key in the Echo state store
 * (the key passed to `EchoDatabase::get_state`/`set_state`).
 *
 * The mapping is NOT 1:1 with the source name: `tcp`'s baseline lives under
 * `"network"`. Sources with no snapshot-diff baseline (`perf`/`procperf` keep an
 * in-memory previous reading; `netqual` is stateless) return an empty view.
 *
 * Single source of truth: both the collectors (`collect_fast`/`collect_slow`)
 * and the enable/disable transition above route through this so the on-disable
 * clear can never target the wrong key (a silent no-op).
 */
[[nodiscard]] std::string_view diff_state_key(std::string_view source);

/**
 * Canonicalise a stored `<source>_enabled` value to a strict tri-state for the
 * `status` surface (#560). do_configure only ever persists "true"/"false", so
 * any other stored value indicates the row was mutated outside the plugin
 * (corruption, disk tampering, downgrade/upgrade) and is reported as the
 * explicit "errored" sentinel — never coerced/guessed — so the dashboard can
 * render a value-error badge instead of silently omitting the source.
 *
 * Both the collect-time gate (`source_enabled`, echo_plugin.cpp) and
 * `run_retention` gate on this canonical value, so a non-canonical value fails
 * closed: collection stops AND the source's rows are preserved (not pruned).
 */
[[nodiscard]] std::string_view canonical_source_enabled(std::string_view stored_value);

/**
 * The three-state read behind the enable gate: `true` / `false` are CONFIRMED
 * (a stored value, or the registry default for a confirmed-absent row, gated on
 * the strict tri-state of #560 -- a non-canonical stored value maps to "errored",
 * which is NOT "true", so it reads `false`); `nullopt` means the config read
 * itself FAILED (closed db, SQL error) and the flag is unknown.
 *
 * Anything that DISCARDS, DRAINS, STOPS or DELETES because a source is disabled
 * must branch on this and act only on a confirmed `false`, treating `nullopt` as
 * "do nothing": collapsing it to `false` turns a transient read failure into data
 * loss for a source that is actually enabled.
 */
[[nodiscard]] std::optional<bool> source_enabled_state(EchoDatabase& db, std::string_view source);

/**
 * Collect-time gate: `source_enabled_state(...).value_or(false)`, so an unreadable flag skips.
 * Collect/retention gate only (false = skip); drain/discard/purge sites use
 * `source_enabled_state()`.
 */
[[nodiscard]] bool source_enabled(EchoDatabase& db, std::string_view source);

// ── Byte budget (echo.db size cap) ────────────────────────────────────────────
//
// `db_budget_bytes` caps what echo.db holds: used pages plus the WAL file. The cap is HARD for
// eligible data pages (the pass stops only at the target) and SOFT for the WAL:
// journal_size_limit only truncates the WAL when a checkpoint resets it, and a long echo.sql
// read on the read-only query connection can pin it, so data + WAL can sit above the budget
// until that reader ends. Rows that are never evicted (the newest 24 h of raw capture rows,
// rows the summary tier or the usage fold has not read, daily and monthly rows, the usage
// tables, paused or errored sources) can hold used pages above the target. The overage is
// measured whenever `status` runs and surfaced as `budget_over_bytes`, never hidden.

/// Default and minimum `db_budget_bytes` (250 MiB and 32 MiB). Eviction targets the budget less
/// kEchoWalAllowanceBytes (echo_db.hpp) of data pages.
inline constexpr int64_t kEchoDbBudgetBytesDefault = 262144000;
inline constexpr int64_t kEchoDbBudgetBytesMin = 33554432;
/// Rows per eviction batch; one batch is one transaction and one hold of the database lock.
inline constexpr int64_t kBudgetBatchRows = 1000;
/// Raw capture rows newer than this are never evicted, whatever the rollup mark says.
inline constexpr int64_t kBudgetRawFloorSec = 86400;
/// Hourly rows newer than this are never evicted. Daily and monthly rows are never evicted.
inline constexpr int64_t kBudgetHourlyFloorSec = 172800;
/// The same floor for procperf_hourly, which the daily app-perf sync re-reads for the last two
/// completed UTC days plus today (sync_source_app_perf.cpp) and the server overwrites those
/// days from whatever it receives: evicting an hour the sync will still re-send would shrink an
/// already-correct daily aggregate. 5 d = 2 completed days + today + slack.
inline constexpr int64_t kBudgetProcPerfHourlyFloorSec = 432000;
/// Steady-state wall-clock budget for one eviction pass, checked between batches.
inline constexpr int64_t kBudgetPassDeadlineMs = 2000;

/// echo_config keys written by the budget engine (the first two are cumulative counters).
inline constexpr std::string_view kBudgetEvictedRawKey = "budget_evicted_raw_rows_total";
inline constexpr std::string_view kBudgetEvictedHourlyKey = "budget_evicted_hourly_rows_total";
inline constexpr std::string_view kDbBudgetKey = "db_budget_bytes";
inline constexpr std::string_view kAutoVacuumDeferredKey = "auto_vacuum_deferred_at";

struct BudgetPassResult {
    int64_t evicted_raw{0};
    int64_t evicted_hourly{0};
    int64_t data_bytes_after{0};
    /// Still over target and nothing evictable is left (floors, exemptions and the rollup
    /// marks leave no eligible row).
    bool exhausted{false};
    /// The pass ran out of time with eligible rows left.
    bool deadline_hit{false};
    /// Something stopped or skipped part of the pass (the cause is logged): the storage size
    /// was unreadable, the clock reading was implausible, or a probe/delete on one table
    /// failed -- that table is skipped for the rest of the pass and the others carry on. Never
    /// retried in-pass; never combined with `exhausted` (a failed table may still hold
    /// eligible rows).
    bool failed{false};
};

/**
 * Evict warehouse rows until used data pages are at or under `target_bytes`.
 *
 * Order: raw capture rows first, from the table holding the most rows,
 * oldest first; only once no raw row is eligible, hourly rows, never newer than 48 h (5 d for
 * procperf_hourly, kBudgetProcPerfHourlyFloorSec). Daily,
 * monthly, `usage_*`, netqual and the sources with no summary tier (netconn, power,
 * removable, registry) are never touched. Paused and errored sources are exempt.
 *
 * Preservation contract: a raw row at or above its source's rollup mark is never evicted
 * (the rollup can still summarise it), nor is any raw row newer than 24 h, nor a process_live
 * row the usage fold has not read. Rows BELOW the mark that the H11 clamp skipped were never
 * summarised; the existing retention already prunes them on age, and eviction treats them the
 * same way, oldest first and only under size pressure.
 *
 * Each batch (kBudgetBatchRows) is one transaction that also bumps the persisted eviction
 * counter, so a crash never loses a count. `time_left` is consulted before every batch.
 *
 * Trust in the inputs: an unreadable storage size and an implausible clock (above
 * kEchoMaxPlausibleNow; every floor derives from `now_epoch`) both fail the pass with nothing
 * evicted; a rollup mark ahead of `now_epoch` proves nothing about what was summarised, so
 * that source's raw rows are skipped. The pass also stops, without arming a catch-up, when a
 * batch leaves the WAL above kEchoWalAllowanceBytes -- a reader is pinning it and further
 * batches could not be recycled -- and the next maintenance pass retries.
 */
[[nodiscard]] BudgetPassResult run_budget(EchoDatabase& db, int64_t now_epoch,
                                          int64_t target_bytes,
                                          const std::function<bool()>& time_left);

/// The table-ranking probe SQL: rows-by-id-span as two separate extrema probes (each is an
/// O(log n) b-tree edge lookup; the combined MAX-MIN aggregate scans). Exposed for the
/// query-plan test.
[[nodiscard]] std::string budget_rank_probe_sql(std::string_view table);

/// Sources whose raw `<src>_live` rows the budget may ever evict / whose `<src>_hourly` rows it
/// may ever evict, derived from the schema registry (structure only: the rollup marks, the
/// enabled flag and the floors decide eligibility at run time). A new capture source joins
/// these sets automatically, so the unit test pins them to literal lists: adding one must be a
/// deliberate decision about whether its rows are a record or a summary.
[[nodiscard]] std::vector<std::string> budget_raw_eligible_sources();
[[nodiscard]] std::vector<std::string> budget_hourly_eligible_sources();

/// Whether the fast tick should run another eviction slice, and with which clock. A pass that
/// ran out of time with rows left to evict arms a catch-up; every slice of that drain then runs
/// with the reading the ARMING pass was admitted with (the retention clock guard had a verdict
/// on it), never a fresh one: a slice has no guard contact of its own, so a clock that stepped
/// forward since would widen every floor with nothing to refuse it. `admitted_now` is only
/// meaningful when `armed` (and is 0 otherwise); it is a separate field, not a sentinel, because
/// a reading <= 0 is the legitimate dead-CMOS case (see kEchoMaxPlausibleNow).
struct BudgetCatchUp {
    bool armed{false};
    int64_t admitted_now{0};
};

/// The catch-up decision after a pass: armed only when the pass ended on its deadline with rows
/// still eligible and data still over target. A failed pass is retried by the next maintenance
/// pass, not hammered; an exhausted one has nothing left to take. A slice re-arms through this
/// same function with the same `admitted_now`, so a drain never acquires a newer clock until a
/// guarded maintenance pass admits one.
[[nodiscard]] constexpr BudgetCatchUp budget_catch_up_after(const BudgetPassResult& res,
                                                            int64_t target_bytes,
                                                            int64_t admitted_now) noexcept {
    if (res.deadline_hit && !res.exhausted && !res.failed && res.data_bytes_after > target_bytes)
        return {true, admitted_now};
    return {};
}

/// Bytes data + WAL sit above the budget; 0 within it. Depends only on the measured sizes,
/// never on how the last eviction pass ended.
[[nodiscard]] constexpr int64_t budget_over_bytes(int64_t data_bytes, int64_t wal_bytes,
                                                  int64_t budget_bytes) noexcept {
    return std::max<int64_t>(0, data_bytes + wal_bytes - budget_bytes);
}

enum class VacuumAction { kSkip, kRun, kDefer };

/// Gate for the one-off conversion VACUUM (auto_vacuum -> incremental). Run only when the file is
/// not already incremental, eviction has brought data under target (or has nothing left to
/// evict -- `eviction_exhausted`, otherwise a database whose remainder is exempt would wait
/// for a shrink that can never come), the freelist is large (at least 32 MiB and a quarter of
/// the file), the volume has twice the used size free, and no deferral was recorded in the
/// last 24 h. A marker ahead of `now` (written during a forward clock excursion) is stale,
/// never a reason to wait. Too little free disk is kDefer (the caller records the time and
/// reports `deferred`); every other unmet condition is kSkip.
[[nodiscard]] VacuumAction vacuum_decision(int64_t auto_vacuum, int64_t data_bytes,
                                           int64_t target_bytes, int64_t freelist_bytes,
                                           int64_t file_bytes, int64_t free_disk_bytes,
                                           int64_t deferred_at, int64_t now,
                                           bool eviction_exhausted) noexcept;

/// The conversion-deferral time to feed vacuum_decision. `failed_write_copy` is the in-memory
/// attempt time kept ONLY while the most recent marker write failed (a later successful write
/// clears it to 0), and the marker has a single writer, so when it is non-zero it is the newest
/// attempt this process knows of and the persisted `stored` value can only be older: a stale
/// positive `stored` must not hide it, or a database that cannot store the marker would repeat a
/// failed conversion every pass instead of daily. Not max(): a persisted marker ahead of the
/// clock (written during a forward excursion) would outrank a sane copy and then be discarded
/// by vacuum_decision's future-marker rule, re-admitting every pass.
[[nodiscard]] constexpr int64_t deferred_marker_reading(int64_t stored,
                                                        int64_t failed_write_copy) noexcept {
    return failed_write_copy > 0 ? failed_write_copy : stored;
}

/// Parse a `db_budget_bytes` value: decimal digits only, fits int64, >= kEchoDbBudgetBytesMin.
[[nodiscard]] std::optional<int64_t> parse_budget_bytes(std::string_view text);

/// The effective budget from a tri-state config read. A failed read is nullopt ("unreadable"):
/// the caller must not substitute the default, because a raised budget silently reverting to
/// 250 MiB would delete down to the smaller target. An absent, unparseable or below-minimum
/// stored value (a row edited outside the plugin) is the default; a valid one is itself.
[[nodiscard]] std::optional<int64_t>
budget_from_config(const std::expected<std::optional<std::string>, std::string>& stored);

} // namespace yuzu::echo
