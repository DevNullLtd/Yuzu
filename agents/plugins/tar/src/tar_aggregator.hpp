#pragma once

/**
 * tar_aggregator.hpp -- Rollup aggregation and retention for TAR warehouse
 *
 * Aggregates live table data into hourly/daily/monthly summary tables.
 * Each rollup is idempotent: tracks last-processed timestamp in tar_config
 * and only processes new data on each invocation.
 */

#include "tar_db.hpp"

#include <yuzu/audit_retention_rules.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

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
 * Reads rollup marks from tar_config, processes new data, updates marks.
 * @param db        The TAR database.
 * @param now_epoch Current epoch seconds.
 * @return Total number of aggregation operations performed.
 */
int run_aggregation(TarDatabase& db, int64_t now_epoch);

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
inline constexpr int64_t kTarRetentionFutureSlackSec = 24 * 3600;

// Upper bound on rows one pass deletes from one table. At the 900-second rollup
// cadence this is ~480k rows/day/table, far above the growth rate of any TAR
// warehouse table on an endpoint, so the accepting path keeps up and the latch
// never sits permanently set. Sized as a drain rate, not a batch guess.
inline constexpr int64_t kMaxTarDeletesPerTablePerPass = 5000;

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
inline constexpr int64_t kTarMinBigStepSec = 30 * 86400;

/**
 * Per-table clock-guard state for time-based retention. Owned by the plugin and
 * passed into every `run_retention` call so recorded fact sets survive across
 * passes.
 *
 * Deliberately IN-MEMORY, not persisted: a reboot re-declines, which is the
 * right behaviour for the wrong-RTC-at-boot case this exists to catch.
 *
 * The state carries its own mutex for the individual map touches, so reading
 * the counters (e.g. from `tar status`) never waits on a whole pass. It IS held
 * briefly across one database read -- the cap-will-bind probe in the decide
 * step -- which is safe because no TarDatabase path ever takes this mutex, so
 * no cycle exists; an earlier version of this comment claimed it was never held
 * across a database call at all, which stopped being true in round 4. That does NOT
 * make a pass atomic: each table's probe / decide / update-entry sequence spans
 * several statements, so the CALLER must still serialise whole rollup passes
 * against each other -- a manual `tar rollup` can arrive while the 900-second
 * trigger is mid-pass. TarPlugin holds `rollup_mu_` for exactly that.
 */
struct RetentionGuardState {
    /// Guards every member below. Held only for brief touches -- the map writes
    /// and one bounded probe -- never for a whole pass, so `tar status` can read
    /// the counters without waiting for a rollup. Serialising the passes
    /// themselves is a separate obligation the caller still owns (TarPlugin's
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
    /// One deliberate TAR-specific rule the audit sibling does not need:
    /// Anomaly::NoAnchor is NEVER recorded here. The audit store's durable
    /// `bootstrap_settled` marker is written in the SAME transaction as its
    /// verdict, so a persist failure there rolls back the whole pass, decline
    /// included. TAR's anchor write (`kRetentionLastPassKey`) is a plain
    /// `set_config` that runs independently of this map -- if it keeps
    /// failing, `no_anchor` stays true forever, and RECORDING that fact set
    /// would turn every later identical pass into a suppressed drain, quietly
    /// defeating the exact fail-safe the no-anchor trigger exists to provide.
    /// See `run_retention`'s decide step.
    std::map<std::string, yuzu::server::audit_retention::Facts> last_reported;
    /// Cumulative declines per table, surfaced through the `tar status` action.
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
};

/// Snapshot of the operator-facing counters, taken under `RetentionGuardState::mu`.
struct RetentionGuardCounters {
    std::map<std::string, int64_t> declines;
    std::map<std::string, int64_t> failures;
};

[[nodiscard]] RetentionGuardCounters retention_guard_counters(const RetentionGuardState& guard);

/// The exact `tar status` lines for the retention guard, in emission order:
/// a `retention_guard|<table>|<declines>` line per table that has declined, a
/// `retention_guard_failed|<table>|<failures>` line per table whose probes OR
/// deletes have failed (the two are merged -- both mean "not being retained"),
/// then the always-present totals. Split out from `do_status` purely so
/// the operator-facing format has a test seam -- `TarPlugin` is a
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
 * larger than kTarMinBigStepSec (an ABSOLUTE threshold -- NOT the tier's
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
 * persisted, when implausibly large (kTarMaxPlausibleNow) -- see the top of
 * the implementation.
 *
 * Every accepted pass deletes at most kMaxTarDeletesPerTablePerPass rows per
 * table, oldest first -- that cap applies to BOTH retention kinds.
 *
 * @param db        The TAR database.
 * @param now_epoch Current epoch seconds.
 * @param guard     Per-table guard state; see RetentionGuardState for the
 *                  caller's serialisation obligation.
 */
void run_retention(TarDatabase& db, int64_t now_epoch, RetentionGuardState& guard);

/**
 * Apply an enable/disable transition for a TAR capture source.
 *
 * Updates `<source>_enabled` to `new_value` and maintains the operator-facing
 * `<source>_paused_at` config row used by the TAR dashboard's
 * retention-paused list (PR-A / issue #547). The semantics are:
 *
 *   - enabled→disabled: writes `<source>_paused_at = now_epoch` AND clears the
 *     source's diff baseline (see #538 below).
 *   - disabled→enabled: writes `<source>_paused_at = "0"` (cleared, but kept
 *     present — a missing row would be ambiguous with "never paused").
 *   - no transition (idempotent set): leaves `<source>_paused_at` untouched.
 *
 * The default for `<source>_enabled` if not yet set comes from
 * `CaptureSourceDef::default_enabled` (`"true"` for always-on sources, `"false"`
 * for the opt-in module/procperf/netqual). So the first-ever set registers as a
 * transition only when it differs from that default — e.g. the first
 * `module_enabled=false` on a fresh DB is a no-op (module already defaults off)
 * and writes no spurious `paused_at`, whereas the first `process_enabled=false`
 * is a real enabled→disabled transition.
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
 * @param db        The TAR database.
 * @param source    Source name (e.g. "process", "tcp", "service", "user").
 * @param new_value Either `"true"` or `"false"`. Other values are rejected
 *                  upstream by the configure action.
 * @param now_epoch Current epoch seconds — used as the paused_at timestamp.
 * @return true iff the transition committed; false when it could not be persisted
 *         (source left in its previous state) or when `new_value` is not
 *         "true"/"false" or `source` is not a registry source.
 */
[[nodiscard]] bool apply_source_enabled_transition(TarDatabase& db, std::string_view source,
                                                   std::string_view new_value, int64_t now_epoch);

/**
 * Map a capture source to its snapshot-diff baseline key in the TAR state store
 * (the key passed to `TarDatabase::get_state`/`set_state`).
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
 * Both the collect-time gate (`source_enabled`, tar_plugin.cpp) and
 * `run_retention` gate on this canonical value, so a non-canonical value fails
 * closed: collection stops AND the source's rows are preserved (not pruned).
 */
[[nodiscard]] std::string_view canonical_source_enabled(std::string_view stored_value);

/**
 * The collect-time (and purge-time) gate: is a capture source actively enabled?
 * Reads `<source>_enabled` (defaulting to the source's declared default) and
 * gates on the strict tri-state (#560) — anything the plugin never wrote maps to
 * "errored", which is NOT "true", so the source reads as disabled (fail closed).
 * A never-configured source returns its `source_default_enabled()` default.
 *
 * This is the authoritative paused-guard for the Phase 15.A destructive purge:
 * `tar.purge_source` refuses unless this returns false. It lives here (beside
 * `canonical_source_enabled`, the tri-state authority it wraps) rather than in
 * the plugin so the guard predicate is directly testable.
 */
[[nodiscard]] bool source_enabled(TarDatabase& db, std::string_view source);

} // namespace yuzu::tar
