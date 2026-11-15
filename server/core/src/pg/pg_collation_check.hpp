#pragma once

/// @file pg_collation_check.hpp
/// A check, run at start and then repeated (`pg_collation_recheck.hpp`), that the database's
/// recorded collation version still matches the one the operating system (libc or ICU) of the
/// PostgreSQL server reports.
///
/// WHY. Text-keyed indexes are ordered by the database's default collation. After an operating-
/// system or libc upgrade that changes collation rules, an index built under the old rules can
/// disagree with the new ones, and an ordered read of a text key can then skip or repeat rows.
/// Keyset walks over a text primary key depend on that agreement. PostgreSQL 15 and later record
/// the collation version a database was created with
/// (`pg_database.datcollversion`) and can compute the current one
/// (`pg_database_collation_actual_version(oid)`); a difference is the signal checked here.
///
/// SHAPE. A pure decision (`decide_collation_verdict`) over three facts, and one I/O function
/// (`check_collation_version`) that fetches them with one short bounded transaction. Neither
/// throws. The check never stops the server: it logs the result, exports a gauge, and keeps
/// booting whatever the verdict, because an operator must be able to start the server to fix the
/// database. It refuses and pauses nothing; the gauge and the log are the whole of its output. It
/// runs once at start and is repeated by `PgCollationRecheck` (hourly once a conclusive Ok or
/// NotApplicable stands and the checks are readable; every minute while a Mismatch stands, no
/// conclusive verdict exists yet, or the latest check was unreadable), so drift that appears while
/// the server keeps running (a provider maintenance event that changes the host library) is seen,
/// and a fixed database clears the gauge without a restart.
///
/// WHAT A REPEAT REPORTS. A second pure function (`next_collation_state`) maps the previous
/// state and the new verdict to the new state, a gauge action and a log action, so that the gauge
/// follows the latest CONCLUSIVE verdict and the log speaks only on a transition:
///   - Ok sets the gauge to 0; NotApplicable removes the series; Mismatch sets it to 1. A
///     Mismatch that becomes NotApplicable (the database no longer records a collation version)
///     logs one INFO line saying the mismatch no longer applies, since the series is removed
///     without ever reading 0.
///   - Unreadable leaves the gauge as it was. A check that could not run says nothing about the
///     database, so it must neither clear a standing mismatch nor invent a healthy 0.
///   - The state remembers the last conclusive finding and whether the checks since then have
///     been unreadable, so a mismatch that is interrupted by an unreadable spell and then seen
///     again is the same mismatch (silent), and a WARN is logged once per spell, not on every
///     repeat.
///   - Every check, the start-time one included, increments
///     `yuzu_pg_collation_check_total{result}`, so a check that cannot run is visible.
///
/// Verdicts:
///   - Ok: the recorded and the actual version are equal.
///   - NotApplicable: this PostgreSQL has no `datcollversion` column (before 15), or the recorded
///     version is NULL (a database on the libc `C`/`POSIX` collation has none; a database on the
///     builtin provider records a version and is checked, measured on PostgreSQL 18.4).
///   - Mismatch: both are known and they differ.
///   - Unreadable: the facts could not be read, or the recorded version is set but the operating
///     system could not report the actual one.

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {

class PgPool;

enum class CollationVerdict { Ok, NotApplicable, Mismatch, Unreadable };

/// A verdict and the fixed text used for it in logs and as the `result` label of
/// `yuzu_pg_collation_check_total`.
struct CollationVerdictName {
    CollationVerdict verdict;
    const char* name;
};

/// The closed set of verdicts with their names: the ONE list `to_string(CollationVerdict)` reads
/// and `seed_collation_metrics` pre-seeds from, so the label set and the counter series cannot
/// drift apart. A new enumerator is added here and nowhere else.
inline constexpr std::array<CollationVerdictName, 4> kCollationVerdictNames{{
    {CollationVerdict::Ok, "ok"},
    {CollationVerdict::NotApplicable, "not_applicable"},
    {CollationVerdict::Mismatch, "mismatch"},
    {CollationVerdict::Unreadable, "unreadable"},
}};

[[nodiscard]] constexpr const std::array<CollationVerdictName, 4>&
all_collation_verdicts() noexcept {
    return kCollationVerdictNames;
}

/// The three facts the decision is made from.
struct CollationFacts {
    bool column_exists{false};           ///< `pg_database.datcollversion` exists (PostgreSQL 15+)
    std::optional<std::string> recorded; ///< `datcollversion`; nullopt when NULL
    /// `pg_database_collation_actual_version(oid)`; nullopt when NULL.
    std::optional<std::string> actual;
};

/// Pure. No I/O.
[[nodiscard]] CollationVerdict decide_collation_verdict(const CollationFacts& facts) noexcept;

/// `name` as a quoted SQL identifier: wrapped in double quotes with every embedded double quote
/// doubled, so the result is safe to paste into `REINDEX DATABASE` and `ALTER DATABASE`. Pure.
/// It quotes and does nothing else: control bytes pass through (a caller that logs the result
/// neutralises them first).
[[nodiscard]] std::string quote_identifier(std::string_view name);

/// Why a check that did not produce a verdict failed, for the log. Pure. `failure` is the text
/// captured inside the transaction; `facts_read` is true when the callback finished reading the
/// facts (so a failure with `failure` empty can only be the COMMIT); `pool_error` is the pool's
/// last error. A failed COMMIT says so rather than echoing an unrelated earlier pool error. When
/// the transaction never ran (acquire or BEGIN failed) the pool error is shown but marked as
/// possibly from an earlier attempt, because the pool keeps only its latest error.
[[nodiscard]] std::string unreadable_failure_text(const std::string& failure, bool facts_read,
                                                  const std::string& pool_error);

/// Fixed text for logs and tests: "ok", "not_applicable", "mismatch", "unreadable".
[[nodiscard]] const char* to_string(CollationVerdict v) noexcept;

struct CollationReport {
    CollationVerdict verdict{CollationVerdict::Unreadable};
    std::string database; ///< `current_database()`; empty when it could not be read
    std::string recorded; ///< empty when absent
    std::string actual;   ///< empty when absent
    std::string failure;  ///< why the facts could not be read (Unreadable only), for the log
};

/// What the previous checks concluded. `last` is the last CONCLUSIVE verdict (None before any);
/// `unreadable` is true while the checks since then have been Unreadable.
enum class CollationLast { None, Ok, Mismatch, NotApplicable };
struct CollationState {
    CollationLast last{CollationLast::None};
    bool unreadable{false};
    friend bool operator==(const CollationState&, const CollationState&) = default;
};

enum class GaugeAction { Leave, SetZero, SetOne, Remove };
enum class LogAction {
    None,
    InfoMatches,                 ///< first conclusive Ok (or Ok after NotApplicable)
    ErrorMismatch,               ///< entering Mismatch
    InfoCleared,                 ///< Mismatch to Ok
    WarnUnreadable,              ///< entering an Unreadable spell
    InfoNotApplicable,           ///< entering NotApplicable (once; the gauge series is absent)
    InfoMismatchNoLongerApplies, ///< Mismatch to NotApplicable (the gauge series is removed)
};

struct CollationStep {
    CollationState next;
    GaugeAction gauge{GaugeAction::Leave};
    LogAction log{LogAction::None};
};

/// Pure. See "WHAT A REPEAT REPORTS" above. Unreadable followed by Ok or Mismatch is judged
/// against `prev.last`, not against the Unreadable: Mismatch, Unreadable, Mismatch logs the ERROR
/// once; Mismatch, Unreadable, Ok logs the "cleared" line; Ok, Unreadable, Ok logs nothing.
[[nodiscard]] CollationStep next_collation_state(const CollationState& prev,
                                                 CollationVerdict verdict) noexcept;

/// The bound on the acquire and on the statements (`SET LOCAL statement_timeout`).
inline constexpr std::chrono::milliseconds kCollationCheckAcquireTimeout{5000};
inline constexpr const char* kCollationCheckStatementTimeout = "5s";

/// Reads the facts on a pooled connection in one short transaction and decides. Never throws:
/// any failure is `Unreadable` with `failure` set.
[[nodiscard]] CollationReport check_collation_version(PgPool& pool) noexcept;

/// Names of the exported series. The counter's `result` label is `to_string(verdict)`, a closed
/// set of four.
inline constexpr const char* kCollationMismatchGauge = "yuzu_pg_collation_version_mismatch";
inline constexpr const char* kCollationCheckCounter = "yuzu_pg_collation_check_total";
/// Unix time, in seconds, of the latest check that COMPLETED with any verdict (Unreadable
/// included). Absent until the first report, never removed. A stale value means the recheck loop
/// has stopped completing checks (a check stuck mid-query, a wedged thread), which the mismatch
/// gauge and the counter cannot show.
inline constexpr const char* kCollationLastCompletedGauge =
    "yuzu_pg_collation_check_last_completed_timestamp_seconds";

/// Applies one check's report: updates `state`, counts the check, stamps the last-completed time,
/// drives the gauge and logs, all
/// as decided by `next_collation_state`. On a Mismatch entry one ERROR names the database, both
/// versions and the remedy. The gauge is absent (not zero) until a conclusive verdict sets it, and
/// is removed again on NotApplicable. `metrics` may be null. Never throws. Not thread-safe:
/// `state` is owned by one caller at a time (the constructor, then the recheck loop).
void report_collation_check(const CollationReport& report, yuzu::MetricsRegistry* metrics,
                            CollationState& state) noexcept;

/// Creates `yuzu_pg_collation_check_total{result}` at 0 for every verdict in
/// `all_collation_verdicts()`, so each result reads 0 rather than absent before it first happens
/// (docs/observability-conventions.md). Does not create the gauge, which stays absent until a
/// check concludes something. Idempotent.
void seed_collation_metrics(yuzu::MetricsRegistry& metrics);

} // namespace yuzu::server::pg
