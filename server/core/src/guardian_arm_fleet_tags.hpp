#pragma once

/// @file guardian_arm_fleet_tags.hpp
/// Reader side of the rung 9c PR-3 arm/disarm ack-ledger fleet telemetry
/// (docs/spark-stage2-guardian-consumer-design.md §R5.2;
/// ~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md Decision 1). Single
/// source of truth for the `yuzu.guardian_arm_*` heartbeat tag keys, the
/// `yuzu_fleet_guardian_arm_*` gauge names they roll up into, their HELP text,
/// and the forged-value-safe parse of the agent-supplied values.
///
/// The writer is agents/core/src/guardian_arm_heartbeat.hpp
/// (`emit_guardian_arm_heartbeat_tags`). Both sides are bound by
/// tests/unit/server/test_guardian_arm_fleet_tags.cpp, which emits through the
/// agent's REAL emitter and asserts every key produced is one the table here
/// recognises - the drift guard, same as guardian_journal_fleet_tags.hpp's own.
///
/// The keys are duplicated here rather than #include-d from the agent header ON
/// PURPOSE, for the exact reason guardian_journal_fleet_tags.hpp's own header
/// states: server production code including an agent private header would add an
/// upward server -> agent dependency edge the build graph does not have and must
/// not gain (tests/meson.build). Only the TEST target carries the agent include
/// path.
///
/// ── SHAPE: SUM, NOT MAX - THESE ARE GAUGES, NOT COUNTERS ────────────────────────
/// Unlike the journal family (32 monotonic per-sweep counters) or the age family
/// (staleness - rolls up as MAX), arm_pending/arm_failed are RE-STATABLE GAUGES:
/// each agent reports its CURRENT count, not a cumulative total, so the fleet
/// question ("how many accepted arms are outstanding/failed RIGHT NOW across the
/// fleet") is answered by a SUM of current values, not a SUM of deltas and not a
/// MAX. The two-row table below still accumulates via `+=` exactly like the
/// journal counter family mechanically (same accumulate-loop shape in
/// agent_registry.cpp) - the difference that matters is in the AGENT's own
/// emission posture (present-and-including-0 vs sparse-monotonic), which this
/// reader does not need to know about: an agent's CURRENT reading, present or
/// absent, is all this table consumes either way.
///
/// ── WHAT ABSENCE MEANS ───────────────────────────────────────────────────────
/// Same rule as every other family here: `AgentHealthStore::recompute_metrics`
/// clears both gauge families at the top of every sweep and re-publishes only
/// what at least one retained agent's latest heartbeat carried this cycle. An
/// absent family means no retained agent reported a parseable value THIS sweep -
/// which, for arm_pending/arm_failed specifically, includes every non-spark
/// (prefer_spark_ off) agent, by construction (see the writer's own Check A doc
/// comment): they never emit the pair at all, so they can never poison "absent"
/// into a false healthy zero.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Max accepted value of any arm tag. Above it the value is treated as "did not
/// report", NOT clamped-and-counted - same rationale as
/// kMaxPlausibleGuardianJournalCount (guardian_journal_fleet_tags.hpp): these are
/// a fleet SUM accumulated into a `double`, so a single agent reporting near
/// UINT64_MAX would make every honest agent's contribution a no-op in IEEE-754.
/// A real pending/failed count is bounded by how many rules a single push can
/// accept, far below this.
inline constexpr unsigned long long kMaxPlausibleGuardianArmCount = 1'000'000ULL;

/// One arm-ledger telemetry signal: heartbeat tag key, fleet gauge, HELP text.
/// Same shape as guardian_journal_fleet_tags.hpp's GuardianJournalMetric
/// (name rule: `gauge` == "yuzu_fleet_" + `tag` with its "yuzu." prefix
/// stripped) - a distinct type, not a reuse, so this family's own structural
/// pin (test file) cannot be satisfied by accident from the journal table.
struct GuardianArmMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// Pinned 1:1 to GuardianArmStats (agents/core/src/guardian_arm_heartbeat.hpp) by
/// the structural size assert in test_guardian_arm_fleet_tags.cpp - adding a
/// field to that struct without a matching row here is a build break, not a
/// silently-dead gauge.
inline constexpr GuardianArmMetric kGuardianArmMetrics[] = {
    {"yuzu.guardian_arm_pending", "yuzu_fleet_guardian_arm_pending",
     "Fleet SUM of accepted spark arms currently pending acknowledgment (still "
     "awaiting a Committed/terminal resolution) - GuardianArmAckLedger's CURRENT "
     "application, summed across agents. A RE-STATABLE gauge, not a cumulative "
     "counter: it can legally decrease as receipts resolve or an application is "
     "replaced. ABSENT means no reporting agent this sweep - prefer_spark_ off, "
     "the engine stopped, Spark unavailable (Unwired/SparkFailed/SparkDisabled), "
     "or no current application yet - including every non-spark agent, which "
     "never emits this pair at all. A completed receipt beyond one heartbeat "
     "tick's bounded drain "
     "can still count here until the next tick - a SAMPLED observation, not an "
     "instantaneous truth"},
    {"yuzu.guardian_arm_failed", "yuzu_fleet_guardian_arm_failed",
     "Fleet SUM of accepted spark arms whose CURRENT application resolved to a "
     "non-Committed terminal outcome (Failed/CongestionExpired/Wedged/Withdrawn/"
     "Stopped), still unresolved for acknowledgment. A RE-STATABLE gauge: resets to 0 the instant "
     "an application that saw a failure is REPLACED (an ordinary retry of that "
     "generation, live today) - REGARDLESS of whether that retry itself then "
     "succeeds, so a persistently-failing rule oscillates across heartbeat ticks "
     "rather than holding steady at nonzero; a for:-duration alert keyed on this "
     "gauge alone can have its timer reset every retry - prefer arm_pending + "
     "arm_failed > 0 sustained, or yuzu.guardian_generation lag. Reflects "
     "same-application recovery for the Wedged case only (rung 9c PR-5d): a "
     "Wedged receipt whose late arm succeeds and is adopted clears its own "
     "contribution here without a new application; every other non-Committed "
     "status still only clears via an application replacement. Zero failed does not itself mean compliant or enforced "
     "- check yuzu_fleet_spark_armed_faulted / the device's own Guardian lens "
     "for that. "
     "ABSENT means no reporting agent this sweep, same as arm_pending"},
};

inline constexpr std::size_t kNGuardianArmMetrics = std::size(kGuardianArmMetrics);

/// Agents whose latest heartbeat carried at least one parseable
/// yuzu.guardian_arm_* tag. Published every sweep INCLUDING 0 (server-owned
/// count, always has a true value) - the coverage denominator the two gauges
/// above lack on their own, same role as kGuardianJournalReportingGauge.
inline constexpr const char* kGuardianArmReportingGauge = "yuzu_fleet_guardian_arm_reporting";
inline constexpr const char* kGuardianArmReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_arm_* tag - the coverage denominator for arm_pending/"
    "arm_failed. Published every sweep INCLUDING 0. 0 means no agent currently "
    "has prefer_spark_ on AND live (not stopped, not "
    "Unwired/SparkFailed/SparkDisabled) AND a current application - the expected "
    "reading on every released fleet today, since prefer_spark_ is hardcoded "
    "false. Do NOT cross-check yuzu_fleet_spark_reporting to disambiguate "
    "'telemetry dark' - that gauge counts SparkEngine running observe-only, "
    "live fleet-wide independent of prefer_spark_, so spark_reporting > 0 with "
    "arm_reporting == 0 is the NORMAL pre-cutover reading, not a dark-telemetry "
    "signal";

/// yuzu.guardian_arm_* tags PRESENT on a heartbeat this sweep but rejected by
/// the forged-value parse. Published every sweep INCLUDING 0, same role as
/// kGuardianJournalTagRejectedGauge - without it a rejected value is a silent
/// drop that can make a reporting fleet read as absent.
inline constexpr const char* kGuardianArmTagRejectedGauge =
    "yuzu_fleet_guardian_arm_tag_rejected";
inline constexpr const char* kGuardianArmTagRejectedHelp =
    "yuzu.guardian_arm_* tags PRESENT on a heartbeat this sweep but rejected by "
    "the forged-value parse (non-numeric, negative, over 7 digits, or above the "
    "plausibility ceiling). Published every sweep INCLUDING 0. > 0 means some "
    "agent is shipping malformed arm-ledger telemetry - investigate that agent";

/// Max digits accepted before an arm tag value is rejected unread. Checked
/// FIRST, same posture as guardian_journal_fleet_tags.hpp's own token-digit gate.
inline constexpr std::size_t kMaxArmTokenDigits = 7;

namespace detail_arm_pow10 {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_arm_pow10

static_assert(kMaxPlausibleGuardianArmCount < detail_arm_pow10::pow10(kMaxArmTokenDigits),
              "kMaxPlausibleGuardianArmCount no longer fits in kMaxArmTokenDigits digits - "
              "the length gate in parse_guardian_arm_count would reject legitimate values "
              "before the ceiling ever applies. Adjust both together.");

/// Forged-value-safe parse of an agent-supplied arm tag value. Full-token,
/// non-negative integer parse only; empty / garbage / signed / overflow /
/// implausible -> nullopt, which the caller MUST treat as "did not report",
/// never as 0. Mirrors parse_guardian_journal_count's own shape (a distinct
/// function, not a reuse - the two families have independent plausibility
/// ceilings and independently-pinned rejection meta-gauges).
inline std::optional<double> parse_guardian_arm_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxArmTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianArmCount)
        return std::nullopt;
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
