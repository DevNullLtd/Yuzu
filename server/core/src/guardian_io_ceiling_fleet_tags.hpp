#pragma once

/// @file guardian_io_ceiling_fleet_tags.hpp
/// Reader side of the rung 9c PR-3 (Decision 3, Option B) physical-orphan-ceiling
/// observability signal. Writer:
/// agents/core/src/guardian_io_ceiling_heartbeat.hpp
/// (`emit_guardian_io_ceiling_heartbeat_tags`). Bound by
/// tests/unit/server/test_guardian_arm_fleet_tags.cpp (shared with the arm-gauge
/// family's own test file - one small table, kept in its own header for the same
/// domain-separation reason the writer side splits guardian_arm_heartbeat.hpp
/// from guardian_io_ceiling_heartbeat.hpp: this signal is executor-fault-family,
/// not ack-ledger-family, and #3415/"PR-3a" is expected to extend THIS table with
/// more GuardianIoExecutor::Counters fields later, not the arm one).
///
/// ── SHAPE: SUM, MONOTONIC COUNTER (the ordinary shape, unlike the arm gauges) ──
/// `rejected_ceiling` genuinely IS a cumulative per-agent counter (never
/// decrements agent-side - see GuardianSparkRuntime::io_ceiling_rejections()'s
/// own doc comment), so the monitor-only fleet-SUM-of-counters shape used by the
/// journal family is the CORRECT one here, not something to avoid. MONITOR-ONLY
/// per docs/observability-conventions.md: neither `increase()` nor a bare `> 0`
/// is a sound alert over an unlabelled fleet sum of per-agent cumulative
/// counters. This tag NAMES the fault class (R5.1's own ask); it does not answer
/// "is some endpoint CURRENTLY under repeated pressure" - that windowed detector
/// is explicitly deferred to PR-6 once real measurement exists to size it
/// (~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md Decision 3).

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Same rationale as kMaxPlausibleGuardianArmCount: a fleet SUM accumulated into
/// a double, so an implausible single-agent value must be rejected, not clamped.
/// Governance fix, adversarial review CODEX-2/K4: `rejected_ceiling` is
/// cumulative for the agent PROCESS LIFETIME with no reset but restart (see
/// GuardianIoExecutor::Counters's own doc comment) - a long-running, rarely
/// restarted endpoint under sustained ceiling pressure can plausibly accumulate
/// well past 1e6 over weeks-to-months of real uptime, and a value above the
/// bound is DROPPED from both the fleet sum and the reporting population (not
/// merely flagged), losing the signal exactly while the fault persists. Matches
/// the sibling cumulative-counter parsers' bound
/// (kMaxPlausibleGuardianJournalCount / kMaxPlausibleGuardianHealthCount), not
/// the tighter, unjustified 1e6 this file shipped with originally.
inline constexpr unsigned long long kMaxPlausibleGuardianIoCeilingCount = 1'000'000'000ULL;

struct GuardianIoCeilingMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// One row today; #3415/"PR-3a" is expected to add more GuardianIoExecutor
/// counter families here later (see this file's header comment) - kept as a
/// table, not a single named constant, so that extension is additive.
inline constexpr GuardianIoCeilingMetric kGuardianIoCeilingMetrics[] = {
    {"yuzu.guardian_io_arm_disarm_rejected_ceiling",
     "yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling",
     "Fleet SUM of admissions refused at the arm/disarm executor's per-instance "
     "PHYSICAL alive-worker ceiling (R5.1's CeilingExhausted - workers still "
     "alive past fn() inside their completion callbacks while ordinary class "
     "quota was free). A cumulative, monotonic per-agent counter, correctly "
     "MONITOR-ONLY: neither increase() nor bare > 0 is sound over a fleet sum of "
     "per-agent cumulative counters. Names the fault class only - it does NOT "
     "answer whether some endpoint is CURRENTLY under repeated pressure; that "
     "windowed detector is deferred to rung 9c PR-6. Scoped to the arm/disarm "
     "executor instance only (label arm_disarm-equivalent by construction, not "
     "an agent-controlled value) - the state reader's own executor instance "
     "runs only the bounded run() form and structurally cannot reach this "
     "ceiling (docs/spark-legacy-delta-registry.md row D10)"},
};

inline constexpr std::size_t kNGuardianIoCeilingMetrics = std::size(kGuardianIoCeilingMetrics);

/// Agents whose latest heartbeat carried at least one parseable
/// yuzu.guardian_io_* tag from this family. Published every sweep INCLUDING 0.
inline constexpr const char* kGuardianIoCeilingReportingGauge =
    "yuzu_fleet_guardian_io_ceiling_reporting";
inline constexpr const char* kGuardianIoCeilingReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_io_* tag from this family - the coverage denominator for "
    "rejected_ceiling. Published every sweep INCLUDING 0. The writer is sparse "
    "(0 ceiling hits ships no tag), so 0 here means no CURRENTLY-RETAINED agent "
    "has hit the ceiling since its own process last started (or none is running "
    "spark) - counters reset on agent restart and this reads only the latest "
    "retained heartbeats, so a restarted or stale-evicted agent's prior hits are "
    "not durable history here; not that the telemetry path is dark";

inline constexpr const char* kGuardianIoCeilingTagRejectedGauge =
    "yuzu_fleet_guardian_io_ceiling_tag_rejected";
inline constexpr const char* kGuardianIoCeilingTagRejectedHelp =
    "yuzu.guardian_io_* tags from this family PRESENT on a heartbeat this sweep "
    "but rejected by the forged-value parse. Published every sweep INCLUDING 0. "
    "> 0 means some agent is shipping malformed io-ceiling telemetry";

inline constexpr std::size_t kMaxIoCeilingTokenDigits = 10;

namespace detail_io_ceiling_pow10 {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_io_ceiling_pow10

static_assert(kMaxPlausibleGuardianIoCeilingCount <
                  detail_io_ceiling_pow10::pow10(kMaxIoCeilingTokenDigits),
              "kMaxPlausibleGuardianIoCeilingCount no longer fits in "
              "kMaxIoCeilingTokenDigits digits - adjust both together.");

inline std::optional<double> parse_guardian_io_ceiling_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxIoCeilingTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianIoCeilingCount)
        return std::nullopt;
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
