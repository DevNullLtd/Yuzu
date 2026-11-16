#pragma once

/// @file guardian_baseline_fleet_tags.hpp
/// Reader side of the Spark baseline-persistence failure signal (#5605, #4045). Writer:
/// agents/core/src/guardian_baseline_heartbeat.hpp (the three tag constants and the
/// `emit_guardian_baseline_*` emitters). Bound by
/// tests/unit/server/test_guardian_baseline_fleet_tags.cpp, which drives the REAL emitters.
///
/// Three rows, three deliberately different shapes (read the shape before writing an alert):
///  - row 0 `unpersisted`: SUM of CURRENT values (re-statable, not a counter). The ONLY row an
///    alert may use (`YuzuGuardianBaselineUnpersisted`). Dormant until prefer_spark, so ABSENT on
///    every released fleet today.
///  - row 1 `rebaselined_at_boot`: SUM of sparse per-boot counts. Live on both detection
///    backends, NOT proof of a lost capture. Monitor-only.
///  - row 2 `persist_failures`: SUM of cumulative-since-boot per-process counters. Latches until
///    the agent restarts, so it cannot back a sustained-condition alert. Monitor-only.
///
/// `_reporting` counts an agent ONLY when row 0 (the unpersisted tag) parsed: the other two tags
/// are sparse, so an any-row union would count a legacy agent that emitted only the boot-scan tag
/// as "reporting the current gauge" and shrink the alert's coverage denominator dishonestly.
///
/// Prose that does not fit a HELP string lives in docs/user-manual/metrics.md and
/// docs/user-manual/guaranteed-state.md; keep this header small.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// A fleet SUM accumulated into a double, so an implausible single-agent value is REJECTED, not
/// clamped (the io-ceiling / journal precedent: 1e9 over 10 digits, because the cumulative row can
/// legitimately grow far past the arm family's 1e6 over a long agent uptime).
inline constexpr unsigned long long kMaxPlausibleGuardianBaselineCount = 1'000'000'000ULL;
inline constexpr std::size_t kMaxBaselineTokenDigits = 10;

namespace detail_baseline_pow10 {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_baseline_pow10

static_assert(kMaxPlausibleGuardianBaselineCount <
                  detail_baseline_pow10::pow10(kMaxBaselineTokenDigits),
              "kMaxPlausibleGuardianBaselineCount no longer fits in kMaxBaselineTokenDigits "
              "digits - adjust both together.");

struct GuardianBaselineMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

inline constexpr GuardianBaselineMetric kGuardianBaselineMetrics[] = {
    // Row 0: the alerted gauge. Keep it first (see kGuardianBaselineUnpersistedIndex).
    {"yuzu.guardian_baseline_unpersisted", "yuzu_fleet_guardian_baseline_unpersisted",
     "Fleet SUM of Spark baseline-on-arm captures currently staged on the agent and not yet "
     "written to its local KV baseline record (file-hash-equals rules with no authored "
     "expected_hash, prefer_spark agents only). A RE-STATABLE current gauge, not a counter: it "
     "falls as captures are written or refused by the overwrite guard. Zero means no capture is "
     "waiting at that agent's persister; it does NOT mean Spark is healthy, and it says nothing "
     "about legacy-path persist failures, which are logged only. ABSENT means no reporting agent "
     "this sweep: prefer_spark off fleet-wide (every released agent today) or the persister not "
     "wired. A sustained non-zero value is a persistence BACKLOG (a failing or slow local store, "
     "a budget-limited pass, a yielded worker pass); it detects a staged-but-unwritten backlog "
     "on a live agent and cannot show that a loss happened. Not seen: a retarget followed by a "
     "crash, a never-staged capture, a malformed record re-baselined at boot, and a crashed "
     "agent (its series vanishes)"},
    {"yuzu.guardian_baseline_rebaselined_at_boot",
     "yuzu_fleet_guardian_baseline_rebaselined_at_boot",
     "Fleet SUM of enabled file-hash-equals rules with no authored expected_hash whose boot re-arm seed "
     "lookup found NO persisted baseline record (both detection backends; counted once per rule "
     "per agent boot; sparse per agent, so ABSENT means no agent reported a non-zero count). "
     "Each such rule re-arms and, where the file mechanism can arm, re-captures the file's "
     "CURRENT content as its baseline at that boot. Only a genuinely absent record counts; a "
     "malformed record, a boot read error and a fingerprint mismatch (retarget) are not counted "
     "but also re-baseline, so a retarget followed by a crash reads as not lost. Two more blind "
     "spots: a malformed record overwritten at boot N reads Ok at boot N+1, and a rule disabled "
     "at boot and enabled later is never counted. NOT proof that "
     "a capture was lost: a never-captured target, a prior failed arm, a platform that cannot "
     "arm the file mechanism, and a lost capture all read the same. On Linux and macOS no "
     "file-hash guard arms, so every agent with such a rule counts it on every boot and the "
     "value is not a baseline-loss signal; meaningful readings come from Windows agents only. "
     "Monitor-only; never alert on it"},
    {"yuzu.guardian_baseline_persist_failures", "yuzu_fleet_guardian_baseline_persist_failures",
     "Fleet SUM of the agents' cumulative-since-boot yuzu.guardian_baseline_persist_failures "
     "counters (failed Spark persist passes, failed or displaced staging attempts, no-store "
     "passes, firewalled throws). Spark path only; cumulative per process, so it latches until "
     "that agent restarts and cannot back a sustained-condition alert. Monitor-only; use "
     "yuzu_fleet_guardian_baseline_unpersisted for the live backlog"},
};

inline constexpr std::size_t kNGuardianBaselineMetrics = std::size(kGuardianBaselineMetrics);

/// The row that `_reporting` keys on. Pinned by the static_asserts below (and by a pin test
/// against the agent's real emitters) so a reorder cannot silently re-point the denominator.
inline constexpr std::size_t kGuardianBaselineUnpersistedIndex = 0;

namespace detail_baseline_str {
/// constexpr C-string equality, so a static_assert can pin row 0's tag.
inline constexpr bool str_eq(const char* a, const char* b) {
    while (*a != '\0' && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}
} // namespace detail_baseline_str

static_assert(kNGuardianBaselineMetrics == 3,
              "kGuardianBaselineMetrics row count changed: the agent emits three baseline tags; "
              "add or remove the matching writer, pin test and docs together.");
static_assert(detail_baseline_str::str_eq(
                  kGuardianBaselineMetrics[kGuardianBaselineUnpersistedIndex].tag,
                  "yuzu.guardian_baseline_unpersisted"),
              "kGuardianBaselineUnpersistedIndex must name the yuzu.guardian_baseline_unpersisted "
              "row: _reporting is keyed on it alone.");

/// Agents whose latest heartbeat carried a parseable yuzu.guardian_baseline_unpersisted tag.
inline constexpr const char* kGuardianBaselineReportingGauge =
    "yuzu_fleet_guardian_baseline_reporting";
inline constexpr const char* kGuardianBaselineReportingHelp =
    "Agents whose latest heartbeat carried a parseable yuzu.guardian_baseline_unpersisted tag, "
    "the coverage denominator for that gauge ONLY (the boot-scan and cumulative tags are sparse "
    "and do not count here). Published every sweep INCLUDING 0. 0 is the expected reading on "
    "every released fleet today (prefer_spark is off)";

inline constexpr const char* kGuardianBaselineTagRejectedGauge =
    "yuzu_fleet_guardian_baseline_tag_rejected";
inline constexpr const char* kGuardianBaselineTagRejectedHelp =
    "yuzu.guardian_baseline_* tags PRESENT on a heartbeat this sweep but rejected by the "
    "forged-value parse (non-numeric, negative, over 10 digits, or above the 1e9 plausibility "
    "ceiling). Published every sweep INCLUDING 0. > 0 means some agent ships malformed baseline "
    "telemetry";

/// Full-token unsigned decimal parse. Rejects empty, garbage, signed, over-long and implausible
/// values (the digit gate runs first, so from_chars overflow is unreachable).
inline std::optional<double> parse_guardian_baseline_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxBaselineTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianBaselineCount)
        return std::nullopt;
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
