#pragma once

/// @file guardian_baseline_heartbeat.hpp
/// Writer side of the Spark baseline-persistence failure signal (#4045): the cumulative count
/// of the channels by which a Spark baseline-on-arm capture failed to reach the #4021 KV
/// record (GuardianEngine::baseline_persist_failures()): failed persist passes (one per pass,
/// however many of its writes failed), firewalled throws, staging attempts that failed (an
/// allocation failure, counted once per attempt; the rule keeps its baseline and retries
/// staging at its next evaluations) or displaced a capture (a retarget over a
/// still-unpersisted capture) and a capture staged with no store. A stop-time loss that is
/// not a failed write (the flush ran out of wall budget, or was skipped because it started
/// late AND the stop had shown a slow store) is logged, not counted. A capture that
/// could not be staged again at stop is counted (per failed attempt) AND logged, but the
/// count dies with the exiting process, so the log line is the evidence. A stop cut off by
/// the shutdown watchdog leaves not even a log line (exit code 4).
///
/// SCOPE, stated plainly: this tag covers the SPARK path only. A legacy FileGuard persist
/// failure is logged and not counted, so an ABSENT tag is not evidence that baselines
/// persisted. It is cumulative since boot (a flat non-zero value does not say whether a
/// failure is still open), and it mixes retryable failures with permanent losses. #5605 adds the
/// two tags below beside it (the CURRENT unpersisted backlog and the boot-scan count) and a
/// server-side rollup of all three into fleet gauges; the agent's own error log
/// ("failed to persist captured baseline") remains the per-incident evidence, and this tag
/// stays the monitor-only cumulative signal, never a sustained-condition alert source.
///
/// A persist failure is a DELIBERATE fail-open (the rule keeps running on its in-memory
/// baseline, and the capture stays staged for a retry), so it must not be silent. Until the
/// capture is persisted, a crash or full_sync can recapture current content, which is the
/// drift-laundering gap #4045 closes; this tag is how an operator sees a box where that window
/// has been open at least once.
///
/// Sparse single counter, 0 omits the tag, the shape of guardian_io_ceiling_heartbeat.hpp, and
/// deliberately NOT a field of GuardianJournalStats: that struct is pinned 1:1 to the server's
/// kGuardianJournalMetrics fleet-gauge table by a sizeof static_assert
/// (tests/unit/server/test_guardian_journal_fleet_tags.cpp), so a field there would force a
/// journal-table gauge. All three baseline tags have their own table instead.
///
/// The two #5605 tags and what each does NOT say:
///  - kGuardianBaselineUnpersistedTag is a CURRENT value (GuardianEngine::baseline_unpersisted():
///    captures staged and not yet written), optional-gated like the arm pair: ABSENT means
///    dormant (prefer_spark off, or no published persister), a present 0 means "no capture
///    waiting at this persister", never "Spark is healthy". It covers the Spark path only.
///  - kGuardianBaselineRebaselinedAtBootTag is sparse (0 omits;
///    GuardianEngine::baseline_rebaselined_at_boot()): rules whose boot re-arm seed lookup found
///    no persisted baseline. It is live on every agent, legacy path included, and is NOT proof
///    that a capture was lost.

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent {

/// The heartbeat key. A named constant (like the kGuardian*Tag siblings in
/// guardian_health_heartbeat.hpp) so a future server reader or pin test cannot re-type it.
inline constexpr char kGuardianBaselinePersistFailuresTag[] =
    "yuzu.guardian_baseline_persist_failures";

/// Populate `tags` with the cumulative baseline-persist failure count. Sparse: 0 omits the tag.
/// `TagMap` is any map with a string `operator[]` (the protobuf status_tags map in production,
/// std::map in tests).
template <typename TagMap>
void emit_guardian_baseline_persist_heartbeat_tags(TagMap& tags, std::uint64_t persist_failures) {
    if (persist_failures != 0)
        tags[kGuardianBaselinePersistFailuresTag] = std::to_string(persist_failures);
}

/// #5605: the heartbeat key for the CURRENT unpersisted-capture count.
inline constexpr char kGuardianBaselineUnpersistedTag[] = "yuzu.guardian_baseline_unpersisted";

/// #5605: the heartbeat key for the boot-scan "no persisted baseline" count.
inline constexpr char kGuardianBaselineRebaselinedAtBootTag[] =
    "yuzu.guardian_baseline_rebaselined_at_boot";

/// Populate `tags` with GuardianEngine::baseline_unpersisted(). std::nullopt (dormant) emits
/// NOTHING; a present value emits INCLUDING a genuine 0, so "checked, nothing waiting" reads
/// differently from "dormant" (the guardian_arm_heartbeat.hpp pattern).
template <typename TagMap>
void emit_guardian_baseline_unpersisted_heartbeat_tag(TagMap& tags,
                                                      const std::optional<std::uint64_t>& v) {
    if (v)
        tags[kGuardianBaselineUnpersistedTag] = std::to_string(*v);
}

/// Populate `tags` with GuardianEngine::baseline_rebaselined_at_boot(). Sparse: 0 omits the tag.
template <typename TagMap>
void emit_guardian_baseline_rebaselined_heartbeat_tag(TagMap& tags, std::uint64_t count) {
    if (count != 0)
        tags[kGuardianBaselineRebaselinedAtBootTag] = std::to_string(count);
}

} // namespace yuzu::agent
