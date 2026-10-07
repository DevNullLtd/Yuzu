#pragma once

/// @file guardian_baseline_heartbeat.hpp
/// Writer side of the Spark baseline-persistence failure signal (#4045): the cumulative count
/// of the channels by which a Spark baseline-on-arm capture failed to reach the #4021 KV
/// record (GuardianEngine::baseline_persist_failures()): failed persist passes (one per pass,
/// however many of its writes failed), firewalled throws, captures that did not reach staging
/// or were displaced from it (an allocation failure, after which the rule captures again at
/// its next evaluation; a retarget over a still-unpersisted capture) and a capture staged
/// with no store.
///
/// SCOPE, stated plainly: this tag covers the SPARK path only. A legacy FileGuard persist
/// failure is logged and not counted, so an ABSENT tag is not evidence that baselines
/// persisted. It is cumulative since boot (a flat non-zero value does not say whether a
/// failure is still open), and it mixes retryable failures with permanent losses. No server
/// gauge, alert rule or reader exists for it in this change: the tag rides the per-agent
/// heartbeat status tags only, so the agent's own error log
/// ("failed to persist captured baseline") is the primary operator signal until a
/// fleet-visible signal ships (an F14 precondition, docs/spark-flip-gate.md).
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
/// server-side gauge this change does not add (a deliberate non-goal of this change).

#include <cstdint>
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

} // namespace yuzu::agent
