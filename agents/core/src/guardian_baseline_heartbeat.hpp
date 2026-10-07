#pragma once

/// @file guardian_baseline_heartbeat.hpp
/// Writer side of the Spark baseline-persistence failure signal (#4045): the count of every
/// channel by which a Spark baseline-on-arm capture failed to reach the #4021 KV record
/// (GuardianEngine::baseline_persist_failures()): failed write attempts, firewalled throws,
/// captures dropped from staging (cap, allocation, restage) and a capture staged with no store.
///
/// A persist failure is a DELIBERATE fail-open (the rule keeps running on its in-memory
/// baseline), so it must not be silent. Until the capture is persisted, a crash or full_sync
/// recaptures current content, which is the drift-laundering gap #4045 closes; this tag is how
/// an operator sees a box where that window is open for longer than the drain cadence.
///
/// Sparse single counter, 0 omits the tag, the shape of guardian_io_ceiling_heartbeat.hpp, and
/// deliberately NOT a field of GuardianJournalStats: that struct is pinned 1:1 to the server's
/// kGuardianJournalMetrics fleet-gauge table by a sizeof static_assert
/// (tests/unit/server/test_guardian_journal_fleet_tags.cpp), so a field there would force a
/// server-side gauge this change does not add. No server reader exists for this tag yet: it
/// ships on the heartbeat (per-agent status tags) and is MONITOR-ONLY, like every cumulative
/// counter in this namespace (docs/observability-conventions.md): a fleet rollup, if wanted,
/// is a follow-up that adds a row to a server table and its pin test in the same change.

#include <cstdint>
#include <string>

namespace yuzu::agent {

/// Populate `tags` with the cumulative baseline-persist failure count. Sparse: 0 omits the tag.
/// `TagMap` is any map with a string `operator[]` (the protobuf status_tags map in production,
/// std::map in tests).
template <typename TagMap>
void emit_guardian_baseline_persist_heartbeat_tags(TagMap& tags, std::uint64_t persist_failures) {
    if (persist_failures != 0)
        tags["yuzu.guardian_baseline_persist_failures"] = std::to_string(persist_failures);
}

} // namespace yuzu::agent
