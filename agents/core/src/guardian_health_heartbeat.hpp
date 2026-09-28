#pragma once

/// @file guardian_health_heartbeat.hpp
/// Writer side of the Guardian health-stream fleet telemetry (M1). Extracted from the agent
/// heartbeat lambda so the exact emitted key + the sparse-emit rule are unit-testable without a
/// heartbeat thread, and so the key is PINNED to the (future #2298) server-side rollup reader by
/// a unit test - a one-character drift would otherwise silently produce a zero fleet gauge with
/// nothing to catch it. Mirrors guardian_journal_heartbeat.hpp.
///
/// SPARSE: the counter is 0 on a healthy / inert (prefer_spark=false) agent, so the tag is
/// emitted ONLY when non-zero, keeping the "absent == nothing to report" reading honest.

#include <cstdint>
#include <string>

namespace yuzu::agent {

/// Heartbeat status_tag key for the edge-suppressed guard.unhealthy count (M1): the number of
/// convergence re-evals of a still-errored rule whose repeat guard.unhealthy was NOT re-emitted
/// (the flood guard). Shared by the emitter below and the pinning test; the #2298 Prometheus
/// rollup reader MUST key on this exact string.
inline constexpr char kGuardianUnhealthySuppressedTag[] = "yuzu.guardian_unhealthy_suppressed";

/// M1 item (a): guard.unhealthy re-emissions for a rule still stuck Unknown, sent at
/// errored_refresh_ms cadence so a lost/coalesced edge cannot leave the server's errored
/// view stale forever. Sibling to kGuardianUnhealthySuppressedTag above - together they
/// partition every committed repeat-Unknown into "put on the wire" vs "not this tick".
inline constexpr char kGuardianUnhealthyRefreshedTag[] = "yuzu.guardian_unhealthy_refreshed";

/// M1 item (b): rule_ids demoted off the 5s convergence priority lane to their normal
/// type-lane cadence (pending_demote_sweeps / pending_demote_ms) - the read-flood guard.
inline constexpr char kGuardianPriorityDemotedTag[] = "yuzu.guardian_priority_demoted";

/// #2993: GuardianSparkRuntime::outbox_backpressure_drops() - compliance/health entries
/// rejected at the MAIN outbox's capacity (distinct from the lifecycle log's own
/// backpressure counter, already surfaced via guardian_journal_heartbeat.hpp) - had zero
/// production consumer before this tag: an on-call operator had no fleet-visible signal
/// for a chronic main-outbox jam at all. Sparse: 0 omits the tag.
inline constexpr char kGuardianOutboxBackpressureDropsTag[] =
    "yuzu.guardian_outbox_backpressure_drops";

/// #4783 commit 4: cumulative count of legacy-sink events GuardianEngine could not
/// deliver (see GuardianLegacySinkExecutor's own loss-table doc comment). Sparse:
/// 0 omits the tag - a healthy fleet (or one running entirely via Spark once that
/// flip lands) reports nothing here.
inline constexpr char kGuardianLegacySinkEventsLostTag[] =
    "yuzu.guardian_legacy_sink_events_lost";

/// #4783 commit 4: CURRENT count of rules with an open sticky legacy-sink
/// integrity gap (GuardianEngine::legacy_sink_kick() repairs these on the
/// heartbeat). Sparse: 0 omits the tag.
inline constexpr char kGuardianLegacySinkGapRulesTag[] = "yuzu.guardian_legacy_sink_gap_rules";

/// #4783 governance follow-up: cumulative count of emit_guard_event() calls that
/// bailed because no sink was wired yet (GuardianEngine::legacy_sink_dropped_unwired()
/// - the pre-network-arm drop, a routine window on every agent boot). Previously
/// counted in-process (legacy_sink_dropped_unwired_) with no accessor, no heartbeat
/// tag, and no fleet visibility - unlike its two siblings above. Sparse: 0 omits the
/// tag.
inline constexpr char kGuardianLegacySinkDroppedUnwiredTag[] =
    "yuzu.guardian_legacy_sink_dropped_unwired";

/// M1 health-stream telemetry (F5: widened from a single scalar to a stats struct, mirroring
/// GuardianJournalStats in guardian_journal_heartbeat.hpp, now that there are three sibling
/// counters instead of one; #4783 commit 4 added the legacy-sink loss-visibility pair; a
/// governance follow-up added the third legacy-sink counter below).
struct GuardianHealthStats {
    std::uint64_t unhealthy_suppressed{0};
    std::uint64_t unhealthy_refreshed{0};
    std::uint64_t priority_demoted{0};
    std::uint64_t outbox_backpressure_drops{0};   ///< #2993
    std::uint64_t legacy_sink_events_lost{0};     ///< #4783
    std::uint64_t legacy_sink_gap_rules{0};       ///< #4783
    std::uint64_t legacy_sink_dropped_unwired{0}; ///< #4783 governance follow-up
};

/// Populate `tags` with the (sparse) Guardian health telemetry. `TagMap` is any map with a
/// string `operator[]` - the protobuf status_tags map in production, std::map in tests.
template <typename TagMap>
void emit_guardian_health_heartbeat_tags(TagMap& tags, const GuardianHealthStats& s) {
    if (s.unhealthy_suppressed != 0)
        tags[kGuardianUnhealthySuppressedTag] = std::to_string(s.unhealthy_suppressed);
    if (s.unhealthy_refreshed != 0)
        tags[kGuardianUnhealthyRefreshedTag] = std::to_string(s.unhealthy_refreshed);
    if (s.priority_demoted != 0)
        tags[kGuardianPriorityDemotedTag] = std::to_string(s.priority_demoted);
    if (s.outbox_backpressure_drops != 0)
        tags[kGuardianOutboxBackpressureDropsTag] = std::to_string(s.outbox_backpressure_drops);
    if (s.legacy_sink_events_lost != 0)
        tags[kGuardianLegacySinkEventsLostTag] = std::to_string(s.legacy_sink_events_lost);
    if (s.legacy_sink_gap_rules != 0)
        tags[kGuardianLegacySinkGapRulesTag] = std::to_string(s.legacy_sink_gap_rules);
    if (s.legacy_sink_dropped_unwired != 0)
        tags[kGuardianLegacySinkDroppedUnwiredTag] =
            std::to_string(s.legacy_sink_dropped_unwired);
}

} // namespace yuzu::agent
