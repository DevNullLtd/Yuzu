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
/// The exceptions are the #5403 pending-Disarm age (emit_guardian_disarm_pending_age_tag) and
/// the #4472 outstanding-compensation age (emit_guardian_compensation_pending_age_tag), which
/// are ages, not counters: each is absent while nothing is pending.

#include <cstdint>
#include <optional>
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

/// #5403: cumulative count of Spark Disarm claims observed pending longer than
/// kDisarmPendingObserveThreshold (GuardianSparkRuntime::disarm_deadline_elapsed(), once per
/// claim). Observation only: nothing is released. Sparse: 0 omits the tag. Same plain
/// cumulative-counter shape as its siblings above, so the server rolls it up as a fleet SUM.
inline constexpr char kGuardianDisarmDeadlineElapsedTag[] = "yuzu.guardian_disarm_deadline_elapsed";

/// #4472: cumulative count of compensating teardowns observed outstanding longer than the
/// claim's own compensation deadline (GuardianSparkRuntime::compensation_deadline_elapsed(),
/// once per claim). The Arm-claim counterpart of the Disarm count above, which cannot see it.
/// Observation only: nothing is released. Sparse: 0 omits the tag; rolled up as a fleet SUM.
inline constexpr char kGuardianCompensationDeadlineElapsedTag[] =
    "yuzu.guardian_compensation_deadline_elapsed";

/// #5404 (gate rows P1/P2): the Spark claim-lifecycle counters. Every one is sparse (0 omits the
/// tag), steady-state 0, and rolled up by the server as a plain fleet SUM like its siblings
/// above; none is gated on prefer_spark (a zero is equally truthful dormant). Nonzero values
/// mean "inspect", not "an outage": the server HELP text in guardian_health_fleet_tags.hpp is
/// the operator-facing statement of what each one says and does not say.
///
/// GuardianSparkRuntime::orphan_disarms_started(): a ->0 index edge was dropped without a
/// Disarm and the reaper's orphan pass queued one.
inline constexpr char kGuardianOrphanDisarmsStartedTag[] = "yuzu.guardian_orphan_disarms_started";
/// GuardianSparkRuntime::dead_watchers_erased_on_lost(): on_subscription_lost erased a dead
/// watcher for a key with no rules.
inline constexpr char kGuardianDeadWatchersErasedOnLostTag[] =
    "yuzu.guardian_dead_watchers_erased_on_lost";
/// GuardianSparkRuntime::tombstones_released_by_reaper(): a release that failed earlier and was
/// recovered by the expiry reaper.
inline constexpr char kGuardianTombstonesReleasedByReaperTag[] =
    "yuzu.guardian_tombstones_released_by_reaper";
/// GuardianSparkRuntime::claim_index_release_failures(): index releases that threw and were
/// contained (counts release ATTEMPTS, not claims).
inline constexpr char kGuardianClaimIndexReleaseFailuresTag[] =
    "yuzu.guardian_claim_index_release_failures";
/// GuardianSparkRuntime::claim_drain_failures(): completion-drain / parked-arm bookkeeping
/// steps that threw and were contained.
inline constexpr char kGuardianClaimDrainFailuresTag[] = "yuzu.guardian_claim_drain_failures";
/// GuardianSparkRuntime::retained_tombstones(): a CURRENT count (not cumulative) of dead Queued
/// Arm claims still holding a genuine index mapping. O(claims) under registry_mu_: read at
/// heartbeat cadence only.
inline constexpr char kGuardianRetainedTombstonesTag[] = "yuzu.guardian_retained_tombstones";
/// GuardianSparkRuntime::detach_sweep_left_residue(): the last-on-key detach sweep left the
/// key's fifo non-empty and took the synchronous residue fallback.
inline constexpr char kGuardianDetachSweepLeftResidueTag[] =
    "yuzu.guardian_detach_sweep_left_residue";
/// GuardianSparkRuntime::detach_claim_failures(): detach could not hand the subscription to a
/// Disarm claim and took the counted rollback or last resort.
inline constexpr char kGuardianDetachClaimFailuresTag[] = "yuzu.guardian_detach_claim_failures";
/// GuardianSparkRuntime::detach_post_commit_failures(): a post-mutation detach step threw and
/// was contained, including a swallowed inline-type backend disarm throw.
inline constexpr char kGuardianDetachPostCommitFailuresTag[] =
    "yuzu.guardian_detach_post_commit_failures";
/// GuardianSparkRuntime::claims_dropped_at_stop(): claims dropped by shutdown only.
inline constexpr char kGuardianClaimsDroppedAtStopTag[] = "yuzu.guardian_claims_dropped_at_stop";
/// GuardianEngine::ack_maint_exceptions(): throws caught by the engine's ack-bookkeeping
/// maintenance firewall (the heartbeat-thread ack drain and apply_rules' ack preamble).
inline constexpr char kGuardianAckMaintExceptionsTag[] = "yuzu.guardian_ack_maint_exceptions";

/// #4472: age in whole seconds (floored) of the oldest compensating teardown still outstanding
/// (GuardianSparkRuntime::oldest_outstanding_compensation_age()), measured from the instant the
/// compensation became owed, not from the original arm. NOT a counter: a re-statable age, so
/// the server rolls it up as the fleet MAX. Emitted by emit_guardian_compensation_pending_age_tag
/// below; ABSENT while none is outstanding. "Teardown pending too long" is what this measures,
/// not proof of a hang.
inline constexpr char kGuardianCompensationPendingAgeTag[] =
    "yuzu.guardian_compensation_pending_age_seconds";

/// #5403: age in whole seconds (floored) of the oldest Spark Disarm claim still pending
/// (GuardianSparkRuntime::oldest_pending_disarm_age()). NOT a counter: a re-statable age, so
/// the server rolls it up as the fleet MAX (a sum of ages is meaningless), never as a sum.
/// Emitted by emit_guardian_disarm_pending_age_tag below; ABSENT while no Disarm is pending.
/// "Pending too long" is what this measures, not proof of a hang.
inline constexpr char kGuardianDisarmPendingAgeTag[] = "yuzu.guardian_disarm_pending_age_seconds";

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
    std::uint64_t disarm_deadline_elapsed{0};     ///< #5403
    std::uint64_t compensation_deadline_elapsed{0}; ///< #4472
    std::uint64_t orphan_disarms_started{0};          ///< #5404 P1
    std::uint64_t dead_watchers_erased_on_lost{0};    ///< #5404 P1
    std::uint64_t tombstones_released_by_reaper{0};   ///< #5404 P1
    std::uint64_t claim_index_release_failures{0};    ///< #5404 P1
    std::uint64_t claim_drain_failures{0};            ///< #5404 P1
    std::uint64_t retained_tombstones{0};             ///< #5404 P1 (a current count, not cumulative)
    std::uint64_t detach_sweep_left_residue{0};       ///< #5404 P1
    std::uint64_t detach_claim_failures{0};           ///< #5404 P1
    std::uint64_t detach_post_commit_failures{0};     ///< #5404 P1
    std::uint64_t claims_dropped_at_stop{0};          ///< #5404 P1
    std::uint64_t ack_maint_exceptions{0};            ///< #5404 P2
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
    if (s.disarm_deadline_elapsed != 0)
        tags[kGuardianDisarmDeadlineElapsedTag] = std::to_string(s.disarm_deadline_elapsed);
    if (s.compensation_deadline_elapsed != 0)
        tags[kGuardianCompensationDeadlineElapsedTag] =
            std::to_string(s.compensation_deadline_elapsed);
    if (s.orphan_disarms_started != 0)
        tags[kGuardianOrphanDisarmsStartedTag] = std::to_string(s.orphan_disarms_started);
    if (s.dead_watchers_erased_on_lost != 0)
        tags[kGuardianDeadWatchersErasedOnLostTag] =
            std::to_string(s.dead_watchers_erased_on_lost);
    if (s.tombstones_released_by_reaper != 0)
        tags[kGuardianTombstonesReleasedByReaperTag] =
            std::to_string(s.tombstones_released_by_reaper);
    if (s.claim_index_release_failures != 0)
        tags[kGuardianClaimIndexReleaseFailuresTag] =
            std::to_string(s.claim_index_release_failures);
    if (s.claim_drain_failures != 0)
        tags[kGuardianClaimDrainFailuresTag] = std::to_string(s.claim_drain_failures);
    if (s.retained_tombstones != 0)
        tags[kGuardianRetainedTombstonesTag] = std::to_string(s.retained_tombstones);
    if (s.detach_sweep_left_residue != 0)
        tags[kGuardianDetachSweepLeftResidueTag] = std::to_string(s.detach_sweep_left_residue);
    if (s.detach_claim_failures != 0)
        tags[kGuardianDetachClaimFailuresTag] = std::to_string(s.detach_claim_failures);
    if (s.detach_post_commit_failures != 0)
        tags[kGuardianDetachPostCommitFailuresTag] =
            std::to_string(s.detach_post_commit_failures);
    if (s.claims_dropped_at_stop != 0)
        tags[kGuardianClaimsDroppedAtStopTag] = std::to_string(s.claims_dropped_at_stop);
    if (s.ack_maint_exceptions != 0)
        tags[kGuardianAckMaintExceptionsTag] = std::to_string(s.ack_maint_exceptions);
}

/// #5404 (P1) and #4472: read the eleven GuardianSparkRuntime claim-lifecycle values into a
/// GuardianHealthStats (every other field stays 0, so emitting it adds only these tags to the
/// sparse emitter above; ack_maint_exceptions is engine-owned and filled by the engine).
/// A template over the runtime type so this header stays free of the runtime's includes (the
/// server-side pin test includes it); the ONE place the runtime accessor -> health field
/// mapping lives, so a swapped pair is caught by a test of this function.
/// `retained_tombstones()` is an O(claims) scan under the runtime's registry lock: call at
/// heartbeat cadence only, never per event.
template <typename Runtime>
[[nodiscard]] GuardianHealthStats guardian_spark_claim_health_stats(const Runtime& rt) {
    GuardianHealthStats s;
    s.compensation_deadline_elapsed = rt.compensation_deadline_elapsed(); // #4472
    s.orphan_disarms_started = rt.orphan_disarms_started();
    s.dead_watchers_erased_on_lost = rt.dead_watchers_erased_on_lost();
    s.tombstones_released_by_reaper = rt.tombstones_released_by_reaper();
    s.claim_index_release_failures = rt.claim_index_release_failures();
    s.claim_drain_failures = rt.claim_drain_failures();
    s.retained_tombstones = static_cast<std::uint64_t>(rt.retained_tombstones());
    s.detach_sweep_left_residue = rt.detach_sweep_left_residue();
    s.detach_claim_failures = rt.detach_claim_failures();
    s.detach_post_commit_failures = rt.detach_post_commit_failures();
    s.claims_dropped_at_stop = rt.claims_dropped_at_stop();
    return s;
}

/// #5403: populate `tags` with the oldest pending Disarm's age. A SEPARATE emitter from the
/// sparse counters above, for the reason GuardianJournalAgeStats is a separate struct: this
/// is an age, GuardianHealthStats is pinned 1:1 to the server's SUM table, and the fleet
/// rollup op is MAX. Dormancy is the OPTIONAL, not a zero: nullopt (no Disarm pending) emits
/// NOTHING, so a quiet agent can never read as "a Disarm is pending, age 0". An engaged
/// optional emits its value including 0, which genuinely means "a Disarm has been pending for
/// less than one second".
template <typename TagMap>
void emit_guardian_disarm_pending_age_tag(TagMap& tags,
                                          const std::optional<std::uint64_t>& age_seconds) {
    if (!age_seconds)
        return;
    tags[kGuardianDisarmPendingAgeTag] = std::to_string(*age_seconds);
}

/// #4472: populate `tags` with the oldest outstanding compensating teardown's age. Same shape
/// and same reasons as emit_guardian_disarm_pending_age_tag (an age, a MAX at the server, its
/// own emitter): nullopt (none outstanding) emits NOTHING, never a fabricated 0, and an engaged
/// optional emits its value including 0 (outstanding for less than one second).
template <typename TagMap>
void emit_guardian_compensation_pending_age_tag(TagMap& tags,
                                                const std::optional<std::uint64_t>& age_seconds) {
    if (!age_seconds)
        return;
    tags[kGuardianCompensationPendingAgeTag] = std::to_string(*age_seconds);
}

} // namespace yuzu::agent
