#pragma once

/// @file guardian_io_ceiling_heartbeat.hpp
/// Writer side of the rung 9c PR-3 (Decision 3, Option B) physical-orphan-ceiling
/// observability signal - R5.1's own flagged gap: "The physical-orphan ceiling
/// (R5.1) similarly has no named observability today ... should be independently
/// alert-worthy, not folded silently into the same signal as ordinary contention."
/// ~/.claude/plans/spark-rung9c-pr3-telemetry-KICKOFF-v2.md Decision 3: Dave ruled
/// a plain counter now (this file), with the "currently under repeated pressure"
/// windowed detector explicitly DEFERRED to PR-6 once real measurement exists.
///
/// Deliberately NOT a general GuardianIoExecutor::Counters egress - #3415
/// (docs/spark-legacy-delta-registry.md row D10) is the broader, still-open gap
/// this file does not close; that is scoped to a separate follow-up ("PR-3a").
/// This is one narrow, separately-motivated signal (R5.1's own ask), not the start
/// of #3415's general counter wiring.
///
/// Ordinary sparse-counter shape (0 omits the tag), like
/// guardian_journal_heartbeat.hpp's 32-row counter family - NOT the age-gauge
/// pattern arm_pending/arm_failed use. This signal needs no prefer_spark_ dormancy
/// gate the way GuardianArmStats does: a plain cumulative count of zero is equally
/// truthful whether spark is dormant or simply has never hit the physical ceiling -
/// unlike GuardianArmAckLedger's re-statable application state, there is no
/// "current application always exists, even when dormant" trap here to gate
/// around.

#include <cstdint>
#include <string>

namespace yuzu::agent {

/// Populate `tags` with the arm/disarm executor's cumulative physical-ceiling
/// refusal count (see GuardianEngine::io_ceiling_rejections()). Sparse: 0 omits
/// the tag entirely, matching every other monitor-only counter in this namespace.
/// MONITOR-ONLY (docs/observability-conventions.md): neither `increase()` nor a
/// bare `> 0` is a sound alert over an unlabelled fleet sum of per-agent cumulative
/// counters - this tag NAMES the fault class (R5.1's own ask), it does not by
/// itself answer "is this endpoint currently wedged" (that detector is PR-6's job).
template <typename TagMap>
void emit_guardian_io_ceiling_heartbeat_tags(TagMap& tags, std::uint64_t rejected_ceiling) {
    if (rejected_ceiling != 0)
        tags["yuzu.guardian_io_arm_disarm_rejected_ceiling"] = std::to_string(rejected_ceiling);
}

} // namespace yuzu::agent
