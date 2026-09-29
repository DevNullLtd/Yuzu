#pragma once

/// @file guardian_arm_heartbeat.hpp
/// Writer side of the rung 9c PR-3 arm/disarm ack-ledger fleet telemetry
/// (docs/spark-stage2-guardian-consumer-design.md §R5.2's "Telemetry-tag semantics,
/// flagged not specified" paragraph; ~/.claude/plans/spark-rung9c-pr3-telemetry-
/// KICKOFF-v2.md Decision 1). Mirrors guardian_journal_heartbeat.hpp's AGE-gauge
/// pattern (emit_guardian_journal_age_tags), NOT its sparse-counter pattern: these
/// are RE-STATABLE GAUGES, not monotonic per-sweep counters rolled up into a fleet
/// sum. A nearby row in docs/spark-legacy-delta-registry.md (the counter-rollup
/// families) uses the opposite shape - copying that by analogy would silently break
/// the K-bound safety argument the whole mechanism rests on, since a cleared
/// wedge (PR-5) would never be reflected by a monotonic counter.
///
/// GuardianArmStats is assembled by GuardianEngine::arm_stats() from
/// GuardianArmAckLedger::arm_stats() (agents/core/src/guardian_arm_ack.hpp) - the
/// CURRENT application's still-pending accepted-arm count and resolved-failure
/// count. Both fields describe the SAME application snapshot, sampled together
/// under GuardianEngine::mtx_, so the pair is internally consistent within one
/// sample (unlike the generation tag read separately elsewhere on the heartbeat -
/// see GuardianEngine::arm_stats()'s own doc comment).

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent {

/// A snapshot of the ack ledger's CURRENT application - yuzu.guardian_arm_pending /
/// yuzu.guardian_arm_failed. Both fields are aggregate-of-uint64_t only (no padding)
/// so a structural size pin against the server-side 2-row table
/// (server/core/src/guardian_arm_fleet_tags.hpp) is meaningful; keep it that way if a
/// field is ever added.
struct GuardianArmStats {
    /// Accepted receipts still pending in the current application's ledger after the
    /// latest maintenance drain (GuardianArmAckLedger::drain_locked()). A completed
    /// receipt beyond that drain's per-tick resolution cap can remain counted here
    /// until a subsequent tick - a SAMPLED ledger observation, not an instantaneous
    /// truth.
    std::uint64_t pending{0};
    /// Current application receipts drained to a non-Committed terminal outcome,
    /// still unresolved for acknowledgment purposes
    /// (GuardianArmAckLedger::Application::resolved_failed). Decrements in place
    /// within one application for exactly ONE case (rung 9c PR-5d, concern 2,
    /// arm-recovery): a Wedged receipt whose exact (rule_id, generation)
    /// incarnation is later ADOPTED by the runtime (PR-5d's own concern 1 - a late
    /// success on a still-desired wedged claim) is detected by drain_locked()'s
    /// own recovery scan (GuardianSparkRuntime::receipt_recovery_status(), rung
    /// 9c PR-5e's atomic combination of receipt_recovered() with the K-eligibility
    /// probe - see that accessor's own doc comment) and its
    /// contribution here is cleared - every OTHER non-Committed status (Failed,
    /// CongestionExpired, Withdrawn, Stopped) still only ever increments this
    /// field within one application, exactly as before. It ALSO still resets to 0
    /// whenever decide_retry() returns Reapply on a generation that previously
    /// failed, which begins a FRESH application via begin_application() - that
    /// Reapply path is driven by the existing ~25s full_sync retry cadence and
    /// predates PR-5d. Recovery is scoped to THIS application's own bookkeeping
    /// only (see Application::failed_receipts' own doc comment) - a durable,
    /// cross-application "last known outcome for every currently-desired rule"
    /// gauge is a separate, stronger semantic 5e's own scope owns, not delivered
    /// here. Zero failed does not itself mean compliant or enforced - latched_
    /// failure and Service-watcher readiness are separate signals.
    std::uint64_t failed{0};
};

/// Populate `tags` with the arm-ledger snapshot. Dormancy is the OPTIONAL, not a
/// zero - matching emit_guardian_journal_age_tags's own posture. `s` is nullopt
/// while GuardianEngine::arm_stats() considers the signal dormant: `prefer_spark_`
/// false, the engine stopped, Spark itself unavailable (Unwired/SparkFailed/
/// SparkDisabled), or the ledger has no current application yet. THIS explicit
/// four-way gate is load-
/// bearing (Check A, KICKOFF-v2): GuardianEngine::apply_rules() calls
/// GuardianArmAckLedger::begin_application() UNCONDITIONALLY, regardless of
/// prefer_spark_, so "is there a current application" alone cannot distinguish
/// "spark dormant" from "spark live, currently clean" - a legacy (non-spark) agent
/// has a live, empty Application on every push. Gating on `current_ != nullptr`
/// alone would read as false-present-healthy ("arm_pending=0, arm_failed=0") on
/// every non-spark agent in the fleet. See GuardianEngine::arm_stats()'s own doc
/// comment for where that gate actually lives.
///
/// A live snapshot emits BOTH keys, including a genuine zero: a rule genuinely at
/// zero pending/failed must read as "checked, healthy", not "dormant" - an omitted
/// tag reads as dormant to a fleet-level consumer, exactly the distinction the
/// age-tag pattern this mirrors was built to make.
template <typename TagMap>
void emit_guardian_arm_heartbeat_tags(TagMap& tags, const std::optional<GuardianArmStats>& s) {
    if (!s)
        return;
    tags["yuzu.guardian_arm_pending"] = std::to_string(s->pending);
    tags["yuzu.guardian_arm_failed"] = std::to_string(s->failed);
}

} // namespace yuzu::agent
