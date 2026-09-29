#pragma once

/// @file guardian_journal_heartbeat.hpp
/// Writer side of the durable lifecycle-audit journal's fleet telemetry (item 7 PR-Ag,
/// design §8). Extracted from the agent heartbeat lambda so the exact emitted keys + the
/// sparse-emit rule are unit-testable without a heartbeat thread. Mirrors
/// spark_heartbeat.hpp; the keys are pinned to the server-side reader by a unit test.
///
/// SPARSE: every field is a counter (or a depth gauge) that is 0 on a healthy, quiescent,
/// or inert (prefer_spark=false) agent, so a tag is emitted ONLY when non-zero. A journal
/// that has never dropped/failed/quarantined/paged anything ships NO journal tags at all -
/// fleet-kind, and it keeps the "absent == nothing to report" reading honest.

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent {

/// A snapshot of the journal's integrity + activity counters, assembled by
/// GuardianEngine::journal_stats() from the runtime (staging) + the journal component.
struct GuardianJournalStats {
    // Staging loss channels (runtime).
    std::uint64_t stage_dropped{0};   ///< pending reserve overflow under sustained write failure
    std::uint64_t stage_failures{0};  ///< a disarm record could not be built post-teardown
    std::uint64_t field_rejected{0};  ///< NUL / oversized / non-UTF-8 field kept a record out
    std::uint64_t clock_rejected{0};  ///< skewed clock (secs<=0) kept a record out
    std::uint64_t pending_depth{0};   ///< records staged but not yet persisted (gauge)
    // Persist (component).
    std::uint64_t batches_written{0};
    std::uint64_t write_failures{0};
    std::uint64_t key_collisions{0};
    // Retention / quarantine (component).
    std::uint64_t quarantined{0};
    std::uint64_t quarantine_failures{0};
    std::uint64_t quarantine_capacity_evicted{0}; ///< over-cap quarantined batches shed (UP-7)
    std::uint64_t batches_pruned{0};
    std::uint64_t prune_failures{0};
    /// Replay-side scan failures. Deliberately NOT folded into prune_failures: the same
    /// O(journal) KvStore read failing on the page side stops all replay while retention keeps
    /// succeeding, which is a different operator situation from retention itself failing.
    std::uint64_t page_read_failures{0};
    /// Retention passes that declined to age-evict because the wall clock jumped implausibly
    /// far forward. Nonzero is NOT an error - it means an endpoint's clock moved and the
    /// journal deliberately kept evidence it would otherwise have deleted.
    std::uint64_t clock_jump_skips{0};
    std::uint64_t write_capacity_rejected{0}; ///< new batch refused: journal at its byte/count cap (UP-1)
    std::uint64_t gauge_underflow{0};         ///< write-ceiling size gauge read NEGATIVE; persist failed CLOSED (UP-2/#2303)
    std::uint64_t journal_bytes{0};           ///< current live journal size estimate (gauge)
    std::uint64_t journal_batch_count{0};     ///< current live batch count (gauge)
    // Replay (component).
    std::uint64_t pages{0};
    std::uint64_t records_paged{0};
    std::uint64_t sent_labels_written{0};
    std::uint64_t evicted_sent_unacked{0};          ///< aged out WITH a sent-label (monitor)
    std::uint64_t evicted_without_send_evidence{0}; ///< aged out with NO sent-label (integrity gap, alert)
    std::uint64_t evicted_unclassified{0};          ///< aged out, disposition unknown - the third eviction
                                                    ///< bucket that makes pruned == the sum exact (item 3)
    std::uint64_t maint_exceptions{0};              ///< swallowed persist/prune/page throws (review B4)
    /// Firewalled OUTBOX-DELIVERY throws on the drain worker (bad_alloc in the drain
    /// machinery). Separate from maint_exceptions: delivery failing and retention failing
    /// need different operator responses.
    std::uint64_t drain_exceptions{0};
    /// Firewalled CONVERGENCE-SWEEP throws on the scheduler lanes. Deliberately NOT folded
    /// into maint_exceptions (#2298 Gate 6 sre): these are drift-DETECTION failures with
    /// nothing to do with the journal, and a tag named journal_maint_exceptions counting
    /// them leaves an operator unable to tell "audit trail at risk" from "detection
    /// degraded" - the two have different urgency and different remediation.
    std::uint64_t sweep_exceptions{0};
    // Lifecycle-audit outbox DELIVERY channel (GuardianSparkRuntime), surfaced by flip item
    // UP-4 (governance ledger): both had accessors but reached no heartbeat tag. send_exceptions
    // spans the lifecycle log AND the general outbox (sibling to drain_exceptions above);
    // lifecycle_backpressure_drops is lifecycle-specific (a staging LOSS, sibling to stage_dropped).
    std::uint64_t send_exceptions{0};              ///< a per-entry drain send THREW; head retained, that log's drain stops
    std::uint64_t lifecycle_backpressure_drops{0}; ///< lifecycle audit entries rejected at outbox enqueue for capacity (LOSS)
    // #3953 items 1+2 (GuardianOutboxSendExecutor, both lanes summed).
    std::uint64_t send_orphan_exceptions{0}; ///< a reclaimed orphan's thrown result, discarded (diagnostic only)
    std::uint64_t send_stalls{0};            ///< a send exceeded its stall threshold before completing/reclaiming
};

/// Populate `tags` with the (sparse) journal telemetry. `TagMap` is any map with a string
/// `operator[]` - the protobuf status_tags map in production, std::map in tests.
template <typename TagMap>
void emit_guardian_journal_heartbeat_tags(TagMap& tags, const GuardianJournalStats& s) {
    const auto put = [&](const char* key, std::uint64_t v) {
        if (v != 0)
            tags[key] = std::to_string(v);
    };
    put("yuzu.guardian_journal_stage_dropped", s.stage_dropped);
    put("yuzu.guardian_journal_stage_failures", s.stage_failures);
    put("yuzu.guardian_journal_field_rejected", s.field_rejected);
    put("yuzu.guardian_journal_clock_rejected", s.clock_rejected);
    put("yuzu.guardian_journal_pending", s.pending_depth);
    put("yuzu.guardian_journal_batches_written", s.batches_written);
    put("yuzu.guardian_journal_write_failures", s.write_failures);
    put("yuzu.guardian_journal_key_collisions", s.key_collisions);
    put("yuzu.guardian_journal_quarantined", s.quarantined);
    put("yuzu.guardian_journal_quarantine_failures", s.quarantine_failures);
    put("yuzu.guardian_journal_quarantine_capacity_evicted", s.quarantine_capacity_evicted);
    put("yuzu.guardian_journal_pruned", s.batches_pruned);
    put("yuzu.guardian_journal_prune_failures", s.prune_failures);
    put("yuzu.guardian_journal_page_read_failures", s.page_read_failures);
    put("yuzu.guardian_journal_clock_jump_skips", s.clock_jump_skips);
    put("yuzu.guardian_journal_write_capacity_rejected", s.write_capacity_rejected);
    put("yuzu.guardian_journal_gauge_underflow", s.gauge_underflow);
    put("yuzu.guardian_journal_bytes", s.journal_bytes);
    put("yuzu.guardian_journal_batch_count", s.journal_batch_count);
    put("yuzu.guardian_journal_pages", s.pages);
    put("yuzu.guardian_journal_records_paged", s.records_paged);
    put("yuzu.guardian_journal_sent_labels", s.sent_labels_written);
    put("yuzu.guardian_journal_evicted_sent_unacked", s.evicted_sent_unacked);
    put("yuzu.guardian_journal_evicted_no_send_evidence", s.evicted_without_send_evidence);
    put("yuzu.guardian_journal_evicted_unclassified", s.evicted_unclassified);
    put("yuzu.guardian_journal_maint_exceptions", s.maint_exceptions);
    put("yuzu.guardian_drain_exceptions", s.drain_exceptions);
    put("yuzu.guardian_sweep_exceptions", s.sweep_exceptions);
    put("yuzu.guardian_send_exceptions", s.send_exceptions);
    put("yuzu.guardian_journal_backpressure_drops", s.lifecycle_backpressure_drops);
    put("yuzu.guardian_send_orphan_exceptions", s.send_orphan_exceptions);
    put("yuzu.guardian_send_stalls", s.send_stalls);
}

/// AGE gauges (flip item 6 + #2364 step-1) - a SEPARATE struct from GuardianJournalStats
/// on purpose: that struct is pinned 1:1 to the server's SUM-rollup table by a sizeof
/// static_assert, and an age is not a counter - a fleet SUM of ages is meaningless, the
/// server rolls these up as MAX (a single stalled endpoint IS the signal). Assembled by
/// GuardianEngine::journal_age_stats(), which returns nullopt while the drain worker is
/// absent/dormant (prefer_spark=false) - that absence, not a zero, is what keeps these
/// gauges silent pre-flip, because unlike the counters above a zero age is a REAL value.
struct GuardianJournalAgeStats {
    /// Seconds since the drain worker's last non-throwing PAGE maintenance pass, seeded from
    /// worker start. A LIVENESS gauge: a dead worker thread or a permanently-throwing pass
    /// reads as an ever-growing age (flip item 14); deferred/read-failed passes still count
    /// as alive (those failure modes have their own counters).
    std::uint64_t page_stale_seconds{0};
    /// PRUNE sibling - separate because the cadences differ (30 s / 120 s) and stall
    /// independently.
    std::uint64_t prune_stale_seconds{0};
    /// Seconds since headroom blocking was first observed in the CURRENT sampled
    /// replay-congestion episode (#2364); 0 = not currently blocked. Clears only after a
    /// proven block-free sweep of all journal candidates; resets on agent restart. Forced
    /// passes can start an episode from already-delivered batches, so this measures
    /// replay-window congestion, not strictly unsent-batch starvation.
    std::uint64_t headroom_blocked_seconds{0};
};

/// Populate `tags` with the journal AGE gauges. Emission posture differs from the sparse
/// counter emitter above, per field:
///  - the two staleness ages are emitted WHENEVER stats is present, INCLUDING 0 - zero is a
///    legitimately-fresh reading, and omitting it would make a dead-idle worker
///    indistinguishable from a healthy idle one (the exact gap item 6 closes);
///  - the headroom-blocked age is emitted SPARSELY - 0 genuinely means "no episode", and
///    absent-means-healthy keeps the fleet MAX honest.
/// Dormancy is the OPTIONAL, not a zero: nullopt (worker absent/dormant) emits nothing, so
/// pre-flip fleets never page on a "stale" journal that is deliberately inert.
template <typename TagMap>
void emit_guardian_journal_age_tags(TagMap& tags,
                                    const std::optional<GuardianJournalAgeStats>& s) {
    if (!s)
        return;
    tags["yuzu.guardian_journal_page_stale_seconds"] = std::to_string(s->page_stale_seconds);
    tags["yuzu.guardian_journal_prune_stale_seconds"] = std::to_string(s->prune_stale_seconds);
    if (s->headroom_blocked_seconds != 0)
        tags["yuzu.guardian_journal_headroom_blocked_seconds"] =
            std::to_string(s->headroom_blocked_seconds);
}

} // namespace yuzu::agent
