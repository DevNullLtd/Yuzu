#pragma once

/// @file guardian_health_fleet_tags.hpp
/// Reader side of the Guardian M1 health-stream fleet telemetry (#2298 gate 3, item
/// 6d; #2993 added the 4th row below; #4783 commit 4 added the 5th/6th rows -
/// legacy-sink loss visibility, unrelated to M1's flood-guard/outbox signals but
/// sharing this family's exact shape: a plain sparse cumulative counter rolled up
/// as an unlabelled fleet sum; a #4783 governance follow-up added the 7th row -
/// the pre-network-arm legacy-sink drop, previously counted in-process only with
/// no accessor, no heartbeat tag, and no fleet visibility; #5403 added the 8th row, the
/// pending-Spark-Disarm deadline count, plus the separate MAX-rollup age table below;
/// #4472 added the 9th row, the compensating-teardown deadline count, and the second age row;
/// #5404 added rows 10-20, the Spark claim-lifecycle counters and the retained-tombstone count).
/// Single source of truth for the `yuzu.guardian_*` heartbeat tag keys this rollup consumes,
/// the `yuzu_fleet_guardian_*` gauge names they roll up into, their HELP text, and the
/// forged-value-safe parse of the agent-supplied values.
///
/// The writer is agents/core/src/guardian_health_heartbeat.hpp (`emit_guardian_health_heartbeat_tags`
/// with `GuardianHealthStats`; the #5403 and #4472 ages share one struct and one emitter,
/// `GuardianHealthAgeStats` and `emit_guardian_health_age_tags`). Both sides are bound by
/// tests/unit/server/test_guardian_health_fleet_tags.cpp, which emits through the agent's REAL
/// emitters and asserts every key produced is one a table here recognises. That test is the
/// drift guard: a rename on either side without the other is a red test, not a silently-dead
/// gauge.
///
/// The keys are duplicated here rather than `#include`d from the agent header ON
/// PURPOSE - same rationale as the guardian-journal sibling this file mirrors: server
/// production code including an agent private header would add an upward server ->
/// agent dependency edge that the build graph does not have and must not gain (the
/// constraint is recorded verbatim in tests/meson.build). Only the TEST target carries
/// the agent include path, which is exactly where the bind belongs. tests/meson.build's
/// hoist comment names THIS file as a third family that must move together with the
/// spark and journal pins when that hoist lands - do not let a future two-family sweep
/// leave this one behind.
///
/// SHAPE: flat and unlabelled. `kGuardianHealthMetrics` is plain sparse rows (cumulative
/// counters, plus the #5404 retained-tombstone current count) rolled up as a fleet SUM; the
/// table, not this comment, is authoritative for how many. `kGuardianHealthAgeMetrics`
/// (#5403, #4472) is the one exception: re-statable AGEs rolled up as the fleet MAX, in their
/// own table for the reasons the journal sibling's age table gives (a sum of ages is
/// meaningless, and the op lives in the consumer). Name rule, asserted by the pin test, for
/// the counter table: `gauge` == "yuzu_fleet_" + `tag` with its "yuzu." heartbeat-namespace
/// prefix stripped; the age table appends "_max". The age table is pinned to the agent's
/// `GuardianHealthAgeStats` by a sizeof static_assert in the pin test, so an age added on
/// either side without the other is a build break.
///
/// WHAT ABSENCE MEANS, MECHANICALLY (same posture as the journal family - stated once
/// there, not re-derived here beyond the mechanics): the writer is SPARSE, a counter
/// that is 0 ships no tag. `AgentHealthStore::recompute_metrics` clears every gauge
/// family in these tables at the top of every sweep and re-publishes only those at least
/// one retained agent reported this cycle. An absent family means: no retained agent's
/// latest heartbeat carried a value for it that PASSED the forged-value parse.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Max accepted value of any health tag. Above it the value is treated as "did not
/// report", NOT clamped-and-counted - same rejecting-not-clamping rationale as
/// kMaxPlausibleGuardianJournalCount (guardian_journal_fleet_tags.hpp): these are a
/// fleet SUM accumulated into a double, so a single agent reporting near-UINT64_MAX
/// would make every honest agent's contribution a no-op in IEEE-754.
inline constexpr unsigned long long kMaxPlausibleGuardianHealthCount = 1'000'000'000ULL;

/// One health telemetry signal: the agent's heartbeat tag key, the fleet gauge it sums
/// into, and the gauge's Prometheus HELP text. Same row shape as
/// guardian_journal_fleet_tags.hpp's GuardianJournalMetric.
struct GuardianHealthMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// The full published set. Order matches GuardianHealthStats / the emit order in
/// agents/core/src/guardian_health_heartbeat.hpp for reviewability; nothing depends on
/// it. Every row is exported as `gauge` - a per-sweep recomputed fleet sum, cleared and
/// rebuilt, never monotonic.
///
/// ALERTING: THESE ARE MONITOR-ONLY, same posture and same reasons as the guardian
/// journal family - no churn-robust new-increment alert exists over an unlabelled
/// fleet sum of per-agent cumulative counters. See the `yuzu-guardian-journal`
/// preamble in docs/prometheus/yuzu-alerts.yml for the full analysis; not restated
/// here.
///
/// ADR-1005 exception ledger, 2026-07-14 class-level entry: a `/metrics`-only fleet
/// gauge family is observability, not capability, so it carries no REST/MCP twin
/// obligation.
inline constexpr GuardianHealthMetric kGuardianHealthMetrics[] = {
    {"yuzu.guardian_unhealthy_suppressed", "yuzu_fleet_guardian_unhealthy_suppressed",
     "Fleet sum of convergence re-evals of a still-errored Guardian rule whose repeat "
     "guard.unhealthy was NOT re-emitted (M1 edge-suppression flood guard). MONITOR-ONLY: "
     "no sound alert form exists over an unlabelled fleet sum of per-agent cumulative "
     "counters - increase() fakes increments on agent churn and bare > 0 never clears at "
     "fleet scale. Graph it; do not page on it"},
    {"yuzu.guardian_unhealthy_refreshed", "yuzu_fleet_guardian_unhealthy_refreshed",
     "Fleet sum of guard.unhealthy re-emissions for a rule still stuck errored, sent at "
     "errored_refresh_ms cadence (M1 item (a)) so a lost/coalesced edge cannot leave the "
     "server's errored view stale forever. Sibling to unhealthy_suppressed - together "
     "they partition every committed repeat-errored eval into \"put on the wire\" vs "
     "\"not this tick\". MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_priority_demoted", "yuzu_fleet_guardian_priority_demoted",
     "Fleet sum of rule_ids demoted off the 5s convergence priority lane to their normal "
     "type-lane cadence after K consecutive Unknown sweeps or T elapsed (M1 item (b), the "
     "read-flood guard for a rule stuck pending-initial). MONITOR-ONLY, same posture as "
     "the rest of this family"},
    {"yuzu.guardian_outbox_backpressure_drops", "yuzu_fleet_guardian_outbox_backpressure_drops",
     "Fleet sum of compliance/health entries rejected at the agent's MAIN outbox capacity "
     "(#2993) - distinct from the lifecycle log's own backpressure counter, which rolls up "
     "separately via guardian_journal_fleet_tags.hpp. A chronic per-agent jam here means "
     "compliance/health drift is being lost, not just delayed. MONITOR-ONLY, same posture "
     "as the rest of this family"},
    {"yuzu.guardian_legacy_sink_events_lost", "yuzu_fleet_guardian_legacy_sink_events_lost",
     "Fleet sum of legacy Guardian sink events an agent could not deliver (#4783) - refused "
     "at the detached sender's queue capacity, an admission failure, a failed Write(), or a "
     "throwing send. Three OTHER legacy-sink drop modes are excluded from this counter: "
     "the pre-network-arm drop (no sink wired yet, before "
     "agent.cpp's post-Subscribe set_event_sink call) is now its OWN fleet gauge, "
     "yuzu_fleet_guardian_legacy_sink_dropped_unwired below (a governance follow-up) - it "
     "can BE loss of already-committed guard state, since a legacy guard only re-reports "
     "on its next real transition, so a drift lost in that pre-network window can go "
     "unreported until the rule's compliance state changes again or the agent restarts; "
     "the stop()-time backlog discard and the link-down drop (LinkDown / the executor's "
     "dropped_link_down counter, D4b) remain genuinely un-signaled outside the agent "
     "process - the pre-existing, un-built \"durable buffering is A3\" residual "
     "(docs/spark-legacy-delta-registry.md), out of scope for this fix. Always live "
     "regardless of the Spark flip (prefer_spark) - the legacy IGuard sink is the current "
     "production path. MONOTONIC PER AGENT AND RESTART-DURABLE (#4783 Gate 4 UP-3): each "
     "agent persists its own counter (and the open-gap ledger below) to its own KvStore "
     "and restores it at boot, so a mid-outage agent restart does not reset that agent's "
     "own value back to 0 - only the raw lost EVENT content is not durable "
     "(docs/spark-legacy-delta-registry.md D13). "
     "The EXPORTED FLEET SUM above is still cleared and rebuilt every sweep like the rest of "
     "this family (not itself monotonic) - it drops when a reporting agent leaves the "
     "retained set, same as every other gauge here; per-agent durability is what survives a "
     "RESTART, not what the fleet aggregate does across a sweep. MONITOR-ONLY, same posture "
     "as the rest of this family"},
    {"yuzu.guardian_legacy_sink_gap_rules", "yuzu_fleet_guardian_legacy_sink_gap_rules",
     "Fleet sum of rules whose SERVER-SIDE CENSUS may be stale because the agent's last "
     "drift/compliance report for that rule was lost and has not yet been confirmed repaired "
     "(#4783) - a count of AFFECTED RULES, not a count of lost events (see "
     "yuzu_fleet_guardian_legacy_sink_events_lost for that). The agent self-heals this every "
     "heartbeat (GuardianEngine::legacy_sink_kick()) by synthesizing a guard.unhealthy report "
     "for each open gap; a persistently non-zero sum means repairs are also failing to "
     "deliver, not just the original reports. RESTART-DURABLE PER AGENT (#4783 "
     "Gate 4 UP-3): each agent persists its own open-gap ledger to its own KvStore and "
     "restores it at boot, so a mid-outage agent restart no longer reads as a false "
     "\"resolved\" the way a genuine repair would (docs/spark-legacy-delta-registry.md D13) - "
     "an interior loss can still self-clear on a later successful event with no repair ever "
     "firing (D13's Gate 4 UP-4, an accepted trade-off, not a bug in this gauge). The "
     "EXPORTED FLEET SUM above is still cleared and rebuilt every sweep like the rest of this "
     "family (not itself monotonic) - per-agent durability is what survives a RESTART, not "
     "what the fleet aggregate does across a sweep. MONITOR-ONLY, same posture as "
     "the rest of this family"},
    {"yuzu.guardian_legacy_sink_dropped_unwired",
     "yuzu_fleet_guardian_legacy_sink_dropped_unwired",
     "Fleet sum of Guardian legacy-sink events dropped because emit_guard_event() ran "
     "before the event sink was wired (governance follow-up to #4783) - the pre-network-"
     "arm drop, a routine window on every agent boot, before agent.cpp's post-Subscribe "
     "set_event_sink call. Distinct from yuzu_fleet_guardian_legacy_sink_events_lost "
     "above: this drop has NO gap-repair mechanism (GuardianEngine::legacy_sink_kick() "
     "never re-sends it), so a nonzero sum can mean genuine loss of already-committed "
     "guard state, not just a delayed report - a lost drift here is only corrected by "
     "the rule's OWN next real transition or the agent's next restart (see "
     "docs/spark-legacy-delta-registry.md D9/D13). Always live regardless of the Spark "
     "flip (prefer_spark) - the legacy IGuard sink is the current production path. "
     "NOT RESTART-DURABLE, unlike events_lost/gap_rules above: legacy_sink_dropped_"
     "unwired_ is a plain in-process atomic, never persisted to KvStore, so it resets "
     "to 0 on every agent restart - and the pre-network-arm window it counts recurs on "
     "every boot regardless. MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_disarm_deadline_elapsed", "yuzu_fleet_guardian_disarm_deadline_elapsed",
     "Fleet sum of Spark Disarm claims an agent observed pending longer than a fixed 30 s "
     "threshold (#5403), counted once per claim. Observation only: the runtime never "
     "releases, pops or force-cancels a pending Disarm, so a nonzero value means a Disarm was "
     "pending TOO LONG, not that its backend call is proven hung. A pending Disarm holds its "
     "key; while its backend call is admitted and running it also holds an executor quota slot "
     "of its class and, if the call is blocked inside a mechanism, that mechanism type's engine "
     "lock (a Disarm retained after an admission refusal holds only its key). Recovery from a "
     "call that never returns is an agent restart, or --spark-disable (which takes effect at "
     "boot: restart the agent with the flag); a restart clears the stuck call, not "
     "necessarily its cause. NOT covered: a compensating disarm (see "
     "yuzu_fleet_guardian_compensation_deadline_elapsed), the direct disarm fallback outside a "
     "compensation, the agent's synchronous teardown fallback in its detach path, and "
     "inline-type teardown. A hang in that synchronous fallback also stalls the heartbeat "
     "thread's reads, so the agent goes stale and drops out of these gauges, which then read "
     "absent, the same as healthy. Cumulative per agent process (resets on restart); the exported "
     "fleet sum is rebuilt every sweep. See "
     "yuzu_fleet_guardian_disarm_pending_age_seconds_max for the "
     "age of what is pending now. MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_compensation_deadline_elapsed",
     "yuzu_fleet_guardian_compensation_deadline_elapsed",
     "Fleet sum of compensating teardowns an agent observed outstanding past the claim's own "
     "compensation deadline (#4472; 5 s after the compensation became owed, fixed in production and "
     "changed only by tests; the pending-Disarm threshold, by contrast, is a fixed 30 s from "
     "claim creation), counted once per claim. The count is observed at the next heartbeat "
     "maintenance pass (about 30 s, only while prefer_spark is on), so it can lag the 5 s "
     "deadline by up to a heartbeat, and the age gauge can read well above 5 s before the count "
     "first fires. A compensating teardown is the "
     "disarm of a live subscription from an arm that nobody adopted: the rule was withdrawn or "
     "superseded while its arm was in flight and the arm still succeeded, or the commit threw. "
     "A young compensation age on a healthy agent is therefore normal. Observation "
     "only: nothing is released, popped or cancelled, so a nonzero value means a teardown was "
     "pending TOO LONG, not that its backend call is proven hung. While it is outstanding the "
     "claim stays its key's head (the key stays held; an asynchronous compensating disarm also "
     "holds an executor quota slot of its class only while its backend call runs, and the "
     "direct fallback holds no quota; if the call is blocked inside a mechanism, that mechanism "
     "type's engine lock stays held) and its "
     "generation is held, not acknowledged: the server re-pushes at a minimum interval of "
     "about 25 s (typically once per ~30 s heartbeat), each push writes a "
     "guaranteed_state.reconcile audit row, and the former bound on that hold (roughly 75 to "
     "90 s, an estimate) no longer applies. Covers the asynchronous compensating disarm and "
     "the direct disarm fallback inside a compensation. A claim compensated a second time "
     "reports its age from its FIRST owed instant, so this count can fire immediately or never "
     "for the second compensation (accepted). Cumulative per agent process (resets "
     "on restart). See yuzu_fleet_guardian_compensation_pending_age_seconds_max for the age of "
     "what is outstanding now. MONITOR-ONLY, same posture as the rest of this family"},
    // ---- #5404: the Spark claim-lifecycle counters (gate rows P1/P2) ----
    // All steady-state 0, sparse (0 omits the tag), summed fleet-wide, MONITOR-ONLY with no
    // alert rule shipped. Cumulative per agent process (resets on restart) except
    // retained_tombstones, a current count. Each HELP says what a nonzero value means and
    // that it means "inspect", not that a fault is proven.
    {"yuzu.guardian_orphan_disarms_started", "yuzu_fleet_guardian_orphan_disarms_started",
     "Fleet sum of Spark Disarm claims an agent's expiry reaper queued for an orphan key (#5404). "
     "Steady state 0. A nonzero value means a release took the last rule off a subscription "
     "key without a teardown being queued (the key's reference count reached zero unnoticed) "
     "and the reaper recovered it by queuing one. The backend disarm itself runs afterwards and off-lock; this "
     "counter does not say it completed (see yuzu_fleet_guardian_disarm_pending_age_seconds_max "
     "and yuzu_fleet_guardian_disarm_deadline_elapsed). Cumulative per agent process (resets on "
     "restart); the exported fleet sum is rebuilt every sweep. MONITOR-ONLY, same posture as the "
     "rest of this family"},
    {"yuzu.guardian_dead_watchers_erased_on_lost",
     "yuzu_fleet_guardian_dead_watchers_erased_on_lost",
     "Fleet sum of dead Spark watcher entries erased when the engine reported a subscription "
     "lost for a key that no rule uses (#5404): the orphan was erased instead of being left for "
     "the next same-key attach to join. Steady state 0. A nonzero value means an orphaned "
     "watcher existed, which is itself the symptom to inspect (compare "
     "yuzu_fleet_guardian_orphan_disarms_started). Cumulative per agent process (resets on "
     "restart). MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_tombstones_released_by_reaper",
     "yuzu_fleet_guardian_tombstones_released_by_reaper",
     "Fleet sum of retained tombstones (a retained tombstone is a dead, never-started Arm "
     "claim that still holds its rule-to-key index entry because its release failed) that the "
     "expiry reaper released and popped (#5404). Steady state 0, and DEFENCE-IN-DEPTH "
     "CONTAINMENT: the index release cannot fail in production (its calls are noexcept; only a "
     "test seam can make it throw), so this is expected to stay 0 permanently and is not "
     "detection evidence. A nonzero value would record a release that failed earlier and was "
     "recovered later; the outstanding ones are yuzu_fleet_guardian_retained_tombstones. "
     "Cumulative per agent process (resets on restart). MONITOR-ONLY, same posture as the rest "
     "of this family"},
    {"yuzu.guardian_claim_index_release_failures",
     "yuzu_fleet_guardian_claim_index_release_failures",
     "Fleet sum of Spark claim index releases that threw and were contained (#5404). It counts "
     "release ATTEMPTS, not claims: a claim whose release keeps failing is counted once per "
     "attempt, and the claim keeps its index ownership for the next release to retry. Steady "
     "state 0, and DEFENCE-IN-DEPTH CONTAINMENT: the release calls only noexcept index "
     "operations, so its try/catch can be exercised only by a test seam and this is expected "
     "to stay 0 permanently in production (it is not detection evidence). A nonzero value "
     "would mean a release failed; see yuzu_fleet_guardian_retained_tombstones for any mapping "
     "still held. Cumulative per agent process (resets on restart). MONITOR-ONLY, same "
     "posture as the rest of this family"},
    {"yuzu.guardian_claim_drain_failures", "yuzu_fleet_guardian_claim_drain_failures",
     "Fleet sum of Spark claim bookkeeping steps that threw and were contained (#5404). It "
     "counts contained throws, not claims, and does not by itself say what became of the "
     "affected claim. Steady state 0. A nonzero value means inspect the agent log. Cumulative per agent process (resets on restart). "
     "MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_retained_tombstones", "yuzu_fleet_guardian_retained_tombstones",
     "Fleet sum of retained tombstones (#5404): dead, never-started Arm claims that still hold "
     "their rule-to-key index entry because the release that should have freed it failed. A "
     "CURRENT count (not cumulative); an agent reports it only while it is nonzero, and it "
     "falls when the expiry reaper or the next sweep releases the claim. Steady state 0, and "
     "DEFENCE-IN-DEPTH CONTAINMENT: the release cannot fail in production (see "
     "yuzu_fleet_guardian_claim_index_release_failures), so this is expected to stay 0 "
     "permanently and is not detection evidence. Computed by an O(claims) scan once per "
     "heartbeat. MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_detach_sweep_left_residue", "yuzu_fleet_guardian_detach_sweep_left_residue",
     "Fleet sum of Spark detaches whose last-on-key sweep left the key's claim queue non-empty "
     "(#5404), so the new Disarm claim was not pushed and the real disarm ran through the "
     "synchronous last-resort fallback instead (the same detach also counts in "
     "yuzu_fleet_guardian_detach_claim_failures). That fallback is an accepted, counted "
     "outcome, not a proven fault: it runs the backend disarm while holding the runtime's "
     "registry lock, which the pending-Disarm age and deadline gauges do not see. Steady state "
     "0 outside a failing index release. Cumulative per agent process (resets on restart). "
     "MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_detach_claim_failures", "yuzu_fleet_guardian_detach_claim_failures",
     "Fleet sum of Spark detaches that could not hand the subscription to a Disarm claim and "
     "took the counted rollback or last resort (#5404): a throw inside the index release after "
     "the claim was pushed, or the cannot-happen prediction mismatch. The residue fallback "
     "(yuzu_fleet_guardian_detach_sweep_left_residue) increments both. Steady state 0. "
     "Cumulative per agent process (resets on restart). MONITOR-ONLY, same posture as the rest "
     "of this family"},
    {"yuzu.guardian_detach_post_commit_failures",
     "yuzu_fleet_guardian_detach_post_commit_failures",
     "Fleet sum of post-mutation steps of a Spark detach that threw and were contained (#5404): "
     "the non-durable outbox drop, or the synchronous backend disarm of an inline-type "
     "mechanism, whose swallowed throw can leave that engine subscription live and unowned. A "
     "nonzero value means INSPECT: it does not mean teardown completed. Steady state 0. "
     "Cumulative per agent process (resets on restart). MONITOR-ONLY, same posture as the rest "
     "of this family"},
    {"yuzu.guardian_claims_dropped_at_stop", "yuzu_fleet_guardian_claims_dropped_at_stop",
     "Fleet sum of Spark claims dropped at agent shutdown (#5404): queued, never-dispatched "
     "claims dropped by the runtime's stop, plus Disarm claims its executor refused with "
     "Stopped. Counts shutdown drops only: it increments only while the agent is shutting down "
     "and resets on restart, so it is rarely observable on the fleet and is not detection "
     "evidence. Not an outage signal on its own. MONITOR-ONLY, same posture as the rest of "
     "this family"},
    {"yuzu.guardian_ack_maint_exceptions", "yuzu_fleet_guardian_ack_maint_exceptions",
     "Fleet sum of throws caught by the agent's Guardian ack-bookkeeping maintenance firewall "
     "(#5404): the heartbeat thread's ack-drain and generation-advance tick (which includes the "
     "runtime's expiry and reaper pass; this source is live only while prefer_spark is on), and "
     "the content-hash and begin-application steps of applying a push (not gated on "
     "prefer_spark). Steady state 0. A caught throw skips the rest of that tick's ack drain, "
     "and one that recurs every tick repeats the skip. Cumulative per agent process "
     "(resets on restart). MONITOR-ONLY, same posture as the rest of this family"},
};

/// Derived with std::size, never a literal - see the sibling table's comment in
/// guardian_journal_fleet_tags.hpp for why a hardcoded count is a governance finding
/// waiting to happen.
inline constexpr std::size_t kNGuardianHealthMetrics = std::size(kGuardianHealthMetrics);

/// #5403, #4472: the AGE family - a SEPARATE, MAX-rollup table, same reasoning as
/// kGuardianJournalAgeMetrics (guardian_journal_fleet_tags.hpp). Not rows of the table above:
/// that one is pinned 1:1 to GuardianHealthStats (all uint64 cumulative counters, SUM), and an
/// age is not a counter - a fleet SUM of ages is meaningless, the question is "how long has
/// the WORST endpoint's Disarm (or compensating teardown) been pending". The op (MAX) lives in
/// the consumer, agent_registry.cpp, because the row struct has no op field. Name rule,
/// asserted by the pin test: gauge == "yuzu_fleet_" + tag minus its "yuzu." prefix + "_max".
/// The table is pinned 1:1 to the agent's GuardianHealthAgeStats (a sizeof static_assert in the
/// pin test), mirroring the journal sibling's GuardianJournalAgeStats pin.
///
/// EMISSION (writer: emit_guardian_health_age_tags over GuardianHealthAgeStats): each tag is ABSENT while the agent has none
/// pending and present, INCLUDING 0, while one is (0 = pending for less than one second). So
/// here, absent family = no retained agent reports one pending; a published 0 = at least one is
/// pending but young. The fleet gauge is NEVER a fabricated 0 for "none".
///
/// COVERAGE: not counted in yuzu_fleet_guardian_health_reporting (that meta's documented
/// meaning is the counter family), and no separate reporting meta ships for it. A value the
/// parse rejects IS counted in yuzu_fleet_guardian_health_tag_rejected. ATTRIBUTION (same
/// #2083-class caveat as the journal age family, and worse under MAX): one agent reporting a
/// plausible but wrong value below the 1e9 ceiling owns the fleet MAX, and no per-agent axis
/// exists to say which endpoint it is - find the endpoint first (query heartbeat tags).
/// No alert rule ships with this gauge; one needs fleet data to tune.
inline constexpr GuardianHealthMetric kGuardianHealthAgeMetrics[] = {
    {"yuzu.guardian_disarm_pending_age_seconds",
     "yuzu_fleet_guardian_disarm_pending_age_seconds_max",
     "Fleet MAX (worst endpoint) of the age in seconds of the oldest Spark Disarm claim still "
     "pending on an agent (#5403), floored to whole seconds. ABSENT means no retained agent "
     "reports a pending Disarm; it is never 0 for \"none\" (a published 0 means a Disarm is "
     "pending for under a second). A large value means a Disarm has been pending TOO LONG - "
     "it is not proof the backend call is hung, and nothing is released, popped or "
     "cancelled while it ages. While pending it holds its key; while its backend call is "
     "admitted and running it also holds an executor quota slot of its class and, if the call "
     "is blocked inside a mechanism, that mechanism type's engine lock (a Disarm retained after "
     "an admission refusal holds only its key, and the age includes such a retained Disarm). "
     "Recovery from a call that never returns is an agent restart, or --spark-disable (which "
     "takes effect at boot: restart the agent with the flag); a restart clears the stuck call, "
     "not necessarily its cause. NOT "
     "covered: a compensating disarm (see "
     "yuzu_fleet_guardian_compensation_pending_age_seconds_max), the direct disarm fallback "
     "outside a compensation, the agent's synchronous teardown fallback in its detach path, "
     "and inline-type teardown. A hang in that synchronous fallback also stalls the heartbeat "
     "thread's reads, so the agent goes stale and leaves the MAX: the gauge then reads ABSENT, "
     "indistinguishable from healthy. Re-statable gauge: it "
     "falls when the Disarm completes. A stale-evicted agent leaves the MAX, and a value that "
     "disappears cannot say whether the agent recovered, was evicted, or never held one. See "
     "yuzu_fleet_guardian_disarm_deadline_elapsed for the cumulative count of Disarms seen "
     "pending past 30 s. MONITOR-ONLY: no alert rule ships with it"},
    {"yuzu.guardian_compensation_pending_age_seconds",
     "yuzu_fleet_guardian_compensation_pending_age_seconds_max",
     "Fleet MAX (worst endpoint) of the age in seconds of the oldest compensating teardown "
     "still outstanding on an agent (#4472), floored to whole seconds and measured from the "
     "instant the compensation became owed (an arm result that nobody adopted: the rule was "
     "withdrawn or superseded while its arm was in flight and the arm still succeeded, or the "
     "commit threw; a young age on a healthy agent is normal), not from the original arm. "
     "ABSENT means no retained agent reports one outstanding; "
     "it is never 0 for \"none\" (a published 0 means one is outstanding for under a "
     "second). A large value means a teardown has been pending TOO LONG - it is not proof the "
     "backend call is hung, and nothing is released, popped or cancelled while it ages. While "
     "outstanding the claim stays its key's head (the key stays held; an asynchronous "
     "compensating disarm also holds an executor quota slot of its class only while its backend "
     "call runs, and the direct fallback holds no quota; if the call is blocked inside a "
     "mechanism, that mechanism type's engine lock stays held), and its generation is held, "
     "not acknowledged, so the server keeps re-pushing "
     "until the teardown finishes (a minimum interval of about 25 s, typically once per ~30 s "
     "heartbeat; each push writes a guaranteed_state.reconcile audit row; the former bound on "
     "that hold, roughly 75 to 90 s (an estimate), no longer applies). A claim compensated a second time reports its "
     "age from its FIRST owed instant (accepted). "
     "Covers the asynchronous compensating disarm and the direct "
     "disarm fallback inside a compensation; NOT covered: a plain Disarm claim (see "
     "yuzu_fleet_guardian_disarm_pending_age_seconds_max), the agent's synchronous teardown "
     "fallback in its detach path (a hang there also stalls the heartbeat thread's reads, so "
     "the agent goes stale and the gauge reads ABSENT, indistinguishable from healthy), and "
     "inline-type teardown. Re-statable gauge: it falls when "
     "the teardown finishes. A stale-evicted agent leaves the MAX, and a value that "
     "disappears cannot say whether the agent recovered, was evicted, or never held one. See "
     "yuzu_fleet_guardian_compensation_deadline_elapsed for the cumulative count. "
     "MONITOR-ONLY: no alert rule ships with it"},
};

inline constexpr std::size_t kNGuardianHealthAgeMetrics = std::size(kGuardianHealthAgeMetrics);

// Meta-signals: about the ROLLUP, not part of the row table above. Same rationale as
// the guardian-journal pair - published on EVERY sweep including at 0, because they
// are server-owned counts that always have a true value, so a 0 is a measurement, not
// a fabrication.
//
// READ 0 CAREFULLY, same caveat as the journal reporting gauge: because the writer is
// SPARSE (a 0 counter emits no tag), `reporting` counts agents with at least one
// NON-ZERO health counter, not agents whose Guardian health pipeline is working. A live
// fleet with nothing currently errored/refreshed/demoted reads 0 legitimately.

/// Agents whose latest heartbeat carried at least one parseable
/// yuzu.guardian_unhealthy_*/guardian_priority_demoted/guardian_outbox_backpressure_drops/
/// guardian_legacy_sink_events_lost/guardian_legacy_sink_gap_rules/
/// guardian_legacy_sink_dropped_unwired/guardian_disarm_deadline_elapsed/
/// guardian_compensation_deadline_elapsed tag or any of the #5404 Spark claim-lifecycle tags
/// (the #5403 and #4472 pending-age tags do not count here; see kGuardianHealthAgeMetrics).
inline constexpr const char* kGuardianHealthReportingGauge = "yuzu_fleet_guardian_health_reporting";
inline constexpr const char* kGuardianHealthReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_unhealthy_suppressed/refreshed, yuzu.guardian_priority_demoted, "
    "yuzu.guardian_outbox_backpressure_drops, yuzu.guardian_legacy_sink_events_lost, "
    "yuzu.guardian_legacy_sink_gap_rules, yuzu.guardian_legacy_sink_dropped_unwired "
    "(#4783), yuzu.guardian_disarm_deadline_elapsed (#5403), "
    "yuzu.guardian_compensation_deadline_elapsed (#4472), or any #5404 Spark "
    "claim-lifecycle tag in this table (yuzu.guardian_orphan_disarms_started through "
    "yuzu.guardian_ack_maint_exceptions) (the "
    "yuzu.guardian_disarm_pending_age_seconds and "
    "yuzu.guardian_compensation_pending_age_seconds age tags do not count here) - the "
    "coverage denominator for this "
    "family. Published every sweep INCLUDING 0, unlike the counters above. READ 0 "
    "CAREFULLY: because the writer is SPARSE (a 0 counter emits no tag), this counts "
    "agents with at least one NON-ZERO counter, not agents whose Guardian health "
    "pipeline is working - a live fleet with nothing currently errored/refreshed/"
    "demoted/backpressured reads 0 legitimately";

/// Health tags that were PRESENT on a heartbeat but failed the forged-value parse.
inline constexpr const char* kGuardianHealthTagRejectedGauge =
    "yuzu_fleet_guardian_health_tag_rejected";
inline constexpr const char* kGuardianHealthTagRejectedHelp =
    "Guardian health tags PRESENT on a heartbeat this sweep but rejected by the "
    "forged-value parse (non-numeric, negative, over 10 digits, or above the "
    "plausibility ceiling), including the #5403 pending-Disarm and #4472 compensation age tags. "
    "An EMPTY value is skipped before the parse and is NOT counted here (the agent never writes "
    "one, so it can only come from a hand-forged heartbeat). Published every "
    "sweep INCLUDING 0. Without it a rejected "
    "value is a SILENT drop: if the rejected agent were the only reporter, its family "
    "goes absent and absent reads as clean. > 0 means some agent is shipping malformed "
    "Guardian health telemetry - investigate that agent, and re-check the ceiling "
    "before raising it";

/// Max digits accepted before the value is rejected unread. Checked FIRST in the parse
/// so an implausible token is refused in O(1) without being scanned - runs under
/// AgentHealthStore::mu_, the same lock heartbeat ingest and every dashboard/REST fleet
/// read take, once per table row per agent per sweep (the tables, not this comment, say
/// how many rows).
inline constexpr std::size_t kMaxHealthTokenDigits = 10;

namespace detail_pow10_health {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_pow10_health

// Bind the digit gate to the plausibility ceiling in BOTH directions - same rationale
// as the journal family's identical assert.
static_assert(kMaxPlausibleGuardianHealthCount <
                  detail_pow10_health::pow10(kMaxHealthTokenDigits),
              "kMaxPlausibleGuardianHealthCount no longer fits in kMaxHealthTokenDigits "
              "digits - the length gate in parse_guardian_health_count would reject "
              "legitimate values before the ceiling ever applies. Adjust both together.");

/// Forged-value-safe parse of an agent-supplied Guardian health tag value. Full-token,
/// non-negative integer parse only; empty / garbage / signed / overflow / implausible
/// -> nullopt, which the caller MUST treat as "did not report", never as 0.
inline std::optional<double> parse_guardian_health_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxHealthTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianHealthCount)
        return std::nullopt; // implausible -> "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
