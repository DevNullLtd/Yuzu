#pragma once

/// @file guardian_journal_fleet_tags.hpp
/// Reader side of the Guardian durable lifecycle-audit journal's fleet telemetry
/// (#2298 gate 3). Single source of truth for the `yuzu.guardian_journal_*` heartbeat
/// tag keys, the `yuzu_fleet_guardian_journal_*` gauge names they roll up into, their
/// HELP text, and the forged-value-safe parse of the agent-supplied values.
///
/// The writer is agents/core/src/guardian_journal_heartbeat.hpp - the sparse counter
/// emitter (`emit_guardian_journal_heartbeat_tags`) for the 32-row table, and the age
/// emitter (`emit_guardian_journal_age_tags`) for the MAX table further down. Both
/// sides are bound by tests/unit/server/test_guardian_journal_fleet_tags.cpp, which
/// emits through the agent's REAL emitters and asserts every key produced is one a
/// table here recognises. That test is the drift guard: a rename on either side
/// without the other is a red test, not a silently-dead gauge.
///
/// The keys are duplicated here rather than `#include`d from the agent header ON
/// PURPOSE. Server production code including an agent private header would add an
/// upward server -> agent dependency edge that the build graph does not have and must
/// not gain (the constraint is recorded verbatim in tests/meson.build, governance
/// Gate-3 architect, on the sibling spark pin). Only the TEST target carries the
/// agent include path, which is exactly where the bind belongs.
///
/// ── SHAPE: FLAT AND UNLABELLED ───────────────────────────────────────────────────
/// One gauge per counter, NO labels - deliberately not the `{stat,os}` distribution
/// shape `yuzu_fleet_net_*` / `yuzu_fleet_perf_*` use (design item 9,
/// "unlabeled/low-cardinality"). These are integrity and loss signals, not
/// distributions: the fleet question is "did ANY endpoint lose a lifecycle record",
/// which a sum answers and a percentile obscures. 32 counter families, 32 series (plus
/// the 2 always-published meta gauges described below), no
/// agent-controlled label anywhere - so no cardinality exposure at all (contrast the
/// `os`-labelled families, which need an allowlist).
///
/// ── WHAT ABSENCE MEANS, MECHANICALLY ─────────────────────────────────────────────
/// This section states the emission MECHANICS only. It deliberately does not tell the
/// reader what a value or an absence PROVES about fleet health - six review rounds of
/// this file each produced exactly one wrong interpretive claim, so the interpretation
/// now belongs to whoever enables these at the cutover, with a live journal to test
/// readings against.
///
/// The writer is SPARSE: a counter that is 0 ships no tag.
/// `AgentHealthStore::recompute_metrics` `clear_gauge_family()`s all 32 (and the age
/// family's 3, same rule) at the top of every sweep and re-publishes only those at
/// least one retained agent reported this cycle. So an absent family means: no retained agent's latest heartbeat carried a
/// value for it that PASSED the forged-value parse. Note both edges, each pinned by a
/// test in tests/unit/server/test_agent_health_store.cpp: a non-conforming agent's
/// explicit "0" parses and PUBLISHES the family at 0, and a rejected non-zero value
/// (over the ceiling, say) leaves it ABSENT while incrementing `..._tag_rejected`.
///
/// The two META-SIGNALS below are NOT in the table and are published on every completed
/// sweep INCLUDING at 0, so they are never absent once a sweep has completed. That is
/// their point (a 0 from a server-owned count is a measurement, not a fabricated zero)
/// and also their limit: because they are never cleared, `MetricsRegistry` retains the
/// last value indefinitely, so NEITHER `absent(..._reporting)` NOR `..._reporting == 0`
/// detects a STALLED sweep - a stall freezes the previous sample in place. Use
/// `yuzu_server_reaper_sweep_duration_seconds` for sweep liveness. An earlier revision
/// of this header claimed `absent()` covered a stall; it does not, and the comment at
/// the publish site in agent_registry.cpp ("never goes stale") is exactly why.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Max accepted value of any journal tag. Above it the value is treated as "did not
/// report", NOT clamped-and-counted.
///
/// Every honest value is far below this. The two size gauges are bounded by the
/// journal's own hard ceilings (64 MiB of bytes, 2000 batches - `hard_max_bytes_` /
/// `hard_max_batches_`); the rest count staging rejections, batch writes, prunes and
/// replay pages on ONE endpoint over its uptime.
///
/// Rejecting rather than clamping matters more than it looks: these gauges are a
/// fleet SUM accumulated into a `double`, so a single agent reporting near-UINT64_MAX
/// (~1.8e19) does not merely dominate the sum, it makes every honest agent's
/// contribution a NO-OP - 1.8e19 + 1 == 1.8e19 in IEEE-754. One compromised or buggy
/// endpoint could otherwise permanently destroy the fleet integrity signal for every
/// operator. At 1e9 x 10k agents the sum is ~1e13, still exact in a double (< 2^53).
inline constexpr unsigned long long kMaxPlausibleGuardianJournalCount = 1'000'000'000ULL;

/// One journal telemetry signal: the agent's heartbeat tag key, the fleet gauge it
/// sums into, and the gauge's Prometheus HELP text.
///
/// Name rule, asserted by the pin test: `gauge` == "yuzu_fleet_" + `tag` with its
/// "yuzu." heartbeat-namespace prefix stripped. Mechanical in both directions, so an
/// operator reading an alert can derive the wire key and vice versa. Keeping the three
/// strings adjacent is what makes adding a signal a one-row change that cannot forget
/// the clear, the publish, or the HELP.
struct GuardianJournalMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// The full published set. Order matches GuardianJournalStats / the emit order in
/// agents/core/src/guardian_journal_heartbeat.hpp for reviewability; nothing depends
/// on it.
///
/// TYPE-HONESTY. All 32 are exported as `gauge` because that is what they are
/// server-side - a per-sweep recomputed fleet sum, cleared and rebuilt, never
/// monotonic: it drops when an agent ages out or restarts, and a family nobody reports
/// goes absent.
///
/// ALERTING: THESE ARE MONITOR-ONLY. No churn-robust new-increment alert exists over an
/// unlabelled fleet sum of per-agent cumulative counters. The full analysis - why
/// increase()/rate(), delta() and bare `> 0` each fail, what the rising-edge template
/// does and does not buy, and the enable-time prerequisites - is stated ONCE, in the
/// `yuzu-guardian-journal` preamble in docs/prometheus/yuzu-alerts.yml. It is
/// deliberately not restated here: it used to be, on four surfaces, and every fix had
/// to land four times.
///
/// ADR-1005 exception ledger, 2026-07-14 class-level entry: a `/metrics`-only fleet
/// gauge family is observability, not capability, so it carries no REST/MCP twin
/// obligation. Cited here so a future rollup does not relitigate it.
///
/// SCOPE OF WHAT THIS FILE ASSERTS: the mechanics stated above are the ones the pin
/// test and the store tests actually assert. Anything beyond them - what a reading
/// proves about fleet health - is deliberately not stated here.
inline constexpr GuardianJournalMetric kGuardianJournalMetrics[] = {
    // ── Staging loss channels (agent runtime, pre-persist) ───────────────────────
    {"yuzu.guardian_journal_stage_dropped", "yuzu_fleet_guardian_journal_stage_dropped",
     "Fleet sum of lifecycle records dropped at staging - the pending reserve overflowed "
     "under sustained write failure. A LOSS channel: these records never reached the "
     "journal. MONITOR-ONLY: no sound alert form exists "
     "over an unlabelled fleet sum of per-agent cumulative counters - increase() fakes "
     "increments on agent churn and misses a first report, and bare > 0 never clears at "
     "fleet scale. Graph it; do not page on it"},
    {"yuzu.guardian_journal_stage_failures", "yuzu_fleet_guardian_journal_stage_failures",
     "Fleet sum of disarm records that could not be built post-teardown. A LOSS channel: "
     "the lifecycle end of a rule is unrecorded. MONITOR-ONLY - see the alerting note on "
     "this family; neither increase() nor bare > 0 is sound over a fleet sum"},
    {"yuzu.guardian_journal_field_rejected", "yuzu_fleet_guardian_journal_field_rejected",
     "Fleet sum of records kept out of the journal by a field that failed validation "
     "(embedded NUL, oversized, or non-UTF-8). A LOSS channel, and a malformed-input "
     "signal - a sustained climb means something upstream is producing garbage"},
    {"yuzu.guardian_journal_clock_rejected", "yuzu_fleet_guardian_journal_clock_rejected",
     "Fleet sum of records kept out of the journal by a skewed clock (timestamp <= 0). A "
     "LOSS channel; also the fleet's clock-health canary, since a journal timestamp that "
     "cannot be trusted is not admissible evidence"},
    {"yuzu.guardian_journal_pending", "yuzu_fleet_guardian_journal_pending",
     "Fleet sum of records staged but not yet persisted. A LIVE DEPTH gauge per agent - "
     "it drains as the backlog clears - but what is PUBLISHED is the fleet SUM, which at "
     "10k agents is non-zero essentially always, so `> 0` fires permanently on a healthy "
     "fleet and is NOT a valid alert. MONITOR-ONLY like the rest of this family. "
     "Sustained depth is the leading indicator of the stage_dropped loss that follows "
     "when the reserve overflows"},
    // ── Persist ──────────────────────────────────────────────────────────────────
    {"yuzu.guardian_journal_batches_written", "yuzu_fleet_guardian_journal_batches_written",
     "Fleet sum of journal batches successfully persisted, in BATCHES of up to 256 "
     "records. A cumulative "
     "process-lifetime count: non-zero means that agent's journal has persisted at least "
     "one batch since it last restarted. It resets to 0 on agent restart, and a journal "
     "whose every write fails never sets it, so do not read it as liveness"},
    {"yuzu.guardian_journal_write_failures", "yuzu_fleet_guardian_journal_write_failures",
     "Fleet sum of failed journal batch writes. Records stay staged and retry, so this is "
     "not itself loss. Sustained failure fills the pending reserve, after which staging "
     "overflow increments stage_dropped. It leads stage_dropped on THAT path only: the "
     "loss channels field_rejected and clock_rejected move without it, and the "
     "capacity-refusal path can reach stage_dropped without a single write failure"},
    {"yuzu.guardian_journal_key_collisions", "yuzu_fleet_guardian_journal_key_collisions",
     "Fleet sum of journal batch key collisions. Should stay 0 in correct operation; any "
     "value is an accounting or id-generation bug surfacing, so investigate rather than "
     "threshold it"},
    // ── Retention / quarantine ───────────────────────────────────────────────────
    {"yuzu.guardian_journal_quarantined", "yuzu_fleet_guardian_journal_quarantined",
     "Fleet sum of journal batches moved aside as unreadable/corrupt. Degrade-don't-"
     "destroy: the batch is preserved for forensics but its records are NOT replayed, so "
     "> 0 means the server is missing lifecycle evidence that still exists on the "
     "endpoint. NOTE the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_quarantine_failures",
     "yuzu_fleet_guardian_journal_quarantine_failures",
     "Fleet sum of quarantine attempts that themselves failed. Strictly worse than "
     "quarantined: the corrupt batch could not even be set aside, so it may be re-hit "
     "every maintenance tick"},
    {"yuzu.guardian_journal_quarantine_capacity_evicted",
     "yuzu_fleet_guardian_journal_quarantine_capacity_evicted",
     "Fleet sum of quarantined batches shed because the quarantine area hit its cap "
     "(UP-7). Terminal loss - forensic evidence that had been preserved is now gone. NOTE "
     "the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_pruned", "yuzu_fleet_guardian_journal_pruned",
     "Fleet sum of journal batches deleted by retention, in BATCHES of up to 256 records "
     "(routine disposal evidence). Expected non-zero on a working fleet; read it as "
     "activity context for the failure counters beside it, not as an alert"},
    {"yuzu.guardian_journal_prune_failures", "yuzu_fleet_guardian_journal_prune_failures",
     "Fleet sum of retention prune failures. Retention not running means the journal "
     "grows toward its byte/count cap, where new writes start being refused - see "
     "write_capacity_rejected"},
    {"yuzu.guardian_journal_page_read_failures",
     "yuzu_fleet_guardian_journal_page_read_failures",
     "Fleet sum of REPLAY-side journal READ FAILURES - the candidate scan (at most once "
     "per pass) plus, since #2299, each per-candidate value read a pass attempts, so ONE "
     "pass can contribute several and this is not a pass-failure rate. Kept separate from "
     "prune_failures because the two fail independently and the pairing is what carries "
     "the meaning: retention succeeding while replay is stalled means records are being "
     "deleted on schedule and shipped never"},
    {"yuzu.guardian_journal_clock_jump_skips",
     "yuzu_fleet_guardian_journal_clock_jump_skips",
     "Fleet sum of retention passes that declined to age-evict because the endpoint's "
     "wall clock had moved further than the whole retention window. Not itself an error - "
     "the journal deliberately kept evidence it would otherwise have deleted - but it "
     "means an endpoint clock moved, and it is the differential diagnosis for a spike in "
     "evicted_no_send_evidence"},
    {"yuzu.guardian_journal_write_capacity_rejected",
     "yuzu_fleet_guardian_journal_write_capacity_rejected",
     "Fleet sum of new batches REFUSED because the journal is at its byte/count cap "
     "(UP-1). NOT itself loss: the refused batch stays staged and the maintenance tick "
     "retries it after a later prune frees capacity, so records are lost only if staging "
     "then overflows (see stage_dropped). Counts BATCHES, each up to 256 records"},
    {"yuzu.guardian_journal_gauge_underflow", "yuzu_fleet_guardian_journal_gauge_underflow",
     "Fleet sum of times an agent's write-ceiling check read the journal size gauge as "
     "NEGATIVE (UP-2 / #2303). Correct operation never underflows, so ANY non-zero here is "
     "a real size-accounting bug on that endpoint: persist then fails CLOSED (defers to RAM "
     "staging) until a prune rebase restores the gauge. It matters because the batch_count "
     "gauge CLAMPS a negative to 0 - the endpoint reads as a healthy EMPTY journal while it "
     "is actually refusing writes, so this is the only signal that de-camouflages that state. "
     "Investigate the endpoint; a sustained climb with stage_dropped means the underflow is "
     "now costing records"},
    {"yuzu.guardian_journal_bytes", "yuzu_fleet_guardian_journal_bytes",
     "Fleet sum of live on-disk journal size in bytes. A LIVE gauge, not cumulative. "
     "Capacity signal: per-endpoint it is bounded by the journal's own cap, so a fleet "
     "value climbing toward (agents x cap) predicts write_capacity_rejected"},
    {"yuzu.guardian_journal_batch_count", "yuzu_fleet_guardian_journal_batch_count",
     "Fleet sum of live journal batch count. A LIVE gauge, not cumulative. The count-cap "
     "twin of _bytes - either ceiling alone can start refusing writes"},
    // ── Replay (agent -> server delivery of journalled records) ───────────────────
    {"yuzu.guardian_journal_pages", "yuzu_fleet_guardian_journal_pages",
     "Fleet sum of replay paging passes (page_into_window). Activity, not health - it is "
     "the denominator that tells you replay is running at all"},
    {"yuzu.guardian_journal_records_paged", "yuzu_fleet_guardian_journal_records_paged",
     "Fleet sum of journalled records newly enqueued into the replay window. Activity "
     "signal for how much backlog is being re-delivered"},
    {"yuzu.guardian_journal_sent_labels", "yuzu_fleet_guardian_journal_sent_labels",
     "Fleet sum of sent-labels written, in BATCHES of up to 256 records (best-effort "
     "delivery evidence). NOT a "
     "valid denominator for the eviction counters despite the matching unit: labels are "
     "counted in the CURRENT agent process, while evictions cover batches written up to "
     "the 7-day retention window earlier across a churning fleet, so after a restart the "
     "eviction numerator can exceed it. Read it as activity, never as a rate base"},
    {"yuzu.guardian_journal_evicted_sent_unacked",
     "yuzu_fleet_guardian_journal_evicted_sent_unacked",
     "Fleet sum of batches aged out of the journal WITH a sent-label but no ack. "
     "MONITOR, do not page: their records were sent and are very likely stored "
     "server-side; the ack simply did not come back. Compare against its no-evidence "
     "sibling. NOTE the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_evicted_no_send_evidence",
     "yuzu_fleet_guardian_journal_evicted_no_send_evidence",
     "Fleet sum of batches aged out of the journal with NO sent-label - no evidence their "
     "records were ever transmitted. The INTEGRITY GAP counter (CC7.3-relevant evidence): "
     "> 0 suggests lifecycle audit records were lost between endpoint and server. Treat a "
     "rise as a TICKET TO INVESTIGATE, not an incident-register entry - classification is "
     "BEST-EFFORT (a crash between the send and the sent-label write counts a sent batch "
     "as no-evidence), so a mass reboot or OTA manufactures a large benign step. Do not "
     "escalate until agent-side corroboration or magnitude analysis rules out that "
     "crash-timing artifact class. MONITOR-ONLY - see the alerting note; neither "
     "increase() nor bare > 0 is sound over a fleet sum. NOTE the unit is BATCHES, each "
     "holding up to 256 records, so this UNDERSTATES the record count. Since #2299 also "
     "cross-check quarantined: corrupt-VALUE quarantine moved to the replay pass, so a "
     "corrupt batch the rotation never reaches before it ages out lands here rather than "
     "as quarantined - both are lost evidence, but this no longer separates 'never "
     "delivered' from 'never deliverable'"},
    {"yuzu.guardian_journal_evicted_unclassified",
     "yuzu_fleet_guardian_journal_evicted_unclassified",
     "Fleet sum of batches aged out of the journal whose sent/unsent disposition was "
     "PERMANENTLY UNKNOWN - the third, mutually-exclusive eviction outcome (item 3). Its "
     "point is accounting exactness: pruned == sent_unacked + no_send_evidence + "
     "unclassified every pass, which is what lets evicted_no_send_evidence be read as a "
     "trustworthy FLOOR on lost evidence rather than a value a mid-pass shutdown could "
     "silently shrink. NEITHER loss NOR success. Three causes: a stop landing mid-pass counts "
     "the unclassified remainder here (at most ONE such bump per process lifetime, since the "
     "stop latches); an UNREADABLE sent-label on the scan-failure fallback (paired with a "
     "same-pass prune_failures increment - a repeated climber, unlike the shutdown bump); and a "
     "throw mid-classification (bad_alloc), whose remainder lands here while the throw itself is "
     "separately counted as journal_maint_exceptions. MONITOR-ONLY - see the alerting note; "
     "neither increase() nor bare > 0 is sound over a fleet sum. NOTE the unit is BATCHES, each "
     "up to 256 records"},
    {"yuzu.guardian_drain_exceptions", "yuzu_fleet_guardian_drain_exceptions",
     "Fleet sum of firewalled throws in the outbox DELIVERY machinery. Distinct from the "
     "journal counters beside it: events are buffered but not shipping, which is a "
     "delivery fault, not a retention or audit-trail fault"},
    {"yuzu.guardian_send_exceptions", "yuzu_fleet_guardian_send_exceptions",
     "Fleet sum of per-entry drain SENDS that threw (UP-4). Finer-grained than "
     "drain_exceptions above: a single entry could not be serialized/sent, so the head is "
     "retained and that log's drain STOPS - a permanently-failing entry jams delivery for "
     "everything behind it, distinct from a stream-down retry. Spans the lifecycle log AND "
     "the general outbox"},
    {"yuzu.guardian_journal_backpressure_drops", "yuzu_fleet_guardian_journal_backpressure_drops",
     "Fleet sum of lifecycle-audit entries REJECTED at outbox enqueue because it was at "
     "capacity (UP-4). A LOSS channel: the arm/disarm itself still succeeds - the audit "
     "trail never blocks a real detection-capability change - but the record of it is "
     "dropped, so a non-zero value means the audit trail is missing lifecycle edges under "
     "sustained delivery backpressure"},
    {"yuzu.guardian_sweep_exceptions", "yuzu_fleet_guardian_sweep_exceptions",
     "Fleet sum of firewalled throws in the convergence SWEEP lanes. Drift DETECTION is "
     "degraded - the endpoint may miss policy violations - while the audit trail itself "
     "is unaffected. Deliberately not folded into the journal counters: different failure "
     "domain, different response"},
    {"yuzu.guardian_journal_maint_exceptions", "yuzu_fleet_guardian_journal_maint_exceptions",
     "Fleet sum of exceptions swallowed by the journal maintenance tick (page/flush). "
     "Swallowed on purpose so maintenance cannot kill the agent, which is exactly why "
     "they must be visible here - a climbing value means maintenance is failing silently "
     "and the counters beside it are understating reality"},
    {"yuzu.guardian_send_orphan_exceptions", "yuzu_fleet_guardian_send_orphan_exceptions",
     "Fleet sum of GuardianOutboxSendExecutor reclaims (either lane) whose orphaned "
     "worker's result was a thrown exception, discarded rather than attributed (#3953 "
     "item 1). MONITOR-ONLY - see the alerting note; the discard itself is correct "
     "(the orphaned result belongs to a superseded entry with nowhere correct to "
     "attribute it) - this is a diagnostic signal, not a loss channel"},
    {"yuzu.guardian_send_stalls", "yuzu_fleet_guardian_send_stalls",
     "Fleet sum of GuardianOutboxSendExecutor sends (either lane) that exceeded their "
     "stall threshold before completing or being reclaimed (#3953 item 2). MONITOR-ONLY "
     "- see the alerting note; a nonzero value means at least one endpoint's outbox "
     "delivery is running slow, not necessarily failing"},
};

/// Derived with std::size, never a literal and never sizeof-arithmetic: the sibling
/// spark table hardcoded its count, a new token was added, and it compiled clean while
/// being silently never read (prior governance finding). std::size also hard-rejects a
/// future refactor to a pointer, which the sizeof form would mis-size to 1.
inline constexpr std::size_t kNGuardianJournalMetrics = std::size(kGuardianJournalMetrics);

// ── AGE gauges: a SEPARATE, MAX-rollup family (flip item 6 + #2364 step-1) ────────
// Deliberately NOT rows in kGuardianJournalMetrics, for two independent reasons:
//  1. That table is pinned 1:1 to GuardianJournalStats (32 uint64 counters) by the
//     sizeof static_assert in its pin test; the ages live in their own agent struct
//     (GuardianJournalAgeStats) with its own pin.
//  2. The rollup op differs and the op lives IN THE CONSUMER, not the row (the row
//     struct has no op field - SUM is implicit in agent_registry.cpp's `+=` for the 32
//     above). These roll up as **MAX across agents**: a fleet SUM of ages is
//     meaningless, and the fleet question is "how stale is the WORST endpoint" /
//     "how old is the LONGEST-blocked episode anywhere" - a single stalled agent IS
//     the signal. The `_max` suffix on every gauge name keeps that visible to an
//     operator reading a graph.
//
// EMISSION differs from the 32 too (writer: emit_guardian_journal_age_tags): the two
// staleness ages ship on every heartbeat INCLUDING 0 while the drain worker is live -
// a zero age is a real "fresh" reading, and the whole point of item 6 is that a dead
// worker must not be indistinguishable from an idle one - and are ABSENT entirely
// while dormant (prefer_spark off). The blocked age stays sparse (0 = "no episode",
// absent-means-healthy). So server-side: absent family = nothing live reported;
// a published 0 = at least one live worker, all of them fresh.
//
// COVERAGE DENOMINATOR, considered and DECLINED (governance Gate 3 architect): ages
// deliberately do not count toward yuzu_fleet_guardian_journal_reporting (that meta's
// documented meaning is the counter family), and no separate ages-reporting meta ships
// with the monitor-only phase - partial coverage (5 live workers reporting fresh reads
// identically to 10,000) is a KNOWN gap. Post-flip, compare the family's presence
// against yuzu_fleet_agents_healthy for a coarse denominator; a real per-family
// coverage meta rides the per-agent operator surface work (#2083-class), not this
// table. Revisit at the flip (#2390) rather than relitigating here.
//
// ATTRIBUTION (same #2083-class caveat as the counter family, WORSE under MAX): a
// single agent shipping a plausible-but-wrong value below the 1e9 ceiling OWNS the
// fleet MAX outright - a sum dilutes a forgery, a max is captured by it - and no
// per-agent axis exists yet to identify which endpoint is reporting the extreme.
// Treat any surprising MAX as "find the endpoint first" (today: query agents'
// heartbeat tags directly), and do not raise the plausibility ceiling to accommodate
// an outlier.
//
// Name rule (asserted by the pin test): gauge == "yuzu_fleet_" + tag minus its
// "yuzu." prefix + "_max".
inline constexpr GuardianJournalMetric kGuardianJournalAgeMetrics[] = {
    {"yuzu.guardian_journal_page_stale_seconds",
     "yuzu_fleet_guardian_journal_page_stale_seconds_max",
     "Fleet MAX (worst endpoint) of seconds since the drain worker's last non-throwing "
     "replay PAGE pass, seeded from worker start. A LIVENESS gauge for the maintenance "
     "loop: a dead worker thread or a permanently-throwing pass grows without bound, "
     "which is what makes silent worker death visible at all (a dead worker's sparse "
     "counters just stay absent, indistinguishable from idle). Deferred or read-failed "
     "passes still stamp - those failure modes have their own counters. Expect it to "
     "hover around the 30 s page cadence on a healthy fleet; sustained multiples of "
     "that on some endpoint is the signal. Absent while the journal path is dormant "
     "(prefer_spark off) or no agent reports"},
    {"yuzu.guardian_journal_prune_stale_seconds",
     "yuzu_fleet_guardian_journal_prune_stale_seconds_max",
     "Fleet MAX (worst endpoint) of seconds since the drain worker's last non-throwing "
     "retention PRUNE pass - the prune sibling of page_stale_seconds, separate because "
     "the cadences differ (120 s prune vs 30 s page) and stall independently. A "
     "growing value means retention is not running on some endpoint: the journal grows "
     "toward its cap, where writes start being refused (write_capacity_rejected). "
     "Expect ~120 s on a healthy fleet. Absent while dormant or unreported"},
    {"yuzu.guardian_journal_headroom_blocked_seconds",
     "yuzu_fleet_guardian_journal_headroom_blocked_seconds_max",
     "Fleet MAX of the age in seconds of the oldest current headroom-blocked "
     "replay-congestion EPISODE (#2364): somewhere a journal batch could not be placed "
     "in the send window for lack of room, continuously since the value's start. "
     "Episode-scoped and sampled at pass granularity: it clears only after a proven "
     "block-free sweep of all of that journal's candidates, resets on agent restart, "
     "and a forced (reconnect/boot) pass can start an episode from already-delivered "
     "batches - so read it as replay-window congestion, not proof of unsent loss. Its "
     "loss-relevant threshold is the 7-day retention window (604800 s): an episode age "
     "approaching that means never-sent records on that endpoint are nearing deletion "
     "(see evicted_no_send_evidence). CAVEAT: a clear can COINCIDE with the blocked "
     "batch's own terminal eviction (the evicted batch stops being a candidate, so "
     "coverage completes) - corroborate any clear against evicted_no_send_evidence "
     "before reading it as recovery. Sparse: absent means no endpoint is blocked"},
};

inline constexpr std::size_t kNGuardianJournalAgeMetrics = std::size(kGuardianJournalAgeMetrics);

// ── Meta-signals: about the ROLLUP, not part of the 32-row table ──────────────
// Deliberately outside kGuardianJournalMetrics. That table is pinned 1:1 to
// GuardianJournalStats by a static_assert on the struct's size, so anything added to
// it that is not an agent counter breaks the pin. These two are computed server-side.
//
// Both are published on EVERY sweep including at 0 - the opposite of the 32, and
// deliberately so. The 32 are agent-population rollups where absent means "nobody
// reported"; these are server-owned counts that always have a true value, so a 0 is a
// measurement ("nothing is reporting") rather than a fabrication. Same split
// docs/observability-conventions.md draws between pre-seeded server-owned series and
// absent-not-zero agent rollups, and the same posture as yuzu_fleet_perf_reporting.

/// Agents whose latest heartbeat carried at least one parseable journal tag. The
/// coverage denominator the 32 lack: without it, 5 reporting agents and 10,000 produce
/// identical output and "absent = clean" is asserted at unknown coverage.
inline constexpr const char* kGuardianJournalReportingGauge =
    "yuzu_fleet_guardian_journal_reporting";
inline constexpr const char* kGuardianJournalReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_journal_* COUNTER tag (the 32-row family; the three *_seconds age "
    "tags deliberately do not count here) - the coverage denominator for the counter "
    "family. "
    "Published every sweep INCLUDING 0, unlike the 32 counters. READ 0 CAREFULLY: "
    "because the writer is SPARSE (a 0 counter emits no tag), this counts agents with "
    "at least one NON-ZERO counter, not agents whose journal pipeline is working. So 0 "
    "means EITHER the telemetry path is dark (pre-cutover, all aged out, reporting "
    "broke) OR nothing has been journalled anywhere since restart - a live journal on "
    "a fleet with no deployed Guardian rules reads 0 legitimately. It narrows the "
    "overloaded absence of the 32 counters; it does not resolve it";

/// Journal tags that were PRESENT on a heartbeat but failed the forged-value parse.
inline constexpr const char* kGuardianJournalTagRejectedGauge =
    "yuzu_fleet_guardian_journal_tag_rejected";
inline constexpr const char* kGuardianJournalTagRejectedHelp =
    "Journal tags PRESENT on a heartbeat this sweep but rejected by the forged-value "
    "parse (non-numeric, negative, over 10 digits, or above the plausibility ceiling). "
    "Published every sweep INCLUDING 0. Without it a rejected value is a SILENT drop: "
    "if the rejected agent were the only reporter, its family goes absent and absent "
    "reads as clean. > 0 means some agent is shipping malformed journal telemetry - "
    "investigate that agent, and re-check the ceiling before raising it";

/// Forged-value-safe parse of an agent-supplied journal tag value. Full-token,
/// non-negative integer parse only; empty / garbage / signed / overflow / implausible
/// -> nullopt, which the caller MUST treat as "did not report", never as 0.
///
/// The length cap is checked BEFORE from_chars so an implausible value is rejected in
/// O(1) without being scanned. kMaxPlausibleGuardianJournalCount is 10 digits, so any
/// longer token is implausible by construction. This matters because the parse runs
/// under AgentHealthStore::mu_ - the same lock heartbeat ingest and every
/// dashboard/REST fleet read take - 32 times per agent per ~15 s sweep. Without it, an
/// agent parking a multi-megabyte all-digit value in each tag gets it O(n)-scanned
/// inside that critical section forever.
///
/// The value BYTES still sit in the tag map until the store-level ingest bound lands
/// (AgentHealthStore::upsert deep-copies the whole agent-controlled tag map with no
/// key-count or value-length cap; tracked as the heartbeat-tag ingest-bound
/// follow-up). This cap keeps the scan out of the sweep, and is not a claim that the
/// ingest DoS is closed.
/// Max digits accepted before the value is rejected unread. Checked FIRST in the parse
/// so an implausible token is refused in O(1) without being scanned.
inline constexpr std::size_t kMaxJournalTokenDigits = 10;

namespace detail_pow10 {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_pow10

// Bind the digit gate to the plausibility ceiling in BOTH directions. Raising the
// ceiling past the gate would silently truncate legitimate values at the gate rather
// than at the documented ceiling; lowering the gate below the ceiling does the same
// thing from the other side. The one-directional version of this assert guarded only
// the first case (governance Gate-3 cpp-safety re-run).
static_assert(kMaxPlausibleGuardianJournalCount <
                  detail_pow10::pow10(kMaxJournalTokenDigits),
              "kMaxPlausibleGuardianJournalCount no longer fits in kMaxJournalTokenDigits "
              "digits - the length gate in parse_guardian_journal_count would reject "
              "legitimate values before the ceiling ever applies. Adjust both together.");

inline std::optional<double> parse_guardian_journal_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxJournalTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianJournalCount)
        return std::nullopt; // implausible -> "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
