#pragma once

// MCP progress bridge CORE (ADR-1005 Decision 15, track 2f PR 3a).
//
// The consumer-side projection of ExecutionEventBus events onto a session's MCP
// stream surfaces: per-request correlation records, the bus subscription, the
// latest-wins progress slot (#2412), one projector thread, and ring/final
// publication. The G1
// core/presentation split is structural - this header knows NOTHING of httplib,
// revalidation, or wire writes (those live in McpPostPump, PR 3b). In-memory,
// non-durable, no new store.
//
// BOTH modes are LIVE. execute_instruction picks between them per request: a
// `_meta.progressToken` alone arms kGetOnly (progress on the session's GET
// channel, 3a.7), and a progressToken WITH an SSE-capable Accept arms kStreaming
// and holds the POST response open as the progress channel (3b C8). Every seam
// this header once listed as deliberately dead - on_post_closed /
// park_after_dispatch_failure / request_cancel / ArmMode::kStreaming, and with
// them the kRingOnly lifecycle of parked finals and the pressure hatch - now has
// a production caller.
//
// ── Record lifecycle ────────────────────────────────────────────────────────
//
//   kArming ──arm(kStreaming)──────────▶ kStreaming ──on_post_closed()─▶ kRingOnly
//      │  ├──arm(kGetOnly | cancel-degrade)─▶ kArmedGetOnly                  ▲
//      │  │                                     │ (terminal projected)       │
//      │  └──park_after_dispatch_failure()──────┼───────────────────────────▶┤
//      │                                        │                            │
//      └──abandon()──▶ kAborted                 ▼                            ▼
//                                             kDone ◀────── sweep() ─────────┘
//
//   The two edges out of kArming on a FAILURE differ by whether dispatch happened:
//   abandon() is pre-dispatch (unsubscribe + discard; nothing is running), while
//   park_after_dispatch_failure() is post-dispatch (subscription and the progress
//   slot RETAINED, because the execution is running and its terminal is still owed).
//
//   kArming        reserved, pre-dispatch; the progress slot latches events, nothing projects.
//   kStreaming     POST pump owns projection (3b). In 3a nothing arms this in
//                  production; a test-driven kStreaming record latches until parked.
//   kArmedGetOnly  plain JSON already answered the POST. Progress goes LIVE on the
//                  GET stream (single stream - no broadcast); NO final frame, NO pin.
//   kRingOnly      parked: progress + the pinned final go to the ring only (resume
//                  replay; the MCP spec's MUST NOT broadcast). Subscription retained
//                  for the pinned terminal. Does NOT extend session life - nothing
//                  here touches last_seen; resume window = idle_ttl from the last
//                  CLIENT activity.
//   kAborted       pre-dispatch failure class (abandon); erased immediately.
//   kDone          terminal state; sweep unsubscribes and erases. It does NOT unpin
//                  a committed final - that pin outlives the record and is released
//                  by resume-consumption (pin-ack) or session death.
//
// Cancel: what it does depends on whether a response already exists, and the two
// halves are genuinely different mechanisms.
//
//   PRE-ARM (kArming, C1 arbitration): request_cancel() only records PENDING
//   intent - arm() and abandon() are the sole arbitrators, both under the record
//   mutex. arm() consuming the flag degrades streamed intent to kArmedGetOnly
//   (subscription retained, no pin, plain-JSON ack) and audits AFTER winning;
//   abandon() discards the pending flag silently (the request died pre-dispatch -
//   its error path is the truth). Here cancel is never a phase winner on its own.
//
//   LIVE STREAM (kStreaming, 3b): nothing is left to arbitrate, so the cancel
//   APPLIES immediately - it closes the bound post_sink and is audited at that
//   site. Exactly-once comes from the close TRANSITION, not from the phase: the
//   phase does not move until the pump's releaser parks the record, so a duplicate
//   cancel arrives while the record still looks cancellable and is rejected by the
//   sink's own false->true flip. See close_post_sink.
//
// NEITHER half touches the execution. Cancellation withdraws the client's interest
// in a RESPONSE; the dispatched command keeps running and its result stays
// fetchable by execution_id (Decision 15(j), chaos CH-12).
//
// Terminal durability (Decision 15(f)): a parked record's real final rides
// publish_final (pinned, resume-replayable). publish_final()==0 → retry once with
// the prebuilt fallback → still 0 → poison_terminal() + counter (the mcp_stream
// caller obligation). The sticky per-record `terminal_accepted` bit is the
// write-once discriminator: once a real terminal is secured, every later bus
// event for that record is dropped - the final is always last (D2).
//
// Pressure escape hatch (cap `ring_only_pressure_cap`, E1 two-stage): sweep picks
// the OLDEST parked record, sets pressure_requested (the projector claims no new
// progress batch for it), and - only once no progress projection is in flight -
// hands a callback to ExecutionEventBus::unsubscribe_and_visit_terminal. That is
// ONE atomic step under the channel mutex: ask the bus whether this execution ever
// reached a terminal, decide, and remove the listener - and the listener is removed
// ONLY if the callback commits a claim. There is no unsubscribe-then-re-check
// window for a terminal to land in; closing that window IS #2409 (C5), so do not
// re-split this into two steps.
//
// A DEFER advances to the next candidate; it does not end the pass (UP-5,
// #2489). The candidate list is built ONCE - a parked_seq-sorted scan taken at
// entry - and iterated ONCE, so the no-tight-re-visit property FA-4 wanted is
// carried structurally: there is no rescan to re-check it against, and no
// separate floor to maintain (Doomgoose, PR #2781 review - the prior shape
// rescanned the full record set, taking every record's own lock, once PER
// VICTIM visited). A pass-local `live` count (the entry ring_only population)
// is decremented only for a teardown THIS PASS itself commits, which is what
// lets the pass stop as soon as the cap is satisfied rather than visiting
// every candidate; a separate `visit_budget`, also captured at entry, bounds
// how many candidates get visited even if none of them settle - a record
// parking mid-pass gets a higher parked_seq and is simply not in the list, so
// a sustained park rate cannot keep one maintenance tick working without end.
// Hitting that budget with the cap still exceeded is counted, never silent
// (yuzu_mcp_bridge_pressure_budget_exhausted_total).
//
// The marks that pass leaves behind, and the budget-exhausted telemetry, are
// both decided by a SINGLE fresh rescan at the very end of the pass - not
// per-victim, and not from the entry-scan snapshot - so a record that parked
// in the gap between entry and now is neither undercounted nor has its
// quiesce mark wrongly cleared. Marks clear only when that fresh count is
// back under the cap (UP-4, #2489); a mark on a merely-deferred victim is
// still live work.
//
// Record state DOMINATES the bus verdict: a record that already holds a real final
// (accepted AND projected) is torn down with nothing published; one with a latched
// but unprojected terminal, or a projection in flight, DEFERS - keeping its
// listener. Only a record the bridge has never seen a terminal for lets the bus
// verdict decide, and the outcome is one of three dispositions:
//
//   kNone                   nothing published (a real final is already pinned, or
//                           this is a plain pin-ack / session-death reap).
//   kFallbackFinal          the bus says a terminal EXISTED but its payload has
//                           aged out of the replay buffer: publish the prebuilt
//                           SUCCESS-shaped final ("fetch it by execution_id").
//   kSynthesizeUnavailable  the bus says this execution never reached a terminal at
//                           all: pin a kMcpTerminalUnavailable (-32014) carrying the
//                           execution_id.
//
// -32014 is reachable ONLY from that last case. An aged-out terminal must NEVER
// become -32014 - the whole point of #2409 is that the bridge stops asserting "no
// result exists" when all it knows is "I no longer have the payload". A REAL pinned
// final is never destroyed and its pin survives the record (ack/session-death rules
// release it). Never evicts a newer record.
//
// Teardown ownership is THREE things - the records_ entry, the streamed charge, and
// the bus subscription. `torn_down` (set once, NEVER cleared) excludes the record
// from every ORDINARY sweep claim - but an incomplete teardown IS retried, from a
// later sweep tick, up to Config::teardown_retry_max times via the record's own
// `teardown_retry_claimable` flag (#2513); shutdown() remains the reclaimer of last
// resort, for a record whose retry budget is exhausted or that shutdown races before
// a retry pass gets to it. Each step is therefore contained separately and counted
// by yuzu_mcp_bridge_teardown_incomplete_total{reason} (#2487). The ORDER is
// load-bearing rather than uniform, so be precise about what each failure retains:
//
//   0. PUBLISH the decided terminal FIRST. A later step failing must never lose a
//      terminal the pressure visitor already decided on. Safe to do before the
//      unsubscribe because every publishing disposition comes from the pressure
//      pass, where unsubscribe_and_visit_terminal has already removed the listener;
//      every other caller passes kNone and publishes nothing.
//   1. unsubscribe fails -> return, record left in the map, still subscribed, still
//      charged. Erasing here would strand a live listener: it holds a shared_ptr to
//      the record, so the erase frees nothing, shutdown() can no longer find it, and
//      the bus channel can never be collected (GC needs listeners.empty()). The
//      terminal from step 0 is already committed, so this is "everything except the
//      publish".
//   2. charge fails -> return, record left in the map, its per-session admission
//      slot still held (#2513: erasing here made sense only when nothing could
//      retry - under retry the record is the only handle back to the leaked charge).
//   3. erase fails -> the subscription is settled and the charge MAY be (steps 2 and
//      3 fail independently); the record and one global slot leak.
//
// Every audit row on these paths is derived from what ACTUALLY happened - whether
// the ladder committed, and whether the charge released - never from what the branch
// intended. A row that overstates an outcome is worse than a missing one, and this
// function has produced that defect once per review round; check it explicitly when
// changing any branch here.
//
// Poison blast radius: poison_terminal() is session-wide - every future attach on
// that session 410s. Reached only on a double publish-failure (allocation death);
// counted, and the durable execution_id fetch remains the recovery path.
//
// ── LOCK HIERARCHY (acquire strictly left→right; releasing before acquiring a
//    lower tier is always allowed) ────────────────────────────────────────────
//
//   bridge_mu_ → ExecutionEventBus Channel::mu → BridgeRecord::mu
//              → McpStreamState::mu_ → SseSinkState::mu
//
//   WakeCore::mu             - wake-only LEAF. Taken (briefly, to flip
//       work_pending_/stop and notify) from under record mu at exactly ONE
//       call site - arm()'s flip handoff - and with NO record mu or
//       bridge_mu_ held at every other mark_dirty call site (#2411): the
//       listener's success and catch paths both call it after their
//       record-mu scope has already closed; park_after_dispatch_failure,
//       on_post_closed_keyed, take_post_batch's park-vs-claim fence, and
//       sweep's per-victim defer call it with nothing held; sweep's
//       pressure mark-clearing walk's own record-mu hold closes BEFORE its
//       mark_dirty call, so that site reaches WakeCore::mu under bridge_mu_
//       alone, not bridge_mu_ → record mu; and run_projector's per-record
//       catch (the projection-failure re-mark, #3331) calls it with nothing
//       held either - its bridge_mu_ scope has already closed before the
//       per-record loop, and project_record's own lock, if any, is released
//       by RAII unwind before the catch runs. NOTHING is ever acquired while
//       holding it.
//   McpSessionRegistry::mu_  - isolated leaf (stream_for/exists acquire nothing
//       beneath; the bridge never calls the registry while holding bridge_mu_).
//
//   Listeners (running under Channel::mu) touch record mu + WakeCore::mu ONLY -
//   never bridge_mu_, never a stream/sink lock, never the bus, never the metrics
//   registry (C5: drops/failures are record-local relaxed atomics flushed by the
//   projector). bridge_mu_ holders MAY call the bus (subscribe under bridge_mu_
//   serializes installation against teardown, A3; shutdown's unsubscribe walk) -
//   legal precisely because listeners never take bridge_mu_.
//
//   C5 (#2409) pressure visitor: the sweep calls unsubscribe_and_visit_terminal
//   WITHOUT holding bridge_mu_ (it re-validates map identity, releases bridge_mu_,
//   then calls the bus). The visit takes Channel::mu → record mu (a valid suffix);
//   its callback runs under Channel::mu and, like a listener, touches record mu +
//   WakeCore::mu ONLY - never bridge_mu_, never the bus (either would invert the
//   order). The streamed-charge decrement it would owe is deferred to the
//   post-visit teardown_claimed (under bridge_mu_), preserving exactly-once.

#include "execution_event_bus.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::detail {
struct SseSinkState;
}

namespace yuzu::server::mcp {

namespace sse_bus = ::yuzu::server::detail;

class McpStreamState;
class McpSessionRegistry;

class McpStreamBridge {
public:
    struct Config {
        /// Decision 15(d): global cap over ALL records, enforced at reserve().
        /// A dispatched record is NEVER evicted to make room (reject-not-evict).
        std::size_t global_record_cap = 256;
        /// Parked (kRingOnly) records tolerated before the pressure escape hatch
        /// force-expires the oldest (see the class comment).
        std::size_t ring_only_pressure_cap = 64;
        /// A kArming record is normally sub-millisecond (reserve→subscribe→arm
        /// all happen in ONE synchronous execute_instruction handler call). A
        /// record still kArming after this long is orphaned - its handler died
        /// between reserve and arm (the double-`bad_alloc` corner: arm's fallback
        /// build throws, then abandon()'s make_key ALSO throws under OOM), which
        /// sweep would otherwise never reclaim because it deliberately skips
        /// kArming (governance cpp-safety SHOULD). The threshold is generous -
        /// dispatch is a fire-and-forget fan-out (it does not wait for agents),
        /// so the reserve→arm window is milliseconds; 5 min is many orders of
        /// margin, so a live handler is never reaped.
        std::chrono::seconds arming_reap_after{300};
        /// A kStreaming record is owned by its POST pump and normally leaves that
        /// phase when the pump's releaser runs. Past this age it is treated as
        /// stranded and PARKED (never reaped) by the sweep backstop. Deliberately
        /// far above the streamed-POST cap so a healthy long stream is never
        /// parked out from under its own pump - this fires only when a close was
        /// swallowed or never delivered.
        std::chrono::seconds streaming_park_after{600};
        /// #2513: retries a sweep gives a teardown whose contained steps did not
        /// all complete, beyond the first attempt (so `teardown_retry_max = 3`
        /// means 4 total attempts). Each retry runs on a LATER sweep tick (real
        /// spacing - never the same tick that failed), so a fault surviving every
        /// attempt has had multiple ticks to self-heal and is effectively
        /// permanent; retrying it forever would re-run the same audit/log/metric
        /// work every tick for a record that is never coming back. `0` restores
        /// the pre-#2513 one-way RETENTION posture (still retained until
        /// shutdown, never retried) - it does NOT restore pre-#2513
        /// observability: the first bail still fires `teardown_retry_total{
        /// outcome="exhausted"}`, the exhaustion error log, and the "(retry
        /// budget exhausted...)" audit suffix, all of which are new. A
        /// code-constant default only, deliberately not exposed as a CLI
        /// flag/env var: this is a fault-recovery bound, not an operator dial.
        std::size_t teardown_retry_max = 3;
    };

    /// Injectable steady clock for the kArming reaper (deterministic tests).
    /// Defaults to steady_clock::now(); only the DIFFERENCE between calls matters.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// Outcome of an audited bridge action. A CLOSED set rather than a string,
    /// so the core carries no audit-store vocabulary and the sink maps it (a raw
    /// `const char*` here would also be a nullptr hazard at the sink's
    /// `std::string` assignment).
    enum class AuditResult { kSuccess, kFailure };

    /// httplib-free audit sink (G1): (action, execution_id, detail, result). Wired
    /// by 3a.7; empty = no audit. Every invocation is exception-contained (C5) -
    /// a throwing sink can never abort a sweep or corrupt accounting.
    ///
    /// `result` exists because the sink used to stamp EVERY bridge row "success",
    /// including rows whose detail says the teardown did not complete or that
    /// nothing was published (#2487 review). An audit row is a compliance artifact;
    /// it must not assert an outcome that did not happen.
    /// `actor` is the principal whose action produced the row, or EMPTY for the
    /// bridge's own background work (sweeps, the projector), which the sink stamps
    /// as "system". That distinction is the whole point: this range added rows
    /// driven directly by an authenticated client (a streamed cancel, a
    /// post-dispatch park), and auditing those as "system" makes them
    /// indistinguishable from internal housekeeping - an investigator could not tell
    /// WHICH client cancelled a live response, which is precisely the
    /// non-repudiation Decision 15(j) and chaos CH-12 require.
    using AuditFn = std::function<void(const std::string& action, const std::string& execution_id,
                                       const std::string& detail, AuditResult result,
                                       const std::string& actor)>;

    /// Phases - see the lifecycle diagram above.
    enum class Phase : int { kArming, kStreaming, kArmedGetOnly, kRingOnly, kDone, kAborted };

    enum class ArmMode { kGetOnly, kStreaming };

    enum class ArmOutcome {
        kArmed,            ///< armed in the requested mode
        kDegradedGetOnly,  ///< streamed intent + pending cancel consumed → GET-only lifecycle (H6)
        kAborted,          ///< abandon already won (record in kAborted)
        kNotFound,         ///< no such record (abandon won and erased, or never reserved)
        kAlreadyArmed,     ///< arm called twice - caller bug, first arm stands
    };

    /// Every `yuzu_mcp_bridge_degrade_total{reason}` literal the MCP handler can
    /// emit. A CLOSED set, declared HERE rather than as a bare list in server.cpp
    /// so the emit sites and the startup pre-seed cannot drift apart the way they
    /// did when the streamed-POST rung added six reasons and seeded none of them
    /// (adversarial review, 2026-07-27). Same both-or-neither shape as
    /// kTeardownStageNames. A new degrade reason belongs in this array first.
    static constexpr std::array kDegradeReasons{
        // 3a (GET-only bridge)
        "reserve_rejected", "reserve_threw", "no_execution_row", "subscribe_failed", "arm_threw",
        // 3b (streamed POST)
        "bind_post_sink_failed", "stream_install_failed", "arm_already_armed", "arm_cancelled",
        "arm_not_armed", "post_dispatch_threw"};

    /// The CLOSED streamed-POST admission-denial labels for
    /// `yuzu_mcp_stream_rejects_total{reason}`. Declared here, beside the code that
    /// emits them, for the third time this pattern has been needed: a hand-written
    /// copy in the startup seed drifts the moment a reason is added, which is what
    /// let `detached` and six degrade reasons ship emitted-but-unseeded.
    static constexpr std::array kPostRejectReasons{
        "post_per_principal_cap", "post_global_cap",          "post_record_cap",
        "post_pin_slots",         "post_duplicate_request_id", "post_unknown_session"};

    enum class CancelOutcome {
        kAcceptedPending,  ///< pre-arm: recorded; arm()/abandon() arbitrate (C1 - no audit yet)
        kDetached,         ///< 3b: a LIVE streamed response was closed BY THIS CALL (audited once)
        kNoOp,             ///< nothing cancellable: unknown, duplicate, or no live response
    };

    /// The CLOSED `yuzu_mcp_cancel_notifications_total{outcome}` label set, and the
    /// one mapping from outcome to label. Declared together, next to the enum they
    /// describe, for the same reason kDegradeReasons is: a hand-written seed list
    /// somewhere else drifts the moment an outcome is added. It already did once -
    /// the commit that introduced kDegradeReasons to stop exactly this drift added
    /// `detached` to the emit site and to no seed list at all (adversarial
    /// re-review, 2026-07-27). A new CancelOutcome must appear in BOTH of these,
    /// and a test walks the enum to prove every label is seeded.
    static constexpr std::array kCancelOutcomeLabels{"accepted", "detached", "noop"};
    /// EVERY enum value returns from its own case, with NO `default`, so adding a
    /// CancelOutcome without extending this WARNS under -Wswitch (GCC/Clang) and
    /// C4062 (MSVC). It does not fail the build - this project sets werror=false -
    /// so the sentinel below is the second line of defence: an unmapped outcome
    /// reports "unknown" rather than silently borrowing a real label, which is what
    /// the previous version's trailing `return kCancelOutcomeLabels[2]` did. That
    /// mattered because it reproduced, one level up, exactly the drift the closed
    /// list exists to prevent. "unknown" is deliberately NOT in the pre-seeded set:
    /// an unseeded series appearing in the metric is the signal.
    [[nodiscard]] static constexpr const char* cancel_outcome_label(CancelOutcome o) noexcept {
        switch (o) {
        case CancelOutcome::kAcceptedPending:
            return kCancelOutcomeLabels[0];
        case CancelOutcome::kDetached:
            return kCancelOutcomeLabels[1];
        case CancelOutcome::kNoOp:
            return kCancelOutcomeLabels[2];
        }
        return "unknown";
    }

    /// C5 (#2409): the terminal frame a claimed pressure-teardown publishes.
    /// kNone = real final already pinned (or nothing to publish); kFallbackFinal =
    /// success-shaped "fetch by execution_id" for a terminal-known-payload-lost
    /// record; kSynthesizeUnavailable = the -32014 error, reachable ONLY for a
    /// record that genuinely never saw a terminal.
    enum class TeardownFinal { kNone, kSynthesizeUnavailable, kFallbackFinal };
    /// sre-N1 (#2489): the CLOSED disposition label set for
    /// yuzu_mcp_bridge_forced_expire_total. Only the failure of a publish was
    /// counted before, so an operator could not tell a degrade-to-fallback from a
    /// synthesized -32014 from an ordinary settle - the distinction existed only
    /// in audit, which is not scraped.
    ///
    /// The label comes from a SWITCH with no `default:`, which is the actual gate:
    /// a fourth TeardownFinal value makes this function a -Wswitch warning at the
    /// point of the change. An index into the array could not do that - it would
    /// have compiled and quietly emitted an unseeded "unknown" (#2489 review). The
    /// array is the seed list `server.cpp` walks, and must carry one entry per
    /// case; the static_assert below only pins its size, not its contents.
    static constexpr std::size_t kTeardownFinalCount = 3;
    static constexpr std::array<const char*, kTeardownFinalCount> kForcedExpireDispositions{
        "none", "synthesize_unavailable", "fallback_final"};
    static constexpr const char* forced_expire_disposition(TeardownFinal d) {
        switch (d) {
        case TeardownFinal::kNone:
            return "none";
        case TeardownFinal::kSynthesizeUnavailable:
            return "synthesize_unavailable";
        case TeardownFinal::kFallbackFinal:
            return "fallback_final";
        }
        return "none";  // unreachable for a valid enumerator; never a new label
    }

    /// The three resources a claimed teardown must settle, in the order it settles
    /// them. ONE source of truth: the metric label set, the pre-seed loop in
    /// server.cpp and the fault seam all derive from this, so adding a fourth owned
    /// resource cannot silently leave one of them behind.
    enum class TeardownStage { kUnsubscribe, kReleaseCharge, kErase };
    static constexpr std::size_t kTeardownStageCount = 3;
    static constexpr std::array<const char*, kTeardownStageCount> kTeardownStageNames{
        "unsubscribe", "release_charge", "erase"};
    static constexpr const char* stage_name(TeardownStage s) {
        const auto idx = static_cast<std::size_t>(s);
        return idx < kTeardownStageCount ? kTeardownStageNames[idx] : "unknown";
    }

    /// #2513: the final disposition of a teardown retry, pre-seeded in server.cpp
    /// the same both-or-neither way as kTeardownStageNames above. `attempted` is
    /// deliberately NOT a member - it is inferable from teardown_incomplete's own
    /// movement plus the mcp.bridge.teardown_retry audit rows, and `exhausted` is
    /// the one value worth alerting on.
    enum class TeardownRetryOutcome { kRecovered, kExhausted };
    static constexpr std::size_t kTeardownRetryOutcomeCount = 2;
    static constexpr std::array<const char*, kTeardownRetryOutcomeCount>
        kTeardownRetryOutcomeNames{"recovered", "exhausted"};
    static constexpr const char* retry_outcome_name(TeardownRetryOutcome o) {
        const auto idx = static_cast<std::size_t>(o);
        return idx < kTeardownRetryOutcomeCount ? kTeardownRetryOutcomeNames[idx] : "unknown";
    }

    /// What was actually holding this session's streamed slots when a `pin_slots`
    /// reject was emitted (#2740). The refusal's remediation is chosen from this,
    /// because ONE sentence cannot be true of both states. `kCharges` means calls
    /// that reserved and have not settled a terminal - ordinarily in flight, so
    /// "wait for one to finish" is true advice. `kPins` means every slot is a
    /// COMMITTED final that no wire has taken delivery of AND the reclaim found
    /// none of them takeable, which happens in three states: a final still being
    /// WRITTEN by a live pump, a transient decline while one of this session's
    /// records is mid-projection, or a slot genuinely stuck. The first two clear
    /// on retry and the client cannot tell which it is in, so the `kPins` text
    /// advises a retry FIRST and only then a resume or a fresh session - do not
    /// reintroduce "waiting will not help" here, which was true only before the
    /// reclaim existed.
    /// Never asserts a fault: a healthy session passes through `kPins` during the
    /// terminal-to-wire flush window, which is why the text points at the metric
    /// rather than declaring one (see `count_pin_slots_reject`).
    /// Three states, not a bool, even though no consumer distinguishes
    /// `kNotApplicable` from `kCharges` today (the field is only read inside the
    /// `pin_slots` arm, so "unset" is unobservable there). The third state keeps
    /// "this reject was not about pin slots at all" explicit for every OTHER
    /// reject reason and for success, which a bool would silently collapse into
    /// "charges" - a wrong answer waiting for the first consumer that reads the
    /// field outside that arm.
    enum class PinSlotsHeld : int { kNotApplicable, kCharges, kPins };

    struct ReserveResult {
        bool ok = false;
        /// Static literal iff !ok - doubles as the reject_total{reason} label:
        /// "disabled" | "shutdown" | "unknown_session" | "duplicate_request_id" |
        /// "global_cap" | "pin_slots".
        const char* reject_reason = nullptr;
        /// Set only alongside `reject_reason == "pin_slots"`. Deliberately NOT a
        /// new reject_reason value: that string is a CLOSED metric label set, and
        /// splitting it would silently re-partition every existing dashboard.
        PinSlotsHeld pin_slots_held = PinSlotsHeld::kNotApplicable;
    };

    /// `bus` nullable ⇒ bridge disabled: reserve() rejects "disabled", nothing
    /// subscribes, callers fall back to today's plain path byte-identically.
    /// Two overloads instead of a `Config cfg = {}` default: GCC rejects
    /// consuming Config's default member initializers before the enclosing
    /// class is complete (the McpSessionRegistry precedent) - the delegation in
    /// the .cpp resolves Config{} where the class is complete.
    McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                    yuzu::MetricsRegistry* metrics = nullptr, AuditFn audit = {});
    McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                    yuzu::MetricsRegistry* metrics, AuditFn audit, Config cfg);
    /// Calls the idempotent shutdown() - correct teardown even if stop() never ran.
    /// MUST run while the bus is still alive (server.cpp resets the bridge BEFORE
    /// the bus, mirroring [BUS-BEFORE-TRACKER]).
    ~McpStreamBridge();
    McpStreamBridge(const McpStreamBridge&) = delete;
    McpStreamBridge& operator=(const McpStreamBridge&) = delete;
    McpStreamBridge(McpStreamBridge&&) = delete;
    McpStreamBridge& operator=(McpStreamBridge&&) = delete;

    /// S1: keyed kArming record insert - dup-key/cap/pin-slot admission BEFORE
    /// create_execution, so every rejection is truthfully "no execution row".
    /// Streamed admission counts LIVE PINS plus streamed records that have not
    /// pinned yet (`pinned_count() + streamed_unpinned_[session]`). Orphan pins
    /// left by pressure/pin-ack teardown are counted the same way, but since
    /// #2740 they are no longer permanent: an at-cap admission RECLAIMS one
    /// rather than refusing (see `select_displaceable_pin_locked`). A transient
    /// over-count still rejects fail-closed (A5/C3).
    ReserveResult reserve(const std::string& session_id, const std::string& principal,
                          const nlohmann::json& jsonrpc_id,
                          std::optional<nlohmann::json> progress_token, bool streamed_intent);

    /// S3: bus subscribe_and_replay(execution_id, 0) onto the reserved record.
    /// Runs UNDER bridge_mu_ (A3): installation and the sub-token store are
    /// serialized against every teardown, so no listener can exist without a
    /// token a teardown can see. A bus throw propagates - the caller abandons
    /// (installation failure has zero side effects per the 3a.3 contract).
    bool subscribe(const std::string& session_id, const nlohmann::json& jsonrpc_id,
                   const std::string& execution_id);

    /// S5/S6: atomic flip-and-drain (H2). Prebuilds the fallback final BEFORE the
    /// flip; CAS + handoff wake under ONE record-mutex hold - a listener append
    /// lands either pre-flip (drained by the handoff wake) or post-flip (drained
    /// by the listener's own unconditional wake); nothing strands.
    /// `result_base` = the serialized JSON-RPC *result object* exactly as today's
    /// plain path builds it (B5); the parked real final re-emits it with
    /// status/agents_success/agents_failure added as TOP-LEVEL result keys.
    /// Empty ⇒ the bus-payload-only shape (tests; 3b always passes the real base).
    ArmOutcome arm(const std::string& session_id, const nlohmann::json& jsonrpc_id, ArmMode mode,
                   std::string result_base = {});

    /// Two phases can be cancelled, and they mean different things:
    ///  - kArming (pre-arm): record cancel INTENT only (C1) - no audit, no
    ///    transition; arm()/abandon() arbitrate, because a pre-dispatch failure
    ///    would invalidate any outcome decided here. -> kAcceptedPending.
    ///  - kStreaming (3b): a live streamed response EXISTS, so there is nothing to
    ///    arbitrate - close its sink now, audited here exactly once. The pump then
    ///    finishes kCancelled and its releaser parks the record. -> kDetached.
    /// Anything else is kNoOp.
    ///
    /// NEVER touches the execution. Cancellation withdraws the client's interest in
    /// a RESPONSE; the dispatched command keeps running and its result stays
    /// fetchable by execution_id. (Decision 15(j); chaos CH-12.)
    /// `principal` is the authenticated caller, recorded on the audit row when this
    /// detaches a live streamed response. Empty is accepted (tests, internal
    /// callers) and audits as "system".
    CancelOutcome request_cancel(const std::string& session_id, const nlohmann::json& jsonrpc_id,
                                 std::string_view principal = {});

    /// Pre-dispatch failure unwind: kArming → kAborted, unsubscribe (waits out
    /// in-flight listeners), discard the progress slot, release charge, erase. The caller
    /// owns lease release / mark_cancelled / the byte-identical error path (G1).
    bool abandon(const std::string& session_id, const nlohmann::json& jsonrpc_id);

    /// 3b pump-releaser seam: kStreaming → kRingOnly, assign parked order, wake the
    /// projector (A1 - a latched terminal must not wait for the next bus event).
    bool on_post_closed(const std::string& session_id, const nlohmann::json& jsonrpc_id);

    /// What one pump tick may write to the live streamed-POST wire. The frames
    /// have ALREADY been committed to the session ring (for GET resume) by the
    /// time this returns - the ring is the durable copy, this is the live one.
    struct PostBatch {
        /// One wire frame plus the replay-ring event id it was committed under
        /// (#2785). The id rides the SSE `id:` line so a client that only ever
        /// saw the POST connection can hand it back as `Last-Event-ID` on a GET
        /// resume - without it the documented resume contract is unreachable
        /// from this surface. 0 = no ring counterpart (a poisoned or pinless
        /// final); format_sse omits the `id:` line for 0 rather than minting a
        /// cursor that would resume onto nothing.
        struct PostFrame {
            std::string data;
            std::uint64_t event_id = 0;
        };
        std::vector<PostFrame> progress;        ///< write in order, oldest first
        std::optional<PostFrame> final_frame;   ///< write LAST, then EOF
        /// Another claimant held the projection claim; nothing was taken and
        /// nothing is owed. The pump retries on its next tick.
        bool deferred = false;
        /// The response cap elapsed with no terminal to deliver. The pump closes
        /// with kCapExpired; the execution continues server-side.
        bool cap_settled = false;
        /// The bridge can no longer serve this key — record erased or bridge
        /// shutting down. Distinct from an idle tick: there will be no next frame,
        /// so the pump must close rather than heartbeat.
        bool record_gone = false;
    };

    /// Bind the streamed-POST wake channel to a kStreaming record, returning its
    /// key. The pump waits on `sink`'s condition variable, and the projector
    /// pokes it whenever work lands - the publish path CANNOT do that job,
    /// because a streamed record's frames are ring-only (deliver_live=false), so
    /// no live-sink notify ever fires for them.
    ///
    /// Includes the bind-time handshake: the pending-work predicate is evaluated
    /// inside the SAME record-lock hold that stores the sink, so a terminal that
    /// latched between arm() and bind cannot be missed by a pump about to wait.
    std::optional<std::string> bind_post_sink(const std::string& session_id,
                                              const nlohmann::json& jsonrpc_id,
                                              std::shared_ptr<sse_bus::SseSinkState> sink);

    /// One pump tick's worth of work for a kStreaming record. `cap_expired` is
    /// decided by the pump but arbitrated HERE, inside the projection claim, so
    /// a terminal that landed in the same instant still wins over the cap - and
    /// so ordinary progress is never ring-committed merely to probe for one.
    PostBatch take_post_batch(const std::string& key, bool cap_expired);

    /// The record key for a live streamed request, resolved ONCE while the
    /// caller can still fail safely. The streamed-POST handler captures this in
    /// its releaser closure and later calls on_post_closed_keyed() with it.
    ///
    /// This exists for one reason: httplib runs a response releaser from
    /// ~Response, so a releaser that rebuilt the key itself would carry a
    /// `bad_alloc` site INSIDE a destructor - std::terminate, the #2037 class -
    /// and swallowing that throw instead would strand the record in kStreaming,
    /// which no sweep pass reclaims. Allocating here moves that cost to a frame
    /// that can still degrade.
    std::optional<std::string> record_key(const std::string& session_id,
                                          const nlohmann::json& jsonrpc_id);

    /// Allocation-free sibling of on_post_closed, keyed by the string
    /// record_key() already returned. Deliberately a DISTINCT NAME rather than
    /// an overload: both identify a record by string, so an overload set would
    /// silently accept a session id and no-op forever.
    bool on_post_closed_keyed(const std::string& key);

    /// The pump wrote the final response to the POST wire. Recorded so the
    /// following close settles the record as kDone instead of parking it for a
    /// GET resume the client no longer needs. Allocation-free for the same
    /// reason as on_post_closed_keyed.
    bool on_final_written(const std::string& key);

    /// POST-DISPATCH failure unwind: kArming → kRingOnly, retaining the bus
    /// subscription, the progress slot and any latched terminal. PARK, NOT abandon -
    /// the work is already running, so the record must stay able to receive and
    /// publish its real terminal for GET resume; abandon() would unsubscribe and
    /// discard a result the client can still legitimately collect. The caller
    /// owns the correlated error response (which MUST carry the execution_id) and
    /// must NOT mark the execution cancelled - unlike the pre-dispatch paths, the
    /// execution is genuinely still running.
    ///
    /// Needed because arm()'s flip is no-throw but its PRE-flip work is not (the
    /// key build, the execution-id copy, the fallback build, and the by-value
    /// result_base copy at the call boundary, which cannot be prebuilt because it
    /// carries post-dispatch data). A throw there leaves a dispatched record stuck
    /// in kArming with no transition of its own.
    ///
    /// Deliberately does NOT set torn_down: that flag means "permanently excluded
    /// from reclaim", and a park is a transition, not a teardown.
    bool park_after_dispatch_failure(const std::string& session_id,
                                     const nlohmann::json& jsonrpc_id,
                                     std::string_view principal = {});

    /// Reap + enforce (server tick wiring is 3a.7; public for tests):
    ///   0. kDone records → unsubscribe/unpin-bookkeeping/erase.
    ///   1. pin-ack: a kRingOnly record whose pinned final left the ring
    ///      (GET resume consumed it - the H4 const poll, no callback edge) → kDone.
    ///   2. session death: kArmedGetOnly/kRingOnly whose session no longer
    ///      exists (the non-touching registry query) → kDone. kArming is
    ///      excluded - request-scoped, its own POST arbitrates.
    ///   3. pressure: see the class comment (E1 two-stage, multi-victim).
    /// NOTE (3a.7): the tick MUST also call McpSessionRegistry::gc() - exists()
    /// never destroys an expired session's stream, so pins held by a dead
    /// session are only released when registry GC actually runs.
    void sweep();

    /// Idempotent. Gates every public mutator (C6), stops + joins the projector
    /// (never holding bridge_mu_ across the join), then unsubscribes everything,
    /// settles charge accounting, and clears the maps.
    void shutdown();

    // ── Observability / test accessors ─────────────────────────────────────
    std::size_t record_count() const;
    /// Test seam: did this record's streamed response get closed? The in-process
    /// test fixture never runs the content provider (no socket, #438), so a
    /// handler-level cancel test cannot observe the pump reacting - it can only
    /// check that the bridge did its half. nullopt = no record, or none bound.
    std::optional<bool> post_sink_closed_for_test(const std::string& session_id,
                                                  const nlohmann::json& jsonrpc_id) const;
    std::size_t ring_only_count() const;
    std::optional<Phase> phase_for(const std::string& session_id,
                                   const nlohmann::json& jsonrpc_id) const;
    /// One-shot: the NEXT listener invocation throws std::bad_alloc inside its
    /// boundary (counted, contained). Mirrors inject_publish_fault_for_test.
    void inject_listener_fault_for_test();
    /// Test seam: force the next audit/metrics flush attempts to observe a
    /// throwing observability layer (C5 fault seam).
    void inject_observability_fault_for_test(int times = 1);
    /// One-shot: the NEXT arm() throws std::bad_alloc pre-flip, modelling an
    /// allocation failure in the result_base copy / fallback build. Proves the
    /// execute_instruction handler's guard degrades to the plain path and leaks
    /// no kArming record.
    void inject_arm_fault_for_test();
    /// One-shot: the NEXT reserve() (after admission) / subscribe() throws
    /// std::bad_alloc, modelling an allocation failure. Proves the handler's
    /// reserve/subscribe guards degrade to the plain path (governance quality).
    void inject_reserve_fault_for_test();
    void inject_subscribe_fault_for_test();
    /// One-shot: the NEXT reserve() throws std::bad_alloc in the window BETWEEN
    /// the streamed-charge ledger bump and the records_ insert - the window
    /// inject_reserve_fault_for_test fires too early to model. Proves the two
    /// mutations commit together: a throw here must leave the ledger AND the map
    /// unchanged, because a surviving bump is a phantom charge that rejects that
    /// session's streamed reserves with pin_slots for the life of the process.
    void inject_reserve_commit_fault_for_test();
    /// The NEXT `times` pressure-visitor terminal-payload copies (kTerminalBuffered
    /// latch) throw std::bad_alloc, modelling a copy OOM. A persistent fault (times
    /// large) makes the record NEVER settle (the copy never latches), which is what
    /// distinguishes "the fault path fired" from a silent no-op; healing (times=0)
    /// then lets it settle. Proves defer + keep-listener + terminal_accepted-false
    /// (#2409 safety-S1).
    void inject_visit_copy_fault_for_test(int times = 1);
    /// The NEXT `times` teardown_claimed steps of `stage` throw, modelling the one
    /// failure those steps actually admit (a mutex failure - all three allocate
    /// nothing). Each stage retains a DIFFERENT resource, so each needs its own
    /// coverage: unsubscribe retains the whole record (and must never erase around a
    /// live listener), release_charge leaks a per-session admission slot while the
    /// record is still erased, and erase leaks the record after the other two
    /// settled. A persistent fault keeps the state observable, which is what
    /// distinguishes "the fault fired" from a silent no-op (#2487). Returns false and
    /// arms nothing on an out-of-range `stage` cast (#2523) - a mistyped stage must
    /// fail the test loudly rather than pass vacuously against an unfaulted teardown.
    [[nodiscard]] bool inject_teardown_step_fault_for_test(TeardownStage stage, int times = 1);
    /// #2519: invoked synchronously on the teardown thread immediately before
    /// (`entering=true`) and after (`entering=false`) each CONTAINED step of
    /// teardown_claimed (unsubscribe / release_charge / erase), OUTSIDE every
    /// lock the step itself takes. Lets a test bracket exactly one step's
    /// allocation footprint, or - for #3095 - block the teardown thread at a
    /// known point to force a deterministic interleave. Must not throw; not
    /// thread-safe to set while a sweep may be running concurrently (arm it
    /// before the first sweep, like set_clock_for_test).
    void set_teardown_step_probe_for_test(
        std::function<void(TeardownStage, bool entering)> probe);
    /// The NEXT `times` ~ClaimGuard record-lock acquisitions throw, modelling the
    /// mutex failure this file's fault model already treats as real. Drives the
    /// #2528 DEGRADED SETTLE: the claim must still be released (else the record is
    /// wedged out of all four consumers, and before UP-5 (#2489) made a deferred
    /// victim advance the pressure pass rather than end it, one such record stalled
    /// ring-only pressure relief bridge-wide), and the settle bookkeeping must be
    /// recorded honestly - terminal_projected when the frame was already published,
    /// terminal_payload_lost when it was extracted and never published.
    void inject_claim_lock_fault_for_test(int times = 1);
    /// The NEXT `times` project_record REAL-final builds throw. The prebuilt
    /// fallback still publishes, so this covers the fallback-final path (and
    /// proves the prebuilt string is non-empty for a record parked before arm).
    void inject_projection_build_fault_for_test(int times = 1);
    /// The NEXT `times` FALLBACK copies throw as well. Armed together with the
    /// build fault this is the double allocation failure - the path that
    /// leaves the terminal extracted but never published, and therefore the only
    /// path whose recovery is the guard's restore. Pairs with
    /// inject_claim_lock_fault_for_test to reach #2528's payload-lost arm.
    void inject_projection_fallback_fault_for_test(int times = 1);
    /// The NEXT `times` teardown terminal-frame BUILDS throw, modelling an
    /// allocation failure before publish_terminal_ladder is ever reached. Proves the
    /// TerminalRung::kNotAttempted audit path: nothing published AND the stream was
    /// not poisoned, which must not be reported as a poisoning (#2487 review).
    void inject_terminal_build_fault_for_test(int times = 1);
    /// The NEXT `times` release_charge() calls throw AT THE LOCK, before either
    /// half of the release runs - the same modelled mutex failure as the claim
    /// seam. Proves #2529's both-or-neither property: a failure here must leave
    /// the record still reading "charge held" AND the ledger still counting it,
    /// so a later release repairs it. The split version cleared the flag first,
    /// and a throw then stranded streamed_unpinned_[session] forever.
    void inject_charge_lock_fault_for_test(int times = 1);
    /// The NEXT `times` calls into teardown_claimed() throw at its entry lock
    /// (attempt bookkeeping / Step-1 idempotence read) - the same modelled mutex
    /// failure as the claim/charge seams above, at the one lock every retry
    /// attempt takes first. Proves the entry lock is CONTAINED rather than
    /// escaping teardown_claimed's noexcept boundary (which would terminate the
    /// process): a hit here must leave attempts NOT incremented and the record
    /// untouched - this call never happened as far as its bookkeeping goes.
    void inject_record_entry_lock_fault_for_test(int times = 1);
    /// Override the reaper clock for deterministic age tests (default:
    /// steady_clock::now). Only the difference between calls matters.
    void set_clock_for_test(ClockFn clock);

    /// #2791 test seam. ONE combined read of the two halves of admission
    /// accounting for `session_id` - the charge ledger (`bridge_mu_`) and
    /// `stream`'s pinned count (its own mutex) - under the SAME `bridge_mu_`
    /// hold reserve() itself uses at cpp:347-350 (read order does not matter;
    /// only the shared hold does). Two separate calls (a hypothetical
    /// `unpinned_for_test()` plus `stream->pinned_count()`) would not be atomic
    /// with EACH OTHER and could observe a torn pair under concurrent
    /// admission/release traffic; this reads both in one `bridge_mu_` hold, so
    /// a caller gets the same snapshot reserve() would have decided on.
    struct AccountingSnapshot {
        std::size_t pinned = 0;
        std::size_t unpinned = 0;
    };
    AccountingSnapshot accounting_snapshot_for_test(const std::string& session_id,
                                                    const std::shared_ptr<McpStreamState>& stream);

    /// #2791 test seam: the NEXT project_record call to reach the window after
    /// `publish_terminal_ladder` commits the frame but before `pinned_event_id`
    /// is stamped (cpp:1719 area) blocks until release_projection_stall_for_test()
    /// runs. BRIDGE-GLOBAL, not per-record: the arm applies to whichever record's
    /// project_record call reaches the window next, on whichever thread reaches
    /// it (the single projector thread, or a live POST pump's take_post_batch).
    /// Every caller of this seam (in test_mcp_stream_bridge.cpp) arms it only
    /// when it can prove no OTHER record is concurrently projectable, which is
    /// what makes "the next call" mean "the intended one" - do not reuse this
    /// seam with concurrent multi-record
    /// streamed activity in flight without first scoping it to a specific `rec`.
    /// This is exactly the window `select_displaceable_pin_locked`'s
    /// `projection_in_flight` guard exists to mask (see its header contract
    /// above `select_displaceable_pin_locked`'s declaration) - a live call's pin
    /// is committed to the ring but not yet attributable to a record, which is
    /// indistinguishable from an orphan without the guard. Neither `bridge_mu_`
    /// nor `rec->mu` is held while parked (both are released before this window
    /// is reached), so a concurrent reserve() runs its full, real admission
    /// decision - including the decline branch - against a record that is
    /// genuinely, deterministically mid-projection, rather than racing for it.
    /// One-shot: disarms itself the instant it is reached. No existing seam
    /// reaches this branch deterministically - `ClaimGuard` is function-local
    /// and every throw path in this file already clears `projection_in_flight`
    /// before returning (#2528), so a fault injected anywhere in the claim
    /// window still lets the NEXT scan see it cleared.
    void arm_projection_stall_for_test();
    /// Blocks until the armed stall has been reached (project_record is parked
    /// in the window) or `timeout` elapses. Bounded like every racer in this
    /// file: a stall never reached must fail the test, not hang CI.
    bool wait_projection_stall_reached_for_test(
        std::chrono::milliseconds timeout = std::chrono::seconds(5));
    /// Releases a parked stall. A no-op if none is parked (idempotent, like the
    /// file's other test-seam releases).
    void release_projection_stall_for_test();

private:
    /// One latched bus event. Nothrow-movable - load-bearing for the projector's
    /// extraction (C4), the listener's construct-then-move commit (D2), and
    /// (#2412) the listener/projector latest-wins progress-slot swaps, which
    /// rely on the same nothrow move to flip buffers without allocating.
    struct MailboxEntry {
        std::uint64_t bus_id = 0;
        std::string data;
    };
    static_assert(std::is_nothrow_move_assignable_v<MailboxEntry> &&
                      std::is_nothrow_move_constructible_v<MailboxEntry> &&
                      std::is_nothrow_swappable_v<MailboxEntry>,
                  "projector extraction and listener commit rely on nothrow moves; "
                  "#2412's progress-slot swaps rely on nothrow swap directly");

    /// Listener-reachable state, shared_ptr-owned so a leaked listener can never
    /// touch a destroyed bridge (C7 - the listener captures {record, wake core}
    /// and NOTHING else; helpers are free functions).
    struct WakeCore {
        std::mutex mu;
        std::condition_variable cv;
        bool work_pending = false;  ///< guarded by mu - the lost-wakeup killer
        bool stop = false;          ///< guarded by mu
        std::atomic<bool> listener_fault{false};
        /// C5/D3: deltas whose registry flush failed transiently, retried by later
        /// projector passes; records also drain their locals here at teardown.
        std::atomic<std::uint64_t> pending_listener_failures{0};
        std::atomic<std::uint64_t> pending_projection_degraded{0};
        std::atomic<std::uint64_t> pending_progress_suppressed{0};
        /// #2411: keys with possibly-unprojected work, pushed by mark_dirty and
        /// swapped out whole by the projector each cycle (bucket storage reused
        /// across cycles - see run_projector). Bounded by live-record-count-ish
        /// churn between drains, never larger, because insertion dedupes.
        ///
        /// INVARIANT, split by how each half gets set:
        ///   - `!dirty.empty() ⇒ work_pending`, and any `mu`-HELD write of
        ///     `scan_all` (the insert-alloc-failure path, run_projector's
        ///     outer-catch re-arm) ⇒ `work_pending` - because those three
        ///     writers - the ordinary dirty-key insert, the alloc-failure
        ///     degrade, and the outer-catch re-arm - set `work_pending = true`
        ///     in the SAME `mu` critical section, and `work_pending` clears
        ///     only in the SAME section that swaps `dirty` out empty and
        ///     exchanges `scan_all` for false. This half is what the
        ///     lost-wakeup proof on mark_dirty depends on,
        ///     and it can never be observed false by a projector that just
        ///     re-acquired `mu`.
        ///   - the LOCK-FREE `scan_all` store (mark_dirty's outer catch, for
        ///     a fault in acquiring `mu` itself) is deliberately NOT paired
        ///     with `work_pending`: it cannot be, since it runs precisely
        ///     when taking `mu` is not possible. It is a latent breadcrumb,
        ///     consumed by whichever wake next reaches `mu` from ANY source -
        ///     correct because the wake this write would have accompanied is
        ///     already lost by hypothesis (the mutex fault ate it), so there
        ///     is nothing here for the invariant's "same critical section" to
        ///     protect. "Consumed" is load-bearing on run_projector's read
        ///     being a SINGLE atomic exchange, not a separate load then
        ///     store: a racing lock-free store(true) then lands either
        ///     before the exchange (captured this cycle) or after (survives
        ///     intact for the next) - a split load/store would let it land
        ///     BETWEEN the two and be silently overwritten by the store,
        ///     losing the breadcrumb this whole path exists to preserve.
        std::unordered_set<std::string> dirty;
        /// Degrade valve: a dirty-key insert hit an allocation failure, a
        /// prior cycle's body threw after already swapping its keys out (see
        /// run_projector's outer catch), or mark_dirty could not even acquire
        /// `mu` - any of these leaves the swapped-away keys untrustworthy as
        /// the FULL set of records with pending work, so the next cycle falls
        /// back to the pre-#2411 full-table scan instead. Lock-free: the
        /// third writer above (mark_dirty's outer catch) fires exactly when
        /// `mu` may be unavailable, so this cannot be `mu`-guarded like
        /// `dirty` is; relaxed suffices because nothing is ordered around it
        /// - only the flag's own eventual visibility to the next reader,
        /// which must consume it via a single exchange (see above), not a
        /// load followed by a separate store.
        std::atomic<bool> scan_all{false};
    };

    /// Which rung of the publish ladder actually committed. The committed id alone
    /// cannot answer this - a nonzero id from the retry looks identical to one from
    /// the primary frame - and teardown's audit must not claim the caller's frame
    /// was delivered when the fallback was (#2506 F4).
    /// kNotAttempted is NOT a ladder result - it means the ladder was never reached
    /// (the caller's own frame-build failed before the ladder was ever called; see
    /// the callers' `built` guard). It is a distinct state on purpose: kPoisoned
    /// asserts poison_terminal() ran, and an audit row must never claim a session
    /// was poisoned when it was not.
    ///
    /// There used to be a third non-ladder state, kPublishThrew, for a throw
    /// escaping the ladder itself - retired once publish_terminal_ladder became
    /// noexcept (#2531 made poison_terminal() noexcept, which was the ladder's
    /// only remaining throw source; #2523 closed the enum value it left
    /// permanently untestable). See the static_assert at publish_terminal_ladder's
    /// definition, which is what makes this enum's shape a compile-time fact
    /// rather than a comment someone has to remember to update.
    ///
    /// Declared here, ahead of BridgeRecord, because BridgeRecord's #2513 retry
    /// fields (`teardown_last_rung`) persist a TerminalRung and a nested struct's
    /// member cannot reference a sibling enum declared later in the same class.
    enum class TerminalRung { kNotAttempted, kPrimary, kFallback, kPoisoned };

    struct BridgeRecord {
        // Immutable after reserve()/subscribe()/arm() hand-off points (each field
        // is written before the record becomes reachable by the code that reads
        // it; see the .cpp field-by-field notes). Safe to read lock-free AFTER
        // observing a post-write phase via the record mutex.
        std::string session_id;
        std::string principal;
        nlohmann::json jsonrpc_id;
        std::string key;               ///< session_id + '\n' + jsonrpc_id.dump()
        bool streamed_intent = false;
        std::uint64_t seq = 0;         ///< reservation order
        std::chrono::steady_clock::time_point created;  ///< set at reserve; the kArming reaper's age base
        std::shared_ptr<McpStreamState> stream;  ///< taken at reserve via stream_for
        std::optional<nlohmann::json> progress_token;
        /// Set by subscribe(), before any listener exists, and never again: subscribe()
        /// ENFORCES that with a state gate (!subscribed && !torn_down && kArming), so
        /// teardown_claimed can borrow this rather than copy it. Not merely a comment -
        /// a late subscribe into a claimed-but-not-yet-erased record would both race
        /// that borrow and strand a fresh listener (#2487 review).
        std::string execution_id;
        std::string fallback_final;    ///< prebuilt at arm(), before the flip
        std::string result_base;       ///< serialized result object (B5); set at arm()

        // Subscription bookkeeping - guarded by bridge_mu_ (A3: installed and
        // torn down only under it or by the kDone claimant).
        std::size_t sub_id = 0;
        bool subscribed = false;

        // Atomic for cheap phase reads; every kArming-EXIT transition and every
        // →kDone claim happens under `mu` (C1/B2 arbitration).
        std::atomic<Phase> phase{Phase::kArming};

        // ── Guarded by mu ──────────────────────────────────────────────────
        mutable std::mutex mu;
        /// #2412: the ONE latched progress snapshot - latest-wins, not a ring.
        /// The listener assigns the newest event into `listener_spare`, then
        /// swaps it with `progress_slot` (noexcept); the projector swaps
        /// `progress_slot` with `projection_spare` to extract. Both spares
        /// exist so every swap is allocation-free once each buffer has grown
        /// to its steady-state payload size - a straight move-out-and-replace
        /// would re-allocate the slot's buffer on every extraction.
        MailboxEntry progress_slot;
        bool progress_pending = false;    ///< progress_slot holds an unprojected snapshot
        MailboxEntry listener_spare;      ///< listener's swap partner
        MailboxEntry projection_spare;    ///< projector's swap partner
        std::optional<MailboxEntry> terminal_slot;  ///< reserved; never dropped
        /// STICKY write-once discriminator (D2): set only after the first
        /// terminal payload is fully secured in terminal_slot; NEVER cleared -
        /// not by extraction, restore, settle, or poison. The listener drops
        /// every event once set. Never inferred from terminal_slot.has_value().
        bool terminal_accepted = false;
        bool cancel_pending = false;       ///< C1 - intent only; arm/abandon arbitrate
        /// B2/C2: claimed around EVERY batch that may publish (progress or
        /// terminal). Sweep never claims kDone while set; stays asserted until
        /// any deferred charge decrement under bridge_mu_ completes (D4).
        ///
        /// PROTOCOL (#2528) - atomic so the claim can ALWAYS be released:
        ///  - SET only under `mu`, as a test-and-set inside one locked critical
        ///    section. Mutual exclusion between claimants comes from `mu`, not
        ///    from the atomic, so the SET may be relaxed; the atomic exists for
        ///    the release below.
        ///  - CLEARED unconditionally by ~ClaimGuard: under `mu` on the normal
        ///    path, and with a lock-free release store when `mu` cannot be
        ///    acquired. It used to be cleared inside the try whose FIRST act was
        ///    that acquisition, so a lock failure left it set forever and wedged
        ///    the record out of all four consumers - and under the defer-exits-
        ///    the-pressure-loop behaviour of the time, one wedged victim stalled
        ///    ring-only pressure relief bridge-wide. UP-5 (#2489) has since made a
        ///    defer advance to the next victim, so a repeat would now cost that
        ///    one record rather than the whole hatch - the containment here is
        ///    still what stops the record itself wedging permanently.
        ///  - READ under `mu` at every consumer, with acquire, to pair with that
        ///    lock-free store.
        ///  - CLEARED LAST, always: whatever settle bookkeeping the degraded path
        ///    can still do is stored (release) BEFORE it, so no consumer can
        ///    observe a released claim over stale bookkeeping.
        /// What the SKIPPED in-try bookkeeping means is stated once, at
        /// ~ClaimGuard in project_record - do not restate it here.
        std::atomic<bool> projection_in_flight{false};
        /// E1 - while set, the projector starts no NEW progress batch for this
        /// record (an already-latched terminal still settles). SET by a pressure
        /// sweep on a victim it is about to visit; CLEARED (UP-4, #2489) by the
        /// sweep pass that finds the cap back under water. It is NOT cleared on a
        /// mere defer: the quiesce has to survive between sweeps or the next visit
        /// finds a fresh projection in flight and defers again. Anything that
        /// leaves it set past the pressure it was raised for freezes this record's
        /// progress for the rest of its execution.
        bool pressure_requested = false;
        /// H1 (MCP MUST: notifications/progress `progress` strictly increases):
        /// the highest `progress` value already committed to the wire for this
        /// record, and whether any has been sent. Touched ONLY by the single
        /// projector thread inside project_record (never the listener/sweep), so
        /// no synchronization is needed.
        std::uint64_t last_progress_sent = 0;
        bool progress_sent_any = false;
        /// Settled: published, GET-only-consumed, or poisoned. Atomic for the
        /// same reason as projection_in_flight - ~ClaimGuard's degraded path must
        /// be able to record a settle it could not take `mu` to write. Written
        /// under `mu` on every normal path; read with acquire everywhere.
        std::atomic<bool> terminal_projected{false};
        /// STICKY (#2528): a terminal payload was extracted from terminal_slot and
        /// then LOST, because the restore-and-retry path could not retake `mu`.
        /// terminal_slot is empty and no listener will refill it (terminal_accepted
        /// is sticky write-once), so the real payload is gone for good and no
        /// projector retry exists. Consumers MUST map this to the success-shaped
        /// fallback final (TeardownFinal::kFallbackFinal) - the same disposition as
        /// TerminalVisit::kTerminalKnownLost. NEVER kNone (which answers the client
        /// nothing) and NEVER -32014 (a terminal demonstrably did happen).
        std::atomic<bool> terminal_payload_lost{false};
        bool final_published = false;      ///< a REAL final committed to the ring
        /// A5/C3: the per-session streamed-admission charge. Released exactly
        /// once (pin proof, cancel-degrade, pinless settle incl. poison, or
        /// teardown of a still-charged record). Clear this flag and decrement
        /// streamed_unpinned_ under BOTH locks, taken bridge_mu_ -> mu, so the two
        /// commit together. This comment used to say "cleared under mu, decremented
        /// under bridge_mu_ AFTER releasing mu" - that split is what let a throw at
        /// the second acquisition desynchronise the record from the ledger
        /// permanently, and the guidance outlived the bug it caused (#2487).
        bool streamed_charge_held = false;
        /// Exactly-once teardown claim: concurrent sweep() calls may both gather
        /// evidence on the same record; the first to set this under mu owns the
        /// teardown, the loser skips (no double synthesis/audit).
        bool torn_down = false;
        /// Set by teardown_claimed's Step 1, right after the publish switch, to
        /// whichever is true first: `decision == kNone` (nothing was ever owed) or
        /// the ladder was actually called (`rung != kNotAttempted` - published OR
        /// poisoned). NOT set when the frame build itself failed, which is the one
        /// state that leaves this record's terminal disposition genuinely
        /// unresolved. Distinct from `terminal_projected` (settle bookkeeping, set
        /// only by project_record) and `final_written` (POST-wire delivery) -
        /// overloading either risks re-claim/projection interactions this flag is
        /// deliberately narrow enough to avoid. shutdown()'s walk reads this to find
        /// a claimed-but-terminal-unresolved record a raced sweep abandoned (#2517).
        bool teardown_terminal_handled = false;
        /// #2513: retry state for a teardown a PRIOR attempt could not complete.
        /// All four guarded by mu. `teardown_retry_claimable` is the retry claim,
        /// distinct from `torn_down` above - `torn_down` is set once and NEVER
        /// cleared (shutdown()'s should_poison depends on that), so retry
        /// eligibility needs its own flag rather than reopening that gate. Set
        /// ONLY at a teardown_claimed bail site, so it cannot be true while any
        /// teardown_claimed for this record is running - single-flight without
        /// touching torn_down's own claim sites.
        bool teardown_retry_claimable = false;
        /// Attempts consumed so far; 0 before the first entry to teardown_claimed,
        /// bounded by Config::teardown_retry_max beyond the first. std::size_t,
        /// not a narrower counter: it is compared directly against
        /// Config::teardown_retry_max (also std::size_t, test-settable), and a
        /// narrower type wrapping at its max would silently re-open eligibility
        /// forever - the exact unbounded-retry outcome this bound exists to
        /// prevent.
        std::size_t teardown_attempts = 0;
        /// The `decision` teardown_claimed's Step 1 ran (or will run) with,
        /// persisted so a retry pass can replay the SAME decision without
        /// independently re-arbitrating what to publish.
        TeardownFinal teardown_decision = TeardownFinal::kNone;
        /// The TerminalRung Step 1 resolved to, persisted alongside
        /// `teardown_terminal_handled` so a retry whose terminal is already
        /// handled can replay disposition_phrase()/terminal_delivered exactly as
        /// the resolving attempt computed them, without re-running the publish.
        TerminalRung teardown_last_rung = TerminalRung::kNotAttempted;
        std::uint64_t pinned_event_id = 0;
        std::uint64_t parked_seq = 0;      ///< assigned on entry to kRingOnly
        /// The live streamed-POST wake channel, bound while phase == kStreaming.
        /// Held PURELY to wake the pump: the pump pulls its frames through
        /// take_post_batch and writes them itself, so nothing ever enqueues onto
        /// this sink's queue. Cleared when the record leaves kStreaming so a
        /// parked record holds no reference to a dead connection.
        std::shared_ptr<sse_bus::SseSinkState> post_sink;
        /// The pump wrote the final JSON-RPC response to the POST wire. A record
        /// that closes with this set is DONE (the client has its answer); one that
        /// closes without it parks for GET resume.
        bool final_written = false;
        /// #2739: the one post-cap-expiry progress drain RAN (set when a
        /// cap-expired take_post_batch extracts a progress batch - before the
        /// publish loop, so a mid-pass throw leaves it set and the record still
        /// settles). Once set, the next cap-expired pass with no pending terminal
        /// arbitrates the cap instead of starting another progress batch, bounding
        /// the response at cap + at most two pump ticks + one progress drain. A
        /// pending terminal bypasses the suppression entirely: the terminal pass
        /// drains intervening progress with it (progress-before-final ordering),
        /// so nothing latched is stranded when the record settles kDone. Frames
        /// latched after the drain pass are NOT lost on the cap path - the record
        /// parks kRingOnly and the projector flushes them to the ring for GET
        /// resume. Guarded by `mu`; read only on the pump (`out != nullptr`) path;
        /// never cleared (no kRingOnly -> kStreaming edge exists, so the flag is
        /// dead after park).
        bool cap_progress_drained = false;

        // C5: record-local, listener-writable observability. Flushed by the
        // projector / teardown through the noexcept obs guard - the listener
        // itself never touches a metrics mutex.
        std::atomic<std::uint64_t> listener_failure_delta{0};
        /// #2438: H1 progress-monotonicity suppressions, WIDENED by #2412 - a
        /// progress event the listener overwrites in `progress_slot` before the
        /// projector ever sees it (latest-wins supersede) is counted here too,
        /// under `mu` in the listener, not just on the (sole) projector-thread
        /// writer the #2438 comment originally described. The atomic is
        /// load-bearing, not belt-and-braces: the projector's H1 fetch_add
        /// (project_record's emission loop) runs AFTER the extraction lock
        /// scope closes - `mu` is not held there - so a listener supersede on
        /// a NEW event can land on another thread while an H1 suppression for
        /// the PREVIOUS snapshot is still in flight on this one. Nothing
        /// serializes the two increments against each other; the atomic RMW
        /// is what keeps that genuinely concurrent case correct.
        std::atomic<std::uint64_t> progress_suppressed_delta{0};
        /// #2528: ~ClaimGuard released the claim without `mu` and therefore could
        /// not run the settle bookkeeping normally. "Should never happen" - it
        /// needs a genuinely broken platform mutex - so any nonzero value is a
        /// signal, not a rate.
        std::atomic<std::uint64_t> projection_degraded_delta{0};
    };

    static std::string make_key(const std::string& session_id, const nlohmann::json& jsonrpc_id);
    /// Free-standing listener factory (C7/D5): captures record + wake core only.
    static ExecutionEventBus::Listener make_listener(std::shared_ptr<BridgeRecord> rec,
                                                     std::shared_ptr<WakeCore> core);
    /// #2411: replaces the old bare `wake(core)` - every caller now names WHICH
    /// record has possibly-unprojected work, so the projector can visit O(dirty)
    /// records per cycle instead of the whole table. See the .cpp definition for
    /// the lost-wakeup proof.
    static void mark_dirty(WakeCore& core, const std::string& key) noexcept;

    std::shared_ptr<BridgeRecord> find_locked(const std::string& key) const;  // holds bridge_mu_

    void run_projector();
    /// ONE projection implementation for all three armed phases. `out` is null
    /// for the projector thread (kArmedGetOnly / kRingOnly, and wake-forwarding
    /// for kStreaming); non-null only for take_post_batch, which additionally
    /// accepts kStreaming and collects the frames it just committed to the ring
    /// so the pump can write the same bytes to the live POST wire.
    ///
    /// Deliberately NOT a second function: the claim, the settle-or-restore
    /// guard, the progress watermark, the terminal ladder and the charge release
    /// all live here, and a parallel copy for the POST path would drift from
    /// this one exactly the way release_charge and project_record once did.
    void project_record(const std::shared_ptr<BridgeRecord>& rec, PostBatch* out = nullptr,
                        bool cap_expired = false);
    /// The one definition of "this record has a batch worth claiming", shared by
    /// project_record, the bind-time handshake and the projector's wake
    /// forwarding, so they cannot disagree. Caller holds `rec.mu`.
    static bool has_pending_work_locked(const BridgeRecord& rec);
    /// Wake a bound streamed-POST pump. Callers hold the record mutex; the sink
    /// mutex sits below it in the hierarchy. Contained - a missed poke costs one
    /// pump tick, never correctness.
    static void poke_post_sink(const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept;
    /// Ends a streamed response: flips `closed` UNDER the sink mutex (same
    /// lost-wakeup discipline as poke_post_sink) and notifies. Callers hold the
    /// record mutex; the record-mu -> sink-mu nesting is the sanctioned direction.
    ///
    /// Returns TRUE only if THIS call performed the false->true transition. That
    /// return value is what makes a caller's action exactly-once: a duplicate
    /// close and an undeliverable one both answer false, so a caller can never
    /// audit a detach that someone else did or that never happened.
    [[nodiscard]] static bool close_post_sink(
        const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept;
    /// Build the parked real final from the bus terminal payload + result_base (B5).
    static std::string build_real_final(const BridgeRecord& rec, const std::string& terminal_data);
    /// The ONE derivation of the minimal success-shaped fallback final ("terminal
    /// counts unavailable - fetch by execution_id"). Built by subscribe() so a
    /// record that parks BEFORE arm still has one, and rebuilt identically by
    /// arm(); every publisher of a fallback reads rec.fallback_final, so this
    /// must stay the only place its bytes are composed.
    static std::string build_fallback_final(const nlohmann::json& jsonrpc_id,
                                            const std::string& execution_id);
    /// Which rung of the publish ladder actually committed - see TerminalRung's
    /// own doc comment above BridgeRecord for what each value means. Declared
    /// there (ahead of member-function declarations that would otherwise need
    /// it) because BridgeRecord's #2513 retry fields persist a TerminalRung.
    struct LadderResult {
        std::uint64_t id = 0;  ///< committed event id; 0 ⇔ kPoisoned
        /// NOT kPoisoned: a defaulted result must not assert a poisoning either.
        TerminalRung rung = TerminalRung::kNotAttempted;
    };
    /// The publish_final → retry-fallback → poison ladder (A6). `frame` is only
    /// viewed (passed as a string_view to publish_final); the retry uses the
    /// record's fallback_final.
    /// `frame` is an RVALUE REFERENCE on purpose, so an lvalue argument does not
    /// compile. A by-value parameter copied at the CALL BOUNDARY is an allocation
    /// that happens after the caller has already decided it reached the ladder,
    /// which made a copy failure audit as "publishing threw" when the ladder was
    /// never entered. Callers must therefore own the frame first and move it in -
    /// the mistake is now a compile error rather than a mislabelled audit row that
    /// no test can distinguish (#2487 Gate 8).
    ///
    /// noexcept (#2531/#2523): both calls inside are noexcept, so a caller no
    /// longer needs its own try/catch around this call - only around building
    /// `frame` beforehand. See the static_assert at the definition, which binds
    /// this to McpStreamState's noexcept-ness at compile time.
    LadderResult publish_terminal_ladder(const std::shared_ptr<BridgeRecord>& rec,
                                         std::string&& frame) noexcept;

    /// Claimed-kDone teardown: unsubscribe, publish the decided terminal frame
    /// (kSynthesizeUnavailable = -32014 for a never-terminal victim; kFallbackFinal
    /// = success-shaped for a terminal-known-payload-lost victim; kNone = nothing),
    /// charge settle, obs transfer, erase.
    /// `rec` BY VALUE: teardown borrows a reference into the record and then drops
    /// one strong reference by erasing it from records_, so the keep-alive must be
    /// structural rather than an obligation on every call site. noexcept: it runs on
    /// the bare maintenance thread and every step is internally contained.
    void teardown_claimed(std::shared_ptr<BridgeRecord> rec, TeardownFinal decision,
                          const char* audit_action) noexcept;
    /// Release the streamed charge exactly once. Takes bridge_mu_ THEN rec->mu and
    /// commits both halves together - caller must hold neither. (It used to clear
    /// the flag first and lock second, so a lock failure desynchronised the record
    /// from the ledger permanently.)
    void release_charge(const std::shared_ptr<BridgeRecord>& rec);
    void decrement_streamed_locked(const std::string& session_id);  // holds bridge_mu_

    // ── noexcept observability (C5) ────────────────────────────────────────
    template <typename F> bool obs_guard(F&& f) noexcept;
    void count_reject(const char* reason) noexcept;
    /// #2487: a teardown step that could not complete on the maintenance thread.
    /// `stage` is a CLOSED literal set - unsubscribe | release_charge | erase.
    void count_teardown_incomplete(TeardownStage stage) noexcept;
    /// #2513: a retry pass's teardown_claimed re-entry settled (`kRecovered`) or
    /// the record hit `Config::teardown_retry_max` (`kExhausted`).
    void count_teardown_retry(TeardownRetryOutcome outcome) noexcept;
    /// #2529: a charge release deferred to teardown because its lock failed.
    void count_charge_release_deferred() noexcept;
    /// sre-N1 (#2489): one pressure-sweep forced expiry, by the disposition it
    /// decided. Called at the two pressure teardown sites rather than inside
    /// teardown_claimed, because "forced expire" is a property of the PRESSURE
    /// pass - the pin-ack / session-death / arming reap shares teardown_claimed
    /// but is not a forced expiry and must not land in this family.
    void count_forced_expire(TeardownFinal decision) noexcept;
    /// #2489 review: the pressure pass stopped on its per-invocation victim budget
    /// with the cap still exceeded. Not an error - the remaining victims roll to the
    /// next tick - but it must not be silent, or a hatch that never keeps up looks
    /// identical to one with nothing to do.
    void count_pressure_budget_exhausted() noexcept;
    /// True iff a fault is armed for `stage` (consumes one). Test seam only.
    bool take_step_fault(TeardownStage stage) noexcept;
    void publish_records_gauge(std::size_t n) noexcept;
    /// Records a pin-slot refusal, labelled by which half of the admission sum was
    /// holding the slots. Called at the reject site so it cannot drift from the
    /// expression admission actually evaluates.
    void count_pin_slots_reject(std::size_t pinned, std::size_t unpinned) noexcept;  ///< never called under bridge_mu_
    /// #2740 displacement counter. Never called under bridge_mu_ (the registry has
    /// its own mutex; the admission lock is the global one).
    void count_pin_displaced_for_admission() noexcept;
    /// #2740: the reclaim's release threw and was contained (the record is already
    /// committed by then, so the throw must not escape). The fault is LATCHED under
    /// `bridge_mu_` and this is called after it releases - never under it, like every
    /// other counter on the admission path.
    void count_pin_release_failed() noexcept;
    /// #2740 / #2795: the reclaim's release returned WITHOUT throwing and without
    /// having cleared the slot - another route (a resume ack, or a final reaching the
    /// wire) got there first. The admission still stands, so the session can sit
    /// transiently one call over its cap for the lifetime of the over-admitted call.
    ///
    /// This exists because that residual was otherwise INVISIBLE: the branch resets
    /// `displaced`, which suppresses the displacement counter, the audit row and the
    /// log line together, and it does not latch `release_failed` either. Two governance
    /// reviewers independently found that a runbook telling an operator to rule the
    /// residual out by checking the other two counters was therefore unsound - both
    /// read flat in exactly the case being ruled out. Deliberately a COUNTER and not an
    /// audit row: no exemption was released by us, so there is no loss to attribute to
    /// the admitting principal (that is why the audit is suppressed here at all).
    /// Never called under `bridge_mu_`, like every other counter on this path.
    void count_pin_release_raced() noexcept;
    /// #2740. Called from the admission path with `bridge_mu_` HELD, on the pass
    /// that would otherwise refuse `pin_slots`: NAMES a pin that may be released
    /// so a new streamed call can take its slot. **Selection only — it mutates
    /// nothing.** The caller unpins only after the admission has actually
    /// committed, so a pass that ends up rejecting anyway, or that throws on the
    /// ledger/map commit, destroys no eviction exemption and needs no rollback.
    ///
    /// Two candidate classes, orphans FIRST because they have no surviving releaser
    /// at all. One caveat on that ordering, deliberately recorded: `teardown_claimed`
    /// publishes its synthesized terminal and never stamps `pinned_event_id`, so
    /// between that publish and the record's erase a freshly-minted pin already
    /// classifies as an orphan. It is therefore reclaimable moments after minting -
    /// which is correct (nothing will ever release it once the erase lands) but
    /// means "deader" is a statement about its RELEASE ROUTES, not its age:
    ///  - an ORPHAN pin: a pinned id no live record of this session references.
    ///    The sweep's teardown erases a record WITHOUT unpinning, so these are
    ///    reachable, and no record scan can ever see them — they were the one
    ///    lockout shape that survived the first cut of this fix.
    ///  - the OLDEST PARKED record (`kRingOnly`) whose committed final no wire
    ///    took delivery of. Its resume window is the one most likely already past.
    /// The rule that admits these two and would exclude a third is TWO criteria,
    /// not one - an earlier single-sentence form ("the last path that could ever
    /// act on it") was true of orphans but false of the parked class, since a GET
    /// resume acking past a parked pin still acts on it, which is exactly why the
    /// `!released` branch in reserve exists. A candidate must satisfy either:
    ///   (i) NO SURVIVING RELEASER - no record remains that any other path could
    ///       use to release it (the orphan case); or
    ///  (ii) DEMAND-DRIVEN EXEMPTION TRANSFER - the reclaim is itself the act that
    ///       un-exempts it, the frame is RETAINED in the ring, and the result stays
    ///       durably fetchable (the parked case).
    /// Never a pin a live path still owns and will release itself.
    /// Returns nullopt when neither exists (every slot backs a live call), or
    /// when ANY of this session's records is mid-projection: the admission sum
    /// transiently counts one settling record as two slots, reserve has always
    /// failed CLOSED on that reading, and a reclaim must inherit it rather than
    /// act on a slot that was never really occupied. That claim flag is an exact
    /// discriminator — it also covers the window in which the terminal ladder has
    /// pinned a final but the bridge has not yet stamped `pinned_event_id`, which
    /// is precisely when a LIVE call's pin would look like an orphan.
    ///
    /// Deliberately under the SAME `bridge_mu_` hold as the admission decision:
    /// every sweep CLAIM takes `bridge_mu_` too, so holding it is what fences a
    /// teardown from claiming a candidate between selection and release. Note the
    /// fence covers the claim, NOT the publish: `teardown_claimed` goes on to
    /// synthesize and pin a terminal without `bridge_mu_`, so a pin can still
    /// appear underneath this scan. That is why the admission is confirmed by the
    /// release reporting success rather than by any count taken here. Lock
    /// order is the declared `bridge_mu_ -> BridgeRecord::mu -> McpStreamState::mu_`
    /// (on_final_written's order). The metric and audit row for a release are
    /// emitted by the CALLER, after the lock is dropped.
    struct DisplacedPin {
        std::string execution_id;  ///< empty for an orphan — no record survives to name it
        std::uint64_t event_id = 0;
        bool orphan = false;
    };
    /// `stream` comes from the CALLER (which already resolved it for the record it
    /// is admitting), not from a record found in the scan: the orphan case can
    /// have ZERO records left for the session, and deriving the ring from a record
    /// would make exactly that case unreachable.
    std::optional<DisplacedPin> select_displaceable_pin_locked(
        const std::string& session_id, const std::shared_ptr<McpStreamState>& stream);
    void flush_record_obs(BridgeRecord& rec) noexcept;
    void flush_core_obs() noexcept;
    /// `detail` is a string_view, NOT a `const std::string&`: every caller passes a
    /// `const char*` literal, and a `const std::string&` parameter materialises that
    /// temporary in the CALLER's frame - outside this function's obs_guard. On the
    /// teardown path that caller is the bare maintenance thread, where an escaped
    /// bad_alloc is std::terminate (#2487). The view converts without allocating;
    /// the owned string the AuditFn sink needs is built INSIDE the guard.
    /// `stage` describes what went wrong with the teardown mechanics; `disposition`
    /// describes what happened to the terminal. They are SEPARATE parameters, not one
    /// pre-joined string, because the disposition was omitted at one bail site three
    /// separate times - each fix corrected the instance and the next site drifted.
    /// Making it a parameter means a new bail site cannot forget it. The two are
    /// joined INSIDE the guard, so the join's allocation stays contained (#2487).
    void audit_contained(const char* action, const std::string& execution_id,
                         std::string_view stage, std::string_view disposition,
                         AuditResult result = AuditResult::kSuccess,
                         std::string_view actor = {}) noexcept;

    /// The ONE derivation of "what happened to the terminal", shared by every
    /// teardown bail site. Returns a static literal; never allocates.
    static const char* disposition_phrase(TeardownFinal decision, TerminalRung rung) noexcept;

    ExecutionEventBus* bus_ = nullptr;
    McpSessionRegistry* sessions_ = nullptr;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    AuditFn audit_;
    Config cfg_;

    mutable std::mutex bridge_mu_;
    bool shutdown_started_ = false;  ///< guarded by bridge_mu_ (C6 lifecycle gate)
    std::unordered_map<std::string, std::shared_ptr<BridgeRecord>> records_;
    /// Streamed records that have NOT yet pinned a final (the admission charge
    /// ledger, A5). Zero-valued entries are erased (no historical-session growth).
    std::unordered_map<std::string, std::size_t> streamed_unpinned_;
    std::uint64_t next_seq_ = 1;         ///< guarded by bridge_mu_
    std::uint64_t next_parked_seq_ = 1;  ///< guarded by bridge_mu_

    std::shared_ptr<WakeCore> core_ = std::make_shared<WakeCore>();
    std::thread projector_;
    std::atomic<bool> shutdown_called_{false};
    std::atomic<int> obs_fault_remaining_{0};  ///< C5 fault seam
    std::atomic<bool> arm_fault_{false};       ///< one-shot arm() throw seam
    std::atomic<bool> reserve_fault_{false};   ///< one-shot reserve() throw seam
    std::atomic<bool> reserve_commit_fault_{false};  ///< one-shot ledger-vs-insert window seam
    std::atomic<bool> subscribe_fault_{false}; ///< one-shot subscribe() throw seam
    std::atomic<int> visit_copy_fault_{0};     ///< remaining pressure-visit copy throws (test seam)
    std::atomic<int> claim_lock_fault_{0};     ///< remaining ~ClaimGuard lock throws (test seam)
    std::atomic<int> projection_build_fault_{0};    ///< remaining real-final build throws
    std::atomic<int> projection_fallback_fault_{0}; ///< remaining fallback-copy throws
    /// Remaining injected throws per teardown stage (test seam), indexed by
    /// TeardownStage.
    std::array<std::atomic<int>, kTeardownStageCount> teardown_step_fault_{};
    /// #2519/#3095 test seam: fired around each contained teardown step. Empty
    /// (default-constructed std::function) in production - never checked on a
    /// hot path beyond the bool test an empty std::function already supports.
    std::function<void(TeardownStage, bool)> teardown_step_probe_for_test_;
    std::atomic<int> terminal_build_fault_{0}; ///< remaining teardown frame-build throws (test seam)
    std::atomic<int> charge_lock_fault_{0};    ///< remaining release_charge lock throws (#2529 seam)
    std::atomic<int> record_entry_lock_fault_{0}; ///< remaining teardown_claimed entry-lock throws (test seam)
    ClockFn clock_;                            ///< reaper clock (default steady_clock::now)
    /// #2791 test seam: the post-ladder-publish, pre-pin-stamp stall. Distinct
    /// mutex from `bridge_mu_`/`BridgeRecord::mu` on purpose - the whole point of
    /// the seam is to park a thread in project_record while holding NEITHER, so
    /// a concurrent reserve() is not itself blocked by the stall.
    std::atomic<bool> projection_stall_armed_for_test_{false};
    std::mutex projection_stall_mu_;
    std::condition_variable projection_stall_cv_;
    bool projection_stall_reached_for_test_ = false;
    bool projection_stall_release_for_test_ = false;

    std::chrono::steady_clock::time_point now() const {
        return clock_ ? clock_() : std::chrono::steady_clock::now();
    }
};

}  // namespace yuzu::server::mcp
