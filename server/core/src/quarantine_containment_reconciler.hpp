#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type
#include "quarantine_reapply.hpp"    // ContainmentReply (the parsed firewall status/release reply)
#include "quarantine_release_decision.hpp" // ReconcileKind and the pure reply tables

/// @file quarantine_containment_reconciler.hpp
/// #3425: closes the "quarantined while offline, never re-contained on
/// reconnect" gap. A `QuarantineStore` active record persists across a
/// device going offline and the #881 dispatch gate keeps refusing operator
/// commands to it — containment holds at the control plane — but nothing on
/// the reconnect path re-applies the device's OWN firewall. This component
/// is that "nothing": it re-drives `redispatch_stored_containment`
/// (`quarantine_reapply.hpp`) for every active record whose endpoint
/// containment is not yet confirmed. The endpoint is the firewall plugin:
/// `firewall.quarantine` applies, `firewall.quarantine_status` reads,
/// `firewall.release` lifts.
///
/// Two triggers, one component, one thread (mirrors PreflightRunner + the Guardian
/// heartbeat reconcile, both already in this file's neighborhood):
///   * `tick()` — the reconciler thread calls this every 20 s (server.cpp).
///     `AgentRegistry::send_to` silently drops offline agents, so a tick
///     against a still-offline device costs one cheap skip and naturally
///     catches a device that reconnected since the last tick.
///   * `notify_agent_heartbeat()` — wired via
///     `HeartbeatIngestion::set_quarantine_reconcile_fn` (heartbeat, NOT
///     `AgentServiceImpl::Register` — Register returns before the Subscribe
///     stream exists, so `send_to` would silently drop a dispatch fired from
///     there). It only MARKS the device due (#7619): one lookup in a cache
///     `tick()` refreshes and, on a hit, an insert into a set, under a small
///     mutex of its own. It reads no store, dispatches nothing and never waits
///     on a pool or a lock the reconcile work holds; a miss (the overwhelming
///     majority of heartbeats, from agents with no active record) costs one
///     hash lookup, and NOTHING touches the registration path (acceptance
///     criterion). The reconciler thread calls `drain_heartbeat_due()` every
///     second, which does the reconcile work for the devices marked since, so
///     a heartbeat-triggered reconcile starts within a second of the mark.
///
/// WHAT CONFIRMED MEANS. Confirmation is a FOLLOW-UP `firewall.quarantine_status`
/// read, never inferred from `agents_reached > 0` (dispatch acceptance is not
/// proof of endpoint containment — see `quarantine_reapply.hpp`). Confirmed means
/// the device reports its rules in force and enforcing: `status|active`, or
/// `status|active_unproven` when the reply carries no `note|probe_target=` row
/// (the server sends no probe target, so its own applies always read unproven;
/// where a probe target is stored on the device, only a verified proof confirms).
/// It is NOT a reachability proof, and the device's allow-list is NOT compared
/// with the stored whitelist: a `firewall.quarantine_allow` sent outside the
/// quarantine routes changes the device and not the record, and the record still
/// reads confirmed. Detecting that belongs with the store-updating allow surface.
///
/// A NEW RECORD ON A DEVICE THAT IS ALREADY CONTAINED. `firewall.quarantine` to a contained
/// device keeps the stored allow set and says so (`kAllowSetUnchangedNote`) when the request's
/// operator exceptions differ from the ones in force, as a set. For a record that was never
/// confirmed that note means the device is contained but NOT under this record's whitelist, so
/// the apply reply is not followed by a status read: the entry backs off, counts `unconfirmed`
/// and writes one `quarantine.reapply` failure row (`allow_set_not_applied record_id=<id>
/// command_id=<id>`, no device text). The record stays unconfirmed and
/// `YuzuQuarantineEndpointUnconfirmed` fires. This component does not make the device take the
/// whitelist (a release, then a new quarantine, does). A record that was confirmed once keeps the
/// behaviour above: later allow-list drift stays undetected (its detection is out of scope here),
/// so a re-apply after a restart or a loss of containment is confirmed by the status read.
///
/// RE-VERIFY AND DRIFT. A confirmed record is re-read every `kReverifyInterval`
/// (5 minutes) while its device is connected; the record stays confirmed meanwhile
/// (the unconfirmed gauge and its alert do not blink) and the CONFIRMED audit row is
/// written once per transition, not on every re-verify. A re-verify that no longer
/// confirms is not called drift on the reply alone (#7621): the store row is read again
/// first, because the reply may describe a record that ended or began releasing while
/// the status command was in flight. A failed read counts `degraded`, writes no row and
/// re-verifies; no row, or another record's row, drops the entry; a release requested in
/// the meantime turns the entry into a releasing one and the reply is handled as the
/// releasing reply it now is. Only a row that still reads active makes it DRIFT: one
/// `quarantine.reapply` failure row (`drift status=<name>`), counted as
/// `yuzu_server_quarantine_reapply_total{result="drift"}` (#7622), then the record is
/// unconfirmed and the next cycle re-applies through the chokepoint.
/// `YuzuQuarantineDriftRepeated` fires when that repeats.
///
/// A previously-CONFIRMED agent also re-verifies on EITHER of two independent churn
/// signals, checked separately every tick (governance re-review, Findings UP-1/UP-2):
///   * SESSION churn — live `AgentSession::session_id` no longer matches
///     `confirmed_session_id` (a reboot, a service restart — the firewall
///     rules from before the restart are gone). Re-verifies via STATUS
///     first, never a blind re-apply, so a genuinely-still-contained
///     reconnect doesn't needlessly contend with the agent-side mutation
///     gate for no reason.
///   * RECORD churn — the row's id no longer matches the id the entry was built
///     for (released, then requarantined — possibly with a different whitelist —
///     while the agent stayed connected on the same session, so session churn
///     alone would never have caught it). A status re-check would prove nothing
///     about whether the NEW record's whitelist was ever applied, so this resets
///     straight to the fresh apply path instead of routing through the
///     status-first recheck.
/// A confirm is additionally checked against the session that was live when
/// the verifying STATUS dispatch was actually SENT (`pending_session_id`),
/// not just the session live at confirm time — closes a narrow reboot
/// window between dispatch and confirm that would otherwise attribute a
/// stale session's status read to a new one.
///
/// RELEASE DRIVING. `DELETE /api/v1/quarantine/{agent_id}` stamps a release request
/// on the record (it then reads "releasing", stays listed and keeps the dispatch
/// refusal) and sends `firewall.release` itself. This component finishes what that
/// request could not: on a releasing row it reads status first (`inactive` ends the
/// record), otherwise sends `firewall.release` and reads status again. It never sends
/// a release for a row a fresh store read does not show as releasing, and no answer to
/// `firewall.release` ends anything: only the device's `status|inactive` does.
///
/// THE TWO WAYS A RECORD ENDS, and no other:
///   1. The device answers `status|inactive` to a release (audit `confirmed`).
///   2. An operator forces it with `DELETE ...?force=true` (REST only; audit names the
///      operator and `reason=forced`). The device is then OWED a release.
/// A device's `status|inactive` on an ACTIVE record ends nothing: it is drift, and the record is
/// re-applied. Nothing a device reports (a time limit, a state) ends a record the server applied.
///
/// THE OWED-RELEASE LEG. A record ended by force before the device confirmed stays on
/// a list (`list_release_owed`) until the device does. Per agent session this component
/// reads status first (`inactive` clears the mark), then sends `firewall.release` once,
/// but only while a fresh store read shows no active record for the device (a device
/// quarantined again is governed by its new record), then reads status again; a device
/// that still does not read `inactive` after a release it answered (anything but `busy`) is
/// PARKED with one failure row, read status-only every `kMaxBackoff`, and sent a new release
/// only on a new session. A `busy` answer means the device did not run the release at all (its
/// mutation gate was held), so the session's one release is not spent: the entry escalates its
/// backoff, reads status first again and sends the release again, so a gate that stays busy
/// costs at most one release and one `forced_release_sent` row per `kMaxBackoff`.
/// WHAT THIS LEG LIFTS: until the device confirms the owed release, the release lifts whatever
/// containment the device holds, including one applied directly with `firewall.quarantine` after
/// the forced end. A containment sent outside the quarantine routes is not recorded, listed,
/// re-applied or protected by this component; to keep such a device contained, quarantine it
/// again through the quarantine routes (the new record stops the owed release).
/// WHEN IT IS SENT: once per device reconnect and once per server start. The in-memory
/// bookkeeping that remembers "this session's release was sent" is not persisted, and a server
/// restart drops every device's Subscribe stream anyway (each device reconnects, a new session),
/// so a still-owed device is sent one more release after a restart, and the `forced_release_*`
/// audit rows repeat with it. A release is idempotent on the device, so persisting the bookkeeping
/// would buy nothing (#7626).
///
/// State: durable across restarts via `QuarantineStore::mark_endpoint_applied`/
/// `mark_endpoint_confirmed` (schema v2) and the v4 release columns; in-memory (this
/// class) for per-agent phase/in-flight-command/backoff/confirmed-session bookkeeping —
/// lost on restart. A restart therefore costs one full apply-then-verify cycle per
/// previously-confirmed active record (a fresh `AgentState` defaults `confirmed=false`).
///
/// Concurrency: the reconciler thread runs `tick()` and `drain_heartbeat_due()` in turn, so
/// production reconcile work is single-threaded; `notify_agent_heartbeat()` is the only entry
/// point called from other threads and it touches `cache_mu_` alone. Both funnel into
/// `reconcile_one()`, which claims a per-agent rate-limit slot UNDER `mu_` before any I/O (the
/// Guardian heartbeat reconcile's claim-then-act shape), so a second caller (a test, a future
/// second thread) for the same agent cannot also dispatch. Store reads and dispatch calls never run
/// WHILE either mutex is held (PolicyEvaluator's rule: dispatch is blocking gRPC), and the two
/// mutexes are never held together. After the claim a pass works from a COPY of the entry, and every
/// write back goes through `entry_for`, which hands the live entry out only while its kind and
/// record id still equal the copy's. An entry reset in the meantime (a `tick()` run from inside the
/// pass's own dispatch, a release requested, a requarantine) therefore drops the pass's result
/// instead of overwriting the new entry's flags and backoff (#7620, #7645); audit rows for facts
/// that did happen are still written.
///
/// Multi-replica: `reconcile_one`'s reachability check
/// (`AgentRegistry::get_session`) naturally partitions reapply work to
/// whichever replica holds the agent's live Subscribe stream — no
/// cross-replica coordination needed.
///
/// THE APPLY FENCE, WHAT IT CLOSES AND WHAT IT DOES NOT (#7613; the store side is in
/// `quarantine_store.hpp`, the chokepoint side in `quarantine_reapply.hpp`). A record ends on the
/// device's `inactive` answer, and an apply that reaches the device after the observation that
/// produced that answer would leave the device contained with no record and nothing owed. The rule:
///   * `redispatch_stored_containment` claims the apply first (`claim_apply` moves the record's
///     `apply_gen` and stamps a claim). A dispatch that returned is not a delivery and a delivered
///     command is not a run (the agent runs commands on a thread pool, in the order its workers
///     reach the plugin's gate), so a dispatch that reached an agent KEEPS the claim: it is dropped
///     when the apply's terminal reply is consumed (`release_held_claim`), and otherwise it expires
///     after `kApplyClaimTtlSecs`. While it is live the token is empty, so a confirmed end fails
///     closed, whether it rests on a release's `inactive` answer or on a status read. A dispatch
///     that threw or reached nobody drops it at once. The generation outlives the claim.
///   * Whoever will act on an `inactive` answer reads `apply_fence_token` BEFORE it sends the
///     command whose answer it will use: `send_status` here (stored as `pending_fence` beside the
///     command id), DELETE after `request_release` and before its `firewall.release`. The token is
///     empty while a claim is live.
///   * The write that ends the record (`mark_released(device_confirmed)`, `clear_release_owed`)
///     presents the token and the store checks it in the same guarded UPDATE: an apply claimed after
///     the token was read refuses the end (`apply_in_flight`). An apply claimed before it had left
///     the server before the observing command was sent, so that command is queued behind it, and
///     its claim stays live until its reply is consumed, so no token is issued while it may still
///     be waiting to run.
///   * A refused end backs off and re-reads: the next status read takes a fresh token and settles it.
///     `send_release` reads no token, because no answer to a release ends a record here.
/// Residuals, stated plainly: (1) the rule assumes commands to one device arrive in the order one
/// server dispatched them (one stream, a first-in first-out gateway queue); a transport that
/// reorders them, or an apply and a release dispatched by two different server replicas, can still
/// reopen the window. (2) A claim older than `kApplyClaimTtlSecs` (120 s) is ignored, so an apply that stays
/// unexecuted longer than that reopens it. (3) DELETE's own release has a check-then-dispatch window
/// against a re-quarantine of the device, as does the owed-release leg; the new record's re-verify
/// corrects either within 5 minutes. (4) The same outcome follows when a release sent earlier is run
/// by the device after a later record's apply, for the same ordering reason: the new record can be
/// confirmed and the device then released, uncontained until the re-verify re-applies it (up to 5
/// minutes).

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Closed label set for `yuzu_server_quarantine_reapply_total{result}`,
/// pre-seeded at boot (server.cpp) so `absent()` on any value can never be
/// confused with "the reconciler has never ticked" (the `kQuarantineGateOutcomes`
/// discipline, `dispatch_confined_arms.hpp`). Several values have more than
/// one `count(...)` call site in `quarantine_containment_reconciler.cpp` —
/// e.g. `degraded` and `not_reached` are each reachable from multiple
/// distinct failure branches — but every site for a given value emits the
/// same semantic outcome, and the SET itself stays closed/exhaustive (grep
/// `count("` to enumerate).
inline constexpr std::array<std::string_view, 14> kQuarantineReapplyResults{
    "reapplied",         // an apply or status dispatch was accepted (agents_reached > 0)
    "confirmed",         // a status read reported the device's rules in force (status|active, or active_unproven with no probe target)
    "unconfirmed",       // a status read reported anything else (partial, refused, degraded, ...) for a record
                         // not yet confirmed, or an apply reply said the device kept other exceptions
    "drift",             // a confirmed record's device no longer reports its rules in force (the store row
                         // was re-read and still reads active); the record is re-applied next cycle
    "busy",              // the plugin's mutation gate answered status|busy
    "offline",           // no live AgentSession — dispatch skipped entirely
    "not_reached",       // dispatched but agents_reached==0, or the response never arrived before kResponseWait
    "rate_limited",      // the per-agent claim was already held
    "pending",           // an in-flight command is still within its response-wait window
    "degraded",          // a store/response read failed
    "validation_failed", // the stored whitelist failed server-edge validation
    "dispatch_error",    // the dispatch call itself threw
    "release_sent",      // a firewall.release dispatch was accepted (releasing row, or the owed-release leg)
    "released",          // a record ended: the device answered inactive to a release, or cleared a
                         // forced end's owed release
};

class QuarantineStore;
class ResponseStore;
struct StoredResponse; // response_store.hpp
class AuditStore;

namespace detail {
class AgentRegistry;
}

class QuarantineContainmentReconciler {
public:
    /// Same 6-param shape as the shared `command_dispatch_fn`
    /// (`server.cpp`) / `PreflightRunner::CommandDispatchFn` — background
    /// dispatch, no per-caller identity (system-attributed inside the
    /// wired lambda).
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// Epoch-seconds clock, injectable for tests.
    using NowFn = std::function<std::int64_t()>;
    /// Monotonic clock for every backoff, claim and wait deadline, injectable for tests (#7583):
    /// a test advances it instead of sleeping.
    using SteadyNowFn = std::function<std::chrono::steady_clock::time_point()>;

    struct Deps {
        QuarantineStore* quarantine_store{nullptr};
        ResponseStore* response_store{nullptr};
        detail::AgentRegistry* registry{nullptr};
        yuzu::MetricsRegistry* metrics{nullptr};
        AuditStore* audit_store{nullptr}; // nullable — tests may omit
        CommandDispatchFn dispatch_fn;
        NowFn now_fn; // unset = system clock
        SteadyNowFn steady_now_fn; // unset = std::chrono::steady_clock::now()
        // governance Gate 5 (chaos-injector, Finding 4b): tick()'s reconcile
        // loop had NO interior cancellation check — once started, a single
        // tick() call could sequentially work through up to
        // kMaxDispatchesPerTick agents' worth of store/dispatch I/O with no
        // way to interrupt it, compounding with the thread-join step in
        // ServerImpl::stop() ahead of it. Checked once per loop iteration
        // (not mid-reconcile_one — an in-flight per-agent I/O sequence still
        // completes cleanly, this only stops the loop from STARTING another
        // one). Unset (default) = never stop, matching every existing
        // production/test Deps that predates this field.
        std::function<bool()> should_stop;
        // Timing overrides — tests only. Defaults (0) mean "use the
        // production constant" (kMinReapplyInterval/kResponseWait/
        // kVerifyGrace below); a non-zero override lets a test drive the
        // full apply -> poll -> status -> confirm state machine in
        // milliseconds instead of real minutes without touching production
        // behavior (every production Deps leaves these at 0).
        std::chrono::milliseconds min_reapply_interval_override{0};
        std::chrono::milliseconds response_wait_override{0};
        std::chrono::milliseconds verify_grace_override{0};
        std::chrono::milliseconds reverify_interval_override{0};
        std::chrono::milliseconds max_backoff_override{0};
    };

    explicit QuarantineContainmentReconciler(Deps deps);

    /// Pre-seeds the reconciler's metric series at 0 across their closed label sets, so an alert
    /// can use `absent()` and an idle server reads as an explicit 0 (server.cpp calls this once at
    /// boot; a test calls it on its own registry). The last-tick gauge starts at the current time.
    static void seed_metrics(yuzu::MetricsRegistry& metrics);

    /// One scheduler cycle. Safe to call from a single background thread.
    /// Lists active records (releasing ones included) and the records ended by
    /// force that still owe their device a release, GCs per-agent state for
    /// anything gone since the last tick, detects session churn and a due
    /// re-verify on previously-confirmed agents, publishes the divergence and
    /// release gauges, refreshes the cache `notify_agent_heartbeat` reads, then
    /// reconciles up to `kMaxDispatchesPerTick` agents — checking
    /// `Deps::should_stop` once per agent so a shutdown request bounds how many
    /// more it starts. A failed owed read counts `degraded`, skips owed work for
    /// this tick and keeps the owed entries; a degraded ACTIVE read still fails
    /// closed.
    void tick();

    /// Heartbeat fast path (#7619): marks the device due and returns. O(1) cache lookup under
    /// `cache_mu_`; a miss (no record needing work for this agent) returns with nothing recorded.
    /// No store read, no dispatch, no `mu_`: heartbeat ingest never waits on reconcile work.
    void notify_agent_heartbeat(std::string_view agent_id);

    /// Does the reconcile work for the devices `notify_agent_heartbeat` marked since the last call
    /// (the set is moved out and cleared first), through the same `reconcile_one` and per-agent
    /// claim as `tick()`. Called every second by the reconciler thread. Checks `Deps::should_stop`
    /// once per device and stops after `kMaxDispatchesPerTick` dispatch attempts or once
    /// `kDrainTimeBudget` has passed since it started, whichever comes first (the rest stay
    /// marked). The time bound is what holds when the store stalls: a degraded read is not a
    /// dispatch attempt and costs up to a store read timeout per device. Returns the number of
    /// dispatch attempts.
    std::size_t drain_heartbeat_due();

    /// #3425 governance correction round (cpp-safety SHOULD + unhappy-path
    /// UP-1, independently converged): call from the tick-thread's outer
    /// catch (`server.cpp`) on ANY exception `tick()` propagates — whether
    /// before the read (never wired, degraded), or after the success-path
    /// publish, from the per-record `reconcile_one` dispatch loop (Gate 8
    /// re-review, docs-writer + security-guardian, independently converged:
    /// an earlier draft of this comment overclaimed "before reaching any
    /// publish_tick_health() call site", which the dispatch-loop case
    /// disproves — the gauge correctly reads unhealthy either way, this was
    /// a wording-only imprecision). Without this, an exception mid-tick (a
    /// PG/gRPC boundary throw) leaves the freshness gauge frozen at its last
    /// value — exactly the outage class it exists to expose, and silently,
    /// since the outer catch only logs. Its own body must not itself throw
    /// (Gate 8, cpp-safety SHOULD + cpp-expert INFO, independently
    /// converged): it runs from inside a catch block nothing else catches.
    void on_tick_exception() const;

private:
    enum class Pending { none, apply, release, status };
    // What the row behind an entry is: an active record, one with a release requested
    // (the store reads it "releasing"), or one ended by force that still owes the device
    // a release.
    using Kind = ReconcileKind;

    struct AgentState {
        Kind kind{Kind::active};
        // The `QuarantineRecord::id` this entry belongs to (set by tick()); a row whose id
        // differs is RECORD churn and resets the entry. 0 until tick() has seen the row.
        std::int64_t record_id{0};
        bool confirmed{false};
        std::string confirmed_session_id;
        // When the latest confirm landed: a confirmed entry older than the re-verify
        // interval is re-read without clearing `confirmed`.
        std::chrono::steady_clock::time_point confirmed_at{};
        // Set on session-churn detection (tick()): the next reconcile_one
        // call verifies via `firewall.quarantine_status` before considering a fresh
        // apply, rather than blindly re-dispatching. Also set by a due re-verify and a
        // releasing/owed entry's first cycle.
        bool verify_first{false};
        Pending pending{Pending::none};
        std::string pending_command_id;
        // #7613: the apply generation read BEFORE the in-flight status command was dispatched, for
        // every kind (empty while an apply's claim was live, or never read). The write that ends a
        // record on this command's `inactive` answer presents it; the store refuses the end when an
        // apply was claimed since.
        std::optional<std::int64_t> pending_fence;
        // #3425 governance Gate 4 (unhappy-path, Finding A): the
        // `QuarantineRecord::id` the in-flight command was actually built
        // from — carried into the eventual `mark_endpoint_applied`/
        // `mark_endpoint_confirmed` call so a release-then-requarantine race
        // that swaps in a new active row for this agent_id mid-cycle cannot
        // have the confirmation stamp land on the wrong (never-dispatched)
        // record. 0 only before the first-ever claim.
        std::int64_t pending_record_id{0};
        // The apply claim this entry's last apply still holds (`ContainmentReapplyResult::
        // held_claim_gen`), `gen` 0 for none, with the record and command it belongs to. It is dropped
        // when that apply's terminal reply is consumed (`release_held_claim`), by the in-flight
        // poll or, after a release request has turned the entry into a releasing one,
        // by `reconcile_one`'s own look at the command. `reset_for` keeps this whole struct: a
        // reset must not strand a claim whose apply may not have run yet. An apply that never
        // answers leaves the claim to expire after `kApplyClaimTtlSecs`.
        struct HeldClaim {
            std::int64_t gen{0};
            std::int64_t record_id{0};
            std::string command_id;
        } held_claim;
        // The in-flight apply is for a record that was never confirmed (`last_confirmed_at == 0`
        // when it was sent): a reply saying the device kept other operator exceptions then
        // leaves the record unconfirmed instead of being followed by a status read.
        bool apply_for_unconfirmed{false};
        // The `allow_set_not_applied` failure row has been written for this entry (one per entry,
        // not one per re-apply cycle).
        bool allow_set_reported{false};
        // #3425 governance re-review (unhappy-path, Finding UP-2): the live
        // `AgentSession::session_id` at the moment the verify status
        // dispatch was SENT — compared against the CURRENT session
        // at confirm time. Without this, a reboot landing between dispatch
        // and confirm lets a status response that describes the OLD
        // session's (possibly already-gone) firewall state get attributed to
        // the NEW session, stamping "confirmed" on evidence that was never
        // actually about the session now live.
        std::string pending_session_id;
        // Owed entries: the session in which this component sent the owed release, and
        // whether the device was then parked (still not inactive after that release).
        std::string owed_tried_session_id;
        bool owed_release_sent{false};
        bool owed_parked{false};
        // Releasing entries (#7625): the `release_sent` audit row is written once per agent session,
        // not once per cycle; the counter still counts every dispatch. The bool is needed beside the
        // id because a session id can be empty (an agent registered with no mapped session), and ""
        // must not read as "already audited" or the first release_sent row would be skipped.
        bool release_audited{false};
        std::string release_audited_session_id;
        std::chrono::steady_clock::time_point pending_since{};
        std::chrono::steady_clock::time_point next_eligible_at{};
        // Zero = "never claimed yet" — reconcile_one initializes it to
        // min_reapply_interval() on first claim (can't use a class-scope
        // default member initializer since the interval may be overridden
        // per-instance via Deps). Milliseconds, not seconds: the test
        // override in Deps is millisecond-granularity so a test can drive
        // the state machine in well under a second, and truncating through
        // seconds here would silently floor any sub-second override to 0.
        std::chrono::milliseconds backoff{0};
    };

    // Steady-clock-facing constants, expressed in milliseconds so a test
    // override (Deps, also milliseconds) composes without a lossy
    // seconds-truncation step. Production values are unchanged (60s/900s/
    // 60s/15s) — only the representation is finer-grained.
    static constexpr std::chrono::milliseconds kMinReapplyInterval{60'000};
    static constexpr std::chrono::milliseconds kMaxBackoff{900'000};
    static constexpr std::chrono::milliseconds kResponseWait{60'000};
    static constexpr std::chrono::milliseconds kVerifyGrace{15'000};
    static constexpr std::chrono::milliseconds kReverifyInterval{300'000};
    static constexpr std::size_t kMaxDispatchesPerTick = 50;
    // One drain pass stops starting devices after this long: about one store read timeout (the
    // store's own 2 s), so a stalled pool costs the thread one timeout, not one per marked device.
    static constexpr std::chrono::milliseconds kDrainTimeBudget{2'000};

    // Returns true iff a dispatch_fn call was actually attempted this call
    // (regardless of its outcome) — the fair-cap signal tick() uses
    // (#3425 adversarial review K11/CDX-P1-05): rate-limited, pending-poll,
    // degraded-read, offline, and no-op transitions (confirm, busy, erase)
    // must NOT consume a tick's kMaxDispatchesPerTick budget, or a stable
    // leading cohort of skip-only agents can starve later ones from ever
    // reaching the periodic backstop.
    bool reconcile_one(const std::string& agent_id, std::string_view trigger);
    // The pieces of reconcile_one. `c` is the copy of the entry taken under `mu_` when the entry
    // was claimed (nothing is read under a lock again after the claim except to write the
    // outcome). The send_* pieces return the same "a dispatch was attempted" signal.
    void handle_mutation_reply(const std::string& agent_id, const AgentState& c,
                               const ContainmentReply& reply,
                               std::chrono::steady_clock::time_point now_steady);
    void handle_status_reply(const std::string& agent_id, const AgentState& c,
                             const ContainmentReply& reply,
                             std::chrono::steady_clock::time_point now_steady);
    bool send_status(const std::string& agent_id, const AgentState& c);
    bool send_release(const std::string& agent_id, const AgentState& c);
    bool send_apply(const std::string& agent_id, const AgentState& c, std::string_view trigger);
    // Dispatches one parameterless firewall containment action to one agent. Returns the command
    // id when an agent was reached; counts `dispatch_error` when the dispatch threw and
    // `not_reached` when it reached nobody (both "a dispatch was attempted").
    std::optional<std::string> dispatch_bare(const std::string& agent_id, std::string_view action);
    // The only reset of an entry: a fresh AgentState for `record_id`, a releasing or owed one reading
    // status before it dispatches anything. Used at every site that starts an entry over.
    static void reset_for(AgentState& st, Kind kind, std::int64_t record_id);

    /// Drops the apply claim the in-flight apply holds, once its terminal reply has been consumed.
    /// A failed drop leaves the claim to expire (it only delays a confirmed end).
    void release_held_claim(const std::string& agent_id, const AgentState& c);

    /// The stored replies to one of our own commands (nullopt: the store is unreadable or absent).
    /// The only response-store read the reconciler makes, so the read-site tripwire stays at one.
    [[nodiscard]] std::optional<std::vector<StoredResponse>>
    poll_command(const std::string& pending_command_id, const std::string& agent_id) const;
    // The live entry for `agent_id` when its kind and record id still equal `c`'s (the copy a pass
    // took at its claim), else nullptr: the entry was reset, replaced or removed since, and the
    // pass's result is dropped. The caller holds `mu_`, and the pointer is valid only while it does.
    [[nodiscard]] AgentState* entry_for(const std::string& agent_id, const AgentState& c);
    // Escalates the entry's backoff and holds its next claim until it elapses (dropped when the
    // entry is no longer the one `c` was copied from). `reverify` also sets verify_first under the
    // same lock, so the next cycle reads status before it dispatches anything.
    void back_off(const std::string& agent_id, const AgentState& c,
                  std::chrono::steady_clock::time_point now_steady, bool reverify = false);
    // Erases the entry only while it is still the one `c` was copied from (dropped otherwise).
    // Takes `mu_` itself: never call it with `mu_` held.
    void erase_if_current(const std::string& agent_id, const AgentState& c);
    void count(const char* result) const;
    [[nodiscard]] std::chrono::steady_clock::time_point steady_now() const;
    // Stamps yuzu_server_quarantine_reconciler_last_tick_unixtime: tick() reached its end (#7623).
    void stamp_last_tick() const;
    // #3425 review (Doomgoose, #3567): freshness signal for
    // yuzu_server_quarantine_endpoint_unconfirmed — see tick()'s call sites.
    void publish_tick_health(bool healthy) const;
    void audit_event(const std::string& agent_id, const std::string& detail, const char* result,
                     const char* action = "quarantine.reapply") const;
    // record_id (governance Gate 6, compliance-officer Finding 2): the
    // QuarantineRecord::id this reapply cycle was built from, threaded into
    // the audit detail string so a release-then-requarantine race for the
    // same agent_id leaves an unambiguous trail across the two episodes —
    // the store-level write is already scoped by id (Gate 4 Finding A); the
    // audit row now carries the same key rather than only agent_id + wall
    // clock ordering.
    void audit_reapply(const std::string& agent_id, std::int64_t record_id,
                       const std::string& command_id, std::string_view trigger) const;
    void audit_confirmed(const std::string& agent_id, std::int64_t record_id,
                         const std::string& command_id) const;
    // #3425 governance Gate 2 (security-guardian): the observable agent-facing
    // action named by `what` already happened (dispatch accepted / status read
    // confirmed status|active) even though the durable stamp write failed — this
    // records that fact with result="failure" so a transient store outage never
    // produces a silent audit gap. See the two call sites for the full rationale.
    void audit_unstamped(const std::string& agent_id, std::int64_t record_id,
                         const std::string& command_id, std::string_view what,
                         const std::string& store_error,
                         const char* action = "quarantine.reapply") const;
    [[nodiscard]] std::int64_t now_epoch() const;
    [[nodiscard]] std::chrono::milliseconds min_reapply_interval() const;
    [[nodiscard]] std::chrono::milliseconds response_wait() const;
    [[nodiscard]] std::chrono::milliseconds verify_grace() const;
    [[nodiscard]] std::chrono::milliseconds reverify_interval() const;
    [[nodiscard]] std::chrono::milliseconds max_backoff() const;

    Deps d_;
    std::mutex mu_; // guards state_
    std::unordered_map<std::string, AgentState> state_;
    // The heartbeat fast path's own mutex (#7619), never held together with mu_: tick() swaps the
    // cache in, notify_agent_heartbeat() reads it and marks devices due, drain_heartbeat_due() takes
    // the marks.
    std::mutex cache_mu_;
    // Looked up by string_view from the heartbeat path, so it hashes and compares transparently.
    struct StringViewHash {
        using is_transparent = void;
        std::size_t operator()(std::string_view s) const noexcept {
            return std::hash<std::string_view>{}(s);
        }
    };
    using IdSet = std::unordered_set<std::string, StringViewHash, std::equal_to<>>;
    IdSet unconfirmed_cache_;                       // refreshed by tick()
    std::unordered_set<std::string> heartbeat_due_; // marked by heartbeats, drained every second
};

} // namespace yuzu::server
