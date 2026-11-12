#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type
#include "quarantine_reapply.hpp"    // ContainmentReply (the parsed firewall status/release reply)

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
/// Two triggers, one component (mirrors PreflightRunner + the Guardian
/// heartbeat reconcile, both already in this file's neighborhood):
///   * `tick()` — a background thread calls this on a cadence (server.cpp).
///     `AgentRegistry::send_to` silently drops offline agents, so a tick
///     against a still-offline device costs one cheap skip and naturally
///     catches a device that reconnected since the last tick.
///   * `notify_agent_heartbeat()` — wired via
///     `HeartbeatIngestion::set_quarantine_reconcile_fn` (heartbeat, NOT
///     `AgentServiceImpl::Register` — Register returns before the Subscribe
///     stream exists, so `send_to` would silently drop a dispatch fired from
///     there). Fast path is one mutex-guarded lookup in a cache `tick()`
///     refreshes; a miss (the overwhelming majority of heartbeats, from
///     agents with no active record) costs nothing — no store read on the
///     hot path, and NOTHING on the registration path at all (acceptance
///     criterion).
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
/// RE-VERIFY AND DRIFT. A confirmed record is re-read every `kReverifyInterval`
/// (5 minutes) while its device is connected; the record stays confirmed meanwhile
/// (the unconfirmed gauge and its alert do not blink) and the CONFIRMED audit row is
/// written once per transition, not on every re-verify. A re-verify that no longer
/// confirms is DRIFT: one `quarantine.reapply` failure row (`drift status=<name>`),
/// then the record is unconfirmed and the next cycle re-applies through the chokepoint.
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
/// THE THREE WAYS A RECORD ENDS, and no other:
///   1. The device answers `status|inactive` to a release (audit `confirmed`).
///   2. The device answers `status|inactive` on an ACTIVE record whose stored device
///      time limit has run out (audit, principal system, `ttl_expired`). The server
///      sets no limit; a limit on a device came from a dispatch outside the quarantine
///      routes, and each confirming reply stores the limit it carries. The test is
///      `now >= limit - kDeviceLimitLapseTolerance`: the device judges the limit on
///      its own clock while NTP is blocked. ACCEPTED BEHAVIOUR (Alex, 2026-11-11):
///      a limit set outside the quarantine routes can end a Security record without
///      DELETE authority; the row names `system`, and the dispatch that set the limit
///      is in the command audit.
///   3. An operator forces it with `DELETE ...?force=true` (REST only; audit names the
///      operator and `reason=forced`). The device is then OWED a release.
///
/// THE OWED-RELEASE LEG. A record ended by force before the device confirmed stays on
/// a list (`list_release_owed`) until the device does. Per agent session this component
/// reads status first (`inactive` clears the mark), then sends `firewall.release` once,
/// but only while a fresh store read shows no active record for the device (a device
/// quarantined again is governed by its new record), then reads status again; a device
/// that still does not read `inactive` is PARKED with one failure row, read status-only
/// every `kMaxBackoff`, and sent a new release only on a new session.
///
/// State: durable across restarts via `QuarantineStore::mark_endpoint_applied`/
/// `mark_endpoint_confirmed` (schema v2) and the v4 release columns; in-memory (this
/// class) for per-agent phase/in-flight-command/backoff/confirmed-session bookkeeping —
/// lost on restart. A restart therefore costs one full apply-then-verify cycle per
/// previously-confirmed active record (a fresh `AgentState` defaults `confirmed=false`),
/// except that a record whose stored device time limit has run out reads status once
/// first, so a restarted server never re-applies to a device whose limit has passed.
///
/// Concurrency: `tick()` and `notify_agent_heartbeat()` both funnel into
/// `reconcile_one()`, which claims a per-agent rate-limit slot UNDER THE
/// LOCK before any I/O (the Guardian heartbeat reconcile's claim-then-act
/// shape) — a concurrent tick and heartbeat for the same agent cannot both
/// dispatch. Store reads/dispatch calls never run WHILE the lock is held
/// (PolicyEvaluator's rule — dispatch is blocking gRPC).
///
/// Multi-replica: `reconcile_one`'s reachability check
/// (`AgentRegistry::get_session`) naturally partitions reapply work to
/// whichever replica holds the agent's live Subscribe stream — no
/// cross-replica coordination needed.
///
/// KNOWN RESIDUAL RACE, DISCLOSED NOT SILENTLY ACCEPTED (adversarial review
/// 2026-08-24, Kimi K8 / Codex CDX-P1-01): `redispatch_stored_containment`
/// reads the active row, then dispatches, with no re-validation in between —
/// a concurrent release request can commit inside that window. The dispatch
/// itself cannot be recalled once sent, so an apply read just before a DELETE can
/// land after the release; the release_pending guard and this component's
/// status-first rule make the next cycle correct it. The owed-release leg has the
/// same narrow read-then-dispatch window against a new quarantine of the same device
/// (the new record's re-verify corrects it within 5 minutes). The window is narrow (one
/// synchronous read-then-dispatch pair inside a single `reconcile_one` call, not
/// spanning any of this component's own waiting); the proper fix (a database-backed
/// claim or generation on the active row, checked by the release and the reapply path)
/// is a real schema/contract change of its own, not a same-round patch.

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
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
inline constexpr std::array<std::string_view, 13> kQuarantineReapplyResults{
    "reapplied",         // an apply or status dispatch was accepted (agents_reached > 0)
    "confirmed",         // a status read reported the device's rules in force (status|active, or active_unproven with no probe target)
    "unconfirmed",       // a status read reported anything else (partial, inactive, refused, degraded, ...)
    "busy",              // the plugin's mutation gate answered status|busy
    "offline",           // no live AgentSession — dispatch skipped entirely
    "not_reached",       // dispatched but agents_reached==0, or the response never arrived before kResponseWait
    "rate_limited",      // the per-agent claim was already held
    "pending",           // an in-flight command is still within its response-wait window
    "degraded",          // a store/response read failed
    "validation_failed", // the stored whitelist failed server-edge validation
    "dispatch_error",    // the dispatch call itself threw
    "release_sent",      // a firewall.release dispatch was accepted (releasing row, or the owed-release leg)
    "released",          // a record ended: the device answered inactive (to a release, on a lapsed time
                         // limit) or cleared a forced end's owed release
};

class QuarantineStore;
class ResponseStore;
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

    struct Deps {
        QuarantineStore* quarantine_store{nullptr};
        ResponseStore* response_store{nullptr};
        detail::AgentRegistry* registry{nullptr};
        yuzu::MetricsRegistry* metrics{nullptr};
        AuditStore* audit_store{nullptr}; // nullable — tests may omit
        CommandDispatchFn dispatch_fn;
        NowFn now_fn; // unset = system clock
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

    /// Heartbeat fast path: O(1) cache lookup; a miss (no active
    /// unconfirmed record for this agent) returns immediately with no store
    /// read. A hit calls `reconcile_one`, which shares the same per-agent
    /// rate-limit claim as `tick()` so a racing tick cannot double-dispatch.
    void notify_agent_heartbeat(std::string_view agent_id);

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
    enum class Kind { active, releasing, owed };

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
        // apply, rather than blindly re-dispatching. Also set by a due re-verify, a
        // lapsed stored time limit, and a releasing/owed entry's first cycle.
        bool verify_first{false};
        Pending pending{Pending::none};
        std::string pending_command_id;
        // #3425 governance Gate 4 (unhappy-path, Finding A): the
        // `QuarantineRecord::id` the in-flight command was actually built
        // from — carried into the eventual `mark_endpoint_applied`/
        // `mark_endpoint_confirmed` call so a release-then-requarantine race
        // that swaps in a new active row for this agent_id mid-cycle cannot
        // have the confirmation stamp land on the wrong (never-dispatched)
        // record. 0 only before the first-ever claim.
        std::int64_t pending_record_id{0};
        // The row's stored `endpoint_ttl_expires`, read at the status dispatch: it decides
        // whether an `inactive` answer is a lapsed device time limit.
        std::int64_t pending_ttl_expires{0};
        // The one status-first read for a lapsed stored limit has been done for this entry
        // (set by any status reply on an active entry).
        bool lapse_checked{false};
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

    // What reconcile_one read about an entry when it claimed it (nothing is read under
    // a lock again after the claim except to write the outcome).
    struct Claim {
        Kind kind{Kind::active};
        std::int64_t record_id{0};
        bool confirmed{false};
        bool verify_first{false};
        Pending pending{Pending::none};
        std::string pending_command_id;
        std::int64_t pending_record_id{0};
        std::int64_t pending_ttl_expires{0};
        std::string pending_session_id;
        std::chrono::steady_clock::time_point pending_since{};
        std::string owed_tried_session_id;
        bool owed_release_sent{false};
        bool owed_parked{false};
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

    // Returns true iff a dispatch_fn call was actually attempted this call
    // (regardless of its outcome) — the fair-cap signal tick() uses
    // (#3425 adversarial review K11/CDX-P1-05): rate-limited, pending-poll,
    // degraded-read, offline, and no-op transitions (confirm, busy, erase)
    // must NOT consume a tick's kMaxDispatchesPerTick budget, or a stable
    // leading cohort of skip-only agents can starve later ones from ever
    // reaching the periodic backstop.
    bool reconcile_one(const std::string& agent_id, std::string_view trigger);
    // The pieces of reconcile_one (each returns the same "a dispatch was attempted" signal).
    void handle_apply_reply(const std::string& agent_id, const ContainmentReply& reply,
                            std::chrono::steady_clock::time_point steady_now);
    void handle_release_reply(const std::string& agent_id, const ContainmentReply& reply,
                              std::chrono::steady_clock::time_point steady_now);
    void handle_status_reply(const std::string& agent_id, const Claim& c,
                             const ContainmentReply& reply,
                             std::chrono::steady_clock::time_point steady_now);
    bool send_status(const std::string& agent_id, const Claim& c);
    bool send_release(const std::string& agent_id, const Claim& c);
    bool send_apply(const std::string& agent_id, const Claim& c, std::string_view trigger);
    // Escalates the entry's backoff and holds its next claim until it elapses.
    void back_off(const std::string& agent_id, std::chrono::steady_clock::time_point steady_now);
    void count(const char* result) const;
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
    std::mutex mu_;
    std::unordered_map<std::string, AgentState> state_;
    std::unordered_set<std::string> unconfirmed_cache_; // refreshed by tick(), read by the heartbeat fast path
};

} // namespace yuzu::server
