#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file quarantine_containment_reconciler.hpp
/// #3425: closes the "quarantined while offline, never re-contained on
/// reconnect" gap. A `QuarantineStore` active record persists across a
/// device going offline and the #881 dispatch gate keeps refusing operator
/// commands to it — containment holds at the control plane — but nothing on
/// the reconnect path re-applies the device's OWN firewall. This component
/// is that "nothing": it re-drives `redispatch_stored_containment`
/// (`quarantine_reapply.hpp`) for every active record whose endpoint
/// containment is not yet confirmed.
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
/// Confirmation is a FOLLOW-UP `quarantine.status` read, never inferred from
/// `agents_reached > 0` (dispatch acceptance is not proof of endpoint
/// containment — see `quarantine_reapply.hpp`). A previously-CONFIRMED
/// agent re-verifies on EITHER of two independent churn signals, checked
/// separately every tick (governance re-review, Findings UP-1/UP-2):
///   * SESSION churn — live `AgentSession::session_id` no longer matches
///     `confirmed_session_id` (a reboot, a service restart — the firewall
///     rules from before the restart are gone). Re-verifies via STATUS
///     first, never a blind re-apply, so a genuinely-still-contained
///     reconnect doesn't needlessly contend with the agent-side mutation
///     gate for no reason.
///   * RECORD churn — the active row's id no longer matches
///     `confirmed_record_id` (released, then requarantined — possibly with
///     a different whitelist — while the agent stayed connected on the same
///     session, so session churn alone would never have caught it). A
///     status re-check would prove nothing about whether the NEW record's
///     whitelist was ever applied, so this resets straight to the fresh
///     apply path instead of routing through the status-first recheck.
/// A confirm is additionally checked against the session that was live when
/// the verifying STATUS dispatch was actually SENT (`pending_session_id`),
/// not just the session live at confirm time — closes a narrow reboot
/// window between dispatch and confirm that would otherwise attribute a
/// stale session's status read to a new one.
///
/// State: durable across restarts via `QuarantineStore::mark_endpoint_applied`/
/// `mark_endpoint_confirmed` (schema v2); in-memory (this class) for
/// per-agent phase/in-flight-command/backoff/confirmed-session bookkeeping —
/// lost on restart. A restart therefore costs one full apply-then-verify
/// cycle per previously-confirmed active record, NOT merely a redundant
/// verify: a fresh `AgentState` defaults `confirmed=false`, so the record
/// re-enters via the normal apply path, not the cheaper `verify_first`
/// status-only path (`last_confirmed_at != 0` is available in the store for
/// a future caller that wants to skip straight to a status-only verify on
/// restart; this component does not read it back today, so it does not).
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
/// a concurrent `release_device` can commit inside that window. The dispatch
/// itself cannot be recalled once sent, so a device released at the exact
/// moment the reconciler is mid-apply can end up firewalled with no active
/// `QuarantineStore` record naming it (the store-side bookkeeping now stays
/// honest either way — see the `mark_endpoint_applied`/`mark_endpoint_confirmed`
/// result-checking below — but the already-sent endpoint action is not
/// itself undone). The window is narrow (one synchronous read-then-dispatch
/// pair inside a single `reconcile_one` call, not spanning any of this
/// component's own waiting) and `release_device` is an infrequent, deliberate
/// operator action, so this ships as a disclosed, tracked limitation rather
/// than a merge-blocking defect — the proper fix (a database-backed claim or
/// generation on the active row, checked by both `release_device` and the
/// reapply path) is a real schema/contract change of its own, not a
/// same-round patch. Track as a follow-up before relying on this component
/// as a complete substitute for auditing release-vs-reapply interleavings by
/// hand on a high-value target.

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
inline constexpr std::array<std::string_view, 11> kQuarantineReapplyResults{
    "reapplied",         // an apply or status dispatch was accepted (agents_reached > 0)
    "confirmed",         // a status read reported state|active
    "unconfirmed",       // a status read reported anything else recognized (partial/inactive/uncertain/degraded)
    "busy",              // the plugin's mutation gate answered status|busy
    "offline",           // no live AgentSession — dispatch skipped entirely
    "not_reached",       // dispatched but agents_reached==0, or the response never arrived before kResponseWait
    "rate_limited",      // the per-agent claim was already held
    "pending",           // an in-flight command is still within its response-wait window
    "degraded",          // a store/response read failed
    "validation_failed", // the stored whitelist failed server-edge validation
    "dispatch_error",    // the dispatch call itself threw
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
    };

    explicit QuarantineContainmentReconciler(Deps deps);

    /// One scheduler cycle. Safe to call from a single background thread.
    /// Lists active records, GCs per-agent state for anything released
    /// since the last tick, detects session churn on previously-confirmed
    /// agents, publishes the divergence gauge, refreshes the cache
    /// `notify_agent_heartbeat` reads, then reconciles up to
    /// `kMaxDispatchesPerTick` unconfirmed agents — checking `Deps::should_stop`
    /// once per agent so a shutdown request bounds how many more it starts.
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
    enum class Pending { none, apply, status };

    struct AgentState {
        bool confirmed{false};
        std::string confirmed_session_id;
        // #3425 governance re-review (unhappy-path, Finding UP-1): the
        // `QuarantineRecord::id` this `confirmed` flag was actually earned
        // against. tick()'s per-agent GC only erases an entry when the
        // agent_id itself leaves the active set — a release-then-requarantine
        // of the SAME agent_id (a normal whitelist-update workflow) swaps in
        // a new active row without ever removing the map entry, so a
        // confirmed-flag keyed on agent_id alone survives untouched and the
        // NEW record is silently treated as already-contained, forever,
        // until the agent's session happens to churn too. Session churn
        // (below) and record churn are independent events; tick() checks
        // both.
        std::int64_t confirmed_record_id{0};
        // Set on session-churn detection (tick()): the next reconcile_one
        // call verifies via `quarantine.status` before considering a fresh
        // apply, rather than blindly re-dispatching.
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
        // #3425 governance re-review (unhappy-path, Finding UP-2): the live
        // `AgentSession::session_id` at the moment the verify `quarantine.
        // status` dispatch was SENT — compared against the CURRENT session
        // at confirm time. Without this, a reboot landing between dispatch
        // and confirm lets a status response that describes the OLD
        // session's (possibly already-gone) firewall state get attributed to
        // the NEW session, stamping "confirmed" on evidence that was never
        // actually about the session now live.
        std::string pending_session_id;
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
    static constexpr std::size_t kMaxDispatchesPerTick = 50;

    // Returns true iff a dispatch_fn call was actually attempted this call
    // (regardless of its outcome) — the fair-cap signal tick() uses
    // (#3425 adversarial review K11/CDX-P1-05): rate-limited, pending-poll,
    // degraded-read, offline, and no-op transitions (confirm, busy, erase)
    // must NOT consume a tick's kMaxDispatchesPerTick budget, or a stable
    // leading cohort of skip-only agents can starve later ones from ever
    // reaching the periodic backstop.
    bool reconcile_one(const std::string& agent_id, std::string_view trigger);
    void count(const char* result) const;
    // #3425 review (Doomgoose, #3567): freshness signal for
    // yuzu_server_quarantine_endpoint_unconfirmed — see tick()'s call sites.
    void publish_tick_health(bool healthy) const;
    void audit_event(const std::string& agent_id, const std::string& detail,
                     const char* result) const;
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
    // confirmed state|active) even though the durable stamp write failed — this
    // records that fact with result="failure" so a transient store outage never
    // produces a silent audit gap. See the two call sites for the full rationale.
    void audit_unstamped(const std::string& agent_id, std::int64_t record_id,
                         const std::string& command_id, std::string_view what,
                         const std::string& store_error) const;
    [[nodiscard]] std::int64_t now_epoch() const;
    [[nodiscard]] std::chrono::milliseconds min_reapply_interval() const;
    [[nodiscard]] std::chrono::milliseconds response_wait() const;
    [[nodiscard]] std::chrono::milliseconds verify_grace() const;

    Deps d_;
    std::mutex mu_;
    std::unordered_map<std::string, AgentState> state_;
    std::unordered_set<std::string> unconfirmed_cache_; // refreshed by tick(), read by the heartbeat fast path
};

} // namespace yuzu::server
