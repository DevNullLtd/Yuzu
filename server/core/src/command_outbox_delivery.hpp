#pragma once

/// @file command_outbox_delivery.hpp
/// WS-3 slice 3.3 (ADR-2002 §6): the leader-gated delivery loop that drains the
/// `command_outbox_store` and performs the actual wire dispatch. This is the
/// "drive `pending → sent`" half of the transactional outbox — a producer
/// (`ScheduleRunner`) commits a `pending` occurrence; a crash before the wire
/// send leaves it `pending`; this loop re-drives it. Effectively-once holds
/// because every dispatch carries the occurrence's STABLE `command_id` and the
/// agent dedups on it (WS-0) — a re-drive of an already-delivered command is
/// suppressed at the endpoint, never re-executed.
///
/// THREE LOAD-BEARING RULES (an adversarial review of the plan made all three
/// binding):
///
///  R1 — NO ADR-1007 concurrency claim on delivery. This loop dispatches
///  through the PLAIN confined path (`DispatchFn` below), never the
///  concurrency-gated one. A concurrency claim keyed on `(command_id, agent_id)`
///  would, on a re-drive of the SAME stable command_id, fail-closed-exclude
///  every device that still holds the first attempt's open claim, so the
///  re-drive would read `sent=0` and be misread as "reached nobody" (and its
///  leak-release could free the live first-attempt claim). The agent's
///  command_id dedup already provides effectively-once; a re-delivered device
///  is a no-op at the endpoint, which is the correct "already delivered".
///
///  Re-authorization at SEND time — authority may have been revoked between
///  enqueue and delivery (a role dropped, a schedule re-pointed). Every
///  occurrence re-runs `arming_check(principal, plugin, action)` fresh; a denial
///  is a PERMANENT `mark_failed`, never a silent send. The caller is
///  re-resolved from the stored `principal` (never a serialized `DispatchCaller`
///  — that would re-create the #1398 provenance-forgery hazard); the approval
///  PROVENANCE that admitted the occurrence is carried on the row's
///  `approval_id` and stamped here (this loop is the declared #1398 stamping
///  site for outbox dispatch — see `dispatch_caller.hpp`'s closed list).
///
///  Fenced marks — `mark_sent` / `mark_failed` / `reschedule` embed the leader
///  epoch (read once per tick from the elector). A stale ex-leader is fenced out
///  of the state change; the row stays `pending` for the true leader (the
///  duplicate send it may already have made is absorbed by command_id dedup).
///
/// OUTCOME discrimination (fire-and-advance, matching `ScheduleRunner`'s
/// historical discipline): a systemic transient gate/directory failure
/// (`containment_unreadable` OR, WS-4 4.2b Task D, `route_unreadable` — a
/// degraded `GatewayRouteStore::lookup_routes` read; both mean "the read
/// itself could not answer", never "answered no") → `reschedule` with
/// back-off (retry, DON'T mark sent); authority revoked → `mark_failed`;
/// every other outcome — including `sent == 0` because the targeted agents
/// are offline right now — → `mark_sent`
/// (a missed occurrence is recorded and skipped, never spun into a backlog).

#include "dispatch_caller.hpp"          // DispatchCaller, ApprovalProvenance
#include "dispatch_confined_arms.hpp"   // ConfinedDispatchOutcome

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class CommandOutboxStore;
class LeaderElector;
class ExecutionTracker;
class AuditStore;
struct OutboxCommand;

class CommandOutboxDelivery {
public:
    /// The PLAIN confined dispatch (R1: NO concurrency gate) WITH a
    /// caller-supplied `command_id` — the occurrence's stable id, threaded so a
    /// re-drive reuses it and the agent dedups. server.cpp binds this to the
    /// shared `dispatch_confined` seam's `supplied_command_id` path with empty
    /// `definition_id`/`concurrency_mode` (so no ADR-1007 per-device claim runs).
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller,
        const std::string& command_id)>;

    /// Resolve the CURRENT `DispatchCaller` for a stored principal at send time
    /// (re-resolving live permissions — never a stale snapshot). server.cpp binds
    /// this to `derive_dispatch_caller_for_username`, the same resolver the
    /// operator dispatch surfaces use.
    using ResolveCallerFn = std::function<yuzu::server::DispatchCaller(const std::string& principal)>;

    /// Re-verify the principal's CURRENT authority to fire one plugin.action at
    /// send time. Fail-closed: an unset callback denies every delivery.
    using ArmingCheckFn = std::function<bool(const std::string& principal,
                                             const std::string& plugin,
                                             const std::string& action)>;

    struct Deps {
        CommandOutboxStore* outbox{nullptr};          // required
        LeaderElector* leader{nullptr};               // required — supplies the fenced epoch
        ExecutionTracker* execution_tracker{nullptr}; // optional — finalizes the exec row
        AuditStore* audit_store{nullptr};             // optional forensic sink
        yuzu::MetricsRegistry* metrics{nullptr};      // optional observability sink
        DispatchFn dispatch_fn;                        // required
        ResolveCallerFn resolve_caller;                // required
        ArmingCheckFn arming_check;                    // required (fail-closed when unset)
        // Mirrors ScheduleRunner/QuarantineContainmentReconciler: a shutdown
        // request stops the loop starting the NEXT occurrence; one already
        // in flight completes. Unset = never stop.
        std::function<bool()> should_stop;
        int max_per_tick{100};
        std::chrono::seconds retry_backoff{std::chrono::seconds(30)};
    };

    explicit CommandOutboxDelivery(Deps deps);

    /// One delivery cycle: drain up to `max_per_tick` due pending occurrences and
    /// deliver each. MUST be called only while this replica holds fenced
    /// leadership (the FencedLeaderOnly loop gate in server.cpp guarantees this);
    /// a defensive `epoch().has_value()` check bails if leadership is not held.
    void tick();

private:
    void deliver(const OutboxCommand& c, const std::string& lock_name, std::int64_t epoch);
    void audit(const OutboxCommand& c, const std::string& result, const std::string& detail);
    void count(const char* name);
    // Labeled companion to count(): the bare counter above stays a single
    // series (dashboards/alerts-in-waiting keep working unchanged), while this
    // one distinguishes WHY within it, mirroring the split this fix already
    // made for the structurally identical generic-inventory rejection
    // (gateway_service_impl.cpp's outcome="rejected_depth").
    void count_cause(const char* name, const char* cause);

    Deps d_;
};

} // namespace yuzu::server
