#include "command_outbox_delivery.hpp"

#include "audit_store.hpp"
#include "command_outbox_store.hpp"
#include "execution_tracker.hpp"
#include "leader_elector.hpp" // kServerBackgroundLeaderLock, LeaderElector::epoch()
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <exception>

namespace yuzu::server {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Decode the opaque producer-serialized payload the outbox round-trips: a JSON
// array of agent ids and a JSON object of scalar parameters (exactly what
// ScheduleRunner stores — `s.parameter_values` is already canonical JSON, and
// agent id lists are dumped as a JSON array). Returns false on malformed JSON so
// the caller fails the occurrence closed rather than dispatching with a
// silently-empty target/param set.
bool decode_payload(const OutboxCommand& c, std::vector<std::string>& agent_ids,
                    std::unordered_map<std::string, std::string>& params) {
    try {
        if (!c.agent_ids.empty()) {
            auto arr = nlohmann::json::parse(c.agent_ids);
            if (!arr.is_array())
                return false;
            for (const auto& e : arr) {
                if (!e.is_string())
                    return false;
                agent_ids.push_back(e.get<std::string>());
            }
        }
        if (!c.parameters.empty()) {
            auto obj = nlohmann::json::parse(c.parameters);
            if (!obj.is_object())
                return false;
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                params[it.key()] = it.value().is_string() ? it.value().get<std::string>()
                                                          : it.value().dump();
            }
        }
    } catch (const nlohmann::json::exception&) {
        return false;
    }
    return true;
}

} // namespace

CommandOutboxDelivery::CommandOutboxDelivery(Deps deps) : d_(std::move(deps)) {
    // Post-merge review #4344 follow-up (MEDIUM finding 2, docs/observability-conventions.md):
    // pre-seed both `cause` values `yuzu_server_command_outbox_deliver_retry_cause_total` can
    // actually emit (see the increment call site below). Lazy-created-on-first-increment means a
    // single isolated incident never crosses `rate()>0`/`increase()>0` — the first sample IS the
    // incident, with no second sample in the window to diff against — so the alert this counter
    // backs (`YuzuGatewayRouteUnreadable`, docs/prometheus/yuzu-alerts.yml) would stay silent on
    // exactly the lone-incident case it exists to catch. Mirrors the desync/write-failed counter
    // pre-seed pattern in gateway_service_impl.cpp's constructor.
    if (d_.metrics) {
        d_.metrics->describe(
            "yuzu_server_command_outbox_deliver_retry_cause_total",
            "HA WS-4 4.2b Task D: additive breakdown, by `cause`, of the command outbox "
            "delivery loop's retry decision when a systemic per-tick gate degrades instead of "
            "answering - `containment_unreadable` (quarantine/containment read) or "
            "`route_unreadable` (GatewayRouteStore directory read). Either cause reschedules the "
            "WHOLE occurrence with back-off, even when some sends already succeeded.",
            "counter");
        d_.metrics->counter("yuzu_server_command_outbox_deliver_retry_cause_total",
                            {{"cause", "containment_unreadable"}});
        d_.metrics->counter("yuzu_server_command_outbox_deliver_retry_cause_total",
                            {{"cause", "route_unreadable"}});
        // json-dump-depth-guard fix: the bare
        // yuzu_server_command_outbox_deliver_decode_failed_total counter stays
        // unchanged (dashboards/alerts-in-waiting keep working), but it now
        // fires for two structurally different causes - pre-seed the labeled
        // companion the same way, for the same lone-incident reason above.
        d_.metrics->describe(
            "yuzu_server_command_outbox_deliver_decode_failed_cause_total",
            "Additive breakdown, by `cause`, of "
            "yuzu_server_command_outbox_deliver_decode_failed_total - "
            "payload_depth_exceeded (structurally valid JSON nested past kMcpMaxJsonDepth, "
            "never parsed/dumped) or payload_decode_failed (genuinely malformed payload).",
            "counter");
        d_.metrics->counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                            {{"cause", "payload_depth_exceeded"}});
        d_.metrics->counter("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                            {{"cause", "payload_decode_failed"}});
    }
}

void CommandOutboxDelivery::tick() {
    if (!d_.outbox || !d_.leader || !d_.dispatch_fn || !d_.resolve_caller)
        return;
    // Read the fenced epoch ONCE per tick. `nullopt` means this replica does not
    // currently hold leadership — the FencedLeaderOnly gate should have stopped
    // us, so this is a defensive bail (never dispatch, never mark) rather than a
    // reason to guess an epoch.
    const auto epoch = d_.leader->epoch();
    if (!epoch)
        return;
    const std::string lock = kServerBackgroundLeaderLock;

    auto pending = d_.outbox->list_pending(d_.max_per_tick);
    if (!pending) {
        // Typed degraded read (authoritative store) — never treated as "nothing
        // owed"; log + count and retry next tick.
        count("yuzu_server_command_outbox_deliver_degrade_total");
        spdlog::warn("command_outbox_delivery: list_pending degraded — deferring this tick");
        return;
    }
    for (const auto& c : *pending) {
        if (d_.should_stop && d_.should_stop()) {
            spdlog::info("command_outbox_delivery: tick stopping early on shutdown — "
                         "remaining occurrence(s) deferred");
            break;
        }
        try {
            deliver(c, lock, *epoch);
        } catch (const std::exception& e) {
            // A per-occurrence failure must not starve the rest. Treat an
            // unexpected throw as transient and reschedule (back-off) so the
            // occurrence is retried, not silently dropped — the stable
            // command_id keeps the eventual redelivery effectively-once.
            count("yuzu_server_command_outbox_deliver_errors_total");
            spdlog::error("command_outbox_delivery: deliver threw for occurrence '{}': {}",
                          c.occurrence_id, e.what());
            (void)d_.outbox->reschedule(c.occurrence_id, lock, *epoch, d_.retry_backoff);
        }
    }
}

void CommandOutboxDelivery::deliver(const OutboxCommand& c, const std::string& lock_name,
                                    std::int64_t epoch) {
    // 1. Re-authorize at SEND time — authority may have been revoked since
    //    enqueue. Fail-closed on an unset check. A denial is PERMANENT.
    if (!d_.arming_check || !d_.arming_check(c.principal, c.plugin, c.action)) {
        count("yuzu_server_command_outbox_deliver_denied_total");
        spdlog::warn("command_outbox_delivery: occurrence '{}' arming denied at delivery — "
                     "principal='{}' target={}.{}",
                     c.occurrence_id, c.principal, c.plugin, c.action);
        // CDX-P1-02: gate the exec-cancel + terminal audit on OWNING the mark
        // (same rule as the success path). A fenced-out (false) / degraded
        // (unexpected) mark_failed means the row stays pending for the true
        // leader — this replica must not cancel the exec row or audit a terminal
        // it did not own.
        auto marked = d_.outbox->mark_failed(c.occurrence_id, lock_name, epoch, "authority_denied");
        if (marked.has_value() && *marked) {
            if (d_.execution_tracker && !c.execution_id.empty())
                (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
            audit(c, "denied", "authority_denied_at_delivery");
        }
        return;
    }

    // #2437-class guard: depth-check the raw stored `parameters` text BEFORE
    // decode_payload() ever parses or, worse, dumps it. `c.parameters` is
    // sourced from ScheduleRunner's `parameter_values` (schedule CREATION is
    // already guarded, schedule_routes.cpp:94), but a row written before that
    // write-side guard shipped, or via any other write path that bypasses it,
    // still reaches this read path, and decode_payload()'s `.dump()` of a
    // non-string parameter value is unboundedly recursive. This tick processes
    // EVERY pending row on EVERY tick with no operator action in the loop at
    // all, so an unguarded poisoned row here would crash-loop this background
    // worker on every restart, not just fail once. Checked on the RAW text,
    // never on a parsed/re-dumped value (mirrors json_exceeds_depth's own
    // "never construct the deep tree" rationale, mcp_jsonrpc.hpp).
    //
    // Treated exactly like the decode-failure path immediately below (same
    // mark_failed/audit mechanism, same fencing/counting shape), so it looks
    // like a normal permanent failure to every other part of this file's state
    // machine. "payload_depth_exceeded" is a distinct reason (not lumped into
    // "payload_decode_failed") in the audit trail AND in the labeled
    // count_cause() companion counter below - both this branch and the
    // structurally identical generic-inventory fix
    // (gateway_service_impl.cpp's outcome="rejected_depth") reuse the SAME
    // bare counter (docs/user-manual/metrics.md documents it as "a malformed
    // row failed to decode", which a valid-but-too-deep payload is not) but
    // give the two causes a distinguishing label so an operator diagnosing
    // via the metric, not just the audit log, does not conflate them.
    if (!c.parameters.empty() &&
        mcp::json_exceeds_depth(c.parameters, mcp::kMcpMaxJsonDepth)) {
        count("yuzu_server_command_outbox_deliver_decode_failed_total");
        count_cause("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                    "payload_depth_exceeded");
        spdlog::error("command_outbox_delivery: occurrence '{}' (command_id={}) parameters "
                      "nested past the depth guard (max {}), marking failed: cannot be safely "
                      "parsed",
                      c.occurrence_id, c.command_id, mcp::kMcpMaxJsonDepth);
        // CDX-P1-02: own-the-mark gating, same as every other terminal path here.
        auto marked =
            d_.outbox->mark_failed(c.occurrence_id, lock_name, epoch, "payload_depth_exceeded");
        if (marked.has_value() && *marked) {
            if (d_.execution_tracker && !c.execution_id.empty())
                (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
            audit(c, "failure", "payload_depth_exceeded");
        }
        return;
    }

    // 2. Decode the opaque payload. A malformed row is a permanent failure —
    //    fail closed rather than dispatch with an empty target/param set.
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    if (!decode_payload(c, agent_ids, params)) {
        count("yuzu_server_command_outbox_deliver_decode_failed_total");
        count_cause("yuzu_server_command_outbox_deliver_decode_failed_cause_total",
                    "payload_decode_failed");
        spdlog::error("command_outbox_delivery: occurrence '{}' payload decode failed — "
                      "marking failed",
                      c.occurrence_id);
        // CDX-P1-02: own-the-mark gating, same as the denial + success paths.
        auto marked =
            d_.outbox->mark_failed(c.occurrence_id, lock_name, epoch, "payload_decode_failed");
        if (marked.has_value() && *marked) {
            if (d_.execution_tracker && !c.execution_id.empty())
                (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
            audit(c, "failure", "payload_decode_failed");
        }
        return;
    }

    // 3. Re-resolve the caller from the stored principal (never a serialized
    //    DispatchCaller — #1398) and stamp the approval provenance the
    //    occurrence carries. THIS is the declared #1398 stamping site for
    //    outbox dispatch (dispatch_caller.hpp closed list).
    auto caller = d_.resolve_caller(c.principal);
    caller.approval_provenance =
        c.approval_id.empty() ? ApprovalProvenance::None : ApprovalProvenance::Ticket;

    // 4. Dispatch through the PLAIN confined path with the STABLE command_id
    //    (R1: no ADR-1007 concurrency claim — a re-drive of an already-delivered
    //    device is absorbed by the agent's command_id dedup).
    //
    //    ORDERING (PR-review, made explicit here): the wire send happens BEFORE
    //    the fenced `mark_sent` below — this loop does NOT claim-before-dispatch
    //    at the occurrence grain. A momentarily-stale leader that has not yet
    //    noticed a handover can therefore send the same command before either
    //    side's fenced write resolves. That double SEND is safe ONLY because of a
    //    CROSS-COMPONENT dependency: the agent's DURABLE command_id dedup (WS-0,
    //    ADR-2002 §6 receiver-idempotency) suppresses the re-execution and replays
    //    the original terminal outcome. Effectively-once is an end-to-end property
    //    of (this send) + (that dedup), not a property of this loop alone — do not
    //    "optimise" the fence away on the assumption the loop self-arbitrates.
    const auto outcome = d_.dispatch_fn(c.plugin, c.action, agent_ids, c.scope_expr, params,
                                        c.execution_id, caller, c.command_id);

    // 5. A systemic transient gate/directory failure — a degraded containment
    //    read, OR (WS-4 4.2b Task D) a degraded gateway routing-directory read
    //    (`route_unreadable`) — reschedules the WHOLE occurrence with back-off,
    //    leaving it pending.
    //
    //    Unlike the store consumers of this same flag (deployment_engine's
    //    `settle_claimed_batch`, policy_evaluator's `compute_delivered`, both of
    //    which must NOT treat it all-or-nothing), this reschedule is correct
    //    EVEN WHEN `outcome.sent > 0` — which `route_unreadable` permits and
    //    `containment_unreadable` does not (see
    //    `ConfinedDispatchOutcome::route_unreadable`). The re-drive re-sends the
    //    STABLE `c.command_id` (step 4), so a device already reached on this
    //    pass is suppressed by the agent's command_id dedup (WS-0) and its
    //    terminal outcome replayed — effectively-once holds. That is what lets
    //    this consumer honour ADR-2002 §7's "undeliverable command stays
    //    pending and is re-driven" for the directory-degraded devices without
    //    the double-EXECUTION a fresh command_id would cause. Do NOT "fix" this
    //    to gate on `sent == 0`: that would drop the directory-degraded devices
    //    instead of re-driving them.
    if (outcome.containment_unreadable || outcome.route_unreadable) {
        // The existing unlabeled retry counter keeps firing for EITHER cause
        // (dashboards/alerts already key on it); the cause-labeled counter is
        // additive so a route-store degradation is separately countable
        // without redefining what the base counter means.
        count("yuzu_server_command_outbox_deliver_retry_total");
        if (d_.metrics)
            d_.metrics
                ->counter("yuzu_server_command_outbox_deliver_retry_cause_total",
                         {{"cause", outcome.containment_unreadable ? "containment_unreadable"
                                                                  : "route_unreadable"}})
                .increment();
        spdlog::warn("command_outbox_delivery: occurrence '{}' {} — rescheduling",
                     c.occurrence_id,
                     outcome.containment_unreadable ? "containment unreadable"
                                                    : "gateway route directory unreadable");
        (void)d_.outbox->reschedule(c.occurrence_id, lock_name, epoch, d_.retry_backoff);
        return;
    }

    // 6. Terminal (fire-and-advance): mark sent FIRST, because the fenced claim
    //    decides whether WE own this delivery's bookkeeping. The wire send already
    //    happened (step 4). A missed occurrence (sent==0) is still recorded and
    //    skipped, never spun into a backlog.
    //    - degraded mark → row stays pending, re-drive next tick; don't finalize/
    //      count/audit here (the re-send is dedup-absorbed).
    //    - fenced out / already terminal → the TRUE leader owns finalize+count+
    //      audit; doing it here too would double-count one logical delivery (C-5).
    auto marked = d_.outbox->mark_sent(c.occurrence_id, lock_name, epoch);
    if (!marked.has_value()) {
        count("yuzu_server_command_outbox_deliver_degrade_total");
        spdlog::warn("command_outbox_delivery: mark_sent degraded for occurrence '{}' — "
                     "will re-drive",
                     c.occurrence_id);
        return;
    }
    if (!*marked)
        return; // fenced out or already terminal — not ours to finalize/count/audit

    // 7. We own this delivery. Finalize the (fire-time-created) execution row so
    //    it cannot idle to the materialise timeout (executions ladder), then count
    //    and audit exactly once. sent==0 (no agents reachable right now) is a
    //    DISTINCT outcome from a real delivery — a separate counter so the
    //    delivered SLI is not inflated by no-agent misses (C-1).
    if (d_.execution_tracker && !c.execution_id.empty()) {
        if (outcome.sent > 0) {
            if (!d_.execution_tracker->set_agents_targeted(c.execution_id, outcome.sent))
                (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        } else {
            (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        }
    }
    if (outcome.sent > 0) {
        count("yuzu_server_command_outbox_delivered_total");
        spdlog::info("command_outbox_delivery: delivered occurrence '{}' — command_id={} "
                     "execution_id={} agents={}",
                     c.occurrence_id, c.command_id, c.execution_id, outcome.sent);
        audit(c, "success",
              "sent=" + std::to_string(outcome.sent) + " command_id=" + c.command_id +
                  " execution_id=" + c.execution_id);
    } else {
        count("yuzu_server_command_outbox_deliver_no_agents_total");
        spdlog::info("command_outbox_delivery: occurrence '{}' reached no agents (command_id={} "
                     "execution_id={}) — recorded and skipped (fire-and-advance)",
                     c.occurrence_id, c.command_id, c.execution_id);
        audit(c, "failure",
              "no_agents_reached command_id=" + c.command_id + " execution_id=" + c.execution_id);
    }
}

void CommandOutboxDelivery::audit(const OutboxCommand& c, const std::string& result,
                                  const std::string& detail) {
    if (!d_.audit_store)
        return;
    AuditEvent ev;
    ev.timestamp = now_epoch_seconds();
    ev.principal = c.principal;
    ev.action = "command.outbox_delivered";
    ev.target_type = "command";
    ev.target_id = c.command_id.empty() ? c.occurrence_id : c.command_id;
    ev.result = result;
    ev.detail = "source=" + c.source + " occurrence_id=" + c.occurrence_id + " plugin=" +
                c.plugin + " action=" + c.action + " " + detail;
    // audit_store.hpp's log() is FAIL-HARD: it returns false when the compliance
    // row did not persist. This is the delivery loop's ONE audit write and the
    // whole point of the two-stage `command.outbox_delivered` verb, so a dropped
    // write must be observable — a background loop has no 503 to return (unlike
    // the REST `Sec-Audit-Failed` / MCP `audit_persisted:false` callers), so
    // surface it via a counter + a warn line rather than swallowing the signal.
    if (!d_.audit_store->log(ev)) {
        count("yuzu_server_command_outbox_audit_failed_total");
        spdlog::warn("command_outbox_delivery: audit persist FAILED for occurrence '{}' "
                     "(command_id={} result={}) — compliance row not recorded",
                     c.occurrence_id, c.command_id, result);
    }
}

void CommandOutboxDelivery::count(const char* name) {
    if (d_.metrics)
        d_.metrics->counter(name).increment();
}

void CommandOutboxDelivery::count_cause(const char* name, const char* cause) {
    if (d_.metrics)
        d_.metrics->counter(name, {{"cause", cause}}).increment();
}

} // namespace yuzu::server
