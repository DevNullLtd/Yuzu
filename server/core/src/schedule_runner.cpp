#include "schedule_runner.hpp"

#include "dispatch_target_shape.hpp" // kBroadcastScope (#2500)

#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "on_behalf_guard.hpp" // onbehalf::sanitize_for_log
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <tuple>

namespace yuzu::server {

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Tickets submitted before this occurrence became the current one are stale:
// a rejected ticket from a PREVIOUS occurrence must not skip this one, and a
// long-spent approved ticket must not fire it. Once a schedule has advanced,
// only tickets submitted STRICTLY after the advance count — that strictness
// is the one-approval == one-run guarantee (advance stamps
// last_executed_at, retiring the ticket that settled the occurrence, even
// within the same second). A never-advanced schedule accepts any ticket
// since its creation (`>=` — create and submit can share a second).
bool ticket_is_current(const Approval& a, const InstructionSchedule& s) {
    return s.last_executed_at > 0 ? a.submitted_at > s.last_executed_at
                                  : a.submitted_at >= s.created_at;
}

} // namespace

ScheduleRunner::ScheduleRunner(Deps deps) : d_(std::move(deps)) {}

void ScheduleRunner::tick() {
    if (!d_.schedule_engine || !d_.instruction_store || !d_.enqueue_fn)
        return;

    for (const auto& s : d_.schedule_engine->evaluate_due()) {
        // #3495: bounds how many MORE schedules a single tick() call fires
        // once shutdown begins — a schedule already firing below still
        // completes cleanly, this only stops the next one from starting.
        if (d_.should_stop && d_.should_stop()) {
            spdlog::info("schedule_runner: tick stopping early on shutdown - "
                         "remaining schedule(s) deferred");
            break;
        }
        // Contain per-schedule failures: one malformed schedule/definition
        // must not stop the remaining due schedules from firing this tick.
        try {
            fire(s);
        } catch (const std::exception& e) {
            count("yuzu_schedule_fire_failures_total");
            spdlog::error("schedule_runner: fire threw for schedule '{}' (id={}): {}", s.name,
                          s.id, e.what());
            // Advance anyway — a schedule whose fire path always throws must
            // not re-fire every tick forever (fire-and-advance discipline).
            d_.schedule_engine->advance_schedule(s.id);
        }
    }
}

void ScheduleRunner::fire(const InstructionSchedule& s) {
    auto def_result = d_.instruction_store->get_definition(s.definition_id);
    if (!def_result) {
        // ADR-0058: a genuine DB error (Postgres blip) — distinguished from
        // "unknown" (id doesn't exist) below so an operator doesn't mistake a
        // transient infrastructure issue for a stale/deleted schedule reference.
        // Do NOT advance: a store-unavailable attempt is not a completed
        // occurrence — advancing would permanently consume this schedule's due
        // slot on a transient failure. Leaving it un-advanced means evaluate_due()
        // returns it again next tick, matching PolicyEvaluator::dispatch_due's
        // throttle-restore-on-store-unavailable fix (gov Gate 3 sibling finding).
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) instruction store read failed for "
                     "'{}' — retrying next tick",
                     s.name, s.id, s.definition_id);
        audit(s, "instruction.schedule_fired", "failure",
              "definition_store_unavailable schedule_id=" + s.id);
        return;
    }
    if (!*def_result || !(*def_result)->enabled) {
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) references {} definition '{}' — "
                     "occurrence skipped",
                     s.name, s.id, *def_result ? "disabled" : "unknown", s.definition_id);
        audit(s, "instruction.schedule_fired", "failure",
              std::string(*def_result ? "definition_disabled" : "definition_unknown") +
                  " schedule_id=" + s.id);
        d_.schedule_engine->advance_schedule(s.id);
        return;
    }
    const auto& def = **def_result;

    // D7 (PLAN-003): re-verify the arming principal BEFORE the
    // approval/direct branch below, so BOTH arms are covered — a check
    // placed only inside fire_with_approval would let every
    // approval_mode == "auto" schedule dispatch under stale authority.
    // Fail-closed: an unset callback (p14 not wired yet, or a deliberate
    // lockdown) denies the fire exactly like an explicit `false`. Always
    // advance so a permanently-denied schedule cannot spin retrying every
    // tick forever.
    if (!d_.arming_check || !d_.arming_check(s.created_by, def.plugin, def.action)) {
        count("yuzu_schedule_arming_denied_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) arming check denied — "
                     "principal='{}' target={}.{}",
                     s.name, s.id, s.created_by, def.plugin, def.action);
        audit(s, "instruction.schedule_fired", "denied",
              "arming_check_denied schedule_id=" + s.id + " principal=" + s.created_by +
                  " plugin=" + def.plugin + " action=" + def.action);
        d_.schedule_engine->advance_schedule(s.id);
        return;
    }

    // Approval gate — mirrors the interactive execute path: "auto" dispatches
    // directly, everything else (always / role-gated / unknown) requires an
    // approval ticket. There is no operator session here, so role-gated
    // cannot be bypassed and fails closed to require-approval.
    const bool needs_approval = s.requires_approval || def.approval_mode != "auto";
    if (needs_approval) {
        // #1398 (Gate 5 chaos-injector finding, LOW): checks is_open(), not
        // pointer-nullness. `d_.approval_manager` is a non-owning pointer set
        // once at server construction and stays non-null for the process
        // lifetime regardless of whether its internal migration later fails
        // (ApprovalManager::create_tables() sets its OWN db_ to nullptr on a
        // failed migration, never this pointer) — so the old `!d_.
        // approval_manager` check could never fire on a migration-closed
        // store, and this diagnostic branch's more specific audit/log
        // message never ran for that case. Net security effect was
        // unchanged either way (fire_with_approval's own query()/submit()
        // calls already fail closed on a closed store), but this is the
        // actually-reachable check for it.
        if (!d_.approval_manager || !d_.approval_manager->is_open()) {
            // Fail closed: never dispatch an approval-gated instruction
            // without the gate. Advance so the schedule doesn't spin.
            count("yuzu_schedule_fire_failures_total");
            spdlog::error("schedule_runner: schedule '{}' (id={}) requires approval but no "
                          "approval manager is wired — occurrence skipped",
                          s.name, s.id);
            audit(s, "instruction.schedule_fired", "failure",
                  "approval_gate_unavailable schedule_id=" + s.id);
            d_.schedule_engine->advance_schedule(s.id);
            return;
        }
        if (fire_with_approval(s, def.plugin, def.action))
            d_.schedule_engine->advance_schedule(s.id);
        return; // pending → stays due, re-checked next tick
    }

    // WS-3 3.3: enqueue a durable occurrence instead of dispatching inline. Only
    // advance on a durable enqueue — a degraded/fenced-out enqueue leaves the
    // schedule due so it retries next tick, and the stable occurrence key makes
    // the retry idempotent (matching the store-unavailable no-advance posture of
    // the get_definition path above).
    if (enqueue_occurrence(s, def.plugin, def.action, /*approval_id=*/""))
        d_.schedule_engine->advance_schedule(s.id);
}

bool ScheduleRunner::fire_with_approval(const InstructionSchedule& s, const std::string& plugin,
                                        const std::string& action) {
    // #1398 hardening (governance Gate 4 unhappy-path CRITICAL finding,
    // then re-hardened by security-guardian's re-review): the definition
    // this schedule fires can be MUTATED (PUT /api/instructions/{id}, gated
    // only on InstructionDefinition:Write) between a ticket's approval and
    // this schedule's next tick — `fire()` re-fetches `def` fresh every
    // time, so `plugin`/`action` here may be DIFFERENT from what was
    // actually reviewed when the ticket below was approved. Comparing
    // against `a.target_plugin`/`a.target_action` (see their doc comment,
    // approval_manager.hpp) closes that: a mismatch on EITHER field —
    // including a pre-migration empty value — simply fails the equality
    // check below and falls through to submitting a fresh ticket for the
    // NEW content, never redeeming stale review for unreviewed content.
    // TWO separate comparisons, not a concatenated string: `plugin`/`action`
    // are free text with no charset restriction, so a single `plugin+"."
    // +action` string would be collision-prone (28 shipped actions already
    // contain a literal `.`) — matching `CommandCapabilityRegistry::
    // classify`'s own independent-field shape eliminates that class.

    // 1) An APPROVED ticket for THIS schedule's occurrence, for THIS exact
    //    target → fire. The caller advances the schedule on our true return,
    //    which retires the ticket via the occurrence anchor (see
    //    ticket_is_current) — approve == at most one scheduled run. Single
    //    tick thread, so no concurrent-fire race. Matching on
    //    a.schedule_id == s.id (M-02, #1806) is required, not just
    //    belt-and-suspenders: without it, two schedules sharing (creator,
    //    definition, scope) would both fire off ONE approval.
    // #1398 (security-guardian re-review, MEDIUM): a ticket that matches
    // this occurrence's identity but NOT its current content is exactly the
    // attack this hardening defends against (get benign content approved,
    // then swap the definition before the next tick) — worth its own
    // detectable audit signal, distinct from "no ticket found at all"
    // (step 4's ordinary first-ask path below). Captured here, AUDITED
    // BELOW (only if this tick actually reaches step 4) rather than
    // immediately: the stale mismatched ticket stays in `approved` status
    // forever (nothing re-statuses it), so auditing on every detection
    // would re-fire this event every tick for as long as the resulting
    // fresh ticket (step 4) stays pending — sre governance finding, audit
    // volume, not correctness. Firing it once, on the tick that actually
    // acts on the mismatch by requesting fresh review, is the meaningful
    // event; every subsequent tick's re-detection of the SAME stale ticket
    // is not new information (step 2 below already suppresses the
    // resubmission that would otherwise duplicate-ask).
    std::string mismatch_audit_detail;
    auto approved = d_.approval_manager->query({.status = "approved", .submitted_by = s.created_by});
    for (const auto& a : approved) {
        if (a.definition_id != s.definition_id || a.scope_expression != s.scope_expression ||
            a.schedule_id != s.id || !ticket_is_current(a, s))
            continue;
        if (a.target_plugin != plugin || a.target_action != action) {
            spdlog::warn("schedule_runner: schedule '{}' (id={}) approval {} no longer matches "
                         "the definition's CURRENT target ({}.{} != approved {}.{}) — refusing "
                         "to redeem stale review; a fresh ticket will be requested",
                         s.name, s.id, a.id, plugin, action, a.target_plugin, a.target_action);
            if (mismatch_audit_detail.empty()) {
                mismatch_audit_detail =
                    "approval_content_mismatch approval_id=" + a.id + " schedule_id=" + s.id +
                    " approved_target=" + onbehalf::sanitize_for_log(a.target_plugin, 128) + "." +
                    onbehalf::sanitize_for_log(a.target_action, 128) +
                    " current_target=" + onbehalf::sanitize_for_log(plugin, 128) + "." +
                    onbehalf::sanitize_for_log(action, 128);
            }
            continue;
        }
        // WS-3 3.3: enqueue instead of inline dispatch. Propagate the enqueue
        // outcome as the settle signal — a degraded enqueue returns false so the
        // caller does NOT advance; the approved ticket stays valid and the next
        // tick re-enqueues the same (idempotent) occurrence.
        return enqueue_occurrence(s, plugin, action, a.id);
    }

    // 2) A PENDING ticket for THIS schedule → the occurrence waits (no
    //    advance), and we never stack a duplicate ask. Scoped to
    //    a.schedule_id == s.id for the same reason as (1): otherwise a
    //    sibling schedule's pending ticket would suppress this schedule's
    //    OWN submission in step 4, and it would never get a ticket to match.
    auto pending = d_.approval_manager->query({.status = "pending", .submitted_by = s.created_by});
    for (const auto& a : pending) {
        if (a.definition_id == s.definition_id && a.scope_expression == s.scope_expression &&
            a.schedule_id == s.id)
            return false;
    }

    // 3) A REJECTED ticket for this occurrence → skip it. The next occurrence
    //    submits a fresh ticket (each occurrence is one ask).
    auto rejected = d_.approval_manager->query({.status = "rejected", .submitted_by = s.created_by});
    for (const auto& a : rejected) {
        if (a.definition_id != s.definition_id || a.scope_expression != s.scope_expression ||
            a.schedule_id != s.id || a.target_plugin != plugin || a.target_action != action ||
            !ticket_is_current(a, s))
            continue;
        spdlog::info("schedule_runner: schedule '{}' (id={}) occurrence skipped — approval {} "
                     "rejected by {}",
                     s.name, s.id, a.id, a.reviewed_by);
        audit(s, "instruction.schedule_fired", "denied",
              "approval_rejected approval_id=" + a.id + " schedule_id=" + s.id);
        return true;
    }

    // 4) No ticket yet → submit one (tagged with this schedule's id, M-02,
    //    and this exact target plugin/action, #1398 hardening) and hold the
    //    occurrence at its due time. This is where a step-1 content mismatch
    //    (if any was found above) gets its one-shot audit row: reaching
    //    here means neither step 2 nor step 3 short-circuited, so this tick
    //    is genuinely the one requesting fresh review for the mismatch.
    if (!mismatch_audit_detail.empty())
        audit(s, "instruction.schedule_fired", "denied", mismatch_audit_detail);
    auto submitted = d_.approval_manager->submit(s.definition_id, s.created_by, s.scope_expression,
                                                 s.id, ApprovalOrigin::kSchedule, plugin, action);
    if (!submitted) {
        // Submit failure (pending cap, store error): drop THIS occurrence
        // (advance) rather than re-submitting every tick against a full cap.
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: approval submit failed for schedule '{}' (id={}): {} — "
                     "occurrence skipped",
                     s.name, s.id, submitted.error());
        audit(s, "instruction.schedule_fired", "failure",
              "approval_submit_failed schedule_id=" + s.id + " error=" + submitted.error());
        return true;
    }
    count("yuzu_schedule_approvals_submitted_total");
    spdlog::info("schedule_runner: schedule '{}' (id={}) requires approval — submitted {}", s.name,
                 s.id, *submitted);
    // Same action string as the interactive path's approval gate so the
    // audit taxonomy stays one-vocabulary; detail marks the scheduled origin.
    audit(s, "instruction.approval_required", "pending",
          "approval_id=" + *submitted + " mode=scheduled schedule_id=" + s.id);
    return false;
}

bool ScheduleRunner::enqueue_occurrence(const InstructionSchedule& s, const std::string& plugin,
                                        const std::string& action, const std::string& approval_id) {
    if (!d_.enqueue_fn) {
        // Fail closed: without a wired enqueue seam a fire cannot be durably
        // recorded. Do NOT advance — the schedule stays due and retries once the
        // seam is wired (never a silently-dropped occurrence).
        count("yuzu_schedule_fire_failures_total");
        spdlog::error("schedule_runner: schedule '{}' (id={}) has no enqueue_fn wired — occurrence "
                      "not queued",
                      s.name, s.id);
        return false;
    }

    // Create-before-dispatch (executions ladder UP2-4): the execution row is
    // created HERE, at enqueue time, so scheduled runs appear in the Executions
    // history immediately; the delivery loop registers the command_id→exec_id
    // mapping and dispatches later. dispatched_by = the schedule's creator.
    std::string exec_id;
    if (d_.execution_tracker) {
        Execution exec;
        exec.definition_id = s.definition_id;
        exec.status = "running";
        exec.scope_expression = s.scope_expression;
        // PR1.5a: the schedule's own canonical parameters, not a hardcoded "{}".
        exec.parameter_values =
            s.parameter_values.empty() ? std::string(kEmptyScheduleParams) : s.parameter_values;
        exec.dispatched_by = s.created_by;
        if (auto created = d_.execution_tracker->create_execution(exec); created.has_value())
            exec_id = *created;
        else
            spdlog::warn("schedule_runner: create_execution failed for schedule '{}' — queuing "
                         "untracked",
                         s.name);
    }

    OutboxEnqueueRequest req;
    // STABLE occurrence key: schedule id + the occurrence's due time. A re-fire
    // after a crash-before-advance recomputes the identical key, so the store
    // returns AlreadyEnqueued (one occurrence, never two). The delivery loop
    // dispatches by scope, so schedules carry no agent_ids.
    req.occurrence_id = s.id + ":" + std::to_string(s.next_execution_at);
    req.source = "schedule_runner";
    req.plugin = plugin;
    req.action = action;
    // #2500: an empty scope has always meant "the whole fleet" on this path — say
    // it explicitly (Broadcast) so the meaning survives the empty-means-everybody
    // inversion, exactly as the inline path did. (The create-route gap that lets
    // an operator store an empty scope at all is tracked separately under #2500.)
    req.scope_expr = s.scope_expression.empty() ? std::string(yuzu::server::kBroadcastScope)
                                                : s.scope_expression;
    req.agent_ids = ""; // schedules target by scope, never an id list
    req.parameters =
        s.parameter_values.empty() ? std::string(kEmptyScheduleParams) : s.parameter_values;
    req.execution_id = exec_id;
    // The schedule's creator: re-resolved to a live caller and re-authorized at
    // SEND time by the delivery loop (never a stale creation-time snapshot).
    req.principal = s.created_by;
    // #1398: carried so the delivery loop can stamp Ticket provenance for an
    // approved fire (empty on a direct auto-mode fire → None).
    req.approval_id = approval_id;

    // qa-1 regression fix: the former inline dispatch_tracked wrapped its dispatch
    // in try/catch and cancelled the speculative exec row on a throw. enqueue_fn
    // can also throw (e.g. an entropy failure minting the command_id). If it does,
    // cancel the row we just created so it can't idle at 'running' to the
    // materialise timeout, then rethrow — tick()'s own catch advances the schedule
    // (fire-and-advance), exactly as the old path did.
    OutboxEnqueueOutcome outcome;
    try {
        outcome = d_.enqueue_fn(req);
    } catch (...) {
        if (d_.execution_tracker && !exec_id.empty() &&
            !d_.execution_tracker->mark_cancelled(exec_id, s.created_by))
            spdlog::error("schedule_runner: mark_cancelled failed for execution_id={} after "
                          "enqueue_fn threw",
                          exec_id);
        throw;
    }
    switch (outcome) {
    case OutboxEnqueueOutcome::AlreadyEnqueued:
        // Idempotent re-fire (a crash between a prior enqueue and its advance):
        // the occurrence already exists with its OWN execution row, so the row we
        // just created is a duplicate the outbox discarded (ON CONFLICT). Cancel it
        // so it cannot idle at 'running', then advance exactly as the first fire
        // would have — but do NOT re-emit the `instruction.schedule_fired`/`queued`
        // audit: the FIRST fire already audited this occurrence, and a second row
        // is the one non-cosmetic consequence of enqueue and advance not being a
        // single transaction (PR-review finding; the enqueue and ScheduleEngine
        // advance are separate writes — see the ADR-2002 §6 "documented exception"
        // note). A log line records the idempotent recovery instead.
        if (d_.execution_tracker && !exec_id.empty() &&
            !d_.execution_tracker->mark_cancelled(exec_id, s.created_by))
            spdlog::error("schedule_runner: mark_cancelled failed for duplicate execution_id={}",
                          exec_id);
        count("yuzu_schedule_fires_idempotent_refire_total");
        spdlog::info("schedule_runner: schedule '{}' (id={}) idempotent re-fire — occurrence_id={} "
                     "already enqueued; advancing without a duplicate audit",
                     s.name, s.id, req.occurrence_id);
        return true;
    case OutboxEnqueueOutcome::Enqueued: {
        count("yuzu_schedule_fires_total");
        spdlog::info("schedule_runner: schedule '{}' (id={}) queued — occurrence_id={} "
                     "execution_id={}",
                     s.name, s.id, req.occurrence_id, exec_id);
        std::string detail = "schedule_id=" + s.id + " occurrence_id=" + req.occurrence_id +
                             " execution_id=" + exec_id;
        if (!approval_id.empty())
            detail += " approval_id=" + approval_id;
        audit(s, "instruction.schedule_fired", "queued", detail);
        return true;
    }
    case OutboxEnqueueOutcome::FencedOut:
        // Leadership lost mid-tick — leave the occurrence for the true leader and
        // do NOT advance. Cancel the exec row we speculatively created.
        spdlog::warn("schedule_runner: schedule '{}' (id={}) enqueue fenced out (leadership "
                     "moved) — deferring",
                     s.name, s.id);
        if (d_.execution_tracker && !exec_id.empty() &&
            !d_.execution_tracker->mark_cancelled(exec_id, s.created_by))
            spdlog::error("schedule_runner: mark_cancelled failed for execution_id={}", exec_id);
        return false;
    case OutboxEnqueueOutcome::Degraded:
    default:
        // Transient store failure — retry next tick (do NOT advance). Cancel the
        // exec row so it cannot idle to the materialise timeout.
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) enqueue degraded — retrying next tick",
                     s.name, s.id);
        if (d_.execution_tracker && !exec_id.empty() &&
            !d_.execution_tracker->mark_cancelled(exec_id, s.created_by))
            spdlog::error("schedule_runner: mark_cancelled failed for execution_id={}", exec_id);
        audit(s, "instruction.schedule_fired", "failure",
              "enqueue_degraded schedule_id=" + s.id + " execution_id=" + exec_id);
        return false;
    }
}

void ScheduleRunner::audit(const InstructionSchedule& s, const std::string& action,
                           const std::string& result, const std::string& detail) {
    if (!d_.audit_store)
        return;
    AuditEvent ev;
    ev.timestamp = now_epoch();
    ev.principal = s.created_by;
    ev.action = action;
    ev.target_type = "instruction";
    ev.target_id = s.definition_id;
    ev.result = result;
    ev.detail = detail;
    // Background fire-and-forget per the AuditStore::log contract — there is
    // no response to surface partial-success on; a failed persist is counted
    // by the store's own emit_failed_ metric.
    (void)d_.audit_store->log(ev);
}

void ScheduleRunner::count(const char* name) {
    if (d_.metrics)
        d_.metrics->counter(name).increment();
}

} // namespace yuzu::server
