#include "deployment_engine.hpp"

#include "deployment_run_store.hpp"
#include "response_store.hpp" // StoredResponse (best_response_per_agent)

#include <chrono>
#include <cstdint>
#include <string_view>
#include <unordered_set>

namespace yuzu::server::deployment {

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// #3424/#3511 fix round (PR #3939 review, finding 2): the ORIGINAL version of
// this function (pre-review) only ever checked `outcome.sent == 0` for the
// WHOLE claimed batch, which had two confirmed bugs. (1) A transient
// `containment_unreadable` (the gate itself failing closed, typically
// recovering within seconds) was indistinguishable from a permanent refusal
// and settled every claimed row straight to 'failed' — unrecoverable, when
// the correct behaviour is to retry once the gate recovers. (2) In a MIXED
// batch — some devices reached, others withheld individually for a named
// permanent reason (quarantined, plugin absent) — `sent > 0` skipped the
// rollback branch entirely, so the withheld devices' rows stayed claimed in
// 'staging'/'executing' with NO transition ever able to move them out
// (a withheld device never gets an agent response, so the response-derived
// transitions at the top of `advance()` never fire for it either) —
// `complete_deployment` blocks forever on that row: an unconditional,
// state-machine-wedging hang on an entirely ordinary path (any deploy cohort
// with mixed device inventory).
//
// `revert_step` is where a CLAIMED-but-not-individually-evaluated row goes
// back to so a LATER tick's own candidate scan reclaims it — 'pending' for
// the stage claim, 'staged' for the exec claim — never 'failed': the gate
// degradation says nothing about these specific devices.
void settle_claimed_batch(const EngineDeps& deps, const std::string& deployment_id,
                          std::string_view phase_label, const std::vector<std::string>& claimed,
                          const yuzu::server::ConfinedDispatchOutcome& outcome,
                          const std::string& claimed_step, const std::string& revert_step,
                          const std::string& failed_step,
                          const yuzu::server::authz::VisibleSet& exec_visible) {
    if (claimed.empty())
        return;

    if (outcome.containment_unreadable) {
        // The gate itself failed closed: EVERY id was withheld by the
        // `contained()` lambda BEFORE its `send_to`, so `sent == 0` and none
        // of them appear in `sent`, `not_sent`, or the named-permanent sets --
        // they are counted only in `denied_quarantined_count`. There is no
        // per-device fact to act on, only a systemic one, and the per-id
        // accounting below cannot see these ids at all. Undo the claim
        // entirely rather than fail it: a fail-closed gate typically recovers
        // within seconds (matching the retry_after_ms: 5000 every other
        // zero-reach cascade in this PR already promises).
        //
        // `route_unreadable` is DELIBERATELY NOT handled here, though WS-4 4.2b
        // Task D's first cut lumped it in with `containment_unreadable`. The
        // two are NOT interchangeable for an all-or-nothing revert (see
        // `ConfinedDispatchOutcome::route_unreadable`'s doc comment): a degraded
        // GatewayRouteStore read does NOT force `sent == 0`. The arm walk still
        // ran, so a locally-connected device in this batch was genuinely sent
        // the command (and, for the execute step, is RUNNING the installer)
        // while a directory-only device merely landed in `not_sent`. Reverting
        // the WHOLE batch would send that already-executed device back to
        // `revert_step`, and a later tick's candidate scan would reclaim and
        // re-dispatch it under a FRESH command_id -- which the agent's
        // command_id dedup (WS-0) does NOT absorb, because it is a different
        // command. That is a double-execution of a destructive installer, the
        // exact execute-once violation the deployment routed concern calls
        // catastrophic. Instead, route-degraded devices flow to `not_sent` and
        // REVERT INDIVIDUALLY below, identical to any offline device, while
        // genuinely-sent devices are left to await their agent response.
        std::vector<DeviceTransition> revert;
        revert.reserve(claimed.size());
        for (const auto& aid : claimed)
            revert.push_back({.agent_id = aid,
                              .from_step = claimed_step,
                              .to_step = revert_step,
                              .error = ""});
        deps.store->apply_results(deployment_id, revert);
        return;
    }

    // Named ids withheld for a PERMANENT reason — settled to 'failed'
    // regardless of `outcome.sent`, so a mixed batch's withheld devices are
    // never left stranded just because other devices in the same batch were
    // reached.
    std::unordered_set<std::string> permanent_ids;
    std::vector<DeviceTransition> failed;
    const std::string phase(phase_label);
    for (const auto& aid : outcome.denied_quarantined) {
        if (permanent_ids.insert(aid).second)
            failed.push_back({.agent_id = aid,
                              .from_step = claimed_step,
                              .to_step = failed_step,
                              .error = phase + " dispatch withheld: device is quarantined"});
    }
    for (const auto& aid : outcome.unknown_plugin) {
        if (permanent_ids.insert(aid).second)
            failed.push_back(
                {.agent_id = aid,
                 .from_step = claimed_step,
                 .to_step = failed_step,
                 .error = phase + " dispatch withheld: content_dist plugin not found on "
                                  "this device's reported inventory"});
    }

    // PR #3939 review round, security-guardian finding: `outcome.not_sent`
    // names ids that survived containment/plugin-presence but whose actual
    // send failed (AgentRegistry::send_to returned false, the ordinary case
    // of a device that went offline between claim and dispatch) --
    // `dispatch_confined_arms`'s Ids-arm walk populates this unconditionally
    // on any delivery failure, not only under an ADR-1007 concurrency claim
    // (this function's dispatch_fn never applies one). Unlike
    // denied_quarantined/unknown_plugin this is NOT a permanent fact: an
    // offline device may reconnect, matching every zero-reach RESPONSE
    // cascade's own "an offline device may reconnect" wording -- so these
    // ids REVERT for retry, same as containment_unreadable, but individually
    // rather than as a whole-batch revert, since the rest of the batch may
    // have been reached or permanently withheld.
    std::unordered_set<std::string> accounted_ids = permanent_ids;
    std::vector<DeviceTransition> reverted;
    for (const auto& aid : outcome.not_sent) {
        if (accounted_ids.insert(aid).second)
            reverted.push_back({.agent_id = aid,
                                .from_step = claimed_step,
                                .to_step = revert_step,
                                .error = ""});
    }

    // Gate 4 happy-path finding, PR #3939 review round 3: an id in `claimed`
    // that its caller's OWN exec_visible set no longer admits is dropped
    // SILENTLY by the arm walk's `authz::filter_to_scope(*targets.agent_ids,
    // exec_visible)` (dispatch_confined_arms.hpp's Ids arm) before its loop
    // body -- the caller's own body never learns which id, only that
    // `outcome.sent` ends up short. Rather than infer identity from
    // arithmetic (unsound: `sent` is a COUNT, not a set of ids, so a
    // claimed-minus-accounted residual cannot distinguish "was sent" from
    // "was filtered" once `sent > 0`), recompute the SAME membership test
    // the arm walk applies, directly: `settle_claimed_batch` already
    // receives the identical `exec_visible` the dispatch call was made
    // under (threaded from `advance()`'s `caller`/`pipeline_caller`), so
    // `authz::in_scope` on each `claimed` id reproduces the walk's own drop
    // point exactly, with no widening of `ConfinedDispatchOutcome` needed.
    // Skip, not fail or revert-to-retry: this mirrors the pre-claim
    // `mark_skipped`/'out of scope at dispatch' treatment for a device that
    // drops out of scope before being claimed (`advance()`'s scan above) --
    // terminal, so it stops blocking `complete_deployment`, and honest,
    // since a caller-visibility narrowing (an entirely ordinary
    // least-privilege RBAC layout, not degradation or attack -- see
    // deployment_routes.cpp / server.cpp's `derive_exec_visible` wiring) is
    // not evidence the device itself will ever come back into scope for
    // THIS operator.
    std::vector<DeviceTransition> skipped;
    for (const auto& aid : claimed) {
        if (accounted_ids.count(aid) || yuzu::server::authz::in_scope(exec_visible, aid))
            continue;
        if (accounted_ids.insert(aid).second)
            skipped.push_back({.agent_id = aid,
                               .from_step = claimed_step,
                               .to_step = step_token(Step::kSkipped),
                               .error = "out of scope at dispatch"});
    }

    // Residual: NEITHER a named-permanent id, a not_sent id, NOR an
    // exec_visible-excluded id accounts for the batch, and NOTHING else in
    // it was reached either -- dispatch never reached the per-id arm walk
    // at all, a chokepoint denial (`dispatch_confined`'s
    // `if (!classified) return {command_id, 0};`, e.g. the caller lost the
    // classified permission for content_dist.stage/execute_staged between
    // claim and dispatch). `ConfinedDispatchOutcome` carries no per-id
    // identification for this class, so -- unlike the accounted classes
    // above -- there is no way to tell which of the remainder is
    // responsible; fail the whole unaccounted remainder, matching this
    // function's original (pre-review) behaviour for exactly this case. Only
    // reachable when `outcome.sent == 0`: once ANY device in `claimed` is
    // sent, denied, plugin-absent, not_sent, or exec_visible-excluded, the
    // count and the identified ids line up exactly and this is empty by
    // construction.
    if (outcome.sent == 0 && claimed.size() > accounted_ids.size()) {
        const std::string reason = phase +
                                   " dispatch refused or reached no agents (command " +
                                   outcome.command_id + ", 0 sent)";
        for (const auto& aid : claimed) {
            if (accounted_ids.count(aid))
                continue;
            failed.push_back(
                {.agent_id = aid, .from_step = claimed_step, .to_step = failed_step, .error = reason});
        }
    }

    if (!failed.empty())
        deps.store->apply_results(deployment_id, failed);
    if (!reverted.empty())
        deps.store->apply_results(deployment_id, reverted);
    if (!skipped.empty())
        deps.store->apply_results(deployment_id, skipped);
}

int response_score(const StoredResponse& r) {
    int s = 0;
    if (r.status != 0) // 0 = RUNNING; terminal beats running
        s += 2;
    if (!r.output.empty())
        s += 1;
    return s;
}

} // namespace

std::unordered_map<std::string, AgentResponse>
best_response_per_agent(const std::vector<StoredResponse>& rows) {
    // Pick the best row per agent without copying every row: addresses into `rows`
    // (a stable local vector — not mutated here) feed `best`, which is consumed
    // into the value-typed result before returning.
    std::unordered_map<std::string, const StoredResponse*> best;
    for (const auto& r : rows) {
        auto it = best.find(r.agent_id);
        if (it == best.end()) {
            best.emplace(r.agent_id, &r);
            continue;
        }
        const StoredResponse& cur = *it->second;
        if (response_score(r) > response_score(cur) ||
            (response_score(r) == response_score(cur) && r.received_at_ms > cur.received_at_ms))
            it->second = &r;
    }
    std::unordered_map<std::string, AgentResponse> out;
    out.reserve(best.size());
    for (const auto& [agent, rp] : best)
        out.emplace(agent, AgentResponse{rp->status, rp->output});
    return out;
}

void advance(const EngineDeps& deps, const std::string& deployment_id, const DeploymentConfig& cfg,
             const std::unordered_set<std::string>& authorized,
             const yuzu::server::DispatchCaller& caller) {
    if (deps.store == nullptr || deployment_id.empty())
        return;

    // #1398: content_dist.{stage,execute_staged} are role-gated content —
    // ExecuteGate::AdminOrApproval at the dispatch chokepoint. The `/auto`
    // Deploy pipeline (this function: creator-authority go-cohort computed
    // upstream, guarded one-way transitions, execute-once CAS via
    // claim_for_stage/claim_for_exec below, full audit) is accepted as the
    // governing control in place of a per-dispatch ApprovalManager ticket
    // (#1398 design doc, Decision 5) — a SEPARATE, explicitly-typed
    // provenance value from a real consumed ticket, never conflated with
    // one. Per-dispatch attribution comes from `execution_id`
    // ("deployment-<id>-stage"/"...-exec", stage_execution_id/
    // exec_execution_id below) rather than a new audit call: it is already
    // the canonical per-dispatch correlation id this codebase threads
    // through the whole dispatch chain (matching the preflight-/polchk-/
    // bundle- id-prefix siblings), so an incident review can already trace
    // any dispatch back to the exact deployment run that authorized it.
    yuzu::server::DispatchCaller pipeline_caller = caller;
    pipeline_caller.approval_provenance = yuzu::server::ApprovalProvenance::GovernedPipeline;

    auto grid = deps.store->get_devices(deployment_id);

    // ── 1. Poll the stage + execute responses (no store lease held) ──────────
    std::unordered_map<std::string, AgentResponse> stage_resp, exec_resp;
    if (deps.poll_fn) {
        stage_resp = deps.poll_fn(stage_execution_id(deployment_id));
        exec_resp = deps.poll_fn(exec_execution_id(deployment_id));
    }

    // ── 2. Response-derived transitions, GUARDED on the source step ──────────
    // A device only moves out of 'staging'/'executing' when ITS phase response is
    // terminal; the store UPDATE re-checks the source step, so a concurrent advance
    // that already moved it is a no-op.
    std::vector<DeviceTransition> transitions;
    for (const auto& d : grid) {
        const Step s = step_from_token(d.step);
        if (s == Step::kStaging) {
            auto it = stage_resp.find(d.agent_id);
            if (it == stage_resp.end())
                continue;
            const StageResult r = parse_stage(it->second.status, it->second.output);
            if (r.outcome == PhaseOutcome::kOk)
                transitions.push_back({d.agent_id, "staging", "staged", 0, ""});
            else if (r.outcome == PhaseOutcome::kFailed)
                transitions.push_back({d.agent_id, "staging", "failed", 0, r.error});
        } else if (s == Step::kExecuting) {
            auto it = exec_resp.find(d.agent_id);
            if (it == exec_resp.end())
                continue;
            const ExecResult r = parse_exec(it->second.status, it->second.output);
            if (r.outcome == PhaseOutcome::kOk)
                transitions.push_back({d.agent_id, "executing", "succeeded", r.exit_code, ""});
            else if (r.outcome == PhaseOutcome::kFailed)
                transitions.push_back({d.agent_id, "executing", "failed", r.exit_code, r.error});
        }
    }
    if (!transitions.empty())
        deps.store->apply_results(deployment_id, transitions);

    // ── 3. Re-read on fresh state for the dispatch decisions ─────────────────
    grid = deps.store->get_devices(deployment_id);

    // ── 4. Skip out-of-scope devices (pending/staged, never executed) ────────
    std::vector<std::string> skip;
    for (const auto& d : grid) {
        const Step s = step_from_token(d.step);
        if ((s == Step::kPending || s == Step::kStaged) && authorized.find(d.agent_id) == authorized.end())
            skip.push_back(d.agent_id);
    }
    if (!skip.empty())
        deps.store->mark_skipped(deployment_id, skip);

    // ── 5. CAS-claim + dispatch STAGE to authorized 'pending' devices ────────
    if (deps.dispatch_fn) {
        std::vector<std::string> cand;
        for (const auto& d : grid)
            if (step_from_token(d.step) == Step::kPending &&
                authorized.find(d.agent_id) != authorized.end())
                cand.push_back(d.agent_id);
        auto claimed = deps.store->claim_for_stage(deployment_id, cand);
        if (!claimed.empty()) {
            const auto outcome = deps.dispatch_fn(
                "content_dist", "stage", claimed, "",
                {{"url", cfg.url}, {"filename", cfg.filename}, {"sha256", cfg.sha256}},
                stage_execution_id(deployment_id), pipeline_caller);
            settle_claimed_batch(deps, deployment_id, "stage", claimed, outcome,
                                 step_token(Step::kStaging), step_token(Step::kPending),
                                 step_token(Step::kFailed), pipeline_caller.exec_visible);
        }
    }

    // ── 6. CAS-claim + dispatch EXECUTE to authorized 'staged' devices ───────
    // claim_for_exec is the execute-once guard: only rows still 'staged' are
    // claimed + dispatched, exactly once across concurrent advances / restart.
    if (deps.dispatch_fn) {
        std::vector<std::string> cand;
        for (const auto& d : grid)
            if (step_from_token(d.step) == Step::kStaged &&
                authorized.find(d.agent_id) != authorized.end())
                cand.push_back(d.agent_id);
        auto claimed = deps.store->claim_for_exec(deployment_id, cand);
        if (!claimed.empty()) {
            std::unordered_map<std::string, std::string> params{{"filename", cfg.filename},
                                                                {"expected_hash", cfg.sha256}};
            if (!cfg.args.empty())
                params["args"] = cfg.args;
            const auto outcome =
                deps.dispatch_fn("content_dist", "execute_staged", claimed, "", params,
                                 exec_execution_id(deployment_id), pipeline_caller);
            // The execute-once property is PRESERVED, not weakened, by
            // settle_claimed_batch's revert path below: claim_for_exec still
            // claims each row exactly once per call, and a revert only
            // returns a row to 'staged' so a LATER tick's claim_for_exec can
            // claim it again — that is a second CLAIM, not a second
            // EXECUTION of a command that was never actually dispatched.
            settle_claimed_batch(deps, deployment_id, "execute", claimed, outcome,
                                 step_token(Step::kExecuting), step_token(Step::kStaged),
                                 step_token(Step::kFailed), pipeline_caller.exec_visible);
        }
    }

    // ── 7. Recompute summary + complete if every device is settled ───────────
    deps.store->refresh_counts(deployment_id);
    deps.store->complete_deployment(deployment_id, now_ms());
}

} // namespace yuzu::server::deployment
