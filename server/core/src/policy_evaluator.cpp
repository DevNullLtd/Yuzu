#include "policy_evaluator.hpp"

#include "agent_registry.hpp"
#include "compliance_eval.hpp"
#include "custom_properties_store.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "mcp_jsonrpc.hpp" // json_exceeds_depth / kMcpMaxJsonDepth (#2437-class depth guard)
#include "policy_store.hpp"
#include "response_store.hpp"
#include "result_envelope.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <yuzu/server/auth.hpp>

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>

#include <chrono>
#include <format>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

// CommandResponse::Status enum values (proto/yuzu/agent/v1/agent.proto).
constexpr int kStatusRunning = 0;
constexpr int kStatusSuccess = 1;
constexpr int kStatusFailure = 2;
constexpr int kStatusTimeout = 3;
constexpr int kStatusRejected = 4;

bool is_terminal_failure(int status) {
    return status == kStatusFailure || status == kStatusTimeout || status == kStatusRejected;
}

/// Substitute every `{{inputs.NAME}}` placeholder in `s` with the matching
/// policy input value (empty if absent). This mirrors the fragment-parameter
/// templating convention used in the policy YAML (the store keeps the raw
/// `{{inputs.X}}` text; interpolation happens at dispatch time).
std::string interpolate_inputs(std::string s,
                               const std::unordered_map<std::string, std::string>& inmap) {
    const std::string pre = "{{inputs.";
    size_t pos = 0;
    while ((pos = s.find(pre, pos)) != std::string::npos) {
        auto end = s.find("}}", pos);
        if (end == std::string::npos)
            break;
        auto name = s.substr(pos + pre.size(), end - (pos + pre.size()));
        // trim surrounding whitespace in the name
        auto b = name.find_first_not_of(" \t");
        auto e = name.find_last_not_of(" \t");
        if (b != std::string::npos)
            name = name.substr(b, e - b + 1);
        auto it = inmap.find(name);
        std::string val = (it != inmap.end()) ? it->second : "";
        s.replace(pos, end + 2 - pos, val);
        pos += val.size();
    }
    return s;
}

/// Build a dispatch parameter map from a fragment's `*_parameters` JSON object
/// plus the policy inputs, interpolating `{{inputs.NAME}}` placeholders.
std::unordered_map<std::string, std::string>
build_params(const std::string& params_json, const std::vector<PolicyInput>& inputs) {
    std::unordered_map<std::string, std::string> inmap;
    for (const auto& i : inputs)
        inmap[i.key] = i.value;

    std::unordered_map<std::string, std::string> out;
    if (params_json.empty())
        return out;
    auto j = nlohmann::json::parse(params_json, nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    for (const auto& [k, v] : j.items()) {
        std::string sval = v.is_string() ? v.get<std::string>() : v.dump();
        out[k] = interpolate_inputs(std::move(sval), inmap);
    }
    return out;
}

std::string map_to_json_obj(const std::unordered_map<std::string, std::string>& m) {
    nlohmann::json o = nlohmann::json::object();
    for (const auto& [k, v] : m)
        o[k] = v;
    return o.dump();
}

std::unordered_map<std::string, std::string> params_from_json_obj(const std::string& s) {
    std::unordered_map<std::string, std::string> out;
    if (s.empty())
        return out;
    auto j = nlohmann::json::parse(s, nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    for (const auto& [k, v] : j.items())
        out[k] = v.is_string() ? v.get<std::string>() : v.dump();
    return out;
}

/// Pick, per agent, the most informative response for an execution: prefer a
/// terminal status over RUNNING, then non-empty output, then the later one.
std::unordered_map<std::string, StoredResponse>
latest_per_agent(const std::vector<StoredResponse>& rows) {
    auto score = [](const StoredResponse& r) {
        int s = 0;
        if (r.status != kStatusRunning)
            s += 2;
        if (!r.output.empty())
            s += 1;
        return s;
    };
    std::unordered_map<std::string, StoredResponse> best;
    for (const auto& r : rows) {
        auto it = best.find(r.agent_id);
        if (it == best.end()) {
            best.emplace(r.agent_id, r);
            continue;
        }
        if (score(r) > score(it->second) ||
            (score(r) == score(it->second) && r.timestamp >= it->second.timestamp))
            it->second = r;
    }
    return best;
}

/// Evaluate one agent's check response into a status string.
std::string verdict_for(const StoredResponse& r, const std::string& policy_id,
                        const std::string& instruction_id, const std::string& cel,
                        InstructionStore* istore) {
    if (is_terminal_failure(r.status))
        return "error"; // the check plugin itself failed/timed out/was rejected

    // Integrity guard (gov COMP-1 / UP-8): an empty compliance expression makes
    // evaluate_compliance() return `compliant` unconditionally (empty == always
    // true). A policy that checks nothing must NOT be reported as compliant —
    // that is false assurance. Treat a misconfigured (empty-CEL) check as an
    // error so it surfaces distinctly instead of inflating the posture number.
    if (cel.empty())
        return "error";

    // #2437-class guard: r.output is agent-reported plugin output with no
    // write-side type bound (unlike check_parameters, already confirmed
    // Bucket-E safe), so an agent can freely report a deeply-nested shape
    // here. parse_result's nlohmann::json::parse tolerates very deep input,
    // but the structured-result branch a few lines below calls val.dump() on
    // every non-string row value, which IS unboundedly recursive and SIGSEGVs
    // the whole process well under 1 MiB of nesting (see mcp_jsonrpc.hpp's
    // json_exceeds_depth doc comment, measured not assumed). Reject on the
    // RAW text before parse_result, or anything else, ever interprets it.
    //
    // This must fail CLOSED: this evaluator's whole job is a compliance
    // verdict that can trigger real remediation, so a poisoned response is
    // routed onto the SAME "error" outcome already used above for a failed
    // check or misconfigured policy, never silently falling through to CEL
    // evaluation over a partially-salvaged shape (which could coincidentally
    // read as compliant depending on the policy's own CEL expression), and
    // never "compliant". Never logs the payload itself, only identifiers.
    //
    // Accepted tradeoff: r.output is not guaranteed to BE JSON at all (see
    // parse_result's raw-text fallback below for genuinely non-JSON output),
    // and json_exceeds_depth is a raw-text bracket scanner, not a JSON
    // validator - plain-text output with 33+ net unclosed '['/'{' (rare;
    // balanced brackets cancel in the depth counter) now reads as "error"
    // instead of reaching parse_result's raw-text fallback and being
    // CEL-evaluated. This is a narrowing of what output this evaluator can
    // interpret, not a correctness or security defect: the direction is
    // still fail-closed (never "compliant"), so it cannot manufacture a
    // false-compliant verdict. Checking depth only after confirming valid
    // JSON would require a second, DOM-based depth check downstream of
    // parse_result - i.e. exactly the recursive traversal this guard exists
    // to avoid - so the guard deliberately stays a pre-parse text scan.
    if (yuzu::server::mcp::json_exceeds_depth(r.output, yuzu::server::mcp::kMcpMaxJsonDepth)) {
        spdlog::error("policy_evaluator: policy {} check {} response from agent {} has output "
                     "nested past the depth guard (max {}); treating as evaluation error, "
                     "cannot be safely parsed",
                     policy_id, instruction_id, r.agent_id, yuzu::server::mcp::kMcpMaxJsonDepth);
        return "error";
    }

    std::string schema;
    if (istore) {
        // ADR-0058: get_definition now returns std::expected<optional<...>, string>. A
        // not-found id leaves schema empty, matching pre-migration behaviour (parse_result
        // tolerates an empty schema) — the check already dispatched successfully against a
        // known instruction, so a since-deleted definition is a narrow edge case, not a
        // reason to error the verdict. A genuine DB error is NOT the same: proceeding with
        // an empty schema on a type-blind parse could silently produce a WRONG
        // compliant/non_compliant verdict instead of surfacing the infrastructure failure
        // (gov Gate 3 architect finding) — persisted straight into SOC2-relevant compliance
        // posture data via update_agent_status.
        auto def_result = istore->get_definition(instruction_id);
        if (!def_result)
            return "error";
        if (*def_result)
            schema = (*def_result)->result_schema;
    }
    InstructionResult ir = parse_result(r.output, schema);
    // CEL resolves `result.<field>` by stripping the `result.` prefix and
    // looking up the BARE field name (cel_eval.cpp resolve_variable), so the
    // fields map must use bare keys — NOT a `result.`-prefixed key.
    std::map<std::string, std::string> fields;
    if (!ir.rows.empty()) {
        for (const auto& [k, v] : ir.rows.front().values)
            fields[k] = v;
    }
    switch (evaluate_compliance(cel, fields)) {
    case ComplianceResult::compliant:
        return "compliant";
    case ComplianceResult::non_compliant:
        return "non_compliant";
    default:
        return "error";
    }
}

std::string make_check_result(const StoredResponse& r) {
    nlohmann::json j;
    j["status"] = r.status;
    j["output"] = r.output.size() > 1000 ? r.output.substr(0, 1000) : r.output;
    return j.dump();
}

/// HA WS-3 3.4 (fold-in #3, PR #3939 review / #3424 / #3511): `.sent` is a
/// COUNT, never a set of ids — the DELIVERED subset of `claimed` can only be
/// recovered by walking `outcome`'s per-id fields, mirroring
/// deployment_engine.cpp's `settle_claimed_batch` residual accounting
/// exactly. PolicyEvaluator's dispatch always runs as
/// `DispatchCaller{.system = true}` (server.cpp's `command_dispatch_fn`),
/// i.e. `exec_visible = nullopt` (unfiltered) — unlike deployment_engine.cpp
/// there is therefore no exec_visible-excluded residual to compute here; a
/// caller-visibility narrowing simply cannot happen on this dispatch path.
std::vector<std::string>
compute_delivered(const std::vector<std::string>& claimed,
                  const yuzu::server::ConfinedDispatchOutcome& outcome) {
    if (outcome.containment_unreadable)
        // The gate itself failed closed: every id was withheld before its
        // `send_to`, so none appear in `not_sent`/denied and the per-id
        // accounting below cannot see them -- it would wrongly compute them as
        // DELIVERED (claimed minus an empty not-delivered set). Treat the whole
        // batch as not delivered.
        //
        // `route_unreadable` is DELIBERATELY NOT handled here (WS-4 4.2b Task
        // D's first cut lumped it in). A degraded GatewayRouteStore read does
        // NOT force `sent == 0` (see `ConfinedDispatchOutcome::route_unreadable`
        // -- the arm walk still ran; directory-only devices land in `not_sent`,
        // locally-connected ones were genuinely delivered). Returning `{}` here
        // would report those genuinely-delivered devices as not-delivered,
        // regressing the per-(policy,agent) delivered CAS and re-dispatching
        // them next tick. The per-id accounting below already excludes the
        // `not_sent` (directory-degraded) devices and reports the delivered
        // ones correctly, so let it run.
        return {};

    std::unordered_set<std::string> not_delivered;
    for (const auto& a : outcome.denied_quarantined)
        not_delivered.insert(a);
    for (const auto& a : outcome.unknown_plugin)
        not_delivered.insert(a);
    for (const auto& a : outcome.not_sent)
        not_delivered.insert(a);

    // Residual: nothing in `claimed` was individually identified (no named
    // permanent withhold, no not_sent) AND nothing was sent either — a
    // chokepoint denial before the per-id arm walk ever ran. Only reachable
    // when outcome.sent == 0; once anything was sent, denied, plugin-absent,
    // or not_sent, the count and the identified ids line up exactly and this
    // is empty by construction (matches settle_claimed_batch's own residual).
    if (outcome.sent == 0 && claimed.size() > not_delivered.size())
        for (const auto& a : claimed)
            not_delivered.insert(a);

    std::vector<std::string> delivered;
    delivered.reserve(claimed.size());
    for (const auto& a : claimed)
        if (!not_delivered.count(a))
            delivered.push_back(a);
    return delivered;
}

} // namespace

PolicyEvaluator::PolicyEvaluator(Deps deps) : d_(std::move(deps)) {
    if (!d_.now_fn) {
        d_.now_fn = [] {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        };
    }

    // ADR-0056: the boot-time stranded-'fixing' reset that used to live here
    // is gone — under N replicas, resetting EVERY 'fixing' row on EVERY
    // process restart (a routine rolling-deploy event, not just a crash)
    // would stomp another replica's still-live remediation. Superseded by
    // PolicyStore::claim_due_policies' per-tick, age-gated staleness sweep
    // (last_fix_at older than Deps::fixing_stale_seconds), which runs
    // continuously rather than only at boot.
}

int64_t PolicyEvaluator::now() const { return d_.now_fn(); }

std::string PolicyEvaluator::gen_execution_id() {
    return "polchk-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
}

std::vector<std::string> PolicyEvaluator::resolve_targets(const Policy& p,
                                                          std::string* out_reason) const {
    std::vector<std::string> out;
    std::set<std::string> seen;
    if (!p.management_groups.empty() && d_.mgmt_group_store) {
        for (const auto& g : p.management_groups)
            for (const auto& m : d_.mgmt_group_store->get_members(g))
                if (seen.insert(m.agent_id).second)
                    out.push_back(m.agent_id);
    } else if (!p.scope_expression.empty() && d_.registry) {
        auto parsed = yuzu::scope::parse(p.scope_expression);
        if (parsed) {
            // No rs_store/principal passed. A from_result_set: atom in a
            // policy scope now ABORTS (H1, 2026-07-29) and value_or({})
            // collapses that to zero targets — evaluate nothing, the safe
            // direction. Unreachable today (create_policy rejects
            // fromResultSet:, PR-E2 pending) but the comment must not claim
            // "cannot degrade" on an authz-adjacent branch.
            //
            // #4981 PR-1 B6: this call site bypasses the dispatch ladder, so
            // it owns its OWN observability for a degraded evaluation — the
            // ladder's audit_scope_evaluation_aborted (server.cpp) never
            // fires for this path. Increment here, never inside
            // AgentRegistry::evaluate_scope itself (that would double-count
            // every ladder-routed caller, which already increments via the
            // audit path).
            auto result = d_.registry->evaluate_scope(*parsed, d_.tag_store,
                                                      d_.custom_properties_store);
            if (!result) {
                if (d_.metrics)
                    d_.metrics
                        ->counter("yuzu_scope_eval_degraded_total",
                                  {{"reason", to_string(result.error().kind)}})
                        .increment();
                if (out_reason)
                    *out_reason = to_string(result.error().kind);
            }
            auto matched = std::move(result).value_or(std::vector<std::string>{});
            for (const auto& a : matched)
                if (seen.insert(a).second)
                    out.push_back(a);
        }
    }
    return out;
}

std::expected<PolicyEvaluator::DispatchInstructionResult, std::string>
PolicyEvaluator::dispatch_instruction(const std::string& instruction_id,
                                      const std::unordered_map<std::string, std::string>& parameters,
                                      const std::vector<std::string>& targets) {
    if (targets.empty() || !d_.dispatch_fn)
        return DispatchInstructionResult{};
    // db_error, not a legitimate no-op (gov Gate 3 architect finding): a null
    // instruction_store is a genuine unavailability, not "no targets"/"unknown
    // instruction" — collapsing it into the same "" those return would silently
    // skip dispatch instead of surfacing degraded. Currently unreachable (this
    // Deps struct is only ever constructed with a live instruction_store — same
    // boot-latch shape as workflow_routes.cpp's uninstall_fn), kept correct as
    // defense-in-depth against that invariant changing.
    if (!d_.instruction_store)
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "instruction store unavailable");
    // ADR-0058: get_definition now returns std::expected<optional<...>, string>.
    // A genuine DB error must surface as `unexpected` — never collapse into the
    // same "" a not-found id legitimately returns (that fail-open is exactly
    // what ADR-0036 exists to close on an authorization/dispatch-adjacent
    // read). Every caller already propagates a std::expected error the same
    // way it propagates its own other degrade paths.
    auto def_result = d_.instruction_store->get_definition(instruction_id);
    if (!def_result) {
        spdlog::warn("policy_evaluator: instruction store unavailable resolving '{}': {}",
                     instruction_id, def_result.error());
        return std::unexpected(def_result.error());
    }
    if (!*def_result) {
        spdlog::warn("policy_evaluator: unknown check/fix instruction '{}'", instruction_id);
        return DispatchInstructionResult{};
    }
    const auto& def = **def_result;
    auto execid = gen_execution_id();
    auto outcome = d_.dispatch_fn(def.plugin, def.action, targets, /*scope_expr=*/"", parameters,
                                  execid);
    return DispatchInstructionResult{.execution_id = execid, .outcome = std::move(outcome)};
}

std::expected<std::string, std::string> PolicyEvaluator::kickoff_check(const Policy& p) {
    if (!d_.policy_store)
        return std::unexpected("policy store not wired");
    auto frag_res = d_.policy_store->get_fragment(p.fragment_id);
    if (!frag_res) {
        // ADR-0036: a degraded read must not be treated as "no fragment" —
        // and must not collapse into the same "" a legitimate no-op returns
        // either (adversarial review / governance, 2026-08-24): a bare ""
        // here was indistinguishable from "no check instruction" / "no
        // targets" / "check already in flight" one level up, so evaluate_now()
        // surfaced this as a false REST 409 instead of a 503.
        spdlog::warn("policy_evaluator: kickoff_check: degraded fragment read for policy {}",
                     p.id);
        return std::unexpected("degraded fragment read for policy " + p.id);
    }
    if (!*frag_res || (*frag_res)->check_instruction.empty())
        return "";
    const PolicyFragment& frag = **frag_res;
    // #4981 PR-1 adversarial-review MEDIUM fix: distinguish "the policy's
    // scope genuinely matched nobody" from "the scope evaluation itself
    // degraded/aborted" (the same distinction `remediate()`'s
    // `degrade_reason` already makes below) — without this, a
    // PresenceDegraded/StoreDegraded abort collapsed to an empty target
    // list here, and evaluate_now() surfaced it as a false REST 409
    // "matches no agents" instead of the 503 every other degraded read on
    // this path already gets (see the ADR-0036 comment on the fragment-read
    // degrade a few lines above, which this exact defect class exists to
    // close).
    std::string degrade_reason;
    auto targets = resolve_targets(p, &degrade_reason);
    if (!degrade_reason.empty())
        return std::unexpected("scope evaluation degraded: " + degrade_reason);
    if (targets.empty())
        return "";

    // Dedupe (gov UP-5 / UP-13): if a Check for this policy is already in flight,
    // do not dispatch another — otherwise rapid /evaluate calls or a tick landing
    // on a still-maturing check pile up duplicate in-flights (unbounded growth)
    // and a stale collect can overwrite a fresher verdict.
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& f : in_flight_)
            if (f.phase == Phase::Check && f.policy_id == p.id)
                return "";
    }

    auto params = build_params(frag.check_parameters, p.inputs);
    // dispatch_instruction invokes the blocking dispatch_fn — call it WITHOUT mu_.
    // ADR-0058: a genuine InstructionStore error propagates as `unexpected` here
    // too, the same way the degraded-fragment-read path above does.
    auto dispatch_result = dispatch_instruction(frag.check_instruction, params, targets);
    if (!dispatch_result)
        return std::unexpected(dispatch_result.error());
    if (dispatch_result->execution_id.empty())
        return "";
    const std::string& execid = dispatch_result->execution_id;

    {
        std::lock_guard<std::mutex> lk(mu_);
        in_flight_.push_back(InFlight{.phase = Phase::Check,
                                      .policy_id = p.id,
                                      .execution_id = execid,
                                      .instruction_id = frag.check_instruction,
                                      .compliance_expr = frag.check_compliance,
                                      .targets = std::move(targets),
                                      .dispatched_at = now(),
                                      .verify_instruction = "",
                                      .verify_compliance = "",
                                      .verify_parameters_json = ""});
    }
    return execid;
}

void PolicyEvaluator::dispatch_due() {
    if (!d_.policy_store)
        return;
    // ADR-0056: due-ness is now a durable, fleet-wide single-sweeper claim —
    // exactly one replica claims (and sweeps stranded 'fixing' rows) per
    // tick. Lock-not-acquired returns an empty, non-error result (another
    // replica claimed this tick); a genuine DB error is `unexpected` and
    // MUST be treated as "skip this tick", never silently as "nothing due".
    // This durable claim also structurally closes the ABA hazard the earlier
    // in-memory last_eval_/EvalClaim generation-counter CAS (gov Gate 8) was
    // patching — that mechanism no longer exists here; see ADR-0058's
    // Consequences.
    auto claimed =
        d_.policy_store->claim_due_policies(now(), d_.default_interval_seconds,
                                            d_.fixing_stale_seconds);
    if (!claimed) {
        // sre (governance, 2026-08-24): this is the ADR's own stated worst
        // case for this store — a persistently failing claim means
        // compliance checks silently stop running fleet-wide. A warn-only
        // log with no counter left that failure mode with no alerting
        // surface at all.
        spdlog::error("policy_evaluator: claim_due_policies degraded, skipping tick: {}",
                     claimed.error());
        if (d_.metrics)
            d_.metrics->counter("yuzu_server_policy_eval_errors_total", {{"phase", "claim"}})
                .increment();
        return;
    }
    // #3495 (governance Gate 4 unhappy-path, 2026-08-30, UP-1/UP-2):
    // Deps::should_stop is DELIBERATELY NOT checked in this loop, unlike its
    // siblings in collect_ready() (above) and every other engine's tick
    // loop. claim_due_policies just durably stamped `last_dispatched_at` for
    // EVERY policy in `claimed`, in ONE transaction, unconditionally — a
    // should_stop break here would leave the un-processed tail claimed but
    // never actually checked. An earlier version of this comment claimed
    // that was "recovered by the staleness sweep (fixing_stale_seconds)" —
    // that claim was FALSE: the sweep only resets `status='fixing'` rows
    // (mid-remediation), never `policy_dispatch_state.last_dispatched_at`.
    // The real consequence of breaking here is every claimed-but-skipped
    // policy silently reading as "already checked this interval" and not
    // being reconsidered until `default_interval_seconds` (3600s default)
    // elapses — a fleet-wide, counter-less, log-less compliance-check gap on
    // the single most common shutdown trigger (a rolling deploy), not a
    // bounded one-tick defer. DO NOT reintroduce a should_stop check here
    // without first giving claim_due_policies a way to release an unclaimed
    // tail back to "due" (a new PolicyStore method — out of scope for a
    // should_stop check). The primary #3495 fix (agent_server_->
    // Shutdown(deadline) now running before policy_eval_thread_'s join)
    // still bounds this loop's total wall time on its own: only the FIRST
    // kickoff_check() call can genuinely block on a stalled stream write —
    // once Shutdown's deadline elapses and forcibly cancels it, every
    // dispatch_fn call attempted afterward against the now-shut-down gRPC
    // server fails fast, so an un-gated loop over N claimed policies does
    // not multiply the shutdown-time cost by N.
    for (const auto& p : *claimed) {
        auto k = kickoff_check(p); // does its own brief locking; dispatch runs without mu_
        if (!k) {
            // Governance UP-2 (2026-08-24): this policy's durable dispatch
            // claim already committed as part of `claimed`'s single
            // transaction — a degraded kickoff_check here leaves it claimed
            // but never actually dispatched, silently skipping this policy
            // for the rest of its interval. Same consequence class as the
            // claim-failure counter above; give it the same visibility. This
            // also covers a genuine InstructionStore error (ADR-0058) —
            // kickoff_check propagates it as `unexpected` the same way it
            // propagates a degraded fragment read.
            spdlog::warn("policy_evaluator: dispatch_due: kickoff_check degraded for policy {}: {}",
                        p.id, k.error());
            if (d_.metrics)
                d_.metrics->counter("yuzu_server_policy_eval_errors_total", {{"phase", "dispatch"}})
                    .increment();
        }
    }
}

std::expected<std::string, std::string>
PolicyEvaluator::evaluate_now(const std::string& policy_id) {
    if (!d_.policy_store)
        return std::unexpected("policy store not wired");
    auto p_res = d_.policy_store->get_policy(policy_id);
    if (!p_res) {
        spdlog::warn("policy_evaluator: evaluate_now: degraded policy read for {}", policy_id);
        return std::unexpected("degraded policy read for " + policy_id);
    }
    if (!*p_res)
        return "";
    // Manual, operator-triggered — bypasses the interval claim entirely (an
    // explicit "check now" request), matching the pre-ADR-0056 behavior.
    // Runs on whichever replica received the REST call; if that replica
    // dies before its own collect_ready() matures this check, it strands —
    // an accepted, narrow residual (ADR-0056 Follow-ups): the operator has
    // a natural retry action.
    //
    // Stamp the durable claim record BEFORE dispatch (claim-before-dispatch,
    // matching claim_due_policies' own claim-then-dispatch order and the
    // pre-ADR-0056 last_eval_ ordering) — kickoff_check's dispatch_fn is
    // blocking gRPC/gateway I/O; stamping after it leaves a real window
    // where a concurrent tick (this replica's background thread, or a
    // sibling replica) sees no row yet and re-dispatches before this
    // manual check's network call even returns. Stamping unconditionally,
    // even if dispatch below ends up failing, matches the original in
    // WHO consumes the interval slot: a failed manual check still consumed
    // it. It does NOT match the original in BLAST RADIUS (governance UP-1,
    // 2026-08-24): the old last_eval_ was per-replica in-memory, so a
    // failed dispatch only cost that one replica's view of the interval —
    // a sibling replica's own last_eval_ was untouched. This stamp is
    // durable and fleet-wide, so the same failure now costs every replica
    // the interval, not just one. Self-heals after one interval; tracked,
    // not fixed, in ADR-0056's Follow-ups (same class as UP-2's
    // dispatch_due() equivalent, just above).
    // If the stamp itself fails, do NOT dispatch (adversarial review,
    // 2026-08-24): the correction above only closed "dispatch succeeded but
    // the stamp was never attempted" — a failed record_dispatch call is the
    // same durable-claim-blind outcome by a different path (the operator's
    // check would still run, still return 202, and the very next automatic
    // tick would see no row and re-claim/re-dispatch it immediately). This
    // is a plain runtime store error on an authoritative write (ADR-0012
    // §1) — surface it as "did not dispatch," never as silent success.
    auto r = d_.policy_store->record_dispatch(policy_id, now());
    if (!r) {
        spdlog::warn("policy_evaluator: evaluate_now: record_dispatch failed for {}: {} — "
                    "not dispatching (would leave the durable claim blind)",
                    policy_id, r.error());
        return std::unexpected("dispatch claim failed for " + policy_id + ": " + r.error());
    }
    auto k = kickoff_check(**p_res); // dispatch runs without mu_ held
    if (!k)
        return std::unexpected("kickoff_check degraded for " + policy_id + ": " + k.error());
    return *k;
}

PolicyEvaluator::RemediateResult
PolicyEvaluator::remediate(const std::string& policy_id,
                           const std::vector<std::string>& agent_ids) {
    RemediateResult out;
    if (!d_.policy_store) {
        out.error = "policy store unavailable";
        out.degraded = true;
        return out;
    }
    auto p_res = d_.policy_store->get_policy(policy_id);
    if (!p_res) {
        out.error = "policy store degraded — try again";
        out.degraded = true;
        return out;
    }
    if (!*p_res) {
        out.error = "policy not found";
        return out;
    }
    const Policy& p_ref = **p_res;
    auto frag_res = d_.policy_store->get_fragment(p_ref.fragment_id);
    if (!frag_res) {
        out.error = "policy store degraded — try again";
        out.degraded = true;
        return out;
    }
    if (!*frag_res || (*frag_res)->fix_instruction.empty()) {
        out.error = "policy has no remediation pathway (fragment defines no fix_instruction)";
        return out;
    }
    const PolicyFragment& frag_ref = **frag_res;
    // p/frag below keep the original body's pointer-like access working
    // (arrow syntax) without renaming every subsequent use.
    const Policy* p = &p_ref;
    const PolicyFragment* frag = &frag_ref;

    std::vector<std::string> targets;
    if (agent_ids.empty()) {
        auto statuses = d_.policy_store->get_policy_agent_statuses(policy_id);
        if (!statuses) {
            // ADR-0036: a degraded read must not resolve to "0 non-compliant
            // agents" — that would silently remediate nobody when the
            // operator asked to fix everyone non-compliant.
            out.error = "policy store degraded — could not determine remediation targets";
            out.degraded = true;
            return out;
        }
        for (const auto& s : *statuses)
            if (s.status == "non_compliant")
                targets.push_back(s.agent_id);
    } else {
        // Confused-deputy guard (gov sec-MEDIUM): a caller-supplied agent list
        // must be intersected with the policy's own scope. Otherwise a
        // Policy:Execute holder could dispatch the fragment's fix instruction to
        // arbitrary fleet agents the policy never targets.
        //
        // #4981 PR-1 B6: `degrade_reason` distinguishes "the policy's scope
        // genuinely matched nobody" from "the scope evaluation itself could
        // not be trusted" (a presence/store degradation) — without this, an
        // operator sees the same generic refusal for both, and the latter
        // reads as a much less actionable message than it should.
        std::string degrade_reason;
        auto scoped = resolve_targets(*p, &degrade_reason);
        std::set<std::string> allowed(scoped.begin(), scoped.end());
        for (const auto& a : agent_ids)
            if (allowed.count(a))
                targets.push_back(a);
        if (targets.empty()) {
            out.error = degrade_reason.empty()
                          ? "no in-scope agents to remediate (requested agents are outside the "
                            "policy's scope)"
                          : "could not determine the policy's scope (" + degrade_reason +
                                ") — remediation target resolution aborted, not evaluated as "
                                "empty";
            // #4981 PR-1 adversarial-review MEDIUM fix: a degraded scope
            // evaluation is an infrastructure fault, not an operator denial —
            // route this the same way every other degraded read in this
            // function already does (out.degraded = true -> 503/"error",
            // not 400/"denied"). Without this, the message above correctly
            // NAMED the degradation but the REST route still answered
            // 400 audited as "denied", exactly the false-classification
            // class ADR-0036 exists to close.
            if (!degrade_reason.empty())
                out.degraded = true;
            return out;
        }
    }
    if (targets.empty()) {
        out.error = "no non_compliant agents to remediate";
        return out;
    }

    // HA WS-3 3.4: claim BEFORE dispatch via a durable per-(policy,agent) CAS
    // in PolicyStore, replacing the old process-local `remediating_`/
    // `ReservationGuard` reservation (ADR-2002 §6 finding 6a) — that guard
    // only ever covered same-process concurrency (two REST calls landing on
    // THIS replica); a sibling replica's independent remediate() call for
    // the same policy had no shared state to see and would dispatch a
    // second, genuinely duplicate fix, double-incrementing
    // update_agent_status's fix_attempt_count on a fix instruction that may
    // not be idempotent. The durable claim closes that gap: it is visible to
    // every replica immediately, per agent (finer-grained than the old
    // per-policy guard), and the SAME `fixing_stale_seconds` window
    // claim_due_policies' own stranded-fixing sweep uses ages it out if the
    // claiming replica dies mid-flight (see collect_ready()'s FixWait
    // maturation and the sweep itself for the two release paths).
    auto claim_result =
        d_.policy_store->claim_remediation(policy_id, targets, d_.fixing_stale_seconds);
    if (!claim_result) {
        out.error = "policy store degraded — could not claim remediation targets";
        out.degraded = true;
        if (d_.metrics)
            // Distinct from dispatch_due's "claim" phase (line ~415, the leader-driven
            // claim_due_policies degrade): this is the operator-synchronous remediation
            // claim, a different failure site — keep them separately countable.
            d_.metrics->counter("yuzu_server_policy_eval_errors_total", {{"phase", "remediate_claim"}})
                .increment();
        return out;
    }
    const std::vector<std::string>& claimed = claim_result->ids;
    const int64_t claim_gen = claim_result->generation;
    if (claimed.empty()) {
        // Every requested target is either already mid-remediation (a live
        // claim — this replica or another) or has already exhausted its
        // retry cap — claim_remediation's WHERE guard cannot distinguish the
        // two without a second query (out of scope for this slice; tracked
        // as a follow-up), so this message states BOTH possible causes
        // honestly (agentic-first A4) rather than the misleading "already in
        // flight" alone, which would tell a capped, no-longer-in-flight
        // caller to retry forever. MUST keep the exact substring "already in
        // flight" — compliance_routes.cpp's handler classifies it to a 409,
        // and that contract must not change underneath it.
        out.error = "remediation already in flight or retry cap reached for this policy";
        return out;
    }

    auto fix_params = build_params(frag->fix_parameters, p->inputs);
    std::string verify_instr = !frag->post_check_instruction.empty() ? frag->post_check_instruction
                                                                     : frag->check_instruction;
    std::string verify_cel =
        !frag->post_check_compliance.empty() ? frag->post_check_compliance : frag->check_compliance;
    auto verify_params = build_params(
        !frag->post_check_parameters.empty() ? frag->post_check_parameters : frag->check_parameters,
        p->inputs);

    // Dispatch the fix to the CLAIMED subset only (never the full `targets`
    // — a target the claim above did not win must never be dispatched to).
    // dispatch_instruction must run without mu_ held.
    auto dispatch_result = dispatch_instruction(frag->fix_instruction, fix_params, claimed);
    if (!dispatch_result) {
        // Dispatch never happened — release every claim so it does not sit
        // orphaned until the stale window expires.
        auto rel = d_.policy_store->release_remediation_claim(policy_id, claimed, claim_gen);
        if (!rel)
            spdlog::warn("policy_evaluator: remediate: failed to release claim for policy {} "
                        "after a dispatch error: {}",
                        policy_id, rel.error());
        out.degraded = true;
        // Gate 3 ARCH-1: dispatch_result.error() carries raw PQerrorMessage() text on a
        // genuine DB failure — genericized here at the source so both consumers
        // (compliance_routes.cpp's audit row AND its POST /api/policies/:id/remediate
        // response body, both of which echo `out.error` verbatim) get the fix for free.
        out.error = yuzu::server::genericize_db_error("PolicyEvaluator::remediate dispatch",
                                                       dispatch_result.error());
        return out;
    }
    if (dispatch_result->execution_id.empty()) {
        auto rel = d_.policy_store->release_remediation_claim(policy_id, claimed, claim_gen);
        if (!rel)
            spdlog::warn("policy_evaluator: remediate: failed to release claim for policy {} "
                        "after an empty dispatch: {}",
                        policy_id, rel.error());
        out.error = "fix dispatch failed (unknown instruction or no agents)";
        return out;
    }
    const auto& execid = dispatch_result->execution_id;

    // fold-in #3 (PR #3939 review, #3424/#3511): `.sent` is a COUNT, not a
    // set — recompute the DELIVERED subset from the outcome's per-id fields.
    std::vector<std::string> delivered = compute_delivered(claimed, dispatch_result->outcome);
    std::vector<std::string> not_delivered;
    {
        std::unordered_set<std::string> delivered_set(delivered.begin(), delivered.end());
        for (const auto& a : claimed)
            if (!delivered_set.count(a))
                not_delivered.push_back(a);
    }
    if (!not_delivered.empty()) {
        // Release WITHOUT touching fix_attempt_count (ADR-2002 §6 finding
        // 6a(ii)): a failed DELIVERY must never burn a capped retry attempt.
        auto rel = d_.policy_store->release_remediation_claim(policy_id, not_delivered, claim_gen);
        if (!rel)
            spdlog::warn("policy_evaluator: remediate: failed to release claim for {} "
                        "not-delivered target(s) of policy {}: {}",
                        not_delivered.size(), policy_id, rel.error());
    }

    // Now mark fixing (increments the attempt counter; >3 auto-transitions to
    // error) — DELIVERED targets only.
    for (const auto& tgt : delivered) {
        auto r = d_.policy_store->update_agent_status(policy_id, tgt, "fixing", "", claim_gen);
        if (!r)
            spdlog::warn("policy_evaluator: remediate: failed to mark {} fixing for policy {}: {}",
                        tgt, policy_id, r.error());
        else if (!*r && d_.metrics)
            // fenced no-op — a sibling reclaimed this row between our claim and
            // this write (see PolicyStore::update_agent_status); visible so a
            // mis-threaded gen does not silently vanish every remediation.
            d_.metrics->counter("yuzu_server_policy_remediation_fence_skip_total").increment();
    }

    if (!delivered.empty()) {
        std::lock_guard<std::mutex> lk(mu_);
        in_flight_.push_back(InFlight{.phase = Phase::FixWait,
                                      .policy_id = policy_id,
                                      .execution_id = execid,
                                      .instruction_id = frag->fix_instruction,
                                      .compliance_expr = "",
                                      .targets = delivered,
                                      .dispatched_at = now(),
                                      .claim_gen = claim_gen,
                                      .verify_instruction = std::move(verify_instr),
                                      .verify_compliance = std::move(verify_cel),
                                      .verify_parameters_json = map_to_json_obj(verify_params)});
    }
    out.ok = true;
    out.execution_id = execid;
    // Honest count (agentic-first A4): a claimed-but-not-delivered target
    // (offline/not_sent, released above without burning a retry attempt) was
    // NOT remediated by this call — counting it here would overstate the
    // result to the caller.
    out.agents = static_cast<int>(delivered.size());
    return out;
}

void PolicyEvaluator::collect_ready() {
    int64_t t = now();
    std::vector<InFlight> ready;
    {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<InFlight> keep;
        for (auto& f : in_flight_) {
            if (t - f.dispatched_at >= d_.grace_seconds)
                ready.push_back(std::move(f));
            else
                keep.push_back(std::move(f));
        }
        in_flight_.swap(keep);
    }

    for (auto& f : ready) {
        // #3495: bounds how many MORE ready items this call processes once
        // shutdown begins — an item already being processed below still
        // finishes cleanly. Unlike dispatch_due()'s loop (below — see its
        // comment for why THAT one does NOT get a should_stop check), this
        // is safe to defer: `ready` is already per-replica, in-memory-only
        // state (see this file's header doc), with no durable claim behind
        // it. Governance Gate 4 unhappy-path (2026-08-30, UP-3) sharpened
        // the consequence: this is a REAL loss on the routine graceful-
        // shutdown path (not merely a restatement of ordinary restart loss —
        // a graceful shutdown happens far more often than a crash), but it
        // is a BOUNDED one: a dropped Check-phase item's stale verdict is
        // superseded the next time this same policy comes due (at most
        // `default_interval_seconds`); a dropped FixWait-phase item's
        // verify-dispatch is skipped, leaving `status='fixing'` until the
        // `fixing_stale_seconds` sweep resets it, then the next interval's
        // Check re-establishes the true state. Neither case silently
        // fleet-wide-skips checking the way an equivalent break in
        // dispatch_due() would.
        if (d_.should_stop && d_.should_stop()) {
            spdlog::info("policy_evaluator: collect_ready stopping early on shutdown - "
                         "remaining ready item(s) deferred");
            break;
        }
        // Degrade → empty (ADR-0039 deny-or-benign): a transient read failure
        // reads as "no terminal response yet", the same as a genuinely slow
        // agent — verdict_for() below already treats an unmatched target as
        // "unknown", never a fabricated compliant/drifted verdict.
        auto rows = d_.response_store
                        ? d_.response_store->query_by_execution(f.execution_id)
                              .value_or(std::vector<StoredResponse>{})
                        : std::vector<StoredResponse>{};
        auto best = latest_per_agent(rows);

        if (f.phase == Phase::Check) {
            for (const auto& tgt : f.targets) {
                auto it = best.find(tgt);
                std::string status, cr;
                if (it == best.end() || it->second.status == kStatusRunning) {
                    status = "unknown"; // no terminal response within the grace window
                } else {
                    status = verdict_for(it->second, f.policy_id, f.instruction_id,
                                         f.compliance_expr, d_.instruction_store);
                    cr = make_check_result(it->second);
                }
                if (d_.policy_store) {
                    // Shared Check-phase write: a REMEDIATION verify entry
                    // carries claim_gen != 0 and its verdict is fenced on it
                    // (a sibling may have reclaimed while the verify was in
                    // flight); an ordinary DETECTION entry carries 0 and writes
                    // unconditionally.
                    std::optional<int64_t> gen =
                        f.claim_gen != 0 ? std::optional<int64_t>(f.claim_gen) : std::nullopt;
                    auto r = d_.policy_store->update_agent_status(f.policy_id, tgt, status, cr, gen);
                    if (!r)
                        spdlog::warn("policy_evaluator: update_agent_status failed: {}", r.error());
                    else if (!*r && d_.metrics)
                        d_.metrics->counter("yuzu_server_policy_remediation_fence_skip_total")
                            .increment();
                }
                if (d_.metrics)
                    d_.metrics->counter("yuzu_server_policy_verdicts_total", {{"status", status}})
                        .increment();
            }
        } else { // Phase::FixWait — fix dispatched; failures error out, the rest go to verify.
            // HA WS-3 3.4: this FixWait entry maturing is the normal,
            // replica-local release path for the durable claim
            // remediate() took on these targets — the dispatching replica
            // is the only holder of this in-memory entry, so this stays
            // per-replica with nothing to coordinate (same reasoning as
            // update_agent_status's own per-replica FixWait writes below).
            // Released unconditionally, BEFORE the verify dispatch and
            // regardless of the fix's own outcome: whether a target's fix
            // failed (-> 'error' below) or succeeds (-> verify), its
            // remediation attempt is over either way, and a later
            // legitimate remediate() call for the same agent must not be
            // refused as "already in flight" by a claim this evaluator no
            // longer needs.
            if (d_.policy_store) {
                auto rel =
                    d_.policy_store->release_remediation_claim(f.policy_id, f.targets, f.claim_gen);
                if (!rel)
                    spdlog::warn("policy_evaluator: collect_ready: failed to release remediation "
                                "claim for policy {}: {}",
                                f.policy_id, rel.error());
            }
            std::vector<std::string> verify_targets;
            for (const auto& tgt : f.targets) {
                auto it = best.find(tgt);
                if (it != best.end() && is_terminal_failure(it->second.status)) {
                    if (d_.policy_store) {
                        auto r = d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error", R"({"phase":"fix","result":"failed"})",
                            f.claim_gen);
                        if (!r)
                            spdlog::warn("policy_evaluator: fix-failure status write failed for "
                                        "{}/{}: {}",
                                        f.policy_id, tgt, r.error());
                        else if (!*r && d_.metrics)
                            // fenced no-op: a sibling reclaimed after our
                            // release above — do not stomp its fresh 'fixing'.
                            d_.metrics
                                ->counter("yuzu_server_policy_remediation_fence_skip_total")
                                .increment();
                    }
                    if (d_.metrics)
                        d_.metrics
                            ->counter("yuzu_server_policy_eval_errors_total", {{"phase", "fix"}})
                            .increment();
                } else {
                    verify_targets.push_back(tgt);
                }
            }
            if (!verify_targets.empty()) {
                auto vparams = params_from_json_obj(f.verify_parameters_json);
                auto result = dispatch_instruction(f.verify_instruction, vparams, verify_targets);
                if (result && !result->execution_id.empty()) {
                    std::lock_guard<std::mutex> lk(mu_);
                    in_flight_.push_back(InFlight{.phase = Phase::Check,
                                                  .policy_id = f.policy_id,
                                                  .execution_id = result->execution_id,
                                                  .instruction_id = f.verify_instruction,
                                                  .compliance_expr = f.verify_compliance,
                                                  .targets = verify_targets,
                                                  .dispatched_at = now(),
                                                  // propagate the claim gen so the
                                                  // verify verdict write (:790) stays
                                                  // fenced on it.
                                                  .claim_gen = f.claim_gen,
                                                  .verify_instruction = "",
                                                  .verify_compliance = "",
                                                  .verify_parameters_json = ""});
                } else if (d_.policy_store) {
                    // A store-unavailable verify dispatch is a transient infra failure, not
                    // a genuine post-fix verification failure — the result JSON records which
                    // it was rather than collapsing both into the same "dispatch_failed".
                    const char* result_tag = !result ? "store_unavailable" : "dispatch_failed";
                    for (const auto& tgt : verify_targets) {
                        auto r = d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error",
                            std::format(R"({{"phase":"verify","result":"{}"}})", result_tag),
                            f.claim_gen);
                        if (!r)
                            spdlog::warn("policy_evaluator: verify-dispatch-failed status write "
                                        "failed for {}/{}: {}",
                                        f.policy_id, tgt, r.error());
                        else if (!*r && d_.metrics)
                            d_.metrics
                                ->counter("yuzu_server_policy_remediation_fence_skip_total")
                                .increment();
                        if (d_.metrics)
                            d_.metrics
                                ->counter("yuzu_server_policy_eval_errors_total",
                                          {{"phase", "verify"}})
                                .increment();
                    }
                }
            }
        }
    }
}

void PolicyEvaluator::tick(bool dispatch_due_allowed) {
    // collect_ready() ALWAYS runs on its owning replica (WS-3 3.2, PR #4134 review):
    // it is the ONLY production path that matures an in-flight Check/FixWait record —
    // created by the operator-synchronous evaluate_now()/remediate() REST handlers,
    // which run on whichever replica received the call — to a terminal verdict. It is
    // replica-local + in-memory and takes no durable claim needing fencing, so gating
    // it would strand an accepted operator remediation as `fixing` forever on any
    // non-leader (the two-dispatch-planes rule: never fence an operator-synchronous
    // path). Only dispatch_due() — the leader-owned durable due-policy scheduling
    // (ADR-0056 claim_due_policies) — is fenced, via `dispatch_due_allowed`.
    collect_ready();
    if (dispatch_due_allowed)
        dispatch_due();
}

} // namespace yuzu::server
