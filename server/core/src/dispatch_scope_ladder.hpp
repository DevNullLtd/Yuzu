#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>

#include "agent_registry.hpp"
#include "authz_model.hpp"
#include "custom_properties_store.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_route_fallback.hpp"
#include "dispatch_target_shape.hpp"
#include "execution_tracker.hpp"
#include "gateway_route_store.hpp"
#include "management_group_store.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"
#include "scope_yaml.hpp"
#include "tag_store.hpp"

/// @file dispatch_scope_ladder.hpp
/// ADR-0036 scope-resolution ladder (A-3), extracted from
/// `ServerImpl::dispatch_confined` and the `/api/command` handler — the two
/// copies had drifted apart only in HOW FAR each threads a principal/role and
/// an HTTP response outward; the ladder itself (alias resolution ->
/// owner-check gate -> parse -> registry evaluation, each step fail-closed)
/// was byte-identical, along with the `ConfinedDispatchSink` literal each
/// caller built around it.
///
/// Also the "middle link" QE-2 names: `resolve_and_dispatch_confined` is the
/// ONE place that classifies a dispatch arm (`classify_dispatch_arm`),
/// resolves ITS targets, and calls `dispatch_confined_arms` — so a caller-side
/// regression (e.g. collapsing the whole thing to an unfiltered loop over
/// `agent_ids`) cannot survive bound only by `dispatch_confined_arms`'s own
/// arm tests, which never exercise the classification or resolution that
/// feeds it. `ServerImpl::dispatch_confined` routes through it entirely; the
/// `/api/command` handler — which legitimately keeps its own HTTP-shaped
/// per-arm refusals (governance, #2557) — routes only its Scope arm's ladder
/// through `resolve_scope_targets` below, the part that was truly duplicated.
namespace yuzu::server {

/// Injected so the two callers can each supply their own audit-store wiring
/// (principal/role, command id) without duplicating the ladder that decides
/// WHEN to fire them. Each is called at most once per resolve.
struct ScopeLadderAudit {
    /// A referenced result-set failed the owner check (absent/expired/not
    /// owned) — one call per failing ref (governance M1 forensic row).
    std::function<void(const std::string& ref)> resolution_failed;
    /// The whole evaluation aborted; reason is one of "db_degraded",
    /// "owner_check_failed", "principal_unresolved".
    std::function<void(const std::string& reason)> evaluation_aborted;
};

/// `matched == nullopt` means ABORT — the caller must not dispatch (ADR-0036
/// fail-closed; mirrors `ConfinedDispatchTargets::scope_matched`'s null-is-
/// abort contract). `parse_error` is set ONLY when the abort was invalid
/// scope SYNTAX (as opposed to a degraded store or a failed owner check):
/// `/api/command` surfaces it as its own 400; `ServerImpl::dispatch_confined`
/// has no response to write and — matching its pre-existing behaviour —
/// simply reaches nobody, no audit row.
struct ScopeLadderResult {
    std::optional<std::vector<std::string>> matched;
    std::optional<std::string> parse_error;
};

/// The ladder itself: alias resolution -> owner-check gate -> parse ->
/// registry evaluation. `evaluate_scope_fn` is injected because the registry
/// call (`AgentRegistry::evaluate_scope`) already differs per caller only in
/// which stores are bound (tag/custom-properties/result-set) and which
/// principal is supplied — never in the ladder's control flow.
inline ScopeLadderResult resolve_scope_targets(
    std::string_view scope_expr, const std::string& principal, ResultSetStore* result_set_store,
    const std::function<std::optional<std::vector<std::string>>(const yuzu::scope::Expression&)>&
        evaluate_scope_fn,
    const ScopeLadderAudit& audit) {
    ScopeLadderResult result;

    auto resolved_scope = resolve_scope_aliases(scope_expr, principal, result_set_store);
    if (!resolved_scope) {
        spdlog::error("scope dispatch: resolve_scope_aliases degraded ({})",
                      to_string(resolved_scope.error()));
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("db_degraded");
        return result;
    }

    std::vector<std::string> failing_refs;
    const auto gate =
        gate_scope_dispatch(*resolved_scope, principal, result_set_store, failing_refs);
    if (gate == ScopeDispatchGate::AbortDbDegraded) {
        spdlog::error("scope dispatch: owner-check scan degraded");
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("db_degraded");
        return result;
    }
    if (gate == ScopeDispatchGate::AbortOwnerCheck) {
        // Governance M1: BINDING owner check — a failing ref aborts dispatch.
        for (const auto& ref : failing_refs)
            if (audit.resolution_failed)
                audit.resolution_failed(ref);
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("owner_check_failed");
        return result;
    }

    auto parsed = yuzu::scope::parse(*resolved_scope);
    if (!parsed) {
        result.parse_error = parsed.error();
        return result;
    }

    if (auto matched = evaluate_scope_fn(*parsed)) {
        result.matched = std::move(matched);
        return result;
    }
    spdlog::error(
        "scope dispatch: evaluate_scope degraded (result-set membership preload failed)");
    if (audit.evaluation_aborted)
        audit.evaluation_aborted(principal.empty() ? "principal_unresolved" : "db_degraded");
    return result;
}

/// The Group/Scope arm resolvers a caller must supply so
/// `resolve_and_dispatch_confined` can own the classification + per-arm
/// dispatch call in one place (QE-2). `group_members_fn` reads the
/// management-group store; `scope_ladder_fn` wraps `resolve_scope_targets`
/// with the caller's principal + audit wiring already bound in.
struct DispatchResolvers {
    std::function<std::vector<std::string>(const std::string& group_id)> group_members_fn;
    std::function<ScopeLadderResult(std::string_view scope_expr)> scope_ladder_fn;
};

/// ADR-1007 — per-device concurrency claim, applied to a resolved candidate
/// LIST before it becomes a `ConfinedDispatchTargets` field (Group/Scope/Ids
/// arms only; Broadcast/None are out of reach today — see the ADR's
/// documented non-goal). Deliberately NOT threaded into
/// `dispatch_confined_arms` itself: that function is kept pure (no store
/// access) by design (its own doc comment: "the seam the confinement tests
/// bind"), and a per-id store call there would also violate the #881 "ONE
/// store operation per dispatch, never per-agent" discipline. A batched
/// claim attempt here — one round trip, `unnest()`-based, same shape as
/// `ExecutionTracker::claim_concurrency_slots` — is the ONE store write for
/// the whole dispatch, taken once per arm's resolved candidate list.
///
/// Returns the SUBSET cleared to dispatch (already claimed the slot);
/// default-constructed (nullptr) means "no concurrency gate for this
/// dispatch" — most dispatches are not driven by a `per-device` definition,
/// so nullable-default is the correct un-set state (unlike
/// `ContainmentGate`, which is deliberately non-default-constructible
/// because it always applies).
using ConcurrencyClaimFn =
    std::function<std::vector<std::string>(const std::vector<std::string>& candidates)>;

// `ConfinedDispatchOutcome` (the return type of `resolve_and_dispatch_confined`
// below, and — #3424/#3511 — every `DispatchFn` typedef across the codebase)
// lives in dispatch_confined_arms.hpp now, next to its inner analog
// `ArmDispatchResult`: a header the 7 `DispatchFn`-declaring headers can
// include without also pulling in this file's much heavier dependency list
// (scope_engine, tag_store, result_set_store, management_group_store,
// execution_tracker). See that header for the struct's own doc comment.

/// The "middle link": classify the arm, resolve ITS targets via the injected
/// resolvers, and route the actual send through `dispatch_confined_arms` —
/// the ONE call every arm makes, so the classification + resolution that
/// feeds it is exercised by the same tests that bind the intersection itself.
inline ConfinedDispatchOutcome resolve_and_dispatch_confined(
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const authz::VisibleSet& exec_visible, bool broadcast_on_none, const ContainmentGate& gate,
    const DispatchResolvers& resolvers, const ConfinedDispatchSink& sink,
    const ConcurrencyClaimFn& claim_fn = nullptr,
    const std::unordered_set<std::string>& plugin_missing = {}) {
    ConfinedDispatchOutcome outcome;
    outcome.containment_unreadable = gate.enforced && gate.fail_closed;
    const auto arm = classify_dispatch_arm(!agent_ids.empty(), scope_expr);

    // ADR-1007 correctness fix (Gate 2 security-guardian SHOULD): claim
    // ONLY against the visible-set-confined candidate list, never the raw
    // one. Without this, a confined operator naming agent_ids/group/scope
    // members outside their own visible set could still successfully claim
    // those agents (the send is later filtered out by the #1788
    // intersection inside dispatch_confined_arms, unchanged below, but the
    // claim itself would already be taken) — an availability side-channel
    // blocking a different operator's legitimate dispatch to those agents
    // for up to the claim's TTL. `authz::filter_to_scope` is the SAME
    // function `dispatch_confined_arms` already applies to the Scope/Ids
    // arms (and an equivalent per-id `in_scope` check for Group) — calling
    // it here first and letting `dispatch_confined_arms` apply it again is
    // a safe, idempotent no-op (pure, deterministic set intersection), not
    // a second copy of the intersection RULE.
    if (arm == DispatchArm::Group) {
        std::vector<std::string> members;
        if (resolvers.group_members_fn)
            members = resolvers.group_members_fn(scope_expr.substr(6));
        if (claim_fn)
            members = claim_fn(authz::filter_to_scope(members, exec_visible));
        ConfinedDispatchTargets t;
        t.group_members = &members;
        const auto r = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, gate, sink,
                                              plugin_missing);
        outcome.sent = r.sent;
        outcome.denied_quarantined = r.denied_quarantined;
        outcome.denied_quarantined_count = r.denied_quarantined_count;
        outcome.not_sent = r.not_sent;
        outcome.unknown_plugin = r.unknown_plugin;
        outcome.unknown_plugin_count = r.unknown_plugin_count;
        outcome.route_unreadable = r.route_unreadable;
        return outcome;
    }

    if (arm == DispatchArm::Scope) {
        if (!resolvers.scope_ladder_fn)
            return outcome; // no resolver wired — reach nobody, matching a null store
        auto ladder = resolvers.scope_ladder_fn(scope_expr);
        outcome.scope_parse_error = ladder.parse_error;
        if (!ladder.matched)
            return outcome; // ABORTED — the ladder already audited it
        if (claim_fn)
            *ladder.matched = claim_fn(authz::filter_to_scope(*ladder.matched, exec_visible));
        ConfinedDispatchTargets t;
        t.scope_matched = &*ladder.matched;
        const auto r = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, gate, sink,
                                              plugin_missing);
        outcome.sent = r.sent;
        outcome.denied_quarantined = r.denied_quarantined;
        outcome.denied_quarantined_count = r.denied_quarantined_count;
        outcome.not_sent = r.not_sent;
        outcome.unknown_plugin = r.unknown_plugin;
        outcome.unknown_plugin_count = r.unknown_plugin_count;
        outcome.route_unreadable = r.route_unreadable;
        return outcome;
    }

    ConfinedDispatchTargets t;
    std::vector<std::string> claimed_ids;
    if (arm == DispatchArm::Ids) {
        if (claim_fn) {
            claimed_ids = claim_fn(authz::filter_to_scope(agent_ids, exec_visible));
            t.agent_ids = &claimed_ids;
        } else {
            t.agent_ids = &agent_ids;
        }
    }
    const auto r = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, gate, sink,
                                          plugin_missing);
    outcome.sent = r.sent;
    outcome.denied_quarantined = r.denied_quarantined;
    outcome.denied_quarantined_count = r.denied_quarantined_count;
    outcome.not_sent = r.not_sent;
    outcome.unknown_plugin = r.unknown_plugin;
    outcome.unknown_plugin_count = r.unknown_plugin_count;
    outcome.route_unreadable = r.route_unreadable;
    return outcome;
}

/// K-1 (QE-2 residual): the wiring `ServerImpl::dispatch_confined` builds
/// around `resolve_and_dispatch_confined` above — constructing the
/// `DispatchResolvers` + `ConfinedDispatchSink` from the concrete
/// registry/stores — extracted VERBATIM into this free function, taking those
/// dependencies as explicit parameters instead of implicit member access.
///
/// `resolve_and_dispatch_confined` itself was already mutation-bound
/// (test_dispatch_confined_arms.cpp), but the GLUE that builds its inputs from
/// `registry_`/the stores lived only inline inside the `ServerImpl` member and
/// had no test exercising it end-to-end: a mutation probe that replaced the
/// ENTIRE `dispatch_confined` body with a naive unfiltered `send_to` loop left
/// every existing test green, because none of them called through THIS glue —
/// they all called `resolve_and_dispatch_confined` directly with a fake sink.
/// `wire_and_dispatch_confined` IS that glue, now callable (and testable) with
/// a real `AgentRegistry` + real/null stores, independent of `ServerImpl`.
/// `ServerImpl::dispatch_confined` becomes a thin wrapper over this function;
/// its own body, behaviour, and every caller are unchanged.
inline ConfinedDispatchOutcome wire_and_dispatch_confined(
    yuzu::server::detail::AgentRegistry& registry, ManagementGroupStore* mgmt_group_store,
    ResultSetStore* result_set_store, const TagStore* tag_store,
    const CustomPropertiesStore* custom_properties_store, ExecutionTracker* execution_tracker,
    const std::function<void(const std::string& principal, const std::string& principal_role,
                             const std::string& command_id, const std::string& ref)>&
        audit_resolution_failed,
    const std::function<void(const std::string& principal, const std::string& principal_role,
                             const std::string& command_id, const std::string& reason)>&
        audit_evaluation_aborted,
    const std::string& command_id, const std::string& execution_id,
    const std::string& principal_role, const std::vector<std::string>& agent_ids,
    const std::string& scope_expr, const yuzu::server::authz::VisibleSet& exec_visible,
    bool broadcast_on_none, const ContainmentGate& gate,
    const yuzu::server::detail::ClassifiedCommand& cmd, const std::string& definition_id = {},
    const std::string& concurrency_mode = {},
    // WS-4 4.2b Task C: trailing, defaulted-null so every existing caller
    // (including every test in test_dispatch_confined_arms.cpp) is
    // unaffected — a null store means `GatewayRouteFallback::prepare` is a
    // pure no-op (see its own doc comment) and behaviour is byte-identical
    // to before this slice.
    GatewayRouteStore* gateway_route_store = nullptr) {
    DispatchResolvers resolvers;
    resolvers.group_members_fn = [mgmt_group_store](const std::string& group_id) {
        std::vector<std::string> members;
        if (mgmt_group_store)
            for (const auto& m : mgmt_group_store->get_members(group_id))
                members.push_back(m.agent_id);
        return members;
    };
    resolvers.scope_ladder_fn = [&](std::string_view expr) {
        // Owner-scoped from_result_set: recover the principal from the
        // execution row (run_async / workflow / scheduled / MCP all create it
        // with dispatched_by before dispatch — review B1). Role is whatever
        // this call's caller supplied (C5).
        std::string principal;
        if (expr.find("from_result_set:") != std::string_view::npos &&
            !execution_id.empty() && execution_tracker) {
            if (auto ex = execution_tracker->get_execution(execution_id))
                principal = ex->dispatched_by;
        }
        yuzu::server::ScopeLadderAudit audit;
        audit.resolution_failed = [&](const std::string& ref) {
            audit_resolution_failed(principal, principal_role, command_id, ref);
        };
        audit.evaluation_aborted = [&](const std::string& reason) {
            audit_evaluation_aborted(principal, principal_role, command_id, reason);
        };
        return yuzu::server::resolve_scope_targets(
            expr, principal, result_set_store,
            [&](const yuzu::scope::Expression& parsed) {
                // #1788: intersect the matched set with the caller's
                // Execution:Execute visible set — done by
                // resolve_and_dispatch_confined below, not here.
                return registry.evaluate_scope(parsed, tag_store, custom_properties_store,
                                               result_set_store, principal);
            },
            audit);
    };

    // WS-4 4.2b Task C: one fallback instance per dispatch (never an
    // AgentRegistry/ServerImpl member — see dispatch_route_fallback.hpp's
    // file header). Shared, via shared_ptr capture, between `send_to` (the
    // per-id consult) and `prepare_route_fallback` (the batched read).
    auto route_fallback =
        std::make_shared<yuzu::server::GatewayRouteFallback>(registry, gateway_route_store);
    yuzu::server::ConfinedDispatchSink sink{
        [&registry, &cmd, route_fallback](const std::string& aid) {
            // A local session ALWAYS wins (route_fallback->prepare() never
            // even looks up an id with one) — this fallback fires ONLY for a
            // candidate this replica has no local session for at all.
            if (auto cluster = route_fallback->cluster_for(aid))
                return registry.send_via_directory(aid, cmd, *cluster);
            return registry.send_to(aid, cmd);
        },
        [&registry, &cmd] { return registry.send_to_all(cmd); },
        [&registry] { return registry.all_ids(); },
        [route_fallback](const std::vector<std::string>& candidates) {
            return route_fallback->prepare(candidates);
        },
        // HA WS-5: this is the PRIMARY production dispatch surface (MCP
        // execute_instruction, workflows, scheduled dispatch, policy
        // remediation, via wire_and_dispatch_confined) — governance Gate 3
        // (architect, 2026-09-22) caught this site missing from the initial
        // WS-5 diff, which would have silently killed confined_broadcast's
        // unfiltered fast path here (an unset presence_widens is treated as
        // "widens", forcing the slow filtered + prepare_route_fallback path
        // on every unfiltered fleet-wide dispatch through this surface,
        // even single-replica) had it shipped unwired.
        [&registry](const std::vector<std::string>& candidates) {
            return registry.has_remote_presence(candidates);
        }};

    // #3424/#3511: one registry read per dispatch, same lifecycle as `gate`
    // (built once by the caller before this function runs) -- never
    // recomputed per arm.
    //
    // COST, ACCEPTED: `ids_missing_plugin` is one locked O(fleet) pass over
    // `agents_` regardless of arm size, so a single-Ids dispatch to one
    // device pays the same registry walk a fleet broadcast does. Same shape
    // and same trade as `gate`'s own containment-store read immediately
    // above -- see `make_containment_gate`'s comment for the equivalent
    // "share the one read across arms rather than skip it for small
    // dispatches" reasoning. Revisit if this shows up in profiling on a
    // large fleet under a high single-target dispatch rate.
    const auto plugin_missing = registry.ids_missing_plugin(cmd.wire().plugin());

    // ADR-1007: per-device concurrency claim. Only wired for
    // concurrency_mode == "per-device" with a definition_id supplied and a
    // live tracker. Two definition-aware callers DO reach this gated
    // (workflow_routes.cpp's execute route and workflow-step dispatch,
    // ScheduleRunner::dispatch_tracked — via a sibling ConcurrencyDispatchFn
    // closure each, not this function's own default parameters). Every
    // OTHER dispatch (raw MCP/REST calls with no definition concept,
    // background system pushes) passes both defaulted-empty here and gets
    // no gate — a real, documented, deliberate gap (ADR-1007), not an
    // oversight. The
    // claim's expires_at mirrors the command's own wire expiry (millis ->
    // seconds) when the caller set one; a wire command with NO expiry
    // (`has_expires_at() == false`, "the agent should run this until it
    // finishes") still needs a FINITE bound for the stale-claim reconciler
    // to key on, so an unset wire expiry falls back to a fixed default
    // rather than never expiring.
    yuzu::server::ConcurrencyClaimFn claim_fn;
    if (concurrency_mode == "per-device" && !definition_id.empty() && execution_tracker) {
        // Shared with ExecutionTracker::renew_concurrency_claim — one
        // constant, so a renewal always extends by the same window the
        // initial claim used (CHAOS-TTL-1 fix round; a second copy here is
        // exactly how the two would drift apart).
        constexpr int64_t kConcurrencyClaimDefaultTtlSeconds =
            yuzu::server::ExecutionTracker::kConcurrencyClaimDefaultTtlSeconds;
        // Gate 3 architect NICE finding: the wire expiry is caller-supplied
        // and was previously trusted unclamped — a garbage/far-past value
        // made the claim look pre-expired (harmless: it just means the
        // reconciler's next pass, not this claim itself, releases it
        // immediately — but a far-FUTURE value pinned a claim past any
        // practical reconciler reach). Clamp to [now, now+default TTL] so
        // the reconciler's reach is bounded regardless of what the caller
        // set.
        const int64_t now_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count();
        int64_t expires_at_seconds = now_seconds + kConcurrencyClaimDefaultTtlSeconds;
        if (cmd.wire().has_expires_at() && cmd.wire().expires_at().millis_epoch() > 0) {
            const int64_t wire_expiry = cmd.wire().expires_at().millis_epoch() / 1000;
            expires_at_seconds =
                std::clamp(wire_expiry, now_seconds, now_seconds + kConcurrencyClaimDefaultTtlSeconds);
        }
        claim_fn = [execution_tracker, &definition_id, &execution_id, &command_id,
                   expires_at_seconds](const std::vector<std::string>& candidates) {
            return execution_tracker->claim_concurrency_slots(
                definition_id, execution_id, command_id, candidates, expires_at_seconds);
        };
    }

    auto outcome =
        resolve_and_dispatch_confined(agent_ids, scope_expr, exec_visible, broadcast_on_none, gate,
                                      resolvers, sink, claim_fn, plugin_missing);
    outcome.command_id = command_id;

    // ADR-1007 claim-leak fix: `claim_fn` above ran BEFORE the send, so every
    // id in `outcome.not_sent` (send attempted, registry reported failure)
    // and every NAMED id in `outcome.denied_quarantined` (send never
    // attempted — contained) already holds a fresh, still-open claim that
    // nothing else will ever release. This is the ONE seam that built
    // `claim_fn` and therefore the only place that can tell whether a claim
    // was even taken for this dispatch — `dispatch_confined_arms` stays pure
    // (no store access) by design, so the release cannot live there.
    //
    // `denied_quarantined` is deliberately empty under fail-closed
    // containment (ArmDispatchResult's own contract — collecting a
    // fleet-sized id list on the exact path that is already degraded is the
    // cost that field's comment explains) — those claims are NOT released
    // here and instead age out via the stale-claim reconciler's own
    // `expires_at` bound, same as any other orphaned claim.
    //
    // #3424/#3511: `outcome.unknown_plugin` is the THIRD bucket in this same
    // leak class — `plugin_absent` in `dispatch_confined_arms` runs the
    // identical "claimed, then `continue` before send" shape `contained`
    // does, so an id withheld for a missing plugin holds an open claim too.
    // No fail-closed analogue here (plugin-presence has no degraded-read
    // mode), so unlike `denied_quarantined` this list is never elided.
    if (claim_fn && execution_tracker) {
        std::size_t leaked = outcome.not_sent.size() + outcome.denied_quarantined.size() +
                             outcome.unknown_plugin.size();
        if (leaked > 0) {
            // One batched UPDATE (#881 discipline — matches `claim_fn`'s own
            // unnest-batched INSERT), not a per-id loop: a large not_sent set
            // under a partial gateway outage must not serialize N sequential
            // pool leases on this request thread.
            std::vector<std::string> to_release;
            to_release.reserve(leaked);
            to_release.insert(to_release.end(), outcome.not_sent.begin(), outcome.not_sent.end());
            to_release.insert(to_release.end(), outcome.denied_quarantined.begin(),
                              outcome.denied_quarantined.end());
            to_release.insert(to_release.end(), outcome.unknown_plugin.begin(),
                              outcome.unknown_plugin.end());
            // definition_id scoping (Gate 2 security-guardian finding, PR
            // #3784 fix round): execution_id alone is NOT a safe match key
            // here — every workflow-step dispatch (workflow_routes.cpp)
            // passes the literal empty string as execution_id for EVERY
            // definition it dispatches (CONSIST-2/sec-M2, pending real
            // correlation), so releasing by execution_id alone could
            // release a DIFFERENT, still-genuinely-open definition's claim
            // on the same agent — admitting the exact concurrent duplicate
            // dispatch this whole mechanism exists to prevent. definition_id
            // is already in scope here (used above building claim_fn).
            execution_tracker->release_concurrency_claims(definition_id, execution_id,
                                                          to_release);
            spdlog::info("wire_and_dispatch_confined: released {} per-device concurrency "
                         "claim(s) for execution_id={} that were taken but never delivered "
                         "(undelivered={}, quarantine-denied={}, unknown-plugin={})",
                         leaked, execution_id, outcome.not_sent.size(),
                         outcome.denied_quarantined.size(), outcome.unknown_plugin.size());
        }
    }
    return outcome;
}

} // namespace yuzu::server
