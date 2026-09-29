#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file deployment_engine.hpp
/// The deployment state-machine driver — ONE standalone callable that advances a
/// deployment one tick. Operator-driven today (the `/auto` deploy poll handler
/// calls it with a live session); an agentic worker via MCP drives the SAME
/// `advance()` later (the engine knows nothing about HTTP). No background thread in
/// slice 1: the open page / the agent poll is what advances the run.
///
/// Per tick: poll the stage + execute responses (by execution_id), apply the
/// response-derived transitions (GUARDED on the source step), mark out-of-scope
/// devices skipped, then CAS-claim and dispatch the next mutating step — stage to
/// 'pending', execute_staged to 'staged'. The claim commits BEFORE the dispatch
/// leaves the server, so the installer runs at most once per device.
///
/// RE-AUTHORIZATION is the caller's responsibility, every tick: `authorized` =
/// devices_fn(principal) ∩ frozen cohort, computed from the LIVE session/principal.
/// A device the operator has lost scope to is never staged/executed — it is marked
/// skipped. This is how a MUTATING step stays safe WITHOUT pre-flight's
/// frozen-cohort re-dispatch (which is sound only for read-only checks).
///
/// Lease discipline (ADR-0012): every store call takes + releases its own lease;
/// a lease is NEVER held across a dispatch or a poll.

#include "deployment_parse.hpp" // DeploymentConfig
#include "dispatch_caller.hpp"  // DispatchCaller

#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

class DeploymentRunStore;
struct StoredResponse; // response_store.hpp

namespace deployment {

/// One agent's best (proto status, raw pipe output) for a phase's execution_id.
struct AgentResponse {
    int status = 0;
    std::string output;
};

/// Best response per agent for a set of rows sharing an execution_id: terminal
/// (status != 0) beats running, then non-empty output, then the latest arrival.
/// Extracted from the server.cpp poll lambda so the borrowed-pointer best-pick is
/// unit-tested + sanitizer-reachable (#governance cpp-safety SHOULD).
std::unordered_map<std::string, AgentResponse>
best_response_per_agent(const std::vector<StoredResponse>& rows);

/// Poll seam: execution_id → best response per agent (the server wires this to
/// ResponseStore::query_by_execution + latest_per_agent; tests pass a fake).
using PollFn = std::function<std::unordered_map<std::string, AgentResponse>(const std::string&)>;

/// The shared command dispatch (execution_id carried for correlation).
///
/// The trailing parameter carries the CALLER (identity + visible set), not
/// merely a visible set — the same PLAN-006 widening `RestApiV1`,
/// `WorkflowRoutes`, and `BundleOrchestrator` already carry.
/// `ServerImpl::build_classified_command` is the single chokepoint every
/// dispatch resolves through, and it authorizes against the CLASSIFIED
/// capability's declared securable/operation for the CALLER it is given;
/// `DeploymentRoutes` used to feed it the background-dispatcher closure
/// (`DispatchCaller{.system = true}`), which the chokepoint's
/// `caller.system` early-return admits unconditionally — so an
/// operator-triggered, MUTATING stage dispatch (`content_dist.stage`,
/// declared `SoftwareDeployment:Write`) never had its RBAC operation
/// checked at all. The route's own `Infrastructure:Read` +
/// `SoftwareDeployment:Execute` gate and its per-tick
/// `devices_fn(viewer)∩cohort` re-authorization are real, but neither is a
/// substitute for the capability's own declared operation — a role holding
/// Execute without Write must still be refused before `content_dist.stage`
/// dispatches, and only a caller-carrying seam lets the chokepoint enforce
/// that as it does for every other operator surface.
using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
    const std::string& plugin, const std::string& action,
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const std::unordered_map<std::string, std::string>& parameters,
    const std::string& execution_id, const yuzu::server::DispatchCaller& caller)>;

struct EngineDeps {
    DeploymentRunStore* store = nullptr;
    PollFn poll_fn;
    DispatchFn dispatch_fn;
};

/// Correlation ids. The `deployment-` prefix is skipped by
/// AgentServiceImpl::notify_exec_tracker (like `preflight-`/`polchk-`/`bundle-`) so
/// these never reach the executions drawer — the store is the completion authority.
inline std::string stage_execution_id(const std::string& deployment_id) {
    return "deployment-" + deployment_id + "-stage";
}
inline std::string exec_execution_id(const std::string& deployment_id) {
    return "deployment-" + deployment_id + "-exec";
}

/// Advance one deployment one tick. `authorized` = the live caller's
/// devices_fn(principal) ∩ cohort — the TARGETING confinement. `caller` is the
/// same live session's DISPATCH identity, threaded to the chokepoint so
/// `content_dist.stage`/`execute_staged` are authorized against the declared
/// `SoftwareDeployment:Write` operation rather than dispatched as SYSTEM
/// (see `DispatchFn`'s doc comment above — targeting and dispatch
/// authorization are two different questions and neither substitutes for
/// the other). Safe to call concurrently / repeatedly: the store's guarded
/// transitions + the execute CAS make every step idempotent at the
/// state-machine level.
void advance(const EngineDeps& deps, const std::string& deployment_id, const DeploymentConfig& cfg,
             const std::unordered_set<std::string>& authorized,
             const yuzu::server::DispatchCaller& caller);

} // namespace deployment
} // namespace yuzu::server
