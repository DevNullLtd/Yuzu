#pragma once

#include "authz_model.hpp"
#include "execution_tracker.hpp"

#include <string>
#include <vector>

/// @file execution_scope_rules.hpp
/// #3789: pure confinement-decision helpers shared by every migrated legacy
/// `/api/executions*` route (`execution_routes.cpp` — extracted from
/// `server.cpp` onto the `HttpRouteSink` seam, #2542 PR-7) and their unit
/// tests. Factored out so a route change and a test change exercise the SAME
/// implementation — a hand-copied loop per route is exactly how the
/// terminal-status-only counting bug (`running` miscounted as `responded`)
/// recurred twice on the sibling #1634 workstream before landing here once.
///
/// None of these functions perform I/O; they operate on already-fetched
/// `Execution`/`AgentExecStatus` rows and an `authz::VisibleSet`. Callers
/// are responsible for fetching those rows via the tracker's `_checked`
/// accessors and failing closed (503) on a degraded read BEFORE calling
/// into this header — these functions have no way to distinguish "no rows"
/// from "read failed" and must not be asked to.

namespace yuzu::server {

/// Is `exec` visible to a caller whose fleet-read scope is `scope`? Mirrors
/// the #1634 `rest_api_v1.cpp` detail-route logic (`owns_execution ||
/// has_visible_agent`, full scan, no early exit — avoids a scan-length
/// existence oracle). `username` empty never satisfies the ownership
/// disjunct (an unauthenticated/unresolved-session comparison against an
/// empty `dispatched_by` must not silently admit).
///
/// Also the correct predicate for a CHILD execution in
/// `/api/executions/{id}/children` (Sol/gpt-5.6-sol adversarial review,
/// overriding an earlier reading of the #1634 precedent): visibility of a
/// PARENT execution that has already passed its own check does not by
/// itself authorize enumerating separate child execution records — each
/// child must pass this same predicate independently.
[[nodiscard]] inline bool execution_visible(const Execution& exec,
                                            const std::vector<AgentExecStatus>& statuses,
                                            const authz::VisibleSet& scope,
                                            const std::string& username) {
    if (!scope)
        return true;
    // Full scan, no early exit — matches the doc comment above. An early
    // `return true` on the first in-scope row makes the loop length
    // (and thus wall-clock time) a function of WHERE in `statuses` the
    // first visible agent falls, a residual timing side-channel on the
    // admit path (cpp-expert, #3789 Gate 3).
    bool visible = !username.empty() && exec.dispatched_by == username;
    for (const auto& a : statuses)
        visible = authz::in_scope(scope, a.agent_id) || visible;
    return visible;
}

/// Recomputed execution counters, projected to only the in-scope agent
/// rows.
struct ConfinedCounts {
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    std::string last_error_detail;
};

/// #1634/#3789 terminal-status-only confined projection. Matches
/// `execution_tracker.cpp`'s canonical `refresh_counts_once` definition of
/// "responded" (`COUNT(status IN ('success','failure','timeout',
/// 'rejected'))`) — `running` must NEVER count, or a confined caller sees
/// 100% progress while an agent is still executing. This exact bug was
/// independently found and fixed twice in sibling surfaces during #1634's
/// review; route code must call this function rather than re-deriving the
/// loop.
[[nodiscard]] inline ConfinedCounts
confined_projection(const std::vector<AgentExecStatus>& statuses, const authz::VisibleSet& scope) {
    ConfinedCounts c;
    int64_t newest_error_at = 0;
    for (const auto& a : statuses) {
        if (!authz::in_scope(scope, a.agent_id))
            continue;
        ++c.agents_targeted;
        if (a.status == "success") {
            ++c.agents_responded;
            ++c.agents_success;
        } else if (a.status == "failure" || a.status == "timeout" || a.status == "rejected") {
            ++c.agents_responded;
            ++c.agents_failure;
        }
        if (!a.error_detail.empty() && a.completed_at >= newest_error_at) {
            newest_error_at = a.completed_at;
            c.last_error_detail = a.error_detail;
        }
    }
    return c;
}

/// #3789 mutation-confinement rule for `POST /api/executions/{id}/rerun`
/// and `/cancel`, under an ENGAGED scope (unconfined callers never call
/// this — `!scope` is always admitted at the route). Adversarially reviewed
/// (Sol/gpt-5.6-sol): "every EXISTING status row is in scope" is a
/// false-admission path, because `agent_exec_status` is response-arrival
/// seeded (see `ExecutionListScope`'s doc comment) — an execution
/// targeting agents A and B can have only A's row while B's response is
/// still pending, and B may be out of scope.
///
/// Rule: zero status rows (the just-dispatched window, before any agent
/// has replied) admits ONLY the dispatcher — an id-enumerating stranger
/// cannot mutate during that window, but the caller who just dispatched
/// their own execution is not locked out of cancelling it. One or more
/// rows requires COMPLETE cohort proof: the row count must equal
/// `exec.agents_targeted` (otherwise at least one targeted agent has not
/// yet reported and its identity — and scope membership — is unknown) AND
/// every existing row's agent must be in scope. Dispatcher ownership is
/// NOT a bypass once rows exist — full visibility is required regardless
/// of who dispatched (user decision, #3789): rerun re-dispatches the full
/// parent cohort and cancel halts pending dispatches, so a partially
/// visible execution must not let a confined caller affect an
/// out-of-scope agent.
[[nodiscard]] inline bool admit_confined_mutation(const Execution& exec,
                                                  const std::vector<AgentExecStatus>& statuses,
                                                  const authz::VisibleSet& scope,
                                                  const std::string& username) {
    const bool owns = !username.empty() && exec.dispatched_by == username;
    if (statuses.empty())
        return owns;
    if (static_cast<int>(statuses.size()) != exec.agents_targeted)
        return false;
    // Full scan, no early exit — same rationale as `execution_visible`
    // above (cpp-expert NICE, folded in for consistency, #3789 Gate 3).
    bool all_in_scope = true;
    for (const auto& a : statuses)
        all_in_scope = authz::in_scope(scope, a.agent_id) && all_in_scope;
    return all_in_scope;
}

} // namespace yuzu::server
