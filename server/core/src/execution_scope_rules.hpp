#pragma once

#include "authz_model.hpp"
#include "execution_tracker.hpp"

#include <yuzu/server/auth.hpp>

#include <string>
#include <utility>
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

/// The OWNERSHIP key for execution visibility (#5557): the identity an ownership-based admission
/// decision compares against `Execution::dispatched_by`. It is derived from a session by
/// `execution_owner_key()` below and by nothing else, so a service-scoped credential's minting
/// account can never be handed to an ownership compare by habit.
///
/// What it is NOT: an authorization gate. It never engages, widens or narrows a scope. Under an
/// UNRESTRICTED scope (`nullopt` from the fleet-read gate) every execution is visible whatever
/// the key is; an empty key only removes the owner disjunct from an ENGAGED scope.
///
/// The key is opaque on purpose: it is constructible only from a session (the private
/// constructor), so `ExecutionOwnerKey{some_string}` and implicit conversion from a string do not
/// compile. This header is its only definition site.
class ExecutionOwnerKey {
public:
    /// The default key owns nothing.
    ExecutionOwnerKey() = default;

    /// True when `exec` was dispatched by the key's principal. An empty key owns nothing, so an
    /// unresolved or empty identity never matches an empty `dispatched_by`.
    [[nodiscard]] bool owns(const Execution& e) const {
        return !key_.empty() && e.dispatched_by == key_;
    }

    /// True when the key owns nothing (service-scoped session or empty username).
    [[nodiscard]] bool empty() const { return key_.empty(); }

private:
    explicit ExecutionOwnerKey(std::string key) : key_(std::move(key)) {}
    friend ExecutionOwnerKey execution_owner_key(const auth::Session&);
    friend ExecutionScope confined_list_scope(const ExecutionOwnerKey&, const authz::VisibleSet&);
    friend std::string owner_only_filter(const ExecutionOwnerKey&);

    std::string key_;
};

/// The ownership key for `s`. Empty (owns nothing) for a service-scoped session, whose `username`
/// is the MINTING account rather than the credential, and for an empty username; otherwise the
/// session's own `username`.
///
/// Session classes (the service scope decides, not the credential tier):
///   - cookie, local, OIDC, SAML human, and an API token without a service scope: `username`.
///   - an MCP-tier token without a service scope: `username`. A tier caps OPERATIONS, not data
///     scope, so this is deliberate; do not "fix" it.
///   - an engine principal: `username` (its own principal). A corrupted engine row that also
///     carries a service scope gets the empty key, because the service scope is tested first.
///   - any session with a non-empty `token_scope_service`: empty.
///
/// A VISIBILITY key only. Audit rows, `dispatched_by` on writes, stream budgets and mutation
/// attribution keep using `session.username` (the real principal); the empty-username guards in
/// the handlers also stay on the raw `session.username`, never on `key.empty()`.
[[nodiscard]] inline ExecutionOwnerKey execution_owner_key(const auth::Session& s) {
    if (!s.token_scope_service.empty() || s.username.empty())
        return {};
    return ExecutionOwnerKey{s.username};
}

/// The SQL admission scope for a LIST or CHILDREN read: `nullopt` (unrestricted, no pushdown)
/// when `scope` is unrestricted, otherwise the engaged scope carrying `owner`'s key and the
/// visible agents. An empty key plus an empty agent set is "visible to nobody" (the tracker's
/// engaged-empty convention), never "no filter". The ONLY production constructor of an engaged
/// `ExecutionListScope`: it is a plain data type, so a route that fills `owner` itself bypasses
/// the key. Pass the result straight to `query_executions_checked` / `get_children_checked`.
[[nodiscard]] inline ExecutionScope confined_list_scope(const ExecutionOwnerKey& owner,
                                                        const authz::VisibleSet& scope) {
    if (!scope)
        return std::nullopt;
    ExecutionListScope out;
    out.owner = owner.key_;
    out.visible_agents.assign(scope->begin(), scope->end());
    return out;
}

/// The value for `ExecutionQuery::dispatched_by` that narrows a LIST to rows `owner` dispatched
/// (an exact-match FILTER, not an admission predicate; compare `ExecutionListScope`). The empty
/// string is `ExecutionQuery`'s own sentinel for "no filter", so an EMPTY key yields NO
/// narrowing: call this only for a caller whose key is known non-empty (a confined non-service
/// session whose raw username was already checked) and route a service-scoped (empty-key)
/// session through `confined_list_scope` instead, never through this.
[[nodiscard]] inline std::string owner_only_filter(const ExecutionOwnerKey& owner) {
    return owner.key_;
}

/// Is `exec` visible to a caller whose fleet-read scope is `scope`? Mirrors
/// the #1634 `rest_api_v1.cpp` detail-route logic (`owns_execution ||
/// has_visible_agent`, full scan, no early exit — avoids a scan-length
/// existence oracle). An empty `owner` key never satisfies the ownership
/// disjunct (an unauthenticated/unresolved-session comparison against an
/// empty `dispatched_by` must not silently admit; a service-scoped session's
/// key is empty, #5557).
///
/// Also the correct predicate for a CHILD execution in
/// `/api/executions/{id}/children` (Sol/gpt-5.6-sol adversarial review,
/// overriding an earlier reading of the #1634 precedent): visibility of a
/// PARENT execution that has already passed its own check does not by
/// itself authorize enumerating separate child execution records — each
/// child must pass this same predicate independently.
/// The key never constrains an UNRESTRICTED scope: `!scope` is visible whatever the key is.
/// Full scan, no early exit, as above.
[[nodiscard]] inline bool execution_visible(const Execution& exec,
                                            const std::vector<AgentExecStatus>& statuses,
                                            const authz::VisibleSet& scope,
                                            const ExecutionOwnerKey& owner) {
    if (!scope)
        return true;
    bool visible = owner.owns(exec);
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
///
/// Keyed on an `ExecutionOwnerKey`: the zero-status-row dispatcher window admits
/// `owner.owns(exec)` only, and an empty key (a service-scoped session) never satisfies it.
[[nodiscard]] inline bool admit_confined_mutation(const Execution& exec,
                                                  const std::vector<AgentExecStatus>& statuses,
                                                  const authz::VisibleSet& scope,
                                                  const ExecutionOwnerKey& owner) {
    if (statuses.empty())
        return owner.owns(exec);
    if (static_cast<int>(statuses.size()) != exec.agents_targeted)
        return false;
    bool all_in_scope = true;
    for (const auto& a : statuses)
        all_in_scope = authz::in_scope(scope, a.agent_id) && all_in_scope;
    return all_in_scope;
}

} // namespace yuzu::server
