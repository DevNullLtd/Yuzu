#pragma once

#include <string>

/// @file scope_eval_error.hpp
/// The typed failure surface for `AgentRegistry::evaluate_scope`/
/// `evaluate_scope_local` (#4981 PR-1). Deliberately a STANDALONE, pure header
/// — no heavy includes (`agent_registry.hpp`'s dependency list, `scope_engine.hpp`,
/// `result_set_store.hpp`, `dispatch_scope_ladder.hpp`'s much larger transitive
/// set) — so a future consumer that only needs to NAME the error kind (e.g.
/// PR-2's `scope_preview.hpp`) does not have to pull in the registry itself.
///
/// `Kind` collapses every abort reason `evaluate_scope` can produce today.
/// `OwnerCheckFailed` and `PresenceDegraded` are new as of #4981 PR-1 — see
/// `agent_registry.hpp`'s `evaluate_scope` doc comment for the full case list
/// this enum backs. Every value here is one of "the preload/read this
/// evaluation depends on could not be trusted" — none of them mean "zero
/// matches"; a caller that dispatches/enforces/targets on evaluate_scope's
/// result MUST treat ANY of these as "abort, do not proceed" (dispatch paths)
/// or "match nothing" (arm/push paths, where matching nothing is the safe
/// direction) — never substitute an empty match set silently.
namespace yuzu::server {

struct ScopeEvalError {
    enum class Kind {
        /// A `from_result_set:<id>` atom is present but no `ResultSetStore*`
        /// was wired to resolve it, OR a `props.<key>` atom is present but no
        /// `CustomPropertiesStore*` was wired — the atom cannot be resolved AT
        /// ALL at this call site. Unreachable on every real production
        /// dispatch ladder path (both stores are always wired there) but a
        /// real, reachable outcome for a caller that legitimately omits one
        /// (e.g. the local-only Guardian push paths, which is why
        /// `evaluate_scope_local` exists instead of hitting this).
        Unresolvable,
        /// A `from_result_set:<id>` atom is present but the caller supplied
        /// no dispatching principal to owner-resolve against.
        PrincipalUnresolved,
        /// A wired store's preload query hit a genuine backend error
        /// (Postgres error, no connection) — `member_set_owned`,
        /// `get_values_for_keys` (props or tag), mid-scan.
        StoreDegraded,
        /// A referenced result set failed the owner check: absent, expired,
        /// or not owned by the dispatching principal — collapsed from
        /// `ResultSetError::NotFound`/`NotOwner` (A3, #4981 PR-1) so a caller
        /// can never distinguish "doesn't exist" from "exists but isn't
        /// yours" (the oracle-safety contract `rest_api_v1.cpp`'s
        /// `load_owned` already maintains). `detail` carries the failing
        /// result-set id.
        OwnerCheckFailed,
        /// The cross-replica presence read (`AgentRegistry::live_presence()`)
        /// could not answer — a degraded `OfflineEndpointStore` read
        /// (`PresenceReadError`) — during evaluation of a FLEET-WIDE scope
        /// (`evaluate_scope`, never `evaluate_scope_local`, which never
        /// consults presence at all).
        PresenceDegraded,
    };
    Kind kind;
    std::string detail; // e.g. the failing result-set id, for OwnerCheckFailed
};

/// Audit/log vocabulary for `Kind`. Kept alongside the enum (rather than only
/// in `dispatch_scope_ladder.hpp`'s `ScopeAbortReason` mapping) so a caller
/// that bypasses the ladder entirely (`PolicyEvaluator::resolve_targets`,
/// #4981 PR-1 B6) can still emit the same string vocabulary without pulling
/// in the ladder header. `dispatch_scope_ladder.hpp`'s `to_string(ScopeAbortReason)`
/// MUST agree with this table pairwise — see
/// `tests/unit/server/test_dispatch_confined_arms.cpp`'s vocabulary-agreement
/// test.
inline const char* to_string(ScopeEvalError::Kind k) {
    switch (k) {
    case ScopeEvalError::Kind::Unresolvable:
        return "unresolvable";
    case ScopeEvalError::Kind::PrincipalUnresolved:
        return "principal_unresolved";
    case ScopeEvalError::Kind::StoreDegraded:
        return "db_degraded";
    case ScopeEvalError::Kind::OwnerCheckFailed:
        return "owner_check_failed";
    case ScopeEvalError::Kind::PresenceDegraded:
        return "presence_degraded";
    }
    return "unknown";
}

} // namespace yuzu::server
