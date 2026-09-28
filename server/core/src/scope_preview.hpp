#pragma once

/// @file scope_preview.hpp
/// PURE evaluate-scope-against-the-fleet logic shared between MCP
/// `preview_scope_targets` and its REST v1 twin, `POST /api/v1/scope/preview`
/// (#2146 Batch B2, re-founded on #4981 PR-2). Extracted so the matched-agent
/// set, the blast-radius warning threshold, and the error/abort cases cannot
/// drift between the two transports (api-twin-recipe.md Rule 1).
///
/// #4981 PR-2: this file now routes through the SAME `resolve_scope_targets`
/// ladder (dispatch_scope_ladder.hpp) real dispatch uses — alias resolution ->
/// owner-check gate -> parse -> registry evaluation, each step fail-closed
/// (ADR-0036) — instead of a bespoke per-agent attribute resolver that only
/// ever populated `ostype`/`arch`/`hostname`/`agent_version`/`tag:<key>`. That
/// bespoke resolver silently mis-evaluated `from_result_set:<id>`/`props.<key>`
/// atoms to "" (unset) for every agent, so `NOT from_result_set:<id>` matched
/// the WHOLE FLEET regardless of the set's real membership — a fleet-wide
/// over-disclosure bug, not merely an undercount (#4981). Routing through the
/// real ladder means a `from_result_set:`/`props.` atom now resolves
/// IDENTICALLY to a real dispatch, including the owner-check gate — EXCEPT
/// the result-set TTL-touch side effect a real dispatch's
/// `AgentRegistry::evaluate_scope` call performs on every owned reference it
/// resolves (#4981 PR-1 A4). This module's caller (server.cpp's shared
/// `scope_evaluate_fn`) passes `touch_referenced_result_sets = false`, so a
/// preview genuinely never mutates a result set's `last_used_at`/`ttl_at` —
/// it stays a read-only dry run, and `preview_scope_targets` keeps its
/// truthful `readOnlyHint: true` (#4981 PR-3).
///
/// No httplib.h dependency.

#include "authz_model.hpp"
#include "scope_eval_error.hpp"
#include "scope_engine.hpp"

#include <nlohmann/json.hpp>

#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::server {

class ResultSetStore;

/// Outcome of a scope-preview evaluation. Exactly one of the three shapes
/// below is populated, discriminated by `kind`:
///   - `kInvalidExpression`: `detail` is the caller-facing parse/validate
///     error message (already prefixed "Invalid scope: "/"Parse error: ",
///     matching the pre-#4981-PR-2 wording verbatim).
///   - `kEvaluationAborted`: the ladder aborted rather than answer — `detail`
///     is `to_string(ScopeAbortReason)` (db_degraded / owner_check_failed /
///     principal_unresolved / presence_degraded / unresolvable). A caller
///     MUST NOT treat this as "no matches" (that would silently under-report
///     a scope's real blast radius, the #2500/#4981 fail-open class).
///     `failing_refs` is populated ONLY for the `owner_check_failed` case —
///     the specific result-set ref(s) that failed the owner check, for the
///     caller's own forensic audit row (mirrors `ScopeLadderAudit::resolution_failed`,
///     dispatch_scope_ladder.hpp).
///   - `kOk`: `payload` is the full response object
///     `{expression, matched_count, matched_agents, [warning]}` — already
///     intersected against the caller's confinement (`visible`).
struct ScopePreviewOutcome {
    enum class Kind { kInvalidExpression, kEvaluationAborted, kOk } kind{Kind::kOk};
    std::string detail;                     // kInvalidExpression / kEvaluationAborted
    std::vector<std::string> failing_refs;  // kEvaluationAborted, OwnerCheckFailed only
    nlohmann::json payload;                 // kOk only
};

/// Injected so this pure module never binds directly to `AgentRegistry`
/// (keeps this header's dependency list light — see the file header). A
/// caller supplies a thin closure over `AgentRegistry::evaluate_scope` with
/// its own stores already bound: `[&](const auto& parsed, const auto&
/// principal){ return registry.evaluate_scope(parsed, tag_store, props_store,
/// rs_store, principal); }` — the SAME shape `dispatch_scope_ladder.hpp`'s
/// own callers (`command_routes.cpp`, `wire_and_dispatch_confined`) already
/// use.
using ScopeEvaluateFn = std::function<std::expected<std::vector<std::string>, ScopeEvalError>(
    const yuzu::scope::Expression&, const std::string& principal)>;

/// `principal` is the dispatching operator's username — required to
/// owner-resolve any `from_result_set:<id>` atom the expression references
/// (mirrors every real dispatch ladder caller). `visible` is the caller's
/// confinement set (ADR-0017 `authz::VisibleSet` — `nullopt` = unfiltered);
/// applied AFTER the (unfiltered, fleet-wide) ladder evaluation, exactly like
/// `command_routes.cpp`'s Scope arm intersects `dispatch_confined_arms`'
/// matched set against `exec_visible` before dispatch — except this is a
/// read-only preview, so the caller filters the matched-id vector directly
/// rather than calling `dispatch_confined_arms`. `result_set_store` may be
/// null (aborts `Unresolvable` on any `from_result_set:`/`props.` atom, same
/// as an unwired store on a real dispatch ladder call).
ScopePreviewOutcome preview_scope_targets(const std::string& expression, const std::string& principal,
                                          const authz::VisibleSet& visible,
                                          ResultSetStore* result_set_store,
                                          const ScopeEvaluateFn& evaluate_scope_fn);

} // namespace yuzu::server
