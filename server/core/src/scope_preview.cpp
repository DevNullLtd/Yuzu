#include "scope_preview.hpp"

#include "dispatch_scope_ladder.hpp"
#include "scope_engine.hpp"

namespace yuzu::server {

ScopePreviewOutcome preview_scope_targets(const std::string& expression, const std::string& principal,
                                          const authz::VisibleSet& visible,
                                          ResultSetStore* result_set_store,
                                          const ScopeEvaluateFn& evaluate_scope_fn) {
    auto valid = yuzu::scope::validate(expression);
    if (!valid) {
        return {.kind = ScopePreviewOutcome::Kind::kInvalidExpression,
                .detail = "Invalid scope: " + valid.error()};
    }

    // #4981 PR-2: the ladder itself (alias resolution -> owner-check gate ->
    // parse -> registry evaluation) does its OWN parse internally, on the
    // string AFTER alias resolution has rewritten any `from_result_set:`
    // shorthand — so this function passes the raw expression string, not a
    // pre-parsed yuzu::scope::Expression, and does NOT duplicate
    // yuzu::scope::parse() itself. The validate() call above still runs
    // first so a genuinely-invalid expression keeps its pre-#4981-PR-2
    // caller-facing wording ("Invalid scope: "); `ladder.parse_error` below
    // covers the (unreachable in practice, but handled) case where alias
    // resolution produces a string that fails the ladder's own later parse
    // despite passing validate() on the original text.
    yuzu::server::ScopeLadderAudit audit;
    std::vector<std::string> failing_refs;
    audit.resolution_failed = [&](const std::string& ref) { failing_refs.push_back(ref); };

    auto ladder = yuzu::server::resolve_scope_targets(
        expression, principal, result_set_store,
        [&](const yuzu::scope::Expression& parsed) { return evaluate_scope_fn(parsed, principal); },
        audit);

    if (ladder.parse_error) {
        return {.kind = ScopePreviewOutcome::Kind::kInvalidExpression,
                .detail = "Parse error: " + *ladder.parse_error};
    }
    if (!ladder.matched) {
        // ABORTED — never "0 matches" (that would silently under-report the
        // scope's real blast radius). `failing_refs` stays empty unless the
        // abort reason is owner_check_failed (the only case
        // ScopeLadderAudit::resolution_failed fires for).
        return {.kind = ScopePreviewOutcome::Kind::kEvaluationAborted,
                .detail = ladder.abort_reason ? to_string(*ladder.abort_reason) : "unknown",
                .failing_refs = std::move(failing_refs)};
    }

    // #1788: a scope match is a targeting mechanism, not an authz exemption —
    // the ladder's evaluation runs UNFILTERED against the whole fleet (plus
    // presence-only cross-replica agents), same as a real dispatch; intersect
    // against the caller's confinement here, mirroring how
    // command_routes.cpp's Scope arm intersects dispatch_confined_arms'
    // matched set against exec_visible before dispatch. This is a read-only
    // preview, so a direct filter over the matched-id vector suffices — no
    // dispatch_confined_arms call (that seam is for actual dispatch).
    std::vector<std::string> matched_agents;
    matched_agents.reserve(ladder.matched->size());
    for (const auto& id : *ladder.matched)
        if (authz::in_scope(visible, id))
            matched_agents.push_back(id);

    // Blast-radius guard: warn when scope matches many agents (G4-UHP-MCP-011)
    // — same threshold as before #4981 PR-2.
    constexpr std::size_t kScopeWarnThreshold = 50;
    const bool scope_warning = matched_agents.size() > kScopeWarnThreshold;

    nlohmann::json payload = {
        {"expression", expression},
        {"matched_count", matched_agents.size()},
        {"matched_agents", matched_agents},
    };
    if (scope_warning) {
        payload["warning"] = "scope matches " + std::to_string(matched_agents.size()) + " agents (>" +
                             std::to_string(kScopeWarnThreshold) +
                             "). Phase 2 write operations targeting this scope will require "
                             "approval.";
    }
    return {.kind = ScopePreviewOutcome::Kind::kOk, .payload = std::move(payload)};
}

} // namespace yuzu::server
