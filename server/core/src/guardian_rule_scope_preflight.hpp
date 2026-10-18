#pragma once

// guardian_rule_scope_preflight.hpp - resolve every rule scope BEFORE a Guardian full_sync fan-out.
//
// The policy-bump fan-out (`guardian_push_fn_`) hands each target the enabled rules whose
// `scope_expr` names it. It used to evaluate those scopes lazily, one per distinct expression,
// with `.value_or({})`: a tag or custom-property store that was degraded at that moment turned
// into "no agent is a member", so every target received a full_sync that OMITTED the scoped
// rule and persisted the new generation as converged (a silent disarm during a store outage
// that coincided with a bump; #5610, ledger R5-PRE-EXISTING-FANOUT-NARROWS). The heartbeat
// reconcile already aborts in that case. This helper evaluates every distinct scope up front
// and lets the caller abort the WHOLE fan-out, before anything is sent, on a transient failure.
//
// What it treats as what:
//   - an expression that does not parse, or that is `Unresolvable` (it names a result set or a
//     property with no store wired: a PERMANENT property of the expression, not a transient
//     failure): the rule is out of scope for everyone, exactly as before;
//   - any other evaluation error (a degraded store read, a principal or owner-check failure):
//     the fan-out must not narrow, so the helper returns that error and the caller aborts.
//
// Header-only and free of server types so a unit test drives it with a stub evaluator.

#include <cstddef>
#include <expected>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "scope_engine.hpp"
#include "scope_eval_error.hpp"

namespace yuzu::server::guardian {

/// Member agent ids per distinct, non-empty scope expression.
class RuleScopeMembers {
public:
    /// An expression that was never resolved (or an empty one) has no members.
    [[nodiscard]] bool contains(const std::string& scope_expr, const std::string& agent_id) const {
        const auto it = by_expr_.find(scope_expr);
        return it != by_expr_.end() && it->second.contains(agent_id);
    }
    [[nodiscard]] bool resolved(const std::string& scope_expr) const {
        return by_expr_.contains(scope_expr);
    }
    [[nodiscard]] std::size_t distinct_scopes() const noexcept { return by_expr_.size(); }
    void set_members(std::string scope_expr, std::unordered_set<std::string> ids) {
        by_expr_.insert_or_assign(std::move(scope_expr), std::move(ids));
    }

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> by_expr_;
};

struct RuleScopePreflightError {
    std::string scope_expr; ///< the expression whose evaluation failed
    ScopeEvalError error;
};

/// `evaluate` is `(const yuzu::scope::Expression&) ->
/// std::expected<std::vector<std::string>, ScopeEvalError>`; `Rules` is any range of rows with a
/// `scope_expr` string (and, optionally, an `enabled` flag: a disabled row is skipped). Each distinct non-empty `scope_expr` is parsed and evaluated once.
template <class Rules, class Eval>
[[nodiscard]] auto preflight_rule_scopes(const Rules& rules, Eval&& evaluate)
    -> std::expected<RuleScopeMembers, RuleScopePreflightError> {
    RuleScopeMembers out;
    for (const auto& row : rules) {
        // A disabled rule is never pushed (build_agent_push skips it), so its scope decides
        // nothing and a degraded read of it must not abort a push that would not send it.
        if constexpr (requires { row.enabled; }) {
            if (!row.enabled)
                continue;
        }
        const std::string& expr = row.scope_expr;
        if (expr.empty() || out.resolved(expr))
            continue;
        std::unordered_set<std::string> ids;
        if (auto parsed = yuzu::scope::parse(expr)) {
            auto members = evaluate(*parsed);
            if (members) {
                ids.insert(members->begin(), members->end());
            } else if (members.error().kind != ScopeEvalError::Kind::Unresolvable) {
                return std::unexpected(RuleScopePreflightError{expr, std::move(members.error())});
            }
        }
        out.set_members(expr, std::move(ids));
    }
    return out;
}

} // namespace yuzu::server::guardian
