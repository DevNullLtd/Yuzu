#pragma once

/// @file scope_attribute_guard.hpp
/// Pure check: does a parsed scope expression reference only attributes the
/// resolver answers?
///
/// WHY THIS EXISTS (operate-extras REVIEW G1 / S4). `AgentRegistry::
/// evaluate_scope`'s resolver returns the empty string for ANY attribute it
/// does not know, and the evaluator treats `!=` as "resolved != value" and
/// `NOT` as the negation of its child. So `ostyp != "windows"` (a one-letter
/// typo), `NOT os == "windows"` and `os != "linux"` all match EVERY enrolled
/// agent: a typo turns a targeted send into a fleet-wide one, and `Validate`
/// cannot catch it because it checks syntax only. A surface that FANS OUT by
/// expression therefore refuses an expression naming an attribute outside
/// `scope_kind_catalog()` before anything is dispatched.
///
/// Catalog-driven on purpose: the allowed set is derived from the catalog's
/// own `kind` strings ("ostype", "tag:<key>", "props.<key>",
/// "from_result_set:<id>"), so a new resolver branch that gets its catalog
/// entry (the drift contract in agent_registry.hpp) is accepted here with no
/// second list to update.

#include "scope_engine.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server {

/// True if `attr` is answered by a resolver whose catalog kinds are `kinds`.
/// A kind with no `<placeholder>` is an exact name; one with a placeholder is
/// a prefix and needs a non-empty suffix (`tag:` alone names no key).
[[nodiscard]] inline bool scope_attribute_known(std::string_view attr,
                                                const std::vector<std::string>& kinds) {
    for (const auto& kind : kinds) {
        const auto lt = kind.find('<');
        if (lt == std::string::npos) {
            if (attr == kind)
                return true;
            continue;
        }
        const std::string_view prefix = std::string_view(kind).substr(0, lt);
        if (attr.size() > prefix.size() && attr.starts_with(prefix))
            return true;
    }
    return false;
}

/// The first condition attribute in `expr` the resolver does not answer, or
/// `nullopt` when every attribute is known. Synthetic forms are decoded first
/// (`LEN(x)` / `STARTSWITH(x, p)` carry `__len:x` / `__startswith:x`; the
/// resolver is asked for `x`), through the one shared decoder.
[[nodiscard]] inline std::optional<std::string>
first_unknown_scope_attribute(const yuzu::scope::Expression& expr,
                              const std::vector<std::string>& kinds) {
    if (const auto* cond = std::get_if<yuzu::scope::Condition>(&expr)) {
        const auto real = yuzu::scope::classify_synthetic(cond->attribute).real;
        if (!scope_attribute_known(real, kinds))
            return std::string(real);
        return std::nullopt;
    }
    if (const auto* comb = std::get_if<std::unique_ptr<yuzu::scope::Combinator>>(&expr)) {
        if (*comb) {
            for (const auto& child : (*comb)->children)
                if (auto bad = first_unknown_scope_attribute(child, kinds))
                    return bad;
        }
    }
    return std::nullopt;
}

} // namespace yuzu::server
