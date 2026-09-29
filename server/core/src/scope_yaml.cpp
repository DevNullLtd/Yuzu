#include "scope_yaml.hpp"

#include "result_set_store.hpp"
#include "yaml_scan.hpp"

#include <cctype>

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Matches scope_engine.cpp read_ident's charset; governs where a
// from_result_set:<ref> atom ends.
bool is_scope_ident_char(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_' || c == '.' || c == ':' || c == '-' || c == '*';
}

// A value that is safe to interpolate into a lowered scope-engine string as a
// single token: non-empty and entirely scope-ident chars (no space, quote,
// paren, or operator). Anything else could inject grammar or produce an
// unparseable expression (governance sec-L1 / dsl-S1).
bool is_safe_scope_token(const std::string& s) {
    if (s.empty())
        return false;
    for (char c : s)
        if (!is_scope_ident_char(c))
            return false;
    return true;
}

} // namespace

ScopeBlock parse_scope_block(const std::string& yaml_source) {
    ScopeBlock sb;

    // Isolate the scope block. Prefer the precise spec.scope path; fall back to
    // a bare `scope:` for YAML without a spec wrapper (e.g. focused tests).
    std::string scope_block = yaml_scan::extract_yaml_section(yaml_source, "spec.scope");
    if (scope_block.empty())
        scope_block = yaml_scan::extract_yaml_section(yaml_source, "scope");
    if (scope_block.empty())
        return sb; // scalar `scope:` or no scope — empty block

    sb.has_from_result_set = yaml_scan::yaml_has_key(scope_block, "fromResultSet");
    if (sb.has_from_result_set)
        sb.from_result_set = yaml_scan::extract_yaml_value(scope_block, "fromResultSet");

    if (yaml_scan::yaml_has_key(scope_block, "selector")) {
        std::string selector_block = yaml_scan::extract_yaml_section(scope_block, "selector");
        sb.has_selector = true;
        sb.selector_platform = yaml_scan::extract_yaml_value(selector_block, "platform");
        sb.selector_tags = yaml_scan::extract_yaml_list(selector_block, "tags");
    }

    return sb;
}

std::optional<std::string> validate_scope_block(const ScopeBlock& sb,
                                                const std::string& assignment_mode,
                                                bool assignment_has_mgmt_groups) {
    // Selector values are interpolated into the lowered scope-engine string
    // (`ostype == "<platform>"`, `EXISTS tag:<name>`); restrict them to the
    // scope-ident charset so each stays a single token — no grammar injection
    // (sec-L1) and no unparseable output (dsl-S1). Applies to selector-only
    // blocks too, hence before the fromResultSet early-return.
    if (sb.has_selector) {
        if (!sb.selector_platform.empty() && !is_safe_scope_token(sb.selector_platform))
            return "spec.scope.selector.platform may contain only letters, digits, and _ . : * -";
        for (const auto& t : sb.selector_tags)
            if (!is_safe_scope_token(t))
                return "spec.scope.selector.tags entry '" + t +
                       "' may contain only letters, digits, and _ . : * -";
    }

    // Rules 1+2 only constrain the fromResultSet form. A selector-only or empty
    // block is otherwise valid (a scalar scope expression never reaches here).
    if (!sb.has_from_result_set)
        return std::nullopt;

    if (sb.from_result_set.empty())
        return "spec.scope.fromResultSet must not be empty: give a result-set id "
               "(rs_...) or a per-operator alias";
    if (sb.from_result_set.size() > 128)
        return "spec.scope.fromResultSet id or alias must be 1-128 chars";
    if (!is_safe_scope_token(sb.from_result_set))
        return "spec.scope.fromResultSet '" + sb.from_result_set +
               "' may contain only letters, digits, and _ . : * - (it lowers to a "
               "from_result_set:<ref> scope atom)";

    if (assignment_has_mgmt_groups)
        return "scope.fromResultSet cannot be combined with assignment.managementGroups: a "
               "result set already defines a fixed device set; remove managementGroups";

    if (assignment_mode == "dynamic")
        return "scope.fromResultSet requires assignment.mode: static (got 'dynamic'): a result "
               "set is a fixed target; dynamic re-evaluation would defeat it";

    return std::nullopt;
}

std::string lower_scope_block(const ScopeBlock& sb) {
    std::vector<std::string> parts;

    if (sb.has_from_result_set && !sb.from_result_set.empty())
        parts.push_back("from_result_set:" + sb.from_result_set);

    if (!sb.selector_platform.empty())
        parts.push_back("ostype == \"" + to_lower(sb.selector_platform) + "\"");

    for (const auto& tag : sb.selector_tags) {
        if (!tag.empty())
            parts.push_back("EXISTS tag:" + tag);
    }

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0)
            out += " AND ";
        out += parts[i];
    }
    return out;
}

std::expected<std::string, ResultSetError> resolve_scope_aliases(std::string_view expr,
                                                                  const std::string& owner,
                                                                  ResultSetStore* store) {
    static constexpr std::string_view kPrefix = "from_result_set:";
    if (owner.empty() || store == nullptr || expr.find(kPrefix) == std::string_view::npos)
        return std::string(expr);
    std::string out;
    out.reserve(expr.size());
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (c == '"' || c == '\'') { // copy quoted literal verbatim
            char quote = c;
            out += c;
            for (++i; i < expr.size(); ++i) {
                out += expr[i];
                if (expr[i] == quote) {
                    ++i;
                    break;
                }
            }
            continue;
        }
        bool at_boundary = (i == 0) || !is_scope_ident_char(expr[i - 1]);
        if (at_boundary && expr.substr(i).starts_with(kPrefix)) {
            size_t rs = i + kPrefix.size();
            size_t j = rs;
            while (j < expr.size() && is_scope_ident_char(expr[j]))
                ++j;
            std::string ref(expr.substr(rs, j - rs));
            if (!ref.empty() && !ref.starts_with("rs_")) {
                auto canon = store->resolve_alias(owner, ref);
                if (!canon) {
                    // ADR-0036 fail-closed contract: a DB error mid-rewrite
                    // ABORTS — returning the expression with this atom left
                    // unresolved would no-match downstream and, under NOT,
                    // invert to match-every-agent.
                    return std::unexpected(canon.error());
                }
                if (*canon)
                    ref = **canon;
                // else: genuinely not found — leave `ref` as the alias text;
                // it no-matches downstream (design §4.3), not a DB error.
            }
            out += kPrefix;
            out += ref;
            i = j;
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

std::expected<std::vector<std::string>, ResultSetError>
scope_refs_failing_owner_check(std::string_view expr, const std::string& owner,
                               ResultSetStore* store) {
    std::vector<std::string> failing;
    static constexpr std::string_view kPrefix = "from_result_set:";
    if (owner.empty() || store == nullptr || expr.find(kPrefix) == std::string_view::npos)
        return failing;
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (c == '"' || c == '\'') {
            char quote = c;
            for (++i; i < expr.size(); ++i)
                if (expr[i] == quote) {
                    ++i;
                    break;
                }
            continue;
        }
        bool at_boundary = (i == 0) || !is_scope_ident_char(expr[i - 1]);
        if (at_boundary && expr.substr(i).starts_with(kPrefix)) {
            size_t rs = i + kPrefix.size();
            size_t j = rs;
            while (j < expr.size() && is_scope_ident_char(expr[j]))
                ++j;
            std::string ref(expr.substr(rs, j - rs));
            if (!ref.empty()) {
                auto set = store->get(ref);
                if (!set) {
                    // ADR-0036 fail-closed contract: a DB error mid-scan
                    // ABORTS the whole check rather than returning a partial
                    // failing-refs list (which the caller would otherwise
                    // treat as "these are the only problems", silently
                    // masking others).
                    return std::unexpected(set.error());
                }
                if (!*set || (*set)->owner_principal != owner)
                    failing.push_back(ref);
            }
            i = j;
            continue;
        }
        ++i;
    }
    return failing;
}

ScopeDispatchGate gate_scope_dispatch(std::string_view resolved_scope,
                                      const std::string& principal, ResultSetStore* store,
                                      std::vector<std::string>& failing_out) {
    failing_out.clear();
    auto failing = scope_refs_failing_owner_check(resolved_scope, principal, store);
    if (!failing)
        return ScopeDispatchGate::AbortDbDegraded;
    if (!failing->empty()) {
        failing_out = std::move(*failing);
        return ScopeDispatchGate::AbortOwnerCheck;
    }
    return ScopeDispatchGate::Proceed;
}

} // namespace yuzu::server
