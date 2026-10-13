#pragma once

/**
 * enablement_resolver.hpp — the pure enablement resolver (ADR-3006, PM1.1a).
 *
 * resolve(rules, overlay, agent_os, view) answers, for ONE endpoint, which
 * units are off and why. Pure: no I/O, no clock, no globals, no shared mutable
 * state.
 *
 * DRIFT CONTRACT. The attribute view is the caller's: a plain
 * `scope::AttributeResolver` produced by the shared per-identity resolver.
 * This header has no attribute-name branches and never grows a third copy of
 * the agent_registry.cpp resolver lambdas. An absent `tag:`/`props.` value is
 * the known value "" (known-none): `!=` and `NOT ==` both match it.
 *
 * Fleet-wide is the ONE spelling `kBroadcastScope` ("__all__",
 * dispatch_target_shape.hpp), authored by name exactly as dispatch passes it
 * and stored as a rule with no selector. An empty selector is refused at
 * authoring: empty never means everyone.
 *
 * Semantics (order-independent; marking is a monotone set union so the
 * fixpoint is unique whatever the rule order):
 *  - a matching rule marks each unit it names; a plugin unit also marks its
 *    applicable contained actions;
 *  - a requirement closure then marks every unit one of whose required units
 *    is off, to a fixpoint;
 *  - reason = OffByRule when a matching rule names the unit or a container of
 *    it, else OffRequirement;
 *  - matches = union over every path that switches the unit off, deduped and
 *    sorted on the full (rule_id, provenance) pair;
 *  - required_off = sorted names of the unit's directly-required units that
 *    are off;
 *  - a rule naming a non-unit (protective, reserved) has no effect but still
 *    appears in matched_rules;
 *  - an unknown agent OS is a fault, not an answer: resolve() returns an error
 *    naming the OS before any rule is evaluated, so "nothing is off" can never
 *    also mean "could not tell".
 *
 * from_result_set:<id> is excluded from enablement selectors at authoring
 * (durable_attribute_kinds): a saved result set is owner-scoped and expiring,
 * and the resolver job runs with no principal, so a durable rule bound to one
 * would silently stop matching.
 *
 * `CommandCapability::system_reserved` is not an enablement marker; see
 * enablement_units.hpp. The protective predicate seam lives there too.
 */

#include <compare>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "dispatch_target_shape.hpp"
#include "enablement_units.hpp"
#include "plugin_config_parsers.hpp"
#include "scope_engine.hpp"

namespace yuzu::server::enablement {

enum class Provenance : std::uint8_t { Operator, CarriedOver, System };

/// Reasons this resolver produces; the closed D13 list (ADR-3006) grows here
/// with the code that produces each value.
enum class Reason : std::uint8_t {
    OffByRule,
    OffRequirement,
};

struct Rule {
    /// Not required to be unique here: matches are keyed on the full
    /// (rule_id, provenance) pair and the output is canonical either way.
    /// Uniqueness is the PM1.1b store's primary key, not a precondition.
    std::string id;
    std::vector<std::string> units;
    /// nullopt = fleet-wide (authored as `__all__`).
    std::optional<scope::Expression> selector;
    Provenance provenance{Provenance::Operator};
};

struct Match {
    std::string rule_id;
    Provenance provenance;
    auto operator<=>(const Match&) const = default;
};

struct OffUnit {
    std::string unit;
    Reason reason;
    std::vector<Match> matches;
    /// The unit's DIRECTLY-required units that are off. A plugin-level edge
    /// records this on the plugin only: its contained actions go
    /// OffRequirement and inherit `matches` but carry an empty required_off.
    std::vector<std::string> required_off;
    bool operator==(const OffUnit&) const = default;
};

struct Resolution {
    std::vector<OffUnit> off;
    std::vector<Match> matched_rules;
    bool operator==(const Resolution&) const = default;
};

// -- Authoring ----------------------------------------------------------------

/// A `tag:`/`props.` key: 1-64 chars of [A-Za-z0-9_.:-]. Mirrors
/// TagStore::validate_key (tag_store.cpp) and CustomPropertiesStore::validate_key
/// (custom_properties_store.cpp), which are the same grammar but not reachable
/// here without a store dependency. A tokenizer-legal `*` is no stored key.
[[nodiscard]] constexpr bool is_valid_selector_key(std::string_view key) {
    if (key.empty() || key.size() > 64)
        return false;
    for (const char c : key)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':'))
            return false;
    return true;
}

/// Refuse the first condition attribute that matches no catalog kind. A kind
/// containing '<' is a prefix kind (`tag:<key>`, `props.<key>`): the attribute
/// must start with the text before '<' and carry a key legal for a stored tag or
/// property. Any other kind matches exactly. Synthetic LEN/STARTSWITH forms are
/// decoded first. Value domains are NOT validated, with ONE exception: `ostype`
/// is closed (windows|linux|darwin), so an `==`, `!=` or `IN` value outside it
/// (compared case-insensitively, as the evaluator does) is refused. LIKE,
/// MATCHES, CONTAINS, EXISTS and the ordering operators stay unvalidated.
[[nodiscard]] inline std::expected<void, std::string>
validate_selector_attributes(const scope::Expression& expr,
                             std::span<const std::string_view> kinds) {
    if (const auto* cond = std::get_if<scope::Condition>(&expr)) {
        const std::string_view real = scope::classify_synthetic(cond->attribute).real;
        bool known = false;
        for (const auto kind : kinds) {
            const auto lt = kind.find('<');
            if (lt == std::string_view::npos) {
                known = real == kind;
            } else {
                const auto prefix = kind.substr(0, lt);
                known = real.starts_with(prefix) &&
                        is_valid_selector_key(real.substr(prefix.size()));
            }
            if (known)
                break;
        }
        if (!known)
            return std::unexpected("unknown selector attribute: " + std::string(real));
        if (cond->attribute == "ostype" && (cond->op == scope::CompOp::Eq ||
                                            cond->op == scope::CompOp::Neq ||
                                            cond->op == scope::CompOp::In)) {
            const auto bad_os = [](std::string v) {
                for (auto& c : v)
                    if (c >= 'A' && c <= 'Z')
                        c = static_cast<char>(c + ('a' - 'A'));
                return !plugin_config::is_valid_agent_os(v);
            };
            const std::vector<std::string> one{cond->value};
            for (const auto& v : cond->op == scope::CompOp::In ? cond->values : one)
                if (bad_os(v))
                    return std::unexpected("selector ostype: unknown OS value \"" + v + "\"");
        }
        // An unrunnable MATCHES pattern evaluates false forever: a durable rule
        // that silently never matches. Refuse it here.
        if (cond->op == scope::CompOp::Matches)
            if (auto re = scope::validate_regex(cond->value); !re)
                return std::unexpected("selector " + std::string(real) + ": " + re.error());
        return {};
    }
    if (const auto* comb = std::get_if<std::unique_ptr<scope::Combinator>>(&expr)) {
        if (*comb)
            for (const auto& child : (*comb)->children)
                if (auto r = validate_selector_attributes(child, kinds); !r)
                    return r;
    }
    return {};
}

/// The attribute kinds a durable rule may use: the scope kind catalog minus
/// from_result_set:<id>. The views alias `catalog`: it must outlive the returned
/// vector, and both must outlive the make_rule call that consumes them (the Rule
/// owns its own parsed strings).
template <typename Catalog>
[[nodiscard]] std::vector<std::string_view> durable_attribute_kinds(const Catalog& catalog) {
    std::vector<std::string_view> out;
    for (const auto& info : catalog)
        if (info.kind != "from_result_set:<id>")
            out.push_back(info.kind);
    return out;
}

[[nodiscard]] inline std::expected<Rule, std::string>
make_rule(std::string id, std::vector<std::string> units, std::string_view selector_text,
          Provenance provenance, const UnitOverlay& overlay,
          std::span<const std::string_view> kinds) {
    using Err = std::unexpected<std::string>;
    if (units.empty())
        return Err("rule names no units");
    for (const auto& name : units)
        if (!overlay.find(name) && !overlay.find_non_unit(name))
            return Err("unknown unit: " + name);

    if (selector_text.find_first_not_of(" \t\r\n") == std::string_view::npos)
        return Err("empty selector; use __all__ for every endpoint");

    // Compared untrimmed, exactly as dispatch does (classify_dispatch_arm): a
    // padded `__all__` is not fleet-wide here either; it fails to parse.
    Rule rule{std::move(id), std::move(units), std::nullopt, provenance};
    if (selector_text != kBroadcastScope) {
        auto parsed = scope::parse(selector_text);
        if (!parsed)
            return Err("selector: " + parsed.error());
        if (auto ok = validate_selector_attributes(*parsed, kinds); !ok)
            return Err(ok.error());
        rule.selector = std::move(*parsed);
    }
    return rule;
}

// -- Resolution ---------------------------------------------------------------

/// Error iff `agent_os` is outside the closed vocabulary (a fault: the caller
/// must not treat it as an empty off-set). `agent_os` and `view` must describe
/// ONE endpoint identity: the caller derives both from the same session.
[[nodiscard]] inline std::expected<Resolution, std::string>
resolve(std::span<const Rule> rules, const UnitOverlay& overlay, std::string_view agent_os,
        const scope::AttributeResolver& view) {
    struct Mark {
        bool direct{false};
        std::set<Match> matches;
        std::set<std::string> required_off;
    };
    const auto os = os_bit(agent_os);
    if (!os)
        return std::unexpected("unknown agent OS: " + std::string(agent_os));
    Resolution res;
    std::map<std::string, Mark> marks;

    // Mark `unit` (and, for a plugin unit, its applicable actions). True if
    // anything new was recorded.
    auto mark = [&](const Unit& unit, bool direct, const std::set<Match>& matches) {
        bool changed = false;
        auto apply = [&](const Unit& u) {
            if (!UnitOverlay::applicable(u, os))
                return;
            auto& m = marks[u.name];
            if (direct && !m.direct) {
                m.direct = true;
                changed = true;
            }
            for (const auto& x : matches)
                changed |= m.matches.insert(x).second;
        };
        apply(unit);
        if (unit.kind == UnitKind::Plugin)
            for (const auto* a : overlay.actions_of(unit.name))
                apply(*a);
        return changed;
    };

    std::set<Match> matched;
    for (const auto& rule : rules) {
        if (rule.selector && !scope::evaluate(*rule.selector, view))
            continue;
        const Match m{rule.id, rule.provenance};
        matched.insert(m);
        for (const auto& name : rule.units)
            if (const auto* unit = overlay.find(name))
                mark(*unit, true, {m});
    }

    for (bool changed = true; changed;) {
        changed = false;
        for (const auto& [name, required] : overlay.requirements) {
            const auto req = marks.find(required);
            if (req == marks.end())
                continue;
            const auto* unit = overlay.find(name);
            if (!unit || !UnitOverlay::applicable(*unit, os))
                continue;
            const std::set<Match> inherited = req->second.matches; // the unit may alias `required`
            changed |= mark(*unit, false, inherited);
            // Direct requirement only: a plugin's fanned-out actions get no entry.
            changed |= marks[name].required_off.insert(required).second;
        }
    }

    for (const auto& [name, m] : marks)
        res.off.push_back(OffUnit{name, m.direct ? Reason::OffByRule : Reason::OffRequirement,
                                  {m.matches.begin(), m.matches.end()},
                                  {m.required_off.begin(), m.required_off.end()}});
    res.matched_rules.assign(matched.begin(), matched.end());
    return res;
}

} // namespace yuzu::server::enablement
