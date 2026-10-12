/**
 * test_enablement_resolver.cpp — truth tables and properties of the pure
 * enablement resolver (enablement_resolver.hpp, ADR-3006 PM1.1a, V7).
 *
 * The overlay is a small fixture (not the real catalogue; that composition is
 * test_enablement_units.cpp). Endpoint views are map-backed. Pure: no I/O, no
 * clock, no process; the property test uses a fixed-seed PRNG.
 */

#include "agent_registry.hpp" // detail::scope_kind_catalog (authoring refusals)
#include "dispatch_confined_arms.hpp"
#include "enablement_resolver.hpp"
#include "enablement_units.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <numeric>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::enablement;

namespace {

constexpr CommandCapability row(std::string_view plugin, std::string_view action) {
    return CommandCapability{.plugin = plugin, .action = action,
                             .execute_gate = ExecuteGate::None};
}

constexpr std::array<CommandCapability, 10> kFixtureRows{{
    row("p", "x"),
    row("p", "y"),
    row("p", "z"),
    row("q", "a"),
    row("q", "b"),
    row("t", "a"),
    row("t", "b"),
    row("t", "c"),
    row("r", "w"),
    row("quarantine", "unquarantine"),
}};

constexpr std::array<UnitOsRow, 9> kFixtureOs{{
    {"p", "x", kAllOs},
    {"p", "y", kAllOs},
    {"p", "z", kAllOs},
    {"q", "a", kAllOs},
    {"q", "b", kAllOs},
    {"t", "a", kAllOs},
    {"t", "b", kAllOs},
    {"t", "c", kAllOs},
    {"r", "w", kWin},
}};

// Diamond q.b -> {p, r}; chain t.c -> t.b -> t.a.
constexpr std::array<RequirementEdge, 5> kFixtureEdges{{
    {"q.a", "p"},
    {"q.b", "p"},
    {"q.b", "r"},
    {"t.b", "t.a"},
    {"t.c", "t.b"},
}};

const UnitOverlay& overlay() {
    static const UnitOverlay ov = [] {
        auto r = build_unit_overlay({std::span<const CommandCapability>{kFixtureRows}},
                                    &is_quarantine_control_plugin, kFixtureOs, kFixtureEdges);
        REQUIRE(r.has_value());
        return std::move(*r);
    }();
    return ov;
}

const std::vector<std::string_view>& kinds() {
    static const auto k = durable_attribute_kinds(yuzu::server::detail::scope_kind_catalog());
    return k;
}

struct Spec {
    std::string id;
    std::vector<std::string> units;
    std::string selector;
    Provenance prov{Provenance::Operator};
};

Rule build(const Spec& s) {
    auto r = make_rule(s.id, s.units, s.selector, s.prov, overlay(), kinds());
    INFO(s.id << ": " << (r ? "" : r.error()));
    REQUIRE(r.has_value());
    return std::move(*r);
}

std::vector<Rule> build_all(const std::vector<Spec>& specs, const std::vector<std::size_t>& order) {
    std::vector<Rule> rules;
    for (auto i : order)
        rules.push_back(build(specs[i]));
    return rules;
}

std::vector<std::size_t> identity(std::size_t n) {
    std::vector<std::size_t> v(n);
    std::iota(v.begin(), v.end(), 0);
    return v;
}

using Attrs = std::unordered_map<std::string, std::string>;

Resolution run_rules(const std::vector<Rule>& rules, std::string_view os, const Attrs& attrs) {
    return resolve(rules, overlay(), os, [&attrs](std::string_view k) {
        auto it = attrs.find(std::string(k));
        return it == attrs.end() ? std::string{} : it->second;
    });
}

Resolution run(const std::vector<Spec>& specs, std::string_view os, const Attrs& attrs = {}) {
    return run_rules(build_all(specs, identity(specs.size())), os, attrs);
}

const OffUnit* find_off(const Resolution& r, std::string_view unit) {
    for (const auto& o : r.off)
        if (o.unit == unit)
            return &o;
    return nullptr;
}

std::vector<std::string> off_names(const Resolution& r) {
    std::vector<std::string> v;
    for (const auto& o : r.off)
        v.push_back(o.unit);
    return v;
}

using Names = std::vector<std::string>;
using Matches = std::vector<Match>;

constexpr auto Op = Provenance::Operator;

} // namespace

TEST_CASE("enablement resolver: V7 truth table is order-independent", "[enablement][scope]") {
    const std::vector<Spec> specs{
        {"r1", {"p.x"}, R"(ostype == "linux")"},
        {"r2", {"p.y"}, "__all__"},
        {"r3", {"p.x"}, R"(tag:lab == "yes")"},
    };
    struct Ep {
        std::string os;
        Attrs attrs;
        Names off;
    };
    const std::vector<Ep> eps{
        {"linux", {{"ostype", "linux"}, {"tag:lab", "yes"}}, {"p.x", "p.y"}},
        {"linux", {{"ostype", "linux"}}, {"p.x", "p.y"}},
        {"windows", {{"ostype", "windows"}, {"tag:lab", "yes"}}, {"p.x", "p.y"}},
        {"windows", {{"ostype", "windows"}}, {"p.y"}},
    };
    for (const auto& ep : eps) {
        auto order = identity(specs.size());
        const auto reference = run_rules(build_all(specs, order), ep.os, ep.attrs);
        CHECK(off_names(reference) == ep.off);
        do {
            CHECK(run_rules(build_all(specs, order), ep.os, ep.attrs) == reference);
        } while (std::next_permutation(order.begin(), order.end()));
    }
    const auto both = run(specs, "linux", {{"ostype", "linux"}, {"tag:lab", "yes"}});
    CHECK(find_off(both, "p.x")->matches == Matches{{"r1", Op}, {"r3", Op}});
    CHECK(find_off(both, "p.y")->matches == Matches{{"r2", Op}});
}

TEST_CASE("enablement resolver: V7 property, random rule orderings", "[enablement][scope]") {
    const std::vector<Spec> specs{
        {"a", {"p.x"}, R"(ostype == "linux")"},
        {"b", {"p"}, R"(tag:lab == "yes")"},
        {"c", {"q.b"}, "__all__"},
        {"d", {"t.a"}, R"(NOT tag:lab == "yes")"},
        {"e", {"p.z", "t.b"}, R"(hostname LIKE "lin%")"},
        {"f", {"quarantine"}, "__all__"},
        {"g", {"q"}, R"(ostype != "windows")", Provenance::CarriedOver},
        {"h", {"p.x"}, "__all__", Provenance::System},
    };
    std::mt19937 rng{20261012};
    for (const Attrs& attrs : {Attrs{{"ostype", "linux"}, {"hostname", "lin1"}},
                               Attrs{{"ostype", "linux"}, {"tag:lab", "yes"}}}) {
        const auto reference = run(specs, "linux", attrs);
        REQUIRE_FALSE(reference.off.empty());
        auto order = identity(specs.size());
        for (int i = 0; i < 30; ++i) {
            std::shuffle(order.begin(), order.end(), rng);
            CHECK(run_rules(build_all(specs, order), "linux", attrs) == reference);
        }
    }
}

TEST_CASE("enablement resolver: off wins and lists every matching rule", "[enablement][scope]") {
    const auto r = run({{"m1", {"p.x"}, "__all__"},
                        {"m2", {"p.x"}, R"(ostype == "linux")"},
                        {"m3", {"p.x"}, R"(tag:a != "no")"},
                        {"nope", {"p.x"}, R"(ostype == "windows")"}},
                       "linux", {{"ostype", "linux"}});
    REQUIRE(r.off.size() == 1);
    CHECK(r.off[0].unit == "p.x");
    CHECK(r.off[0].reason == Reason::OffByRule);
    CHECK(r.off[0].matches == Matches{{"m1", Op}, {"m2", Op}, {"m3", Op}});
    CHECK(r.matched_rules == Matches{{"m1", Op}, {"m2", Op}, {"m3", Op}});
}

TEST_CASE("enablement resolver: provenance keys the match, not the id alone", "[enablement][scope]") {
    SECTION("a rule naming only a non-unit still appears in matched_rules") {
        const auto r = run({{"only-non", {"quarantine"}, "__all__"}}, "linux");
        CHECK(r.off.empty());
        CHECK(r.matched_rules == Matches{{"only-non", Op}});
    }
    SECTION("naming both a plugin and its action dedupes the unit's matches") {
        const auto r = run({{"both", {"p", "p.x"}, "__all__"}}, "linux");
        CHECK(find_off(r, "p.x")->matches == Matches{{"both", Op}});
    }
    SECTION("one id with two provenances is two matches, in every order") {
        const std::vector<Spec> specs{{"dup", {"p.x"}, "__all__", Provenance::Operator},
                                      {"dup", {"p.x"}, "__all__", Provenance::System}};
        const auto fwd = run_rules(build_all(specs, {0, 1}), "linux", {});
        const auto rev = run_rules(build_all(specs, {1, 0}), "linux", {});
        CHECK(fwd == rev);
        CHECK(find_off(fwd, "p.x")->matches ==
              Matches{{"dup", Provenance::Operator}, {"dup", Provenance::System}});
        CHECK(fwd.matched_rules.size() == 2);
    }
}

TEST_CASE("enablement resolver: != and NOT agree on an absent tag (known-none)",
          "[enablement][scope]") {
    const auto neq = run({{"n", {"p.x"}, R"(tag:lab != "yes")"}}, "linux");
    const auto neg = run({{"n", {"p.x"}, R"(NOT tag:lab == "yes")"}}, "linux");
    CHECK(neq == neg);
    CHECK(neq.off.size() == 1);
    const Attrs lab{{"tag:lab", "yes"}};
    CHECK(run({{"n", {"p.x"}, R"(tag:lab != "yes")"}}, "linux", lab).off.empty());
    CHECK(run({{"n", {"p.x"}, R"(NOT tag:lab == "yes")"}}, "linux", lab).off.empty());
}

TEST_CASE("enablement resolver: absent tag is known-none inside a conjunction",
          "[enablement][scope]") {
    const std::vector<Spec> specs{{"s", {"p.x"}, R"(ostype == "linux" AND NOT tag:lab == "yes")"}};
    CHECK_FALSE(run(specs, "linux", {{"ostype", "linux"}}).off.empty());
    CHECK(run(specs, "windows", {{"ostype", "windows"}}).off.empty());
    CHECK(run(specs, "linux", {{"ostype", "linux"}, {"tag:lab", "yes"}}).off.empty());
}

TEST_CASE("enablement resolver: authoring validates attributes against the real catalog",
          "[enablement][scope]") {
    for (const char* ok : {R"(ostype == "linux")", R"(hostname LIKE "w%")", R"(arch == "x86_64")",
                           R"(agent_version == "1")", R"(tag:x == "1")", R"(props.y == "1")",
                           R"(LEN(tag:x) > 3)", R"(STARTSWITH(hostname, "w"))",
                           R"(ostype == "linux" AND (tag:a == "1" OR NOT props.b == "2"))"}) {
        INFO(ok);
        CHECK(make_rule("r", {"p.x"}, ok, Op, overlay(), kinds()).has_value());
    }
    for (const char* bad : {R"(colour == "red")", R"(tags:x == "1")", R"(tag: == "1")",
                            R"(from_result_set:abc == "1")", R"(ostype == "linux" AND colour == "r")",
                            R"(ostype ==)", R"(group:x)"}) {
        INFO(bad);
        CHECK_FALSE(make_rule("r", {"p.x"}, bad, Op, overlay(), kinds()).has_value());
    }
    const auto err = make_rule("r", {"p.x"}, R"(colour == "red")", Op, overlay(), kinds());
    REQUIRE_FALSE(err.has_value());
    CHECK(err.error().find("colour") != std::string::npos);
}

TEST_CASE("enablement resolver: fleet-wide is __all__ by name; empty never means everyone",
          "[enablement][scope]") {
    auto all = make_rule("r", {"p.x"}, "__all__", Op, overlay(), kinds());
    REQUIRE(all.has_value());
    CHECK_FALSE(all->selector.has_value());
    for (const char* os : {"windows", "linux", "darwin"})
        CHECK(find_off(run({{"r", {"p.x"}, "__all__"}}, os), "p.x") != nullptr);
    CHECK_FALSE(make_rule("r", {"p.x"}, "", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {"p.x"}, "  \t", Op, overlay(), kinds()).has_value());
}

TEST_CASE("enablement resolver: make_rule validates the unit names", "[enablement][scope]") {
    CHECK_FALSE(make_rule("r", {"nope.x"}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {"p.nope"}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK(make_rule("r", {"quarantine.unquarantine"}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK(make_rule("r", {"quarantine"}, "__all__", Op, overlay(), kinds()).has_value());
}

TEST_CASE("enablement resolver: a protective rule has no effect but is listed",
          "[enablement][scope]") {
    const auto r = run({{"a", {"quarantine.unquarantine"}, "__all__"},
                        {"b", {"quarantine"}, "__all__"}},
                       "linux");
    CHECK(r.off.empty());
    CHECK(r.matched_rules == Matches{{"a", Op}, {"b", Op}});
}

TEST_CASE("enablement resolver: a plugin unit contains its actions", "[enablement][scope]") {
    const auto plugin = run({{"r", {"p"}, "__all__"}}, "linux");
    CHECK(off_names(plugin) == Names{"p", "p.x", "p.y", "p.z", "q.a", "q.b"});
    CHECK(find_off(plugin, "p.z")->reason == Reason::OffByRule);
    CHECK(find_off(plugin, "p.z")->matches == Matches{{"r", Op}});

    const auto action = run({{"r", {"p.x"}, "__all__"}}, "linux");
    CHECK(off_names(action) == Names{"p.x"});
}

TEST_CASE("enablement resolver: per-OS applicability and unknown OS", "[enablement][scope]") {
    const std::vector<Spec> specs{{"r", {"r.w"}, "__all__"}};
    CHECK(off_names(run(specs, "windows")) == Names{"r.w"});
    CHECK(run(specs, "linux").off.empty());
    const auto unknown = run(specs, "plan9");
    CHECK(unknown.off.empty());
    CHECK(unknown.matched_rules == Matches{{"r", Op}});
}

TEST_CASE("enablement resolver: requirement closure", "[enablement][scope]") {
    SECTION("a unit whose requirement is off is off by requirement") {
        const auto r = run({{"A", {"p"}, "__all__"}}, "linux");
        const auto* qa = find_off(r, "q.a");
        REQUIRE(qa != nullptr);
        CHECK(qa->reason == Reason::OffRequirement);
        CHECK(qa->required_off == Names{"p"});
        CHECK(qa->matches == Matches{{"A", Op}});
    }
    SECTION("with the requirement on, the dependent is never off by requirement") {
        const auto r = run({{"A", {"q.b"}, "__all__"}}, "linux");
        CHECK(off_names(r) == Names{"q.b"});
        CHECK(find_off(r, "q.b")->reason == Reason::OffByRule);
        CHECK(find_off(r, "q.b")->required_off.empty());
    }
    SECTION("diamond lists both requirements and the union of matches") {
        const auto r = run({{"A", {"p"}, "__all__"}, {"B", {"r"}, "__all__"}}, "windows");
        const auto* qb = find_off(r, "q.b");
        REQUIRE(qb != nullptr);
        CHECK(qb->reason == Reason::OffRequirement);
        CHECK(qb->required_off == Names{"p", "r"});
        CHECK(qb->matches == Matches{{"A", Op}, {"B", Op}});
    }
    SECTION("a directly-disabled dependent keeps OffByRule and gains the requirement's matches") {
        const auto r = run({{"A", {"p"}, "__all__"}, {"C", {"q.a"}, "__all__"}}, "linux");
        const auto* qa = find_off(r, "q.a");
        REQUIRE(qa != nullptr);
        CHECK(qa->reason == Reason::OffByRule);
        CHECK(qa->matches == Matches{{"A", Op}, {"C", Op}});
    }
    SECTION("naming the plugin of a dependent is off by rule, not by requirement") {
        const auto r = run({{"A", {"q"}, "__all__"}}, "linux");
        CHECK(find_off(r, "q.a")->reason == Reason::OffByRule);
        CHECK(find_off(r, "q.b")->reason == Reason::OffByRule);
    }
    SECTION("a chain resolves identically in every rule order") {
        const std::vector<Spec> specs{{"X", {"t.a"}, "__all__"},
                                      {"Y", {"t.b"}, "__all__"},
                                      {"Z", {"p.z"}, "__all__"}};
        auto order = identity(specs.size());
        const auto reference = run_rules(build_all(specs, order), "linux", {});
        const auto* tb = find_off(reference, "t.b");
        const auto* tc = find_off(reference, "t.c");
        REQUIRE((tb && tc));
        CHECK(tb->reason == Reason::OffByRule);
        CHECK(tb->matches == Matches{{"X", Op}, {"Y", Op}});
        CHECK(tc->reason == Reason::OffRequirement);
        CHECK(tc->required_off == Names{"t.b"});
        CHECK(tc->matches == Matches{{"X", Op}, {"Y", Op}});
        do {
            CHECK(run_rules(build_all(specs, order), "linux", {}) == reference);
        } while (std::next_permutation(order.begin(), order.end()));
    }
}

TEST_CASE("enablement resolver: nothing matches, nothing happens", "[enablement][scope]") {
    CHECK(run(std::vector<Spec>{}, "linux") == Resolution{});
    const auto r = run({{"n", {"p.x"}, R"(ostype == "windows")"}}, "linux", {{"ostype", "linux"}});
    CHECK(r.off.empty());
    CHECK(r.matched_rules.empty());
}
