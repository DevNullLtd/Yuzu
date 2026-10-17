/**
 * test_enablement_resolver.cpp — truth tables and properties of the pure
 * enablement resolver (enablement_resolver.hpp, ADR-3006).
 *
 * The overlay is a small fixture (not the real catalogue; that composition is
 * test_enablement_units.cpp). Endpoint views are map-backed. Pure: no I/O, no
 * clock, no process; the property test uses a fixed-seed PRNG.
 */

#include "agent_registry.hpp" // detail::scope_kind_catalog (authoring refusals)
#include "enablement_resolver.hpp"
#include "custom_properties_store.hpp"
#include "enablement_units.hpp"
#include "tag_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <expected>
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

constexpr std::array<CommandCapability, 18> kFixtureRows{{
    row("p", "x"),
    row("p", "y"),
    row("p", "z"),
    row("q", "a"),
    row("q", "b"),
    row("t", "a"),
    row("t", "b"),
    row("t", "c"),
    row("r", "w"),
    row("s", "m"),
    row("s", "n"),
    row("quarantine", "unquarantine"),
    row("u", "v"), // 2-cycle with u.w, and a self-edged u.s
    row("u", "w"),
    row("u", "s"),
    row("k", "a"), // plugin-level dependent of plugin j
    row("k", "b"),
    row("j", "a"),
}};

constexpr std::array<UnitOsRow, 17> kFixtureOs{{
    {"p", "x", kAllOs},
    {"p", "y", kAllOs},
    {"p", "z", kAllOs},
    {"q", "a", kAllOs},
    {"q", "b", kAllOs},
    {"t", "a", kAllOs},
    {"t", "b", kAllOs},
    {"t", "c", kAllOs},
    {"r", "w", kWin},
    {"s", "m", kWin}, // heterogeneous masks under one plugin: s.m win-only, s.n everywhere
    {"s", "n", kAllOs},
    {"u", "v", kAllOs},
    {"u", "w", kAllOs},
    {"u", "s", kAllOs},
    {"k", "a", kAllOs},
    {"k", "b", kAllOs},
    {"j", "a", kAllOs},
}};

// Diamond q.b -> {p, r}; chain t.c -> t.b -> t.a, listed dependent-first so a
// single pass over the edges cannot reach the fixpoint. u.v <-> u.w is a cycle,
// u.s requires itself, and plugin k requires plugin j (a plugin-level edge).
constexpr std::array<RequirementEdge, 9> kFixtureEdges{{
    {"q.a", "p"},
    {"q.b", "p"},
    {"q.b", "r"},
    {"t.c", "t.b"},
    {"t.b", "t.a"},
    {"u.v", "u.w"},
    {"u.w", "u.v"},
    {"u.s", "u.s"},
    {"k", "j"},
}};

const UnitOverlay& overlay() {
    static const UnitOverlay ov = [] {
        auto r = build_unit_overlay({std::span<const CommandCapability>{kFixtureRows}},
                                    kProtectivePredicate, kFixtureOs, kFixtureEdges);
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

std::expected<Resolution, std::string> try_run_rules(const std::vector<Rule>& rules,
                                                     std::string_view os, const Attrs& attrs) {
    return resolve(rules, overlay(), os, [&attrs](std::string_view k) {
        auto it = attrs.find(std::string(k));
        return it == attrs.end() ? std::string{} : it->second;
    });
}

Resolution run_rules(const std::vector<Rule>& rules, std::string_view os, const Attrs& attrs) {
    auto r = try_run_rules(rules, os, attrs);
    INFO(os << ": " << (r ? "" : r.error()));
    REQUIRE(r.has_value());
    return std::move(*r);
}

Resolution run(const std::vector<Spec>& specs, std::string_view os, const Attrs& attrs = {}) {
    return run_rules(build_all(specs, identity(specs.size())), os, attrs);
}

// Protective by a local predicate: only zz.a, so plugin zz is a mixed plugin.
bool zz_a_is_protective(std::string_view plugin, std::string_view action) {
    return plugin == "zz" && action == "a";
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

Rule load_persisted(const std::string& id, std::vector<std::string> units,
                    std::string_view selector, Provenance prov = Provenance::Operator) {
    auto r = make_persisted_rule(id, std::move(units), selector, prov, kinds());
    INFO(id << ": " << (r ? "" : r.error()));
    REQUIRE(r.has_value());
    return std::move(*r);
}

} // namespace

TEST_CASE("enablement resolver: order-independence truth table", "[enablement][scope]") {
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

TEST_CASE("enablement resolver: order-independence over random rule orderings", "[enablement][scope]") {
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

TEST_CASE("enablement resolver: provenance keys the match and not the id alone",
          "[enablement][scope]") {
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

// Two-valued by design until the first asynchronous provider (#5973): an
// attribute no provider has reported evaluates as known-none, which ADR-3006 D5
// will replace with "undetermined". These cases pin today's behaviour so that
// change is a visible edit to the contract, not a silent one.
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

TEST_CASE("enablement resolver: absent props is known-none too", "[enablement][scope]") {
    CHECK_FALSE(run({{"n", {"p.x"}, R"(NOT props.owner == "x")"}}, "linux").off.empty());
    CHECK(run({{"n", {"p.x"}, R"(NOT props.owner == "x")"}}, "linux", {{"props.owner", "x"}})
              .off.empty());
}

TEST_CASE("enablement resolver: durable kinds drop only from_result_set", "[enablement][scope]") {
    const auto& catalog = yuzu::server::detail::scope_kind_catalog();
    CHECK(kinds().size() == catalog.size() - 1);
    for (const auto k : kinds())
        CHECK_FALSE(k.starts_with("from_result_set"));
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
                            R"(from_result_set:abc == "1")",
                            R"(ostype == "linux" AND colour == "r")", R"(ostype ==)",
                            R"(group:x)"}) {
        INFO(bad);
        CHECK_FALSE(make_rule("r", {"p.x"}, bad, Op, overlay(), kinds()).has_value());
    }
    const auto err = make_rule("r", {"p.x"}, R"(colour == "red")", Op, overlay(), kinds());
    REQUIRE_FALSE(err.has_value());
    CHECK(err.error().find("colour") != std::string::npos);

    SECTION("ostype is a closed domain for ==, != and IN, compared case-insensitively") {
        const auto plan9 = make_rule("r", {"p.x"}, R"(ostype == "plan9")", Op, overlay(), kinds());
        REQUIRE_FALSE(plan9.has_value());
        CHECK(plan9.error().find("plan9") != std::string::npos);
        CHECK_FALSE(make_rule("r", {"p.x"}, R"(ostype != "macos")", Op, overlay(), kinds())
                        .has_value());
        const auto in = make_rule("r", {"p.x"}, R"(ostype IN ("windows", "plan9"))", Op, overlay(),
                                  kinds());
        REQUIRE_FALSE(in.has_value());
        CHECK(in.error().find("plan9") != std::string::npos);
        // The evaluator folds case, so these select real endpoints.
        CHECK(make_rule("r", {"p.x"}, R"(ostype == "Linux")", Op, overlay(), kinds()).has_value());
        CHECK(make_rule("r", {"p.x"}, R"(ostype IN ("WINDOWS", "darwin"))", Op, overlay(), kinds())
                  .has_value());
        // Other operators are not value-validated.
        CHECK(make_rule("r", {"p.x"}, R"(ostype LIKE "win%")", Op, overlay(), kinds()).has_value());
    }
    SECTION("a tag or props key must be a stored-key shape") {
        const std::string long_key(65, 'k');
        for (const std::string& bad :
             {std::string(R"(tag:* == "1")"), std::string(R"(props.* == "1")"),
              "tag:" + long_key + " == \"1\""}) {
            INFO(bad);
            const auto r = make_rule("r", {"p.x"}, bad, Op, overlay(), kinds());
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().find("unknown selector attribute") != std::string::npos);
        }
        CHECK(make_rule("r", {"p.x"}, "tag:" + std::string(64, 'k') + " == \"1\"", Op, overlay(),
                        kinds())
                  .has_value());
        CHECK(make_rule("r", {"p.x"}, R"(tag:a.b-c:d == "1")", Op, overlay(), kinds()).has_value());
        CHECK(make_rule("r", {"p.x"}, R"(props.owner == "1")", Op, overlay(), kinds()).has_value());
    }
}

TEST_CASE("enablement resolver: a MATCHES pattern the evaluator cannot run is refused",
          "[enablement][scope]") {
    // scope::evaluate answers false for an over-cap or RE2-rejected pattern, so a
    // durable rule built on one would never match and say nothing.
    CHECK(make_rule("r", {"p.x"}, R"(hostname MATCHES "^lin[0-9]+$")", Op, overlay(), kinds())
              .has_value());
    const std::string at_cap(yuzu::scope::kMaxRegexPattern, 'a');
    CHECK(make_rule("r", {"p.x"}, "hostname MATCHES \"" + at_cap + "\"", Op, overlay(), kinds())
              .has_value());
    const std::string over_cap(yuzu::scope::kMaxRegexPattern + 1, 'a');
    const auto too_long =
        make_rule("r", {"p.x"}, "hostname MATCHES \"" + over_cap + "\"", Op, overlay(), kinds());
    REQUIRE_FALSE(too_long.has_value());
    CHECK(too_long.error().find("hostname") != std::string::npos);
    const auto unparseable =
        make_rule("r", {"p.x"}, R"(hostname MATCHES "([")", Op, overlay(), kinds());
    REQUIRE_FALSE(unparseable.has_value());
    CHECK(unparseable.error().find("invalid regex") != std::string::npos);
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
    // Compared exactly as dispatch does: padding never makes it fleet-wide.
    CHECK_FALSE(make_rule("r", {"p.x"}, " __all__ ", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {"p.x"}, "__all__\n", Op, overlay(), kinds()).has_value());
}

TEST_CASE("enablement resolver: make_rule validates the unit names", "[enablement][scope]") {
    CHECK_FALSE(make_rule("r", {"nope.x"}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {"p.nope"}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK_FALSE(make_rule("r", {}, "__all__", Op, overlay(), kinds()).has_value());
    CHECK(make_rule("r", {"quarantine.unquarantine"}, "__all__", Op, overlay(), kinds())
              .has_value());
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

TEST_CASE("enablement resolver: plugin fan-out skips actions not applicable on the OS",
          "[enablement][scope]") {
    // s.m is windows-only, s.n runs everywhere, plugin s is applicable wherever
    // either is. Fan-out must apply each action's own mask.
    const std::vector<Spec> specs{{"r", {"s"}, "__all__"}};
    CHECK(off_names(run(specs, "linux")) == Names{"s", "s.n"});
    CHECK(off_names(run(specs, "darwin")) == Names{"s", "s.n"});
    CHECK(off_names(run(specs, "windows")) == Names{"s", "s.m", "s.n"});
    // Naming the inapplicable action directly is a no-op on linux but still matches.
    const auto direct = run({{"d", {"s.m"}, "__all__"}}, "linux");
    CHECK(direct.off.empty());
    CHECK(direct.matched_rules == Matches{{"d", Op}});
}

TEST_CASE("enablement resolver: per-OS applicability", "[enablement][scope]") {
    const std::vector<Spec> specs{{"r", {"r.w"}, "__all__"}};
    CHECK(off_names(run(specs, "windows")) == Names{"r.w"});
    CHECK(run(specs, "linux").off.empty());
    CHECK(off_names(run(specs, "darwin")).empty());
}

TEST_CASE("enablement resolver: an unknown agent OS is a fault and not an empty off-set",
          "[enablement][scope]") {
    const auto rules = build_all({{"r", {"r.w"}, "__all__"}}, {0});
    for (const char* os : {"plan9", "", "Linux"}) {
        INFO(os);
        const auto r = try_run_rules(rules, os, {});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("unknown agent OS") != std::string::npos);
        CHECK(r.error().find(os) != std::string::npos);
    }
    // No rules at all is still an error: the OS, not the rules, is the fault.
    CHECK_FALSE(try_run_rules({}, "plan9", {}).has_value());
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
    SECTION("a dependent-first chain needs a second pass: both dependents inherit the leaf") {
        const auto r = run({{"L", {"t.a"}, "__all__"}}, "linux");
        CHECK(off_names(r) == Names{"t.a", "t.b", "t.c"});
        const auto* ta = find_off(r, "t.a");
        const auto* tb = find_off(r, "t.b");
        const auto* tc = find_off(r, "t.c");
        REQUIRE((ta && tb && tc));
        CHECK(ta->reason == Reason::OffByRule);
        CHECK(tb->reason == Reason::OffRequirement);
        CHECK(tc->reason == Reason::OffRequirement);
        CHECK(tb->required_off == Names{"t.a"});
        CHECK(tc->required_off == Names{"t.b"});
        CHECK(tb->matches == Matches{{"L", Op}});
        CHECK(tc->matches == Matches{{"L", Op}});
    }
    SECTION("a requirement cycle terminates; both ends are off, in every rule order") {
        const std::vector<Spec> specs{{"C1", {"u.w"}, "__all__"},
                                      {"C2", {"p.z"}, "__all__"},
                                      {"C3", {"t.a"}, "__all__"}};
        auto order = identity(specs.size());
        const auto reference = run_rules(build_all(specs, order), "linux", {});
        const auto* uv = find_off(reference, "u.v");
        const auto* uw = find_off(reference, "u.w");
        REQUIRE((uv && uw));
        CHECK(uv->reason == Reason::OffRequirement);
        CHECK(uv->required_off == Names{"u.w"});
        CHECK(uv->matches == Matches{{"C1", Op}});
        CHECK(uw->reason == Reason::OffByRule);
        CHECK(uw->required_off == Names{"u.v"});
        CHECK(uw->matches == Matches{{"C1", Op}});
        do {
            CHECK(run_rules(build_all(specs, order), "linux", {}) == reference);
        } while (std::next_permutation(order.begin(), order.end()));
    }
    SECTION("a self-requiring unit terminates and is off by rule, in every rule order") {
        // Only termination, reason and order-invariance are contract; the shape of
        // a self-edge's required_off is a data-table error, deliberately unpinned.
        const std::vector<Spec> specs{{"S1", {"u.s"}, "__all__"}, {"S2", {"p.z"}, "__all__"}};
        auto order = identity(specs.size());
        const auto reference = run_rules(build_all(specs, order), "linux", {});
        const auto* us = find_off(reference, "u.s");
        REQUIRE(us != nullptr);
        CHECK(us->reason == Reason::OffByRule);
        CHECK(us->matches == Matches{{"S1", Op}});
        do {
            CHECK(run_rules(build_all(specs, order), "linux", {}) == reference);
        } while (std::next_permutation(order.begin(), order.end()));
    }
    SECTION("a plugin-level edge records required_off on the plugin only") {
        const auto r = run({{"J", {"j"}, "__all__"}}, "linux");
        CHECK(off_names(r) == Names{"j", "j.a", "k", "k.a", "k.b"});
        const auto* k = find_off(r, "k");
        REQUIRE(k != nullptr);
        CHECK(k->reason == Reason::OffRequirement);
        CHECK(k->required_off == Names{"j"});
        CHECK(k->matches == Matches{{"J", Op}});
        for (const auto* action : {"k.a", "k.b"}) {
            INFO(action);
            const auto* a = find_off(r, action);
            REQUIRE(a != nullptr);
            CHECK(a->reason == Reason::OffRequirement);
            CHECK(a->required_off.empty());
            CHECK(a->matches == Matches{{"J", Op}});
        }
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

TEST_CASE("enablement resolver: a plugin entry is not a blanket block over its protective actions",
          "[enablement][scope]") {
    const std::array<CommandCapability, 2> frag{row("zz", "a"), row("zz", "b")};
    const std::array<UnitOsRow, 2> os{{{"zz", "a", kAllOs}, {"zz", "b", kAllOs}}};
    auto ov = build_unit_overlay({std::span<const CommandCapability>{frag}}, &zz_a_is_protective,
                                 os, {});
    REQUIRE(ov.has_value());
    const auto* protective = ov->find_non_unit("zz.a");
    REQUIRE(protective != nullptr);
    CHECK(protective->reason == NonUnitReason::Protective);

    auto rule = make_rule("r", {"zz"}, "__all__", Op, *ov, kinds());
    REQUIRE(rule.has_value());
    std::vector<Rule> rules;
    rules.push_back(std::move(*rule));
    const auto res = resolve(rules, *ov, "linux", [](std::string_view) { return std::string{}; });
    REQUIRE(res.has_value());
    // The plugin entry and its switchable action are off; the protective action
    // is not, so a consumer must key on (plugin, action).
    CHECK(off_names(*res) == Names{"zz", "zz.b"});
    CHECK(find_off(*res, "zz.a") == nullptr);
}

TEST_CASE("enablement resolver: a requirement edge from a unit inapplicable on the OS is inert",
          "[enablement][scope]") {
    // s.m is windows-only: with p off it must be off by requirement on windows
    // and absent (not even a required_off entry) on linux.
    const std::array<RequirementEdge, 1> edges{{{"s.m", "p"}}};
    auto ov = build_unit_overlay({std::span<const CommandCapability>{kFixtureRows}},
                                 kProtectivePredicate, kFixtureOs, edges);
    REQUIRE(ov.has_value());
    auto rule = make_rule("r", {"p"}, "__all__", Op, *ov, kinds());
    REQUIRE(rule.has_value());
    std::vector<Rule> rules;
    rules.push_back(std::move(*rule));
    const auto view = [](std::string_view) { return std::string{}; };

    const auto lin = resolve(rules, *ov, "linux", view);
    REQUIRE(lin.has_value());
    CHECK(find_off(*lin, "s.m") == nullptr);
    for (const auto& o : lin->off)
        CHECK(std::find(o.required_off.begin(), o.required_off.end(), "p") == o.required_off.end());

    const auto win = resolve(rules, *ov, "windows", view);
    REQUIRE(win.has_value());
    const auto* sm = find_off(*win, "s.m");
    REQUIRE(sm != nullptr);
    CHECK(sm->reason == Reason::OffRequirement);
    CHECK(sm->required_off == Names{"p"});
}

TEST_CASE("enablement resolver: a rule naming a vanished unit is reported and switches nothing",
          "[enablement][scope]") {
    // Built through the loader constructor, as a stale persisted rule is after a
    // unit was removed: make_rule would refuse these names today.
    std::vector<Rule> rules;
    rules.push_back(load_persisted("g1", {"gone.x", "p.y"}, "__all__"));
    rules.push_back(load_persisted("g2", {"p.x", "gone.z", "gone.x"}, R"(ostype == "windows")"));
    rules.push_back(load_persisted("g3", {"quarantine"}, "__all__"));

    // g2's selector does not match a linux endpoint, yet its stale name is
    // reported: the answer is the same on every endpoint.
    for (const char* os : {"linux", "windows"}) {
        INFO(os);
        const auto r = run_rules(rules, os, {{"ostype", os}});
        CHECK(r.unresolved_units == Names{"gone.x", "gone.z"}); // quarantine is a known non-unit
        CHECK(find_off(r, "p.y") != nullptr);
        CHECK(find_off(r, "gone.x") == nullptr);
    }
}

TEST_CASE("enablement resolver: a loaded rule keeps stale units but is validated like authored",
          "[enablement][scope]") {
    // Same result as make_rule on a valid, current rule.
    const Spec s{"same", {"p.x"}, R"(ostype == "linux" AND tag:lab == "y")"};
    auto authored = make_rule(s.id, s.units, s.selector, s.prov, overlay(), kinds());
    auto loaded = make_persisted_rule(s.id, s.units, s.selector, s.prov, kinds());
    REQUIRE(authored.has_value());
    REQUIRE(loaded.has_value());
    CHECK(loaded->id == authored->id);
    CHECK(loaded->units == authored->units);
    CHECK(loaded->provenance == authored->provenance);
    CHECK(loaded->selector.has_value());
    // Same meaning, not just a non-null selector: identical resolution on a matching
    // and a non-matching endpoint. Rule is move-only, so build fresh ones each time.
    const auto authored_rules = [&] {
        std::vector<Rule> v;
        v.push_back(std::move(*make_rule(s.id, s.units, s.selector, s.prov, overlay(), kinds())));
        return v;
    };
    const auto loaded_rules = [&] {
        std::vector<Rule> v;
        v.push_back(std::move(*make_persisted_rule(s.id, s.units, s.selector, s.prov, kinds())));
        return v;
    };
    for (const char* os : {"linux", "windows"}) {
        INFO(os);
        const Attrs attrs{{"ostype", os}, {"tag:lab", "y"}};
        CHECK(run_rules(authored_rules(), os, attrs) == run_rules(loaded_rules(), os, attrs));
    }
    CHECK_FALSE(
        run_rules(loaded_rules(), "linux", {{"ostype", "linux"}, {"tag:lab", "y"}}).off.empty());
    CHECK(run_rules(loaded_rules(), "windows", {{"ostype", "windows"}, {"tag:lab", "y"}})
              .off.empty());

    // The unit-name check is the only thing the loader skips.
    CHECK_FALSE(make_rule("g", {"gone.x"}, "__all__", Provenance::Operator, overlay(), kinds()));
    CHECK(make_persisted_rule("g", {"gone.x"}, "__all__", Provenance::Operator, kinds()));

    // Everything else still refuses: a corrupt or renamed-kind rule must not load.
    const std::vector<std::string> one{"p.x"};
    for (const char* bad : {"", "   ", R"(nosuchattr == "x")", R"(ostype == "plan9")",
                            R"(from_result_set:rs_1 == "x")", R"(hostname MATCHES "(")",
                            "ostype ==", " __all__"}) {
        INFO(bad);
        CHECK_FALSE(make_persisted_rule("b", one, bad, Provenance::Operator, kinds()));
    }
    CHECK_FALSE(make_persisted_rule("b", {}, "__all__", Provenance::Operator, kinds()));

    // A unit name is held to the shape build_unit_overlay freezes: a corrupt row must not
    // reach unresolved_units (audit and export strings). Legal-but-stale shapes still load.
    for (const char* ok : {"gone", "gone.x", "tar.fleet_snapshot", "__guard__.push_rules"})
        CHECK(make_persisted_rule("g", {ok}, "__all__", Provenance::Operator, kinds()));
    for (const std::string& bad :
         {std::string{}, std::string{"a\nb"}, std::string{"a\x01"}, std::string{"../../x"},
          std::string{"A.b"}, std::string{"a.b.c"}, std::string{"a."}, std::string{".a"},
          std::string{"a b"}, std::string(100000, 'x')}) {
        INFO("bad unit name of " << bad.size() << " bytes");
        auto r = make_persisted_rule("b", {bad}, "__all__", Provenance::Operator, kinds());
        REQUIRE_FALSE(r);
        CHECK(r.error() == "rule names a unit of no legal shape"); // never echoes the name
    }
    CHECK_FALSE(make_rule("b", {}, "__all__", Provenance::Operator, overlay(), kinds()));
}

TEST_CASE("enablement resolver: the selector key alphabet AGREES with both stores",
          "[enablement][scope][pin]") {
    // is_valid_selector_key copies the TagStore / CustomPropertiesStore key
    // grammar (the stores are not reachable from the header). Drift in any of
    // the three fails here.
    const std::vector<std::string> keys{"model", "a.b:c-d_e", "Az09", "", std::string(64, 'k'),
                                        std::string(65, 'k'), "has space", "*", "a*", "a/b",
                                        "tab\t", "caf\xc3\xa9", "a=b", "a\"b"};
    for (const auto& key : keys) {
        INFO(key);
        const bool mine = is_valid_selector_key(key);
        CHECK(mine == TagStore::validate_key(key));
        CHECK(mine == CustomPropertiesStore::validate_key(key));
    }
    CHECK(is_valid_selector_key("a.b:c-d_e"));
    CHECK_FALSE(is_valid_selector_key(""));
    CHECK_FALSE(is_valid_selector_key("*"));
}

TEST_CASE("enablement resolver: nothing matches so nothing happens", "[enablement][scope]") {
    CHECK(run(std::vector<Spec>{}, "linux") == Resolution{});
    const auto r = run({{"n", {"p.x"}, R"(ostype == "windows")"}}, "linux", {{"ostype", "linux"}});
    CHECK(r.off.empty());
    CHECK(r.matched_rules.empty());
}
