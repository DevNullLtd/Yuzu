// #4990: the Forensics tier on stored-response reads -- the filter type and the catalogue-derived
// plugin set. Pure: no Postgres, no store. The SQL push-down is exercised against a real store in
// test_response_store.cpp; this file pins the TYPES (what can be constructed, what a filter says)
// and the derivation (what counts as a Forensics plugin).
#include "capability_fragments.hpp"
#include "forensics_plugin_set.hpp"
#include "forensics_visibility.hpp"
#include "response_store.hpp"
#include "response_tier_filter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <unordered_set>
#include <string>
#include <type_traits>
#include <vector>

using namespace yuzu::server;

namespace {

ForensicsPluginSet make_set(std::vector<std::string> names) {
    auto s = ForensicsPluginSet::from_names(std::move(names));
    REQUIRE(s.has_value());
    return *s;
}

// A registry with no row on the Forensics securable: the empty-derivation (boot refusal) case.
constexpr std::array<CommandCapability, 1> kNoForensicsRows{{
    {
        .plugin = "tar",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// Mixed-case and duplicate plugin names across rows on the Forensics securable, plus a row on
// another securable that must not contribute.
constexpr std::array<CommandCapability, 3> kMixedRows{{
    {
        .plugin = "Browser_Inventory",
        .action = "profiles",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "browser_inventory",
        .action = "extensions",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "tar",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

} // namespace

TEST_CASE("response tier filter: the types cannot be default-constructed",
          "[server][responses][security][forensics]") {
    STATIC_REQUIRE_FALSE(std::is_default_constructible_v<ForensicsPluginSet>);
    STATIC_REQUIRE_FALSE(std::is_default_constructible_v<ResponseTierFilter>);
}

TEST_CASE("ForensicsPluginSet::from_names normalises and refuses an empty set",
          "[server][responses][security][forensics]") {
    const auto s = make_set({"Privacy_Permissions", "app_usage", "APP_USAGE", ""});
    CHECK(s.names() == std::vector<std::string>{"app_usage", "privacy_permissions"});

    CHECK_FALSE(ForensicsPluginSet::from_names({}).has_value());
    CHECK_FALSE(ForensicsPluginSet::from_names({"", ""}).has_value());
}

TEST_CASE("ResponseTierFilter::exclude follows the ADR-0033 VisibleSet semantics",
          "[server][responses][security][forensics]") {
    const auto set = make_set({"app_usage", "execution_artifacts"});

    SECTION("nullopt (global Forensics:Read) restricts nothing") {
        const auto f = ResponseTierFilter::exclude(set, std::nullopt);
        CHECK_FALSE(f.restricts());
        CHECK(f.excluded_plugins().empty());
        CHECK(f.exempt_agents().empty());
    }
    SECTION("present-empty excludes every Forensics plugin for every agent") {
        const auto f = ResponseTierFilter::exclude(set, authz::deny_all());
        CHECK(f.restricts());
        CHECK(f.excluded_plugins() == set.names());
        CHECK(f.exempt_agents().empty());
    }
    SECTION("a present subset exempts only those agents, sorted") {
        const auto f = ResponseTierFilter::exclude(
            set, authz::VisibleSet{std::unordered_set<std::string>{"agent-b", "agent-a"}});
        CHECK(f.restricts());
        CHECK(f.excluded_plugins() == set.names());
        CHECK(f.exempt_agents() == std::vector<std::string>{"agent-a", "agent-b"});
    }
    SECTION("a default-spelled VisibleSet is nullopt, not deny-all") {
        // The trap authz::deny_all() exists for: this is unfiltered.
        const auto f = ResponseTierFilter::exclude(set, authz::VisibleSet{});
        CHECK_FALSE(f.restricts());
    }
}

TEST_CASE("ResponseTierFilter::unrestricted_internal_consumer restricts nothing",
          "[server][responses][security][forensics]") {
    const auto f = ResponseTierFilter::unrestricted_internal_consumer();
    CHECK_FALSE(f.restricts());
    CHECK(f.excluded_plugins().empty());
}

TEST_CASE("the Forensics plugin set is derived from the catalogue, not a hand-kept list",
          "[server][responses][security][forensics]") {
    const CommandCapabilityRegistry registry{YUZU_ALL_CAPABILITY_FRAGMENTS};
    const auto set = derive_forensics_plugin_set(registry);
    REQUIRE(set.has_value());
    // Pinned exactly. A NEW Forensics plugin changes this set: acknowledge it here AND in
    // test_capability_catalogue.cpp, and confirm its stored rows are Forensics-tier on purpose.
    CHECK(set->names() == std::vector<std::string>{"app_usage", "browser_inventory",
                                                   "execution_artifacts", "privacy_permissions",
                                                   "remote_access_audit"});
}

TEST_CASE("an empty derivation is refused, never an empty exclusion set",
          "[server][responses][security][forensics]") {
    SECTION("a catalogue with no Forensics row") {
        const CommandCapabilityRegistry registry{std::span<const CommandCapability>(kNoForensicsRows)};
        CHECK_FALSE(derive_forensics_plugin_set(registry).has_value());
    }
    SECTION("a registry with no sources at all") {
        const CommandCapabilityRegistry registry{
            std::initializer_list<std::span<const CommandCapability>>{}};
        CHECK_FALSE(derive_forensics_plugin_set(registry).has_value());
    }
}

TEST_CASE("plugins_on_securable lowercases, de-duplicates and filters by securable",
          "[server][responses][security][forensics]") {
    const CommandCapabilityRegistry registry{std::span<const CommandCapability>(kMixedRows)};
    CHECK(registry.plugins_on_securable(kForensicsSecurable) ==
          std::vector<std::string>{"browser_inventory"});
    CHECK(registry.plugins_on_securable("Infrastructure") == std::vector<std::string>{"tar"});
    CHECK(registry.plugins_on_securable("NoSuchSecurable").empty());
}

// -- The tier filter is a REQUIRED argument of every public ResponseStore read --------------------
//
// Each block proves two things at compile time: the read is NOT callable in any form that omits the
// filter (a default value on the parameter, or an overload without it, would flip the first assert),
// and it IS callable with the filter (so the first assert is not vacuously true). A NEW public read
// method on ResponseStore needs a line here; tests/test_response_store_read_tripwire.py enforces the
// exact set of read methods and the call-site rules.

namespace {

// Dependent on S so a failed call is a substitution failure (false), not a hard error.
#define YUZU_RS_PARAMS                                                                               \
    S &s, const std::string &id, const std::vector<int64_t> &ids, const ResponseQuery &q,           \
        const AggregateScope &sc, const AggregationQuery &aq, const std::vector<FacetFilter> &fl,   \
        const ResponseTierFilter &tier, int col, std::size_t cap,                                    \
        const std::optional<std::vector<std::string>> &as

#define YUZU_TIER_REQUIRED(NAME, METHOD, ARGS_WITH)                                           \
    template <class S>                                                                               \
    concept NAME##Tiered = requires(YUZU_RS_PARAMS) { s.METHOD ARGS_WITH; };                         \
    static_assert(NAME##Tiered<const ResponseStore>, #METHOD " must accept a ResponseTierFilter")

#define YUZU_TIER_OMITTED(NAME, METHOD, ARGS_WITHOUT)                                                \
    template <class S>                                                                               \
    concept NAME##Untiered = requires(YUZU_RS_PARAMS) { s.METHOD ARGS_WITHOUT; };                    \
    static_assert(!NAME##Untiered<const ResponseStore>,                                              \
                  #METHOD " must not be callable without a ResponseTierFilter")

YUZU_TIER_REQUIRED(Query, query, (id, tier, q, sc));
YUZU_TIER_OMITTED(Query0, query, (id));
YUZU_TIER_OMITTED(Query1, query, (id, q));
YUZU_TIER_OMITTED(Query2, query, (id, q, sc));

YUZU_TIER_REQUIRED(QueryBounded, query_bounded, (id, tier, q, sc, cap));
YUZU_TIER_OMITTED(QueryBounded0, query_bounded, (id, q, sc, cap));

YUZU_TIER_REQUIRED(QueryByExecution, query_by_execution, (id, tier, q, sc));
YUZU_TIER_OMITTED(QueryByExecution0, query_by_execution, (id));
YUZU_TIER_OMITTED(QueryByExecution1, query_by_execution, (id, q));
YUZU_TIER_OMITTED(QueryByExecution2, query_by_execution, (id, q, sc));

YUZU_TIER_REQUIRED(GetByInstruction, get_by_instruction, (id, tier));
YUZU_TIER_OMITTED(GetByInstruction0, get_by_instruction, (id));

YUZU_TIER_REQUIRED(Aggregate, aggregate, (id, tier, aq, q, sc));
YUZU_TIER_OMITTED(Aggregate0, aggregate, (id, aq));
YUZU_TIER_OMITTED(Aggregate1, aggregate, (id, aq, q));
YUZU_TIER_OMITTED(Aggregate2, aggregate, (id, aq, q, sc));

YUZU_TIER_REQUIRED(DistinctAgentIds, distinct_agent_ids, (id, tier));
YUZU_TIER_OMITTED(DistinctAgentIds0, distinct_agent_ids, (id));

YUZU_TIER_REQUIRED(DistinctAgentIdsByExecution, distinct_agent_ids_by_execution, (id, tier));
YUZU_TIER_OMITTED(DistinctAgentIdsByExecution0, distinct_agent_ids_by_execution, (id));

YUZU_TIER_REQUIRED(TotalCount, total_count, (tier));
YUZU_TIER_OMITTED(TotalCount0, total_count, ());

YUZU_TIER_REQUIRED(FacetValues, facet_values, (id, tier, col, as));
YUZU_TIER_OMITTED(FacetValues0, facet_values, (id, col));
YUZU_TIER_OMITTED(FacetValues1, facet_values, (id, col, as));

YUZU_TIER_REQUIRED(FacetAgentIds, facet_agent_ids, (id, tier, fl));
YUZU_TIER_OMITTED(FacetAgentIds0, facet_agent_ids, (id, fl));

YUZU_TIER_REQUIRED(FacetAgentCount, facet_agent_count, (id, tier, fl, as));
YUZU_TIER_OMITTED(FacetAgentCount0, facet_agent_count, (id, fl));
YUZU_TIER_OMITTED(FacetAgentCount1, facet_agent_count, (id, fl, as));

YUZU_TIER_REQUIRED(FacetLineCount, facet_line_count, (id, tier, fl));
YUZU_TIER_OMITTED(FacetLineCount0, facet_line_count, (id, fl));

YUZU_TIER_REQUIRED(QueryByIds, query_by_ids, (ids, tier));
YUZU_TIER_OMITTED(QueryByIds0, query_by_ids, (ids));

YUZU_TIER_REQUIRED(FacetResponseIds, facet_response_ids, (id, tier, fl, col, col));
YUZU_TIER_OMITTED(FacetResponseIds0, facet_response_ids, (id, fl));
YUZU_TIER_OMITTED(FacetResponseIds1, facet_response_ids, (id, fl, col, col));

#undef YUZU_TIER_OMITTED
#undef YUZU_TIER_REQUIRED
#undef YUZU_RS_PARAMS

} // namespace

TEST_CASE("ResponseStore reads require a tier filter (compile-time, see the static_asserts above)",
          "[server][responses][security][forensics]") {
    // The assertions are static_asserts; this case exists so the file shows up in a test listing and
    // a build that compiled this translation unit has, by definition, passed them.
    SUCCEED("static_asserts hold");
}

// -- tier_filter_for: an unwired input resolves to the fail-closed answer ---------------------------

TEST_CASE("tier_filter_for fails closed on unwired inputs",
          "[server][responses][security][forensics]") {
    httplib::Request req;
    const auto set = make_set({"app_usage", "execution_artifacts"});

    SECTION("no resolver wired: present-empty (every Forensics plugin excluded for every agent)") {
        const auto f = tier_filter_for(req, ForensicsVisibilityFn{}, &set);
        CHECK(f.restricts());
        CHECK_FALSE(f.refuses_every_row());
        CHECK(f.excluded_plugins() == set.names());
        CHECK(f.exempt_agents().empty());
    }
    SECTION("no plugin set wired: every row is refused, never admitted") {
        const auto f = tier_filter_for(
            req, [](const httplib::Request&) { return authz::VisibleSet{}; }, nullptr);
        CHECK(f.restricts());
        CHECK(f.refuses_every_row());
        // Even a resolver that would admit everything cannot make an unwired set permissive.
        const auto g = tier_filter_for(req, ForensicsVisibilityFn{}, nullptr);
        CHECK(g.refuses_every_row());
    }
    SECTION("the resolver's answer is applied, and consulted once per request") {
        int calls = 0;
        const ForensicsVisibilityFn global = [&](const httplib::Request&) {
            ++calls;
            return authz::VisibleSet{};
        };
        CHECK_FALSE(tier_filter_for(req, global, &set).restricts());
        const ForensicsVisibilityFn subset = [&](const httplib::Request&) {
            ++calls;
            return authz::VisibleSet{std::unordered_set<std::string>{"agent-a"}};
        };
        const auto f = tier_filter_for(req, subset, &set);
        CHECK(f.restricts());
        CHECK(f.exempt_agents() == std::vector<std::string>{"agent-a"});
        CHECK(calls == 2);
    }
}

TEST_CASE("ResponseTierFilter::refuse_unwired and for_fixed_plugin_poll",
          "[server][responses][security][forensics]") {
    const auto set = make_set({"app_usage"});
    CHECK(ResponseTierFilter::refuse_unwired().refuses_every_row());
    CHECK(ResponseTierFilter::refuse_unwired().restricts());

    // A poll of a fixed non-Forensics plugin excludes the Forensics plugins outright...
    const auto poll = ResponseTierFilter::for_fixed_plugin_poll(&set);
    CHECK(poll.restricts());
    CHECK(poll.excluded_plugins() == set.names());
    CHECK(poll.exempt_agents().empty());
    // ...and an unwired surface (no set) refuses every row: a fixed plugin does not make an
    // unwired poll safe to run unfiltered.
    const auto unwired = ResponseTierFilter::for_fixed_plugin_poll(nullptr);
    CHECK(unwired.restricts());
    CHECK(unwired.refuses_every_row());
}
