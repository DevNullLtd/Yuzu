// #4990: the Forensics tier on stored-response reads -- the filter type and the catalogue-derived
// plugin set. Pure: no Postgres, no store. The SQL push-down is exercised against a real store in
// test_response_store.cpp; this file pins the TYPES (what can be constructed, what a filter says)
// and the derivation (what counts as a Forensics plugin).
#include "capability_fragments.hpp"
#include "forensics_plugin_set.hpp"
#include "response_tier_filter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <initializer_list>
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
