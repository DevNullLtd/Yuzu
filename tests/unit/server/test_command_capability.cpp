/**
 * test_command_capability.cpp — PR1.9a's pure classification core:
 * `CommandCapabilityRegistry::classify`, the `command_capability_parsers.hpp`
 * helpers (`normalize_action_key`, `compute_plan_hash`, `encode_dispatch_tag`
 * / `decode_dispatch_tag`), and the `core_dispatch_capabilities()` fragment.
 *
 * Pure — no Postgres, no sleeps, no spawns. Everything under test is a
 * header-only, `const`/`constexpr`/pure-function surface with zero
 * `server.cpp` involvement.
 */

#include "capability_decls/core_dispatch_capabilities.hpp"
#include "command_capability.hpp"
#include "command_capability_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <map>
#include <span>
#include <stdexcept>
#include <string>

using namespace yuzu::server;

// ── CommandCapabilityRegistry::classify ──────────────────────────────────

namespace {

inline constexpr std::array<CommandCapability, 2> kFragmentAlpha{{
    {
        .plugin = "tar",
        .action = "collect_inventory",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
    },
    {
        .plugin = "guardian",
        .action = "quarantine",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Security",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Critical,
        .system_reserved = false,
    },
}};

inline constexpr std::array<CommandCapability, 1> kFragmentBeta{{
    {
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Inventory",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
    },
}};

// Deliberately collides with kFragmentAlpha's tar.collect_inventory row, to
// exercise the Ambiguous path — a second, independently-authored fragment
// that happens to declare the same plugin.action.
inline constexpr std::array<CommandCapability, 1> kFragmentGamma{{
    {
        .plugin = "TAR",
        .action = "COLLECT_INVENTORY",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Inventory",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
    },
}};

} // namespace

TEST_CASE("CommandCapabilityRegistry: classify resolves a known plugin.action",
          "[server][dispatch][capability]") {
    CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(kFragmentAlpha),
        std::span<const CommandCapability>(kFragmentBeta),
    };

    auto result = registry.classify("guardian", "quarantine");
    REQUIRE(result.has_value());
    CHECK(result->securable == "Security");
    CHECK(result->operation == authz::Operation::Execute);
    CHECK(result->dispatch_class == DispatchClass::Destructive);
}

TEST_CASE("CommandCapabilityRegistry: unknown plugin.action is Unclassified, never a "
          "permissive default",
          "[server][dispatch][capability]") {
    CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(kFragmentAlpha),
        std::span<const CommandCapability>(kFragmentBeta),
    };

    auto result = registry.classify("nonexistent_plugin", "nonexistent_action");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == ClassificationError::Unclassified);
}

TEST_CASE("CommandCapabilityRegistry: an empty registry classifies nothing",
          "[server][dispatch][capability]") {
    CommandCapabilityRegistry registry{};
    auto result = registry.classify("tar", "collect_inventory");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == ClassificationError::Unclassified);
}

TEST_CASE("CommandCapabilityRegistry: the same plugin.action declared by two sources is "
          "Ambiguous, never first-wins",
          "[server][dispatch][capability]") {
    CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(kFragmentAlpha),
        std::span<const CommandCapability>(kFragmentGamma),
    };

    auto result = registry.classify("tar", "collect_inventory");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == ClassificationError::Ambiguous);

    // A DIFFERENT action from the same two sources is unaffected — ambiguity
    // is per plugin.action, not a registry-wide poison.
    auto other = registry.classify("tar", "purge_source");
    REQUIRE_FALSE(other.has_value());
    CHECK(other.error() == ClassificationError::Unclassified);
}

TEST_CASE("CommandCapabilityRegistry: classify is case-insensitive on both plugin and action",
          "[server][dispatch][capability]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kFragmentAlpha)};

    auto upper = registry.classify("TAR", "Collect_Inventory");
    auto lower = registry.classify("tar", "collect_inventory");
    REQUIRE(upper.has_value());
    REQUIRE(lower.has_value());
    CHECK(upper->securable == lower->securable);
    CHECK(upper->operation == lower->operation);
    CHECK(upper->dispatch_class == lower->dispatch_class);
}

TEST_CASE("CommandCapabilityRegistry: too many sources throws rather than silently dropping "
          "one",
          "[server][dispatch][capability]") {
    // std::initializer_list cannot be built programmatically (no (count,
    // value) constructor like std::vector) — it only exists as a brace-enclosed
    // literal at the call site, so exceeding kMaxSources means literally
    // writing kMaxSources + 1 elements. The static_assert keeps that literal
    // count honest if kMaxSources ever changes.
    static_assert(CommandCapabilityRegistry::kMaxSources == 24,
                 "this test hardcodes 25 literal sources (kMaxSources + 1); update the "
                 "literal list below if kMaxSources changes");
    const auto s = std::span<const CommandCapability>(kFragmentAlpha);
    CHECK_THROWS_AS(
        CommandCapabilityRegistry({s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s,
                                    s, s, s, s}),
        std::invalid_argument);
}

// ── core_dispatch_capabilities() ─────────────────────────────────────────

TEST_CASE("capdecls::core_dispatch_capabilities: exactly the four system-initiated dispatches, "
          "all system_reserved",
          "[server][dispatch][capability]") {
    auto rows = capdecls::core_dispatch_capabilities();
    REQUIRE(rows.size() == 4);
    for (const auto& row : rows)
        CHECK(row.system_reserved);

    CommandCapabilityRegistry registry{rows};

    auto tar = registry.classify("tar", "fleet_snapshot");
    REQUIRE(tar.has_value());
    CHECK(tar->dispatch_class == DispatchClass::ReadOnly);
    CHECK(tar->mutability == Mutability::None);

    auto guard = registry.classify("__guard__", "push_rules");
    REQUIRE(guard.has_value());
    CHECK(guard->securable == "GuaranteedState");
    CHECK(guard->operation == authz::Operation::Push);

    auto tags = registry.classify("asset_tags", "sync");
    REQUIRE(tags.has_value());
    CHECK(tags->securable == "Tag");
    CHECK(tags->operation == authz::Operation::Write);

    // Sync-on-demand (__sync__.now): read-only, system-reserved, lands under Inventory.
    auto sync = registry.classify("__sync__", "now");
    REQUIRE(sync.has_value());
    CHECK(sync->dispatch_class == DispatchClass::ReadOnly);
    CHECK(sync->mutability == Mutability::None);
    CHECK(sync->securable == "Inventory");
    CHECK(sync->operation == authz::Operation::Read);
    CHECK(sync->system_reserved);
    CHECK(sync->execute_gate == ExecuteGate::None);
}

// ── normalize_action_key ─────────────────────────────────────────────────

TEST_CASE("normalize_action_key: lowercases both components and joins with '.'",
          "[server][dispatch][capability]") {
    CHECK(normalize_action_key("TAR", "Fleet_Snapshot") == "tar.fleet_snapshot");
    CHECK(normalize_action_key("tar", "fleet_snapshot") == "tar.fleet_snapshot");
    CHECK(normalize_action_key("__Guard__", "PUSH_RULES") == "__guard__.push_rules");
}

// ── compute_plan_hash ─────────────────────────────────────────────────────

TEST_CASE("compute_plan_hash: invariant to parameter map insertion order",
          "[server][dispatch][capability]") {
    std::map<std::string, std::string> params_a;
    params_a["zeta"] = "1";
    params_a["alpha"] = "2";
    params_a["mu"] = "3";

    std::map<std::string, std::string> params_b;
    params_b["mu"] = "3";
    params_b["zeta"] = "1";
    params_b["alpha"] = "2";

    auto hash_a = compute_plan_hash("tar", "purge_source", params_a, "scope:win", "exec-1");
    auto hash_b = compute_plan_hash("tar", "purge_source", params_b, "scope:win", "exec-1");
    CHECK(hash_a == hash_b);
    CHECK_FALSE(hash_a.empty());
}

TEST_CASE("compute_plan_hash: changes when any single component changes",
          "[server][dispatch][capability]") {
    std::map<std::string, std::string> params{{"key", "value"}};
    auto base = compute_plan_hash("tar", "purge_source", params, "scope:win", "exec-1");

    CHECK(compute_plan_hash("tar2", "purge_source", params, "scope:win", "exec-1") != base);
    CHECK(compute_plan_hash("tar", "purge_source2", params, "scope:win", "exec-1") != base);
    CHECK(compute_plan_hash("tar", "purge_source", params, "scope:mac", "exec-1") != base);
    CHECK(compute_plan_hash("tar", "purge_source", params, "scope:win", "exec-2") != base);

    std::map<std::string, std::string> params_changed{{"key", "different_value"}};
    CHECK(compute_plan_hash("tar", "purge_source", params_changed, "scope:win", "exec-1") !=
         base);

    std::map<std::string, std::string> params_extra{{"key", "value"}, {"extra", "x"}};
    CHECK(compute_plan_hash("tar", "purge_source", params_extra, "scope:win", "exec-1") != base);

    std::map<std::string, std::string> empty_params;
    auto base_empty = compute_plan_hash("tar", "purge_source", empty_params, "scope:win", "exec-1");
    CHECK(base_empty != base);
}

TEST_CASE("compute_plan_hash: is a lowercase hex digest", "[server][dispatch][capability]") {
    std::map<std::string, std::string> params;
    auto hash = compute_plan_hash("tar", "purge_source", params, "scope:win", "exec-1");
    CHECK_FALSE(hash.empty());
    for (char c : hash) {
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }
}

// ── encode_dispatch_tag / decode_dispatch_tag ────────────────────────────

TEST_CASE("dispatch tag: round-trips for every DispatchClass x Mutability pair",
          "[server][dispatch][capability]") {
    const std::string plan_hash = "deadbeefcafef00d0123456789abcdef";
    const std::array<DispatchClass, 3> classes{
        DispatchClass::ReadOnly,
        DispatchClass::Mutating,
        DispatchClass::Destructive,
    };
    const std::array<Mutability, 3> mutabilities{
        Mutability::None,
        Mutability::Reversible,
        Mutability::Irreversible,
    };

    for (auto c : classes) {
        for (auto m : mutabilities) {
            auto tag = encode_dispatch_tag(c, m, plan_hash);
            auto decoded = decode_dispatch_tag(tag);
            REQUIRE(decoded.has_value());
            const DispatchTag expected{c, m, plan_hash};
            CHECK(*decoded == expected);
        }
    }
}

TEST_CASE("dispatch tag: encode produces exactly the v1|<class>|<mutability>|<hash> grammar",
          "[server][dispatch][capability]") {
    CHECK(encode_dispatch_tag(DispatchClass::ReadOnly, Mutability::None, "abc123") ==
         "v1|ro|none|abc123");
    CHECK(encode_dispatch_tag(DispatchClass::Mutating, Mutability::Reversible, "abc123") ==
         "v1|mut|rev|abc123");
    CHECK(encode_dispatch_tag(DispatchClass::Destructive, Mutability::Irreversible, "abc123") ==
         "v1|dest|irrev|abc123");
}

TEST_CASE("dispatch tag: decode rejects a wrong version prefix", "[server][dispatch][capability]") {
    auto result = decode_dispatch_tag("v2|ro|none|abc123");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == DispatchTagError::Malformed);
}

TEST_CASE("dispatch tag: decode rejects an embedded newline", "[server][dispatch][capability]") {
    auto result = decode_dispatch_tag("v1|ro|none|abc\n123");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == DispatchTagError::Malformed);
}

TEST_CASE("dispatch tag: decode rejects an extra '|'", "[server][dispatch][capability]") {
    auto result = decode_dispatch_tag("v1|ro|none|abc|123");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == DispatchTagError::Malformed);
}

TEST_CASE("dispatch tag: decode rejects a malformed tag (too few fields, bad class/mutability, "
          "empty/non-hex hash)",
          "[server][dispatch][capability]") {
    CHECK_FALSE(decode_dispatch_tag("v1|ro|none").has_value());          // too few fields
    CHECK_FALSE(decode_dispatch_tag("").has_value());                    // empty
    CHECK_FALSE(decode_dispatch_tag("v1|bogus|none|abc123").has_value()); // bad class
    CHECK_FALSE(decode_dispatch_tag("v1|ro|bogus|abc123").has_value());   // bad mutability
    CHECK_FALSE(decode_dispatch_tag("v1|ro|none|").has_value());          // empty hash
    CHECK_FALSE(decode_dispatch_tag("v1|ro|none|ABC123").has_value());    // uppercase hex
    CHECK_FALSE(decode_dispatch_tag("v1|ro|none|not-hex!").has_value());  // non-hex chars
}

TEST_CASE("dispatch tag: encode/decode round-trips a real compute_plan_hash output",
          "[server][dispatch][capability]") {
    std::map<std::string, std::string> params{{"target", "win"}};
    auto hash = compute_plan_hash("tar", "purge_source", params, "scope:win", "exec-1");
    auto tag = encode_dispatch_tag(DispatchClass::Destructive, Mutability::Irreversible, hash);
    auto decoded = decode_dispatch_tag(tag);
    REQUIRE(decoded.has_value());
    CHECK(decoded->plan_hash == hash);
    CHECK(decoded->dispatch_class == DispatchClass::Destructive);
    CHECK(decoded->mutability == Mutability::Irreversible);
}
