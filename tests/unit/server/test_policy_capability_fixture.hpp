#pragma once

// test_policy_capability_fixture.hpp: a fragment-only capability registry for the policy
// tests that dispatch FAKE plugins.
//
// Policy evaluation refuses a pair its capability registry does not classify (fail closed),
// so once the evaluator holds a registry every test that defines an instruction on a
// made-up plugin needs a row for it. The full production registry is exactly at
// `CommandCapabilityRegistry::kMaxSources` (32 of 32), so a fixture fragment cannot be
// composed beside `YUZU_ALL_CAPABILITY_FRAGMENTS`: this registry is ONE source of its own.
// The tests that need REAL pairs (the dispatch-approval cases and the sweep) build the full
// registry from `YUZU_ALL_CAPABILITY_FRAGMENTS` instead.
//
// Five rows cover what `test_policy_evaluator.cpp` and `test_policy_admin_routes.cpp` define:
//   checkp.run, verifyp.run, checkp2.run   read-only, no execute gate
//   fixp.run                               Mutating, no execute gate (the fix instruction)
//   <kForensicsPlugin>.run                 read-only, no execute gate
// The Forensics row is something production cannot have: every production row of a
// Forensics plugin is gated, so after policy evaluation refuses gated pairs the evaluator's
// Forensics tier exclusion is defence in depth there, and the tests that exercise it depend
// on this fixture row.
//
// The remaining rows are fakes for tests of the refusal itself, so those need no real pair:
// a gated row, a Destructive row, a system-reserved row, a row that is both reserved and
// gated (precedence), an unspecified-gate row, and two identical rows (ambiguity).

#include "command_capability.hpp"
#include "test_forensics_tier_fixture.hpp"

#include <array>
#include <span>
#include <string_view>

namespace yuzu::server::test {

inline constexpr std::string_view kFixtureForensicsPlugin{kForensicsPlugin};

inline constexpr std::array kPolicyFixtureRows = std::to_array<CommandCapability>({
    {.plugin = "checkp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = "verifyp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = "checkp2",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = kFixtureForensicsPlugin,
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = "fixp",
     .action = "run",
     .dispatch_class = DispatchClass::Mutating,
     .mutability = Mutability::Reversible,
     .securable = "Infrastructure",
     .operation = authz::Operation::Write,
     .risk_tier = authz::RiskTier::Medium,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    // Fakes for the refusal tests.
    {.plugin = "gatedp",
     .action = "run",
     .dispatch_class = DispatchClass::Mutating,
     .mutability = Mutability::Reversible,
     .securable = "Infrastructure",
     .operation = authz::Operation::Write,
     .risk_tier = authz::RiskTier::Medium,
     .system_reserved = false,
     .execute_gate = ExecuteGate::AdminOrApproval},
    {.plugin = "destrp",
     .action = "run",
     .dispatch_class = DispatchClass::Destructive,
     .mutability = Mutability::Irreversible,
     .securable = "Infrastructure",
     .operation = authz::Operation::Delete,
     .risk_tier = authz::RiskTier::High,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = "resvp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = true,
     .execute_gate = ExecuteGate::None},
    {.plugin = "resgatedp",
     .action = "run",
     .dispatch_class = DispatchClass::Mutating,
     .mutability = Mutability::Reversible,
     .securable = "Infrastructure",
     .operation = authz::Operation::Write,
     .risk_tier = authz::RiskTier::Medium,
     .system_reserved = true,
     .execute_gate = ExecuteGate::AdminOrApproval},
    {.plugin = "unspecp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::Unspecified},
    {.plugin = "dupp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
    {.plugin = "dupp",
     .action = "run",
     .dispatch_class = DispatchClass::ReadOnly,
     .mutability = Mutability::None,
     .securable = "Infrastructure",
     .operation = authz::Operation::Read,
     .risk_tier = authz::RiskTier::Low,
     .system_reserved = false,
     .execute_gate = ExecuteGate::None},
});

/// The fragment-only registry (one source). Function-local static: the span it holds points
/// at `kPolicyFixtureRows`, which has static storage duration.
[[nodiscard]] inline const CommandCapabilityRegistry& policy_fixture_registry() {
    static const CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(kPolicyFixtureRows)};
    return registry;
}

} // namespace yuzu::server::test
