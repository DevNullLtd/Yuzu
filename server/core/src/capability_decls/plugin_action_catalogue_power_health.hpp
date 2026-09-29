#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_power_health.hpp
/// One fragment of the command capability catalogue: `power_health`'s four
/// actions (`agents/plugins/power_health/src/power_health_plugin.cpp`).
/// Classified by READING the implementation, per this package's spec.
///
/// `battery`/`thermal`/`power_plan` are ReadOnly/None — none opens a write
/// handle or issues a mutating call on any platform; grouped under the
/// existing `Inventory` securable, the same read-only-fact-collection
/// precedent `filesystem_posture`'s three actions use
/// (`plugin_action_catalogue_filesystem_posture.hpp`).
///
/// `set_power_plan` is this plugin's ONLY mutating action — the sole caller
/// of PowerSetActiveScheme (Windows; UNSUPPORTED on macOS, PLANNED on
/// Linux, and never mutates on either — see power_health_plugin.cpp).
/// Classified Destructive/Reversible (a power-plan switch changes live
/// device behaviour but a subsequent set_power_plan back to the prior GUID
/// fully undoes it — never Irreversible) under a freshly-minted
/// `PowerManagement` securable (rbac_store.cpp's `seed_defaults()`
/// `types[]`, Administrator-only per the PluginConfig/UploadGrant
/// precedent — never Viewer), `authz::Operation::Write`,
/// `authz::RiskTier::Medium`, and `ExecuteGate::AdminOrApproval`: the
/// registry-driven gate (server.cpp:14971, dispatch_destructive_gate.hpp
/// :222) covers REST /api/command, MCP execute_instruction, and the
/// dashboard exec console with no further wiring. ScheduleRunner
/// deliberately retains its own approval-gated scope/broadcast fan-out
/// (routed-concerns-access-control.md:22, D3 — this gate must never move
/// into dispatch_confined), so an approved fleet-wide scheduled
/// set_power_plan is permitted under the platform's schedule-approval
/// posture — see docs/user-manual/power-health.md.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 4> kPluginActionCataloguePowerHealth{{
    {
        .plugin = "power_health",
        .action = "battery",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "power_health",
        .action = "thermal",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "power_health",
        .action = "power_plan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "power_health",
        .action = "set_power_plan",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Reversible,
        .securable = "PowerManagement",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kPluginActionCataloguePowerHealth must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePowerHealth),
    "every row in kPluginActionCataloguePowerHealth must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_power_health() noexcept {
    return detail::kPluginActionCataloguePowerHealth;
}

} // namespace yuzu::server::capdecls
