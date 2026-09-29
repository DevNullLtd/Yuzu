#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_app_control.hpp
/// One fragment of the command capability catalogue:
/// `app_control`'s two actions
/// (`agents/plugins/app_control/src/app_control_plugin.cpp`).
/// Classified by READING the implementation, per this package's spec.
///
/// Both `wdac_policy` and `applocker_policy` are ReadOnly/None: the Windows leg
/// only enumerates `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy`, lists
/// `CodeIntegrity\CiPolicies\Active`, runs a bounded read-only WQL SELECT
/// against `MSFT_ApplockerPolicy` and walks `SrpV2` (grep-provable: no registry
/// write, no policy-mutating CIM method, no subprocess). Grouped under the
/// existing `Security` securable: these are security-posture reads (which controls
/// are not enforced), like firewall, antivirus, bitlocker and autoruns. No
/// securable is added. Refs #282 (PARTIAL): add_rule/remove_rule would be
/// Destructive-class rows in a separate PR.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueAppControl{{
    {
        .plugin = "app_control",
        .action = "wdac_policy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "app_control",
        .action = "applocker_policy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueAppControl must
// author .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueAppControl),
    "every row in kPluginActionCatalogueAppControl must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_app_control() noexcept {
    return detail::kPluginActionCatalogueAppControl;
}

} // namespace yuzu::server::capdecls
