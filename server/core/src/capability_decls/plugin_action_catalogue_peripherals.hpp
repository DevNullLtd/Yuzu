#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_peripherals.hpp
/// One fragment of the command capability catalogue: `peripherals`'s three
/// actions (`agents/plugins/peripherals/src/peripherals_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// All three actions are ReadOnly/None. Every OS leg is a device-tree
/// enumeration (SetupAPI/sysfs/IOKit; see peripherals_{win,linux,macos}.cpp);
/// nothing requests a write, format, authorization-state change, or any
/// other mutation.
///
///   `usb`         — enumerates USB devices: identity, class, speed, hub flag.
///   `pci`         — enumerates PCI/PCIe devices: identity, class, driver.
///   `thunderbolt` — enumerates Thunderbolt/USB4 nodes (the bus_inventory
///                   fold): host controllers and attached devices.
///
/// Grouped under the existing `Inventory` securable — the same
/// read-only-fact-collection precedent `disk_actions.*` and
/// `filesystem_posture.*` use.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCataloguePeripherals{{
    {
        .plugin = "peripherals",
        .action = "usb",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "peripherals",
        .action = "pci",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "peripherals",
        .action = "thunderbolt",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePeripherals),
              "every row in kPluginActionCataloguePeripherals must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_peripherals() noexcept {
    return detail::kPluginActionCataloguePeripherals;
}

} // namespace yuzu::server::capdecls
