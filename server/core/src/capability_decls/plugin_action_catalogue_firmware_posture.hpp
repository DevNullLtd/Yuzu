#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_firmware_posture.hpp
/// One fragment of the command capability catalogue: `firmware_posture`'s
/// single action (`agents/plugins/firmware_posture/src/firmware_posture_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `firmware` is ReadOnly/None: every OS leg reads firmware identity
/// (Windows `Win32_BIOS` + the raw SMBIOS type-0 table, Linux sysfs DMI +
/// fwupd `GetDevices`/`GetUpgrades` over the sd-bus system bus, macOS
/// IODeviceTree). fwupd is only ever asked to list devices and upgrades;
/// no leg installs, downgrades, verifies or activates firmware, writes, or
/// spawns a process. Grouped under the existing `Security` securable, as
/// `antivirus.*`, `bitlocker.*` and `firewall.*` are: a read-only security
/// posture plugin.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueFirmwarePosture{{
    {
        .plugin = "firmware_posture",
        .action = "firmware",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueFirmwarePosture),
              "every row in kPluginActionCatalogueFirmwarePosture must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_firmware_posture() noexcept {
    return detail::kPluginActionCatalogueFirmwarePosture;
}

} // namespace yuzu::server::capdecls
