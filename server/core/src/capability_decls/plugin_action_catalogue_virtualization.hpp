#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_virtualization.hpp
/// One fragment of the command capability catalogue: `virtualization`'s single action
/// (`agents/plugins/virtualization/src/virtualization_plugin.cpp`). Classified by READING the
/// implementation, not the name. `securable`/`operation` reuse an EXISTING `RbacStore`
/// `types[]`/`ops[]` entry; none is minted here.
///
/// `host` is ReadOnly/None. Every leg reads in-process only: CPUID leaves, sysctl values, sysfs/
/// procfs files, marker-file existence and (Windows) the SMBIOS System Information table. No leg
/// spawns a process, touches the network, takes an operator-supplied argument or changes host
/// state, and the action reports whether the device is a VM, which hypervisor, and whether the
/// agent runs in a container as FACTS. An unreadable source is reported `unknown` with a reason,
/// never as bare metal.
///
/// Grouped under `Inventory`: the rows are estate-inventory device facts, not privacy-gated data
/// (no account, hostname or serial is emitted), so the action is default-on for inventory
/// readers, like `mgmt_posture` and `shares`.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueVirtualization{{
    {
        .plugin = "virtualization",
        .action = "host",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// .execute_gate -- an omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a silent runtime gap. See
// ExecuteGate's doc comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueVirtualization),
    "every row in kPluginActionCatalogueVirtualization must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_virtualization() noexcept {
    return detail::kPluginActionCatalogueVirtualization;
}

} // namespace yuzu::server::capdecls
