#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_mgmt_posture.hpp
/// One fragment of the command capability catalogue: `mgmt_posture`'s
/// single action (`agents/plugins/mgmt_posture/src/mgmt_posture_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `posture` is ReadOnly/None. The Linux leg reads sssd/ipa configuration
/// files and the keytab's presence; the macOS leg runs one bounded, fixed-argv
/// `profiles` query. The Windows leg is a PLANNED placeholder that reads
/// nothing. No leg touches the network, takes an operator-supplied argument,
/// or changes host state, and the action reports which management plane
/// controls the device as a FACT -- it never enforces or judges. A refused
/// read is reported as `permission_denied`, never as "not joined".
///
/// Grouped under `Inventory`, not `Security` (roadmap decision): the rows
/// describe what manages the device (plane, MDM enrolment), which is
/// estate-inventory data, and the action is default-on for inventory readers.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueMgmtPosture{{
    {
        .plugin = "mgmt_posture",
        .action = "posture",
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
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueMgmtPosture),
    "every row in kPluginActionCatalogueMgmtPosture must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_mgmt_posture() noexcept {
    return detail::kPluginActionCatalogueMgmtPosture;
}

} // namespace yuzu::server::capdecls
