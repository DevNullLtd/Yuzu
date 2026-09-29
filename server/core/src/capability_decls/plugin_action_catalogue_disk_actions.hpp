#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_disk_actions.hpp
/// One fragment of the command capability catalogue: `disk_actions`'s two
/// actions (`agents/plugins/disk_actions/src/disk_actions_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// Both actions are ReadOnly/None, and the plugin name is the one thing that
/// could mislead a reader into assuming otherwise — "disk_actions" sounds
/// mutating. It is not, in this change. Every OS call in every leg opens its
/// device or volume handle with ZERO access rights (Windows) or reads an IOKit
/// property (macOS); nothing requests a write, format or delete right, issues a
/// mutating IOCTL, or trims, formats or deletes anything.
///
///   `smart`   — reads drive identity and, on NVMe, the SMART/Health log page.
///               `IOCTL_STORAGE_QUERY_PROPERTY` is a pure query control; the
///               handle carries no access rights at all, so a mutating control
///               could not be issued through it even by mistake.
///   `volumes` — enumerates volumes and reads their disk extents and mount
///               points, to report which physical drive backs which mount
///               point. `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` is a query.
///
/// The mutating half of the original Wave 6 PR6.1-a row — `cleanup_temp`,
/// `cleanup_recycle`, `trim` — is a SEPARATE change and will need
/// `DispatchClass::Destructive` + `Mutability::Irreversible` rows plus an
/// `ExecuteGate`, which is exactly why the two halves were split: those rows
/// deserve their own security review rather than riding in behind two
/// read-only ones.
///
/// Grouped under the existing `Inventory` securable — the same
/// read-only-fact-collection precedent `disk_space.free` and
/// `filesystem_posture.*` use.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueDiskActions{{
    {
        .plugin = "disk_actions",
        .action = "smart",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "disk_actions",
        .action = "volumes",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueDiskActions),
              "every row in kPluginActionCatalogueDiskActions must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_disk_actions() noexcept {
    return detail::kPluginActionCatalogueDiskActions;
}

} // namespace yuzu::server::capdecls
