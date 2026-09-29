#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_pkg_inventory.hpp
/// One fragment of the command capability catalogue: `pkg_inventory`'s two
/// actions (`agents/plugins/pkg_inventory/src/pkg_inventory_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// Both actions are ReadOnly/None. Every leg is a zero-subprocess
/// filesystem read (open/openat/readdir with O_NOFOLLOW over Homebrew
/// Library/Taps, Cellar and Caskroom directory names; see
/// pkg_inventory_macos_parsers.hpp; the Linux `managers` leg follows as its
/// own PR); nothing spawns a package manager, and nothing writes, installs, or
/// removes a package.
///
///   `managers` — which package managers are present on this host, plus
///                manager-level configuration facts (machine scope only).
///   `packages` — macOS Homebrew formulae and casks (Cellar/Caskroom
///                directory names). Linux is UNSUPPORTED by construction
///                (`installed_apps` owns the Linux roster); Windows is a
///                PLANNED placeholder.
///
/// Grouped under the existing `Inventory` securable — the same
/// read-only-fact-collection precedent `peripherals.*` and
/// `filesystem_posture.*` use.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCataloguePkgInventory{{
    {
        .plugin = "pkg_inventory",
        .action = "managers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "pkg_inventory",
        .action = "packages",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePkgInventory),
              "every row in kPluginActionCataloguePkgInventory must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_pkg_inventory() noexcept {
    return detail::kPluginActionCataloguePkgInventory;
}

} // namespace yuzu::server::capdecls
