#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_pkg_inventory.hpp
/// One fragment of the command capability catalogue: `pkg_inventory`'s three
/// actions (`agents/plugins/pkg_inventory/src/pkg_inventory_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// All three actions are ReadOnly/None. Every leg is a zero-subprocess read:
/// on macOS and Linux a filesystem read (open/openat/readdir/readlinkat with
/// O_NOFOLLOW over Homebrew Library/Taps, Cellar and Caskroom directory names,
/// and the Linux snap and flatpak stores; see pkg_inventory_macos_parsers.hpp
/// and pkg_inventory_linux_parsers.hpp); on Windows registry key reads
/// (Reg*W over the HKLM Appx store keys, 64-bit view), a Chocolatey lib
/// directory listing (FindFirstFileExW) and one bounded CreateFileW read per
/// package nuspec (see pkg_inventory_win_parsers.hpp). Nothing spawns a package
/// manager, and nothing writes, installs, or removes a package.
///
///   `managers` — which package managers are present on this host, plus
///                manager-level configuration facts (machine scope only);
///                on Windows Chocolatey and winget presence.
///   `packages` — macOS Homebrew formulae and casks (Cellar/Caskroom
///                directory names) and Windows Chocolatey packages (lib
///                nuspec versions). Linux is UNSUPPORTED by construction
///                (`installed_apps` owns the Linux roster).
///   `store_packages` — Linux snaps and flatpak apps/runtimes from the system
///                stores, and the Windows Appx/MSIX all-user roster from the
///                HKLM Appx store keys. macOS is UNSUPPORTED by design
///                (`installed_apps` owns the application list).
///
/// Grouped under the existing `Inventory` securable — the same
/// read-only-fact-collection precedent `peripherals.*` and
/// `filesystem_posture.*` use.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCataloguePkgInventory{{
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
    {
        .plugin = "pkg_inventory",
        .action = "store_packages",
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
