#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_component_inventory.hpp
/// One fragment of the command capability catalogue: `component_inventory`'s two
/// read-only actions (`agents/plugins/component_inventory/src/component_inventory_plugin.cpp`).
/// Classified by READING the implementation.
///
/// `scan` is ReadOnly/None: it lists directories and reads bounded, link-free file bytes
/// (archive directories, two small entries per archive) under fixed machine roots, plus the
/// mount table, all in-process with no subprocess. It writes nothing on the host beyond the
/// plugin's own heartbeat keys, and it takes no parameter, so a request cannot choose a path.
///
/// `native` is the same shape for shared libraries (ELF, Mach-O): bounded, link-free, in-process
/// reads of fixed machine roots, no subprocess, no parameter, nothing written. It is ReadOnly/None
/// and `ExecuteGate::None` like `scan`; what makes it ship off is NOT a gate but an action-level
/// kill-switch row seeded at boot (server.cpp, `seed_action_kill_switch_default_off`), which the
/// dispatch gate already honours and an operator lifts with PUT
/// /api/v1/plugin-config/component_inventory/kill-switch.
///
/// The `Inventory` securable is deliberate: the Java archives and libraries found are a
/// software-inventory fact, not a security-posture fact (Security:Read is for posture
/// plugins). Same precedent as `runtimes`.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueComponentInventory{{
    {
        .plugin = "component_inventory",
        .action = "scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "component_inventory",
        .action = "native",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueComponentInventory must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueComponentInventory),
    "every row in kPluginActionCatalogueComponentInventory must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_component_inventory() noexcept {
    return detail::kPluginActionCatalogueComponentInventory;
}

} // namespace yuzu::server::capdecls
