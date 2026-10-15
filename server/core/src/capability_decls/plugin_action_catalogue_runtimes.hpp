#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_runtimes.hpp
/// One fragment of the command capability catalogue: `runtimes`'s two
/// read-only actions (`agents/plugins/runtimes/src/runtimes_plugin.cpp`).
/// Classified by READING the implementation.
///
/// `dotnet`/`jvm` are ReadOnly/None on every leg: each is a
/// directory-name or metadata-file read (rung 1, zero subprocess) that
/// mutates nothing. Grouped under the existing `Inventory` securable, the
/// same read-only-fact-collection precedent `printing`, `peripherals` and
/// `power_health`'s read actions use.
///
/// The `Inventory` securable is deliberate: an installed-runtime list is a
/// software-inventory fact, not a security-posture fact (Security:Read is
/// for posture plugins).
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueRuntimes{{
    {
        .plugin = "runtimes",
        .action = "dotnet",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "runtimes",
        .action = "jvm",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueRuntimes must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueRuntimes),
    "every row in kPluginActionCatalogueRuntimes must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_runtimes() noexcept {
    return detail::kPluginActionCatalogueRuntimes;
}

} // namespace yuzu::server::capdecls
