#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_autoruns.hpp
/// One fragment of the command capability catalogue: `autoruns`'s two
/// actions (`agents/plugins/autoruns/src/autoruns_plugin.cpp`). Classified by
/// READING the implementation, not the name.
///
/// Both actions are ReadOnly/None. `catalog` performs no OS call at all (a
/// pure reflection of the plugin's own static source catalog); `list` reads
/// registry values, files, and plist/task/WMI metadata across its three
/// legs, plus one bounded, read-only subprocess spawn -- the Linux leg's
/// rung-2 `systemctl list-timers` fallback, used only when none of the
/// three systemd unit directories is directly readable (disclosed in
/// docs/user-manual/autoruns.md and the privilege matrix). That child is
/// itself read-only, so the ReadOnly/no-execute-gate classification below
/// still holds -- nothing in either action opens a handle for write or
/// changes any persistence entry it reports on.
///
/// Grouped under `Security`, matching the read-only fact-collection precedent
/// `vuln_scan.*` uses for security-relevant inventory: an autorun listing is
/// exactly this class of fact -- what could run automatically -- not a
/// resource inventory in the `Inventory` securable's sense.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueAutoruns{{
    {
        .plugin = "autoruns",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "autoruns",
        .action = "catalog",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueAutoruns),
              "every row in kPluginActionCatalogueAutoruns must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_autoruns() noexcept {
    return detail::kPluginActionCatalogueAutoruns;
}

} // namespace yuzu::server::capdecls
