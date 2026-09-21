#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_update_source_trust.hpp
/// One fragment of the command capability catalogue: `update_source_trust`'s
/// single action (`agents/plugins/update_source_trust/src/update_source_trust_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `sources` is ReadOnly/None. Every leg is a plain, bounded read of local
/// configuration: apt sources/keyrings and yum/dnf `.repo` files on Linux,
/// the two com.apple.SoftwareUpdate property lists on macOS (the Windows leg
/// is a PLANNED placeholder that reads nothing). No leg fetches anything over
/// the network, spawns a subprocess, or changes host state, and the action
/// reports how a source is configured to trust its signing authority as a
/// FACT -- it never enforces or judges.
///
/// Grouped under `Security`, not `Inventory`: the rows are supply-chain
/// POSTURE facts (is a repository signed, is a key trusted), the same
/// read-only security-fact class `autoruns.*` and `vuln_scan.*` use, rather
/// than a resource inventory in the `Inventory` securable's sense.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueUpdateSourceTrust{{
    {
        .plugin = "update_source_trust",
        .action = "sources",
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
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueUpdateSourceTrust),
    "every row in kPluginActionCatalogueUpdateSourceTrust must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_update_source_trust() noexcept {
    return detail::kPluginActionCatalogueUpdateSourceTrust;
}

} // namespace yuzu::server::capdecls
