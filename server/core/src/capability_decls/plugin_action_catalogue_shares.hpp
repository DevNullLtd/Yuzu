#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_shares.hpp
/// One fragment of the command capability catalogue: `shares`'s single action
/// (`agents/plugins/shares/src/shares_plugin.cpp`). Classified by READING the
/// implementation, not the name. `securable`/`operation` reuse an EXISTING
/// `RbacStore` `types[]`/`ops[]` entry; none is minted here.
///
/// `list` is ReadOnly/None. The Linux leg reads /etc/exports, /etc/exports.d/*.exports and
/// /etc/samba/smb.conf with bounded no-follow reads plus one lstat; the macOS and Windows
/// legs are PLANNED placeholders that read nothing. No leg touches the network, takes an
/// operator-supplied argument, emits an ACL or an NFS client host list, or changes host
/// state: the action reports which shares the host is configured to serve as a FACT. Share
/// names and paths can embed account names; that is disclosed in the README and definition.
///
/// Grouped under `Infrastructure` (the network_config.routes precedent): what this host
/// exposes to the network is infrastructure state, default-on for infrastructure readers.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueShares{{
    {
        .plugin = "shares",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
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
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueShares),
    "every row in kPluginActionCatalogueShares must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_shares() noexcept {
    return detail::kPluginActionCatalogueShares;
}

} // namespace yuzu::server::capdecls
