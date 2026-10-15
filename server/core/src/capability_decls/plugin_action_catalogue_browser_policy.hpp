#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_browser_policy.hpp
/// One fragment of the command capability catalogue: `browser_policy`'s single
/// action (`agents/plugins/browser_policy/src/browser_policy_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `policies` is ReadOnly/None. The Linux leg reads root-owned JSON policy
/// files under /etc/opt/{chrome,edge} and /etc/chromium with
/// O_NOFOLLOW/O_NONBLOCK and never writes; the Windows and macOS legs are
/// planned placeholders that read nothing and return one in-band `status` row.
///
/// Grouped under the existing `Inventory` securable (Inventory:Read), the same
/// read-only-fact-collection precedent `peripherals.*` and `printing.*` use.
/// The rows describe operator/IT-authored browser configuration, not
/// user-identifying data, so there is no `Forensics` classification and no
/// default-off kill switch (`ExecuteGate::None`).
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueBrowserPolicy{{
    {
        .plugin = "browser_policy",
        .action = "policies",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueBrowserPolicy must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueBrowserPolicy),
    "every row in kPluginActionCatalogueBrowserPolicy must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_browser_policy() noexcept {
    return detail::kPluginActionCatalogueBrowserPolicy;
}

} // namespace yuzu::server::capdecls
