#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_platform_security.hpp
/// One fragment of the command capability catalogue: `platform_security`'s two
/// actions (`agents/plugins/platform_security/src/platform_security_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `secure_boot` and `code_integrity` are ReadOnly/None: every OS leg reads a
/// fixed set of boot-integrity / code-signing-enforcement values (Linux
/// efivarfs, securityfs `lsm`/`lockdown`; macOS `spctl --status` and
/// `csrutil status` as literal-argv rung-2 leaves; Windows `SecureBoot\State`,
/// `CI\Policy`, `DeviceGuard` and `Lsa\LsaCfgFlags` registry values). No leg
/// writes, and the only spawns are the two fixed macOS argv leaves. Grouped
/// under the existing `Security` securable, as `antivirus.*`, `bitlocker.*`
/// and `firewall.*` are: the rows say which enforcement is not active.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCataloguePlatformSecurity{{
    {
        .plugin = "platform_security",
        .action = "secure_boot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "platform_security",
        .action = "code_integrity",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePlatformSecurity),
              "every row in kPluginActionCataloguePlatformSecurity must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_platform_security() noexcept {
    return detail::kPluginActionCataloguePlatformSecurity;
}

} // namespace yuzu::server::capdecls
