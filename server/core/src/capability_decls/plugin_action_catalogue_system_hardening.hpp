#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_system_hardening.hpp
/// One fragment of the command capability catalogue: `system_hardening`'s
/// single action (`agents/plugins/system_hardening/src/system_hardening_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// `posture` is ReadOnly/None: every OS leg reads a fixed allowlist of
/// exploit-mitigation / kernel-hardening values (Linux `/proc/sys`, macOS
/// `sysctlbyname`, Windows mitigation registry + `GetProcessMitigationPolicy`
/// on the agent's own process). No leg writes, spawns a process, or
/// enumerates other processes. Grouped under the existing `Security`
/// securable, as `antivirus.*`, `bitlocker.*`, `firewall.*` and `autoruns.*` are:
/// the rows say which mitigations are not enforced.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueSystemHardening{{
    {
        .plugin = "system_hardening",
        .action = "posture",
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
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueSystemHardening),
              "every row in kPluginActionCatalogueSystemHardening must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_system_hardening() noexcept {
    return detail::kPluginActionCatalogueSystemHardening;
}

} // namespace yuzu::server::capdecls
