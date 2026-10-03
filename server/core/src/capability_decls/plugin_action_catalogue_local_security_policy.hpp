#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_local_security_policy.hpp
/// One fragment of the command capability catalogue: `local_security_policy`'s
/// four actions (`agents/plugins/local_security_policy/src/local_security_policy_plugin.cpp`).
/// Classified by READING the implementation, not the name.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry; none is minted here.
///
/// All four actions are ReadOnly/None: Linux reads bounded config files
/// (`login.defs`, pwquality/faillock, `/etc/pam.d`, audit rules, sudoers),
/// macOS runs `pwpolicy -getaccountpolicies` (a read-only argv leaf) and reads
/// `audit_control` / sudoers, and Windows runs `secedit.exe /export` (a
/// read-only argv leaf) into an agent-owned scratch directory under
/// `agent.data_dir`, removed on return and swept by a later dispatch if a crash
/// orphans it. No leg changes host policy or account state. Grouped
/// under the existing `Security` securable, the antivirus/bitlocker/firewall/
/// autoruns class of read-only security-posture plugins.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 4> kPluginActionCatalogueLocalSecurityPolicy{{
    {
        .plugin = "local_security_policy",
        .action = "password_policy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "local_security_policy",
        .action = "lockout_policy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "local_security_policy",
        .action = "audit_policy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "local_security_policy",
        .action = "sudoers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        // Medium, not Low (owner decision, 2026-09-22, co-01): sudoers rows carry the NOPASSWD flag and
        // the command allowlist -- a map of where a compromised or careless account could
        // already run something as root without a password, the same "gaps in coverage"
        // shape antivirus.av_exclusions' Medium tier is based on. Operator-triage metadata
        // only (no production code branches on risk_tier today), but published verbatim via
        // yuzu://plugin-docs.
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueLocalSecurityPolicy),
              "every row in kPluginActionCatalogueLocalSecurityPolicy must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function over
/// file-scope `constexpr` storage: this header only DECLARES rows, it never
/// aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_local_security_policy() noexcept {
    return detail::kPluginActionCatalogueLocalSecurityPolicy;
}

} // namespace yuzu::server::capdecls
