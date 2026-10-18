#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_remote_access_audit.hpp
/// One fragment of the command capability catalogue: `remote_access_audit`'s single action
/// (`agents/plugins/remote_access_audit/src/remote_access_audit_plugin.cpp`). Classified by
/// reading the implementation.
///
/// `list` is ReadOnly/None -- the plugin never writes a file or changes a key or service. It
/// reads sshd_config and each account's authorized_keys with bounded no-follow reads, runs one
/// fixed read-only argv per sshd unit, and emits key FINGERPRINTS and option NAMES only.
///
/// Grouped under the SAME `Forensics` securable execution_artifacts and privacy_permissions
/// use (`rbac_store.cpp`'s seeded `types[]` entry; the string below MUST equal that seed
/// literal byte-for-byte, validated by `test_capability_catalogue`'s seeded-securable-types
/// check) -- reusing `Forensics` rather than minting a new securable gets
/// `dispatch_destructive_gate.hpp`'s `kForensicsSecurable`/`requires_explicit_targets`
/// single-target + audited enforcement for free.
///
/// `authz::RiskTier::High`: per-account SSH key fingerprints on a SINGLE named machine name
/// which keys can log in as which account -- identity material. Ships default-off behind the
/// plugin-config kill switch.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueRemoteAccessAudit{{
    {
        .plugin = "remote_access_audit",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// Every row must author .execute_gate -- an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), a compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueRemoteAccessAudit),
    "every row in kPluginActionCatalogueRemoteAccessAudit must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_remote_access_audit() noexcept {
    return detail::kPluginActionCatalogueRemoteAccessAudit;
}

} // namespace yuzu::server::capdecls
