#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_privacy_permissions.hpp
/// One fragment of the command capability catalogue: `privacy_permissions`'s single action
/// (`agents/plugins/privacy_permissions/src/privacy_permissions_plugin.cpp`). Classified by
/// reading the implementation.
///
/// `permissions` is ReadOnly/None -- the plugin never requests, revokes or modifies a permission
/// grant on any platform. It reads TCC.db (opened immutable: no lock taken, no sidecar file
/// created), the ConsentStore registry subtree (an offline profile hive is mounted for the read
/// and unloaded before return), or the xdg-desktop-portal permission store.
///
/// Grouped under the SAME `Forensics` securable execution_artifacts uses (`rbac_store.cpp`'s
/// seeded `types[]` entry; the string below MUST equal that seed literal byte-for-byte,
/// validated by `test_capability_catalogue`'s seeded-securable-types check) -- reusing
/// `Forensics` rather than minting a new securable gets `dispatch_destructive_gate.hpp`'s
/// `kForensicsSecurable`/`requires_explicit_targets` single-target + audited enforcement for
/// free, the same way `app_usage` already does for its own Forensics-class row.
///
/// `authz::RiskTier::High` (matching execution_artifacts, not app_usage's Medium): this data
/// names, per app, whether that app currently holds live audio/video/location/filesystem
/// surveillance capability on a SINGLE named machine -- at least as sensitive a fingerprint of
/// operator-triage-worthy evidence as ShimCache/Amcache/Prefetch, and exactly the kind of read
/// a rogue or compromised operator identity could misuse to profile a target's installed
/// software and its access without the target's knowledge.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCataloguePrivacyPermissions{{
    {
        .plugin = "privacy_permissions",
        .action = "permissions",
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
    ::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePrivacyPermissions),
    "every row in kPluginActionCataloguePrivacyPermissions must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_privacy_permissions() noexcept {
    return detail::kPluginActionCataloguePrivacyPermissions;
}

} // namespace yuzu::server::capdecls
