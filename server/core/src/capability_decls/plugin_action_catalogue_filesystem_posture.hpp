#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_filesystem_posture.hpp
/// One fragment of the command capability catalogue: `filesystem_posture`'s
/// three actions (`agents/plugins/filesystem_posture/src/filesystem_posture_
/// plugin.cpp`). Classified by READING the implementation, not the name, per
/// this package's spec — all three rows below cite what they actually do.
/// `securable`/`operation` reuse an EXISTING `RbacStore` `types[]`/`ops[]`
/// entry (`rbac_store.cpp:978`); none is minted here.
///
/// All three actions — `mounts` (enumerate mounted volumes and their flags),
/// `quotas` (report volume-level disk quota state), and `snapshots`
/// (enumerate filesystem snapshots) — are ReadOnly/None: none opens any
/// handle for write, issues any mutating ioctl or FSCTL, or calls
/// `fs_snapshot_create`/`fs_snapshot_delete`/`fs_snapshot_revert`. The
/// Windows quota leg specifically initializes its `IDiskQuotaControl`
/// control object read-only (`bReadWrite = FALSE`); no leg on any platform
/// mutates volume, quota, or snapshot state. Grouped under the existing
/// `Inventory` securable — the same read-only-fact-collection precedent
/// `disk_space.free` uses (`plugin_action_catalogue_b.hpp`).
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCatalogueFilesystemPosture{{
    {
        .plugin = "filesystem_posture",
        .action = "mounts",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem_posture",
        .action = "quotas",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem_posture",
        .action = "snapshots",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueFilesystemPosture must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueFilesystemPosture),
    "every row in kPluginActionCatalogueFilesystemPosture must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_filesystem_posture() noexcept {
    return detail::kPluginActionCatalogueFilesystemPosture;
}

} // namespace yuzu::server::capdecls
