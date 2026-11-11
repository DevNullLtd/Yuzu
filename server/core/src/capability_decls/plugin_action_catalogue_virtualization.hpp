#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_virtualization.hpp
/// One fragment of the command capability catalogue: `virtualization`'s actions
/// (`agents/plugins/virtualization/src/virtualization_plugin.cpp`). Classified by READING the
/// implementation, not the name. `securable`/`operation` reuse an EXISTING `RbacStore`
/// `types[]`/`ops[]` entry; none is minted here.
///
/// `host` is ReadOnly/None. Every leg reads in-process only: CPUID leaves, sysctl values, sysfs/
/// procfs files, marker-file existence and (Windows) the SMBIOS System Information table. No leg
/// spawns a process, touches the network, takes an operator-supplied argument or changes host
/// state, and the action reports whether the device is a VM, which hypervisor, and whether the
/// agent runs in a container as FACTS. A host-decision source (SMBIOS, CPUID, OS hint) that
/// cannot be read is reported `unknown` with a reason, never as bare metal.
///
/// Grouped under `Inventory`: the rows are estate-inventory device facts, not privacy-gated data
/// (no account, hostname or serial is emitted), so the action is default-on for inventory
/// readers, like `mgmt_posture` and `shares`.
///
/// `wsl` is ReadOnly/None too, but it is PER-USER data: on Windows it lists the WSL distributions
/// of every local profile (the account name and the distribution name are emitted) and, for a
/// profile that is not logged on, reads that profile's NTUSER.DAT through the shared
/// `with_user_hive` offline arm (SeBackup/SeRestore already held, taken inside the helper under
/// the process-wide offline-hive lock and the default-on hive-file guard). It therefore mirrors
/// `installed_apps.list_per_user`: `Inventory`:Read, default-on, `ExecuteGate::AdminOrApproval`,
/// no Forensics securable and no kill-switch seed. Linux and macOS answer one `unsupported` row.
///
/// `runtime_posture` is ReadOnly/None and Linux-only (macOS and Windows answer one `unsupported`
/// row). It stats the container runtimes' default sockets and config files and, ONLY when the
/// operator has set `--container-runtime-endpoint`, sends four fixed GET requests over that one
/// unix socket (docs/virtualization-runtime-posture-design.md). It reports container posture
/// (names, images, privileged, network mode, host-socket-mounted), which is security posture rather
/// than estate inventory, so it is `Security`:Read like `system_hardening` and `app_control` (owner
/// decision 2026-11-08), ExecuteGate::None, no Forensics securable and no kill-switch seed.
/// The enforced control is this gate; the definition's `executeRoles` are advisory and follow the
/// `host` document (`content/definitions/virtualization.yaml`), not `list_per_user`'s narrower list.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCatalogueVirtualization{{
    {
        .plugin = "virtualization",
        .action = "host",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "virtualization",
        .action = "wsl",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "virtualization",
        .action = "runtime_posture",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// .execute_gate -- an omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a silent runtime gap. See
// ExecuteGate's doc comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueVirtualization),
    "every row in kPluginActionCatalogueVirtualization must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_virtualization() noexcept {
    return detail::kPluginActionCatalogueVirtualization;
}

} // namespace yuzu::server::capdecls
