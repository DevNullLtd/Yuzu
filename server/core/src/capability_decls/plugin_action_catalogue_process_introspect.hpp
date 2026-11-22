#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_process_introspect.hpp
/// One fragment of the command capability catalogue: `process_introspect`'s single action
/// (`agents/plugins/process_introspect/src/process_introspect_plugin.cpp`). Classified by
/// reading the implementation.
///
/// `inspect` is ReadOnly/None -- the plugin never writes, signals or attaches to a process. It
/// opens `/proc/<pid>` once and reads bounded numbers, masks and fixed tokens (resource limits,
/// signal masks, capabilities, seccomp, OOM and scheduling state) of ONE named process.
///
/// ONE row covers every facet at the top tier: data above this contract (file or memory
/// contents, environment values, socket payloads, command-line arguments) is a NEW action with
/// its own row here, never a new facet of this one.
///
/// Grouped under the SAME `Forensics` securable execution_artifacts, privacy_permissions and
/// remote_access_audit use (`rbac_store.cpp`'s seeded `types[]` entry; the string below MUST
/// equal that seed literal byte-for-byte, validated by `test_capability_catalogue`'s
/// seeded-securable-types check) -- reusing `Forensics` gets
/// `dispatch_destructive_gate.hpp`'s `kForensicsSecurable`/`requires_explicit_targets`
/// single-target + audited enforcement for free.
///
/// `authz::RiskTier::High`: the security posture of one named process on one named machine
/// (which capabilities and seccomp filter it holds) is reconnaissance material. Ships default-off
/// behind the plugin-config kill switch.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueProcessIntrospect{{
    {
        .plugin = "process_introspect",
        .action = "inspect",
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
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueProcessIntrospect),
    "every row in kPluginActionCatalogueProcessIntrospect must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_process_introspect() noexcept {
    return detail::kPluginActionCatalogueProcessIntrospect;
}

} // namespace yuzu::server::capdecls
