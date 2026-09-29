#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_app_usage.hpp
/// One fragment of the command capability catalogue: `app_usage`'s three
/// actions (`agents/plugins/app_usage/src/app_usage_plugin.cpp`).
/// Classified by READING the implementation, per this package's spec.
///
/// All three actions (`summary`, `last_used`, `foreground`) are
/// ReadOnly/None — the plugin opens tar.db with
/// `SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX` plus `PRAGMA query_only=1`
/// and never mutates anything on any platform; `foreground` never even
/// opens the database (it is an unconditional CONSTRAINED line).
///
/// Grouped under a freshly-minted `Forensics` securable — the string MUST
/// equal P0's seed literal byte-for-byte (server/core/src/rbac_store.cpp's
/// `seed_defaults()` `types[]`; validated at wave-1 integration by
/// test_capability_catalogue's `kSeededSecurableTypes` check, which runs
/// after P0 lands) — rather than the existing `Inventory` securable
/// `power_health`/`filesystem_posture` use: this data derives from TAR's
/// process-event fold and is deliberately kept out of the broad
/// operational-inventory read population (P0's `Forensics` comment: "Wave 7
/// forensics class: execution_artifacts, app_usage, later
/// shell_history/yara_scan"; deliberately absent from the Viewer
/// read-list). `authz::RiskTier::Medium` (not `Low`, unlike power_health's
/// read-only rows) and `ExecuteGate::AdminOrApproval` (not `None`) reflect
/// that per-executable usage history, even with names redacted, is a
/// forensics-sensitive read — the registry-driven gate (server.cpp,
/// dispatch_destructive_gate.hpp) covers REST /api/command, MCP
/// execute_instruction, and the dashboard exec console with no further
/// wiring.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCatalogueAppUsage{{
    {
        .plugin = "app_usage",
        .action = "summary",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "app_usage",
        .action = "last_used",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "app_usage",
        .action = "foreground",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kPluginActionCatalogueAppUsage must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueAppUsage),
    "every row in kPluginActionCatalogueAppUsage must author .execute_gate");

// The Forensics securable is P0's seed string, not this package's own —
// this static_assert only pins that this fragment's literal matches ITSELF
// across all three rows (a copy/paste divergence within the fragment); the
// cross-package byte-for-byte match against rbac_store.cpp's seeded
// `types[]` entry is what test_capability_catalogue's
// kSeededSecurableTypes check verifies at wave-1 integration, after P0
// lands (this package has no way to see P0's file at engineer time).
static_assert(kPluginActionCatalogueAppUsage[0].securable ==
                  kPluginActionCatalogueAppUsage[1].securable &&
              kPluginActionCatalogueAppUsage[1].securable ==
                  kPluginActionCatalogueAppUsage[2].securable,
              "app_usage's three rows must share one securable literal");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_app_usage() noexcept {
    return detail::kPluginActionCatalogueAppUsage;
}

} // namespace yuzu::server::capdecls
