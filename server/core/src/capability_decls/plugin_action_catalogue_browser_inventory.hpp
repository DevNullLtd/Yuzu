#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_browser_inventory.hpp
/// One fragment of the command capability catalogue: `browser_inventory`'s
/// two actions (`agents/plugins/browser_inventory/src/
/// browser_inventory_plugin.cpp`). Classified by READING the
/// implementation, per this package's spec.
///
/// Both actions (`browsers`, `profiles`) are ReadOnly/None — the plugin
/// only ever reads browser installation state and `Local State` JSON and
/// never mutates host state on any platform; per
/// browser_inventory_parsers.hpp's PRIVACY CONTRACT, no row ever carries an
/// account identifier, browsing history or cookie. The per-profile
/// `extensions` action follows as its own PR and adds its row then.
///
/// Grouped under the `Forensics` securable P0 seeds
/// (server/core/src/rbac_store.cpp's `seed_defaults()` `types[]` array,
/// the "Forensics" entry) — the string below MUST equal that seed literal
/// byte-for-byte; validated at wave-1 integration by
/// test_capability_catalogue's `kSeededSecurableTypes` check, which runs
/// after P0 lands. Field-for-field copy of
/// plugin_action_catalogue_execution_artifacts.hpp's precedent (that
/// plugin's own Forensics/AdminOrApproval boundary) — see that file's
/// header comment for the fuller rationale, which applies unchanged here:
/// `browser_inventory` reads per-user browser profile state
/// for a SINGLE named machine, the kind of evidence a rogue or compromised
/// operator identity could otherwise use to fingerprint a target's activity
/// undetected. Single-target, audited, and Administrator-gated dispatch
/// semantics are enforced at the server dispatch layer
/// (server/core/src/dispatch_destructive_gate.hpp, P0's
/// `kForensicsSecurable`/`requires_explicit_targets`) — this fragment only
/// carries the per-action classification that layer keys on. The plugin
/// additionally ships default-off via a server-side kill switch
/// (PluginConfigStore::seed_kill_switch_default_off, wired in server.cpp
/// next to execution_artifacts' precedent) — that gate is independent of
/// this fragment's classification. See this plugin's README
/// (agents/plugins/browser_inventory/README.md) for the role-boundary
/// statement this comment mirrors; the docs/user-manual page is a separate
/// follow-up.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCatalogueBrowserInventory{{
    {
        .plugin = "browser_inventory",
        .action = "browsers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "browser_inventory",
        .action = "profiles",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kPluginActionCatalogueBrowserInventory must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueBrowserInventory),
    "every row in kPluginActionCatalogueBrowserInventory must author .execute_gate");

// The Forensics securable is P0's seed string, not this package's own —
// this static_assert only pins that this fragment's literal matches ITSELF
// across both rows (a copy/paste divergence within the fragment); the
// cross-package byte-for-byte match against rbac_store.cpp's seeded
// `types[]` entry is what test_capability_catalogue's
// kSeededSecurableTypes check verifies at wave-1 integration, after P0
// lands (this package has no way to see P0's file at engineer time).
static_assert(kPluginActionCatalogueBrowserInventory[0].securable ==
                  kPluginActionCatalogueBrowserInventory[1].securable,
              "browser_inventory's two rows must share one securable literal");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_browser_inventory() noexcept {
    return detail::kPluginActionCatalogueBrowserInventory;
}

} // namespace yuzu::server::capdecls
