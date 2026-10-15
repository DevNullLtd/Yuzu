#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_execution_artifacts.hpp
/// One fragment of the command capability catalogue: `execution_artifacts`'s
/// three actions (`agents/plugins/execution_artifacts/src/
/// execution_artifacts_plugin.cpp`). Classified by READING the
/// implementation, per this package's spec.
///
/// All three actions (`shimcache`, `amcache`, `prefetch`) are ReadOnly/None —
/// the plugin only ever reads a registry value, a private hive copy, or a
/// prefetch file and never mutates host state on any platform; the data
/// bytes of any artefact are never emitted (paths and hashes only).
///
/// Grouped under the `Forensics` securable P0 seeds
/// (server/core/src/rbac_store.cpp's `seed_defaults()` `types[]` array,
/// the "Forensics" entry) — the string below MUST equal that seed literal
/// byte-for-byte; validated at wave-1 integration by
/// test_capability_catalogue's `kSeededSecurableTypes` check, which runs
/// after P0 lands.
///
/// `execution_artifacts` authorizes as `Forensics:Read` with
/// `ExecuteGate::AdminOrApproval`, and `Forensics` is seeded to Administrator
/// only. `app_usage` (a sibling Wave 7b plugin, not yet merged as of this
/// writing — verify its own catalogue fragment once it lands rather than
/// trusting this comment) is PLANNED to share the same `Forensics:Read`/
/// `AdminOrApproval` boundary at a lower `authz::RiskTier::Medium`.
/// `authz::RiskTier::High` here is operator-triage metadata, not a wider
/// authorization gap — it does not gate who can dispatch this plugin. The
/// higher tier reflects that ShimCache/Amcache/Prefetch name real executable
/// paths, cryptographic hashes, and precise run timestamps for a SINGLE named
/// machine — the kind of evidence an incident responder pulls during an
/// active investigation, and exactly the kind of read a rogue or compromised
/// operator identity could otherwise use to fingerprint a target's activity
/// undetected. Single-target, audited, and Administrator-gated dispatch
/// semantics are enforced at the server dispatch layer
/// (server/core/src/dispatch_destructive_gate.hpp, P0's
/// `kForensicsSecurable`/`requires_explicit_targets`) — this fragment only
/// carries the per-action classification that layer keys on. See this
/// plugin's README (agents/plugins/execution_artifacts/README.md) for the
/// role-boundary statement this comment mirrors; the docs/user-manual page
/// is a separate follow-up.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCatalogueExecutionArtifacts{{
    {
        .plugin = "execution_artifacts",
        .action = "shimcache",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "execution_artifacts",
        .action = "amcache",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "execution_artifacts",
        .action = "prefetch",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Forensics",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kPluginActionCatalogueExecutionArtifacts must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueExecutionArtifacts),
    "every row in kPluginActionCatalogueExecutionArtifacts must author .execute_gate");

// The Forensics securable is P0's seed string, not this package's own —
// this static_assert only pins that this fragment's literal matches ITSELF
// across all three rows (a copy/paste divergence within the fragment); the
// cross-package byte-for-byte match against rbac_store.cpp's seeded
// `types[]` entry is what test_capability_catalogue's
// kSeededSecurableTypes check verifies at wave-1 integration, after P0
// lands (this package has no way to see P0's file at engineer time).
static_assert(kPluginActionCatalogueExecutionArtifacts[0].securable ==
                  kPluginActionCatalogueExecutionArtifacts[1].securable &&
              kPluginActionCatalogueExecutionArtifacts[1].securable ==
                  kPluginActionCatalogueExecutionArtifacts[2].securable,
              "execution_artifacts's three rows must share one securable literal");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_execution_artifacts() noexcept {
    return detail::kPluginActionCatalogueExecutionArtifacts;
}

} // namespace yuzu::server::capdecls
