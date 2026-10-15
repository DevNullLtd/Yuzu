#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file core_dispatch_capabilities.hpp
/// The ONE fragment of the command capability catalogue this package owns:
/// the four dispatches the SERVER issues to itself rather than on a
/// caller's behalf. Every other `capability_decls/*.hpp` fragment (the five
/// per-group plugin.action catalogues) belongs to a different package and is
/// composed alongside this one only at the `CommandCapabilityRegistry`
/// construction site — never merged into this array.
///
/// The four rows, each `system_reserved = true` because none of them is
/// reachable via an operator-attributable RBAC decision — they run on the
/// server's own schedule/reconcile loops (or, for `__sync__.now`, behind a
/// route that gates the operator itself and then dispatches as the system):
///
///   - `tar.fleet_snapshot` (`server.cpp:2427`) — the periodic fleet-wide
///     snapshot pull. Read-only: it asks agents to report, it does not
///     change agent state.
///   - `__guard__.push_rules` (`server.cpp:2907`, `:14195`) — the Guardian
///     rule-set push/reconcile. Mutating-but-reversible: it replaces the
///     agent's active rule set, and a subsequent push replaces it again;
///     nothing about it is destructive.
///   - `asset_tags.sync` (`server.cpp:6586`) — structured tag-category sync
///     to an agent. Mutating-but-reversible for the same reason: a later
///     sync simply supersedes the prior one.
///   - `__sync__.now` (hardware_routes.cpp `POST /api/v1/hardware/{id}/sync`)
///     — operator-requested inventory sync-on-demand (ADR-0016 update).
///     Read-only: the agent re-runs a daily-sync source and reports.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 4> kCoreDispatchCapabilities{{
    {
        .plugin = "tar",
        .action = "fleet_snapshot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Response",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = true,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "__guard__",
        .action = "push_rules",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "GuaranteedState",
        .operation = authz::Operation::Push,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = true,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "asset_tags",
        .action = "sync",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Tag",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = true,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Operator-REQUESTED but system-DISPATCHED (POST /api/v1/hardware/{id}/sync
        // RBAC-gates the operator, then dispatches as the system caller): asks the
        // agent to run its daily-sync source(s) now and report — the same thing it
        // does unprompted every 24h. Read-only like tar.fleet_snapshot: nothing on
        // the endpoint changes. The securable/operation here never admit anyone
        // (system_reserved); they name the data the report lands under.
        .plugin = "__sync__",
        .action = "now",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = true,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kCoreDispatchCapabilities must author .execute_gate — an
// omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in
// command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kCoreDispatchCapabilities),
              "every row in kCoreDispatchCapabilities must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage, deliberately not a `CommandCapabilityRegistry`
/// instance itself: this header only DECLARES rows, it never aggregates or
/// singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> core_dispatch_capabilities() noexcept {
    return detail::kCoreDispatchCapabilities;
}

} // namespace yuzu::server::capdecls
