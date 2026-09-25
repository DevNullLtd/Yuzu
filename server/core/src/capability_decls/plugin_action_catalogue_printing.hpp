#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_printing.hpp
/// One fragment of the command capability catalogue: `printing`'s three
/// actions (`agents/plugins/printing/src/printing_plugin.cpp`). Classified
/// by READING the implementation, per this package's spec.
///
/// `printers`/`jobs` are ReadOnly/None — neither opens a mutating handle nor
/// issues a mutating IPP request on any platform; grouped under the
/// existing `Inventory` securable, the same read-only-fact-collection
/// precedent `power_health`'s three read actions use
/// (`plugin_action_catalogue_power_health.hpp`).
///
/// `clear_queue` is this plugin's ONLY mutating action — the sole caller of
/// SetJobW(JOB_CONTROL_CANCEL) (Windows) and IPP Cancel-Job (macOS/Linux),
/// always targeting exactly one job id on one printer; there is no
/// purge-all path anywhere in the plugin. Classified
/// `DispatchClass::Destructive, Mutability::Irreversible, "Infrastructure",
/// authz::Operation::Write, authz::RiskTier::Medium,
/// ExecuteGate::AdminOrApproval`. NOT `Reversible`: `command_capability.hpp`'s
/// own contract is explicit that Reversible means undoable "by a subsequent
/// dispatch of the same or a compensating action" — this plugin has neither.
/// Unlike `power_health.set_power_plan` (genuinely Reversible: a second
/// dispatch of the SAME action, carrying the captured `previous_guid`,
/// restores the prior state through Yuzu's own dispatch surface), there is
/// no `printing.*` action that re-queues a cancelled job — "the operator can
/// resubmit" means a human re-printing the document from their own
/// application, entirely outside any Yuzu dispatch. That is real-world
/// recoverability, not `Mutability::Reversible`'s dispatch-level contract, so
/// this row is Irreversible like every other Destructive row in the
/// catalogue except `power_health.set_power_plan`.
///
/// THE GATE'S REAL REACH (stated explicitly so a reader never overstates
/// it): Destructive means `dispatch_destructive_gate.hpp`:222-227's
/// `RefuseUntargeted` (keyed on `DispatchClass::Destructive` alone) refuses
/// scope/broadcast dispatch of `clear_queue` on the THREE operator-facing
/// route handlers that consult it — REST `/api/command`, MCP
/// `execute_instruction`, and the dashboard exec console (`server.cpp`
/// :1344-1350) — because `job_id` names a DIFFERENT document on every
/// endpoint, and a broadcast "clear_queue" would cancel an unbounded,
/// unrelated set of jobs across the fleet. Schedules
/// (`ScheduleRunner::dispatch_tracked`, `schedule_runner.cpp`:340-342 maps
/// an empty scope to `kBroadcastScope` with `agent_ids={}`), workflows, and
/// `instruction_execute` apply NO Destructive targeting gate by design
/// (`dispatch_destructive_gate.hpp` D3, pinned by
/// `test_dispatch_confined_arms.cpp`:815) — this is the SAME reach every
/// other Destructive row in the catalogue has, not a gap specific to this
/// plugin. What actually protects those un-gated paths is
/// `ExecuteGate::AdminOrApproval` at the shared chokepoint
/// (`classify_and_authorize_dispatch`, `agent_registry.hpp`:270-276) — this
/// row is `Mutability::Irreversible` (see above), so unlike
/// `power_health.set_power_plan` there is no dispatch-level undo to lean on
/// either; `AdminOrApproval` is the row's only real control on every route,
/// gated or not. Never state "scope/broadcast dispatch is refused" for this
/// row without naming the three route handlers it is true for.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kPluginActionCataloguePrinting{{
    {
        .plugin = "printing",
        .action = "printers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "printing",
        .action = "jobs",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "printing",
        .action = "clear_queue",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kPluginActionCataloguePrinting must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePrinting),
    "every row in kPluginActionCataloguePrinting must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_printing() noexcept {
    return detail::kPluginActionCataloguePrinting;
}

} // namespace yuzu::server::capdecls
