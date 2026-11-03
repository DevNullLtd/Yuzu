#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_middleware.hpp
/// One fragment of the command capability catalogue: `middleware`'s read-only product actions
/// (`agents/plugins/middleware/src/middleware_plugin.cpp`), currently `ibm_mq`.
/// Classified by READING the implementation.
///
/// The plugin is table-driven (agents/shared/middleware_products.hpp): every product action is
/// ReadOnly/None/Inventory:Read BY CONSTRUCTION, because each is a config/inventory-file read
/// (rung 1, zero subprocess) that mutates nothing. A future row with another classification is a
/// review decision, not a drift this header absorbs. Grouped under the existing `Inventory`
/// securable, the same read-only-fact-collection precedent `printing`, `peripherals` and
/// `power_health`'s read actions use: an installed-product list is a software-inventory fact,
/// not a security-posture fact (Security:Read is for posture plugins).
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueMiddleware{{
    {
        .plugin = "middleware",
        .action = "ibm_mq",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueMiddleware must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueMiddleware),
    "every row in kPluginActionCatalogueMiddleware must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_middleware() noexcept {
    return detail::kPluginActionCatalogueMiddleware;
}

} // namespace yuzu::server::capdecls
