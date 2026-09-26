#pragma once

// test_real_capability_registry.hpp — the REAL `CommandCapabilityRegistry`,
// composed from the same twenty-two capability-declaration spans the production site
// composes, for route-handler fixtures that must wire a `ClassifyFn`.
//
// WHY A SHARED HEADER. PR6.0b gave `DashboardRoutes` a `ClassifyFn` with the
// same fail-closed contract `McpServer::ClassifyFn` carries — an unwired
// classifier refuses every `/api/dashboard/execute` dispatch rather than
// silently reverting the Destructive targeting gate. That makes "compose the
// real registry" a thing more than one route fixture needs, and a per-fixture
// copy of the twenty-two-span composition is the drift a shared seam exists to
// remove: a new catalogue fragment added to production and to only some
// of the copies would leave the stragglers classifying real pairs as
// `Unclassified` — an honest-looking miss that is actually a stale fixture.
//
// Deliberately NOT used by `test_capability_catalogue.cpp` or
// `test_dispatch_destructive_gate.cpp`, which compose the spans themselves ON
// PURPOSE: composition is part of what those two files are testing, so
// borrowing a pre-composed registry would make them assert against the helper
// rather than against the catalogue.

#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "capability_decls/plugin_action_catalogue_b.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "capability_decls/plugin_action_catalogue_content_dist.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "capability_decls/plugin_action_catalogue_disk_actions.hpp"
#include "capability_decls/plugin_action_catalogue_filesystem_posture.hpp"
#include "capability_decls/plugin_action_catalogue_power_health.hpp"
#include "capability_decls/plugin_action_catalogue_autoruns.hpp"
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
#include "capability_decls/plugin_action_catalogue_execution_artifacts.hpp"
#include "capability_decls/plugin_action_catalogue_windows_optional_features.hpp"
#include "capability_decls/plugin_action_catalogue_peripherals.hpp"
#include "capability_decls/plugin_action_catalogue_printing.hpp"
#include "capability_decls/plugin_action_catalogue_app_control.hpp"
#include "capability_decls/plugin_action_catalogue_firmware_posture.hpp"
#include "capability_decls/plugin_action_catalogue_runtimes.hpp"
#include "capability_decls/plugin_action_catalogue_platform_security.hpp"
#include "capability_decls/plugin_action_catalogue_browser_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_system_hardening.hpp"
#include "capability_decls/plugin_action_catalogue_pkg_inventory.hpp"
#include "command_capability.hpp"

#include <string_view>

namespace yuzu::test {

/// The production composition. Function-local static: the spans it holds
/// point at `constexpr` arrays with static storage, so the reference stays
/// valid for the life of the process and every fixture shares one instance.
inline const yuzu::server::CommandCapabilityRegistry& real_capability_registry() {
    namespace capdecls = yuzu::server::capdecls;
    static const yuzu::server::CommandCapabilityRegistry reg{
        capdecls::plugin_action_catalogue_content_dist(),
        capdecls::plugin_action_catalogue_a(),
        capdecls::plugin_action_catalogue_b(),
        capdecls::plugin_action_catalogue_c(),
        capdecls::plugin_action_catalogue_d(),
        capdecls::plugin_action_catalogue_disk_actions(),
        capdecls::plugin_action_catalogue_filesystem_posture(),
        capdecls::plugin_action_catalogue_power_health(),
        capdecls::plugin_action_catalogue_autoruns(),
        capdecls::plugin_action_catalogue_app_usage(),
        capdecls::plugin_action_catalogue_execution_artifacts(),
        capdecls::plugin_action_catalogue_windows_optional_features(),
        capdecls::plugin_action_catalogue_peripherals(),
        capdecls::plugin_action_catalogue_printing(),
        capdecls::plugin_action_catalogue_app_control(),
        capdecls::plugin_action_catalogue_firmware_posture(),
        capdecls::plugin_action_catalogue_runtimes(),
        capdecls::plugin_action_catalogue_platform_security(),
        capdecls::plugin_action_catalogue_browser_inventory(),
        capdecls::plugin_action_catalogue_system_hardening(),
        capdecls::plugin_action_catalogue_pkg_inventory(),
        capdecls::core_dispatch_capabilities(),
    };
    return reg;
}

/// Ready-made `ClassifyFn` body for a fixture that just needs the production
/// classifier wired. Spelled here so a fixture cannot accidentally wire a
/// permissive stand-in and call it "the real one".
inline auto real_classify_fn() {
    return [](std::string_view plugin, std::string_view action) {
        return real_capability_registry().classify(plugin, action);
    };
}

} // namespace yuzu::test
