#pragma once

/// @file capability_fragments.hpp
/// The 28 capability fragments, spelled ONCE. A macro because CommandCapabilityRegistry and
/// enablement::build_unit_overlay take a brace-enclosed initializer_list, which a function cannot
/// forward. A new fragment is added here (its header AND its accessor in the macro) and nowhere
/// else; the order is the registry's (core first) and irrelevant to the overlay.
///
/// This header lives beside, not inside, capability_decls/: that directory holds exactly the
/// fragments themselves, which tests/test_capability_gate_consistency.py compares with its
/// FRAGMENT_FILES. tests/test_capability_catalogue_complete.py's production-wiring tripwire
/// requires server.cpp to include this header and compose YUZU_ALL_CAPABILITY_FRAGMENTS into
/// capability_registry_, and requires this header to include every fragment and name every
/// accessor.

#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "capability_decls/plugin_action_catalogue_app_control.hpp"
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
#include "capability_decls/plugin_action_catalogue_autoruns.hpp"
#include "capability_decls/plugin_action_catalogue_b.hpp"
#include "capability_decls/plugin_action_catalogue_browser_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_browser_policy.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "capability_decls/plugin_action_catalogue_content_dist.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "capability_decls/plugin_action_catalogue_disk_actions.hpp"
#include "capability_decls/plugin_action_catalogue_execution_artifacts.hpp"
#include "capability_decls/plugin_action_catalogue_filesystem_posture.hpp"
#include "capability_decls/plugin_action_catalogue_firmware_posture.hpp"
#include "capability_decls/plugin_action_catalogue_local_security_policy.hpp"
#include "capability_decls/plugin_action_catalogue_mgmt_posture.hpp"
#include "capability_decls/plugin_action_catalogue_peripherals.hpp"
#include "capability_decls/plugin_action_catalogue_pkg_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_platform_security.hpp"
#include "capability_decls/plugin_action_catalogue_power_health.hpp"
#include "capability_decls/plugin_action_catalogue_printing.hpp"
#include "capability_decls/plugin_action_catalogue_privacy_permissions.hpp"
#include "capability_decls/plugin_action_catalogue_runtimes.hpp"
#include "capability_decls/plugin_action_catalogue_shares.hpp"
#include "capability_decls/plugin_action_catalogue_system_hardening.hpp"
#include "capability_decls/plugin_action_catalogue_update_source_trust.hpp"
#include "capability_decls/plugin_action_catalogue_windows_optional_features.hpp"

#define YUZU_ALL_CAPABILITY_FRAGMENTS \
    ::yuzu::server::capdecls::core_dispatch_capabilities(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_a(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_b(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_c(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_d(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_content_dist(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_disk_actions(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_filesystem_posture(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_power_health(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_autoruns(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_app_usage(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_execution_artifacts(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_windows_optional_features(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_peripherals(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_printing(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_browser_policy(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_update_source_trust(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_app_control(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_firmware_posture(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_runtimes(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_platform_security(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_browser_inventory(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_local_security_policy(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_privacy_permissions(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_system_hardening(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_pkg_inventory(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_mgmt_posture(),\
    ::yuzu::server::capdecls::plugin_action_catalogue_shares()
